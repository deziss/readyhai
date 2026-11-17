use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use super::html_analyzer::{
    collect_html_snapshots, extract_post_html_forms, form_urlencoded_encode, is_danger_route,
};
use super::models::{BrowserSecOutcome, path_of_url};
use super::playwright::try_playwright_browser_security;
use super::report_parser::results_from_browser_report;
use crate::agent::budget::{RunBudget, SliceLimits};
use crate::agent::discover::Discovery;
use crate::agent::exec::{ExecOptions, execute_cases_with};
use crate::agent::oracle::{Verdict, has_dom_xss_sink_flow, is_login_location};
use crate::agent::plan::Depth;
use crate::agent::types::{CaseExecutionResult, CreatedLedger, PlannedCase, ProbeOracle, StatefulStep};

const MAX_SYNTHETIC_CASES: usize = 8;
const STORED_XSS_CANARY: &str = "<img src=x onerror=\"window.__rh_xss_hit('sxss')\">";
const STORED_XSS_MARKER: &str = "<img src=x onerror=";

fn make_browser_finding_case(
    id: String,
    title: String,
    component: String,
    method: &str,
    probe_oracle: Option<ProbeOracle>,
    expected_behavior: String,
    risk_level: &str,
) -> PlannedCase {
    PlannedCase {
        id,
        title,
        component,
        method: method.to_string(),
        technique: "browser_security".into(),
        input_hint: "Browser security verification".into(),
        payload: None,
        headers: Vec::new(),
        content_type: None,
        probe_oracle,
        expected_behavior,
        expected_status: None,
        risk_level: risk_level.to_string(),
        role: Some("anon".into()),
        secured: None,
        route_status: Some(200),
        expect_fields: Vec::new(),
        expected_content_type: None,
        source: Some("browser_security".into()),
        stateful_steps: None,
        concurrency_burst: None,
        contract: None,
        changed_ops: Vec::new(),
        area: "ui".into(),
        regression_of: Vec::new(),
        history_priority: false,
    }
}

/// Execute browser-based (Playwright when available) and deterministic DOM/Stored XSS verification.
#[allow(clippy::too_many_arguments)]
pub fn run_browser_security(
    target: &str,
    depth: Depth,
    disc: &Discovery,
    exec_opts: &ExecOptions,
    created: &CreatedLedger,
    work_dir: &Path,
    run_id: &str,
    allow_writes: bool,
    budget: &mut RunBudget,
    existing_results: &[CaseExecutionResult],
) -> BrowserSecOutcome {
    let mut outcome = BrowserSecOutcome::default();
    if exec_opts.dry_run
        || depth == Depth::Quick
        || budget.is_cancelled()
        || budget.wall_left() < Duration::from_secs(2)
    {
        return outcome;
    }

    // `verify::verify_failures` charges requests (never steps), so keep a modest request
    // reserve for verification/cleanup and only a tiny step guard after Lead + ReAct finish.
    let reserve_requests = (budget.max_requests() / 6).max(12);
    let reserve_steps = (budget.max_steps() / 16).clamp(1, 6);
    if budget.steps_left() <= reserve_steps || budget.requests_left() <= reserve_requests {
        return outcome;
    }

    // 1. Optional real Chromium pass when Docker + Playwright image are locally installed.
    let mut pw_used = false;
    match try_playwright_browser_security(target, disc, exec_opts, work_dir, run_id, allow_writes) {
        Ok(Some(pw_rep)) => {
            pw_used = true;
            outcome.notes.extend(pw_rep.notes.iter().cloned());
            let (pw_cases, pw_results) = results_from_browser_report(&pw_rep, target);
            outcome.added_cases.extend(pw_cases);
            outcome.added_results.extend(pw_results);
        }
        Ok(None) => {}
        Err(msg) => outcome
            .notes
            .push(format!("playwright browser security skipped: {msg}")),
    }

    // 2. Deterministic offline HTTP + DOM-sink + Stored-XSS verification (works in air-gapped CI
    //    and enables verify_k >= 2 replay via execute_cases_with -> verify.rs).
    let html_pages = collect_html_snapshots(target, disc, exec_opts, budget, existing_results);
    let mut synth_cases: Vec<PlannedCase> = Vec::new();
    let mut seen_dom_paths: HashSet<String> = outcome
        .added_results
        .iter()
        .filter(|r| {
            r.oracle.as_ref().is_some_and(|o| {
                o.checks
                    .iter()
                    .any(|c| c.code == "dom_xss" && c.verdict == Verdict::Fail)
            })
        })
        .map(|r| path_of_url(&r.component))
        .collect();
    let mut seen_stored_paths: HashSet<String> = outcome
        .added_results
        .iter()
        .filter(|r| {
            r.oracle.as_ref().is_some_and(|o| {
                o.checks
                    .iter()
                    .any(|c| c.code == "stored_xss" && c.verdict == Verdict::Fail)
            })
        })
        .map(|r| path_of_url(&r.component))
        .collect();
    let mut next_id = 0usize;

    for (path, html) in &html_pages {
        if synth_cases.len() >= MAX_SYNTHETIC_CASES {
            break;
        }
        if has_dom_xss_sink_flow(html).is_some() && seen_dom_paths.insert(path.clone()) {
            next_id += 1;
            synth_cases.push(make_browser_finding_case(
                format!("BS{next_id:03}"),
                format!("DOM XSS source-to-sink flow verification on GET {path}"),
                path.clone(),
                "GET",
                Some(ProbeOracle::DomXss {
                    canary: "window.__rh_xss_hit".into(),
                }),
                "Client scripts must sanitize URL/location sources before HTML/eval sinks".into(),
                "high",
            ));
        }

        if allow_writes
            && synth_cases.len() < MAX_SYNTHETIC_CASES
            && !is_login_location(path)
            && !is_danger_route(path)
        {
            for form in extract_post_html_forms(target, path, html) {
                if synth_cases.len() >= MAX_SYNTHETIC_CASES
                    || !seen_stored_paths.insert(path.clone())
                {
                    break;
                }
                next_id += 1;
                let mut body_parts: Vec<String> = form
                    .field_names
                    .iter()
                    .enumerate()
                    .map(|(i, k)| {
                        let v = if i == 0 { STORED_XSS_CANARY } else { "test" };
                        format!(
                            "{}={}",
                            form_urlencoded_encode(k),
                            form_urlencoded_encode(v)
                        )
                    })
                    .collect();
                for (hk, hv) in &form.hidden_fields {
                    body_parts.push(format!(
                        "{}={}",
                        form_urlencoded_encode(hk),
                        form_urlencoded_encode(hv)
                    ));
                }
                let form_payload = body_parts.join("&");

                let poster = exec_opts
                    .credentials
                    .actor()
                    .unwrap_or_else(|| "anon".into());
                let viewer = if exec_opts.credentials.has_role("bob") && poster != "bob" {
                    "bob".to_string()
                } else {
                    poster.clone()
                };

                let mut case = make_browser_finding_case(
                    format!("BS{next_id:03}"),
                    format!(
                        "Stored XSS HTML persistence check ({} -> GET {path})",
                        form.action_path
                    ),
                    path.clone(),
                    "GET",
                    None,
                    "Submitted HTML/script input must be output-encoded before rendering in HTML"
                        .into(),
                    "high",
                );
                case.role = Some(poster.clone());
                case.stateful_steps = Some(vec![
                    StatefulStep {
                        step_number: 1,
                        actor: poster,
                        method: "POST".into(),
                        path: form.action_path.clone(),
                        payload: Some(form_payload),
                        extract_vars: None,
                        expected_status: None,
                        violation_condition: None,
                    },
                    StatefulStep {
                        step_number: 2,
                        actor: viewer,
                        method: "GET".into(),
                        path: path.clone(),
                        payload: None,
                        extract_vars: None,
                        expected_status: Some(200),
                        violation_condition: Some(format!(
                            "stored_xss:unescaped:{STORED_XSS_MARKER}"
                        )),
                    },
                ]);
                synth_cases.push(case);
            }
        }
    }

    if !synth_cases.is_empty() {
        let avail_steps = budget.steps_left().saturating_sub(reserve_steps);
        let avail_reqs = budget.requests_left().saturating_sub(reserve_requests);
        let keep = synth_cases.len().min(avail_steps).min(avail_reqs / 2);
        synth_cases.truncate(keep);
        if !synth_cases.is_empty() {
            let mut slice = budget.slice(
                "browser_security",
                SliceLimits {
                    steps: synth_cases.len(),
                    requests: avail_reqs.min(synth_cases.len() * (3 + exec_opts.reruns as usize)),
                    wall: budget.wall_left().min(Duration::from_secs(45)),
                    llm_calls: 0,
                },
            );
            let _installed = created.install();
            let res = execute_cases_with(&synth_cases, target, exec_opts, &mut slice);
            budget.absorb(&slice.usage());
            outcome.added_cases.extend(synth_cases);
            outcome.added_results.extend(res);
        }
    }

    outcome.source = if pw_used {
        "playwright+deterministic"
    } else {
        "deterministic"
    };
    outcome
}
