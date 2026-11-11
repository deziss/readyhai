//! Bounded multi-turn ReAct Lead Loop (Phase 4).
//!
//! After Wave 1 + deterministic Wave 2 finish, summarizes high-signal redacted anomalies
//! (5xx stack traces, reflected parameters, created tokens/records, path hints) across waves,
//! synthesizes adaptive follow-up hypotheses via the LLM (validated strictly through `plan::validate_raw`)
//! with an offline deterministic rule fallback, executes within spare budget while reserving capacity
//! for `verify` + cleanup, and stops early when no new anomalies emerge.

use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;
use std::time::Duration;

use super::budget::{RunBudget, SliceLimits};
use super::discover::Discovery;
use super::exec::{Credentials, ExecOptions, execute_cases_with};
use super::lead::Area;
use super::oracle::Verdict;
use super::plan::{Depth, Known, PlannerOutput, key_of, validate_raw};
use super::triage::path_of;
use super::types::{CaseExecutionResult, CreatedLedger, PlannedCase, ProbeOracle};
use crate::llm::{Budget, LlmConfig, untrusted};

pub const MAX_REACT_WAVES: usize = 2;
pub const MAX_REACT_CASES_PER_WAVE: usize = 6;

#[derive(Debug, Clone, Default)]
pub struct ReactOutcome {
    pub added_cases: Vec<PlannedCase>,
    pub added_results: Vec<CaseExecutionResult>,
    pub waves_run: usize,
    pub llm_used: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct Anomaly {
    dedup_key: String,
    component: String,
    method: String,
    status_code: Option<u16>,
    signals: Vec<&'static str>,
    request_payload: Option<String>,
    body_excerpt: String,
    hinted_params: Vec<String>,
    hinted_routes: Vec<String>,
}

fn body_excerpt(r: &CaseExecutionResult) -> &str {
    r.evidence_detail
        .as_ref()
        .and_then(|d| d.get("response"))
        .and_then(|resp| resp.get("body_excerpt"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn has_fail_check(r: &CaseExecutionResult, codes: &[&str]) -> bool {
    r.oracle.as_ref().is_some_and(|o| {
        o.checks
            .iter()
            .any(|c| c.verdict == Verdict::Fail && codes.iter().any(|want| c.code == *want))
    })
}

fn param_hint_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:render|eval|compile|param(?:eter)?|field|key)\s*(?:\(|:|is|=)?\s*['"`]?([a-zA-Z_][a-zA-Z0-9_]{0,24})"#)
            .expect("valid param regex")
    })
}

fn route_hint_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(/(?:api|admin|internal|v[12]|graphql)[a-zA-Z0-9_./-]*)"#)
            .expect("valid route regex")
    })
}

fn extract_payload_keys(payload: Option<&str>) -> Vec<String> {
    let mut keys = Vec::new();
    let Some(p) = payload.map(str::trim).filter(|s| !s.is_empty()) else {
        return keys;
    };
    if p.starts_with('{')
        && let Ok(Value::Object(map)) = serde_json::from_str::<Value>(p)
    {
        for k in map.keys() {
            if !k.trim().is_empty() && !keys.contains(k) {
                keys.push(k.clone());
            }
        }
        return keys;
    }
    for pair in p.split('&') {
        if let Some((k, _)) = pair.split_once('=') {
            let clean = k.trim().to_string();
            if !clean.is_empty() && !keys.contains(&clean) {
                keys.push(clean);
            }
        }
    }
    keys
}

fn extract_hinted_params(body: &str, req_payload: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let low = body.to_ascii_lowercase();
    let interesting = low.contains("traceback")
        || low.contains("template")
        || low.contains("syntaxerror")
        || low.contains("param")
        || low.contains("render(")
        || low.contains("keyerror")
        || low.contains("missing")
        || low.contains("ssti");
    if interesting {
        for cap in param_hint_re().captures_iter(body) {
            if let Some(m) = cap.get(1) {
                let name = m.as_str().trim();
                let nl = name.to_ascii_lowercase();
                if !matches!(
                    nl.as_str(),
                    "none" | "null" | "true" | "false" | "error" | "string" | "int" | "for" | "in"
                ) && !out.iter().any(|x| x == name)
                {
                    out.push(name.to_string());
                }
            }
        }
        for common in [
            "tpl", "template", "q", "query", "cmd", "url", "file", "name",
        ] {
            if (low.contains(&format!("{common} param")) || low.contains(&format!("'{common}'")))
                && !out.iter().any(|x| x == common)
            {
                out.push(common.to_string());
            }
        }
    }
    for k in extract_payload_keys(req_payload) {
        if !out.contains(&k) {
            out.push(k);
        }
    }
    out
}

fn extract_hinted_routes(body: &str, current_component: &str) -> Vec<String> {
    let mut out = Vec::new();
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed.starts_with("<!") || trimmed.starts_with("<html") {
        return out;
    }
    let cur_path = path_of(current_component);
    for cap in route_hint_re().captures_iter(trimmed) {
        if let Some(m) = cap.get(1) {
            let candidate = m
                .as_str()
                .trim_end_matches(['.', ',', ';', ')', ']', '"', '\'']);
            if candidate != cur_path && candidate.len() > 2 && !out.iter().any(|x| x == candidate) {
                out.push(candidate.to_string());
            }
        }
    }
    out
}

fn extract_anomalies(
    results: &[CaseExecutionResult],
    existing_ssti_paths: &HashSet<String>,
    seen_anomalies: &HashSet<String>,
) -> Vec<Anomaly> {
    let mut out = Vec::new();
    let mut seen_this_wave = HashSet::new();

    for r in results {
        if matches!(r.status.as_str(), "SKIPPED" | "NOT_APPLICABLE") {
            continue;
        }
        let body = body_excerpt(r);
        let mut signals: Vec<&'static str> = Vec::new();

        if r.status_code.is_some_and(|s| s >= 500) {
            signals.push("http_5xx");
        }
        if has_fail_check(r, &["error_disclosure", "stack_trace", "server_error"]) {
            signals.push("error_disclosure");
        }
        if has_fail_check(r, &["injection_reflection"]) {
            signals.push("reflected_input");
        }
        if r.status_code.is_some_and(|s| matches!(s, 200 | 201))
            && matches!(r.method.as_str(), "POST" | "PUT" | "PATCH")
            && !r.is_spa_shell
            && r.technique != "boundary"
            && r.technique != "negative"
            && (body.contains("\"token\"")
                || body.contains("\"access_token\"")
                || body.contains("\"jwt\"")
                || body.contains("\"role\""))
            && serde_json::from_str::<Value>(body).is_ok_and(|v| v.is_object())
        {
            signals.push("created_auth_token");
        }
        if has_fail_check(
            r,
            &[
                "blind_boolean_injection",
                "blind_time_injection",
                "ssrf_oast",
                "ssti",
            ],
        ) {
            signals.push("oob_or_timing_signal");
        }

        if signals.is_empty() {
            continue;
        }
        let norm_path = path_of(&r.component);
        if signals.iter().all(|s| *s == "oob_or_timing_signal")
            && existing_ssti_paths.contains(norm_path)
        {
            continue;
        }
        let dedup_key = format!("{}:{}:{}", r.method, norm_path, signals.join(","));
        if seen_anomalies.contains(&dedup_key) || !seen_this_wave.insert(dedup_key.clone()) {
            continue;
        }

        let hinted_params = extract_hinted_params(body, r.request_payload.as_deref());
        let hinted_routes = extract_hinted_routes(body, &r.component);

        out.push(Anomaly {
            dedup_key,
            component: r.component.clone(),
            method: r.method.clone(),
            status_code: r.status_code,
            signals,
            request_payload: r.request_payload.clone(),
            body_excerpt: untrusted::redact_then_truncate(body, 280),
            hinted_params,
            hinted_routes,
        });
    }
    out
}

fn enrich_react_oracle(c: &mut PlannedCase) {
    if c.probe_oracle.is_some() {
        return;
    }
    let payload = c.payload.as_deref().unwrap_or("");
    if payload.contains("{{1337*79}}")
        || payload.contains("${1337*79}")
        || payload.contains("<%= 1337*79 %>")
    {
        c.probe_oracle = Some(ProbeOracle::Ssti {
            expected_eval: "105623".into(),
        });
    } else if payload.contains("{{OAST_URL}}") {
        c.probe_oracle = Some(ProbeOracle::OastCallback {
            placeholder: "{{OAST_URL}}".into(),
            wait_ms: 800,
        });
    } else if payload.contains("evil.invalid") {
        c.probe_oracle = Some(ProbeOracle::OpenRedirect {
            canary_host: "evil.invalid".into(),
        });
    }
}

fn propose_via_llm(
    cfg: &LlmConfig,
    llm_budget: &mut Budget,
    wave: usize,
    anomalies: &[Anomaly],
    disc: &Discovery,
    creds: &Credentials,
    seen_keys: &mut HashSet<String>,
    next_id: &mut usize,
    cap: usize,
    notes: &mut Vec<String>,
) -> Option<Vec<PlannedCase>> {
    let known = Known::new(&disc.routes);
    let routes_summary: Vec<Value> = disc
        .routes
        .iter()
        .filter(|r| !r.catch_all && !r.is_spa_shell)
        .take(30)
        .map(|r| {
            json!({
                "path": r.path,
                "method": r.method,
                "status_code": r.status_code,
                "is_api": r.is_api,
                "auth_wall": r.auth_wall,
                "input_surface": format!("{:?}", r.input_surface),
            })
        })
        .collect();
    let anomaly_summary: Vec<Value> = anomalies
        .iter()
        .take(10)
        .map(|a| {
            json!({
                "method": a.method,
                "component": a.component,
                "status_code": a.status_code,
                "signals": a.signals,
                "request_payload": a.request_payload,
                "hinted_params": a.hinted_params,
                "hinted_routes": a.hinted_routes,
                "body_excerpt": a.body_excerpt,
            })
        })
        .collect();

    let fenced_data = untrusted::fence_capped(
        &json!({
            "wave": wave,
            "known_routes": routes_summary,
            "anomalies": anomaly_summary,
        }),
        350,
    );

    let system = untrusted::system(
        "You are an adaptive security tester running a bounded ReAct exploration loop. \
         Examine the HTTP anomalies, error tracebacks, parameter hints, and newly revealed tokens inside <data>. \
         Propose up to 6 concrete follow-up test cases strictly targeting known routes listed in <data>. \
         Return JSON {\"cases\": [{\"title\", \"component\", \"method\", \"technique\", \"input_hint\", \"payload\", \"expected_behavior\", \"risk_level\", \"role\"}]}.",
    );
    let prompt = format!(
        "Wave {wave} observed HTTP anomalies that may unlock deeper injection (use SSTI payload {{{{1337*79}}}} when template rendering is suspected), SSRF (use {{{{OAST_URL}}}}), BOLA/IDOR, or privilege escalation paths.\n\n{fenced_data}"
    );

    let res = crate::llm::ask_typed::<PlannerOutput>(cfg, llm_budget, &system, &prompt, |p| {
        if p.cases.len() > MAX_REACT_CASES_PER_WAVE * 2 {
            anyhow::bail!("too many cases returned by ReAct planner");
        }
        Ok(())
    });

    match res {
        Ok(out) => {
            if out.cases.is_empty() {
                return Some(Vec::new());
            }
            let mut valid = Vec::new();
            for raw in out.cases {
                if valid.len() >= cap {
                    break;
                }
                match validate_raw(&raw, &known, creds) {
                    Ok(mut c) => {
                        c.source = Some("llm".into());
                        enrich_react_oracle(&mut c);
                        let key = key_of(&c);
                        if !seen_keys.insert(key) {
                            continue;
                        }
                        *next_id += 1;
                        c.id = format!("R{:03}", *next_id);
                        c.area = Area::classify(&c).as_str().to_string();
                        valid.push(c);
                    }
                    Err(e) => {
                        notes.push(format!("react wave {wave}: rejected LLM proposal: {e}"));
                    }
                }
            }
            if valid.is_empty() { None } else { Some(valid) }
        }
        Err(e) => {
            notes.push(format!(
                "react wave {wave}: LLM adaptive proposal failed ({e}); using deterministic fallback"
            ));
            None
        }
    }
}

fn synthesize_offline_followups(
    anomalies: &[Anomaly],
    disc: &Discovery,
    creds: &Credentials,
    seen_keys: &mut HashSet<String>,
    existing_ssti_paths: &mut HashSet<String>,
    next_id: &mut usize,
    cap: usize,
) -> Vec<PlannedCase> {
    let mut out = Vec::new();
    let actor = creds.actor();
    let known_paths: BTreeSet<String> = disc
        .routes
        .iter()
        .filter(|r| !r.catch_all)
        .map(|r| path_of(&r.path).to_string())
        .collect();

    for a in anomalies {
        if out.len() >= cap {
            break;
        }
        let exploitable_signal = a
            .signals
            .iter()
            .any(|s| matches!(*s, "http_5xx" | "error_disclosure" | "reflected_input"));
        if !exploitable_signal {
            continue;
        }
        let norm_path = path_of(&a.component);
        if !known_paths.contains(norm_path) || existing_ssti_paths.contains(norm_path) {
            continue;
        }

        let param = a.hinted_params.first().map(String::as_str).unwrap_or("q");
        let method = if matches!(a.method.as_str(), "POST" | "PUT" | "PATCH") {
            a.method.as_str()
        } else {
            "GET"
        };
        let payload = if method == "GET" {
            format!("{param}={{{{1337*79}}}}")
        } else {
            json!({ param: "{{1337*79}}" }).to_string()
        };

        let mut c = PlannedCase {
            id: String::new(),
            title: format!("ReAct SSTI follow-up on {method} {norm_path} via `{param}`"),
            component: norm_path.to_string(),
            method: method.to_string(),
            technique: "injection".into(),
            input_hint: format!(
                "Escalated from wave anomaly ({}) via param `{param}`",
                a.signals.join(", ")
            ),
            payload: Some(payload),
            headers: Vec::new(),
            content_type: None,
            probe_oracle: Some(ProbeOracle::Ssti {
                expected_eval: "105623".into(),
            }),
            expected_behavior: "Server must not evaluate template syntax in user input".into(),
            expected_status: None,
            risk_level: "high".into(),
            role: actor.clone().or_else(|| Some("anon".into())),
            secured: None,
            route_status: a.status_code,
            expect_fields: Vec::new(),
            expected_content_type: None,
            source: Some("followup".into()),
            stateful_steps: None,
            concurrency_burst: None,
            contract: None,
            changed_ops: Vec::new(),
            area: String::new(),
            regression_of: Vec::new(),
            history_priority: false,
        };
        c.area = Area::classify(&c).as_str().to_string();
        let key = key_of(&c);
        if seen_keys.insert(key) {
            *next_id += 1;
            c.id = format!("R{:03}", *next_id);
            existing_ssti_paths.insert(norm_path.to_string());
            out.push(c);
        }
    }
    out
}

/// Bounded multi-turn ReAct adaptive execution loop across post-Wave 1/2 HTTP anomalies.
#[allow(clippy::too_many_arguments)]
pub fn run_adaptive_waves(
    target: &str,
    depth: Depth,
    disc: &Discovery,
    exec_opts: &ExecOptions,
    created: &CreatedLedger,
    mut llm: Option<(&LlmConfig, &mut Budget)>,
    budget: &mut RunBudget,
    existing_cases: &[PlannedCase],
    existing_results: &[CaseExecutionResult],
) -> ReactOutcome {
    let mut outcome = ReactOutcome::default();
    if depth == Depth::Quick || exec_opts.dry_run || budget.is_cancelled() {
        return outcome;
    }

    let reserve_requests = (budget.max_requests() / 3).max(15);
    let reserve_steps = (budget.max_steps() / 4).max(8);

    let mut seen_keys: HashSet<String> = existing_cases.iter().map(key_of).collect();
    let mut existing_ssti_paths: HashSet<String> = existing_cases
        .iter()
        .filter(|c| matches!(c.probe_oracle, Some(ProbeOracle::Ssti { .. })))
        .map(|c| path_of(&c.component).to_string())
        .collect();
    let mut seen_anomalies = HashSet::new();
    let mut frontier = existing_results.to_vec();
    let mut next_id = 0usize;

    for wave in 1..=MAX_REACT_WAVES {
        if budget.is_cancelled() || budget.wall_left() < Duration::from_secs(2) {
            break;
        }
        let avail_steps = budget.steps_left().saturating_sub(reserve_steps);
        let avail_reqs = budget.requests_left().saturating_sub(reserve_requests);
        if avail_steps == 0 || avail_reqs == 0 {
            outcome.notes.push(format!(
                "react wave {wave}: stopped cleanly to preserve verification/cleanup budget"
            ));
            break;
        }

        let anomalies = extract_anomalies(&frontier, &existing_ssti_paths, &seen_anomalies);
        if anomalies.is_empty() {
            break;
        }
        for a in &anomalies {
            seen_anomalies.insert(a.dedup_key.clone());
        }

        let cap = MAX_REACT_CASES_PER_WAVE.min(avail_steps).min(avail_reqs);
        if cap == 0 {
            break;
        }

        let mut proposals = None;
        if let Some((cfg, llm_budget)) = llm.as_mut() {
            let cfg = *cfg;
            let llm_budget: &mut Budget = llm_budget;
            if let Some(cases) = propose_via_llm(
                cfg,
                llm_budget,
                wave,
                &anomalies,
                disc,
                &exec_opts.credentials,
                &mut seen_keys,
                &mut next_id,
                cap,
                &mut outcome.notes,
            ) {
                outcome.llm_used = true;
                proposals = Some(cases);
            }
        }

        let wave_cases = proposals.unwrap_or_else(|| {
            synthesize_offline_followups(
                &anomalies,
                disc,
                &exec_opts.credentials,
                &mut seen_keys,
                &mut existing_ssti_paths,
                &mut next_id,
                cap,
            )
        });

        if wave_cases.is_empty() {
            break;
        }

        let req_grant = avail_reqs.min(
            wave_cases
                .len()
                .saturating_mul(3 + exec_opts.reruns as usize),
        );
        if req_grant == 0 {
            break;
        }
        let mut slice = budget.slice(
            "react_lead",
            SliceLimits {
                steps: wave_cases.len(),
                requests: req_grant,
                wall: budget.wall_left().min(Duration::from_secs(60)),
                llm_calls: 0,
            },
        );
        let _installed = created.install();
        let wave_results = execute_cases_with(&wave_cases, target, exec_opts, &mut slice);
        budget.absorb(&slice.usage());

        outcome.waves_run += 1;
        frontier = wave_results.clone();
        outcome.added_cases.extend(wave_cases);
        outcome.added_results.extend(wave_results);
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::pipeline::{LlmMode, RunOptions, run_with};
    use crate::agent::types::AgentRunRequest;
    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn mock_llm_react_loop_adapts_on_wave2_exposes_chained_endpoint_and_bounds_waves() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new()
                    .route(
                        "/",
                        get(|| async {
                            (
                                StatusCode::OK,
                                [(
                                    axum::http::header::CONTENT_TYPE,
                                    "text/html; charset=utf-8",
                                )],
                                "<html><body><a href=\"/api/ping\">Ping</a></body></html>",
                            )
                        }),
                    )
                    .route(
                        "/api/ping",
                        get(|Query(q): Query<HashMap<String, String>>| async move {
                            let tpl = q.get("tpl").map(String::as_str).unwrap_or("");
                            if tpl.contains("{{1337*79}}") {
                                return (
                                    StatusCode::OK,
                                    Json(json!({ "rendered": "105623" })),
                                );
                            }
                            let v = q
                                .get("q")
                                .or_else(|| q.get("host"))
                                .map(String::as_str)
                                .unwrap_or("ok");
                            if v.contains('\'') || v.contains("alert") {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({
                                        "error": "traceback: see query handler at /api/ping for SSTI tpl param"
                                    })),
                                )
                            } else {
                                (StatusCode::OK, Json(json!({ "pong": v })))
                            }
                        }),
                    );

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://127.0.0.1:{}", addr.port())).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let base_url = rx.recv().unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = Arc::clone(&calls);
        let saw_fence = Arc::new(AtomicUsize::new(0));
        let fence_ref = Arc::clone(&saw_fence);
        let m = crate::llm::mock::start(move |body| {
            if body.contains("<data>") && body.contains("SECURITY RULES") {
                fence_ref.fetch_add(1, Ordering::SeqCst);
            }
            if body.contains("adaptive security tester") || body.contains("anomalies") {
                let rn = calls_ref.fetch_add(1, Ordering::SeqCst);
                if rn == 0 {
                    r#"{"cases":[
                        {"title":"ReAct SSTI follow-up via tpl param","component":"/api/ping","method":"GET","technique":"injection","payload":{"tpl":"{{1337*79}}"},"risk_level":"critical"},
                        {"title":"ReAct hallucinated route must be rejected","component":"/api/never/existed","method":"GET","technique":"injection","payload":{"q":"1"}}
                    ]}"#
                    .into()
                } else {
                    r#"{"cases":[]}"#.into()
                }
            } else {
                r#"{"cases":[]}"#.into()
            }
        });

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let llm_cache = std::env::temp_dir().join(format!("rh-react-llm-{nonce}"));
        let run_base = std::env::temp_dir().join(format!("rh-react-run-{nonce}"));
        std::fs::create_dir_all(&run_base).unwrap();
        let mut cfg = crate::llm::mock::cfg(&m.base, &llm_cache);
        cfg.model = format!("react-test-{nonce}");

        let req = AgentRunRequest {
            target: base_url,
            profile: "standard".into(),
            spec_url: None,
            custom_instructions: None,
            max_steps: None,
            dry_run: false,
            thinking: false,
            model_tier: "balanced".into(),
            thinking_budget_tokens: 1024,
            repo: None,
            diff_base: None,
        };
        let budget = RunBudget::new(80, 200, Duration::from_secs(60), 0.0);
        let opts = RunOptions {
            budget,
            credentials: Credentials::default(),
            llm: LlmMode::Use(Box::new(cfg)),
            reruns: 0,
            verify_k: 1,
            request_timeout: Duration::from_secs(5),
            lookup_requester_ip: false,
            workers: 2,
            memory_dir: None,
        };

        let rep = run_with(&run_base, &req, "react-llm", opts, Some(true)).unwrap();
        let _ = std::fs::remove_dir_all(&llm_cache);
        let _ = std::fs::remove_dir_all(&run_base);

        assert!(
            rep.steps.iter().any(|s| s.action == "ReAct Adaptive Loop"),
            "expected ReAct Adaptive Loop step in report: {:?}",
            rep.steps
        );
        assert_eq!(
            rep.stage_sources.get("react_lead").map(String::as_str),
            Some("llm+deterministic"),
            "expected LLM adaptive source tag in report: {:?}",
            rep.stage_sources
        );
        assert!(
            rep.planned_cases
                .iter()
                .all(|c| c.component != "/api/never/existed"),
            "hallucinated route must never pass validate_raw"
        );
        assert!(
            saw_fence.load(Ordering::SeqCst) > 0,
            "anomalies prompt must fence data with <data> and include SECURITY RULES"
        );
        assert!(
            calls.load(Ordering::SeqCst) <= MAX_REACT_WAVES,
            "ReAct LLM calls exceeded MAX_REACT_WAVES: {}",
            calls.load(Ordering::SeqCst)
        );
        assert!(
            rep.triaged_defects
                .iter()
                .any(|d| d.component.contains("/api/ping") && d.rule == "ssti"),
            "expected LLM-proposed SSTI follow-up via tpl param to fail & triage: {:?}",
            rep.triaged_defects
        );
    }

    #[test]
    fn offline_react_fallback_chains_error_disclosure_and_reflected_input_without_llm() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new()
                    .route(
                        "/",
                        get(|| async {
                            (
                                StatusCode::OK,
                                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                                "<html><body><a href=\"/api/calc\">Calc</a></body></html>",
                            )
                        }),
                    )
                    // Returns 500 on malformed quotes (anomaly in Wave 1), AND evaluates SSTI `{{1337*79}}`
                    // under query param `q`.
                    .route(
                        "/api/calc",
                        get(|Query(q): Query<HashMap<String, String>>| async move {
                            let v = q.get("q").map(String::as_str).unwrap_or("");
                            if v.contains("{{1337*79}}") {
                                (StatusCode::OK, Json(json!({ "result": 105623 })))
                            } else if v.contains('\'') || v.contains("script") {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({ "error": "TemplateSyntaxError in render(q)" })),
                                )
                            } else {
                                (StatusCode::OK, Json(json!({ "value": v })))
                            }
                        }),
                    );

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://127.0.0.1:{}", addr.port()))
                    .unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let base_url = rx.recv().unwrap();

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let run_base = std::env::temp_dir().join(format!("rh-react-off-{nonce}"));
        std::fs::create_dir_all(&run_base).unwrap();

        let req = AgentRunRequest {
            target: base_url,
            profile: "standard".into(),
            spec_url: None,
            custom_instructions: None,
            max_steps: None,
            dry_run: false,
            thinking: false,
            model_tier: "balanced".into(),
            thinking_budget_tokens: 1024,
            repo: None,
            diff_base: None,
        };
        let budget = RunBudget::new(80, 200, Duration::from_secs(60), 0.0);
        let opts = RunOptions {
            budget,
            credentials: Credentials::default(),
            llm: LlmMode::Off,
            reruns: 0,
            verify_k: 2,
            request_timeout: Duration::from_secs(5),
            lookup_requester_ip: false,
            workers: 2,
            memory_dir: None,
        };

        let rep = run_with(&run_base, &req, "react-offline", opts, Some(true)).unwrap();
        let _ = std::fs::remove_dir_all(&run_base);

        assert!(
            rep.steps.iter().any(|s| s.action == "ReAct Adaptive Loop"),
            "offline ReAct must run when Wave 1 produces 500 error anomaly: {:?}",
            rep.steps
        );
        let ssti = rep
            .triaged_defects
            .iter()
            .find(|d| d.component.contains("/api/calc") && d.rule == "ssti")
            .unwrap_or_else(|| {
                panic!(
                    "expected offline ReAct SSTI follow-up to confirm SSTI on /api/calc; defects={:?}",
                    rep.triaged_defects
                )
            });
        assert!(
            ssti.verified,
            "SSTI from offline ReAct wave must verify cleanly"
        );
    }
}
