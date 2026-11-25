//! Discovery scan runner for URL discovery, attack-surface probing, and test case synthesis without execution.

use anyhow::{Result, bail};
use std::path::Path;

use super::super::discover::discover;
use super::super::ledger;
use super::super::plan::{plan_cases_seeded, seed_from_run_id};
use super::super::store::{agent_runs_dir, checkpoint_agent_run_in, now_iso, save_agent_run_in};
use super::super::types::{AgentRunReport, ExitCheckItem, default_model_tier, register_run};
use super::options::{
    RunOptions, blank_report, checkpoint, ip_fields, log, measure_llm, require_http, resolve_llm,
};
use super::run_guarded;

/// Discovery + planning only (no case is executed). The ledger says so instead of inventing scores.
pub fn run_discovery_scan(target: &str, spec_url: Option<&str>) -> Result<AgentRunReport> {
    run_discovery_in(
        &agent_runs_dir(),
        target,
        spec_url,
        RunOptions::default(),
        &crate::engine::new_run_id(),
    )
}

pub(crate) fn run_discovery_in(
    base: &Path,
    target: &str,
    spec_url: Option<&str>,
    mut opts: RunOptions,
    run_id: &str,
) -> Result<AgentRunReport> {
    if !crate::engine::valid_run_id(run_id) {
        bail!("invalid run id");
    }
    require_http(target)?;
    let mut rep = blank_report(run_id, target, "discovery-scan", false);
    rep.approval_status = Some("scanned".into());
    rep.model_tier = default_model_tier();
    let marker = base.join(run_id).join("CANCEL");
    let token = opts.budget.cancel_token().clone().with_file(marker.clone());
    opts.budget = opts.budget.clone().with_cancel(token.clone());
    let registration = (register_run(run_id, &token), marker);
    log(
        &mut rep.steps,
        "Supervisor",
        "Session Init",
        &format!("URL discovery and attack-surface scan for {target}"),
        "running",
        None,
    );
    {
        let mut r = rep.clone();
        r.budget = Some(opts.budget.usage());
        checkpoint_agent_run_in(base, &r)?;
    }
    run_guarded(base, rep, registration, |rep| {
        let RunOptions {
            mut budget,
            credentials,
            llm,
            lookup_requester_ip,
            ..
        } = opts;
        let mut llm_budget = budget.llm_budget();
        let (ip, ip_type, guidance) = ip_fields(lookup_requester_ip, &mut rep.steps);
        rep.requester_ip = ip;
        rep.requester_ip_type = ip_type;
        rep.allowlist_guidance = guidance;
        let llm_cfg = match resolve_llm(&llm) {
            Ok(c) => {
                let latency = measure_llm(&c);
                log(
                    &mut rep.steps,
                    "Supervisor",
                    "Model Connectivity",
                    &format!("Connected to {}", c.describe()),
                    "completed",
                    Some("llm"),
                );
                rep.llm_status = Some(format!("connected: {} ({})", c.describe(), latency.summary));
                rep.model = c.model.clone();
                rep.provider = c.provider.id.to_string();
                Some(c)
            }
            Err(why) => {
                log(
                    &mut rep.steps,
                    "Supervisor",
                    "Model Connectivity",
                    &format!("{why}; deterministic planning"),
                    "warning",
                    Some("deterministic"),
                );
                rep.llm_status = Some(format!("unavailable: {why}"));
                None
            }
        };
        let disc = discover(target, spec_url, 20, &mut budget);
        log(
            &mut rep.steps,
            "Discovery",
            "Route Inspection",
            &format!(
                "{} ({}); {} route(s)",
                disc.tech.app_architecture,
                disc.tech.primary_framework,
                disc.routes.len()
            ),
            "completed",
            Some("deterministic"),
        );
        rep.notes.extend(disc.notes.iter().cloned());
        rep.discovered_routes = disc.routes.clone();
        rep.app_architecture = Some(disc.tech.app_architecture.clone());
        rep.framework = Some(disc.tech.primary_framework.clone());
        rep.detected_tech = disc.tech.detected_signals.clone();
        checkpoint(base, rep, &budget, &llm_budget);
        let plan = plan_cases_seeded(
            llm_cfg
                .as_ref()
                .filter(|_| !budget.is_cancelled())
                .map(|c| (c, &mut llm_budget)),
            target,
            "discovery-scan",
            &disc,
            None,
            &credentials,
            seed_from_run_id(run_id),
        );
        log(
            &mut rep.steps,
            "Planner",
            "Test Synthesis",
            &format!(
                "{} planned scenario(s) ({}), none executed",
                plan.cases.len(),
                plan.source
            ),
            "completed",
            Some(if plan.llm_cases > 0 {
                "llm+deterministic"
            } else {
                "deterministic"
            }),
        );
        rep.notes.extend(plan.notes.iter().cloned());
        super::options::take_llm_notes(rep, &mut llm_budget);
        rep.stage_sources
            .insert("discovery".into(), "deterministic".into());
        rep.stage_sources
            .insert("planner".into(), plan.source.clone());

        let checklist = vec![
            ExitCheckItem {
                criterion: "Attack surface discovered".into(),
                met: !disc.routes.is_empty(),
                status: Some(if !disc.routes.is_empty() {
                    "met".into()
                } else {
                    "unmet".into()
                }),
                details: format!(
                    "{} route(s), {} ({})",
                    disc.routes.len(),
                    disc.tech.app_architecture,
                    disc.tech.primary_framework
                ),
                case_ids: vec![],
                evidence_files: vec![],
            },
            ExitCheckItem {
                criterion: "Test scenarios synthesized".into(),
                met: !plan.cases.is_empty(),
                status: Some(if !plan.cases.is_empty() {
                    "met".into()
                } else {
                    "unmet".into()
                }),
                details: format!("{} planned scenario(s)", plan.cases.len()),
                case_ids: plan.cases.iter().map(|c| c.id.clone()).collect(),
                evidence_files: vec![],
            },
        ];
        rep.evidence_ledger = Some(ledger::not_evaluated(
            "SCANNED",
            format!(
                "Discovery only: {} route(s) found, {} scenario(s) planned. No test was executed, so nothing is scored.",
                disc.routes.len(),
                plan.cases.len()
            ),
            checklist,
        ));
        rep.planned_cases = plan.cases;
        budget.sync_llm(&llm_budget);
        rep.budget = Some(budget.usage());
        rep.status = if budget.is_cancelled() {
            "cancelled".into()
        } else {
            "completed".into()
        };
        rep.finished_at = Some(now_iso());
        save_agent_run_in(base, rep)?;
        Ok(())
    })
}
