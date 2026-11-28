//! Orchestration of the multi-agent pipeline stages: Discovery, Planning, Exploration, Verification, Teardown, Triage, and Readiness Gate.

use anyhow::Result;
use serde_json::Value;
use std::path::Path;
use std::sync::Mutex;

use super::super::change;
use super::super::discover::{discover, harvest_ids};
use super::super::exec::{Auth, Clients, Credentials, ExecOptions, auth_for};
use super::super::lead;
use super::super::ledger::{self, LedgerInput};
use super::super::plan::{
    Depth, plan_cases_remembered_with_whitebox, plans_from_spec, seed_from_run_id,
};
use super::super::store::{checkpoint_agent_run_in, now_iso, save_agent_run_in, save_cleanup_in};
use super::super::triage::{add_llm_notes, derive_defects_verified};
use super::super::types::*;
use super::super::verify::{self, VerifyOptions};
use super::change::analyze_change;
use super::cleanup::{delete_check_results, harvest_created, target_is_nonprod, teardown};
use super::gate::llm_gate;
use super::gates::{
    DiscoveryGate, DiscoveryGateInput, ExecutionGate, ExecutionGateInput, PlanGate, PlanGateInput,
    ReconGate, ReconGateInput, ReleaseGateInput, VerifyGate, VerifyGateInput,
    release_gate_verdict_for, validate_discovery_gate, validate_execution_gate, validate_plan_gate,
    validate_recon_gate, validate_verify_gate,
};
use super::graph::{PipelineState, RoutingCondition, StationNode};
use super::intel;
use super::memory::{recall, remember};
use super::options::{
    RunOptions, cap_if_slow, checkpoint, ip_fields, log, measure_llm, resolve_llm, take_llm_notes,
};
use super::order::order_and_trim;
use crate::llm::{call_params, clamp_thinking_budget};

pub(crate) fn agent_stages(
    base: &Path,
    req: &AgentRunRequest,
    rep: &mut AgentRunReport,
    opts: RunOptions,
    nonprod_pin: Option<bool>,
) -> Result<()> {
    let RunOptions {
        mut budget,
        mut credentials,
        llm,
        reruns,
        verify_k,
        request_timeout,
        lookup_requester_ip,
        workers,
        memory_dir,
        data_dir,
    } = opts;
    // The run's project-intel root: the process data directory in production, an
    // injected directory in tests, so a run can never touch the operator's own
    // vulnerability database by accident.
    let data_root = data_dir.unwrap_or_else(crate::engine::data_dir);
    let data_root = data_root.as_path();
    let mut llm_budget = budget.llm_budget();
    let (ip, ip_type, guidance) = ip_fields(lookup_requester_ip, &mut rep.steps);
    rep.requester_ip = ip;
    rep.requester_ip_type = ip_type;
    rep.allowlist_guidance = guidance;

    // LLM: resolved and probed once; every LLM step is skipped when it is not reachable
    let llm_cfg = match resolve_llm(&llm) {
        Ok(mut c) => {
            let latency = measure_llm(&c);
            if req.thinking {
                c = c.with_thinking(true, &req.model_tier, req.thinking_budget_tokens);
            }
            cap_if_slow(&mut c, &latency, &mut rep.notes);
            if req.thinking {
                let p = call_params(&c);
                let sent = p.anthropic_thinking.is_some() || p.reasoning_effort.is_some();
                log(
                    &mut rep.steps,
                    "Supervisor",
                    "Extended Thinking (CoT)",
                    &format!(
                        "Thinking requested: tier '{}', budget {} tokens (clamped to {}..={}). What {} receives: {}",
                        c.model_tier,
                        c.thinking_budget_tokens,
                        crate::llm::MIN_THINKING_BUDGET,
                        crate::llm::MAX_THINKING_BUDGET,
                        c.describe(),
                        c.thinking_summary()
                    ),
                    if sent { "completed" } else { "warning" },
                    Some("llm"),
                );
            }
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
                &format!("{why}; every LLM step is skipped and the deterministic path is used"),
                "warning",
                Some("deterministic"),
            );
            rep.llm_status = Some(format!("unavailable: {why}"));
            None
        }
    };
    rep.thinking = req.thinking;
    rep.model_tier = req.model_tier.clone();
    rep.thinking_budget_tokens = clamp_thinking_budget(req.thinking_budget_tokens);
    if let Some(c) = llm_cfg.as_ref().filter(|_| req.thinking) {
        // what the planner really runs at (a slow endpoint holds it at the High tier)
        rep.model_tier = c.model_tier.clone();
        rep.thinking_budget_tokens = c.thinking_budget_tokens;
    }
    checkpoint(base, rep, &budget, &llm_budget);

    if credentials.has_pending_logins()
        && !req.dry_run
        && let Ok(u) = reqwest::Url::parse(&req.target)
        && let Ok(cl) = Clients::new(request_timeout, &u)
    {
        for note in credentials.bootstrap_pending(&cl) {
            rep.notes.push(note);
        }
    }

    // Station 1: Recon (Autonomous Directives & Posture Fingerprinting)
    let mut station_node = StationNode::new(PipelineState::Recon);
    if let Ok(verdict) = ReconGate::check_entrance(&req.target, budget.max_requests()) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Recon Entrance Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            "completed",
            Some("deterministic"),
        );
    }
    log(
        &mut rep.steps,
        "Recon",
        "Target Fingerprinting & Directives",
        "Inspecting security headers, cookies, and synthesizing autonomous rules of engagement",
        "running",
        Some("deterministic"),
    );
    let host = reqwest::Url::parse(&req.target)
        .ok()
        .map(|u| {
            format!(
                "{}:{}",
                u.host_str().unwrap_or(""),
                u.port_or_known_default().unwrap_or(0)
            )
        })
        .unwrap_or_default();
    let recon_allowed = !req.dry_run && budget.take_request(&host).is_ok();
    let empty_headers = reqwest::header::HeaderMap::new();
    let recon_directives = super::super::recon::synthesize_directives(
        llm_cfg
            .as_ref()
            .filter(|_| !budget.is_cancelled())
            .map(|c| (c, &mut llm_budget)),
        &req.target,
        req.spec_url.as_deref(),
        if recon_allowed {
            None
        } else {
            Some(&empty_headers)
        },
    );
    rep.directives = Some(recon_directives.clone());
    let effective_instructions: Option<String> = match req.custom_instructions.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(s.to_string()),
        _ => Some(recon_directives.as_custom_instructions()),
    };
    log(
        &mut rep.steps,
        "Recon",
        "Target Fingerprinting & Directives",
        &format!(
            "Synthesized {} focus areas; canary token: {}",
            recon_directives.focus_areas.len(),
            recon_directives.canary_token
        ),
        "completed",
        Some(if llm_cfg.is_some() {
            "llm"
        } else {
            "deterministic"
        }),
    );

    let recon_gate_in = ReconGateInput {
        target_reachable: recon_allowed || req.dry_run,
        directives_present: true,
        focus_areas_count: recon_directives.focus_areas.len(),
    };
    if let Ok(verdict) = validate_recon_gate(&recon_gate_in) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Recon Quality Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            if verdict.passed {
                "completed"
            } else {
                "warning"
            },
            Some("deterministic"),
        );
    }
    let _ = station_node.route(RoutingCondition::NormalProgression);

    // Station 2: Discovery
    if let Ok(verdict) = DiscoveryGate::check_entrance(recon_allowed || req.dry_run) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Discovery Entrance Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            "completed",
            Some("deterministic"),
        );
    }
    log(
        &mut rep.steps,
        "Discovery",
        "Route Inspection",
        "Fingerprinting the target, crawling same-host links, loading the OpenAPI spec when available",
        "running",
        Some("deterministic"),
    );
    let mut disc = discover(&req.target, req.spec_url.as_deref(), 20, &mut budget);
    // headless XHR capture (standard/deep, SPA, Docker + runner image present; a note otherwise)
    super::super::discover::run_xhr_discovery(
        &mut disc,
        &req.target,
        &req.profile,
        &base.join(&rep.id),
        &rep.id,
        &mut budget,
        !req.dry_run && nonprod_pin.unwrap_or_else(|| target_is_nonprod(&req.target)),
    );
    log(
        &mut rep.steps,
        "Discovery",
        "Route Inspection",
        &format!(
            "{} ({}); {} route(s){}",
            disc.tech.app_architecture,
            disc.tech.primary_framework,
            disc.routes.len(),
            if disc.spec.is_some() {
                ", OpenAPI spec loaded"
            } else {
                ""
            }
        ),
        "completed",
        Some("deterministic"),
    );
    if disc.routes.is_empty() {
        rep.notes.push("no routes were discovered (target unreachable or empty); only root and sensitive-file probes are planned".into());
    }
    rep.notes.extend(disc.notes.iter().cloned());
    // 1b. what did the code change? (only when the caller gave a checkout and a base ref)
    let change = analyze_change(req, disc.spec.as_ref(), rep);
    let change_ops = change.as_ref().is_some_and(|a| !a.set.is_empty());
    // 1b-wb. white-box AST bridge when `--repo` is supplied (works even without `--diff-base` or `--spec`)
    let depth = Depth::from_profile(&req.profile);
    let whitebox = req.repo.as_deref().and_then(|repo| {
        if depth == Depth::Quick {
            return None;
        }
        match super::super::whitebox::analyze_and_enrich(repo, &mut disc, depth) {
            Ok(wb) => {
                if !wb.hypotheses.is_empty() || wb.routes_injected > 0 || wb.findings_count > 0 {
                    log(
                        &mut rep.steps,
                        "Discovery",
                        "White-Box Code Audit",
                        &format!(
                            "{} endpoint(s) analyzed in repo; {} hidden route(s) injected; {} targeted sink/guard hypothesis(es)",
                            wb.endpoints_analyzed,
                            wb.routes_injected,
                            wb.hypotheses.len()
                        ),
                        "completed",
                        Some("deterministic"),
                    );
                }
                Some(wb)
            }
            Err(why) => {
                rep.notes
                    .push(format!("white-box repo audit skipped: {why}"));
                None
            }
        }
    });
    // a changed read of one record (`GET /orders/{id}`) is planned against real ids, even at quick
    let change_needs_ids = change
        .as_ref()
        .is_some_and(|a| a.set.labels().any(|l| l.contains('{')));
    // the ids of records that exist (read-only GETs of the spec's collection endpoints), so the
    // plan reads and validates real ones
    let harvested = disc
        .spec
        .as_ref()
        .filter(|_| plans_from_spec(&req.profile) || change_needs_ids)
        .map(|spec| {
            harvest_ids(
                spec,
                &req.target,
                &credentials,
                request_timeout,
                &mut budget,
            )
        });
    if let Some((ids, notes)) = harvested {
        disc.ids = ids;
        rep.notes.extend(notes);
    }
    // Semantic shadow route & parameter boundary prediction using LLM reasoning and directives
    if let Some(cfg) = llm_cfg
        .as_ref()
        .filter(|_| !budget.is_cancelled() && !disc.routes.is_empty())
    {
        let semantic_routes = super::super::discover::semantic::discover_semantic_routes(
            Some((cfg, &mut llm_budget)),
            &req.target,
            &disc.tech,
            &disc.routes,
            rep.directives.as_ref(),
        );
        take_llm_notes(rep, &mut llm_budget);
        if !semantic_routes.is_empty() {
            let sem_n = semantic_routes.len();
            for r in semantic_routes {
                if !disc
                    .routes
                    .iter()
                    .any(|existing| existing.path == r.path && existing.method == r.method)
                {
                    disc.routes.push(r);
                }
            }
            log(
                &mut rep.steps,
                "Discovery",
                "Semantic Shadow Discovery",
                &format!(
                    "Predicted and injected {} shadow endpoint(s) and parameter boundaries",
                    sem_n
                ),
                "completed",
                Some("llm"),
            );
        }
    }

    let disc_gate_in = DiscoveryGateInput {
        routes_count: disc.routes.len(),
        verified_empty_fallback: disc.routes.is_empty(),
        semantic_predictions_validated: true,
    };
    if let Ok(verdict) = validate_discovery_gate(&disc_gate_in) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Discovery Quality Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            if verdict.passed {
                "completed"
            } else {
                "warning"
            },
            Some("deterministic"),
        );
    }
    let _ = station_node.route(RoutingCondition::NormalProgression);

    rep.stage_sources
        .insert("discovery".into(), "deterministic".into());
    rep.discovered_routes = disc.routes.clone();
    rep.app_architecture = Some(disc.tech.app_architecture.clone());
    rep.framework = Some(disc.tech.primary_framework.clone());
    rep.detected_tech = disc.tech.detected_signals.clone();
    checkpoint(base, rep, &budget, &llm_budget);

    // 1c. what the agent remembers about this target (deterministic: a file, no LLM, no request)
    let today = crate::engine::today();
    let (mut hints, memory_notes) = recall(memory_dir.as_deref(), &req.target, rep, &today);
    checkpoint(base, rep, &budget, &llm_budget);

    // 1d. project intel: the vulnerability database, the opt-in exploitation engine and the
    // plugged-tool registry, as ADVISORY planning context (see `intel` for the three
    // invariants). Deterministic data only — it never changes a verdict. A broken settings
    // FILE hard-fails the run like a scan does; no file means defaults.
    let settings_path = crate::settings::settings_path_from_env().or_else(|| {
        let d = data_root.join("settings.toml");
        d.is_file().then_some(d)
    });
    let run_settings = crate::settings::Settings::load(settings_path.as_deref()).map_err(|e| {
        anyhow::anyhow!(
            "settings file {} cannot be used: {e:#}",
            settings_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<none: defaults>".into())
        )
    })?;
    // A configured-but-broken scope file degrades this step with a visible note and
    // switches active probing off (see `intel::gather`), unlike the scan commands.
    let (run_scope, scope_note) = match crate::scope::from_env() {
        Ok(sc) => (sc, None),
        Err(e) => (
            None,
            Some(format!(
                "exploitation: skipped (scope file unusable: {e:#})"
            )),
        ),
    };
    let nonprod_now = nonprod_pin.unwrap_or_else(|| target_is_nonprod(&req.target));
    let gathered = intel::gather(
        req.dry_run,
        &req.target,
        &run_settings,
        run_scope.as_ref(),
        nonprod_now,
        data_root,
    );
    let intel_reproduced = gathered.reproduced.clone();
    if let Some(n) = scope_note {
        rep.notes.push(n);
    }
    for n in &gathered.notes {
        rep.notes.push(n.clone());
    }
    if hints.is_none() && !gathered.open.is_empty() {
        hints = Some(Default::default());
    }
    if let Some(h) = hints.as_mut() {
        h.merge_intel(
            gathered
                .open
                .iter()
                .map(|r| (r.fingerprint.clone(), r.rule.clone(), r.severity.clone()))
                .collect(),
            gathered.reproduced.clone(),
        );
    }
    log(
        &mut rep.steps,
        "Intel",
        "Context Gather",
        &intel::step_summary(&gathered),
        "completed",
        Some("deterministic"),
    );
    checkpoint(base, rep, &budget, &llm_budget);

    // Station 3: Plan
    if let Ok(verdict) = PlanGate::check_entrance(disc.routes.len(), disc.routes.is_empty()) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Plan Entrance Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            "completed",
            Some("deterministic"),
        );
    }
    log(
        &mut rep.steps,
        "Planner",
        "Test Synthesis",
        "Building the deterministic plan (and asking the LLM for extra cases when available)",
        "running",
        None,
    );
    let planner_llm = llm_cfg.as_ref().filter(|_| !budget.is_cancelled());
    let mut plan = plan_cases_remembered_with_whitebox(
        planner_llm.map(|c| (c, &mut llm_budget)),
        &req.target,
        &req.profile,
        &disc,
        req.custom_instructions.as_deref(),
        &credentials,
        seed_from_run_id(&rep.id),
        change.as_ref().map(|a| &a.set),
        hints.as_ref(),
        whitebox.as_ref(),
    );
    take_llm_notes(rep, &mut llm_budget);

    // Stateful multi-step adversarial Attack DAG synthesis (when LLM is configured)
    let mut dag_acyclic = true;
    if let Some(cfg) = llm_cfg
        .as_ref()
        .filter(|_| !budget.is_cancelled() && !disc.routes.is_empty())
    {
        let attack_dag = super::super::plan::synthesize_attack_dag(
            Some((cfg, &mut llm_budget)),
            &req.target,
            &disc.routes,
            effective_instructions.as_deref(),
        );
        take_llm_notes(rep, &mut llm_budget);
        dag_acyclic = !attack_dag.is_cyclic();
        if dag_acyclic
            && !attack_dag.nodes.is_empty()
            && let Ok(mut dag_case) =
                attack_dag.to_planned_case("Attack DAG Adversarial Workflow", "/api")
        {
            dag_case.id = format!("DAG{:03}", plan.cases.len() + 1);
            dag_case.area = "stateful".into();
            plan.cases.push(dag_case);
            log(
                &mut rep.steps,
                "Planner",
                "Attack DAG Synthesis",
                &format!(
                    "Synthesized {}-node acyclic Attack DAG across {} branch(es)",
                    attack_dag.nodes.len(),
                    attack_dag.partition_independent_branches().len()
                ),
                "completed",
                Some("llm"),
            );
        }
    }
    // Never plan more than the allowance, and make sure what is cut is not what matters most
    let (limit, limit_why) = {
        let by_request = req.max_steps.filter(|&n| n > 0);
        let by_profile = profile_case_cap(&req.profile);
        match (by_request, by_profile) {
            (Some(a), Some(b)) if b < a => (Some(b), format!("the '{}' profile cap", req.profile)),
            (Some(a), _) => (Some(a), "max_steps".to_string()),
            (None, Some(b)) => (Some(b), format!("the '{}' profile cap", req.profile)),
            (None, None) => (None, String::new()),
        }
    };
    let planned_total = plan.cases.len();
    let (kept, dropped) =
        order_and_trim(std::mem::take(&mut plan.cases), limit, budget.max_steps());
    plan.cases = kept;
    if !dropped.is_empty() {
        let n = dropped.len();
        let l = limit.unwrap_or(plan.cases.len());
        let first: Vec<String> = dropped
            .iter()
            .take(5)
            .map(|c| format!("{} {}", c.method, c.component))
            .collect();
        rep.notes.push(format!(
            "plan truncated: {n} of {planned_total} planned case(s) were dropped to fit {limit_why} = {l}. {} were kept first; the dropped cases are listed as SKIPPED and lower coverage (e.g. {}{})",
            if change_ops {
                "Cases of changed operations, then authorization, stateful and OpenAPI cases"
            } else {
                "Authorization, stateful and OpenAPI cases"
            },
            first.join(", "),
            if n > first.len() { ", ..." } else { "" }
        ));
        budget.note_stopped(format!(
            "plan truncated to {l} case(s) by {limit_why}: {n} of {planned_total} not run"
        ));
    }
    log(
        &mut rep.steps,
        "Planner",
        "Test Synthesis",
        &format!(
            "{} planned case(s) ({}), {} from the LLM{}",
            planned_total,
            plan.source,
            plan.llm_cases,
            if dropped.is_empty() {
                String::new()
            } else {
                format!("; {} dropped by {limit_why}", dropped.len())
            }
        ),
        if dropped.is_empty() {
            "completed"
        } else {
            "warning"
        },
        Some(if plan.llm_cases > 0 {
            "llm+deterministic"
        } else {
            "deterministic"
        }),
    );
    rep.notes.extend(plan.notes.iter().cloned());
    rep.stage_sources
        .insert("planner".into(), plan.source.clone());
    rep.planned_cases = plan.cases.iter().chain(dropped.iter()).cloned().collect();
    checkpoint(base, rep, &budget, &llm_budget);

    let plan_gate_in = PlanGateInput {
        is_dag_acyclic: dag_acyclic,
        baseline_cases_count: plan.cases.len(),
        directives_covered: rep.directives.is_some(),
    };
    if let Ok(verdict) = validate_plan_gate(&plan_gate_in) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Plan Quality Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            if verdict.passed {
                "completed"
            } else {
                "warning"
            },
            Some("deterministic"),
        );
    }
    let _ = station_node.route(RoutingCondition::NormalProgression);

    // 3. explorer
    log(
        &mut rep.steps,
        "Explorer",
        "Execution & Probing",
        "Sending real HTTP requests; failures are re-run to detect flakiness",
        "running",
        Some("deterministic"),
    );
    let exec_opts = ExecOptions {
        dry_run: req.dry_run,
        is_spa_target: disc.tech.is_spa,
        credentials: credentials.clone(),
        reruns,
        timeout: request_timeout,
    };
    // Station 4: Execute
    if let Ok(verdict) = ExecutionGate::check_entrance(plan.cases.len(), budget.max_steps()) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Execution Entrance Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            "completed",
            Some("deterministic"),
        );
    }
    let created = CreatedLedger::new();
    // the lead splits the plan by area and runs the area workers; its progress is checkpointed
    // into report.json while the workers go, so a status poll sees every area
    let mut executed = {
        let live = Mutex::new(rep.clone());
        let observe = |a: &AgentsReport| {
            let mut snap = live.lock().unwrap_or_else(|e| e.into_inner());
            snap.agents = Some(a.clone());
            let _ = checkpoint_agent_run_in(base, &snap);
        };
        let cfg = lead::LeadConfig {
            target: &req.target,
            opts: &exec_opts,
            workers,
            created: &created,
            llm_calls_left: llm_budget.remaining_calls(),
            on_progress: Some(&observe),
        };
        let out = lead::run(&cfg, &plan.cases, &mut budget);
        log(
            &mut rep.steps,
            "Lead",
            "Area Workers",
            &format!(
                "{} worker(s), {} wave(s): {}",
                out.agents.workers,
                out.agents.waves,
                lead::summary_lines(&out.agents)
            ),
            if out.agents.areas.iter().any(|a| a.error.is_some()) {
                "warning"
            } else {
                "completed"
            },
            Some("deterministic"),
        );
        if !out.follow_ups.is_empty() {
            log(
                &mut rep.steps,
                "Lead",
                "Wave 2",
                &format!(
                    "{} follow-up case(s) planned by rule: {}",
                    out.follow_ups.len(),
                    out.agents
                        .wave2
                        .iter()
                        .filter(|w| w.rule != lead::RULE_RESUME)
                        .map(|w| format!("{} <- {} ({})", w.case_id, w.origin, w.rule))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                "completed",
                Some("deterministic"),
            );
        }
        // follow-up cases are part of the plan from here on (verification replays them by id)
        plan.cases.extend(out.follow_ups.iter().cloned());
        rep.planned_cases.extend(out.follow_ups.iter().cloned());
        rep.agents = Some(out.agents);
        out.results
    };
    let all_non_probe_walled = !disc.routes.is_empty()
        && disc
            .routes
            .iter()
            .filter(|r| !r.catch_all && r.source != "probe")
            .all(|r| r.auth_wall);
    if !req.dry_run && depth != Depth::Quick && !budget.is_cancelled() && !all_non_probe_walled {
        let react_llm = llm_cfg.as_ref().filter(|_| !budget.is_cancelled());
        let rout = super::super::react::run_adaptive_waves(
            &req.target,
            depth,
            &disc,
            &exec_opts,
            &created,
            react_llm.map(|c| (c, &mut llm_budget)),
            &mut budget,
            &plan.cases,
            &executed,
        );
        take_llm_notes(rep, &mut llm_budget);
        if rout.waves_run > 0 || !rout.added_cases.is_empty() {
            if station_node.can_route(&RoutingCondition::AnomalyDetected) {
                let _ = station_node.route(RoutingCondition::AnomalyDetected);
            }
            let added_n = rout.added_cases.len();
            plan.cases.extend(rout.added_cases.iter().cloned());
            rep.planned_cases.extend(rout.added_cases);
            executed.extend(rout.added_results);
            if let Some(a) = rep.agents.as_mut() {
                a.waves += rout.waves_run as u32;
                super::super::lead::recount(a, &executed, &[]);
            }
            rep.stage_sources.insert(
                "react_lead".into(),
                if rout.llm_used {
                    "llm+deterministic"
                } else {
                    "deterministic"
                }
                .into(),
            );
            log(
                &mut rep.steps,
                "Lead",
                "ReAct Adaptive Loop",
                &format!(
                    "{} adaptive wave(s) synthesized and executed {} follow-up case(s)",
                    rout.waves_run, added_n
                ),
                "completed",
                Some(if rout.llm_used {
                    "llm+deterministic"
                } else {
                    "deterministic"
                }),
            );
        }
        rep.notes.extend(rout.notes);
    }
    if !req.dry_run && depth != Depth::Quick && !budget.is_cancelled() && !all_non_probe_walled {
        let allow_browser_writes =
            !req.dry_run && nonprod_pin.unwrap_or_else(|| target_is_nonprod(&req.target));
        let bout = super::super::browser_sec::run_browser_security(
            &req.target,
            depth,
            &disc,
            &exec_opts,
            &created,
            &base.join(&rep.id),
            &rep.id,
            allow_browser_writes,
            &mut budget,
            &executed,
        );
        if !bout.added_cases.is_empty() || !bout.added_results.is_empty() {
            let added_n = bout.added_cases.len();
            plan.cases.extend(bout.added_cases.iter().cloned());
            rep.planned_cases.extend(bout.added_cases);
            executed.extend(bout.added_results);
            if let Some(a) = rep.agents.as_mut() {
                super::super::lead::recount(a, &executed, &[]);
            }
            rep.stage_sources
                .insert("browser_security".into(), bout.source.into());
            log(
                &mut rep.steps,
                "BrowserSecurity",
                "DOM & Client-Side Security",
                &format!("Executed {added_n} browser security verification case(s)"),
                "completed",
                Some(bout.source),
            );
        }
        rep.notes.extend(bout.notes);
    }
    let drop_reason = format!(
        "dropped: the plan was truncated to {} case(s) by {limit_why}; not sent",
        limit.unwrap_or(0)
    );
    executed.extend(
        dropped
            .iter()
            .map(|c| CaseExecutionResult::not_run(c, drop_reason.clone())),
    );
    let n = |s: &str| executed.iter().filter(|r| r.status == s).count();
    let mutations_count = executed
        .iter()
        .filter_map(|r| r.evidence_detail.as_ref())
        .filter(|d| !d.get("adaptive_mutation").unwrap_or(&Value::Null).is_null())
        .count();
    let penetrated_count = executed
        .iter()
        .filter_map(|r| r.evidence_detail.as_ref())
        .filter_map(|d| d.get("adaptive_mutation"))
        .filter(|m| {
            m.get("penetrated_validation")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    if mutations_count > 0 {
        log(
            &mut rep.steps,
            "Explorer",
            "Adaptive Schema Mutation",
            &format!(
                "Triggered {mutations_count} adaptive mutation probe(s) from schema feedback; {penetrated_count} penetrated validation filters"
            ),
            "completed",
            Some("deterministic"),
        );
    }
    log(
        &mut rep.steps,
        "Explorer",
        "Execution & Probing",
        &format!(
            "{} PASS, {} FAIL, {} WARN, {} INCONCLUSIVE, {} BLOCKED, {} SKIPPED",
            n("PASS"),
            n("FAIL"),
            n("WARN"),
            n("INCONCLUSIVE"),
            n("BLOCKED"),
            n("SKIPPED")
        ),
        if n("BLOCKED") > 0 {
            "warning"
        } else {
            "completed"
        },
        Some("deterministic"),
    );
    if let Some(stop) = budget.stopped() {
        log(
            &mut rep.steps,
            "Explorer",
            "Budget",
            stop,
            "warning",
            Some("deterministic"),
        );
        rep.notes.push(format!("run budget: {stop}"));
    }
    // A plain case whose role has no token is still sent (without Authorization); a stateful chain
    // needs the token of every actor and is SKIPPED, nothing sent, when one is missing.
    let is_chain = |c: &PlannedCase| c.stateful_steps.as_ref().is_some_and(|s| !s.is_empty());
    let roles_missing: Vec<String> = {
        let mut r: Vec<String> = plan
            .cases
            .iter()
            .filter(|c| !is_chain(c))
            .filter_map(|c| match auth_for(c) {
                Auth::Role(r) if !credentials.has_role(&r) => Some(r),
                _ => None,
            })
            .collect();
        r.sort();
        r.dedup();
        r
    };
    for r in roles_missing {
        rep.notes.push(format!("no credential for role '{r}': requests for it were sent without Authorization (set {})", Credentials::env_var(&r)));
    }
    for c in plan.cases.iter().filter(|c| is_chain(c)) {
        if let Some(steps) = &c.stateful_steps
            && let Err(why) = super::super::stateful::preflight(steps, &credentials)
            && why.contains("missing credential")
        {
            rep.notes.push(format!(
                "{}: stateful chain skipped, nothing was sent: {why}",
                c.id
            ));
        }
    }
    rep.executed_results = executed;
    checkpoint(base, rep, &budget, &llm_budget);

    let exec_gate_in = ExecutionGateInput {
        waves_completed: rep.agents.as_ref().map(|a| a.waves as usize).unwrap_or(1),
        budget_compliant: !budget.is_cancelled(),
        worker_panics: 0,
    };
    if let Ok(verdict) = validate_execution_gate(&exec_gate_in) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Execution Quality Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            if verdict.passed {
                "completed"
            } else {
                "warning"
            },
            Some("deterministic"),
        );
    }
    let _ = station_node.route(RoutingCondition::NormalProgression);

    // Station 5: Verify (Independent Replay & Contextual Taint Tracing Juror)
    if let Ok(verdict) = VerifyGate::check_entrance(rep.executed_results.len()) {
        log(
            &mut rep.steps,
            "SoftwareFactory",
            "Verify Entrance Gate",
            &format!(
                "Verdict: {} ({})",
                if verdict.passed { "PASS" } else { "FAIL" },
                verdict.summary
            ),
            "completed",
            Some("deterministic"),
        );
    }
    // 3a. verifier: replay every FAIL independently, so only what reproduces reaches triage. Replays
    // are charged to the run budget; what a replay creates lands on the same ledger as the rest
    // and is torn down below.
    // failures of cases that were flaky in earlier runs get the maximum number of replays
    let raise_k = hints
        .as_ref()
        .map(|h| h.flaky_case_ids(&plan.cases))
        .unwrap_or_default();
    let vopts = VerifyOptions {
        k: verify_k,
        raise_k: &raise_k,
        dry_run: req.dry_run,
        is_spa_target: disc.tech.is_spa,
        credentials: &credentials,
        timeout: request_timeout,
    };
    let verified = {
        let _scope = created.install();
        verify::verify_failures(
            &mut rep.executed_results,
            &plan.cases,
            &req.target,
            &vopts,
            &mut budget,
        )
    };
    {
        let v = &verified.summary;
        let (text, status) = if v.k == 0 {
            (
                "verification is off (READYHAI_VERIFY_K=0): failures were not replayed".to_string(),
                "completed",
            )
        } else if v.candidates == 0 {
            ("no FAIL to verify".to_string(), "completed")
        } else {
            (
                format!(
                    "{} FAIL(s) replayed up to {}x with fresh credentials and the same oracle: {} confirmed, {} flaky, {} not reproduced (now INCONCLUSIVE, not defects), {} unverified; pass^{} {}; {} replay request(s){}",
                    v.candidates,
                    v.k,
                    v.confirmed,
                    v.flaky,
                    v.not_reproduced,
                    v.unverified,
                    v.k,
                    v.pass_k_text(),
                    v.replay_requests,
                    v.stopped
                        .as_ref()
                        .map(|s| format!("; stopped: {s}"))
                        .unwrap_or_default()
                ),
                if v.unverified > 0 || v.stopped.is_some() {
                    "warning"
                } else {
                    "completed"
                },
            )
        };
        log(
            &mut rep.steps,
            "Verifier",
            "Independent Replay",
            &text,
            status,
            Some("deterministic"),
        );
        if v.k > 0 {
            for r in v
                .records
                .iter()
                .filter(|r| r.verdict == super::super::types::VerifyVerdict::NotReproduced)
                .take(10)
            {
                rep.notes.push(format!(
                    "verification: {} {} {} failed on the original run but 0 of {} independent replay(s) reproduced it: reported as INCONCLUSIVE, not a defect",
                    r.case_id, r.method, r.component, r.k
                ));
            }
            for r in v
                .records
                .iter()
                .filter(|r| r.verdict == super::super::types::VerifyVerdict::Unverified)
                .take(10)
            {
                rep.notes.push(format!(
                    "verification: {} {} {} was not verified{}; it stays FAIL",
                    r.case_id,
                    r.method,
                    r.component,
                    r.note
                        .as_ref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                ));
            }
            if let Some(s) = &v.stopped {
                rep.notes.push(format!("verification stopped early: {s}"));
            }
        }
        let raised = v.records.iter().filter(|r| r.k > v.k).count();
        if raised > 0 {
            rep.notes.push(format!(
                "agent memory: {raised} failed case(s) were flaky in earlier runs and were replayed {} times instead of {}",
                super::super::verify::MAX_K,
                v.k
            ));
        }
        if v.replay_requests > 0 && station_node.can_route(&RoutingCondition::ReplayRequired) {
            let _ = station_node.route(RoutingCondition::ReplayRequired);
        }
        rep.stage_sources.insert(
            "verifier".into(),
            if v.k == 0 {
                "off".to_string()
            } else {
                format!("deterministic, k={}", v.k)
            },
        );
    }
    checkpoint(base, rep, &budget, &llm_budget);

    // 3b. cleanup: delete what the run created (nonprod only), confirm it is gone, report what is left
    let mut unidentified = harvest_created(&rep.executed_results, &plan.cases, &created);
    unidentified.extend(verified.unidentified.iter().cloned());
    let nonprod = nonprod_pin.unwrap_or_else(|| target_is_nonprod(&req.target));
    let cleanup = teardown(
        &req.target,
        &created,
        unidentified,
        &credentials,
        nonprod,
        req.dry_run,
        request_timeout,
    );
    if cleanup.created > 0
        || cleanup.skipped.as_deref().is_some_and(|s| {
            !s.starts_with("the run created nothing") && !s.starts_with("dry-run: no state")
        })
    {
        log(
            &mut rep.steps,
            "Cleanup",
            "Teardown",
            &format!(
                "{}{}",
                cleanup.summary(),
                if cleanup.leftovers.is_empty() {
                    String::new()
                } else {
                    format!(
                        ". Left over: {}",
                        cleanup
                            .leftovers
                            .iter()
                            .take(10)
                            .map(|l| format!("{} {} ({})", l.method, l.path, l.reason))
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                }
            ),
            if cleanup.leftovers.is_empty() {
                "completed"
            } else {
                "warning"
            },
            Some("deterministic"),
        );
        if !cleanup.leftovers.is_empty() {
            rep.notes.push(format!(
                "cleanup: {} resource(s) created by this run were NOT removed from {} (see cleanup.json): {}",
                cleanup.leftovers.len(),
                req.target,
                cleanup
                    .leftovers
                    .iter()
                    .take(10)
                    .map(|l| format!("{} {} [{}]", l.method, l.path, l.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        } else {
            rep.notes.push(format!("cleanup: {}", cleanup.summary()));
        }
    }
    rep.stage_sources.insert(
        "cleanup".into(),
        match (&cleanup.skipped, cleanup.created) {
            (Some(_), 0) => "not needed".to_string(),
            (Some(why), _) => format!("skipped: {why}"),
            (None, _) => format!("deleted {} of {}", cleanup.deleted, cleanup.created),
        },
    );
    if cleanup.created > 0 {
        let _ = save_cleanup_in(base, &rep.id, &cleanup);
    }
    // a DELETE that answered 2xx while the resource stayed is a defect, not a clean teardown
    let not_deleted = delete_check_results(&req.target, &cleanup);
    if !not_deleted.is_empty() {
        log(
            &mut rep.steps,
            "Cleanup",
            "Delete Verification",
            &format!(
                "{} resource(s) were still present after a 2xx DELETE (follow-up GET): reported as defects",
                not_deleted.len()
            ),
            "warning",
            Some("deterministic"),
        );
        rep.executed_results.extend(not_deleted);
    }

    // how the changed operations were covered, from the final statuses
    if let (Some(a), Some(ci)) = (change.as_ref(), rep.change_impact.as_mut()) {
        let labels: Vec<String> = a.set.labels().cloned().collect();
        ci.coverage = change::coverage(&labels, &rep.planned_cases, &rep.executed_results);
        let (sent, planned) = change::coverage_totals(&ci.coverage);
        log(
            &mut rep.steps,
            "Planner",
            "Change Impact",
            &format!(
                "{} changed operation(s): {sent} of {planned} planned case(s) sent",
                labels.len()
            ),
            if sent < planned {
                "warning"
            } else {
                "completed"
            },
            Some("deterministic"),
        );
    }

    // 4. triager: deterministic defects, LLM prose only
    log(
        &mut rep.steps,
        "Triager",
        "Root Cause Analysis",
        "Deriving defects from failed assertions",
        "running",
        Some("deterministic"),
    );
    let mut defects = derive_defects_verified(&rep.executed_results, Some(&verified.summary));
    if let Some(wb) = whitebox.as_ref() {
        wb.annotate_defects(&mut defects);
    }
    // Contextual Taint Tracing Juror: false-positive elimination and unified diff remediation
    let juror_llm = llm_cfg.as_ref().filter(|_| !budget.is_cancelled());
    let (audited_defects, juror_audit) = super::super::verify::juror::audit_defects_with_juror(
        juror_llm.map(|c| (c, &mut llm_budget)),
        defects,
        &rep.executed_results,
    );
    if juror_audit.eliminated > 0 {
        rep.notes.push(format!(
            "juror: eliminated {0} candidate defect(s) judged false positives; none of them had              reproduced, so nothing measured was discarded",
            juror_audit.eliminated
        ));
    }
    if juror_audit.disagreed > 0 {
        rep.notes.push(format!(
            "juror: {0} reproduced defect(s) were judged likely false positives by the taint juror.              They are kept — a reproduced failure is a measurement, an opinion is not — and              each carries the disagreement in `juror_opinion`.",
            juror_audit.disagreed
        ));
    }
    if juror_audit.not_evaluated > 0 {
        rep.notes.push(format!(
            "juror: {0} defect(s) were not adjudicated (no matching case result, or insufficient              evidence); they remain as reported",
            juror_audit.not_evaluated
        ));
    }
    // Did the juror actually reach a conclusion about every surviving defect? It can only judge a
    // defect it can tie back to an executed result, and it abstains when the evidence does not
    // support a call. `true` with no defects is honest: there was nothing to trace.
    let juror_covered_all_defects = audited_defects.iter().all(|d| d.juror_evaluated);
    let juror_disagreements = juror_audit.disagreed;
    let mut defects = audited_defects;
    let mut triage_src = "deterministic".to_string();
    if let (Some(cfg), false) = (
        llm_cfg.as_ref().filter(|_| !budget.is_cancelled()),
        defects.is_empty(),
    ) {
        // short prose over defects found already: 2048 tokens and no reasoning, whatever the planner's tier
        let light = cfg.without_thinking();
        match add_llm_notes(&light, &mut llm_budget, &mut defects, &rep.executed_results) {
            Ok(k) if k > 0 => triage_src = "deterministic+llm-notes".into(),
            Ok(_) => rep.notes.push("LLM triage notes: none usable".into()),
            Err(e) => rep.notes.push(format!("LLM triage notes skipped: {e}")),
        }
        take_llm_notes(rep, &mut llm_budget);
    }
    let failed = rep
        .executed_results
        .iter()
        .filter(|r| r.status == "FAIL")
        .count();
    log(
        &mut rep.steps,
        "Triager",
        "Root Cause Analysis",
        &format!(
            "{} defect(s) cover {} failed case(s)",
            defects.len(),
            failed
        ),
        "completed",
        Some(if triage_src == "deterministic" {
            "deterministic"
        } else {
            "llm+deterministic"
        }),
    );
    rep.stage_sources.insert("triage".into(), triage_src);
    rep.triaged_defects = defects;
    // 4a2. record this run's defects into the project's vulnerability database (advisory
    // bookkeeping only — verdicts are already final; a dry-run records nothing)
    {
        let db_note = intel::record_to_vulndb(
            data_root,
            &run_settings,
            &req.target,
            &rep.triaged_defects,
            req.dry_run,
        );
        let note = db_note.unwrap_or_else(|| "vulnerability DB: no update".to_string());
        log(
            &mut rep.steps,
            "Intel",
            "Vulnerability DB Record",
            &note,
            "completed",
            Some("deterministic"),
        );
        rep.notes.push(note);
        if !intel_reproduced.is_empty() {
            rep.notes.push(format!(
                "exploitation: {} of the host's known-open findings reproduced under safe templates (advisory)",
                intel_reproduced.len()
            ));
        }
    }
    // 4b. memory: fold this run into what the agent knew; an unexpired acceptance of a known
    // defect is applied here, so the ledger below does not count it as blocking
    let mut remembered = remember(memory_dir.as_deref(), req, rep, &cleanup, &today);
    // what each area ended as, after verification and triage changed some statuses
    if let Some(a) = rep.agents.as_mut() {
        lead::recount(a, &rep.executed_results, &rep.triaged_defects);
    }
    checkpoint(base, rep, &budget, &llm_budget);

    let verify_gate_in = VerifyGateInput {
        k_replay_executed: verified.summary.k > 0 || verified.summary.candidates == 0,
        juror_taint_evaluated: juror_covered_all_defects,
        juror_disagreements,
        unverified_false_positives: verified.summary.unverified,
    };
    match validate_verify_gate(&verify_gate_in) {
        Ok(verdict) if verdict.passed => log(
            &mut rep.steps,
            "SoftwareFactory",
            "Verify Quality Gate",
            &format!("Verdict: PASS ({})", verdict.summary),
            "completed",
            Some("deterministic"),
        ),
        Ok(verdict) => log(
            &mut rep.steps,
            "SoftwareFactory",
            "Verify Quality Gate",
            &format!("Verdict: FAIL ({})", verdict.summary),
            "warning",
            Some("deterministic"),
        ),
        Err(err) => {
            // A gate that could not even evaluate used to vanish from the log here, which left the
            // report reading as though the station had passed.
            log(
                &mut rep.steps,
                "SoftwareFactory",
                "Verify Quality Gate",
                &format!("Verdict: NOT_EVALUATED ({err})"),
                "warning",
                Some("deterministic"),
            );
        }
    }
    let _ = station_node.route(RoutingCondition::NormalProgression);

    // Station 6: Gate (Evidence Ledger & Software Factory Attestation)
    log(
        &mut rep.steps,
        "ReadinessGate",
        "Evidence Ledger",
        "Computing the technique-coverage matrix, pillars and verdict",
        "running",
        Some("deterministic"),
    );
    let mut led = ledger::compute(&LedgerInput {
        results: &rep.executed_results,
        defects: &rep.triaged_defects,
        dry_run: req.dry_run,
        budget_stop: budget.stopped(),
    });
    ledger::attach_verification(&mut led, verified.summary.clone(), &rep.triaged_defects);
    let mut gate_src = "computed".to_string();
    if let Some(cfg) = llm_cfg.as_ref().filter(|_| !budget.is_cancelled()) {
        match llm_gate(
            cfg,
            &mut llm_budget,
            &req.target,
            &mut led,
            &rep.triaged_defects,
        ) {
            Ok(()) => gate_src = "computed+llm-advisory".into(),
            Err(e) => rep.notes.push(format!("LLM gate advisory skipped: {e}")),
        }
        take_llm_notes(rep, &mut llm_budget);
    }
    log(
        &mut rep.steps,
        "ReadinessGate",
        "Evidence Ledger",
        &format!("Gate verdict {} ({})", led.gate_verdict, led.verdict_basis),
        "completed",
        Some(if gate_src == "computed" {
            "deterministic"
        } else {
            "llm+deterministic"
        }),
    );
    rep.stage_sources.insert("gate".into(), gate_src);
    let gate_verdict = led.gate_verdict.clone();
    rep.evidence_ledger = Some(led);

    let attestation_llm = llm_cfg.as_ref().filter(|_| !budget.is_cancelled());
    let attestation = super::gate::software_factory_attestation(
        attestation_llm.map(|c| (c, &mut llm_budget)),
        rep.evidence_ledger
            .as_ref()
            .expect("evidence ledger present"),
        &rep.triaged_defects,
    );
    log(
        &mut rep.steps,
        "SoftwareFactory",
        "Factory Attestation",
        &format!(
            "Release readiness score: {}, verdict: {}, cases conclusively evaluated: {}",
            match attestation.release_readiness_score {
                Some(score) => format!("{score}/100"),
                None => "not evaluated".to_string(),
            },
            attestation.gate_verdict,
            match attestation.asvs_breakdown.cases_conclusively_evaluated_pct {
                Some(pct) => format!("{pct}%"),
                None => "no applicable coverage data".to_string(),
            }
        ),
        if attestation.gate_verdict == "GO" {
            "completed"
        } else {
            "warning"
        },
        Some("deterministic"),
    );

    // Pillar scores are passed through as they are: `None` means the ledger did not evaluate that
    // pillar, and the gate reports not-evaluated rather than inventing a plausible default. A
    // pillar computed for an unevaluated ledger is not a measurement of readiness either.
    let pillars_measured = super::gate::ledger_evaluated(
        rep.evidence_ledger
            .as_ref()
            .expect("evidence ledger present"),
    );
    let ledger = rep
        .evidence_ledger
        .as_ref()
        .expect("evidence ledger present");
    let pillar = |score: Option<u32>| score.filter(|_| pillars_measured);
    let critical_defects = rep
        .triaged_defects
        .iter()
        .filter(|d| d.severity.eq_ignore_ascii_case("critical"))
        .count();
    let high_defects = rep
        .triaged_defects
        .iter()
        .filter(|d| d.severity.eq_ignore_ascii_case("high"))
        .count();
    let release_gate_in = ReleaseGateInput {
        value_score: pillar(ledger.value_score),
        authority_score: pillar(ledger.authority_score),
        safety_score: pillar(ledger.safety_score),
        evidence_score: pillar(ledger.evidence_score),
        min_threshold: 70,
        no_critical_or_high_findings: critical_defects == 0 && high_defects == 0,
        critical_defects,
        pillar_scores_measured: pillars_measured,
    };
    // The gate verdict is derived from the attestation this run just recorded, so the logged score
    // and integrity digest are the ones stored in `rep.attestation`. A cancelled run tested less
    // than it planned, which the attestation cannot know, so it is passed as a blocking condition.
    let mut blockers: Vec<String> = Vec::new();
    if budget.is_cancelled() {
        blockers.push("run was cancelled before it finished; coverage is incomplete".to_string());
    }
    let verdict = release_gate_verdict_for(&release_gate_in, &attestation, &blockers);
    log(
        &mut rep.steps,
        "SoftwareFactory",
        "Release Quality Gate",
        &format!(
            "Verdict: {} ({})",
            if verdict.passed { "PASS" } else { "FAIL" },
            verdict.summary
        ),
        if verdict.passed {
            "completed"
        } else {
            "warning"
        },
        Some("deterministic"),
    );
    rep.attestation = Some(attestation);
    let _ = station_node.route(RoutingCondition::NormalProgression);
    rep.graph_telemetry = Some(station_node.telemetry().clone());

    budget.sync_llm(&llm_budget);
    rep.budget = Some(budget.usage());
    let cancelled = budget.is_cancelled();
    rep.status = if cancelled {
        "cancelled".into()
    } else {
        "completed".into()
    };
    rep.finished_at = Some(now_iso());
    // a cancelled run did not test everything it planned: it must not mark a defect fixed
    rep.since_last_run = remembered
        .take()
        .map(|r| r.finish(&gate_verdict, !cancelled, memory_notes));
    if let Some(s) = &rep.since_last_run {
        log(
            &mut rep.steps,
            "Memory",
            "Since Last Run",
            &s.summary_line(),
            "completed",
            Some("deterministic"),
        );
        let fresh: Vec<String> = s
            .notes
            .iter()
            .filter(|n| !rep.notes.contains(*n))
            .cloned()
            .collect();
        rep.notes.extend(fresh);
    }
    save_agent_run_in(base, rep)?;
    Ok(())
}
