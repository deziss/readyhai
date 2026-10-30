//! The agent loop: Discovery -> Planner -> Explorer -> Triager -> Readiness gate -> save.
//! Deterministic code decides every verdict; the LLM (when configured AND reachable) adds extra
//! planned cases, prose notes and an advisory opinion, and every stage records which one produced it.
use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use super::budget::RunBudget;
use super::discover::discover;
use super::exec::{Credentials, ExecOptions, execute_cases_with};
use super::ledger::{self, LedgerInput};
use super::plan::plan_cases;
use super::store::{agent_runs_dir, now_iso, save_agent_run_in};
use super::triage::{add_llm_notes, derive_defects};
use super::types::*;
use crate::llm::untrusted::{self, clean_output, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed, probe};

/// How the run decides whether to use an LLM.
#[derive(Debug, Clone, Default)]
pub enum LlmMode {
    /// READYHAI_LLM_* environment, probed once; unreachable => deterministic.
    #[default]
    Env,
    /// Deterministic only.
    Off,
    /// An explicit config (probed once as well).
    Use(Box<LlmConfig>),
}

/// Everything a run needs beyond the request itself.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub budget: RunBudget,
    /// Test credentials per role (default: RH_<ROLE>_TOKEN environment variables).
    pub credentials: Credentials,
    pub llm: LlmMode,
    /// Re-runs of a failing case to detect flakiness.
    pub reruns: u32,
    pub request_timeout: Duration,
    /// Resolve the requester's egress IP (contacts public IP echo services unless READYHAI_PUBLIC_IP is set).
    pub lookup_requester_ip: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            budget: RunBudget::from_env(),
            credentials: Credentials::from_env(),
            llm: LlmMode::Env,
            reruns: 2,
            request_timeout: Duration::from_secs(10),
            lookup_requester_ip: true,
        }
    }
}

impl RunOptions {
    /// What `readyhai agent --max-steps N` should call.
    pub fn with_max_steps(mut self, n: usize) -> Self {
        self.budget = self.budget.with_max_steps(n);
        self
    }
}

fn log(
    steps: &mut Vec<AgentStepLog>,
    agent: &str,
    action: &str,
    details: &str,
    status: &str,
    source: Option<&str>,
) {
    steps.push(AgentStepLog {
        timestamp: now_iso(),
        agent: agent.into(),
        action: action.into(),
        details: details.into(),
        status: status.into(),
        source: source.map(String::from),
    });
}

fn require_http(target: &str) -> Result<()> {
    match reqwest::Url::parse(target) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => Ok(()),
        _ => bail!(
            "target must be an http(s) URL (the agent probes over HTTP only), got '{}'",
            target.chars().take(80).collect::<String>()
        ),
    }
}

/// Resolve the LLM once per run. Err(reason) is logged and the run continues deterministically.
fn resolve_llm(mode: &LlmMode) -> std::result::Result<LlmConfig, String> {
    match mode {
        LlmMode::Off => Err("disabled for this run".into()),
        LlmMode::Env => LlmConfig::connect_from_env(),
        LlmMode::Use(c) => {
            if probe(c) {
                Ok((**c).clone())
            } else {
                Err(format!("LLM {} unreachable", c.describe()))
            }
        }
    }
}

// ---------------------------------------------------------------- gate prose (advisory)

const GATE_ROLE: &str = "You are a production-readiness reviewer. You receive facts that deterministic code computed from real HTTP test results. \
Write a short summary for a release manager and give an advisory opinion. Your opinion cannot raise the verdict; it can only be stricter. \
Format: {\"executive_summary\": string, \"gate_verdict\": \"GO\"|\"CONDITIONAL_GO\"|\"NO_GO\", \"overall_readiness\": int, \"value_score\": int, \"authority_score\": int, \"safety_score\": int, \"evidence_score\": int}";

#[derive(Debug, Deserialize)]
struct GateOut {
    #[serde(default)]
    executive_summary: Option<String>,
    #[serde(default)]
    gate_verdict: Option<String>,
    #[serde(default)]
    overall_readiness: Option<i64>,
    #[serde(default)]
    value_score: Option<i64>,
    #[serde(default)]
    authority_score: Option<i64>,
    #[serde(default)]
    safety_score: Option<i64>,
    #[serde(default)]
    evidence_score: Option<i64>,
}

fn llm_gate(
    cfg: &LlmConfig,
    budget: &mut Budget,
    target: &str,
    l: &mut EvidenceLedger,
    defects: &[TriagedDefect],
) -> Result<()> {
    let facts = json!({
        "target": target, "computed_verdict": l.computed_verdict, "overall_readiness": l.overall_readiness, "verdict_basis": l.verdict_basis,
        "pillars": l.pillars.iter().map(|p| json!({"id": p.id, "score": p.score, "status": p.status, "claim": p.claim})).collect::<Vec<_>>(),
        "defects": defects.iter().take(20).map(|d| json!({"id": d.id, "severity": d.severity, "title": d.title, "component": d.component})).collect::<Vec<_>>(),
    });
    let prompt = format!(
        "Computed readiness facts:\n{}\nWrite the summary and your advisory opinion.",
        fence_capped(&facts, 240)
    );
    let out: GateOut = ask_typed(
        cfg,
        budget,
        &untrusted::system(GATE_ROLE),
        &prompt,
        |o: &GateOut| {
            if let Some(v) = o.gate_verdict.as_deref()
                && !matches!(v, "GO" | "CONDITIONAL_GO" | "NO_GO")
            {
                bail!(
                    "gate_verdict '{}' is not one of GO, CONDITIONAL_GO, NO_GO",
                    v.chars().take(20).collect::<String>()
                );
            }
            if o.gate_verdict.is_none()
                && o.executive_summary
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
            {
                bail!("neither a verdict nor a summary");
            }
            Ok(())
        },
    )?;
    let summary = out
        .executive_summary
        .as_deref()
        .map(|s| clean_output(s, 900))
        .filter(|s| !s.is_empty());
    ledger::apply_llm(
        l,
        out.gate_verdict.as_deref(),
        [
            out.overall_readiness,
            out.value_score,
            out.authority_score,
            out.safety_score,
            out.evidence_score,
        ],
        summary,
    );
    Ok(())
}

// ---------------------------------------------------------------- run

pub fn run_agentic_loop(req: &AgentRunRequest, run_id: &str) -> Result<AgentRunReport> {
    run_agentic_loop_with(req, run_id, RunOptions::default())
}

pub fn run_agentic_loop_with(
    req: &AgentRunRequest,
    run_id: &str,
    opts: RunOptions,
) -> Result<AgentRunReport> {
    run_in(&agent_runs_dir(), req, run_id, opts)
}

fn ip_fields(
    lookup: bool,
    steps: &mut Vec<AgentStepLog>,
) -> (Option<String>, Option<String>, Option<String>) {
    if !lookup {
        return (None, None, None);
    }
    let ip = crate::network::detect_requester_public_ip();
    log(
        steps,
        "Supervisor",
        "Requester Egress IP Check",
        &format!(
            "Requester outbound IP: {} ({}); {}",
            ip.egress_public_ip, ip.ip_type, ip.allowlist_guidance
        ),
        "completed",
        Some("deterministic"),
    );
    (
        Some(ip.egress_public_ip),
        Some(ip.ip_type),
        Some(ip.allowlist_guidance),
    )
}

pub(crate) fn run_in(
    base: &Path,
    req: &AgentRunRequest,
    run_id: &str,
    opts: RunOptions,
) -> Result<AgentRunReport> {
    if !crate::engine::valid_run_id(run_id) {
        bail!("invalid run id");
    }
    require_http(&req.target)?;
    let started_at = now_iso();
    let mut steps = vec![];
    let mut notes: Vec<String> = vec![];
    let mut stages: BTreeMap<String, String> = BTreeMap::new();
    let RunOptions {
        mut budget,
        credentials,
        llm,
        reruns,
        request_timeout,
        lookup_requester_ip,
    } = opts;

    log(
        &mut steps,
        "Supervisor",
        "Session Init",
        &format!(
            "Autonomous session for {}{}",
            req.target,
            if req.dry_run {
                " (dry-run: no state-changing requests)"
            } else {
                ""
            }
        ),
        "running",
        None,
    );
    let (requester_ip, requester_ip_type, allowlist_guidance) =
        ip_fields(lookup_requester_ip, &mut steps);
    if req.thinking {
        notes.push(format!("thinking/model_tier/thinking_budget_tokens ({}, {}) are recorded but not forwarded to the provider: every LLM step is a single-shot JSON call", req.model_tier, req.thinking_budget_tokens));
    }

    // LLM: resolved and probed once; every LLM step is skipped when it is not reachable
    let (llm_cfg, llm_status) = match resolve_llm(&llm) {
        Ok(c) => {
            log(
                &mut steps,
                "Supervisor",
                "Model Connectivity",
                &format!("Connected to {}", c.describe()),
                "completed",
                Some("llm"),
            );
            let s = format!("connected: {}", c.describe());
            (Some(c), s)
        }
        Err(why) => {
            log(
                &mut steps,
                "Supervisor",
                "Model Connectivity",
                &format!("{why}; every LLM step is skipped and the deterministic path is used"),
                "warning",
                Some("deterministic"),
            );
            (None, format!("unavailable: {why}"))
        }
    };
    let mut llm_budget = Budget::per_run();

    // 1. discovery
    log(
        &mut steps,
        "Discovery",
        "Route Inspection",
        "Fingerprinting the target, crawling same-host links, loading the OpenAPI spec when available",
        "running",
        Some("deterministic"),
    );
    let disc = discover(&req.target, req.spec_url.as_deref(), 20, &mut budget);
    log(
        &mut steps,
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
        notes.push("no routes were discovered (target unreachable or empty); only root and sensitive-file probes are planned".into());
    }
    notes.extend(disc.notes.iter().cloned());
    stages.insert("discovery".into(), "deterministic".into());

    // 2. planner
    log(
        &mut steps,
        "Planner",
        "Test Synthesis",
        "Building the deterministic plan (and asking the LLM for extra cases when available)",
        "running",
        None,
    );
    let plan = plan_cases(
        llm_cfg.as_ref().map(|c| (c, &mut llm_budget)),
        &req.target,
        &req.profile,
        &disc,
        req.custom_instructions.as_deref(),
        &credentials,
    );
    log(
        &mut steps,
        "Planner",
        "Test Synthesis",
        &format!(
            "{} planned case(s) ({}), {} from the LLM",
            plan.cases.len(),
            plan.source,
            plan.llm_cases
        ),
        "completed",
        Some(if plan.llm_cases > 0 {
            "llm+deterministic"
        } else {
            "deterministic"
        }),
    );
    notes.extend(plan.notes.iter().cloned());
    stages.insert("planner".into(), plan.source.clone());

    // 3. explorer
    log(
        &mut steps,
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
    let executed = execute_cases_with(&plan.cases, &req.target, &exec_opts, &mut budget);
    let n = |s: &str| executed.iter().filter(|r| r.status == s).count();
    log(
        &mut steps,
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
            &mut steps,
            "Explorer",
            "Budget",
            stop,
            "warning",
            Some("deterministic"),
        );
        notes.push(format!("run budget: {stop}"));
    }
    let roles_missing: Vec<String> = {
        let mut r: Vec<String> = plan
            .cases
            .iter()
            .filter_map(|c| match super::exec::auth_for(c) {
                super::exec::Auth::Role(r) if !credentials.has_role(&r) => Some(r),
                _ => None,
            })
            .collect();
        r.sort();
        r.dedup();
        r
    };
    for r in roles_missing {
        notes.push(format!("no credential for role '{r}': requests for it were sent without Authorization (set {})", Credentials::env_var(&r)));
    }

    // 4. triager: deterministic defects, LLM prose only
    log(
        &mut steps,
        "Triager",
        "Root Cause Analysis",
        "Deriving defects from failed assertions",
        "running",
        Some("deterministic"),
    );
    let mut defects = derive_defects(&executed);
    let mut triage_src = "deterministic".to_string();
    if let (Some(cfg), false) = (llm_cfg.as_ref(), defects.is_empty()) {
        match add_llm_notes(cfg, &mut llm_budget, &mut defects, &executed) {
            Ok(k) if k > 0 => triage_src = "deterministic+llm-notes".into(),
            Ok(_) => notes.push("LLM triage notes: none usable".into()),
            Err(e) => notes.push(format!("LLM triage notes skipped: {e}")),
        }
    }
    log(
        &mut steps,
        "Triager",
        "Root Cause Analysis",
        &format!(
            "{} defect(s) cover {} failed case(s)",
            defects.len(),
            n("FAIL")
        ),
        "completed",
        Some(if triage_src == "deterministic" {
            "deterministic"
        } else {
            "llm+deterministic"
        }),
    );
    stages.insert("triage".into(), triage_src);

    // 5. readiness gate: computed first, LLM can only make it stricter
    log(
        &mut steps,
        "ReadinessGate",
        "Evidence Ledger",
        "Computing the technique-coverage matrix, pillars and verdict",
        "running",
        Some("deterministic"),
    );
    let mut led = ledger::compute(&LedgerInput {
        results: &executed,
        defects: &defects,
        dry_run: req.dry_run,
        budget_stop: budget.stopped(),
    });
    let mut gate_src = "computed".to_string();
    if let Some(cfg) = llm_cfg.as_ref() {
        match llm_gate(cfg, &mut llm_budget, &req.target, &mut led, &defects) {
            Ok(()) => gate_src = "computed+llm-advisory".into(),
            Err(e) => notes.push(format!("LLM gate advisory skipped: {e}")),
        }
    }
    log(
        &mut steps,
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
    stages.insert("gate".into(), gate_src);

    let report = AgentRunReport {
        id: run_id.to_string(),
        target: req.target.clone(),
        profile: req.profile.clone(),
        model: llm_cfg
            .as_ref()
            .map(|c| c.model.clone())
            .unwrap_or_else(|| "none".into()),
        provider: llm_cfg
            .as_ref()
            .map(|c| c.provider.id.to_string())
            .unwrap_or_else(|| "deterministic".into()),
        started_at,
        finished_at: Some(now_iso()),
        status: "completed".into(),
        steps,
        discovered_routes: disc.routes,
        planned_cases: plan.cases,
        executed_results: executed,
        triaged_defects: defects,
        evidence_ledger: Some(led),
        approval_status: Some("pending".into()),
        approved_by: None,
        approval_notes: None,
        approved_at: None,
        error: None,
        thinking: req.thinking,
        model_tier: req.model_tier.clone(),
        thinking_budget_tokens: req.thinking_budget_tokens,
        app_architecture: Some(disc.tech.app_architecture),
        framework: Some(disc.tech.primary_framework),
        detected_tech: disc.tech.detected_signals,
        requester_ip,
        requester_ip_type,
        allowlist_guidance,
        dry_run: req.dry_run,
        stage_sources: stages,
        llm_status: Some(llm_status),
        budget: Some(budget.usage()),
        notes,
    };
    save_agent_run_in(base, &report)?;
    Ok(report)
}

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
    opts: RunOptions,
    run_id: &str,
) -> Result<AgentRunReport> {
    require_http(target)?;
    let started_at = now_iso();
    let mut steps = vec![];
    let mut notes = vec![];
    let mut stages = BTreeMap::new();
    let RunOptions {
        mut budget,
        credentials,
        llm,
        lookup_requester_ip,
        ..
    } = opts;
    log(
        &mut steps,
        "Supervisor",
        "Session Init",
        &format!("URL discovery and attack-surface scan for {target}"),
        "running",
        None,
    );
    let (requester_ip, requester_ip_type, allowlist_guidance) =
        ip_fields(lookup_requester_ip, &mut steps);
    let (llm_cfg, llm_status) = match resolve_llm(&llm) {
        Ok(c) => {
            log(
                &mut steps,
                "Supervisor",
                "Model Connectivity",
                &format!("Connected to {}", c.describe()),
                "completed",
                Some("llm"),
            );
            let s = format!("connected: {}", c.describe());
            (Some(c), s)
        }
        Err(why) => {
            log(
                &mut steps,
                "Supervisor",
                "Model Connectivity",
                &format!("{why}; deterministic planning"),
                "warning",
                Some("deterministic"),
            );
            (None, format!("unavailable: {why}"))
        }
    };
    let mut llm_budget = Budget::per_run();
    let disc = discover(target, spec_url, 20, &mut budget);
    log(
        &mut steps,
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
    notes.extend(disc.notes.iter().cloned());
    let plan = plan_cases(
        llm_cfg.as_ref().map(|c| (c, &mut llm_budget)),
        target,
        "discovery-scan",
        &disc,
        None,
        &credentials,
    );
    log(
        &mut steps,
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
    notes.extend(plan.notes.iter().cloned());
    stages.insert("discovery".into(), "deterministic".into());
    stages.insert("planner".into(), plan.source.clone());

    let checklist = vec![
        ExitCheckItem {
            criterion: "Attack surface discovered".into(),
            met: !disc.routes.is_empty(),
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
            details: format!("{} planned scenario(s)", plan.cases.len()),
            case_ids: plan.cases.iter().map(|c| c.id.clone()).collect(),
            evidence_files: vec![],
        },
    ];
    let led = ledger::not_evaluated(
        "SCANNED",
        format!(
            "Discovery only: {} route(s) found, {} scenario(s) planned. No test was executed, so nothing is scored.",
            disc.routes.len(),
            plan.cases.len()
        ),
        checklist,
    );
    let report = AgentRunReport {
        id: run_id.to_string(),
        target: target.to_string(),
        profile: "discovery-scan".into(),
        model: llm_cfg
            .as_ref()
            .map(|c| c.model.clone())
            .unwrap_or_else(|| "none".into()),
        provider: llm_cfg
            .as_ref()
            .map(|c| c.provider.id.to_string())
            .unwrap_or_else(|| "deterministic".into()),
        started_at,
        finished_at: Some(now_iso()),
        status: "completed".into(),
        steps,
        discovered_routes: disc.routes,
        planned_cases: plan.cases,
        executed_results: vec![],
        triaged_defects: vec![],
        evidence_ledger: Some(led),
        approval_status: Some("scanned".into()),
        approved_by: None,
        approval_notes: None,
        approved_at: None,
        error: None,
        thinking: false,
        model_tier: default_model_tier(),
        thinking_budget_tokens: 0,
        app_architecture: Some(disc.tech.app_architecture),
        framework: Some(disc.tech.primary_framework),
        detected_tech: disc.tech.detected_signals,
        requester_ip,
        requester_ip_type,
        allowlist_guidance,
        dry_run: false,
        stage_sources: stages,
        llm_status: Some(llm_status),
        budget: Some(budget.usage()),
        notes,
    };
    save_agent_run_in(base, &report)?;
    Ok(report)
}
