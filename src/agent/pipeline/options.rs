//! Pipeline options, LLM resolution, and logging helpers.

use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::budget::RunBudget;
use super::super::exec::Credentials;
use super::super::memory;
use super::super::store::{checkpoint_agent_run_in, now_iso};
use super::super::types::*;
use super::super::verify;
use crate::llm::{
    Budget, LatencyReport, LlmConfig, latency_report, probe, probe_latency,
};

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
    /// Independent replays of every FAIL before it becomes a defect (`READYHAI_VERIFY_K`, default 2,
    /// at most 5; 0 turns the verifier off).
    pub verify_k: u32,
    pub request_timeout: Duration,
    /// Resolve the requester's egress IP (contacts public IP echo services unless READYHAI_PUBLIC_IP is set).
    pub lookup_requester_ip: bool,
    /// Area worker threads of the lead (`READYHAI_AGENT_WORKERS`, default 4, at most 8; 1 runs the
    /// areas one after another with the same results).
    pub workers: usize,
    /// Where the agent remembers its targets (`<data_dir>/memory`; None = no memory: the run plans
    /// from the profile alone and writes nothing). `READYHAI_AGENT_MEMORY=off` turns it off.
    pub memory_dir: Option<PathBuf>,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            budget: RunBudget::from_env(),
            credentials: Credentials::from_env(),
            llm: LlmMode::Env,
            reruns: 2,
            verify_k: verify::k_from_env(),
            request_timeout: Duration::from_secs(10),
            lookup_requester_ip: true,
            workers: super::super::lead::workers_from_env(),
            memory_dir: memory::default_dir(),
        }
    }
}

impl RunOptions {
    /// What `readyhai agent --max-steps N` should call.
    pub fn with_max_steps(mut self, n: usize) -> Self {
        self.budget = self.budget.with_max_steps(n);
        self
    }

    pub fn with_workers(mut self, n: usize) -> Self {
        self.workers = n.clamp(1, super::super::lead::MAX_WORKERS);
        self
    }

    /// Keep the target's memory in `dir` (None: no memory).
    pub fn with_memory_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.memory_dir = dir;
        self
    }
}

pub(crate) fn log(
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

pub(crate) fn require_http(target: &str) -> Result<()> {
    match reqwest::Url::parse(target) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => Ok(()),
        _ => bail!(
            "target must be an http(s) URL (the agent probes over HTTP only), got '{}'",
            target.chars().take(80).collect::<String>()
        ),
    }
}

/// Resolve the LLM once per run. Err(reason) is logged and the run continues deterministically.
pub(crate) fn resolve_llm(mode: &LlmMode) -> std::result::Result<LlmConfig, String> {
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

/// The LLM's answer to a real 1-token completion (`/models` answering only says the server is up).
/// Its words go into `llm_status`, e.g. "connected: vllm/m (latency 840 ms)".
pub(crate) fn measure_llm(c: &LlmConfig) -> LatencyReport {
    latency_report(&probe_latency(c))
}

/// A slow endpoint (answers in more than 10 s, or not at all in time) cannot serve long reasoning
/// calls: hold the planner at the High tier (8192 tokens) and say so in the run notes.
pub(crate) fn cap_if_slow(c: &mut LlmConfig, latency: &LatencyReport, notes: &mut Vec<String>) {
    if !latency.slow {
        return;
    }
    let mut note = format!("LLM endpoint is slow ({})", latency.summary);
    if let Some(capped) = c.capped_to_high_tier() {
        note.push_str(&format!(
            "; planner thinking is capped at the High tier ({} tokens) instead of tier '{}' ({} tokens) so its calls fit the timeout",
            capped.thinking_budget_tokens, c.model_tier, c.thinking_budget_tokens
        ));
        *c = capped;
    }
    notes.push(note);
}

/// Move what the LLM layer noted (a call that timed out and was retried smaller, ...) into the run's notes.
pub(crate) fn take_llm_notes(rep: &mut AgentRunReport, llm: &mut Budget) {
    for n in llm.notes.drain(..) {
        if !rep.notes.contains(&n) {
            rep.notes.push(n);
        }
    }
}

pub(crate) fn ip_fields(
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

pub(crate) fn blank_report(run_id: &str, target: &str, profile: &str, dry_run: bool) -> AgentRunReport {
    AgentRunReport {
        id: run_id.to_string(),
        target: target.to_string(),
        profile: profile.to_string(),
        model: "none".into(),
        provider: "deterministic".into(),
        started_at: now_iso(),
        finished_at: None,
        status: "running".into(),
        steps: vec![],
        discovered_routes: vec![],
        planned_cases: vec![],
        executed_results: vec![],
        triaged_defects: vec![],
        evidence_ledger: None,
        approval_status: Some("pending".into()),
        approved_by: None,
        approval_notes: None,
        approved_at: None,
        error: None,
        thinking: false,
        model_tier: default_model_tier(),
        thinking_budget_tokens: 0,
        app_architecture: None,
        framework: None,
        detected_tech: vec![],
        requester_ip: None,
        requester_ip_type: None,
        allowlist_guidance: None,
        dry_run,
        stage_sources: BTreeMap::new(),
        llm_status: None,
        budget: None,
        notes: vec![],
        change_impact: None,
        agents: None,
        since_last_run: None,
    }
}

/// Persist the run as it stands (status `running`). A failed checkpoint never fails the run.
pub(crate) fn checkpoint(base: &Path, rep: &mut AgentRunReport, budget: &RunBudget, llm: &Budget) {
    let mut usage = budget.usage();
    usage.llm_calls = llm.calls;
    usage.llm_ms = llm.elapsed_ms();
    rep.budget = Some(usage);
    if let Err(e) = checkpoint_agent_run_in(base, rep) {
        eprintln!("readyhai agent: checkpoint of run {} failed: {e}", rep.id);
    }
}

pub(crate) fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    let s = p
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into());
    format!("agent run panicked: {s}")
}
