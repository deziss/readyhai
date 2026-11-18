//! Agent run requests, reports, summaries, evidence ledgers, and defect models.

use serde::{Deserialize, Serialize};

use super::change::ChangeImpact;
use super::defaults::{
    default_model_tier, default_profile, default_reasoning_tokens, default_true,
};
use super::discovery::{Blocker, DiscoveredRoute};
use super::execution::CaseExecutionResult;
use super::planning::PlannedCase;
use super::verification::VerificationSummary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunRequest {
    pub target: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default)]
    pub spec_url: Option<String>,
    #[serde(default, alias = "directives")]
    pub custom_instructions: Option<String>,
    /// Optional cap on exploration steps (the server clamps it to 1..=50).
    #[serde(default)]
    pub max_steps: Option<usize>,
    /// Never send state-changing methods (POST/PUT/PATCH/DELETE); such cases are recorded as SKIPPED.
    #[serde(default)]
    pub dry_run: bool,
    /// Ask the provider for extended reasoning. What is actually sent depends on the transport
    /// (see `LlmConfig::thinking_summary`); the run log says which. Structured planning, triage and
    /// verdict calls always use a low temperature.
    #[serde(default = "default_true")]
    pub thinking: bool,
    #[serde(default = "default_model_tier")]
    pub model_tier: String,
    /// Clamped to `llm::MIN_THINKING_BUDGET..=llm::MAX_THINKING_BUDGET` before it is used.
    #[serde(default = "default_reasoning_tokens")]
    pub thinking_budget_tokens: u32,
    /// Local checkout of the service under test. With `diff_base` the run plans around what the
    /// code changed (see `agent::change`); REST and MCP confine it to READYHAI_ALLOWED_ROOTS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Git ref the change is measured from (`git diff <diff_base>...HEAD` inside `repo`), e.g.
    /// `origin/main`. Without it `repo` is ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_base: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TriagedDefect {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub priority: String,
    pub component: String,
    pub root_cause_hypothesis: String,
    pub blast_radius: String, // isolated | service | platform
    pub owasp_category: String,
    pub recommended_fix: String,
    pub reproduction: String,
    /// Every FAIL case maps to exactly one defect through this list.
    #[serde(default)]
    pub case_ids: Vec<String>,
    #[serde(default)]
    pub evidence_files: Vec<String>,
    /// Advisory LLM prose. Never used for severity, priority or the gate.
    #[serde(default)]
    pub ai_note: Option<String>,
    #[serde(default)]
    pub remediation_patch: Option<String>,
    #[serde(default)]
    pub remediation_explanation: Option<String>,
    #[serde(default)]
    pub reproduction_script: Option<String>,
    /// White-box source location / call chain discovered via AST analysis (when `--repo` is supplied).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_context: Option<String>,
    /// The independent verifier replayed the failure and it reproduced on every replay.
    #[serde(default)]
    pub verified: bool,
    /// Replays that reproduced the failure out of the replays run: "2/2" (confirmed) or "1/2" (flaky).
    #[serde(default)]
    pub reproduced: Option<String>,
    /// confirmed | flaky | unverified. None = the verifier did not run for this defect (older run,
    /// verification disabled, or a defect that was not derived from a replayable case).
    #[serde(default)]
    pub verification: Option<String>,
    /// The failure did not reproduce on every attempt.
    #[serde(default)]
    pub flaky: bool,
    /// The failing check that defines the defect (`authz`, `server_error`, ...): the first half of
    /// its identity.
    #[serde(default)]
    pub rule: String,
    /// Stable identity across runs: `sha256(rule, endpoint template)`, 24 hex characters. The
    /// same fingerprint in the next run is the same defect (see `memory`).
    #[serde(default)]
    pub fingerprint: String,
    /// An unexpired acceptance (`readyhai agent-memory accept`) covers this defect: it is listed
    /// but does not block the gate, and its failing cases are not scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<crate::agent::memory::Acceptance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitCheckItem {
    pub criterion: String,
    pub met: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub details: String,
    #[serde(default)]
    pub case_ids: Vec<String>,
    #[serde(default)]
    pub evidence_files: Vec<String>,
}

/// One row of the technique-coverage matrix.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageCell {
    pub technique: String,
    pub planned: usize,
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub inconclusive: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub flaky: usize,
    #[serde(default)]
    pub not_applicable: usize,
    pub case_ids: Vec<String>,
    pub evidence_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PillarResult {
    /// value | authority | safety | evidence
    pub id: String,
    pub name: String,
    /// None = not evaluated
    pub score: Option<u32>,
    pub status: String, // pass | fail | partial | not_evaluated
    pub claim: String,
    /// Conclusive (pass+warn+fail) share of the applicable cases, 0..=100. None: nothing applicable.
    #[serde(default)]
    pub confidence: Option<u32>,
    pub techniques: Vec<String>,
    pub case_ids: Vec<String>,
    pub evidence_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerClaim {
    pub claim: String,
    pub status: String, // pass | fail | partial | not_evaluated
    pub case_ids: Vec<String>,
    pub evidence_files: Vec<String>,
}

/// What the LLM said about the gate. Advisory only: it is stored beside the ledger, its scores are
/// clamped to 0..=100, and neither its verdict nor its scores ever change `gate_verdict`, `verdict`
/// or any computed score.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmAdvisory {
    pub verdict: Option<String>,
    pub overall_readiness: Option<u32>,
    pub value_score: Option<u32>,
    pub authority_score: Option<u32>,
    pub safety_score: Option<u32>,
    pub evidence_score: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceLedger {
    /// None = not evaluated (no conclusive case covered the pillar). Never a constant.
    #[serde(default)]
    pub value_score: Option<u32>,
    #[serde(default)]
    pub authority_score: Option<u32>,
    #[serde(default)]
    pub safety_score: Option<u32>,
    #[serde(default)]
    pub evidence_score: Option<u32>,
    /// Weighted over the evaluated pillars; 0 when nothing was evaluated (see `evaluated`).
    pub overall_readiness: u32,
    /// GO | CONDITIONAL_GO | NO_GO | NOT_EVALUATED (| SCANNED for discovery-only runs)
    pub gate_verdict: String,
    pub executive_summary: String,
    pub exit_criteria_checklist: Vec<ExitCheckItem>,
    #[serde(default)]
    pub composite_score: Option<u32>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub evaluated: bool,
    /// Verdict from the deterministic rules alone.
    #[serde(default)]
    pub computed_verdict: String,
    /// How `gate_verdict` was derived: the computed verdict, plus a note on how the LLM advisory compared (it changes nothing).
    #[serde(default)]
    pub verdict_basis: String,
    #[serde(default)]
    pub pillars: Vec<PillarResult>,
    #[serde(default)]
    pub coverage: Vec<CoverageCell>,
    #[serde(default)]
    pub claims: Vec<LedgerClaim>,
    #[serde(default)]
    pub llm_advisory: Option<LlmAdvisory>,
    /// LLM executive prose (advisory). `executive_summary` is generated from the facts.
    #[serde(default)]
    pub ai_summary: Option<String>,
    /// What the independent verifier did with the failed cases (None: older run / not attached).
    #[serde(default)]
    pub verification: Option<VerificationSummary>,
    /// Conclusive share of the applicable cases over the whole run, 0..=100.
    #[serde(default)]
    pub confidence: Option<u32>,
    /// What kept evidence from being gathered (auth wall, no API surface, LLM down, ...) and the
    /// next step for each. Drives NOT_EVALUATED explanations in the report and UI.
    #[serde(default)]
    pub blockers: Vec<Blocker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStepLog {
    pub timestamp: String,
    pub agent: String, // Supervisor | Discovery | Planner | Explorer | Triager | ReadinessGate
    pub action: String,
    pub details: String,
    pub status: String, // running | completed | warning | error
    /// llm | deterministic | llm+deterministic
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunReport {
    pub id: String,
    pub target: String,
    pub profile: String,
    /// The model actually used, or "none" when every stage ran deterministically.
    pub model: String,
    /// The provider actually used, or "deterministic".
    pub provider: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    /// running (checkpoint) | completed | failed | cancelled
    pub status: String,
    pub steps: Vec<AgentStepLog>,
    #[serde(default)]
    pub discovered_routes: Vec<DiscoveredRoute>,
    pub planned_cases: Vec<PlannedCase>,
    pub executed_results: Vec<CaseExecutionResult>,
    pub triaged_defects: Vec<TriagedDefect>,
    pub evidence_ledger: Option<EvidenceLedger>,
    pub approval_status: Option<String>, // pending | approved | rejected
    pub approved_by: Option<String>,
    pub approval_notes: Option<String>,
    pub approved_at: Option<String>,
    pub error: Option<String>,
    #[serde(default = "default_true")]
    pub thinking: bool,
    #[serde(default = "default_model_tier")]
    pub model_tier: String,
    #[serde(default = "default_reasoning_tokens")]
    pub thinking_budget_tokens: u32,
    #[serde(default)]
    pub app_architecture: Option<String>,
    #[serde(default)]
    pub framework: Option<String>,
    #[serde(default)]
    pub detected_tech: Vec<String>,
    #[serde(default)]
    pub requester_ip: Option<String>,
    #[serde(default)]
    pub requester_ip_type: Option<String>,
    #[serde(default)]
    pub allowlist_guidance: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    /// Which stages used the LLM: {"planner": "deterministic", "triage": "llm", ...}
    #[serde(default)]
    pub stage_sources: std::collections::BTreeMap<String, String>,
    /// Why the LLM was (not) used, e.g. "used vllm/qwen..." or "unavailable: ...".
    #[serde(default)]
    pub llm_status: Option<String>,
    #[serde(default)]
    pub budget: Option<crate::agent::budget::BudgetUsage>,
    #[serde(default)]
    pub notes: Vec<String>,
    /// What the code diff changed and how the run covered it (None: not a change-aware run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_impact: Option<ChangeImpact>,
    /// What the lead and its area workers did (None: a run from before the lead existed, or a
    /// discovery-only run). Updated while the run is `running`, so a status poll sees the progress
    /// of every area.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<AgentsReport>,
    /// Dynamic directives synthesized during reconnaissance and passed to planning and execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directives: Option<crate::agent::recon::SynthesizedDirectives>,
    /// Software factory attestation for release readiness and OWASP ASVS compliance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<SoftwareFactoryAttestation>,
    /// Execution graph telemetry and state transitions across the 6 software factory stations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_telemetry: Option<crate::agent::pipeline::graph::GraphTelemetry>,
    /// What changed since the previous run against this target, from the agent's memory (None:
    /// memory is off, or the run is from before it existed). Deterministic; never changes a verdict
    /// by itself (only an explicit, unexpired acceptance does).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_last_run: Option<crate::agent::memory::SinceLastRun>,
}

// ---------------------------------------------------------------- the lead and its area workers

/// What an area (or the pool) was given, or used: the four things a run budget limits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    pub steps: usize,
    pub requests: usize,
    pub wall_ms: u64,
    pub llm_calls: usize,
}

/// Allocated against used, for one wave of one area.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AreaBudget {
    pub allocated: Quota,
    pub used: Quota,
}

/// A case the lead added in wave 2, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveTwoCase {
    pub case_id: String,
    pub area: String,
    /// `auth-to-contract` | `inconclusive-reprobe` | `budget-resume`
    pub rule: String,
    /// The case (or result) that triggered it.
    pub origin: String,
    pub reason: String,
}

/// One area worker's part of the run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AreaReport {
    pub area: String,
    /// idle (no case) | pending | running | done | cancelled | failed
    pub status: String,
    /// Cases handed to the worker in wave 1 (what the planner tagged with this area).
    pub cases: usize,
    pub case_ids: Vec<String>,
    /// Final statuses of this area's results (wave 1, its sub-cases and the wave-2 additions).
    pub executed: usize,
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub inconclusive: usize,
    pub blocked: usize,
    pub skipped: usize,
    /// Triaged defects that contain a failed case of this area.
    pub defect_ids: Vec<String>,
    pub budget: AreaBudget,
    /// The wave-2 slice, when the area got one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wave2_budget: Option<AreaBudget>,
    /// Ids of the cases wave 2 added to this area (new follow-up cases only).
    #[serde(default)]
    pub wave2_added: Vec<String>,
    /// Why the worker stopped before it ran everything (a limit, a cancellation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The lead's account of a run: how the plan was split, what each area was allowed and used, what
/// wave 2 added, and where the leftover budget went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentsReport {
    /// Worker threads (`READYHAI_AGENT_WORKERS`; 1 = the areas ran one after another).
    pub workers: usize,
    /// running | done | cancelled
    pub status: String,
    /// 1 or 2 (wave 2 ran).
    pub waves: u32,
    pub areas: Vec<AreaReport>,
    /// Not handed to any area in wave 1: the lead's reserve.
    pub pool_reserve: Quota,
    /// Handed to an area and given back unused when its wave ended.
    pub pool_reclaimed: Quota,
    /// What wave 2 was allowed to spend (from the reserve and the reclaimed budget).
    pub pool_granted_wave2: Quota,
    /// What the run had left after the last wave.
    pub pool_left: Quota,
    pub wave2: Vec<WaveTwoCase>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunSummary {
    pub id: String,
    pub target: String,
    pub status: String,
    pub started_at: String,
    pub readiness_score: Option<u32>,
    pub gate_verdict: Option<String>,
    pub defects_count: usize,
    pub cases_count: usize,
    pub approval_status: Option<String>,
    #[serde(default)]
    pub app_architecture: Option<String>,
    #[serde(default)]
    pub requester_ip: Option<String>,
}

/// Category compliance score under OWASP ASVS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsvsCategoryScore {
    pub code: String,
    pub name: String,
    pub score: u32,
    pub passed: bool,
    pub findings: usize,
}

/// OWASP ASVS compliance breakdown across verification levels and categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwaspAsvsBreakdown {
    pub level_1_compliant: bool,
    pub level_2_compliant: bool,
    pub level_3_compliant: bool,
    pub overall_coverage_pct: u32,
    pub categories: Vec<AsvsCategoryScore>,
}

/// Formal Software Factory Attestation certifying release readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareFactoryAttestation {
    pub release_readiness_score: u32,
    pub gate_verdict: String,
    pub asvs_breakdown: OwaspAsvsBreakdown,
    pub release_directives: Vec<String>,
    pub attestation_digest: String,
    pub timestamp: String,
    #[serde(default)]
    pub advisory_summary: Option<String>,
}
