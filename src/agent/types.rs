//! Wire/storage types of the agent. Everything added after the first release is `#[serde(default)]`
//! so reports persisted by older builds still load.
use serde::{Deserialize, Serialize};

use super::oracle::OracleOutcome;

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_model_tier() -> String {
    "high".to_string()
}

pub(crate) fn default_reasoning_tokens() -> u32 {
    8192
}

fn default_profile() -> String {
    "standard".to_string()
}

pub(crate) fn default_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunRequest {
    pub target: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default)]
    pub spec_url: Option<String>,
    #[serde(default)]
    pub custom_instructions: Option<String>,
    /// Never send state-changing methods (POST/PUT/PATCH/DELETE); such cases are recorded as SKIPPED.
    #[serde(default)]
    pub dry_run: bool,
    /// Accepted for compatibility; recorded in the report but not forwarded to the provider.
    #[serde(default = "default_true")]
    pub thinking: bool,
    #[serde(default = "default_model_tier")]
    pub model_tier: String,
    #[serde(default = "default_reasoning_tokens")]
    pub thinking_budget_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredRoute {
    pub path: String,
    pub method: String,
    pub status_code: u16,
    pub content_type: String,
    pub is_spa_shell: bool,
    pub is_api: bool,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub has_form: bool,
    /// From the OpenAPI spec: does the operation declare security? None = no spec information.
    #[serde(default)]
    pub secured: Option<bool>,
    #[serde(default)]
    pub has_body: bool,
    /// crawl | probe | openapi
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTechProfile {
    pub is_spa: bool,
    pub app_architecture: String,
    pub primary_framework: String,
    pub detected_signals: Vec<String>,
    pub is_php: bool,
    pub is_api_only: bool,
}

impl Default for TargetTechProfile {
    fn default() -> Self {
        Self {
            is_spa: false,
            app_architecture: "Traditional Web / API".to_string(),
            primary_framework: "Unknown".to_string(),
            detected_signals: vec![],
            is_php: false,
            is_api_only: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedCase {
    pub id: String,
    pub title: String,
    pub component: String,
    #[serde(default = "default_method")]
    pub method: String, // GET | HEAD | OPTIONS | POST | PUT | PATCH | DELETE
    pub technique: String, // boundary | negative | authz | state_transition | injection
    pub input_hint: String,
    /// For GET/HEAD/OPTIONS this becomes the query string (JSON object or k=v&k2=v2 or free text -> q=);
    /// for body methods it is the request body.
    #[serde(default)]
    pub payload: Option<String>,
    pub expected_behavior: String,
    #[serde(default)]
    pub expected_status: Option<u16>,
    pub risk_level: String, // critical | high | medium | low
    /// Credential role: anon | forged | user | admin | ... (token from RH_<ROLE>_TOKEN). None = infer.
    #[serde(default)]
    pub role: Option<String>,
    /// Spec says this operation needs credentials (Some(true)) / is public (Some(false)).
    #[serde(default)]
    pub secured: Option<bool>,
    /// Status seen for this route during discovery (no credentials).
    #[serde(default)]
    pub route_status: Option<u16>,
    /// Response fields the spec marks required (contract check).
    #[serde(default)]
    pub expect_fields: Vec<String>,
    #[serde(default)]
    pub expected_content_type: Option<String>,
    /// deterministic | openapi | llm
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub attempt: u32,
    pub status_code: Option<u16>,
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub title: String,
    pub component: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub technique: String,
    /// PASS | FAIL | WARN | INCONCLUSIVE | BLOCKED (could not run: transport error) | SKIPPED (not run: dry-run, budget, invalid)
    pub status: String,
    pub status_code: Option<u16>,
    pub latency_ms: u64,
    pub reproduction_curl: String,
    pub request_payload: Option<String>,
    pub evidence: String,
    pub content_type: Option<String>,
    pub is_spa_shell: bool,
    pub failure_reason: Option<String>,
    #[serde(default)]
    pub expected_status: Option<u16>,
    #[serde(default)]
    pub oracle: Option<OracleOutcome>,
    /// A FAIL that did not reproduce on every re-run.
    #[serde(default)]
    pub flaky: bool,
    #[serde(default)]
    pub attempts: Vec<AttemptRecord>,
    /// Run-relative path (evidence/<case>.json) written when the report is saved.
    #[serde(default)]
    pub evidence_file: Option<String>,
    /// Full (redacted) request/response record behind `evidence_file`; not part of the report JSON.
    #[serde(skip)]
    pub evidence_detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitCheckItem {
    pub criterion: String,
    pub met: bool,
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

/// What the LLM said about the gate. Advisory: scores are clamped 0..=100, the verdict can only
/// make the final verdict worse, never better.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmAdvisory {
    pub verdict: Option<String>,
    pub overall_readiness: Option<u32>,
    pub value_score: Option<u32>,
    pub authority_score: Option<u32>,
    pub safety_score: Option<u32>,
    pub evidence_score: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// How `gate_verdict` was derived (worst of computed vs LLM).
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
    pub status: String, // completed | failed | running
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
    pub budget: Option<super::budget::BudgetUsage>,
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
