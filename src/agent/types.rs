//! Wire/storage types of the agent. Everything added after the first release is `#[serde(default)]`
//! so reports persisted by older builds still load.
//!
//! Also home of the small shared run-lifecycle API that other agent modules call without any
//! plumbing: the [`CreatedLedger`] (resources a run created, for teardown), the [`CancelToken`]
//! registry ([`request_cancel`]) and the profile depth helper ([`profile_case_cap`]).
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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
pub struct StatefulStep {
    pub step_number: u32,
    pub actor: String, // "alice", "bob", "anon", "admin"
    pub method: String,
    pub path: String, // e.g. "/api/items/{{item_id}}"
    pub payload: Option<String>,
    pub extract_vars: Option<Vec<String>>, // variable names to extract from JSON response
    pub expected_status: Option<u16>,
    pub violation_condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulStepExecution {
    pub step_number: u32,
    pub actor: String,
    pub method: String,
    pub resolved_path: String,
    pub status_code: u16,
    pub latency_ms: u64,
    pub extracted_values: std::collections::HashMap<String, String>,
    pub passed: bool,
    #[serde(default)]
    pub violation_triggered: bool,
    #[serde(default)]
    pub error_detail: Option<String>,
}

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

/// One hop of a redirect chain: the status that redirected and where it pointed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedirectHop {
    pub status: u16,
    pub location: String,
}

/// Where a route takes input. `None` = nothing an input-class test (injection, boundary,
/// negative) could exercise, so those techniques are not planned there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSurface {
    #[default]
    None,
    Query,
    Form,
    Json,
    Spec,
}

/// Soft-404 calibration: how the target answers paths that cannot exist. A route whose response
/// matches is a catch-all (SPA shell / custom not-found page), not a real route.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Soft404Fingerprint {
    pub status: u16,
    /// Body length in bytes (matching allows a +/-5% tolerance).
    pub len: usize,
    /// Hash of the normalised visible text (tokens, numbers, timestamps stripped).
    pub text_hash: String,
}

/// Why a case could not produce evidence. A BLOCKED case is not a failure and not a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// The route sits behind a login wall and no role/credential was provided.
    AuthWall,
    /// The request would leave the allowed scope.
    OutOfScope,
    /// Nothing on the route accepts input for this technique.
    NoSurface,
    /// Transport error: no HTTP answer.
    Transport,
}

/// Something that kept the run from gathering evidence, and what the user can do about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocker {
    pub reason: BlockReason,
    pub detail: String,
    pub next_step: String,
    #[serde(default)]
    pub case_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// crawl | probe | openapi | manifest | js | sitemap | xhr
    #[serde(default)]
    pub source: String,
    /// URL the route finally answered from after same-origin redirects (None: no redirect).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    /// Redirect hops before the final answer; `status_code` is the FIRST hop's status.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_chain: Vec<RedirectHop>,
    /// 401, or a redirect to a login/sign-in/SSO page, or a password form: needs credentials.
    #[serde(default)]
    pub auth_wall: bool,
    /// The response matches the soft-404 fingerprint: not a real route.
    #[serde(default)]
    pub catch_all: bool,
    #[serde(default)]
    pub input_surface: InputSurface,
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

/// What the spec documents about the responses of a case's operation. It travels with the case,
/// so the oracle and every verifier replay judge against the same contract without the spec.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResponseContract {
    /// Documented statuses ("200", "2XX", "default") to the JSON schema of a 2xx body. Only 2xx
    /// bodies are validated, so other statuses carry just their key.
    pub responses: crate::qa::api::contract::Responses,
    /// A plain read: its latency is judged against the QA engine's threshold
    /// (`qa::api::latency`).
    #[serde(default)]
    pub latency: bool,
}

fn default_oast_wait_ms() -> u64 {
    350
}

/// Optional deterministic differential / timing / template / redirect / OAST verification oracle
/// attached to a [`PlannedCase`], executed identically during exploration and verification replays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeOracle {
    BooleanDiff {
        baseline_payload: String,
        false_payload: String,
    },
    TimeDelay {
        baseline_payload: String,
        min_delay_ms: u64,
    },
    Ssti {
        expected_eval: String,
    },
    OpenRedirect {
        canary_host: String,
    },
    OastCallback {
        placeholder: String,
        #[serde(default = "default_oast_wait_ms")]
        wait_ms: u64,
    },
    ExcessiveDataExposure,
    GraphqlIntrospection,
    DomXss {
        #[serde(default)]
        canary: String,
    },
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
    /// Custom request headers attached to the request (excluding credential overrides).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// Explicit Content-Type override for the request body (validated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Optional specialized verification oracle (differential, timing, SSTI, redirect, OAST, PII).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_oracle: Option<ProbeOracle>,
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
    #[serde(default)]
    pub stateful_steps: Option<Vec<StatefulStep>>,
    #[serde(default)]
    pub concurrency_burst: Option<u32>,
    /// The response contract of the operation (see [`ResponseContract`]): documented statuses,
    /// 2xx body schema, latency. Planned from the spec only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ResponseContract>,
    /// The changed operations (`GET /search`) this case tests, when the run is change-aware. A
    /// case with an entry here is planned first and dropped last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_ops: Vec<String>,
    /// The area worker that runs this case: `auth`, `contract`, `state` or `ui` (see `lead::Area`).
    /// Set by the planner; a plan from an older build has none and the lead classifies the case.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub area: String,
    /// Fingerprints of the known defects (the agent's memory of this target) this case re-tests:
    /// it belongs to the failing case class of an open or recently fixed defect. Set by the
    /// planner, which puts these cases first so the report can say still open or fixed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regression_of: Vec<String>,
    /// The operation failed, or was flaky, in an earlier run: planned early. Only ever reorders,
    /// it never removes or adds a case.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub history_priority: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub attempt: u32,
    pub status_code: Option<u16>,
    pub verdict: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub title: String,
    pub component: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub technique: String,
    /// PASS | FAIL | WARN | INCONCLUSIVE | BLOCKED (could not gather evidence: see `blocked_reason`)
    /// | SKIPPED (not run: dry-run, budget, invalid) | NOT_APPLICABLE (technique has no surface on
    /// this route; excluded from every denominator)
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
    #[serde(default)]
    pub stateful_chain: Option<Vec<StatefulStepExecution>>,
    #[serde(default)]
    pub concurrency_burst_results: Option<Vec<u16>>,
    /// Set when `status` is BLOCKED (or NOT_APPLICABLE): why no evidence could be gathered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<BlockReason>,
    /// Same-origin redirects the executor followed before the judged response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_chain: Vec<RedirectHop>,
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
    pub accepted: Option<super::memory::Acceptance>,
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
    pub budget: Option<super::budget::BudgetUsage>,
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
    /// What changed since the previous run against this target, from the agent's memory (None:
    /// memory is off, or the run is from before it existed). Deterministic; never changes a verdict
    /// by itself (only an explicit, unexpired acceptance does).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_last_run: Option<super::memory::SinceLastRun>,
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

/// An operation of the OpenAPI spec that the code diff touched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangedOperation {
    /// `GET /search`, as the spec writes it.
    pub operation: String,
    /// `route`: a route extracted from a changed file matched it. `file`: a changed handler file
    /// maps to it (operationId or resource name) but its routes could not be extracted ("file
    /// changed, routes unknown").
    pub via: String,
    /// The changed files that lead to it.
    pub files: Vec<String>,
    pub detail: String,
}

/// How the run covered one changed operation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChangedOpCoverage {
    pub operation: String,
    pub planned: usize,
    /// Planned cases that were sent (not SKIPPED).
    pub executed: usize,
    pub pass: usize,
    pub fail: usize,
    /// WARN, INCONCLUSIVE or BLOCKED: sent, but not a clean answer.
    pub inconclusive: usize,
    /// Techniques of the executed cases (authz, boundary, negative, injection, state_transition).
    pub techniques: Vec<String>,
    pub case_ids: Vec<String>,
}

/// The "Change impact" of a change-aware run: what the diff touched, which operations that maps
/// to, what could not be mapped, and how the changed operations were covered. Deterministic; the
/// optional retriever notes are the only advisory part and are kept apart.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChangeImpact {
    /// applied | no_changes | skipped | failed
    pub status: String,
    pub repo: String,
    pub diff_base: String,
    /// Changed files, at most `change::MAX_LISTED_FILES` of them.
    #[serde(default)]
    pub changed_files: Vec<String>,
    /// All of them (the list above is capped).
    #[serde(default)]
    pub changed_files_total: usize,
    #[serde(default)]
    pub operations: Vec<ChangedOperation>,
    /// Changed files that map to no operation (tests, docs, shared code, routes not in the spec),
    /// at most `change::MAX_LISTED_FILES` of them.
    #[serde(default)]
    pub unmapped_files: Vec<String>,
    /// All of them (the list above is capped).
    #[serde(default)]
    pub unmapped_total: usize,
    #[serde(default)]
    pub coverage: Vec<ChangedOpCoverage>,
    #[serde(default)]
    pub notes: Vec<String>,
    /// Text from the optional context retriever. UNTRUSTED and advisory: it never adds a case and
    /// never changes a verdict.
    #[serde(default)]
    pub context_notes: Vec<String>,
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

// ---------------------------------------------------------------- shared run-lifecycle API

/// `PlannedCase::source` of a planner-made ledger row that sends nothing: no technique has a
/// surface on the discovered routes. The executor turns it into a NOT_APPLICABLE result
/// (`BlockReason::NoSurface`) without a request, a step or any budget.
pub const SRC_NOT_APPLICABLE: &str = "ledger:not_applicable";
/// Same, for routes behind a login wall with no credential to get past it: a BLOCKED result
/// (`BlockReason::AuthWall`).
pub const SRC_AUTH_WALL: &str = "ledger:auth_wall";

impl PlannedCase {
    /// A planner-made ledger row (see [`SRC_NOT_APPLICABLE`], [`SRC_AUTH_WALL`]), not a request.
    pub fn is_ledger_row(&self) -> bool {
        matches!(
            self.source.as_deref(),
            Some(SRC_NOT_APPLICABLE) | Some(SRC_AUTH_WALL)
        )
    }
}

impl CaseExecutionResult {
    /// A request went to the target for this result: not SKIPPED, not NOT_APPLICABLE, and not a
    /// ledger-only BLOCKED row (an auth wall the planner already knew about, nothing was sent).
    /// A transport error counts: the request was sent, it just got no answer.
    pub fn was_sent(&self) -> bool {
        match self.status.as_str() {
            "SKIPPED" | "NOT_APPLICABLE" => false,
            "BLOCKED" => {
                self.status_code.is_some()
                    || !matches!(
                        self.blocked_reason,
                        Some(
                            BlockReason::AuthWall
                                | BlockReason::NoSurface
                                | BlockReason::OutOfScope
                        )
                    )
            }
            _ => true,
        }
    }

    /// A SKIPPED result for a planned case that was never sent (dropped by plan truncation, ...).
    pub fn not_run(case: &PlannedCase, reason: impl Into<String>) -> Self {
        CaseExecutionResult {
            blocked_reason: None,
            redirect_chain: vec![],
            case_id: case.id.clone(),
            title: case.title.clone(),
            component: case.component.clone(),
            method: case.method.clone(),
            technique: case.technique.clone(),
            status: "SKIPPED".into(),
            status_code: None,
            latency_ms: 0,
            reproduction_curl: String::new(),
            request_payload: case.payload.clone(),
            evidence: String::new(),
            content_type: None,
            is_spa_shell: false,
            failure_reason: Some(reason.into()),
            expected_status: case.expected_status,
            oracle: None,
            flaky: false,
            attempts: vec![],
            evidence_file: None,
            evidence_detail: None,
            stateful_chain: None,
            concurrency_burst_results: None,
        }
    }

    /// A request/response pair was recorded for this case: the target answered (`status_code`) and
    /// the evidence file exists. A transport error (BLOCKED) or a case that was not sent has none.
    pub fn has_stored_evidence(&self) -> bool {
        self.evidence_file.is_some() && self.status_code.is_some()
    }
}

/// (executed cases with stored request/response evidence, executed cases). Cases that were never
/// sent (SKIPPED, NOT_APPLICABLE, ledger-only rows: see `was_sent`) are not counted. The evidence pillar should be this share, not a constant.
pub fn evidence_share(results: &[CaseExecutionResult]) -> (usize, usize) {
    let executed = results.iter().filter(|r| r.was_sent());
    let total = executed.clone().count();
    (executed.filter(|r| r.has_stored_evidence()).count(), total)
}

/// How many cases a profile plans at most. `None` = the planner's own cap. A quick run is a smoke
/// test; the planner may additionally use the profile name for depth (it receives it unchanged).
pub fn profile_case_cap(profile: &str) -> Option<usize> {
    match profile.trim().to_ascii_lowercase().as_str() {
        "quick" => Some(20),
        _ => None,
    }
}

/// Sort key: lower runs first and is dropped last. Access control (auth), stateful scenarios and
/// OpenAPI-derived cases outrank generic probes; the root liveness probe is always kept.
pub fn case_priority(c: &PlannedCase) -> (u8, u8) {
    let class = if c.technique == "authz"
        || c.technique == "injection"
        || c.component == "/"
        || c.is_ledger_row()
        || c.source.as_deref() == Some("directives")
    {
        0
    } else if c.stateful_steps.as_ref().is_some_and(|s| !s.is_empty())
        || c.concurrency_burst.is_some_and(|b| b > 1)
    {
        1
    } else if c.source.as_deref() == Some("openapi") {
        2
    } else if c.source.as_deref() == Some("llm") {
        5
    } else {
        4
    };
    let risk = match c.risk_level.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    (class, risk)
}

/// The sort key of a plan that has to be cut or ordered. With nothing to prioritise (`any_priority`
/// false) it is exactly [`case_priority`]. Otherwise the cases that re-test a known defect (memory)
/// come first, then every case that tests a changed operation or one with a failing or flaky past
/// (and the root liveness probe, which is always kept), then the rest, each tier by
/// [`case_priority`]. So truncation drops unchanged, never-failed operations first.
pub fn plan_order(any_priority: bool) -> impl Fn(&PlannedCase) -> (u8, u8, u8) {
    move |c| {
        let (class, risk) = case_priority(c);
        let tier = if !c.regression_of.is_empty() {
            0
        } else if !any_priority
            || !c.changed_ops.is_empty()
            || c.history_priority
            || c.source.as_deref() == Some("directives")
            || c.technique == "authz"
            || c.technique == "injection"
            || c.component == "/"
            || c.is_ledger_row()
        {
            1
        } else {
            2
        };
        (tier, class, risk)
    }
}

/// Does any case of the plan test a changed operation?
pub fn any_changed(cases: &[PlannedCase]) -> bool {
    cases.iter().any(|c| !c.changed_ops.is_empty())
}

/// Does any case of the plan have a reason to run early: a changed operation, a failing or flaky
/// past, a known defect to re-test? Feeds [`plan_order`].
pub fn any_prioritised(cases: &[PlannedCase]) -> bool {
    cases
        .iter()
        .any(|c| !c.changed_ops.is_empty() || c.history_priority || !c.regression_of.is_empty())
}

// ---------------------------------------------------------------- created-resource ledger

/// One resource the run created on the target (so it can be torn down again).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedResource {
    /// Method of the creating request (POST, PUT, ...).
    pub method: String,
    /// Path of the creating request (collection or resource path), no query string.
    pub path: String,
    /// Identifier the target returned for the new resource.
    pub id: String,
    /// Explicit path to DELETE when it is not `<path>/<id>` (e.g. taken from a Location header).
    #[serde(default)]
    pub delete_path: Option<String>,
    /// Credential role that created it (the same role deletes it, when a token is configured).
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub case_id: Option<String>,
}

impl CreatedResource {
    /// The path a teardown DELETE goes to.
    pub fn teardown_path(&self) -> String {
        if let Some(p) = &self.delete_path {
            return p.clone();
        }
        let base = self.path.trim_end_matches('/');
        if base.rsplit('/').next() == Some(self.id.as_str()) {
            base.to_string()
        } else {
            format!("{base}/{}", self.id)
        }
    }
}

const MAX_CREATED: usize = 500;

fn safe_created_path(p: &str) -> bool {
    p.starts_with('/')
        && !p.starts_with("//")
        && p.len() <= 512
        && !p
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || c == '?' || c == '#')
        && !p.split('/').any(|seg| seg == ".." || seg == ".")
}

fn safe_created_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

/// Resources created during a run, shared between the executor and the pipeline (cheap `Clone`).
///
/// The executor/stateful code records every resource it creates:
/// `CreatedLedger::record("/api/items", "42")` after a 2xx POST that returned `{"id": 42}`, or the
/// free function [`record_created`] (no plumbing: the pipeline installs the run's ledger for the
/// running thread). At the end of a non-dry-run run against a nonprod target the pipeline DELETEs
/// them newest first and lists whatever it could not remove under the report's cleanup section.
#[derive(Debug, Clone, Default)]
pub struct CreatedLedger {
    inner: Arc<Mutex<Vec<CreatedResource>>>,
}

impl CreatedLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// A POST created `id` under `path`. Returns false when the entry is unusable (kept out of the
    /// ledger: ids and paths end up in URLs, so only URL-safe values are accepted).
    pub fn record(&self, path: &str, id: &str) -> bool {
        self.record_with("POST", path, id, None, None)
    }

    pub fn record_with(
        &self,
        method: &str,
        path: &str,
        id: &str,
        role: Option<&str>,
        case_id: Option<&str>,
    ) -> bool {
        self.record_resource(CreatedResource {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            id: id.to_string(),
            delete_path: None,
            role: role.map(str::to_string),
            case_id: case_id.map(str::to_string),
        })
    }

    pub fn record_resource(&self, r: CreatedResource) -> bool {
        if !safe_created_path(&r.path)
            || !safe_created_id(&r.id)
            || r.delete_path
                .as_deref()
                .is_some_and(|p| !safe_created_path(p))
        {
            return false;
        }
        let mut v = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if v.len() >= MAX_CREATED || v.iter().any(|x| x.teardown_path() == r.teardown_path()) {
            return false;
        }
        v.push(r);
        true
    }

    pub fn entries(&self) -> Vec<CreatedResource> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether an entry with the same teardown path is already recorded.
    pub fn contains(&self, r: &CreatedResource) -> bool {
        let t = r.teardown_path();
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|x| x.teardown_path() == t)
    }

    /// How many entries were recorded for this case id (the executor tags every creation).
    pub fn recorded_for_case(&self, case_id: &str) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|x| x.case_id.as_deref() == Some(case_id))
            .count()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Make this the ledger [`record_created`] writes to on the current thread until the guard drops.
    pub fn install(&self) -> CreatedScope {
        let prev = CURRENT_LEDGER.with(|c| c.borrow_mut().replace(self.clone()));
        CreatedScope { prev }
    }
}

thread_local! {
    static CURRENT_LEDGER: RefCell<Option<CreatedLedger>> = const { RefCell::new(None) };
}

/// Restores the previously installed ledger on drop.
pub struct CreatedScope {
    prev: Option<CreatedLedger>,
}

impl Drop for CreatedScope {
    fn drop(&mut self) {
        let prev = self.prev.take();
        CURRENT_LEDGER.with(|c| *c.borrow_mut() = prev);
    }
}

/// Record a created resource on the current run's ledger (no-op, false, when none is installed).
pub fn record_created(path: &str, id: &str) -> bool {
    record_created_with("POST", path, id, None, None)
}

pub fn record_created_with(
    method: &str,
    path: &str,
    id: &str,
    role: Option<&str>,
    case_id: Option<&str>,
) -> bool {
    CURRENT_LEDGER.with(|c| {
        c.borrow()
            .as_ref()
            .is_some_and(|l| l.record_with(method, path, id, role, case_id))
    })
}

/// The ledger installed on the current thread, if any. Code that fans out to other threads (a
/// concurrency burst) takes this clone and hands it to them: the thread-local does not reach them.
pub fn current_ledger() -> Option<CreatedLedger> {
    CURRENT_LEDGER.with(|c| c.borrow().clone())
}

/// [`record_created_with`] for a fully described resource (explicit delete path, role, case id).
pub fn record_created_resource(r: CreatedResource) -> bool {
    CURRENT_LEDGER.with(|c| c.borrow().as_ref().is_some_and(|l| l.record_resource(r)))
}

/// A request that created something: a POST that answered 2xx, or a PUT that answered 201.
pub(crate) fn is_creation(method: &str, status: u16) -> bool {
    (method.eq_ignore_ascii_case("POST") && (200..300).contains(&status))
        || (method.eq_ignore_ascii_case("PUT") && status == 201)
}

fn id_from_json(v: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    let scalar = |x: &Value| match x {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let from_obj = |o: &serde_json::Map<String, Value>| {
        ["id", "_id", "uuid"]
            .iter()
            .find_map(|k| o.get(*k).and_then(scalar))
            .or_else(|| {
                o.iter()
                    .find(|(k, _)| k.to_ascii_lowercase().ends_with("_id"))
                    .and_then(|(_, x)| scalar(x))
            })
    };
    let o = v.as_object()?;
    from_obj(o).or_else(|| {
        ["data", "result", "item", "resource"]
            .iter()
            .find_map(|k| o.get(*k).and_then(Value::as_object).and_then(from_obj))
    })
}

/// The id a creation response announced: parsed from the body (or a stored excerpt), or, when the
/// text was cut mid-JSON, from the first `"id": ...` in it.
pub(crate) fn id_from_body(body: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        return id_from_json(&v);
    }
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r#""(?:id|_id|uuid)"\s*:\s*(?:"([A-Za-z0-9._~-]{1,128})"|(\d{1,20}))"#)
            .unwrap()
    });
    let c = re.captures(body)?;
    c.get(1)
        .or_else(|| c.get(2))
        .map(|m| m.as_str().to_string())
}

pub(crate) fn path_of_url(u: &str) -> Option<String> {
    reqwest::Url::parse(u).ok().map(|u| u.path().to_string())
}

/// Record the resource a creating response produced (see [`is_creation`]): the id comes from the
/// body, the delete path from a same-origin `Location` header when there is one. Written to
/// `ledger` when given, otherwise to the ledger installed on the current thread (a no-op when
/// there is none). Returns whether a new entry was recorded; a response that names no id (and no
/// `Location`) cannot be torn down and is reported by the pipeline as unidentified.
pub(crate) fn record_creation_response(
    ledger: Option<&CreatedLedger>,
    method: &str,
    request_url: &str,
    status: u16,
    headers: &[(String, String)],
    body: &str,
    role: Option<&str>,
    case_id: Option<&str>,
) -> bool {
    if !is_creation(method, status) {
        return false;
    }
    let Ok(req) = reqwest::Url::parse(request_url) else {
        return false;
    };
    let location = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .and_then(|(_, v)| req.join(v).ok())
        .filter(|l| l.origin() == req.origin())
        .map(|l| l.path().to_string());
    let body_id = id_from_body(body);
    let (id, delete_path) = match (&location, body_id) {
        (Some(loc), id) => (
            id.unwrap_or_else(|| {
                loc.trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_string()
            }),
            Some(loc.clone()),
        ),
        (None, Some(id)) => (id, None),
        (None, None) => return false,
    };
    let r = CreatedResource {
        method: method.to_ascii_uppercase(),
        path: req.path().to_string(),
        id,
        delete_path,
        role: role.map(str::to_string),
        case_id: case_id.map(str::to_string),
    };
    match ledger {
        Some(l) => l.record_resource(r),
        None => record_created_resource(r),
    }
}

/// A created resource the teardown could not (or was not allowed to) remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leftover {
    pub method: String,
    pub path: String,
    pub id: String,
    pub reason: String,
}

/// What the end-of-run teardown did. Stored beside the report as `cleanup.json`; the report's notes
/// and the "Cleanup" step carry the same facts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    pub created: usize,
    pub attempted: usize,
    pub deleted: usize,
    /// Why no teardown ran (dry-run, target not confirmed nonprod, nothing created, cancelled).
    #[serde(default)]
    pub skipped: Option<String>,
    #[serde(default)]
    pub leftovers: Vec<Leftover>,
    #[serde(default)]
    pub resources: Vec<CreatedResource>,
    /// Deleted resources a follow-up GET confirmed gone (404/410).
    #[serde(default)]
    pub confirmed_gone: usize,
    /// DELETE answered 2xx but the follow-up GET still found the resource: not removed (also listed
    /// under `leftovers`, reason starting `delete_not_effective`).
    #[serde(default)]
    pub still_present: usize,
    /// DELETE answered 2xx and the read-back proved nothing (401/403/5xx/transport error).
    #[serde(default)]
    pub unconfirmed: usize,
}

impl CleanupReport {
    pub fn summary(&self) -> String {
        match (&self.skipped, self.created) {
            (Some(why), 0) => format!("no cleanup needed: {why}"),
            (Some(why), n) => format!(
                "{n} resource(s) created, teardown skipped ({why}); {} left on the target",
                self.leftovers.len()
            ),
            (None, n) => format!(
                "{n} resource(s) created, {} deleted, {} left on the target (follow-up GET: {} confirmed gone, {} still present after a 2xx DELETE, {} unconfirmed)",
                self.deleted,
                self.leftovers.len(),
                self.confirmed_gone,
                self.still_present,
                self.unconfirmed
            ),
        }
    }
}

// ---------------------------------------------------------------- independent verification

/// What the verifier concluded about one failed case after replaying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyVerdict {
    /// All k replays reproduced the failure.
    Confirmed,
    /// Some, but not all, replays reproduced it.
    Flaky,
    /// None of the k replays reproduced it.
    NotReproduced,
    /// Not (fully) replayed: a state-changing request that is not safe to repeat, a burst, a budget or
    /// cancellation stop, or replays that could not be sent.
    Unverified,
}

impl VerifyVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyVerdict::Confirmed => "confirmed",
            VerifyVerdict::Flaky => "flaky",
            VerifyVerdict::NotReproduced => "not_reproduced",
            VerifyVerdict::Unverified => "unverified",
        }
    }
}

/// One replay of a failed case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayRecord {
    pub replay: u32,
    pub status_code: Option<u16>,
    pub latency_ms: u64,
    /// The oracle's verdict on the replay (PASS | FAIL | INCONCLUSIVE), or ERROR when it was not
    /// sent / did not complete.
    pub verdict: String,
    /// The replay failed the same way the original did.
    pub reproduced: bool,
    #[serde(default)]
    pub note: Option<String>,
}

/// The verifier's record for one failed case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub case_id: String,
    pub method: String,
    pub component: String,
    pub verdict: VerifyVerdict,
    /// Severity of the original failure (lowercase).
    pub severity: String,
    /// Replays asked for.
    pub k: u32,
    /// Replays that completed (got an answer that was judged).
    pub completed: u32,
    /// Completed replays that reproduced the failure.
    pub reproduced: u32,
    #[serde(default)]
    pub replays: Vec<ReplayRecord>,
    /// Why it was not replayed (`unverified-write`, burst, budget...) or how the replays ended.
    #[serde(default)]
    pub note: Option<String>,
    /// Status of the result before / after the verdict was applied.
    pub original_status: String,
    pub final_status: String,
    /// Run-relative evidence file; its `verification` section holds the replays' responses.
    #[serde(default)]
    pub evidence_file: Option<String>,
}

impl VerificationRecord {
    /// "2/2" for a confirmed failure, "1/2" for a flaky one; None when nothing was replayed.
    pub fn ratio(&self) -> Option<String> {
        (self.completed > 0).then(|| format!("{}/{}", self.reproduced, self.k))
    }
}

/// What the verifier did in one run. Stored on the evidence ledger.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VerificationSummary {
    /// Replays per failed case (0 = verification was off).
    pub k: u32,
    /// FAIL results the verifier looked at.
    pub candidates: usize,
    /// Candidates that got all k replays (confirmed + flaky + not reproduced).
    pub replayed: usize,
    pub confirmed: usize,
    pub flaky: usize,
    pub not_reproduced: usize,
    pub unverified: usize,
    /// HTTP requests the replays sent (charged to the run budget).
    pub replay_requests: usize,
    /// pass^k: the share of replayed failures that reproduced on all k replays (confirmed / replayed).
    /// None when nothing was replayed.
    #[serde(default)]
    pub pass_k: Option<f64>,
    /// Why verification stopped early or did not run (budget, cancellation, disabled).
    #[serde(default)]
    pub stopped: Option<String>,
    #[serde(default)]
    pub records: Vec<VerificationRecord>,
}

impl VerificationSummary {
    /// Recompute the counters and pass^k from `records`.
    pub fn tally(&mut self) {
        let n = |v: VerifyVerdict| self.records.iter().filter(|r| r.verdict == v).count();
        self.candidates = self.records.len();
        self.confirmed = n(VerifyVerdict::Confirmed);
        self.flaky = n(VerifyVerdict::Flaky);
        self.not_reproduced = n(VerifyVerdict::NotReproduced);
        self.unverified = n(VerifyVerdict::Unverified);
        self.replayed = self.confirmed + self.flaky + self.not_reproduced;
        self.pass_k = (self.replayed > 0).then(|| self.confirmed as f64 / self.replayed as f64);
    }

    /// "75%" / "not evaluated".
    pub fn pass_k_text(&self) -> String {
        match self.pass_k {
            Some(p) => format!("{:.0}%", p * 100.0),
            None => "not evaluated".into(),
        }
    }

    pub fn record(&self, case_id: &str) -> Option<&VerificationRecord> {
        self.records.iter().find(|r| r.case_id == case_id)
    }
}

// ---------------------------------------------------------------- cancellation

/// Cooperative cancellation: an in-process flag plus an optional marker file (so another process,
/// e.g. the CLI or a second server worker, can ask a running run to stop). Checked between steps
/// and before every request by the run budget.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
    file: Option<PathBuf>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_file(mut self, path: PathBuf) -> Self {
        self.file = Some(path);
        self
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst) || self.file.as_deref().is_some_and(Path::exists)
    }
}

fn registry() -> &'static Mutex<HashMap<String, CancelToken>> {
    static R: OnceLock<Mutex<HashMap<String, CancelToken>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Keeps a run cancellable by id for as long as it is alive.
pub struct RunRegistration {
    id: String,
}

impl Drop for RunRegistration {
    fn drop(&mut self) {
        registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

pub fn register_run(id: &str, token: &CancelToken) -> RunRegistration {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.to_string(), token.clone());
    RunRegistration { id: id.to_string() }
}

/// Ids of the runs executing in this process.
pub fn running_run_ids() -> Vec<String> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect()
}

/// Ask a run to stop at its next step. A run of this process is flagged directly; for a run whose
/// checkpoint says `running` a `CANCEL` marker is written into its directory, which a run in
/// another process honours too. Returns whether anything was asked to stop.
pub fn request_cancel(run_id: &str) -> bool {
    if !crate::engine::valid_run_id(run_id) {
        return false;
    }
    let mut hit = false;
    if let Some(t) = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(run_id)
    {
        t.cancel();
        hit = true;
    }
    let dir = super::store::agent_runs_dir().join(run_id);
    if super::store::checkpoint_status(&dir).as_deref() == Some("running") {
        hit |= std::fs::write(dir.join("CANCEL"), b"cancel requested").is_ok();
    }
    hit
}

/// Small constructors shared by the agent tests that live in this crate's own modules.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use serde_json::json;

    pub fn planned(id: &str, technique: &str, method: &str, component: &str) -> PlannedCase {
        serde_json::from_value(json!({
            "id": id, "title": format!("case {id}"), "component": component, "method": method,
            "technique": technique, "input_hint": "", "expected_behavior": "", "risk_level": "medium"
        }))
        .unwrap()
    }

    /// A finished result that carries stored evidence (status 200, evidence file, curl).
    pub fn result(id: &str, technique: &str, status: &str) -> CaseExecutionResult {
        let mut r = CaseExecutionResult::not_run(&planned(id, technique, "GET", "/x"), "");
        r.status = status.into();
        r.failure_reason = (status == "FAIL").then(|| "expected 401, got 200".into());
        r.status_code = Some(200);
        r.reproduction_curl = "curl -sS -i -X GET 'http://h/x'".into();
        r.evidence_file = Some(format!("evidence/{id}.json"));
        r.evidence = "ok".into();
        r
    }

    pub fn report(id: &str) -> AgentRunReport {
        serde_json::from_value(json!({
            "id": id, "target": "http://127.0.0.1:1/", "profile": "standard", "model": "none",
            "provider": "deterministic", "started_at": "2026-01-01T00:00:00Z", "finished_at": null,
            "status": "completed", "steps": [], "planned_cases": [], "executed_results": [],
            "triaged_defects": [], "evidence_ledger": null, "approval_status": "pending",
            "approved_by": null, "approval_notes": null, "approved_at": null, "error": null
        }))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn created_ledger_records_validates_and_deduplicates() {
        let l = CreatedLedger::new();
        assert!(l.record("/api/items", "42"));
        assert!(!l.record("/api/items", "42"), "same resource twice");
        assert!(l.record_with("put", "/api/items/7", "7", Some("user"), Some("TC-002")));
        // path or id that cannot be put in a URL safely are refused
        for (p, i) in [
            ("api/items", "1"),
            ("//evil.example/x", "1"),
            ("/a/../b", "1"),
            ("/a b", "1"),
            ("/a?x=1", "1"),
            ("/a", "1/2"),
            ("/a", ""),
            ("/a", "x y"),
            ("/a", "1;DROP"),
        ] {
            assert!(!l.record(p, i), "{p} {i}");
        }
        let e = l.entries();
        assert_eq!(l.len(), 2);
        assert_eq!(e[0].teardown_path(), "/api/items/42");
        assert_eq!(
            (e[1].method.as_str(), e[1].role.as_deref()),
            ("PUT", Some("user"))
        );
        assert_eq!(
            e[1].teardown_path(),
            "/api/items/7",
            "a path already ending in the id is not extended"
        );
        let mut with_loc = e[0].clone();
        with_loc.delete_path = Some("/v2/things/abc".into());
        assert_eq!(with_loc.teardown_path(), "/v2/things/abc");
        assert!(!l.record_resource(CreatedResource {
            delete_path: Some("/x?y".into()),
            ..e[0].clone()
        }));
    }

    #[test]
    fn record_created_writes_to_the_installed_ledger_and_restores_the_previous() {
        assert!(
            !record_created("/a", "1"),
            "no ledger installed: nothing recorded"
        );
        let outer = CreatedLedger::new();
        let inner = CreatedLedger::new();
        {
            let _o = outer.install();
            assert!(record_created("/a", "1"));
            {
                let _i = inner.install();
                assert!(record_created_with("POST", "/b", "2", None, Some("TC-1")));
            }
            assert!(record_created("/c", "3"), "outer ledger is current again");
        }
        assert!(!record_created("/d", "4"));
        assert_eq!(outer.len(), 2);
        assert_eq!(inner.len(), 1);
        assert_eq!(inner.entries()[0].case_id.as_deref(), Some("TC-1"));
        // another thread sees no ledger
        let _g = outer.install();
        assert!(
            !std::thread::spawn(|| record_created("/e", "5"))
                .join()
                .unwrap()
        );
    }

    #[test]
    fn evidence_share_counts_stored_request_response_pairs_not_constants() {
        let ok = result("TC-001", "boundary", "PASS");
        let mut blocked = result("TC-002", "boundary", "BLOCKED");
        blocked.status_code = None; // transport error: request recorded, no response
        let mut no_file = result("TC-003", "authz", "PASS");
        no_file.evidence_file = None;
        let skipped =
            CaseExecutionResult::not_run(&planned("TC-004", "authz", "POST", "/y"), "dry-run");
        assert!(
            ok.has_stored_evidence()
                && !blocked.has_stored_evidence()
                && !no_file.has_stored_evidence()
        );
        assert_eq!(
            evidence_share(&[ok.clone(), blocked, no_file, skipped]),
            (1, 3),
            "skipped cases are not executed"
        );
        assert_eq!(evidence_share(&[]), (0, 0));
        assert_eq!(evidence_share(&[ok]), (1, 1));
    }

    #[test]
    fn priority_puts_auth_stateful_and_openapi_before_generic_probes() {
        let mut stateful = planned("a", "authz_chain", "POST", "/items");
        stateful.stateful_steps = Some(vec![StatefulStep {
            step_number: 1,
            actor: "alice".into(),
            method: "POST".into(),
            path: "/items".into(),
            payload: None,
            extract_vars: None,
            expected_status: None,
            violation_condition: None,
        }]);
        let mut openapi = planned("b", "boundary", "POST", "/orders");
        openapi.source = Some("openapi".into());
        let auth = planned("c", "authz", "GET", "/admin");
        let root = planned("d", "state_transition", "GET", "/");
        let mut llm = planned("e", "boundary", "GET", "/z");
        llm.source = Some("llm".into());
        let generic = planned("f", "boundary", "GET", "/about");
        let key = |c: &PlannedCase| case_priority(c).0;
        assert!(key(&auth) == 0 && key(&root) == 0 && key(&stateful) == 1 && key(&openapi) == 2);
        assert!(key(&openapi) < key(&generic) && key(&generic) < key(&llm));
        assert_eq!(profile_case_cap("QUICK"), Some(20));
        assert_eq!(
            (
                profile_case_cap("standard"),
                profile_case_cap("deep"),
                profile_case_cap("discovery-scan")
            ),
            (None, None, None)
        );
    }

    #[test]
    fn cancel_token_honours_the_flag_and_a_marker_file() {
        let t = CancelToken::new();
        assert!(!t.is_cancelled());
        t.clone().cancel();
        assert!(t.is_cancelled(), "clones share the flag");
        let dir = std::env::temp_dir().join(format!("rh-cancel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("CANCEL");
        let _ = std::fs::remove_file(&marker);
        let t = CancelToken::new().with_file(marker.clone());
        assert!(!t.is_cancelled());
        std::fs::write(&marker, b"x").unwrap();
        assert!(
            t.is_cancelled(),
            "another process asked through the marker file"
        );
        let _ = std::fs::remove_dir_all(&dir);
        // registry: an id is cancellable only while its registration is alive
        let tok = CancelToken::new();
        let reg = register_run("run-unit-cancel", &tok);
        assert!(running_run_ids().contains(&"run-unit-cancel".to_string()));
        assert!(request_cancel("run-unit-cancel") && tok.is_cancelled());
        drop(reg);
        assert!(!running_run_ids().contains(&"run-unit-cancel".to_string()));
        assert!(!request_cancel("../etc/passwd"));
    }
}
