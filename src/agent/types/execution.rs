//! Case execution models, stateful step chains, and execution results.

use serde::{Deserialize, Serialize};

use super::defaults::default_method;
use super::discovery::{BlockReason, RedirectHop};
use super::planning::PlannedCase;
use crate::agent::oracle::OracleOutcome;

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
