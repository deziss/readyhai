use crate::agent::oracle::{BurstResponse, OracleOutcome};
use crate::agent::types::StatefulStepExecution;

/// Keys extracted from a response even when the step names none.
pub const DEFAULT_ID_KEYS: [&str; 6] = [
    "id",
    "uuid",
    "item_id",
    "order_id",
    "user_id",
    "resource_id",
];

#[derive(Debug, Clone)]
pub struct StatefulScenarioResult {
    /// Why nothing (or nothing conclusive) was run: the chain is SKIPPED, not judged.
    pub skipped: Option<String>,
    /// The oracle's verdict for the chain.
    pub outcome: Option<OracleOutcome>,
    pub steps: Vec<StatefulStepExecution>,
    /// One curl per request, tokens as `${RH_<ROLE>_TOKEN}` placeholders.
    pub reproduction_curl: String,
    pub final_status: u16,
    pub total_latency_ms: u64,
    /// One-line, redacted description of what happened.
    pub summary: String,
    // views of `outcome`, kept for callers that only need a flag
    pub passed: bool,
    pub violation_triggered: bool,
    pub setup_failed: bool,
    pub failure_reason: Option<String>,
}

/// What a burst saw. The verdict is `oracle::judge_burst`.
#[derive(Debug, Clone)]
pub struct BurstRun {
    pub requested: usize,
    pub responses: Vec<BurstResponse>,
    pub status_codes: Vec<u16>,
    /// Bodies of a safe GET of the same URL before / after the burst (state-changing bursts only).
    pub pre_read: Option<String>,
    pub post_read: Option<String>,
    pub notes: Vec<String>,
}
