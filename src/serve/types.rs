//! Request / Response DTOs, query schemas, and domain payloads for the serve module.

use serde::Deserialize;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use crate::engine::ScanOpts;

pub const MIN_TOKEN_CHARS: usize = 16;
/// Tokens that shipped in earlier versions or docs: refused even though they are long enough.
pub const BANNED_TOKENS: &[&str] = &["rh-dev-token-9f8e7d6c5b4a3210"];
/// Concurrent blocking probes (agent run/discover/crawl, network lab) before `429`.
pub const MAX_CONCURRENT_PROBES: usize = 16;
/// `max_pages` bounds for the crawler routes.
pub const DEFAULT_CRAWL_PAGES: usize = 25;
pub const MAX_CRAWL_PAGES: usize = 100;
pub const MAX_NOTES_CHARS: usize = 2000;
/// REST agent runs: the same bounds the MCP tool enforces on its inputs.
pub const DEFAULT_MAX_CUSTOM_INSTRUCTIONS_BYTES: usize = 32_768;
#[allow(dead_code)]
pub const MAX_CUSTOM_INSTRUCTIONS_BYTES: usize = DEFAULT_MAX_CUSTOM_INSTRUCTIONS_BYTES;

pub const PROFILES: &[&str] = &["quick", "standard", "deep"];
pub const MODEL_TIERS: &[&str] = &["low", "medium", "high", "max", "max_pro"];
/// Run listings return at most this many runs (newest first).
pub const MAX_LISTED_RUNS: usize = 50;
/// Run/status JSON larger than this is treated as unreadable rather than loaded into memory.
pub const MAX_RUN_JSON_BYTES: u64 = 64 * 1024 * 1024;
/// The scope check resolves names; a resolver that hangs must not hang the request.
pub const GUARD_TIMEOUT: Duration = Duration::from_secs(15);
/// Shutdown budget. Must stay under the orchestrator's stop grace period (compose sets 20 s):
/// drain connections up to `FORCED_SHUTDOWN`, then stop containers and flush within the rest.
pub const FORCED_SHUTDOWN: Duration = Duration::from_secs(8);
pub const SHUTDOWN_REAP_PER_CALL: Duration = Duration::from_secs(4);
pub const BADGE_VALUE_MAX: usize = 24;

pub struct App {
    pub token_digest: [u8; 32],
    pub principal: String,
    pub tx: mpsc::Sender<(String, ScanOpts)>,
    pub allowed_roots: Vec<PathBuf>,
    pub scope: Option<PathBuf>,
    pub plugins: Option<PathBuf>,
    pub active: Mutex<HashSet<String>>,
    pub probes: Arc<Semaphore>,
}

/// Authenticated caller, injected by the auth middleware.
#[derive(Clone, Debug)]
pub struct Principal(pub String);

impl Principal {
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub enum CancelOutcome {
    /// The run was asked to stop at its next step.
    Requested,
    /// No such agent run.
    Unknown,
    /// The run exists but is not running (its status, for the message).
    NotRunning(String),
}

#[derive(Deserialize)]
pub struct ApprovalPayload {
    #[serde(default)]
    pub notes: String,
}

pub fn clip_notes(s: &str) -> String {
    s.chars().take(MAX_NOTES_CHARS).collect()
}

#[derive(Deserialize)]
pub struct MemoryQuery {
    pub target: String,
}

#[derive(Deserialize)]
pub struct MemoryAccept {
    pub target: String,
    pub fingerprint: String,
    pub reason: String,
    /// Last day the acceptance holds, `YYYY-MM-DD`.
    pub expires: String,
}

#[derive(Deserialize)]
pub struct DiscoverQuery {
    pub target: String,
    #[serde(default, alias = "spec_url")]
    pub spec: Option<String>,
}

#[derive(Deserialize)]
pub struct DiscoverBody {
    pub target: String,
    #[serde(default, alias = "spec")]
    pub spec_url: Option<String>,
}

#[derive(Deserialize)]
pub struct CrawlQuery {
    pub target: String,
    #[serde(default)]
    pub max_pages: Option<usize>,
}

#[derive(Deserialize)]
pub struct CrawlBody {
    pub target: String,
    #[serde(default)]
    pub max_pages: Option<usize>,
}

/// `max_pages` default 25, hard maximum 100 (also bounds the work per request).
pub fn clamp_pages(p: Option<usize>) -> usize {
    p.unwrap_or(DEFAULT_CRAWL_PAGES).clamp(1, MAX_CRAWL_PAGES)
}

#[derive(Deserialize)]
pub struct RetestPayload {
    pub target: String,
    pub case: crate::agent::PlannedCase,
    #[serde(default)]
    pub is_spa: bool,
    #[serde(default)]
    pub run_id: Option<String>,
}

/// Why a retest was not run.
#[derive(Debug)]
pub enum RetestError {
    NoSuchRun,
    TargetMismatch,
}

#[derive(Deserialize)]
pub struct TriggerScanReq {
    pub target: String,
    #[serde(default = "default_profile_str")]
    pub profile: String,
}

pub fn default_profile_str() -> String {
    "quick".into()
}

#[derive(Deserialize)]
pub struct PrCommentPayload {
    /// Accepted for compatibility with older clients; the comment heading is fixed.
    #[serde(default)]
    #[allow(dead_code)]
    pub title: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub score: Option<i32>,
    #[serde(default)]
    pub commit_sha: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub findings_count: Option<usize>,
    #[serde(default)]
    pub ledger_conformance: Option<i32>,
    #[serde(default)]
    pub ledger_rbac: Option<i32>,
    #[serde(default)]
    pub ledger_resilience: Option<i32>,
    #[serde(default)]
    pub ledger_observability: Option<i32>,
}

#[derive(Deserialize)]
pub struct ApiEvalAiPayload {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub context: Option<String>,
    #[serde(default)]
    pub response: Option<String>,
    #[serde(default)]
    pub expected: Option<String>,
    #[serde(default)]
    pub trajectory: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub cases: Option<Vec<crate::eval_ai::AiTestCase>>,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default)]
    pub red_team: bool,
}

pub fn default_threshold() -> f64 {
    0.70
}

#[derive(Deserialize)]
pub struct ApiFixPayload {
    #[serde(default = "default_fix_repo")]
    pub repo: String,
    #[serde(default)]
    pub defect: Option<String>,
    #[serde(default)]
    pub run: Option<String>,
    #[serde(default = "default_fix_dry_run")]
    pub dry_run: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub verify: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub branch: Option<String>,
}

pub fn default_fix_repo() -> String {
    ".".into()
}

pub fn default_fix_dry_run() -> bool {
    true
}

#[derive(Deserialize)]
pub struct ApiMutatePayload {
    #[serde(default = "default_mutate_repo")]
    pub repo: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default = "default_max_mutants")]
    pub max_mutants: usize,
}

pub fn default_mutate_repo() -> String {
    ".".into()
}

pub fn default_max_mutants() -> usize {
    10
}

#[derive(Deserialize)]
pub struct BadgeQuery {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub score: Option<String>,
}
