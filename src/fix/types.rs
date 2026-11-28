//! Data types and configuration options for the Agentic Fixer.

use std::path::PathBuf;

use clap::Args;
use serde::{Deserialize, Serialize};

use crate::model::Severity;

#[derive(Args, Debug, Clone, Serialize, Deserialize)]
pub struct FixOpts {
    /// Path to repository root (defaults to current directory)
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    /// Filter to specific defect ID or finding rule (e.g. D-001, security.auth.missing_guard, security.taint.sql_injection)
    #[arg(long)]
    pub defect: Option<String>,

    /// Run ID to load findings from runs/<ID>/run.json or artifacts/evidence_ledger.json
    #[arg(long)]
    pub run: Option<String>,

    /// Preview synthesized patches and verification plan without modifying files on disk
    #[arg(long)]
    pub dry_run: bool,

    /// Run the repository's test suite against each patch and roll it back if it fails
    /// (default: true). Only detects regressions the suite itself covers.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub verify: bool,

    /// Create local git branch with verified fix and commit message (never pushed)
    #[arg(long)]
    pub branch: Option<String>,

    /// Output format: text (terminal summary), json, or markdown (PR description)
    #[arg(long, default_value = "text")]
    pub format: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchStatus {
    /// Patch text was built; nothing was run against it.
    Synthesized,
    /// The repository's test suite passed with the patch applied.
    Verified,
    VerificationFailed,
    /// Written to disk after the suite passed.
    Applied,
    /// Written to disk **without** any suite run (`--verify` off, or no supported runner found).
    /// Distinct from `Applied` so a report can never count an unchecked patch as checked.
    AppliedWithoutVerification,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetDefect {
    pub id: String,
    pub rule: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub title: String,
    pub component: String,
    pub reproduction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRemediation {
    pub defect_id: String,
    pub rule: String,
    pub file_path: String,
    pub line: usize,
    /// The single source line as it was before the fix, for display.
    pub original_snippet: String,
    /// The single source line after the fix, for display only. Writing this to disk would replace
    /// the whole file with one line — use `patched_content` for that.
    pub patched_snippet: String,
    /// Complete file content with the fix applied. This is what is written to disk.
    pub patched_content: String,
    pub unified_diff: String,
    pub rationale: String,
    pub status: PatchStatus,
    pub verification_runner: Option<String>,
    pub verification_duration_ms: Option<u128>,
    pub error_log: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixReport {
    pub repo: String,
    pub total_defects_evaluated: usize,
    pub patches_synthesized: usize,
    /// Patches whose *test-suite* run passed after the patch was applied on disk. A green suite
    /// says the suite still passes; it does not establish the absence of regressions the suite
    /// does not cover, so nothing here claims that.
    pub patches_verified: usize,
    /// Patches that reached disk (or the report) **without** any test-suite verification, because
    /// `--verify` was off or no supported test runner was detected. Kept separate from
    /// `patches_verified` on purpose: these were never checked, and a report that folded them into
    /// the verified count would claim a check that never ran.
    pub patches_unverified: usize,
    pub patches_applied: usize,
    pub branch_created: Option<String>,
    pub commit_sha: Option<String>,
    pub patches: Vec<PatchRemediation>,
    pub pr_title: String,
    pub pr_body: String,
}
