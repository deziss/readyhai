//! Autonomous QA and production-readiness gate.
//!
//! Pipeline (see `pipeline`): Discovery -> Planner -> Explorer -> Triager -> Readiness gate -> sign-off.
//!
//! Design rules that every module follows:
//! * Verdicts are deterministic. `oracle` judges each HTTP observation (PASS/FAIL/INCONCLUSIVE),
//!   `triage` derives defects and severities from failed assertions, `ledger` computes pillars and the
//!   gate from a technique-coverage matrix. The LLM can add planned cases (validated), prose notes and an
//!   advisory opinion; its verdict can only make the gate stricter and its scores are clamped and advisory.
//! * Everything that reaches an LLM and came from the target (or an operator) goes through
//!   `crate::llm::untrusted` (SYSTEM preamble, redaction, fence, output cleaning, guard).
//! * A run has a `RunBudget` (steps, requests, wall clock, per-host rate) and honours `dry_run`.
//! * Test credentials come only from `RH_<ROLE>_TOKEN` environment variables (or `Credentials::with`);
//!   the server's own secrets are never attached to requests sent to targets.
//! * Nothing is invented: a pillar with no conclusive evidence is "not evaluated", an unreachable
//!   target is BLOCKED (never PASS), a missing IP is "not detected".

#![allow(dead_code, unused_imports)]

mod budget;
mod discover;
mod exec;
mod ledger;
mod oracle;
mod pipeline;
mod plan;
mod report;
mod store;
mod triage;
mod types;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use budget::{BudgetUsage, RunBudget};
pub use discover::{crawl_and_discover_routes, detect_target_tech, discover_routes};
#[allow(unused_imports)]
pub use exec::{execute_cases, execute_cases_with, Credentials, ExecOptions};
#[allow(unused_imports)]
pub use oracle::{OracleCheck, OracleOutcome, Severity, Verdict};
#[allow(unused_imports)]
pub use pipeline::{run_agentic_loop, run_agentic_loop_with, run_discovery_scan, LlmMode, RunOptions};
pub use report::{generate_agent_html_report, generate_agent_junit_report, generate_agent_markdown_report, generate_agent_report_formats, generate_agent_sarif_report};
pub use store::{agent_runs_dir, approve_agent_run, convert_engine_run_to_agent_report, delete_agent_run, list_agent_full_runs, list_agent_runs, load_agent_run, reject_agent_run, save_agent_run, update_run_case_result};
#[allow(unused_imports)]
pub use types::*;
