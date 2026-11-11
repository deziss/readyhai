//! Autonomous QA and production-readiness gate.
//!
//! Pipeline (see `pipeline`): Discovery -> Planner -> Explorer -> Verifier -> Cleanup -> Triager -> Readiness gate -> sign-off.
//!
//! Design rules that every module follows:
//! * Verdicts are deterministic. `oracle` judges each HTTP observation (PASS/FAIL/INCONCLUSIVE),
//!   `triage` derives defects and severities from failed assertions, `ledger` computes pillars and the
//!   gate from a technique-coverage matrix. The LLM can add planned cases (validated) and prose notes
//!   and give an advisory opinion on the gate. That opinion is stored separately (`llm_advisory`, scores
//!   clamped) and NEVER changes the verdict: `gate_verdict` is the computed verdict, stricter or softer
//!   opinion alike.
//! * Everything that reaches an LLM and came from the target (or an operator) goes through
//!   `crate::llm::untrusted` (SYSTEM preamble, redaction, fence, output cleaning, guard).
//! * `verify` replays every FAIL k times (`READYHAI_VERIFY_K`, default 2, max 5, 0 = off) before triage: only a
//!   failure that reproduces stays a defect (confirmed = verified k/k, flaky high/critical = FAIL with a flag);
//!   one that does not reproduce is INCONCLUSIVE. Teardown confirms every 2xx DELETE with a GET.
//! * A run remembers its target (`memory`): known defects, flaky history, coverage. The planner uses it
//!   only to reorder cases and raise the verify k of flaky ones, never to skip a case or change a
//!   verdict; an explicit, unexpired acceptance is the one thing that lets a known defect through the gate.
//! * A run has a `RunBudget` (steps, requests, wall clock, per-host rate) and honours `dry_run`.
//! * Test credentials come only from `RH_<ROLE>_TOKEN` environment variables (or `Credentials::with`);
//!   the server's own secrets are never attached to requests sent to targets.
//! * Nothing is invented: a pillar with no conclusive evidence is "not evaluated", an unreachable
//!   target is BLOCKED (never PASS), a missing IP is "not detected".

#![allow(dead_code, unused_imports)]

pub mod attacks;
pub mod browser_sec;
mod budget;
pub mod change;
mod discover;
mod exec;
pub mod lead;
mod ledger;
pub mod memory;
pub mod mutation;
pub mod oast;
mod oracle;
mod pipeline;
mod plan;
pub mod react;
pub mod remediation;
mod report;
pub mod stateful;
mod store;
mod triage;
mod types;
pub mod verify;
pub mod whitebox;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use budget::{BudgetUsage, RunBudget};
pub use discover::{crawl_and_discover_routes, detect_target_tech, discover_routes};
#[allow(unused_imports)]
pub use exec::{Credentials, ExecOptions, execute_cases, execute_cases_with};
#[allow(unused_imports)]
pub use oracle::{OracleCheck, OracleOutcome, Severity, Verdict};
#[allow(unused_imports)]
pub use pipeline::{
    LlmMode, RunOptions, run_agentic_loop, run_agentic_loop_with, run_discovery_scan,
};
pub use report::{
    generate_agent_html_report, generate_agent_junit_report, generate_agent_markdown_report,
    generate_agent_report_formats, generate_agent_sarif_report,
};
pub use store::{
    SignOffRefused, agent_runs_dir, approve_agent_run, convert_engine_run_to_agent_report,
    delete_agent_run, list_agent_full_runs, list_agent_runs, load_agent_run, reject_agent_run,
    save_agent_run, update_run_case_result,
};
#[allow(unused_imports)]
pub use types::*;
