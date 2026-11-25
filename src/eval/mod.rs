//! Evaluation harness: scores ReadyHai's QA engine and agent against fixtures with seeded defects.
//!
//! `readyhai eval` runs suites in `tests/eval/<suite>.toml` `k` times and reports, per suite:
//! recall, precision, false positives, pass^k, inconclusive rate and confidence of agent runs,
//! verdict stability and match, blockers, requests sent, and wall time.

#![allow(unused_imports)]

pub mod checks;
pub mod fixture;
pub mod parser;
pub mod report;
pub mod runner;
pub mod scoring;
pub mod types;

#[cfg(test)]
mod tests;

// Re-exports for clean API and 100% backward compatibility
pub use checks::{agent_stats, build_fixture_repo, change_checks, memory_checks};
pub use fixture::Fixture;
pub use parser::{load_suites, parse_suite};
pub use report::render_markdown;
pub use runner::run_eval;
pub use scoring::{glob_match, score_run, summarize_suite};
pub use types::{
    Allow, ChangeSpec, Check, EvalOpts, EvalSummary, Expect, MemorySpec, Observed, RepoSpec,
    RunScore, RunStats, SuiteKind, SuiteResult, SuiteSpec, TargetSpec, Thresholds,
    inconclusive_rate,
};
