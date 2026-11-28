//! Agentic Fixer: AST-grounded vulnerability & defect remediation, local test
//! verification sandbox, and automated Pull Request generation.
//!
//! Capabilities:
//! 1. AST-grounded code patching for missing auth guards, SQL injection, path traversal,
//!    command injection, CORS wildcards, and hardcoded secrets.
//! 2. Sibling guard mining: examines protected routes in the repository to discover and
//!    reuse project-specific authentication middleware identifiers.
//! 3. Test-Before-PR verification sandbox: automatically detects project test runners
//!    (`cargo test`, `npm test`, `pytest`, `go test`), applies patches, and automatically
//!    rolls back if tests fail. That bounds *regressions the suite can detect* — it is not a
//!    guarantee of zero regressions for behavior the suite does not cover.
//! 4. Automated Git branch creation & commit authoring (strict local-only push policy).
//! 5. Evidence Ledger-backed Pull Request markdown synthesis with unified diffs and curl proofs.

#![allow(unused_imports)]

pub mod defects;
pub mod diff;
pub mod git;
pub mod pr;
pub mod remediate;
pub mod runner;
pub mod sandbox;
pub mod sibling;
pub mod types;

#[cfg(test)]
mod tests;

pub use defects::collect_target_defects;
pub use diff::compute_unified_diff;
pub use git::commit_local_branch;
pub use pr::generate_pr_markdown;
pub use remediate::synthesize_remediation;
pub use runner::run;
pub use sandbox::{detect_test_runner, verify_in_sandbox};
pub use sibling::mine_sibling_guards;
pub use types::{FixOpts, FixReport, PatchRemediation, PatchStatus, TargetDefect};
