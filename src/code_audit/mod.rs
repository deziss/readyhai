//! Native Tree-sitter AST & cross-file security code auditor (Python, JS/TS, Go, PHP).
//!
//! Capabilities:
//! 1. True AST function, import, endpoint, guard-middleware, and local variable taint parsing via
//!    `tree-sitter` grammars (Python, JavaScript/JSX, TypeScript/TSX, Go, PHP).
//! 2. Cross-file import & call-graph traversal (up to 3 hops) linking route handlers to dangerous
//!    sinks (`SqlInjection`, `CommandExec`, `Ssrf`, `PathTraversal`, `ServerSideTemplate`) while
//!    ignoring parameterized/literal queries.
//! 3. Authentication middleware consistency checking (`security.auth.missing_guard`) across sibling
//!    endpoints in a protected service/prefix.
//! 4. Package import collection (`called_packages`) for supply-chain reachability enrichment.

pub mod ast;
pub mod audit;
pub mod classify;
pub mod go;
pub mod javascript;
pub mod php;
pub mod python;
pub mod types;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use audit::{audit_tree, audit_tree_filtered, called_packages, package_is_imported};
#[allow(unused_imports)]
pub use types::{CodeInventory, DiscoveredEndpoint, Lang, SinkHit, SinkKind};

use crate::checks::Check;
use crate::model::{Profile, TargetKind};

pub fn checks() -> Vec<Check> {
    vec![Check::new(
        "security.code_audit",
        "AST & cross-file security code audit (Python, JS/TS, Go, PHP)",
        &[TargetKind::Repo],
        Profile::Quick,
        audit::code_audit_check,
    )]
}
