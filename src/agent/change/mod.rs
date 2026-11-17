//! Change-aware planning: which OpenAPI operations did the code diff touch?
//!
//! Deterministic, no LLM. `git diff --name-only <base>...HEAD` names the changed files; the route
//! extractors of the QA engine (`qa::suite::extract_routes`) read the routes those files declare;
//! a route is matched to a spec operation by its normalised path template (`qa::suite::route_segments`).

pub mod analyze;
pub mod git;
pub mod matcher;
pub mod models;
pub mod retriever;
pub mod validation;

#[cfg(test)]
pub(crate) mod testkit;

#[cfg(test)]
mod tests;

pub use analyze::{analyze, coverage, coverage_totals};
pub use models::*;
pub use retriever::{retrieve_context, retriever_from_env};
pub use validation::{resolve_repo, validate_diff_base, validate_request};
