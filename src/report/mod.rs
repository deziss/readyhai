//! Reports: HTML (auto-escaped, CSP, no JS), JSON, SARIF 2.1.0, JUnit XML; QA formats live in qa::report.

#![allow(unused_imports)]

pub mod common;
pub mod html;
pub mod junit;
pub mod pr;
pub mod sarif;
pub mod writer;

#[cfg(test)]
mod tests;

pub use common::{esc, is_component, sev_order, status_str, uri_escape};
pub use html::html;
pub use junit::{junit, junit_failure, junit_failure_case};
pub use pr::{pr_comment, PR_COMMENT_MARKER, PR_COMMENT_MAX};
pub use sarif::sarif;
pub use writer::write;
