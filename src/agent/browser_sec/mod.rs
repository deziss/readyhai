//! Browser & client-side security verification for ReadyHai Agent (Phase 5).
//!
//! Combines Playwright real-Chromium instrumentation (`agent_browser.mjs`, when Docker + image
//! exist) with deterministic offline HTML/DOM sink & Stored XSS verification:
//! - DOM XSS source-to-sink analysis (`oracle::has_dom_xss_sink_flow`) + `ProbeOracle::DomXss`
//! - Stored XSS HTML form/endpoint write -> unescaped HTML render verification (`StatefulStep`)
//! - Client-side secret/JWT storage leaks, cookie HttpOnly/Secure hygiene, `.js.map` exposure,
//!   and iframe clickjacking reports from Chromium (all raw secrets strictly redacted).

pub mod engine;
pub mod html_analyzer;
pub mod models;
pub mod playwright;
pub mod redact;
pub mod report_parser;

#[cfg(test)]
mod tests;

pub use engine::run_browser_security;
pub use models::*;
pub use report_parser::results_from_browser_report;
