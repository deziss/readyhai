//! Typed assertion oracle for security testing, invariant verification, and contract evaluation.
//!
//! Provides deterministic verdicts (PASS / FAIL / INCONCLUSIVE) with structured failure severities
//! across security techniques, contract conformance, stateful chains, and concurrency bursts.

pub mod access;
pub mod burst;
pub mod contract;
pub mod expectations;
pub mod judge;
pub mod probes;
pub mod signatures;
pub mod stateful;
pub mod types;

#[cfg(test)]
mod tests;

// Re-exports for backward-compatibility and clean module interface

pub use burst::{BurstFacts, BurstResponse, judge_burst, judge_burst_on_path};
pub use contract::{primary_object, traversal_signature};
pub use expectations::{
    Expect, derive_expectation, expects_denial, expects_redirect, is_privileged_api_path,
    is_rejection,
};
pub use judge::judge;
pub use signatures::{
    WallSignal, auth_wall_signal, disclosure_signature, has_dom_xss_sink_flow, has_password_field,
    is_login_location, is_sensitive_path,
};
pub use stateful::{StatefulFacts, judge_stateful};
pub use types::{
    CORS_PROBE_ORIGIN, Observation, OracleCheck, OracleOutcome, ProbeEvidence, ProbeSnapshot,
    Severity, Technique, Verdict, is_cors_case,
};
