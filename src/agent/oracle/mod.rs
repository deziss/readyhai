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

pub use burst::{judge_burst, judge_burst_on_path, BurstFacts, BurstResponse};
pub use contract::{primary_object, traversal_signature};
pub use expectations::{
    derive_expectation, expects_denial, expects_redirect, is_privileged_api_path, is_rejection,
    Expect,
};
pub use judge::judge;
pub use signatures::{
    auth_wall_signal, disclosure_signature, has_dom_xss_sink_flow, has_password_field,
    is_login_location, is_sensitive_path, WallSignal,
};
pub use stateful::{judge_stateful, StatefulFacts};
pub use types::{
    is_cors_case, Observation, OracleCheck, OracleOutcome, ProbeEvidence, ProbeSnapshot, Severity,
    Technique, Verdict, CORS_PROBE_ORIGIN,
};
