//! Core types for the typed assertion oracle: verdicts, severities, techniques, checks, and observations.

use super::super::types::PlannedCase;
use serde::{Deserialize, Serialize};

/// Snapshot of a companion request sent by the executor/verifier (`baseline` or `false` control).
#[derive(Debug, Clone, Default)]
pub struct ProbeSnapshot {
    pub status: u16,
    pub body: String,
    pub latency_ms: u64,
}

/// Companion evidence gathered alongside the primary response for specialized verification oracles.
#[derive(Debug, Clone, Default)]
pub struct ProbeEvidence {
    pub baseline: Option<ProbeSnapshot>,
    pub control: Option<ProbeSnapshot>,
    pub oast_hit: bool,
    pub oast_detail: Option<String>,
    pub oast_unavailable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Inconclusive => "INCONCLUSIVE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    pub fn priority(self) -> &'static str {
        match self {
            Severity::Critical => "P0",
            Severity::High => "P1",
            Severity::Medium => "P2",
            Severity::Low => "P3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Technique {
    Authz,
    Boundary,
    Negative,
    Injection,
    StateTransition,
    Other,
}

impl Technique {
    pub fn parse(s: &str) -> Technique {
        match s.trim().to_ascii_lowercase().as_str() {
            "authz" | "auth_matrix" | "authorization" | "authz_matrix" => Technique::Authz,
            "boundary" => Technique::Boundary,
            "negative" => Technique::Negative,
            "injection" | "sqli" | "ssti" | "xss" | "sql_injection" => Technique::Injection,
            "state_transition" | "state" | "liveness" => Technique::StateTransition,
            _ => Technique::Other,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Technique::Authz => "authz",
            Technique::Boundary => "boundary",
            Technique::Negative => "negative",
            Technique::Injection => "injection",
            Technique::StateTransition => "state_transition",
            Technique::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleCheck {
    pub code: String,
    pub verdict: Verdict,
    #[serde(default)]
    pub severity: Option<Severity>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleOutcome {
    pub verdict: Verdict,
    pub checks: Vec<OracleCheck>,
    /// Advisory findings that do not fail the case (the case is reported as WARN).
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The case was proposed by the LLM. Its own expectations (expected status, content type) are
    /// not evidence, so only deterministic invariant checks can fail it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exploratory: bool,
}

impl OracleOutcome {
    pub fn max_fail_severity(&self) -> Option<Severity> {
        self.checks
            .iter()
            .filter(|c| c.verdict == Verdict::Fail)
            .filter_map(|c| c.severity)
            .max()
    }
    pub fn first_fail(&self) -> Option<&OracleCheck> {
        // the most severe failing check leads
        self.checks
            .iter()
            .filter(|c| c.verdict == Verdict::Fail)
            .max_by_key(|c| c.severity)
    }
    /// One-line reason for the report.
    pub fn reason(&self) -> Option<String> {
        let pick = |v: Verdict| -> Vec<&str> {
            self.checks
                .iter()
                .filter(|c| c.verdict == v)
                .map(|c| c.detail.as_str())
                .collect()
        };
        let f = pick(Verdict::Fail);
        if !f.is_empty() {
            return Some(f.join("; "));
        }
        let i = pick(Verdict::Inconclusive);
        if !i.is_empty() {
            return Some(i.join("; "));
        }
        if !self.warnings.is_empty() {
            return Some(self.warnings.join("; "));
        }
        None
    }
}

/// What the executor saw. Borrowed so judging never copies bodies.
pub struct Observation<'a> {
    pub status: u16,
    pub content_type: &'a str,
    /// Lower-cased header names.
    pub headers: &'a [(String, String)],
    /// Response body (capped by the executor).
    pub body: &'a str,
    /// Decoded query/body values we sent (used for reflection checks).
    pub sent_values: &'a [String],
    pub is_spa_shell: bool,
    /// A credential was attached to the request.
    pub authenticated: bool,
    pub https: bool,
    /// Request body as sent (JSON or form), for the mass-assignment reflection check.
    pub request_body: Option<&'a str>,
    /// `Origin` header sent with the request (CORS probe), if any.
    pub origin: Option<&'a str>,
    /// How long the response took, in milliseconds.
    pub latency_ms: u64,
    /// Optional companion evidence (baseline, differential control, OAST hit) for specialized oracles.
    pub probe: Option<&'a ProbeEvidence>,
}

/// Foreign origin sent by the CORS probe. `.invalid` can never be a real site.
pub const CORS_PROBE_ORIGIN: &str = "https://readyhai-cors-probe.invalid";

/// A CORS probe is an OPTIONS case whose title/hint says so. The executor sends `Origin` for it
/// and the oracle judges the `Access-Control-Allow-Origin` answer, not the status class.
pub fn is_cors_case(case: &PlannedCase) -> bool {
    case.method.trim().eq_ignore_ascii_case("OPTIONS")
        && (case.title.to_ascii_lowercase().contains("cors")
            || case.input_hint.to_ascii_lowercase().contains("cors"))
}

pub(crate) fn chk(
    code: &str,
    verdict: Verdict,
    severity: Option<Severity>,
    detail: impl Into<String>,
) -> OracleCheck {
    OracleCheck {
        code: code.into(),
        verdict,
        severity,
        detail: detail.into(),
    }
}

pub(crate) fn outcome(checks: Vec<OracleCheck>, warnings: Vec<String>) -> OracleOutcome {
    let verdict = if checks.iter().any(|c| c.verdict == Verdict::Fail) {
        Verdict::Fail
    } else if checks.iter().any(|c| c.verdict == Verdict::Inconclusive) {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    };
    OracleOutcome {
        verdict,
        checks,
        warnings,
        exploratory: false,
    }
}
