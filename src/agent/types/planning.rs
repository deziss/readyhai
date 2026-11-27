//! Test case planning, probe oracles, contracts, and scheduling prioritization.

use serde::{Deserialize, Serialize};

use super::defaults::{default_method, default_oast_wait_ms};
use super::execution::StatefulStep;

/// What the spec documents about the responses of a case's operation. It travels with the case,
/// so the oracle and every verifier replay judge against the same contract without the spec.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResponseContract {
    /// Documented statuses ("200", "2XX", "default") to the JSON schema of a 2xx body. Only 2xx
    /// bodies are validated, so other statuses carry just their key.
    pub responses: crate::qa::api::contract::Responses,
    /// A plain read: its latency is judged against the QA engine's threshold
    /// (`qa::api::latency`).
    #[serde(default)]
    pub latency: bool,
}

/// Optional deterministic differential / timing / template / redirect / OAST verification oracle
/// attached to a [`PlannedCase`], executed identically during exploration and verification replays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeOracle {
    BooleanDiff {
        baseline_payload: String,
        false_payload: String,
    },
    TimeDelay {
        baseline_payload: String,
        min_delay_ms: u64,
    },
    Ssti {
        expected_eval: String,
    },
    OpenRedirect {
        canary_host: String,
    },
    OastCallback {
        placeholder: String,
        #[serde(default = "default_oast_wait_ms")]
        wait_ms: u64,
    },
    ExcessiveDataExposure,
    GraphqlIntrospection,
    DomXss {
        #[serde(default)]
        canary: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedCase {
    pub id: String,
    pub title: String,
    pub component: String,
    #[serde(default = "default_method")]
    pub method: String, // GET | HEAD | OPTIONS | POST | PUT | PATCH | DELETE
    pub technique: String, // boundary | negative | authz | state_transition | injection
    pub input_hint: String,
    /// For GET/HEAD/OPTIONS this becomes the query string (JSON object or k=v&k2=v2 or free text -> q=);
    /// for body methods it is the request body.
    #[serde(default)]
    pub payload: Option<String>,
    /// Custom request headers attached to the request (excluding credential overrides).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// Explicit Content-Type override for the request body (validated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Optional specialized verification oracle (differential, timing, SSTI, redirect, OAST, PII).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_oracle: Option<ProbeOracle>,
    pub expected_behavior: String,
    #[serde(default)]
    pub expected_status: Option<u16>,
    pub risk_level: String, // critical | high | medium | low
    /// Credential role: anon | forged | user | admin | ... (token from RH_<ROLE>_TOKEN). None = infer.
    #[serde(default)]
    pub role: Option<String>,
    /// Spec says this operation needs credentials (Some(true)) / is public (Some(false)).
    #[serde(default)]
    pub secured: Option<bool>,
    /// Status seen for this route during discovery (no credentials).
    #[serde(default)]
    pub route_status: Option<u16>,
    /// Response fields the spec marks required (contract check).
    #[serde(default)]
    pub expect_fields: Vec<String>,
    #[serde(default)]
    pub expected_content_type: Option<String>,
    /// deterministic | openapi | llm
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub stateful_steps: Option<Vec<StatefulStep>>,
    #[serde(default)]
    pub concurrency_burst: Option<u32>,
    /// The response contract of the operation (see [`ResponseContract`]): documented statuses,
    /// 2xx body schema, latency. Planned from the spec only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ResponseContract>,
    /// The changed operations (`GET /search`) this case tests, when the run is change-aware. A
    /// case with an entry here is planned first and dropped last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_ops: Vec<String>,
    /// The area worker that runs this case: `auth`, `contract`, `state` or `ui` (see `lead::Area`).
    /// Set by the planner; a plan from an older build has none and the lead classifies the case.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub area: String,
    /// Fingerprints of the known defects (the agent's memory of this target) this case re-tests:
    /// it belongs to the failing case class of an open or recently fixed defect. Set by the
    /// planner, which puts these cases first so the report can say still open or fixed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regression_of: Vec<String>,
    /// The operation failed, or was flaky, in an earlier run: planned early. Only ever reorders,
    /// it never removes or adds a case.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub history_priority: bool,
    /// Why this case runs early because of the run's project intelligence (the vulnerability
    /// database and the opt-in exploitation engine): the planner writes
    /// [`INTEL_REPRODUCED`]<rule> when the case re-tests a finding that safe templates
    /// re-confirmed live this run, or [`INTEL_OPEN`]<rule> when it relates to a finding the
    /// database still holds open. Advisory priority only — it reorders, never adds, drops or
    /// reclassifies anything, and no verdict reads it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub intel_note: String,
}

/// [`PlannedCase::intel_note`] prefix: the finding was re-confirmed live this run.
pub const INTEL_REPRODUCED: &str = "re-tests reproduced finding ";
/// [`PlannedCase::intel_note`] prefix: the finding is merely known-open in the database.
pub const INTEL_OPEN: &str = "re-tests known-open finding ";

/// Intel tier of a case: 0 re-tests a finding reproduced live right now, 1 relates to a
/// known-open database finding, 2 neither. Feeds [`plan_order`]: a live weakness outranks a
/// merely-known one, which outranks the memory's regression probes.
pub fn intel_rank(c: &PlannedCase) -> u8 {
    if c.intel_note.starts_with(INTEL_REPRODUCED) {
        0
    } else if c.intel_note.starts_with(INTEL_OPEN) {
        1
    } else {
        2
    }
}

/// `PlannedCase::source` of a planner-made ledger row that sends nothing: no technique has a
/// surface on the discovered routes. The executor turns it into a NOT_APPLICABLE result
/// (`BlockReason::NoSurface`) without a request, a step or any budget.
pub const SRC_NOT_APPLICABLE: &str = "ledger:not_applicable";
/// Same, for routes behind a login wall with no credential to get past it: a BLOCKED result
/// (`BlockReason::AuthWall`).
pub const SRC_AUTH_WALL: &str = "ledger:auth_wall";

impl PlannedCase {
    /// A planner-made ledger row (see [`SRC_NOT_APPLICABLE`], [`SRC_AUTH_WALL`]), not a request.
    pub fn is_ledger_row(&self) -> bool {
        matches!(
            self.source.as_deref(),
            Some(SRC_NOT_APPLICABLE) | Some(SRC_AUTH_WALL)
        )
    }
}

pub fn profile_case_cap(profile: &str) -> Option<usize> {
    match profile.trim().to_ascii_lowercase().as_str() {
        "quick" => Some(20),
        _ => None,
    }
}

/// Sort key: lower runs first and is dropped last. Access control (auth), stateful scenarios and
/// OpenAPI-derived cases outrank generic probes; the root liveness probe is always kept.
pub fn case_priority(c: &PlannedCase) -> (u8, u8) {
    let class = if c.technique == "authz"
        || c.technique == "injection"
        || c.component == "/"
        || c.source.as_deref() == Some("directives")
    {
        0
    } else if c.stateful_steps.as_ref().is_some_and(|s| !s.is_empty())
        || c.concurrency_burst.is_some_and(|b| b > 1)
    {
        1
    } else if c.source.as_deref() == Some("openapi") {
        2
    } else if c.is_ledger_row() {
        3
    } else if c.source.as_deref() == Some("llm") {
        5
    } else {
        4
    };
    let risk = match c.risk_level.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    (class, risk)
}

/// The sort key of a plan that has to be cut or ordered. With nothing to prioritise (`any_priority`
/// false) every case shares one tier, so the key reduces to [`case_priority`]. Otherwise the cases
/// that re-test a finding the run reproduced live come first, then the cases that re-test a past
/// defect (memory regression probes — the agent's own remembered reproduction always outranks
/// advisory database context), then those related to a merely-known-open database finding, then
/// every case that tests a changed operation or one with a failing or flaky past (and the root
/// liveness probe, which is always kept), then the rest, each tier by [`case_priority`]. So
/// truncation drops unchanged, never-failed operations with no open finding first. With no intel
/// markers anywhere the relative order is exactly what it was before the intel tiers existed.
pub fn plan_order(any_priority: bool) -> impl Fn(&PlannedCase) -> (u8, u8, u8) {
    move |c| {
        let (class, risk) = case_priority(c);
        let tier = match intel_rank(c) {
            0 => 0,
            _ if !c.regression_of.is_empty() => 1,
            1 => 2,
            _ if !any_priority
                || !c.changed_ops.is_empty()
                || c.history_priority
                || c.source.as_deref() == Some("directives")
                || c.technique == "authz"
                || c.technique == "injection"
                || c.component == "/" =>
            {
                3
            }
            _ => 4,
        };
        (tier, class, risk)
    }
}

/// Does any case of the plan test a changed operation?
pub fn any_changed(cases: &[PlannedCase]) -> bool {
    cases.iter().any(|c| !c.changed_ops.is_empty())
}

/// Does any case of the plan have a reason to run early: a changed operation, a failing or flaky
/// past, a known defect to re-test, or a related open/reproduced finding? Feeds [`plan_order`].
pub fn any_prioritised(cases: &[PlannedCase]) -> bool {
    cases.iter().any(|c| {
        !c.changed_ops.is_empty()
            || c.history_priority
            || !c.regression_of.is_empty()
            || !c.intel_note.is_empty()
    })
}
