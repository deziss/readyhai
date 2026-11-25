//! Stateful multi-actor and chain execution oracles (IDOR isolation, step sequence validation).

use super::super::triage::severity_for;
use super::expectations::not_exercised;
use super::types::{OracleOutcome, Severity, Technique, Verdict, chk, outcome};

/// What a two-actor stateful chain observed. The executor reports facts; the verdict (and its
/// severity, from `triage::severity_for`) is decided here.
#[derive(Debug, Clone)]
pub enum StatefulFacts {
    /// The creator made a resource; a second actor then tried to read it.
    CrossActor {
        second_actor_anon: bool,
        /// The access step is a safe (GET/HEAD/OPTIONS) request, so it may be re-run.
        safe_method: bool,
        /// Status of the creator reading its own resource at the same URL (control).
        owner_control: Option<u16>,
        second_status: u16,
        /// The same request sent without credentials (only when the second actor got 2xx).
        anon_status: Option<u16>,
        /// A second identical request by the second actor again returned 2xx.
        reproduced: Option<bool>,
    },
    /// A plain workflow chain: every step must answer its expected status.
    Workflow {
        /// (step, expected status, got) of the first step that did not match.
        failed_step: Option<(u32, Option<u16>, u16)>,
    },
    /// A prerequisite step failed; nothing about authorization was exercised.
    Setup {
        step: u32,
        status: Option<u16>,
        reason: String,
    },
    /// A stateful security invariant was triggered (e.g. persisted mass assignment or logic bypass).
    Violation {
        step: u32,
        code: String,
        severity: Severity,
        detail: String,
    },
}

pub fn judge_stateful(f: &StatefulFacts) -> OracleOutcome {
    let two = |c: u16| (200..=299).contains(&c);
    let inc = |code: &str, d: String| chk(code, Verdict::Inconclusive, None, d);
    let check = match f {
        StatefulFacts::Setup {
            step,
            status,
            reason,
        } => inc(
            "stateful_setup",
            format!(
                "prerequisite step {step} not met{}: {reason}",
                status.map(|s| format!(" (HTTP {s})")).unwrap_or_default()
            ),
        ),
        StatefulFacts::Violation {
            step,
            code,
            severity,
            detail,
        } => chk(
            code,
            Verdict::Fail,
            Some(*severity),
            format!("step {step} triggered security invariant violation: {detail}"),
        ),
        StatefulFacts::Workflow { failed_step: None } => chk(
            "expected_status",
            Verdict::Pass,
            None,
            "every step of the chain answered its expected status",
        ),
        StatefulFacts::Workflow {
            failed_step: Some((step, expected, got)),
        } => {
            if not_exercised(*got).is_some() || (300..=399).contains(got) {
                inc(
                    "expected_status",
                    format!(
                        "step {step} answered HTTP {got}: the chain was not exercised (route, credential or rate limit)"
                    ),
                )
            } else {
                chk(
                    "expected_status",
                    Verdict::Fail,
                    Some(severity_for("expected_status", Technique::StateTransition)),
                    match expected {
                        Some(e) => format!("step {step} expected HTTP {e}, got HTTP {got}"),
                        None => format!("step {step} failed with HTTP {got}"),
                    },
                )
            }
        }
        StatefulFacts::CrossActor {
            second_actor_anon,
            safe_method,
            owner_control,
            second_status,
            anon_status,
            reproduced,
        } => {
            let s = *second_status;
            match owner_control {
                None => inc(
                    "authz",
                    "the owner control read was not performed, so the second actor's answer cannot be attributed to isolation".into(),
                ),
                Some(c) if !two(*c) => inc(
                    "authz",
                    format!(
                        "owner control read returned HTTP {c}: the resource is not readable by its creator at this path, so the second actor's answer says nothing about isolation"
                    ),
                ),
                Some(_) if two(s) => {
                    if !*safe_method {
                        inc(
                            "authz",
                            format!(
                                "the state-changing access step answered HTTP {s}; it cannot be re-run safely to confirm, check it manually"
                            ),
                        )
                    } else if anon_status.is_some_and(two) {
                        inc(
                            "authz",
                            format!(
                                "HTTP {s} for the second actor, but the same request without credentials also succeeds: this looks like a public resource, not an isolation breach"
                            ),
                        )
                    } else {
                        match reproduced {
                            Some(true) => chk(
                                "authz",
                                Verdict::Fail,
                                Some(severity_for("authz", Technique::Authz)),
                                format!(
                                    "a second actor read another actor's resource (HTTP {s}, reproduced on a safe re-run, not readable without credentials)"
                                ),
                            ),
                            Some(false) => inc(
                                "authz",
                                format!(
                                    "HTTP {s} for the second actor did not reproduce on a safe re-run"
                                ),
                            ),
                            None => inc(
                                "authz",
                                format!(
                                    "HTTP {s} for the second actor was not confirmed by a re-run"
                                ),
                            ),
                        }
                    }
                }
                Some(c) => match s {
                    404 | 410 => chk(
                        "authz",
                        Verdict::Pass,
                        None,
                        format!(
                            "resource hidden from the second actor (HTTP {s}) while its owner reads it (HTTP {c})"
                        ),
                    ),
                    401 | 403 if *second_actor_anon => chk(
                        "authz",
                        Verdict::Pass,
                        None,
                        format!(
                            "denied without credentials (HTTP {s}) while the owner reads the resource (HTTP {c})"
                        ),
                    ),
                    401 | 403 => inc(
                        "authz",
                        format!(
                            "HTTP {s} for the second actor cannot be told apart from an invalid or under-scoped credential: not counted as isolation evidence"
                        ),
                    ),
                    429 => inc(
                        "authz",
                        "the second actor's request was rate-limited (429)".into(),
                    ),
                    300..=399 => inc(
                        "authz",
                        format!("the second actor was redirected (HTTP {s})"),
                    ),
                    _ => inc(
                        "authz",
                        format!("HTTP {s} for the second actor: isolation was not exercised"),
                    ),
                },
            }
        }
    };
    outcome(vec![check], vec![])
}
