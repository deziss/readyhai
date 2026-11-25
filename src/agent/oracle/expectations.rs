//! Expected status, behavior derivation, and HTTP status verification checks.

use super::super::triage::severity_for;
use super::super::types::PlannedCase;
use super::types::{Observation, OracleCheck, Technique, Verdict, chk};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Denied,
    Exact(u16),
    Success,
    ClientError,
    Redirect,
    Unspecified,
}

impl Expect {
    /// Exact 2xx expectations are satisfied by any 2xx (200 vs 201/204 is not a defect).
    pub fn min_exact(self, e: u16) -> Expect {
        if e == 200 {
            Expect::Success
        } else {
            Expect::Exact(e)
        }
    }
}

/// `expected_status` first; otherwise coarse classes parsed out of `expected_behavior`.
/// Ambiguous text ("encoded or blocked with 403") yields Unspecified rather than a guess.
pub fn derive_expectation(case: &PlannedCase, tech: Technique) -> Expect {
    if let Some(e) = case.expected_status {
        return match e {
            401 | 403 => Expect::Denied,
            300..=399 => Expect::Redirect,
            200..=299 => Expect::Success.min_exact(e),
            _ => Expect::Exact(e),
        };
    }
    if case.probe_oracle.is_some() && tech != Technique::Authz {
        return Expect::Unspecified;
    }
    let t = case.expected_behavior.to_ascii_lowercase();
    let has = |ws: &[&str]| ws.iter().any(|w| t.contains(w));
    let denied_words = has(&[
        "reject",
        "denied",
        "deny",
        "forbidden",
        "unauthori",
        "blocked",
        "refus",
        "not allowed",
        "4xx",
        "client error",
        "must be rejected",
    ]);
    let ok_words = has(&[
        "200",
        "2xx",
        "success",
        "succeed",
        "returns ok",
        "http ok",
        "valid response",
    ]);
    let tolerant = has(&[
        "encoded",
        "escaped",
        "sanitiz",
        "literally",
        "never evaluated",
        "not evaluated",
        "handled",
        "graceful",
        "without crash",
        "no crash",
        "cleanly",
        "safely",
        "no 5xx",
        "without 5xx",
        "not reflected",
    ]);
    if denied_words && !ok_words && !tolerant {
        if tech == Technique::Authz
            || has(&["401", "403", "unauthori", "forbidden", "denied"])
                && tech != Technique::Boundary
                && tech != Technique::Negative
                && tech != Technique::Injection
        {
            return Expect::Denied;
        }
        return Expect::ClientError;
    }
    if ok_words && !denied_words && !tolerant {
        return Expect::Success;
    }
    if has(&["redirect", "3xx"]) && !denied_words && !ok_words {
        return Expect::Redirect;
    }
    if tech == Technique::Authz && !ok_words {
        return Expect::Denied;
    }
    Expect::Unspecified
}

/// The case wants a redirect (expected 3xx, or its expected behaviour says so): the executor does
/// not follow one for it, the raw 3xx is the evidence.
pub fn expects_redirect(case: &PlannedCase) -> bool {
    derive_expectation(case, Technique::parse(&case.technique)) == Expect::Redirect
}

/// The case wants the request refused (401/403): the raw status is the evidence, so it is never
/// relabelled as an auth wall.
pub fn expects_denial(case: &PlannedCase) -> bool {
    derive_expectation(case, Technique::parse(&case.technique)) == Expect::Denied
}

/// 4xx statuses that mean "this input was rejected". 401/403 are the auth layer, 404/405/410 mean
/// the route or verb is not served, 408/429 are timeouts and rate limits: none of them shows that
/// input validation ran, so none of them is "rejected".
pub fn is_rejection(code: u16) -> bool {
    (400..=499).contains(&code) && !matches!(code, 401 | 403 | 404 | 405 | 408 | 410 | 429)
}

/// Why a 4xx says nothing about validation (None for a real rejection or a non-4xx status).
pub(crate) fn not_exercised(code: u16) -> Option<&'static str> {
    match code {
        401 | 403 => Some("refused at the auth layer"),
        404 | 410 => Some("route not served"),
        405 => Some("method not allowed"),
        408 | 429 => Some("timeout or rate limit"),
        _ => None,
    }
}

pub fn is_privileged_api_path(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or(path).to_ascii_lowercase();
    p.split('/')
        .map(|s| s.trim_matches(|c| c == '{' || c == '}'))
        .any(|seg| {
            matches!(
                seg,
                "admin"
                    | "internal"
                    | "staff"
                    | "superuser"
                    | "superadmin"
                    | "manage"
                    | "management"
                    | "roles"
                    | "permissions"
                    | "audit"
                    | "metrics"
                    | "debug"
            )
        })
}

pub(crate) fn is_rbac_scope_refusal(case: &PlannedCase, o: &Observation) -> bool {
    if !o.authenticated || o.status != 403 {
        return false;
    }
    let role_is_priv = case.role.as_deref().is_some_and(|r| {
        let up = r.to_ascii_uppercase();
        ["ADMIN", "ROOT", "SUPER", "SYSTEM", "STAFF"]
            .iter()
            .any(|p| up.contains(p))
    });
    if role_is_priv {
        return false;
    }
    is_privileged_api_path(&case.component)
        || case
            .contract
            .as_ref()
            .is_some_and(|c| c.responses.contains_key("403"))
}

pub(crate) fn expectation_checks(
    case: &PlannedCase,
    o: &Observation,
    tech: Technique,
    exp: Expect,
    out: &mut Vec<OracleCheck>,
) {
    let code = o.status;
    if (500..=599).contains(&code) {
        return; // reported by server_error
    }
    let unauth_denied = !o.authenticated && matches!(code, 401 | 403);
    let rbac_denied = is_rbac_scope_refusal(case, o);
    let rate_limited = code == 429;
    match exp {
        Expect::Unspecified | Expect::Denied => {}
        Expect::Exact(e) => {
            let v = if code == e {
                chk(
                    "expected_status",
                    Verdict::Pass,
                    None,
                    format!("HTTP {code} as expected"),
                )
            } else if unauth_denied {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!(
                        "expected HTTP {e} but the request was refused with {code}: no credential for this role (set RH_<ROLE>_TOKEN)"
                    ),
                )
            } else if rbac_denied && (200..=299).contains(&e) {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!(
                        "expected HTTP {e}, got HTTP 403 Forbidden for non-privileged role `{}` (supply an admin credential to verify privileged contract)",
                        case.role.as_deref().unwrap_or("user")
                    ),
                )
            } else if rate_limited {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!("expected HTTP {e} but the target rate-limited the request (429)"),
                )
            } else {
                chk(
                    "expected_status",
                    Verdict::Fail,
                    Some(severity_for("expected_status", tech)),
                    format!("expected HTTP {e}, got HTTP {code}"),
                )
            };
            out.push(v);
        }
        Expect::Success => {
            let v = if (200..=299).contains(&code) {
                chk(
                    "expected_status",
                    Verdict::Pass,
                    None,
                    format!("HTTP {code} (2xx) as expected"),
                )
            } else if unauth_denied {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!(
                        "expected success but refused with {code}: no credential for this role (set RH_<ROLE>_TOKEN)"
                    ),
                )
            } else if rbac_denied {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!(
                        "expected 2xx, got HTTP 403 Forbidden for non-privileged role `{}` (supply an admin credential to verify privileged contract)",
                        case.role.as_deref().unwrap_or("user")
                    ),
                )
            } else if rate_limited {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    "expected success but the target rate-limited the request (429)",
                )
            } else if (300..=399).contains(&code) {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!("expected 2xx, got redirect HTTP {code}"),
                )
            } else {
                chk(
                    "expected_status",
                    Verdict::Fail,
                    Some(severity_for("expected_status", tech)),
                    format!("expected 2xx, got HTTP {code}"),
                )
            };
            out.push(v);
        }
        Expect::ClientError => {
            let v = if let Some(why) = not_exercised(code) {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!(
                        "expected a 4xx validation rejection, got HTTP {code} ({why}): input validation was not exercised{}",
                        if unauth_denied {
                            " (no credential for this role, set RH_<ROLE>_TOKEN)"
                        } else {
                            ""
                        }
                    ),
                )
            } else if is_rejection(code) {
                chk(
                    "expected_status",
                    Verdict::Pass,
                    None,
                    format!("rejected with HTTP {code}"),
                )
            } else if (300..=399).contains(&code) {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!("expected a 4xx rejection, got redirect HTTP {code}"),
                )
            } else {
                chk(
                    "expected_status",
                    Verdict::Fail,
                    Some(severity_for("expected_status", tech)),
                    format!("invalid input was accepted: HTTP {code} instead of a 4xx rejection"),
                )
            };
            out.push(v);
        }
        Expect::Redirect => {
            let v = if (300..=399).contains(&code) {
                chk(
                    "expected_status",
                    Verdict::Pass,
                    None,
                    format!("redirected with HTTP {code}"),
                )
            } else if rate_limited {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    "expected a redirect but the target rate-limited the request (429)",
                )
            } else {
                chk(
                    "expected_redirect",
                    Verdict::Fail,
                    Some(severity_for("expected_redirect", tech)),
                    format!("expected a 3xx redirect, got HTTP {code}"),
                )
            };
            out.push(v);
        }
    }
    let _ = case;
}
