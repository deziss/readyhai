//! Access control verification: sensitive resource exposure, authorization denial checks, and CORS policy enforcement.

use super::super::triage::severity_for;
use super::super::types::PlannedCase;
use super::signatures::{is_login_location, looks_like_secret_or_config};
use super::types::{Observation, OracleCheck, Technique, Verdict, chk};

pub(crate) fn sensitive_checks(case: &PlannedCase, o: &Observation, out: &mut Vec<OracleCheck>) {
    let code = o.status;
    let html = o.content_type.to_ascii_lowercase().contains("html");
    if (200..=299).contains(&code) && !html && looks_like_secret_or_config(o.body) {
        out.push(chk(
            "sensitive_exposure",
            Verdict::Fail,
            Some(severity_for("sensitive_exposure", Technique::Other)),
            format!(
                "{} is publicly readable (HTTP {code}) and contains secret/configuration-looking content",
                case.component.split('?').next().unwrap_or("")
            ),
        ));
    } else if (200..=299).contains(&code) {
        out.push(chk(
            "sensitive_exposure",
            Verdict::Pass,
            None,
            format!(
                "HTTP {code} without secret-looking content{}",
                if html {
                    " (HTML page, not the file)"
                } else {
                    ""
                }
            ),
        ));
    } else {
        out.push(chk(
            "sensitive_exposure",
            Verdict::Pass,
            None,
            format!("not exposed: HTTP {code}"),
        ));
    }
}

pub(crate) fn denied_check(
    case: &PlannedCase,
    o: &Observation,
    tech: Technique,
    out: &mut Vec<OracleCheck>,
) {
    let code = o.status;
    let protected = case.secured == Some(true) || matches!(case.route_status, Some(401 | 403));
    let forged = case
        .role
        .as_deref()
        .is_some_and(|r| r.eq_ignore_ascii_case("forged"));
    let c = match code {
        401 | 403 => chk(
            "authz",
            Verdict::Pass,
            None,
            format!("denied with HTTP {code}"),
        ),
        404 | 410 => chk(
            "authz",
            Verdict::Inconclusive,
            None,
            format!("HTTP {code}: route not served, authorization was not exercised"),
        ),
        300..=399 => {
            let loc = o
                .headers
                .iter()
                .find(|(k, _)| k == "location")
                .map(|(_, v)| v.to_ascii_lowercase())
                .unwrap_or_default();
            if is_login_location(&loc) {
                chk(
                    "authz",
                    Verdict::Pass,
                    None,
                    format!("redirected to an authentication page (HTTP {code})"),
                )
            } else {
                chk(
                    "authz",
                    Verdict::Inconclusive,
                    None,
                    format!(
                        "HTTP {code} redirect that does not look like an authentication redirect"
                    ),
                )
            }
        }
        200..=299 => {
            if o.is_spa_shell {
                chk(
                    "authz",
                    Verdict::Inconclusive,
                    None,
                    "SPA shell served for the route; server-side authorization is not observable from the HTML shell",
                )
            } else if protected {
                chk(
                    "authz",
                    Verdict::Fail,
                    Some(severity_for("authz", tech)),
                    if forged {
                        format!(
                            "forged token accepted: HTTP {code} on a route that requires credentials"
                        )
                    } else {
                        format!(
                            "HTTP {code} without valid credentials on a route that requires them"
                        )
                    },
                )
            } else {
                chk(
                    "authz",
                    Verdict::Inconclusive,
                    None,
                    format!(
                        "HTTP {code} without credentials, but nothing (spec or discovery) says this route must be protected"
                    ),
                )
            }
        }
        _ => chk(
            "authz",
            Verdict::Inconclusive,
            None,
            format!("HTTP {code}: authorization was not exercised"),
        ),
    };
    out.push(c);
}

/// Judge the answer to a request that carried a foreign `Origin`.
pub(crate) fn cors_check(o: &Observation, out: &mut Vec<OracleCheck>, warnings: &mut Vec<String>) {
    let Some(origin) = o.origin else {
        out.push(chk(
            "cors",
            Verdict::Inconclusive,
            None,
            "no Origin header was sent, so the CORS policy was not exercised",
        ));
        return;
    };
    let hdr = |name: &str| {
        o.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.trim().to_string())
    };
    let acao = hdr("access-control-allow-origin");
    let creds =
        hdr("access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let code = o.status;
    let fail = |what: String| {
        let c = if creds { "cors_credentialed" } else { "cors" };
        chk(
            "cors",
            Verdict::Fail,
            Some(severity_for(c, Technique::Authz)),
            format!(
                "{what}{}",
                if creds {
                    " together with Access-Control-Allow-Credentials: true"
                } else {
                    ""
                }
            ),
        )
    };
    out.push(match acao.as_deref() {
        Some(a) if a == origin => fail(format!(
            "Access-Control-Allow-Origin reflects the foreign Origin '{origin}'"
        )),
        Some(a) if a.eq_ignore_ascii_case("null") => {
            fail("Access-Control-Allow-Origin allows the opaque origin 'null'".into())
        }
        Some("*") if creds => chk(
            "cors",
            Verdict::Fail,
            Some(severity_for("cors", Technique::Authz)),
            "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true",
        ),
        Some("*") => {
            warnings.push(
                "Access-Control-Allow-Origin: * (any site may read responses; acceptable only for public, credential-less resources)"
                    .into(),
            );
            chk(
                "cors",
                Verdict::Pass,
                None,
                "wildcard origin without credentials",
            )
        }
        Some(a) => chk(
            "cors",
            Verdict::Pass,
            None,
            format!(
                "the foreign Origin was not granted (allowed origin: {})",
                crate::llm::untrusted::redact_then_truncate(a, 80)
            ),
        ),
        None if (200..=299).contains(&code) || matches!(code, 400 | 401 | 403) => chk(
            "cors",
            Verdict::Pass,
            None,
            format!("HTTP {code} without Access-Control-Allow-Origin: the foreign Origin was not granted"),
        ),
        None => chk(
            "cors",
            Verdict::Inconclusive,
            None,
            format!(
                "HTTP {code} without Access-Control-Allow-Origin: route or verb not served, the CORS policy was not exercised"
            ),
        ),
    });
}
