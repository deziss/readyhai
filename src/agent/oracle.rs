//! Typed assertion oracle: turns one HTTP observation plus the planned case into PASS / FAIL /
//! INCONCLUSIVE checks. Deterministic: no LLM input is consulted, and no check depends on a
//! handful of fixed JSON key names (structure and status semantics only).
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use super::triage::severity_for;
use super::types::{PlannedCase, RedirectHop, ResponseContract};
use crate::qa::api::{contract, latency};

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
            "injection" => Technique::Injection,
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

fn chk(
    code: &str,
    verdict: Verdict,
    severity: Option<Severity>,
    detail: impl Into<String>,
) -> OracleCheck {
    OracleCheck {
        code: code.to_string(),
        verdict,
        severity,
        detail: detail.into(),
    }
}

fn re(cell: &'static OnceLock<Regex>, p: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(p).unwrap())
}

/// A stack trace / SQL error / internal path in a response body: the QA engine's catalog
/// (`qa::api::contract::leak_kind`), worded for a report.
pub fn disclosure_signature(body: &str) -> Option<&'static str> {
    contract::leak_kind(body).map(contract::leak_description)
}

pub fn is_sensitive_path(component: &str) -> bool {
    let path = component
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if path.starts_with("/.well-known") {
        return false;
    }
    path.contains("/.")
        || [
            "phpinfo",
            "/actuator",
            "server-status",
            "wp-config",
            "id_rsa",
            ".bak",
            ".sql",
            ".old",
            "/debug",
        ]
        .iter()
        .any(|k| path.contains(k))
}

fn looks_like_secret_or_config(body: &str) -> bool {
    let head = body.trim_start();
    let lower = head
        .get(..head.len().min(64))
        .unwrap_or("")
        .to_ascii_lowercase();
    if lower.starts_with("<!") || lower.starts_with("<html") {
        return false;
    }
    static KV: OnceLock<Regex> = OnceLock::new();
    re(
        &KV,
        r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*\S",
    )
    .is_match(body)
        || body.contains("[core]")
        || body.contains("repositoryformatversion")
        || body.contains("PHP Version")
        || body.contains("<?php")
        || crate::llm::redact_for_llm(body) != body
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Denied,
    Exact(u16),
    Success,
    ClientError,
    Redirect,
    Unspecified,
}

/// `expected_status` first; otherwise coarse classes parsed out of `expected_behavior`.
/// Ambiguous text ("encoded or blocked with 403") yields Unspecified rather than a guess.
fn derive_expectation(case: &PlannedCase, tech: Technique) -> Expect {
    if let Some(e) = case.expected_status {
        return match e {
            401 | 403 => Expect::Denied,
            300..=399 => Expect::Redirect,
            200..=299 => Expect::Success.min_exact(e),
            _ => Expect::Exact(e),
        };
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

impl Expect {
    /// Exact 2xx expectations are satisfied by any 2xx (200 vs 201/204 is not a defect).
    fn min_exact(self, e: u16) -> Expect {
        if e == 200 {
            Expect::Success
        } else {
            Expect::Exact(e)
        }
    }
}

/// Is this redirect target (a `Location` value, relative or absolute) a login / sign-in / SSO /
/// OAuth page? Matched on whole words of the host and path (the query string is ignored, so
/// `/dashboard?next=/login` is not a login page and `/authors` is not an auth page). The one
/// matcher behind the authz oracle, the executor's auth-wall detection and the planner.
pub fn is_login_location(loc: &str) -> bool {
    let l = loc.trim().to_ascii_lowercase();
    let base = l.split(['?', '#']).next().unwrap_or("");
    let words: Vec<&str> = base
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let word = |w: &str| {
        w.contains("login")
            || w.contains("signin")
            || w.contains("oauth")
            || w.contains("openid")
            || matches!(w, "logon" | "sso" | "saml" | "auth" | "authn" | "adfs")
            || w.starts_with("authenticat")
            || w.starts_with("authoriz")
            // auth0, auth2 ... but not author, authors, authority
            || (w.starts_with("auth") && w[4..].chars().all(|c| c.is_ascii_digit()))
    };
    words.iter().any(|w| word(w)) || words.windows(2).any(|p| p[0] == "sign" && p[1] == "in")
}

/// Does an HTML body hold a password input: the page asks for credentials.
pub fn has_password_field(body: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r#"(?i)<input\b[^>]*\btype\s*=\s*["']?password"#).is_match(body)
}

/// Why a response says "you need to log in" and whether the page the case targeted was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WallSignal {
    /// What was seen, for the report ("HTTP 307 redirect to a login page (/login)").
    pub what: String,
    /// A redirect to a login page: the request never reached the page it targeted, whatever the
    /// final answer says.
    pub redirected: bool,
}

/// The auth-wall evidence in a response (the final one, after any same-origin redirects followed:
/// `chain`): a 401, a redirect to a login page, or a redirect that ended on a password form. None
/// when the response is not a wall. Whether it applies to a case (no credential was sent, the case
/// does not expect a denial) is the caller's call.
pub fn auth_wall_signal(
    status: u16,
    content_type: &str,
    headers: &[(String, String)],
    body: &str,
    chain: &[RedirectHop],
) -> Option<WallSignal> {
    let show = |loc: &str| crate::llm::untrusted::redact_then_truncate(loc, 120);
    if let Some(h) = chain.iter().find(|h| is_login_location(&h.location)) {
        return Some(WallSignal {
            what: format!(
                "HTTP {} redirect to a login page ({})",
                h.status,
                show(&h.location)
            ),
            redirected: true,
        });
    }
    if (300..=399).contains(&status)
        && let Some((_, loc)) = headers.iter().find(|(k, _)| k == "location")
        && is_login_location(loc)
    {
        return Some(WallSignal {
            what: format!("HTTP {status} redirect to a login page ({})", show(loc)),
            redirected: true,
        });
    }
    if status == 401 {
        return Some(WallSignal {
            what: "HTTP 401: the route requires credentials".into(),
            redirected: false,
        });
    }
    if (200..=299).contains(&status)
        && !chain.is_empty()
        && content_type.to_ascii_lowercase().contains("html")
        && has_password_field(body)
    {
        return Some(WallSignal {
            what: "the redirect ended on a page with a password form".into(),
            redirected: true,
        });
    }
    None
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

fn sensitive_checks(case: &PlannedCase, o: &Observation, out: &mut Vec<OracleCheck>) {
    let code = o.status;
    let html = o.content_type.to_ascii_lowercase().contains("html");
    if (200..=299).contains(&code) && !html && looks_like_secret_or_config(o.body) {
        out.push(chk("sensitive_exposure", Verdict::Fail, Some(severity_for("sensitive_exposure", Technique::Other)), format!("{} is publicly readable (HTTP {code}) and contains secret/configuration-looking content", case.component.split('?').next().unwrap_or(""))));
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

fn denied_check(case: &PlannedCase, o: &Observation, tech: Technique, out: &mut Vec<OracleCheck>) {
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

/// 4xx statuses that mean "this input was rejected". 401/403 are the auth layer, 404/405/410 mean
/// the route or verb is not served, 408/429 are timeouts and rate limits: none of them shows that
/// input validation ran, so none of them is "rejected".
pub fn is_rejection(code: u16) -> bool {
    (400..=499).contains(&code) && !matches!(code, 401 | 403 | 404 | 405 | 408 | 410 | 429)
}

/// Why a 4xx says nothing about validation (None for a real rejection or a non-4xx status).
fn not_exercised(code: u16) -> Option<&'static str> {
    match code {
        401 | 403 => Some("refused at the auth layer"),
        404 | 410 => Some("route not served"),
        405 => Some("method not allowed"),
        408 | 429 => Some("timeout or rate limit"),
        _ => None,
    }
}

fn expectation_checks(
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

fn json_of(body: &str) -> Option<serde_json::Value> {
    serde_json::from_str(body.trim()).ok()
}

/// The object a response is "about": the top-level object, or the single envelope object
/// (`data`, `result`, `item`, ...) when the top level carries no identifier of its own. Never a
/// nested sub-resource (`owner`, `tenant`, ...), and never an array element.
pub fn primary_object(
    v: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    let m = v.as_object()?;
    if ["id", "uuid", "_id"].iter().any(|k| m.contains_key(*k)) {
        return Some(m);
    }
    for w in [
        "data", "result", "item", "resource", "record", "entity", "object", "payload", "created",
    ] {
        if let Some(serde_json::Value::Object(inner)) = m.get(w) {
            return Some(inner);
        }
    }
    Some(m)
}

fn json_scalar_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Server file content that only a traversal can have produced.
pub fn traversal_signature(body: &str) -> Option<&'static str> {
    static SIGS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let sigs =
        SIGS.get_or_init(|| {
            [
            (r"(?m)^root:[^:\r\n]*:0:0:", "the contents of /etc/passwd"),
            (r"(?m)^(?:daemon|bin|sys|nobody):[^:\r\n]*:\d+:\d+:", "the contents of /etc/passwd"),
            (
                r"(?i)\[(?:boot loader|fonts|extensions|mci extensions)\]|for 16-bit app support",
                "the contents of win.ini / boot.ini",
            ),
        ]
        .into_iter()
        .map(|(p, n)| (Regex::new(p).unwrap(), n))
        .collect()
        });
    sigs.iter().find(|(r, _)| r.is_match(body)).map(|(_, n)| *n)
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Did the request carry a directory-traversal sequence (plain, percent- or double-encoded)?
fn is_traversal_probe(case: &PlannedCase, o: &Observation) -> bool {
    std::iter::once(case.component.as_str())
        .chain(o.sent_values.iter().map(String::as_str))
        .any(|raw| {
            let once = pct_decode(raw);
            let twice = pct_decode(&once);
            [raw.to_string(), once, twice].iter().any(|v| {
                let l = v.to_ascii_lowercase();
                l.contains("../")
                    || l.contains("..\\")
                    || l.contains("etc/passwd")
                    || l.contains("win.ini")
                    || l.contains("boot.ini")
            })
        })
}

const PRIVILEGED_KEYS: [&str; 14] = [
    "role",
    "roles",
    "is_admin",
    "isadmin",
    "admin",
    "is_superuser",
    "issuperuser",
    "superuser",
    "is_staff",
    "permissions",
    "scope",
    "scopes",
    "account_tier",
    "is_verified",
];

fn same_json(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value::*;
    match (a, b) {
        (String(x), Bool(y)) | (Bool(y), String(x)) => x.eq_ignore_ascii_case(&y.to_string()),
        (String(x), Number(y)) | (Number(y), String(x)) => *x == y.to_string(),
        _ => a == b,
    }
}

/// Privileged attributes of the request body that the response echoes back with the same value:
/// the server bound a client-supplied role/admin flag to the object (mass assignment).
fn mass_assignment_reflection(o: &Observation) -> Option<String> {
    let body = o.request_body?;
    if !(200..=299).contains(&o.status) {
        return None;
    }
    let sent: Vec<(String, serde_json::Value)> = match json_of(body) {
        Some(serde_json::Value::Object(m)) => m.into_iter().collect(),
        Some(_) => return None,
        None => body
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(pct_decode(v))))
            .collect(),
    };
    let sent: Vec<_> = sent
        .into_iter()
        .filter(|(k, _)| PRIVILEGED_KEYS.contains(&k.to_ascii_lowercase().as_str()))
        .collect();
    if sent.is_empty() {
        return None;
    }
    let resp = json_of(o.body)?;
    let obj = primary_object(&resp)?;
    for (k, v) in &sent {
        if let Some((_, got)) = obj.iter().find(|(rk, _)| rk.eq_ignore_ascii_case(k))
            && same_json(v, got)
        {
            return Some(format!(
                "the response echoes the injected privileged attribute '{k}' = {} (mass assignment / BOPLA)",
                crate::llm::untrusted::redact_then_truncate(&v.to_string(), 40)
            ));
        }
    }
    None
}

/// Judge the answer to a request that carried a foreign `Origin`.
fn cors_check(o: &Observation, out: &mut Vec<OracleCheck>, warnings: &mut Vec<String>) {
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

/// "a" or "an" for the word that follows ("an injection", "a boundary").
fn a_or_an(word: &str) -> &'static str {
    if word
        .chars()
        .next()
        .is_some_and(|c| "aeiouAEIOU".contains(c))
    {
        "an"
    } else {
        "a"
    }
}

/// A boundary/negative/injection case with no explicit expectation passes only on class-specific
/// evidence. The absence of a server error is not evidence.
fn class_evidence(
    case: &PlannedCase,
    o: &Observation,
    tech: Technique,
    out: &mut Vec<OracleCheck>,
) {
    let code = o.status;
    let verb_probe = tech == Technique::Negative
        && matches!(
            case.method.trim().to_ascii_uppercase().as_str(),
            "HEAD" | "OPTIONS"
        );
    if is_rejection(code) {
        out.push(chk(
            "validation_rejection",
            Verdict::Pass,
            None,
            format!("explicit input rejection: HTTP {code}"),
        ));
    } else if verb_probe && ((200..=299).contains(&code) || matches!(code, 405 | 501)) {
        out.push(chk(
            "verb_handling",
            Verdict::Pass,
            None,
            format!(
                "the {} verb was answered cleanly (HTTP {code})",
                case.method.to_ascii_uppercase()
            ),
        ));
    } else {
        let why = not_exercised(code)
            .map(|w| format!(" ({w})"))
            .unwrap_or_default();
        out.push(chk(
            "no_class_evidence",
            Verdict::Inconclusive,
            None,
            format!(
                "HTTP {code}{why} without a server error: {} {} case needs class-specific evidence (an explicit 4xx validation response, or a checked reflection) to pass, and the absence of a 5xx alone proves nothing",
                a_or_an(tech.as_str()),
                tech.as_str()
            ),
        ));
    }
}

/// Judge a response against the documented contract of its operation, with the QA engine's own
/// validators (`qa::api::contract`, `qa::api::latency`): an undocumented status, a 2xx body that
/// breaks its schema (`contract_fields`), a slow answer. Returns true when a body schema was
/// applied, which supersedes the bare required-field check.
fn contract_checks(
    c: &ResponseContract,
    o: &Observation,
    tech: Technique,
    out: &mut Vec<OracleCheck>,
    warnings: &mut Vec<String>,
) -> bool {
    let code = o.status;
    if contract::undocumented(&c.responses, code) {
        out.push(chk(
            "undocumented_status",
            Verdict::Fail,
            Some(severity_for("undocumented_status", tech)),
            format!("HTTP {code} is not a response the spec documents for this operation"),
        ));
    }
    if !(200..=299).contains(&code) {
        return false;
    }
    if c.latency {
        let ms = u128::from(o.latency_ms);
        out.push(if latency::is_slow(ms) {
            chk(
                "slow_response",
                Verdict::Fail,
                Some(severity_for("slow_response", tech)),
                format!(
                    "answered in {ms} ms, over the {} ms p95 limit",
                    latency::SLOW_P95_MS
                ),
            )
        } else {
            chk(
                "latency",
                Verdict::Pass,
                None,
                format!("answered in {ms} ms (limit {} ms)", latency::SLOW_P95_MS),
            )
        });
    }
    if !matches!(contract::schema_in(&c.responses, code), Some(Some(_))) {
        return false;
    }
    let Some(body) = json_of(o.body) else {
        warnings.push(
            "the response body is not (complete) JSON: the documented schema was not checked"
                .into(),
        );
        return false;
    };
    out.push(match contract::schema_mismatch(&c.responses, code, &body) {
        Some(m) => chk(
            "contract_fields",
            Verdict::Fail,
            Some(severity_for("contract_fields", tech)),
            format!("response violates the documented schema ({m})"),
        ),
        None => chk(
            "contract_fields",
            Verdict::Pass,
            None,
            "response matches the documented schema",
        ),
    });
    true
}

pub fn judge(case: &PlannedCase, o: &Observation) -> OracleOutcome {
    let tech = Technique::parse(&case.technique);
    let code = o.status;
    let ct = o.content_type.to_ascii_lowercase();
    let html = ct.contains("html");
    let mut checks: Vec<OracleCheck> = vec![];
    let mut warnings: Vec<String> = vec![];
    let exploratory = case.source.as_deref() == Some("llm");

    // 1. a 5xx after any input (negative/injection/boundary especially) is a failure
    if (500..=599).contains(&code) {
        let sev = severity_for("server_error", tech);
        let after = match tech {
            Technique::Injection => "injection-style input",
            Technique::Boundary => "boundary input",
            Technique::Negative => "malformed/negative input",
            _ => "the request",
        };
        checks.push(chk(
            "server_error",
            Verdict::Fail,
            Some(sev),
            format!("server error HTTP {code} after {after}"),
        ));
    } else {
        checks.push(chk(
            "no_server_error",
            Verdict::Pass,
            None,
            format!("HTTP {code}, no server error"),
        ));
    }

    // 2. stack traces / SQL errors / internal paths in any body
    if let Some(sig) = disclosure_signature(o.body) {
        checks.push(chk(
            "error_disclosure",
            Verdict::Fail,
            Some(severity_for("error_disclosure", tech)),
            format!("response discloses {sig}"),
        ));
    }

    // 3. sensitive files: the only question is "is it readable"
    let sensitive = is_sensitive_path(&case.component);
    if sensitive {
        sensitive_checks(case, o, &mut checks);
    }

    // 3b. CORS probe: the answer is the Access-Control-Allow-Origin header, not the status class
    let cors = is_cors_case(case) || o.origin.is_some();
    if cors {
        cors_check(o, &mut checks, &mut warnings);
    }

    // 4. status expectation (expected_status, else expected_behavior)
    if !cors {
        let exp = derive_expectation(case, tech);
        if exp == Expect::Denied && !sensitive {
            denied_check(case, o, tech, &mut checks);
        } else if exp != Expect::Denied {
            expectation_checks(case, o, tech, exp, &mut checks);
        }
    }

    // 5. reflected payloads (HTML only: a JSON/plain response echoing text is not executable)
    let markup_sent = o.sent_values.iter().any(|v| v.contains('<'));
    if (html || ct.is_empty()) && !o.body.is_empty() {
        let reflected = o.sent_values.iter().any(|v| {
            let danger = v.contains('<')
                || v.to_ascii_lowercase().contains("onerror=")
                || v.to_ascii_lowercase().contains("javascript:");
            danger && v.len() >= 5 && o.body.contains(v.as_str())
        });
        if reflected {
            checks.push(chk(
                "injection_reflection",
                Verdict::Fail,
                Some(severity_for("injection_reflection", tech)),
                "injected markup was reflected unescaped in an HTML response",
            ));
        } else if tech == Technique::Injection && markup_sent {
            checks.push(chk(
                "injection_reflection",
                Verdict::Pass,
                None,
                "injected markup was not reflected unescaped",
            ));
        }
    } else if tech == Technique::Injection
        && markup_sent
        && !ct.is_empty()
        && !html
        && (200..=299).contains(&code)
    {
        // class evidence for an XSS probe: a non-HTML body cannot execute markup in a browser
        checks.push(chk(
            "injection_reflection",
            Verdict::Pass,
            None,
            format!(
                "non-HTML response ({}): injected markup cannot execute",
                o.content_type
            ),
        ));
    }
    if let Some(canary) = o
        .sent_values
        .iter()
        .flat_map(|v| v.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')))
        .find(|w| w.starts_with("CANARY_") && o.body.contains(*w))
    {
        checks.push(chk(
            "injection_reflection",
            Verdict::Fail,
            Some(severity_for("injection_reflection", tech)),
            format!("canary '{canary}' came back in the response"),
        ));
    }

    // 5b. path traversal: file content that only a traversal can have produced
    if is_traversal_probe(case, o)
        && let Some(sig) = traversal_signature(o.body)
    {
        checks.push(chk(
            "path_traversal",
            Verdict::Fail,
            Some(severity_for("path_traversal", tech)),
            format!("response contains {sig} after a directory-traversal sequence"),
        ));
    }

    // 5c. mass assignment: a privileged attribute we injected is echoed back
    if let Some(detail) = mass_assignment_reflection(o) {
        checks.push(chk(
            "mass_assignment",
            Verdict::Fail,
            Some(severity_for("mass_assignment", tech)),
            detail,
        ));
    }

    // 6. contract: what the spec documents about the response (statuses, 2xx body schema, latency)
    //    when the plan carries it; otherwise just the field names the spec marks required
    let schema_judged = case
        .contract
        .as_ref()
        .is_some_and(|c| contract_checks(c, o, tech, &mut checks, &mut warnings));
    if !schema_judged && !case.expect_fields.is_empty() && (200..=299).contains(&code) {
        match json_of(o.body) {
            None => checks.push(chk(
                "contract_fields",
                Verdict::Inconclusive,
                None,
                "response is not JSON; required fields could not be checked",
            )),
            Some(v) => {
                let obj = match &v {
                    serde_json::Value::Array(a) => a.first().cloned(),
                    other => Some(other.clone()),
                };
                match obj {
                    Some(serde_json::Value::Object(m)) => {
                        let missing: Vec<&str> = case
                            .expect_fields
                            .iter()
                            .filter(|f| !m.contains_key(f.as_str()))
                            .map(|s| s.as_str())
                            .collect();
                        if missing.is_empty() {
                            checks.push(chk(
                                "contract_fields",
                                Verdict::Pass,
                                None,
                                "all required response fields present",
                            ));
                        } else {
                            checks.push(chk(
                                "contract_fields",
                                Verdict::Fail,
                                Some(severity_for("contract_fields", tech)),
                                format!(
                                    "required response field(s) missing: {}",
                                    missing.join(", ")
                                ),
                            ));
                        }
                    }
                    _ => checks.push(chk(
                        "contract_fields",
                        Verdict::Inconclusive,
                        None,
                        "no object in the response to check required fields against",
                    )),
                }
            }
        }
    }
    if let Some(want) = case
        .expected_content_type
        .as_deref()
        .filter(|w| !w.is_empty())
        && (200..=299).contains(&code)
    {
        if ct.contains(&want.to_ascii_lowercase()) {
            checks.push(chk(
                "content_type",
                Verdict::Pass,
                None,
                format!("content-type contains {want}"),
            ));
        } else {
            checks.push(chk(
                "content_type",
                Verdict::Fail,
                Some(severity_for("content_type", tech)),
                format!("expected content-type {want}, got '{}'", o.content_type),
            ));
        }
    }

    // 7. session cookie hygiene is advisory (case becomes WARN, not FAIL)
    if tech == Technique::StateTransition {
        for (k, v) in o.headers.iter().filter(|(k, _)| k == "set-cookie") {
            let _ = k;
            let name = v.split('=').next().unwrap_or("").trim().to_string();
            let ln = name.to_ascii_lowercase();
            if ["sess", "sid", "auth", "token", "jwt", "login"]
                .iter()
                .any(|s| ln.contains(s))
            {
                let low = v.to_ascii_lowercase();
                if !low.contains("httponly") {
                    warnings.push(format!("session cookie '{name}' is missing HttpOnly"));
                }
                if o.https && !low.contains("secure") {
                    warnings.push(format!(
                        "session cookie '{name}' is missing Secure over HTTPS"
                    ));
                }
            }
        }
    }

    // 8. an LLM-proposed case brings its own expectation. That is a hypothesis, not evidence:
    //    only deterministic invariant checks (5xx, disclosure, reflection, traversal, mass
    //    assignment, CORS, authz on a route discovery/spec says is protected) may fail it.
    if exploratory {
        for c in checks.iter_mut() {
            if c.verdict == Verdict::Fail
                && matches!(
                    c.code.as_str(),
                    "expected_status" | "expected_redirect" | "content_type"
                )
            {
                c.verdict = Verdict::Inconclusive;
                c.severity = None;
                c.detail = format!(
                    "exploratory case: the LLM-proposed expectation is unconfirmed, no deterministic invariant was violated ({})",
                    c.detail
                );
            }
        }
    }

    // 9. verdict
    let has_fail = checks.iter().any(|c| c.verdict == Verdict::Fail);
    let decisive = checks.iter().any(|c| {
        matches!(
            c.code.as_str(),
            "expected_status"
                | "expected_redirect"
                | "authz"
                | "sensitive_exposure"
                | "injection_reflection"
                | "contract_fields"
                | "content_type"
                | "cors"
        )
    });
    let robustness = matches!(
        tech,
        Technique::Boundary | Technique::Negative | Technique::Injection
    );
    if !has_fail && !decisive {
        if robustness {
            class_evidence(case, o, tech, &mut checks);
        } else {
            checks.push(chk(
                "no_assertion",
                Verdict::Inconclusive,
                None,
                "no machine-checkable expectation for this case (expected_status/expected_behavior)",
            ));
        }
    }
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
        exploratory,
    }
}

// ---------------------------------------------------------------- typed oracles for sub-checks

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
}

fn outcome(checks: Vec<OracleCheck>, warnings: Vec<String>) -> OracleOutcome {
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
                None => inc("authz", "the owner control read was not performed, so the second actor's answer cannot be attributed to isolation".into()),
                Some(c) if !two(*c) => inc(
                    "authz",
                    format!("owner control read returned HTTP {c}: the resource is not readable by its creator at this path, so the second actor's answer says nothing about isolation"),
                ),
                Some(_) if two(s) => {
                    if !*safe_method {
                        inc(
                            "authz",
                            format!("the state-changing access step answered HTTP {s}; it cannot be re-run safely to confirm, check it manually"),
                        )
                    } else if anon_status.is_some_and(two) {
                        inc(
                            "authz",
                            format!("HTTP {s} for the second actor, but the same request without credentials also succeeds: this looks like a public resource, not an isolation breach"),
                        )
                    } else {
                        match reproduced {
                            Some(true) => chk(
                                "authz",
                                Verdict::Fail,
                                Some(severity_for("authz", Technique::Authz)),
                                format!("a second actor read another actor's resource (HTTP {s}, reproduced on a safe re-run, not readable without credentials)"),
                            ),
                            Some(false) => inc(
                                "authz",
                                format!("HTTP {s} for the second actor did not reproduce on a safe re-run"),
                            ),
                            None => inc(
                                "authz",
                                format!("HTTP {s} for the second actor was not confirmed by a re-run"),
                            ),
                        }
                    }
                }
                Some(c) => match s {
                    404 | 410 => chk(
                        "authz",
                        Verdict::Pass,
                        None,
                        format!("resource hidden from the second actor (HTTP {s}) while its owner reads it (HTTP {c})"),
                    ),
                    401 | 403 if *second_actor_anon => chk(
                        "authz",
                        Verdict::Pass,
                        None,
                        format!("denied without credentials (HTTP {s}) while the owner reads the resource (HTTP {c})"),
                    ),
                    401 | 403 => inc(
                        "authz",
                        format!("HTTP {s} for the second actor cannot be told apart from an invalid or under-scoped credential: not counted as isolation evidence"),
                    ),
                    429 => inc("authz", "the second actor's request was rate-limited (429)".into()),
                    300..=399 => inc("authz", format!("the second actor was redirected (HTTP {s})")),
                    _ => inc("authz", format!("HTTP {s} for the second actor: isolation was not exercised")),
                },
            }
        }
    };
    outcome(vec![check], vec![])
}

/// One response of a concurrent burst (body capped by the executor).
#[derive(Debug, Clone)]
pub struct BurstResponse {
    pub status: u16,
    pub body: String,
}

pub struct BurstFacts<'a> {
    pub method: &'a str,
    pub requested: usize,
    pub responses: &'a [BurstResponse],
    /// Body of a safe GET of the same URL before / after the burst.
    pub pre_read: Option<&'a str>,
    pub post_read: Option<&'a str>,
}

const COUNTER_KEYS: [&str; 14] = [
    "count",
    "counter",
    "total",
    "quantity",
    "qty",
    "stock",
    "balance",
    "remaining",
    "inventory",
    "likes",
    "votes",
    "version",
    "seq",
    "uses",
];

fn counters(body: &str) -> Vec<(String, f64)> {
    let Some(v) = json_of(body) else {
        return vec![];
    };
    let Some(obj) = primary_object(&v) else {
        return vec![];
    };
    obj.iter()
        .filter(|(k, _)| COUNTER_KEYS.contains(&k.to_ascii_lowercase().as_str()))
        .filter_map(|(k, v)| v.as_f64().map(|n| (k.to_ascii_lowercase(), n)))
        .collect()
}

/// Concurrency verdict from invariants only. "Every request answered 2xx" is not a race: FAIL needs
/// a violated invariant (duplicate created ids, or acknowledged increments missing on re-read).
pub fn judge_burst(f: &BurstFacts) -> OracleOutcome {
    let mut checks = vec![];
    let mut warnings = vec![];
    let method = f.method.to_ascii_uppercase();
    let ok: Vec<&BurstResponse> = f
        .responses
        .iter()
        .filter(|r| (200..=299).contains(&r.status))
        .collect();
    let n5xx = f.responses.iter().filter(|r| r.status >= 500).count();
    if n5xx > 0 {
        warnings.push(format!(
            "{n5xx} of {} concurrent requests answered HTTP 5xx; a server error is judged by the single-request case, it is not an invariant violation here",
            f.responses.len()
        ));
    }
    if f.responses.len() < 2 {
        checks.push(chk(
            "race_condition",
            Verdict::Inconclusive,
            None,
            format!(
                "only {} of {} concurrent responses were received: nothing to compare",
                f.responses.len(),
                f.requested
            ),
        ));
        return outcome(checks, warnings);
    }
    let mut evaluated = false;

    // invariant A: concurrent creations must not hand out the same id twice
    if method == "POST" {
        let ids: Vec<String> = ok
            .iter()
            .filter_map(|r| {
                let v = json_of(&r.body)?;
                let obj = primary_object(&v)?;
                ["id", "uuid", "_id"]
                    .iter()
                    .find_map(|k| obj.get(*k).and_then(json_scalar_string))
            })
            .collect();
        if ids.len() >= 2 {
            evaluated = true;
            let mut seen = std::collections::BTreeSet::new();
            let dup = ids.iter().find(|i| !seen.insert((*i).clone())).cloned();
            match dup {
                Some(d) => checks.push(chk(
                    "race_condition",
                    Verdict::Fail,
                    Some(severity_for("race_condition", Technique::Other)),
                    format!(
                        "{} concurrent creations returned only {} distinct ids (duplicate id '{}')",
                        ids.len(),
                        seen.len(),
                        crate::llm::untrusted::redact_then_truncate(&d, 40)
                    ),
                )),
                None => checks.push(chk(
                    "race_condition",
                    Verdict::Pass,
                    None,
                    format!(
                        "{} concurrent creations returned {} distinct ids",
                        ids.len(),
                        ids.len()
                    ),
                )),
            }
        }
    }

    // invariant B: acknowledged increments must show up when the resource is read back
    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS")
        && let (Some(pre), Some(post)) = (f.pre_read, f.post_read)
    {
        let (pre_c, post_c) = (counters(pre), counters(post));
        let mut per_key: std::collections::BTreeMap<String, Vec<f64>> = Default::default();
        for r in &ok {
            for (k, v) in counters(&r.body) {
                per_key.entry(k).or_default().push(v);
            }
        }
        for (key, vals) in per_key.iter().filter(|(_, v)| v.len() >= 2) {
            let (Some(a), Some(b)) = (
                pre_c.iter().find(|(k, _)| k == key).map(|(_, v)| *v),
                post_c.iter().find(|(k, _)| k == key).map(|(_, v)| *v),
            ) else {
                continue;
            };
            let delta = (b - a).abs();
            if delta == 0.0 {
                continue; // the burst did not touch this field: not a counter of ours
            }
            evaluated = true;
            let mut distinct: Vec<f64> = vals.clone();
            distinct.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
            distinct.dedup();
            let dup = distinct.len() < vals.len();
            let k = ok.len() as f64;
            if dup && delta + 0.5 < k {
                checks.push(chk(
                    "race_condition",
                    Verdict::Fail,
                    Some(severity_for("race_condition", Technique::Other)),
                    format!(
                        "lost update: {} requests were acknowledged but counter '{key}' moved by {delta} on re-read, and several responses reported the same new value"
                    , ok.len()),
                ));
            } else {
                checks.push(chk(
                    "race_condition",
                    Verdict::Pass,
                    None,
                    format!(
                        "counter '{key}' moved by {delta} for {} acknowledged requests",
                        ok.len()
                    ),
                ));
            }
        }
    }

    if !evaluated {
        checks.push(chk(
            "race_condition",
            Verdict::Inconclusive,
            None,
            format!(
                "{} of {} concurrent requests answered 2xx, but no invariant could be evaluated (no created ids or counter to compare); concurrent success alone is not evidence of a race",
                ok.len(),
                f.requested
            ),
        ));
    }
    outcome(checks, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(tech: &str, method: &str, component: &str) -> PlannedCase {
        PlannedCase {
            id: "TC-001".into(),
            title: "t".into(),
            component: component.into(),
            method: method.into(),
            technique: tech.into(),
            input_hint: String::new(),
            payload: None,
            expected_behavior: String::new(),
            expected_status: None,
            risk_level: "medium".into(),
            role: None,
            secured: None,
            route_status: None,
            expect_fields: vec![],
            expected_content_type: None,
            source: None,
            stateful_steps: None,
            concurrency_burst: None,
            contract: None,
            changed_ops: vec![],
            area: String::new(),
            regression_of: vec![],
            history_priority: false,
        }
    }

    fn obs<'a>(status: u16, ct: &'a str, body: &'a str) -> Observation<'a> {
        Observation {
            status,
            content_type: ct,
            headers: &[],
            body,
            sent_values: &[],
            is_spa_shell: false,
            authenticated: false,
            https: false,
            request_body: None,
            origin: None,
            latency_ms: 5,
        }
    }

    fn v(c: &PlannedCase, o: &Observation) -> (Verdict, Option<Severity>) {
        let r = judge(c, o);
        (r.verdict, r.max_fail_severity())
    }

    #[test]
    fn authz_golden_table() {
        let mut c = case("authz", "GET", "/admin/stats");
        c.secured = Some(true);
        c.expected_status = Some(401);
        assert_eq!(
            v(&c, &obs(401, "application/json", "{}")),
            (Verdict::Pass, None)
        );
        assert_eq!(
            v(&c, &obs(403, "application/json", "{}")),
            (Verdict::Pass, None)
        );
        // arbitrary keys: the verdict must not depend on "id"/"user"/"token"/"session"
        assert_eq!(
            v(&c, &obs(200, "application/json", r#"{"orders": 3}"#)),
            (Verdict::Fail, Some(Severity::Critical))
        );
        assert_eq!(
            v(&c, &obs(200, "application/json", r#"{"zzz": [1,2,3]}"#)),
            (Verdict::Fail, Some(Severity::Critical))
        );
        assert_eq!(
            v(&c, &obs(404, "application/json", "{}")).0,
            Verdict::Inconclusive
        );
        let mut spa = obs(200, "text/html", "<!doctype html><div id=root>");
        spa.is_spa_shell = true;
        assert_eq!(v(&c, &spa).0, Verdict::Inconclusive);
        // unknown protection + 2xx is not a failure, it is unknown
        let mut open = case("authz", "GET", "/pricing");
        open.expected_status = Some(401);
        assert_eq!(
            v(&open, &obs(200, "text/html", "<p>hi</p>")).0,
            Verdict::Inconclusive
        );
        // protected by discovery (401 without creds) but a forged token gets 200
        let mut forged = case("authz", "GET", "/me");
        forged.role = Some("forged".into());
        forged.route_status = Some(401);
        let r = judge(&forged, &obs(200, "application/json", r#"{"a":1}"#));
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.reason().unwrap().contains("forged token accepted"));
    }

    #[test]
    fn sensitive_files() {
        let mut c = case("authz", "GET", "/.env");
        c.expected_status = Some(403);
        assert_eq!(v(&c, &obs(404, "text/html", "nf")), (Verdict::Pass, None));
        assert_eq!(v(&c, &obs(403, "text/html", "no")), (Verdict::Pass, None));
        assert_eq!(
            v(&c, &obs(200, "text/plain", "DB_HOST=db\nAPP_KEY=abc")),
            (Verdict::Fail, Some(Severity::Critical))
        );
        assert_eq!(
            v(
                &c,
                &obs(200, "text/html", "<!doctype html><title>x</title>")
            ),
            (Verdict::Pass, None)
        );
        let g = case("authz", "GET", "/.git/config");
        assert_eq!(
            v(
                &g,
                &obs(200, "text/plain", "[core]\n\trepositoryformatversion = 0")
            ),
            (Verdict::Fail, Some(Severity::Critical))
        );
        assert!(
            is_sensitive_path("/.env")
                && is_sensitive_path("/a/phpinfo.php?x=1")
                && !is_sensitive_path("/.well-known/security.txt")
                && !is_sensitive_path("/orders")
        );
    }

    #[test]
    fn five_xx_after_negative_or_injection_input_fails() {
        let b = case("boundary", "POST", "/orders");
        assert_eq!(
            v(&b, &obs(500, "application/json", "{}")),
            (Verdict::Fail, Some(Severity::Medium))
        );
        let n = case("negative", "POST", "/orders");
        assert_eq!(
            v(&n, &obs(502, "text/html", "bad gateway")),
            (Verdict::Fail, Some(Severity::Medium))
        );
        let i = case("injection", "GET", "/search");
        assert_eq!(
            v(&i, &obs(500, "text/plain", "oops")),
            (Verdict::Fail, Some(Severity::High))
        );
        // robustness cases pass on a clean 4xx even without an explicit expectation
        assert_eq!(
            v(&b, &obs(422, "application/json", "{}")),
            (Verdict::Pass, None)
        );
    }

    #[test]
    fn expected_status_and_behavior_are_compared() {
        let mut c = case("state_transition", "GET", "/health");
        c.expected_status = Some(200);
        assert_eq!(v(&c, &obs(200, "application/json", "{}")).0, Verdict::Pass);
        assert_eq!(v(&c, &obs(204, "", "")).0, Verdict::Pass, "same 2xx class");
        assert_eq!(
            v(&c, &obs(404, "text/html", "x")),
            (Verdict::Fail, Some(Severity::Medium))
        );
        assert_eq!(
            v(&c, &obs(401, "application/json", "{}")).0,
            Verdict::Inconclusive,
            "no credential: not a defect"
        );
        let mut e = case("state_transition", "GET", "/x");
        e.expected_status = Some(201);
        assert_eq!(
            v(&e, &obs(200, "application/json", "{}")),
            (Verdict::Fail, Some(Severity::Medium))
        );
        // behaviour text
        let mut b = case("negative", "POST", "/orders");
        b.expected_behavior = "Malformed JSON must be rejected with a 4xx client error".into();
        assert_eq!(v(&b, &obs(400, "application/json", "{}")).0, Verdict::Pass);
        assert_eq!(
            v(&b, &obs(201, "application/json", "{}")),
            (Verdict::Fail, Some(Severity::Medium))
        );
        assert_eq!(
            v(&b, &obs(401, "application/json", "{}")).0,
            Verdict::Inconclusive,
            "refused at auth: validation not exercised"
        );
        let mut s = case("state_transition", "GET", "/p");
        s.expected_behavior = "HTTP 200 OK with a valid response".into();
        assert_eq!(v(&s, &obs(302, "", "")).0, Verdict::Inconclusive);
        assert_eq!(v(&s, &obs(200, "text/html", "ok")).0, Verdict::Pass);
        // ambiguous text yields no expectation, and a liveness case with none is INCONCLUSIVE
        let mut amb = case("state_transition", "GET", "/p");
        amb.expected_behavior = "Payload is HTML encoded or blocked with 403".into();
        assert_eq!(
            v(&amb, &obs(200, "text/html", "ok")).0,
            Verdict::Inconclusive
        );
    }

    #[test]
    fn error_disclosure_and_reflection() {
        let c = case("negative", "GET", "/x");
        let tb = "Traceback (most recent call last):\n  File \"/home/app/server.py\", line 88";
        let r = judge(&c, &obs(400, "text/plain", tb));
        assert_eq!(
            (r.verdict, r.max_fail_severity()),
            (Verdict::Fail, Some(Severity::High))
        );
        assert_eq!(
            disclosure_signature("You have an error in your SQL syntax near"),
            Some("a SQL error")
        );
        assert_eq!(
            disclosure_signature("Fatal error: Uncaught x in /var/www/a.php on line 4"),
            Some("a PHP error")
        );
        assert_eq!(disclosure_signature("all good"), None);

        let i = case("injection", "GET", "/search");
        let sent = vec![r#""><script>alert(1)</script>"#.to_string()];
        let mut o = obs(200, "text/html", r#"<p>"><script>alert(1)</script></p>"#);
        o.sent_values = &sent;
        assert_eq!(judge(&i, &o).verdict, Verdict::Fail);
        let mut o2 = obs(
            200,
            "text/html",
            "<p>&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;</p>",
        );
        o2.sent_values = &sent;
        assert_eq!(judge(&i, &o2).verdict, Verdict::Pass);
        // reflected inside JSON is not executable markup
        let mut o3 = obs(
            200,
            "application/json",
            r#"{"q":"\"><script>alert(1)</script>"}"#,
        );
        o3.sent_values = &sent;
        assert_eq!(judge(&i, &o3).verdict, Verdict::Pass);
        // canary
        let canary = vec!["CANARY_PROMPT_LEAK_7".to_string()];
        let mut o4 = obs(
            200,
            "application/json",
            "{\"echo\": \"CANARY_PROMPT_LEAK_7\"}",
        );
        o4.sent_values = &canary;
        assert_eq!(judge(&i, &o4).verdict, Verdict::Fail);
    }

    #[test]
    fn contract_fields_come_from_the_spec() {
        let mut c = case("state_transition", "GET", "/orders/2");
        c.expected_status = Some(200);
        c.expect_fields = vec!["id".into(), "total".into()];
        assert_eq!(
            v(&c, &obs(200, "application/json", r#"{"id":2,"item":"m"}"#)),
            (Verdict::Fail, Some(Severity::Medium))
        );
        assert_eq!(
            v(&c, &obs(200, "application/json", r#"{"id":2,"total":10}"#)).0,
            Verdict::Pass
        );
        assert_eq!(
            v(
                &c,
                &obs(200, "application/json", r#"[{"id":2,"total":10}]"#)
            )
            .0,
            Verdict::Pass
        );
        assert_eq!(
            v(&c, &obs(200, "text/html", "<p>")).0,
            Verdict::Inconclusive
        );
    }

    fn order_contract(latency: bool) -> ResponseContract {
        let order = serde_json::json!({"type":"object","required":["id","total"],"properties":{
            "id":{"type":"integer"},"total":{"type":"integer"}}});
        let mut responses = contract::Responses::new();
        responses.insert("200".into(), Some(order));
        responses.insert("404".into(), None);
        responses.insert("401".into(), None);
        ResponseContract { responses, latency }
    }

    #[test]
    fn the_documented_schema_judges_a_2xx_body_with_the_qa_validator() {
        let mut c = case("state_transition", "GET", "/orders/2");
        c.expected_status = Some(200);
        c.contract = Some(order_contract(false));
        // the QA engine's bug 5: a required field is missing
        let r = judge(&c, &obs(200, "application/json", r#"{"id":2,"item":"m"}"#));
        assert_eq!(
            (r.verdict, r.max_fail_severity()),
            (Verdict::Fail, Some(Severity::Medium))
        );
        let f = r.first_fail().unwrap();
        assert_eq!(f.code, "contract_fields");
        assert!(
            f.detail.contains("$.total: required property missing"),
            "{}",
            f.detail
        );
        // a type the schema forbids is caught too, which the field-name check never saw
        let r = judge(
            &c,
            &obs(200, "application/json", r#"{"id":"2","total":10}"#),
        );
        assert!(
            r.first_fail()
                .unwrap()
                .detail
                .contains("$.id: expected integer")
        );
        assert_eq!(
            v(&c, &obs(200, "application/json", r#"{"id":2,"total":10}"#)).0,
            Verdict::Pass
        );
        // the schema supersedes the bare field check (one contract verdict, not two)
        c.expect_fields = vec!["id".into(), "total".into()];
        let r = judge(&c, &obs(200, "application/json", r#"{"id":2,"item":"m"}"#));
        assert_eq!(
            r.checks
                .iter()
                .filter(|k| k.code == "contract_fields")
                .count(),
            1
        );
        // an unparseable body does not turn a good status into INCONCLUSIVE: it is a warning (the
        // bare field check, when the case has one, keeps judging it as before)
        c.expect_fields.clear();
        let r = judge(&c, &obs(200, "text/html", "<p>shell</p>"));
        assert_eq!(r.verdict, Verdict::Pass, "{r:?}");
        assert!(r.warnings.iter().any(|w| w.contains("not (complete) JSON")));
        // without a contract the legacy field-name check still runs
        c.contract = None;
        c.expect_fields = vec!["id".into(), "total".into()];
        assert_eq!(
            v(&c, &obs(200, "application/json", r#"{"id":2,"item":"m"}"#)).0,
            Verdict::Fail
        );
    }

    #[test]
    fn an_undocumented_status_is_a_low_finding_but_auth_rate_limit_and_5xx_are_not() {
        let mut c = case("boundary", "POST", "/orders");
        c.expected_behavior = "Invalid input is rejected with a 4xx client error".into();
        c.contract = Some(order_contract(false));
        // 409 is a rejection (the input was refused) but the spec does not list it
        let r = judge(&c, &obs(409, "application/json", "{}"));
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.first_fail().unwrap().code, "undocumented_status");
        assert_eq!(r.max_fail_severity(), Some(Severity::Low));
        // documented 404 is fine; 401/403/429 are the auth layer and the limiter, not the contract
        for st in [404, 401, 403, 429] {
            let r = judge(&c, &obs(st, "application/json", "{}"));
            assert!(
                r.checks.iter().all(|k| k.code != "undocumented_status"),
                "{st}: {r:?}"
            );
        }
        // a 500 stays a server_error alone
        let r = judge(&c, &obs(500, "application/json", "{}"));
        assert!(r.checks.iter().all(|k| k.code != "undocumented_status"));
        assert_eq!(r.first_fail().unwrap().code, "server_error");
        // a spec that documents no response judges no status
        c.contract = Some(ResponseContract::default());
        assert!(
            judge(&c, &obs(409, "application/json", "{}"))
                .checks
                .iter()
                .all(|k| k.code != "undocumented_status")
        );
    }

    #[test]
    fn a_read_over_the_qa_latency_limit_fails_as_slow_response() {
        let mut c = case("state_transition", "GET", "/reports/slow");
        c.expected_status = Some(200);
        c.contract = Some(ResponseContract {
            responses: Default::default(),
            latency: true,
        });
        let mut o = obs(200, "application/json", "{}");
        o.latency_ms = latency::SLOW_P95_MS as u64 + 1;
        let r = judge(&c, &o);
        assert_eq!(
            (r.verdict, r.max_fail_severity()),
            (Verdict::Fail, Some(Severity::Low))
        );
        assert_eq!(r.first_fail().unwrap().code, "slow_response");
        assert!(r.reason().unwrap().contains("1001 ms"), "{:?}", r.reason());
        // exactly at the limit is not slow, and a case without `latency` is never judged on it
        o.latency_ms = latency::SLOW_P95_MS as u64;
        let r = judge(&c, &o);
        assert_eq!(r.verdict, Verdict::Pass);
        assert!(
            r.checks
                .iter()
                .any(|k| k.code == "latency" && k.verdict == Verdict::Pass)
        );
        o.latency_ms = 60_000;
        c.contract.as_mut().unwrap().latency = false;
        assert_eq!(judge(&c, &o).verdict, Verdict::Pass);
        // a slow error answer is not the operation's latency
        c.contract.as_mut().unwrap().latency = true;
        assert!(
            judge(&c, &obs_at(404, 60_000))
                .checks
                .iter()
                .all(|k| k.code != "slow_response")
        );
    }

    fn obs_at(status: u16, ms: u64) -> Observation<'static> {
        let mut o = obs(status, "application/json", "{}");
        o.latency_ms = ms;
        o
    }

    #[test]
    fn the_severities_of_the_contract_checks_come_from_the_triage_table() {
        use super::super::triage::severity_for;
        assert_eq!(
            severity_for("contract_fields", Technique::Other),
            Severity::Medium
        );
        assert_eq!(
            severity_for("slow_response", Technique::Other),
            Severity::Low
        );
        assert_eq!(
            severity_for("undocumented_status", Technique::Other),
            Severity::Low
        );
    }

    #[test]
    fn cookie_flags_warn_but_do_not_fail() {
        let mut c = case("state_transition", "GET", "/");
        c.expected_status = Some(200);
        let hdrs = vec![(
            "set-cookie".to_string(),
            "PHPSESSID=abc; path=/".to_string(),
        )];
        let mut o = obs(200, "text/html", "<p>");
        o.headers = &hdrs;
        let r = judge(&c, &o);
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("HttpOnly"));
        assert!(
            !r.warnings[0].contains("abc"),
            "cookie value must not be copied"
        );
    }

    #[test]
    fn liveness_without_any_expectation_is_inconclusive_not_pass() {
        let c = case("state_transition", "GET", "/x");
        let r = judge(&c, &obs(200, "text/html", "ok"));
        assert_eq!(r.verdict, Verdict::Inconclusive);
        assert!(r.checks.iter().any(|c| c.code == "no_assertion"));
    }

    // ------------------------------------------------------------ class-specific evidence

    #[test]
    fn robustness_cases_pass_only_on_class_specific_evidence() {
        let b = case("boundary", "POST", "/orders");
        // "no 5xx" alone proves nothing
        for code in [200u16, 201, 204] {
            let r = judge(&b, &obs(code, "application/json", "{}"));
            assert_eq!(r.verdict, Verdict::Inconclusive, "boundary {code}");
            assert!(r.checks.iter().any(|c| c.code == "no_class_evidence"));
        }
        // an explicit validation response is evidence
        for code in [400u16, 413, 422] {
            let r = judge(&b, &obs(code, "application/json", "{}"));
            assert_eq!(r.verdict, Verdict::Pass, "boundary {code}");
            assert!(r.checks.iter().any(|c| c.code == "validation_rejection"));
        }
        // 404 / 405 / 429 / auth-layer refusals are not "rejected"
        for code in [401u16, 403, 404, 405, 410, 429] {
            assert_eq!(
                judge(&b, &obs(code, "application/json", "{}")).verdict,
                Verdict::Inconclusive,
                "boundary {code}"
            );
        }
        // the same holds for an explicit "must be rejected" expectation
        let mut n = case("negative", "POST", "/orders");
        n.expected_behavior = "Malformed input must be rejected with a 4xx client error".into();
        for code in [404u16, 405, 429] {
            assert_eq!(
                judge(&n, &obs(code, "application/json", "{}")).verdict,
                Verdict::Inconclusive,
                "{code} is not a validation rejection"
            );
        }
        assert_eq!(
            judge(&n, &obs(422, "application/json", "{}")).verdict,
            Verdict::Pass
        );
        // a SQL-style probe answered 200 with no error is inconclusive, not a pass
        let mut sqli = case("injection", "GET", "/search");
        sqli.payload = Some("q=' OR '1'='1' --".into());
        let sent = vec!["' OR '1'='1' --".to_string()];
        let mut o = obs(200, "application/json", r#"{"results": []}"#);
        o.sent_values = &sent;
        assert_eq!(judge(&sqli, &o).verdict, Verdict::Inconclusive);
        let mut rej = obs(400, "application/json", "{}");
        rej.sent_values = &sent;
        assert_eq!(judge(&sqli, &rej).verdict, Verdict::Pass);
        // verb probes: a clean 2xx or 405 is how a server handles HEAD/OPTIONS
        let head = case("negative", "HEAD", "/about");
        assert_eq!(
            judge(&head, &obs(200, "text/html", "")).verdict,
            Verdict::Pass
        );
        assert_eq!(
            judge(&head, &obs(405, "text/html", "")).verdict,
            Verdict::Pass
        );
        assert_eq!(
            judge(&head, &obs(404, "text/html", "")).verdict,
            Verdict::Inconclusive
        );
    }

    #[test]
    fn path_traversal_content_signature() {
        let mut c = case("injection", "GET", "/files");
        c.payload = Some("file=..%2f..%2f..%2fetc%2fpasswd".into());
        let sent = vec!["..%2f..%2f..%2fetc%2fpasswd".to_string()];
        let mut o = obs(
            200,
            "text/plain",
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin",
        );
        o.sent_values = &sent;
        let r = judge(&c, &o);
        assert_eq!(
            (r.verdict, r.max_fail_severity()),
            (Verdict::Fail, Some(Severity::Critical))
        );
        assert!(r.checks.iter().any(|c| c.code == "path_traversal"));
        assert_eq!(
            traversal_signature("[boot loader]\ntimeout=30"),
            Some("the contents of win.ini / boot.ini")
        );
        // the same text on a request that carried no traversal sequence is a document, not a finding
        let plain = case("injection", "GET", "/docs");
        let r = judge(
            &plain,
            &obs(200, "text/plain", "root:x:0:0:root:/root:/bin/bash"),
        );
        assert!(r.checks.iter().all(|c| c.code != "path_traversal"));
        // a traversal answered with an ordinary page is not evidence of anything
        let mut o2 = obs(200, "text/html", "<p>welcome</p>");
        o2.sent_values = &sent;
        assert_eq!(judge(&c, &o2).verdict, Verdict::Inconclusive);
    }

    #[test]
    fn mass_assignment_reflection_check() {
        let mut c = case("boundary", "POST", "/users");
        c.payload = Some(r#"{"name":"x","role":"admin","is_admin":true}"#.into());
        let body = r#"{"name":"x","role":"admin","is_admin":true}"#;
        let mut o = obs(
            201,
            "application/json",
            r#"{"id":7,"name":"x","role":"admin"}"#,
        );
        o.request_body = Some(body);
        let r = judge(&c, &o);
        assert_eq!(
            (r.verdict, r.max_fail_severity()),
            (Verdict::Fail, Some(Severity::High))
        );
        assert!(r.checks.iter().any(|c| c.code == "mass_assignment"));
        // envelope responses are looked through; nested sub-resources are not
        let mut env = obs(
            200,
            "application/json",
            r#"{"data":{"id":7,"is_admin":true}}"#,
        );
        env.request_body = Some(body);
        assert_eq!(judge(&c, &env).verdict, Verdict::Fail);
        let mut nested = obs(
            200,
            "application/json",
            r#"{"id":7,"owner":{"role":"admin"}}"#,
        );
        nested.request_body = Some(body);
        assert_eq!(
            judge(&c, &nested).verdict,
            Verdict::Inconclusive,
            "not echoed on the primary object"
        );
        // role was ignored: no reflection, and 2xx alone is still not evidence
        let mut ign = obs(
            201,
            "application/json",
            r#"{"id":7,"name":"x","role":"user"}"#,
        );
        ign.request_body = Some(body);
        assert_eq!(judge(&c, &ign).verdict, Verdict::Inconclusive);
        // rejected: explicit evidence
        let mut rej = obs(422, "application/json", r#"{"error":"unknown field role"}"#);
        rej.request_body = Some(body);
        assert_eq!(judge(&c, &rej).verdict, Verdict::Pass);
        // form-encoded bodies work too
        let mut form = obs(200, "application/json", r#"{"id":1,"role":"admin"}"#);
        form.request_body = Some("name=x&role=admin");
        assert_eq!(judge(&c, &form).verdict, Verdict::Fail);
    }

    #[test]
    fn cors_probe_is_judged_on_the_allow_origin_header() {
        let mut c = case("authz", "OPTIONS", "/");
        c.title = "CORS preflight validation (/)".into();
        c.expected_status = Some(200); // must be ignored: the status class is not the question
        assert!(is_cors_case(&c));
        let h = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let run = |status: u16, hdrs: &[(&str, &str)]| {
            let hv = h(hdrs);
            let mut o = obs(status, "", "");
            o.headers = &hv;
            o.origin = Some(CORS_PROBE_ORIGIN);
            judge(&c, &o)
        };
        // reflects the foreign origin
        let r = run(204, &[("access-control-allow-origin", CORS_PROBE_ORIGIN)]);
        assert_eq!(
            (r.verdict, r.max_fail_severity()),
            (Verdict::Fail, Some(Severity::Medium))
        );
        // ... with credentials: worse
        let r = run(
            204,
            &[
                ("access-control-allow-origin", CORS_PROBE_ORIGIN),
                ("access-control-allow-credentials", "true"),
            ],
        );
        assert_eq!(
            (r.verdict, r.max_fail_severity()),
            (Verdict::Fail, Some(Severity::High))
        );
        // wildcard + credentials fails; a bare wildcard is an advisory warning
        assert_eq!(
            run(
                200,
                &[
                    ("access-control-allow-origin", "*"),
                    ("access-control-allow-credentials", "true")
                ]
            )
            .verdict,
            Verdict::Fail
        );
        let w = run(200, &[("access-control-allow-origin", "*")]);
        assert_eq!(w.verdict, Verdict::Pass);
        assert_eq!(w.warnings.len(), 1);
        // not granted: absent, or a different fixed origin
        assert_eq!(run(204, &[]).verdict, Verdict::Pass);
        assert_eq!(
            run(
                200,
                &[("access-control-allow-origin", "https://app.example")]
            )
            .verdict,
            Verdict::Pass
        );
        // route not served: nothing was learned
        assert_eq!(run(404, &[]).verdict, Verdict::Inconclusive);
        assert_eq!(run(405, &[]).verdict, Verdict::Inconclusive);
        // a 200 does NOT pass a CORS case by itself when the origin is reflected
        assert_eq!(
            run(200, &[("access-control-allow-origin", CORS_PROBE_ORIGIN)]).verdict,
            Verdict::Fail
        );
        // no Origin was sent: the policy was not exercised
        let r = judge(&c, &obs(200, "", ""));
        assert_eq!(r.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn llm_proposed_cases_cannot_fail_on_their_own_expectation() {
        let mut c = case("state_transition", "GET", "/health");
        c.source = Some("llm".into());
        c.expected_status = Some(200);
        let r = judge(&c, &obs(404, "text/html", "x"));
        assert_eq!(r.verdict, Verdict::Inconclusive, "{r:?}");
        assert!(r.exploratory && r.max_fail_severity().is_none());
        assert!(r.reason().unwrap().contains("exploratory"));
        // the same case from the deterministic planner fails
        c.source = Some("deterministic".into());
        assert_eq!(
            judge(&c, &obs(404, "text/html", "x")).verdict,
            Verdict::Fail
        );
        // a deterministic invariant still fails an LLM case
        let mut l = case("injection", "GET", "/search");
        l.source = Some("llm".into());
        let r = judge(&l, &obs(500, "text/plain", "oops"));
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.exploratory);
        let r = judge(
            &l,
            &obs(200, "text/plain", "Traceback (most recent call last):\n x"),
        );
        assert_eq!(
            r.verdict,
            Verdict::Fail,
            "stack trace disclosure is deterministic"
        );
    }

    #[test]
    fn stateful_oracle_table() {
        use StatefulFacts::*;
        let cross = |second: u16,
                     anon: Option<u16>,
                     again: Option<bool>,
                     owner: Option<u16>,
                     anon_actor: bool| {
            judge_stateful(&CrossActor {
                second_actor_anon: anon_actor,
                safe_method: true,
                owner_control: owner,
                second_status: second,
                anon_status: anon,
                reproduced: again,
            })
        };
        // confirmed breach
        let r = cross(200, Some(401), Some(true), Some(200), false);
        assert_eq!(
            (r.verdict, r.max_fail_severity()),
            (Verdict::Fail, Some(Severity::Critical))
        );
        // not reproduced / public resource / unconfirmed
        assert_eq!(
            cross(200, Some(401), Some(false), Some(200), false).verdict,
            Verdict::Inconclusive
        );
        assert_eq!(
            cross(200, Some(200), None, Some(200), false).verdict,
            Verdict::Inconclusive
        );
        assert_eq!(
            cross(200, Some(401), None, Some(200), false).verdict,
            Verdict::Inconclusive
        );
        // 401/403/429/3xx from the second actor are never a PASS
        for s in [401u16, 403, 429, 301, 302, 400, 405, 500] {
            assert_eq!(
                cross(s, None, None, Some(200), false).verdict,
                Verdict::Inconclusive,
                "{s}"
            );
        }
        // hidden resource while the owner reads it: the one positive isolation signal
        assert_eq!(
            cross(404, None, None, Some(200), false).verdict,
            Verdict::Pass
        );
        // an anonymous second actor has no credential that could be "wrong"
        assert_eq!(
            cross(401, None, None, Some(200), true).verdict,
            Verdict::Pass
        );
        // the owner control failing makes any answer meaningless
        assert_eq!(
            cross(404, None, None, Some(404), false).verdict,
            Verdict::Inconclusive
        );
        assert_eq!(
            cross(200, Some(401), Some(true), Some(403), false).verdict,
            Verdict::Inconclusive
        );
        assert_eq!(
            cross(404, None, None, None, false).verdict,
            Verdict::Inconclusive
        );
        // a state-changing access step cannot be re-run safely
        let w = judge_stateful(&CrossActor {
            second_actor_anon: false,
            safe_method: false,
            owner_control: Some(200),
            second_status: 200,
            anon_status: None,
            reproduced: None,
        });
        assert_eq!(w.verdict, Verdict::Inconclusive);
        // workflow + setup
        assert_eq!(
            judge_stateful(&Workflow { failed_step: None }).verdict,
            Verdict::Pass
        );
        assert_eq!(
            judge_stateful(&Workflow {
                failed_step: Some((2, Some(200), 404))
            })
            .verdict,
            Verdict::Inconclusive
        );
        assert_eq!(
            judge_stateful(&Workflow {
                failed_step: Some((2, Some(200), 409))
            })
            .verdict,
            Verdict::Fail
        );
        assert_eq!(
            judge_stateful(&Setup {
                step: 1,
                status: Some(401),
                reason: "x".into()
            })
            .verdict,
            Verdict::Inconclusive
        );
    }

    #[test]
    fn burst_oracle_fails_only_on_a_violated_invariant() {
        let r = |status: u16, body: &str| BurstResponse {
            status,
            body: body.into(),
        };
        let judge = |method: &str, rs: &[BurstResponse], pre: Option<&str>, post: Option<&str>| {
            judge_burst(&BurstFacts {
                method,
                requested: rs.len(),
                responses: rs,
                pre_read: pre,
                post_read: post,
            })
        };
        // every request 2xx and nothing to compare: INCONCLUSIVE, never FAIL
        let all_ok: Vec<_> = (0..5).map(|_| r(200, "{\"ok\":true}")).collect();
        let o = judge("POST", &all_ok, None, None);
        assert_eq!(o.verdict, Verdict::Inconclusive);
        assert!(o.max_fail_severity().is_none());
        // duplicate created ids
        let dup: Vec<_> = (0..4).map(|_| r(201, "{\"id\": 4}")).collect();
        let o = judge("POST", &dup, None, None);
        assert_eq!(
            (o.verdict, o.max_fail_severity()),
            (Verdict::Fail, Some(Severity::High))
        );
        // distinct ids: the invariant held
        let ok: Vec<_> = (1..=4)
            .map(|i| r(201, &format!("{{\"id\": {i}}}")))
            .collect();
        assert_eq!(judge("POST", &ok, None, None).verdict, Verdict::Pass);
        // PUT answering the same id is idempotence, not a duplicate creation
        let put: Vec<_> = (0..3).map(|_| r(200, "{\"id\": 9}")).collect();
        assert_eq!(
            judge("PUT", &put, None, None).verdict,
            Verdict::Inconclusive
        );
        // lost update: five acknowledged increments, same value in the responses, +1 on re-read
        let lost: Vec<_> = (0..5).map(|_| r(200, "{\"count\": 1}")).collect();
        let o = judge(
            "POST",
            &lost,
            Some("{\"count\": 0}"),
            Some("{\"count\": 1}"),
        );
        assert_eq!(o.verdict, Verdict::Fail, "{o:?}");
        // atomic counter: distinct values, final == acknowledged
        let good: Vec<_> = (1..=5)
            .map(|i| r(200, &format!("{{\"count\": {i}}}")))
            .collect();
        assert_eq!(
            judge(
                "POST",
                &good,
                Some("{\"count\": 0}"),
                Some("{\"count\": 5}")
            )
            .verdict,
            Verdict::Pass
        );
        // an unrelated field that did not move is not a counter of ours
        let still: Vec<_> = (0..3).map(|_| r(200, "{\"total\": 3}")).collect();
        assert_eq!(
            judge(
                "POST",
                &still,
                Some("{\"total\": 3}"),
                Some("{\"total\": 3}")
            )
            .verdict,
            Verdict::Inconclusive
        );
        // 5xx under load is recorded as a warning, not an invariant failure
        let mixed = vec![r(200, "{}"), r(500, "oops"), r(500, "oops")];
        let o = judge("POST", &mixed, None, None);
        assert_eq!(o.verdict, Verdict::Inconclusive);
        assert_eq!(o.warnings.len(), 1);
        // too few answers
        assert_eq!(
            judge("POST", &[r(200, "{}")], None, None).verdict,
            Verdict::Inconclusive
        );
    }
    // ------------------------------------------------------------ login matcher, auth wall

    #[test]
    fn the_login_matcher_knows_login_pages_and_not_lookalikes() {
        for yes in [
            "/login",
            "/Login?next=/dashboard",
            "/users/sign-in",
            "/signin",
            "/sso/start",
            "https://idp.example.com/oauth2/authorize?client_id=1",
            "https://tenant.auth0.com/authorize",
            "/auth/callback",
            "/account/authentication",
            "https://accounts.example.com/saml/redirect",
        ] {
            assert!(is_login_location(yes), "{yes} is a login page");
        }
        for no in [
            "/",
            "/authors",
            "/authors/42",
            "/blog/author-bio",
            "/associates",
            "/dashboard?next=/login",
            "/products?utm=sso",
            "/pricing#login",
            "",
        ] {
            assert!(!is_login_location(no), "{no} is not a login page");
        }
    }

    #[test]
    fn a_password_input_is_found_and_text_about_passwords_is_not() {
        assert!(has_password_field(
            r#"<form><input type="password" name="p"></form>"#
        ));
        assert!(has_password_field(
            "<INPUT name=p class='x' TYPE = 'Password'>"
        ));
        assert!(!has_password_field(
            r#"<input type="text" name="password_hint"> Reset your password here"#
        ));
        assert!(!has_password_field("{\"type\": \"password\"}"));
    }

    fn hop(status: u16, to: &str) -> RedirectHop {
        RedirectHop {
            status,
            location: to.into(),
        }
    }

    #[test]
    fn auth_wall_signals_are_a_401_a_login_redirect_or_a_password_form_after_a_redirect() {
        let loc = |v: &str| vec![("location".to_string(), v.to_string())];
        // a 401
        let w = auth_wall_signal(401, "application/json", &[], "{}", &[]).unwrap();
        assert!(w.what.contains("401") && !w.redirected);
        // a redirect to a login page that was not followed
        let w = auth_wall_signal(307, "text/plain", &loc("/login"), "", &[]).unwrap();
        assert!(w.what.contains("307") && w.what.contains("/login") && w.redirected);
        // ... or one that was followed
        let w = auth_wall_signal(
            200,
            "text/html",
            &[],
            "<h1>Sign in</h1>",
            &[hop(302, "/accounts/login?next=/")],
        )
        .unwrap();
        assert!(w.redirected && w.what.contains("login"));
        // a redirect that ended on a password form
        let w = auth_wall_signal(
            200,
            "text/html",
            &[],
            r#"<input type="password">"#,
            &[hop(302, "/welcome")],
        )
        .unwrap();
        assert!(w.redirected && w.what.contains("password"));
        // not walls: a page with a password field that nothing redirected to, a plain 200, a
        // redirect to somewhere else, a 403
        assert_eq!(
            auth_wall_signal(200, "text/html", &[], r#"<input type="password">"#, &[]),
            None
        );
        assert_eq!(
            auth_wall_signal(200, "application/json", &[], "{}", &[]),
            None
        );
        assert_eq!(auth_wall_signal(302, "", &loc("/home"), "", &[]), None);
        assert_eq!(
            auth_wall_signal(200, "text/html", &[], "<p>ok</p>", &[hop(301, "/new-home")]),
            None
        );
        assert_eq!(auth_wall_signal(403, "text/html", &[], "no", &[]), None);
    }

    #[test]
    fn the_authz_oracle_uses_the_same_login_matcher() {
        let mut c = case("authz", "GET", "/account");
        c.expected_status = Some(401);
        let mut o = obs(302, "text/plain", "");
        let to_login = [("location".to_string(), "/users/sign-in".to_string())];
        o.headers = &to_login;
        assert_eq!(judge(&c, &o).verdict, Verdict::Pass);
        let lookalike = [("location".to_string(), "/authors".to_string())];
        o.headers = &lookalike;
        assert_eq!(
            judge(&c, &o).verdict,
            Verdict::Inconclusive,
            "/authors is not an authentication page"
        );
    }

    #[test]
    fn the_case_says_what_it_expects_for_redirects_and_denials() {
        let mut c = case("state_transition", "GET", "/");
        assert!(!expects_redirect(&c) && !expects_denial(&c));
        c.expected_status = Some(307);
        assert!(expects_redirect(&c));
        c.expected_status = Some(401);
        assert!(expects_denial(&c));
        c.expected_status = Some(200);
        assert!(!expects_redirect(&c) && !expects_denial(&c));
        let mut t = case("state_transition", "GET", "/");
        t.expected_behavior = "redirects as it did during discovery".into();
        assert!(expects_redirect(&t));
    }

    #[test]
    fn the_class_evidence_message_reads_right_for_every_technique() {
        for (tech, article) in [
            ("injection", "an injection case"),
            ("boundary", "a boundary case"),
            ("negative", "a negative case"),
        ] {
            let r = judge(
                &case(tech, "GET", "/x"),
                &obs(200, "application/json", "{}"),
            );
            let msg = r.reason().unwrap();
            assert!(msg.contains(article), "{msg}");
            assert!(!msg.contains("a injection"), "{msg}");
        }
    }
}
