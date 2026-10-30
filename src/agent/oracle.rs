//! Typed assertion oracle: turns one HTTP observation plus the planned case into PASS / FAIL /
//! INCONCLUSIVE checks. Deterministic: no LLM input is consulted, and no check depends on a
//! handful of fixed JSON key names (structure and status semantics only).
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use super::types::PlannedCase;

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

/// A stack trace / SQL error / internal path in a response body.
pub fn disclosure_signature(body: &str) -> Option<&'static str> {
    static SIGS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let sigs = SIGS.get_or_init(|| {
        [
            (r"Traceback \(most recent call last\)", "a Python stack trace"),
            (r"(?m)^\s+at [\w.$<>]+\([\w.]+\.(?:java|kt|scala):\d+\)", "a Java stack trace"),
            (r"\bat [\w.$<>]+ \([^)\n]*:\d+:\d+\)", "a Node.js stack trace"),
            (r"(?i)(?:error in your sql syntax|sqlite3?\.(?:operational|programming|integrity)error|unrecognized token|pg::\w+error|psycopg2\.\w+|\bora-\d{5}|sqlstate\[|unclosed quotation mark)", "a SQL error"),
            (r"(?i)\b(?:fatal error|warning|notice|parse error)\b: .{0,160} on line \d+", "a PHP error"),
            (r"(?i)panicked at|goroutine \d+ \[", "a runtime panic"),
            (r"(?i)exception in thread|java\.lang\.\w+exception|system\.\w+exception", "an exception trace"),
            (r"(?i)(?:/home/|/var/www/|/usr/src/|/srv/|c:\\)[\w./\\-]*\.(?:py|php|rb|js|ts|java|go|rs)\b", "an internal file path"),
        ]
        .into_iter()
        .map(|(p, n)| (Regex::new(p).unwrap(), n))
        .collect()
    });
    sigs.iter().find(|(r, _)| r.is_match(body)).map(|(_, n)| *n)
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

fn sensitive_checks(case: &PlannedCase, o: &Observation, out: &mut Vec<OracleCheck>) {
    let code = o.status;
    let html = o.content_type.to_ascii_lowercase().contains("html");
    if (200..=299).contains(&code) && !html && looks_like_secret_or_config(o.body) {
        out.push(chk("sensitive_exposure", Verdict::Fail, Some(Severity::Critical), format!("{} is publicly readable (HTTP {code}) and contains secret/configuration-looking content", case.component.split('?').next().unwrap_or(""))));
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
            if ["login", "signin", "sign-in", "auth", "sso", "oauth"]
                .iter()
                .any(|k| loc.contains(k))
            {
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
                    Some(Severity::Critical),
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
    let _ = tech;
    out.push(c);
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
            } else {
                chk(
                    "expected_status",
                    Verdict::Fail,
                    Some(Severity::Medium),
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
                    Some(Severity::Medium),
                    format!("expected 2xx, got HTTP {code}"),
                )
            };
            out.push(v);
        }
        Expect::ClientError => {
            let v = if unauth_denied
                && matches!(
                    tech,
                    Technique::Boundary | Technique::Negative | Technique::Injection
                ) {
                chk(
                    "expected_status",
                    Verdict::Inconclusive,
                    None,
                    format!(
                        "request was refused at the auth layer (HTTP {code}); input validation was not exercised (no credential for this role)"
                    ),
                )
            } else if (400..=499).contains(&code) {
                chk(
                    "expected_status",
                    Verdict::Pass,
                    None,
                    format!("rejected with HTTP {code}"),
                )
            } else {
                chk(
                    "expected_status",
                    Verdict::Fail,
                    Some(Severity::Medium),
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
            } else {
                chk(
                    "expected_status",
                    Verdict::Fail,
                    Some(Severity::Low),
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

pub fn judge(case: &PlannedCase, o: &Observation) -> OracleOutcome {
    let tech = Technique::parse(&case.technique);
    let code = o.status;
    let ct = o.content_type.to_ascii_lowercase();
    let html = ct.contains("html");
    let mut checks: Vec<OracleCheck> = vec![];
    let mut warnings: Vec<String> = vec![];

    // 1. a 5xx after any input (negative/injection/boundary especially) is a failure
    if (500..=599).contains(&code) {
        let sev = match tech {
            Technique::Injection | Technique::Authz => Severity::High,
            _ => Severity::Medium,
        };
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
            Some(Severity::High),
            format!("response discloses {sig}"),
        ));
    }

    // 3. sensitive files: the only question is "is it readable"
    let sensitive = is_sensitive_path(&case.component);
    if sensitive {
        sensitive_checks(case, o, &mut checks);
    }

    // 4. status expectation (expected_status, else expected_behavior)
    let exp = derive_expectation(case, tech);
    if exp == Expect::Denied && !sensitive {
        denied_check(case, o, tech, &mut checks);
    } else if exp != Expect::Denied {
        expectation_checks(case, o, tech, exp, &mut checks);
    }

    // 5. reflected payloads (HTML only: a JSON/plain response echoing text is not executable)
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
                Some(Severity::High),
                "injected markup was reflected unescaped in an HTML response",
            ));
        } else if tech == Technique::Injection && o.sent_values.iter().any(|v| v.contains('<')) {
            checks.push(chk(
                "injection_reflection",
                Verdict::Pass,
                None,
                "injected markup was not reflected unescaped",
            ));
        }
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
            Some(Severity::High),
            format!("canary '{canary}' came back in the response"),
        ));
    }

    // 6. contract: response fields the spec marks required (names come from the spec, not from us)
    if !case.expect_fields.is_empty() && (200..=299).contains(&code) {
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
                                Some(Severity::Medium),
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
                Some(Severity::Low),
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

    // 8. verdict
    let decisive = checks.iter().any(|c| {
        matches!(
            c.code.as_str(),
            "expected_status"
                | "authz"
                | "sensitive_exposure"
                | "injection_reflection"
                | "contract_fields"
                | "content_type"
        )
    });
    let robustness = matches!(
        tech,
        Technique::Boundary | Technique::Negative | Technique::Injection
    );
    if !decisive && !robustness && !checks.iter().any(|c| c.verdict == Verdict::Fail) {
        checks.push(chk(
            "no_assertion",
            Verdict::Inconclusive,
            None,
            "no machine-checkable expectation for this case (expected_status/expected_behavior)",
        ));
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
    }
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
}
