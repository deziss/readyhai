//! Explorer: turns planned cases into real HTTP requests, judges them with the oracle, re-runs
//! failures to detect flakiness, and writes down exactly what was sent (reproduction curl) and seen.
use regex::Regex;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::budget::RunBudget;
use super::oracle::{self, Observation, OracleOutcome, Verdict};
use super::types::{AttemptRecord, CaseExecutionResult, PlannedCase};
use crate::llm::{is_sensitive_key, redact_for_llm};

pub const METHODS: [&str; 7] = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
const BODY_CAP: usize = 64 * 1024;
const FORGED_TOKEN: &str = "forged.signature.token123";

/// Canonical upper-case method if (and only if) it is on the allow-list.
pub fn normalize_method(m: &str) -> Option<&'static str> {
    let u = m.trim().to_ascii_uppercase();
    METHODS.iter().copied().find(|k| *k == u)
}

pub fn is_mutating(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

// ---------------------------------------------------------------- credentials

/// Test credentials per role. Sources: `RH_<ROLE>_TOKEN` environment variables or the caller
/// (`with`). The server's own tokens are never used, and tokens never appear in reports.
#[derive(Clone, Default)]
pub struct Credentials {
    tokens: BTreeMap<String, String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("roles", &self.tokens.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn role_key(role: &str) -> String {
    role.trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

impl Credentials {
    pub fn none() -> Self {
        Credentials::default()
    }

    pub fn from_env() -> Self {
        let mut c = Credentials::default();
        for (k, v) in std::env::vars() {
            if let Some(role) = k.strip_prefix("RH_").and_then(|r| r.strip_suffix("_TOKEN"))
                && !role.is_empty()
                && !v.trim().is_empty()
            {
                c.tokens
                    .insert(role.to_ascii_uppercase(), v.trim().to_string());
            }
        }
        c
    }

    pub fn with(mut self, role: &str, token: &str) -> Self {
        if !token.trim().is_empty() {
            self.tokens.insert(role_key(role), token.trim().to_string());
        }
        self
    }

    pub fn token(&self, role: &str) -> Option<&str> {
        self.tokens.get(&role_key(role)).map(|s| s.as_str())
    }

    /// Name of the environment variable that supplies `role`'s token.
    pub fn env_var(role: &str) -> String {
        format!("RH_{}_TOKEN", role_key(role))
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.token(role).is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    None,
    Forged,
    Role(String),
}

/// Explicit `role` wins; legacy cases (no role) are inferred from the title/hint like before.
pub fn auth_for(case: &PlannedCase) -> Auth {
    if let Some(r) = case
        .role
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        return match r.to_ascii_lowercase().as_str() {
            "anon" | "anonymous" | "none" | "unauthenticated" => Auth::None,
            "forged" => Auth::Forged,
            _ => Auth::Role(r.to_string()),
        };
    }
    let title = case.title.to_ascii_lowercase();
    let hint = case.input_hint.to_ascii_lowercase();
    if title.contains("forged") {
        return Auth::Forged;
    }
    if case.technique == "authz"
        && (title.contains("unauth")
            || hint.contains("without auth")
            || hint.contains("no auth")
            || case.expected_status.is_some_and(|s| s == 401 || s == 403)
            || case.component.starts_with("/."))
    {
        return Auth::None;
    }
    if case.technique == "authz" {
        return Auth::None;
    }
    Auth::Role("user".into())
}

// ---------------------------------------------------------------- request construction

#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub method: &'static str,
    pub url: String,
    /// Path (+query from the component) as sent.
    pub path: String,
    /// (content-type, body) for body methods.
    pub body: Option<(String, String)>,
    pub auth: Auth,
    /// Decoded query/body values we sent (for reflection checks).
    pub sent_values: Vec<String>,
}

pub fn normalize_component(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("empty component".into());
    }
    if t.len() > 2048 {
        return Err("component longer than 2048 bytes".into());
    }
    if t.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("component contains whitespace or control characters".into());
    }
    if t.starts_with("//") || t.contains("://") {
        return Err("component must be a path on the target, not an absolute URL".into());
    }
    if t.contains('{') || t.contains('}') {
        return Err("unresolved path template placeholder".into());
    }
    Ok(if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    })
}

fn form_key_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.\-\[\]]*=").unwrap())
}

fn looks_like_form(p: &str) -> bool {
    form_key_re().is_match(p.trim_start())
}

/// Payload as decoded key/value pairs: JSON object, `k=v&k2=v2`, or free text (`q=`).
pub fn payload_pairs(p: &str) -> Vec<(String, String)> {
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(p.trim()) {
        return m
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    match v {
                        Value::String(s) => s,
                        other => other.to_string(),
                    },
                )
            })
            .collect();
    }
    if looks_like_form(p) {
        return p
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (kv.to_string(), String::new()),
            })
            .collect();
    }
    vec![("q".to_string(), p.to_string())]
}

fn body_and_type(p: &str) -> (String, String) {
    let t = p.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        ("application/json".into(), p.to_string())
    } else if looks_like_form(p) {
        ("application/x-www-form-urlencoded".into(), p.to_string())
    } else {
        ("text/plain".into(), p.to_string())
    }
}

fn string_leaves(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| string_leaves(x, out)),
        Value::Object(m) => m.values().for_each(|x| string_leaves(x, out)),
        _ => {}
    }
}

/// Validate and build the request for a case. Errors mean "this case must not be sent".
pub fn build_request(case: &PlannedCase, target: &str) -> Result<RequestSpec, String> {
    let method = normalize_method(&case.method).ok_or_else(|| {
        format!(
            "method '{}' is not allowed (GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE only)",
            case.method.chars().take(16).collect::<String>()
        )
    })?;
    let base = reqwest::Url::parse(target).map_err(|e| format!("bad target URL: {e}"))?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err("target is not an http(s) URL".into());
    }
    let path = normalize_component(&case.component)?;
    let mut url = reqwest::Url::parse(&format!("{}{}", target.trim_end_matches('/'), path))
        .map_err(|e| format!("bad URL: {e}"))?;
    if url.host_str() != base.host_str()
        || url.port_or_known_default() != base.port_or_known_default()
        || url.scheme() != base.scheme()
    {
        return Err("request would leave the target origin".into());
    }
    let mut sent_values: Vec<String> = url.query_pairs().map(|(_, v)| v.into_owned()).collect();
    let mut body = None;
    if let Some(p) = case.payload.as_deref().filter(|p| !p.is_empty()) {
        if matches!(method, "GET" | "HEAD" | "OPTIONS") {
            // payloads for bodiless methods belong in the query string
            let pairs = payload_pairs(p);
            url.query_pairs_mut()
                .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            sent_values.extend(pairs.into_iter().map(|(_, v)| v));
        } else {
            let (ct, b) = body_and_type(p);
            match serde_json::from_str::<Value>(&b) {
                Ok(v) if ct == "application/json" => string_leaves(&v, &mut sent_values),
                _ => sent_values.extend(payload_pairs(p).into_iter().map(|(_, v)| v)),
            }
            sent_values.push(p.to_string());
            body = Some((ct, b));
        }
    }
    Ok(RequestSpec {
        method,
        path: path.clone(),
        url: url.to_string(),
        body,
        auth: auth_for(case),
        sent_values,
    })
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Reproduction command: same method, same URL (incl. query), same body, every dynamic string
/// single-quoted. The token comes from the environment, never from the report.
pub fn curl_for(spec: &RequestSpec) -> String {
    let mut p: Vec<String> = vec!["curl -sS".into()];
    if spec.method == "HEAD" {
        p.push("-I -X HEAD".into());
    } else {
        p.push(format!("-i -X {}", spec.method));
    }
    match &spec.auth {
        Auth::Role(r) => p.push(format!(
            "-H \"Authorization: Bearer ${{{}}}\"",
            Credentials::env_var(r)
        )),
        Auth::Forged => p.push(format!(
            "-H {}",
            sq(&format!("Authorization: Bearer {FORGED_TOKEN}"))
        )),
        Auth::None => {}
    }
    if let Some((ct, body)) = &spec.body {
        p.push(format!("-H {}", sq(&format!("Content-Type: {ct}"))));
        p.push(format!("--data-raw {}", sq(body)));
    }
    p.push(sq(&spec.url));
    p.join(" ")
}

// ---------------------------------------------------------------- execution

#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Never send POST/PUT/PATCH/DELETE.
    pub dry_run: bool,
    pub is_spa_target: bool,
    pub credentials: Credentials,
    /// Extra attempts for a FAIL (flaky detection).
    pub reruns: u32,
    pub timeout: Duration,
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            dry_run: false,
            is_spa_target: false,
            credentials: Credentials::from_env(),
            reruns: 2,
            timeout: Duration::from_secs(10),
        }
    }
}

fn build_client(timeout: Duration) -> Result<reqwest::blocking::Client, reqwest::Error> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        // a redirect is an observation, and it must never carry credentials to another host
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("ReadyHai-Agent/1.0")
        .build()
}

struct Seen {
    status: u16,
    content_type: String,
    headers: Vec<(String, String)>,
    body: String,
    latency_ms: u64,
}

fn send_once(
    client: &reqwest::blocking::Client,
    spec: &RequestSpec,
    bearer: Option<&str>,
) -> Result<Seen, String> {
    let t0 = Instant::now();
    let method = reqwest::Method::from_bytes(spec.method.as_bytes()).map_err(|e| e.to_string())?;
    let mut rb = client.request(method, &spec.url);
    if let Some(b) = bearer {
        rb = rb.header("Authorization", b);
    }
    if let Some((ct, body)) = &spec.body {
        rb = rb.header("Content-Type", ct.as_str()).body(body.clone());
    }
    let resp = rb.send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let mut buf = Vec::new();
    let _ = resp.take(BODY_CAP as u64).read_to_end(&mut buf);
    Ok(Seen {
        status,
        content_type,
        headers,
        body: String::from_utf8_lossy(&buf).into_owned(),
        latency_ms: t0.elapsed().as_millis() as u64,
    })
}

fn safe_id(id: &str) -> String {
    let s: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if s.is_empty() { "case".into() } else { s }
}

pub fn evidence_rel_path(case_id: &str) -> String {
    format!("evidence/{}.json", safe_id(case_id))
}

fn skeleton(c: &PlannedCase, status: &str, reason: String, curl: String) -> CaseExecutionResult {
    CaseExecutionResult {
        case_id: c.id.clone(),
        title: c.title.clone(),
        component: c.component.clone(),
        method: c.method.clone(),
        technique: c.technique.clone(),
        status: status.into(),
        status_code: None,
        latency_ms: 0,
        reproduction_curl: curl,
        request_payload: c.payload.clone(),
        evidence: String::new(),
        content_type: None,
        is_spa_shell: false,
        failure_reason: Some(reason),
        expected_status: c.expected_status,
        oracle: None,
        flaky: false,
        attempts: vec![],
        evidence_file: None,
        evidence_detail: None,
    }
}

fn skipped(c: &PlannedCase, reason: impl Into<String>, curl: String) -> CaseExecutionResult {
    skeleton(c, "SKIPPED", reason.into(), curl)
}

fn spa_shell(ct: &str, body: &str, is_spa_target: bool) -> bool {
    ct.to_ascii_lowercase().contains("html")
        && is_spa_target
        && [
            "__NEXT_DATA__",
            "/_next/static/",
            "__NUXT__",
            "ng-version",
            "data-reactroot",
            "<app-root",
            "id=\"root\"",
            "id=\"app\"",
            "/@vite/client",
        ]
        .iter()
        .any(|m| body.contains(m))
}

fn redacted_headers(h: &[(String, String)]) -> Vec<Value> {
    h.iter()
        .map(|(k, v)| {
            json!([
                k,
                if is_sensitive_key(k) {
                    "[REDACTED]".to_string()
                } else {
                    redact_for_llm(v)
                }
            ])
        })
        .collect()
}

/// Execute `cases` against `target` with default options (used by the operator "retest" action).
pub fn execute_cases(
    cases: &[PlannedCase],
    target: &str,
    is_spa_target: bool,
) -> Vec<CaseExecutionResult> {
    let opts = ExecOptions {
        is_spa_target,
        ..ExecOptions::default()
    };
    execute_cases_with(cases, target, &opts, &mut RunBudget::from_env())
}

pub fn execute_cases_with(
    cases: &[PlannedCase],
    target: &str,
    opts: &ExecOptions,
    budget: &mut RunBudget,
) -> Vec<CaseExecutionResult> {
    let curl_of = |c: &PlannedCase| {
        build_request(c, target)
            .map(|s| curl_for(&s))
            .unwrap_or_default()
    };
    let parsed = reqwest::Url::parse(target)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some());
    let Some(parsed) = parsed else {
        return cases.iter().map(|c| skipped(c, "target is not an http(s) URL: the agent only probes over HTTP, nothing was executed", curl_of(c))).collect();
    };
    let client = match build_client(opts.timeout) {
        Ok(c) => c,
        Err(e) => {
            return cases
                .iter()
                .map(|c| {
                    skeleton(
                        c,
                        "BLOCKED",
                        format!("could not build the HTTP client: {e}"),
                        curl_of(c),
                    )
                })
                .collect();
        }
    };
    let host = format!(
        "{}:{}",
        parsed.host_str().unwrap_or(""),
        parsed.port_or_known_default().unwrap_or(0)
    );
    cases
        .iter()
        .map(|c| run_case(&client, c, target, &host, opts, budget))
        .collect()
}

fn run_case(
    client: &reqwest::blocking::Client,
    c: &PlannedCase,
    target: &str,
    host: &str,
    opts: &ExecOptions,
    budget: &mut RunBudget,
) -> CaseExecutionResult {
    let spec = match build_request(c, target) {
        Ok(s) => s,
        Err(e) => return skipped(c, format!("invalid case, not sent: {e}"), String::new()),
    };
    let curl = curl_for(&spec);
    if opts.dry_run && is_mutating(spec.method) {
        return skipped(
            c,
            format!(
                "dry_run: state-changing method {} was not sent",
                spec.method
            ),
            curl,
        );
    }
    if let Err(m) = budget.take_step() {
        return skipped(c, m, curl);
    }
    let (bearer, authenticated, auth_note) = match &spec.auth {
        Auth::None => (None, false, None),
        Auth::Forged => (Some(format!("Bearer {FORGED_TOKEN}")), true, None),
        Auth::Role(r) => match opts.credentials.token(r) {
            Some(t) => (Some(format!("Bearer {t}")), true, None),
            None => (
                None,
                false,
                Some(format!(
                    "no credential for role '{r}': request sent without Authorization (set {})",
                    Credentials::env_var(r)
                )),
            ),
        },
    };
    let https = spec.url.starts_with("https://");

    let mut attempts: Vec<(Option<Seen>, Option<OracleOutcome>, Option<String>)> = vec![];
    let total = 1 + opts.reruns;
    for attempt in 0..total {
        if let Err(m) = budget.take_request(host) {
            if attempt == 0 {
                return skipped(c, m, curl);
            }
            attempts.push((None, None, Some(format!("re-run not sent: {m}"))));
            break;
        }
        match send_once(client, &spec, bearer.as_deref()) {
            Ok(seen) => {
                let shell = spa_shell(&seen.content_type, &seen.body, opts.is_spa_target);
                let outcome = oracle::judge(
                    c,
                    &Observation {
                        status: seen.status,
                        content_type: &seen.content_type,
                        headers: &seen.headers,
                        body: &seen.body,
                        sent_values: &spec.sent_values,
                        is_spa_shell: shell,
                        authenticated,
                        https,
                    },
                );
                let again = outcome.verdict == Verdict::Fail;
                attempts.push((Some(seen), Some(outcome), None));
                if !again {
                    break; // only a FAIL is worth re-running
                }
            }
            Err(e) => {
                attempts.push((None, None, Some(e)));
                break; // a transport error is not a verdict, and is not retried
            }
        }
    }

    let records: Vec<AttemptRecord> = attempts
        .iter()
        .enumerate()
        .map(|(i, (s, o, e))| AttemptRecord {
            attempt: i as u32 + 1,
            status_code: s.as_ref().map(|s| s.status),
            verdict: o
                .as_ref()
                .map(|o| o.verdict.label().to_string())
                .or_else(|| e.as_ref().map(|_| "ERROR".to_string()))
                .unwrap_or_default(),
        })
        .collect();

    // first attempt decides the shape of the result
    let (first_seen, first_outcome, first_err) = attempts.remove(0);
    let mut res = skeleton(c, "BLOCKED", String::new(), curl.clone());
    res.failure_reason = None;
    res.attempts = records;
    res.evidence_file = Some(evidence_rel_path(&c.id));
    let mut detail = json!({
        "case_id": c.id, "title": c.title, "technique": c.technique, "expected_status": c.expected_status, "expected_behavior": c.expected_behavior,
        "request": {"method": spec.method, "url": spec.url, "curl": curl, "payload": c.payload, "auth": match &spec.auth { Auth::None => "none".to_string(), Auth::Forged => "forged-token".to_string(), Auth::Role(r) => format!("role:{r} (token not recorded)") }, "auth_note": auth_note},
    });

    let (Some(seen), Some(outcome)) = (first_seen, first_outcome) else {
        let e = first_err.unwrap_or_else(|| "unknown error".into());
        res.status = "BLOCKED".into();
        res.failure_reason = Some(format!("Connection error: {e}"));
        res.evidence = format!(
            "request failed: {}",
            crate::llm::untrusted::redact_then_truncate(&e, 300)
        );
        detail["response"] = json!({"error": e});
        res.evidence_detail = Some(detail);
        return res;
    };

    // flaky: failed first, but a completed re-run did not reproduce it
    let reruns_done: Vec<&OracleOutcome> =
        attempts.iter().filter_map(|(_, o, _)| o.as_ref()).collect();
    let non_repro = reruns_done
        .iter()
        .filter(|o| o.verdict != Verdict::Fail)
        .count();
    let flaky = outcome.verdict == Verdict::Fail && non_repro > 0;

    res.status_code = Some(seen.status);
    res.latency_ms = seen.latency_ms;
    res.content_type = Some(seen.content_type.clone());
    res.is_spa_shell = spa_shell(&seen.content_type, &seen.body, opts.is_spa_target);
    res.flaky = flaky;
    res.status = match outcome.verdict {
        Verdict::Fail if flaky => "WARN".into(),
        Verdict::Fail => "FAIL".into(),
        Verdict::Inconclusive => "INCONCLUSIVE".into(),
        Verdict::Pass if !outcome.warnings.is_empty() => "WARN".into(),
        Verdict::Pass => "PASS".into(),
    };
    res.failure_reason = if flaky {
        Some(format!(
            "flaky: failed on attempt 1, but {non_repro} of {} re-run(s) did not reproduce it. Original failure: {}",
            reruns_done.len(),
            outcome.reason().unwrap_or_default()
        ))
    } else {
        outcome.reason()
    };
    // redact FIRST, then cut: a secret straddling the cut must not survive as a prefix
    res.evidence = if seen.body.is_empty() {
        format!(
            "{} {} bytes=0 content-type={}",
            spec.method, seen.status, seen.content_type
        )
    } else {
        crate::llm::untrusted::redact_then_truncate(&seen.body, 300)
    };
    detail["response"] = json!({
        "status": seen.status, "content_type": seen.content_type, "latency_ms": seen.latency_ms,
        "headers": redacted_headers(&seen.headers),
        "body_excerpt": crate::llm::untrusted::redact_then_truncate(&seen.body, 4000),
    });
    detail["oracle"] = serde_json::to_value(&outcome).unwrap_or(Value::Null);
    detail["attempts"] = serde_json::to_value(&res.attempts).unwrap_or(Value::Null);
    detail["flaky"] = json!(flaky);
    res.oracle = Some(outcome);
    res.evidence_detail = Some(detail);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(method: &str, component: &str, payload: Option<&str>) -> PlannedCase {
        PlannedCase {
            id: "TC-001".into(),
            title: "t".into(),
            component: component.into(),
            method: method.into(),
            technique: "boundary".into(),
            input_hint: String::new(),
            payload: payload.map(String::from),
            expected_behavior: String::new(),
            expected_status: None,
            risk_level: "low".into(),
            role: None,
            secured: None,
            route_status: None,
            expect_fields: vec![],
            expected_content_type: None,
            source: None,
        }
    }

    #[test]
    fn only_the_seven_http_methods_are_allowed() {
        for m in ["GET", "head", "Options", "POST", "put", "PATCH", "delete"] {
            assert!(
                build_request(&case(m, "/x", None), "http://h").is_ok(),
                "{m}"
            );
        }
        for m in [
            "TRACE",
            "CONNECT",
            "PROPFIND",
            "",
            "GET /x HTTP/1.1\r\nX:",
            "G ET",
        ] {
            assert!(
                build_request(&case(m, "/x", None), "http://h").is_err(),
                "{m:?} must be rejected"
            );
        }
    }

    #[test]
    fn components_cannot_leave_the_target_or_inject() {
        for bad in [
            "http://evil.test/x",
            "//evil.test/x",
            "/a b",
            "/a\r\nHost: evil",
            "",
            "/orders/{id}",
        ] {
            assert!(
                build_request(&case("GET", bad, None), "http://h").is_err(),
                "{bad:?}"
            );
        }
        let ok = build_request(&case("GET", "orders", None), "http://h:8080/").unwrap();
        assert_eq!(ok.url, "http://h:8080/orders");
    }

    #[test]
    fn get_payload_goes_to_the_query_string_not_the_body() {
        let s = build_request(
            &case("GET", "/search", Some("q=\"><script>alert(1)</script>")),
            "http://h",
        )
        .unwrap();
        assert!(s.body.is_none());
        assert!(s.url.starts_with("http://h/search?q="), "{}", s.url);
        assert!(
            s.sent_values
                .iter()
                .any(|v| v == "\"><script>alert(1)</script>")
        );
        let j = build_request(
            &case("HEAD", "/search", Some("{\"a\": 1, \"b\": \"x y\"}")),
            "http://h",
        )
        .unwrap();
        assert!(
            j.body.is_none()
                && j.url.contains("a=1")
                && (j.url.contains("b=x+y") || j.url.contains("b=x%20y")),
            "{}",
            j.url
        );
        let free = build_request(&case("GET", "/s?z=1", Some("' OR '1'='1")), "http://h").unwrap();
        assert!(
            free.url.contains("z=1") && free.url.contains("q="),
            "{}",
            free.url
        );
        let post = build_request(
            &case("POST", "/orders", Some("{\"item\": \"a\"}")),
            "http://h",
        )
        .unwrap();
        assert_eq!(post.body.as_ref().unwrap().0, "application/json");
        let bad_json = build_request(&case("POST", "/orders", Some("{\"")), "http://h").unwrap();
        assert_eq!(
            bad_json.body.unwrap().0,
            "application/json",
            "malformed JSON is still sent as JSON: that is the test"
        );
        let form = build_request(&case("POST", "/f", Some("data=AAA&x=1")), "http://h").unwrap();
        assert_eq!(form.body.unwrap().0, "application/x-www-form-urlencoded");
    }

    #[test]
    fn curl_uses_the_same_method_url_body_and_single_quotes() {
        let mut c = case("PATCH", "/o/1", Some("{\"note\": \"it's\"}"));
        c.role = Some("user".into());
        let s = build_request(&c, "http://h").unwrap();
        let curl = curl_for(&s);
        assert!(curl.contains("-X PATCH"), "{curl}");
        assert!(curl.contains("'http://h/o/1'"), "{curl}");
        assert!(
            curl.contains("--data-raw '{\"note\": \"it'\\''s\"}'"),
            "{curl}"
        );
        assert!(
            curl.contains("Authorization: Bearer ${RH_USER_TOKEN}"),
            "{curl}"
        );
        // a hostile path cannot break out of the quotes
        let h = build_request(&case("GET", "/x'$(id)'", None), "http://h").unwrap();
        let hc = curl_for(&h);
        assert!(hc.ends_with("'http://h/x'\\''$(id)'\\'''"), "{hc}");
        assert!(
            !hc.contains("\"http"),
            "URL must not be double-quoted: {hc}"
        );
        let head = curl_for(&build_request(&case("HEAD", "/x", None), "http://h").unwrap());
        assert!(head.contains("-I -X HEAD"), "{head}");
        let g = curl_for(&build_request(&case("GET", "/s", Some("q=1")), "http://h").unwrap());
        assert!(g.contains("-X GET") && !g.contains("--data"), "{g}");
    }

    #[test]
    fn auth_roles_and_env_names() {
        let mut c = case("GET", "/x", None);
        assert_eq!(auth_for(&c), Auth::Role("user".into()));
        c.technique = "authz".into();
        assert_eq!(auth_for(&c), Auth::None);
        c.title = "Forged JWT".into();
        assert_eq!(auth_for(&c), Auth::Forged);
        c.role = Some("Admin".into());
        assert_eq!(auth_for(&c), Auth::Role("Admin".into()));
        assert_eq!(Credentials::env_var("shop-admin"), "RH_SHOP_ADMIN_TOKEN");
        let creds = Credentials::none().with("admin", "tok");
        assert_eq!(creds.token("ADMIN"), Some("tok"));
        assert!(
            !format!("{creds:?}").contains("tok\""),
            "Debug must not print tokens"
        );
    }
}
