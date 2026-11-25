use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

use super::auth::{Auth, FORGED_TOKEN, auth_for};
use super::clients::METHODS;
use super::credentials::{Credentials, HeaderEnvKind, role_key};
use crate::agent::oracle::{CORS_PROBE_ORIGIN, is_cors_case};
use crate::agent::types::PlannedCase;

/// Canonical upper-case method if (and only if) it is on the allow-list.
pub fn normalize_method(m: &str) -> Option<&'static str> {
    let u = m.trim().to_ascii_uppercase();
    METHODS.iter().copied().find(|k| *k == u)
}

/// State-changing method, whatever its case ("post" is POST).
pub fn is_mutating(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Safe (read-only) method: the only ones the agent ever repeats.
pub fn is_safe_method(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

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
    /// Extra request headers (the CORS probe's `Origin`).
    pub extra_headers: Vec<(String, String)>,
}

impl RequestSpec {
    /// The `Origin` header this request carries, if any.
    pub fn origin(&self) -> Option<&str> {
        self.extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
            .map(|(_, v)| v.as_str())
    }
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

/// (content-type, body) for a body payload: JSON, form-encoded or plain text.
pub fn body_and_type(p: &str) -> (String, String) {
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

/// Safe, bounded validation of custom request headers. Rejects control/CRLF/NUL bytes,
/// invalid token names, and hop-by-hop smuggling headers. `allow_auth_header` is only enabled
/// for internal deterministic token-tampering probes (`role = "raw_jwt"`), never for LLM cases.
pub fn sanitize_custom_headers(
    headers: &[(String, String)],
    allow_auth_header: bool,
) -> Result<Vec<(String, String)>, String> {
    if headers.len() > 16 {
        return Err("too many custom headers (max 16)".into());
    }
    let mut out = Vec::with_capacity(headers.len());
    for (k, v) in headers {
        let name = k.trim();
        if name.is_empty() || name.len() > 64 {
            return Err("invalid custom header name length".into());
        }
        if !name.bytes().all(|b| {
            b.is_ascii_graphic()
                && !matches!(
                    b,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        }) {
            return Err(format!("invalid character in header name '{name}'"));
        }
        if v.len() > 1024
            || v.chars()
                .any(|c| c == '\r' || c == '\n' || c == '\0' || (c.is_control() && c != '\t'))
        {
            return Err(format!("control or oversized value in header '{name}'"));
        }
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "te"
                | "trailer"
                | "upgrade"
                | "proxy-connection"
        ) {
            return Err(format!("hop-by-hop header '{name}' is not allowed"));
        }
        if matches!(
            lower.as_str(),
            "authorization" | "proxy-authorization" | "cookie"
        ) && (!allow_auth_header || lower != "authorization")
        {
            return Err(format!("credential header '{name}' cannot be overridden"));
        }
        out.push((name.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Validate an explicit `Content-Type` header override against control/CRLF injection.
pub fn validate_content_type(ct: &str) -> Result<String, String> {
    let t = ct.trim();
    if t.is_empty() || t.len() > 128 {
        return Err("content_type must be 1..=128 characters".into());
    }
    if t.chars().any(|c| c.is_control()) || !t.contains('/') {
        return Err("invalid content_type".into());
    }
    Ok(t.to_string())
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
    let allow_auth_hdr = case
        .role
        .as_deref()
        .is_some_and(|r| r.trim().eq_ignore_ascii_case("raw_jwt"))
        && case.source.as_deref() != Some("llm");
    let custom_headers = sanitize_custom_headers(&case.headers, allow_auth_hdr)?;
    let explicit_ct = match case.content_type.as_deref() {
        Some(ct) => Some(validate_content_type(ct)?),
        None => None,
    };
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
            let (inferred_ct, b) = body_and_type(p);
            let ct = explicit_ct.clone().unwrap_or(inferred_ct);
            match serde_json::from_str::<Value>(&b) {
                Ok(v) if ct.starts_with("application/json") => string_leaves(&v, &mut sent_values),
                _ => sent_values.extend(payload_pairs(p).into_iter().map(|(_, v)| v)),
            }
            sent_values.push(p.to_string());
            body = Some((ct, b));
        }
    }
    let mut extra_headers = vec![];
    for (k, v) in custom_headers {
        if k.eq_ignore_ascii_case("content-type") && body.is_some() {
            continue;
        }
        extra_headers.push((k, v));
    }
    if body.is_none()
        && let Some(ct) = explicit_ct
        && !extra_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        extra_headers.push(("Content-Type".to_string(), ct));
    }
    if is_cors_case(case)
        && !extra_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("origin"))
    {
        // a CORS probe is only meaningful with a foreign Origin
        extra_headers.push(("Origin".to_string(), CORS_PROBE_ORIGIN.to_string()));
        extra_headers.push((
            "Access-Control-Request-Method".to_string(),
            "GET".to_string(),
        ));
    }
    let auth = if allow_auth_hdr {
        Auth::None
    } else {
        auth_for(case)
    };
    Ok(RequestSpec {
        method,
        path: path.clone(),
        url: url.to_string(),
        body,
        auth,
        sent_values,
        extra_headers,
    })
}

pub(crate) fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Secret-safe curl auth arguments for `auth` given configured `creds`.
/// Uses shell placeholders (`${RH_<ROLE>_TOKEN}`, `${RH_<ROLE>_COOKIE}`, `${RH_<ROLE>_HEADER}`)
/// and never writes raw secret values into repro strings.
pub fn curl_auth_args_for(auth: &Auth, creds: &Credentials) -> Vec<String> {
    match auth {
        Auth::None => vec![],
        Auth::Forged => vec![format!(
            "-H {}",
            sq(&format!("Authorization: Bearer {FORGED_TOKEN}"))
        )],
        Auth::Role(r) => {
            let rk = role_key(r);
            let mut args = Vec::new();
            let has_token = creds.token(r).is_some();
            let has_cookie = creds.cookie(r).is_some();
            let has_header = creds.header(r).is_some();
            if has_token || (!has_cookie && !has_header) {
                let var = creds
                    .token_envs
                    .get(&rk)
                    .cloned()
                    .unwrap_or_else(|| Credentials::env_var(r));
                args.push(format!("-H \"Authorization: Bearer ${{{var}}}\""));
            }
            if has_cookie {
                args.push(format!(
                    "-H \"Cookie: ${{{}}}\"",
                    Credentials::cookie_env_var(r)
                ));
            }
            if has_header {
                match creds.header_envs.get(&rk) {
                    Some(HeaderEnvKind::ValueVar { name, var }) => {
                        args.push(format!("-H \"{name}: ${{{var}}}\""));
                    }
                    Some(HeaderEnvKind::FullVar(var)) => {
                        args.push(format!("-H \"${{{var}}}\""));
                    }
                    None => {
                        if let Some((name, _)) = creds.header(r) {
                            args.push(format!(
                                "-H \"{name}: ${{{}}}\"",
                                Credentials::header_env_var(r)
                            ));
                        }
                    }
                }
            }
            args
        }
    }
}

/// The curl `-H` argument for an actor. Tokens are never written: a real role becomes the
/// `${RH_<ROLE>_TOKEN}` placeholder (double-quoted so the shell expands it from the environment).
pub fn curl_auth_arg(auth: &Auth) -> Option<String> {
    match auth {
        Auth::Role(r) => Some(format!(
            "-H \"Authorization: Bearer ${{{}}}\"",
            Credentials::env_var(r)
        )),
        Auth::Forged => Some(format!(
            "-H {}",
            sq(&format!("Authorization: Bearer {FORGED_TOKEN}"))
        )),
        Auth::None => None,
    }
}

/// Reproduction command using configured multi-modal credentials (`Token`, `Cookie`, `Header`),
/// with secret placeholders instead of raw values.
pub fn curl_for_auth(spec: &RequestSpec, creds: &Credentials) -> String {
    let mut p: Vec<String> = vec!["curl -sS".into()];
    if spec.method == "HEAD" {
        p.push("-I -X HEAD".into());
    } else {
        p.push(format!("-i -X {}", spec.method));
    }
    p.extend(curl_auth_args_for(&spec.auth, creds));
    for (k, v) in &spec.extra_headers {
        p.push(format!("-H {}", sq(&format!("{k}: {v}"))));
    }
    if let Some((ct, body)) = &spec.body {
        p.push(format!("-H {}", sq(&format!("Content-Type: {ct}"))));
        p.push(format!("--data-raw {}", sq(body)));
    }
    p.push(sq(&spec.url));
    p.join(" ")
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
    if let Some(a) = curl_auth_arg(&spec.auth) {
        p.push(a);
    }
    for (k, v) in &spec.extra_headers {
        p.push(format!("-H {}", sq(&format!("{k}: {v}"))));
    }
    if let Some((ct, body)) = &spec.body {
        p.push(format!("-H {}", sq(&format!("Content-Type: {ct}"))));
        p.push(format!("--data-raw {}", sq(body)));
    }
    p.push(sq(&spec.url));
    p.join(" ")
}
