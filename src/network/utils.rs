//! HTTP core utilities, method safety guards, URL parsers, and header validators.

use super::types::{MAX_HEADER_BYTES, MAX_HEADERS, MAX_PAYLOAD_BYTES, MAX_REDIRECTS};
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

pub fn is_safe_method(m: &str) -> bool {
    matches!(
        m.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

pub fn parse_method(m: &str) -> Result<reqwest::Method> {
    let up = m.trim().to_ascii_uppercase();
    match up.as_str() {
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" => {
            Ok(reqwest::Method::from_bytes(up.as_bytes())?)
        }
        _ => bail!("method must be one of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"),
    }
}

/// http(s) target, normalised by the URL parser, without embedded credentials.
pub fn parse_target(raw: &str) -> Result<reqwest::Url> {
    let u = crate::scope::parse_web_url(raw)?;
    if !u.username().is_empty() || u.password().is_some() {
        bail!("credentials in the URL are not accepted; send an Authorization header instead");
    }
    Ok(u)
}

/// Host without IPv6 brackets.
pub fn host_of(u: &reqwest::Url) -> String {
    u.host_str()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

pub fn hostport(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn port_of(u: &reqwest::Url) -> u16 {
    u.port_or_known_default().unwrap_or(80)
}

pub fn validate_headers(h: &HashMap<String, String>) -> Result<()> {
    if h.len() > MAX_HEADERS {
        bail!("at most {MAX_HEADERS} headers");
    }
    for (k, v) in h {
        let name_ok = !k.is_empty()
            && k.len() <= 128
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        // no CR/LF/NUL/DEL: header injection into the request or the curl argv
        let value_ok = v.len() <= MAX_HEADER_BYTES
            && v.bytes()
                .all(|b| b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80);
        if !name_ok || !value_ok {
            bail!(
                "invalid header '{}'",
                k.chars().take(40).collect::<String>()
            );
        }
    }
    Ok(())
}

pub fn validate_payload(p: &Option<String>) -> Result<()> {
    if p.as_ref().is_some_and(|p| p.len() > MAX_PAYLOAD_BYTES) {
        bail!("payload larger than {MAX_PAYLOAD_BYTES} bytes");
    }
    Ok(())
}

pub fn has_header(h: &HashMap<String, String>, name: &str) -> bool {
    h.keys().any(|k| k.eq_ignore_ascii_case(name))
}

/// First `max` characters (never a partial one), with "..." when something was cut.
pub fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

/// Read at most `cap` bytes of a response body; the bool says whether more was available.
pub fn read_capped(resp: reqwest::blocking::Response, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let _ = resp.take(cap as u64 + 1).read_to_end(&mut buf);
    let truncated = buf.len() > cap;
    buf.truncate(cap);
    (buf, truncated)
}

/// Number of body bytes (up to `cap`) without keeping them.
pub fn count_capped(resp: reqwest::blocking::Response, cap: usize) -> usize {
    std::io::copy(&mut resp.take(cap as u64), &mut std::io::sink()).unwrap_or(0) as usize
}

/// Follow at most 3 redirects and never to another host: a scoped host must not be able to
/// bounce the probe to an internal address.
pub fn same_host_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|a| {
        let first = a
            .previous()
            .first()
            .and_then(|u| u.host_str().map(str::to_owned));
        if a.previous().len() >= MAX_REDIRECTS
            || first.as_deref() != a.url().host_str()
            || !matches!(a.url().scheme(), "http" | "https")
        {
            a.stop()
        } else {
            a.follow()
        }
    })
}

/// How long a scan-side client waits for a connection to be established before giving up.
///
/// A connect timeout only bounds "the host never completed the handshake". A target that accepts
/// the TCP socket and then goes silent (a firewalled port, a dead load balancer, a SYN-lost route)
/// would otherwise hold the request open until the scan-wide deadline, wedging the whole run. It
/// never shortens how long a *connected* server may take to answer, which is what the timing-based
/// checks (`qa.api.slow_response`, time-delay blind SQLi) measure.
///
/// Override with `READYHAI_CONNECT_TIMEOUT_MS` (100..=30_000 ms).
pub const SCAN_CONNECT_TIMEOUT: Duration = Duration::from_millis(5000);
const SCAN_CONNECT_TIMEOUT_MIN_MS: u64 = 100;
const SCAN_CONNECT_TIMEOUT_MAX_MS: u64 = 30_000;

/// The connect timeout in force: [`SCAN_CONNECT_TIMEOUT`], or `READYHAI_CONNECT_TIMEOUT_MS`.
pub fn scan_connect_timeout() -> Duration {
    scan_connect_timeout_from(std::env::var("READYHAI_CONNECT_TIMEOUT_MS").ok().as_deref())
}

/// The env override of [`scan_connect_timeout`] as a pure function: unparsable or absent input
/// keeps the default, anything else is clamped into the supported range.
pub(crate) fn scan_connect_timeout_from(raw: Option<&str>) -> Duration {
    match raw.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(ms) => Duration::from_millis(
            SCAN_CONNECT_TIMEOUT_MIN_MS
                .max(ms)
                .min(SCAN_CONNECT_TIMEOUT_MAX_MS),
        ),
        None => SCAN_CONNECT_TIMEOUT,
    }
}

/// A connect timeout for scan-side clients, as an existing [`reqwest::blocking::ClientBuilder`]
/// transform. It changes nothing else: redirect policy, TLS validation, proxy handling, headers
/// and pooling stay exactly as the caller configured them, so clients that deliberately differ
/// (strict-TLS vs `danger_accept_invalid_certs`, `no_proxy`, per-site redirect policies) must not
/// be merged into one shared client.
pub fn with_connect_timeout(
    b: reqwest::blocking::ClientBuilder,
) -> reqwest::blocking::ClientBuilder {
    connect_timeout_builder(b, scan_connect_timeout())
}

/// [`with_connect_timeout`] with an explicit bound, for callers (and tests) that need a connect
/// timeout shorter than the scan default.
pub fn connect_timeout_builder(
    b: reqwest::blocking::ClientBuilder,
    connect: Duration,
) -> reqwest::blocking::ClientBuilder {
    b.connect_timeout(connect)
}

pub fn http_client(timeout_ms: u64, fresh_connections: bool) -> reqwest::blocking::Client {
    let mut b = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_millis(timeout_ms))
        .redirect(same_host_redirects())
        // diagnostics must be able to talk to staging hosts with broken certificates; the TLS
        // audit reports the certificate problems itself
        .danger_accept_invalid_certs(true);
    if fresh_connections {
        // pool_max_idle_per_host(0) forces zero connection reuse across iterations
        b = b.pool_max_idle_per_host(0);
    }
    b.build().unwrap_or_default()
}

pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
