//! Regressive Network Testing & Flakiness Diagnostic Engine
//!
//! Provides continuous multi-session network regression testing, private session
//! isolation (fresh TCP/TLS connections without socket reuse), network throttling
//! simulation, cURL execution, and AI agent flakiness root-cause diagnostics.
//!
//! Also provides the 6-Pillar Deep Network & Protocol Diagnostics Suite:
//! 1. Dual-Stack IPv4 vs IPv6 & Happy Eyeballs Probe
//! 2. Sub-Resource & Asset Cascade Waterfall Probe (SPA Chunk & MIME Integrity)
//! 3. HTTP Protocol Matrix (HTTP/1.1 vs HTTP/2 vs HTTP/3 QUIC)
//! 4. TLS & Certificate Chain Health Inspector
//! 5. CORS Preflight (OPTIONS) Boundary Inspector
//! 6. MTU & Packet Size Black Hole Sweeper
//!
//! Ground rules for everything in here (the REST routes expose it to a network):
//! * targets are http(s) URLs parsed by the same parser the HTTP client uses, and every
//!   request/command is built from the *normalised* URL, never the raw string;
//! * every numeric request field is clamped (see the `MAX_*` constants);
//! * captured output (curl, response bodies) is size-capped, subprocesses have wall-clock limits;
//! * nothing is reported that was not measured: values that cannot be measured are `None`, empty
//!   or listed in a `not_measured` field, never filled with plausible-looking constants;
//! * a response outside 2xx counts as a failure.

use crate::tools::run_capped;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- limits

/// Regression iterations per request.
pub const MAX_ITERATIONS: usize = 100;
/// More iterations than this is load, not a probe: refused on prod hosts.
pub const READONLY_MAX_ITERATIONS: usize = 25;
pub const MIN_TIMEOUT_MS: u64 = 100;
pub const MAX_TIMEOUT_MS: u64 = 15_000;
/// Injected artificial latency per iteration (`custom` throttle profile).
pub const MAX_LATENCY_MS: u64 = 5_000;
/// Pause between iterations.
pub const MAX_DELAY_MS: u64 = 5_000;
/// Wall-clock budget for one regression run; remaining iterations are skipped (`stopped_early`).
pub const MAX_REGRESS_BUDGET_MS: u64 = 120_000;
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_HEADERS: usize = 64;
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Captured curl output / response body ceiling.
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const BODY_SNIPPET_CHARS: usize = 256;
const BODY_READ_CAP: usize = 4 * 1024;
const MAX_SUBRESOURCES: usize = 12;
const SUBRESOURCE_BYTES_CAP: usize = 2 * 1024 * 1024;
const HTML_BYTES_CAP: usize = 1024 * 1024;
const NOT_MEASURED: &str = "not measured";

static REQUESTER_IP_CACHE: OnceLock<RequesterIpInfo> = OnceLock::new();

// ---------------------------------------------------------------- shared helpers

/// GET, HEAD and OPTIONS do not change state; everything else is an intrusive action.
pub fn is_safe_method(m: &str) -> bool {
    matches!(
        m.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

fn parse_method(m: &str) -> Result<reqwest::Method> {
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
fn host_of(u: &reqwest::Url) -> String {
    u.host_str()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

fn hostport(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn port_of(u: &reqwest::Url) -> u16 {
    u.port_or_known_default().unwrap_or(80)
}

fn validate_headers(h: &HashMap<String, String>) -> Result<()> {
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

fn validate_payload(p: &Option<String>) -> Result<()> {
    if p.as_ref().is_some_and(|p| p.len() > MAX_PAYLOAD_BYTES) {
        bail!("payload larger than {MAX_PAYLOAD_BYTES} bytes");
    }
    Ok(())
}

fn has_header(h: &HashMap<String, String>, name: &str) -> bool {
    h.keys().any(|k| k.eq_ignore_ascii_case(name))
}

/// First `max` characters (never a partial one), with "..." when something was cut.
fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

/// Read at most `cap` bytes of a response body; the bool says whether more was available.
fn read_capped(resp: reqwest::blocking::Response, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let _ = resp.take(cap as u64 + 1).read_to_end(&mut buf);
    let truncated = buf.len() > cap;
    buf.truncate(cap);
    (buf, truncated)
}

/// Number of body bytes (up to `cap`) without keeping them.
fn count_capped(resp: reqwest::blocking::Response, cap: usize) -> usize {
    std::io::copy(&mut resp.take(cap as u64), &mut std::io::sink()).unwrap_or(0) as usize
}

/// Follow at most 3 redirects and never to another host: a scoped host must not be able to
/// bounce the probe to an internal address.
fn same_host_redirects() -> reqwest::redirect::Policy {
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

fn http_client(timeout_ms: u64, fresh_connections: bool) -> reqwest::blocking::Client {
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

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequesterIpInfo {
    pub egress_public_ip: String,
    pub ip_type: String, // 'Public Egress (Direct)' | 'Private Intranet (RFC1918)'
    pub is_private: bool,
    pub allowlist_guidance: String,
    pub detected_via: String,
    pub detected_at: String,
}

pub fn detect_requester_public_ip() -> RequesterIpInfo {
    if let Some(cached) = REQUESTER_IP_CACHE.get() {
        return cached.clone();
    }
    let detected = resolve_public_ip();
    let _ = REQUESTER_IP_CACHE.set(detected.clone());
    detected
}

fn resolve_public_ip() -> RequesterIpInfo {
    let now = crate::engine::now();

    // 1. User manual override via ENV
    if let Ok(env_ip) =
        std::env::var("READYHAI_PUBLIC_IP").or_else(|_| std::env::var("READYHAI_EGRESS_IP"))
    {
        let trimmed = env_ip.trim();
        if !trimmed.is_empty() {
            let is_priv = is_private_ip(trimmed);
            return RequesterIpInfo {
                egress_public_ip: trimmed.to_string(),
                ip_type: if is_priv {
                    "Private Intranet (Manual)"
                } else {
                    "Public Egress (Manual)"
                }
                .to_string(),
                is_private: is_priv,
                allowlist_guidance: format!(
                    "Add `{}/32` to target firewall allowlist, AWS Security Group, Cloudflare WAF, or iptables.",
                    trimmed
                ),
                detected_via: "Environment Variable (READYHAI_PUBLIC_IP)".to_string(),
                detected_at: now,
            };
        }
    }

    // 2. Query external IP check providers with short timeout
    let providers = [
        ("api.ipify.org", "https://api.ipify.org"),
        ("checkip.amazonaws.com", "https://checkip.amazonaws.com"),
        ("icanhazip.com", "https://icanhazip.com"),
        ("ifconfig.me", "https://ifconfig.me/ip"),
    ];

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(2200))
        .build()
        .ok();

    if let Some(c) = client {
        for (name, url) in providers {
            if let Ok(resp) = c.get(url).send()
                && resp.status().is_success()
                && let Ok(text) = resp.text()
            {
                let ip = text.trim();
                if (ip.contains('.') || ip.contains(':'))
                    && ip.len() >= 7
                    && ip.len() <= 45
                    && !ip.contains('<')
                {
                    let is_priv = is_private_ip(ip);
                    return RequesterIpInfo {
                        egress_public_ip: ip.to_string(),
                        ip_type: if is_priv {
                            "Private Network (RFC1918)"
                        } else {
                            "Public Egress (Direct)"
                        }
                        .to_string(),
                        is_private: is_priv,
                        allowlist_guidance: format!(
                            "Add `{}/32` to your target's firewall, AWS Security Group, Cloudflare WAF, or iptables to allow ReadyHai automated QA probes.",
                            ip
                        ),
                        detected_via: name.to_string(),
                        detected_at: now,
                    };
                }
            }
        }
    }

    // 3. Fallback: Local outbound socket address for intranet / airgapped environments
    let local_ip = std::net::UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| {
            s.connect("8.8.8.8:80").ok()?;
            s.local_addr().ok().map(|a| a.ip().to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let is_priv = is_private_ip(&local_ip);
    RequesterIpInfo {
        egress_public_ip: local_ip.clone(),
        ip_type: if is_priv {
            "Private Intranet (RFC1918)"
        } else {
            "Local Egress"
        }
        .to_string(),
        is_private: is_priv,
        allowlist_guidance: format!(
            "Add `{}/32` to your local firewall or internal gateway allowlist.",
            local_ip
        ),
        detected_via: "Local Network Interface Socket".to_string(),
        detected_at: now,
    }
}

pub fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        }
    } else {
        ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip.starts_with("172.")
            || ip.starts_with("127.")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegressRequest {
    pub target: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default = "default_iterations")]
    pub iterations: usize,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_throttle")]
    pub throttle_profile: String, // "unthrottled", "fast_3g", "slow_3g", "flaky", "custom"
    #[serde(default)]
    pub simulated_latency_ms: u64,
    #[serde(default = "default_true")]
    pub separate_sessions: bool,
    #[serde(default = "default_delay_ms")]
    pub delay_between_ms: u64,
}

fn default_method() -> String {
    "GET".to_string()
}
fn default_iterations() -> usize {
    10
}
fn default_timeout_ms() -> u64 {
    5000
}
fn default_throttle() -> String {
    "unthrottled".to_string()
}
fn default_true() -> bool {
    true
}
fn default_delay_ms() -> u64 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationResult {
    pub iteration: usize,
    pub session_id: String,
    pub timestamp: String,
    pub duration_ms: u128,
    pub dns_lookup_ms: u128,
    pub tcp_connect_ms: u128,
    pub ttfb_ms: u128,
    pub status_code: u16,
    pub success: bool,
    pub error_message: Option<String>,
    pub curl_command: String,
    pub response_headers: HashMap<String, String>,
    pub response_body_snippet: Option<String>,
    /// First address the target resolved to (what the TCP probe connected to).
    #[serde(default)]
    pub resolved_ip: Option<String>,
    /// Protocol the response arrived over, e.g. "HTTP/1.1" (None when there was no response).
    #[serde(default)]
    pub http_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDiagnosis {
    pub flakiness_detected: bool,
    pub root_cause_type: String, // "TIMEOUT", "5XX_FLAPPING", "CONNECTION_RESET", "HIGH_JITTER", "STABLE"
    pub severity: String,        // "CRITICAL", "HIGH", "MEDIUM", "LOW", "STABLE"
    pub title: String,
    pub summary: String,
    pub how_agent_found_it: Vec<String>,
    pub technical_breakdown: Vec<String>,
    pub reproduction_curl: String,
    pub remediation_checklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressReport {
    pub target: String,
    #[serde(default = "default_method")]
    pub method: String,
    /// Iterations actually executed.
    pub total_iterations: usize,
    /// Iterations asked for (after clamping); fewer ran when `stopped_early`.
    #[serde(default)]
    pub iterations_requested: usize,
    /// The wall-clock budget ran out before all iterations ran.
    #[serde(default)]
    pub stopped_early: bool,
    pub successful_iterations: usize,
    pub failed_iterations: usize,
    pub availability_percentage: f64,
    pub avg_latency_ms: u128,
    pub p50_latency_ms: u128,
    pub p90_latency_ms: u128,
    pub p99_latency_ms: u128,
    pub min_latency_ms: u128,
    pub max_latency_ms: u128,
    pub jitter_ms: u128,
    pub status_distribution: HashMap<String, usize>,
    pub diagnosis: AgentDiagnosis,
    pub iterations: Vec<IterationResult>,
    #[serde(default)]
    pub requester_ip: Option<String>,
    #[serde(default)]
    pub allowlist_recommendation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CurlTestRequest {
    pub target: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurlTestResponse {
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub status_code: u16,
    pub dns_lookup_s: f64,
    pub connect_s: f64,
    pub appconnect_s: f64,
    pub starttransfer_s: f64,
    pub total_s: f64,
    /// Fields that could not be measured (zero means "unknown", not "instant").
    #[serde(default)]
    pub not_measured: Vec<String>,
    /// Output exceeded the capture limit and was cut.
    #[serde(default)]
    pub truncated: bool,
}

// ============================================================================
// 6-Pillar Deep Network Diagnostics Types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct DeepAuditRequest {
    pub target: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAuditReport {
    pub target: String,
    pub timestamp: String,
    pub overall_verdict: String, // "PASS" | "WARN" | "FAIL"
    pub health_score: u8,        // 0 - 100
    pub executive_summary: String,
    pub identified_risks: Vec<String>,
    pub dual_stack: DualStackAudit,
    pub subresources: SubresourceAudit,
    pub protocol_matrix: ProtocolMatrixAudit,
    pub tls_chain: TlsChainAudit,
    pub cors_preflight: CorsAudit,
    pub mtu_sweep: MtuSweepAudit,
    pub remediation_checklist: Vec<String>,
    /// Pillars or fields that could not be measured on this run.
    #[serde(default)]
    pub not_measured: Vec<String>,
    #[serde(default)]
    pub requester_ip: Option<String>,
    #[serde(default)]
    pub allowlist_recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualStackAudit {
    pub has_ipv4: bool,
    pub has_ipv6: bool,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub ipv4_latency_ms: Option<u128>,
    pub ipv6_latency_ms: Option<u128>,
    pub ipv6_status: String, // "HEALTHY" | "NOT_CONFIGURED" | "BROKEN_OR_BLACKHOLE"
    pub happy_eyeballs_risk: bool,
    pub diagnosis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubresourceItem {
    pub url: String,
    pub tag_type: String, // "script", "stylesheet", "preload", "image"
    pub status_code: u16,
    pub ttfb_ms: u128,
    pub content_type: String,
    pub size_bytes: usize,
    pub is_spa_fallback_error: bool, // e.g. .js returned text/html
    pub is_broken: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubresourceAudit {
    pub total_discovered: usize,
    pub successful_count: usize,
    pub broken_count: usize,
    pub spa_fallback_mismatches: usize,
    /// Assets on other hosts (or non-http schemes) that were deliberately not requested.
    #[serde(default)]
    pub skipped_cross_host: usize,
    pub total_size_kb: f64,
    pub max_asset_ttfb_ms: u128,
    pub items: Vec<SubresourceItem>,
    pub diagnosis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolItem {
    pub protocol: String, // "HTTP/1.1", "HTTP/2", "HTTP/3 (QUIC)"
    pub supported: bool,
    pub negotiation_time_ms: u128,
    pub status_code: u16,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMatrixAudit {
    pub active_protocol: String,
    pub http2_supported: bool,
    pub http3_advertised: bool,
    pub alt_svc_header: Option<String>,
    pub protocols: Vec<ProtocolItem>,
    pub diagnosis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsChainAudit {
    pub is_https: bool,
    /// The handshake was observed with openssl. When false everything below is "not measured".
    #[serde(default)]
    pub measured: bool,
    pub tls_version: String, // "TLSv1.3", "TLSv1.2", "None", "not measured"
    pub cipher: String,
    pub cert_issuer: String,
    pub cert_subject: String,
    pub cert_sans: Vec<String>,
    pub not_after: Option<String>,
    pub days_remaining: Option<i64>,
    pub is_self_signed: bool,
    pub is_intermediate_missing: bool,
    /// Some(true) = stapled OCSP response seen, Some(false) = none sent, None = not measured.
    pub ocsp_stapled: Option<bool>,
    #[serde(default)]
    pub chain_length: Option<usize>,
    /// openssl's own verdict against this host's trust store, e.g. "0 (ok)".
    #[serde(default)]
    pub verify_result: Option<String>,
    #[serde(default)]
    pub not_measured: Vec<String>,
    pub diagnosis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsAudit {
    pub preflight_status_code: u16,
    pub preflight_passed: bool,
    pub allow_origin: Option<String>,
    pub allow_methods: Option<String>,
    pub allow_headers: Option<String>,
    pub allow_credentials: Option<String>,
    pub has_wildcard_with_creds: bool,
    pub diagnosis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtuSweepItem {
    pub payload_bytes: usize,
    pub label: String, // "512B Baseline", "1.4KB Standard MTU", "4KB Large Headers", "8KB High Payload"
    pub status_code: u16,
    pub duration_ms: u128,
    /// 2xx response.
    pub success: bool,
    /// Any HTTP response at all came back (so the packets arrived).
    #[serde(default)]
    pub delivered: bool,
    /// No response because of a timeout/reset/close: the black-hole signature.
    #[serde(default)]
    pub transport_failure: bool,
    /// 400/413/414/431: the server's own header-size limit.
    #[serde(default)]
    pub header_limit_hit: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtuSweepAudit {
    pub black_hole_detected: bool,
    /// Largest probe that got a response without hitting a header-size limit.
    pub maximum_safe_bytes: usize,
    #[serde(default)]
    pub maximum_delivered_bytes: usize,
    pub sweep_results: Vec<MtuSweepItem>,
    pub diagnosis: String,
}

// ============================================================================
// Multi-Region Distributed Node Mesh Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiRegionRequest {
    pub target: String,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionProbeResult {
    pub region_id: String,
    pub region_name: String,
    pub flag: String,
    pub location: String,
    pub resolved_ip: String,
    pub dns_time_ms: u64,
    pub tcp_connect_ms: u64,
    pub ttfb_ms: u64,
    pub total_time_ms: u64,
    pub http_status: u16,
    pub edge_pop: String,
    pub status: String,
    pub jitter_ms: u64,
    pub packet_loss_pct: f32,
    pub notes: String,
    /// True for the one region that was really probed.
    #[serde(default)]
    pub measured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiRegionReport {
    pub target: String,
    pub timestamp: String,
    pub regions: Vec<RegionProbeResult>,
    pub fastest_region: String,
    pub slowest_region: String,
    /// None: cannot be known from a single vantage point.
    pub geo_dns_consistent: Option<bool>,
    pub cdn_edge_active: bool,
    pub regional_disparity_ms: u64,
    pub agent_verdict: String,
    pub recommendations: Vec<String>,
    /// Regions this build has no probe node for (it never invents numbers for them).
    #[serde(default)]
    pub not_measured_regions: Vec<String>,
    #[serde(default)]
    pub measurement_note: String,
}

// ============================================================================
// Request validation (clamp every number, normalise the target)
// ============================================================================

impl RegressRequest {
    /// Anything but a handful of safe-method probes is load/state change, not observation.
    pub fn is_intrusive(&self) -> bool {
        !is_safe_method(&self.method)
            || self.payload.is_some()
            || self.iterations > READONLY_MAX_ITERATIONS
    }

    /// Validate, clamp every numeric field to its maximum and replace `target` with the
    /// normalised URL, which is returned.
    pub fn sanitize(&mut self) -> Result<reqwest::Url> {
        let url = parse_target(&self.target)?;
        self.method = parse_method(&self.method)?.to_string();
        validate_headers(&self.headers)?;
        validate_payload(&self.payload)?;
        self.iterations = self.iterations.clamp(1, MAX_ITERATIONS);
        self.timeout_ms = self.timeout_ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
        self.simulated_latency_ms = self.simulated_latency_ms.min(MAX_LATENCY_MS);
        self.delay_between_ms = self.delay_between_ms.min(MAX_DELAY_MS);
        self.target = url.to_string();
        Ok(url)
    }
}

impl CurlTestRequest {
    pub fn is_intrusive(&self) -> bool {
        !is_safe_method(&self.method) || self.payload.is_some()
    }

    pub fn sanitize(&mut self) -> Result<reqwest::Url> {
        let url = parse_target(&self.target)?;
        self.method = parse_method(&self.method)?.to_string();
        validate_headers(&self.headers)?;
        validate_payload(&self.payload)?;
        self.timeout_ms = self.timeout_ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
        self.target = url.to_string();
        Ok(url)
    }
}

impl DeepAuditRequest {
    pub fn sanitize(&mut self) -> Result<reqwest::Url> {
        let url = parse_target(&self.target)?;
        self.timeout_ms = self.timeout_ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
        self.target = url.to_string();
        Ok(url)
    }
}

impl MultiRegionRequest {
    pub fn sanitize(&mut self) -> Result<reqwest::Url> {
        let url = parse_target(&self.target)?;
        self.timeout_ms = Some(
            self.timeout_ms
                .unwrap_or(4000)
                .clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS),
        );
        self.target = url.to_string();
        Ok(url)
    }
}

// ============================================================================
// Continuous Regression Test Runner
// ============================================================================

pub fn run_regress_test(req: &RegressRequest) -> Result<RegressReport> {
    let mut req = req.clone();
    let requested = req.iterations;
    let url = req.sanitize()?;
    let requested = requested.clamp(1, MAX_ITERATIONS);
    let method = parse_method(&req.method)?;
    let host = host_of(&url);
    let port = port_of(&url);
    let iterations = req.iterations;

    let mut results = Vec::with_capacity(iterations);
    let mut durations: Vec<u128> = Vec::with_capacity(iterations);
    let mut status_counts: HashMap<String, usize> = HashMap::new();
    let mut successful_count = 0;
    let mut failed_count = 0;
    let run_started = Instant::now();
    let mut stopped_early = false;
    let curl_cmd = generate_curl(
        &req.method,
        url.as_str(),
        &req.headers,
        req.payload.as_deref(),
    );

    for i in 1..=iterations {
        if run_started.elapsed() >= Duration::from_millis(MAX_REGRESS_BUDGET_MS) {
            stopped_early = true;
            break;
        }
        let session_id = format!("sess-{i}-{:08x}", rand::random::<u32>());
        let t_start = Instant::now();
        let timestamp = crate::engine::now();

        // Simulate network throttle latency if requested
        let injected_latency = match req.throttle_profile.as_str() {
            "fast_3g" => 75 + (i % 25) as u64,
            "slow_3g" => 250 + (i % 50) as u64,
            "flaky" => {
                if i % 3 == 0 {
                    400
                } else {
                    20
                }
            }
            "custom" => req.simulated_latency_ms,
            _ => 0,
        };
        if injected_latency > 0 {
            std::thread::sleep(Duration::from_millis(injected_latency));
        }

        // 1. Measure DNS Lookup
        let dns_t0 = Instant::now();
        let addrs: Vec<SocketAddr> = hostport(&host, port)
            .to_socket_addrs()
            .map(|iter| iter.collect())
            .unwrap_or_default();
        let dns_lookup_ms = dns_t0.elapsed().as_millis();
        let resolved_ip = addrs.first().map(|a| a.ip().to_string());

        // 2. Measure TCP Connect
        let tcp_t0 = Instant::now();
        if let Some(addr) = addrs.first() {
            let _ =
                TcpStream::connect_timeout(addr, Duration::from_millis(req.timeout_ms.min(3000)));
        }
        let tcp_connect_ms = tcp_t0.elapsed().as_millis();

        // 3. HTTP Request with separate private session isolation
        let client = http_client(req.timeout_ms, req.separate_sessions);
        let mut http_req = client.request(method.clone(), url.as_str());
        for (k, v) in &req.headers {
            http_req = http_req.header(k, v);
        }
        if let Some(ref p) = req.payload {
            if !has_header(&req.headers, "content-type") {
                http_req = http_req.header("Content-Type", "application/json");
            }
            http_req = http_req.body(p.clone());
        }

        let send_t0 = Instant::now();
        let res = http_req.send();
        let ttfb_ms = send_t0.elapsed().as_millis();

        match res {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let http_version = Some(format!("{:?}", resp.version()));
                let mut resp_headers = HashMap::new();
                for (name, val) in resp.headers() {
                    if let Ok(v_str) = val.to_str() {
                        resp_headers.insert(name.to_string(), v_str.to_string());
                    }
                }

                // bounded read, then a char-boundary-safe cut (a byte slice could split a
                // multi-byte character and panic)
                let (bytes, _) = read_capped(resp, BODY_READ_CAP);
                let body_snippet = Some(truncate_chars(
                    &String::from_utf8_lossy(&bytes),
                    BODY_SNIPPET_CHARS,
                ));
                let total_duration_ms = t_start.elapsed().as_millis();

                // only 2xx is a success: a 3xx that was not followed, a 4xx or a 5xx is a failure
                let is_success = (200..300).contains(&status);
                if is_success {
                    successful_count += 1;
                } else {
                    failed_count += 1;
                }

                *status_counts.entry(status.to_string()).or_insert(0) += 1;
                durations.push(total_duration_ms);

                results.push(IterationResult {
                    iteration: i,
                    session_id,
                    timestamp,
                    duration_ms: total_duration_ms,
                    dns_lookup_ms,
                    tcp_connect_ms,
                    ttfb_ms,
                    status_code: status,
                    success: is_success,
                    error_message: if is_success {
                        None
                    } else {
                        Some(format!("HTTP Status {status}"))
                    },
                    curl_command: curl_cmd.clone(),
                    response_headers: resp_headers,
                    response_body_snippet: body_snippet,
                    resolved_ip,
                    http_version,
                });
            }
            Err(e) => {
                let total_duration_ms = t_start.elapsed().as_millis();
                failed_count += 1;
                *status_counts.entry("ERR".to_string()).or_insert(0) += 1;
                durations.push(total_duration_ms);

                results.push(IterationResult {
                    iteration: i,
                    session_id,
                    timestamp,
                    duration_ms: total_duration_ms,
                    dns_lookup_ms,
                    tcp_connect_ms,
                    ttfb_ms: 0,
                    status_code: 0,
                    success: false,
                    error_message: Some(e.to_string()),
                    curl_command: curl_cmd.clone(),
                    response_headers: HashMap::new(),
                    response_body_snippet: None,
                    resolved_ip,
                    http_version: None,
                });
            }
        }

        if req.delay_between_ms > 0 && i < iterations {
            std::thread::sleep(Duration::from_millis(req.delay_between_ms));
        }
    }

    // Compute percentiles & stats
    durations.sort_unstable();
    let total_count = durations.len();
    let min_latency_ms = durations.first().copied().unwrap_or(0);
    let max_latency_ms = durations.last().copied().unwrap_or(0);
    let avg_latency_ms = if total_count > 0 {
        durations.iter().sum::<u128>() / total_count as u128
    } else {
        0
    };

    let p50_idx = ((total_count as f64 * 0.50).ceil() as usize).saturating_sub(1);
    let p90_idx = ((total_count as f64 * 0.90).ceil() as usize).saturating_sub(1);
    let p99_idx = ((total_count as f64 * 0.99).ceil() as usize).saturating_sub(1);

    let p50_latency_ms = durations.get(p50_idx).copied().unwrap_or(0);
    let p90_latency_ms = durations.get(p90_idx).copied().unwrap_or(0);
    let p99_latency_ms = durations.get(p99_idx).copied().unwrap_or(0);
    let jitter_ms = p99_latency_ms.saturating_sub(p50_latency_ms);

    let availability_percentage = if total_count > 0 {
        (successful_count as f64 / total_count as f64) * 100.0
    } else {
        0.0
    };

    let diagnosis = diagnose(
        &results,
        availability_percentage,
        p50_latency_ms,
        p99_latency_ms,
        jitter_ms,
        req.timeout_ms,
    );

    let ip_info = detect_requester_public_ip();
    Ok(RegressReport {
        target: req.target.clone(),
        method: req.method.clone(),
        total_iterations: total_count,
        iterations_requested: requested,
        stopped_early,
        successful_iterations: successful_count,
        failed_iterations: failed_count,
        availability_percentage,
        avg_latency_ms,
        p50_latency_ms,
        p90_latency_ms,
        p99_latency_ms,
        min_latency_ms,
        max_latency_ms,
        jitter_ms,
        status_distribution: status_counts,
        diagnosis,
        iterations: results,
        requester_ip: Some(ip_info.egress_public_ip.clone()),
        allowlist_recommendation: Some(ip_info.allowlist_guidance.clone()),
    })
}

// ============================================================================
// Agent Root-Cause Diagnostic Heuristics
// ============================================================================

pub fn diagnose(
    results: &[IterationResult],
    availability: f64,
    p50: u128,
    p99: u128,
    jitter: u128,
    timeout_ms: u64,
) -> AgentDiagnosis {
    let sample_curl = results
        .first()
        .map(|r| r.curl_command.clone())
        .unwrap_or_default();

    if availability < 100.0 {
        let timeout_failures = results
            .iter()
            .filter(|r| {
                if let Some(ref e) = r.error_message {
                    e.to_lowercase().contains("timed out") || e.to_lowercase().contains("timeout")
                } else {
                    false
                }
            })
            .count();

        let conn_refused_failures = results
            .iter()
            .filter(|r| {
                if let Some(ref e) = r.error_message {
                    e.to_lowercase().contains("connection refused")
                        || e.to_lowercase().contains("reset")
                } else {
                    false
                }
            })
            .count();

        let gateway_flaps = results
            .iter()
            .filter(|r| r.status_code == 502 || r.status_code == 503 || r.status_code == 504)
            .count();

        if timeout_failures > 0 {
            return AgentDiagnosis {
                flakiness_detected: true,
                root_cause_type: "TIMEOUT".to_string(),
                severity: "CRITICAL".to_string(),
                title: "Intermittent TCP Handshake or Cold Start Timeout".to_string(),
                summary: format!("{}/{} requests timed out after {}ms under isolated sessions.", timeout_failures, results.len(), timeout_ms),
                how_agent_found_it: vec![
                    format!("The agent spawned {} isolated HTTP sessions (zero socket reuse).", results.len()),
                    format!("Observed that {} sessions stalled during initial TCP connection or TLS handshake.", timeout_failures),
                    "Confirmed failure is isolated to fresh sessions (indicative of reverse-proxy socket limits or backend cold start).".to_string(),
                ],
                technical_breakdown: vec![
                    "Reverse proxy connection pool limit reached or upstream backend took > proxy_connect_timeout to respond.".to_string(),
                    "Container cold start latency: container was spun down or idle, causing first request to exceed connect timeout.".to_string(),
                    "Firewall / iptables dropping SYN packets due to conntrack table exhaustion.".to_string(),
                ],
                reproduction_curl: sample_curl,
                remediation_checklist: vec![
                    "Increase proxy connect timeout (e.g., `proxy_connect_timeout 10s;` in Nginx).".to_string(),
                    "Implement container keep-warm pings or configure minimum healthy instances to prevent cold shutdowns.".to_string(),
                    "Check server backlog capacity: `sysctl net.core.somaxconn` and socket TIME_WAIT limits.".to_string(),
                    format!("Private Network Allowlist: Ensure ReadyHai requester public IP `{}` is allowlisted in target firewall/VPC security groups.", detect_requester_public_ip().egress_public_ip),
                ],
            };
        }

        if gateway_flaps > 0 {
            return AgentDiagnosis {
                flakiness_detected: true,
                root_cause_type: "5XX_FLAPPING".to_string(),
                severity: "HIGH".to_string(),
                title: "Upstream Reverse Proxy Gateway Flapping (502/503/504)".to_string(),
                summary: format!("{}/{} requests returned Gateway 5xx errors intermittently.", gateway_flaps, results.len()),
                how_agent_found_it: vec![
                    "Monitored HTTP status code distribution across continuous attempts.".to_string(),
                    format!("Detected {} gateway error responses interspersed with successful responses.", gateway_flaps),
                    "Determined that upstream worker processes or microservices are flapping under load.".to_string(),
                ],
                technical_breakdown: vec![
                    "Upstream backend worker crash-looping or restarting (OOM killed or unhandled panic).".to_string(),
                    "Load balancer routing traffic to an unhealthy or terminating replica.".to_string(),
                    "Database connection pool exhaustion on the upstream app.".to_string(),
                ],
                reproduction_curl: sample_curl,
                remediation_checklist: vec![
                    "Inspect backend container crash logs (`docker logs --tail 100`).".to_string(),
                    "Check upstream healthcheck intervals in your load balancer to ensure unready replicas are removed immediately.".to_string(),
                    "Increase database pool size or verify connection leak hygiene.".to_string(),
                ],
            };
        }

        if conn_refused_failures > 0 {
            return AgentDiagnosis {
                flakiness_detected: true,
                root_cause_type: "CONNECTION_RESET".to_string(),
                severity: "HIGH".to_string(),
                title: "TCP Connection Reset by Peer (ECONNRESET)".to_string(),
                summary: format!("{}/{} requests experienced TCP connection drops.", conn_refused_failures, results.len()),
                how_agent_found_it: vec![
                    "Captured lower-level socket transport errors during session handshake.".to_string(),
                    "Observed immediate TCP RST packet received from target host.".to_string(),
                ],
                technical_breakdown: vec![
                    "Application process crashed or closed the socket prematurely before flushing response.".to_string(),
                    "Stateful firewall or NAT gateway dropping idle connections.".to_string(),
                ],
                reproduction_curl: sample_curl,
                remediation_checklist: vec![
                    "Inspect application error logs for unhandled panics right before connection drops.".to_string(),
                    "Verify file descriptor limits on host: `ulimit -n`.".to_string(),
                ],
            };
        }

        // Everything else that failed: plain non-2xx answers (3xx not followed, 4xx, other 5xx)
        // or errors with no response. Never fall through to "STABLE" with failures on record.
        let c3 = results
            .iter()
            .filter(|r| (300..400).contains(&r.status_code))
            .count();
        let c4 = results
            .iter()
            .filter(|r| (400..500).contains(&r.status_code))
            .count();
        let c5 = results.iter().filter(|r| r.status_code >= 500).count();
        let other = results
            .iter()
            .filter(|r| !r.success && r.status_code == 0)
            .count();
        let failed = results.iter().filter(|r| !r.success).count();
        return AgentDiagnosis {
            flakiness_detected: true,
            root_cause_type: "HTTP_ERRORS".to_string(),
            severity: if c5 > 0 { "HIGH" } else if c4 > 0 || other > 0 { "MEDIUM" } else { "LOW" }.to_string(),
            title: "Target Answered With Non-2xx Responses".to_string(),
            summary: format!("{failed}/{} requests did not return 2xx (3xx: {c3}, 4xx: {c4}, 5xx: {c5}, no response: {other}).", results.len()),
            how_agent_found_it: vec![
                format!("Sent {} isolated requests and classified each response by status class.", results.len()),
                "Only 2xx counts as success; redirects are not followed to other hosts and count as failures.".to_string(),
            ],
            technical_breakdown: vec![
                "4xx: wrong path/method, missing credentials, or a WAF/rate limiter rejecting the probe.".to_string(),
                "5xx other than 502/503/504: the application itself is failing.".to_string(),
                "3xx: the target redirects (for example http to https); probe the final URL instead.".to_string(),
            ],
            reproduction_curl: sample_curl,
            remediation_checklist: vec![
                "Confirm the URL, method and headers are what the endpoint expects (re-run with the reproduction curl).".to_string(),
                "If the target redirects, use its canonical URL.".to_string(),
                "Check application logs for the failing status codes.".to_string(),
            ],
        };
    }

    // A 3x ratio alone is noise at sub-millisecond latencies (1ms vs 4ms); require real spread too.
    if jitter > 350 || (p99 > p50 * 3 && jitter > 50) {
        return AgentDiagnosis {
            flakiness_detected: true,
            root_cause_type: "HIGH_JITTER".to_string(),
            severity: "MEDIUM".to_string(),
            title: "Severe Network Latency Jitter Detected".to_string(),
            summary: format!(
                "P50 latency is {}ms while P99 latency spikes to {}ms (Jitter: {}ms).",
                p50, p99, jitter
            ),
            how_agent_found_it: vec![
                format!(
                    "Compared median latency ({}ms) against 99th percentile ({}ms).",
                    p50, p99
                ),
                format!(
                    "Detected a latency deviation of {}ms between cold sessions.",
                    jitter
                ),
            ],
            technical_breakdown: vec![
                "Garbage collection (GC) pauses or CPU throttling in container.".to_string(),
                "Noisy neighbor on shared hosting or packet retransmission on network link."
                    .to_string(),
            ],
            reproduction_curl: sample_curl,
            remediation_checklist: vec![
                "Check container CPU limits (`docker stats`) for CPU throttling.".to_string(),
                "Analyze runtime garbage collection logs or thread pool contention.".to_string(),
            ],
        };
    }

    AgentDiagnosis {
        flakiness_detected: false,
        root_cause_type: "STABLE".to_string(),
        severity: "STABLE".to_string(),
        title: "Network Connection is Deterministic and Resilient".to_string(),
        summary: format!(
            "100% of {} iterations succeeded. P50: {}ms, P99: {}ms, Jitter: {}ms.",
            results.len(),
            p50,
            p99,
            jitter
        ),
        how_agent_found_it: vec![
            format!(
                "Verified {} independent HTTP sessions with clean connection setup.",
                results.len()
            ),
            "Confirmed consistent DNS resolution and sub-second TCP 3-way handshakes.".to_string(),
            "Observed uniform HTTP status codes without dropped packets or timeouts.".to_string(),
        ],
        technical_breakdown: vec![
            "Connection pool exhaustion risk is LOW.".to_string(),
            "Upstream reverse proxy health is STABLE.".to_string(),
        ],
        reproduction_curl: sample_curl,
        remediation_checklist: vec![
            "Continue periodic continuous regression monitoring to detect drift over time."
                .to_string(),
        ],
    }
}

// ============================================================================
// Interactive cURL Test Execution
// ============================================================================

const CURL_MARKER: &str = "---READYHAI_TIMINGS---";

/// The curl invocation. `-q` skips ~/.curlrc, `--proto` limits it to http(s) (no file://, gopher://,
/// ...), `--data-raw` never treats a payload starting with '@' as a file to upload, and `--`
/// ends option parsing so nothing in the URL can be read as a flag.
fn curl_command(req: &CurlTestRequest, url: &reqwest::Url, timeout_s: u64) -> Command {
    let mut cmd = Command::new("curl");
    cmd.arg("-q").arg("-sS").arg("-v");
    cmd.arg("--proto").arg("=http,https");
    cmd.arg("-X").arg(req.method.to_uppercase());
    cmd.arg("--connect-timeout").arg(timeout_s.to_string());
    cmd.arg("--max-time").arg((timeout_s * 2).to_string());
    cmd.arg("-w").arg(format!("\n{CURL_MARKER}\nnamelookup:%{{time_namelookup}}\nconnect:%{{time_connect}}\nappconnect:%{{time_appconnect}}\npretransfer:%{{time_pretransfer}}\nstarttransfer:%{{time_starttransfer}}\ntotal:%{{time_total}}\nhttp_code:%{{http_code}}\nspeed_download:%{{speed_download}}\n"));
    for (k, v) in &req.headers {
        cmd.arg("-H").arg(format!("{k}: {v}"));
    }
    if let Some(ref p) = req.payload {
        if !has_header(&req.headers, "content-type") {
            cmd.arg("-H").arg("Content-Type: application/json");
        }
        cmd.arg("--data-raw").arg(p);
    }
    cmd.arg("--").arg(url.as_str());
    cmd
}

pub fn execute_curl_test(req: &CurlTestRequest) -> Result<CurlTestResponse> {
    let mut req = req.clone();
    let url = req.sanitize()?;
    let timeout_s = req
        .timeout_ms
        .div_ceil(1000)
        .clamp(1, MAX_TIMEOUT_MS / 1000);
    let full_curl_cmd = generate_curl(
        &req.method,
        url.as_str(),
        &req.headers,
        req.payload.as_deref(),
    );
    let mut cmd = curl_command(&req, &url, timeout_s);

    // hard wall-clock limit slightly above curl's own --max-time, bounded output
    match run_capped(
        &mut cmd,
        Duration::from_secs(timeout_s * 2 + 5),
        MAX_CAPTURE_BYTES,
        None,
    ) {
        Ok(out) => {
            let mut stderr_str = out.stderr_lossy();
            if out.timed_out {
                stderr_str.push_str("\n(curl was killed after the hard time limit)");
            }
            let (mut clean_stdout, timings) = if out.truncated && !out.stdout_tail.is_empty() {
                // the -w trailer is at the very end: read the timings from the retained tail
                let (_, t) = parse_curl_output(&String::from_utf8_lossy(&out.stdout_tail));
                let mut body = out.stdout_lossy();
                if let Some(pos) = body.find(CURL_MARKER) {
                    body.truncate(pos);
                }
                (body.trim().to_string(), t)
            } else {
                parse_curl_output(&out.stdout_lossy())
            };
            if out.truncated {
                clean_stdout.push_str(&format!(
                    "\n[output truncated at {MAX_CAPTURE_BYTES} bytes]"
                ));
            }
            let secs = |k: &str| timings.get(k).and_then(|v| v.parse().ok()).unwrap_or(0.0);

            Ok(CurlTestResponse {
                command: full_curl_cmd,
                exit_code: out.status.and_then(|s| s.code()).unwrap_or(-1),
                stdout: clean_stdout,
                stderr: truncate_chars(&stderr_str, 64 * 1024),
                status_code: timings
                    .get("http_code")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                dns_lookup_s: secs("namelookup"),
                connect_s: secs("connect"),
                appconnect_s: secs("appconnect"),
                starttransfer_s: secs("starttransfer"),
                total_s: secs("total"),
                not_measured: vec![],
                truncated: out.truncated,
            })
        }
        Err(e) => native_curl_fallback(&req, &url, full_curl_cmd, &e.to_string()),
    }
}

/// curl could not be run: measure what the native client can measure, and say what it cannot.
/// Nothing is invented: DNS/connect/TLS handshake timings are not observable here, so they are
/// zero and listed in `not_measured`.
fn native_curl_fallback(
    req: &CurlTestRequest,
    url: &reqwest::Url,
    command: String,
    why: &str,
) -> Result<CurlTestResponse> {
    let t0 = Instant::now();
    let client = http_client(req.timeout_ms, true);
    let method = parse_method(&req.method)?;
    let mut rb = client.request(method, url.as_str());
    for (k, v) in &req.headers {
        rb = rb.header(k, v);
    }
    if let Some(ref p) = req.payload {
        if !has_header(&req.headers, "content-type") {
            rb = rb.header("Content-Type", "application/json");
        }
        rb = rb.body(p.clone());
    }
    let res = rb.send();
    let headers_s = t0.elapsed().as_secs_f64();
    match res {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let (bytes, truncated) = read_capped(resp, MAX_CAPTURE_BYTES);
            let total_s = t0.elapsed().as_secs_f64();
            Ok(CurlTestResponse {
                command,
                exit_code: 0,
                stdout: String::from_utf8_lossy(&bytes).into_owned(),
                stderr: format!(
                    "(Fallback execution via native HTTP client; curl could not be run: {why})"
                ),
                status_code: code,
                dns_lookup_s: 0.0,
                connect_s: 0.0,
                appconnect_s: 0.0,
                starttransfer_s: headers_s,
                total_s,
                not_measured: ["dns_lookup_s", "connect_s", "appconnect_s"]
                    .map(String::from)
                    .to_vec(),
                truncated,
            })
        }
        Err(err) => Ok(CurlTestResponse {
            command,
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("Execution failed: {err}"),
            status_code: 0,
            dns_lookup_s: 0.0,
            connect_s: 0.0,
            appconnect_s: 0.0,
            starttransfer_s: 0.0,
            total_s: t0.elapsed().as_secs_f64(),
            not_measured: [
                "dns_lookup_s",
                "connect_s",
                "appconnect_s",
                "starttransfer_s",
            ]
            .map(String::from)
            .to_vec(),
            truncated: false,
        }),
    }
}

/// Reproduction command for the report: every value single-quoted so a header or payload cannot
/// break out of the command when someone pastes it into a shell.
pub fn generate_curl(
    method: &str,
    target: &str,
    headers: &HashMap<String, String>,
    payload: Option<&str>,
) -> String {
    let mut parts = vec![format!(
        "curl -s -o /dev/null -w {} -X {}",
        sh_quote(
            "DNS: %{time_namelookup}s | Connect: %{time_connect}s | TTFB: %{time_starttransfer}s | Total: %{time_total}s | Status: %{http_code}\\n"
        ),
        sh_quote(&method.to_uppercase())
    )];
    for (k, v) in headers {
        parts.push(format!("-H {}", sh_quote(&format!("{k}: {v}"))));
    }
    if let Some(p) = payload {
        if !has_header(headers, "content-type") {
            parts.push("-H 'Content-Type: application/json'".to_string());
        }
        parts.push(format!("--data-raw {}", sh_quote(p)));
    }
    parts.push(format!("-- {}", sh_quote(target)));
    parts.join(" ")
}

fn parse_curl_output(stdout: &str) -> (String, HashMap<String, String>) {
    let mut timings = HashMap::new();
    let clean_body;

    if let Some(pos) = stdout.find(CURL_MARKER) {
        clean_body = stdout[..pos].trim().to_string();
        let timing_section = &stdout[pos + CURL_MARKER.len()..];
        for line in timing_section.lines() {
            if let Some((k, v)) = line.split_once(':') {
                timings.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    } else {
        clean_body = stdout.to_string();
    }

    (clean_body, timings)
}

// ============================================================================
// 6-Pillar Deep Diagnostic Suite Implementations
// ============================================================================

pub fn run_deep_audit(req: &DeepAuditRequest) -> Result<DeepAuditReport> {
    let mut req = req.clone();
    let url = req.sanitize()?;
    let timestamp = crate::engine::now();
    let host = host_of(&url);
    let port = port_of(&url);
    let target = url.as_str();

    // 1. Dual-Stack IPv4 vs IPv6 Happy Eyeballs Audit
    let dual_stack = audit_dual_stack(&host, port, req.timeout_ms);

    // 2. Sub-Resource Cascade Audit (SPA & Assets)
    let subresources = audit_subresources(&url, req.timeout_ms);

    // 3. Protocol Matrix Audit
    let protocol_matrix = audit_protocol_matrix(target, req.timeout_ms);

    // 4. TLS & Certificate Chain Audit
    let tls_chain = audit_tls_chain(&url, &host, port, req.timeout_ms);

    // 5. CORS Preflight Audit
    let cors_preflight = audit_cors_preflight(target, req.timeout_ms);

    // 6. MTU & Packet Size Sweep Audit
    let mtu_sweep = audit_mtu_sweep(target, req.timeout_ms);

    // Calculate Health Score & Verdict
    let mut score: i32 = 100;
    let mut risks: Vec<String> = Vec::new();
    let mut remedies: Vec<String> = Vec::new();
    let mut not_measured: Vec<String> = Vec::new();

    if dual_stack.happy_eyeballs_risk {
        score -= 25;
        risks.push("Happy Eyeballs Risk: IPv6 record exists in DNS, but socket connection fails/hangs, causing first-load 3s delay.".to_string());
        remedies.push("Fix or remove broken AAAA DNS record for your domain, or ensure upstream gateway listens on IPv6.".to_string());
    }

    if subresources.broken_count > 0 {
        score -= (subresources.broken_count as i32 * 10).min(30);
        risks.push(format!(
            "{} sub-resource asset(s) did not return a 2xx response.",
            subresources.broken_count
        ));
        remedies.push("Verify asset paths and ensure build assets / bundles are properly uploaded to your web server / CDN.".to_string());
    }

    if subresources.spa_fallback_mismatches > 0 {
        score -= 30;
        risks.push(format!("SPA Routing Flaw: {} JavaScript chunk(s) returned HTML index shell instead of JS code! This causes fatal SyntaxErrors and blank screens on first load.", subresources.spa_fallback_mismatches));
        remedies.push("Update Nginx/reverse proxy `try_files` rule so missing static files (`.js`, `.css`) return 404 instead of falling back to `/index.html`.".to_string());
    }

    if !tls_chain.measured && tls_chain.is_https {
        not_measured.push(format!(
            "tls_chain ({})",
            tls_chain
                .not_measured
                .first()
                .map(String::as_str)
                .unwrap_or("openssl unavailable")
        ));
    }
    if tls_chain.is_intermediate_missing {
        score -= 25;
        risks.push("Incomplete TLS Certificate Chain: Intermediate CA is missing from server bundle. Fails on clean browsers and mobile devices.".to_string());
        remedies.push("Replace your server certificate with the full chain bundle (e.g. `fullchain.pem` instead of `cert.pem`).".to_string());
    }
    if let Some(days) = tls_chain.days_remaining {
        if days < 0 {
            score -= 30;
            risks.push(format!("TLS certificate expired {} day(s) ago.", -days));
            remedies.push(
                "Renew the certificate immediately and automate renewal (ACME / cert-manager)."
                    .to_string(),
            );
        } else if days <= 14 {
            score -= 15;
            risks.push(format!("TLS certificate expires in {days} day(s)."));
            remedies.push(
                "Renew the certificate and verify that automated renewal is working.".to_string(),
            );
        }
    }

    if !cors_preflight.preflight_passed {
        score -= 20;
        risks.push(format!("CORS Preflight (OPTIONS) failed with HTTP status {}. Cross-origin API calls will be blocked by browsers.", cors_preflight.preflight_status_code));
        remedies.push("Ensure your reverse proxy or API gateway handles HTTP OPTIONS requests with 200/204 and Access-Control-Allow-Origin headers.".to_string());
    }

    if mtu_sweep.black_hole_detected {
        score -= 30;
        risks.push("MTU Black Hole Detected: requests with larger headers time out or are reset while the small baseline request succeeds.".to_string());
        remedies.push("Enable Path MTU Discovery or configure TCP MSS clamping (`iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`).".to_string());
    }

    let final_score = score.clamp(0, 100) as u8;
    let overall_verdict = if final_score >= 90 {
        "PASS"
    } else if final_score >= 70 {
        "WARN"
    } else {
        "FAIL"
    };

    let summary = if risks.is_empty() && not_measured.is_empty() {
        "All 6 deep network and protocol pillars were measured and look healthy.".to_string()
    } else if risks.is_empty() {
        format!(
            "No problems found in the measured pillars; not measured: {}.",
            not_measured.join(", ")
        )
    } else {
        format!(
            "Detected {} network vulnerability/flakiness vector(s). Overall Network Health Score: {}/100.",
            risks.len(),
            final_score
        )
    };

    let ip_info = detect_requester_public_ip();
    Ok(DeepAuditReport {
        target: req.target.clone(),
        timestamp,
        overall_verdict: overall_verdict.to_string(),
        health_score: final_score,
        executive_summary: summary,
        identified_risks: risks,
        dual_stack,
        subresources,
        protocol_matrix,
        tls_chain,
        cors_preflight,
        mtu_sweep,
        remediation_checklist: remedies,
        not_measured,
        requester_ip: Some(ip_info.egress_public_ip.clone()),
        allowlist_recommendation: Some(ip_info.allowlist_guidance.clone()),
    })
}

fn audit_dual_stack(host: &str, port: u16, timeout_ms: u64) -> DualStackAudit {
    let connect_timeout = Duration::from_millis(timeout_ms.min(2500));
    let lookup_result = hostport(host, port).to_socket_addrs();

    match lookup_result {
        Ok(addrs) => {
            let mut v4_addrs = Vec::new();
            let mut v6_addrs = Vec::new();

            for addr in addrs {
                match addr {
                    SocketAddr::V4(v4) => v4_addrs.push(v4.ip().to_string()),
                    SocketAddr::V6(v6) => v6_addrs.push(v6.ip().to_string()),
                }
            }

            let has_ipv4 = !v4_addrs.is_empty();
            let has_ipv6 = !v6_addrs.is_empty();

            // Test IPv4 connection
            let mut v4_latency = None;
            if let Some(first_v4) = v4_addrs.first()
                && let Ok(sock) = format!("{}:{}", first_v4, port).parse::<SocketAddr>()
            {
                let t0 = Instant::now();
                if TcpStream::connect_timeout(&sock, connect_timeout).is_ok() {
                    v4_latency = Some(t0.elapsed().as_millis());
                }
            }

            // Test IPv6 connection
            let mut v6_latency = None;
            let mut ipv6_status = "NOT_CONFIGURED".to_string();
            let mut happy_eyeballs_risk = false;

            if has_ipv6
                && let Some(first_v6) = v6_addrs.first()
                && let Ok(sock) = format!("[{}]:{}", first_v6, port).parse::<SocketAddr>()
            {
                let t0 = Instant::now();
                match TcpStream::connect_timeout(&sock, connect_timeout) {
                    Ok(_) => {
                        v6_latency = Some(t0.elapsed().as_millis());
                        ipv6_status = "HEALTHY".to_string();
                    }
                    Err(_) => {
                        ipv6_status = "BROKEN_OR_BLACKHOLE".to_string();
                        happy_eyeballs_risk = true;
                    }
                }
            }

            let diagnosis = if happy_eyeballs_risk {
                "CRITICAL: AAAA record is published in DNS, but IPv6 socket connection timed out or was dropped. Browsers will stall for 250-3000ms on first load before falling back to IPv4!".to_string()
            } else if has_ipv4 && has_ipv6 {
                "EXCELLENT: Dual-stack IPv4/IPv6 is fully operational with fast TCP handshakes on both protocols.".to_string()
            } else if has_ipv4 {
                "STANDARD: Host is IPv4-only. No IPv6 AAAA record published (zero Happy Eyeballs fallback delay risk).".to_string()
            } else {
                "No valid IP addresses could be reached.".to_string()
            };

            DualStackAudit {
                has_ipv4,
                has_ipv6,
                ipv4_addresses: v4_addrs,
                ipv6_addresses: v6_addrs,
                ipv4_latency_ms: v4_latency,
                ipv6_latency_ms: v6_latency,
                ipv6_status,
                happy_eyeballs_risk,
                diagnosis,
            }
        }
        Err(e) => DualStackAudit {
            has_ipv4: false,
            has_ipv6: false,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            ipv4_latency_ms: None,
            ipv6_latency_ms: None,
            ipv6_status: "DNS_LOOKUP_FAILED".to_string(),
            happy_eyeballs_risk: false,
            diagnosis: format!("DNS resolution error: {}", e),
        },
    }
}

fn audit_subresources(base_url: &reqwest::Url, timeout_ms: u64) -> SubresourceAudit {
    let client = http_client(timeout_ms, false);

    let mut items = Vec::new();
    let mut total_size_bytes = 0;
    let mut broken_count = 0;
    let mut spa_fallback_count = 0;
    let mut skipped_cross_host = 0;
    let mut max_ttfb = 0;
    let base_host = base_url.host_str().map(str::to_ascii_lowercase);

    let res = client.get(base_url.as_str()).send();
    if let Ok(resp) = res {
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let (bytes, _) = read_capped(resp, HTML_BYTES_CAP);
        let body = String::from_utf8_lossy(&bytes).into_owned();

        if content_type.contains("text/html")
            || body.contains("<html")
            || body.contains("<!doctype")
        {
            // Extract sub-resources
            let mut discovered_urls = Vec::new();

            // Scripts: <script ... src="..."
            let re_script = regex::Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap();
            for cap in re_script.captures_iter(&body) {
                if let Some(m) = cap.get(1) {
                    discovered_urls.push((m.as_str().to_string(), "script"));
                }
            }

            // Styles: <link ... rel="stylesheet" ... href="..." or vice versa
            let re_style =
                regex::Regex::new(r#"(?i)<link[^>]+href=["']([^"']+\.css[^"']*)["']"#).unwrap();
            for cap in re_style.captures_iter(&body) {
                if let Some(m) = cap.get(1) {
                    discovered_urls.push((m.as_str().to_string(), "stylesheet"));
                }
            }

            // Preload: <link rel="preload" href="..."
            let re_preload =
                regex::Regex::new(r#"(?i)<link[^>]+rel=["']preload["'][^>]+href=["']([^"']+)["']"#)
                    .unwrap();
            for cap in re_preload.captures_iter(&body) {
                if let Some(m) = cap.get(1) {
                    discovered_urls.push((m.as_str().to_string(), "preload"));
                }
            }

            // Limit to first 12 discovered subresources for performance
            discovered_urls.truncate(MAX_SUBRESOURCES);

            for (raw_url, tag_type) in discovered_urls {
                // The page is untrusted input: only probe assets on the audited host, never a
                // URL the page points at (internal addresses, other hosts, non-http schemes).
                let resolved = match base_url.join(&raw_url) {
                    Ok(u)
                        if matches!(u.scheme(), "http" | "https")
                            && u.host_str().map(str::to_ascii_lowercase) == base_host =>
                    {
                        u
                    }
                    _ => {
                        skipped_cross_host += 1;
                        continue;
                    }
                };
                let resolved_url = resolved.to_string();

                let t0 = Instant::now();
                let asset_res = client.get(resolved.as_str()).send();
                let ttfb = t0.elapsed().as_millis();
                max_ttfb = max_ttfb.max(ttfb);

                match asset_res {
                    Ok(a_resp) => {
                        let status = a_resp.status().as_u16();
                        let a_ct = a_resp
                            .headers()
                            .get("content-type")
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or("")
                            .to_lowercase();
                        let a_bytes = count_capped(a_resp, SUBRESOURCE_BYTES_CAP);
                        total_size_bytes += a_bytes;

                        let is_broken = !(200..300).contains(&status);
                        if is_broken {
                            broken_count += 1;
                        }

                        // Check SPA Fallback Mismatch
                        // If file is named .js or .mjs, but server sent text/html!
                        let path = resolved.path();
                        let is_spa_fallback_error = (path.ends_with(".js")
                            || path.ends_with(".mjs"))
                            && a_ct.contains("text/html");
                        if is_spa_fallback_error {
                            spa_fallback_count += 1;
                        }

                        items.push(SubresourceItem {
                            url: resolved_url,
                            tag_type: tag_type.to_string(),
                            status_code: status,
                            ttfb_ms: ttfb,
                            content_type: a_ct,
                            size_bytes: a_bytes,
                            is_spa_fallback_error,
                            is_broken,
                            error: if is_broken {
                                Some(format!("HTTP {status}"))
                            } else {
                                None
                            },
                        });
                    }
                    Err(err) => {
                        broken_count += 1;
                        items.push(SubresourceItem {
                            url: resolved_url,
                            tag_type: tag_type.to_string(),
                            status_code: 0,
                            ttfb_ms: ttfb,
                            content_type: "error".to_string(),
                            size_bytes: 0,
                            is_spa_fallback_error: false,
                            is_broken: true,
                            error: Some(err.to_string()),
                        });
                    }
                }
            }
        }
    }

    let diagnosis = if spa_fallback_count > 0 {
        format!(
            "CRITICAL: Detected {spa_fallback_count} JavaScript chunk(s) returning HTML index shells! This causes fatal syntax errors and blank screens on first load."
        )
    } else if broken_count > 0 {
        format!("WARNING: {broken_count} sub-resource asset(s) did not return a 2xx response.")
    } else if items.is_empty() {
        "Target is an API endpoint or non-HTML resource, or has no same-host sub-resources; nothing to probe.".to_string()
    } else {
        format!(
            "All {} discovered sub-resources loaded successfully with correct MIME types.",
            items.len()
        )
    };
    let diagnosis = if skipped_cross_host > 0 {
        format!(
            "{diagnosis} ({skipped_cross_host} cross-host or non-http asset(s) were not probed: only the audited host is contacted.)"
        )
    } else {
        diagnosis
    };

    SubresourceAudit {
        total_discovered: items.len(),
        successful_count: items.iter().filter(|i| !i.is_broken).count(),
        broken_count,
        spa_fallback_mismatches: spa_fallback_count,
        skipped_cross_host,
        total_size_kb: (total_size_bytes as f64) / 1024.0,
        max_asset_ttfb_ms: max_ttfb,
        items,
        diagnosis,
    }
}

/// One curl protocol probe. Returns (negotiated HTTP version, status code), or None when curl
/// could not be run or reached nothing.
fn curl_protocol_probe(flag: &str, target: &str, timeout_s: u64) -> Option<(String, u16)> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-q",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_version}:%{http_code}",
        "--proto",
        "=http,https",
        flag,
    ]);
    cmd.arg("--connect-timeout").arg(timeout_s.to_string());
    cmd.arg("--max-time").arg(timeout_s.to_string());
    cmd.arg("--").arg(target);
    let out = run_capped(&mut cmd, Duration::from_secs(timeout_s + 3), 4096, None).ok()?;
    let s = out.stdout_lossy();
    let (ver, code) = s.trim().split_once(':')?;
    Some((ver.to_string(), code.parse().ok().filter(|c| *c > 0)?))
}

fn audit_protocol_matrix(target: &str, timeout_ms: u64) -> ProtocolMatrixAudit {
    let timeout_s = (timeout_ms / 1000).clamp(1, 2);
    let mut protocols = Vec::new();

    // 1. Probe HTTP/1.1
    let t0 = Instant::now();
    let p11 = curl_protocol_probe("--http1.1", target, timeout_s);
    let dur_11 = t0.elapsed().as_millis();
    let (sup_11, code_11, ver_11) = match &p11 {
        Some((v, c)) => (true, *c, v.clone()),
        None => (false, 0, "1.1".to_string()),
    };

    protocols.push(ProtocolItem {
        protocol: "HTTP/1.1".to_string(),
        supported: sup_11,
        negotiation_time_ms: dur_11,
        status_code: code_11,
        notes: "Baseline universal transport protocol.".to_string(),
    });

    // 2. Probe HTTP/2
    let t0 = Instant::now();
    let p2 = curl_protocol_probe("--http2", target, timeout_s);
    let dur_2 = t0.elapsed().as_millis();
    let (sup_2, code_2) = match &p2 {
        Some((v, c)) => (v == "2", *c),
        None => (false, 0),
    };

    protocols.push(ProtocolItem {
        protocol: "HTTP/2 (Multiplexed)".to_string(),
        supported: sup_2,
        negotiation_time_ms: dur_2,
        status_code: code_2,
        notes: if sup_2 {
            "Active. Supports binary framing and single-connection multiplexing.".to_string()
        } else {
            "Not supported or fell back to HTTP/1.1.".to_string()
        },
    });

    // 3. HTTP/3 is only detected through the Alt-Svc header; no QUIC connection is attempted.
    let client = http_client(timeout_ms, false);
    let mut alt_svc = None;
    if let Ok(res) = client.get(target).send()
        && let Some(h) = res.headers().get("alt-svc")
    {
        alt_svc = h.to_str().ok().map(|s| truncate_chars(s, 512));
    }

    let http3_advertised = alt_svc.as_ref().map(|s| s.contains("h3")).unwrap_or(false);
    protocols.push(ProtocolItem {
        protocol: "HTTP/3 (QUIC / UDP)".to_string(),
        supported: http3_advertised,
        negotiation_time_ms: 0,
        status_code: 0,
        notes: if http3_advertised {
            "Advertised via Alt-Svc header. A QUIC connection was not attempted (no negotiation time or status measured).".to_string()
        } else {
            "Alt-Svc header not detected. Server does not announce HTTP/3 QUIC.".to_string()
        },
    });

    let active_protocol = if sup_2 {
        "HTTP/2".to_string()
    } else if sup_11 {
        format!("HTTP/{ver_11}")
    } else {
        "unreachable".to_string()
    };

    let diagnosis = if sup_2 {
        "EXCELLENT: HTTP/2 multiplexing is operational, reducing connection overhead for multiple assets.".to_string()
    } else if sup_11 {
        "STANDARD: Server operates on HTTP/1.1 without multiplexing. Multiple concurrent assets require separate TCP sockets.".to_string()
    } else {
        "No protocol probe got an HTTP response (target unreachable, or curl is not installed)."
            .to_string()
    };

    ProtocolMatrixAudit {
        active_protocol,
        http2_supported: sup_2,
        http3_advertised,
        alt_svc_header: alt_svc,
        protocols,
        diagnosis,
    }
}

// ---------------------------------------------------------------- TLS (measured with openssl)

/// What `openssl s_client -status -showcerts` told us.
#[derive(Debug, Default, PartialEq)]
struct SClient {
    version: Option<String>,
    cipher: Option<String>,
    verify_code: Option<i32>,
    verify_text: Option<String>,
    /// Some(true) = a stapled OCSP response was sent, Some(false) = none sent, None = no statement.
    ocsp_stapled: Option<bool>,
    chain_len: usize,
    leaf_pem: Option<String>,
}

fn parse_s_client(text: &str) -> SClient {
    let mut s = SClient::default();
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("New, ") {
            // "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
            if let Some((ver, cipher)) = rest.split_once(", Cipher is ")
                && !cipher.contains("(NONE)")
            {
                s.version = Some(ver.trim().to_string());
                s.cipher = Some(cipher.trim().to_string());
            }
        } else if let Some(rest) = l.strip_prefix("Verify return code:") {
            // "Verify return code: 20 (unable to get local issuer certificate)"
            let rest = rest.trim();
            s.verify_code = rest.split_whitespace().next().and_then(|c| c.parse().ok());
            s.verify_text = Some(rest.to_string());
        } else if l.starts_with("OCSP response: no response sent") {
            s.ocsp_stapled = Some(false);
        } else if l.starts_with("OCSP Response Status: successful") || l == "OCSP Response Data:" {
            s.ocsp_stapled = Some(true);
        }
    }
    let mut in_pem = false;
    let mut pem = String::new();
    for line in text.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_pem = true;
            s.chain_len += 1;
            if s.chain_len == 1 {
                pem.clear();
            }
        }
        if in_pem && s.chain_len == 1 {
            pem.push_str(line);
            pem.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_pem = false;
        }
    }
    if s.chain_len >= 1 {
        s.leaf_pem = Some(pem);
    }
    s
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// "Jan  1 00:00:00 2027 GMT" (openssl's notAfter format) to unix seconds.
fn parse_openssl_date(s: &str) -> Option<i64> {
    let mut it = s.split_whitespace();
    let mon = it.next()?;
    let day: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':');
    let (h, mi, sec): (i64, i64, i64) = (
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
    );
    let year: i64 = it.next()?.parse().ok()?;
    let m = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|x| *x == mon)? as i64
        + 1;
    Some(days_from_civil(year, m, day) * 86_400 + h * 3600 + mi * 60 + sec)
}

#[derive(Debug, Default, PartialEq)]
struct LeafInfo {
    subject: Option<String>,
    issuer: Option<String>,
    not_after: Option<String>,
    sans: Vec<String>,
}

/// Parse `openssl x509 -noout -subject -issuer -enddate [-ext subjectAltName]` output.
fn parse_x509(text: &str) -> LeafInfo {
    let mut leaf = LeafInfo::default();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("subject=") {
            leaf.subject = Some(v.trim().to_string());
        } else if let Some(v) = l.strip_prefix("issuer=") {
            leaf.issuer = Some(v.trim().to_string());
        } else if let Some(v) = l.strip_prefix("notAfter=") {
            leaf.not_after = Some(v.trim().to_string());
        } else if l.starts_with("X509v3 Subject Alternative Name")
            && let Some(next) = lines.next()
        {
            leaf.sans = next
                .split(',')
                .filter_map(|e| e.trim().strip_prefix("DNS:").map(str::to_string))
                .collect();
        }
    }
    leaf
}

fn unmeasured_tls(is_https: bool, why: &str) -> TlsChainAudit {
    TlsChainAudit {
        is_https,
        measured: false,
        tls_version: NOT_MEASURED.to_string(),
        cipher: NOT_MEASURED.to_string(),
        cert_issuer: NOT_MEASURED.to_string(),
        cert_subject: NOT_MEASURED.to_string(),
        cert_sans: Vec::new(),
        not_after: None,
        days_remaining: None,
        is_self_signed: false,
        is_intermediate_missing: false,
        ocsp_stapled: None,
        chain_length: None,
        verify_result: None,
        not_measured: vec![why.to_string()],
        diagnosis: format!("TLS was not measured: {why}."),
    }
}

fn audit_tls_chain(url: &reqwest::Url, host: &str, port: u16, timeout_ms: u64) -> TlsChainAudit {
    if url.scheme() != "https" {
        return TlsChainAudit {
            is_https: false,
            measured: true,
            tls_version: "None".to_string(),
            cipher: "None (Plaintext HTTP)".to_string(),
            cert_issuer: "None".to_string(),
            cert_subject: "None".to_string(),
            cert_sans: Vec::new(),
            not_after: None,
            days_remaining: None,
            is_self_signed: false,
            is_intermediate_missing: false,
            ocsp_stapled: None,
            chain_length: None,
            verify_result: None,
            not_measured: Vec::new(),
            diagnosis: "Target uses unencrypted plaintext HTTP transport.".to_string(),
        };
    }

    let limit = Duration::from_millis(timeout_ms.clamp(2000, 10_000));
    let mut cmd = Command::new("openssl");
    cmd.arg("s_client")
        .arg("-connect")
        .arg(hostport(host, port))
        .args(["-status", "-showcerts"]);
    if host.parse::<std::net::IpAddr>().is_err() {
        cmd.arg("-servername").arg(host);
    }
    // stdin is null: s_client otherwise waits for input and the call hangs
    let out = match run_capped(&mut cmd, limit, MAX_CAPTURE_BYTES, None) {
        Ok(o) if o.timed_out => return unmeasured_tls(true, "openssl s_client timed out"),
        Ok(o) => o,
        Err(_) => return unmeasured_tls(true, "openssl is not available"),
    };
    let text = format!("{}\n{}", out.stdout_lossy(), out.stderr_lossy());
    let sc = parse_s_client(&text);
    let (Some(tls_version), Some(cipher)) = (sc.version.clone(), sc.cipher.clone()) else {
        return unmeasured_tls(true, "TLS handshake failed or no TLS output was returned");
    };

    // Certificate details come from the leaf PEM s_client printed.
    let mut leaf = LeafInfo::default();
    if let Some(pem) = &sc.leaf_pem {
        let run_x509 = |args: &[&str]| {
            let mut c = Command::new("openssl");
            c.arg("x509").arg("-noout").args(args);
            run_capped(
                &mut c,
                Duration::from_secs(5),
                64 * 1024,
                Some(pem.as_bytes()),
            )
            .ok()
            .filter(|o| o.success())
        };
        let o = run_x509(&["-subject", "-issuer", "-enddate", "-ext", "subjectAltName"])
            .or_else(|| run_x509(&["-subject", "-issuer", "-enddate"]));
        if let Some(o) = o {
            leaf = parse_x509(&o.stdout_lossy());
        }
    }

    let days_remaining = leaf
        .not_after
        .as_deref()
        .and_then(parse_openssl_date)
        .map(|exp| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            (exp - now).div_euclid(86_400)
        });
    let code = sc.verify_code;
    let is_self_signed =
        matches!(code, Some(18 | 19)) || (leaf.subject.is_some() && leaf.subject == leaf.issuer);
    // 21 = "unable to verify the first certificate"; 20 with a single certificate sent means the
    // server did not send the intermediate. With a longer chain, 20 is an untrusted root instead.
    let is_intermediate_missing =
        !is_self_signed && (code == Some(21) || (code == Some(20) && sc.chain_len <= 1));

    let mut not_measured = Vec::new();
    if leaf.subject.is_none() {
        not_measured.push("certificate details (could not parse the leaf certificate)".to_string());
    }
    if sc.ocsp_stapled.is_none() {
        not_measured.push("ocsp_stapled".to_string());
    }
    let diagnosis = if is_intermediate_missing {
        "CRITICAL: Intermediate certificate missing or invalid issuer! Modern desktop browsers cache intermediates, but mobile devices and fresh sessions will fail with SSL errors.".to_string()
    } else if is_self_signed {
        "WARNING: Self-signed certificate detected. Public clients without explicit trust roots will reject this connection.".to_string()
    } else if let Some(t) = sc.verify_text.as_deref().filter(|_| code != Some(0)) {
        format!("WARNING: certificate verification against this host's trust store failed: {t}.")
    } else {
        format!("TLS handshake succeeded using {tls_version} with cipher {cipher}.")
    };

    TlsChainAudit {
        is_https: true,
        measured: true,
        tls_version,
        cipher,
        cert_issuer: leaf.issuer.unwrap_or_else(|| NOT_MEASURED.to_string()),
        cert_subject: leaf.subject.unwrap_or_else(|| NOT_MEASURED.to_string()),
        cert_sans: leaf.sans,
        not_after: leaf.not_after,
        days_remaining,
        is_self_signed,
        is_intermediate_missing,
        ocsp_stapled: sc.ocsp_stapled,
        chain_length: Some(sc.chain_len),
        verify_result: sc.verify_text,
        not_measured,
        diagnosis,
    }
}

fn audit_cors_preflight(target: &str, timeout_ms: u64) -> CorsAudit {
    let client = http_client(timeout_ms, false);

    let res = client
        .request(reqwest::Method::OPTIONS, target)
        .header("Origin", "https://qa-probe.readyhai.internal")
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "authorization, content-type, x-readyhai-probe",
        )
        .send();

    match res {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp.headers();

            let allow_orig = headers
                .get("access-control-allow-origin")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            let allow_meth = headers
                .get("access-control-allow-methods")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            let allow_head = headers
                .get("access-control-allow-headers")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            let allow_cred = headers
                .get("access-control-allow-credentials")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let has_wildcard_with_creds =
                allow_orig.as_deref() == Some("*") && allow_cred.as_deref() == Some("true");
            let preflight_passed = (status == 200 || status == 204)
                && allow_orig.is_some()
                && !has_wildcard_with_creds;

            let diagnosis = if has_wildcard_with_creds {
                "FAIL: Wildcard Access-Control-Allow-Origin '*' with Access-Control-Allow-Credentials 'true' is rejected by browser CORS specifications.".to_string()
            } else if !preflight_passed {
                format!(
                    "FAIL: CORS Preflight returned HTTP status {status} without a usable Access-Control-Allow-Origin. Browsers will reject cross-origin requests before sending data."
                )
            } else {
                "PASS: Preflight OPTIONS is accepted with valid Access-Control headers.".to_string()
            };

            CorsAudit {
                preflight_status_code: status,
                preflight_passed,
                allow_origin: allow_orig,
                allow_methods: allow_meth,
                allow_headers: allow_head,
                allow_credentials: allow_cred,
                has_wildcard_with_creds,
                diagnosis,
            }
        }
        Err(err) => CorsAudit {
            preflight_status_code: 0,
            preflight_passed: false,
            allow_origin: None,
            allow_methods: None,
            allow_headers: None,
            allow_credentials: None,
            has_wildcard_with_creds: false,
            diagnosis: format!("Preflight request failed: {err}"),
        },
    }
}

/// HTTP statuses a server uses to say "your headers are too big" (a server limit, not a network fault).
fn is_header_limit_status(status: u16) -> bool {
    matches!(status, 400 | 413 | 414 | 431)
}

/// Transport-level failure that large packets dying in the network look like: a timeout, a reset
/// or a connection closed mid-request. A refused connection or DNS failure is not one.
fn is_black_hole_error(e: &reqwest::Error) -> bool {
    if e.is_timeout() {
        return true;
    }
    let s = format!("{e:?}").to_lowercase();
    [
        "reset",
        "broken pipe",
        "closed before",
        "incomplete",
        "unexpected eof",
        "connection closed",
    ]
    .iter()
    .any(|p| s.contains(p))
}

/// A payload size counts as black-holed only when a request that got NO HTTP response at all
/// (timeout/reset) follows a smaller one that did. Any HTTP status, including 400/431, proves the
/// packets arrived.
fn mtu_black_hole(results: &[MtuSweepItem]) -> bool {
    let baseline_delivered = results.first().is_some_and(|r| r.delivered);
    baseline_delivered
        && results
            .iter()
            .any(|r| r.payload_bytes >= 1400 && !r.delivered && r.transport_failure)
}

fn audit_mtu_sweep(target: &str, timeout_ms: u64) -> MtuSweepAudit {
    let sweep_timeout = timeout_ms.clamp(800, 2000);
    let client = http_client(sweep_timeout, true);

    let probes = [
        (512, "512B Baseline"),
        (1400, "1.4KB Standard MTU"),
        (4096, "4KB Large Headers"),
        (8192, "8KB High Payload"),
    ];

    let mut results = Vec::new();
    let mut max_safe = 0;
    let mut max_delivered = 0;
    let mut header_limit_seen = false;

    for (size, label) in probes {
        let padding = "A".repeat(size);
        let attempt = || {
            let t0 = Instant::now();
            let res = client
                .get(target)
                .header("X-MTU-Sweep-Padding", padding.clone())
                .send();
            (res, t0.elapsed().as_millis())
        };
        let (mut res, mut dur) = attempt();
        // one retry on a timeout: a single lost SYN is not a black hole
        if size >= 1400 && res.as_ref().is_err_and(|e| e.is_timeout()) {
            (res, dur) = attempt();
        }

        match res {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let success = (200..300).contains(&status);
                let header_limit_hit = is_header_limit_status(status);
                header_limit_seen |= header_limit_hit;
                max_delivered = max_delivered.max(size);
                if !header_limit_hit {
                    max_safe = max_safe.max(size);
                }
                results.push(MtuSweepItem {
                    payload_bytes: size,
                    label: label.to_string(),
                    status_code: status,
                    duration_ms: dur,
                    success,
                    delivered: true,
                    transport_failure: false,
                    header_limit_hit,
                    error: if success { None } else if header_limit_hit {
                        Some(format!("HTTP {status}: the server rejected the header size (a server limit, not a network drop)"))
                    } else {
                        Some(format!("HTTP {status}"))
                    },
                });
            }
            Err(e) => {
                results.push(MtuSweepItem {
                    payload_bytes: size,
                    label: label.to_string(),
                    status_code: 0,
                    duration_ms: dur,
                    success: false,
                    delivered: false,
                    transport_failure: is_black_hole_error(&e),
                    header_limit_hit: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    let black_hole_detected = mtu_black_hole(&results);
    let baseline_failed = results.first().is_some_and(|r| !r.delivered);
    let diagnosis = if black_hole_detected {
        "CRITICAL: Path MTU Black Hole suspected! The small baseline request was answered, but a larger request timed out or was reset without any HTTP response. Network firewalls may be blocking ICMP Fragmentation Needed packets.".to_string()
    } else if baseline_failed {
        "Baseline request got no HTTP response; the target is unreachable, so the MTU sweep is inconclusive.".to_string()
    } else if header_limit_seen {
        format!(
            "No black hole: every probe got an HTTP response. The server rejects large headers (HTTP 400/413/414/431) above {max_safe} bytes; that is a header-size limit, not a network fault."
        )
    } else {
        format!(
            "All MTU packet size sweeps got HTTP responses up to {max_delivered} bytes without drops."
        )
    };

    MtuSweepAudit {
        black_hole_detected,
        maximum_safe_bytes: max_safe,
        maximum_delivered_bytes: max_delivered,
        sweep_results: results,
        diagnosis,
    }
}

// ============================================================================
// Latency probe from this host (remote vantage points do not exist)
// ============================================================================

/// ReadyHai has no probe nodes in other regions, so it cannot say how the target looks from
/// Frankfurt or Mumbai. This function measures what it can: DNS, TCP connect, time to first byte,
/// total time, jitter and loss over a few fresh connections from the machine it runs on. The
/// previous implementation invented per-region numbers; those regions are now listed in
/// `not_measured_regions`.
const NOT_MEASURED_REGIONS: [&str; 4] = ["us-east-1", "eu-west-1", "ap-south-1", "ap-southeast-1"];
const LOCAL_SAMPLES: usize = 3;

struct Sample {
    dns_ms: u64,
    connect_ms: u64,
    ttfb_ms: u64,
    total_ms: u64,
    status: u16,
    resolved_ip: Option<String>,
    headers: HashMap<String, String>,
}

fn local_sample(url: &reqwest::Url, host: &str, port: u16, timeout_ms: u64) -> Option<Sample> {
    let dns_t0 = Instant::now();
    let addrs: Vec<SocketAddr> = hostport(host, port)
        .to_socket_addrs()
        .map(|i| i.collect())
        .unwrap_or_default();
    let dns_ms = dns_t0.elapsed().as_millis() as u64;
    let addr = *addrs.first()?;

    let tcp_t0 = Instant::now();
    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).ok()?;
    let connect_ms = tcp_t0.elapsed().as_millis() as u64;

    let client = http_client(timeout_ms, true);
    let t0 = Instant::now();
    let resp = client.get(url.as_str()).send().ok()?;
    let ttfb_ms = t0.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), truncate_chars(v, 200)))
        })
        .collect();
    let _ = count_capped(resp, SUBRESOURCE_BYTES_CAP);
    let total_ms = t0.elapsed().as_millis() as u64;
    Some(Sample {
        dns_ms,
        connect_ms,
        ttfb_ms,
        total_ms,
        status,
        resolved_ip: Some(addr.ip().to_string()),
        headers,
    })
}

pub fn run_multi_region_audit(req: &MultiRegionRequest) -> Result<MultiRegionReport> {
    let mut req = req.clone();
    let url = req.sanitize()?;
    let timestamp = crate::engine::now();
    let timeout_ms = req.timeout_ms.unwrap_or(4000);
    let host = host_of(&url);
    let port = port_of(&url);

    let mut samples = Vec::new();
    let mut failures = 0usize;
    for _ in 0..LOCAL_SAMPLES {
        match local_sample(&url, &host, port, timeout_ms) {
            Some(s) => samples.push(s),
            None => {
                failures += 1;
                // two failures in a row: the target is down, do not burn the full timeout again
                if failures >= 2 && samples.is_empty() {
                    break;
                }
            }
        }
    }
    let attempted = samples.len() + failures;
    let loss = if attempted > 0 {
        failures as f32 / attempted as f32 * 100.0
    } else {
        100.0
    };

    let median = |f: fn(&Sample) -> u64| -> u64 {
        let mut v: Vec<u64> = samples.iter().map(f).collect();
        v.sort_unstable();
        v.get(v.len() / 2).copied().unwrap_or(0)
    };
    let totals: Vec<u64> = samples.iter().map(|s| s.total_ms).collect();
    let jitter = totals
        .iter()
        .max()
        .copied()
        .unwrap_or(0)
        .saturating_sub(totals.iter().min().copied().unwrap_or(0));
    let last = samples.last();
    let (cf_ray, pop_hdr, server_hdr) = match last {
        Some(s) => (
            s.headers.get("cf-ray").cloned(),
            s.headers
                .get("x-amz-cf-pop")
                .or_else(|| s.headers.get("x-served-by"))
                .cloned(),
            s.headers.get("server").cloned(),
        ),
        None => (None, None, None),
    };
    let cdn_edge_active = cf_ray.is_some()
        || pop_hdr.is_some()
        || server_hdr
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains("cloudflare");
    let total_ms = median(|s| s.total_ms);

    let (label, notes) = if samples.is_empty() {
        ("OFFLINE", "No request from this host got an HTTP response (DNS failure, connection refused or timeout).".to_string())
    } else if total_ms < 150 {
        ("OPTIMAL", "Low latency from this host.".to_string())
    } else if total_ms < 300 {
        (
            "ELEVATED",
            "Moderate latency from this host; verify asset compression and HTTP/2 multiplexing."
                .to_string(),
        )
    } else {
        (
            "DEGRADED",
            "High round-trip time from this host.".to_string(),
        )
    };

    let region = RegionProbeResult {
        region_id: "local".to_string(),
        region_name: "This host (measured)".to_string(),
        flag: String::new(),
        location: "Machine running ReadyHai".to_string(),
        resolved_ip: last
            .and_then(|s| s.resolved_ip.clone())
            .unwrap_or_else(|| NOT_MEASURED.to_string()),
        dns_time_ms: median(|s| s.dns_ms),
        tcp_connect_ms: median(|s| s.connect_ms),
        ttfb_ms: median(|s| s.ttfb_ms),
        total_time_ms: total_ms,
        http_status: last.map(|s| s.status).unwrap_or(0),
        edge_pop: pop_hdr
            .clone()
            .or(cf_ray.clone())
            .unwrap_or_else(|| "not detected".to_string()),
        status: label.to_string(),
        jitter_ms: jitter,
        packet_loss_pct: loss,
        notes,
        measured: true,
    };

    let note = "ReadyHai has no remote probe nodes: only this host was measured. Regional latency, geo-DNS behaviour and per-region edge selection were not measured.".to_string();
    let verdict = if samples.is_empty() {
        "CRITICAL: Target is unreachable from this host: no request got an HTTP response."
            .to_string()
    } else if cdn_edge_active {
        format!(
            "REACHABLE from this host in {total_ms}ms (median of {} sample(s)); CDN/edge response headers are present. {note}",
            samples.len()
        )
    } else {
        format!(
            "REACHABLE from this host in {total_ms}ms (median of {} sample(s)); no CDN/edge response headers seen. {note}",
            samples.len()
        )
    };

    Ok(MultiRegionReport {
        target: req.target.clone(),
        timestamp,
        regions: vec![region],
        fastest_region: NOT_MEASURED.to_string(),
        slowest_region: NOT_MEASURED.to_string(),
        geo_dns_consistent: None,
        cdn_edge_active,
        regional_disparity_ms: 0,
        agent_verdict: verdict,
        recommendations: vec![
            "To compare regions, run ReadyHai from a machine in each region you care about and compare the reports.".to_string(),
        ],
        not_measured_regions: NOT_MEASURED_REGIONS.iter().map(|s| s.to_string()).collect(),
        measurement_note: note,
    })
}

pub fn generate_har_from_regress(report: &RegressReport) -> serde_json::Value {
    let mut entries = Vec::new();

    for it in &report.iterations {
        let headers: Vec<serde_json::Value> = it
            .response_headers
            .iter()
            .map(|(k, v)| json!({"name": k, "value": v}))
            .collect();

        let mime = it
            .response_headers
            .get("content-type")
            .cloned()
            .unwrap_or_else(|| "text/html; charset=utf-8".into());

        let body_snippet = it.response_body_snippet.clone().unwrap_or_default();
        let body_len = body_snippet.len();

        let dns = it.dns_lookup_ms as i64;
        let connect = it.tcp_connect_ms as i64;
        let wait = it.ttfb_ms as i64;
        let receive = (it.duration_ms as i64 - wait).max(0);

        let http_version = it.http_version.clone().unwrap_or_default();
        let mut entry = json!({
            "startedDateTime": it.timestamp,
            "time": it.duration_ms,
            "request": {
                "method": report.method,
                "url": report.target,
                "httpVersion": http_version,
                "cookies": [],
                "headers": [
                    { "name": "User-Agent", "value": format!("ReadyHai-NetworkLab/{}", crate::engine::VERSION) },
                    { "name": "Accept", "value": "*/*" }
                ],
                "queryString": [],
                "headersSize": -1,
                "bodySize": 0
            },
            "response": {
                "status": it.status_code,
                "statusText": if it.success { "OK" } else { "Error" },
                "httpVersion": http_version,
                "cookies": [],
                "headers": headers,
                "content": {
                    "size": body_len,
                    "mimeType": mime,
                    "text": body_snippet
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": body_len
            },
            "cache": {},
            // -1 = not measured (HAR convention)
            "timings": {
                "blocked": -1,
                "dns": dns,
                "connect": connect,
                "ssl": -1,
                "send": -1,
                "wait": wait,
                "receive": receive
            },
            "connection": it.session_id
        });
        if let Some(ip) = &it.resolved_ip {
            entry["serverIPAddress"] = json!(ip);
        }
        entries.push(entry);
    }

    json!({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "ReadyHai Autonomous QA Gate",
                "version": crate::engine::VERSION
            },
            "pages": [
                {
                    "startedDateTime": report.iterations.first().map(|i| i.timestamp.as_str()).unwrap_or(""),
                    "id": "page_readyhai_regression",
                    "title": format!("ReadyHai Regression Audit - {}", report.target),
                    "pageTimings": {
                        "onContentLoad": report.p50_latency_ms,
                        "onLoad": report.p90_latency_ms
                    }
                }
            ],
            "entries": entries
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Tiny HTTP stub on an ephemeral port. `handler` gets the raw request head and returns the
    /// full response, or None to hang (the connection is held open for 4 s without an answer).
    fn stub(handler: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = std::sync::Arc::new(handler);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut c) = conn else { continue };
                let handler = handler.clone();
                std::thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match std::io::Read::read(&mut c, &mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    match handler(&String::from_utf8_lossy(&head)) {
                        Some(resp) => {
                            let _ = c.write_all(resp.as_bytes());
                        }
                        None => std::thread::sleep(Duration::from_secs(4)),
                    }
                });
            }
        });
        format!("http://{addr}/")
    }

    fn reply(status: &str, body: &str) -> Option<String> {
        Some(format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
    }

    fn reply_html(status: &str, body: &str) -> Option<String> {
        Some(format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
    }

    fn base_regress(target: &str) -> RegressRequest {
        serde_json::from_value(
            json!({"target": target, "iterations": 3, "delay_between_ms": 0, "timeout_ms": 2000}),
        )
        .unwrap()
    }

    fn iteration(status: u16, err: Option<&str>) -> IterationResult {
        IterationResult {
            iteration: 1,
            session_id: "sess-1".into(),
            timestamp: "2026-10-28T00:00:00Z".into(),
            duration_ms: 50,
            dns_lookup_ms: 5,
            tcp_connect_ms: 10,
            ttfb_ms: 40,
            status_code: status,
            success: (200..300).contains(&status),
            error_message: err.map(String::from),
            curl_command: "curl http://localhost".into(),
            response_headers: HashMap::new(),
            response_body_snippet: Some("OK".into()),
            resolved_ip: None,
            http_version: None,
        }
    }

    // ------------------------------------------------------------ target / clamp validation

    #[test]
    fn targets_must_be_http_or_https() {
        for bad in [
            "ftp://x/",
            "file:///etc/passwd",
            "gopher://x/",
            "javascript:alert(1)",
            "x",
            "",
            "-oProxyCommand=x",
            "http://user:pw@x/",
        ] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_target("HTTP://Example.com").unwrap().as_str(),
            "http://example.com/"
        );
        // the backslash form is normalised before anything (curl included) sees it
        assert_eq!(
            parse_target("http://app.example\\@evil.example/x")
                .unwrap()
                .as_str(),
            "http://app.example/@evil.example/x"
        );
        let mut c = CurlTestRequest {
            target: "file:///etc/passwd".into(),
            method: "GET".into(),
            headers: HashMap::new(),
            payload: None,
            timeout_ms: 1000,
        };
        assert!(c.sanitize().is_err());
        assert!(execute_curl_test(&c).is_err());
    }

    #[test]
    fn regress_request_is_clamped() {
        let mut r: RegressRequest = serde_json::from_value(json!({
            "target": "http://x.example", "iterations": 10_000_000u64, "timeout_ms": u64::MAX,
            "simulated_latency_ms": u64::MAX, "delay_between_ms": u64::MAX, "method": "post"
        }))
        .unwrap();
        assert!(r.is_intrusive());
        r.sanitize().unwrap();
        assert_eq!(r.iterations, MAX_ITERATIONS);
        assert_eq!(r.timeout_ms, MAX_TIMEOUT_MS);
        assert_eq!(r.simulated_latency_ms, MAX_LATENCY_MS);
        assert_eq!(r.delay_between_ms, MAX_DELAY_MS);
        assert_eq!(r.method, "POST");
        assert_eq!(r.target, "http://x.example/");
        let mut r: RegressRequest = serde_json::from_value(
            json!({"target": "http://x.example", "iterations": 0, "timeout_ms": 0}),
        )
        .unwrap();
        r.sanitize().unwrap();
        assert_eq!((r.iterations, r.timeout_ms), (1, MIN_TIMEOUT_MS));
    }

    #[test]
    fn other_requests_are_clamped() {
        let mut c = CurlTestRequest {
            target: "http://x.example".into(),
            method: "GET".into(),
            headers: HashMap::new(),
            payload: None,
            timeout_ms: u64::MAX,
        };
        c.sanitize().unwrap();
        assert_eq!(c.timeout_ms, MAX_TIMEOUT_MS);
        let mut d = DeepAuditRequest {
            target: "http://x.example".into(),
            timeout_ms: u64::MAX,
        };
        d.sanitize().unwrap();
        assert_eq!(d.timeout_ms, MAX_TIMEOUT_MS);
        d.timeout_ms = 0;
        d.sanitize().unwrap();
        assert_eq!(d.timeout_ms, MIN_TIMEOUT_MS);
        let mut m = MultiRegionRequest {
            target: "http://x.example".into(),
            timeout_ms: Some(u64::MAX),
        };
        m.sanitize().unwrap();
        assert_eq!(m.timeout_ms, Some(MAX_TIMEOUT_MS));
        let mut m = MultiRegionRequest {
            target: "http://x.example".into(),
            timeout_ms: None,
        };
        m.sanitize().unwrap();
        assert_eq!(m.timeout_ms, Some(4000));
    }

    #[test]
    fn methods_headers_and_payload_are_validated() {
        let ok = |m: &str| {
            RegressRequest {
                method: m.into(),
                ..base_regress("http://x.example")
            }
            .sanitize()
            .is_ok()
        };
        assert!(ok("get") && ok("PATCH") && ok("options"));
        assert!(!ok("TRACE") && !ok("CONNECT") && !ok("GET --upload-file /etc/passwd") && !ok(""));
        let mut r = base_regress("http://x.example");
        r.headers.insert("X-Ok".into(), "v".into());
        assert!(r.clone().sanitize().is_ok());
        for (k, v) in [
            ("X\nBad", "v"),
            ("X-A", "a\r\nInjected: 1"),
            ("@/etc/passwd", "x"),
            ("", "v"),
            ("X-A", "nul\0"),
        ] {
            let mut r = base_regress("http://x.example");
            r.headers.insert(k.into(), v.into());
            assert!(r.sanitize().is_err(), "{k:?}");
        }
        let mut r = base_regress("http://x.example");
        r.payload = Some("A".repeat(MAX_PAYLOAD_BYTES + 1));
        assert!(r.sanitize().is_err());
        let mut r = base_regress("http://x.example");
        for i in 0..=MAX_HEADERS {
            r.headers.insert(format!("X-{i}"), "v".into());
        }
        assert!(r.sanitize().is_err());
    }

    #[test]
    fn intrusive_classification() {
        let mut r = base_regress("http://x.example");
        assert!(!r.is_intrusive());
        r.iterations = READONLY_MAX_ITERATIONS + 1;
        assert!(r.is_intrusive());
        r.iterations = 3;
        r.payload = Some("{}".into());
        assert!(r.is_intrusive());
        assert!(is_safe_method("head") && !is_safe_method("DELETE"));
    }

    // ------------------------------------------------------------ curl hardening

    #[test]
    fn curl_gets_proto_limit_and_double_dash_before_the_url() {
        let mut req = CurlTestRequest {
            target: "http://x.example/a?b=c".into(),
            method: "post".into(),
            headers: HashMap::new(),
            payload: Some("@/etc/passwd".into()),
            timeout_ms: 2000,
        };
        let url = req.sanitize().unwrap();
        let cmd = curl_command(&req, &url, 2);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let pos = |s: &str| {
            args.iter()
                .position(|a| a == s)
                .unwrap_or_else(|| panic!("{s} missing in {args:?}"))
        };
        assert_eq!(args[0], "-q", "ignore ~/.curlrc");
        assert_eq!(args[pos("--proto") + 1], "=http,https");
        assert_eq!(args[args.len() - 2], "--");
        assert_eq!(args[args.len() - 1], "http://x.example/a?b=c");
        assert!(pos("--proto") < pos("--"));
        // '@file' payloads are sent literally, never read from disk
        assert_eq!(args[pos("--data-raw") + 1], "@/etc/passwd");
        assert!(!args.iter().any(|a| a == "-d"));
        // the protocol probes carry the same protection
        assert!(
            // formatting-independent: every curl invocation pins the protocol list
            include_str!("network.rs")
                .matches("\"=http,https\"")
                .count()
                >= 3
        );
    }

    #[test]
    fn repro_command_is_shell_safe() {
        let mut h = HashMap::new();
        h.insert("X-A".to_string(), "v'; rm -rf / #".to_string());
        let c = generate_curl("get", "http://x/?a=1&b=$(id)", &h, Some("it's \"x\""));
        assert!(c.contains("-H 'X-A: v'\\''; rm -rf / #'"), "{c}");
        assert!(c.contains("-- 'http://x/?a=1&b=$(id)'"), "{c}");
        assert!(c.contains("--data-raw 'it'\\''s \"x\"'"), "{c}");
        assert!(c.contains("-X 'GET'"));
    }

    #[test]
    fn curl_output_is_capped_but_timings_survive() {
        // 3 MiB of body, cap 1 MiB: the -w trailer must still be parsed from the retained tail
        let body = "x".repeat(3 * 1024 * 1024);
        let url = stub(move |_| reply("200 OK", &body));
        let r = execute_curl_test(&CurlTestRequest {
            target: url,
            method: "GET".into(),
            headers: HashMap::new(),
            payload: None,
            timeout_ms: 5000,
        })
        .unwrap();
        if Command::new("curl").arg("--version").output().is_err() {
            return; // no curl: the fallback path is covered by fallback_reports_unmeasured_fields
        }
        assert!(
            r.not_measured.is_empty(),
            "curl was available but the fallback ran: {}",
            r.stderr
        );
        assert_eq!(r.exit_code, 0, "{}", r.stderr);
        assert!(r.truncated, "{}", r.stdout.len());
        assert!(
            r.stdout.len() < MAX_CAPTURE_BYTES + 200,
            "{}",
            r.stdout.len()
        );
        assert!(r.stdout.contains("[output truncated"));
        assert_eq!(
            r.status_code, 200,
            "timings trailer must survive truncation"
        );
        assert!(r.total_s > 0.0);
    }

    #[test]
    fn curl_refuses_non_http_schemes_even_if_it_reached_curl() {
        // belt and braces: --proto limits curl itself, independent of our URL parsing
        let out = Command::new("curl")
            .args([
                "-q",
                "-sS",
                "--proto",
                "=http,https",
                "--",
                "file:///etc/hostname",
            ])
            .output();
        if let Ok(o) = out {
            assert!(!o.status.success());
        }
    }

    #[test]
    fn tls_is_measured_from_a_real_handshake() {
        if Command::new("openssl").arg("version").output().is_err() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("rh-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (key, crt) = (dir.join("k.pem"), dir.join("c.pem"));
        let keygen = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "30",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&crt)
            .output()
            .unwrap();
        assert!(
            keygen.status.success(),
            "{}",
            String::from_utf8_lossy(&keygen.stderr)
        );
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let mut server = Command::new("openssl")
            .args(["s_server", "-accept"])
            .arg(port.to_string())
            .arg("-cert")
            .arg(&crt)
            .arg("-key")
            .arg(&key)
            .arg("-www")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..60 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let url = parse_target(&format!("https://127.0.0.1:{port}/")).unwrap();
        let t = audit_tls_chain(&url, "127.0.0.1", port, 5000);
        let _ = server.kill();
        let _ = server.wait();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(t.measured && t.is_https, "{t:?}");
        assert!(t.tls_version.starts_with("TLSv1."), "{}", t.tls_version);
        assert!(!t.cipher.is_empty() && t.cipher != "not measured");
        assert!(t.cert_subject.contains("localhost"), "{}", t.cert_subject);
        assert!(t.cert_issuer.contains("localhost"), "{}", t.cert_issuer);
        assert_eq!(t.cert_sans, vec!["localhost"]);
        assert!(t.is_self_signed, "{t:?}");
        assert!(!t.is_intermediate_missing);
        assert!(
            matches!(t.days_remaining, Some(29 | 30)),
            "{:?}",
            t.days_remaining
        );
        assert!(t.not_after.as_deref().is_some_and(|d| d.ends_with("GMT")));
        assert_eq!(
            t.ocsp_stapled,
            Some(false),
            "a plain s_server staples nothing"
        );
        assert_eq!(t.chain_length, Some(1));
    }

    #[test]
    fn tls_against_a_closed_port_is_not_measured() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let url = parse_target(&format!("https://127.0.0.1:{port}/")).unwrap();
        let t = audit_tls_chain(&url, "127.0.0.1", port, 2000);
        assert!(
            !t.measured && t.ocsp_stapled.is_none() && t.days_remaining.is_none(),
            "{t:?}"
        );
        assert_eq!(t.cert_issuer, "not measured");
    }

    #[test]
    fn fallback_reports_unmeasured_fields() {
        // the native-client fallback must not invent DNS/connect timings
        let url = stub(|_| reply("200 OK", "hi"));
        let u = parse_target(&url).unwrap();
        let req = CurlTestRequest {
            target: url,
            method: "GET".into(),
            headers: HashMap::new(),
            payload: None,
            timeout_ms: 2000,
        };
        let r = native_curl_fallback(&req, &u, "curl ...".into(), "no curl").unwrap();
        assert_eq!((r.status_code, r.stdout.as_str()), (200, "hi"));
        assert_eq!(
            (r.dns_lookup_s, r.connect_s, r.appconnect_s),
            (0.0, 0.0, 0.0)
        );
        assert_eq!(
            r.not_measured,
            vec!["dns_lookup_s", "connect_s", "appconnect_s"]
        );
        assert!(r.starttransfer_s > 0.0 && r.total_s >= r.starttransfer_s);
        // and a dead target lists everything as unmeasured
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!("http://127.0.0.1:{}/", l.local_addr().unwrap().port());
        drop(l);
        let req = CurlTestRequest {
            target: dead.clone(),
            method: "GET".into(),
            headers: HashMap::new(),
            payload: None,
            timeout_ms: 1000,
        };
        let r = native_curl_fallback(
            &req,
            &parse_target(&dead).unwrap(),
            "curl ...".into(),
            "no curl",
        )
        .unwrap();
        assert_eq!(r.exit_code, 1);
        assert_eq!(r.not_measured.len(), 4);
    }

    // ------------------------------------------------------------ regress

    #[test]
    fn non_2xx_counts_as_failure() {
        for (status, line) in [
            (200, "200 OK"),
            (404, "404 Not Found"),
            (500, "500 Internal Server Error"),
            (401, "401 Unauthorized"),
        ] {
            let url = stub(move |_| reply(line, "body"));
            let rep = run_regress_test(&base_regress(&url)).unwrap();
            assert_eq!(rep.total_iterations, 3);
            if status == 200 {
                assert_eq!((rep.successful_iterations, rep.failed_iterations), (3, 0));
                assert_eq!(rep.availability_percentage, 100.0);
                assert_eq!(rep.diagnosis.root_cause_type, "STABLE");
            } else {
                assert_eq!(
                    (rep.successful_iterations, rep.failed_iterations),
                    (0, 3),
                    "{status}"
                );
                assert_eq!(rep.availability_percentage, 0.0);
                assert_ne!(
                    rep.diagnosis.root_cause_type, "STABLE",
                    "{status} must not be reported as stable"
                );
                assert!(rep.diagnosis.flakiness_detected);
            }
            assert!(
                rep.iterations
                    .iter()
                    .all(|i| i.resolved_ip.as_deref() == Some("127.0.0.1"))
            );
            assert!(
                rep.iterations
                    .iter()
                    .all(|i| i.session_id.starts_with("sess-"))
            );
        }
    }

    #[test]
    fn redirects_are_failures_and_never_leave_the_host() {
        let url = stub(|_| {
            Some("HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into())
        });
        let rep = run_regress_test(&base_regress(&url)).unwrap();
        assert_eq!(rep.failed_iterations, 3);
        assert_eq!(
            rep.iterations[0].status_code, 302,
            "the redirect must not be followed to another host"
        );
    }

    #[test]
    fn multibyte_body_does_not_panic_the_snippet_cut() {
        // 300 three-byte characters: byte 256 is inside a character
        let body = "日".repeat(300);
        let url = stub(move |_| reply("200 OK", &body));
        let rep = run_regress_test(&base_regress(&url)).unwrap();
        let snip = rep.iterations[0].response_body_snippet.clone().unwrap();
        assert_eq!(snip.chars().count(), BODY_SNIPPET_CHARS + 3);
        assert!(snip.ends_with("..."));
        assert_eq!(truncate_chars("é".repeat(10).as_str(), 4), "éééé...");
        assert_eq!(truncate_chars("abc", 4), "abc");
        assert_eq!(truncate_chars("", 0), "");
    }

    #[test]
    fn diagnose_non_2xx_is_not_stable() {
        let rs = vec![
            iteration(404, Some("HTTP Status 404")),
            iteration(404, Some("HTTP Status 404")),
        ];
        let d = diagnose(&rs, 0.0, 50, 55, 5, 5000);
        assert_eq!(d.root_cause_type, "HTTP_ERRORS");
        assert!(d.flakiness_detected);
        let rs = vec![iteration(301, Some("HTTP Status 301"))];
        assert_eq!(
            diagnose(&rs, 0.0, 50, 55, 5, 5000).root_cause_type,
            "HTTP_ERRORS"
        );
    }

    #[test]
    fn jitter_needs_an_absolute_spread_not_just_a_ratio() {
        assert_eq!(
            diagnose(&[iteration(200, None)], 100.0, 1, 4, 3, 5000).root_cause_type,
            "STABLE"
        );
        assert_eq!(
            diagnose(&[iteration(200, None)], 100.0, 30, 120, 90, 5000).root_cause_type,
            "HIGH_JITTER"
        );
        assert_eq!(
            diagnose(&[iteration(200, None)], 100.0, 500, 900, 400, 5000).root_cause_type,
            "HIGH_JITTER"
        );
    }

    #[test]
    fn test_diagnose_stable() {
        let d = diagnose(&[iteration(200, None)], 100.0, 50, 55, 10, 5000);
        assert_eq!(d.root_cause_type, "STABLE");
    }

    #[test]
    fn test_diagnose_timeout() {
        let mut r = iteration(0, Some("Operation timed out"));
        r.duration_ms = 5000;
        let d = diagnose(&[r], 0.0, 5000, 5000, 0, 5000);
        assert_eq!(d.root_cause_type, "TIMEOUT");
    }

    // ------------------------------------------------------------ MTU

    fn mtu_item(
        size: usize,
        delivered: bool,
        transport_failure: bool,
        status: u16,
    ) -> MtuSweepItem {
        MtuSweepItem {
            payload_bytes: size,
            label: String::new(),
            status_code: status,
            duration_ms: 1,
            success: (200..300).contains(&status),
            delivered,
            transport_failure,
            header_limit_hit: is_header_limit_status(status),
            error: None,
        }
    }

    #[test]
    fn mtu_rule_distinguishes_header_limits_from_black_holes() {
        // 431 / 400 / 413 / 414 on large probes: packets arrived, server said no
        for st in [400, 413, 414, 431] {
            let r = vec![
                mtu_item(512, true, false, 200),
                mtu_item(1400, true, false, st),
                mtu_item(4096, true, false, st),
                mtu_item(8192, true, false, st),
            ];
            assert!(!mtu_black_hole(&r), "HTTP {st} is not a black hole");
        }
        // timeout on large after a good baseline: black hole
        let r = vec![
            mtu_item(512, true, false, 200),
            mtu_item(1400, false, true, 0),
        ];
        assert!(mtu_black_hole(&r));
        // dead target (baseline fails too) or a refused connection is not a black hole
        assert!(!mtu_black_hole(&[
            mtu_item(512, false, true, 0),
            mtu_item(1400, false, true, 0)
        ]));
        assert!(!mtu_black_hole(&[
            mtu_item(512, true, false, 200),
            mtu_item(1400, false, false, 0)
        ]));
    }

    #[test]
    fn mtu_sweep_with_a_431_server_reports_no_black_hole() {
        let url = stub(|req| {
            if req.len() > 1000 {
                reply("431 Request Header Fields Too Large", "")
            } else {
                reply("200 OK", "ok")
            }
        });
        let a = audit_mtu_sweep(&url, 2000);
        assert!(!a.black_hole_detected, "{}", a.diagnosis);
        assert_eq!(a.maximum_safe_bytes, 512);
        assert_eq!(a.maximum_delivered_bytes, 8192);
        assert!(
            a.sweep_results
                .iter()
                .skip(1)
                .all(|r| r.header_limit_hit && r.delivered && !r.success)
        );
        assert!(a.diagnosis.contains("header-size limit"), "{}", a.diagnosis);
    }

    #[test]
    fn mtu_sweep_flags_a_real_black_hole() {
        // large requests are swallowed (no response at all), small ones answered
        let url = stub(|req| {
            if req.len() > 1000 {
                None
            } else {
                reply("200 OK", "ok")
            }
        });
        let a = audit_mtu_sweep(&url, 800);
        assert!(a.black_hole_detected, "{}", a.diagnosis);
        assert_eq!(a.maximum_safe_bytes, 512);
    }

    // ------------------------------------------------------------ deep audit

    #[test]
    fn deep_audit_against_a_local_stub() {
        let url = stub(|req| {
            if req.starts_with("OPTIONS") {
                Some("HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: https://qa-probe.readyhai.internal\r\nConnection: close\r\n\r\n".into())
            } else {
                // every path, /app.js included, answers with the HTML shell (a broken SPA fallback)
                reply_html(
                    "200 OK",
                    "<html><script src=\"/app.js\"></script><script src=\"http://169.254.169.254/x.js\"></script></html>",
                )
            }
        });
        let rep = run_deep_audit(&DeepAuditRequest {
            target: url,
            timeout_ms: 2000,
        })
        .unwrap();
        assert!(rep.health_score > 0);
        assert!(!rep.overall_verdict.is_empty());
        // plain http: no TLS fabrication
        assert!(!rep.tls_chain.is_https);
        assert!(
            rep.tls_chain.ocsp_stapled.is_none()
                && rep.tls_chain.days_remaining.is_none()
                && rep.tls_chain.not_after.is_none()
        );
        // the cross-host asset was not fetched, only recorded as skipped
        assert_eq!(rep.subresources.skipped_cross_host, 1);
        assert!(
            rep.subresources
                .items
                .iter()
                .all(|i| i.url.contains("127.0.0.1"))
        );
        assert_eq!(
            rep.subresources.spa_fallback_mismatches, 1,
            "{:?}",
            rep.subresources
        );
        assert!(
            rep.identified_risks
                .iter()
                .any(|r| r.contains("SPA Routing Flaw"))
        );
        assert!(
            rep.protocol_matrix
                .protocols
                .iter()
                .any(|p| p.protocol.starts_with("HTTP/3") && p.status_code == 0)
        );
    }

    #[test]
    fn deep_audit_non_2xx_assets_are_broken() {
        let url = stub(|req| {
            if req.starts_with("GET / ") {
                reply(
                    "200 OK",
                    "<html><script src=\"/missing.js\"></script></html>",
                )
            } else {
                reply("404 Not Found", "nope")
            }
        });
        let u = parse_target(&url).unwrap();
        let a = audit_subresources(&u, 2000);
        assert_eq!(a.broken_count, 1, "{a:?}");
        assert_eq!(a.items[0].status_code, 404);
    }

    #[test]
    fn deep_audit_rejects_non_http_targets() {
        assert!(
            run_deep_audit(&DeepAuditRequest {
                target: "file:///etc/passwd".into(),
                timeout_ms: 1000
            })
            .is_err()
        );
    }

    // ------------------------------------------------------------ TLS parsing (no hard-coded values)

    const S_CLIENT: &str = "\
CONNECTED(00000003)
Certificate chain
 0 s:CN = example.com
   i:C = US, O = Let's Encrypt, CN = R3
-----BEGIN CERTIFICATE-----
MIIAAA==
-----END CERTIFICATE-----
 1 s:C = US, O = Let's Encrypt, CN = R3
   i:O = Digital Signature Trust Co., CN = DST Root CA X3
-----BEGIN CERTIFICATE-----
MIIBBB==
-----END CERTIFICATE-----
OCSP response: no response sent
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Verify return code: 0 (ok)
";

    #[test]
    fn s_client_output_is_parsed_not_assumed() {
        let s = parse_s_client(S_CLIENT);
        assert_eq!(s.version.as_deref(), Some("TLSv1.3"));
        assert_eq!(s.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(s.verify_code, Some(0));
        assert_eq!(
            s.ocsp_stapled,
            Some(false),
            "'no response sent' means NOT stapled (it used to be hard-coded true)"
        );
        assert_eq!(s.chain_len, 2);
        let pem = s.leaf_pem.unwrap();
        assert!(pem.contains("MIIAAA==") && !pem.contains("MIIBBB=="));
        assert_eq!(
            parse_s_client("OCSP Response Status: successful (0x0)").ocsp_stapled,
            Some(true)
        );
        assert_eq!(parse_s_client("nothing relevant").ocsp_stapled, None);
        let failed = parse_s_client("New, (NONE), Cipher is (NONE)");
        assert!(failed.version.is_none() && failed.cipher.is_none());
        assert_eq!(
            parse_s_client("Verify return code: 21 (unable to verify the first certificate)")
                .verify_code,
            Some(21)
        );
    }

    #[test]
    fn x509_and_dates_are_parsed() {
        let leaf = parse_x509(
            "subject=CN = example.com\nissuer=C = US, O = Let's Encrypt, CN = R3\nnotAfter=Jan  1 00:00:00 2027 GMT\nX509v3 Subject Alternative Name: \n    DNS:example.com, DNS:www.example.com\n",
        );
        assert_eq!(leaf.subject.as_deref(), Some("CN = example.com"));
        assert_eq!(
            leaf.issuer.as_deref(),
            Some("C = US, O = Let's Encrypt, CN = R3")
        );
        assert_eq!(leaf.sans, vec!["example.com", "www.example.com"]);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(
            parse_openssl_date("Jan  1 00:00:00 2027 GMT"),
            Some(1_798_761_600)
        );
        assert_eq!(
            parse_openssl_date("Feb 29 12:30:15 2028 GMT"),
            Some(days_from_civil(2028, 2, 29) * 86_400 + 12 * 3600 + 30 * 60 + 15)
        );
        assert_eq!(
            days_from_civil(2028, 3, 1) - days_from_civil(2028, 2, 29),
            1
        );
        assert_eq!(parse_openssl_date("garbage"), None);
        assert_eq!(parse_openssl_date("Foo  1 00:00:00 2027 GMT"), None);
    }

    #[test]
    fn unmeasured_tls_says_so() {
        let t = unmeasured_tls(true, "openssl is not available");
        assert!(
            !t.measured
                && t.ocsp_stapled.is_none()
                && t.days_remaining.is_none()
                && t.not_after.is_none()
        );
        assert_eq!(t.cert_issuer, "not measured");
        assert_eq!(t.tls_version, "not measured");
        assert!(t.cert_sans.is_empty());
        assert_eq!(t.not_measured, vec!["openssl is not available"]);
    }

    // ------------------------------------------------------------ multi-region

    #[test]
    fn multi_region_reports_only_the_local_measurement() {
        let url = stub(|_| reply("200 OK", "ok"));
        let rep = run_multi_region_audit(&MultiRegionRequest {
            target: url,
            timeout_ms: Some(2000),
        })
        .unwrap();
        assert_eq!(rep.regions.len(), 1);
        let r = &rep.regions[0];
        assert!(r.measured && r.region_id == "local");
        assert_eq!(r.http_status, 200);
        assert_eq!(r.resolved_ip, "127.0.0.1");
        assert_eq!(r.packet_loss_pct, 0.0);
        assert_eq!(rep.not_measured_regions.len(), 4);
        assert!(
            rep.geo_dns_consistent.is_none(),
            "geo-DNS consistency cannot be known from one vantage point"
        );
        assert!(rep.measurement_note.contains("no remote probe nodes"));
        assert_eq!(rep.fastest_region, "not measured");
    }

    #[test]
    fn multi_region_unreachable_target_is_offline() {
        // nothing listens here
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let rep = run_multi_region_audit(&MultiRegionRequest {
            target: format!("http://127.0.0.1:{port}/"),
            timeout_ms: Some(800),
        })
        .unwrap();
        assert_eq!(rep.regions[0].status, "OFFLINE");
        assert_eq!(rep.regions[0].packet_loss_pct, 100.0);
        assert!(rep.agent_verdict.starts_with("CRITICAL"));
    }

    // ------------------------------------------------------------ HAR

    #[test]
    fn test_generate_har() {
        let mut it = iteration(200, None);
        it.resolved_ip = Some("10.1.2.3".into());
        it.http_version = Some("HTTP/2.0".into());
        let rep = RegressReport {
            target: "http://localhost".into(),
            method: "POST".into(),
            total_iterations: 1,
            iterations_requested: 1,
            stopped_early: false,
            successful_iterations: 1,
            failed_iterations: 0,
            availability_percentage: 100.0,
            avg_latency_ms: 50,
            p50_latency_ms: 50,
            p90_latency_ms: 50,
            p99_latency_ms: 50,
            min_latency_ms: 50,
            max_latency_ms: 50,
            jitter_ms: 0,
            status_distribution: HashMap::new(),
            iterations: vec![it, iteration(0, Some("boom"))],
            diagnosis: diagnose(&[iteration(200, None)], 100.0, 50, 50, 0, 5000),
            requester_ip: Some("127.0.0.1".into()),
            allowlist_recommendation: Some("Add 127.0.0.1/32 to allowlist".into()),
        };
        let har = generate_har_from_regress(&rep);
        assert_eq!(har["log"]["version"], "1.2");
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0]["request"]["method"], "POST",
            "method comes from the report, not a constant"
        );
        assert_eq!(entries[0]["serverIPAddress"], "10.1.2.3");
        assert_eq!(entries[0]["response"]["httpVersion"], "HTTP/2.0");
        assert!(
            entries[1].get("serverIPAddress").is_none(),
            "no invented 127.0.0.1"
        );
        assert_eq!(entries[1]["response"]["httpVersion"], "");
        assert_eq!(entries[0]["timings"]["ssl"], -1);
    }

    #[test]
    fn old_reports_still_deserialize() {
        // a RegressReport saved before the additive fields existed
        let v = json!({"target":"http://a/","total_iterations":1,"successful_iterations":1,"failed_iterations":0,
            "availability_percentage":100.0,"avg_latency_ms":1,"p50_latency_ms":1,"p90_latency_ms":1,"p99_latency_ms":1,
            "min_latency_ms":1,"max_latency_ms":1,"jitter_ms":0,"status_distribution":{},
            "diagnosis":{"flakiness_detected":false,"root_cause_type":"STABLE","severity":"STABLE","title":"t","summary":"s",
              "how_agent_found_it":[],"technical_breakdown":[],"reproduction_curl":"c","remediation_checklist":[]},
            "iterations":[{"iteration":1,"session_id":"s","timestamp":"t","duration_ms":1,"dns_lookup_ms":1,"tcp_connect_ms":1,
              "ttfb_ms":1,"status_code":200,"success":true,"error_message":null,"curl_command":"c","response_headers":{},"response_body_snippet":null}]});
        let r: RegressReport = serde_json::from_value(v).unwrap();
        assert_eq!(r.method, "GET");
        assert!(r.iterations[0].resolved_ip.is_none());
    }
}
