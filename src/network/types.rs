//! Domain models, request/response DTOs, audit structures, and diagnostic types for network testing.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use super::utils::{is_safe_method, parse_method, parse_target, validate_headers, validate_payload};

pub const MAX_ITERATIONS: usize = 100;
pub const READONLY_MAX_ITERATIONS: usize = 25;
pub const MIN_TIMEOUT_MS: u64 = 100;
pub const MAX_TIMEOUT_MS: u64 = 15_000;
pub const MAX_LATENCY_MS: u64 = 5_000;
pub const MAX_DELAY_MS: u64 = 5_000;
pub const MAX_REGRESS_BUDGET_MS: u64 = 120_000;
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_HEADERS: usize = 64;
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
pub const MAX_REDIRECTS: usize = 3;
pub const BODY_SNIPPET_CHARS: usize = 256;
pub const BODY_READ_CAP: usize = 4 * 1024;
pub const MAX_SUBRESOURCES: usize = 12;
pub const SUBRESOURCE_BYTES_CAP: usize = 2 * 1024 * 1024;
pub const HTML_BYTES_CAP: usize = 1024 * 1024;
pub const NOT_MEASURED: &str = "not measured";
pub const NOT_MEASURED_REGIONS: [&str; 4] = ["us-east-1", "eu-west-1", "ap-south-1", "ap-southeast-1"];

pub const IP_CACHE_OK_TTL: Duration = Duration::from_secs(600);
pub const IP_CACHE_FAIL_TTL: Duration = Duration::from_secs(30);
pub const IP_PROVIDER_CONNECT: Duration = Duration::from_millis(1000);
pub const IP_PROVIDER_TIMEOUT: Duration = Duration::from_millis(1500);
pub const IP_LOOKUP_BUDGET: Duration = Duration::from_millis(4000);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequesterIpInfo {
    pub egress_public_ip: String,
    pub ip_type: String, // 'Public Egress (Direct)' | 'Private Intranet (RFC1918)'
    pub is_private: bool,
    pub allowlist_guidance: String,
    pub detected_via: String,
    pub detected_at: String,
}

/// The egress IP as seen by targets, for firewall allow-listing. **Blocking** (may contact IP-echo
/// services): async callers use the blocking pool. Not contacted at all in offline mode
/// (`READYHAI_OFFLINE`); results are cached with a TTL (short for a failed lookup).

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

