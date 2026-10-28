export interface RegressRequest {
  target: string;
  method?: string;
  headers?: Record<string, string>;
  payload?: string | null;
  iterations?: number;
  timeout_ms?: number;
  throttle_profile?: "unthrottled" | "fast_3g" | "slow_3g" | "flaky" | "custom" | string;
  simulated_latency_ms?: number;
  separate_sessions?: boolean;
  delay_between_ms?: number;
}

export interface IterationResult {
  iteration: number;
  session_id: string;
  timestamp: string;
  duration_ms: number;
  dns_lookup_ms: number;
  tcp_connect_ms: number;
  ttfb_ms: number;
  status_code: number;
  success: boolean;
  error_message?: string | null;
  curl_command: string;
  response_headers: Record<string, string>;
  response_body_snippet?: string | null;
}

export interface AgentDiagnosis {
  flakiness_detected: boolean;
  root_cause_type: "STABLE" | "TIMEOUT" | "CONNECTION_RESET" | "5XX_FLAPPING" | "HIGH_JITTER" | string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "STABLE" | string;
  title: string;
  summary: string;
  how_agent_found_it: string[];
  technical_breakdown: string[];
  reproduction_curl: string;
  remediation_checklist: string[];
}

export interface RegressReport {
  target: string;
  total_iterations: number;
  successful_iterations: number;
  failed_iterations: number;
  availability_percentage: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p90_latency_ms: number;
  p99_latency_ms: number;
  min_latency_ms: number;
  max_latency_ms: number;
  jitter_ms: number;
  status_distribution: Record<string, number>;
  diagnosis: AgentDiagnosis;
  iterations: IterationResult[];
  requester_ip?: string;
  allowlist_recommendation?: string;
}

export interface CurlTestRequest {
  target: string;
  method?: string;
  headers?: Record<string, string>;
  payload?: string | null;
  timeout_ms?: number;
}

export interface CurlTestResponse {
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  status_code: number;
  dns_lookup_s: number;
  connect_s: number;
  appconnect_s: number;
  starttransfer_s: number;
  total_s: number;
}

// ============================================================================
// 6-Pillar Deep Network & Protocol Diagnostics Types
// ============================================================================

export interface DualStackAudit {
  has_ipv4: boolean;
  has_ipv6: boolean;
  ipv4_addresses: string[];
  ipv6_addresses: string[];
  ipv4_latency_ms?: number | null;
  ipv6_latency_ms?: number | null;
  ipv6_status: "HEALTHY" | "NOT_CONFIGURED" | "BROKEN_OR_BLACKHOLE" | string;
  happy_eyeballs_risk: boolean;
  diagnosis: string;
}

export interface SubresourceItem {
  url: string;
  tag_type: "script" | "stylesheet" | "preload" | "image" | string;
  status_code: number;
  ttfb_ms: number;
  content_type: string;
  size_bytes: number;
  is_spa_fallback_error: boolean;
  is_broken: boolean;
  error?: string | null;
}

export interface SubresourceAudit {
  total_discovered: number;
  successful_count: number;
  broken_count: number;
  spa_fallback_mismatches: number;
  total_size_kb: number;
  max_asset_ttfb_ms: number;
  items: SubresourceItem[];
  diagnosis: string;
}

export interface ProtocolItem {
  protocol: string;
  supported: boolean;
  negotiation_time_ms: number;
  status_code: number;
  notes: string;
}

export interface ProtocolMatrixAudit {
  active_protocol: string;
  http2_supported: boolean;
  http3_advertised: boolean;
  alt_svc_header?: string | null;
  protocols: ProtocolItem[];
  diagnosis: string;
}

export interface TlsChainAudit {
  is_https: boolean;
  tls_version: string;
  cipher: string;
  cert_issuer: string;
  cert_subject: string;
  cert_sans: string[];
  not_after: string;
  days_remaining: number;
  is_self_signed: boolean;
  is_intermediate_missing: boolean;
  ocsp_stapled: boolean;
  diagnosis: string;
}

export interface CorsAudit {
  preflight_status_code: number;
  preflight_passed: boolean;
  allow_origin?: string | null;
  allow_methods?: string | null;
  allow_headers?: string | null;
  allow_credentials?: string | null;
  has_wildcard_with_creds: boolean;
  diagnosis: string;
}

export interface MtuSweepItem {
  payload_bytes: number;
  label: string;
  status_code: number;
  duration_ms: number;
  success: boolean;
  error?: string | null;
}

export interface MtuSweepAudit {
  black_hole_detected: boolean;
  maximum_safe_bytes: number;
  sweep_results: MtuSweepItem[];
  diagnosis: string;
}

export interface DeepAuditReport {
  target: string;
  timestamp: string;
  overall_verdict: "PASS" | "WARN" | "FAIL" | string;
  health_score: number;
  executive_summary: string;
  identified_risks: string[];
  dual_stack: DualStackAudit;
  subresources: SubresourceAudit;
  protocol_matrix: ProtocolMatrixAudit;
  tls_chain: TlsChainAudit;
  cors_preflight: CorsAudit;
  mtu_sweep: MtuSweepAudit;
  remediation_checklist: string[];
  requester_ip?: string;
  allowlist_recommendation?: string;
}

export interface MultiRegionRequest {
  target: string;
  timeout_ms?: number;
}

export interface RegionProbeResult {
  region_id: string;
  region_name: string;
  flag: string;
  location: string;
  resolved_ip: string;
  dns_time_ms: number;
  tcp_connect_ms: number;
  ttfb_ms: number;
  total_time_ms: number;
  http_status: number;
  edge_pop: string;
  status: "OPTIMAL" | "ELEVATED" | "DEGRADED" | "OFFLINE" | string;
  jitter_ms: number;
  packet_loss_pct: number;
  notes: string;
}

export interface MultiRegionReport {
  target: string;
  timestamp: string;
  regions: RegionProbeResult[];
  fastest_region: string;
  slowest_region: string;
  geo_dns_consistent: boolean;
  cdn_edge_active: boolean;
  regional_disparity_ms: number;
  agent_verdict: string;
  recommendations: string[];
}

export interface PrCommentPayload {
  title?: string;
  verdict?: string;
  score?: number;
  commit_sha?: string;
  target?: string;
  findings_count?: number;
  ledger_conformance?: number;
  ledger_rbac?: number;
  ledger_resilience?: number;
  ledger_observability?: number;
}

export interface PrCommentResponse {
  markdown: string;
  github_action_yaml: string;
  badge_markdown: string;
}
