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
  summary: string;
  root_cause_type: "STABLE" | "TIMEOUT" | "CONNECTION_RESET" | "5XX_FLAPPING" | "HIGH_JITTER" | "INTERMITTENT_DEGRADATION" | string;
  how_agent_found_it: string[];
  technical_breakdown: string;
  remediation_steps: string[];
}

export interface RegressReport {
  target: string;
  method: string;
  iterations_requested: number;
  iterations_completed: number;
  successful_count: number;
  failed_count: number;
  success_rate_pct: number;
  flakiness_verdict: "STABLE" | "FLAKY" | "CRITICAL_OUTAGE" | string;
  p50_ms: number;
  p90_ms: number;
  p99_ms: number;
  avg_ms: number;
  min_ms: number;
  max_ms: number;
  jitter_ms: number;
  status_counts: Record<string, number>;
  results: IterationResult[];
  agent_diagnosis: AgentDiagnosis;
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
