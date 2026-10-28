export type ModelTier = "low" | "medium" | "high" | "max" | "max_pro";

export interface DiscoveredRoute {
  path: string;
  method: string;
  status_code: number;
  content_type: string;
  is_spa_shell: boolean;
  is_api: boolean;
  title?: string;
  has_form?: boolean;
}

export interface DiscoveredTarget {
  target: string;
  is_spa: boolean;
  app_architecture?: string;
  framework?: string;
  detected_tech?: string[];
  count: number;
  routes: DiscoveredRoute[];
}

export interface PlannedCase {
  id: string;
  component: string;
  title: string;
  method: string;
  technique: string;
  input_hint: string;
  payload: string | null;
  expected_behavior: string;
  expected_status: number;
  risk_level: string;
}

export interface TestCaseResult {
  id: string;
  title: string;
  component: string;
  technique: string;
  method: string;
  status: "PASS" | "FAIL" | "WARN" | "SKIPPED" | "PLANNED" | "PENDING";
  latency_ms: number;
  curl: string;
  request_payload?: string | null;
  response_status?: number | null;
  response_content_type?: string | null;
  response_body?: string | null;
  assertion_details?: string | null;
  retested?: boolean;
}

export interface ThreatFinding {
  owasp_category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  affected_routes: string[];
  remediation: string;
}

export interface TriagedDefect {
  case_id: string;
  owasp_category: string;
  severity: string;
  title: string;
  evidence_snippet: string;
  remediation_patch_suggestion: string;
  affected_endpoints: string[];
}

export interface AgentStep {
  agent: string;
  action: string;
  details: string;
  status: string;
  timestamp: string;
}

export interface PillarScore {
  score: number;
  status: "PASS" | "WARN" | "FAIL";
  evidence: string;
}

export interface EvidenceLedger {
  contract?: PillarScore;
  authz?: PillarScore;
  resilience?: PillarScore;
  observability?: PillarScore;
  value_score?: number;
  authority_score?: number;
  safety_score?: number;
  evidence_score?: number;
  overall_readiness?: number;
  gate_verdict?: string;
  composite_score?: number;
  verdict?: "GO" | "CONDITIONAL_GO" | "NO_GO";
  approval_status?: "PENDING" | "APPROVED" | "REJECTED";
  approved_by?: string;
  approval_notes?: string;
  executive_summary?: string;
}

export interface AgentRunData {
  run_id: string;
  target: string;
  spec_url?: string;
  timestamp: string;
  is_spa: boolean;
  app_architecture?: string;
  framework?: string;
  detected_tech?: string[];
  discovered_routes: DiscoveredRoute[];
  test_cases: TestCaseResult[];
  threats: ThreatFinding[];
  evidence_ledger: EvidenceLedger;
  requester_ip?: string;
  requester_ip_type?: string;
  allowlist_guidance?: string;
}

export interface AgentRunFull {
  id: string;
  target: string;
  status: string;
  started_at: string;
  completed_at?: string;
  profile: string;
  provider: string;
  thinking?: boolean;
  model_tier?: ModelTier | string;
  thinking_budget_tokens?: number;
  app_architecture?: string;
  framework?: string;
  detected_tech?: string[];
  steps: AgentStep[];
  discovered_routes: DiscoveredRoute[];
  planned_cases: PlannedCase[];
  executed_results: TestCaseResult[];
  triaged_defects: TriagedDefect[];
  evidence_ledger?: EvidenceLedger;
  approval_status?: string;
  approved_by?: string;
  approval_notes?: string;
  approved_at?: string;
  requester_ip?: string;
  requester_ip_type?: string;
  allowlist_guidance?: string;
}

export interface RequesterIpResponse {
  egress_public_ip: string;
  ip_type: string;
  is_private: boolean;
  allowlist_guidance: string;
  detected_via: string;
  detected_at: string;
  client_inbound_ip: string;
}
