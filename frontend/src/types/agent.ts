export interface DiscoveredRoute {
  path: string;
  method: string;
  status_code: number;
  content_type: string;
  is_spa_shell: boolean;
  is_api: boolean;
}

export interface DiscoveredTarget {
  target: string;
  is_spa: boolean;
  count: number;
  routes: DiscoveredRoute[];
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
  discovered_routes: DiscoveredRoute[];
  test_cases: TestCaseResult[];
  threats: ThreatFinding[];
  evidence_ledger: EvidenceLedger;
}
