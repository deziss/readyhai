export type ModelTier = "low" | "medium" | "high" | "max" | "max_pro";

/** Why a case could not produce evidence (BLOCKED / NOT_APPLICABLE). Backend spelling. */
export type BlockReason = "auth_wall" | "out_of_scope" | "no_surface" | "transport";

/** One redirect the executor followed: the status that redirected and where it pointed. */
export interface RedirectHop {
  status: number;
  location: string;
}

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

export interface StatefulStep {
  step_number: number;
  actor: string; // "alice", "bob", "anon", "admin"
  method: string;
  path: string;
  payload?: string;
  extract_vars?: string[];
  expected_status?: number;
  violation_condition?: string;
}

export interface StatefulStepExecution {
  step_number: number;
  actor: string;
  method: string;
  resolved_path: string;
  status_code: number;
  latency_ms: number;
  extracted_values: Record<string, string>;
  passed: boolean;
  violation_triggered?: boolean;
  error_detail?: string;
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
  stateful_steps?: StatefulStep[];
  concurrency_burst?: number;
}

export interface TestCaseResult {
  id: string;
  title: string;
  component: string;
  technique: string;
  method: string;
  status:
    | "PASS"
    | "FAIL"
    | "WARN"
    | "BLOCKED"
    | "SKIPPED"
    | "PLANNED"
    | "PENDING"
    | "INCONCLUSIVE"
    | "NOT_APPLICABLE";
  /** Set when status is BLOCKED or NOT_APPLICABLE: why no evidence could be gathered. */
  blocked_reason?: BlockReason | string | null;
  /** Same-origin redirects followed before the judged response (empty / absent: none). */
  redirect_chain?: RedirectHop[];
  /** null when the backend did not report a latency (planned / not executed). */
  latency_ms: number | null;
  curl: string;
  request_payload?: string | null;
  response_status?: number | null;
  response_content_type?: string | null;
  response_body?: string | null;
  assertion_details?: string | null;
  retested?: boolean;
  stateful_steps?: StatefulStep[];
  stateful_chain?: StatefulStepExecution[];
  concurrency_burst?: number;
  concurrency_burst_results?: number[];
  remediation_patch?: string;
  remediation_explanation?: string;
  reproduction_script?: string;
  adaptive_mutation?: {
    framework?: string;
    required_fields?: string[];
    mutated_payload?: string;
    mutated_status?: number;
    penetrated_validation?: boolean;
    mutated_verdict?: string;
  } | null;
}

export interface CaseExecutionResult {
  case_id?: string;
  id?: string;
  title?: string;
  component?: string;
  technique?: string;
  method?: string;
  status?: string;
  status_code?: number | null;
  latency_ms?: number | null;
  reproduction_curl?: string;
  curl?: string;
  request_payload?: string | null;
  evidence?: string | null;
  content_type?: string | null;
  is_spa_shell?: boolean;
  failure_reason?: string | null;
  expected_status?: number | null;
  blocked_reason?: BlockReason | string | null;
  redirect_chain?: RedirectHop[];
  stateful_steps?: StatefulStep[];
  stateful_chain?: StatefulStepExecution[];
  concurrency_burst?: number;
  concurrency_burst_results?: number[];
  remediation_patch?: string;
  remediation_explanation?: string;
  reproduction_script?: string;
  flaky?: boolean;
  adaptive_mutation?: {
    framework?: string;
    required_fields?: string[];
    mutated_payload?: string;
    mutated_status?: number;
    penetrated_validation?: boolean;
    mutated_verdict?: string;
  } | null;
}

export interface ThreatFinding {
  owasp_category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  title: string;
  affected_routes: string[];
  remediation: string;
  remediation_patch?: string;
  remediation_explanation?: string;
  reproduction_script?: string;
}

export interface TriagedDefect {
  case_id?: string;
  id?: string;
  owasp_category: string;
  severity: string;
  title: string;
  evidence_snippet: string;
  remediation_patch_suggestion: string;
  affected_endpoints: string[];
  component?: string;
  recommended_fix?: string;
  reproduction?: string;
  remediation_patch?: string;
  remediation_explanation?: string;
  reproduction_script?: string;
}

export interface AgentStep {
  agent: string;
  action: string;
  details: string;
  status: string;
  timestamp: string;
}

/** Pre-pillars[] shape: a run saved before the backend sent `pillars`. Fallback only. */
export interface PillarScore {
  score?: number | null;
  status?: string | null;
  evidence?: string | null;
}

/** One pillar as the backend reports it in `evidence_ledger.pillars[]`. */
export interface LedgerPillar {
  /** value | authority | safety | evidence */
  id: string;
  name: string;
  /** null = not evaluated (no conclusive result), never a default score. */
  score: number | null;
  /** pass | fail | partial | not_evaluated */
  status: string;
  claim: string;
  /** Conclusive (pass + warn + fail) share of the applicable cases, 0..=100; null = nothing applicable. */
  confidence?: number | null;
  techniques?: string[];
  case_ids?: string[];
  evidence_files?: string[];
}

/** Something that kept the run from gathering evidence, and the next step the user can take. */
export interface LedgerBlocker {
  reason: BlockReason | string;
  detail: string;
  next_step: string;
  case_ids?: string[];
}

/** One row of the technique-coverage matrix. */
export interface CoverageCell {
  technique: string;
  planned: number;
  pass: number;
  warn: number;
  fail: number;
  inconclusive: number;
  blocked: number;
  skipped: number;
  /** Cases with no surface for this technique; excluded from every denominator. */
  not_applicable?: number;
  flaky?: number;
  case_ids?: string[];
  evidence_files?: string[];
}

export interface ExitCriterion {
  criterion: string;
  met: boolean;
  details?: string;
}

export interface EvidenceLedger {
  /** The pillars the backend evaluated (or did not): the source of the pillar cards. */
  pillars?: LedgerPillar[];
  /** Overall conclusive share of the applicable cases, 0..=100. */
  confidence?: number | null;
  /** What kept evidence from being gathered, with the next step for each. */
  blockers?: LedgerBlocker[];
  coverage?: CoverageCell[];
  /** False when no pillar could be evaluated: the score is then not a result. */
  evaluated?: boolean;
  verdict_basis?: string;
  /** Legacy per-pillar objects (old runs only). */
  contract?: PillarScore;
  authz?: PillarScore;
  resilience?: PillarScore;
  observability?: PillarScore;
  value_score?: number | null;
  authority_score?: number | null;
  safety_score?: number | null;
  evidence_score?: number | null;
  overall_readiness?: number;
  /** GO | CONDITIONAL_GO | NO_GO | NOT_EVALUATED (| SCANNED for discovery-only runs) */
  gate_verdict?: string;
  composite_score?: number;
  verdict?: string;
  exit_criteria_checklist?: ExitCriterion[];
  approval_status?: string;
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
  model?: string;
  thinking?: boolean;
  model_tier?: ModelTier | string;
  thinking_budget_tokens?: number;
  app_architecture?: string;
  framework?: string;
  detected_tech?: string[];
  steps: AgentStep[];
  discovered_routes: DiscoveredRoute[];
  planned_cases: PlannedCase[];
  executed_results: RawCaseResult[];
  triaged_defects: RawDefect[];
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

/** Raw executed-case row as the backend serialises it (field names vary by version). */
export interface RawCaseResult {
  case_id?: string;
  id?: string;
  title?: string;
  component?: string;
  technique?: string;
  method?: string;
  status?: string;
  latency_ms?: number | null;
  curl?: string;
  curl_reproduction?: string;
  reproduction_curl?: string;
  request_payload?: string | null;
  response_status?: number | null;
  status_code?: number | null;
  response_content_type?: string | null;
  content_type?: string | null;
  response_body?: string | null;
  response_body_snippet?: string | null;
  evidence?: string | null;
  assertion_details?: string | null;
  failure_reason?: string | null;
  blocked_reason?: BlockReason | string | null;
  redirect_chain?: RedirectHop[];
  /** Older backends nest the extra evidence fields under this object. */
  evidence_detail?: {
    adaptive_mutation?: RawCaseResult["adaptive_mutation"];
    stateful_steps?: StatefulStep[];
    stateful_chain?: StatefulStepExecution[];
    concurrency_burst?: number;
    concurrency_burst_results?: number[];
    remediation_patch?: string;
    remediation_explanation?: string;
    reproduction_script?: string;
  } | null;
  stateful_steps?: StatefulStep[];
  stateful_chain?: StatefulStepExecution[];
  concurrency_burst?: number;
  concurrency_burst_results?: number[];
  remediation_patch?: string;
  remediation_explanation?: string;
  reproduction_script?: string;
  adaptive_mutation?: {
    framework?: string;
    required_fields?: string[];
    mutated_payload?: string;
    mutated_status?: number;
    penetrated_validation?: boolean;
    mutated_verdict?: string;
  } | null;
}

/** Raw triaged defect (older and newer backend field names are both accepted). */
export interface RawDefect {
  id?: string;
  case_id?: string;
  title?: string;
  severity?: string;
  owasp_category?: string;
  component?: string;
  affected_endpoints?: string[];
  remediation_patch_suggestion?: string;
  recommended_fix?: string;
  evidence_snippet?: string;
  reproduction?: string;
  remediation_patch?: string;
  remediation_explanation?: string;
  reproduction_script?: string;
}

/**
 * Loose run record: a run summary (list endpoint), a full report, or a
 * launch response. Every field is optional because the shape differs.
 */
export interface AgentRunRecord {
  id?: string;
  run_id?: string;
  target?: string;
  profile?: string;
  provider?: string;
  model?: string;
  status?: string;
  error?: string | null;
  started_at?: string;
  is_spa?: boolean;
  app_architecture?: string;
  framework?: string;
  detected_tech?: string[];
  steps?: AgentStep[];
  discovered_routes?: DiscoveredRoute[];
  planned_cases?: PlannedCase[];
  executed_results?: RawCaseResult[];
  test_cases?: TestCaseResult[];
  triaged_defects?: RawDefect[];
  threats?: ThreatFinding[];
  evidence_ledger?: EvidenceLedger | null;
  approval_status?: string | null;
  approved_by?: string | null;
  approval_notes?: string | null;
  readiness_score?: number | null;
  gate_verdict?: string | null;
  verdict?: string | null;
  defects_count?: number;
  cases_count?: number;
  requester_ip?: string | null;
  requester_ip_type?: string | null;
  allowlist_guidance?: string | null;
}
