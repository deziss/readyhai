import type {
  AgentRunRecord,
  EvidenceLedger,
  PlannedCase,
  RawCaseResult,
  RawDefect,
  TestCaseResult,
  ThreatFinding,
} from "@/types/agent";

/**
 * Helpers that turn backend run data into UI data WITHOUT inventing values.
 * Anything the backend did not report stays null/undefined so the UI can
 * render "not evaluated" instead of a made-up score or a green verdict.
 */

export const GATE_VERDICTS = ["GO", "CONDITIONAL_GO", "NO_GO"] as const;
export type GateVerdict = (typeof GATE_VERDICTS)[number];

export function isGateVerdict(v: string | null | undefined): v is GateVerdict {
  return !!v && (GATE_VERDICTS as readonly string[]).includes(v);
}

export function normalizeVerdict(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const t = v.trim().toUpperCase();
  return t ? t : null;
}

export function numOrNull(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export function strOrNull(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v : null;
}

export function ledgerVerdict(el?: EvidenceLedger | null): string | null {
  return normalizeVerdict(el?.gate_verdict) ?? normalizeVerdict(el?.verdict);
}

export function ledgerScore(el?: EvidenceLedger | null): number | null {
  return numOrNull(el?.overall_readiness) ?? numOrNull(el?.composite_score);
}

export interface PillarView {
  key: "contract" | "authz" | "resilience" | "observability";
  title: string;
  short: string;
  score: number | null;
  status: string | null;
  evidence: string | null;
}

/** The four pillars as reported by the backend; any missing piece is null. */
export function getPillars(el?: EvidenceLedger | null): PillarView[] {
  const p = (
    key: PillarView["key"],
    title: string,
    short: string,
    nested: EvidenceLedger["contract"],
    legacy: number | undefined
  ): PillarView => ({
    key,
    title,
    short,
    score: numOrNull(nested?.score) ?? numOrNull(legacy),
    status: strOrNull(nested?.status),
    evidence: strOrNull(nested?.evidence),
  });
  return [
    p("contract", "1. API Contract & Schema Compliance", "Contract Fidelity", el?.contract, el?.value_score),
    p("authz", "2. Authorization & Tenant Isolation", "AuthZ Boundary", el?.authz, el?.authority_score),
    p("resilience", "3. Input Fuzzing & Boundary Resilience", "Failure Resilience", el?.resilience, el?.safety_score),
    p("observability", "4. Observability & Leak Detection", "Observability", el?.observability, el?.evidence_score),
  ];
}

/**
 * Evidence ledger for a run, built only from fields the backend returned.
 * Returns null when the run carries no ledger, score or verdict at all.
 */
export function buildLedger(run: AgentRunRecord): EvidenceLedger | null {
  const el = run.evidence_ledger ?? null;
  const score = ledgerScore(el) ?? numOrNull(run.readiness_score);
  const verdict = ledgerVerdict(el) ?? normalizeVerdict(run.gate_verdict) ?? normalizeVerdict(run.verdict);
  if (!el && score === null && !verdict) return null;

  const approval = strOrNull(run.approval_status) ?? strOrNull(el?.approval_status);
  return {
    ...(el ?? {}),
    overall_readiness: score ?? undefined,
    composite_score: score ?? undefined,
    gate_verdict: verdict ?? undefined,
    verdict: verdict ?? undefined,
    approval_status: approval ? approval.toUpperCase() : undefined,
    approved_by: strOrNull(run.approved_by) ?? el?.approved_by,
    approval_notes: strOrNull(run.approval_notes) ?? el?.approval_notes,
  };
}

// ---------------------------------------------------------------------------
// Cases / defects
// ---------------------------------------------------------------------------

const CASE_STATUSES = ["PASS", "FAIL", "WARN", "BLOCKED", "SKIPPED", "PLANNED", "PENDING"] as const;

export function normalizeCaseStatus(raw: unknown): TestCaseResult["status"] {
  const s = typeof raw === "string" ? raw.trim().toUpperCase() : "";
  // Unknown / missing status is NOT a pass: show it as skipped (not evaluated).
  return (CASE_STATUSES as readonly string[]).includes(s) ? (s as TestCaseResult["status"]) : "SKIPPED";
}

export function normalizeExecutedCase(c: RawCaseResult): TestCaseResult {
  const status = normalizeCaseStatus(c.status);
  const detail = strOrNull(c.assertion_details) ?? strOrNull(c.failure_reason);
  return {
    id: c.case_id || c.id || "unknown",
    title: c.title || "(untitled case)",
    component: c.component || "",
    technique: c.technique || "",
    method: c.method || "GET",
    status,
    latency_ms: numOrNull(c.latency_ms),
    curl: c.curl_reproduction || c.reproduction_curl || c.curl || "",
    request_payload: c.request_payload ?? null,
    response_status: numOrNull(c.response_status) ?? numOrNull(c.status_code),
    response_content_type: c.response_content_type ?? c.content_type ?? null,
    response_body: c.response_body_snippet ?? c.response_body ?? c.evidence ?? null,
    assertion_details: detail,
    adaptive_mutation: c.adaptive_mutation ?? c.evidence_detail?.adaptive_mutation ?? null,
    stateful_steps: c.stateful_steps ?? c.evidence_detail?.stateful_steps ?? null,
    stateful_chain: c.stateful_chain ?? c.evidence_detail?.stateful_chain ?? null,
    concurrency_burst: c.concurrency_burst ?? c.evidence_detail?.concurrency_burst,
    concurrency_burst_results: c.concurrency_burst_results ?? c.evidence_detail?.concurrency_burst_results,
    remediation_patch: c.remediation_patch ?? c.evidence_detail?.remediation_patch,
    remediation_explanation: c.remediation_explanation ?? c.evidence_detail?.remediation_explanation,
    reproduction_script: c.reproduction_script ?? c.evidence_detail?.reproduction_script,
  };
}

export function normalizePlannedCase(c: PlannedCase, target: string): TestCaseResult {
  return {
    id: c.id,
    title: c.title,
    component: c.component,
    technique: c.technique,
    method: c.method,
    status: "PLANNED",
    latency_ms: null,
    curl: `curl -X ${c.method} "${target}${c.component}"`,
    request_payload: c.payload,
    response_status: null,
    assertion_details: c.expected_behavior,
    stateful_steps: c.stateful_steps,
    concurrency_burst: c.concurrency_burst,
  };
}

export function runCases(run: AgentRunRecord): TestCaseResult[] {
  if (run.executed_results && run.executed_results.length > 0) {
    return run.executed_results.map(normalizeExecutedCase);
  }
  if (run.planned_cases && run.planned_cases.length > 0) {
    return run.planned_cases.map((c) => normalizePlannedCase(c, run.target ?? ""));
  }
  if (run.test_cases && run.test_cases.length > 0) return run.test_cases;
  return [];
}

export function runThreats(run: AgentRunRecord): ThreatFinding[] {
  if (run.triaged_defects && run.triaged_defects.length > 0) {
    return run.triaged_defects.map((d: RawDefect) => ({
      owasp_category: d.owasp_category || "unclassified",
      severity: (d.severity || "unknown") as ThreatFinding["severity"],
      title: d.title || "(untitled defect)",
      affected_routes: d.affected_endpoints ?? (d.component ? [d.component] : []),
      remediation: d.remediation_patch_suggestion ?? d.recommended_fix ?? "",
      remediation_patch: d.remediation_patch ?? d.remediation_patch_suggestion ?? d.recommended_fix,
      remediation_explanation: d.remediation_explanation,
      reproduction_script: d.reproduction_script ?? d.reproduction,
    }));
  }
  return run.threats ?? [];
}

/** Defect count for display, or null when the run does not say. */
export function runDefectCount(run: AgentRunRecord): number | null {
  if (run.triaged_defects) return run.triaged_defects.length;
  return numOrNull(run.defects_count);
}

export function runId(run: AgentRunRecord): string | null {
  return run.id || run.run_id || null;
}

/**
 * Apply a retest response (a backend case-execution result) onto an existing case.
 * A response without a recognisable status becomes SKIPPED, never PASS.
 */
export function mergeRetestResult(base: TestCaseResult, raw: RawCaseResult): TestCaseResult {
  const u = normalizeExecutedCase({ ...raw, case_id: base.id });
  return {
    ...base,
    status: u.status,
    latency_ms: u.latency_ms,
    curl: u.curl || base.curl,
    response_status: u.response_status ?? base.response_status ?? null,
    response_content_type: u.response_content_type ?? base.response_content_type ?? null,
    response_body: u.response_body ?? base.response_body ?? null,
    assertion_details: u.assertion_details ?? base.assertion_details ?? null,
    adaptive_mutation: u.adaptive_mutation ?? base.adaptive_mutation ?? null,
    stateful_steps: u.stateful_steps ?? base.stateful_steps,
    stateful_chain: u.stateful_chain ?? base.stateful_chain,
    concurrency_burst: u.concurrency_burst ?? base.concurrency_burst,
    concurrency_burst_results: u.concurrency_burst_results ?? base.concurrency_burst_results,
    remediation_patch: u.remediation_patch ?? base.remediation_patch,
    remediation_explanation: u.remediation_explanation ?? base.remediation_explanation,
    reproduction_script: u.reproduction_script ?? base.reproduction_script,
    retested: true,
  };
}
