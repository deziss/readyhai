import type {
  AgentRunRecord,
  EvidenceLedger,
  LedgerBlocker,
  LedgerPillar,
  PlannedCase,
  RawCaseResult,
  RawDefect,
  RedirectHop,
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

/** Only a GO or CONDITIONAL_GO gate verdict may be approved for deployment; NO_GO can only be blocked. */
export function canApproveVerdict(v: string | null | undefined): boolean {
  return v === "GO" || v === "CONDITIONAL_GO";
}

export type SignOffStatus = "approved" | "rejected";

/**
 * The sign-off state the backend confirmed in its approve/reject response, or null when it echoed
 * nothing usable. Callers must not substitute the action the operator clicked.
 */
export function confirmedSignOffStatus(v: unknown): SignOffStatus | null {
  if (typeof v !== "string") return null;
  const t = v.trim().toLowerCase();
  return t === "approved" || t === "rejected" ? t : null;
}

// ---------------------------------------------------------------------------
// Run lifecycle (running -> completed | failed | cancelled)
// ---------------------------------------------------------------------------

export type RunLifecycle = "running" | "completed" | "failed" | "cancelled";

/**
 * The lifecycle state the backend reported, or null when it reported none (a legacy report) or
 * something unknown. Callers must not turn "unknown" into "completed" on their own.
 */
export function normalizeRunStatus(raw: unknown): RunLifecycle | null {
  if (typeof raw !== "string") return null;
  const s = raw.trim().toLowerCase();
  if (s === "running" || s === "queued") return "running";
  if (s === "completed" || s === "done") return "completed";
  if (s === "failed" || s === "error") return "failed";
  if (s === "cancelled" || s === "canceled") return "cancelled";
  return null;
}

export function runLifecycle(run: Pick<AgentRunRecord, "status">): RunLifecycle | null {
  return normalizeRunStatus(run.status);
}

/** True while the backend is still executing the run: it can be cancelled, not signed off. */
export function isRunActive(run: Pick<AgentRunRecord, "status">): boolean {
  return runLifecycle(run) === "running";
}

/**
 * A finished run that ended early (cancelled or failed) carries partial results at best: its
 * verdict must not be presented as a normal gate decision.
 */
export function runEndedEarly(run: Pick<AgentRunRecord, "status">): boolean {
  const l = runLifecycle(run);
  return l === "cancelled" || l === "failed";
}

export const RUN_STATUS_LABEL: Record<RunLifecycle, string> = {
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

/** Why a run cannot be signed off right now, or null when it can (the backend enforces it too). */
export function signOffBlockedReason(run: Pick<AgentRunRecord, "status">, action: "approve" | "reject"): string | null {
  const l = runLifecycle(run);
  if (l === "running") return "The run is still running. Sign-off is possible once it finishes (or is cancelled, which allows rejecting it).";
  if (action === "approve" && l === "cancelled") return "A cancelled run only has partial results and cannot be approved for deployment. It can be rejected.";
  if (action === "approve" && l === "failed") return "A failed run cannot be approved for deployment. It can be rejected.";
  return null;
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

/** The backend could not reach a verdict: too little conclusive evidence. Not a failure, not a pass. */
export const NOT_EVALUATED = "NOT_EVALUATED";

export function isNotEvaluatedVerdict(v: string | null | undefined): boolean {
  return v === NOT_EVALUATED;
}

/**
 * The overall score, or null when the backend did not evaluate the run. A not-evaluated ledger
 * reports 0 as a placeholder: that is not a result and must never be shown as "0%".
 */
export function ledgerScore(el?: EvidenceLedger | null): number | null {
  if (isNotEvaluatedVerdict(normalizeVerdict(el?.gate_verdict)) || el?.evaluated === false) return null;
  return numOrNull(el?.overall_readiness) ?? numOrNull(el?.composite_score);
}

/** Overall confidence (0..=100) the backend reported: the conclusive share of applicable cases. */
export function ledgerConfidence(el?: EvidenceLedger | null): number | null {
  const c = numOrNull(el?.confidence);
  return c === null ? null : Math.max(0, Math.min(100, Math.round(c)));
}

export interface PillarView {
  /** Backend pillar id (value | authority | safety | evidence). */
  key: string;
  /** The backend's own name for the pillar. */
  title: string;
  score: number | null;
  /** pass | fail | partial | not_evaluated, as reported (lower case). */
  status: string | null;
  /** The backend's claim: what the evidence says. */
  evidence: string | null;
  /** Conclusive share of the applicable cases, 0..=100; null when not reported. */
  confidence: number | null;
  /** No score or an explicit not_evaluated status: show "Not evaluated: insufficient evidence". */
  notEvaluated: boolean;
  caseCount: number;
}

function clampPct(v: unknown): number | null {
  const n = numOrNull(v);
  return n === null ? null : Math.max(0, Math.min(100, Math.round(n)));
}

function pillarView(p: LedgerPillar): PillarView {
  const score = numOrNull(p.score);
  const status = strOrNull(p.status)?.trim().toLowerCase() ?? null;
  return {
    key: p.id,
    title: strOrNull(p.name) ?? p.id,
    score,
    status,
    evidence: strOrNull(p.claim),
    confidence: clampPct(p.confidence),
    notEvaluated: score === null || status === "not_evaluated",
    caseCount: Array.isArray(p.case_ids) ? p.case_ids.length : 0,
  };
}

/**
 * Backend pillar names and ids, with the pre-pillars[] ledger fields each one was once read from.
 * Used only for a run saved before the backend sent `pillars`; the names are the backend's.
 */
const LEGACY_PILLARS = [
  { id: "value", name: "Functional correctness and input handling", nested: "contract", score: "value_score" },
  { id: "authority", name: "Authorization and least privilege", nested: "authz", score: "authority_score" },
  { id: "safety", name: "Injection resistance and data safety", nested: "resilience", score: "safety_score" },
  { id: "evidence", name: "Reproducible evidence", nested: "observability", score: "evidence_score" },
] as const;

/**
 * The pillars as the backend reported them (`evidence_ledger.pillars[]`: name, score, status, claim,
 * confidence). Only an old run without `pillars` falls back to the legacy fields; whatever is missing
 * stays null so the UI says "not evaluated" instead of inventing a score or a label.
 */
export function getPillars(el?: EvidenceLedger | null): PillarView[] {
  if (Array.isArray(el?.pillars) && el.pillars.length > 0) {
    return el.pillars.filter((p): p is LedgerPillar => !!p && typeof p.id === "string").map(pillarView);
  }
  return LEGACY_PILLARS.map((l) =>
    pillarView({
      id: l.id,
      name: l.name,
      score: numOrNull(el?.[l.nested]?.score) ?? numOrNull(el?.[l.score]),
      status: el?.[l.nested]?.status ?? "",
      claim: el?.[l.nested]?.evidence ?? "",
    })
  );
}

// ---------------------------------------------------------------------------
// Blockers: what kept the run from gathering evidence, and what to provide next
// ---------------------------------------------------------------------------

const BLOCK_REASON_LABEL: Record<string, string> = {
  auth_wall: "Auth wall",
  out_of_scope: "Out of scope",
  no_surface: "No input surface",
  transport: "No HTTP answer",
};

/** Human label for a backend block reason, or null when the case carries none. */
export function blockReasonLabel(reason: unknown): string | null {
  const r = strOrNull(reason)?.trim().toLowerCase();
  if (!r) return null;
  return BLOCK_REASON_LABEL[r] ?? r.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}

export interface BlockerView {
  reason: string;
  label: string;
  detail: string;
  nextStep: string;
  caseCount: number;
}

/** The ledger's blockers, ready to render. Entries with neither a detail nor a next step are dropped. */
export function ledgerBlockers(el?: EvidenceLedger | null): BlockerView[] {
  if (!Array.isArray(el?.blockers)) return [];
  const out: BlockerView[] = [];
  for (const b of el.blockers as LedgerBlocker[]) {
    if (!b || typeof b !== "object") continue;
    const detail = strOrNull(b.detail);
    const nextStep = strOrNull(b.next_step);
    if (!detail && !nextStep) continue;
    const reason = strOrNull(b.reason) ?? "unknown";
    out.push({
      reason,
      label: blockReasonLabel(reason) ?? "Blocked",
      detail: detail ?? "",
      nextStep: nextStep ?? "",
      caseCount: Array.isArray(b.case_ids) ? b.case_ids.length : 0,
    });
  }
  return out;
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

const CASE_STATUSES = [
  "PASS",
  "FAIL",
  "WARN",
  "BLOCKED",
  "SKIPPED",
  "PLANNED",
  "PENDING",
  "INCONCLUSIVE",
  "NOT_APPLICABLE",
] as const;

export function normalizeCaseStatus(raw: unknown): TestCaseResult["status"] {
  const s = typeof raw === "string" ? raw.trim().toUpperCase() : "";
  // Unknown / missing status is NOT a pass: show it as skipped (not evaluated).
  return (CASE_STATUSES as readonly string[]).includes(s) ? (s as TestCaseResult["status"]) : "SKIPPED";
}

/** The followed redirects the backend reported, malformed hops dropped. */
export function normalizeRedirects(raw: unknown): RedirectHop[] {
  if (!Array.isArray(raw)) return [];
  const hops: RedirectHop[] = [];
  for (const h of raw) {
    const status = numOrNull((h as RedirectHop | null)?.status);
    const location = strOrNull((h as RedirectHop | null)?.location);
    if (status !== null && location) hops.push({ status, location });
  }
  return hops;
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
    blocked_reason: strOrNull(c.blocked_reason),
    redirect_chain: normalizeRedirects(c.redirect_chain),
    latency_ms: numOrNull(c.latency_ms),
    curl: c.curl_reproduction || c.reproduction_curl || c.curl || "",
    request_payload: c.request_payload ?? null,
    response_status: numOrNull(c.response_status) ?? numOrNull(c.status_code),
    response_content_type: c.response_content_type ?? c.content_type ?? null,
    response_body: c.response_body_snippet ?? c.response_body ?? c.evidence ?? null,
    assertion_details: detail,
    adaptive_mutation: c.adaptive_mutation ?? c.evidence_detail?.adaptive_mutation ?? null,
    stateful_steps: c.stateful_steps ?? c.evidence_detail?.stateful_steps,
    stateful_chain: c.stateful_chain ?? c.evidence_detail?.stateful_chain,
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
    blocked_reason: u.blocked_reason ?? null,
    redirect_chain: u.redirect_chain,
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
