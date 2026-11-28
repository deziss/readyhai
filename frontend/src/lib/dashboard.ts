import {
  confirmedSignOffStatus,
  ledgerBlockers,
  ledgerConfidence,
  ledgerScore,
  ledgerVerdict,
  runDefectCount,
  runLifecycle,
  type BlockerView,
} from "./runs";
import type { AgentRunRecord } from "@/types/agent";
import type { ScanSummary } from "@/types/scans";
import type { VulnEntry } from "@/components/VulnsView";

/**
 * Derives dashboard state from whatever the backend actually reported.
 *
 * The rule this file exists to enforce: an absent measurement is reported as absent. Nothing here
 * substitutes a default score, a zero count, or an "OK" for data the backend did not send, because
 * a readiness dashboard that guesses green is worse than one that admits it looked at nothing.
 */

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

/** Parses an ISO timestamp; null when absent or unparseable, never Date.now(). */
export function parseTime(raw: unknown, now = Date.now()): number | null {
  if (typeof raw !== "string" || !raw.trim()) return null;
  const t = Date.parse(raw);
  return Number.isFinite(t) && t <= now + 60_000 ? t : null;
}

/** Host of a target URL, or the raw string when it is not a URL (a repo path, an image ref). */
export function targetLabel(target: string | null | undefined): string {
  const raw = (target ?? "").trim();
  if (!raw) return "unknown target";
  try {
    const u = new URL(raw);
    return u.host + (u.pathname === "/" ? "" : u.pathname.replace(/\/+$/, ""));
  } catch {
    return raw.length > 60 ? `${raw.slice(0, 57)}…` : raw;
  }
}

/** Groups records by normalised target so a target's runs and scans land on one row. */
export function targetKey(target: string | null | undefined): string {
  return (target ?? "").trim().replace(/\/+$/, "").toLowerCase();
}

// ---------------------------------------------------------------------------
// Per-target rollup
// ---------------------------------------------------------------------------

export interface TargetRow {
  key: string;
  label: string;
  /** Raw target string as the backend stored it. */
  target: string;
  /** Latest agent run for this target, running or not. */
  run: AgentRunRecord | null;
  runTs: number | null;
  /**
   * Latest run that has finished. The release gate reads this, because a pass still executing has
   * no verdict: showing "no verdict" while an older GO exists would be wrong.
   */
  finishedRun: AgentRunRecord | null;
  finishedRunTs: number | null;
  verdict: string | null;
  score: number | null;
  /** Count the backend reported, or null when it reported none. */
  defects: number | null;
  approval: string | null;
  /** Latest scan for this target. */
  scan: ScanSummary | null;
  scanTs: number | null;
  scanVerdict: string | null;
  /** Open vuln rows for this target. */
  openVulns: number;
  /** Open rows whose exploitation state is "verified": a measurement, not a guess. */
  verifiedOpen: number;
  /** Open rows that were never exploited: a rule match awaiting verification. */
  unverifiedOpen: number;
  /** Newest signal across runs and scans, for ordering. */
  lastSeen: number | null;
  /** True when the newest run is still executing. */
  active: boolean;
}

export interface DashboardInput {
  runs: AgentRunRecord[];
  scans: ScanSummary[];
  vulns: VulnEntry[];
  now?: number;
}

/**
 * The list endpoints answer with either a bare array or an envelope, and the shape is not stated in
 * the shared type, so every consumer unwraps defensively. Getting this wrong silently drops the
 * data: a bare-array check against `{"runs":[...]}` yields an empty dashboard with HTTP 200.
 */
export function asList<T>(
  data: unknown,
  envelopeKey: string
): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const inner = (data as Record<string, unknown>)[envelopeKey];
    if (Array.isArray(inner)) return inner as T[];
  }
  return [];
}

/** Newest-first sort by parsed timestamp; records with no usable timestamp sink to the bottom. */
function byTs<T>(items: T[], ts: (item: T) => number | null): T[] {
  return [...items].sort((a, b) => (ts(b) ?? -Infinity) - (ts(a) ?? -Infinity));
}

export function targetsFrom(input: DashboardInput): TargetRow[] {
  const now = input.now ?? Date.now();
  const keys = new Set<string>();
  for (const r of input.runs) keys.add(targetKey(r.target));
  for (const s of input.scans) keys.add(targetKey(s.target));
  for (const v of input.vulns) keys.add(targetKey(v.target || v.target_key));
  keys.delete("");

  const rows: TargetRow[] = [];
  for (const key of keys) {
    const runs = byTs(
      input.runs.filter((r) => targetKey(r.target) === key),
      (r) => parseTime(r.started_at, now)
    );
    const scans = byTs(input.scans.filter((s) => targetKey(s.target) === key), (s) =>
      parseTime(s.finished ?? s.started, now)
    );
    const vulns = input.vulns.filter((v) => targetKey(v.target || v.target_key) === key);
    const open = vulns.filter((v) => String(v.status).toLowerCase() === "open");

    const run = runs[0] ?? null;
    const finished = runs.find((r) => runLifecycle(r) !== "running") ?? null;
    const scan = scans[0] ?? null;
    const runTs = run ? parseTime(run.started_at, now) : null;
    const scanTs = scan ? parseTime(scan.finished ?? scan.started, now) : null;

    rows.push({
      key,
      label: targetLabel(run?.target ?? scan?.target ?? vulns[0]?.target ?? null),
      target: run?.target ?? scan?.target ?? vulns[0]?.target ?? "",
      run,
      runTs,
      finishedRun: finished,
      finishedRunTs: finished ? parseTime(finished.started_at, now) : null,
      // Prefer the ledger, then the flat field the run list carries for rows without a ledger.
      verdict:
        ledgerVerdict(finished?.evidence_ledger) ?? normalizeGate(finished?.gate_verdict),
      score: ledgerScore(finished?.evidence_ledger),
      defects: finished ? runDefectCount(finished) : null,
      approval: finished ? confirmedSignOffStatus(finished.approval_status) : null,
      scan,
      scanTs,
      scanVerdict: scan ? normalizeScanVerdict(scan.verdict) : null,
      openVulns: open.length,
      verifiedOpen: open.filter((v) => String(v.verification).toLowerCase() === "verified").length,
      unverifiedOpen: open.filter((v) => String(v.verification).toLowerCase() !== "verified").length,
      lastSeen: lastOf([runTs, scanTs]),
      active: run ? runLifecycle(run) === "running" : false,
    });
  }

  return rows.sort((a, b) => (b.lastSeen ?? -Infinity) - (a.lastSeen ?? -Infinity));
}

/** Newest of a set of timestamps, or null when none of them is known. */
function lastOf(times: (number | null)[]): number | null {
  const known = times.filter((t): t is number => t !== null);
  return known.length ? Math.max(...known) : null;
}

// ---------------------------------------------------------------------------
// Verdict / status normalisation
// ---------------------------------------------------------------------------

export type GateLight = "go" | "conditional" | "no_go" | "unknown";

export function normalizeGate(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const v = raw.trim().toUpperCase();
  if (!v) return null;
  if (v === "GO" || v === "CONDITIONAL_GO" || v === "NO_GO" || v === "NOT_EVALUATED" || v === "SCANNED") {
    return v;
  }
  return null;
}

export function normalizeScanVerdict(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const v = raw.trim().toUpperCase();
  return v === "PASS" || v === "WARN" || v === "FAIL" ? v : null;
}

/**
 * Traffic light for one target. A GO that nobody has signed off is deliberately not "ready": the
 * product's own rule is that a run needs a sign-off to be a release decision.
 */
export function gateLight(row: TargetRow): GateLight {
  if (row.verdict === "GO") return "go";
  if (row.verdict === "CONDITIONAL_GO") return "conditional";
  if (row.verdict === "NO_GO") return "no_go";
  return "unknown";
}

// ---------------------------------------------------------------------------
// Headline numbers
// ---------------------------------------------------------------------------

export interface GateSummary {
  /** The target whose most recent finished run is newest: what the next release looks like. */
  latest: TargetRow | null;
  /** Targets with at least one run, so the dashboard can say how much is covered at all. */
  targetsWithRuns: number;
  targetsTotal: number;
  activeRuns: number;
  /** Runs still awaiting a decision, newest first. */
  awaitingSignOff: TargetRow[];
  /** Open findings split by whether exploitation was actually demonstrated. */
  verifiedOpen: number;
  unverifiedOpen: number;
  /** Scan FAILs whose newest run has no defect list: measured, not counted as zero. */
  failingScans: number;
  /** True when no run has ever been recorded, which is a different message from "all clear". */
  nothingMeasured: boolean;
}

export function gateSummary(rows: TargetRow[]): GateSummary {
  const withRuns = rows.filter((r) => r.run);
  const finished = rows
    .filter((r) => r.finishedRun)
    .sort((a, b) => (b.finishedRunTs ?? -Infinity) - (a.finishedRunTs ?? -Infinity));
  const latest = finished[0] ?? null;
  return {
    latest,
    targetsWithRuns: withRuns.length,
    targetsTotal: rows.length,
    activeRuns: rows.filter((r) => r.active).length,
    awaitingSignOff: finished
      .filter((r) => (r.verdict === "GO" || r.verdict === "CONDITIONAL_GO") && !r.approval)
      .slice(0, 6),
    verifiedOpen: rows.reduce((sum, r) => sum + r.verifiedOpen, 0),
    unverifiedOpen: rows.reduce((sum, r) => sum + r.unverifiedOpen, 0),
    failingScans: rows.filter((r) => r.scanVerdict === "FAIL").length,
    nothingMeasured: withRuns.length === 0,
  };
}

/**
 * What the newest run proved, as counts, from the ledger's own pillars. An unevaluated pillar is
 * reported as unevaluated; its score is never read as 0.
 */
export interface LedgerSummary {
  evaluated: boolean;
  confidence: number | null;
  pillars: { id: string; name: string; score: number | null; status: string; claim: string }[];
  blockers: BlockerView[];
  basis: string | null;
}

export function ledgerSummary(run: AgentRunRecord | null): LedgerSummary | null {
  const ledger = run?.evidence_ledger;
  if (!ledger) return null;
  const pillars = (ledger.pillars ?? []).map((p) => ({
    id: p.id,
    name: p.name,
    score: typeof p.score === "number" && Number.isFinite(p.score) ? p.score : null,
    status: String(p.status ?? "not_evaluated"),
    claim: p.claim ?? "",
  }));
  return {
    evaluated: ledger.evaluated !== false && pillars.length > 0,
    confidence: ledgerConfidence(ledger),
    pillars,
    blockers: ledgerBlockers(ledger),
    basis: ledger.verdict_basis ?? ledger.executive_summary ?? null,
  };
}

/** Ids used to cache and invalidate per-subject, so a write clears exactly what changed. */
export const CACHE_KEYS = {
  runs: "/api/agent/runs",
  scans: "/api/scans",
  vulns: "/api/vulns",
  status: "/api/agent/status",
} as const;
