import type { DeepAuditReport } from "@/types/network";

/**
 * Deep-audit results are cached per target. An entry always carries the target it was measured for
 * and when, so one target's audit is never shown, or posted to a PR comment, for another target.
 */

export interface DeepAuditEntry {
  /** Normalised target the audit was run against (see deepAuditKey). */
  key: string;
  /** Epoch milliseconds when the audit finished. */
  ts: number;
  report: DeepAuditReport;
}

const STORAGE_PREFIX = "readyhai_deep_audit_v2:";

/** A cached audit older than this is not restored from storage at all. */
export const DEEP_AUDIT_CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
/** A PR comment is only generated from an audit at most this old. */
export const DEEP_AUDIT_FRESH_MS = 30 * 60 * 1000;

/** Cache key for a target: trimmed, without trailing slashes. */
export function deepAuditKey(target: string): string {
  return target.trim().replace(/\/+$/, "");
}

export function isDeepAuditFresh(entry: DeepAuditEntry | null | undefined, now = Date.now()): boolean {
  return !!entry && now - entry.ts <= DEEP_AUDIT_FRESH_MS && entry.ts <= now + 60_000;
}

export function readDeepAuditCache(key: string, now = Date.now()): DeepAuditEntry | null {
  if (!key) return null;
  try {
    const raw = window.localStorage.getItem(STORAGE_PREFIX + key);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const e = parsed as Partial<DeepAuditEntry>;
    // The stored key must match: a copied or tampered entry for another target is ignored.
    if (e.key !== key) return null;
    if (typeof e.ts !== "number" || !Number.isFinite(e.ts)) return null;
    if (now - e.ts > DEEP_AUDIT_CACHE_MAX_AGE_MS || e.ts > now + 60_000) return null;
    if (!e.report || typeof e.report !== "object") return null;
    return { key, ts: e.ts, report: e.report };
  } catch {
    return null; // storage blocked or corrupt JSON
  }
}

export function writeDeepAuditCache(entry: DeepAuditEntry): void {
  try {
    window.localStorage.setItem(STORAGE_PREFIX + entry.key, JSON.stringify(entry));
  } catch {
    // storage unavailable: the report is still shown, just not cached
  }
}
