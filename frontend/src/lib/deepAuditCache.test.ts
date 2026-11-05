import { beforeEach, describe, expect, it } from "vitest";
import type { DeepAuditReport } from "@/types/network";
import {
  DEEP_AUDIT_CACHE_MAX_AGE_MS,
  DEEP_AUDIT_FRESH_MS,
  deepAuditKey,
  isDeepAuditFresh,
  readDeepAuditCache,
  writeDeepAuditCache,
} from "./deepAuditCache";

const report = { overall_verdict: "PASS", health_score: 95 } as unknown as DeepAuditReport;

beforeEach(() => window.localStorage.clear());

describe("deep audit cache", () => {
  it("normalises the key", () => {
    expect(deepAuditKey("  https://a.test/// ")).toBe("https://a.test");
  });

  it("is keyed by target: another target's audit is never returned", () => {
    writeDeepAuditCache({ key: "https://a.test", ts: Date.now(), report });
    expect(readDeepAuditCache("https://a.test")?.report).toEqual(report);
    expect(readDeepAuditCache("https://b.test")).toBeNull();
  });

  it("ignores an entry whose stored key does not match the slot it was read from", () => {
    const entry = { key: "https://a.test", ts: Date.now(), report };
    window.localStorage.setItem("readyhai_deep_audit_v2:https://b.test", JSON.stringify(entry));
    expect(readDeepAuditCache("https://b.test")).toBeNull();
  });

  it("ignores legacy (timestamp-less) and expired entries", () => {
    window.localStorage.setItem("readyhai_deep_audit_v2:https://a.test", JSON.stringify(report));
    expect(readDeepAuditCache("https://a.test")).toBeNull();
    const old = Date.now() - DEEP_AUDIT_CACHE_MAX_AGE_MS - 1000;
    writeDeepAuditCache({ key: "https://c.test", ts: old, report });
    expect(readDeepAuditCache("https://c.test")).toBeNull();
  });

  it("freshness is bounded by DEEP_AUDIT_FRESH_MS", () => {
    const now = Date.now();
    expect(isDeepAuditFresh({ key: "k", ts: now - 1000, report }, now)).toBe(true);
    expect(isDeepAuditFresh({ key: "k", ts: now - DEEP_AUDIT_FRESH_MS - 1, report }, now)).toBe(false);
    expect(isDeepAuditFresh(null, now)).toBe(false);
  });
});
