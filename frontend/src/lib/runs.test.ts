import { describe, expect, it } from "vitest";
import type { AgentRunRecord } from "@/types/agent";
import {
  buildLedger,
  getPillars,
  isGateVerdict,
  ledgerScore,
  ledgerVerdict,
  normalizeCaseStatus,
  normalizeVerdict,
  numOrNull,
} from "./runs";

describe("verdict normalizers", () => {
  it("normalizes strings and rejects non-strings", () => {
    expect(normalizeVerdict(" go ")).toBe("GO");
    expect(normalizeVerdict("")).toBeNull();
    expect(normalizeVerdict(5)).toBeNull();
    expect(normalizeVerdict(undefined)).toBeNull();
  });

  it("isGateVerdict only accepts the three gate verdicts", () => {
    expect(isGateVerdict("GO")).toBe(true);
    expect(isGateVerdict("SCANNED")).toBe(false);
    expect(isGateVerdict(null)).toBe(false);
  });

  it("numOrNull rejects NaN, Infinity and strings", () => {
    expect(numOrNull(0)).toBe(0);
    expect(numOrNull(NaN)).toBeNull();
    expect(numOrNull(Infinity)).toBeNull();
    expect(numOrNull("5")).toBeNull();
  });
});

describe("no fabricated results", () => {
  it("empty ledger has no score and no verdict", () => {
    expect(ledgerScore(null)).toBeNull();
    expect(ledgerScore({})).toBeNull();
    expect(ledgerVerdict(undefined)).toBeNull();
    expect(ledgerVerdict({})).toBeNull();
  });

  it("buildLedger returns null for a run with nothing reported", () => {
    expect(buildLedger({} as AgentRunRecord)).toBeNull();
  });

  it("buildLedger does not invent a verdict or score from a bare ledger", () => {
    const l = buildLedger({ evidence_ledger: {} } as AgentRunRecord);
    expect(l).not.toBeNull();
    expect(l?.gate_verdict).toBeUndefined();
    expect(l?.overall_readiness).toBeUndefined();
  });

  it("buildLedger keeps a reported verdict", () => {
    const l = buildLedger({ gate_verdict: "no_go" } as AgentRunRecord);
    expect(l?.gate_verdict).toBe("NO_GO");
  });

  it("getPillars leaves unreported pillars null", () => {
    for (const p of getPillars(null)) {
      expect(p.score).toBeNull();
      expect(p.status).toBeNull();
      expect(p.evidence).toBeNull();
    }
  });

  it("unknown or missing case status is not a pass", () => {
    expect(normalizeCaseStatus(undefined)).toBe("SKIPPED");
    expect(normalizeCaseStatus("weird")).toBe("SKIPPED");
    expect(normalizeCaseStatus(" pass ")).toBe("PASS");
    expect(normalizeCaseStatus("INCONCLUSIVE")).toBe("INCONCLUSIVE");
    expect(normalizeCaseStatus("inconclusive")).toBe("INCONCLUSIVE");
  });
});
