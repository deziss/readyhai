import { describe, expect, it } from "vitest";
import type { AgentRunRecord } from "@/types/agent";
import {
  buildLedger,
  canApproveVerdict,
  confirmedSignOffStatus,
  getPillars,
  isGateVerdict,
  isRunActive,
  ledgerScore,
  ledgerVerdict,
  normalizeCaseStatus,
  normalizeRunStatus,
  normalizeVerdict,
  numOrNull,
  runEndedEarly,
  signOffBlockedReason,
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

describe("sign-off helpers", () => {
  it("only GO and CONDITIONAL_GO can be approved", () => {
    expect(canApproveVerdict("GO")).toBe(true);
    expect(canApproveVerdict("CONDITIONAL_GO")).toBe(true);
    expect(canApproveVerdict("NO_GO")).toBe(false);
    expect(canApproveVerdict(null)).toBe(false);
    expect(canApproveVerdict("SCANNED")).toBe(false);
  });

  it("confirmedSignOffStatus accepts only an echoed approved/rejected", () => {
    expect(confirmedSignOffStatus("approved")).toBe("approved");
    expect(confirmedSignOffStatus(" Rejected ")).toBe("rejected");
    expect(confirmedSignOffStatus("pending")).toBeNull();
    expect(confirmedSignOffStatus(undefined)).toBeNull();
    expect(confirmedSignOffStatus(null)).toBeNull();
  });
});

describe("run lifecycle status", () => {
  it("normalizes the backend statuses and never guesses an unknown one", () => {
    expect(normalizeRunStatus("running")).toBe("running");
    expect(normalizeRunStatus(" Cancelled ")).toBe("cancelled");
    expect(normalizeRunStatus("canceled")).toBe("cancelled");
    expect(normalizeRunStatus("failed")).toBe("failed");
    expect(normalizeRunStatus("completed")).toBe("completed");
    // a legacy report without a status, or a status we do not know, is NOT turned into "completed"
    expect(normalizeRunStatus(undefined)).toBeNull();
    expect(normalizeRunStatus("")).toBeNull();
    expect(normalizeRunStatus("weird")).toBeNull();
    expect(normalizeRunStatus(3)).toBeNull();
  });

  it("only a running run is active; a cancelled or failed one ended early", () => {
    expect(isRunActive({ status: "running" })).toBe(true);
    expect(isRunActive({ status: "completed" })).toBe(false);
    expect(isRunActive({})).toBe(false);
    expect(runEndedEarly({ status: "cancelled" })).toBe(true);
    expect(runEndedEarly({ status: "failed" })).toBe(true);
    expect(runEndedEarly({ status: "completed" })).toBe(false);
    expect(runEndedEarly({ status: "running" })).toBe(false);
  });

  it("mirrors the backend sign-off rules", () => {
    // running: nothing can be signed
    expect(signOffBlockedReason({ status: "running" }, "approve")).toContain("still running");
    expect(signOffBlockedReason({ status: "running" }, "reject")).toContain("still running");
    // cancelled / failed: reject only
    for (const status of ["cancelled", "failed"]) {
      expect(signOffBlockedReason({ status }, "approve")).toContain("cannot be approved");
      expect(signOffBlockedReason({ status }, "reject")).toBeNull();
    }
    // completed and legacy runs: allowed (the verdict rules apply on top)
    expect(signOffBlockedReason({ status: "completed" }, "approve")).toBeNull();
    expect(signOffBlockedReason({}, "approve")).toBeNull();
  });
});
