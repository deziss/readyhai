import { describe, expect, it } from "vitest";
import type { AgentRunRecord } from "@/types/agent";
import {
  blockReasonLabel,
  buildLedger,
  canApproveVerdict,
  confirmedSignOffStatus,
  getPillars,
  isGateVerdict,
  isNotEvaluatedVerdict,
  isRunActive,
  ledgerBlockers,
  ledgerConfidence,
  ledgerScore,
  ledgerVerdict,
  normalizeCaseStatus,
  normalizeExecutedCase,
  normalizeRunStatus,
  normalizeVerdict,
  numOrNull,
  runCases,
  runEndedEarly,
  signOffBlockedReason,
} from "./runs";
import { NOT_EVALUATED_LEDGER } from "./testFixtures";

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

describe("getPillars with the backend's pillars[]", () => {
  const pillars = getPillars(NOT_EVALUATED_LEDGER);

  it("uses the backend names, ids, claims and statuses, in the backend's order", () => {
    expect(pillars.map((p) => p.key)).toEqual(["value", "authority", "safety", "evidence"]);
    expect(pillars.map((p) => p.title)).toEqual([
      "Functional correctness and input handling",
      "Authorization and least privilege",
      "Injection resistance and data safety",
      "Reproducible evidence",
    ]);
    expect(pillars[0].evidence).toBe("boundary: 2 passed, 1 failed of 3 conclusive");
    expect(pillars[0].status).toBe("partial");
    expect(pillars[0].score).toBe(62);
    expect(pillars[0].caseCount).toBe(3);
  });

  it("never shows the old hard-coded labels", () => {
    const text = JSON.stringify(pillars);
    for (const wrong of ["API Contract", "Schema Compliance", "Input Fuzzing", "Observability & Leak"]) {
      expect(text).not.toContain(wrong);
    }
  });

  it("carries the confidence and marks a pillar without conclusive evidence as not evaluated", () => {
    expect(pillars[0].confidence).toBe(40);
    expect(pillars[0].notEvaluated).toBe(false);
    expect(pillars[1].score).toBeNull();
    expect(pillars[1].notEvaluated).toBe(true);
    expect(pillars[1].confidence).toBe(0);
    expect(pillars[2].confidence).toBeNull();
    expect(pillars[3].notEvaluated).toBe(false);
  });

  it("every pillar has its claim as evidence text (no 'No evidence text' for a reported claim)", () => {
    expect(pillars.every((p) => p.evidence !== null)).toBe(true);
  });

  it("keeps an out-of-range confidence inside 0..=100 and ignores a non-number", () => {
    const [a, b] = getPillars({
      pillars: [
        { id: "value", name: "V", score: 50, status: "partial", claim: "c", confidence: 140 },
        { id: "authority", name: "A", score: 50, status: "partial", claim: "c", confidence: "x" as unknown as number },
      ],
    });
    expect(a.confidence).toBe(100);
    expect(b.confidence).toBeNull();
  });

  it("falls back to the legacy fields only for an old run without pillars[], with the backend's names", () => {
    const legacy = getPillars({ value_score: 80, authz: { score: 70, status: "partial", evidence: "old text" } });
    expect(legacy.map((p) => p.key)).toEqual(["value", "authority", "safety", "evidence"]);
    expect(legacy[0].title).toBe("Functional correctness and input handling");
    expect(legacy[0].score).toBe(80);
    expect(legacy[1].score).toBe(70);
    expect(legacy[1].evidence).toBe("old text");
    expect(legacy[2].score).toBeNull();
    expect(legacy[2].notEvaluated).toBe(true);
    expect(legacy.every((p) => p.confidence === null)).toBe(true);
  });

  it("an empty pillars[] counts as an old run: four not-evaluated pillars, nothing invented", () => {
    const empty = getPillars({ pillars: [] });
    expect(empty).toHaveLength(4);
    expect(empty.every((p) => p.score === null && p.notEvaluated)).toBe(true);
  });
});

describe("not evaluated verdict", () => {
  it("is recognised and is not a gate verdict that can be approved", () => {
    expect(isNotEvaluatedVerdict("NOT_EVALUATED")).toBe(true);
    expect(isNotEvaluatedVerdict("NO_GO")).toBe(false);
    expect(isGateVerdict("NOT_EVALUATED")).toBe(false);
    expect(canApproveVerdict("NOT_EVALUATED")).toBe(false);
  });

  it("its placeholder score of 0 is not a score", () => {
    expect(NOT_EVALUATED_LEDGER.overall_readiness).toBe(0);
    expect(ledgerScore(NOT_EVALUATED_LEDGER)).toBeNull();
    expect(ledgerVerdict(NOT_EVALUATED_LEDGER)).toBe("NOT_EVALUATED");
    // a real 0 from an evaluated run stays a score; a ledger that says it was not evaluated has none
    expect(ledgerScore({ gate_verdict: "NO_GO", overall_readiness: 0, evaluated: true })).toBe(0);
    expect(ledgerScore({ gate_verdict: "NO_GO", overall_readiness: 40 })).toBe(40);
    expect(ledgerScore({ overall_readiness: 0, evaluated: false })).toBeNull();
  });

  it("buildLedger keeps the verdict, the blockers and the pillars of a stored run", () => {
    const l = buildLedger({ evidence_ledger: NOT_EVALUATED_LEDGER } as AgentRunRecord);
    expect(l?.gate_verdict).toBe("NOT_EVALUATED");
    expect(l?.pillars).toHaveLength(4);
    expect(l?.blockers).toHaveLength(2);
    expect(ledgerScore(l)).toBeNull();
  });

  it("reads the overall confidence", () => {
    expect(ledgerConfidence(NOT_EVALUATED_LEDGER)).toBe(22);
    expect(ledgerConfidence({})).toBeNull();
    expect(ledgerConfidence({ confidence: 250 })).toBe(100);
  });
});

describe("blockers", () => {
  it("turns the backend blockers into what to show, with the case count", () => {
    const [auth, surface] = ledgerBlockers(NOT_EVALUATED_LEDGER);
    expect(auth.reason).toBe("auth_wall");
    expect(auth.label).toBe("Auth wall");
    expect(auth.detail).toContain("307 to /login");
    expect(auth.nextStep).toContain("readyhai roles init --spec");
    expect(auth.caseCount).toBe(3);
    expect(surface.label).toBe("No input surface");
    expect(surface.caseCount).toBe(0);
  });

  it("is empty without blockers and skips entries that say nothing", () => {
    expect(ledgerBlockers(null)).toEqual([]);
    expect(ledgerBlockers({})).toEqual([]);
    expect(ledgerBlockers({ blockers: [{ reason: "transport", detail: "", next_step: "" }] })).toEqual([]);
    expect(
      ledgerBlockers({ blockers: [{ reason: "something_new", detail: "d", next_step: "" }] })[0].label
    ).toBe("Something new");
  });

  it("labels the block reasons", () => {
    expect(blockReasonLabel("auth_wall")).toBe("Auth wall");
    expect(blockReasonLabel("out_of_scope")).toBe("Out of scope");
    expect(blockReasonLabel("transport")).toBe("No HTTP answer");
    expect(blockReasonLabel(null)).toBeNull();
    expect(blockReasonLabel("")).toBeNull();
  });
});

describe("case results with the new statuses", () => {
  it("keeps NOT_APPLICABLE (it is excluded from the counts, not skipped)", () => {
    expect(normalizeCaseStatus("NOT_APPLICABLE")).toBe("NOT_APPLICABLE");
    expect(normalizeCaseStatus("not_applicable")).toBe("NOT_APPLICABLE");
  });

  it("carries the block reason and the redirect chain of an executed case", () => {
    const blocked = normalizeExecutedCase({
      case_id: "TC-004",
      status: "BLOCKED",
      blocked_reason: "auth_wall",
      redirect_chain: [
        { status: 307, location: "/login" },
        { status: 302, location: "/login?next=%2F" },
        { status: "x", location: "/bad" } as never,
      ],
    });
    expect(blocked.status).toBe("BLOCKED");
    expect(blocked.blocked_reason).toBe("auth_wall");
    expect(blocked.redirect_chain).toEqual([
      { status: 307, location: "/login" },
      { status: 302, location: "/login?next=%2F" },
    ]);
    const plain = normalizeExecutedCase({ case_id: "TC-001", status: "PASS" });
    expect(plain.blocked_reason).toBeNull();
    expect(plain.redirect_chain).toEqual([]);
  });

  it("runCases surfaces them from a run's executed_results", () => {
    const cases = runCases({
      executed_results: [{ case_id: "TC-009", status: "NOT_APPLICABLE", blocked_reason: "no_surface" }],
    } as AgentRunRecord);
    expect(cases[0].status).toBe("NOT_APPLICABLE");
    expect(cases[0].blocked_reason).toBe("no_surface");
  });
});
