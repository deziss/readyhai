import { describe, expect, it } from "vitest";
import { asList, gateSummary, ledgerSummary, parseTime, targetLabel, targetsFrom } from "./dashboard";
import type { AgentRunRecord } from "@/types/agent";
import type { ScanSummary } from "@/types/scans";
import type { VulnEntry } from "@/components/VulnsView";

const NOW = Date.parse("2026-01-20T12:00:00Z");

function run(over: Partial<AgentRunRecord> = {}): AgentRunRecord {
  return {
    id: "run-1",
    target: "https://app.example.com/",
    status: "completed",
    started_at: "2026-01-20T11:00:00Z",
    ...over,
  };
}

function scan(over: Partial<ScanSummary> = {}): ScanSummary {
  return {
    id: "scan-1",
    target: "https://app.example.com",
    verdict: "PASS",
    state: "complete",
    started: "2026-01-20T10:00:00Z",
    findings_count: 0,
    hard_fail_count: 0,
    reasons: [],
    reports: {},
    ...over,
  } as ScanSummary;
}

function vuln(over: Partial<VulnEntry> = {}): VulnEntry {
  return {
    fingerprint: "a",
    target: "https://app.example.com",
    target_key: "https://app.example.com",
    kind: "http",
    rule: "r",
    title: "t",
    severity: "high",
    resource: "/",
    first_seen: "",
    last_seen: "",
    occurrences: 1,
    status: "open",
    message: "",
    verification: "verified",
    verified_by: "tpl",
    verified_at: "",
    ...over,
  };
}

describe("parseTime", () => {
  it("returns null instead of guessing when a timestamp is missing or impossible", () => {
    expect(parseTime(undefined, NOW)).toBeNull();
    expect(parseTime("", NOW)).toBeNull();
    expect(parseTime("not a date", NOW)).toBeNull();
    // A future-dated record is corrupt data, not a real measurement.
    expect(parseTime("2026-01-21T00:00:00Z", NOW)).toBeNull();
  });

  it("parses a real timestamp", () => {
    expect(parseTime("2026-01-20T11:00:00Z", NOW)).toBe(Date.parse("2026-01-20T11:00:00Z"));
  });
});

describe("targetLabel", () => {
  it("keeps the host legible and never invents a target", () => {
    expect(targetLabel("https://app.example.com/v2/")).toBe("app.example.com/v2");
    expect(targetLabel("")).toBe("unknown target");
    expect(targetLabel("my-repo/main")).toBe("my-repo/main");
  });
});

describe("targetsFrom", () => {
  it("groups runs, scans and findings onto one row per target", () => {
    const rows = targetsFrom({
      now: NOW,
      runs: [run()],
      scans: [scan()],
      vulns: [
        vuln(),
        vuln({ fingerprint: "b", status: "open", verification: "unverified" }),
        vuln({ fingerprint: "c", status: "accepted" }),
      ],
    });

    expect(rows).toHaveLength(1);
    const row = rows[0];
    // Accepted rows must not count as open, and the two verification states stay separate.
    expect(row.openVulns).toBe(2);
    expect(row.verifiedOpen).toBe(1);
    expect(row.unverifiedOpen).toBe(1);
    expect(row.runTs).not.toBeNull();
    expect(row.active).toBe(false);
  });

  it("reports a missing defect count as missing rather than zero", () => {
    const rows = targetsFrom({ now: NOW, runs: [run({ defects_count: undefined })], scans: [], vulns: [] });
    expect(rows[0].defects).toBeNull();
  });

  it("splits a trailing slash so the same target does not appear twice", () => {
    const rows = targetsFrom({
      now: NOW,
      runs: [run({ target: "https://a.example.com" })],
      scans: [scan({ target: "https://a.example.com//" })],
      vulns: [],
    });
    expect(rows).toHaveLength(1);
  });
});

describe("gateSummary", () => {
  it("says nothing has been measured when there are no runs", () => {
    const summary = gateSummary(targetsFrom({ now: NOW, runs: [], scans: [scan()], vulns: [] }));
    expect(summary.nothingMeasured).toBe(true);
    expect(summary.latest).toBeNull();
    expect(summary.targetsWithRuns).toBe(0);
    expect(summary.targetsTotal).toBe(1);
  });

  it("lists a GO without a sign-off as awaiting a decision", () => {
    const rows = targetsFrom({
      now: NOW,
      runs: [run({ evidence_ledger: { gate_verdict: "GO", evaluated: true, pillars: [] } })],
      scans: [],
      vulns: [],
    });
    expect(gateSummary(rows).awaitingSignOff).toHaveLength(1);
  });

  it("ignores a running pass when choosing the release gate", () => {
    const rows = targetsFrom({
      now: NOW,
      runs: [
        run({ id: "old", started_at: "2026-01-20T09:00:00Z", evidence_ledger: { gate_verdict: "NO_GO" } }),
        run({ id: "new", status: "running", started_at: "2026-01-20T11:30:00Z" }),
      ],
      scans: [],
      vulns: [],
    });
    const summary = gateSummary(rows);
    expect(summary.activeRuns).toBe(1);
    // The row is one target; its gate is the newest run that has finished.
    expect(summary.latest?.finishedRun?.id).toBe("old");
    expect(summary.latest?.run?.id).toBe("new");
  });
});

describe("ledgerSummary", () => {
  it("keeps an unevaluated pillar free of a score", () => {
    const summary = ledgerSummary(
      run({
        evidence_ledger: {
          evaluated: false,
          pillars: [{ id: "value", name: "Value", score: null, status: "not_evaluated", claim: "" }],
        },
      })
    );
    expect(summary?.evaluated).toBe(false);
    expect(summary?.pillars[0].score).toBeNull();
  });

  it("drops blockers that carry neither a detail nor a next step", () => {
    const summary = ledgerSummary(
      run({
        evidence_ledger: {
          evaluated: true,
          pillars: [{ id: "value", name: "Value", score: 50, status: "partial", claim: "" }],
          blockers: [
            { reason: "no_auth", detail: "", next_step: "" },
            { reason: "no_auth", detail: "Login flow was not reachable", next_step: "Supply credentials" },
          ],
        },
      })
    );
    expect(summary?.blockers).toHaveLength(1);
    expect(summary?.blockers[0].nextStep).toBe("Supply credentials");
  });

  it("returns null when the run carries no ledger at all", () => {
    expect(ledgerSummary(run())).toBeNull();
  });
});

describe("asList", () => {
  it("accepts the bare-array and envelope shapes the backend actually returns", () => {
    expect(asList([1, 2], "runs")).toEqual([1, 2]);
    expect(asList({ runs: [{ id: "r1" }] }, "runs")).toEqual([{ id: "r1" }]);
  });

  it("returns empty for anything else rather than crashing the dashboard", () => {
    expect(asList(null, "runs")).toEqual([]);
    expect(asList({ runs: null }, "runs")).toEqual([]);
    expect(asList("nope", "runs")).toEqual([]);
  });
});
