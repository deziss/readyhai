import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { getPillars, ledgerBlockers } from "@/lib/runs";
import { NOT_EVALUATED_LEDGER } from "@/lib/testFixtures";
import type { EvidenceLedger, TestCaseResult } from "@/types/agent";
import { NextStepsCard, PillarCard } from "./LedgerPanels";
import { Scenarios } from "./Scenarios";
import { SideCanvas } from "./SideCanvas";

const pillars = getPillars(NOT_EVALUATED_LEDGER);

describe("PillarCard", () => {
  it("shows the backend name, claim, score, status and a confidence chip", () => {
    render(<PillarCard pillar={pillars[0]} />);
    expect(screen.getByText("Functional correctness and input handling")).toBeTruthy();
    expect(screen.getByText("boundary: 2 passed, 1 failed of 3 conclusive")).toBeTruthy();
    expect(screen.getByText("confidence 40%")).toBeTruthy();
    expect(screen.getByText("Partial")).toBeTruthy();
    expect(screen.getByRole("progressbar").getAttribute("aria-valuenow")).toBe("62");
    expect(screen.queryByText(/No evidence text/)).toBeNull();
  });

  it("says 'Not evaluated: insufficient evidence' instead of a score when there is no conclusive result", () => {
    render(<PillarCard pillar={pillars[1]} />);
    expect(screen.getByText("Not evaluated: insufficient evidence")).toBeTruthy();
    expect(screen.queryByRole("progressbar")).toBeNull();
    // the claim still explains why, and the confidence of 0 is shown rather than hidden
    expect(screen.getByText(/no conclusive result for authz/)).toBeTruthy();
    expect(screen.getByText("confidence 0%")).toBeTruthy();
  });

  it("shows no confidence chip when the backend reported none", () => {
    render(<PillarCard pillar={pillars[3]} />);
    expect(screen.queryByText(/confidence/)).toBeNull();
  });

  it("numbers the pillar when given an index", () => {
    render(<PillarCard pillar={pillars[2]} index={2} surface="surface" />);
    expect(screen.getByText(/^3\. Injection resistance and data safety/)).toBeTruthy();
  });
});

describe("NextStepsCard", () => {
  it("lists each blocker with its detail, its next step and how many cases it blocks", () => {
    render(<NextStepsCard blockers={ledgerBlockers(NOT_EVALUATED_LEDGER)} />);
    const card = screen.getByRole("region", { name: "What to provide next" });
    expect(within(card).getByText("What to provide next")).toBeTruthy();
    expect(within(card).getByText("Auth wall")).toBeTruthy();
    expect(within(card).getByText(/answers 307 to \/login/)).toBeTruthy();
    expect(within(card).getByText(/Provide test accounts: readyhai roles init --spec/)).toBeTruthy();
    expect(within(card).getByText("3 cases blocked")).toBeTruthy();
    expect(within(card).getByText("No input surface")).toBeTruthy();
    expect(within(card).getByText(/Provide the OpenAPI spec URL/)).toBeTruthy();
  });

  it("renders nothing when there are no blockers", () => {
    const { container } = render(<NextStepsCard blockers={[]} />);
    expect(container.innerHTML).toBe("");
  });
});

const baseProps = {
  testCases: [] as TestCaseResult[],
  discoveredRoutes: [],
  threats: [],
  isSpa: false,
  onRetestCase: async () => {},
  runsHistory: [],
  onLoadRun: () => {},
};

function openLedger(ledger: EvidenceLedger | null) {
  render(<SideCanvas {...baseProps} evidenceLedger={ledger} />);
  fireEvent.click(screen.getByRole("tab", { name: /Evidence ledger/ }));
}

describe("SideCanvas evidence ledger tab", () => {
  it("shows the not-evaluated verdict, the blockers card and the backend pillars for a real payload", () => {
    openLedger(NOT_EVALUATED_LEDGER);
    expect(screen.getByText("Not evaluated", { selector: "span" })).toBeTruthy();
    expect(screen.getByText("Composite score: not evaluated")).toBeTruthy();
    expect(screen.queryByText("Composite score: 0%")).toBeNull();
    expect(screen.getByText("confidence 22%")).toBeTruthy();
    expect(screen.getByRole("region", { name: "What to provide next" })).toBeTruthy();
    expect(screen.getByText("Reproducible evidence")).toBeTruthy();
    expect(screen.getAllByText("Not evaluated: insufficient evidence")).toHaveLength(2);
    expect(screen.queryByText(/No evidence text was reported/)).toBeNull();
  });

  it("has no what-to-provide-next card when nothing blocked the run", () => {
    openLedger({ ...NOT_EVALUATED_LEDGER, blockers: [], gate_verdict: "GO", evaluated: true, overall_readiness: 90 });
    expect(screen.queryByRole("region", { name: "What to provide next" })).toBeNull();
    expect(screen.getByText("Composite score: 90%")).toBeTruthy();
  });
});

describe("Scenarios with the new statuses", () => {
  const cases: TestCaseResult[] = [
    {
      id: "TC-001",
      title: "Liveness of /",
      component: "/",
      technique: "liveness",
      method: "GET",
      status: "PASS",
      latency_ms: 20,
      curl: "curl https://t/",
      response_status: 200,
      redirect_chain: [{ status: 307, location: "/login" }],
    },
    {
      id: "TC-002",
      title: "Cross-user read",
      component: "/api/me",
      technique: "authz",
      method: "GET",
      status: "BLOCKED",
      blocked_reason: "auth_wall",
      latency_ms: null,
      curl: "curl https://t/api/me",
    },
    {
      id: "TC-003",
      title: "Injection on the shell",
      component: "/",
      technique: "injection",
      method: "GET",
      status: "NOT_APPLICABLE",
      blocked_reason: "no_surface",
      latency_ms: null,
      curl: "curl https://t/",
    },
  ];

  it("shows NOT_APPLICABLE as a muted chip and BLOCKED with its reason", () => {
    render(<Scenarios testCases={cases} />);
    const na = screen.getByText("Not applicable", { selector: "span" });
    expect(na.className).toContain("text-rh-muted");
    expect(na.className).not.toContain("rh-nogo");
    expect(na.getAttribute("title")).toContain("no input surface");
    const blocked = screen.getByText("Blocked: auth wall");
    expect(blocked.getAttribute("title")).toContain("auth wall");
    expect(blocked.className).not.toContain("rh-nogo");
  });

  it("shows the redirect chain in the inspector of a case that followed redirects", () => {
    render(<Scenarios testCases={cases} />);
    // the first row opens by default; a row without redirects has no chain
    const chain = screen.getByTestId("redirect-chain");
    expect(chain.textContent).toContain("307");
    expect(chain.textContent).toContain("/login");
    fireEvent.click(screen.getByText("Cross-user read"));
    expect(screen.queryByTestId("redirect-chain")).toBeNull();
  });

  it("can filter to the blocked and not-applicable cases", () => {
    render(<Scenarios testCases={cases} />);
    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "NOT_APPLICABLE" } });
    expect(screen.queryByText("Liveness of /")).toBeNull();
    expect(screen.getByText("Injection on the shell")).toBeTruthy();
  });
});
