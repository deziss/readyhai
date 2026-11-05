import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AutoRemediationCard, REMEDIATION_TITLE } from "./AutoRemediationCard";
import { StatefulChainFlow } from "./StatefulChainFlow";
import { ConcurrencyBurstMeter } from "./ConcurrencyBurstMeter";
import { Scenarios } from "./Scenarios";
import { ThreatTriage } from "./ThreatTriage";
import type { TestCaseResult, ThreatFinding, StatefulStep, StatefulStepExecution } from "@/types/agent";

describe("AutoRemediationCard", () => {
  it("renders unified git diff and explanation", () => {
    const patch = `--- a/src/auth.rs\n+++ b/src/auth.rs\n@@ -10,3 +10,4 @@\n- old_code();\n+ new_secure_code();`;
    render(
      <AutoRemediationCard
        patch={patch}
        explanation="Enforce tenant isolation on workspace query."
        reproScript="curl -H 'Authorization: Bearer bob' https://target/api/workspaces/ws_alice"
      />
    );

    expect(screen.getByText("Example remediation \u2014 adapt to your code")).toBeDefined();
    expect(screen.getByText("Enforce tenant isolation on workspace query.")).toBeDefined();
    expect(screen.getByText("Copy example diff")).toBeDefined();
    expect(screen.getByText("Copy repro script")).toBeDefined();
    expect(screen.getByText("+ new_secure_code();")).toBeDefined();
  });

  it("presents the diff as an example and never claims it is verified", () => {
    const { container } = render(
      <AutoRemediationCard patch="+ secure_fix()" explanation="Check the owner." reproScript="curl x" />
    );
    expect(REMEDIATION_TITLE).toBe("Example remediation \u2014 adapt to your code");
    const text = (container.textContent ?? "") + " " + Array.from(container.querySelectorAll("[title]")).map((e) => e.getAttribute("title")).join(" ");
    expect(text).not.toMatch(/verified/i);
    expect(text).not.toMatch(/git patch/i);
    expect(text).not.toMatch(/ready to apply|one-click/i);
    expect(screen.getByText("Example diff")).toBeDefined();
  });

  it("copies patch to clipboard when clicked", async () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText: writeTextMock },
    });

    render(<AutoRemediationCard patch="+ secure_fix()" />);

    const copyBtn = screen.getByText("Copy example diff");
    fireEvent.click(copyBtn);

    expect(writeTextMock).toHaveBeenCalledWith("+ secure_fix()");
    expect(await screen.findByText("Copied!")).toBeDefined();
  });

  it("does not claim success when the clipboard is unavailable", async () => {
    Object.assign(navigator, { clipboard: undefined });
    const notices: string[] = [];
    const onNotice = (e: Event) => notices.push((e as CustomEvent<{ message: string }>).detail.message);
    window.addEventListener("readyhai:notice", onNotice);

    render(<AutoRemediationCard patch="+ secure_fix()" />);
    fireEvent.click(screen.getByText("Copy example diff"));

    await waitFor(() => expect(notices.length).toBe(1));
    window.removeEventListener("readyhai:notice", onNotice);
    expect(screen.queryByText("Copied!")).toBeNull();
  });
});

describe("StatefulChainFlow", () => {
  it("renders multi-actor sequence with Alice, Bob, and violation alert", () => {
    const steps: StatefulStep[] = [
      {
        step_number: 1,
        actor: "alice",
        method: "POST",
        path: "/api/workspaces",
        extract_vars: ["workspace_id"],
      },
      {
        step_number: 2,
        actor: "bob",
        method: "GET",
        path: "/api/workspaces/{{workspace_id}}",
        violation_condition: "BOLA Breached: Bob accessed Alice's object",
      },
    ];

    const chain: StatefulStepExecution[] = [
      {
        step_number: 1,
        actor: "alice",
        method: "POST",
        resolved_path: "/api/workspaces",
        status_code: 201,
        latency_ms: 32,
        extracted_values: { workspace_id: "ws_8f92" },
        passed: true,
      },
      {
        step_number: 2,
        actor: "bob",
        method: "GET",
        resolved_path: "/api/workspaces/ws_8f92",
        status_code: 200,
        latency_ms: 45,
        extracted_values: {},
        passed: false,
      },
    ];

    render(<StatefulChainFlow steps={steps} chain={chain} />);

    expect(screen.getByText("Stateful scenario chain")).toBeDefined();
    expect(screen.getByText("Alice")).toBeDefined();
    expect(screen.getByText("Bob")).toBeDefined();
    expect(screen.getByText('"ws_8f92"')).toBeDefined();
    expect(screen.getByText("Critical breach detected")).toBeDefined();
    expect(screen.getAllByText(/BOLA Breached/i).length).toBeGreaterThan(0);
  });

  it("renders prerequisite setup notice when Alice receives HTTP 401 instead of a false breach", () => {
    const steps: StatefulStep[] = [
      {
        step_number: 1,
        actor: "alice",
        method: "POST",
        path: "/api/workspaces",
        extract_vars: ["workspace_id"],
      },
      {
        step_number: 2,
        actor: "bob",
        method: "GET",
        path: "/api/workspaces/{{workspace_id}}",
        violation_condition: "status == 200",
      },
    ];

    const chain: StatefulStepExecution[] = [
      {
        step_number: 1,
        actor: "alice",
        method: "POST",
        resolved_path: "/api/workspaces",
        status_code: 401,
        latency_ms: 15,
        extracted_values: {},
        passed: false,
        violation_triggered: false,
        error_detail: "Prerequisite setup step 1 not met (actor 'alice', POST /api/workspaces): received HTTP 401",
      },
    ];

    render(<StatefulChainFlow steps={steps} chain={chain} />);

    expect(screen.getByText("Prerequisite setup not met")).toBeDefined();
    expect(screen.queryByText("Critical breach detected")).toBeNull();
    expect(screen.getByText(/Prerequisite setup notice/i)).toBeDefined();
    expect(screen.getAllByText(/received HTTP 401/i).length).toBeGreaterThan(0);
  });
});

describe("ConcurrencyBurstMeter", () => {
  it("renders burst count and status chips for TOCTOU race test", () => {
    render(
      <ConcurrencyBurstMeter
        burstCount={5}
        burstResults={[200, 409, 409, 409, 409]}
      />
    );

    expect(screen.getByText("TOCTOU concurrency burst")).toBeDefined();
    expect(screen.getByText("5x concurrent burst")).toBeDefined();
    expect(screen.getByText("200 OK")).toBeDefined();
    expect(screen.getAllByText("409 Conflict").length).toBe(4);
    expect(screen.getByText("Mutex lock enforced")).toBeDefined();
  });

  it("identifies race condition vulnerability when multiple requests succeed", () => {
    render(
      <ConcurrencyBurstMeter
        burstCount={3}
        burstResults={[200, 200, 200]}
      />
    );

    expect(screen.getByText("Race condition vulnerability")).toBeDefined();
  });
});

describe("Scenarios component", () => {
  it("renders compact badges for stateful, BOLA, and burst cases", () => {
    const testCases: TestCaseResult[] = [
      {
        id: "TC-001",
        title: "Cross-Tenant Document Read BOLA",
        component: "/api/docs",
        technique: "bola",
        method: "GET",
        status: "FAIL",
        latency_ms: 55,
        curl: "curl https://target/api/docs",
        stateful_steps: [
          { step_number: 1, actor: "alice", method: "POST", path: "/api/docs" },
          { step_number: 2, actor: "bob", method: "GET", path: "/api/docs/1" },
        ],
        remediation_patch: "--- a/app.py\n+++ b/app.py\n+ check_owner()",
      },
      {
        id: "TC-002",
        title: "Concurrent Balance Depletion TOCTOU",
        component: "/api/transfer",
        technique: "toctou",
        method: "POST",
        status: "FAIL",
        latency_ms: 120,
        curl: "curl -X POST https://target/api/transfer",
        concurrency_burst: 5,
        concurrency_burst_results: [200, 200, 200, 409, 409],
      },
    ];

    render(<Scenarios testCases={testCases} />);

    expect(screen.getByText("BOLA test")).toBeDefined();
    expect(screen.getByText("Stateful chain")).toBeDefined();
    expect(screen.getByText("TOCTOU burst")).toBeDefined();
    expect(screen.getByText("Example remediation \u2014 adapt to your code")).toBeDefined();
  });

  it("gives the sticky toolbar an opaque surface so scrolled rows never bleed through", () => {
    const testCases: TestCaseResult[] = [
      {
        id: "TC-001",
        title: "Row under the toolbar",
        component: "/api/docs",
        technique: "authz",
        method: "GET",
        status: "PASS",
        latency_ms: 10,
        curl: "curl https://target/api/docs",
      },
    ];
    render(<Scenarios testCases={testCases} />);

    const toolbar = screen.getByText("Adversarial scenarios").closest("div.sticky") as HTMLElement | null;
    expect(toolbar).not.toBeNull();
    const cls = toolbar!.className.split(/\s+/);
    expect(cls).toContain("sticky");
    expect(cls).toContain("top-0");
    expect(cls).toContain("bg-rh-surface");
    expect(cls).toContain("border-b");
    expect(cls).toContain("border-rh-line");
    expect(cls).toContain("z-20");
    // Rows live in their own stacking context so inner z-index (chain nodes) cannot paint over the toolbar.
    expect(screen.getByText("TC-001").closest("div.isolate")).not.toBeNull();
  });
});

describe("ThreatTriage component", () => {
  it("renders threats and AutoRemediationCard", () => {
    const threats: ThreatFinding[] = [
      {
        owasp_category: "API1:2023",
        severity: "CRITICAL",
        title: "Broken Object Level Authorization in Workspaces",
        affected_routes: ["/api/workspaces/{id}"],
        remediation: "Add tenant ID filter in query.",
        remediation_patch: "--- a/repo\n+++ b/repo\n+ if user != owner: raise 403",
        remediation_explanation: "Verifies user ID against workspace owner ID.",
      },
    ];

    render(<ThreatTriage threats={threats} />);

    expect(screen.getByText("Broken Object Level Authorization in Workspaces")).toBeDefined();
    expect(screen.getByText("API1:2023")).toBeDefined();
    expect(screen.getByText("Critical", { selector: "span" })).toBeDefined();
    expect(screen.getByText("Example remediation \u2014 adapt to your code")).toBeDefined();
    expect(screen.getByText("Verifies user ID against workspace owner ID.")).toBeDefined();
  });
});
