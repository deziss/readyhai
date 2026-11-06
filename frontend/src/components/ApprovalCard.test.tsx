import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApprovalCard } from "./ApprovalCard";
import { apiRequest } from "@/lib/api";

const ledger = { gate_verdict: "GO", overall_readiness: 90 };

describe("ApprovalCard sign-off", () => {
  it("shows the error and stays pending when the backend rejects", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "denied" }), { status: 403 }))
    );
    // onSignOff mirrors the real wiring: backend failure -> error string, no state flip.
    const onSignOff = vi.fn(async (action: string, operator: string, notes: string) => {
      const r = await apiRequest("/api/agent/runs/r1/approve", {
        method: "POST",
        json: { action, operator, notes },
        label: "Sign-off",
      });
      return r.ok ? null : r.error;
    });

    render(<ApprovalCard runId="r1" evidenceLedger={ledger} defectCount={0} onSignOff={onSignOff} />);
    fireEvent.change(screen.getByLabelText(/Operator ID/), { target: { value: "op@example.test" } });
    fireEvent.click(screen.getByText("Approve release"));

    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("denied"));
    expect(onSignOff).toHaveBeenCalledWith("approve", "op@example.test", "");
    expect(screen.getByText("Pending sign-off")).toBeTruthy();
    expect(screen.queryByText("Approved")).toBeNull();
    vi.unstubAllGlobals();
  });

  it("disables approve without a gate verdict and without an operator", () => {
    render(
      <ApprovalCard runId="r1" evidenceLedger={{}} defectCount={null} onSignOff={vi.fn(async () => null)} />
    );
    expect((screen.getByText("Approve release").closest("button") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getAllByText("not evaluated").length).toBeGreaterThan(0);
  });

  const approveButton = () => screen.getByText("Approve release").closest("button") as HTMLButtonElement;
  const typeOperator = () =>
    fireEvent.change(screen.getByLabelText(/Operator ID/), { target: { value: "op@example.test" } });

  it("explains a not-evaluated verdict as missing evidence and never offers approval", () => {
    render(
      <ApprovalCard
        runId="r1"
        evidenceLedger={{ gate_verdict: "NOT_EVALUATED", overall_readiness: 0, evaluated: false }}
        defectCount={0}
        onSignOff={vi.fn(async () => null)}
      />
    );
    expect(screen.getAllByText("Not evaluated").length).toBeGreaterThan(0);
    expect(screen.getByText(/not enough conclusive evidence/i)).toBeTruthy();
    expect(screen.queryByText(/NO GO/)).toBeNull();
    expect((screen.getByText("Approve release").closest("button") as HTMLButtonElement).disabled).toBe(true);
    // 0 is a placeholder, not a score
    expect(screen.queryByText("0%")).toBeNull();
  });

  it("never offers approval for a NO_GO verdict", () => {
    render(
      <ApprovalCard
        runId="r1"
        evidenceLedger={{ gate_verdict: "NO_GO", overall_readiness: 20 }}
        defectCount={3}
        onSignOff={vi.fn(async () => null)}
      />
    );
    typeOperator();
    expect(approveButton().disabled).toBe(true);
    // Blocking the release stays available.
    expect((screen.getByText("Block release").closest("button") as HTMLButtonElement).disabled).toBe(false);
  });

  it("offers approval for GO and CONDITIONAL_GO", () => {
    for (const verdict of ["GO", "CONDITIONAL_GO"]) {
      const { unmount } = render(
        <ApprovalCard
          runId="r1"
          evidenceLedger={{ gate_verdict: verdict, overall_readiness: 80 }}
          defectCount={0}
          onSignOff={vi.fn(async () => null)}
        />
      );
      typeOperator();
      expect(approveButton().disabled).toBe(false);
      unmount();
    }
  });

  it("only shows the state the backend ledger reports, not the clicked action", async () => {
    // onSignOff succeeds but the ledger prop is unchanged: the card must stay pending.
    const onSignOff = vi.fn(async () => null);
    render(<ApprovalCard runId="r1" evidenceLedger={ledger} defectCount={0} onSignOff={onSignOff} />);
    typeOperator();
    fireEvent.click(screen.getByText("Approve release"));
    await waitFor(() => expect(onSignOff).toHaveBeenCalled());
    expect(screen.getByText("Pending sign-off")).toBeTruthy();
  });

  it("is a Release gate panel that starts open while a decision is pending and can be collapsed", () => {
    render(<ApprovalCard runId="r1" evidenceLedger={ledger} defectCount={0} onSignOff={vi.fn(async () => null)} />);
    const toggle = screen.getByRole("button", { name: /Release gate/ });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    const body = document.getElementById(toggle.getAttribute("aria-controls") as string) as HTMLElement;
    expect(body.className).not.toContain("hidden");

    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(body.className).toContain("hidden");
    // The verdict and review state stay visible in the header while collapsed.
    expect(screen.getByText("Pending sign-off")).toBeTruthy();
    expect(screen.getByText(/^go$/i)).toBeTruthy();

    // Collapsing keeps what the operator already typed.
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
  });

  it("keeps typed sign-off details across a collapse and expand", () => {
    render(<ApprovalCard runId="r1" evidenceLedger={ledger} defectCount={0} onSignOff={vi.fn(async () => null)} />);
    typeOperator();
    const toggle = screen.getByRole("button", { name: /Release gate/ });
    fireEvent.click(toggle);
    fireEvent.click(toggle);
    expect((screen.getByLabelText(/Operator ID/) as HTMLInputElement).value).toBe("op@example.test");
  });

  it("shows the confirmed sign-off, collapsed by default, and no longer offers the actions", () => {
    render(
      <ApprovalCard
        runId="r1"
        evidenceLedger={{ ...ledger, approval_status: "APPROVED", approved_by: "lead@example.test", approval_notes: "all clear" }}
        defectCount={0}
        onSignOff={vi.fn(async () => null)}
      />
    );
    expect(screen.getByRole("button", { name: /Release gate/ }).getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText("Approved")).toBeTruthy();
    expect(screen.getByText(/lead@example\.test/)).toBeTruthy();
    expect(screen.queryByText("Approve release")).toBeNull();
  });

  it("explains why sign-off is unavailable instead of silently disabling it", () => {
    render(<ApprovalCard runId="r1" evidenceLedger={ledger} defectCount={0} onSignOff={vi.fn(async () => null)} />);
    expect(screen.getByText("Enter your operator ID to approve or block.")).toBeTruthy();
    typeOperator();
    expect(screen.queryByText("Enter your operator ID to approve or block.")).toBeNull();
  });
});
