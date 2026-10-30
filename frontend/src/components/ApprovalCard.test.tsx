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
    fireEvent.change(screen.getByPlaceholderText(/Operator sign-off ID/), { target: { value: "op@example.test" } });
    fireEvent.click(screen.getByText("Approve for Deployment"));

    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("denied"));
    expect(onSignOff).toHaveBeenCalledWith("approve", "op@example.test", "");
    expect(screen.getByText("Pending Sign-Off")).toBeTruthy();
    expect(screen.queryByText("Approved")).toBeNull();
    vi.unstubAllGlobals();
  });

  it("disables approve without a gate verdict and without an operator", () => {
    render(
      <ApprovalCard runId="r1" evidenceLedger={{}} defectCount={null} onSignOff={vi.fn(async () => null)} />
    );
    expect((screen.getByText("Approve for Deployment").closest("button") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getAllByText("not evaluated").length).toBeGreaterThan(0);
  });
});
