import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentHistoryView } from "./AgentHistoryView";

const run = (id: string, status: string, over: Record<string, unknown> = {}) => ({
  id,
  target: `https://${id}.example/`,
  profile: "standard",
  provider: "deterministic",
  model: "none",
  status,
  started_at: "2026-01-01T00:00:00Z",
  steps: [],
  discovered_routes: [],
  planned_cases: [],
  executed_results: [],
  triaged_defects: [],
  evidence_ledger: null,
  approval_status: null,
  ...over,
});

const RUNS = [
  run("20260101-000000-aaaaaaaaaaaaaaa1", "running"),
  run("20260101-000000-aaaaaaaaaaaaaaa2", "cancelled"),
  run("20260101-000000-aaaaaaaaaaaaaaa3", "failed", { error: "target unreachable" }),
  run("20260101-000000-aaaaaaaaaaaaaaa4", "completed", {
    evidence_ledger: { gate_verdict: "GO", overall_readiness: 91 },
  }),
];

type Call = { url: string; method: string };

function stubBackend(cancelStatus = 202) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      calls.push({ url: String(input), method });
      if (method === "POST" && String(input).endsWith("/cancel")) {
        return cancelStatus === 202
          ? new Response(JSON.stringify({ status: "cancelling" }), { status: 202 })
          : new Response(JSON.stringify({ error: "run is not running (status: completed)" }), { status: cancelStatus });
      }
      return new Response(JSON.stringify({ runs: RUNS }), { status: 200 });
    })
  );
  return calls;
}

beforeEach(() => {
  vi.stubGlobal("confirm", vi.fn(() => true));
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AgentHistoryView run statuses", () => {
  it("labels running, cancelled and failed runs and leaves a completed one with its verdict", async () => {
    stubBackend();
    render(<AgentHistoryView />);
    // the first run is auto-selected, so its target is in the list row and in the detail header
    await screen.findAllByText("https://20260101-000000-aaaaaaaaaaaaaaa1.example/");
    // the list rows: one badge per non-completed state, in-progress instead of a verdict for the running one
    expect(screen.getAllByText("Running").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Cancelled").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Failed").length).toBeGreaterThan(0);
    expect(screen.getByText("in progress")).toBeTruthy();
    expect(screen.getAllByText("partial results, no gate decision")).toHaveLength(2);
    expect(screen.getAllByText("GO").length).toBeGreaterThan(0);
  });

  it("offers Cancel only on running runs and POSTs the cancel route for that run", async () => {
    const calls = stubBackend();
    render(<AgentHistoryView />);
    // the first run is auto-selected, so its target is in the list row and in the detail header
    await screen.findAllByText("https://20260101-000000-aaaaaaaaaaaaaaa1.example/");
    // exactly one running run -> one Cancel button in the list (the first run is selected: its detail shows another)
    const listCancel = screen.getAllByRole("button", { name: /^Cancel$/ });
    expect(listCancel).toHaveLength(1);
    fireEvent.click(listCancel[0]);
    await waitFor(() =>
      expect(calls).toContainEqual({
        url: "/api/agent/runs/20260101-000000-aaaaaaaaaaaaaaa1/cancel",
        method: "POST",
      })
    );
    // the run stays "running" until the backend says otherwise: the button turns into Cancelling...
    await waitFor(() => expect(screen.getAllByText("Cancelling...").length).toBeGreaterThan(0));
    // the list is reloaded afterwards
    await waitFor(() => expect(calls.filter((c) => c.method === "GET" && c.url === "/api/agent/runs").length).toBeGreaterThan(1));
  });

  it("does not claim a cancel when the backend refuses it", async () => {
    const calls = stubBackend(409);
    const notices: string[] = [];
    const onNotice = (e: Event) => notices.push((e as CustomEvent<{ message: string }>).detail.message);
    window.addEventListener("readyhai:notice", onNotice);
    render(<AgentHistoryView />);
    // the first run is auto-selected, so its target is in the list row and in the detail header
    await screen.findAllByText("https://20260101-000000-aaaaaaaaaaaaaaa1.example/");
    fireEvent.click(screen.getAllByRole("button", { name: /^Cancel$/ })[0]);
    await waitFor(() => expect(notices.length).toBe(1));
    window.removeEventListener("readyhai:notice", onNotice);
    expect(notices[0]).toContain("not running");
    expect(calls.some((c) => c.url.endsWith("/cancel"))).toBe(true);
    // still cancellable: nothing pretends it is being cancelled
    expect(screen.queryByText("Cancelling...")).toBeNull();
  });

  it("explains a failed run and blocks approval of it", async () => {
    stubBackend();
    render(<AgentHistoryView />);
    const row = await screen.findByText("https://20260101-000000-aaaaaaaaaaaaaaa3.example/");
    fireEvent.click(row);
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("target unreachable"));
    fireEvent.click(screen.getByText(/Ledger|Sign-off|Evidence/i, { selector: "button" }));
    const approve = await screen.findByText("Approve production gate");
    expect((approve.closest("button") as HTMLButtonElement).disabled).toBe(true);
    expect(within(document.body).getByText(/failed run cannot be approved/i)).toBeTruthy();
  });
});
