import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PIPELINE_STAGES, ToolCallList, buildStages, type StageStatus } from "./ToolCallList";

const stageButtons = () => screen.getAllByRole("button");
const detail = () => screen.getByRole("region", { name: "Stage details" });

describe("pipeline stages", () => {
  it("runs Recon, Discovery, Plan, Execute, Verify, Gate in that order", () => {
    expect(PIPELINE_STAGES.map((s) => s.label)).toEqual(["Recon", "Discovery", "Plan", "Execute", "Verify", "Gate"]);
    expect(buildStages().every((s) => s.status === "standby")).toBe(true);
    expect(buildStages((i) => (i === 0 ? "running" : "standby"))[0].status).toBe("running");
  });
});

describe("ToolCallList stepper", () => {
  it("renders every stage as a button with aria-expanded, all collapsed at first", () => {
    render(<ToolCallList stages={buildStages()} />);
    const buttons = stageButtons();
    expect(buttons).toHaveLength(6);
    for (const b of buttons) expect(b.getAttribute("aria-expanded")).toBe("false");
    expect(detail().textContent).toContain("Run the agent");
  });

  it("opens a stage on click, closes it on a second click, and moves between stages", () => {
    render(<ToolCallList stages={buildStages()} />);
    const [recon, discovery] = stageButtons();

    fireEvent.click(recon);
    expect(recon.getAttribute("aria-expanded")).toBe("true");
    expect(detail().textContent).toContain("Recon");
    expect(detail().textContent).toContain("model connection");

    fireEvent.click(discovery);
    expect(recon.getAttribute("aria-expanded")).toBe("false");
    expect(discovery.getAttribute("aria-expanded")).toBe("true");
    expect(detail().textContent).toContain("maps the endpoints");

    fireEvent.click(discovery);
    expect(discovery.getAttribute("aria-expanded")).toBe("false");
    expect(detail().textContent).toContain("Run the agent");
  });

  it("does nothing on hover: no detail opens and no state changes", () => {
    render(<ToolCallList stages={buildStages()} />);
    const before = detail().innerHTML;
    for (const b of stageButtons()) {
      fireEvent.mouseEnter(b);
      fireEvent.mouseOver(b);
      fireEvent.mouseLeave(b);
    }
    expect(detail().innerHTML).toBe(before);
    for (const b of stageButtons()) expect(b.getAttribute("aria-expanded")).toBe("false");
  });

  it("keeps one fixed-height detail area whatever is shown", () => {
    const { rerender } = render(<ToolCallList stages={buildStages()} />);
    const height = (el: HTMLElement) => el.className.split(" ").find((c) => /^h-\d+$/.test(c));
    const idle = height(detail());
    expect(idle).toBeTruthy();

    fireEvent.click(stageButtons()[2]);
    expect(height(detail())).toBe(idle);

    rerender(<ToolCallList stages={buildStages((i) => (i === 1 ? "running" : i < 1 ? "succeeded" : "standby"))} />);
    expect(height(detail())).toBe(idle);
  });

  it("gives hover only colour classes: no size, spacing or transition changes", () => {
    render(<ToolCallList stages={buildStages()} />);
    for (const el of document.querySelectorAll<HTMLElement>("button, button *")) {
      for (const cls of el.classList) {
        if (!/(^|:)(group-)?hover:/.test(cls)) continue;
        expect(cls).toMatch(/hover:(text|border|bg)-/);
      }
      expect(el.className).not.toMatch(/transition|duration|scale|translate/);
    }
  });

  it("summarises live status in the header and the detail area", () => {
    const running = buildStages((i) => (i === 0 ? "succeeded" : i === 1 ? "running" : "standby"));
    render(<ToolCallList stages={running} />);
    expect(screen.getByText("Running Discovery")).toBeTruthy();
    expect(detail().textContent).toContain("Discovery is running");
  });

  it("reports a failed stage", () => {
    const failed = buildStages((i): StageStatus => (i === 0 ? "succeeded" : i === 1 ? "failed" : "standby"));
    render(<ToolCallList stages={failed} />);
    expect(screen.getByText("Discovery failed")).toBeTruthy();
    expect(detail().textContent).toContain("The run stopped at Discovery");
  });

  it("ends with the backend verdict once the gate stage is done", () => {
    const done = buildStages(() => "succeeded");
    const { rerender } = render(<ToolCallList stages={done} verdict="NO_GO" />);
    expect(screen.getByText("All stages complete")).toBeTruthy();
    expect(screen.getByText(/^no go$/i)).toBeTruthy();
    fireEvent.click(stageButtons()[5]);
    expect(detail().textContent).toContain("Verdict: no go");

    rerender(<ToolCallList stages={done} verdict="GO" />);
    expect(screen.getByText(/^go$/i)).toBeTruthy();
    expect(detail().textContent).toContain("Verdict: go");
  });

  it("never invents a verdict", () => {
    render(<ToolCallList stages={buildStages(() => "succeeded")} verdict={null} />);
    expect(screen.getByText("No verdict yet")).toBeTruthy();
    fireEvent.click(stageButtons()[5]);
    expect(detail().textContent).toContain("No verdict reported");
  });
});
