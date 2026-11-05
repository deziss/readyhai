import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FloatingTaskWidget, type ActiveTaskItem } from "./FloatingTaskWidget";

const task = (over: Partial<ActiveTaskItem>): ActiveTaskItem => ({
  id: "agent_swarm",
  instanceId: "i1",
  title: "Swarm",
  target: "http://t",
  view: "studio",
  status: "completed",
  startTime: 0,
  ...over,
});

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("FloatingTaskWidget auto-dismiss", () => {
  it("dismisses a finished task by instance id after 6s", () => {
    const onDismiss = vi.fn();
    render(<FloatingTaskWidget tasks={[task({})]} currentView="studio" onJumpToView={vi.fn()} onDismiss={onDismiss} />);
    act(() => void vi.advanceTimersByTime(6000));
    expect(onDismiss).toHaveBeenCalledWith("i1");
  });

  it("an old timer cannot remove a relaunched task of the same type", () => {
    const onDismiss = vi.fn();
    const { rerender } = render(
      <FloatingTaskWidget tasks={[task({})]} currentView="studio" onJumpToView={vi.fn()} onDismiss={onDismiss} />
    );
    act(() => void vi.advanceTimersByTime(4000));
    // Same task type relaunched: new instance, running.
    rerender(
      <FloatingTaskWidget
        tasks={[task({ instanceId: "i2", status: "running" })]}
        currentView="studio"
        onJumpToView={vi.fn()}
        onDismiss={onDismiss}
      />
    );
    act(() => void vi.advanceTimersByTime(10_000));
    expect(onDismiss).not.toHaveBeenCalled();
    expect(screen.getByText("Swarm")).toBeTruthy();
  });

  it("clears pending timers on unmount", () => {
    const onDismiss = vi.fn();
    const { unmount } = render(
      <FloatingTaskWidget tasks={[task({})]} currentView="studio" onJumpToView={vi.fn()} onDismiss={onDismiss} />
    );
    unmount();
    act(() => void vi.advanceTimersByTime(10_000));
    expect(onDismiss).not.toHaveBeenCalled();
  });
});

describe("FloatingTaskWidget cancelled tasks", () => {
  it("shows a cancelled run as Cancelled (not Completed) and auto-dismisses it", () => {
    const onDismiss = vi.fn();
    render(
      <FloatingTaskWidget
        tasks={[task({ status: "cancelled", detail: "Cancelled - partial results only" })]}
        currentView="studio"
        onJumpToView={vi.fn()}
        onDismiss={onDismiss}
      />
    );
    expect(screen.getByText("Cancelled")).toBeTruthy();
    expect(screen.queryByText("Completed")).toBeNull();
    act(() => void vi.advanceTimersByTime(6000));
    expect(onDismiss).toHaveBeenCalledWith("i1");
  });
});
