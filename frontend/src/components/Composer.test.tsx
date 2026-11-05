import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Composer } from "./Composer";

function renderComposer(overrides: Partial<React.ComponentProps<typeof Composer>> = {}) {
  const props: React.ComponentProps<typeof Composer> = {
    target: "http://localhost:3000",
    setTarget: vi.fn(),
    specUrl: "",
    setSpecUrl: vi.fn(),
    directives: "Strict QA",
    setDirectives: vi.fn(),
    profile: "standard",
    setProfile: vi.fn(),
    maxSteps: 15,
    setMaxSteps: vi.fn(),
    onDiscover: vi.fn(async () => {}),
    isDiscovering: false,
    onCrawl: vi.fn(async () => {}),
    isCrawling: false,
    discoveredData: null,
    onLaunch: vi.fn(async () => {}),
    isRunning: false,
    thinking: true,
    setThinking: vi.fn(),
    modelTier: "high",
    setModelTier: vi.fn(),
    thinkingBudget: 8192,
    setThinkingBudget: vi.fn(),
    onOpenAgentHistory: vi.fn(),
    ...overrides,
  };
  return { props, ...render(<Composer {...props} />) };
}

beforeEach(() => {
  // The component asks the backend for the requester IP on mount.
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ egress_public_ip: "203.0.113.7", ip_type: "public", allowlist_guidance: "" })))
  );
});

describe("Composer layout", () => {
  it("pins the mode tabs on top and the Run agent button at the bottom, with only the controls scrolling", () => {
    renderComposer();
    const modes = screen.getByRole("radiogroup", { name: "Testing mode" });
    const launch = screen.getByRole("button", { name: /Run agent/ });
    const target = screen.getByLabelText("Target URL");

    const scroller = target.closest<HTMLElement>("[class*=overflow-y-auto]");
    expect(scroller).toBeTruthy();
    expect(scroller!.className).toContain("min-h-0");
    expect(scroller!.className).toContain("flex-1");
    // Neither the mode tabs nor the launch button live inside the scrolling region.
    expect(scroller!.contains(modes)).toBe(false);
    expect(scroller!.contains(launch)).toBe(false);
    // They sit in shrink-0 bars on either side of it.
    expect(modes.closest(".shrink-0")).toBeTruthy();
    expect(launch.closest(".shrink-0")).toBeTruthy();
    // The panel itself is a clipped flex column so the page never double-scrolls.
    const panel = scroller!.parentElement!;
    expect(panel.className).toContain("flex-col");
    expect(panel.className).toContain("min-h-0");
    expect(panel.className).toContain("overflow-hidden");
  });

  it("does not host the release gate: sign-off belongs to the workspace", () => {
    renderComposer();
    expect(screen.queryByText("Release gate")).toBeNull();
    expect(screen.queryByText("Approve release")).toBeNull();
  });
});

describe("Composer behaviour", () => {
  it("launches the agent and shows progress while running", () => {
    const { props, rerender } = renderComposer();
    fireEvent.click(screen.getByRole("button", { name: "Run agent" }));
    expect(props.onLaunch).toHaveBeenCalledTimes(1);

    rerender(<Composer {...props} isRunning />);
    const busy = screen.getByRole("button", { name: /Running agent/ }) as HTMLButtonElement;
    expect(busy.disabled).toBe(true);
  });

  it("switching mode rewrites the directives, with arrow-key navigation", () => {
    const { props } = renderComposer();
    const radios = screen.getAllByRole("radio").filter((r) => r.tagName === "BUTTON");
    expect(radios.map((r) => r.getAttribute("aria-checked"))).toEqual(["true", "false", "false"]);

    fireEvent.click(radios[1]);
    expect(props.setDirectives).toHaveBeenLastCalledWith(expect.stringContaining("authorization bypass"));

    fireEvent.keyDown(radios[1], { key: "ArrowRight" });
    expect(props.setDirectives).toHaveBeenLastCalledWith(expect.stringContaining("OpenAPI contract"));
    expect(radios[2].getAttribute("aria-checked")).toBe("true");
  });

  it("picking a model tier also sets the reasoning budget", () => {
    const { props } = renderComposer();
    fireEvent.click(screen.getByLabelText(/Max Pro/));
    expect(props.setModelTier).toHaveBeenCalledWith("max_pro");
    expect(props.setThinkingBudget).toHaveBeenCalledWith(32768);
  });

  it("uses plain, sentence-case copy with no arrows", () => {
    const { container } = renderComposer();
    expect(screen.getByText("Agent command center")).toBeTruthy();
    expect(container.textContent).not.toMatch(/→|->/);
    expect(container.querySelector(".uppercase")).toBeNull();
  });
});
