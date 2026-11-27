import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import DocsPage from "./page";
import { DOC_CATEGORIES, DOC_FEATURES, DOCS_VERSION } from "@/lib/docs-features";

// next/link needs the app-router context; render a plain anchor in tests.
vi.mock("next/link", async () => {
  const React = await import("react");
  return {
    default: ({ href, children, ...rest }: { href: string } & Record<string, unknown>) =>
      React.createElement("a", { href: String(href), ...rest }, children as React.ReactNode),
  };
});

describe("DocsPage", () => {
  it("renders the heading with the version badge", () => {
    render(<DocsPage />);
    expect(
      screen.getByRole("heading", { level: 1, name: /ReadyHai documentation/i })
    ).toBeTruthy();
    expect(screen.getByText(`v${DOCS_VERSION}`)).toBeTruthy();
  });

  it("renders a section per category with its feature cards", () => {
    render(<DocsPage />);
    for (const category of DOC_CATEGORIES) {
      const heading = screen.getByRole("heading", { level: 2, name: category });
      expect(heading).toBeTruthy();
    }
    // A sample feature card from each end of the registry renders collapsed-open by default.
    expect(screen.getByText("Repository scanning")).toBeTruthy();
    expect(screen.getByText("CI/CD gating & release train")).toBeTruthy();
  });

  it("narrows results when the search filter matches a feature name", () => {
    render(<DocsPage />);
    const search = screen.getByRole("searchbox", { name: /search features/i });

    fireEvent.change(search, { target: { value: "wireguard" } });

    // "Network lab & WireGuard audit" matches; unrelated features disappear.
    expect(screen.getByText(/Network lab & WireGuard audit/)).toBeTruthy();
    expect(screen.queryByText("Repository scanning")).toBeNull();
    expect(screen.queryByText("Baselines")).toBeNull();
    // Only the matching category keeps its section heading.
    expect(screen.getAllByRole("heading", { level: 2 })).toHaveLength(1);
  });

  it("filters by tagline text too", () => {
    render(<DocsPage />);
    fireEvent.change(screen.getByRole("searchbox", { name: /search features/i }), {
      target: { value: "seeded" },
    });
    expect(screen.getByText(/Eval harness/)).toBeTruthy();
    expect(screen.queryByText(/Super Agent/)).toBeNull();
  });

  it("shows an empty state when nothing matches and recovers when cleared", () => {
    render(<DocsPage />);
    const search = screen.getByRole("searchbox", { name: /search features/i });

    fireEvent.change(search, { target: { value: "zzz-no-such-feature" } });
    expect(screen.getByText(/No features match/)).toBeTruthy();
    expect(screen.queryAllByRole("heading", { level: 2 })).toHaveLength(0);

    fireEvent.change(search, { target: { value: "" } });
    expect(screen.queryAllByRole("heading", { level: 2 })).toHaveLength(DOC_CATEGORIES.length);
  });

  it("links back to the studio and to the repository docs index", () => {
    render(<DocsPage />);
    const back = screen.getByRole("link", { name: /back to agent studio/i });
    expect(back.getAttribute("href")).toBe("/");
    const repo = screen.getByRole("link", { name: /repository docs index/i });
    expect(repo.getAttribute("href")).toBe(
      "https://github.com/deziss/readyhai/blob/main/docs/README.md"
    );
  });

  it("collapses and expands a feature card via its toggle", () => {
    render(<DocsPage />);
    const toggle = screen.getByRole("button", { name: /repository scanning/i });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByText(/46 built-in native readiness rules/)).toBeNull();
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(
      within(document.getElementById("repo-scanning")!).getByText(/46 built-in native readiness rules/)
    ).toBeTruthy();
  });
});

describe("DOC_FEATURES registry", () => {
  it("uses only known categories and unique ids", () => {
    const ids = new Set<string>();
    for (const feature of DOC_FEATURES) {
      expect(DOC_CATEGORIES).toContain(feature.category);
      expect(ids.has(feature.id)).toBe(false);
      ids.add(feature.id);
      expect(feature.whatItDoes.length).toBeGreaterThanOrEqual(3);
      expect(feature.howToUse.length).toBeGreaterThanOrEqual(1);
    }
  });
});
