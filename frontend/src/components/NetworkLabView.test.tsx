import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { NetworkLabView } from "./NetworkLabView";
import { apiRequest } from "@/lib/api";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, apiRequest: vi.fn() };
});

type Resolver = (v: { ok: false; error: string }) => void;

describe("NetworkLabView regressive lab", () => {
  let pendingRegress: Resolver | null;

  beforeEach(() => {
    pendingRegress = null;
    vi.mocked(apiRequest).mockImplementation(((url: string) => {
      if (url === "/api/network/regress") {
        return new Promise((resolve) => {
          pendingRegress = resolve as Resolver;
        });
      }
      return Promise.resolve({ ok: false, error: "not mocked" });
    }) as unknown as typeof apiRequest);
  });

  it("puts the Run regressive test button in the config panel, not the header", () => {
    const { container } = render(<NetworkLabView initialTarget="https://example.com" />);

    const buttons = screen.getAllByRole("button", { name: /Run regressive test/ });
    expect(buttons).toHaveLength(1);
    const runBtn = buttons[0];

    const aside = container.querySelector("aside");
    expect(aside).not.toBeNull();
    expect(aside?.textContent).toContain("Environment and target");
    expect(aside?.contains(runBtn)).toBe(true);

    // Header actions stay in the header; the primary action is no longer next to them.
    const exportHar = screen.getByRole("button", { name: /Export HAR/ });
    expect(aside?.contains(exportHar)).toBe(false);
    expect(exportHar.parentElement?.contains(runBtn)).toBe(false);

    // Full-width primary button.
    expect(runBtn.className).toContain("w-full");
    expect(runBtn.className).toContain("bg-rh-primary");
  });

  it("keeps the handler and the disabled/loading state", async () => {
    render(<NetworkLabView initialTarget="https://example.com" />);

    const runBtn = screen.getByRole("button", { name: /Run regressive test/ }) as HTMLButtonElement;
    expect(runBtn.disabled).toBe(false);

    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(vi.mocked(apiRequest)).toHaveBeenCalledWith(
        "/api/network/regress",
        expect.objectContaining({ method: "POST" }),
      );
    });

    const busy = (await screen.findByText(/Probing \(10x\)/)).closest("button") as HTMLButtonElement;
    expect(busy.id).toBe("btn-run-regress");
    expect(busy.disabled).toBe(true);

    pendingRegress?.({ ok: false, error: "boom" });
    await waitFor(() => expect(screen.getByText("Run regressive test")).toBeDefined());
  });

  it("does not render the run button on the other lab tabs", () => {
    render(<NetworkLabView initialTarget="https://example.com" />);
    fireEvent.click(screen.getByRole("button", { name: /PR status gate/ }));
    expect(screen.queryByRole("button", { name: /Run regressive test/ })).toBeNull();
  });
});
