import { afterEach, describe, expect, it, vi } from "vitest";
import { NOTICE_EVENT } from "./api";
import { copyTextSafely } from "./clipboard";

function collectNotices() {
  const seen: string[] = [];
  const h = (e: Event) => seen.push((e as CustomEvent<{ message: string }>).detail.message);
  window.addEventListener(NOTICE_EVENT, h);
  return { seen, stop: () => window.removeEventListener(NOTICE_EVENT, h) };
}

afterEach(() => {
  Object.assign(navigator, { clipboard: undefined });
  Reflect.deleteProperty(document, "execCommand");
});

describe("copyTextSafely", () => {
  it("uses navigator.clipboard when available", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    expect(await copyTextSafely("hello")).toBe(true);
    expect(writeText).toHaveBeenCalledWith("hello");
  });

  it("falls back to execCommand when the clipboard API is missing (plain http)", async () => {
    Object.assign(navigator, { clipboard: undefined });
    const exec = vi.fn().mockReturnValue(true);
    Object.defineProperty(document, "execCommand", { value: exec, configurable: true });
    const n = collectNotices();
    expect(await copyTextSafely("hello")).toBe(true);
    n.stop();
    expect(exec).toHaveBeenCalledWith("copy");
    expect(n.seen).toEqual([]);
  });

  it("falls back when writeText rejects, and notifies when everything fails", async () => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    const n = collectNotices();
    expect(await copyTextSafely("hello", "The patch")).toBe(false);
    n.stop();
    expect(n.seen).toHaveLength(1);
    expect(n.seen[0]).toContain("The patch could not be copied");
  });

  it("never throws when execCommand throws", async () => {
    Object.assign(navigator, { clipboard: undefined });
    Object.defineProperty(document, "execCommand", {
      value: () => {
        throw new Error("nope");
      },
      configurable: true,
    });
    await expect(copyTextSafely("x")).resolves.toBe(false);
  });
});
