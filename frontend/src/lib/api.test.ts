import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AUTH_REQUIRED_EVENT,
  TOKEN_STORAGE_KEY,
  UNAUTHORIZED_MESSAGE,
  apiFetch,
  apiRequest,
  clearApiToken,
  getApiToken,
  setApiToken,
} from "./api";

function mockFetch(res: Response | Error) {
  const fn = vi.fn(async () => {
    if (res instanceof Error) throw res;
    return res;
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

beforeEach(() => {
  window.localStorage.clear();
  clearApiToken();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("token storage", () => {
  it("stores and trims the token in localStorage", () => {
    setApiToken("  abc123  ");
    expect(window.localStorage.getItem(TOKEN_STORAGE_KEY)).toBe("abc123");
    expect(getApiToken()).toBe("abc123");
  });

  it("clearing removes it", () => {
    setApiToken("abc");
    clearApiToken();
    expect(window.localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
    expect(getApiToken()).toBe("");
  });

  it("falls back to memory when storage throws", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(() => setApiToken("mem-token")).not.toThrow();
    expect(getApiToken()).toBe("mem-token");
  });
});

describe("apiFetch", () => {
  it("attaches the bearer header when a token is set", async () => {
    setApiToken("tok");
    const f = mockFetch(new Response("{}", { status: 200 }));
    await apiFetch("/api/x");
    const init = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init[1].headers).get("Authorization")).toBe("Bearer tok");
  });

  it("sends no Authorization header without a token", async () => {
    const f = mockFetch(new Response("{}", { status: 200 }));
    await apiFetch("/api/x");
    const init = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init[1].headers).has("Authorization")).toBe(false);
  });

  it("does not override an explicit Authorization header", async () => {
    setApiToken("tok");
    const f = mockFetch(new Response("{}", { status: 200 }));
    await apiFetch("/api/x", { headers: { Authorization: "Bearer other" } });
    const init = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init[1].headers).get("Authorization")).toBe("Bearer other");
  });

  it("dispatches the auth-required event on 401", async () => {
    mockFetch(new Response("", { status: 401 }));
    const handler = vi.fn();
    window.addEventListener(AUTH_REQUIRED_EVENT, handler);
    await apiFetch("/api/x");
    window.removeEventListener(AUTH_REQUIRED_EVENT, handler);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("does not dispatch the event on other statuses", async () => {
    mockFetch(new Response("", { status: 500 }));
    const handler = vi.fn();
    window.addEventListener(AUTH_REQUIRED_EVENT, handler);
    await apiFetch("/api/x");
    window.removeEventListener(AUTH_REQUIRED_EVENT, handler);
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("apiRequest", () => {
  it("returns parsed data on success", async () => {
    mockFetch(new Response(JSON.stringify({ a: 1 }), { status: 200 }));
    const r = await apiRequest<{ a: number }>("/api/x");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data).toEqual({ a: 1 });
  });

  it("maps 401 to the unauthorized message", async () => {
    mockFetch(new Response("", { status: 401 }));
    const r = await apiRequest("/api/x");
    expect(r).toMatchObject({ ok: false, status: 401, unauthorized: true, error: UNAUTHORIZED_MESSAGE });
  });

  it("surfaces backend error detail on non-2xx", async () => {
    mockFetch(new Response(JSON.stringify({ error: "boom" }), { status: 500 }));
    const r = await apiRequest("/api/x", { label: "Thing" });
    expect(r).toMatchObject({ ok: false, status: 500 });
    if (!r.ok) expect(r.error).toBe("Thing failed (HTTP 500): boom");
  });

  it("never throws on network failure", async () => {
    mockFetch(new Error("offline"));
    const r = await apiRequest("/api/x");
    expect(r).toMatchObject({ ok: false, status: 0 });
  });
});
