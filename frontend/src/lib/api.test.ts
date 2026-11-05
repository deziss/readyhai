import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AUTH_REQUIRED_EVENT,
  TOKEN_STORAGE_KEY,
  UNAUTHORIZED_MESSAGE,
  apiFetch,
  REPORT_CSP,
  apiRequest,
  buildReportViewerHtml,
  cancelAgentRun,
  clearApiToken,
  getApiToken,
  setApiToken,
  withReportCsp,
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

describe("report hardening", () => {
  it("the report CSP allows no script at all", () => {
    expect(REPORT_CSP).not.toContain("script-src");
    expect(REPORT_CSP).toContain("default-src 'none'");
  });

  it("injects the CSP right after <head>, and not after <header>", () => {
    const withHead = withReportCsp("<html><head lang=\"en\"><title>t</title></head><body></body></html>");
    expect(withHead.indexOf("Content-Security-Policy")).toBeGreaterThan(withHead.indexOf("<head"));
    expect(withHead.indexOf("Content-Security-Policy")).toBeLessThan(withHead.indexOf("<title>"));
    const noHead = withReportCsp("<html><body><header>x</header></body></html>");
    expect(noHead).toMatch(/^<html><head><meta http-equiv="Content-Security-Policy"/);
    expect(withReportCsp("<p>x</p>").startsWith("<meta")).toBe(true);
  });

  it("the tab viewer wraps the report in an iframe sandboxed without scripts or same-origin", () => {
    const html = buildReportViewerHtml("blob:http://localhost/abc", 'Report "x" <b>');
    const iframe = html.match(/<iframe[^>]*>/)?.[0] ?? "";
    expect(iframe).toContain(" sandbox ");
    expect(iframe).not.toMatch(/sandbox="[^"]/);
    expect(html).not.toContain("allow-scripts");
    expect(html).not.toContain("allow-same-origin");
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;b&gt;");
    expect(html).toContain("frame-src blob:");
  });
});

describe("cancelAgentRun", () => {
  it("POSTs to the cancel route with the bearer token and the id encoded", async () => {
    setApiToken("tok");
    const fn = mockFetch(new Response(JSON.stringify({ id: "r1", status: "cancelling" }), { status: 202 }));
    const r = await cancelAgentRun("r 1/x");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.status).toBe("cancelling");
    const [url, init] = fn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/agent/runs/r%201%2Fx/cancel");
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer tok");
  });

  it("reports 404 (unknown run) and 409 (not running) as errors with the backend message", async () => {
    mockFetch(new Response(JSON.stringify({ error: "agent run not found" }), { status: 404 }));
    const nf = await cancelAgentRun("nope");
    expect(nf).toMatchObject({ ok: false, status: 404 });
    if (!nf.ok) expect(nf.error).toContain("agent run not found");
    mockFetch(new Response(JSON.stringify({ error: "run is not running (status: completed)" }), { status: 409 }));
    const nr = await cancelAgentRun("done");
    expect(nr).toMatchObject({ ok: false, status: 409 });
    if (!nr.ok) expect(nr.error).toContain("not running");
  });
});
