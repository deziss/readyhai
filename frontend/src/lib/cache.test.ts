import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CACHE_STALE_MS,
  cacheStatus,
  clearCache,
  invalidate,
  readCache,
  writeCache,
} from "./cache";

beforeEach(() => {
  window.localStorage.clear();
  clearCache();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("read/write cache", () => {
  it("round-trips a value and reports its age", () => {
    const now = Date.parse("2026-01-20T12:00:00Z");
    writeCache("/api/scans", { ok: 1 }, now);
    const hit = readCache<{ ok: number }>("/api/scans", now + 60_000);
    expect(hit?.data).toEqual({ ok: 1 });
    expect(hit?.stale).toBe(false);
    expect(readCache("/api/scans", now + CACHE_STALE_MS + 1_000)?.stale).toBe(true);
  });

  it("persists an envelope that carries its own key and timestamp", () => {
    const now = Date.parse("2026-01-20T12:00:00Z");
    writeCache("/api/agent/runs", [1, 2], now);
    const raw = window.localStorage.getItem("readyhai_cache_v1:/api/agent/runs");
    expect(JSON.parse(raw ?? "{}")).toEqual({ key: "/api/agent/runs", ts: now, data: [1, 2] });
  });

  it("ignores a stored entry whose key does not match", () => {
    const now = Date.parse("2026-01-20T12:00:00Z");
    window.localStorage.setItem(
      "readyhai_cache_v1:/api/x",
      JSON.stringify({ key: "/api/other", ts: now, data: { bad: true } })
    );
    expect(readCache("/api/x", now)).toBeNull();
  });

  it("rejects a future-dated or corrupt entry", () => {
    const now = Date.parse("2026-01-20T12:00:00Z");
    window.localStorage.setItem(
      "readyhai_cache_v1:/api/future",
      JSON.stringify({ key: "/api/future", ts: now + 3_600_000, data: 1 })
    );
    expect(readCache("/api/future", now)).toBeNull();

    window.localStorage.setItem("readyhai_cache_v1:/api/junk", "{not json");
    expect(readCache("/api/junk", now)).toBeNull();
  });
});

describe("invalidate", () => {
  it("drops keys by prefix and leaves the rest", () => {
    const now = Date.parse("2026-01-20T12:00:00Z");
    writeCache("/api/agent/runs", [1], now);
    writeCache("/api/agent/runs/r-9", { id: "r-9" }, now);
    writeCache("/api/scans", [], now);

    invalidate("/api/agent/runs");

    expect(readCache("/api/agent/runs", now)).toBeNull();
    expect(readCache("/api/agent/runs/r-9", now)).toBeNull();
    expect(readCache("/api/scans", now)?.data).toEqual([]);
    expect(window.localStorage.getItem("readyhai_cache_v1:/api/scans")).not.toBeNull();
  });

  it("clears everything when no prefix is given", () => {
    const now = Date.parse("2026-01-20T12:00:00Z");
    writeCache("/api/a", 1, now);
    clearCache();
    expect(readCache("/api/a", now)).toBeNull();
    expect(cacheStatus(now)).toEqual({ keys: 0, bytes: 0, oldest: null });
  });
});

describe("cacheStatus", () => {
  it("counts keys, bytes and the oldest entry", () => {
    const now = Date.parse("2026-01-20T12:00:00Z");
    writeCache("/api/a", "x", now - 5_000);
    writeCache("/api/b", "yy", now);
    const status = cacheStatus(now);
    expect(status.keys).toBe(2);
    expect(status.bytes).toBeGreaterThan(0);
    expect(status.oldest).toBe(5_000);
  });
});
