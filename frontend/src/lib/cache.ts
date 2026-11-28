"use client";

import { useCallback, useEffect, useSyncExternalStore } from "react";
import { apiRequest, getApiTokenVersion, type ApiResult } from "./api";
import { pollIntervalMs, usePrefs } from "./prefs";

/**
 * Read-through cache for backend GETs.
 *
 * The problem it solves: every view used to refetch from zero on mount, so a refresh or a tab
 * switch blanked the panel and replayed a spinner even though the data had not changed. Here the
 * last good response renders immediately from memory or localStorage, and a fresh copy is fetched
 * in the background and swapped in when it differs.
 *
 * What it deliberately does NOT do: cache anything a POST changes silently. Mutating calls carry a
 * run id, so `invalidate(prefix)` is exposed and the views that write call it. Cached data is also
 * scoped to the API token version: switching tokens drops the visible cache, so one operator's runs
 * are never shown under another operator's token.
 */

const INDEX_KEY = "readyhai_cache_index_v1";
const PREFIX = "readyhai_cache_v1:";
/** Entries this old are not painted from storage; they are only a fallback when the network fails. */
export const CACHE_STALE_MS = 10 * 60_000;
/** Entries older than this are dropped from storage entirely. */
export const CACHE_MAX_AGE_MS = 24 * 60 * 60_000;
/** Most keys kept in localStorage; least recently used are evicted first. */
export const CACHE_MAX_KEYS = 60;
/** Ceiling on one stored value. Bigger payloads stay in memory for the session only. */
const MAX_STORED_BYTES = 400_000;

interface IndexEntry {
  key: string;
  /** Epoch ms of the last successful write. */
  ts: number;
  bytes: number;
}

interface MemoryEntry {
  ts: number;
  data: unknown;
  bytes: number;
}

const memory = new Map<string, MemoryEntry>();
let index: IndexEntry[] | null = null;
let tokenScope = -1;

const listeners = new Set<() => void>();

function emit(): void {
  version += 1;
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

/**
 * Monotonic counter bumped on every cache write or invalidation. Components that read the cache
 * directly (rather than through useCachedApi) subscribe to this so a background update repaints them.
 */
let version = 0;

export function getCacheVersion(): number {
  return version;
}

export function useCacheVersion(): number {
  return useSyncExternalStore(
    subscribe,
    () => version,
    () => 0
  );
}

function readIndex(): IndexEntry[] {
  if (index !== null) return index;
  try {
    const raw = window.localStorage.getItem(INDEX_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    index = Array.isArray(parsed)
      ? parsed.filter(
          (e): e is IndexEntry =>
            !!e &&
            typeof e === "object" &&
            typeof (e as IndexEntry).key === "string" &&
            typeof (e as IndexEntry).ts === "number" &&
            typeof (e as IndexEntry).bytes === "number"
        )
      : [];
  } catch {
    index = [];
  }
  return index;
}

function writeIndex(entries: IndexEntry[]): void {
  index = entries;
  try {
    window.localStorage.setItem(INDEX_KEY, JSON.stringify(entries));
  } catch {
    // storage blocked or full: the in-memory cache still works
  }
}

/**
 * Removes entries that expired, then the least recently written keys, until the limits hold.
 * Runs on every write so a long-lived tab cannot grow storage without bound.
 */
function enforceLimits(now: number): void {
  const drop = (e: IndexEntry) => {
    try {
      window.localStorage.removeItem(PREFIX + e.key);
    } catch {
      // ignore
    }
    memory.delete(e.key);
  };
  let entries: IndexEntry[] = [];
  for (const e of readIndex()) {
    if (now - e.ts <= CACHE_MAX_AGE_MS && e.ts <= now + 60_000) entries.push(e);
    else drop(e);
  }
  while (entries.length > CACHE_MAX_KEYS) {
    const oldest = [...entries].sort((a, b) => a.ts - b.ts)[0];
    if (!oldest) break;
    drop(oldest);
    entries = entries.filter((e) => e.key !== oldest.key);
  }
  writeIndex(entries);
}

/** Restores one key from storage when memory does not hold it. */
function hydrate(key: string, now: number): MemoryEntry | null {
  // A new token means nothing cached under the previous operator may be shown, memory included.
  const tokenVersion = getApiTokenVersion();
  if (tokenScope !== tokenVersion) {
    tokenScope = tokenVersion;
    memory.clear();
    index = null;
  }
  const hit = memory.get(key);
  if (hit) return hit;
  try {
    const raw = window.localStorage.getItem(PREFIX + key);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const entry = parsed as { key?: unknown; ts?: unknown; data?: unknown };
    if (entry.key !== key || typeof entry.ts !== "number" || !Number.isFinite(entry.ts)) return null;
    if (now - entry.ts > CACHE_MAX_AGE_MS || entry.ts > now + 60_000) return null;
    const loaded: MemoryEntry = { ts: entry.ts, data: entry.data, bytes: raw.length };
    memory.set(key, loaded);
    return loaded;
  } catch {
    return null;
  }
}

export interface CacheHit<T> {
  data: T;
  /** Epoch ms of the response. */
  ts: number;
  /** True when the response is older than CACHE_STALE_MS. */
  stale: boolean;
}

export function readCache<T = unknown>(key: string, now = Date.now()): CacheHit<T> | null {
  if (typeof window === "undefined") return null;
  const hit = hydrate(key, now);
  if (!hit) return null;
  return { data: hit.data as T, ts: hit.ts, stale: now - hit.ts > CACHE_STALE_MS };
}

export function writeCache<T = unknown>(key: string, data: T, now = Date.now()): void {
  if (typeof window === "undefined") return;
  let bytes = 0;
  let serialized = "";
  try {
    serialized = JSON.stringify(data);
    bytes = serialized.length;
  } catch {
    return; // not serialisable: nothing to cache
  }
  memory.set(key, { ts: now, data, bytes });
  if (bytes <= MAX_STORED_BYTES) {
    try {
      window.localStorage.setItem(PREFIX + key, JSON.stringify({ key, ts: now, data }));
    } catch {
      // Quota: evict what we know about and try once more before giving up quietly.
      try {
        enforceLimits(now);
        window.localStorage.setItem(PREFIX + key, JSON.stringify({ key, ts: now, data }));
      } catch {
        // still no room: memory-only for this key
      }
    }
    const rest = readIndex().filter((e) => e.key !== key);
    rest.push({ key, ts: now, bytes });
    writeIndex(rest);
  }
  enforceLimits(now);
  emit();
}

/** Forgets published snapshots so panels stop showing data that was just invalidated. */
function resetRecords(prefix = ""): void {
  for (const [key, rec] of records) {
    if (!key.startsWith(prefix)) continue;
    rec.loading = false;
    rec.error = null;
    rec.data = undefined;
    rec.hasData = false;
    rec.fromNetwork = false;
    rec.ts = null;
    rec.stale = false;
    bump(rec);
  }
}

/** Drops every cached key that starts with `prefix`, so the next read refetches. */
export function invalidate(prefix = ""): void {
  if (typeof window === "undefined") return;
  // Force the next read to re-check the token scope and rebuild the index from storage.
  tokenScope = -1;
  index = null;
  const drop = readIndex().filter((e) => e.key.startsWith(prefix));
  for (const e of drop) {
    try {
      window.localStorage.removeItem(PREFIX + e.key);
    } catch {
      // ignore
    }
    memory.delete(e.key);
  }
  writeIndex(readIndex().filter((e) => !e.key.startsWith(prefix)));
  resetRecords(prefix);
  emit();
}

export function clearCache(): void {
  if (typeof window === "undefined") return;
  tokenScope = -1;
  index = null;
  for (const e of readIndex()) {
    try {
      window.localStorage.removeItem(PREFIX + e.key);
    } catch {
      // ignore
    }
  }
  writeIndex([]);
  memory.clear();
  resetRecords();
  emit();
}

/** Keys the user can see in Settings, with age, so clearing is not a blind act. */
export function cacheStatus(now = Date.now()): { keys: number; bytes: number; oldest: number | null } {
  if (typeof window === "undefined") return { keys: 0, bytes: 0, oldest: null };
  const entries = readIndex();
  return {
    keys: entries.length,
    bytes: entries.reduce((sum, e) => sum + e.bytes, 0),
    // Age of the oldest entry: how far behind the oldest number on screen could be.
    oldest: entries.length ? now - Math.min(...entries.map((e) => e.ts)) : null,
  };
}

/**
 * Cached fetch. Serves the cached value when it is younger than `ttl`, otherwise refetches; a failed
 * refetch falls back to the stale value rather than reporting an error the UI cannot act on.
 */
export async function cachedRequest<T>(
  path: string,
  options: { ttlMs?: number; label?: string; force?: boolean } = {}
): Promise<{ result: ApiResult<T>; cached: boolean; ts: number }> {
  const { ttlMs = CACHE_STALE_MS, label, force = false } = options;
  const now = Date.now();
  const hit = readCache<T>(path, now);
  if (hit && !force && now - hit.ts <= ttlMs) {
    return { result: { ok: true, data: hit.data, status: 200 }, cached: true, ts: hit.ts };
  }
  const started: Promise<{ result: ApiResult<T>; cached: boolean; ts: number }> = (async () => {
    const result = await apiRequest<T>(path, { label });
    if (result.ok) {
      writeCache(path, result.data);
      return { result, cached: false, ts: Date.now() };
    }
    if (hit) {
      // The value on disk may be older than the TTL, but it is better than losing the panel.
      return { result: { ok: true, data: hit.data, status: 200 }, cached: true, ts: hit.ts };
    }
    return { result, cached: false, ts: Date.now() };
  })();
  return await started;
}

export interface CachedState<T> {
  /** Cached or fresh data; null on a cold cache before the first response. */
  data: T | null;
  /** True until the first settle, so the caller can tell "cold" from "empty". */
  loading: boolean;
  /** Data came from the cache rather than this request. */
  cached: boolean;
  stale: boolean;
  ts: number | null;
  /** Set only when there was nothing cached AND the request failed. */
  error: string | null;
  /** Refetch, ignoring the TTL. */
  refresh: () => Promise<void>;
}

/**
 * Per-key store record.
 *
 * Panels subscribe to these records instead of holding their own copy of the response. That keeps
 * one number on screen in exactly one place: two panels reading the same key share a snapshot, and
 * an update notifies subscribers from the fetch continuation rather than from a component effect.
 */
interface KeyRecord {
  loading: boolean;
  error: string | null;
  /** Last published payload, kept so an unchanged refetch does not re-render panels. */
  data: unknown;
  hasData: boolean;
  fromNetwork: boolean;
  ts: number | null;
  stale: boolean;
  /** Frozen snapshot handed to useSyncExternalStore; nulled whenever anything below changes. */
  snap: CachedState<unknown> | null;
  listeners: Set<() => void>;
}

const records = new Map<string, KeyRecord>();

function record(key: string): KeyRecord {
  let rec = records.get(key);
  if (!rec) {
    rec = {
      loading: false,
      error: null,
      data: undefined,
      hasData: false,
      fromNetwork: false,
      ts: null,
      stale: false,
      snap: null,
      listeners: new Set(),
    };
    records.set(key, rec);
  }
  return rec;
}

function bump(rec: KeyRecord): void {
  rec.snap = null;
  rec.listeners.forEach((l) => l());
}

/**
 * Publishes a settled response. Kept out of `run` so the store's current values are read fresh:
 * inside `run`, TypeScript still holds the `loading = true` narrowing across the await.
 */
function finish(
  rec: KeyRecord,
  update: { error?: string | null; data?: unknown; ts?: number; stale?: boolean; fromNetwork?: boolean; keepData?: boolean }
): void {
  let changed = false;
  if (update.data !== undefined && !update.keepData) {
    rec.data = update.data;
    rec.hasData = true;
    changed = true;
  }
  const next: Partial<KeyRecord> = { loading: false };
  if (update.error !== undefined) next.error = update.error;
  if (update.ts !== undefined) next.ts = update.ts;
  if (update.stale !== undefined) next.stale = update.stale;
  if (update.fromNetwork !== undefined) next.fromNetwork = update.fromNetwork;
  for (const [k, v] of Object.entries(next)) {
    const key = k as keyof KeyRecord;
    if (rec[key] !== v) {
      (rec as unknown as Record<string, unknown>)[k] = v;
      changed = true;
    }
  }
  if (changed) bump(rec);
}

/**
 * Requests already in flight, so two panels reading one key cost one round trip.
 */
const flights = new Map<string, Promise<void>>();

/**
 * Fetches one key into the store. Updates happen in the await continuations only, which is what
 * keeps a mount to a single paint: the effect that starts this call never sets state itself.
 */
function run<T>(key: string, ttlMs: number | undefined, label: string | undefined, force: boolean): Promise<void> {
  const running = flights.get(key);
  if (running) return running;
  const rec = record(key);
  const flight = (async () => {
    if (!rec.loading) {
      rec.loading = true;
      bump(rec);
    }
    const { result, cached, ts } = await cachedRequest<T>(key, { ttlMs, label, force });
    if (!result.ok) {
      // A refetch that failed while a stale copy exists is not an error the UI can act on.
      finish(rec, { error: readCache<T>(key) ? null : result.error });
      return;
    }
    // An identical payload keeps the published object, so panels whose data did not actually
    // change skip the re-render; only the age moves.
    const same = rec.hasData && JSON.stringify(rec.data) === JSON.stringify(result.data);
    finish(rec, {
      data: result.data,
      ts,
      stale: Date.now() - ts > CACHE_STALE_MS,
      fromNetwork: !cached,
      keepData: same,
    });
  })().finally(() => {
    flights.delete(key);
  });
  flights.set(key, flight);
  return flight;
}

/**
 * Snapshot for useSyncExternalStore. Must return the identical object until something changes, so
 * the value is frozen into the record and only rebuilt after a bump.
 */
function snapshot<T>(key: string): CachedState<T> {
  const rec = record(key);
  if (rec.snap) return rec.snap as CachedState<T>;
  if (!rec.hasData && !rec.loading) {
    // First read for this key: paint straight from storage, then validate in the background.
    const hit = readCache<T>(key);
    if (hit) {
      rec.data = hit.data;
      rec.hasData = true;
      rec.ts = hit.ts;
      rec.stale = hit.stale;
      rec.fromNetwork = false;
    }
  }
  rec.snap = {
    data: rec.hasData ? (rec.data as T) : null,
    loading: !rec.hasData,
    cached: !rec.fromNetwork,
    stale: rec.stale,
    ts: rec.ts,
    error: rec.error,
    refresh: () => run<T>(key, undefined, undefined, true),
  };
  return rec.snap as CachedState<T>;
}

function subscribeKey(key: string, cb: () => void): () => void {
  const rec = record(key);
  rec.listeners.add(cb);
  return () => {
    rec.listeners.delete(cb);
  };
}

/** Returned when a panel passes a null path, so it stays in its cold state. */
const PARKED: CachedState<unknown> = {
  data: null,
  loading: true,
  cached: false,
  stale: false,
  ts: null,
  error: null,
  refresh: () => Promise.resolve(),
};

/**
 * Hook form of cachedRequest. The first paint comes from cache when there is one; the network
 * update lands afterwards and only re-renders when the payload actually changed. Pass a null path
 * to park the panel.
 */
export function useCachedApi<T>(
  path: string | null,
  options: { ttlMs?: number; label?: string; pollMs?: number | null } = {}
): CachedState<T> {
  const { ttlMs, label, pollMs } = options;
  const key = path ?? "__parked__";
  const subscribe = useCallback((cb: () => void) => subscribeKey(key, cb), [key]);
  const read = useCallback(() => (path ? snapshot(path) : PARKED), [path]);
  const snap = useSyncExternalStore<unknown>(subscribe, read, () => PARKED);

  const parked = path === null;
  useEffect(() => {
    if (parked) return;
    void run(path as string, ttlMs, label, false);
  }, [parked, path, ttlMs, label]);

  // Revalidate when the token changes: the previous operator's cache is already cleared, so
  // without this the panel would sit on an empty cache until a manual refresh. Refetch when the
  // tab becomes visible again too, which is the moment the data is about to be looked at.
  useEffect(() => {
    if (parked) return;
    const p = path as string;
    const bump = () => void run(p, ttlMs, label, true);
    const onVisible = () => {
      if (document.visibilityState === "visible") void run(p, ttlMs, label, false);
    };
    window.addEventListener("readyhai:token-changed", bump);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.removeEventListener("readyhai:token-changed", bump);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [parked, path, ttlMs, label]);

  const prefs = usePrefs();
  const intervalMs = pollMs === undefined ? pollIntervalMs(prefs) : pollMs;
  useEffect(() => {
    if (parked || intervalMs === null) return;
    const p = path as string;
    const id = window.setInterval(() => {
      if (document.visibilityState === "hidden") return;
      void run(p, ttlMs, label, true);
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [parked, path, ttlMs, label, intervalMs]);

  return snap as CachedState<T>;
}

