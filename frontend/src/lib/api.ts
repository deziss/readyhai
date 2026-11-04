import { useSyncExternalStore } from "react";

/**
 * Small API helper for the ReadyHai backend.
 *
 * Every /api route (except /health) requires `Authorization: Bearer <token>`.
 * The token is entered in the Settings dialog and kept in localStorage; if
 * storage is blocked it is kept in memory for the current page session.
 */

export const TOKEN_STORAGE_KEY = "readyhai_api_token";

export const AUTH_REQUIRED_EVENT = "readyhai:auth-required";
export const NOTICE_EVENT = "readyhai:notice";
export const OPEN_SETTINGS_EVENT = "readyhai:open-settings";

export const UNAUTHORIZED_MESSAGE =
  "Unauthorized (401): set your API token. Open Settings (key icon in the header), paste the backend bearer token, then retry.";

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

let memoryToken = "";
let tokenVersion = 0;
const tokenListeners = new Set<() => void>();

function emitTokenChanged() {
  tokenVersion += 1;
  tokenListeners.forEach((l) => l());
}

function subscribeToken(cb: () => void) {
  tokenListeners.add(cb);
  return () => {
    tokenListeners.delete(cb);
  };
}

export function getApiToken(): string {
  let stored: string | null = null;
  try {
    stored = window.localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    stored = null;
  }
  return (stored ?? memoryToken).trim();
}

export function setApiToken(token: string): void {
  const clean = token.trim();
  memoryToken = clean;
  try {
    if (clean) window.localStorage.setItem(TOKEN_STORAGE_KEY, clean);
    else window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Storage blocked: the in-memory copy still works for this session.
  }
  emitTokenChanged();
}

export function clearApiToken(): void {
  setApiToken("");
}

/** Printable ASCII without whitespace: the only thing a bearer header can carry safely. */
export function isValidTokenFormat(token: string): boolean {
  return /^[\x21-\x7e]+$/.test(token);
}

/** Current token string (re-renders when it changes). */
export function useApiToken(): string {
  return useSyncExternalStore(subscribeToken, getApiToken, () => "");
}

/** Monotonic counter that changes whenever the token is set or cleared. */
export function useApiTokenVersion(): number {
  return useSyncExternalStore(
    subscribeToken,
    () => tokenVersion,
    () => 0
  );
}

export function getApiTokenVersion(): number {
  return tokenVersion;
}

// ---------------------------------------------------------------------------
// Notices (cross-component error surfacing)
// ---------------------------------------------------------------------------

export type NoticeKind = "error" | "info";

export function notify(message: string, kind: NoticeKind = "error"): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(NOTICE_EVENT, { detail: { message, kind } }));
}

export function openSettings(): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(OPEN_SETTINGS_EVENT));
}

function emitAuthRequired() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(AUTH_REQUIRED_EVENT, { detail: { version: tokenVersion } }));
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---------------------------------------------------------------------------
// Fetch wrappers
// ---------------------------------------------------------------------------

/** fetch() with the bearer token attached. Emits an auth-required event on 401. */
export async function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = getApiToken();
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const res = await fetch(input, { ...init, headers });
  if (res.status === 401) emitAuthRequired();
  return res;
}

async function readErrorDetail(res: Response): Promise<string> {
  let text = "";
  try {
    text = (await res.text()).trim();
  } catch {
    text = "";
  }
  if (!text) return res.statusText || "no details returned";
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object") {
      const obj = parsed as { error?: unknown; message?: unknown };
      const m = obj.error ?? obj.message;
      if (typeof m === "string" && m) return m;
      if (m !== undefined && m !== null) return JSON.stringify(m).slice(0, 300);
    }
  } catch {
    // not JSON; fall through to raw text
  }
  return text.length > 300 ? `${text.slice(0, 300)}...` : text;
}

export interface ApiRequestInit extends Omit<RequestInit, "body"> {
  /** JSON-serialisable request body; sets Content-Type. */
  json?: unknown;
  body?: BodyInit | null;
  /** Human label used in error messages, e.g. "Deep audit". */
  label?: string;
}

export type ApiResult<T> =
  | { ok: true; data: T; status: number }
  | { ok: false; error: string; status: number; unauthorized: boolean };

/**
 * Request + JSON parse with uniform error handling. Never throws: a network
 * failure, non-2xx response or unparsable body all come back as `{ ok: false }`
 * with a message that can be shown to the user.
 */
export async function apiRequest<T = unknown>(
  path: string,
  init: ApiRequestInit = {}
): Promise<ApiResult<T>> {
  const { json, label, ...rest } = init;
  const what = label ?? "Request";
  const headers = new Headers(rest.headers);
  let body = rest.body;
  if (json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(json);
  }

  let res: Response;
  try {
    res = await apiFetch(path, { ...rest, headers, body });
  } catch (e) {
    return { ok: false, status: 0, unauthorized: false, error: `${what} failed: ${errorText(e)}` };
  }

  if (res.status === 401) {
    return { ok: false, status: 401, unauthorized: true, error: UNAUTHORIZED_MESSAGE };
  }
  if (!res.ok) {
    const detail = await readErrorDetail(res);
    return {
      ok: false,
      status: res.status,
      unauthorized: false,
      error: `${what} failed (HTTP ${res.status}): ${detail}`,
    };
  }

  let text = "";
  try {
    text = await res.text();
  } catch (e) {
    return { ok: false, status: res.status, unauthorized: false, error: `${what} failed: ${errorText(e)}` };
  }
  if (!text.trim()) return { ok: true, data: null as T, status: res.status };
  try {
    return { ok: true, data: JSON.parse(text) as T, status: res.status };
  } catch {
    return {
      ok: false,
      status: res.status,
      unauthorized: false,
      error: `${what} failed: backend returned a response that is not valid JSON`,
    };
  }
}

// ---------------------------------------------------------------------------
// Authenticated file access (reports). Plain <a href> / <iframe src> cannot
// send an Authorization header, so reports are fetched and shown as blobs.
// ---------------------------------------------------------------------------

/** Same policy the backend sets on its HTML reports; re-applied because blob URLs lose headers. */
const REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline'";

function withReportCsp(html: string): string {
  const meta = `<meta http-equiv="Content-Security-Policy" content="${REPORT_CSP}">`;
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, (m) => `${m}${meta}`);
  if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, (m) => `${m}<head>${meta}</head>`);
  return `${meta}${html}`;
}

export type BlobResult = { ok: true; blob: Blob } | { ok: false; error: string };

export async function fetchReportBlob(path: string, label = "Report"): Promise<BlobResult> {
  let res: Response;
  try {
    res = await apiFetch(path);
  } catch (e) {
    return { ok: false, error: `${label} failed: ${errorText(e)}` };
  }
  if (res.status === 401) return { ok: false, error: UNAUTHORIZED_MESSAGE };
  if (!res.ok) {
    const detail = await readErrorDetail(res);
    return { ok: false, error: `${label} failed (HTTP ${res.status}): ${detail}` };
  }
  const type = res.headers.get("content-type") || "application/octet-stream";
  try {
    if (type.toLowerCase().includes("text/html")) {
      const html = withReportCsp(await res.text());
      return { ok: true, blob: new Blob([html], { type: "text/html;charset=utf-8" }) };
    }
    return { ok: true, blob: await res.blob() };
  } catch (e) {
    return { ok: false, error: `${label} failed: ${errorText(e)}` };
  }
}

/** Open an authenticated report in a new tab. Resolves to an error message, or null on success. */
export async function openAuthedInTab(path: string, label = "Report"): Promise<string | null> {
  // Open synchronously (inside the click gesture) so popup blockers allow it.
  const win = window.open("", "_blank");
  if (!win) return "The browser blocked the new tab. Allow pop-ups for this site and try again.";
  try {
    win.opener = null;
  } catch {
    // ignore
  }
  const r = await fetchReportBlob(path, label);
  if (!r.ok) {
    win.close();
    return r.error;
  }
  const url = URL.createObjectURL(r.blob);
  win.location.href = url;
  window.setTimeout(() => URL.revokeObjectURL(url), 5 * 60 * 1000);
  return null;
}

/** Download an authenticated file. Resolves to an error message, or null on success. */
export async function downloadAuthed(path: string, filename: string, label = "Download"): Promise<string | null> {
  const r = await fetchReportBlob(path, label);
  if (!r.ok) return r.error;
  const url = URL.createObjectURL(r.blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
  return null;
}
