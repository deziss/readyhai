"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Info, KeyRound, X } from "lucide-react";
import {
  AUTH_REQUIRED_EVENT,
  NOTICE_EVENT,
  UNAUTHORIZED_MESSAGE,
  getApiTokenVersion,
  openSettings,
  useApiToken,
  useApiTokenVersion,
} from "@/lib/api";

interface Notice {
  id: number;
  message: string;
  kind: "error" | "info";
}

let nextNoticeId = 1;

/**
 * Page-level banner strip: the "set your API token" prompt (shown after any 401)
 * and dismissible error notices raised by `notify()`.
 */
export function GlobalNotices() {
  const version = useApiTokenVersion();
  const token = useApiToken();
  // Token version at which the last 401 happened. The banner hides itself as soon
  // as the token changes (version differs) and returns on the next 401.
  const [authFailedAt, setAuthFailedAt] = useState<number | null>(null);
  const [notices, setNotices] = useState<Notice[]>([]);

  useEffect(() => {
    const onAuth = () => setAuthFailedAt(getApiTokenVersion());
    const onNotice = (e: Event) => {
      const detail = (e as CustomEvent<{ message: string; kind?: "error" | "info" }>).detail;
      if (!detail?.message || detail.message === UNAUTHORIZED_MESSAGE) return; // covered by the auth banner
      setNotices((prev) => {
        if (prev.some((n) => n.message === detail.message)) return prev;
        return [...prev, { id: nextNoticeId++, message: detail.message, kind: detail.kind ?? "error" }].slice(-3);
      });
    };
    window.addEventListener(AUTH_REQUIRED_EVENT, onAuth);
    window.addEventListener(NOTICE_EVENT, onNotice);
    return () => {
      window.removeEventListener(AUTH_REQUIRED_EVENT, onAuth);
      window.removeEventListener(NOTICE_EVENT, onNotice);
    };
  }, []);

  const showAuth = authFailedAt !== null && authFailedAt === version;

  if (!showAuth && notices.length === 0) return null;

  return (
    <div className="flex shrink-0 flex-col gap-2 px-4 pt-3" role="alert">
      {showAuth && (
        <div className="flex items-center justify-between gap-3 rounded-sm border border-rh-cond/40 bg-rh-cond/10 px-3 py-2 text-ui text-rh-text">
          <div className="flex min-w-0 items-center gap-2">
            <KeyRound className="h-4 w-4 shrink-0 text-rh-cond" aria-hidden="true" />
            <span>
              {token
                ? "The backend rejected your saved API token (401). Set a valid token to continue."
                : "No API token is set. Add your API token to use the ReadyHai backend."}
            </span>
          </div>
          <button
            type="button"
            onClick={openSettings}
            className="shrink-0 cursor-pointer rounded-sm bg-rh-primary px-3 py-1 text-ui font-semibold text-rh-bg hover:bg-rh-primary-hover"
          >
            Set API token
          </button>
        </div>
      )}
      {notices.map((n) => (
        <div
          key={n.id}
          className={`flex items-start justify-between gap-3 rounded-sm border px-3 py-2 text-ui text-rh-text ${
            n.kind === "error" ? "border-rh-nogo/40 bg-rh-nogo/10" : "border-rh-info/40 bg-rh-info/10"
          }`}
        >
          <div className="flex min-w-0 items-start gap-2">
            {n.kind === "error" ? (
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rh-nogo" aria-hidden="true" />
            ) : (
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-rh-info" aria-hidden="true" />
            )}
            <span className="min-w-0 break-words">{n.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotices((prev) => prev.filter((x) => x.id !== n.id))}
            className="shrink-0 cursor-pointer rounded-sm p-0.5 text-rh-muted hover:text-rh-text"
            aria-label="Dismiss notice"
            title="Dismiss"
          >
            <X className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>
      ))}
    </div>
  );
}
