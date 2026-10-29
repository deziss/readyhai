"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, KeyRound, X } from "lucide-react";
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
    <div className="shrink-0 flex flex-col gap-1 px-4 pt-2" role="alert">
      {showAuth && (
        <div className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-amber-950/50 border border-amber-700/60 text-xs text-amber-200">
          <div className="flex items-center gap-2 min-w-0">
            <KeyRound className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              {token
                ? "The backend rejected the saved API token (401). Set a valid API token to continue."
                : "No API token set. Set your API token to use the ReadyHai backend."}
            </span>
          </div>
          <button
            type="button"
            onClick={openSettings}
            className="px-3 py-1 rounded bg-amber-600 hover:bg-amber-500 text-slate-950 font-mono font-bold text-[11px] shrink-0 cursor-pointer"
          >
            Set API token
          </button>
        </div>
      )}
      {notices.map((n) => (
        <div
          key={n.id}
          className={`flex items-start justify-between gap-3 px-3 py-2 rounded-lg border text-xs ${
            n.kind === "error"
              ? "bg-rose-950/40 border-rose-700/60 text-rose-200"
              : "bg-cyan-950/40 border-cyan-700/60 text-cyan-200"
          }`}
        >
          <div className="flex items-start gap-2 min-w-0">
            <AlertTriangle className={`w-4 h-4 shrink-0 mt-px ${n.kind === "error" ? "text-rose-400" : "text-cyan-400"}`} />
            <span className="break-words min-w-0">{n.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotices((prev) => prev.filter((x) => x.id !== n.id))}
            className="text-slate-400 hover:text-white shrink-0 cursor-pointer"
            title="Dismiss"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}
