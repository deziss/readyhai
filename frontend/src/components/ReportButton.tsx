"use client";

import { useEffect, useState, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import {
  downloadAuthed,
  fetchReportBlob,
  notify,
  openAuthedInTab,
  useApiTokenVersion,
} from "@/lib/api";

interface ReportButtonProps {
  /** Backend path, e.g. /api/agent/runs/<id>/report/html */
  path: string;
  mode: "tab" | "download";
  /** File name for downloads. */
  filename?: string;
  className?: string;
  title?: string;
  /** Stop the click from reaching a clickable parent row. */
  stopPropagation?: boolean;
  children: ReactNode;
}

/**
 * Replacement for `<a href="/api/...">`: plain links cannot send the bearer
 * token, so the file is fetched with it and opened/downloaded from a blob.
 */
export function ReportButton({ path, mode, filename, className, title, stopPropagation, children }: ReportButtonProps) {
  const [busy, setBusy] = useState(false);

  async function onClick(e: React.MouseEvent) {
    if (stopPropagation) e.stopPropagation();
    if (busy) return;
    setBusy(true);
    try {
      const err =
        mode === "tab"
          ? await openAuthedInTab(path)
          : await downloadAuthed(path, filename || "report", "Download");
      if (err) notify(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <button type="button" onClick={onClick} disabled={busy} className={className} title={title}>
      {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : children}
    </button>
  );
}

interface ReportFrameProps {
  path: string;
  title: string;
  className?: string;
}

/** Authenticated HTML report in a sandboxed iframe (opaque origin: it cannot read the stored token). */
export function ReportFrame({ path, title, className }: ReportFrameProps) {
  const version = useApiTokenVersion();
  const key = `${path}|${version}`;
  const [state, setState] = useState<{ key: string; url: string | null; error: string | null }>({
    key: "",
    url: null,
    error: null,
  });

  useEffect(() => {
    let cancelled = false;
    let objectUrl: string | null = null;
    fetchReportBlob(path, "Report").then((r) => {
      if (cancelled) return;
      if (r.ok) {
        objectUrl = URL.createObjectURL(r.blob);
        setState({ key, url: objectUrl, error: null });
      } else {
        setState({ key, url: null, error: r.error });
      }
    });
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [path, key]);

  if (state.key !== key) {
    return (
      <div className="w-full h-full flex items-center justify-center text-xs font-mono text-slate-400 gap-2">
        <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
        Loading report...
      </div>
    );
  }
  if (state.error || !state.url) {
    return (
      <div className="w-full h-full flex items-center justify-center p-6 text-xs font-mono text-rose-300 text-center">
        {state.error || "Report unavailable."}
      </div>
    );
  }
  return (
    <iframe
      src={state.url}
      title={title}
      className={className}
      sandbox="allow-scripts allow-modals"
    />
  );
}
