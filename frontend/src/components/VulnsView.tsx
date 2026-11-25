"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Ban, RefreshCw, ShieldCheck } from "lucide-react";
import { apiRequest, notify, useApiTokenVersion } from "@/lib/api";

// Shared control styles, mirroring SettingsView / AgentHistoryView.
const FOCUS = "focus-visible:outline-2 focus-visible:outline-rh-primary";
const INPUT =
  "px-3 py-1.5 rounded-[6px] bg-rh-bg border border-rh-line text-xs text-rh-text placeholder:text-rh-muted focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
const BTN_SECONDARY = `inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${FOCUS}`;
const BTN_GHOST = `inline-flex items-center gap-1.5 px-2 py-1 rounded-[6px] border border-rh-line text-rh-muted hover:text-rh-text hover:bg-rh-raised text-xs font-medium transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${FOCUS}`;
const CHIP = "px-2 py-0.5 rounded-[6px] text-xs font-semibold whitespace-nowrap";
const MUTED_NOTE = "text-xs text-rh-muted";

/** Debounce for the free-text target filter before it is sent as a query param. */
const TARGET_DEBOUNCE_MS = 300;

// ---------------------------------------------------------------------------
// API shapes (GET /api/vulns, POST /api/vulns/{fingerprint})
// ---------------------------------------------------------------------------

export type VulnSeverity = "low" | "medium" | "high";
export type VulnStatus = "open" | "accepted" | "forgotten";

export interface VulnEntry {
  fingerprint: string;
  target: string;
  target_key: string;
  kind: string;
  rule: string;
  title: string;
  severity: VulnSeverity | string;
  resource: string;
  first_seen: string;
  last_seen: string;
  occurrences: number;
  status: VulnStatus | string;
  message: string;
}

export interface VulnsResponse {
  count: number;
  vulns: VulnEntry[];
}

type StatusFilter = "all" | VulnStatus;
type SeverityFilter = "all" | VulnSeverity;

const STATUS_OPTIONS: StatusFilter[] = ["open", "accepted", "forgotten", "all"];
const SEVERITY_OPTIONS: SeverityFilter[] = ["all", "low", "medium", "high"];

/** Tolerant readers: the backend is Rust and may add, omit or reorder fields. */
function str(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

function asVulnList(data: VulnsResponse | null | undefined): VulnEntry[] {
  const raw: unknown[] = data && Array.isArray(data.vulns) ? data.vulns : [];
  return raw
    .filter((v): v is Record<string, unknown> => !!v && typeof v === "object")
    .map((v) => ({
      fingerprint: str(v.fingerprint),
      target: str(v.target),
      target_key: str(v.target_key),
      kind: str(v.kind),
      rule: str(v.rule),
      title: str(v.title),
      severity: str(v.severity, "low"),
      resource: str(v.resource),
      first_seen: str(v.first_seen),
      last_seen: str(v.last_seen),
      occurrences: num(v.occurrences),
      status: str(v.status, "open"),
      message: str(v.message),
    }))
    .filter((v) => v.fingerprint !== "");
}

function sentence(v: string): string {
  return v ? v.charAt(0).toUpperCase() + v.slice(1) : v;
}

/** Severity chip tones, matching the report view idiom (ScansHistoryView). */
function severityTone(severity: string): string {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "bg-rh-nogo/15 text-rh-nogo";
  if (s === "high" || s === "medium") return "bg-rh-cond/15 text-rh-cond";
  if (s === "low") return "bg-rh-info/15 text-rh-info";
  return "bg-rh-raised text-rh-muted";
}

function statusTone(status: string): string {
  const s = (status || "").toLowerCase();
  if (s === "open") return "bg-rh-cond/15 text-rh-cond";
  if (s === "accepted") return "bg-rh-go/15 text-rh-go";
  if (s === "forgotten") return "bg-rh-raised text-rh-muted";
  return "bg-rh-raised text-rh-muted";
}

/** Plain timestamps: existing views format with toLocaleString, no relative helper exists. */
function formatTs(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

export function VulnsView() {
  const tokenVersion = useApiTokenVersion();

  const [vulns, setVulns] = useState<VulnEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [busyFingerprint, setBusyFingerprint] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("open");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [targetText, setTargetText] = useState("");
  /** Debounced copy of targetText that is sent to the backend as ?target=. */
  const [targetParam, setTargetParam] = useState("");

  useEffect(() => {
    const t = window.setTimeout(() => setTargetParam(targetText.trim()), TARGET_DEBOUNCE_MS);
    return () => window.clearTimeout(t);
  }, [targetText]);

  // Loading is always in-flight from mount and whenever filters/token change, so the
  // spinner starts from initial state; setting `loading` synchronously inside the
  // effect body would just be a cascading render, which the react-hooks lint rule
  // forbids. Every state write below lands in a promise continuation (async).
  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (statusFilter !== "all") params.set("status", statusFilter);
    if (severityFilter !== "all") params.set("severity", severityFilter);
    if (targetParam) params.set("target", targetParam);
    const qs = params.toString();
    const url = qs ? `/api/vulns?${qs}` : "/api/vulns";
    return apiRequest<VulnsResponse>(url, { label: "Loading findings" }).then((r) => {
      if (r.ok) {
        setVulns(asVulnList(r.data));
        setLoadError(null);
      } else {
        setLoadError(r.error);
      }
      setLoading(false);
    });
  }, [statusFilter, severityFilter, targetParam]);

  useEffect(() => {
    load();
  }, [load, tokenVersion]);

  function refresh() {
    setLoading(true);
    load();
  }

  async function setStatusFor(fingerprint: string, next: VulnStatus) {
    setBusyFingerprint(fingerprint);
    setActionError(null);
    setActionMessage(null);
    const r = await apiRequest<{ ok?: boolean }>(`/api/vulns/${encodeURIComponent(fingerprint)}`, {
      method: "POST",
      json: { status: next },
      label: "Updating finding",
    });
    setBusyFingerprint(null);
    if (r.ok) {
      // Update the row locally; the server is the source of truth on the next load.
      setVulns((prev) =>
        prev.map((v) => (v.fingerprint === fingerprint ? { ...v, status: next } : v))
      );
      const short = fingerprint.slice(0, 8);
      const msg = `Finding ${short} marked ${sentence(next)}.`;
      setActionMessage(msg);
      notify(msg, "info");
    } else if (r.status === 403) {
      const msg = "Changing a finding's status requires admin. Your role can view findings but not triage them.";
      setActionError(msg);
      notify(msg);
    } else {
      setActionError(r.error);
      notify(r.error);
    }
  }

  const counts = useMemo(() => {
    const c = { open: 0, accepted: 0, forgotten: 0 };
    for (const v of vulns) {
      const s = String(v.status).toLowerCase();
      if (s === "open") c.open += 1;
      else if (s === "accepted") c.accepted += 1;
      else if (s === "forgotten") c.forgotten += 1;
    }
    return c;
  }, [vulns]);

  // Client-side narrowing on top of whatever the server returned: server-side
  // filters are best-effort (older builds may ignore query params).
  const rows = useMemo(() => {
    const needle = targetText.trim().toLowerCase();
    return vulns.filter((v) => {
      if (statusFilter !== "all" && String(v.status).toLowerCase() !== statusFilter) return false;
      if (severityFilter !== "all" && String(v.severity).toLowerCase() !== severityFilter)
        return false;
      if (needle) {
        const hay = `${v.target} ${v.target_key} ${v.resource}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [vulns, statusFilter, severityFilter, targetText]);

  const busy = busyFingerprint !== null;
  const filtersActive = statusFilter !== "open" || severityFilter !== "all" || targetText.trim() !== "";

  function clearFilters() {
    setStatusFilter("open");
    setSeverityFilter("all");
    setTargetText("");
    setTargetParam("");
  }

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-rh-bg overflow-hidden">
      {/* Top subbar: title + counts + refresh */}
      <div className="min-h-11 px-6 py-2 border-b border-rh-line bg-rh-surface flex flex-wrap items-center justify-between gap-2 text-xs text-rh-muted shrink-0">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-rh-muted" aria-hidden="true" />
          <h2 className="text-rh-text font-semibold text-sm">Vulns</h2>
          <span className="text-rh-muted">Findings recorded by scans, triaged here</span>
          {!loading && !loadError && (
            <span
              className="ml-2 px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text text-xs font-medium tabular-nums"
              data-testid="vuln-counts"
            >
              {counts.open} open
              {" · "}
              {counts.accepted} accepted
              {" · "}
              {counts.forgotten} forgotten
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={refresh}
            disabled={busy}
            className={BTN_SECONDARY}
            title="Reload findings from GET /api/vulns"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {/* Result strip */}
      {(loadError || actionError || actionMessage) && (
        <div className="shrink-0 px-6 pt-3 space-y-2">
          {loadError && (
            <p role="alert" className="rounded-[6px] border border-rh-nogo/40 bg-rh-nogo/10 px-3 py-2 text-xs text-rh-nogo">
              {loadError}
            </p>
          )}
          {actionError && (
            <p role="alert" className="rounded-[6px] border border-rh-nogo/40 bg-rh-nogo/10 px-3 py-2 text-xs text-rh-nogo">
              {actionError}
            </p>
          )}
          {actionMessage && !actionError && (
            <p className="rounded-[6px] border border-rh-go/40 bg-rh-go/10 px-3 py-2 text-xs text-rh-go">
              {actionMessage}
            </p>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="shrink-0 px-6 pt-3 flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1">
          <label htmlFor="vulns-filter-status" className="text-xs font-medium text-rh-text">
            Status
          </label>
          <select
            id="vulns-filter-status"
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
            className={`${INPUT} cursor-pointer`}
          >
            {STATUS_OPTIONS.map((v) => (
              <option key={v} value={v}>
                {v === "all" ? "All" : sentence(v)}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="vulns-filter-severity" className="text-xs font-medium text-rh-text">
            Severity
          </label>
          <select
            id="vulns-filter-severity"
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
            className={`${INPUT} cursor-pointer`}
          >
            {SEVERITY_OPTIONS.map((v) => (
              <option key={v} value={v}>
                {v === "all" ? "All" : sentence(v)}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="vulns-filter-target" className="text-xs font-medium text-rh-text">
            Target
          </label>
          <input
            id="vulns-filter-target"
            type="text"
            aria-label="Filter by target"
            value={targetText}
            onChange={(e) => setTargetText(e.target.value)}
            placeholder="contains, e.g. api.example.com"
            spellCheck={false}
            className={`${INPUT} w-64 font-mono`}
          />
        </div>
        {filtersActive && (
          <button type="button" onClick={clearFilters} className={BTN_SECONDARY}>
            Clear filters
          </button>
        )}
      </div>

      {/* Body */}
      <div className="flex-1 min-h-0 overflow-y-auto p-6">
        {loading && vulns.length === 0 ? (
          <p className="text-sm text-rh-muted">Loading findings...</p>
        ) : loadError && vulns.length === 0 ? (
          <p className="text-sm text-rh-nogo">{loadError}</p>
        ) : vulns.length === 0 ? (
          <div className="rounded-md border border-rh-line bg-rh-surface px-4 py-8 text-center">
            <p className="text-sm text-rh-text">
              No vulnerabilities recorded yet — findings from WARN/FAIL checks land here
              automatically after your first deep scan.
            </p>
            <p className={`${MUTED_NOTE} mt-2`}>
              Inspect or triage them from the CLI too:{" "}
              <span className="font-mono text-rh-text">readyhai vulns list</span> ·{" "}
              <span className="font-mono text-rh-text">readyhai vulns accept &lt;fingerprint&gt;</span>
            </p>
          </div>
        ) : rows.length === 0 ? (
          <div className="rounded-md border border-rh-line bg-rh-surface px-4 py-8 text-center">
            <p className="text-sm text-rh-text">No findings match the current filters.</p>
            <p className={`${MUTED_NOTE} mt-2`}>
              {counts.open} open · {counts.accepted} accepted · {counts.forgotten} forgotten in total.
            </p>
            <button type="button" onClick={clearFilters} className={`${BTN_SECONDARY} mt-3`}>
              Clear filters
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-md border border-rh-line bg-rh-surface">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-rh-line text-rh-muted">
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">Title</th>
                  <th className="px-3 py-2 font-medium">Target</th>
                  <th className="px-3 py-2 font-medium">Rule</th>
                  <th className="px-3 py-2 font-medium">First seen</th>
                  <th className="px-3 py-2 font-medium">Last seen</th>
                  <th className="px-3 py-2 font-medium">Occurrences</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((v) => {
                  const rowBusy = busy;
                  return (
                    <tr
                      key={v.fingerprint}
                      className="border-b border-rh-line/50 last:border-0 align-top"
                    >
                      <td className="px-3 py-2">
                        <span className={`${CHIP} ${severityTone(String(v.severity))}`}>
                          {sentence(String(v.severity).toLowerCase()) || "Unknown"}
                        </span>
                      </td>
                      <td className="px-3 py-2 max-w-[320px]">
                        <span className="block font-medium text-rh-text">
                          {v.title || v.rule || "Untitled finding"}
                        </span>
                        {v.message && (
                          <span className="block text-rh-muted break-words">{v.message}</span>
                        )}
                        {v.kind && <span className="block text-rh-muted">{v.kind}</span>}
                      </td>
                      <td className="px-3 py-2 max-w-[220px]">
                        <span className="block font-mono text-rh-text break-all">{v.target || "—"}</span>
                        {v.resource && (
                          <span className="block font-mono text-rh-muted break-all">{v.resource}</span>
                        )}
                      </td>
                      <td className="px-3 py-2 font-mono text-rh-muted">{v.rule || "—"}</td>
                      <td className="px-3 py-2 text-rh-muted whitespace-nowrap">{formatTs(v.first_seen)}</td>
                      <td className="px-3 py-2 text-rh-muted whitespace-nowrap">{formatTs(v.last_seen)}</td>
                      <td className="px-3 py-2 text-rh-text tabular-nums">{v.occurrences}</td>
                      <td className="px-3 py-2">
                        <span className={`${CHIP} ${statusTone(String(v.status))}`}>
                          {sentence(String(v.status).toLowerCase()) || "Unknown"}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => setStatusFor(v.fingerprint, "accepted")}
                            disabled={rowBusy}
                            title="Mark this finding accepted (needs admin)"
                            aria-label={`Accept finding ${v.fingerprint}`}
                            className={BTN_GHOST}
                          >
                            Accept
                          </button>
                          <button
                            type="button"
                            onClick={() => setStatusFor(v.fingerprint, "forgotten")}
                            disabled={rowBusy}
                            title="Forget this finding (needs admin)"
                            aria-label={`Forget finding ${v.fingerprint}`}
                            className={BTN_GHOST}
                          >
                            <Ban className="w-3 h-3" aria-hidden="true" />
                            Forget
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <p className={`${MUTED_NOTE} mt-3`}>
          Statuses are stored in the vulnerability database and shared with the scans and the
          <span className="font-mono text-rh-text"> readyhai vulns</span> CLI.
        </p>
      </div>
    </div>
  );
}
