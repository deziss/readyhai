"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Ban, FlaskConical, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
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
// API shapes (GET /api/vulns, POST /api/vulns/{fingerprint},
// GET /api/exploits/templates, POST /api/exploits/run)
// ---------------------------------------------------------------------------

export type VulnSeverity = "low" | "medium" | "high";
export type VulnStatus = "open" | "accepted" | "forgotten";
export type VulnVerification =
  | "unverified"
  | "verified"
  | "not_reproducible"
  | "inconclusive"
  | "skipped";

const VERIFICATIONS: readonly string[] = [
  "unverified",
  "verified",
  "not_reproducible",
  "inconclusive",
  "skipped",
];

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
  /** Exploitation-verification stamp. Missing/unknown values act as "unverified". */
  verification: VulnVerification | string;
  /** Exploit template id that last verified the row, "" when there is none. */
  verified_by: string;
  verified_at: string;
}

export interface VulnsResponse {
  count: number;
  vulns: VulnEntry[];
}

/** GET /api/exploits/templates entry (see src/exploits/mod.rs on the backend). */
export interface ExploitTemplate {
  id: string;
  title: string;
  family: string;
  /** Lower-case fragments matched against a row's kind + rule + title. */
  applies_keywords: string[];
  http: boolean;
  description: string;
}

export interface ExploitTemplatesResponse {
  count: number;
  templates: ExploitTemplate[];
}

/** One row of a POST /api/exploits/run result set. */
interface ExploitRunResult {
  fingerprint: string;
  template: string;
  verdict: string;
  reason: string;
  evidence: string;
  verified_at: string;
}

interface ExploitRunResponse {
  executed: number;
  results: ExploitRunResult[];
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

/** Any value the backend does not recognise (or omits) means "never verified". */
function asVerification(v: unknown): string {
  return typeof v === "string" && VERIFICATIONS.includes(v) ? v : "unverified";
}

/** Optional ISO timestamp: null/absent/blank all become "". */
function optStr(v: unknown): string {
  return typeof v === "string" ? v : "";
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
      verification: asVerification(v.verification),
      verified_by: optStr(v.verified_by),
      verified_at: optStr(v.verified_at),
    }))
    .filter((v) => v.fingerprint !== "");
}

function asTemplateList(data: ExploitTemplatesResponse | null | undefined): ExploitTemplate[] {
  const raw: unknown[] = data && Array.isArray(data.templates) ? data.templates : [];
  return raw
    .filter((t): t is Record<string, unknown> => !!t && typeof t === "object")
    .map((t) => ({
      id: str(t.id),
      title: str(t.title),
      family: str(t.family),
      applies_keywords: Array.isArray(t.applies_keywords)
        ? t.applies_keywords.filter((k): k is string => typeof k === "string")
        : [],
      http: t.http === true,
      description: str(t.description),
    }))
    .filter((t) => t.id !== "" && t.applies_keywords.length > 0);
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

/**
 * Verification chip tones. "unverified" has no tone: an unstamped row shows no
 * badge at all, so only the meaningful verdicts take up space in the table.
 */
function verificationTone(verification: string): string | null {
  const s = (verification || "").toLowerCase();
  if (s === "verified") return "bg-rh-go/15 text-rh-go";
  if (s === "not_reproducible") return "bg-rh-nogo/15 text-rh-nogo";
  if (s === "inconclusive") return "bg-rh-cond/15 text-rh-cond";
  if (s === "skipped") return "bg-rh-raised text-rh-muted";
  return null;
}

const VERIFICATION_LABEL: Record<string, string> = {
  verified: "verified",
  not_reproducible: "not reproducible",
  inconclusive: "inconclusive",
  skipped: "skipped",
};

/** Label for a verdict/verification value; unknown values are shown as-is. */
function verificationLabel(verification: string): string {
  const s = (verification || "").toLowerCase();
  return VERIFICATION_LABEL[s] ?? s;
}

/**
 * Does this template apply to a finding? Mirrors the backend rule
 * (`exploits::matches`): any lower-case keyword is a substring of
 * kind + rule + title. The backend still makes the final choice per run.
 */
function templateApplies(t: ExploitTemplate, v: VulnEntry): boolean {
  if (t.applies_keywords.length === 0) return false;
  const hay = `${v.kind} ${v.rule} ${v.title}`.toLowerCase();
  return t.applies_keywords.some((k) => k !== "" && hay.includes(k));
}

/** Tooltip for the verification chip: who stamped it, when and why. */
function verificationTip(v: VulnEntry): string {
  const parts = [`Verification: ${verificationLabel(v.verification)}`];
  if (v.verified_by) parts.push(`template ${v.verified_by}`);
  if (v.verified_at) parts.push(formatTs(v.verified_at));
  return parts.join(" · ");
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

  /** Exploit templates (GET /api/exploits/templates). [] until loaded, and []
   * stays when the backend has no exploits support: no Verify buttons then. */
  const [templates, setTemplates] = useState<ExploitTemplate[]>([]);
  /** Fingerprint of the row whose POST /api/exploits/run is in flight. */
  const [verifyingFingerprint, setVerifyingFingerprint] = useState<string | null>(null);
  /** Last verdict reason/evidence per fingerprint (tooltip on the badge/Verify). */
  const [verifyNotes, setVerifyNotes] = useState<Record<string, { reason: string; evidence: string; template: string }>>({});

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

  // Templates decide whether a row can be verified at all. Like the list load,
  // every state write happens in the promise continuation, so the effect below
  // stays free of synchronous setState. A 404/401/5xx just means "no templates",
  // which hides the Verify buttons instead of nagging about an optional feature.
  const loadTemplates = useCallback(() => {
    return apiRequest<ExploitTemplatesResponse>("/api/exploits/templates", {
      label: "Loading exploit templates",
    }).then((r) => {
      setTemplates(r.ok ? asTemplateList(r.data) : []);
    });
  }, []);

  useEffect(() => {
    loadTemplates();
  }, [loadTemplates, tokenVersion]);

  function refresh() {
    setLoading(true);
    load();
    loadTemplates();
  }

  /**
   * Verify one finding with `POST /api/exploits/run`. The answer carries the new
   * stamp, so the row updates locally from the result. A 409 means the operator
   * has not enabled exploitation: its message goes into the shared notice area.
   */
  async function verifyFingerprint(fingerprint: string) {
    setVerifyingFingerprint(fingerprint);
    setActionError(null);
    setActionMessage(null);
    const r = await apiRequest<ExploitRunResponse>("/api/exploits/run", {
      method: "POST",
      json: { fingerprints: [fingerprint] },
      label: "Verification run",
    });
    setVerifyingFingerprint(null);
    if (r.ok) {
      const result = (r.data && Array.isArray(r.data.results) ? r.data.results : []).find(
        (x) => x && typeof x.fingerprint === "string" && x.fingerprint.startsWith(fingerprint)
      );
      if (!result) {
        const msg = "Verification run failed: the server returned no result for this finding.";
        setActionError(msg);
        notify(msg);
        return;
      }
      const verification = asVerification(result.verdict);
      const template = optStr(result.template);
      const reason = optStr(result.reason);
      setVulns((prev) =>
        prev.map((v) =>
          v.fingerprint === fingerprint
            ? {
                ...v,
                verification,
                verified_by: template || v.verified_by,
                verified_at: optStr(result.verified_at) || v.verified_at,
              }
            : v
        )
      );
      setVerifyNotes((prev) => ({
        ...prev,
        [fingerprint]: { reason, evidence: optStr(result.evidence), template },
      }));
      const msg = `Finding ${fingerprint.slice(0, 8)}: ${verificationLabel(verification)}${
        reason ? ` — ${reason}` : ""
      }`;
      setActionMessage(msg);
      notify(msg, "info");
    } else if (r.status === 409) {
      // Exploitation is disabled in settings: show the server's own wording.
      setActionError(r.error);
      notify(r.error);
    } else {
      setActionError(r.error);
      notify(r.error);
    }
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

  const busy = busyFingerprint !== null || verifyingFingerprint !== null;
  const filtersActive = statusFilter !== "open" || severityFilter !== "all" || targetText.trim() !== "";

  /** First catalogue template that applies to each loaded row, by fingerprint. */
  const applicableTemplates = useMemo(() => {
    const map: Record<string, ExploitTemplate> = {};
    if (templates.length === 0) return map;
    for (const v of vulns) {
      const t = templates.find((tpl) => templateApplies(tpl, v));
      if (t) map[v.fingerprint] = t;
    }
    return map;
  }, [vulns, templates]);

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
                  <th className="px-3 py-2 font-medium">Verification</th>
                  <th className="px-3 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((v) => {
                  const rowBusy = busy;
                  const vTone = verificationTone(String(v.verification));
                  const template = applicableTemplates[v.fingerprint];
                  const note = verifyNotes[v.fingerprint];
                  const chipTip = [
                    verificationTip(v),
                    note?.reason ? `reason: ${note.reason}` : "",
                    note?.evidence ? `evidence: ${note.evidence}` : "",
                  ]
                    .filter(Boolean)
                    .join(" · ");
                  const verifyTitle = [
                    template
                      ? `Verify with ${template.id}: ${template.description}`
                      : "Verify this finding",
                    note?.reason ? `Last run: ${note.reason}` : "",
                  ]
                    .filter(Boolean)
                    .join(" — ");
                  const pending = verifyingFingerprint === v.fingerprint;
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
                        {vTone && (
                          <span
                            className={`${CHIP} ${vTone}`}
                            title={chipTip}
                            data-testid={`verification-${v.fingerprint}`}
                          >
                            {verificationLabel(String(v.verification))}
                          </span>
                        )}
                        {note?.reason && (
                          <span className={`${vTone ? "block mt-0.5" : ""} max-w-[200px] text-rh-muted`}>
                            {note.reason}
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">
                          {template && (
                            <button
                              type="button"
                              onClick={() => verifyFingerprint(v.fingerprint)}
                              disabled={rowBusy}
                              title={verifyTitle}
                              aria-label={`Verify finding ${v.fingerprint}`}
                              className={BTN_GHOST}
                            >
                              {pending ? (
                                <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
                              ) : (
                                <FlaskConical className="w-3 h-3" aria-hidden="true" />
                              )}
                              {pending ? "Verifying..." : "Verify"}
                            </button>
                          )}
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
          <span className="font-mono text-rh-text"> readyhai vulns</span> CLI. Verification stamps
          come from <span className="font-mono text-rh-text">readyhai exploits run</span> and must be
          enabled by the operator in Settings.
        </p>
      </div>
    </div>
  );
}
