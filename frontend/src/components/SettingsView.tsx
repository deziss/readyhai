"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Settings,
  SlidersHorizontal,
} from "lucide-react";
import { apiRequest, notify, useApiTokenVersion } from "@/lib/api";

// Shared control styles, mirroring AgentHistoryView.
const FOCUS = "focus-visible:outline-2 focus-visible:outline-rh-primary";
const INPUT =
  "px-3 py-1.5 rounded-[6px] bg-rh-bg border border-rh-line text-xs text-rh-text placeholder:text-rh-muted focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
const BTN_SECONDARY = `inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${FOCUS}`;
const BTN_PRIMARY = `inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${FOCUS}`;
const BTN_DANGER = `inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-[6px] border border-rh-nogo/60 text-rh-nogo hover:bg-rh-nogo/10 text-xs font-medium transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${FOCUS}`;
const CARD = "rounded-md border border-rh-line bg-rh-surface";
const CHIP = "px-2 py-0.5 rounded-[6px] text-xs font-semibold whitespace-nowrap";
const MUTED_NOTE = "text-xs text-rh-muted";

// ---------------------------------------------------------------------------
// API shapes (GET/PUT/DELETE /api/settings, GET /api/settings/checks, GET /api/rbac)
// ---------------------------------------------------------------------------

export type TriState = "auto" | "on" | "off";

const TRI_STATES: readonly TriState[] = ["auto", "on", "off"];
const TRI_LABEL: Record<TriState, string> = { auto: "Auto", on: "On", off: "Off" };

export interface IntegrationsDoc {
  tools: TriState;
  plugins: TriState;
  intrusive: TriState;
}

export interface SettingsToggleEntry {
  id: string;
  enabled: TriState;
}

export interface SettingsResponse {
  /** Effective settings file path, or null when the server has none. */
  path: string | null;
  exists: boolean;
  editable: boolean;
  /** Write epoch: increments per write. */
  version: number;
  effective: {
    integrations: IntegrationsDoc;
    toggle: SettingsToggleEntry[];
    /** Server releases that report the sections put them here (see settings_api.rs). */
    vulndb?: VulnDbInfo | null;
    exploits?: ExploitsInfo | null;
  };
  override_count: number;
  /** True when a READYHAI_SETTINGS env file is being overridden by the data-dir file. */
  shadowing_env: boolean;
  /**
   * Vulnerability database status from `effective.vulndb` (display-only on this
   * card, carried back on every save). Older backends omit the section entirely:
   * treat it as not reported.
   */
  vulndb?: VulnDbInfo | null;
  /**
   * Exploitation verification (`POST /api/exploits/run`) from `effective.exploits`.
   * Editable: while the card is visible the section rides along in every PUT,
   * exactly like vulndb. Older backends omit it: the card hides itself.
   */
  exploits?: ExploitsInfo | null;
}

export interface VulnDbInfo {
  enabled: boolean;
  /** Absolute path, or null when the default data dir is used. */
  path: string | null;
}

export interface ExploitsInfo {
  /** When false the server refuses verification runs (POST /api/exploits/run → 409). */
  enabled: boolean;
  /** Verification probes allowed per run. The server bounds it to 1..=100. */
  max_probes: number;
}

/** Server bounds and defaults for exploits (settings.rs Exploits::default/validate). */
export const MAX_PROBES_MIN = 1;
export const MAX_PROBES_MAX = 100;
const EXPLOITS_DEFAULT: ExploitsInfo = { enabled: false, max_probes: 25 };

/** Sections live under `effective` on current servers and were read at the top
 * level by earlier builds; accept either shape. */
export function exploitsOf(d: SettingsResponse | null | undefined): ExploitsInfo | null | undefined {
  return d?.effective?.exploits ?? d?.exploits;
}

/**
 * Normalizes the wire section into a draft: a boolean enabled, and a max_probes
 * that always satisfies the server bounds (a present section is sent back on
 * every Save, so an out-of-range draft would make the whole PUT 400). Unknown
 * values fall back to the built-in settings defaults (off, 25 probes), matching
 * the tolerant readers elsewhere.
 */
export function normalizeExploits(x: ExploitsInfo | null | undefined): ExploitsInfo {
  const enabled = x?.enabled === true;
  let maxProbes = EXPLOITS_DEFAULT.max_probes;
  if (typeof x?.max_probes === "number" && Number.isFinite(x.max_probes)) {
    maxProbes = Math.round(x.max_probes);
  }
  if (maxProbes < MAX_PROBES_MIN) maxProbes = MAX_PROBES_MIN;
  if (maxProbes > MAX_PROBES_MAX) maxProbes = MAX_PROBES_MAX;
  return { enabled, max_probes: maxProbes };
}

export interface SettingsCheckInfo {
  id: string;
  title: string;
  source: string; // "builtin" | "plugin"
  kinds: string[];
  profile: string;
  intrusive: boolean;
  /** Effective settings decision: true unless a toggle disables this check. */
  enabled: boolean;
  decided_by: string; // "auto" | "settings" | "integrations" | "gate"
  reason: string | null;
}

interface RbacKey {
  name: string;
  role: string;
  fingerprint: string;
}

interface RbacResponse {
  enabled: boolean;
  mode: string; // "auto" | "on" | "off"
  file: string | null;
  boot_admin: boolean;
  keys: RbacKey[];
  counts: { viewer: number; operator: number; admin: number };
}

// ---------------------------------------------------------------------------
// Draft helpers
// ---------------------------------------------------------------------------

function normalizeIntegrations(i: IntegrationsDoc | undefined): IntegrationsDoc {
  return {
    tools: i?.tools ?? "auto",
    plugins: i?.plugins ?? "auto",
    intrusive: i?.intrusive ?? "auto",
  };
}

function togglesToMap(entries: SettingsToggleEntry[]): Record<string, TriState> {
  const map: Record<string, TriState> = {};
  for (const e of entries) {
    if (e && typeof e.id === "string") map[e.id] = e.enabled ?? "auto";
  }
  return map;
}

/**
 * Turn the draft toggle map back into the wire list. Entries set to "auto" are
 * dropped unless the id was already present in the saved document (an explicit
 * "auto" entry overrides lower-level defaults and must be preserved).
 */
function togglesToEntries(
  map: Record<string, TriState>,
  keepAutoIds: ReadonlySet<string>
): SettingsToggleEntry[] {
  return Object.keys(map)
    .sort()
    .filter((id) => map[id] !== "auto" || keepAutoIds.has(id))
    .map((id) => ({ id, enabled: map[id] }));
}

function fingerprint(
  integrations: IntegrationsDoc,
  toggle: SettingsToggleEntry[],
  exploits: ExploitsInfo | null
): string {
  // Key order must be fixed on both sides: the server's JSON key order can
  // differ from our object literals, and JSON.stringify is order-sensitive.
  const canonicalIntegrations = INTEGRATION_ROWS.map((r) => [r.key, integrations[r.key]] as const);
  const canonicalToggle = [...toggle]
    .sort((a, b) => (a.id < b.id ? -1 : 1))
    .map((e) => [e.id, e.enabled] as const);
  const canonicalExploits = exploits
    ? ([
        ["enabled", exploits.enabled],
        ["max_probes", exploits.max_probes],
      ] as const)
    : null;
  return JSON.stringify({
    integrations: canonicalIntegrations,
    toggle: canonicalToggle,
    exploits: canonicalExploits,
  });
}

// ---------------------------------------------------------------------------
// Small pieces
// ---------------------------------------------------------------------------

/** Tri-state segmented control (auto / on / off). */
function TriStateSegment({
  name,
  value,
  disabled = false,
  onSelect,
}: {
  name: string;
  value: TriState;
  disabled?: boolean;
  onSelect: (v: TriState) => void;
}) {
  return (
    <div
      role="group"
      aria-label={name}
      className="inline-flex items-center gap-1 rounded-[6px] border border-rh-line bg-rh-bg p-1"
    >
      {TRI_STATES.map((v) => {
        const active = value === v;
        return (
          <button
            key={v}
            type="button"
            onClick={() => onSelect(v)}
            disabled={disabled}
            aria-pressed={active}
            className={`min-w-12 px-2.5 py-1 text-xs rounded-[6px] transition-colors text-center cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${FOCUS} ${
              active ? "bg-rh-raised text-rh-text font-semibold" : "text-rh-muted hover:text-rh-text"
            }`}
          >
            {TRI_LABEL[v]}
          </button>
        );
      })}
    </div>
  );
}

function SectionCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className={CARD}>
      <div className="border-b border-rh-line px-4 py-3">
        <h3 className="text-sm font-semibold text-rh-text">{title}</h3>
        {subtitle && <p className="mt-0.5 text-xs text-rh-muted">{subtitle}</p>}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

const INTEGRATION_ROWS: { key: keyof IntegrationsDoc; label: string; help: string }[] = [
  {
    key: "tools",
    label: "Tools",
    help: "Bundled scanner tools (e.g. Nuclei). auto enables the ones that are installed and applicable.",
  },
  {
    key: "plugins",
    label: "Plugins",
    help: "External plugin scanners. auto follows the plugin registry.",
  },
  {
    key: "intrusive",
    label: "Intrusive",
    help: "Checks that can modify or load the target. auto defers to the scan gate; the server rejects forcing this on.",
  },
];

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

interface SettingsViewProps {
  onBackToStudio?: () => void;
}

export function SettingsView({ onBackToStudio }: SettingsViewProps) {
  const tokenVersion = useApiTokenVersion();

  // /api/settings (server document + editable draft)
  const [doc, setDoc] = useState<SettingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draftIntegrations, setDraftIntegrations] = useState<IntegrationsDoc>({
    tools: "auto",
    plugins: "auto",
    intrusive: "auto",
  });
  const [draftToggles, setDraftToggles] = useState<Record<string, TriState>>({});
  const [intrusiveWarning, setIntrusiveWarning] = useState(false);
  /**
   * Exploitation draft; null while the backend does not report `effective.exploits`
   * (older servers). While non-null the section rides along in every PUT, like vulndb.
   */
  const [draftExploits, setDraftExploits] = useState<ExploitsInfo | null>(null);

  // Save/reset state
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  // /api/settings/checks
  const [checks, setChecks] = useState<SettingsCheckInfo[] | null>(null);
  const [checksLoading, setChecksLoading] = useState(true);
  const [checksError, setChecksError] = useState<string | null>(null);
  const [customId, setCustomId] = useState("");
  const [customError, setCustomError] = useState<string | null>(null);

  // /api/rbac
  const [rbac, setRbac] = useState<RbacResponse | null>(null);
  const [rbacLoading, setRbacLoading] = useState(true);
  const [rbacDenied, setRbacDenied] = useState(false);
  const [rbacError, setRbacError] = useState<string | null>(null);

  // Open findings for the vuln database card. null = unknown (old backend, 404, or error).
  const [openVulnCount, setOpenVulnCount] = useState<number | null>(null);

  /** Ids the saved document toggles explicitly; their "auto" drafts must survive serialization. */
  const savedToggleIds = useMemo(
    () => new Set((doc?.effective.toggle ?? []).map((e) => e.id)),
    [doc]
  );

  const applyDoc = useCallback((d: SettingsResponse) => {
    setDoc(d);
    setDraftIntegrations(normalizeIntegrations(d.effective?.integrations));
    setDraftToggles(togglesToMap(d.effective?.toggle ?? []));
    const exploits = exploitsOf(d);
    setDraftExploits(exploits && typeof exploits.enabled === "boolean" ? normalizeExploits(exploits) : null);
    setIntrusiveWarning(false);
    setSaveError(null);
    setCustomError(null);
  }, []);

  const loadSettings = useCallback(
    () =>
      apiRequest<SettingsResponse>("/api/settings", { label: "Loading settings" }).then((r) => {
        if (r.ok && r.data) {
          applyDoc(r.data);
          setSaveMessage(null);
          setLoadError(null);
        } else {
          setLoadError(r.ok ? "Loading settings failed: empty response." : r.error);
        }
        setLoading(false);
      }),
    [applyDoc]
  );

  const loadChecks = useCallback(
    () =>
      apiRequest<{ checks?: SettingsCheckInfo[] }>("/api/settings/checks", {
        label: "Loading checks",
      }).then((r) => {
        if (r.ok && r.data) {
          setChecks(Array.isArray(r.data.checks) ? r.data.checks : []);
          setChecksError(null);
        } else {
          setChecksError(r.ok ? "Loading checks failed: empty response." : r.error);
        }
        setChecksLoading(false);
      }),
    []
  );

  const loadRbac = useCallback(
    () =>
      apiRequest<RbacResponse>("/api/rbac", { label: "Loading RBAC status" }).then((r) => {
        if (r.ok) {
          if (r.data) {
            setRbac(r.data);
            setRbacDenied(false);
            setRbacError(null);
          } else {
            setRbacError("Loading RBAC status failed: empty response.");
          }
        } else if (r.status === 403) {
          setRbacDenied(true);
          setRbacError(null);
        } else {
          setRbacError(r.error);
        }
        setRbacLoading(false);
      }),
    []
  );

  const loadOpenVulns = useCallback(
    () =>
      apiRequest<{ count?: number; vulns?: unknown[] }>("/api/vulns?status=open", {
        label: "Loading findings",
      }).then((r) => {
        // Any failure (404 on an older backend, 401, network) just means "unknown".
        if (r.ok && r.data && typeof r.data.count === "number" && r.data.count >= 0) {
          setOpenVulnCount(r.data.count);
        } else {
          setOpenVulnCount(null);
        }
      }),
    []
  );

  useEffect(() => {
    loadSettings();
    loadChecks();
    loadRbac();
    loadOpenVulns();
  }, [loadSettings, loadChecks, loadRbac, loadOpenVulns, tokenVersion]);

  const refresh = () => {
    setLoading(true);
    setChecksLoading(true);
    setRbacLoading(true);
    loadSettings();
    loadChecks();
    loadRbac();
    loadOpenVulns();
  };

  // Dirty tracking: compare the draft with the saved document in wire shape.
  const dirty = useMemo(() => {
    if (!doc) return false;
    const savedExploits = exploitsOf(doc);
    const server = fingerprint(
      doc.effective.integrations,
      doc.effective.toggle,
      savedExploits && typeof savedExploits.enabled === "boolean"
        ? normalizeExploits(savedExploits)
        : null
    );
    const draft = fingerprint(
      draftIntegrations,
      togglesToEntries(draftToggles, savedToggleIds),
      draftExploits
    );
    return server !== draft;
  }, [doc, draftIntegrations, draftToggles, savedToggleIds, draftExploits]);

  function setIntegration(key: keyof IntegrationsDoc, next: TriState) {
    // The backend rejects integrations.intrusive = "on": never select it, just warn.
    if (key === "intrusive" && next === "on") {
      setIntrusiveWarning(true);
      return;
    }
    setIntrusiveWarning(false);
    setSaveMessage(null);
    setDraftIntegrations((prev) => ({ ...prev, [key]: next }));
  }

  function setToggle(id: string, next: TriState) {
    setSaveMessage(null);
    setDraftToggles((prev) => ({ ...prev, [id]: next }));
  }

  function setExploitsEnabled(next: boolean) {
    setSaveMessage(null);
    setDraftExploits((prev) => (prev ? { ...prev, enabled: next } : prev));
  }

  function setExploitsMaxProbes(next: number) {
    setSaveMessage(null);
    setDraftExploits((prev) =>
      prev
        ? { ...prev, max_probes: Math.min(MAX_PROBES_MAX, Math.max(MAX_PROBES_MIN, Math.round(next))) }
        : prev
    );
  }

  function removeToggle(id: string) {
    setSaveMessage(null);
    setDraftToggles((prev) => {
      const map = { ...prev };
      delete map[id];
      return map;
    });
  }

  function addCustomToggle() {
    const id = customId.trim();
    if (!id) {
      setCustomError("Enter a check id or glob, e.g. tool.nuclei or plugin.*");
      return;
    }
    if (/\s/.test(id)) {
      setCustomError("The id cannot contain spaces.");
      return;
    }
    if (draftToggles[id] !== undefined) {
      setCustomError("That id already has a toggle in this draft.");
      return;
    }
    setCustomError(null);
    setCustomId("");
    setToggle(id, "on");
  }

  async function save() {
    if (!doc || !dirty) return;
    setSaving(true);
    setSaveError(null);
    setSaveMessage(null);
    const payload: {
      integrations: IntegrationsDoc;
      toggle: SettingsToggleEntry[];
      exploits?: ExploitsInfo;
    } = {
      integrations: draftIntegrations,
      toggle: togglesToEntries(draftToggles, savedToggleIds),
    };
    // Like vulndb, once the section exists it rides along in every PUT so a
    // partial payload can never silently reset the server's exploitation config.
    if (draftExploits) payload.exploits = { ...draftExploits };
    const r = await apiRequest<SettingsResponse>("/api/settings", {
      method: "PUT",
      json: payload,
      label: "Save settings",
    });
    setSaving(false);
    if (r.ok) {
      if (r.data) {
        applyDoc(r.data);
        setSaveMessage(`Settings saved (version ${r.data.version}).`);
        notify("Settings saved.", "info");
      } else {
        setSaveError("Save settings failed: empty response.");
      }
    } else {
      // 400 (bad payload/glob) and 403 (viewer/operator) messages surface as returned.
      setSaveError(r.error);
      notify(r.error);
    }
  }

  function discard() {
    if (doc) applyDoc(doc);
  }

  async function resetToDefaults() {
    if (!window.confirm("Reset to defaults? This removes the server settings overrides.")) return;
    setResetting(true);
    setSaveError(null);
    setSaveMessage(null);
    const r = await apiRequest<SettingsResponse>("/api/settings", {
      method: "DELETE",
      label: "Reset settings",
    });
    setResetting(false);
    if (r.ok) {
      if (r.data) {
        applyDoc(r.data);
        setSaveMessage("Settings reset to defaults.");
        notify("Settings reset to defaults.", "info");
      } else {
        setSaveError("Reset settings failed: empty response.");
      }
    } else {
      setSaveError(r.error);
      notify(r.error);
    }
  }

  // Draft-only ids (custom entries/globs) that no known check row already renders.
  const customToggleIds = useMemo(() => {
    const known = new Set((checks ?? []).map((c) => c.id));
    return Object.keys(draftToggles)
      .filter((id) => !known.has(id))
      .sort();
  }, [draftToggles, checks]);

  const busy = saving || resetting;
  /** Wire section for the Exploitation card; null on backends without it. */
  const docExploits =
    doc && typeof exploitsOf(doc)?.enabled === "boolean" ? exploitsOf(doc) : null;

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-rh-bg overflow-hidden">
      {/* Top subbar */}
      <div className="min-h-11 px-6 py-2 border-b border-rh-line bg-rh-surface flex flex-wrap items-center justify-between gap-2 text-xs text-rh-muted shrink-0">
        <div className="flex items-center gap-2">
          <Settings className="w-4 h-4 text-rh-muted" aria-hidden="true" />
          <h2 className="text-rh-text font-semibold text-sm">Settings</h2>
          <span className="text-rh-muted">Server tool integrations and access control</span>
          {doc && (
            <span className="ml-2 px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text text-xs font-medium tabular-nums">
              v{doc.version}
              {!doc.exists && " · defaults"}
            </span>
          )}
          {dirty && (
            <span className="px-2 py-0.5 rounded-[6px] bg-rh-cond/15 text-rh-cond text-xs font-medium">
              unsaved changes
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {onBackToStudio && (
            <button
              type="button"
              onClick={onBackToStudio}
              className={BTN_SECONDARY}
              title="Return to Agent Studio"
            >
              <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Back to Studio</span>
            </button>
          )}
          <button type="button" onClick={refresh} className={BTN_SECONDARY} title="Reload settings, checks and RBAC">
            <RefreshCw
              className={`w-3.5 h-3.5 ${loading || checksLoading || rbacLoading ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            Refresh
          </button>
          {dirty && (
            <>
              <button type="button" onClick={discard} disabled={busy} className={BTN_SECONDARY} title="Discard the draft and show the saved document again">
                Discard
              </button>
              <button
                type="button"
                onClick={save}
                disabled={busy || !doc}
                className={BTN_PRIMARY}
                title="Save the whole settings document"
              >
                <Save className="w-3.5 h-3.5" aria-hidden="true" />
                {saving ? "Saving..." : "Save"}
              </button>
            </>
          )}
        </div>
      </div>

      {/* Load/save result strip */}
      {(loadError || saveError || saveMessage) && (
        <div className="shrink-0 px-6 pt-3 space-y-2">
          {loadError && (
            <p role="alert" className="rounded-[6px] border border-rh-nogo/40 bg-rh-nogo/10 px-3 py-2 text-xs text-rh-nogo">
              {loadError}
            </p>
          )}
          {saveError && (
            <p role="alert" className="rounded-[6px] border border-rh-nogo/40 bg-rh-nogo/10 px-3 py-2 text-xs text-rh-nogo">
              {saveError}
            </p>
          )}
          {saveMessage && !saveError && (
            <p className="rounded-[6px] border border-rh-go/40 bg-rh-go/10 px-3 py-2 text-xs text-rh-go">
              {saveMessage}
            </p>
          )}
        </div>
      )}

      {/* Body */}
      <div className="flex-1 min-h-0 overflow-y-auto p-4 lg:p-6">
        {loading && !doc ? (
          <p className="text-sm text-rh-muted">Loading settings...</p>
        ) : loadError && !doc ? (
          <p className="text-sm text-rh-nogo">{loadError}</p>
        ) : doc ? (
          <div className="mx-auto flex w-full max-w-4xl flex-col gap-4">
            {/* File status line */}
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-rh-muted">
              <span>
                Settings file:{" "}
                <span className="font-mono text-rh-text">{doc.path ?? "not configured"}</span>
                {doc.exists ? "" : " (does not exist yet)"}
              </span>
              <span>
                Status:{" "}
                {doc.editable ? (
                  <span className="text-rh-go">writable by the server</span>
                ) : (
                  <span className="text-rh-cond">read-only (the server cannot write this file)</span>
                )}
              </span>
              <span className="tabular-nums">Overrides: {doc.override_count}</span>
              {doc.shadowing_env && (
                <span className="text-rh-cond">
                  A READYHAI_SETTINGS env file is present but the data-dir file shadows it.
                </span>
              )}
            </div>

            {/* Section 1: Integrations */}
            <SectionCard
              title="Integrations"
              subtitle="Tri-state defaults for scanner categories. auto lets ReadyHai decide what a scan uses."
            >
              <div className="flex flex-col gap-3">
                {INTEGRATION_ROWS.map(({ key, label, help }) => (
                  <div
                    key={key}
                    className="flex flex-col gap-1.5 sm:flex-row sm:items-start sm:justify-between sm:gap-6"
                  >
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-rh-text">{label}</p>
                      <p className={`${MUTED_NOTE} max-w-prose`}>{help}</p>
                      {key === "intrusive" && intrusiveWarning && (
                        <p role="alert" className="mt-1 text-xs text-rh-cond">
                          Intrusive checks cannot be forced on from here. The server rejects
                          intrusive = on; pick auto (the gate decides) or off.
                        </p>
                      )}
                    </div>
                    <TriStateSegment
                      name={`Integration setting for ${label}`}
                      value={draftIntegrations[key]}
                      disabled={busy}
                      onSelect={(v) => setIntegration(key, v)}
                    />
                  </div>
                ))}
              </div>
              <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-rh-line pt-3">
                <p className={`${MUTED_NOTE} max-w-prose`}>
                  Saving replaces the whole settings document. Viewers and operators see an error
                  here: saving requires the admin role.
                </p>
                <button
                  type="button"
                  onClick={resetToDefaults}
                  disabled={busy || !doc.editable}
                  className={BTN_DANGER}
                  title="Reset the server settings to built-in defaults"
                >
                  <RotateCcw className={`w-3.5 h-3.5 ${resetting ? "animate-spin" : ""}`} aria-hidden="true" />
                  Reset to defaults
                </button>
              </div>
            </SectionCard>

            {/* Section 1b: Vulnerability database (display-only) */}
            <SectionCard
              title="Vulnerability database"
              subtitle="Where recorded findings live and how many are open. Read-only: triage findings on the Vulns page or with the readyhai vulns CLI."
            >
              {doc.vulndb && typeof doc.vulndb.enabled === "boolean" ? (
                <div className="flex flex-col gap-3">
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
                    <span
                      className={
                        CHIP +
                        (doc.vulndb.enabled ? " bg-rh-go/15 text-rh-go" : " bg-rh-raised text-rh-muted")
                      }
                    >
                      {doc.vulndb.enabled ? "vuln database enabled" : "vuln database disabled"}
                    </span>
                    <span className="text-rh-muted">
                      Path:{" "}
                      <span className="font-mono text-rh-text">
                        {doc.vulndb.path ?? "default data dir"}
                      </span>
                    </span>
                  </div>
                  <p className={MUTED_NOTE}>
                    Open findings:{" "}
                    <span className="tabular-nums text-rh-text">
                      {openVulnCount === null ? "—" : openVulnCount}
                    </span>
                    {openVulnCount === null && " (not reported by this backend version)"}
                  </p>
                </div>
              ) : (
                <p className={MUTED_NOTE}>
                  Vulnerability database status is not reported by this backend version. Update the
                  server to see its path and open-finding count here.
                </p>
              )}
            </SectionCard>

            {/* Section 1c: Exploitation verification (editable, rides along in every PUT) */}
            {docExploits && (
              <SectionCard
                title="Exploitation"
                subtitle="Safe verification of recorded findings. While disabled the server refuses verification runs; the Vulns page shows a Verify button for findings an exploit template covers."
              >
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
                  <button
                    type="button"
                    role="switch"
                    aria-checked={draftExploits?.enabled ?? false}
                    aria-label="Exploitation enabled"
                    disabled={!doc.editable || !draftExploits}
                    onClick={() => setExploitsEnabled(!(draftExploits?.enabled ?? false))}
                    className={
                      CHIP +
                      " cursor-pointer transition-colors disabled:cursor-not-allowed disabled:opacity-50 " +
                      (draftExploits?.enabled
                        ? "bg-rh-go/15 text-rh-go"
                        : "bg-rh-raised text-rh-muted") +
                      " " +
                      FOCUS
                    }
                    title="Let ReadyHai replay an exploit template against a finding to confirm it"
                  >
                    {draftExploits?.enabled ? "exploitation enabled" : "exploitation disabled"}
                  </button>
                  <span className="flex items-center gap-2 text-rh-muted">
                    Max probes per run
                    <input
                      type="number"
                      min={MAX_PROBES_MIN}
                      max={MAX_PROBES_MAX}
                      step={1}
                      className={INPUT + " w-20 tabular-nums"}
                      aria-label={`Max probes (${MAX_PROBES_MIN} to ${MAX_PROBES_MAX})`}
                      disabled={!doc.editable || !draftExploits}
                      value={draftExploits?.max_probes ?? EXPLOITS_DEFAULT.max_probes}
                      onChange={(e) => {
                        const next = Number(e.target.value);
                        if (Number.isFinite(next)) setExploitsMaxProbes(next);
                      }}
                    />
                  </span>
                </div>
                <p className={MUTED_NOTE}>
                  Each Verify click replays one safe template against one finding and records the
                  verdict (verified / not reproducible / inconclusive) on the finding. Bounds:{" "}
                  {MAX_PROBES_MIN}&ndash;{MAX_PROBES_MAX} probes per run.
                </p>
              </SectionCard>
            )}

            {/* Section 2: Checks & plugins */}
            <SectionCard
              title="Checks & plugins"
              subtitle="Every known check and how it is decided today. Flip ids (or globs like plugin.*) into the draft; nothing is sent until Save."
            >
              {checksLoading && !checks ? (
                <p className="text-sm text-rh-muted">Loading checks...</p>
              ) : checksError ? (
                <p className="text-sm text-rh-nogo">{checksError}</p>
              ) : !checks || checks.length === 0 ? (
                <p className="text-sm text-rh-muted">No checks reported by this server.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-rh-line text-rh-muted">
                        <th className="py-2 pr-3 font-medium">Check</th>
                        <th className="py-2 pr-3 font-medium">Source</th>
                        <th className="py-2 pr-3 font-medium">Kinds</th>
                        <th className="py-2 pr-3 font-medium">Intrusive</th>
                        <th className="py-2 pr-3 font-medium">Effective</th>
                        <th className="py-2 font-medium">Toggle</th>
                      </tr>
                    </thead>
                    <tbody>
                      {checks.map((c) => (
                        <tr key={c.id} className="border-b border-rh-line/50 last:border-0 align-top">
                          <td className="py-2 pr-3">
                            <span className="block font-medium text-rh-text">{c.title}</span>
                            <span className="block font-mono text-rh-muted">{c.id}</span>
                          </td>
                          <td className="py-2 pr-3">
                            <span
                              className={`${CHIP} ${
                                c.source === "plugin"
                                  ? "bg-rh-info/15 text-rh-info"
                                  : "bg-rh-raised text-rh-muted"
                              }`}
                            >
                              {c.source}
                            </span>
                          </td>
                          <td className="py-2 pr-3 text-rh-muted">{c.kinds.join(", ") || "—"}</td>
                          <td className="py-2 pr-3">
                            {c.intrusive ? (
                              <span className={`${CHIP} bg-rh-cond/15 text-rh-cond`}>intrusive</span>
                            ) : (
                              <span className="text-rh-muted">no</span>
                            )}
                          </td>
                          <td className="py-2 pr-3">
                            <span className={c.enabled ? "text-rh-go" : "text-rh-nogo"}>
                              {c.enabled ? "on" : "off"}
                            </span>
                            <span className="block text-rh-muted">by {c.decided_by}</span>
                            {!c.enabled && c.reason && (
                              <span className="block max-w-[240px] text-rh-cond">{c.reason}</span>
                            )}
                          </td>
                          <td className="py-2">
                            <select
                              aria-label={`Toggle for ${c.id}`}
                              value={draftToggles[c.id] ?? "auto"}
                              onChange={(e) => setToggle(c.id, e.target.value as TriState)}
                              disabled={busy}
                              className={`${INPUT} cursor-pointer`}
                            >
                              {TRI_STATES.map((v) => (
                                <option key={v} value={v}>
                                  {TRI_LABEL[v]}
                                </option>
                              ))}
                            </select>
                          </td>
                        </tr>
                      ))}
                      {customToggleIds.map((id) => (
                        <tr key={id} className="border-b border-rh-line/50 last:border-0 align-top">
                          <td className="py-2 pr-3">
                            <span className="block font-medium text-rh-text">
                              Custom entry
                              <span className={`${CHIP} ml-1 bg-rh-primary/15 text-rh-primary`}>added</span>
                            </span>
                            <span className="block font-mono text-rh-muted">{id}</span>
                          </td>
                          <td className="py-2 pr-3 text-rh-muted">—</td>
                          <td className="py-2 pr-3 text-rh-muted">—</td>
                          <td className="py-2 pr-3 text-rh-muted">—</td>
                          <td className="py-2 pr-3 text-rh-muted">not matched yet</td>
                          <td className="py-2">
                            <div className="flex items-center gap-1.5">
                              <select
                                aria-label={`Toggle for ${id}`}
                                value={draftToggles[id]}
                                onChange={(e) => setToggle(id, e.target.value as TriState)}
                                disabled={busy}
                                className={`${INPUT} cursor-pointer`}
                              >
                                {TRI_STATES.map((v) => (
                                  <option key={v} value={v}>
                                    {TRI_LABEL[v]}
                                  </option>
                                ))}
                              </select>
                              <button
                                type="button"
                                onClick={() => removeToggle(id)}
                                disabled={busy}
                                aria-label={`Remove toggle for ${id}`}
                                title="Remove this draft entry"
                                className="cursor-pointer rounded-sm p-1 text-rh-muted hover:bg-rh-raised hover:text-rh-nogo"
                              >
                                ×
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="mt-3 flex flex-col gap-1.5 border-t border-rh-line pt-3">
                <label htmlFor="settings-custom-toggle-id" className="text-xs font-medium text-rh-text">
                  Add custom toggle
                </label>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    id="settings-custom-toggle-id"
                    type="text"
                    value={customId}
                    onChange={(e) => {
                      setCustomId(e.target.value);
                      setCustomError(null);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        addCustomToggle();
                      }
                    }}
                    placeholder="tool.nuclei or plugin.*"
                    spellCheck={false}
                    className={`${INPUT} w-64 font-mono`}
                  />
                  <button type="button" onClick={addCustomToggle} disabled={busy} className={BTN_SECONDARY}>
                    <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                    Add
                  </button>
                </div>
                {customError ? (
                  <p className="text-xs text-rh-nogo">{customError}</p>
                ) : (
                  <p className={MUTED_NOTE}>
                    Globs like plugin.* are accepted here; the server validates the pattern on Save and
                    rejects invalid ones.
                  </p>
                )}
              </div>
            </SectionCard>

            {/* Section 3: Access control (RBAC) */}
            <SectionCard
              title="Access control (RBAC)"
              subtitle="Read-only view of the server RBAC status. Editing rbac.toml requires access to the server."
            >
              {rbacLoading && !rbac && !rbacDenied && !rbacError ? (
                <p className="text-sm text-rh-muted">Loading access control...</p>
              ) : rbacDenied ? (
                <p className={MUTED_NOTE}>RBAC details require admin. Your role can see settings but not keys.</p>
              ) : rbacError ? (
                <p className="text-sm text-rh-nogo">{rbacError}</p>
              ) : rbac ? (
                <div className="flex flex-col gap-3">
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
                    <span className={CHIP + (rbac.enabled ? " bg-rh-go/15 text-rh-go" : " bg-rh-raised text-rh-muted")}>
                      {rbac.enabled ? "RBAC enabled" : "RBAC disabled"}
                    </span>
                    <span className="text-rh-muted">
                      Mode: <span className="text-rh-text">{rbac.mode}</span>
                    </span>
                    <span className="text-rh-muted">
                      File: <span className="font-mono text-rh-text">{rbac.file ?? "not configured"}</span>
                    </span>
                    {rbac.boot_admin && (
                      <span
                        className={CHIP + " bg-rh-cond/15 text-rh-cond"}
                        title="A bootstrap admin route is active on this server"
                      >
                        boot admin enabled
                      </span>
                    )}
                    <span className="text-rh-muted">
                      Keys by role: viewer <span className="tabular-nums text-rh-text">{rbac.counts.viewer}</span>
                      {" · "}operator <span className="tabular-nums text-rh-text">{rbac.counts.operator}</span>
                      {" · "}admin <span className="tabular-nums text-rh-text">{rbac.counts.admin}</span>
                    </span>
                  </div>

                  {rbac.keys.length === 0 ? (
                    <p className="text-sm text-rh-muted">No API keys are registered.</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="border-b border-rh-line text-rh-muted">
                            <th className="py-2 pr-3 font-medium">Name</th>
                            <th className="py-2 pr-3 font-medium">Role</th>
                            <th className="py-2 font-medium">Fingerprint</th>
                          </tr>
                        </thead>
                        <tbody>
                          {rbac.keys.map((k) => (
                            <tr key={`${k.name}-${k.fingerprint}`} className="border-b border-rh-line/50 last:border-0">
                              <td className="py-2 pr-3 text-rh-text">{k.name}</td>
                              <td className="py-2 pr-3">
                                <span className={`${CHIP} bg-rh-raised text-rh-muted`}>{k.role}</span>
                              </td>
                              <td className="py-2 font-mono text-rh-muted">{k.fingerprint}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  <p className={MUTED_NOTE}>
                    Read-only here: edit rbac.toml on the server and restart it to change keys.
                  </p>
                </div>
              ) : (
                <p className="text-sm text-rh-muted">RBAC status unavailable.</p>
              )}
            </SectionCard>

            <div className="flex items-center gap-2 text-xs text-rh-muted">
              <SlidersHorizontal className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span>Changes stay local until Save writes the whole document with PUT /api/settings.</span>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
