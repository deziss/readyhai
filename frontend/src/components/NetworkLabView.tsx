"use client";

import { useState, useEffect } from "react";
import {
  Activity,
  Globe,
  Sliders,
  Play,
  RotateCw,
  Terminal,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Clock,
  WifiOff,
  Cpu,
  Layers,
  ChevronDown,
  ChevronUp,
  BrainCircuit,
  Zap,
  Download,
  GitPullRequest,
  Compass,
  Lock,
  Unlock,
  Network,
  FileCode,
  Flame,
  ShieldCheck,
} from "lucide-react";
import { apiRequest, notify, useApiTokenVersion } from "@/lib/api";
import { copyTextSafely } from "@/lib/clipboard";
import {
  deepAuditKey,
  isDeepAuditFresh,
  readDeepAuditCache,
  writeDeepAuditCache,
  type DeepAuditEntry,
} from "@/lib/deepAuditCache";
import type {
  RegressRequest,
  RegressReport,
  IterationResult,
  CurlTestResponse,
  DeepAuditReport,
  MultiRegionReport,
  PrCommentResponse,
} from "@/types/network";

interface NetworkLabViewProps {
  initialTarget?: string;
  /** `failed` is true when the run ended in an error rather than a result. */
  onRunningChange?: (running: boolean, detail: string, failed?: boolean) => void;
  /** Score of the currently loaded agent run's evidence ledger, or null when there is no real one. */
  ledgerScore?: number | null;
}

// Badge URLs are origin-relative and go through the Next.js /api proxy.
const badgeBase = () => (typeof window === "undefined" ? "" : window.location.origin);

const FOCUS = "focus-visible:outline-2 focus-visible:outline-rh-primary";
const BTN_PRIMARY = `inline-flex items-center justify-center gap-2 px-4 py-2 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS}`;
const BTN_SECONDARY = `inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS}`;
const INPUT_CLS =
  "bg-rh-bg border border-rh-line rounded-[6px] text-xs text-rh-text placeholder:text-rh-muted focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
const PANEL = "p-4 rounded-[10px] bg-rh-surface border border-rh-line";
const KPI_CARD = "p-4 rounded-[10px] bg-rh-surface border border-rh-line flex flex-col justify-between";
const PILLAR_TITLE = "text-sm font-semibold text-rh-text flex items-center gap-2";
const KV_ROW = "flex justify-between gap-3";
const CHIP = "text-xs font-semibold px-2 py-0.5 rounded-[6px]";

/** "CRITICAL" -> "Critical". Backend enum values are shown in sentence case. */
const sentence = (s: string | null | undefined) =>
  s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "";

function tabClass(active: boolean) {
  return `flex items-center gap-2 px-3.5 py-1.5 rounded-[6px] text-xs font-medium transition-colors cursor-pointer ${FOCUS} ${
    active ? "bg-rh-primary/15 text-rh-primary font-semibold" : "text-rh-muted hover:text-rh-text hover:bg-rh-raised"
  }`;
}

export function NetworkLabView({
  initialTarget = "http://readyhai:8080",
  onRunningChange,
  ledgerScore = null,
}: NetworkLabViewProps) {
  // Mode selection: "regress" | "deep_audit"
  const [activeTab, setActiveTab] = useState<"regress" | "deep_audit" | "multi_region" | "pr_gate">("regress");

  // Common target
  const [target, setTarget] = useState(initialTarget);
  const targetKey = deepAuditKey(target);
  const [timeoutMs, setTimeoutMs] = useState(5000);

  // Regressive test configuration
  const [method, setMethod] = useState("GET");
  const [iterations, setIterations] = useState(10);
  const [isCustomIterations, setIsCustomIterations] = useState(false);
  const [throttleProfile, setThrottleProfile] = useState("unthrottled");
  const [customLatency] = useState(120);
  const [separateSessions, setSeparateSessions] = useState(true);
  const [delayBetweenMs, setDelayBetweenMs] = useState(25);
  const [customHeaders, setCustomHeaders] = useState("");
  const [showAdvancedHeaders, setShowAdvancedHeaders] = useState(false);
  const [customPayload] = useState("");

  // Regressive Results
  const [isRegressRunning, setIsRegressRunning] = useState(false);
  const [regressReport, setRegressReport] = useState<RegressReport | null>(null);
  const [selectedIteration, setSelectedIteration] = useState<IterationResult | null>(null);

  // Deep Audit Results
  const [isDeepAuditRunning, setIsDeepAuditRunning] = useState(false);
  // Audits are kept per target (with the time they finished). Only the entry for the CURRENT target
  // is ever shown, used for badges or sent to the PR-comment endpoint.
  const [deepAuditEntries, setDeepAuditEntries] = useState<Record<string, DeepAuditEntry>>({});
  const deepAuditEntry: DeepAuditEntry | null = deepAuditEntries[targetKey] ?? null;
  const deepAuditReport: DeepAuditReport | null = deepAuditEntry?.report ?? null;
  const [deepAuditError, setDeepAuditError] = useState<string | null>(null);
  const [showRemediation, setShowRemediation] = useState(false);

  // Restore this target's cached deep audit (never another target's) when the target changes.
  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) return;
      const cached = readDeepAuditCache(targetKey);
      if (cached) setDeepAuditEntries((prev) => (prev[targetKey] ? prev : { ...prev, [targetKey]: cached }));
    });
    return () => {
      cancelled = true;
    };
  }, [targetKey]);

  // cURL Runner
  const [isCurlRunning, setIsCurlRunning] = useState(false);
  const [curlResult, setCurlResult] = useState<CurlTestResponse | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [isMultiRegionRunning, setIsMultiRegionRunning] = useState(false);
  const [multiRegionReport, setMultiRegionReport] = useState<MultiRegionReport | null>(null);
  // The generated comment is bound to the target AND the audit it was built from.
  const [prCommentEntry, setPrCommentEntry] = useState<{
    key: string;
    auditTs: number;
    data: PrCommentResponse;
  } | null>(null);
  const [prLoadingKey, setPrLoadingKey] = useState<string | null>(null);
  const prCommentData =
    prCommentEntry && prCommentEntry.key === targetKey && prCommentEntry.auditTs === deepAuditEntry?.ts
      ? prCommentEntry.data
      : null;
  const isPrCommentLoading = prLoadingKey === targetKey;
  // Last failed action (regress / cURL / multi-region / PR comment). Cleared when a new action starts.
  const [labError, setLabError] = useState<string | null>(null);
  const [probeIp, setProbeIp] = useState<string | null>(null);
  const tokenVersion = useApiTokenVersion();

  // Requester egress IP from the backend. No fallback value: if the lookup fails it stays unknown.
  useEffect(() => {
    let cancelled = false;
    apiRequest<{ egress_public_ip?: string }>("/api/network/requester-ip", { label: "Requester IP lookup" }).then((r) => {
      if (cancelled) return;
      setProbeIp(r.ok && r.data?.egress_public_ip ? r.data.egress_public_ip : null);
    });
    return () => {
      cancelled = true;
    };
  }, [tokenVersion]);
  const requesterIp = regressReport?.requester_ip || deepAuditReport?.requester_ip || probeIp;

  // Parse headers helper
  const getParsedHeaders = (): Record<string, string> => {
    const res: Record<string, string> = {};
    if (!customHeaders.trim()) return res;
    for (const line of customHeaders.split("\n")) {
      const idx = line.indexOf(":");
      if (idx !== -1) {
        const k = line.substring(0, idx).trim();
        const v = line.substring(idx + 1).trim();
        if (k) res[k] = v;
      }
    }
    return res;
  };

  // A non-empty absolute http(s) URL, or an error message to show instead of calling the backend.
  function validTarget(): string | null {
    const t = target.trim();
    if (!t) {
      return "Enter a target URL first (e.g. http://host.docker.internal:3000 or https://app.example.com).";
    }
    let u: URL;
    try {
      u = new URL(t);
    } catch {
      return `"${t}" is not a valid URL. Include the scheme, e.g. https://${t}.`;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return "Target must be an http:// or https:// URL.";
    }
    return null;
  }

  // Run continuous regress test
  async function handleRunRegress() {
    const bad = validTarget();
    if (bad) {
      setLabError(bad);
      notify(bad);
      return;
    }
    setIsRegressRunning(true);
    setCurlResult(null);
    setLabError(null);
    onRunningChange?.(true, `Regressive network test (${iterations}x iterations)`);
    let failure: string | null = null;
    {
      const payload: RegressRequest = {
        target,
        method,
        headers: getParsedHeaders(),
        payload: customPayload.trim() ? customPayload.trim() : null,
        iterations,
        timeout_ms: timeoutMs,
        throttle_profile: throttleProfile,
        simulated_latency_ms: throttleProfile === "custom" ? customLatency : 0,
        separate_sessions: separateSessions,
        delay_between_ms: delayBetweenMs,
      };

      const r = await apiRequest<RegressReport>("/api/network/regress", {
        method: "POST",
        json: payload,
        label: "Regressive test",
      });

      if (r.ok && r.data) {
        setRegressReport(r.data);
        if (r.data.iterations && r.data.iterations.length > 0) {
          setSelectedIteration(r.data.iterations[0]);
        }
      } else {
        failure = r.ok ? "Regressive test failed: empty response." : r.error;
      }
    }
    if (failure) {
      setLabError(failure);
      notify(failure);
    }
    setIsRegressRunning(false);
    onRunningChange?.(false, failure ? "Regressive test failed" : `Completed ${iterations}x regressive test`, !!failure);
  }

  // Run 6-Pillar Deep Audit
  async function handleRunDeepAudit() {
    const bad = validTarget();
    if (bad) {
      setDeepAuditError(bad);
      notify(bad);
      return;
    }
    // The result belongs to the target it was run for, even if the field is edited while it runs.
    const auditKey = targetKey;
    setIsDeepAuditRunning(true);
    setDeepAuditError(null);
    onRunningChange?.(true, "6-pillar deep network and protocol audit");
    const r = await apiRequest<DeepAuditReport>("/api/network/deep-audit", {
      method: "POST",
      json: { target: auditKey, timeout_ms: timeoutMs },
      label: "Deep audit",
    });
    let failed = false;
    if (r.ok && r.data) {
      const entry: DeepAuditEntry = { key: auditKey, ts: Date.now(), report: r.data };
      setDeepAuditEntries((prev) => ({ ...prev, [auditKey]: entry }));
      writeDeepAuditCache(entry);
    } else {
      failed = true;
      setDeepAuditError(r.ok ? "Deep audit failed: empty response." : r.error);
    }
    setIsDeepAuditRunning(false);
    onRunningChange?.(false, failed ? "6-pillar deep protocol audit failed" : "Completed 6-pillar deep protocol audit", failed);
  }

  // Run cURL test
  async function handleRunCurl() {
    const bad = validTarget();
    if (bad) {
      setLabError(bad);
      notify(bad);
      return;
    }
    setIsCurlRunning(true);
    setLabError(null);
    const r = await apiRequest<CurlTestResponse>("/api/network/curl", {
      method: "POST",
      json: {
        target,
        method,
        headers: getParsedHeaders(),
        payload: customPayload.trim() ? customPayload.trim() : null,
        timeout_ms: timeoutMs,
      },
      label: "cURL probe",
    });
    if (r.ok && r.data) {
      setCurlResult(r.data);
    } else {
      const msg = r.ok ? "cURL probe failed: empty response." : r.error;
      setLabError(msg);
      notify(msg);
    }
    setIsCurlRunning(false);
  }

    async function handleRunMultiRegion() {
    const bad = validTarget();
    if (bad) {
      setLabError(bad);
      notify(bad);
      return;
    }
    setIsMultiRegionRunning(true);
    setLabError(null);
    onRunningChange?.(true, `Probing 4-region edge mesh (${target})`);
    const r = await apiRequest<MultiRegionReport>("/api/network/multi-region", {
      method: "POST",
      json: { target, timeout_ms: timeoutMs },
      label: "Multi-region probe",
    });
    let failed = false;
    if (r.ok && r.data) {
      setMultiRegionReport(r.data);
    } else {
      failed = true;
      const msg = r.ok ? "Multi-region probe failed: empty response." : r.error;
      setLabError(msg);
      notify(msg);
    }
    setIsMultiRegionRunning(false);
    onRunningChange?.(false, failed ? "4-region edge mesh probe failed" : "Completed 4-region edge mesh probe", failed);
  }

  async function handleFetchPrComment() {
    // The PR comment carries a verdict and score, so it needs a measured one for THIS target: no
    // default PASS / score, no other target's audit, and nothing stale.
    if (!deepAuditEntry) {
      setLabError(`Run the 6-pillar protocol audit for ${targetKey || "this target"} first: the PR comment needs its measured verdict and score.`);
      return;
    }
    if (!isDeepAuditFresh(deepAuditEntry)) {
      setLabError(
        `The 6-pillar audit for ${targetKey} is from ${new Date(deepAuditEntry.ts).toLocaleString()} and is too old to post. Re-run it first.`
      );
      return;
    }
    const { key, ts, report } = deepAuditEntry;
    setPrLoadingKey(key);
    setLabError(null);
    const r = await apiRequest<PrCommentResponse>("/api/github/pr-comment", {
      method: "POST",
      json: {
        target: key,
        verdict: report.overall_verdict,
        score: report.health_score,
      },
      label: "PR comment",
    });
    if (r.ok && r.data) {
      setPrCommentEntry({ key, auditTs: ts, data: r.data });
    } else {
      const msg = r.ok ? "PR comment failed: empty response." : r.error;
      setLabError(msg);
      notify(msg);
    }
    setPrLoadingKey((cur) => (cur === key ? null : cur));
  }

  function handleExportHar() {
    // Export only measured data: with no regressive-test result there is nothing real to export.
    if (!regressReport || regressReport.iterations.length === 0) {
      const msg = "Nothing to export: run a regressive test first (the HAR is built from its measured iterations).";
      setLabError(msg);
      notify(msg);
      return;
    }
    const harData = {
        log: {
          version: "1.2",
          creator: { name: "ReadyHai Network Lab", version: "0.1.0" },
          pages: [
            {
              startedDateTime: regressReport.iterations[0]?.timestamp || new Date().toISOString(),
              id: "page_readyhai_regression",
              title: `ReadyHai Regression Audit - ${regressReport.target}`,
              pageTimings: {
                onContentLoad: Number(regressReport.p50_latency_ms),
                onLoad: Number(regressReport.p90_latency_ms),
              },
            },
          ],
          entries: regressReport.iterations.map((it) => {
            const wait = Number(it.ttfb_ms);
            const total = Number(it.duration_ms);
            const receive = Math.max(0, total - wait);
            return {
              startedDateTime: it.timestamp,
              time: total,
              request: {
                method: method || "GET",
                url: regressReport.target,
                httpVersion: "HTTP/1.1",
                cookies: [],
                headers: Object.entries(it.response_headers || {}).map(([k, v]) => ({ name: k, value: v })),
                queryString: [],
                headersSize: -1,
                bodySize: 0,
              },
              response: {
                status: it.status_code,
                statusText: it.success ? "OK" : "Error",
                httpVersion: "HTTP/1.1",
                cookies: [],
                headers: Object.entries(it.response_headers || {}).map(([k, v]) => ({ name: k, value: v })),
                content: {
                  size: (it.response_body_snippet || "").length,
                  mimeType: it.response_headers?.["content-type"] || "",
                  text: it.response_body_snippet || "",
                },
                redirectURL: "",
                headersSize: -1,
                bodySize: (it.response_body_snippet || "").length,
              },
              cache: {},
              timings: {
                blocked: 0,
                dns: Number(it.dns_lookup_ms),
                connect: Number(it.tcp_connect_ms),
                ssl: 0,
                send: 1,
                wait: wait,
                receive: receive,
              },
              connection: it.session_id,
            };
          }),
        },
    };

    const blob = new Blob([JSON.stringify(harData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `readyhai-trace-${Date.now()}.har`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Badge values come only from measured results; nothing is defaulted to PASS / a score / "Optimal".
  const gateStatus = deepAuditReport?.overall_verdict ? deepAuditReport.overall_verdict.toUpperCase() : null;
  const gateBadgeText = gateStatus ?? "not evaluated";
  const gateBadgeColor =
    gateStatus === "PASS" ? "#22c55e" : gateStatus === "WARN" ? "#eab308" : gateStatus ? "#ef4444" : "#475569";
  const meshTotal = multiRegionReport?.regions.length ?? 0;
  const meshOptimal = multiRegionReport ? multiRegionReport.regions.filter((r) => r.status === "OPTIMAL").length : 0;
  const meshBadgeText = meshTotal > 0 ? `${meshOptimal}/${meshTotal} optimal` : null;
  const meshBadgeColor =
    meshTotal === 0 ? "#475569" : meshOptimal === meshTotal ? "#10b981" : meshOptimal === 0 ? "#ef4444" : "#eab308";

  const copyToClipboard = async (text: string, id: string) => {
    if (!(await copyTextSafely(text))) return;
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  return (
    <div className="flex-1 min-h-0 flex flex-col h-full overflow-hidden bg-rh-bg text-rh-text">
      {/* Sub-header navigation tabs */}
      <div className="border-b border-rh-line bg-rh-surface px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex flex-wrap items-center gap-1 p-1 bg-rh-bg rounded-[10px] border border-rh-line">
            <button
              id="tab-regress-stress"
              onClick={() => setActiveTab("regress")}
              type="button"
              aria-pressed={activeTab === "regress"}
              className={tabClass(activeTab === "regress")}
            >
              <Activity className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Regressive lab</span>
            </button>

            <button
              id="tab-deep-audit"
              onClick={() => {
                setActiveTab("deep_audit");
                if (!deepAuditReport && !isDeepAuditRunning) {
                  handleRunDeepAudit();
                }
              }}
              type="button"
              aria-pressed={activeTab === "deep_audit"}
              className={tabClass(activeTab === "deep_audit")}
            >
              <Network className="w-3.5 h-3.5" aria-hidden="true" />
              <span>6-pillar protocol audit</span>
            </button>

            <button
              id="tab-multi-region"
              onClick={() => {
                setActiveTab("multi_region");
                if (!multiRegionReport && !isMultiRegionRunning) {
                  handleRunMultiRegion();
                }
              }}
              type="button"
              aria-pressed={activeTab === "multi_region"}
              className={tabClass(activeTab === "multi_region")}
            >
              <Compass className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Multi-region mesh</span>
            </button>

            <button
              id="tab-pr-gate"
              onClick={() => {
                setActiveTab("pr_gate");
                if (isDeepAuditFresh(deepAuditEntry) && !prCommentData && !isPrCommentLoading) {
                  handleFetchPrComment();
                }
              }}
              type="button"
              aria-pressed={activeTab === "pr_gate"}
              className={tabClass(activeTab === "pr_gate")}
            >
              <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
              <span>PR status gate</span>
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 px-3 py-1 rounded-[6px] bg-rh-surface border border-rh-line text-xs">
            <Globe className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
            <span className="text-rh-muted">Active URL</span>
            <span className="text-rh-text font-mono truncate max-w-[18rem]">{target}</span>
          </div>

          {/* Requester egress IP */}
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-[6px] bg-rh-surface border border-rh-line text-xs" title="Requester public egress IP. Add this IP to your target firewall or cloud security group allowlist for private network testing.">
            <span className="text-rh-muted">Requester IP</span>
            <span className="text-rh-text font-mono tabular-nums">{requesterIp || "unknown"}</span>
            <button
              type="button"
              disabled={!requesterIp}
              onClick={() => requesterIp && copyToClipboard(requesterIp, "probe-ip")}
              className={`text-rh-muted hover:text-rh-text ml-1 p-1 rounded-[6px] cursor-pointer transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
              title="Copy IP for firewall allowlist"
              aria-label="Copy requester IP"
            >
              {copiedText === "probe-ip" ? <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
            </button>
          </div>

          {/* Export HAR */}
          <button
            id="btn-export-har"
            type="button"
            onClick={handleExportHar}
            className={BTN_SECONDARY}
            title="Download an HTTP Archive (HAR 1.2) for Chrome DevTools or support tickets"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Export HAR</span>
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className={`flex-1 min-h-0 ${activeTab === "regress" ? "grid grid-cols-1 xl:grid-cols-12 xl:grid-rows-1 overflow-y-auto xl:overflow-hidden" : "flex flex-col overflow-hidden bg-rh-bg"}`}>
        {/* Left config sidebar (regressive lab only) */}
        {activeTab === "regress" && (
          <aside className="xl:col-span-4 xl:min-h-0 xl:overflow-y-auto border-b xl:border-b-0 xl:border-r border-rh-line bg-rh-surface p-4 space-y-4 text-xs">
            {/* Header: Compact & Professional */}
            <div className="flex items-center justify-between pb-2 border-b border-rh-line">
              <div className="flex items-center gap-2">
                <Sliders className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                <h2 className="text-sm font-semibold text-rh-text">Environment and target</h2>
              </div>
              <span
                className="text-xs text-rh-muted bg-rh-raised px-2 py-0.5 rounded-[6px] font-medium tabular-nums"
                title="Active execution profile"
              >
                {throttleProfile === "unthrottled" ? "Direct" : throttleProfile.replace(/_/g, " ")} · {iterations}x
              </span>
            </div>

            {/* Target App URL & Method: Unified Group */}
            <div className="space-y-1">
              <label htmlFor="input-target-url" className="text-xs font-medium text-rh-muted flex items-center justify-between">
                <span>Target endpoint</span>
                <span className="text-xs text-rh-muted">HTTP/1.1 and HTTP/2</span>
              </label>
              <div className="flex rounded-[6px] border border-rh-line bg-rh-bg focus-within:border-rh-primary focus-within:ring-1 focus-within:ring-rh-primary overflow-hidden">
                <div className="relative border-r border-rh-line shrink-0">
                  <select
                    id="select-method"
                    aria-label="HTTP method"
                    value={method}
                    onChange={(e) => setMethod(e.target.value)}
                    className="h-8 pl-2.5 pr-6 bg-transparent text-xs font-semibold text-rh-text focus:outline-none cursor-pointer appearance-none"
                  >
                    <option value="GET" className="bg-rh-bg text-rh-text">GET</option>
                    <option value="POST" className="bg-rh-bg text-rh-text">POST</option>
                    <option value="PUT" className="bg-rh-bg text-rh-text">PUT</option>
                    <option value="DELETE" className="bg-rh-bg text-rh-text">DELETE</option>
                    <option value="HEAD" className="bg-rh-bg text-rh-text">HEAD</option>
                  </select>
                  <ChevronDown className="w-3.5 h-3.5 text-rh-muted absolute right-1.5 top-2.5 pointer-events-none" aria-hidden="true" />
                </div>
                <div className="relative flex-1 flex items-center min-w-0">
                  <Globe className="w-3.5 h-3.5 text-rh-muted absolute left-2.5 pointer-events-none shrink-0" aria-hidden="true" />
                  <input
                    id="input-target-url"
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="http://127.0.0.1:8080 or https://app.example.com"
                    className="w-full pl-8 pr-2.5 py-1.5 bg-transparent font-mono text-xs text-rh-text placeholder:text-rh-muted focus:outline-none truncate"
                  />
                </div>
              </div>
            </div>

            {/* Probe Iterations (N) Segmented Selector */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-rh-muted">
                <span>Iterations</span>
                <span className="text-rh-text font-semibold tabular-nums">{iterations} repetitions</span>
              </div>
              <div className="grid grid-cols-6 gap-1 p-0.5 bg-rh-bg border border-rh-line rounded-[6px] text-xs" role="radiogroup" aria-label="Iterations">
                {[5, 10, 25, 50, 100].map((count) => {
                  const active = iterations === count && !isCustomIterations;
                  return (
                    <button
                      key={count}
                      type="button"
                      role="radio"
                      aria-checked={active}
                      onClick={() => {
                        setIsCustomIterations(false);
                        setIterations(count);
                      }}
                      className={`py-1.5 rounded-[6px] text-center font-medium transition-colors cursor-pointer ${FOCUS} ${
                        active
                          ? "bg-rh-primary/15 text-rh-primary font-semibold"
                          : "text-rh-muted hover:text-rh-text hover:bg-rh-raised border border-transparent"
                      }`}
                    >
                      {count}x
                    </button>
                  );
                })}
                <button
                  type="button"
                  role="radio"
                  aria-checked={isCustomIterations}
                  onClick={() => setIsCustomIterations(true)}
                  className={`py-1.5 rounded-[6px] text-center font-medium transition-colors cursor-pointer ${FOCUS} ${
                    isCustomIterations
                      ? "bg-rh-primary/15 text-rh-primary font-semibold"
                      : "text-rh-muted hover:text-rh-text hover:bg-rh-raised border border-transparent"
                  }`}
                >
                  Custom
                </button>
              </div>
              {isCustomIterations && (
                <div className="flex items-center gap-2 pt-1">
                  <label htmlFor="input-custom-iterations" className="text-xs text-rh-muted">Custom count</label>
                  <input
                    id="input-custom-iterations"
                    type="number"
                    min="1"
                    max="100"
                    value={iterations}
                    onChange={(e) => setIterations(Math.max(1, Math.min(100, Number(e.target.value) || 1)))}
                    className={`w-20 px-2 py-1 tabular-nums ${INPUT_CLS}`}
                  />
                  <span className="text-xs text-rh-muted">1 to 100</span>
                </div>
              )}
            </div>

            {/* Socket Isolation Radio Button Switch */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-rh-muted">
                <span className="flex items-center gap-1.5">
                  <WifiOff className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                  <span>Socket isolation</span>
                </span>
                <span
                  className="text-xs font-mono text-rh-muted cursor-help"
                  title="Forces zero connection pooling (pool_max_idle_per_host(0)) to catch socket starvation and TLS leaks."
                >
                  pool_max_idle(0)
                </span>
              </div>
              <div
                className="grid grid-cols-2 gap-1 p-1 bg-rh-bg border border-rh-line rounded-[6px] text-xs"
                role="radiogroup"
                aria-label="Socket isolation mode"
              >
                <button
                  type="button"
                  role="radio"
                  id="toggle-separate-sessions"
                  aria-checked={separateSessions}
                  onClick={() => setSeparateSessions(true)}
                  className={`flex items-center justify-center gap-2 py-1.5 px-2 rounded-[6px] transition-colors cursor-pointer ${FOCUS} ${
                    separateSessions
                      ? "bg-rh-primary/15 text-rh-primary font-semibold"
                      : "text-rh-muted hover:text-rh-text hover:bg-rh-raised border border-transparent"
                  }`}
                >
                  <div className={`w-2.5 h-2.5 rounded-full border flex items-center justify-center shrink-0 ${separateSessions ? "border-rh-primary" : "border-rh-line"}`}>
                    {separateSessions && <div className="w-1.5 h-1.5 rounded-full bg-rh-primary" />}
                  </div>
                  <span className="text-xs truncate">Fresh DNS and TLS</span>
                </button>

                <button
                  type="button"
                  role="radio"
                  aria-checked={!separateSessions}
                  onClick={() => setSeparateSessions(false)}
                  className={`flex items-center justify-center gap-2 py-1.5 px-2 rounded-[6px] transition-colors cursor-pointer ${FOCUS} ${
                    !separateSessions
                      ? "bg-rh-primary/15 text-rh-primary font-semibold"
                      : "text-rh-muted hover:text-rh-text hover:bg-rh-raised border border-transparent"
                  }`}
                >
                  <div className={`w-2.5 h-2.5 rounded-full border flex items-center justify-center shrink-0 ${!separateSessions ? "border-rh-primary" : "border-rh-line"}`}>
                    {!separateSessions && <div className="w-1.5 h-1.5 rounded-full bg-rh-primary" />}
                  </div>
                  <span className="text-xs truncate">Pool and keep-alive</span>
                </button>
              </div>
            </div>

            {/* Network Throttling 4-Option Radio Switch */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-rh-muted">
                <span className="flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                  <span>Network simulation</span>
                </span>
                <span className="text-xs text-rh-text font-semibold">{throttleProfile.replace(/_/g, " ")}</span>
              </div>
              <div
                className="grid grid-cols-4 gap-1 p-1 bg-rh-bg border border-rh-line rounded-[6px] text-xs"
                role="radiogroup"
                aria-label="Network throttling profile"
              >
                {[
                  { id: "unthrottled", label: "Native", desc: "Native network speed (no artificial delay)" },
                  { id: "fast_3g", label: "Fast 3G", desc: "Fast 3G profile (+75ms mobile RTT)" },
                  { id: "slow_3g", label: "Slow 3G", desc: "Slow 3G profile (+250ms high latency)" },
                  { id: "flaky", label: "Flaky", desc: "Flaky network with random jitter and packet drops" },
                ].map((p) => {
                  const active = throttleProfile === p.id;
                  return (
                    <button
                      key={p.id}
                      id={`throttle-${p.id}`}
                      type="button"
                      role="radio"
                      aria-checked={active}
                      title={p.desc}
                      onClick={() => setThrottleProfile(p.id)}
                      className={`py-1.5 px-1 rounded-[6px] flex items-center justify-center gap-1.5 transition-colors cursor-pointer ${FOCUS} ${
                        active
                          ? "bg-rh-primary/15 text-rh-primary font-semibold"
                          : "text-rh-muted hover:text-rh-text hover:bg-rh-raised border border-transparent"
                      }`}
                    >
                      <div className={`w-2 h-2 rounded-full border flex items-center justify-center shrink-0 ${active ? "border-rh-primary" : "border-rh-line"}`}>
                        {active && <div className="w-1 h-1 rounded-full bg-rh-primary" />}
                      </div>
                      <span className="text-xs truncate">{p.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Timing Controls (Timeout & Delay): Compact 2-Column Grid */}
            <div className="grid grid-cols-2 gap-3 pt-0.5">
              <div className="space-y-1">
                <div className="flex justify-between text-xs text-rh-muted">
                  <label htmlFor="range-timeout">Timeout</label>
                  <span className="text-rh-text font-semibold tabular-nums">{timeoutMs}ms</span>
                </div>
                <input
                  id="range-timeout"
                  type="range"
                  min="1000"
                  max="15000"
                  step="500"
                  value={timeoutMs}
                  onChange={(e) => setTimeoutMs(Number(e.target.value))}
                  className="w-full accent-rh-primary h-1 bg-rh-raised rounded-[6px] cursor-pointer focus-visible:outline-2 focus-visible:outline-rh-primary"
                />
              </div>

              <div className="space-y-1">
                <div className="flex justify-between text-xs text-rh-muted">
                  <label htmlFor="range-delay">Delay between probes</label>
                  <span className="text-rh-text font-semibold tabular-nums">{delayBetweenMs}ms</span>
                </div>
                <input
                  id="range-delay"
                  type="range"
                  min="0"
                  max="500"
                  step="25"
                  value={delayBetweenMs}
                  onChange={(e) => setDelayBetweenMs(Number(e.target.value))}
                  className="w-full accent-rh-primary h-1 bg-rh-raised rounded-[6px] cursor-pointer focus-visible:outline-2 focus-visible:outline-rh-primary"
                />
              </div>
            </div>

            {/* Custom headers: collapsible disclosure */}
            <div className="border border-rh-line rounded-[6px] bg-rh-bg overflow-hidden">
              <button
                type="button"
                onClick={() => setShowAdvancedHeaders(!showAdvancedHeaders)}
                aria-expanded={showAdvancedHeaders}
                className={`w-full px-3 py-2.5 flex items-center justify-between text-xs text-rh-text hover:bg-rh-raised transition-colors cursor-pointer ${FOCUS}`}
              >
                <div className="flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                  <span>Custom headers</span>
                  {customHeaders.trim() ? (
                    <span className="px-1.5 py-0.5 bg-rh-raised text-rh-text rounded-[6px] text-xs font-semibold tabular-nums">
                      {customHeaders.trim().split("\n").filter(Boolean).length} set
                    </span>
                  ) : (
                    <span className="text-xs text-rh-muted">Optional</span>
                  )}
                </div>
                {showAdvancedHeaders ? (
                  <ChevronUp className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                )}
              </button>
              {showAdvancedHeaders && (
                <div className="p-2.5 pt-1 border-t border-rh-line">
                  <textarea
                    aria-label="Custom request headers, one per line"
                    value={customHeaders}
                    onChange={(e) => setCustomHeaders(e.target.value)}
                    placeholder={"Authorization: Bearer my-token\nX-Custom-Tenant: prod-1"}
                    rows={2}
                    className={`w-full p-2 font-mono resize-none ${INPUT_CLS}`}
                  />
                </div>
              )}
            </div>

            {/* Primary action: run the regressive test */}
            <div className="pt-0.5">
              <button
                id="btn-run-regress"
                type="button"
                onClick={handleRunRegress}
                disabled={isRegressRunning}
                className={`${BTN_PRIMARY} w-full`}
              >
                {isRegressRunning ? (
                  <>
                    <RotateCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                    <span className="tabular-nums">Probing ({iterations}x)...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
                    <span>Run regressive test</span>
                  </>
                )}
              </button>
            </div>

            {/* cURL action */}
            <div className="pt-0.5">
              <button
                id="btn-run-curl"
                type="button"
                onClick={handleRunCurl}
                disabled={isCurlRunning}
                className={`w-full py-2.5 px-3 rounded-[6px] bg-rh-raised hover:bg-rh-line text-xs text-rh-text font-semibold flex items-center justify-between transition-colors cursor-pointer disabled:opacity-50 ${FOCUS}`}
              >
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                  <span>Stage timing probe</span>
                </span>
                <span className="text-xs font-normal text-rh-muted">
                  {isCurlRunning ? "Probing..." : "Run cURL test"}
                </span>
              </button>
            </div>
          </aside>
        )}

        {/* Main content viewport */}
        <main className={`${activeTab === "regress" ? "xl:col-span-8 xl:min-h-0 p-6 xl:overflow-y-auto" : "flex-1 min-h-0 p-6 overflow-y-auto"}`}>
          <div className={activeTab === "regress" ? "space-y-6" : "max-w-6xl mx-auto w-full space-y-6"}>
          {labError && (
            <div
              className="flex items-start justify-between gap-3 p-3 rounded-[6px] bg-rh-nogo/15 text-xs text-rh-text"
              role="alert"
            >
              <span className="flex items-start gap-2 min-w-0">
                <XCircle className="w-4 h-4 text-rh-nogo shrink-0" aria-hidden="true" />
                <span className="break-words min-w-0">{labError}</span>
              </span>
              <button
                type="button"
                onClick={() => setLabError(null)}
                className={`text-rh-muted hover:text-rh-text shrink-0 cursor-pointer text-xs font-semibold rounded-[6px] px-1.5 py-0.5 ${FOCUS}`}
                aria-label="Dismiss error"
              >
                Dismiss
              </button>
            </div>
          )}
          {/* TAB 1: CONTINUOUS REGRESSIVE TESTING */}
          {activeTab === "regress" && (
            <>
              {/* Hero KPI cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className={KPI_CARD}>
                  <span className="text-xs text-rh-muted">Availability</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className={`text-2xl font-semibold tabular-nums ${
                      !regressReport ? "text-rh-muted" :
                      regressReport.availability_percentage >= 99 ? "text-rh-go" :
                      regressReport.availability_percentage >= 80 ? "text-rh-cond" : "text-rh-nogo"
                    }`}>
                      {regressReport ? `${regressReport.availability_percentage.toFixed(1)}%` : "--"}
                    </span>
                    <span className="text-xs text-rh-muted tabular-nums">
                      {regressReport ? `${regressReport.successful_iterations}/${regressReport.total_iterations}` : "0/0"}
                    </span>
                  </div>
                </div>

                <div className={KPI_CARD}>
                  <span className="text-xs text-rh-muted">P50 latency (median)</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl font-semibold text-rh-text tabular-nums">
                      {regressReport ? `${regressReport.p50_latency_ms}ms` : "--"}
                    </span>
                    <span className="text-xs text-rh-muted tabular-nums">
                      avg {regressReport?.avg_latency_ms || 0}ms
                    </span>
                  </div>
                </div>

                <div className={KPI_CARD}>
                  <span className="text-xs text-rh-muted">P99 latency (tail)</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl font-semibold text-rh-text tabular-nums">
                      {regressReport ? `${regressReport.p99_latency_ms}ms` : "--"}
                    </span>
                    <span className="text-xs text-rh-muted tabular-nums">
                      max {regressReport?.max_latency_ms || 0}ms
                    </span>
                  </div>
                </div>

                <div className={KPI_CARD}>
                  <span className="text-xs text-rh-muted">Network jitter</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className={`text-2xl font-semibold tabular-nums ${
                      !regressReport ? "text-rh-muted" :
                      regressReport.jitter_ms < 100 ? "text-rh-go" :
                      regressReport.jitter_ms < 300 ? "text-rh-cond" : "text-rh-nogo"
                    }`}>
                      {regressReport ? `${regressReport.jitter_ms}ms` : "--"}
                    </span>
                    <span className="text-xs text-rh-muted">
                      {regressReport?.jitter_ms && regressReport.jitter_ms > 200 ? "High variance" : "Low variance"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Empty state before the first run */}
              {!regressReport && !isRegressRunning && (
                <div className="p-8 rounded-[10px] bg-rh-surface border border-dashed border-rh-line text-center space-y-2">
                  <Activity className="w-8 h-8 text-rh-muted mx-auto" aria-hidden="true" />
                  <h3 className="text-sm font-semibold text-rh-text">No regressive test results yet</h3>
                  <p className="text-xs text-rh-muted max-w-md mx-auto">
                    Set the target, iterations and network profile in the sidebar, then choose Run regressive test to
                    measure availability, latency percentiles and jitter.
                  </p>
                </div>
              )}

              {/* Agent root cause diagnosis */}
              {regressReport && (
                <div className={`p-5 rounded-[10px] bg-rh-surface border border-rh-line border-l-4 space-y-4 ${
                  regressReport.diagnosis.severity === "CRITICAL"
                    ? "border-l-rh-nogo"
                    : regressReport.diagnosis.severity === "HIGH"
                    ? "border-l-rh-cond"
                    : "border-l-rh-info"
                }`}>
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="flex items-start gap-2.5 min-w-0">
                      <div className="p-2 rounded-[6px] bg-rh-raised shrink-0" aria-hidden="true">
                        <BrainCircuit className="w-5 h-5 text-rh-muted" aria-hidden="true" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted font-semibold">
                            {regressReport.diagnosis.root_cause_type}
                          </span>
                          <span className={`${CHIP} ${
                            regressReport.diagnosis.severity === "CRITICAL" ? "bg-rh-nogo/15 text-rh-nogo" :
                            regressReport.diagnosis.severity === "HIGH" ? "bg-rh-cond/15 text-rh-cond" : "bg-rh-info/15 text-rh-info"
                          }`}>
                            {sentence(regressReport.diagnosis.severity)}
                          </span>
                        </div>
                        <h3 className="text-base font-semibold text-rh-text mt-1">
                          {regressReport.diagnosis.title}
                        </h3>
                      </div>
                    </div>

                    <div className="text-xs text-rh-muted min-w-0">
                      Target: <span className="text-rh-text font-mono break-all">{regressReport.target}</span>
                    </div>
                  </div>

                  <p className="text-sm text-rh-text leading-relaxed">
                    {regressReport.diagnosis.summary}
                  </p>

                  <div className="space-y-2 pt-3 border-t border-rh-line">
                    <div className="text-xs font-semibold text-rh-text flex items-center gap-2">
                      <Zap className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                      <span>How the agent identified the issue</span>
                    </div>
                    <ul className="space-y-1.5 pl-5 list-disc text-xs text-rh-text">
                      {regressReport.diagnosis.how_agent_found_it.map((step, idx) => (
                        <li key={idx} className="leading-relaxed">{step}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="space-y-2 pt-3 border-t border-rh-line">
                    <div className="text-xs font-semibold text-rh-text flex items-center gap-2">
                      <Cpu className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                      <span>Technical root cause breakdown</span>
                    </div>
                    <ul className="space-y-1.5 pl-5 list-disc text-xs text-rh-text">
                      {regressReport.diagnosis.technical_breakdown.map((item, idx) => (
                        <li key={idx} className="leading-relaxed">{item}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-3.5 rounded-[6px] bg-rh-bg border border-rh-line space-y-2">
                    <span className="text-xs font-semibold text-rh-text flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                      <span>Recommended remediation actions</span>
                    </span>
                    <ol className="space-y-1 text-xs text-rh-text pl-4 list-decimal">
                      {regressReport.diagnosis.remediation_checklist.map((act, idx) => (
                        <li key={idx}>{act}</li>
                      ))}
                    </ol>
                  </div>
                </div>
              )}

              {/* Latency waterfall bar chart */}
              {regressReport && regressReport.iterations.length > 0 && (
                <div className={`${PANEL} space-y-3`}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-rh-text flex items-center gap-2">
                      <Activity className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                      <span>Session latency and handshake distribution ({regressReport.iterations.length} attempts)</span>
                    </span>
                    <span className="text-xs text-rh-muted">
                      Select a bar to inspect that attempt
                    </span>
                  </div>

                  <div className="flex items-end gap-1.5 h-60 pt-28 px-10 overflow-x-auto">
                    {regressReport.iterations.map((it) => {
                      const maxMs = Math.max(...regressReport.iterations.map((i) => Number(i.duration_ms)), 100);
                      const heightPct = Math.min(100, Math.max(10, (Number(it.duration_ms) / maxMs) * 100));
                      const isSelected = selectedIteration?.iteration === it.iteration;

                      return (
                        <button
                          key={it.iteration}
                          type="button"
                          onClick={() => setSelectedIteration(it)}
                          aria-pressed={isSelected}
                          aria-label={`Iteration ${it.iteration}: ${it.status_code || "error"}, ${it.duration_ms} milliseconds`}
                          className={`flex-1 min-w-[20px] max-w-[40px] rounded-t flex flex-col justify-end transition-colors relative group cursor-pointer ${FOCUS} ${
                            it.success
                              ? isSelected ? "bg-rh-primary" : "bg-rh-primary/60 hover:bg-rh-primary"
                              : isSelected ? "bg-rh-nogo" : "bg-rh-nogo/70 hover:bg-rh-nogo"
                          }`}
                          style={{ height: `${heightPct}%` }}
                        >
                          <div className="opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100 absolute bottom-full mb-2 left-1/2 -translate-x-1/2 p-2 bg-rh-raised border border-rh-line rounded-[6px] text-xs text-rh-text text-left whitespace-nowrap z-30 pointer-events-none tabular-nums shadow-lg">
                            <div>Iteration #{it.iteration} ({it.status_code || "error"})</div>
                            <div>DNS: {it.dns_lookup_ms}ms</div>
                            <div>TCP: {it.tcp_connect_ms}ms</div>
                            <div>TTFB: {it.ttfb_ms}ms</div>
                            <div className="font-semibold">Total: {it.duration_ms}ms</div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Iteration session log */}
              {regressReport && regressReport.iterations.length > 0 && (
                <div className={`${PANEL} space-y-3`}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-rh-text flex items-center gap-2">
                      <Clock className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                      <span>Cold session log ({regressReport.iterations.length} iterations)</span>
                    </span>
                    <span className="text-xs text-rh-muted">
                      Each iteration used its own socket
                    </span>
                  </div>

                  <div className="max-h-72 min-h-0 overflow-y-auto border border-rh-line rounded-[6px] bg-rh-bg">
                    <div className="sticky top-0 z-10 flex bg-rh-bg border-b border-rh-line text-xs text-rh-muted">
                      <div className="flex-1 min-w-0 grid grid-cols-[4rem_minmax(0,1fr)_4.5rem_4.5rem_4.5rem_4.5rem] gap-3 px-3 py-2">
                        <span>Status</span>
                        <span>Iteration</span>
                        <span className="text-right">DNS</span>
                        <span className="text-right">TCP</span>
                        <span className="text-right">TTFB</span>
                        <span className="text-right">Total</span>
                      </div>
                      <div className="w-11 shrink-0" aria-hidden="true" />
                    </div>
                    <div className="divide-y divide-rh-line">
                      {regressReport.iterations.map((it) => {
                        const selected = selectedIteration?.iteration === it.iteration;
                        return (
                          <div
                            key={it.iteration}
                            className={`flex items-center text-xs transition-colors ${selected ? "bg-rh-raised" : "hover:bg-rh-raised"}`}
                          >
                            <button
                              type="button"
                              onClick={() => setSelectedIteration(it)}
                              aria-pressed={selected}
                              className={`flex-1 min-w-0 grid grid-cols-[4rem_minmax(0,1fr)_4.5rem_4.5rem_4.5rem_4.5rem] items-center gap-3 px-3 py-2.5 text-left cursor-pointer ${FOCUS}`}
                            >
                              <span className={`justify-self-start px-2 py-0.5 rounded-[6px] text-xs font-semibold tabular-nums ${
                                it.success ? "bg-rh-go/15 text-rh-go" : "bg-rh-nogo/15 text-rh-nogo"
                              }`}>
                                {it.status_code || "ERR"}
                              </span>
                              <span className="min-w-0">
                                <span className="text-rh-text font-semibold block">Iteration #{it.iteration}</span>
                                <span className="text-rh-muted font-mono text-xs block truncate">{it.session_id}</span>
                              </span>
                              <span className="text-right text-rh-text tabular-nums">{it.dns_lookup_ms}ms</span>
                              <span className="text-right text-rh-text tabular-nums">{it.tcp_connect_ms}ms</span>
                              <span className="text-right text-rh-text tabular-nums">{it.ttfb_ms}ms</span>
                              <span className="text-right text-rh-text font-semibold tabular-nums">{it.duration_ms}ms</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(it.curl_command, `curl-${it.iteration}`)}
                              className={`w-11 shrink-0 self-stretch flex items-center justify-center text-rh-muted hover:text-rh-text cursor-pointer ${FOCUS}`}
                              title="Copy reproduction cURL"
                              aria-label={`Copy reproduction cURL for iteration ${it.iteration}`}
                            >
                              {copiedText === `curl-${it.iteration}` ? (
                                <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                              )}
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}

          {/* TAB 2: 6-PILLAR DEEP PROTOCOL AND NETWORK AUDIT */}
          {activeTab === "deep_audit" && (
            <div className="space-y-6">
              {/* Target and action bar */}
              <div className="flex flex-wrap items-center gap-3 p-2.5 rounded-[10px] bg-rh-surface border border-rh-line">
                <div className="relative flex-1 min-w-[16rem]">
                  <Globe className="w-4 h-4 text-rh-muted absolute left-3 top-2.5" aria-hidden="true" />
                  <input
                    id="input-deep-audit-target"
                    type="text"
                    aria-label="Target URL"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="https://app.example.com"
                    className={`w-full pl-9 pr-3 py-2 font-mono ${INPUT_CLS}`}
                  />
                </div>

                <button
                  id="btn-run-deep-audit"
                  type="button"
                  onClick={handleRunDeepAudit}
                  disabled={isDeepAuditRunning}
                  className={`${BTN_PRIMARY} shrink-0`}
                >
                  {isDeepAuditRunning ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                      <span>Auditing 6 pillars...</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>Run complete deep audit</span>
                    </>
                  )}
                </button>
              </div>
              {/* Health banner, live progress, or launch prompt */}
              {isDeepAuditRunning ? (
                <div role="status" className="p-7 rounded-[10px] bg-rh-surface border border-rh-line text-center space-y-4">
                  <RotateCw className="w-7 h-7 text-rh-info animate-spin mx-auto" aria-hidden="true" />
                  <div className="space-y-1">
                    <h3 className="text-base font-semibold text-rh-text flex items-center justify-center gap-2 flex-wrap">
                      <span>Probing all 6 network and protocol pillars</span>
                      <span className="text-xs font-normal font-mono text-rh-text bg-rh-raised px-2 py-0.5 rounded-[6px] break-all">
                        {target}
                      </span>
                    </h3>
                    <p className="text-xs text-rh-muted max-w-lg mx-auto">
                      Running parallel protocol sweeps: IPv4/IPv6 Happy Eyeballs, sub-resource cascade, HTTP/2 ALPN, TLS 1.3 chain, CORS preflight and path MTU black holes. This usually takes 4 to 8 seconds.
                    </p>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2 max-w-xl mx-auto pt-2 text-left text-xs">
                    {[
                      "IPv4 / IPv6 Happy Eyeballs",
                      "Sub-resource cascade",
                      "HTTP/2 and HTTP/3 matrix",
                      "TLS 1.3 chain check",
                      "CORS preflight check",
                      "MTU size sweep",
                    ].map((label, i) => (
                      <div key={label} className="p-2 rounded-[6px] bg-rh-bg border border-rh-line flex items-center gap-2 text-rh-text">
                        <span className="w-1.5 h-1.5 rounded-full bg-rh-info shrink-0" aria-hidden="true" />
                        <span>{i + 1}. {label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : deepAuditError ? (
                <div role="alert" className="p-6 rounded-[10px] bg-rh-surface border border-rh-line border-l-4 border-l-rh-nogo space-y-3">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-rh-nogo shrink-0" aria-hidden="true" />
                    <h3 className="text-sm font-semibold text-rh-text">The deep audit did not complete</h3>
                  </div>
                  <p className="text-xs text-rh-text break-words">{deepAuditError}</p>
                  <p className="text-xs text-rh-muted">
                    Check that the target URL is reachable from the ReadyHai backend, then retry.
                  </p>
                  <button
                    type="button"
                    onClick={handleRunDeepAudit}
                    className={BTN_PRIMARY}
                  >
                    Retry audit
                  </button>
                </div>
              ) : deepAuditReport ? (
                <div className={`p-5 rounded-[10px] bg-rh-surface border border-rh-line border-l-4 space-y-4 ${
                  deepAuditReport.overall_verdict === "PASS"
                    ? "border-l-rh-go"
                    : deepAuditReport.overall_verdict === "WARN"
                    ? "border-l-rh-cond"
                    : deepAuditReport.overall_verdict === "FAIL"
                    ? "border-l-rh-nogo"
                    : "border-l-rh-line"
                }`}>
                  {/* Verdict, evaluated target and health score */}
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="space-y-1.5 min-w-0 flex-1">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className={`px-2.5 py-0.5 rounded-[6px] text-xs font-semibold ${
                          deepAuditReport.overall_verdict === "PASS" ? "bg-rh-go/15 text-rh-go" :
                          deepAuditReport.overall_verdict === "WARN" ? "bg-rh-cond/15 text-rh-cond" :
                          deepAuditReport.overall_verdict === "FAIL" ? "bg-rh-nogo/15 text-rh-nogo" :
                          "bg-rh-raised text-rh-muted"
                        }`}>
                          Verdict: {sentence(deepAuditReport.overall_verdict) || "not evaluated"}
                        </span>
                        <span className="text-xs text-rh-muted truncate max-w-sm">
                          Evaluated <span className="font-mono">{deepAuditReport.target}</span>
                          {deepAuditEntry && ` · audited ${new Date(deepAuditEntry.ts).toLocaleString()}`}
                        </span>
                      </div>
                      <p className="text-sm font-semibold text-rh-text leading-relaxed">
                        {deepAuditReport.executive_summary}
                      </p>
                    </div>

                    <div className="flex flex-col items-center justify-center p-3 px-5 rounded-[10px] bg-rh-bg border border-rh-line shrink-0">
                      <span className="text-xs text-rh-muted">Health score</span>
                      <span className={`text-3xl font-semibold tabular-nums ${
                        deepAuditReport.health_score >= 90 ? "text-rh-go" :
                        deepAuditReport.health_score >= 70 ? "text-rh-cond" : "text-rh-nogo"
                      }`}>
                        {deepAuditReport.health_score}
                        <span className="text-sm text-rh-muted font-normal">/100</span>
                      </span>
                    </div>
                  </div>

                  {/* Identified risks */}
                  {deepAuditReport.identified_risks.length > 0 && (
                    <div className="pt-3 border-t border-rh-line space-y-2">
                      <div className="flex items-center gap-2 text-rh-text text-xs font-semibold">
                        <ShieldAlert className="w-3.5 h-3.5 text-rh-nogo" aria-hidden="true" />
                        <span>Identified flakiness and network risks ({deepAuditReport.identified_risks.length})</span>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {deepAuditReport.identified_risks.map((risk, idx) => (
                          <div key={idx} className="flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-nogo/15 text-xs text-rh-nogo">
                            <span className="w-1.5 h-1.5 rounded-full bg-rh-nogo shrink-0" aria-hidden="true" />
                            <span>{risk}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Expandable remediation */}
                  {deepAuditReport.remediation_checklist.length > 0 && (
                    <div className="pt-3 border-t border-rh-line">
                      <button
                        type="button"
                        onClick={() => setShowRemediation(!showRemediation)}
                        aria-expanded={showRemediation}
                        className={`flex items-center gap-2 text-xs font-medium text-rh-text hover:text-rh-primary transition-colors cursor-pointer rounded-[6px] ${FOCUS}`}
                      >
                        {showRemediation ? <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" /> : <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />}
                        <span>{showRemediation ? "Hide" : "Show"} remediation steps ({deepAuditReport.remediation_checklist.length} actions)</span>
                      </button>

                      {showRemediation && (
                        <ol className="mt-2.5 space-y-1.5 pl-8 list-decimal text-xs text-rh-text bg-rh-bg p-3 rounded-[6px] border border-rh-line">
                          {deepAuditReport.remediation_checklist.map((rem, idx) => (
                            <li key={idx} className="leading-relaxed">{rem}</li>
                          ))}
                        </ol>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-8 rounded-[10px] bg-rh-surface border border-dashed border-rh-line text-center space-y-3">
                  <Network className="w-10 h-10 text-rh-muted mx-auto" aria-hidden="true" />
                  <h3 className="text-base font-semibold text-rh-text">No deep audit yet for this target</h3>
                  <p className="text-xs text-rh-muted max-w-md mx-auto">
                    The audit checks IPv4 vs IPv6 Happy Eyeballs, the sub-resource cascade (MIME and SPA fallbacks), HTTP/1.1 vs HTTP/2 vs HTTP/3, the TLS certificate chain, CORS preflight and MTU black holes.
                  </p>
                  <button
                    type="button"
                    onClick={handleRunDeepAudit}
                    disabled={isDeepAuditRunning}
                    className={BTN_PRIMARY}
                  >
                    Run 6-pillar audit
                  </button>
                </div>
              )}

              {/* The 6 pillars */}
              {deepAuditReport && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {/* Pillar 1: dual-stack IPv4 vs IPv6 */}
                  <div className={`${PANEL} space-y-3`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className={PILLAR_TITLE}>
                        <Globe className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                        <span>1. Dual-stack and Happy Eyeballs</span>
                      </span>
                      <span className={`${CHIP} ${
                        deepAuditReport.dual_stack.happy_eyeballs_risk ? "bg-rh-nogo/15 text-rh-nogo" :
                        deepAuditReport.dual_stack.has_ipv4 ? "bg-rh-go/15 text-rh-go" : "bg-rh-raised text-rh-muted"
                      }`}>
                        {deepAuditReport.dual_stack.ipv6_status}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs text-rh-text">
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">IPv4 address</span>
                        <span className="text-rh-text font-mono tabular-nums">{deepAuditReport.dual_stack.ipv4_addresses[0] || "None"}</span>
                      </div>
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">IPv4 latency</span>
                        <span className="text-rh-text tabular-nums">{deepAuditReport.dual_stack.ipv4_latency_ms ?? "--"}ms</span>
                      </div>
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">IPv6 AAAA record</span>
                        <span className={`font-mono break-all text-right ${deepAuditReport.dual_stack.has_ipv6 ? "text-rh-text" : "text-rh-muted font-sans"}`}>
                          {deepAuditReport.dual_stack.has_ipv6 ? deepAuditReport.dual_stack.ipv6_addresses[0] : "None published"}
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
                      {deepAuditReport.dual_stack.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 2: sub-resource cascade and SPA mismatch */}
                  <div className={`${PANEL} space-y-3`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className={PILLAR_TITLE}>
                        <FileCode className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                        <span>2. Sub-resource cascade (SPA and assets)</span>
                      </span>
                      <span className={`${CHIP} tabular-nums ${
                        deepAuditReport.subresources.spa_fallback_mismatches > 0 ? "bg-rh-nogo/15 text-rh-nogo" :
                        deepAuditReport.subresources.broken_count > 0 ? "bg-rh-cond/15 text-rh-cond" :
                        "bg-rh-go/15 text-rh-go"
                      }`}>
                        {deepAuditReport.subresources.successful_count}/{deepAuditReport.subresources.total_discovered} OK
                      </span>
                    </div>

                    <div className="space-y-2 text-xs text-rh-text">
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">Total assets probed</span>
                        <span className="text-rh-text tabular-nums">{deepAuditReport.subresources.total_discovered} files ({deepAuditReport.subresources.total_size_kb.toFixed(1)} KB)</span>
                      </div>
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">Broken assets (4xx/5xx)</span>
                        <span className={`tabular-nums ${deepAuditReport.subresources.broken_count > 0 ? "text-rh-nogo font-semibold" : "text-rh-text"}`}>
                          {deepAuditReport.subresources.broken_count}
                        </span>
                      </div>
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">SPA fallback mismatch (JS served as HTML)</span>
                        <span className={`tabular-nums ${deepAuditReport.subresources.spa_fallback_mismatches > 0 ? "text-rh-nogo font-semibold" : "text-rh-text"}`}>
                          {deepAuditReport.subresources.spa_fallback_mismatches}
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
                      {deepAuditReport.subresources.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 3: HTTP protocol matrix */}
                  <div className={`${PANEL} space-y-3`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className={PILLAR_TITLE}>
                        <Layers className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                        <span>3. HTTP protocol matrix</span>
                      </span>
                      <span className={`${CHIP} bg-rh-raised text-rh-text`}>
                        {deepAuditReport.protocol_matrix.active_protocol}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs">
                      {deepAuditReport.protocol_matrix.protocols.map((p, idx) => (
                        <div key={idx} className="flex items-center justify-between gap-3 px-3 py-2 rounded-[6px] bg-rh-bg">
                          <span className="font-semibold text-rh-text">{p.protocol}</span>
                          <span className={`text-xs px-1.5 py-0.5 rounded-[6px] font-semibold tabular-nums ${
                            p.supported ? "bg-rh-go/15 text-rh-go" : "bg-rh-raised text-rh-muted"
                          }`}>
                            {p.supported ? `Supported (${p.negotiation_time_ms}ms)` : "Unavailable"}
                          </span>
                        </div>
                      ))}
                    </div>
                    <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
                      {deepAuditReport.protocol_matrix.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 4: TLS and certificate chain */}
                  <div className={`${PANEL} space-y-3`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className={PILLAR_TITLE}>
                        {deepAuditReport.tls_chain.is_https ? (
                          <Lock className="w-4 h-4 text-rh-go" aria-hidden="true" />
                        ) : (
                          <Unlock className="w-4 h-4 text-rh-cond" aria-hidden="true" />
                        )}
                        <span>4. TLS and certificate chain</span>
                      </span>
                      <span className={`${CHIP} bg-rh-raised text-rh-text`}>
                        {deepAuditReport.tls_chain.tls_version}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs text-rh-text">
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">Cipher suite</span>
                        <span className="text-rh-text font-mono truncate max-w-[200px]" title={deepAuditReport.tls_chain.cipher}>{deepAuditReport.tls_chain.cipher}</span>
                      </div>
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">Issuer</span>
                        <span className="text-rh-text text-right">{deepAuditReport.tls_chain.cert_issuer}</span>
                      </div>
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">Intermediate chain</span>
                        <span className={deepAuditReport.tls_chain.is_intermediate_missing ? "text-rh-nogo font-semibold" : "text-rh-text"}>
                          {deepAuditReport.tls_chain.is_intermediate_missing ? "Incomplete bundle" : "Complete"}
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
                      {deepAuditReport.tls_chain.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 5: CORS preflight */}
                  <div className={`${PANEL} space-y-3`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className={PILLAR_TITLE}>
                        <ShieldAlert className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                        <span>5. CORS preflight boundary (OPTIONS)</span>
                      </span>
                      <span className={`${CHIP} tabular-nums ${
                        deepAuditReport.cors_preflight.preflight_passed ? "bg-rh-go/15 text-rh-go" : "bg-rh-nogo/15 text-rh-nogo"
                      }`}>
                        HTTP {deepAuditReport.cors_preflight.preflight_status_code}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs text-rh-text">
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">Allow-Origin</span>
                        <span className="text-rh-text font-mono break-all text-right">{deepAuditReport.cors_preflight.allow_origin || "None"}</span>
                      </div>
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">Allow-Methods</span>
                        <span className="text-rh-text font-mono break-all text-right">{deepAuditReport.cors_preflight.allow_methods || "None"}</span>
                      </div>
                      <div className={KV_ROW}>
                        <span className="text-rh-muted">Preflight accepted</span>
                        <span className={deepAuditReport.cors_preflight.preflight_passed ? "text-rh-go font-semibold" : "text-rh-nogo font-semibold"}>
                          {deepAuditReport.cors_preflight.preflight_passed ? "Yes (200/204)" : "No (blocked)"}
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
                      {deepAuditReport.cors_preflight.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 6: MTU and packet size sweep */}
                  <div className={`${PANEL} space-y-3`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className={PILLAR_TITLE}>
                        <Flame className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                        <span>6. MTU and packet black hole sweep</span>
                      </span>
                      <span className={`${CHIP} tabular-nums ${
                        deepAuditReport.mtu_sweep.black_hole_detected ? "bg-rh-nogo/15 text-rh-nogo" : "bg-rh-go/15 text-rh-go"
                      }`}>
                        Max safe: {deepAuditReport.mtu_sweep.maximum_safe_bytes}B
                      </span>
                    </div>

                    <div className="grid grid-cols-4 gap-2 text-center text-xs">
                      {deepAuditReport.mtu_sweep.sweep_results.map((m, idx) => (
                        <div key={idx} className={`p-2 rounded-[6px] tabular-nums ${
                          m.success ? "bg-rh-go/15 text-rh-go" : "bg-rh-nogo/15 text-rh-nogo"
                        }`}>
                          <div className="font-semibold text-xs">{m.payload_bytes}B</div>
                          <div className="text-xs text-rh-muted">{m.duration_ms}ms</div>
                        </div>
                      ))}
                    </div>
                    <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
                      {deepAuditReport.mtu_sweep.diagnosis}
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: MULTI-REGION DISTRIBUTED EDGE MESH */}
          {activeTab === "multi_region" && (
            <div className="space-y-6">
              {/* Target bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 p-2.5 rounded-[10px] bg-rh-surface border border-rh-line">
                <div className="flex items-center gap-2 text-xs min-w-0">
                  <Globe className="w-3.5 h-3.5 text-rh-muted shrink-0" aria-hidden="true" />
                  <span className="text-rh-muted">Target URL</span>
                  <span className="text-rh-text font-mono truncate">{target}</span>
                </div>
                <button
                  id="btn-run-multi-region"
                  type="button"
                  onClick={handleRunMultiRegion}
                  disabled={isMultiRegionRunning}
                  className={BTN_PRIMARY}
                >
                  {isMultiRegionRunning ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                      <span>Probing global mesh...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
                      <span>Probe 4-region edge mesh</span>
                    </>
                  )}
                </button>
              </div>
              {/* Global edge overview */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className={KPI_CARD}>
                  <span className="text-xs text-rh-muted">Global edge CDN</span>
                  <div className="flex items-center gap-2 mt-2">
                    <span className={`text-xl font-semibold ${
                      !multiRegionReport ? "text-rh-muted" :
                      multiRegionReport.cdn_edge_active ? "text-rh-go" : "text-rh-cond"
                    }`}>
                      {multiRegionReport ? (multiRegionReport.cdn_edge_active ? "Active (edge POPs)" : "Direct origin") : "--"}
                    </span>
                  </div>
                </div>

                <div className={KPI_CARD}>
                  <span className="text-xs text-rh-muted">Fastest node</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-xl font-semibold text-rh-text">
                      {multiRegionReport?.fastest_region || "--"}
                    </span>
                  </div>
                </div>

                <div className={KPI_CARD}>
                  <span className="text-xs text-rh-muted">Slowest node</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-xl font-semibold text-rh-text">
                      {multiRegionReport?.slowest_region || "--"}
                    </span>
                  </div>
                </div>

                <div className={KPI_CARD}>
                  <span className="text-xs text-rh-muted">Max regional disparity</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className={`text-2xl font-semibold tabular-nums ${
                      !multiRegionReport ? "text-rh-muted" :
                      multiRegionReport.regional_disparity_ms <= 100 ? "text-rh-go" :
                      multiRegionReport.regional_disparity_ms <= 200 ? "text-rh-cond" : "text-rh-nogo"
                    }`}>
                      {multiRegionReport ? `${multiRegionReport.regional_disparity_ms}ms` : "--"}
                    </span>
                    <span className="text-xs text-rh-muted">cross-continental delta</span>
                  </div>
                </div>
              </div>

              {/* Regional cards */}
              {multiRegionReport ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {multiRegionReport.regions.map((reg) => (
                    <div
                      key={reg.region_id}
                      className={`${PANEL} space-y-3`}
                    >
                      <div className="flex items-center justify-between gap-2 border-b border-rh-line pb-2.5">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xl" aria-hidden="true">{reg.flag}</span>
                          <div className="min-w-0">
                            <h4 className="text-sm font-semibold text-rh-text">{reg.region_name}</h4>
                            <span className="text-xs text-rh-muted">{reg.location}</span>
                          </div>
                        </div>
                        <span className={`${CHIP} shrink-0 ${
                          reg.status === "OPTIMAL"
                            ? "bg-rh-go/15 text-rh-go"
                            : reg.status === "ELEVATED"
                            ? "bg-rh-cond/15 text-rh-cond"
                            : "bg-rh-nogo/15 text-rh-nogo"
                        }`}>
                          {sentence(reg.status)}
                        </span>
                      </div>

                      {/* Timing metrics */}
                      <div className="grid grid-cols-4 gap-2 text-center">
                        <div className="p-2 rounded-[6px] bg-rh-bg">
                          <span className="text-xs text-rh-muted block">DNS</span>
                          <span className="text-xs font-semibold text-rh-text tabular-nums">{reg.dns_time_ms}ms</span>
                        </div>
                        <div className="p-2 rounded-[6px] bg-rh-bg">
                          <span className="text-xs text-rh-muted block">TCP SYN</span>
                          <span className="text-xs font-semibold text-rh-text tabular-nums">{reg.tcp_connect_ms}ms</span>
                        </div>
                        <div className="p-2 rounded-[6px] bg-rh-bg">
                          <span className="text-xs text-rh-muted block">TTFB</span>
                          <span className="text-xs font-semibold text-rh-text tabular-nums">{reg.ttfb_ms}ms</span>
                        </div>
                        <div className="p-2 rounded-[6px] bg-rh-bg">
                          <span className="text-xs text-rh-muted block">Total RTT</span>
                          <span className="text-xs font-semibold text-rh-text tabular-nums">{reg.total_time_ms}ms</span>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-rh-muted pt-1">
                        <span>Edge POP: <span className="text-rh-text font-mono">{reg.edge_pop}</span></span>
                        <span>Jitter: <span className="text-rh-text tabular-nums">{reg.jitter_ms}ms</span></span>
                        <span>Loss: <span className="text-rh-text tabular-nums">{reg.packet_loss_pct}%</span></span>
                      </div>

                      <p className="text-xs text-rh-muted leading-relaxed border-t border-rh-line pt-2">
                        {reg.notes}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-8 rounded-[10px] bg-rh-surface border border-dashed border-rh-line text-center space-y-3">
                  <Compass className="w-8 h-8 text-rh-muted mx-auto" aria-hidden="true" />
                  <h4 className="text-sm font-semibold text-rh-text">No edge mesh results yet</h4>
                  <p className="text-xs text-rh-muted max-w-lg mx-auto">
                    This probes the target URL from 4 geographic regions (US-East, EU-West, APAC-Mumbai, APAC-Singapore) to catch geo-DNS propagation issues and CDN edge cache misses.
                  </p>
                  <button
                    type="button"
                    onClick={handleRunMultiRegion}
                    disabled={isMultiRegionRunning}
                    className={BTN_PRIMARY}
                  >
                    {isMultiRegionRunning ? "Probing global nodes..." : "Run 4-region edge probe"}
                  </button>
                </div>
              )}

              {/* Agent verdict */}
              {multiRegionReport && (
                <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line space-y-3">
                  <div className="flex items-center gap-2">
                    <BrainCircuit className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                    <h4 className="text-sm font-semibold text-rh-text">
                      Agent verdict and routing insights
                    </h4>
                  </div>
                  <p className="text-xs text-rh-text leading-relaxed bg-rh-bg p-3 rounded-[6px] border border-rh-line">
                    {multiRegionReport.agent_verdict}
                  </p>
                  {multiRegionReport.recommendations.length > 0 && (
                    <div className="space-y-1.5 pt-2">
                      <span className="text-xs font-semibold text-rh-muted block">Recommended optimizations</span>
                      <ul className="space-y-1.5 pl-5 list-disc text-xs text-rh-text">
                        {multiRegionReport.recommendations.map((rec, idx) => (
                          <li key={idx}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: PR GATE & GITHUB APP INTEGRATION */}
          {activeTab === "pr_gate" && (
            <div className="space-y-6">
              {/* Target bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 p-2.5 rounded-[10px] bg-rh-surface border border-rh-line">
                <div className="flex items-center gap-2 text-xs min-w-0">
                  <Globe className="w-3.5 h-3.5 text-rh-muted shrink-0" aria-hidden="true" />
                  <span className="text-rh-muted">Target URL</span>
                  <span className="text-rh-text font-mono truncate">{target}</span>
                </div>
                <button
                  id="btn-refresh-pr-comment"
                  type="button"
                  onClick={handleFetchPrComment}
                  disabled={isPrCommentLoading}
                  className={BTN_PRIMARY}
                >
                  <RotateCw className={`w-3.5 h-3.5 ${isPrCommentLoading ? "animate-spin" : ""}`} aria-hidden="true" />
                  <span>Refresh PR checks</span>
                </button>
              </div>
              {/* SVG badges */}
              <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <GitPullRequest className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                    <h4 className="text-sm font-semibold text-rh-text">
                      Embeddable SVG badges
                    </h4>
                  </div>
                  <span className="text-xs text-rh-muted">Built from measured results only. Badges without a measurement stay neutral.</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Badge 1: Quality Gate (from the 6-Pillar audit verdict) */}
                  <div className="p-3.5 rounded-[6px] bg-rh-bg border border-rh-line space-y-2.5">
                    <span className="text-xs font-medium text-rh-text block">Quality gate verdict</span>
                    <div className="flex items-center justify-between">
                      <div className="inline-flex rounded-[6px] overflow-hidden text-xs font-semibold">
                        <span className="bg-[#1e293b] text-white px-2.5 py-1">ReadyHai</span>
                        <span className="text-white px-2.5 py-1" style={{ backgroundColor: gateBadgeColor }}>
                          {gateBadgeText}
                        </span>
                      </div>
                      <button
                        disabled={!gateStatus}
                        onClick={() => copyToClipboard(`![ReadyHai Gate](${badgeBase()}/api/badges/gate?status=${encodeURIComponent((gateStatus || "").toLowerCase())})`, "badge-gate")}
                        type="button"
                        aria-label="Copy quality gate badge markdown"
                        className={`text-xs text-rh-primary hover:text-rh-primary-hover flex items-center gap-1 rounded-[6px] px-1 py-0.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
                      >
                        {copiedText === "badge-gate" ? <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
                        <span>{copiedText === "badge-gate" ? "Copied" : "Copy"}</span>
                      </button>
                    </div>
                    {!gateStatus && <p className="text-xs text-rh-muted">Run the 6-pillar protocol audit to get a verdict.</p>}
                  </div>

                  {/* Badge 2: Evidence Ledger (from the loaded agent run, if any) */}
                  <div className="p-3.5 rounded-[6px] bg-rh-bg border border-rh-line space-y-2.5">
                    <span className="text-xs font-medium text-rh-text block">4-pillar evidence ledger</span>
                    <div className="flex items-center justify-between">
                      <div className="inline-flex rounded-[6px] overflow-hidden text-xs font-semibold">
                        <span className="bg-[#0f172a] text-white px-2.5 py-1">Evidence Ledger</span>
                        <span className="text-white px-2.5 py-1" style={{ backgroundColor: ledgerScore === null ? "#475569" : "#3b82f6" }}>
                          {ledgerScore === null ? "not evaluated" : `${ledgerScore}/100`}
                        </span>
                      </div>
                      <button
                        disabled={ledgerScore === null}
                        onClick={() => copyToClipboard(`![Evidence Ledger](${badgeBase()}/api/badges/ledger?score=${encodeURIComponent(`${ledgerScore}/100`)})`, "badge-ledger")}
                        type="button"
                        aria-label="Copy evidence ledger badge markdown"
                        className={`text-xs text-rh-primary hover:text-rh-primary-hover flex items-center gap-1 rounded-[6px] px-1 py-0.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
                      >
                        {copiedText === "badge-ledger" ? <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
                        <span>{copiedText === "badge-ledger" ? "Copied" : "Copy"}</span>
                      </button>
                    </div>
                    {ledgerScore === null && <p className="text-xs text-rh-muted">Open an evaluated run in Agent studio to get a ledger score.</p>}
                  </div>

                  {/* Badge 3: Network Mesh (from the multi-region probe) */}
                  <div className="p-3.5 rounded-[6px] bg-rh-bg border border-rh-line space-y-2.5">
                    <span className="text-xs font-medium text-rh-text block">Global network mesh</span>
                    <div className="flex items-center justify-between">
                      <div className="inline-flex rounded-[6px] overflow-hidden text-xs font-semibold">
                        <span className="bg-[#18181b] text-white px-2.5 py-1">Network Mesh</span>
                        <span className="text-white px-2.5 py-1" style={{ backgroundColor: meshBadgeColor }}>
                          {meshBadgeText ?? "not evaluated"}
                        </span>
                      </div>
                      <button
                        disabled={!meshBadgeText}
                        onClick={() => meshBadgeText && copyToClipboard(`![Network Mesh](${badgeBase()}/api/badges/network?status=${encodeURIComponent(meshBadgeText)})`, "badge-mesh")}
                        type="button"
                        aria-label="Copy network mesh badge markdown"
                        className={`text-xs text-rh-primary hover:text-rh-primary-hover flex items-center gap-1 rounded-[6px] px-1 py-0.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
                      >
                        {copiedText === "badge-mesh" ? <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
                        <span>{copiedText === "badge-mesh" ? "Copied" : "Copy"}</span>
                      </button>
                    </div>
                    {!meshBadgeText && <p className="text-xs text-rh-muted">Run the multi-region mesh probe to get a status.</p>}
                  </div>
                </div>
              </div>

              {/* PR Status Comment Preview & Copy */}
              <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rh-line pb-3">
                  <div>
                    <h4 className="text-sm font-semibold text-rh-text">
                      Pull request comment markdown
                    </h4>
                    <span className="text-xs text-rh-muted">Post it to a GitHub PR with the CLI or a GitHub Action step</span>
                  </div>
                  {prCommentData && (
                    <button
                      type="button"
                      onClick={() => copyToClipboard(prCommentData.markdown, "pr-comment-md")}
                      className={BTN_SECONDARY}
                    >
                      {copiedText === "pr-comment-md" ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                          <span>Copied markdown</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Copy PR comment</span>
                        </>
                      )}
                    </button>
                  )}
                </div>

                {prCommentData ? (
                  <>
                    <p className="text-xs text-rh-cond bg-rh-cond/15 p-3 rounded-[6px]">
                      Only the verdict and score above come from this audit. The pillar table and overview lines in the
                      generated comment are the backend&apos;s template text and were not measured here.
                    </p>
                    <div className="p-4 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-xs text-rh-text overflow-auto whitespace-pre-wrap max-h-72 min-h-0 leading-relaxed">
                      {prCommentData.markdown}
                    </div>
                  </>
                ) : (
                  <div className="p-4 rounded-[6px] bg-rh-bg border border-rh-line text-rh-muted text-xs flex flex-wrap items-center justify-between gap-3">
                    <span>
                      {deepAuditReport
                        ? `Generate a PR comment for ${target} from the 6-pillar audit verdict and score.`
                        : "Run the 6-pillar protocol audit first: the PR comment needs a measured verdict and score."}
                    </span>
                    <button
                      type="button"
                      onClick={handleFetchPrComment}
                      disabled={isPrCommentLoading || !deepAuditReport}
                      className={BTN_SECONDARY}
                    >
                      {isPrCommentLoading ? "Generating..." : "Generate comment"}
                    </button>
                  </div>
                )}
              </div>

              {/* GitHub Actions workflow (.github/workflows/readyhai.yml) */}
              <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rh-line pb-3">
                  <div>
                    <h4 className="text-sm font-semibold text-rh-text">
                      GitHub Actions workflow snippet (<span className="font-mono">.github/workflows/readyhai.yml</span>)
                    </h4>
                    <span className="text-xs text-rh-muted">Enforce a blocking readiness gate and SARIF code scanning on every commit</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(
`name: ReadyHai Production Readiness Gate\non: [pull_request, push]\n\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n\n      - name: Install ReadyHai\n        run: |\n          curl -sSfL https://github.com/deziss/readyhai/releases/latest/download/readyhai-linux-x86_64.tar.gz | sudo tar xz -C /usr/local/bin\n\n      - name: Execute Quality & Network Gate\n        run: |\n          readyhai scan . --profile quick --format sarif,html --out readyhai-report\n\n      - name: Upload SARIF to GitHub Code Scanning\n        if: always()\n        uses: github/codeql-action/upload-sarif@v3\n        with:\n          sarif_file: readyhai-report/readyhai-report.sarif`,
                      "action-yaml"
                    )}
                    className={BTN_SECONDARY}
                  >
                    {copiedText === "action-yaml" ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                        <span>Copied YAML</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>Copy workflow YAML</span>
                      </>
                    )}
                  </button>
                </div>

                <pre className="p-4 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-xs text-rh-text overflow-auto leading-relaxed">
{`name: ReadyHai Production Readiness Gate
on: [pull_request, push]

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ReadyHai
        run: |
          curl -sSfL https://github.com/deziss/readyhai/releases/latest/download/readyhai-linux-x86_64.tar.gz | sudo tar xz -C /usr/local/bin

      - name: Execute Quality & Network Gate
        run: |
          readyhai scan . --profile quick --format sarif,html --out readyhai-report

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: readyhai-report/readyhai-report.sarif`}
                </pre>
              </div>
            </div>
          )}


          {/* cURL diagnostic probe (regressive lab, or whenever a result exists) */}
          {(activeTab === "regress" || curlResult) && (
            <div className={`${PANEL} space-y-3`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-sm font-semibold text-rh-text flex items-center gap-2">
                <Terminal className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                <span>cURL diagnostic probe</span>
              </span>

              {curlResult && (
                <button
                  type="button"
                  onClick={() => copyToClipboard(curlResult.command, "curl-command")}
                  className={BTN_SECONDARY}
                >
                  {copiedText === "curl-command" ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>Copy cURL</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {curlResult ? (
              <div className="space-y-3 text-xs">
                {/* Generated cURL command */}
                <div className="p-3 bg-rh-bg rounded-[6px] border border-rh-line font-mono text-rh-text break-all select-all">
                  {curlResult.command}
                </div>

                {/* Sub-millisecond timing chips */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                  <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
                    <span className="text-xs text-rh-muted block">DNS lookup</span>
                    <span className="font-semibold text-rh-text tabular-nums">{(curlResult.dns_lookup_s * 1000).toFixed(1)}ms</span>
                  </div>
                  <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
                    <span className="text-xs text-rh-muted block">TCP connect</span>
                    <span className="font-semibold text-rh-text tabular-nums">{(curlResult.connect_s * 1000).toFixed(1)}ms</span>
                  </div>
                  <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
                    <span className="text-xs text-rh-muted block">TLS / app connect</span>
                    <span className="font-semibold text-rh-text tabular-nums">{(curlResult.appconnect_s * 1000).toFixed(1)}ms</span>
                  </div>
                  <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
                    <span className="text-xs text-rh-muted block">TTFB</span>
                    <span className="font-semibold text-rh-text tabular-nums">{(curlResult.starttransfer_s * 1000).toFixed(1)}ms</span>
                  </div>
                  <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
                    <span className="text-xs text-rh-muted block">Total RTT</span>
                    <span className="font-semibold text-rh-text tabular-nums">{(curlResult.total_s * 1000).toFixed(1)}ms</span>
                  </div>
                </div>

                {/* Output text */}
                {curlResult.stdout && (
                  <div className="p-3 bg-rh-bg rounded-[6px] border border-rh-line font-mono text-rh-text max-h-40 min-h-0 overflow-y-auto whitespace-pre-wrap">
                    {curlResult.stdout}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-4 rounded-[6px] bg-rh-bg border border-rh-line text-rh-muted text-xs flex flex-wrap items-center justify-between gap-3">
                <span>No cURL probe has run yet. Run one to time DNS, TCP, TLS and TTFB against <span className="font-mono text-rh-text">{target}</span>.</span>
                <button
                  type="button"
                  onClick={handleRunCurl}
                  disabled={isCurlRunning}
                  className={BTN_SECONDARY}
                >
                  {isCurlRunning ? "Running..." : "Run probe"}
                </button>
              </div>
            )}
          </div>
          )}
          </div>
        </main>
      </div>
    </div>
  );
}
