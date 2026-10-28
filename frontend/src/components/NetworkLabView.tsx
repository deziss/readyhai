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
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Clock,
  Wifi,
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
  Server,
  Info,
  Lock,
  Unlock,
  Network,
  FileCode,
  Flame,
  ShieldCheck,
} from "lucide-react";
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
  onRunningChange?: (running: boolean, detail: string) => void;
}

export function NetworkLabView({
  initialTarget = "http://readyhai:8080",
  onRunningChange,
}: NetworkLabViewProps) {
  // Mode selection: "regress" | "deep_audit"
  const [activeTab, setActiveTab] = useState<"regress" | "deep_audit" | "multi_region" | "pr_gate">("regress");

  // Common target
  const [target, setTarget] = useState(initialTarget);
  const [timeoutMs, setTimeoutMs] = useState(5000);

  // Regressive test configuration
  const [method, setMethod] = useState("GET");
  const [iterations, setIterations] = useState(10);
  const [throttleProfile, setThrottleProfile] = useState("unthrottled");
  const [customLatency, setCustomLatency] = useState(120);
  const [separateSessions, setSeparateSessions] = useState(true);
  const [delayBetweenMs, setDelayBetweenMs] = useState(25);
  const [customHeaders, setCustomHeaders] = useState("");
  const [customPayload, setCustomPayload] = useState("");

  // Regressive Results
  const [isRegressRunning, setIsRegressRunning] = useState(false);
  const [regressReport, setRegressReport] = useState<RegressReport | null>(null);
  const [selectedIteration, setSelectedIteration] = useState<IterationResult | null>(null);

  // Deep Audit Results
  const [isDeepAuditRunning, setIsDeepAuditRunning] = useState(false);
  const [deepAuditReport, setDeepAuditReport] = useState<DeepAuditReport | null>(null);
  const [deepAuditError, setDeepAuditError] = useState<string | null>(null);

  // Restore cached deep audit result if available for target
  useEffect(() => {
    try {
      const cached = localStorage.getItem(`readyhai_deep_audit_${target}`);
      if (cached && !deepAuditReport) {
        setDeepAuditReport(JSON.parse(cached));
      }
    } catch (_) {}
  }, [target]);

  // cURL Runner
  const [isCurlRunning, setIsCurlRunning] = useState(false);
  const [curlResult, setCurlResult] = useState<CurlTestResponse | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [isMultiRegionRunning, setIsMultiRegionRunning] = useState(false);
  const [multiRegionReport, setMultiRegionReport] = useState<MultiRegionReport | null>(null);
  const [isPrCommentLoading, setIsPrCommentLoading] = useState(false);
  const [prCommentData, setPrCommentData] = useState<PrCommentResponse | null>(null);

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

  // Run continuous regress test
  async function handleRunRegress() {
    setIsRegressRunning(true);
    setCurlResult(null);
    onRunningChange?.(true, `Regressive Network Test (${iterations}x iterations)`);
    try {
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

      const res = await fetch("/api/network/regress", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data: RegressReport = await res.json();
        setRegressReport(data);
        if (data.iterations && data.iterations.length > 0) {
          setSelectedIteration(data.iterations[0]);
        }
      }
    } catch (err) {
      console.error("Regress test failed:", err);
    } finally {
      setIsRegressRunning(false);
      onRunningChange?.(false, `Completed ${iterations}x regressive test`);
    }
  }

  // Run 6-Pillar Deep Audit
  async function handleRunDeepAudit() {
    setIsDeepAuditRunning(true);
    setDeepAuditError(null);
    onRunningChange?.(true, "6-Pillar Deep Network & Protocol Audit");
    try {
      const res = await fetch("/api/network/deep-audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, timeout_ms: timeoutMs }),
      });

      if (res.ok) {
        const data: DeepAuditReport = await res.json();
        setDeepAuditReport(data);
        try {
          localStorage.setItem(`readyhai_deep_audit_${target}`, JSON.stringify(data));
        } catch (_) {}
      } else {
        const errText = await res.text();
        setDeepAuditError(`Deep audit probe failed (${res.status}): ${errText || "Request failed"}`);
      }
    } catch (err: any) {
      console.error("Deep audit failed:", err);
      setDeepAuditError(`Deep audit request failed: ${err?.message || "Failed to reach backend service"}`);
    } finally {
      setIsDeepAuditRunning(false);
      onRunningChange?.(false, "Completed 6-Pillar Deep Protocol Audit");
    }
  }

  // Run cURL test
  async function handleRunCurl() {
    setIsCurlRunning(true);
    try {
      const res = await fetch("/api/network/curl", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          method,
          headers: getParsedHeaders(),
          payload: customPayload.trim() ? customPayload.trim() : null,
          timeout_ms: timeoutMs,
        }),
      });

      if (res.ok) {
        const data: CurlTestResponse = await res.json();
        setCurlResult(data);
      }
    } catch (err) {
      console.error("Curl test failed:", err);
    } finally {
      setIsCurlRunning(false);
    }
  }

    async function handleRunMultiRegion() {
    setIsMultiRegionRunning(true);
    onRunningChange?.(true, `Probing 4-Region Edge Mesh (${target})`);
    try {
      const res = await fetch("/api/network/multi-region", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, timeout_ms: timeoutMs }),
      });
      if (res.ok) {
        const data: MultiRegionReport = await res.json();
        setMultiRegionReport(data);
      }
    } catch (err) {
      console.error("Multi-region probe failed:", err);
    } finally {
      setIsMultiRegionRunning(false);
      onRunningChange?.(false, "Completed 4-Region Edge Mesh Probe");
    }
  }

  async function handleFetchPrComment() {
    setIsPrCommentLoading(true);
    try {
      const verdict = deepAuditReport ? deepAuditReport.overall_verdict : (regressReport && regressReport.availability_percentage >= 99 ? "PASS" : "WARN");
      const score = deepAuditReport ? deepAuditReport.health_score : 94;
      const res = await fetch("/api/github/pr-comment", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          verdict,
          score,
          commit_sha: "main",
        }),
      });
      if (res.ok) {
        const data: PrCommentResponse = await res.json();
        setPrCommentData(data);
      }
    } catch (err) {
      console.error("PR comment generation failed:", err);
    } finally {
      setIsPrCommentLoading(false);
    }
  }

  function handleExportHar() {
    let harData: any = null;
    if (regressReport && regressReport.iterations.length > 0) {
      harData = {
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
                  mimeType: it.response_headers?.["content-type"] || "text/html; charset=utf-8",
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
              serverIPAddress: "127.0.0.1",
              connection: it.session_id,
            };
          }),
        },
      };
    } else {
      harData = {
        log: {
          version: "1.2",
          creator: { name: "ReadyHai Network Lab", version: "0.1.0" },
          pages: [
            {
              startedDateTime: new Date().toISOString(),
              id: "page_readyhai",
              title: `ReadyHai Network Baseline - ${target}`,
              pageTimings: { onContentLoad: 45, onLoad: 85 },
            },
          ],
          entries: [
            {
              startedDateTime: new Date().toISOString(),
              time: 45,
              request: {
                method,
                url: target,
                httpVersion: "HTTP/1.1",
                cookies: [],
                headers: [{ name: "User-Agent", value: "ReadyHai-NetworkLab/0.1.0" }],
                queryString: [],
                headersSize: -1,
                bodySize: 0,
              },
              response: {
                status: 200,
                statusText: "OK",
                httpVersion: "HTTP/1.1",
                cookies: [],
                headers: [{ name: "Content-Type", value: "text/html; charset=utf-8" }],
                content: { size: 1024, mimeType: "text/html", text: "<!-- ReadyHai Baseline -->" },
                redirectURL: "",
                headersSize: -1,
                bodySize: 1024,
              },
              cache: {},
              timings: { blocked: 0, dns: 5, connect: 12, ssl: 0, send: 1, wait: 24, receive: 3 },
              serverIPAddress: "127.0.0.1",
            },
          ],
        },
      };
    }

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

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-[#070b13] text-slate-200">
      {/* Sub-Header Navigation Tabs */}
      <div className="border-b border-[#182338] bg-[#090e1a]/90 backdrop-blur px-6 py-2.5 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 p-1 bg-[#0d1527] rounded-xl border border-[#1b2b48]">
            <button
              id="tab-regress-stress"
              onClick={() => setActiveTab("regress")}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeTab === "regress"
                  ? "bg-gradient-to-r from-cyan-950 to-[#12233f] text-cyan-300 border border-cyan-600/50 shadow-[0_0_10px_rgba(6,182,212,0.25)] font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-[#121c32]"
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Continuous Regressive Stress Lab</span>
            </button>

            <button
              id="tab-deep-audit"
              onClick={() => {
                setActiveTab("deep_audit");
                if (!deepAuditReport && !isDeepAuditRunning) {
                  handleRunDeepAudit();
                }
              }}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeTab === "deep_audit"
                  ? "bg-gradient-to-r from-cyan-950 to-[#12233f] text-cyan-300 border border-cyan-600/50 shadow-[0_0_10px_rgba(6,182,212,0.25)] font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-[#121c32]"
              }`}
            >
              <Network className="w-3.5 h-3.5 text-cyan-400" />
              <span>6-Pillar Deep Protocol & Network Audit</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-cyan-900/60 text-cyan-300 border border-cyan-700/50 font-bold">
                ALL 6
              </span>
            </button>

            <button
              id="tab-multi-region"
              onClick={() => {
                setActiveTab("multi_region");
                if (!multiRegionReport && !isMultiRegionRunning) {
                  handleRunMultiRegion();
                }
              }}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeTab === "multi_region"
                  ? "bg-gradient-to-r from-cyan-950 to-[#12233f] text-cyan-300 border border-cyan-600/50 shadow-[0_0_10px_rgba(6,182,212,0.25)] font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-[#121c32]"
              }`}
            >
              <Compass className="w-3.5 h-3.5 text-cyan-400" />
              <span>Multi-Region Edge Mesh</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-indigo-900/60 text-indigo-300 border border-indigo-700/50 font-bold">
                4 REGIONS
              </span>
            </button>

            <button
              id="tab-pr-gate"
              onClick={() => {
                setActiveTab("pr_gate");
                if (!prCommentData && !isPrCommentLoading) {
                  handleFetchPrComment();
                }
              }}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeTab === "pr_gate"
                  ? "bg-gradient-to-r from-cyan-950 to-[#12233f] text-cyan-300 border border-cyan-600/50 shadow-[0_0_10px_rgba(6,182,212,0.25)] font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-[#121c32]"
              }`}
            >
              <GitPullRequest className="w-3.5 h-3.5 text-cyan-400" />
              <span>PR Gate & Badges</span>
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-[#0d1527] border border-[#1d2b45] text-xs font-mono">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400 font-normal">Active URL:</span>
            <span className="text-cyan-300 font-semibold">{target}</span>
          </div>

          {/* Requester Egress IP Clearance */}
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-[#0d1527] border border-[#1d2b45] text-xs font-mono" title="Requester public egress IP. Add this IP to target firewall/AWS security group allowlists for private network testing.">
            <span className="text-slate-400 font-normal">Requester IP:</span>
            <span className="text-cyan-300 font-bold">{regressReport?.requester_ip || deepAuditReport?.requester_ip || "47.29.26.1"}</span>
            <button
              type="button"
              onClick={() => copyToClipboard(regressReport?.requester_ip || deepAuditReport?.requester_ip || "47.29.26.1", "probe-ip")}
              className="text-slate-400 hover:text-cyan-300 ml-1 p-0.5 cursor-pointer transition-colors"
              title="Copy IP for firewall allowlist"
            >
              {copiedText === "probe-ip" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>

          {/* Export HAR Button */}
          <button
            id="btn-export-har"
            onClick={handleExportHar}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0d1527] hover:bg-[#121c32] text-slate-300 hover:text-white border border-[#1b2b48] hover:border-cyan-500/50 font-mono text-xs transition-all cursor-pointer"
            title="Download HTTP Archive (HAR v1.2) for Chrome DevTools or Cloudflare support"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export HAR</span>
          </button>

          {activeTab === "multi_region" && (
            <button
              id="btn-run-multi-region"
              onClick={handleRunMultiRegion}
              disabled={isMultiRegionRunning}
              className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-slate-950 font-mono text-xs font-bold shadow-[0_0_14px_rgba(6,182,212,0.3)] transition-all cursor-pointer disabled:opacity-50"
            >
              {isMultiRegionRunning ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Probing Mesh...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Probe Global Mesh</span>
                </>
              )}
            </button>
          )}

          {activeTab === "pr_gate" && (
            <button
              id="btn-refresh-pr-comment"
              onClick={handleFetchPrComment}
              disabled={isPrCommentLoading}
              className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-slate-950 font-mono text-xs font-bold shadow-[0_0_14px_rgba(6,182,212,0.3)] transition-all cursor-pointer disabled:opacity-50"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isPrCommentLoading ? "animate-spin" : ""}`} />
              <span>Refresh PR Checks</span>
            </button>
          )}

          {activeTab === "regress" && (
            <button
              id="btn-run-regress"
              onClick={handleRunRegress}
              disabled={isRegressRunning}
              className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-slate-950 font-mono text-xs font-bold shadow-[0_0_14px_rgba(6,182,212,0.3)] transition-all cursor-pointer disabled:opacity-50"
            >
              {isRegressRunning ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Probing ({iterations}x)...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Run Regressive Test</span>
                </>
              )}
            </button>
          )}

          {activeTab === "deep_audit" && (
            <button
              id="btn-run-deep-audit"
              onClick={handleRunDeepAudit}
              disabled={isDeepAuditRunning}
              className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-slate-950 font-mono text-xs font-bold shadow-[0_0_14px_rgba(6,182,212,0.3)] transition-all cursor-pointer disabled:opacity-50"
            >
              {isDeepAuditRunning ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditing 6 Pillars...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Run Complete Deep Audit</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-hidden grid grid-cols-1 xl:grid-cols-12 min-h-0">
        {/* Left Config Sidebar (4 cols) */}
        <aside className="xl:col-span-4 border-r border-[#182338] bg-[#090d18] p-4 overflow-y-auto space-y-4">
          <div className="space-y-1">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>Target & Parameters</span>
            </h2>
            <p className="text-xs text-slate-400">
              Configure app endpoint, socket isolation, and simulated network environments.
            </p>
          </div>

          {/* Target App URL */}
          <div className="space-y-1.5">
            <label className="text-xs font-mono font-medium text-slate-300">Target App URL</label>
            <div className="relative">
              <Globe className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                id="input-target-url"
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="http://127.0.0.1:8080 or https://app.example.com"
                className="w-full pl-9 pr-3 py-2 bg-[#0d1424] border border-[#1e2c47] rounded-lg text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* HTTP Method & Iterations */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300">Method</label>
              <select
                id="select-method"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="w-full px-3 py-2 bg-[#0d1424] border border-[#1e2c47] rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="HEAD">HEAD</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300">Iterations (N)</label>
              <select
                id="select-iterations"
                value={iterations}
                onChange={(e) => setIterations(Number(e.target.value))}
                className="w-full px-3 py-2 bg-[#0d1424] border border-[#1e2c47] rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value={5}>5 Repetitions</option>
                <option value={10}>10 Repetitions</option>
                <option value={25}>25 Repetitions</option>
                <option value={50}>50 Repetitions</option>
                <option value={100}>100 Repetitions</option>
              </select>
            </div>
          </div>

          {/* Private Session Isolation Switch */}
          <div className="p-3 bg-[#0d1526] rounded-xl border border-[#1e2d49] space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <WifiOff className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-semibold text-slate-200">Separate Private Sessions</span>
              </div>
              <input
                id="toggle-separate-sessions"
                type="checkbox"
                checked={separateSessions}
                onChange={(e) => setSeparateSessions(e.target.checked)}
                className="w-4 h-4 accent-cyan-500 cursor-pointer"
              />
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Forces zero connection pooling (<code className="text-cyan-300 font-mono">pool_max_idle_per_host(0)</code>).
              Every single iteration forces fresh DNS resolution and TCP/TLS handshake to catch socket starvation.
            </p>
          </div>

          {/* Network Throttling Presets */}
          <div className="space-y-2">
            <label className="text-xs font-mono font-medium text-slate-300 flex items-center justify-between">
              <span>Network Throttling Simulation</span>
              <span className="text-[10px] text-cyan-400 font-semibold uppercase">{throttleProfile}</span>
            </label>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              {[
                { id: "unthrottled", label: "Unthrottled", desc: "Native network speed" },
                { id: "fast_3g", label: "Fast 3G", desc: "+75ms mobile RTT" },
                { id: "slow_3g", label: "Slow 3G", desc: "+250ms high latency" },
                { id: "flaky", label: "Flaky Network", desc: "Jitter & packet drops" },
              ].map((p) => (
                <button
                  key={p.id}
                  id={`throttle-${p.id}`}
                  onClick={() => setThrottleProfile(p.id)}
                  className={`p-2.5 rounded-lg border text-left transition-all ${
                    throttleProfile === p.id
                      ? "bg-cyan-950/60 border-cyan-500/70 text-cyan-300 shadow-[0_0_8px_rgba(6,182,212,0.2)]"
                      : "bg-[#0d1424] border-[#1d2b45] text-slate-400 hover:text-slate-200 hover:border-slate-700"
                  }`}
                >
                  <div className="font-semibold text-[11px]">{p.label}</div>
                  <div className="text-[10px] text-slate-500 truncate">{p.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Timeout & Delay Sliders */}
          <div className="space-y-3 pt-1">
            <div className="space-y-1">
              <div className="flex justify-between text-xs font-mono text-slate-400">
                <span>Per-Attempt Timeout:</span>
                <span className="text-cyan-300 font-semibold">{timeoutMs}ms</span>
              </div>
              <input
                type="range"
                min="1000"
                max="15000"
                step="500"
                value={timeoutMs}
                onChange={(e) => setTimeoutMs(Number(e.target.value))}
                className="w-full accent-cyan-500 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
              />
            </div>

            <div className="space-y-1">
              <div className="flex justify-between text-xs font-mono text-slate-400">
                <span>Delay Between Requests:</span>
                <span className="text-cyan-300 font-semibold">{delayBetweenMs}ms</span>
              </div>
              <input
                type="range"
                min="0"
                max="500"
                step="25"
                value={delayBetweenMs}
                onChange={(e) => setDelayBetweenMs(Number(e.target.value))}
                className="w-full accent-cyan-500 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
              />
            </div>
          </div>

          {/* Custom Headers */}
          <div className="space-y-1.5">
            <label className="text-xs font-mono font-medium text-slate-300">Custom Headers (Key: Value)</label>
            <textarea
              value={customHeaders}
              onChange={(e) => setCustomHeaders(e.target.value)}
              placeholder={"Authorization: Bearer my-token\nX-Custom-Tenant: prod-1"}
              rows={2}
              className="w-full p-2.5 bg-[#0d1424] border border-[#1e2c47] rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Quick cURL Runner Card */}
          <div className="p-3 bg-[#0c1220] rounded-xl border border-[#1c2a44] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>Instant cURL Probe</span>
              </span>
              <button
                id="btn-run-curl"
                onClick={handleRunCurl}
                disabled={isCurlRunning}
                className="px-2.5 py-1 rounded bg-cyan-950 border border-cyan-600/50 hover:bg-cyan-900/50 text-[11px] font-mono text-cyan-300 font-semibold transition-all cursor-pointer disabled:opacity-50"
              >
                {isCurlRunning ? "Running..." : "Run cURL Test"}
              </button>
            </div>
            <p className="text-[10px] text-slate-500 font-mono">
              Executes sub-millisecond stage breakdown (DNS, TCP, TLS, TTFB, Total).
            </p>
          </div>
        </aside>

        {/* Right Pane (8 cols): Either Regressive Dashboard OR 6-Pillar Deep Audit */}
        <main className="xl:col-span-8 p-6 overflow-y-auto space-y-6">
          {/* TAB 1: CONTINUOUS REGRESSIVE TESTING */}
          {activeTab === "regress" && (
            <>
              {/* Hero KPI Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] flex flex-col justify-between">
                  <span className="text-xs font-mono text-slate-400">Availability</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className={`text-2xl font-bold font-mono ${
                      !regressReport ? "text-slate-500" :
                      regressReport.availability_percentage >= 99 ? "text-emerald-400" :
                      regressReport.availability_percentage >= 80 ? "text-amber-400" : "text-rose-400"
                    }`}>
                      {regressReport ? `${regressReport.availability_percentage.toFixed(1)}%` : "--"}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      {regressReport ? `${regressReport.successful_iterations}/${regressReport.total_iterations}` : "0/0"}
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] flex flex-col justify-between">
                  <span className="text-xs font-mono text-slate-400">P50 Latency (Median)</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl font-bold font-mono text-cyan-300">
                      {regressReport ? `${regressReport.p50_latency_ms}ms` : "--"}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      avg {regressReport?.avg_latency_ms || 0}ms
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] flex flex-col justify-between">
                  <span className="text-xs font-mono text-slate-400">P99 Latency (Tail)</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl font-bold font-mono text-indigo-300">
                      {regressReport ? `${regressReport.p99_latency_ms}ms` : "--"}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      max {regressReport?.max_latency_ms || 0}ms
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] flex flex-col justify-between">
                  <span className="text-xs font-mono text-slate-400">Network Jitter</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className={`text-2xl font-bold font-mono ${
                      !regressReport ? "text-slate-500" :
                      regressReport.jitter_ms < 100 ? "text-emerald-400" :
                      regressReport.jitter_ms < 300 ? "text-amber-400" : "text-rose-400"
                    }`}>
                      {regressReport ? `${regressReport.jitter_ms}ms` : "--"}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      {regressReport?.jitter_ms && regressReport.jitter_ms > 200 ? "High Variance" : "Low Variance"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Agent Root Cause Diagnosis Card */}
              {regressReport && (
                <div className={`p-5 rounded-xl border ${
                  regressReport.diagnosis.severity === "CRITICAL"
                    ? "bg-rose-950/20 border-rose-600/50"
                    : regressReport.diagnosis.severity === "HIGH"
                    ? "bg-amber-950/20 border-amber-600/50"
                    : "bg-cyan-950/20 border-cyan-600/40"
                } space-y-4`}>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 rounded-lg bg-[#0e1628] border border-[#1e2d48]">
                        <BrainCircuit className="w-5 h-5 text-cyan-400" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 font-bold tracking-wider">
                            {regressReport.diagnosis.root_cause_type}
                          </span>
                          <span className={`text-xs font-mono uppercase px-2 py-0.5 rounded font-bold ${
                            regressReport.diagnosis.severity === "CRITICAL" ? "bg-rose-900/60 text-rose-300" :
                            regressReport.diagnosis.severity === "HIGH" ? "bg-amber-900/60 text-amber-300" : "bg-emerald-900/60 text-emerald-300"
                          }`}>
                            {regressReport.diagnosis.severity}
                          </span>
                        </div>
                        <h3 className="text-base font-bold text-white mt-1">
                          {regressReport.diagnosis.title}
                        </h3>
                      </div>
                    </div>

                    <div className="text-right font-mono text-xs text-slate-400">
                      Target: <span className="text-cyan-300">{regressReport.target}</span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed font-mono">
                    {regressReport.diagnosis.summary}
                  </p>

                  {/* How The Agent Identified The Issue */}
                  <div className="space-y-2 pt-2 border-t border-[#1e2b46]">
                    <div className="text-xs font-mono font-semibold text-cyan-300 flex items-center gap-2">
                      <Zap className="w-3.5 h-3.5 text-cyan-400" />
                      <span>How The Agent Identified The Issue:</span>
                    </div>
                    <ul className="space-y-1.5 pl-5 list-disc text-xs text-slate-300 font-mono">
                      {regressReport.diagnosis.how_agent_found_it.map((step, idx) => (
                        <li key={idx} className="leading-relaxed">{step}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Technical Breakdown */}
                  <div className="space-y-2 pt-2 border-t border-[#1e2b46]">
                    <div className="text-xs font-mono font-semibold text-indigo-300 flex items-center gap-2">
                      <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Technical Root Cause Breakdown:</span>
                    </div>
                    <ul className="space-y-1.5 pl-5 list-disc text-xs text-slate-300 font-mono">
                      {regressReport.diagnosis.technical_breakdown.map((item, idx) => (
                        <li key={idx} className="leading-relaxed">{item}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Prescriptive Remediation Checklist */}
                  <div className="p-3.5 rounded-lg bg-[#0a1120] border border-[#1b2a45] space-y-2">
                    <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Prescriptive Remediation Actions:</span>
                    </span>
                    <ul className="space-y-1 text-xs font-mono text-slate-300 pl-4 list-decimal">
                      {regressReport.diagnosis.remediation_checklist.map((act, idx) => (
                        <li key={idx}>{act}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* Latency Waterfall Bar Chart */}
              {regressReport && regressReport.iterations.length > 0 && (
                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-cyan-400" />
                      <span>Session Latency & Handshake Distribution ({regressReport.iterations.length} attempts)</span>
                    </span>
                    <span className="text-xs font-mono text-slate-500">
                      Hover to view session timing breakdown
                    </span>
                  </div>

                  <div className="flex items-end gap-1.5 h-28 pt-4 px-2 overflow-x-auto">
                    {regressReport.iterations.map((it) => {
                      const maxMs = Math.max(...regressReport.iterations.map((i) => Number(i.duration_ms)), 100);
                      const heightPct = Math.min(100, Math.max(10, (Number(it.duration_ms) / maxMs) * 100));
                      const isSelected = selectedIteration?.iteration === it.iteration;

                      return (
                        <button
                          key={it.iteration}
                          onClick={() => setSelectedIteration(it)}
                          className={`flex-1 min-w-[20px] max-w-[40px] rounded-t flex flex-col justify-end transition-all relative group cursor-pointer ${
                            it.success
                              ? isSelected ? "bg-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.5)]" : "bg-cyan-600/70 hover:bg-cyan-500"
                              : "bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.4)]"
                          }`}
                          style={{ height: `${heightPct}%` }}
                        >
                          <div className="opacity-0 group-hover:opacity-100 absolute bottom-full mb-2 left-1/2 -translate-x-1/2 p-2 bg-slate-900 border border-slate-700 rounded-lg text-[10px] font-mono text-white whitespace-nowrap z-30 pointer-events-none shadow-xl">
                            <div>Iter #{it.iteration} ({it.status_code || "ERR"})</div>
                            <div>DNS: {it.dns_lookup_ms}ms</div>
                            <div>TCP: {it.tcp_connect_ms}ms</div>
                            <div>TTFB: {it.ttfb_ms}ms</div>
                            <div className="text-cyan-300 font-bold">Total: {it.duration_ms}ms</div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Iteration Session Log & Details */}
              {regressReport && regressReport.iterations.length > 0 && (
                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-2">
                      <Clock className="w-4 h-4 text-cyan-400" />
                      <span>Cold Session Log ({regressReport.iterations.length} Iterations)</span>
                    </span>
                    <span className="text-xs font-mono text-slate-500">
                      Isolated Private Sockets
                    </span>
                  </div>

                  <div className="max-h-64 overflow-y-auto divide-y divide-[#182339] border border-[#182339] rounded-lg">
                    {regressReport.iterations.map((it) => (
                      <div
                        key={it.iteration}
                        onClick={() => setSelectedIteration(it)}
                        className={`p-3 flex items-center justify-between text-xs font-mono cursor-pointer transition-colors ${
                          selectedIteration?.iteration === it.iteration ? "bg-cyan-950/40" : "hover:bg-[#10192e]"
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            it.success ? "bg-emerald-950 text-emerald-400 border border-emerald-800/50" : "bg-rose-950 text-rose-400 border border-rose-800/50"
                          }`}>
                            {it.status_code || "ERR"}
                          </span>
                          <span className="text-slate-300 font-semibold">Iteration #{it.iteration}</span>
                          <span className="text-slate-500 text-[11px]">{it.session_id}</span>
                        </div>

                        <div className="flex items-center gap-4 text-slate-400">
                          <span>DNS: <strong className="text-slate-200">{it.dns_lookup_ms}ms</strong></span>
                          <span>TCP: <strong className="text-slate-200">{it.tcp_connect_ms}ms</strong></span>
                          <span>TTFB: <strong className="text-slate-200">{it.ttfb_ms}ms</strong></span>
                          <span className="text-cyan-300 font-bold">{it.duration_ms}ms</span>

                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              copyToClipboard(it.curl_command, `curl-${it.iteration}`);
                            }}
                            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300"
                            title="Copy reproduction cURL"
                          >
                            {copiedText === `curl-${it.iteration}` ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {/* TAB 2: 6-PILLAR DEEP PROTOCOL & NETWORK AUDIT */}
          {activeTab === "deep_audit" && (
            <div className="space-y-6">
              {/* Executive Health Banner, Live Progress Cockpit, or Launch CTA */}
              {isDeepAuditRunning ? (
                <div className="p-7 rounded-xl bg-[#080e1c] border border-cyan-500/50 text-center space-y-4 shadow-[0_0_25px_rgba(6,182,212,0.18)]">
                  <div className="relative w-14 h-14 mx-auto flex items-center justify-center">
                    <div className="absolute inset-0 rounded-full border-2 border-cyan-500/40 animate-ping" />
                    <RotateCw className="w-7 h-7 text-cyan-400 animate-spin" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-base font-bold text-white flex items-center justify-center gap-2 flex-wrap">
                      <span>Probing All 6 Deep Network &amp; Protocol Pillars...</span>
                      <span className="text-xs font-mono font-normal text-cyan-300 bg-cyan-950/90 px-2 py-0.5 rounded border border-cyan-800">
                        {target}
                      </span>
                    </h3>
                    <p className="text-xs text-slate-400 max-w-lg mx-auto">
                      Executing parallel protocol sweeps: IPv4/IPv6 Happy Eyeballs, Sub-Resource Cascade, HTTP/2 ALPN, TLS 1.3 Chain, CORS Preflight, and Path MTU Black Holes (~4-8 seconds).
                    </p>
                  </div>

                  {/* 6-Pillar Stepper Visualizer */}
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2 max-w-xl mx-auto pt-2 text-left font-mono text-[11px]">
                    <div className="p-2 rounded bg-[#0b1426] border border-cyan-800/60 flex items-center gap-2 text-cyan-300">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping shrink-0" />
                      <span>1. IPv4 / IPv6 Eyeballs</span>
                    </div>
                    <div className="p-2 rounded bg-[#0b1426] border border-cyan-800/60 flex items-center gap-2 text-cyan-300">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping shrink-0" />
                      <span>2. Sub-Resource Cascade</span>
                    </div>
                    <div className="p-2 rounded bg-[#0b1426] border border-cyan-800/60 flex items-center gap-2 text-cyan-300">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping shrink-0" />
                      <span>3. HTTP/2 &amp; 3 Matrix</span>
                    </div>
                    <div className="p-2 rounded bg-[#0b1426] border border-cyan-800/60 flex items-center gap-2 text-cyan-300">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping shrink-0" />
                      <span>4. TLS 1.3 Chain Check</span>
                    </div>
                    <div className="p-2 rounded bg-[#0b1426] border border-cyan-800/60 flex items-center gap-2 text-cyan-300">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping shrink-0" />
                      <span>5. CORS Preflight Check</span>
                    </div>
                    <div className="p-2 rounded bg-[#0b1426] border border-cyan-800/60 flex items-center gap-2 text-cyan-300">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping shrink-0" />
                      <span>6. MTU Size Sweep</span>
                    </div>
                  </div>
                </div>
              ) : deepAuditError ? (
                <div className="p-6 rounded-xl bg-rose-950/30 border border-rose-600/50 space-y-3">
                  <div className="flex items-center gap-2 text-rose-300">
                    <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
                    <h3 className="text-sm font-bold">Deep Network Audit Failed</h3>
                  </div>
                  <p className="text-xs font-mono text-rose-200">{deepAuditError}</p>
                  <button
                    onClick={handleRunDeepAudit}
                    className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold transition-all cursor-pointer"
                  >
                    Retry 6-Pillar Audit
                  </button>
                </div>
              ) : deepAuditReport ? (
                <div className={`p-5 rounded-xl border flex items-center justify-between gap-6 ${
                  deepAuditReport.overall_verdict === "PASS"
                    ? "bg-emerald-950/20 border-emerald-500/50"
                    : deepAuditReport.overall_verdict === "WARN"
                    ? "bg-amber-950/20 border-amber-500/50"
                    : "bg-rose-950/20 border-rose-500/50"
                }`}>
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2.5">
                      <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase tracking-wider ${
                        deepAuditReport.overall_verdict === "PASS" ? "bg-emerald-900/60 text-emerald-300" :
                        deepAuditReport.overall_verdict === "WARN" ? "bg-amber-900/60 text-amber-300" : "bg-rose-900/60 text-rose-300"
                      }`}>
                        VERDICT: {deepAuditReport.overall_verdict}
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        Evaluated {deepAuditReport.target}
                      </span>
                    </div>
                    <p className="text-sm font-semibold text-white">
                      {deepAuditReport.executive_summary}
                    </p>
                  </div>

                  <div className="flex flex-col items-center justify-center p-3 px-5 rounded-xl bg-[#0b101c] border border-[#1c2944] shrink-0">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Health Score</span>
                    <span className={`text-3xl font-extrabold font-mono ${
                      deepAuditReport.health_score >= 90 ? "text-emerald-400" :
                      deepAuditReport.health_score >= 70 ? "text-amber-400" : "text-rose-400"
                    }`}>
                      {deepAuditReport.health_score}
                      <span className="text-sm text-slate-500 font-normal">/100</span>
                    </span>
                  </div>
                </div>
              ) : (
                <div className="p-8 rounded-xl bg-[#0c1222] border border-[#1c2a44] text-center space-y-3">
                  <Network className="w-10 h-10 text-cyan-400 mx-auto animate-pulse" />
                  <h3 className="text-base font-bold text-white">Ready to Audit All 6 Deep Network Pillars</h3>
                  <p className="text-xs text-slate-400 max-w-md mx-auto">
                    Inspects IPv4 vs IPv6 Happy Eyeballs, Sub-Resource Cascade (MIME / SPA fallbacks), HTTP/1.1 vs HTTP/2 vs HTTP/3, TLS Certificate Chain, CORS Preflight, and MTU Black Holes.
                  </p>
                  <button
                    onClick={handleRunDeepAudit}
                    disabled={isDeepAuditRunning}
                    className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold cursor-pointer transition-all"
                  >
                    Launch 6-Pillar Audit
                  </button>
                </div>
              )}

              {/* Identified Risks & Remediation */}
              {deepAuditReport && deepAuditReport.identified_risks.length > 0 && (
                <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-600/40 space-y-3">
                  <div className="flex items-center gap-2 text-rose-300 font-mono text-xs font-bold">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <span>Identified Flakiness & Network Vectors ({deepAuditReport.identified_risks.length})</span>
                  </div>
                  <ul className="space-y-1.5 pl-5 list-disc text-xs font-mono text-rose-200">
                    {deepAuditReport.identified_risks.map((risk, idx) => (
                      <li key={idx}>{risk}</li>
                    ))}
                  </ul>

                  {deepAuditReport.remediation_checklist.length > 0 && (
                    <div className="pt-3 border-t border-rose-900/40">
                      <span className="text-[11px] font-mono font-bold text-slate-300">Prescriptive Remediation:</span>
                      <ul className="space-y-1 pl-4 list-decimal text-xs font-mono text-slate-300 mt-1">
                        {deepAuditReport.remediation_checklist.map((rem, idx) => (
                          <li key={idx}>{rem}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* The 6 Pillars Grid */}
              {deepAuditReport && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Pillar 1: Dual-Stack IPv4 vs IPv6 */}
                  <div className="p-4 rounded-xl bg-[#0c1220] border border-[#1b2942] space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-2">
                        <Globe className="w-4 h-4 text-cyan-400" />
                        <span>1. Dual-Stack & Happy Eyeballs</span>
                      </span>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                        deepAuditReport.dual_stack.happy_eyeballs_risk ? "bg-rose-950 text-rose-300 border border-rose-800" :
                        deepAuditReport.dual_stack.has_ipv4 ? "bg-emerald-950 text-emerald-300 border border-emerald-800" : "bg-slate-800 text-slate-400"
                      }`}>
                        {deepAuditReport.dual_stack.ipv6_status}
                      </span>
                    </div>

                    <div className="space-y-1.5 text-xs font-mono text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-500">IPv4 Address:</span>
                        <span className="text-slate-200 font-semibold">{deepAuditReport.dual_stack.ipv4_addresses[0] || "None"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">IPv4 Latency:</span>
                        <span className="text-emerald-400">{deepAuditReport.dual_stack.ipv4_latency_ms ?? "--"}ms</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">IPv6 AAAA Record:</span>
                        <span className={deepAuditReport.dual_stack.has_ipv6 ? "text-cyan-300" : "text-slate-500"}>
                          {deepAuditReport.dual_stack.has_ipv6 ? deepAuditReport.dual_stack.ipv6_addresses[0] : "None published"}
                        </span>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono leading-relaxed pt-2 border-t border-slate-800">
                      {deepAuditReport.dual_stack.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 2: Sub-Resource Cascade & SPA Mismatch */}
                  <div className="p-4 rounded-xl bg-[#0c1220] border border-[#1b2942] space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-2">
                        <FileCode className="w-4 h-4 text-cyan-400" />
                        <span>2. Sub-Resource Cascade (SPA/Assets)</span>
                      </span>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                        deepAuditReport.subresources.spa_fallback_mismatches > 0 ? "bg-rose-950 text-rose-300 border border-rose-800" :
                        deepAuditReport.subresources.broken_count > 0 ? "bg-amber-950 text-amber-300 border border-amber-800" :
                        "bg-emerald-950 text-emerald-300 border border-emerald-800"
                      }`}>
                        {deepAuditReport.subresources.successful_count}/{deepAuditReport.subresources.total_discovered} OK
                      </span>
                    </div>

                    <div className="space-y-1.5 text-xs font-mono text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Total Assets Probed:</span>
                        <span className="text-slate-200">{deepAuditReport.subresources.total_discovered} files ({deepAuditReport.subresources.total_size_kb.toFixed(1)} KB)</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Broken Assets (4xx/5xx):</span>
                        <span className={deepAuditReport.subresources.broken_count > 0 ? "text-rose-400 font-bold" : "text-emerald-400"}>
                          {deepAuditReport.subresources.broken_count}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">SPA Fallback Mismatch (JS=HTML):</span>
                        <span className={deepAuditReport.subresources.spa_fallback_mismatches > 0 ? "text-rose-400 font-bold" : "text-emerald-400"}>
                          {deepAuditReport.subresources.spa_fallback_mismatches}
                        </span>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono leading-relaxed pt-2 border-t border-slate-800">
                      {deepAuditReport.subresources.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 3: HTTP Protocol Matrix */}
                  <div className="p-4 rounded-xl bg-[#0c1220] border border-[#1b2942] space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-2">
                        <Layers className="w-4 h-4 text-cyan-400" />
                        <span>3. HTTP Protocol Matrix</span>
                      </span>
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                        {deepAuditReport.protocol_matrix.active_protocol}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs font-mono">
                      {deepAuditReport.protocol_matrix.protocols.map((p, idx) => (
                        <div key={idx} className="flex items-center justify-between p-2 rounded bg-[#0f172a] border border-[#1d2b45]">
                          <span className="font-semibold text-slate-200">{p.protocol}</span>
                          <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
                            p.supported ? "bg-emerald-950 text-emerald-300" : "bg-slate-800 text-slate-400"
                          }`}>
                            {p.supported ? `Supported (${p.negotiation_time_ms}ms)` : "Unavailable"}
                          </span>
                        </div>
                      ))}
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono leading-relaxed pt-2 border-t border-slate-800">
                      {deepAuditReport.protocol_matrix.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 4: TLS & Certificate Chain */}
                  <div className="p-4 rounded-xl bg-[#0c1220] border border-[#1b2942] space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-2">
                        {deepAuditReport.tls_chain.is_https ? (
                          <Lock className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <Unlock className="w-4 h-4 text-amber-400" />
                        )}
                        <span>4. TLS & Certificate Chain</span>
                      </span>
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {deepAuditReport.tls_chain.tls_version}
                      </span>
                    </div>

                    <div className="space-y-1.5 text-xs font-mono text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Cipher Suite:</span>
                        <span className="text-slate-200 truncate max-w-[200px]">{deepAuditReport.tls_chain.cipher}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Issuer:</span>
                        <span className="text-slate-200">{deepAuditReport.tls_chain.cert_issuer}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Intermediate Chain:</span>
                        <span className={deepAuditReport.tls_chain.is_intermediate_missing ? "text-rose-400 font-bold" : "text-emerald-400"}>
                          {deepAuditReport.tls_chain.is_intermediate_missing ? "Incomplete Bundle" : "Complete"}
                        </span>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono leading-relaxed pt-2 border-t border-slate-800">
                      {deepAuditReport.tls_chain.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 5: CORS Preflight Inspector */}
                  <div className="p-4 rounded-xl bg-[#0c1220] border border-[#1b2942] space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-cyan-400" />
                        <span>5. CORS Preflight Boundary (OPTIONS)</span>
                      </span>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                        deepAuditReport.cors_preflight.preflight_passed ? "bg-emerald-950 text-emerald-300 border border-emerald-800" : "bg-rose-950 text-rose-300 border border-rose-800"
                      }`}>
                        HTTP {deepAuditReport.cors_preflight.preflight_status_code}
                      </span>
                    </div>

                    <div className="space-y-1.5 text-xs font-mono text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Allow-Origin:</span>
                        <span className="text-cyan-300 font-semibold">{deepAuditReport.cors_preflight.allow_origin || "None"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Allow-Methods:</span>
                        <span className="text-slate-300">{deepAuditReport.cors_preflight.allow_methods || "None"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Preflight Accepted:</span>
                        <span className={deepAuditReport.cors_preflight.preflight_passed ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
                          {deepAuditReport.cors_preflight.preflight_passed ? "Yes (200/204)" : "No (Blocked)"}
                        </span>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono leading-relaxed pt-2 border-t border-slate-800">
                      {deepAuditReport.cors_preflight.diagnosis}
                    </p>
                  </div>

                  {/* Pillar 6: MTU & Packet Size Sweep */}
                  <div className="p-4 rounded-xl bg-[#0c1220] border border-[#1b2942] space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-2">
                        <Flame className="w-4 h-4 text-cyan-400" />
                        <span>6. MTU & Packet Black Hole Sweeper</span>
                      </span>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                        deepAuditReport.mtu_sweep.black_hole_detected ? "bg-rose-950 text-rose-300 border border-rose-800" : "bg-emerald-950 text-emerald-300 border border-emerald-800"
                      }`}>
                        Max Safe: {deepAuditReport.mtu_sweep.maximum_safe_bytes}B
                      </span>
                    </div>

                    <div className="grid grid-cols-4 gap-2 text-center text-xs font-mono">
                      {deepAuditReport.mtu_sweep.sweep_results.map((m, idx) => (
                        <div key={idx} className={`p-2 rounded border ${
                          m.success ? "bg-emerald-950/40 border-emerald-800 text-emerald-300" : "bg-rose-950/40 border-rose-800 text-rose-300"
                        }`}>
                          <div className="font-bold text-[11px]">{m.payload_bytes}B</div>
                          <div className="text-[9px] text-slate-400">{m.duration_ms}ms</div>
                        </div>
                      ))}
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono leading-relaxed pt-2 border-t border-slate-800">
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
              {/* Global Edge Overview KPI */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] flex flex-col justify-between">
                  <span className="text-xs font-mono text-slate-400">Global Edge CDN</span>
                  <div className="flex items-center gap-2 mt-2">
                    <span className={`text-xl font-bold font-mono ${
                      !multiRegionReport ? "text-slate-500" :
                      multiRegionReport.cdn_edge_active ? "text-emerald-400" : "text-amber-400"
                    }`}>
                      {multiRegionReport ? (multiRegionReport.cdn_edge_active ? "ACTIVE (Edge POPs)" : "DIRECT ORIGIN") : "--"}
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] flex flex-col justify-between">
                  <span className="text-xs font-mono text-slate-400">Fastest Node</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-xl font-bold font-mono text-cyan-300">
                      {multiRegionReport?.fastest_region || "--"}
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] flex flex-col justify-between">
                  <span className="text-xs font-mono text-slate-400">Slowest Node</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-xl font-bold font-mono text-indigo-300">
                      {multiRegionReport?.slowest_region || "--"}
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#0d1424] border border-[#1c2b47] flex flex-col justify-between">
                  <span className="text-xs font-mono text-slate-400">Max Regional Disparity</span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className={`text-2xl font-bold font-mono ${
                      !multiRegionReport ? "text-slate-500" :
                      multiRegionReport.regional_disparity_ms <= 100 ? "text-emerald-400" :
                      multiRegionReport.regional_disparity_ms <= 200 ? "text-amber-400" : "text-rose-400"
                    }`}>
                      {multiRegionReport ? `${multiRegionReport.regional_disparity_ms}ms` : "--"}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">cross-continental delta</span>
                  </div>
                </div>
              </div>

              {/* Regional Cards Grid */}
              {multiRegionReport ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {multiRegionReport.regions.map((reg) => (
                    <div
                      key={reg.region_id}
                      className="p-4 rounded-xl bg-[#0d1424] border border-[#1d2b45] space-y-3 hover:border-cyan-500/40 transition-all"
                    >
                      <div className="flex items-center justify-between border-b border-[#182338] pb-2.5">
                        <div className="flex items-center gap-2">
                          <span className="text-xl">{reg.flag}</span>
                          <div>
                            <h4 className="font-mono text-xs font-bold text-slate-200">{reg.region_name}</h4>
                            <span className="text-[11px] font-mono text-slate-400">{reg.location}</span>
                          </div>
                        </div>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                          reg.status === "OPTIMAL"
                            ? "bg-emerald-950/60 border-emerald-700/60 text-emerald-300"
                            : reg.status === "ELEVATED"
                            ? "bg-amber-950/60 border-amber-700/60 text-amber-300"
                            : "bg-rose-950/60 border-rose-700/60 text-rose-300"
                        }`}>
                          {reg.status}
                        </span>
                      </div>

                      {/* Metrics Chips */}
                      <div className="grid grid-cols-4 gap-2 text-center font-mono">
                        <div className="p-2 rounded bg-[#070b13] border border-[#162136]">
                          <span className="text-[9px] text-slate-500 block uppercase">DNS</span>
                          <span className="text-xs font-bold text-slate-200">{reg.dns_time_ms}ms</span>
                        </div>
                        <div className="p-2 rounded bg-[#070b13] border border-[#162136]">
                          <span className="text-[9px] text-slate-500 block uppercase">TCP SYN</span>
                          <span className="text-xs font-bold text-slate-200">{reg.tcp_connect_ms}ms</span>
                        </div>
                        <div className="p-2 rounded bg-[#070b13] border border-[#162136]">
                          <span className="text-[9px] text-slate-500 block uppercase">TTFB</span>
                          <span className="text-xs font-bold text-cyan-300">{reg.ttfb_ms}ms</span>
                        </div>
                        <div className="p-2 rounded bg-[#070b13] border border-[#162136]">
                          <span className="text-[9px] text-slate-500 block uppercase">Total RTT</span>
                          <span className="text-xs font-bold text-emerald-400">{reg.total_time_ms}ms</span>
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                        <span>Edge POP: <span className="text-slate-200">{reg.edge_pop}</span></span>
                        <span>Jitter: <span className="text-slate-200">{reg.jitter_ms}ms</span></span>
                        <span>Loss: <span className="text-emerald-400">{reg.packet_loss_pct}%</span></span>
                      </div>

                      <p className="text-[11px] font-mono text-slate-400 leading-relaxed border-t border-[#182338] pt-2">
                        {reg.notes}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-8 rounded-xl bg-[#090e18] border border-[#1c2a42] text-center font-mono space-y-3">
                  <Compass className="w-8 h-8 text-cyan-400 mx-auto animate-pulse" />
                  <h4 className="text-sm font-bold text-slate-200">Global Distributed Edge Mesh</h4>
                  <p className="text-xs text-slate-400 max-w-lg mx-auto">
                    Simultaneously probes target URL from 4 distributed geographic regions (US-East, EU-West, APAC-Mumbai, APAC-Singapore) to catch geo-DNS propagation anomalies and CDN edge caching misses.
                  </p>
                  <button
                    onClick={handleRunMultiRegion}
                    disabled={isMultiRegionRunning}
                    className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-cyan-500 text-slate-950 rounded-lg text-xs font-bold cursor-pointer hover:brightness-110 disabled:opacity-50"
                  >
                    {isMultiRegionRunning ? "Probing Global Nodes..." : "Execute 4-Region Edge Probe"}
                  </button>
                </div>
              )}

              {/* Autonomous Multi-Region Agent Verdict */}
              {multiRegionReport && (
                <div className="p-5 rounded-xl bg-[#0b1222] border border-[#1b2b48] space-y-3 font-mono">
                  <div className="flex items-center gap-2">
                    <BrainCircuit className="w-4 h-4 text-cyan-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                      Autonomous Agent Global Verdict & Routing Insights
                    </h4>
                  </div>
                  <p className="text-xs text-slate-200 leading-relaxed bg-[#060a14] p-3 rounded-lg border border-[#152238]">
                    {multiRegionReport.agent_verdict}
                  </p>
                  {multiRegionReport.recommendations.length > 0 && (
                    <div className="space-y-1.5 pt-2">
                      <span className="text-[11px] font-semibold text-slate-400 block">Recommended Optimizations:</span>
                      {multiRegionReport.recommendations.map((rec, idx) => (
                        <div key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                          <span className="text-cyan-400 font-bold">•</span>
                          <span>{rec}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: PR GATE & GITHUB APP INTEGRATION */}
          {activeTab === "pr_gate" && (
            <div className="space-y-6">
              {/* SVG Badges Showcase */}
              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1c2b47] space-y-4 font-mono">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <GitPullRequest className="w-4 h-4 text-cyan-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                      Dynamic Embeddable SVG Badges
                    </h4>
                  </div>
                  <span className="text-[10px] text-slate-400">Live vector status for GitHub READMEs & PRs</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Badge 1: Quality Gate */}
                  <div className="p-3.5 rounded-lg bg-[#070b13] border border-[#182338] space-y-2.5">
                    <span className="text-[11px] text-slate-400 block">Quality Gate Verdict</span>
                    <div className="flex items-center justify-between">
                      <div className="inline-flex rounded overflow-hidden text-xs font-bold">
                        <span className="bg-[#1e293b] text-white px-2.5 py-1">ReadyHai</span>
                        <span className="bg-[#22c55e] text-white px-2.5 py-1">PASS</span>
                      </div>
                      <button
                        onClick={() => copyToClipboard("![ReadyHai Gate](http://localhost:8080/api/badges/gate?status=pass)", "badge-gate")}
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedText === "badge-gate" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedText === "badge-gate" ? "Copied" : "Copy"}</span>
                      </button>
                    </div>
                  </div>

                  {/* Badge 2: Evidence Ledger */}
                  <div className="p-3.5 rounded-lg bg-[#070b13] border border-[#182338] space-y-2.5">
                    <span className="text-[11px] text-slate-400 block">4-Pillar Evidence Ledger</span>
                    <div className="flex items-center justify-between">
                      <div className="inline-flex rounded overflow-hidden text-xs font-bold">
                        <span className="bg-[#0f172a] text-white px-2.5 py-1">Evidence Ledger</span>
                        <span className="bg-[#3b82f6] text-white px-2.5 py-1">94/100</span>
                      </div>
                      <button
                        onClick={() => copyToClipboard("![Evidence Ledger](http://localhost:8080/api/badges/ledger?score=94)", "badge-ledger")}
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedText === "badge-ledger" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedText === "badge-ledger" ? "Copied" : "Copy"}</span>
                      </button>
                    </div>
                  </div>

                  {/* Badge 3: Network Mesh */}
                  <div className="p-3.5 rounded-lg bg-[#070b13] border border-[#182338] space-y-2.5">
                    <span className="text-[11px] text-slate-400 block">Global Network Mesh</span>
                    <div className="flex items-center justify-between">
                      <div className="inline-flex rounded overflow-hidden text-xs font-bold">
                        <span className="bg-[#18181b] text-white px-2.5 py-1">Network Mesh</span>
                        <span className="bg-[#10b981] text-white px-2.5 py-1">100% Optimal</span>
                      </div>
                      <button
                        onClick={() => copyToClipboard("![Network Mesh](http://localhost:8080/api/badges/network?status=optimal)", "badge-mesh")}
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedText === "badge-mesh" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedText === "badge-mesh" ? "Copied" : "Copy"}</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* PR Status Comment Preview & Copy */}
              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1c2b47] space-y-4 font-mono">
                <div className="flex items-center justify-between border-b border-[#182338] pb-3">
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                      Pull Request Comment Markdown
                    </h4>
                    <span className="text-[11px] text-slate-400">Post directly to GitHub PR via CLI or GitHub Action step</span>
                  </div>
                  {prCommentData && (
                    <button
                      onClick={() => copyToClipboard(prCommentData.markdown, "pr-comment-md")}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950 border border-cyan-700/60 text-cyan-300 hover:bg-cyan-900 text-xs font-bold cursor-pointer transition-all"
                    >
                      {copiedText === "pr-comment-md" ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Copied Markdown!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy PR Comment</span>
                        </>
                      )}
                    </button>
                  )}
                </div>

                {prCommentData ? (
                  <div className="p-4 rounded-lg bg-[#060a14] border border-[#162238] text-xs text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap max-h-72 leading-relaxed">
                    {prCommentData.markdown}
                  </div>
                ) : (
                  <div className="p-4 rounded-lg bg-[#060a14] border border-[#162238] text-slate-400 text-xs flex items-center justify-between">
                    <span>Click below to generate an Evidence Ledger PR comment for {target}.</span>
                    <button
                      onClick={handleFetchPrComment}
                      disabled={isPrCommentLoading}
                      className="px-3 py-1 bg-cyan-950 border border-cyan-700 text-cyan-300 rounded font-semibold text-xs cursor-pointer"
                    >
                      {isPrCommentLoading ? "Generating..." : "Generate Comment"}
                    </button>
                  </div>
                )}
              </div>

              {/* GitHub Actions CI/CD Workflow (.github/workflows/readyhai.yml) */}
              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1c2b47] space-y-3 font-mono">
                <div className="flex items-center justify-between border-b border-[#182338] pb-3">
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                      GitHub Actions Workflow Snippet (.github/workflows/readyhai.yml)
                    </h4>
                    <span className="text-[11px] text-slate-400">Enforce blocking readiness gate & SARIF code scanning on every commit</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(
`name: ReadyHai Production Readiness Gate\non: [pull_request, push]\n\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n\n      - name: Install ReadyHai\n        run: |\n          curl -sSfL https://github.com/deziss/readyhai/releases/latest/download/readyhai-linux-x86_64.tar.gz | sudo tar xz -C /usr/local/bin\n\n      - name: Execute Quality & Network Gate\n        run: |\n          readyhai scan . --profile quick --format sarif,html --out readyhai-report\n\n      - name: Upload SARIF to GitHub Code Scanning\n        if: always()\n        uses: github/codeql-action/upload-sarif@v3\n        with:\n          sarif_file: readyhai-report/readyhai-report.sarif`,
                      "action-yaml"
                    )}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#080d19] border border-[#1b2b48] hover:border-cyan-500/50 text-cyan-300 text-xs font-bold cursor-pointer transition-all"
                  >
                    {copiedText === "action-yaml" ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Copied YAML!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Workflow YAML</span>
                      </>
                    )}
                  </button>
                </div>

                <pre className="p-4 rounded-lg bg-[#060a14] border border-[#162238] text-[11px] text-slate-300 font-mono overflow-x-auto leading-relaxed">
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

          
{/* Interactive cURL Execution Terminal (Available in both modes) */}
          <div className="p-4 rounded-xl bg-[#090e18] border border-[#1c2a42] space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-300 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Interactive cURL Diagnostic Terminal</span>
              </span>

              {curlResult && (
                <button
                  onClick={() => copyToClipboard(curlResult.command, "curl-command")}
                  className="flex items-center gap-1.5 text-xs font-mono text-cyan-400 hover:text-cyan-300"
                >
                  {copiedText === "curl-command" ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy cURL</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {curlResult ? (
              <div className="space-y-3 font-mono text-xs">
                {/* Generated cURL command */}
                <div className="p-3 bg-[#060912] rounded-lg border border-[#162136] text-cyan-300 break-all select-all">
                  {curlResult.command}
                </div>

                {/* Sub-millisecond timing chips */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                  <div className="p-2 rounded bg-[#0d1424] border border-[#1d2b45] text-center">
                    <span className="text-[10px] text-slate-500 block">DNS Lookup</span>
                    <span className="font-bold text-slate-200">{(curlResult.dns_lookup_s * 1000).toFixed(1)}ms</span>
                  </div>
                  <div className="p-2 rounded bg-[#0d1424] border border-[#1d2b45] text-center">
                    <span className="text-[10px] text-slate-500 block">TCP Connect</span>
                    <span className="font-bold text-slate-200">{(curlResult.connect_s * 1000).toFixed(1)}ms</span>
                  </div>
                  <div className="p-2 rounded bg-[#0d1424] border border-[#1d2b45] text-center">
                    <span className="text-[10px] text-slate-500 block">TLS / AppConnect</span>
                    <span className="font-bold text-slate-200">{(curlResult.appconnect_s * 1000).toFixed(1)}ms</span>
                  </div>
                  <div className="p-2 rounded bg-[#0d1424] border border-[#1d2b45] text-center">
                    <span className="text-[10px] text-slate-500 block">TTFB</span>
                    <span className="font-bold text-cyan-300">{(curlResult.starttransfer_s * 1000).toFixed(1)}ms</span>
                  </div>
                  <div className="p-2 rounded bg-[#0d1424] border border-[#1d2b45] text-center">
                    <span className="text-[10px] text-slate-500 block">Total RTT</span>
                    <span className="font-bold text-emerald-400">{(curlResult.total_s * 1000).toFixed(1)}ms</span>
                  </div>
                </div>

                {/* Output text */}
                {curlResult.stdout && (
                  <div className="p-3 bg-[#060912] rounded-lg border border-[#162136] text-slate-300 max-h-40 overflow-y-auto whitespace-pre-wrap">
                    {curlResult.stdout}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-[#060912] border border-[#162136] text-slate-500 font-mono text-xs flex items-center justify-between">
                <span>Click &quot;Run cURL Test&quot; in the left sidebar to execute real-time timing probes against {target}.</span>
                <button
                  onClick={handleRunCurl}
                  disabled={isCurlRunning}
                  className="px-3 py-1 bg-cyan-950 border border-cyan-700/50 hover:bg-cyan-900 text-cyan-300 rounded font-semibold text-xs cursor-pointer"
                >
                  {isCurlRunning ? "Executing..." : "Run Probe"}
                </button>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
