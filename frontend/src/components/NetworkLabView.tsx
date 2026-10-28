"use client";

import { useState } from "react";
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
  const [activeTab, setActiveTab] = useState<"regress" | "deep_audit">("regress");

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

  // cURL Runner
  const [isCurlRunning, setIsCurlRunning] = useState(false);
  const [curlResult, setCurlResult] = useState<CurlTestResponse | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);

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
      }
    } catch (err) {
      console.error("Deep audit failed:", err);
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
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-[#0d1527] border border-[#1d2b45] text-xs font-mono">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400 font-normal">Active URL:</span>
            <span className="text-cyan-300 font-semibold">{target}</span>
          </div>

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
              {/* Executive Health Banner */}
              {deepAuditReport ? (
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
                    {isDeepAuditRunning ? "Running Deep Audit..." : "Launch 6-Pillar Audit"}
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
