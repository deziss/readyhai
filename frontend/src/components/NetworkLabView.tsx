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
} from "lucide-react";
import type {
  RegressRequest,
  RegressReport,
  IterationResult,
  CurlTestResponse,
} from "@/types/network";

interface NetworkLabViewProps {
  initialTarget?: string;
}

export function NetworkLabView({ initialTarget = "http://readyhai:8080" }: NetworkLabViewProps) {
  // Test configuration
  const [target, setTarget] = useState(initialTarget);
  const [method, setMethod] = useState("GET");
  const [iterations, setIterations] = useState(10);
  const [timeoutMs, setTimeoutMs] = useState(5000);
  const [throttleProfile, setThrottleProfile] = useState<string>("unthrottled");
  const [separateSessions, setSeparateSessions] = useState(true);
  const [delayBetweenMs, setDelayBetweenMs] = useState(50);
  const [customHeaders, setCustomHeaders] = useState("");
  const [customPayload, setCustomPayload] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Execution state
  const [isRunning, setIsRunning] = useState(false);
  const [progressMsg, setProgressMsg] = useState("");
  const [report, setReport] = useState<RegressReport | null>(null);
  const [selectedIteration, setSelectedIteration] = useState<IterationResult | null>(null);

  // cURL test state
  const [isCurlRunning, setIsCurlRunning] = useState(false);
  const [curlResult, setCurlResult] = useState<CurlTestResponse | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [filterMode, setFilterMode] = useState<"ALL" | "FAILED" | "PASSED">("ALL");

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const parseHeaders = (): Record<string, string> => {
    const map: Record<string, string> = {};
    if (!customHeaders.trim()) return map;
    try {
      if (customHeaders.trim().startsWith("{")) {
        return JSON.parse(customHeaders);
      }
      for (const line of customHeaders.split("\n")) {
        const idx = line.indexOf(":");
        if (idx > 0) {
          const k = line.slice(0, idx).trim();
          const v = line.slice(idx + 1).trim();
          if (k) map[k] = v;
        }
      }
    } catch {
      // ignore parse err
    }
    return map;
  };

  const handleRunRegress = async () => {
    if (!target.trim()) return;
    setIsRunning(true);
    setProgressMsg(`Spawning ${iterations} isolated private sessions...`);
    setCurlResult(null);

    const payload: RegressRequest = {
      target: target.trim(),
      method,
      headers: parseHeaders(),
      payload: customPayload.trim() || null,
      iterations,
      timeout_ms: timeoutMs,
      throttle_profile: throttleProfile,
      separate_sessions: separateSessions,
      delay_between_ms: delayBetweenMs,
    };

    try {
      const res = await fetch("/api/network/regress", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data: RegressReport = await res.json();
        setReport(data);
        if (data.results.length > 0) {
          setSelectedIteration(data.results[0]);
        }
      } else {
        const err = await res.json().catch(() => ({ error: "Request failed" }));
        alert(`Regressive test error: ${err.error || res.statusText}`);
      }
    } catch (e: any) {
      alert(`Network execution error: ${e.message}`);
    } finally {
      setIsRunning(false);
      setProgressMsg("");
    }
  };

  const handleRunCurl = async (overrideTarget?: string) => {
    const tgt = overrideTarget || target;
    if (!tgt.trim()) return;
    setIsCurlRunning(true);
    try {
      const res = await fetch("/api/network/curl", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: tgt.trim(),
          method,
          headers: parseHeaders(),
          payload: customPayload.trim() || null,
          timeout_ms: timeoutMs,
        }),
      });
      if (res.ok) {
        const data: CurlTestResponse = await res.json();
        setCurlResult(data);
      }
    } catch (e: any) {
      console.error("cURL test error:", e);
    } finally {
      setIsCurlRunning(false);
    }
  };

  const filteredResults = report?.results.filter((r) => {
    if (filterMode === "PASSED") return r.success;
    if (filterMode === "FAILED") return !r.success;
    return true;
  }) || [];

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-[#06080e] overflow-hidden">
      {/* Top Breadcrumb Bar */}
      <div className="h-11 px-6 border-b border-[#161f30] bg-[#0a0f1b] flex items-center justify-between text-xs text-slate-400 shrink-0">
        <div className="flex items-center gap-2 font-mono">
          <Activity className="w-4 h-4 text-cyan-400" />
          <span className="text-slate-200 font-semibold">Regressive Network Lab</span>
          <span className="text-slate-600">/</span>
          <span>Continuous Multi-Session Flakiness & Throttle Diagnostics</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/40 text-cyan-300">
            Isolated Sockets Mode
          </span>
        </div>
      </div>

      {/* Main Dual-Column Layout */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 min-h-0 overflow-hidden">
        {/* LEFT COLUMN: Test Configuration & Controls (5 cols) */}
        <div className="lg:col-span-5 border-r border-[#161f30] bg-[#080d17] p-5 overflow-y-auto space-y-4 min-h-0">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Regressive Test Configuration
            </h3>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Execute repeated requests across clean private sessions to expose intermittent connection drops, DNS lag, and gateway flapping.
            </p>
          </div>

          {/* Target URL */}
          <div className="space-y-1.5 font-mono text-xs">
            <label className="text-slate-300 font-semibold flex items-center justify-between">
              <span>Target URL:</span>
              <div className="flex items-center gap-1.5 text-[10px]">
                <button
                  type="button"
                  onClick={() => setTarget("http://readyhai:8080/health")}
                  className="text-cyan-400 hover:underline cursor-pointer"
                >
                  /health
                </button>
                <span className="text-slate-600">·</span>
                <button
                  type="button"
                  onClick={() => setTarget("http://readyhai:8080/api/agent/status")}
                  className="text-cyan-400 hover:underline cursor-pointer"
                >
                  /api/status
                </button>
              </div>
            </label>
            <div className="flex items-center gap-2">
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="bg-[#0e1626] border border-[#1c283f] rounded-lg px-2.5 py-2 text-xs font-bold text-cyan-300 focus:outline-none focus:border-cyan-500/60 cursor-pointer"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="HEAD">HEAD</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="https://example.com/api/endpoint"
                className="flex-1 bg-[#0e1626] border border-[#1c283f] rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
              />
            </div>
          </div>

          {/* Regressive Iterations & Presets */}
          <div className="space-y-1.5 font-mono text-xs">
            <div className="flex items-center justify-between">
              <label className="text-slate-300 font-semibold">Continuous Regressive Iterations:</label>
              <span className="text-cyan-300 font-bold">{iterations} runs</span>
            </div>
            <div className="flex items-center gap-2">
              {[5, 10, 25, 50].map((num) => (
                <button
                  key={num}
                  type="button"
                  onClick={() => setIterations(num)}
                  className={`flex-1 py-1.5 rounded-lg border text-xs font-mono font-semibold transition-all cursor-pointer ${
                    iterations === num
                      ? "bg-cyan-950/80 text-cyan-300 border-cyan-600/60 shadow-sm"
                      : "bg-[#0e1626] text-slate-400 border-[#1c283f] hover:text-white"
                  }`}
                >
                  {num}x
                </button>
              ))}
            </div>
            <input
              type="range"
              min="1"
              max="100"
              value={iterations}
              onChange={(e) => setIterations(Number(e.target.value))}
              className="w-full accent-cyan-400 cursor-pointer mt-1"
            />
          </div>

          {/* Private Sessions Isolation Toggle */}
          <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2b46] space-y-1 font-mono text-xs">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-200 font-semibold">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <span>Separate Private Sessions</span>
              </div>
              <input
                type="checkbox"
                checked={separateSessions}
                onChange={(e) => setSeparateSessions(e.target.checked)}
                className="accent-cyan-400 w-4 h-4 cursor-pointer"
              />
            </div>
            <p className="text-[11px] text-slate-400 pt-0.5">
              Enforces a clean connection per iteration without socket pooling. Tests cold connection negotiation, fresh DNS, and TLS handshakes to catch transient 502/timeout flapping.
            </p>
          </div>

          {/* Network Throttling Profiles */}
          <div className="space-y-1.5 font-mono text-xs">
            <label className="text-slate-300 font-semibold flex items-center gap-1.5">
              <Wifi className="w-3.5 h-3.5 text-cyan-400" />
              <span>Network Throttling Profile:</span>
            </label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { id: "unthrottled", name: "Unthrottled", desc: "Direct low latency" },
                { id: "fast_3g", name: "Mobile / 4G", desc: "+75ms latency" },
                { id: "slow_3g", name: "Slow 3G", desc: "+250ms latency" },
                { id: "flaky", name: "Flaky Simulation", desc: "Jitter + 400ms drops" },
              ].map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setThrottleProfile(p.id)}
                  className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                    throttleProfile === p.id
                      ? "bg-cyan-950/80 text-cyan-300 border-cyan-600/60 shadow-sm"
                      : "bg-[#0e1626] text-slate-400 border-[#1c283f] hover:text-slate-200"
                  }`}
                >
                  <div className="text-xs font-bold">{p.name}</div>
                  <div className="text-[10px] text-slate-500 font-normal mt-0.5">{p.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Timeout & Delay Controls */}
          <div className="grid grid-cols-2 gap-3 font-mono text-xs">
            <div>
              <label className="text-slate-400 block mb-1">Timeout Budget:</label>
              <select
                value={timeoutMs}
                onChange={(e) => setTimeoutMs(Number(e.target.value))}
                className="w-full bg-[#0e1626] border border-[#1c283f] rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500/60 cursor-pointer"
              >
                <option value={1000}>1,000 ms (1s)</option>
                <option value={3000}>3,000 ms (3s)</option>
                <option value={5000}>5,000 ms (5s)</option>
                <option value={10000}>10,000 ms (10s)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 block mb-1">Delay Between:</label>
              <select
                value={delayBetweenMs}
                onChange={(e) => setDelayBetweenMs(Number(e.target.value))}
                className="w-full bg-[#0e1626] border border-[#1c283f] rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500/60 cursor-pointer"
              >
                <option value={0}>0 ms (Burst)</option>
                <option value={50}>50 ms</option>
                <option value={100}>100 ms</option>
                <option value={300}>300 ms</option>
              </select>
            </div>
          </div>

          {/* Advanced Headers & Payload Accordion */}
          <div className="border border-[#162238] rounded-lg overflow-hidden font-mono text-xs">
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="w-full p-2.5 bg-[#0a101d] flex items-center justify-between text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              <span>Custom Headers & Payload</span>
              {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
            {showAdvanced && (
              <div className="p-3 bg-[#080d17] space-y-3 border-t border-[#162238]">
                <div>
                  <label className="text-slate-400 block mb-1">Custom Headers (Header: Value):</label>
                  <textarea
                    rows={2}
                    value={customHeaders}
                    onChange={(e) => setCustomHeaders(e.target.value)}
                    placeholder="Authorization: Bearer token&#10;X-Custom-Header: value"
                    className="w-full bg-[#0e1626] border border-[#1c283f] rounded-md p-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60"
                  />
                </div>
                {["POST", "PUT"].includes(method) && (
                  <div>
                    <label className="text-slate-400 block mb-1">JSON Payload Body:</label>
                    <textarea
                      rows={2}
                      value={customPayload}
                      onChange={(e) => setCustomPayload(e.target.value)}
                      placeholder='{"key": "value"}'
                      className="w-full bg-[#0e1626] border border-[#1c283f] rounded-md p-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60"
                    />
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="pt-2 flex flex-col gap-2.5 font-mono">
            <button
              type="button"
              onClick={handleRunRegress}
              disabled={isRunning || isCurlRunning}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs tracking-wide shadow-lg shadow-cyan-950/40 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {isRunning ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  Testing Regressively...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  Start Regressive Multi-Session Test
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => handleRunCurl()}
              disabled={isRunning || isCurlRunning}
              className="w-full py-2 rounded-xl bg-[#101b2d] hover:bg-[#15233b] border border-[#1d2d48] text-cyan-300 font-semibold text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {isCurlRunning ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                  Executing cURL...
                </>
              ) : (
                <>
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  Run Instant cURL Test
                </>
              )}
            </button>
          </div>
        </div>

        {/* RIGHT COLUMN: Results, Flakiness Analysis & Agent Diagnostics (7 cols) */}
        <div className="lg:col-span-7 bg-[#070b14] p-6 overflow-y-auto min-h-0 space-y-5">
          {isRunning && (
            <div className="p-8 rounded-xl bg-[#0c1424] border border-[#1b2b46] text-center space-y-3 font-mono">
              <RotateCw className="w-8 h-8 animate-spin mx-auto text-cyan-400" />
              <h3 className="text-sm font-bold text-white">Running Regressive Network Test</h3>
              <p className="text-xs text-slate-400">{progressMsg}</p>
              <div className="w-48 h-1.5 bg-slate-800 rounded-full mx-auto overflow-hidden">
                <div className="h-full bg-cyan-400 animate-pulse w-3/4"></div>
              </div>
            </div>
          )}

          {/* cURL Test Terminal Inspector (When executed) */}
          {curlResult && (
            <div className="rounded-xl bg-[#080d17] border border-[#1d2f4d] shadow-lg overflow-hidden font-mono">
              <div className="p-3 bg-[#0d1627] border-b border-[#1d2f4d] flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 text-cyan-300 font-bold">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <span>cURL Command Execution Output</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${curlResult.exit_code === 0 ? 'bg-emerald-950 text-emerald-400 border border-emerald-600/50' : 'bg-red-950 text-red-400 border border-red-600/50'}`}>
                    EXIT: {curlResult.exit_code}
                  </span>
                  <button
                    onClick={() => handleCopy(curlResult.command, "curl-cmd")}
                    className="text-slate-400 hover:text-cyan-300 cursor-pointer flex items-center gap-1"
                  >
                    {copiedId === "curl-cmd" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                    Copy cURL
                  </button>
                </div>
              </div>

              {/* cURL Timing Variables Breakdown */}
              <div className="p-3 bg-[#0a111f] border-b border-[#17253d] grid grid-cols-2 sm:grid-cols-5 gap-2 text-[11px]">
                <div className="p-2 rounded bg-[#0e172a] border border-[#1a2b47]">
                  <span className="text-slate-500 block">DNS Lookup:</span>
                  <span className="text-cyan-300 font-bold">{(curlResult.dns_lookup_s * 1000).toFixed(1)} ms</span>
                </div>
                <div className="p-2 rounded bg-[#0e172a] border border-[#1a2b47]">
                  <span className="text-slate-500 block">TCP Connect:</span>
                  <span className="text-cyan-300 font-bold">{(curlResult.connect_s * 1000).toFixed(1)} ms</span>
                </div>
                <div className="p-2 rounded bg-[#0e172a] border border-[#1a2b47]">
                  <span className="text-slate-500 block">TLS Handshake:</span>
                  <span className="text-cyan-300 font-bold">{(curlResult.appconnect_s * 1000).toFixed(1)} ms</span>
                </div>
                <div className="p-2 rounded bg-[#0e172a] border border-[#1a2b47]">
                  <span className="text-slate-500 block">TTFB:</span>
                  <span className="text-cyan-300 font-bold">{(curlResult.starttransfer_s * 1000).toFixed(1)} ms</span>
                </div>
                <div className="p-2 rounded bg-[#0e172a] border border-[#1a2b47]">
                  <span className="text-slate-500 block">Total Transfer:</span>
                  <span className="text-emerald-400 font-bold">{(curlResult.total_s * 1000).toFixed(1)} ms</span>
                </div>
              </div>

              {/* Terminal Pre */}
              <pre className="p-4 text-xs text-slate-200 overflow-x-auto max-h-56 select-text whitespace-pre-wrap">
                {curlResult.stdout || curlResult.stderr || "No output returned"}
              </pre>
            </div>
          )}

          {!report && !isRunning && !curlResult && (
            <div className="p-12 text-center text-slate-500 font-mono space-y-3">
              <Activity className="w-12 h-12 mx-auto text-slate-700 stroke-[1.5]" />
              <h3 className="text-base font-bold text-slate-300">Ready to Regressively Test Target</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Configure your target URL and iteration count on the left, then click <strong>&quot;Start Regressive Multi-Session Test&quot;</strong> to detect transient connection drops, port flapping, and network latency anomalies.
              </p>
            </div>
          )}

          {/* REPORT SUMMARY & DIAGNOSTICS */}
          {report && (
            <div className="space-y-5">
              {/* Top Hero KPI Banner */}
              <div className="p-5 rounded-xl bg-gradient-to-br from-[#0c1527] to-[#080d19] border border-[#1b2a45] shadow-lg font-mono">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/50 uppercase font-bold">
                        {report.iterations_completed} Sessions Completed
                      </span>
                      <span className="text-xs text-slate-400 truncate max-w-sm" title={report.target}>
                        {report.target}
                      </span>
                    </div>
                    <div className="text-xl font-bold text-white mt-1">
                      {report.success_rate_pct.toFixed(1)}% Success Rate
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Verdict:</span>
                    <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold uppercase ${
                      report.flakiness_verdict === 'STABLE'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/50'
                        : report.flakiness_verdict === 'FLAKY'
                        ? 'bg-amber-950 text-amber-400 border border-amber-500/50'
                        : 'bg-red-950 text-red-400 border border-red-500/50'
                    }`}>
                      {report.flakiness_verdict === 'STABLE' && <CheckCircle2 className="w-3.5 h-3.5" />}
                      {report.flakiness_verdict === 'FLAKY' && <AlertTriangle className="w-3.5 h-3.5" />}
                      {report.flakiness_verdict === 'CRITICAL_OUTAGE' && <XCircle className="w-3.5 h-3.5" />}
                      {report.flakiness_verdict}
                    </span>
                  </div>
                </div>

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-3 border-t border-[#182640] text-xs">
                  <div className="p-2.5 rounded bg-[#090e1a] border border-[#16243a]">
                    <span className="text-slate-500 block">Median (P50):</span>
                    <span className="text-cyan-300 font-bold text-base">{report.p50_ms} ms</span>
                  </div>
                  <div className="p-2.5 rounded bg-[#090e1a] border border-[#16243a]">
                    <span className="text-slate-500 block">Tail (P99):</span>
                    <span className="text-purple-300 font-bold text-base">{report.p99_ms} ms</span>
                  </div>
                  <div className="p-2.5 rounded bg-[#090e1a] border border-[#16243a]">
                    <span className="text-slate-500 block">Jitter Variance:</span>
                    <span className={`font-bold text-base ${report.jitter_ms > 150 ? 'text-amber-400' : 'text-emerald-400'}`}>
                      ±{report.jitter_ms} ms
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-[#090e1a] border border-[#16243a]">
                    <span className="text-slate-500 block">Failures / Drops:</span>
                    <span className={`font-bold text-base ${report.failed_count > 0 ? 'text-red-400' : 'text-slate-300'}`}>
                      {report.failed_count} / {report.iterations_completed}
                    </span>
                  </div>
                </div>
              </div>

              {/* HOW THE AGENT FOUND THE ISSUE (CORE DELIVERABLE) */}
              <div className="p-5 rounded-xl bg-[#090f1d] border border-cyan-800/40 shadow-lg font-mono space-y-3 relative overflow-hidden">
                <div className="flex items-center justify-between gap-2 border-b border-[#182845] pb-3">
                  <div className="flex items-center gap-2">
                    <BrainCircuit className="w-5 h-5 text-cyan-400" />
                    <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                      How The Agent Identified The Issue
                    </h4>
                  </div>
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-bold uppercase bg-[#132238] text-cyan-300 border border-[#203658]">
                    Root Cause: {report.agent_diagnosis.root_cause_type}
                  </span>
                </div>

                {/* Summary */}
                <div className="p-3 rounded-lg bg-[#0e172a] border border-[#1a2c49] text-xs text-slate-200">
                  <span className="text-cyan-400 font-bold">Agent Diagnostic Summary: </span>
                  {report.agent_diagnosis.summary}
                </div>

                {/* Step-by-Step Diagnostic Reasoning Chain */}
                <div className="space-y-2">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide">
                    Agent Investigation & Reasoning Trace:
                  </span>
                  <div className="space-y-1.5">
                    {report.agent_diagnosis.how_agent_found_it.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-300 bg-[#060a13] p-2 rounded border border-[#152238]">
                        <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-700/60 text-cyan-300 text-[10px] font-bold flex items-center justify-center shrink-0">
                          {idx + 1}
                        </span>
                        <span className="flex-1 leading-relaxed">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Technical Breakdown */}
                <div className="p-3 rounded-lg bg-[#060a13] border border-[#152238] space-y-1 text-xs">
                  <span className="text-[11px] font-bold text-purple-300 uppercase tracking-wide">
                    Technical Root Cause Analysis:
                  </span>
                  <p className="text-slate-300 leading-relaxed">
                    {report.agent_diagnosis.technical_breakdown}
                  </p>
                </div>

                {/* Remediation Prescription */}
                <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/40 space-y-1.5 text-xs">
                  <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wide flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Recommended Remediation Prescription:
                  </span>
                  <ul className="space-y-1 text-slate-300 list-disc list-inside text-[11px]">
                    {report.agent_diagnosis.remediation_steps.map((rem, idx) => (
                      <li key={idx}>{rem}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Visual Latency Waterfall Strip */}
              <div className="p-4 rounded-xl bg-[#0c1424] border border-[#1b2b46] font-mono space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-bold">Session Latency Waterfall</span>
                  <span className="text-slate-500 text-[11px]">Click a bar to inspect session</span>
                </div>
                <div className="flex items-end gap-1.5 h-20 pt-2 border-b border-[#182640]">
                  {report.results.map((r) => {
                    const maxD = Math.max(...report.results.map((x) => x.duration_ms), 1);
                    const pct = Math.max(12, Math.min(100, (r.duration_ms / maxD) * 100));
                    const isSelected = selectedIteration?.iteration === r.iteration;

                    return (
                      <button
                        key={r.iteration}
                        type="button"
                        onClick={() => setSelectedIteration(r)}
                        className={`flex-1 rounded-t transition-all cursor-pointer relative group ${
                          !r.success
                            ? 'bg-red-500'
                            : r.duration_ms > report.p90_ms
                            ? 'bg-amber-400'
                            : 'bg-cyan-500'
                        } ${isSelected ? 'ring-2 ring-white' : 'opacity-80 hover:opacity-100'}`}
                        style={{ height: `${pct}%` }}
                        title={`Run #${r.iteration}: ${r.duration_ms}ms (${r.status_code || 'Dropped'})`}
                      >
                      </button>
                    );
                  })}
                </div>
                <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                  <span>Run #1</span>
                  <span>Run #{report.iterations_completed}</span>
                </div>
              </div>

              {/* Iterations Results Table */}
              <div className="rounded-xl bg-[#0c1424] border border-[#1b2b46] overflow-hidden font-mono text-xs shadow-sm">
                <div className="p-3 bg-[#0f192d] border-b border-[#1b2b46] flex items-center justify-between">
                  <span className="font-bold text-slate-200">Iteration Session Logs</span>
                  <div className="flex items-center gap-1 text-[11px]">
                    {(['ALL', 'FAILED', 'PASSED'] as const).map((m) => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setFilterMode(m)}
                        className={`px-2 py-0.5 rounded cursor-pointer ${
                          filterMode === m ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/50' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="divide-y divide-[#152238] max-h-72 overflow-y-auto">
                  {filteredResults.map((res) => {
                    const isSelected = selectedIteration?.iteration === res.iteration;
                    return (
                      <div
                        key={res.iteration}
                        onClick={() => setSelectedIteration(res)}
                        className={`p-3 flex items-center justify-between gap-3 cursor-pointer transition-colors ${
                          isSelected ? 'bg-[#121f36]' : 'hover:bg-[#0e172a]'
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <span className="font-bold text-slate-400 w-8">#{res.iteration}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            res.success ? 'bg-emerald-950 text-emerald-400 border border-emerald-600/50' : 'bg-red-950 text-red-400 border border-red-600/50'
                          }`}>
                            {res.status_code > 0 ? `HTTP ${res.status_code}` : 'DROPPED'}
                          </span>
                          <span className="text-slate-300 text-xs truncate max-w-xs">
                            {res.error_message || "Completed OK"}
                          </span>
                        </div>

                        <div className="flex items-center gap-4 shrink-0 text-right">
                          <span className="text-slate-400 text-xs">{res.duration_ms} ms</span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopy(res.curl_command, `curl-${res.iteration}`);
                            }}
                            className="text-slate-500 hover:text-cyan-300 p-1 cursor-pointer"
                            title="Copy reproduction cURL"
                          >
                            {copiedId === `curl-${res.iteration}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Selected Iteration Inspector */}
              {selectedIteration && (
                <div className="p-4 rounded-xl bg-[#090e1a] border border-[#192b47] font-mono text-xs space-y-3">
                  <div className="flex items-center justify-between border-b border-[#16233a] pb-2">
                    <span className="font-bold text-slate-200">
                      Session Inspector: Iteration #{selectedIteration.iteration} ({selectedIteration.session_id})
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopy(selectedIteration.curl_command, "inspect-curl")}
                      className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 cursor-pointer"
                    >
                      {copiedId === "inspect-curl" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      Copy cURL
                    </button>
                  </div>

                  {/* Timing Breakdown Badges */}
                  <div className="grid grid-cols-3 gap-2 text-[11px]">
                    <div className="p-2 rounded bg-[#060a12] border border-[#162238]">
                      <span className="text-slate-500 block">DNS Lookup:</span>
                      <span className="text-cyan-300 font-bold">{selectedIteration.dns_lookup_ms} ms</span>
                    </div>
                    <div className="p-2 rounded bg-[#060a12] border border-[#162238]">
                      <span className="text-slate-500 block">TCP Connect:</span>
                      <span className="text-cyan-300 font-bold">{selectedIteration.tcp_connect_ms} ms</span>
                    </div>
                    <div className="p-2 rounded bg-[#060a12] border border-[#162238]">
                      <span className="text-slate-500 block">TTFB:</span>
                      <span className="text-cyan-300 font-bold">{selectedIteration.ttfb_ms} ms</span>
                    </div>
                  </div>

                  {/* cURL String */}
                  <div>
                    <span className="text-slate-500 block mb-1 font-bold">Reproduction cURL:</span>
                    <pre className="p-2.5 rounded bg-[#060a12] border border-[#162238] text-cyan-300/90 overflow-x-auto">
                      {selectedIteration.curl_command}
                    </pre>
                  </div>

                  {/* Response Body Snippet */}
                  {selectedIteration.response_body_snippet && (
                    <div>
                      <span className="text-slate-500 block mb-1 font-bold">Response Body Snippet:</span>
                      <pre className="p-2.5 rounded bg-[#060a12] border border-[#162238] text-slate-300 overflow-x-auto max-h-32">
                        {selectedIteration.response_body_snippet}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
