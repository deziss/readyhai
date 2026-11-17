import React from "react";
import {
  Sliders,
  Globe,
  ChevronDown,
  ChevronUp,
  FileCode,
  RotateCw,
  Play,
  Terminal,
} from "lucide-react";
import { BTN_PRIMARY, FOCUS, INPUT_CLS } from "./types";

interface RegressConfigPanelProps {
  target: string;
  setTarget: (target: string) => void;
  method: string;
  setMethod: (method: string) => void;
  iterations: number;
  setIterations: (iterations: number) => void;
  isCustomIterations: boolean;
  setIsCustomIterations: (isCustom: boolean) => void;
  throttleProfile: string;
  setThrottleProfile: (profile: string) => void;
  timeoutMs: number;
  setTimeoutMs: (timeoutMs: number) => void;
  delayBetweenMs: number;
  setDelayBetweenMs: (delayMs: number) => void;
  customHeaders: string;
  setCustomHeaders: (headers: string) => void;
  showAdvancedHeaders: boolean;
  setShowAdvancedHeaders: (show: boolean) => void;
  isRegressRunning: boolean;
  isCurlRunning: boolean;
  onRunRegress: () => void;
  onRunCurl: () => void;
}

export function RegressConfigPanel({
  target,
  setTarget,
  method,
  setMethod,
  iterations,
  setIterations,
  isCustomIterations,
  setIsCustomIterations,
  throttleProfile,
  setThrottleProfile,
  timeoutMs,
  setTimeoutMs,
  delayBetweenMs,
  setDelayBetweenMs,
  customHeaders,
  setCustomHeaders,
  showAdvancedHeaders,
  setShowAdvancedHeaders,
  isRegressRunning,
  isCurlRunning,
  onRunRegress,
  onRunCurl,
}: RegressConfigPanelProps) {
  return (
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
          <div className="pt-1">
            <input
              type="number"
              min={1}
              max={100}
              value={iterations}
              onChange={(e) => setIterations(Math.max(1, Math.min(100, Number(e.target.value) || 1)))}
              className={`w-full px-2.5 py-1 ${INPUT_CLS}`}
              placeholder="1 to 100 iterations"
            />
          </div>
        )}
      </div>

      {/* Network Profiles: 3 Profiles Grid */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-rh-muted block">Network emulation</label>
        <div className="grid grid-cols-3 gap-1.5" role="radiogroup" aria-label="Network emulation profile">
          {[
            { id: "unthrottled", label: "Direct host" },
            { id: "intercontinental", label: "Global link" },
            { id: "flaky_cellular", label: "Lossy / Jitter" },
          ].map((p) => {
            const active = throttleProfile === p.id;
            return (
              <button
                key={p.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => setThrottleProfile(p.id)}
                className={`p-2 rounded-[6px] text-left transition-colors cursor-pointer flex items-center gap-1.5 ${FOCUS} ${
                  active
                    ? "bg-rh-primary/15 border border-rh-primary/40 text-rh-primary font-semibold"
                    : "bg-rh-bg border border-rh-line text-rh-muted hover:text-rh-text hover:bg-rh-raised"
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
          onClick={onRunRegress}
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
          onClick={onRunCurl}
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
  );
}
