import React from "react";
import {
  Activity,
  BrainCircuit,
  Zap,
  Cpu,
  CheckCircle2,
  Clock,
  Copy,
  Check,
} from "lucide-react";
import { RegressReport, IterationResult } from "@/types/network";
import { CHIP, FOCUS, KPI_CARD, PANEL, sentence } from "./types";

interface RegressResultsViewProps {
  regressReport: RegressReport | null;
  isRegressRunning: boolean;
  selectedIteration: IterationResult | null;
  setSelectedIteration: (it: IterationResult | null) => void;
  copiedText: string | null;
  copyToClipboard: (text: string, id: string) => void;
}

export function RegressResultsView({
  regressReport,
  isRegressRunning,
  selectedIteration,
  setSelectedIteration,
  copiedText,
  copyToClipboard,
}: RegressResultsViewProps) {
  return (
    <>
      {/* Hero KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className={KPI_CARD}>
          <span className="text-xs text-rh-muted">Availability</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span
              className={`text-2xl font-semibold tabular-nums ${
                !regressReport
                  ? "text-rh-muted"
                  : regressReport.availability_percentage >= 99
                  ? "text-rh-go"
                  : regressReport.availability_percentage >= 80
                  ? "text-rh-cond"
                  : "text-rh-nogo"
              }`}
            >
              {regressReport
                ? `${regressReport.availability_percentage.toFixed(1)}%`
                : "--"}
            </span>
            <span className="text-xs text-rh-muted tabular-nums">
              {regressReport
                ? `${regressReport.successful_iterations}/${regressReport.total_iterations}`
                : "0/0"}
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
            <span
              className={`text-2xl font-semibold tabular-nums ${
                !regressReport
                  ? "text-rh-muted"
                  : regressReport.jitter_ms < 100
                  ? "text-rh-go"
                  : regressReport.jitter_ms < 300
                  ? "text-rh-cond"
                  : "text-rh-nogo"
              }`}
            >
              {regressReport ? `${regressReport.jitter_ms}ms` : "--"}
            </span>
            <span className="text-xs text-rh-muted">
              {regressReport?.jitter_ms && regressReport.jitter_ms > 200
                ? "High variance"
                : "Low variance"}
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
        <div
          className={`p-5 rounded-[10px] bg-rh-surface border border-rh-line border-l-4 space-y-4 ${
            regressReport.diagnosis.severity === "CRITICAL"
              ? "border-l-rh-nogo"
              : regressReport.diagnosis.severity === "HIGH"
              ? "border-l-rh-cond"
              : "border-l-rh-info"
          }`}
        >
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
                  <span
                    className={`${CHIP} ${
                      regressReport.diagnosis.severity === "CRITICAL"
                        ? "bg-rh-nogo/15 text-rh-nogo"
                        : regressReport.diagnosis.severity === "HIGH"
                        ? "bg-rh-cond/15 text-rh-cond"
                        : "bg-rh-info/15 text-rh-info"
                    }`}
                  >
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
                <li key={idx} className="leading-relaxed">
                  {step}
                </li>
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
                <li key={idx} className="leading-relaxed">
                  {item}
                </li>
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
              <span>
                Session latency and handshake distribution ({regressReport.iterations.length} attempts)
              </span>
            </span>
            <span className="text-xs text-rh-muted">
              Select a bar to inspect that attempt
            </span>
          </div>

          <div className="flex items-end gap-1.5 h-60 pt-28 px-10 overflow-x-auto">
            {regressReport.iterations.map((it) => {
              const maxMs = Math.max(
                ...regressReport.iterations.map((i) => Number(i.duration_ms)),
                100
              );
              const heightPct = Math.min(
                100,
                Math.max(10, (Number(it.duration_ms) / maxMs) * 100)
              );
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
                      ? isSelected
                        ? "bg-rh-primary"
                        : "bg-rh-primary/60 hover:bg-rh-primary"
                      : isSelected
                      ? "bg-rh-nogo"
                      : "bg-rh-nogo/70 hover:bg-rh-nogo"
                  }`}
                  style={{ height: `${heightPct}%` }}
                >
                  <div className="opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100 absolute bottom-full mb-2 left-1/2 -translate-x-1/2 p-2 bg-rh-raised border border-rh-line rounded-[6px] text-xs text-rh-text text-left whitespace-nowrap z-30 pointer-events-none tabular-nums shadow-lg">
                    <div>
                      Iteration #{it.iteration} ({it.status_code || "error"})
                    </div>
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
                    className={`flex items-center text-xs transition-colors ${
                      selected ? "bg-rh-raised" : "hover:bg-rh-raised"
                    }`}
                  >
                    <button
                      type="button"
                      onClick={() => setSelectedIteration(it)}
                      aria-pressed={selected}
                      className={`flex-1 min-w-0 grid grid-cols-[4rem_minmax(0,1fr)_4.5rem_4.5rem_4.5rem_4.5rem] items-center gap-3 px-3 py-2.5 text-left cursor-pointer ${FOCUS}`}
                    >
                      <span
                        className={`justify-self-start px-2 py-0.5 rounded-[6px] text-xs font-semibold tabular-nums ${
                          it.success ? "bg-rh-go/15 text-rh-go" : "bg-rh-nogo/15 text-rh-nogo"
                        }`}
                      >
                        {it.status_code || "ERR"}
                      </span>
                      <span className="min-w-0">
                        <span className="text-rh-text font-semibold block">
                          Iteration #{it.iteration}
                        </span>
                        <span className="text-rh-muted font-mono text-xs block truncate">
                          {it.session_id}
                        </span>
                      </span>
                      <span className="text-right text-rh-text tabular-nums">{it.dns_lookup_ms}ms</span>
                      <span className="text-right text-rh-text tabular-nums">{it.tcp_connect_ms}ms</span>
                      <span className="text-right text-rh-text tabular-nums">{it.ttfb_ms}ms</span>
                      <span className="text-right text-rh-text font-semibold tabular-nums">
                        {it.duration_ms}ms
                      </span>
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
  );
}
