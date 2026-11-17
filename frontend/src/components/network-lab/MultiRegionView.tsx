import React from "react";
import { Globe, RotateCw, Play, Compass, BrainCircuit } from "lucide-react";
import type { MultiRegionReport } from "@/types/network";
import { BTN_PRIMARY, KPI_CARD, PANEL, CHIP, sentence } from "./types";

export interface MultiRegionViewProps {
  target: string;
  multiRegionReport: MultiRegionReport | null;
  isMultiRegionRunning: boolean;
  handleRunMultiRegion: () => void;
}

export function MultiRegionView({
  target,
  multiRegionReport,
  isMultiRegionRunning,
  handleRunMultiRegion,
}: MultiRegionViewProps) {
  return (
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
            <span
              className={`text-xl font-semibold ${
                !multiRegionReport
                  ? "text-rh-muted"
                  : multiRegionReport.cdn_edge_active
                  ? "text-rh-go"
                  : "text-rh-cond"
              }`}
            >
              {multiRegionReport
                ? multiRegionReport.cdn_edge_active
                  ? "Active (edge POPs)"
                  : "Direct origin"
                : "--"}
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
            <span
              className={`text-2xl font-semibold tabular-nums ${
                !multiRegionReport
                  ? "text-rh-muted"
                  : multiRegionReport.regional_disparity_ms <= 100
                  ? "text-rh-go"
                  : multiRegionReport.regional_disparity_ms <= 200
                  ? "text-rh-cond"
                  : "text-rh-nogo"
              }`}
            >
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
            <div key={reg.region_id} className={`${PANEL} space-y-3`}>
              <div className="flex items-center justify-between gap-2 border-b border-rh-line pb-2.5">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-xl" aria-hidden="true">
                    {reg.flag}
                  </span>
                  <div className="min-w-0">
                    <h4 className="text-sm font-semibold text-rh-text">{reg.region_name}</h4>
                    <span className="text-xs text-rh-muted">{reg.location}</span>
                  </div>
                </div>
                <span
                  className={`${CHIP} shrink-0 ${
                    reg.status === "OPTIMAL"
                      ? "bg-rh-go/15 text-rh-go"
                      : reg.status === "ELEVATED"
                      ? "bg-rh-cond/15 text-rh-cond"
                      : "bg-rh-nogo/15 text-rh-nogo"
                  }`}
                >
                  {sentence(reg.status)}
                </span>
              </div>

              {/* Timing metrics */}
              <div className="grid grid-cols-4 gap-2 text-center">
                <div className="p-2 rounded-[6px] bg-rh-bg">
                  <span className="text-xs text-rh-muted block">DNS</span>
                  <span className="text-xs font-semibold text-rh-text tabular-nums">
                    {reg.dns_time_ms}ms
                  </span>
                </div>
                <div className="p-2 rounded-[6px] bg-rh-bg">
                  <span className="text-xs text-rh-muted block">TCP SYN</span>
                  <span className="text-xs font-semibold text-rh-text tabular-nums">
                    {reg.tcp_connect_ms}ms
                  </span>
                </div>
                <div className="p-2 rounded-[6px] bg-rh-bg">
                  <span className="text-xs text-rh-muted block">TTFB</span>
                  <span className="text-xs font-semibold text-rh-text tabular-nums">
                    {reg.ttfb_ms}ms
                  </span>
                </div>
                <div className="p-2 rounded-[6px] bg-rh-bg">
                  <span className="text-xs text-rh-muted block">Total RTT</span>
                  <span className="text-xs font-semibold text-rh-text tabular-nums">
                    {reg.total_time_ms}ms
                  </span>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-rh-muted pt-1">
                <span>
                  Edge POP: <span className="text-rh-text font-mono">{reg.edge_pop}</span>
                </span>
                <span>
                  Jitter: <span className="text-rh-text tabular-nums">{reg.jitter_ms}ms</span>
                </span>
                <span>
                  Loss: <span className="text-rh-text tabular-nums">{reg.packet_loss_pct}%</span>
                </span>
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
            This probes the target URL from 4 geographic regions (US-East, EU-West, APAC-Mumbai,
            APAC-Singapore) to catch geo-DNS propagation issues and CDN edge cache misses.
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
              <span className="text-xs font-semibold text-rh-muted block">
                Recommended optimizations
              </span>
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
  );
}
