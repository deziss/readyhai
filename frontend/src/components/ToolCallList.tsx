"use client";

import { useState } from "react";
import {
  Check,
  Loader2,
  Workflow,
  Compass,
  BrainCircuit,
  Terminal,
  Flame,
  ShieldCheck,
  X,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

export type PipelineStage = "discovery" | "planner" | "explorer" | "triager" | "gate";

export interface StageState {
  id: PipelineStage;
  label: string;
  subtext: string;
  status: "standby" | "running" | "succeeded" | "failed";
}

interface ToolCallListProps {
  stages: StageState[];
  currentRunningIndex: number;
}

const STAGE_ICONS: Record<PipelineStage, React.ReactNode> = {
  discovery: <Compass className="w-3.5 h-3.5" />,
  planner: <BrainCircuit className="w-3.5 h-3.5" />,
  explorer: <Terminal className="w-3.5 h-3.5" />,
  triager: <Flame className="w-3.5 h-3.5" />,
  gate: <ShieldCheck className="w-3.5 h-3.5" />,
};

const STAGE_SHORT_LABELS: Record<PipelineStage, string> = {
  discovery: "Recon",
  planner: "Discovery",
  explorer: "Planner",
  triager: "Triage",
  gate: "Gate",
};

export function ToolCallList({ stages }: ToolCallListProps) {
  const [hoveredStageId, setHoveredStageId] = useState<PipelineStage | null>(null);
  const [pinnedStageId, setPinnedStageId] = useState<PipelineStage | null>(null);
  const [isExpanded, setIsExpanded] = useState(false);

  // Active tooltip target: pinned has priority, then hovered
  const activeTooltipId = pinnedStageId || hoveredStageId;
  const activeTooltipStage = stages.find((s) => s.id === activeTooltipId);

  // Compute overall status summary
  const runningStage = stages.find((s) => s.status === "running");
  const failedStage = stages.find((s) => s.status === "failed");
  const allSucceeded = stages.every((s) => s.status === "succeeded");

  return (
    <div className="bg-[#0b101a] border border-[#1a2436] rounded-xl p-3 shadow-xl flex flex-col gap-2 relative">
      {/* Header Bar */}
      <div className="flex items-center justify-between pb-1.5 border-b border-[#141f33]/80">
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-5 h-5 rounded bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <Workflow className="w-3 h-3" />
          </div>
          <span className="text-xs font-bold tracking-wider uppercase text-slate-200 truncate">
            Agent Pipeline
          </span>
          <span className="text-[10px] font-mono text-slate-500">
            {runningStage ? (
              <span className="text-cyan-300 font-semibold flex items-center gap-1">
                <Loader2 className="w-2.5 h-2.5 animate-spin" />
                {runningStage.label}...
              </span>
            ) : failedStage ? (
              <span className="text-rose-400 font-semibold">{failedStage.label} Failed</span>
            ) : allSucceeded ? (
              <span className="text-emerald-400 font-semibold">4/4 Complete</span>
            ) : (
              <span>Standby</span>
            )}
          </span>
        </div>

        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-400 hover:text-slate-200 hover:bg-[#121c2d] transition-colors cursor-pointer"
          title={isExpanded ? "Collapse to compact view" : "Expand all stage details"}
        >
          <span>{isExpanded ? "Compact" : "Details"}</span>
          {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </button>
      </div>

      {/* Compact Horizontal Stepper Track */}
      <div className="grid grid-cols-4 gap-1.5 pt-0.5">
        {stages.map((stage) => {
          const isRunning = stage.status === "running";
          const isSucceeded = stage.status === "succeeded";
          const isFailed = stage.status === "failed";
          const isPinned = pinnedStageId === stage.id;

          return (
            <button
              key={stage.id}
              type="button"
              onMouseEnter={() => setHoveredStageId(stage.id)}
              onMouseLeave={() => setHoveredStageId(null)}
              onClick={() => setPinnedStageId(isPinned ? null : stage.id)}
              className={`group relative flex items-center justify-center gap-1.5 py-1.5 px-2 rounded-lg border text-xs font-mono transition-all cursor-pointer ${
                isRunning
                  ? "bg-cyan-950/70 border-cyan-400 text-cyan-200 shadow-[0_0_10px_rgba(6,182,212,0.3)] animate-pulse"
                  : isSucceeded
                  ? "bg-emerald-950/40 border-emerald-500/50 text-emerald-300 hover:border-emerald-400"
                  : isFailed
                  ? "bg-rose-950/50 border-rose-500/70 text-rose-300 hover:border-rose-400"
                  : "bg-[#07090e]/60 border-[#162238] text-slate-400 hover:text-slate-200 hover:border-slate-700"
              } ${isPinned ? "ring-1 ring-cyan-400" : ""}`}
            >
              <span className="shrink-0">
                {isRunning ? (
                  <Loader2 className="w-3 h-3 animate-spin text-cyan-300" />
                ) : isSucceeded ? (
                  <Check className="w-3 h-3 text-emerald-400" />
                ) : (
                  STAGE_ICONS[stage.id]
                )}
              </span>
              <span className="font-semibold truncate text-[11px]">
                {STAGE_SHORT_LABELS[stage.id] || stage.label}
              </span>
            </button>
          );
        })}
      </div>

      {/* Floating Interactive Tooltip / Status Popover (shown on Hover or Click) */}
      {activeTooltipStage && !isExpanded && (
        <div className="mt-1 p-2.5 rounded-lg bg-[#070b14] border border-cyan-500/40 shadow-[0_4px_20px_rgba(0,0,0,0.5)] flex flex-col gap-1 text-xs animate-in fade-in zoom-in-95 duration-100">
          <div className="flex items-center justify-between pb-1 border-b border-[#141f33]">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400">{STAGE_ICONS[activeTooltipStage.id]}</span>
              <span className="font-bold text-slate-200 font-mono">
                {activeTooltipStage.label}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${
                  activeTooltipStage.status === "running"
                    ? "bg-cyan-900/60 text-cyan-300 border border-cyan-500/50 animate-pulse"
                    : activeTooltipStage.status === "succeeded"
                    ? "bg-emerald-900/60 text-emerald-300 border border-emerald-500/50"
                    : activeTooltipStage.status === "failed"
                    ? "bg-rose-900/60 text-rose-300 border border-rose-500/50"
                    : "bg-slate-800 text-slate-400 border border-slate-700"
                }`}
              >
                {activeTooltipStage.status}
              </span>
              {pinnedStageId && (
                <button
                  type="button"
                  onClick={() => setPinnedStageId(null)}
                  className="text-slate-500 hover:text-slate-300 p-0.5 cursor-pointer"
                  title="Close pinned view"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
          <p className="text-[11px] text-slate-300 font-sans leading-relaxed">
            {activeTooltipStage.subtext}
          </p>
          <div className="flex items-center justify-between text-[9px] font-mono text-slate-500 pt-0.5">
            <span>Observable Trace Stage</span>
            <span>{pinnedStageId ? "Click again or X to unpin" : "Click to pin tooltip"}</span>
          </div>
        </div>
      )}

      {/* Expanded View (optional when user toggles Details) */}
      {isExpanded && (
        <div className="flex flex-col gap-1.5 pt-1">
          {stages.map((stage) => {
            const isRunning = stage.status === "running";
            const isSucceeded = stage.status === "succeeded";
            const isFailed = stage.status === "failed";

            return (
              <div
                key={stage.id}
                className={`flex items-center justify-between p-2 rounded-lg border text-xs transition-all ${
                  isRunning
                    ? "bg-cyan-950/30 border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.15)]"
                    : isSucceeded
                    ? "bg-[#07090e]/80 border-[#162033]"
                    : isFailed
                    ? "bg-rose-950/30 border-rose-500/50"
                    : "bg-[#07090e]/40 border-[#121927] opacity-60"
                }`}
              >
                <div className="flex items-center gap-2">
                  <div
                    className={`w-6 h-6 rounded flex items-center justify-center text-xs ${
                      isRunning
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/50"
                        : isSucceeded
                        ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/50"
                        : isFailed
                        ? "bg-rose-500/20 text-rose-300 border border-rose-500/50"
                        : "bg-[#111827] text-slate-500 border border-[#1a2436]"
                    }`}
                  >
                    {STAGE_ICONS[stage.id]}
                  </div>
                  <div className="flex flex-col">
                    <span className={`font-semibold tracking-tight text-[11px] ${isRunning ? "text-cyan-300" : isSucceeded ? "text-slate-200" : "text-slate-400"}`}>
                      {stage.label}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">{stage.subtext}</span>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 font-mono text-[10px]">
                  {isRunning && (
                    <span className="flex items-center gap-1 text-cyan-400 font-semibold">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Executing
                    </span>
                  )}
                  {isSucceeded && (
                    <span className="flex items-center gap-1 text-emerald-400 font-semibold">
                      <Check className="w-3 h-3" />
                      Complete
                    </span>
                  )}
                  {isFailed && <span className="text-rose-400 font-semibold">Failed</span>}
                  {stage.status === "standby" && <span className="text-slate-600">Standby</span>}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
