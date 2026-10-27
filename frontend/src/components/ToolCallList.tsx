"use client";

import { Check, Loader2, Workflow, Compass, BrainCircuit, Terminal, Flame, ShieldCheck } from "lucide-react";

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

export function ToolCallList({ stages }: ToolCallListProps) {
  return (
    <div className="bg-[#0b101a] border border-[#1a2436] rounded-xl p-4 shadow-xl flex flex-col gap-3">
      <div className="flex items-center justify-between pb-2 border-b border-[#162033]">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <Workflow className="w-3 h-3" />
          </div>
          <span className="text-xs font-bold tracking-wider uppercase text-slate-200">
            Live Agent Tool Pipeline
          </span>
        </div>
        <span className="text-[10px] font-mono text-slate-500 font-semibold tracking-wider uppercase">
          Observable Trace
        </span>
      </div>

      <div className="flex flex-col gap-2">
        {stages.map((stage) => {
          const isRunning = stage.status === "running";
          const isSucceeded = stage.status === "succeeded";
          const isFailed = stage.status === "failed";

          return (
            <div
              key={stage.id}
              className={`flex items-center justify-between p-2.5 rounded-lg border text-xs transition-all ${
                isRunning
                  ? "bg-cyan-950/30 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)]"
                  : isSucceeded
                  ? "bg-[#07090e]/80 border-[#162033]"
                  : isFailed
                  ? "bg-rose-950/30 border-rose-500/50"
                  : "bg-[#07090e]/40 border-[#121927] opacity-60"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <div
                  className={`w-7 h-7 rounded-md flex items-center justify-center text-xs ${
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
                  <span className={`font-semibold tracking-tight ${isRunning ? "text-cyan-300" : isSucceeded ? "text-slate-200" : "text-slate-400"}`}>
                    {stage.label}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">{stage.subtext}</span>
                </div>
              </div>

              <div className="flex items-center gap-1.5 font-mono text-[11px]">
                {isRunning && (
                  <span className="flex items-center gap-1 text-cyan-400 font-semibold">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    Executing
                  </span>
                )}
                {isSucceeded && (
                  <span className="flex items-center gap-1 text-emerald-400 font-semibold">
                    <Check className="w-3.5 h-3.5" />
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
    </div>
  );
}
