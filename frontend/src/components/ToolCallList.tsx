"use client";

import { Check, Loader2, Workflow, Pause } from "lucide-react";

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

export function ToolCallList({ stages }: ToolCallListProps) {
  return (
    <div className="bg-[#0e1526] border border-slate-800/80 rounded-xl p-5 shadow-xl flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-cyan-400 font-bold text-xs tracking-wide uppercase flex items-center gap-1.5">
          <Workflow className="w-4 h-4 text-cyan-400" />
          Live Agent Tool Pipeline
        </span>
        <span className="text-[10px] font-mono text-slate-400">
          OBSERVABLE TRACE
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
                  ? "bg-cyan-950/20 border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.15)]"
                  : isSucceeded
                  ? "bg-slate-900/60 border-slate-800"
                  : isFailed
                  ? "bg-rose-950/20 border-rose-500/40"
                  : "bg-slate-900/30 border-slate-850 opacity-60"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <span
                  className={`w-6 h-6 rounded flex items-center justify-center font-mono text-[10px] font-bold ${
                    isRunning
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                      : isSucceeded
                      ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                      : isFailed
                      ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                      : "bg-slate-800 text-slate-400"
                  }`}
                >
                  {stage.id.substring(0, 3).toUpperCase()}
                </span>
                <div className="flex flex-col">
                  <span className={`font-semibold ${isRunning ? "text-cyan-300" : isSucceeded ? "text-slate-200" : "text-slate-400"}`}>
                    {stage.label}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">{stage.subtext}</span>
                </div>
              </div>

              <div className="flex items-center gap-1.5 font-mono text-[11px]">
                {isRunning && (
                  <span className="flex items-center gap-1 text-cyan-400">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    Running
                  </span>
                )}
                {isSucceeded && (
                  <span className="flex items-center gap-1 text-emerald-400">
                    <Check className="w-3.5 h-3.5" />
                    Complete
                  </span>
                )}
                {isFailed && <span className="text-rose-400">Failed</span>}
                {stage.status === "standby" && <span className="text-slate-600">Standby</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
