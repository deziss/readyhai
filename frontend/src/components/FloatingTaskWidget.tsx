"use client";

import { useEffect, useState } from "react";
import {
  Activity,
  Bot,
  CheckCircle2,
  ChevronRight,
  ExternalLink,
  RotateCw,
  X,
  Zap,
} from "lucide-react";
import type { SaaSViewMode } from "./Header";

export interface ActiveTaskItem {
  id: string;
  title: string;
  target: string;
  view: SaaSViewMode;
  status: "running" | "completed";
  detail?: string;
  startTime: number;
}

interface FloatingTaskWidgetProps {
  tasks: ActiveTaskItem[];
  currentView: SaaSViewMode;
  onJumpToView: (view: SaaSViewMode) => void;
  onDismiss: (id: string) => void;
}

export function FloatingTaskWidget({
  tasks,
  currentView,
  onJumpToView,
  onDismiss,
}: FloatingTaskWidgetProps) {
  // Timer for elapsed seconds
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (tasks.length === 0) return;
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, [tasks.length]);

  if (tasks.length === 0) return null;

  return (
    <aside
      aria-label="Active background tasks"
      className="fixed bottom-6 right-6 z-50 flex flex-col gap-2.5 max-w-sm w-full pointer-events-auto"
    >
      {tasks.map((task) => {
        const isCurrentView = currentView === task.view;
        const elapsedSec = Math.floor((now - task.startTime) / 1000);
        const isRunning = task.status === "running";

        return (
          <div
            key={task.id}
            id={`floating-task-${task.id}`}
            className={`p-3.5 rounded-xl border backdrop-blur-xl transition-all shadow-[0_12px_36px_rgba(0,0,0,0.65)] ${
              isRunning
                ? "bg-[#0b1222]/95 border-cyan-500/50 shadow-[0_0_20px_rgba(6,182,212,0.15)]"
                : "bg-[#0a1816]/95 border-emerald-500/50 shadow-[0_0_20px_rgba(16,185,129,0.15)]"
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5 min-w-0">
                <div
                  className={`p-2 rounded-lg border shrink-0 ${
                    isRunning
                      ? "bg-cyan-950/80 border-cyan-500/40 text-cyan-400"
                      : "bg-emerald-950/80 border-emerald-500/40 text-emerald-400"
                  }`}
                >
                  {isRunning ? (
                    <RotateCw className="w-4 h-4 animate-spin text-cyan-400" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  )}
                </div>

                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.2 rounded font-bold uppercase ${
                        isRunning
                          ? "bg-cyan-900/60 text-cyan-300 border border-cyan-700/50"
                          : "bg-emerald-900/60 text-emerald-300 border border-emerald-700/50"
                      }`}
                    >
                      {isRunning ? "Running in BG" : "Completed"}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      {elapsedSec}s
                    </span>
                  </div>

                  <h3 className="text-xs font-bold text-white truncate mt-0.5">
                    {task.title}
                  </h3>
                </div>
              </div>

              <button
                onClick={() => onDismiss(task.id)}
                className="text-slate-500 hover:text-slate-300 p-1 rounded hover:bg-slate-800 transition-colors cursor-pointer"
                title="Dismiss notification"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Target and Details */}
            <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
              <div className="min-w-0 pr-2">
                <div className="text-[11px] text-slate-300 truncate font-semibold">
                  {task.detail || task.target}
                </div>
                <div className="text-[10px] text-slate-500 truncate">
                  Target: {task.target}
                </div>
              </div>

              {!isCurrentView ? (
                <button
                  id={`btn-jump-to-${task.view}`}
                  onClick={() => onJumpToView(task.view)}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900/80 border border-cyan-600/50 text-cyan-300 text-[11px] font-bold shrink-0 transition-all cursor-pointer shadow-[0_0_8px_rgba(6,182,212,0.2)]"
                >
                  <span>Return</span>
                  <ChevronRight className="w-3 h-3" />
                </button>
              ) : (
                <span className="text-[10px] text-cyan-400/80 font-bold px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/30">
                  Viewing
                </span>
              )}
            </div>
          </div>
        );
      })}
    </aside>
  );
}
