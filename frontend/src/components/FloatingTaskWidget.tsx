"use client";

import { useEffect, useRef, useState } from "react";
import {
  Ban,
  CheckCircle2,
  XCircle,
  ChevronRight,
  RotateCw,
  X,
} from "lucide-react";
import type { SaaSViewMode } from "./Header";

export interface ActiveTaskItem {
  /** Task type (e.g. "agent_swarm"). Relaunching a task replaces the previous one of the same type. */
  id: string;
  /** Unique per launch. Timers and dismissals are keyed by this, never by `id`. */
  instanceId: string;
  title: string;
  target: string;
  view: SaaSViewMode;
  status: "running" | "completed" | "failed" | "cancelled";
  detail?: string;
  startTime: number;
}

interface FloatingTaskWidgetProps {
  tasks: ActiveTaskItem[];
  currentView: SaaSViewMode;
  onJumpToView: (view: SaaSViewMode) => void;
  /** Called with the task's `instanceId`. */
  onDismiss: (instanceId: string) => void;
}

const AUTO_DISMISS_MS = 6000;

let taskInstanceSeq = 0;

/** A fresh id for one launch of a task. */
export function newTaskInstanceId(): string {
  taskInstanceSeq += 1;
  return `task-${Date.now().toString(36)}-${taskInstanceSeq}`;
}

export function FloatingTaskWidget({
  tasks,
  currentView,
  onJumpToView,
  onDismiss,
}: FloatingTaskWidgetProps) {
  // Timer for elapsed seconds
  const [now, setNow] = useState(() => Date.now());

  // Auto-dismiss finished tasks after 6 seconds. Timers are keyed by task instance and are cleared
  // as soon as that instance is gone (dismissed, replaced by a relaunch) or the widget unmounts, so
  // an old timer can never remove a newer task of the same type.
  const dismissTimers = useRef<Map<string, number>>(new Map());
  const onDismissRef = useRef(onDismiss);
  useEffect(() => {
    onDismissRef.current = onDismiss;
  }, [onDismiss]);

  useEffect(() => {
    const timers = dismissTimers.current;
    const finished = new Set(
      tasks.filter((t) => t.status !== "running").map((t) => t.instanceId)
    );
    // Drop timers for instances that are no longer on screen or no longer finished.
    for (const [instanceId, handle] of timers) {
      if (!finished.has(instanceId)) {
        window.clearTimeout(handle);
        timers.delete(instanceId);
      }
    }
    for (const instanceId of finished) {
      if (timers.has(instanceId)) continue;
      const handle = window.setTimeout(() => {
        timers.delete(instanceId);
        onDismissRef.current(instanceId);
      }, AUTO_DISMISS_MS);
      timers.set(instanceId, handle);
    }
  }, [tasks]);

  useEffect(() => {
    const timers = dismissTimers.current;
    return () => {
      timers.forEach((handle) => window.clearTimeout(handle));
      timers.clear();
    };
  }, []);

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
        const isFailed = task.status === "failed";
        const isCancelled = task.status === "cancelled";
        const tone = isRunning
          ? { chip: "bg-rh-info/15 text-rh-info", icon: "text-rh-info", edge: "border-l-rh-info" }
          : isFailed
          ? { chip: "bg-rh-nogo/15 text-rh-nogo", icon: "text-rh-nogo", edge: "border-l-rh-nogo" }
          : isCancelled
          ? { chip: "bg-rh-cond/15 text-rh-cond", icon: "text-rh-cond", edge: "border-l-rh-cond" }
          : { chip: "bg-rh-go/15 text-rh-go", icon: "text-rh-go", edge: "border-l-rh-go" };

        return (
          <div
            key={task.instanceId}
            id={`floating-task-${task.id}`}
            role="status"
            className={`p-3.5 rounded-[10px] border border-rh-line border-l-4 bg-rh-surface shadow-lg ${tone.edge}`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className={`p-2 rounded-[6px] shrink-0 ${tone.chip}`} aria-hidden="true">
                  {isRunning ? (
                    <RotateCw className="w-4 h-4 animate-spin" />
                  ) : isFailed ? (
                    <XCircle className="w-4 h-4" />
                  ) : isCancelled ? (
                    <Ban className="w-4 h-4" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4" />
                  )}
                </div>

                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded-[6px] font-semibold ${tone.chip}`}>
                      {isRunning ? "Running in background" : isFailed ? "Failed" : isCancelled ? "Cancelled" : "Completed"}
                    </span>
                    <span className="text-xs text-rh-muted tabular-nums">
                      {isRunning ? `${elapsedSec}s` : "Closing soon"}
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-rh-text truncate mt-1">{task.title}</h3>
                </div>
              </div>

              <button
                type="button"
                onClick={() => onDismiss(task.instanceId)}
                className="text-rh-muted hover:text-rh-text p-1.5 rounded-[6px] hover:bg-rh-raised transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-rh-primary"
                title="Dismiss notification"
                aria-label={`Dismiss ${task.title}`}
              >
                <X className="w-4 h-4" aria-hidden="true" />
              </button>
            </div>

            <div className="mt-2.5 pt-2.5 border-t border-rh-line flex items-center justify-between gap-2 text-xs">
              <div className="min-w-0">
                <div className="text-rh-text truncate font-medium">{task.detail || task.target}</div>
                <div className="text-rh-muted truncate">Target: {task.target}</div>
              </div>

              {!isCurrentView ? (
                <button
                  type="button"
                  id={`btn-jump-to-${task.view}`}
                  onClick={() => onJumpToView(task.view)}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-[6px] bg-rh-primary/15 hover:bg-rh-primary/25 text-rh-primary text-xs font-semibold shrink-0 transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-rh-primary"
                >
                  <span>Return</span>
                  <ChevronRight className="w-3.5 h-3.5" aria-hidden="true" />
                </button>
              ) : (
                <span className="text-xs text-rh-muted px-2 py-1 rounded-[6px] bg-rh-raised shrink-0">Viewing</span>
              )}
            </div>
          </div>
        );
      })}
    </aside>
  );
}
