"use client";

import { useMemo } from "react";
import {
  Link2,
  ShieldAlert,
  ShieldCheck,
  Clock,
  ArrowRight,
  User,
  KeyRound,
  AlertTriangle,
  Code,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import type { StatefulStep, StatefulStepExecution } from "@/types/agent";

export interface StatefulChainFlowProps {
  steps?: StatefulStep[] | null;
  chain?: StatefulStepExecution[] | null;
  className?: string;
  caseStatus?: string;
  violationCondition?: string;
}

interface MergedStep {
  step_number: number;
  actor: string;
  method: string;
  path: string;
  payload?: string;
  extract_vars?: string[];
  expected_status?: number;
  violation_condition?: string;
  // Execution data if available
  executed?: boolean;
  resolved_path?: string;
  status_code?: number;
  latency_ms?: number;
  extracted_values?: Record<string, string>;
  passed?: boolean;
}

function getActorBadge(actorName: string) {
  const norm = actorName.trim().toLowerCase();
  if (norm.includes("alice")) {
    return {
      name: "Alice",
      role: "Owner / Tenant A",
      badgeClass: "bg-emerald-950/80 text-emerald-300 border-emerald-600/70",
      dotClass: "bg-emerald-400",
      icon: User,
    };
  }
  if (norm.includes("bob")) {
    return {
      name: "Bob",
      role: "Attacker / Tenant B",
      badgeClass: "bg-amber-950/80 text-amber-300 border-amber-600/70",
      dotClass: "bg-amber-400",
      icon: ShieldAlert,
    };
  }
  if (norm.includes("admin")) {
    return {
      name: "Admin",
      role: "Privileged Root",
      badgeClass: "bg-purple-950/80 text-purple-300 border-purple-600/70",
      dotClass: "bg-purple-400",
      icon: KeyRound,
    };
  }
  if (norm.includes("anon")) {
    return {
      name: "Anon",
      role: "Unauthenticated",
      badgeClass: "bg-slate-900 text-slate-300 border-slate-700",
      dotClass: "bg-slate-400",
      icon: User,
    };
  }
  return {
    name: actorName,
    role: "Actor",
    badgeClass: "bg-cyan-950/80 text-cyan-300 border-cyan-600/70",
    dotClass: "bg-cyan-400",
    icon: User,
  };
}

function getMethodBadge(method: string) {
  const m = (method || "GET").toUpperCase();
  if (m === "POST") return "bg-indigo-950 text-indigo-300 border-indigo-700/60";
  if (m === "PUT" || m === "PATCH") return "bg-amber-950 text-amber-300 border-amber-700/60";
  if (m === "DELETE") return "bg-rose-950 text-rose-300 border-rose-700/60";
  return "bg-sky-950 text-sky-300 border-sky-700/60";
}

function getStatusCodeBadge(code?: number) {
  if (code == null) return "bg-slate-900 text-slate-500 border-slate-800";
  if (code >= 200 && code < 300) return "bg-emerald-950/80 text-emerald-300 border-emerald-700/60";
  if (code >= 300 && code < 400) return "bg-sky-950/80 text-sky-300 border-sky-700/60";
  if (code >= 400 && code < 500) return "bg-amber-950/80 text-amber-300 border-amber-700/60";
  return "bg-rose-950/80 text-rose-300 border-rose-700/60";
}

export function StatefulChainFlow({
  steps,
  chain,
  className = "",
  caseStatus,
  violationCondition,
}: StatefulChainFlowProps) {
  const mergedSteps: MergedStep[] = useMemo(() => {
    const map = new Map<number, MergedStep>();

    // 1. Seed with plan steps if available
    if (steps && steps.length > 0) {
      steps.forEach((s) => {
        map.set(s.step_number, {
          step_number: s.step_number,
          actor: s.actor,
          method: s.method,
          path: s.path,
          payload: s.payload,
          extract_vars: s.extract_vars,
          expected_status: s.expected_status,
          violation_condition: s.violation_condition,
        });
      });
    }

    // 2. Overlay with actual executed results
    if (chain && chain.length > 0) {
      chain.forEach((e) => {
        const existing = map.get(e.step_number) || {
          step_number: e.step_number,
          actor: e.actor,
          method: e.method,
          path: e.resolved_path,
        };

        map.set(e.step_number, {
          ...existing,
          actor: e.actor || existing.actor,
          method: e.method || existing.method,
          resolved_path: e.resolved_path,
          status_code: e.status_code,
          latency_ms: e.latency_ms,
          extracted_values: e.extracted_values,
          passed: e.passed,
          executed: true,
        });
      });
    }

    return Array.from(map.values()).sort((a, b) => a.step_number - b.step_number);
  }, [steps, chain]);

  if (mergedSteps.length === 0) {
    return null;
  }

  // Detect breach in the chain
  const breach = mergedSteps.find(
    (s) =>
      s.executed &&
      (s.passed === false ||
        (s.violation_condition && s.status_code != null && s.status_code >= 200 && s.status_code < 300 && s.actor.toLowerCase().includes("bob")))
  );

  const breachMessage =
    breach?.violation_condition ||
    violationCondition ||
    (breach ? `BOLA Breached: ${breach.actor} successfully accessed protected resource (HTTP ${breach.status_code})` : null);

  return (
    <div className={`p-4 rounded-xl border border-cyan-800/40 bg-[#070d18] flex flex-col gap-3.5 shadow-xl ${className}`}>
      {/* Chain Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[#16233a]">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-cyan-950 border border-cyan-700/60 text-cyan-300">
            <Link2 className="w-3.5 h-3.5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-cyan-200 tracking-wider uppercase font-mono">
                Stateful Scenario Chain Flow
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-300 border border-cyan-800 font-semibold">
                {mergedSteps.length} Step Multi-Actor Sequence
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              Cross-step variable extraction & cross-tenant authorization audit
            </span>
          </div>
        </div>

        {breach ? (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-950/80 text-rose-300 border border-rose-600 font-mono text-xs font-bold shadow-[0_0_12px_rgba(244,63,94,0.3)]">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
            <span>CRITICAL BREACH DETECTED</span>
          </span>
        ) : (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-600 font-mono text-xs font-bold">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>ISOLATION MAINTAINED</span>
          </span>
        )}
      </div>

      {/* Breach Alert Banner */}
      {breachMessage && (
        <div className="p-3 rounded-lg bg-rose-950/70 border border-rose-500/80 text-rose-200 text-xs font-mono shadow-[0_0_15px_rgba(244,63,94,0.25)] flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5 animate-pulse" />
          <div className="flex flex-col gap-0.5">
            <span className="font-bold text-rose-300 uppercase tracking-wide">
              Security Violation Alert:
            </span>
            <span className="text-rose-100 font-sans text-xs">
              {breachMessage.includes("BOLA") || breachMessage.includes("Breach")
                ? breachMessage
                : `BOLA Breached: ${breachMessage}`}
            </span>
          </div>
        </div>
      )}

      {/* Timeline Steps */}
      <div className="relative flex flex-col gap-3 pt-1">
        {mergedSteps.map((step, idx) => {
          const actor = getActorBadge(step.actor);
          const ActorIcon = actor.icon;
          const isLast = idx === mergedSteps.length - 1;
          const displayPath = step.resolved_path || step.path;

          return (
            <div key={step.step_number} className="relative flex items-start gap-3 group">
              {/* Vertical connector line */}
              {!isLast && (
                <div className="absolute left-4 top-8 bottom-[-16px] w-0.5 bg-gradient-to-b from-cyan-600/60 to-slate-700/40 group-hover:from-cyan-400 transition-colors" />
              )}

              {/* Step Number Circle */}
              <div
                className={`relative z-10 w-8 h-8 rounded-full flex items-center justify-center font-mono text-xs font-bold shrink-0 border shadow-md ${
                  step.executed
                    ? step.passed === false
                      ? "bg-rose-950 text-rose-300 border-rose-600 shadow-[0_0_8px_rgba(244,63,94,0.4)]"
                      : "bg-emerald-950 text-emerald-300 border-emerald-600"
                    : "bg-[#0b1323] text-cyan-300 border-cyan-700/60"
                }`}
              >
                {step.step_number}
              </div>

              {/* Step Card */}
              <div className="flex-1 rounded-lg border border-[#1b2b46] bg-[#091120] p-3 flex flex-col gap-2 hover:border-cyan-700/60 transition-colors">
                {/* Header Row */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Actor Badge */}
                    <span
                      className={`flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${actor.badgeClass}`}
                    >
                      <ActorIcon className="w-3 h-3" />
                      <span>{actor.name}</span>
                      <span className="text-[9px] font-normal opacity-75">({actor.role})</span>
                    </span>

                    {/* Method Badge */}
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${getMethodBadge(
                        step.method
                      )}`}
                    >
                      {step.method}
                    </span>

                    {/* Resolved Path */}
                    <span className="text-xs font-mono font-semibold text-slate-100 break-all">
                      {displayPath}
                    </span>
                  </div>

                  {/* Status & Latency Badges */}
                  <div className="flex items-center gap-2 font-mono text-xs">
                    {step.latency_ms != null && (
                      <span className="flex items-center gap-1 text-[10px] text-slate-400">
                        <Clock className="w-3 h-3 text-cyan-400" />
                        {step.latency_ms}ms
                      </span>
                    )}

                    {step.status_code != null ? (
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusCodeBadge(
                          step.status_code
                        )}`}
                      >
                        HTTP {step.status_code}
                      </span>
                    ) : step.expected_status != null ? (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-[#111c30] text-slate-400 border border-slate-700">
                        Expected: {step.expected_status}
                      </span>
                    ) : null}

                    {step.executed && (
                      <span title={step.passed ? "Step Passed" : "Step Failed"}>
                        {step.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-rose-400" />
                        )}
                      </span>
                    )}
                  </div>
                </div>

                {/* Extracted Variables Pills */}
                {step.extracted_values && Object.keys(step.extracted_values).length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[10px] font-mono text-cyan-400 font-semibold uppercase">
                      Extracted:
                    </span>
                    {Object.entries(step.extracted_values).map(([k, v]) => (
                      <span
                        key={k}
                        className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-200 border border-cyan-600/60 font-mono text-[10px] flex items-center gap-1 shadow-sm"
                      >
                        <span className="text-cyan-400 font-bold">{`{{${k}}}`}</span>
                        <ArrowRight className="w-2.5 h-2.5 text-cyan-500" />
                        <span className="text-emerald-300 font-semibold">&quot;{v}&quot;</span>
                      </span>
                    ))}
                  </div>
                )}

                {/* Planned extraction variable hints if not yet executed */}
                {!step.extracted_values && step.extract_vars && step.extract_vars.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[10px] font-mono text-slate-400 font-semibold uppercase">
                      Extracts Variables:
                    </span>
                    {step.extract_vars.map((v) => (
                      <span
                        key={v}
                        className="px-2 py-0.5 rounded bg-[#101c30] text-cyan-300 border border-cyan-800 font-mono text-[10px]"
                      >
                        {`{{${v}}}`}
                      </span>
                    ))}
                  </div>
                )}

                {/* Violation Condition Warning */}
                {step.violation_condition && (
                  <div
                    className={`mt-1 p-2 rounded text-[11px] font-mono flex items-center gap-2 border ${
                      step.executed && step.passed === false
                        ? "bg-rose-950/50 border-rose-600/70 text-rose-300"
                        : "bg-[#0b1626] border-slate-700/70 text-slate-300"
                    }`}
                  >
                    <AlertTriangle className={`w-3.5 h-3.5 shrink-0 ${step.executed && step.passed === false ? "text-rose-400" : "text-amber-400"}`} />
                    <span>
                      <strong className="text-slate-400">Violation Check: </strong>
                      {step.violation_condition}
                    </span>
                  </div>
                )}

                {/* Payload snippet if available */}
                {step.payload && (
                  <div className="mt-1">
                    <span className="text-[10px] font-mono text-slate-500 block mb-0.5">Payload:</span>
                    <pre className="p-1.5 rounded bg-black/60 border border-[#16233a] font-mono text-[10px] text-slate-300 overflow-x-auto max-h-16">
                      {step.payload}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
