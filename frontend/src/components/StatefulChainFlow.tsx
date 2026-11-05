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
  AlertCircle,
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
  violation_triggered?: boolean;
  error_detail?: string;
}

function getActorBadge(actorName: string) {
  const norm = actorName.trim().toLowerCase();
  if (norm.includes("alice")) {
    return { name: "Alice", role: "Owner / Tenant A", badgeClass: "bg-rh-go/15 text-rh-go", icon: User };
  }
  if (norm.includes("bob")) {
    return { name: "Bob", role: "Attacker / Tenant B", badgeClass: "bg-rh-cond/15 text-rh-cond", icon: ShieldAlert };
  }
  if (norm.includes("admin")) {
    return { name: "Admin", role: "Privileged root", badgeClass: "bg-rh-info/15 text-rh-info", icon: KeyRound };
  }
  if (norm.includes("anon")) {
    return { name: "Anon", role: "Unauthenticated", badgeClass: "bg-rh-raised text-rh-muted", icon: User };
  }
  return { name: actorName, role: "Actor", badgeClass: "bg-rh-raised text-rh-text", icon: User };
}

function getMethodBadge(method: string) {
  const m = (method || "GET").toUpperCase();
  if (m === "POST") return "bg-rh-info/15 text-rh-info";
  if (m === "PUT" || m === "PATCH") return "bg-rh-cond/15 text-rh-cond";
  if (m === "DELETE") return "bg-rh-nogo/15 text-rh-nogo";
  return "bg-rh-raised text-rh-text";
}

function getStatusCodeBadge(code?: number) {
  if (code == null) return "bg-rh-raised text-rh-muted";
  if (code >= 200 && code < 300) return "bg-rh-go/15 text-rh-go";
  if (code >= 300 && code < 400) return "bg-rh-info/15 text-rh-info";
  if (code >= 400 && code < 500) return "bg-rh-cond/15 text-rh-cond";
  return "bg-rh-nogo/15 text-rh-nogo";
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
          violation_triggered: e.violation_triggered,
          error_detail: e.error_detail,
          executed: true,
        });
      });
    }

    return Array.from(map.values()).sort((a, b) => a.step_number - b.step_number);
  }, [steps, chain]);

  if (mergedSteps.length === 0) {
    return null;
  }

  // Detect genuine security breach in the chain
  // A breach occurs ONLY when a security violation condition triggered OR an unauthorized actor (e.g. Bob) succeeded with 2xx
  const breach = mergedSteps.find(
    (s) =>
      s.executed &&
      (s.violation_triggered === true ||
        (s.violation_condition &&
          s.status_code != null &&
          s.status_code >= 200 &&
          s.status_code < 300 &&
          !s.actor.toLowerCase().includes("alice") &&
          !s.actor.toLowerCase().includes("owner")))
  );

  // Setup failure: Step 1 (or resource setup) could not be established (e.g. 401 Unauthorized / missing creds / 404)
  const setupFailedStep = mergedSteps.find(
    (s) =>
      s.executed &&
      s.passed === false &&
      !s.violation_triggered &&
      (s.step_number === 1 || !s.violation_condition)
  );

  const breachMessage =
    breach?.error_detail ||
    breach?.violation_condition ||
    violationCondition ||
    (breach ? `BOLA Breached: ${breach.actor} successfully accessed protected resource (HTTP ${breach.status_code})` : null);

  const setupMessage =
    setupFailedStep?.error_detail ||
    (setupFailedStep
      ? `Prerequisite setup step ${setupFailedStep.step_number} not met: ${setupFailedStep.actor} received HTTP ${setupFailedStep.status_code} (${
          setupFailedStep.status_code === 401
            ? "Missing or invalid bearer credentials"
            : setupFailedStep.status_code === 403
            ? "Access forbidden"
            : setupFailedStep.status_code === 404
            ? "Endpoint not found"
            : "Setup rejected"
        }). Scenario could not provision initial test state.`
      : null);

  return (
    <div className={`p-4 rounded-[10px] border border-rh-line bg-rh-bg flex flex-col gap-3.5 ${className}`}>
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-rh-line">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-[6px] bg-rh-primary/15 text-rh-primary" aria-hidden="true">
            <Link2 className="w-4 h-4" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-rh-text">Stateful scenario chain</span>
              <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted font-medium tabular-nums">
                {mergedSteps.length}-step multi-actor sequence
              </span>
            </div>
            <span className="text-xs text-rh-muted">
              Variables extracted between steps, used to audit cross-tenant authorization
            </span>
          </div>
        </div>

        {breach ? (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-[6px] bg-rh-nogo/15 text-rh-nogo text-xs font-semibold">
            <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Critical breach detected</span>
          </span>
        ) : setupFailedStep ? (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-[6px] bg-rh-cond/15 text-rh-cond text-xs font-semibold">
            <AlertCircle className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Prerequisite setup not met</span>
          </span>
        ) : (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-[6px] bg-rh-go/15 text-rh-go text-xs font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Isolation maintained</span>
          </span>
        )}
      </div>

      {breach && breachMessage && (
        <div role="alert" className="p-3 rounded-[6px] bg-rh-nogo/15 text-xs flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-rh-nogo shrink-0 mt-0.5" aria-hidden="true" />
          <div className="flex flex-col gap-0.5">
            <span className="font-semibold text-rh-nogo">Security violation</span>
            <span className="text-rh-text text-xs">{breachMessage}</span>
          </div>
        </div>
      )}

      {!breach && setupFailedStep && setupMessage && (
        <div className="p-3 rounded-[6px] bg-rh-cond/15 text-xs flex items-start gap-2.5">
          <AlertCircle className="w-4 h-4 text-rh-cond shrink-0 mt-0.5" aria-hidden="true" />
          <div className="flex flex-col gap-0.5">
            <span className="font-semibold text-rh-cond">Prerequisite setup notice</span>
            <span className="text-rh-text text-xs">{setupMessage}</span>
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
            <div key={step.step_number} className="relative flex items-start gap-3">
              {/* Vertical connector line */}
              {!isLast && (
                <div className="absolute left-4 top-8 bottom-[-16px] w-0.5 bg-rh-line" aria-hidden="true" />
              )}

              {/* Step Number Circle */}
              <div
                className={`relative z-10 w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold shrink-0 tabular-nums ${
                  step.executed
                    ? step.passed === false
                      ? step.violation_triggered
                        ? "bg-rh-nogo/15 text-rh-nogo"
                        : "bg-rh-cond/15 text-rh-cond"
                      : "bg-rh-go/15 text-rh-go"
                    : "bg-rh-raised text-rh-muted"
                }`}
              >
                {step.step_number}
              </div>

              {/* Step Card */}
              <div className="flex-1 min-w-0 rounded-[10px] border border-rh-line bg-rh-surface p-3 flex flex-col gap-2">
                {/* Header Row */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Actor Badge */}
                    <span
                      className={`flex items-center gap-1.5 px-2 py-0.5 rounded-[6px] text-xs font-semibold ${actor.badgeClass}`}
                    >
                      <ActorIcon className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>{actor.name}</span>
                      <span className="text-xs font-normal">({actor.role})</span>
                    </span>

                    {/* Method Badge */}
                    <span
                      className={`px-1.5 py-0.5 rounded-[6px] text-xs font-mono font-semibold ${getMethodBadge(
                        step.method
                      )}`}
                    >
                      {step.method}
                    </span>

                    {/* Resolved Path */}
                    <span className="text-xs font-medium font-mono text-rh-text break-all">
                      {displayPath}
                    </span>
                  </div>

                  {/* Status & Latency Badges */}
                  <div className="flex items-center gap-2 text-xs">
                    {step.latency_ms != null && (
                      <span className="flex items-center gap-1 text-xs text-rh-muted tabular-nums">
                        <Clock className="w-3.5 h-3.5" aria-hidden="true" />
                        {step.latency_ms}ms
                      </span>
                    )}

                    {step.status_code != null ? (
                      <span
                        className={`px-2 py-0.5 rounded-[6px] text-xs font-semibold tabular-nums ${getStatusCodeBadge(
                          step.status_code
                        )}`}
                      >
                        HTTP {step.status_code}
                      </span>
                    ) : step.expected_status != null ? (
                      <span className="px-1.5 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-raised text-rh-muted tabular-nums">
                        Expected: {step.expected_status}
                      </span>
                    ) : null}

                    {step.executed && (
                      <span title={step.passed ? "Step passed" : step.violation_triggered ? "Security violation" : "Prerequisite setup failed"}>
                        {step.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-rh-go" aria-label="Step passed" />
                        ) : step.violation_triggered ? (
                          <XCircle className="w-4 h-4 text-rh-nogo" aria-label="Security violation" />
                        ) : (
                          <AlertCircle className="w-4 h-4 text-rh-cond" aria-label="Prerequisite setup failed" />
                        )}
                      </span>
                    )}
                  </div>
                </div>

                {/* Step Failure / Notice Detail */}
                {step.error_detail && !step.passed && (
                  <div
                    className={`p-2 rounded-[6px] text-xs ${
                      step.violation_triggered
                        ? "bg-rh-nogo/15 text-rh-nogo"
                        : "bg-rh-cond/15 text-rh-cond"
                    }`}
                  >
                    {step.error_detail}
                  </div>
                )}

                {/* Extracted Variables Pills */}
                {step.extracted_values && Object.keys(step.extracted_values).length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-xs text-rh-muted font-semibold">
                      Extracted
                    </span>
                    {Object.entries(step.extracted_values).map(([k, v]) => (
                      <span
                        key={k}
                        className="px-2 py-0.5 rounded-[6px] bg-rh-raised text-xs flex items-center gap-1 font-mono"
                      >
                        <span className="text-rh-text font-semibold">{`{{${k}}}`}</span>
                        <ArrowRight className="w-3 h-3 text-rh-muted" aria-hidden="true" />
                        <span className="text-rh-go font-semibold">&quot;{v}&quot;</span>
                      </span>
                    ))}
                  </div>
                )}

                {/* Planned extraction variable hints if not yet executed */}
                {!step.extracted_values && step.extract_vars && step.extract_vars.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-xs text-rh-muted font-semibold">
                      Extracts variables:
                    </span>
                    {step.extract_vars.map((v) => (
                      <span
                        key={v}
                        className="px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text text-xs font-mono"
                      >
                        {`{{${v}}}`}
                      </span>
                    ))}
                  </div>
                )}

                {/* Violation Condition Warning */}
                {step.violation_condition && (
                  <div
                    className={`mt-1 p-2 rounded-[6px] text-xs flex items-center gap-2 ${
                      step.executed && step.passed === false
                        ? "bg-rh-nogo/15 text-rh-nogo"
                        : "bg-rh-raised text-rh-text"
                    }`}
                  >
                    <AlertTriangle className={`w-3.5 h-3.5 shrink-0 ${step.executed && step.passed === false ? "text-rh-nogo" : "text-rh-cond"}`} aria-hidden="true" />
                    <span>
                      <strong className="text-rh-muted">Violation check: </strong>
                      {step.violation_condition}
                    </span>
                  </div>
                )}

                {/* Payload snippet if available */}
                {step.payload && (
                  <div className="mt-1">
                    <span className="text-xs text-rh-muted block mb-1">Payload</span>
                    <pre className="p-2 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-xs text-rh-text overflow-auto max-h-24">
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
