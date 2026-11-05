"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import {
  Globe,
  Bot,
  Radar,
  ShieldCheck,
  Search,
  RefreshCw,
  Trash2,
  Copy,
  Check,
  Clock,
  RotateCw,
  Terminal,
  ChevronDown,
  ChevronUp,
  Cpu,
  ShieldAlert,
  Sliders,
  CheckCircle,
  Eye,
  FileText,
  FileCode,
  ExternalLink,
  Shield,
  Ban,
  X,
  ArrowLeft,
} from "lucide-react";
import type {
  AgentRunRecord,
  TestCaseResult,
} from "@/types/agent";
import { apiRequest, cancelAgentRun, notify, useApiTokenVersion } from "@/lib/api";
import { copyTextSafely } from "@/lib/clipboard";
import {
  buildLedger,
  canApproveVerdict,
  confirmedSignOffStatus,
  getPillars,
  isGateVerdict,
  isRunActive,
  ledgerScore,
  ledgerVerdict,
  normalizeVerdict,
  numOrNull,
  runCases,
  runDefectCount,
  runEndedEarly,
  runLifecycle,
  signOffBlockedReason,
  strOrNull,
} from "@/lib/runs";
import { ReportButton, ReportFrame } from "./ReportButton";
import { VerdictBadge } from "./VerdictBadge";
import { RunStatusBadge } from "./RunStatusBadge";
import { StatefulChainFlow } from "./StatefulChainFlow";
import { ConcurrencyBurstMeter } from "./ConcurrencyBurstMeter";
import { AutoRemediationCard } from "./AutoRemediationCard";

/** How often the run list is refreshed while at least one run is still running. */
const RUNNING_POLL_MS = 4000;

const FOCUS = "focus-visible:outline-2 focus-visible:outline-rh-primary";
const INPUT =
  "w-full px-3 py-1.5 rounded-[6px] bg-rh-bg border border-rh-line text-xs text-rh-text placeholder:text-rh-muted focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
const BTN_SECONDARY = `inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer ${FOCUS}`;

const VERDICT_FILTER_LABEL = {
  ALL: "All",
  GO: "GO",
  CONDITIONAL_GO: "Conditional",
  NO_GO: "No go",
} as const;

/** "INCONCLUSIVE" -> "Inconclusive"; display only, filter values keep the backend spelling. */
function sentence(v: string): string {
  const t = (v || "").trim();
  return t ? t.charAt(0).toUpperCase() + t.slice(1).toLowerCase() : t;
}

function severityTone(severity: string | undefined): string {
  const s = (severity || "").toUpperCase();
  if (s === "CRITICAL") return "bg-rh-nogo/15 text-rh-nogo";
  if (s === "HIGH" || s === "MEDIUM") return "bg-rh-cond/15 text-rh-cond";
  if (s === "LOW") return "bg-rh-info/15 text-rh-info";
  return "bg-rh-raised text-rh-muted";
}

interface AgentHistoryViewProps {
  onLoadRunInStudio?: (run: AgentRunRecord) => void;
  onRetestCase?: (testCase: TestCaseResult) => Promise<void>;
  onBackToStudio?: () => void;
}

export function AgentHistoryView({ onLoadRunInStudio, onRetestCase, onBackToStudio }: AgentHistoryViewProps) {
  const [runs, setRuns] = useState<AgentRunRecord[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [fetchedRun, setFetchedRun] = useState<AgentRunRecord | null>(null);
  const [signedOff, setSignedOff] = useState<Record<string, AgentRunRecord>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [detailFailure, setDetailFailure] = useState<{ id: string; message: string } | null>(null);
  const tokenVersion = useApiTokenVersion();
  const [searchQuery, setSearchQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("ALL");
  const [activeTab, setActiveTab] = useState<"scenarios" | "routes" | "ledger" | "threats" | "steps">("scenarios");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedCaseId, setExpandedCaseId] = useState<string | null>(null);
  const [scenarioFilter, setScenarioFilter] = useState<string>("ALL");
  const [showReportModal, setShowReportModal] = useState(false);

  // Signoff state (no pre-filled operator or attestation text: a sign-off must be written by a person)
  const [operatorName, setOperatorName] = useState("");
  const [approvalNotes, setApprovalNotes] = useState("");
  // Both are keyed by run id, so a request that settles after the operator switched runs can
  // neither disable the new run's buttons nor show its error there.
  const [signingRunId, setSigningRunId] = useState<string | null>(null);
  const [signOffFailure, setSignOffFailure] = useState<{ runId: string; message: string } | null>(null);
  // Runs for which a cancel request is in flight or was accepted (they stop at their next step).
  const [cancelRequested, setCancelRequested] = useState<Record<string, boolean>>({});

  const loadRuns = useCallback(
    () =>
      apiRequest<AgentRunRecord[] | { runs?: AgentRunRecord[] }>("/api/agent/runs", {
        label: "Loading agent runs",
      }).then((r) => {
        if (r.ok && r.data) {
          const list: AgentRunRecord[] = Array.isArray(r.data) ? r.data : r.data.runs || [];
          setRuns(list);
          setListError(null);
          setSelectedRunId((cur) => cur ?? list[0]?.id ?? null);
        } else {
          setListError(r.ok ? "Loading agent runs failed: empty response." : r.error);
        }
        setIsLoading(false);
      }),
    []
  );

  // Manual refresh (button / after a sign-off): shows the spinner.
  const fetchRuns = () => {
    setIsLoading(true);
    return loadRuns();
  };

  useEffect(() => {
    loadRuns();
  }, [loadRuns, tokenVersion]);

  // A running run changes state on the backend (finishes, is cancelled, fails): keep the list
  // fresh while there is one, and stop polling as soon as none is left.
  const hasActiveRun = runs.some(isRunActive);
  useEffect(() => {
    if (!hasActiveRun) return;
    const timer = window.setInterval(() => {
      loadRuns();
    }, RUNNING_POLL_MS);
    return () => window.clearInterval(timer);
  }, [hasActiveRun, loadRuns]);

  // Fetch the full run when it is not in the list. A sign-off confirmed by the backend is
  // layered on top, so the view only ever shows backend-confirmed approval state.
  useEffect(() => {
    if (!selectedRunId) return;
    if (runs.some((r) => r.id === selectedRunId)) return;
    let cancelled = false;
    apiRequest<AgentRunRecord>(`/api/agent/runs/${encodeURIComponent(selectedRunId)}`, {
      label: `Loading run ${selectedRunId}`,
    }).then((r) => {
      if (cancelled) return;
      if (r.ok && r.data) {
        setFetchedRun(r.data);
        setDetailFailure(null);
      } else {
        setFetchedRun(null);
        setDetailFailure({ id: selectedRunId, message: r.ok ? "Run details were empty." : r.error });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [selectedRunId, runs]);

  const baseRun: AgentRunRecord | null = selectedRunId
    ? runs.find((r) => r.id === selectedRunId) ?? (fetchedRun?.id === selectedRunId ? fetchedRun : null)
    : null;
  const selectedRun: AgentRunRecord | null = useMemo(
    () => (baseRun && baseRun.id && signedOff[baseRun.id] ? { ...baseRun, ...signedOff[baseRun.id] } : baseRun),
    [baseRun, signedOff]
  );
  const selectedId = selectedRun?.id ?? "";
  const selectedLifecycle = selectedRun ? runLifecycle(selectedRun) : null;
  const selectedActive = selectedLifecycle === "running";
  const selectedCancelPending = selectedActive && !!cancelRequested[selectedId];
  const isSigning = signingRunId === selectedId;
  const signOffError = signOffFailure && signOffFailure.runId === selectedId ? signOffFailure.message : null;
  const detailError = detailFailure && detailFailure.id === selectedRunId ? detailFailure.message : null;

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete agent swarm run ${id}?`)) return;
    const r = await apiRequest<unknown>(`/api/agent/runs/${encodeURIComponent(id)}`, {
      method: "DELETE",
      label: "Delete run",
    });
    if (!r.ok) {
      notify(r.error);
      return;
    }
    setRuns((prev) => prev.filter((x) => x.id !== id));
    if (selectedRunId === id) {
      const remaining = runs.filter((x) => x.id !== id);
      setSelectedRunId(remaining.length > 0 ? remaining[0].id ?? null : null);
    }
  };

  const handleCancel = async (id: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    if (!id) return;
    if (!confirm(`Cancel running agent swarm ${id}? It stops at its next step and keeps what it already did.`)) return;
    setCancelRequested((prev) => ({ ...prev, [id]: true }));
    const r = await cancelAgentRun(id);
    if (!r.ok) {
      // Not accepted (unknown run, already finished, auth): the run is not being cancelled.
      setCancelRequested((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
      notify(r.error);
    } else {
      notify(`Cancel requested for run ${id.slice(-8)}. It stops at its next step.`, "info");
    }
    // Whatever the answer, the run's stored state may have changed.
    loadRuns();
  };

  const handleCopy = async (text: string, id: string) => {
    if (!(await copyTextSafely(text))) return;
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleSignOff = async (action: "approve" | "reject") => {
    if (!selectedRun?.id) return;
    const runId = selectedRun.id;
    const blocked = signOffBlockedReason(selectedRun, action);
    if (blocked) {
      setSignOffFailure({ runId, message: blocked });
      return;
    }
    if (action === "approve" && !canApproveVerdict(selectedVerdict)) {
      setSignOffFailure({
        runId,
        message: "Only a GO or CONDITIONAL_GO run can be approved for deployment. A NO_GO run can only be rejected.",
      });
      return;
    }
    setSigningRunId(runId);
    setSignOffFailure(null);
    // Only the backend's confirmed response changes the displayed approval state.
    const r = await apiRequest<AgentRunRecord>(`/api/agent/runs/${encodeURIComponent(runId)}/${action}`, {
      method: "POST",
      json: { user: operatorName.trim(), notes: approvalNotes.trim() },
      label: action === "approve" ? "Approve" : "Reject",
    });
    setSigningRunId((cur) => (cur === runId ? null : cur));
    if (!r.ok) {
      setSignOffFailure({ runId, message: r.error });
      return;
    }
    // Whatever the backend answered, the stored run may have changed: refresh the list.
    fetchRuns();
    const confirmed = r.data;
    // The status the backend echoed back, never the action that was clicked.
    const status = confirmedSignOffStatus(confirmed?.approval_status);
    if (!status) {
      setSignOffFailure({
        runId,
        message: "The backend did not confirm the sign-off status, so the review state was not changed. Reload the run to check it.",
      });
      return;
    }
    setSignedOff((prev) => ({
      ...prev,
      [runId]: {
        approval_status: status,
        approved_by: strOrNull(confirmed?.approved_by),
        approval_notes: strOrNull(confirmed?.approval_notes),
      },
    }));
  };

  const filteredRuns = useMemo(() => {
    return runs.filter((r) => {
      const verdict = ledgerVerdict(r.evidence_ledger) ?? normalizeVerdict(r.gate_verdict);
      if (verdictFilter !== "ALL" && verdict !== verdictFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTarget = (r.target ?? "").toLowerCase().includes(q);
        const matchId = (r.id ?? "").toLowerCase().includes(q);
        if (!matchTarget && !matchId) return false;
      }
      return true;
    });
  }, [runs, verdictFilter, searchQuery]);

  // Normalize test cases from executed results or planned cases (no invented status or latency)
  const allCases: TestCaseResult[] = useMemo(() => (selectedRun ? runCases(selectedRun) : []), [selectedRun]);

  const filteredCases = useMemo(() => {
    if (scenarioFilter === "ALL") return allCases;
    return allCases.filter((c) => c.status === scenarioFilter);
  }, [allCases, scenarioFilter]);

  // Gate verdict for the selected run, as reported by the backend (null = not evaluated)
  const selectedLedger = selectedRun ? buildLedger(selectedRun) : null;
  const selectedVerdict = ledgerVerdict(selectedLedger);
  const selectedPillars = getPillars(selectedLedger);

  const getCaseStatusBadge = (status: string) => {
    const chip = "px-2 py-0.5 rounded-[6px] text-xs font-semibold whitespace-nowrap";
    switch (status) {
      case "PASS":
        return <span className={`${chip} bg-rh-go/15 text-rh-go`}>Pass</span>;
      case "FAIL":
        return <span className={`${chip} bg-rh-nogo/15 text-rh-nogo`}>Fail</span>;
      case "WARN":
        return <span className={`${chip} bg-rh-cond/15 text-rh-cond`}>Warn</span>;
      case "INCONCLUSIVE":
        return <span className={`${chip} bg-rh-cond/15 text-rh-cond`}>Inconclusive</span>;
      case "PLANNED":
        return <span className={`${chip} bg-rh-info/15 text-rh-info`}>Planned</span>;
      default:
        return <span className={`${chip} bg-rh-raised text-rh-muted`}>{sentence(status)}</span>;
    }
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-rh-bg overflow-hidden">
      {/* Top subbar */}
      <div className="min-h-11 px-6 py-2 border-b border-rh-line bg-rh-surface flex flex-wrap items-center justify-between gap-2 text-xs text-rh-muted shrink-0">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-rh-muted" aria-hidden="true" />
          <h2 className="text-rh-text font-semibold text-sm">Run history</h2>
          <span className="text-rh-muted">4-agent adversarial runs</span>
          <span className="ml-2 px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text text-xs font-medium tabular-nums">
            {runs.length} {runs.length === 1 ? "run" : "runs"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {onBackToStudio && (
            <button
              type="button"
              onClick={onBackToStudio}
              className={`${BTN_SECONDARY}`}
              title="Return to Agent Studio"
            >
              <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Back to Studio</span>
            </button>
          )}
          <button
            type="button"
            onClick={fetchRuns}
            className={`${BTN_SECONDARY}`}
            title="Refresh agent runs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {/* Master-detail split */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Left pane: run list */}
        <div className="w-80 lg:w-96 border-r border-rh-line bg-rh-surface flex flex-col shrink-0 min-h-0">
          <div className="p-3 border-b border-rh-line space-y-2.5 shrink-0">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-rh-muted" aria-hidden="true" />
              <input
                type="text"
                placeholder="Filter by URL or run ID"
                aria-label="Filter runs by URL or run ID"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={`${INPUT} pl-9`}
              />
            </div>

            <div role="group" aria-label="Filter by verdict" className="flex items-center gap-1 bg-rh-bg p-1 rounded-[6px] border border-rh-line">
              {(["ALL", "GO", "CONDITIONAL_GO", "NO_GO"] as const).map((v) => (
                <button
                  type="button"
                  key={v}
                  onClick={() => setVerdictFilter(v)}
                  aria-pressed={verdictFilter === v}
                  className={`flex-1 py-1.5 text-xs rounded-[6px] transition-colors text-center cursor-pointer ${FOCUS} ${
                    verdictFilter === v
                      ? "bg-rh-raised text-rh-text font-semibold"
                      : "text-rh-muted hover:text-rh-text hover:bg-rh-raised"
                  }`}
                >
                  {VERDICT_FILTER_LABEL[v]}
                </button>
              ))}
            </div>
          </div>

          {/* Scrolling run list */}
          <div className="flex-1 overflow-y-auto divide-y divide-rh-line min-h-0">
            {isLoading && runs.length === 0 ? (
              <div className="p-6 text-center text-xs text-rh-muted space-y-2">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto text-rh-muted" aria-hidden="true" />
                <p>Loading agent runs...</p>
              </div>
            ) : listError ? (
              <div className="p-6 text-center text-xs text-rh-nogo space-y-1" role="alert">
                <p className="font-semibold">Could not load agent runs</p>
                <p className="text-xs break-words">{listError}</p>
                <p className="text-rh-muted">Check that the backend is reachable, then press Refresh.</p>
              </div>
            ) : filteredRuns.length === 0 ? (
              <div className="p-6 text-center text-xs text-rh-muted">
                <p className="font-semibold text-rh-text">{runs.length === 0 ? "No agent runs yet" : "No runs match these filters"}</p>
                <p className="mt-1 text-xs">
                  {runs.length === 0
                    ? "Start a swarm in Agent Studio and it will appear here."
                    : "Clear the search box or choose All to see every run."}
                </p>
              </div>
            ) : (
              filteredRuns.map((run) => {
                const isSelected = selectedRunId === run.id;
                const dateStr = run.started_at ? new Date(run.started_at).toLocaleString() : "Unknown";
                // Backend-reported values only; a run without them shows "not evaluated".
                const gate = ledgerVerdict(run.evidence_ledger) ?? normalizeVerdict(run.gate_verdict);
                const rawReadiness = ledgerScore(run.evidence_ledger) ?? numOrNull(run.readiness_score);
                const readiness = gate === "SCANNED" ? null : rawReadiness;
                const routesCount = run.discovered_routes?.length || 0;
                const casesCount = run.executed_results?.length || run.planned_cases?.length || run.cases_count || 0;
                const defectsCount = runDefectCount(run) ?? 0;
                const active = isRunActive(run);
                const endedEarly = runEndedEarly(run);
                const cancelPending = active && !!cancelRequested[run.id ?? ""];

                return (
                  <div
                    key={run.id}
                    className={`border-l-2 transition-colors ${
                      isSelected ? "bg-rh-raised border-l-rh-primary" : "border-l-transparent hover:bg-rh-raised"
                    }`}
                  >
                    <button
                      type="button"
                      onClick={() => setSelectedRunId(run.id ?? null)}
                      aria-current={isSelected ? "true" : undefined}
                      className={`block w-full text-left px-3.5 pt-3 pb-2 cursor-pointer focus-visible:-outline-offset-2 ${FOCUS}`}
                    >
                      <span className="flex items-start justify-between gap-2">
                        <span className="block min-w-0 flex-1">
                          <span className="flex items-center gap-1.5">
                            <Radar className="w-3.5 h-3.5 text-rh-muted shrink-0" aria-hidden="true" />
                            <span className="block text-xs font-semibold text-rh-text font-mono truncate" title={run.target}>
                              {run.target}
                            </span>
                          </span>
                          <span className="flex items-center gap-2 mt-1.5">
                            <span className="text-xs text-rh-muted font-mono">#{(run.id ?? "").slice(-8)}</span>
                            <span className="text-xs px-1.5 py-0.5 rounded-[6px] bg-rh-bg text-rh-muted">
                              {run.profile || "profile unknown"}
                            </span>
                          </span>
                        </span>
                        <span className="shrink-0 flex flex-col items-end gap-1">
                          {active ? (
                            <>
                              <RunStatusBadge status={run.status} />
                              <span className="text-xs text-rh-muted mt-0.5">in progress</span>
                            </>
                          ) : (
                            <>
                              <RunStatusBadge status={run.status} />
                              <VerdictBadge verdict={gate} />
                              <span className="text-xs font-semibold text-rh-text mt-0.5 tabular-nums">
                                {readiness === null ? <span className="text-rh-muted font-normal">not evaluated</span> : `${readiness}/100`}
                              </span>
                              {endedEarly && (
                                <span className="text-xs text-rh-cond">partial results, no gate decision</span>
                              )}
                            </>
                          )}
                        </span>
                      </span>
                    </button>

                    <div className="mx-3.5 mb-3 pt-2 border-t border-rh-line flex flex-col gap-2 text-xs text-rh-muted">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <span className="flex items-center gap-1 tabular-nums">
                          <Clock className="w-3.5 h-3.5" aria-hidden="true" />
                          {dateStr}
                        </span>
                        <span className="tabular-nums">{routesCount} routes · {casesCount} tests</span>
                        {run.requester_ip && (
                          <span className="font-mono hidden md:inline">{run.requester_ip}</span>
                        )}
                        {defectsCount > 0 && (
                          <span className="px-1.5 py-0.5 rounded-[6px] bg-rh-cond/15 text-rh-cond text-xs font-semibold tabular-nums">
                            {defectsCount} defects
                          </span>
                        )}
                      </div>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedRunId(run.id ?? null);
                            setShowReportModal(true);
                          }}
                          className={`px-2.5 py-1 rounded-[6px] bg-rh-bg hover:bg-rh-line text-rh-text text-xs flex items-center gap-1.5 transition-colors cursor-pointer ${FOCUS}`}
                          title="View executive HTML report"
                        >
                          <Eye className="w-3.5 h-3.5" aria-hidden="true" />
                          Report
                        </button>
                        {active && (
                          <button
                            type="button"
                            onClick={(e) => handleCancel(run.id ?? "", e)}
                            disabled={cancelPending}
                            className={`px-2.5 py-1 rounded-[6px] bg-rh-cond/15 hover:bg-rh-cond/25 text-rh-cond text-xs flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS}`}
                            title="Stop this run at its next step"
                          >
                            <Ban className="w-3.5 h-3.5" aria-hidden="true" />
                            {cancelPending ? "Cancelling..." : "Cancel"}
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={(e) => handleDelete(run.id ?? "", e)}
                          disabled={active}
                          className={`text-rh-muted hover:text-rh-nogo transition-colors p-1.5 rounded-[6px] cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${FOCUS}`}
                          title={active ? "Cancel the run before deleting it" : "Delete run"}
                          aria-label={`Delete run ${(run.id ?? "").slice(-8)}`}
                        >
                          <Trash2 className="w-4 h-4" aria-hidden="true" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right pane: run inspector */}
        <div className="flex-1 flex flex-col bg-rh-bg min-h-0 overflow-y-auto">
          {!selectedRunId ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-rh-muted">
              <Bot className="w-12 h-12 text-rh-muted mb-3 stroke-[1.5]" aria-hidden="true" />
              <h3 className="text-base font-semibold text-rh-text">Select a run to inspect it</h3>
              <p className="text-xs text-rh-muted max-w-sm mt-1">
                Pick a run on the left to see its test scenarios, reproduction cURL commands, discovered routes and the evidence ledger you sign off.
              </p>
            </div>
          ) : !selectedRun ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-xs">
              {detailError ? (
                <div className="max-w-md space-y-1" role="alert">
                  <p className="text-rh-nogo break-words">{detailError}</p>
                  <p className="text-rh-muted">Pick another run, or press Refresh to try again.</p>
                </div>
              ) : (
                <p className="text-rh-muted flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin" aria-hidden="true" /> Loading run details...
                </p>
              )}
            </div>
          ) : (
            <div className="p-6 space-y-5 max-w-6xl w-full mx-auto">
              {/* Hero */}
              <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line">
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  <div className="space-y-2 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <RunStatusBadge status={selectedRun.status} />
                      {!selectedActive && <VerdictBadge verdict={selectedVerdict} />}
                      <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted font-medium">
                        4-agent QA swarm
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted font-medium">
                        Profile: {selectedRun.profile || "unknown"}
                      </span>
                    </div>

                    <h3 className="text-lg font-semibold text-rh-text break-all flex items-center gap-2 font-mono">
                      {selectedRun.target}
                      <button
                        type="button"
                        onClick={() => handleCopy(selectedRun.target ?? "", "target")}
                        className={`text-rh-muted hover:text-rh-text cursor-pointer p-1 rounded-[6px] ${FOCUS}`}
                        title="Copy target URL"
                        aria-label="Copy target URL"
                      >
                        {copiedId === "target" ? <Check className="w-4 h-4 text-rh-go" aria-hidden="true" /> : <Copy className="w-4 h-4" aria-hidden="true" />}
                      </button>
                    </h3>

                    <div className="flex items-center gap-x-4 gap-y-1 text-xs text-rh-muted flex-wrap">
                      <span className="flex items-center gap-1">
                        Run ID
                        <span className="font-mono text-rh-text break-all">{selectedRun.id}</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(selectedId, "id")}
                          className={`text-rh-muted hover:text-rh-text cursor-pointer p-1 rounded-[6px] ${FOCUS}`}
                          title="Copy run ID"
                          aria-label="Copy run ID"
                        >
                          {copiedId === "id" ? <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
                        </button>
                      </span>
                      <span className="tabular-nums">Started {selectedRun.started_at ? new Date(selectedRun.started_at).toLocaleString() : "-"}</span>
                      <span className="flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5" aria-hidden="true" />
                        {selectedRun.model || "model not reported"} · {selectedRun.provider || "provider not reported"}
                      </span>
                    </div>
                  </div>
                  {selectedActive && (
                    <button
                      type="button"
                      onClick={() => handleCancel(selectedId)}
                      disabled={selectedCancelPending}
                      className={`px-3 py-1.5 rounded-[6px] bg-rh-cond/15 hover:bg-rh-cond/25 text-rh-cond text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shrink-0 disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS}`}
                      title="Stop this run at its next step; it keeps what it already did"
                    >
                      <Ban className="w-3.5 h-3.5" aria-hidden="true" />
                      {selectedCancelPending ? "Cancelling..." : "Cancel run"}
                    </button>
                  )}
                </div>
              </div>

              {selectedActive && (
                <div className="p-3 rounded-[10px] bg-rh-info/15 border-l-2 border-rh-info text-xs text-rh-text" role="status">
                  This run is still running. The list refreshes every few seconds; the gate verdict appears when it finishes.
                </div>
              )}
              {selectedLifecycle === "cancelled" && (
                <div className="p-3 rounded-[10px] bg-rh-cond/15 border-l-2 border-rh-cond text-xs text-rh-text" role="status">
                  This run was cancelled before it finished. The cases and defects below are partial and no gate decision was made.
                  {selectedRun.error ? ` ${selectedRun.error}` : ""}
                </div>
              )}
              {selectedLifecycle === "failed" && (
                <div className="p-3 rounded-[10px] bg-rh-nogo/15 border-l-2 border-rh-nogo text-xs text-rh-text break-words" role="alert">
                  This run failed{selectedRun.error ? `: ${selectedRun.error}` : " and the backend gave no reason."} Any results below are partial.
                </div>
              )}

              {/* Requester egress IP / allowlist */}
              <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-8 h-8 rounded-[6px] bg-rh-raised flex items-center justify-center text-rh-muted shrink-0" aria-hidden="true">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold text-rh-muted">Requester egress public IP</span>
                      <span className="text-xs font-semibold text-rh-text bg-rh-bg px-2 py-0.5 rounded-[6px] border border-rh-line font-mono">
                        {selectedRun.requester_ip || "unknown"}
                      </span>
                      {selectedRun.requester_ip_type && (
                        <span className="text-xs px-1.5 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted">
                          {selectedRun.requester_ip_type}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-rh-muted mt-1">
                      {selectedRun.requester_ip
                        ? selectedRun.allowlist_guidance ||
                          "Allowlist this IP on your target firewall, AWS security group or Cloudflare WAF if you are testing a private network."
                        : "No requester IP was recorded for this run."}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={!selectedRun.requester_ip}
                  onClick={() => handleCopy(selectedRun.requester_ip ?? "", "ip")}
                  className={`${BTN_SECONDARY} shrink-0 disabled:opacity-40 disabled:cursor-not-allowed`}
                  title="Copy the requester egress IP for firewall allowlisting"
                >
                  {copiedId === "ip" ? <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
                  {copiedId === "ip" ? "Copied IP" : "Copy IP"}
                </button>
              </div>

              {/* Reports and exports */}
              <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                  <span className="text-xs font-semibold text-rh-text">Reports and exports</span>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  {onLoadRunInStudio && (
                    <button
                      type="button"
                      onClick={() => onLoadRunInStudio(selectedRun)}
                      className={BTN_SECONDARY}
                      title="Load this run into Agent Studio"
                    >
                      <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                      Open in Studio
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => setShowReportModal(true)}
                    className={`px-3 py-1.5 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${FOCUS}`}
                  >
                    <Eye className="w-3.5 h-3.5" aria-hidden="true" />
                    View executive report
                  </button>

                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/html`}
                    mode="tab"
                    className={BTN_SECONDARY}
                    title="Open the HTML report in a full browser tab"
                  >
                    <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                    Open in tab
                  </ReportButton>

                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/markdown`}
                    mode="download"
                    filename={`readyhai-agent-report-${selectedId}.md`}
                    className={BTN_SECONDARY}
                    title="Download a Markdown summary for pull requests"
                  >
                    <FileCode className="w-3.5 h-3.5" aria-hidden="true" />
                    Markdown (PR)
                  </ReportButton>

                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/sarif`}
                    mode="download"
                    filename={`readyhai-agent-report-${selectedId}.sarif`}
                    className={BTN_SECONDARY}
                    title="Download OASIS SARIF v2.1.0 for the GitHub or GitLab security tab"
                  >
                    <Shield className="w-3.5 h-3.5" aria-hidden="true" />
                    SARIF
                  </ReportButton>

                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/json`}
                    mode="download"
                    filename={`readyhai-agent-report-${selectedId}.json`}
                    className={BTN_SECONDARY}
                    title="Download the complete execution data (JSON)"
                  >
                    <FileText className="w-3.5 h-3.5" aria-hidden="true" />
                    JSON
                  </ReportButton>

                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/junit`}
                    mode="download"
                    filename={`readyhai-agent-report-${selectedId}.junit.xml`}
                    className={BTN_SECONDARY}
                    title="Download JUnit XML for CI test results"
                  >
                    <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                    JUnit
                  </ReportButton>
                </div>
              </div>

              {/* KPI cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
                <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line">
                  <div className="text-xs text-rh-muted">Adversarial tests</div>
                  <div className="text-2xl font-semibold text-rh-text mt-1 tabular-nums">{allCases.length}</div>
                  <div className="text-xs text-rh-muted mt-0.5 tabular-nums">
                    {allCases.filter((c) => c.status === "PASS").length} passing
                  </div>
                </div>

                <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line">
                  <div className="text-xs text-rh-muted">Discovered routes</div>
                  <div className="text-2xl font-semibold text-rh-text mt-1 tabular-nums">
                    {selectedRun.discovered_routes?.length || 0}
                  </div>
                  <div className="text-xs text-rh-muted mt-0.5 tabular-nums">
                    {selectedRun.discovered_routes?.filter((r) => r.is_api).length || 0} APIs identified
                  </div>
                </div>

                <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line">
                  <div className="text-xs text-rh-muted">OWASP defects</div>
                  <div
                    className={`text-2xl font-semibold mt-1 tabular-nums ${
                      (runDefectCount(selectedRun) ?? 0) > 0 ? "text-rh-cond" : isGateVerdict(selectedVerdict) ? "text-rh-go" : "text-rh-text"
                    }`}
                  >
                    {runDefectCount(selectedRun) ?? "n/a"}
                  </div>
                  <div className="text-xs text-rh-muted mt-0.5">Triaged vulnerabilities</div>
                </div>

                <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line">
                  <div className="text-xs text-rh-muted">Agent steps</div>
                  <div className="text-2xl font-semibold text-rh-text mt-1 tabular-nums">{selectedRun.steps?.length || 0}</div>
                  <div className="text-xs text-rh-muted mt-0.5">Supervisor and planner traces</div>
                </div>
              </div>

              {/* Detail tabs */}
              <div role="tablist" aria-label="Run details" className="border-b border-rh-line flex items-center gap-2 overflow-x-auto">
                {(
                  [
                    { key: "scenarios", icon: Sliders, label: `Scenarios (${allCases.length})` },
                    { key: "ledger", icon: ShieldCheck, label: "Evidence ledger" },
                    { key: "routes", icon: Radar, label: `Discovered routes (${selectedRun.discovered_routes?.length || 0})` },
                    { key: "threats", icon: ShieldAlert, label: `Threat triage (${selectedRun.triaged_defects?.length || 0})` },
                    { key: "steps", icon: Terminal, label: `Execution trace (${selectedRun.steps?.length || 0})` },
                  ] as const
                ).map(({ key, icon: Icon, label }) => (
                  <button
                    type="button"
                    key={key}
                    role="tab"
                    aria-selected={activeTab === key}
                    onClick={() => setActiveTab(key)}
                    className={`pb-2.5 px-3 text-xs font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer shrink-0 tabular-nums ${FOCUS} ${
                      activeTab === key
                        ? "border-rh-primary text-rh-text font-semibold"
                        : "border-transparent text-rh-muted hover:text-rh-text"
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" aria-hidden="true" />
                    {label}
                  </button>
                ))}
              </div>

              {/* Tab: scenarios */}
              {activeTab === "scenarios" && (
                <div className="space-y-4">
                  <div role="group" aria-label="Filter scenarios by status" className="flex flex-wrap items-center gap-1 bg-rh-surface p-1.5 rounded-[6px] border border-rh-line text-xs">
                    <span className="text-rh-muted px-2">Status</span>
                    {(["ALL", "PASS", "FAIL", "WARN", "INCONCLUSIVE", "BLOCKED", "SKIPPED", "PLANNED"] as const).map((s) => (
                      <button
                        type="button"
                        key={s}
                        onClick={() => setScenarioFilter(s)}
                        aria-pressed={scenarioFilter === s}
                        className={`px-2.5 py-1 rounded-[6px] cursor-pointer transition-colors ${FOCUS} ${
                          scenarioFilter === s
                            ? "bg-rh-raised text-rh-text font-semibold"
                            : "text-rh-muted hover:bg-rh-raised hover:text-rh-text"
                        }`}
                      >
                        {sentence(s)}
                      </button>
                    ))}
                  </div>

                  {filteredCases.length === 0 ? (
                    <div className="p-8 text-center text-xs text-rh-muted bg-rh-surface rounded-[10px] border border-rh-line">
                      {allCases.length === 0
                        ? "This run has no test scenarios yet. Re-run the swarm from Agent Studio to generate them."
                        : "No scenarios have this status. Choose All to see every scenario."}
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {filteredCases.map((tc) => {
                        const isExpanded = expandedCaseId === tc.id;
                        return (
                          <div key={tc.id} className="rounded-[10px] bg-rh-surface border border-rh-line overflow-hidden">
                            <button
                              type="button"
                              onClick={() => setExpandedCaseId(isExpanded ? null : tc.id)}
                              aria-expanded={isExpanded}
                              className={`w-full text-left px-3.5 py-3 flex items-center justify-between gap-3 cursor-pointer hover:bg-rh-raised transition-colors focus-visible:-outline-offset-2 ${FOCUS}`}
                            >
                              <span className="flex items-center gap-3 min-w-0">
                                <span className="text-xs font-semibold text-rh-text w-20 shrink-0 font-mono">{tc.id}</span>
                                <span
                                  className={`px-2 py-0.5 rounded-[6px] text-xs font-mono font-semibold shrink-0 ${
                                    tc.method === "POST"
                                      ? "bg-rh-info/15 text-rh-info"
                                      : tc.method === "PUT" || tc.method === "PATCH"
                                      ? "bg-rh-cond/15 text-rh-cond"
                                      : tc.method === "DELETE"
                                      ? "bg-rh-nogo/15 text-rh-nogo"
                                      : "bg-rh-raised text-rh-text"
                                  }`}
                                >
                                  {tc.method}
                                </span>
                                <span className="block min-w-0">
                                  <span className="flex items-center gap-2 flex-wrap">
                                    <span className="text-xs font-semibold text-rh-text">{tc.title}</span>
                                    {(tc.technique?.toLowerCase().includes("bola") ||
                                      (tc.stateful_steps && tc.stateful_steps.some((s) => s.actor.toLowerCase() === "bob"))) && (
                                      <span className="px-1.5 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-cond/15 text-rh-cond shrink-0">
                                        BOLA test
                                      </span>
                                    )}
                                    {((tc.stateful_chain && tc.stateful_chain.length > 0) ||
                                      (tc.stateful_steps && tc.stateful_steps.length > 0) ||
                                      tc.technique?.toLowerCase().includes("stateful")) && (
                                      <span className="px-1.5 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-info/15 text-rh-info shrink-0">
                                        Stateful chain
                                      </span>
                                    )}
                                    {(tc.concurrency_burst != null ||
                                      (tc.concurrency_burst_results && tc.concurrency_burst_results.length > 0) ||
                                      tc.technique?.toLowerCase().includes("toctou") ||
                                      tc.technique?.toLowerCase().includes("burst") ||
                                      tc.technique?.toLowerCase().includes("race")) && (
                                      <span className="px-1.5 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-cond/15 text-rh-cond shrink-0">
                                        TOCTOU burst
                                      </span>
                                    )}
                                  </span>
                                  <span className="block text-xs text-rh-muted truncate mt-0.5">
                                    <span className="font-mono">{tc.component}</span> · technique: {tc.technique}
                                  </span>
                                </span>
                              </span>

                              <span className="flex items-center gap-3 shrink-0">
                                {tc.latency_ms != null && tc.latency_ms > 0 && (
                                  <span className="text-xs text-rh-muted hidden sm:inline tabular-nums">{tc.latency_ms}ms</span>
                                )}
                                {getCaseStatusBadge(tc.status)}
                                {isExpanded ? (
                                  <ChevronUp className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                                ) : (
                                  <ChevronDown className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                                )}
                              </span>
                            </button>

                            {isExpanded && (
                              <div className="p-4 border-t border-rh-line space-y-3 text-xs">
                                {(tc.stateful_chain || tc.stateful_steps) && (
                                  <StatefulChainFlow
                                    steps={tc.stateful_steps}
                                    chain={tc.stateful_chain}
                                    caseStatus={tc.status}
                                  />
                                )}

                                {(tc.concurrency_burst != null || (tc.concurrency_burst_results && tc.concurrency_burst_results.length > 0)) && (
                                  <ConcurrencyBurstMeter
                                    burstCount={tc.concurrency_burst}
                                    burstResults={tc.concurrency_burst_results}
                                    technique={tc.technique}
                                    caseStatus={tc.status}
                                  />
                                )}

                                {(tc.remediation_patch || tc.remediation_explanation || tc.reproduction_script) && (
                                  <AutoRemediationCard
                                    patch={tc.remediation_patch}
                                    explanation={tc.remediation_explanation}
                                    reproScript={tc.reproduction_script}
                                  />
                                )}

                                {tc.assertion_details && (
                                  <div>
                                    <span className="text-xs text-rh-muted font-semibold">Expected behaviour</span>
                                    <p className="text-rh-text mt-0.5">{tc.assertion_details}</p>
                                  </div>
                                )}

                                {tc.curl && (
                                  <div>
                                    <div className="flex items-center justify-between text-xs text-rh-muted font-semibold mb-1">
                                      <span>Reproduction cURL</span>
                                      <button
                                        type="button"
                                        onClick={() => handleCopy(tc.curl, tc.id + "-curl")}
                                        className={`flex items-center gap-1 px-2 py-1 rounded-[6px] text-rh-primary hover:text-rh-primary-hover cursor-pointer ${FOCUS}`}
                                      >
                                        {copiedId === tc.id + "-curl" ? <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
                                        Copy cURL
                                      </button>
                                    </div>
                                    <pre className="p-2.5 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-rh-text overflow-x-auto">
                                      {tc.curl}
                                    </pre>
                                  </div>
                                )}

                                {tc.response_body && (
                                  <div>
                                    <span className="text-xs text-rh-muted font-semibold">Response body snippet</span>
                                    <pre className="p-2.5 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-rh-text overflow-auto max-h-48 mt-1">
                                      {tc.response_body}
                                    </pre>
                                  </div>
                                )}

                                {onRetestCase && (
                                  <div className="pt-1 flex justify-end">
                                    <button
                                      type="button"
                                      onClick={() => onRetestCase(tc)}
                                      className={BTN_SECONDARY}
                                    >
                                      <RotateCw className="w-3.5 h-3.5" aria-hidden="true" />
                                      Retest this case
                                    </button>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* Tab: evidence ledger */}
              {activeTab === "ledger" && (
                <div className="space-y-4">
                  <div className="p-4 rounded-[10px] bg-rh-surface border border-rh-line flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <VerdictBadge verdict={selectedVerdict} />
                      <span className="text-xs text-rh-muted">
                        Composite score:{" "}
                        {ledgerScore(selectedLedger) === null || selectedVerdict === "SCANNED" ? (
                          <span className="text-rh-muted">not evaluated</span>
                        ) : (
                          <span className="text-rh-text font-semibold tabular-nums">{ledgerScore(selectedLedger)}/100</span>
                        )}
                      </span>
                    </div>
                    {selectedLedger?.executive_summary && (
                      <p className="text-xs text-rh-text w-full leading-relaxed">{selectedLedger.executive_summary}</p>
                    )}
                    {!selectedLedger && (
                      <p className="text-xs text-rh-muted w-full">
                        This run has no evidence ledger: it was not evaluated.
                      </p>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {selectedPillars.map((pillar, idx) => (
                      <div key={pillar.key} className="p-4 rounded-[10px] bg-rh-surface border border-rh-line space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-rh-text">
                            {idx + 1}. {pillar.short}
                          </span>
                          {pillar.status && (
                            <span className="px-2 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-raised text-rh-text">
                              {pillar.status}
                            </span>
                          )}
                        </div>
                        {pillar.score === null ? (
                          <div className="text-sm text-rh-muted">not evaluated</div>
                        ) : (
                          <div className="text-2xl font-semibold text-rh-text tabular-nums">{pillar.score}/100</div>
                        )}
                        <p className="text-xs text-rh-muted">
                          {pillar.evidence ?? "No evidence text was reported for this pillar."}
                        </p>
                      </div>
                    ))}
                  </div>

                  {selectedLedger?.exit_criteria_checklist && selectedLedger.exit_criteria_checklist.length > 0 && (
                    <div className="p-4 rounded-[10px] bg-rh-surface border border-rh-line space-y-2">
                      <span className="text-xs font-semibold text-rh-text">Exit criteria</span>
                      {selectedLedger.exit_criteria_checklist.map((c, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs">
                          <span
                            className={`px-1.5 py-0.5 rounded-[6px] font-semibold shrink-0 ${
                              c.met ? "bg-rh-go/15 text-rh-go" : "bg-rh-nogo/15 text-rh-nogo"
                            }`}
                          >
                            {c.met ? "Met" : "Not met"}
                          </span>
                          <span className="text-rh-text">{c.criterion}</span>
                          {c.details && <span className="text-rh-muted">- {c.details}</span>}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Sign-off form */}
                  <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line space-y-3">
                    <h4 className="text-sm font-semibold text-rh-text flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                      Production gate sign-off
                    </h4>
                    {(() => {
                      const status = (selectedRun.approval_status || "").toLowerCase();
                      if (status === "approved" || status === "rejected") {
                        return (
                          <div className="p-3 bg-rh-bg rounded-[6px] border border-rh-line text-xs text-rh-text">
                            {status === "approved" ? "Approved" : "Rejected"} by{" "}
                            <strong className="text-rh-text">{selectedRun.approved_by || "unknown operator"}</strong>
                            {selectedRun.approval_notes ? ` · ${selectedRun.approval_notes}` : ""}
                          </div>
                        );
                      }
                      const rejectBlocked = signOffBlockedReason(selectedRun, "reject");
                      const approveBlocked = signOffBlockedReason(selectedRun, "approve");
                      return (
                        <>
                          {approveBlocked && (
                            <p className="text-xs text-rh-cond">{approveBlocked}</p>
                          )}
                          {!approveBlocked && !canApproveVerdict(selectedVerdict) && (
                            <p className="text-xs text-rh-cond">
                              {isGateVerdict(selectedVerdict)
                                ? "The backend reported NO_GO for this run, so it cannot be approved. It can only be rejected."
                                : "The backend reported no gate verdict for this run, so it cannot be approved."}
                            </p>
                          )}
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                            <label className="block">
                              <span className="text-rh-muted block mb-1">Operator or role (required)</span>
                              <input
                                type="text"
                                value={operatorName}
                                onChange={(e) => setOperatorName(e.target.value)}
                                className={INPUT}
                              />
                            </label>
                            <label className="block">
                              <span className="text-rh-muted block mb-1">Audit notes</span>
                              <input
                                type="text"
                                value={approvalNotes}
                                onChange={(e) => setApprovalNotes(e.target.value)}
                                className={INPUT}
                              />
                            </label>
                          </div>
                          {!operatorName.trim() && (
                            <p className="text-xs text-rh-muted">Enter your name or role to enable sign-off.</p>
                          )}
                          {signOffError && (
                            <p className="text-xs text-rh-nogo break-words" role="alert">
                              {signOffError}
                            </p>
                          )}
                          <div className="pt-2 flex items-center justify-end gap-2.5">
                            <button
                              type="button"
                              onClick={() => handleSignOff("reject")}
                              disabled={isSigning || !operatorName.trim() || !!rejectBlocked}
                              title={rejectBlocked ?? undefined}
                              className={`px-4 py-1.5 rounded-[6px] bg-rh-nogo/15 hover:bg-rh-nogo/25 text-rh-nogo text-xs font-semibold cursor-pointer transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
                            >
                              Reject gate
                            </button>
                            <button
                              type="button"
                              onClick={() => handleSignOff("approve")}
                              disabled={isSigning || !operatorName.trim() || !!approveBlocked || !canApproveVerdict(selectedVerdict)}
                              title={
                                approveBlocked
                                  ? approveBlocked
                                  : canApproveVerdict(selectedVerdict)
                                  ? undefined
                                  : isGateVerdict(selectedVerdict)
                                  ? "NO_GO verdict: approval is unavailable"
                                  : "No backend gate verdict: approval is unavailable"
                              }
                              className={`px-5 py-1.5 rounded-[6px] bg-rh-go hover:bg-rh-go/90 text-rh-bg text-xs font-semibold cursor-pointer transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
                            >
                              Approve production gate
                            </button>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* Tab: discovered routes */}
              {activeTab === "routes" && (
                <div className="rounded-[10px] bg-rh-surface border border-rh-line overflow-hidden text-xs">
                  {(selectedRun.discovered_routes?.length ?? 0) === 0 ? (
                    <div className="p-8 text-center text-rh-muted">
                      No routes were discovered for this run. Check that the target is reachable, then run the swarm again.
                    </div>
                  ) : (
                    <div className="max-h-[60vh] min-h-0 overflow-y-auto">
                      <div className="sticky top-0 z-10 px-4 py-2.5 bg-rh-raised border-b border-rh-line grid grid-cols-[minmax(0,1fr)_4rem_4rem_7rem] items-center gap-4 text-rh-muted font-semibold">
                        <span>Endpoint path</span>
                        <span className="text-right">Method</span>
                        <span className="text-right">Status</span>
                        <span>Type</span>
                      </div>
                      <div className="divide-y divide-rh-line">
                        {selectedRun.discovered_routes?.map((r, idx) => (
                          <div
                            key={r.path + idx}
                            className="px-4 py-2.5 grid grid-cols-[minmax(0,1fr)_4rem_4rem_7rem] items-center gap-4 hover:bg-rh-raised transition-colors"
                          >
                            <span className="text-rh-text font-mono truncate" title={r.path}>{r.path}</span>
                            <span className="text-rh-text font-mono font-semibold text-right">{r.method}</span>
                            <span className="text-rh-muted text-right tabular-nums">{r.status_code ?? "n/a"}</span>
                            <span>
                              <span
                                className={`px-2 py-0.5 rounded-[6px] text-xs font-semibold ${
                                  r.is_api ? "bg-rh-info/15 text-rh-info" : "bg-rh-raised text-rh-muted"
                                }`}
                              >
                                {r.is_api ? "API route" : r.is_spa_shell ? "SPA shell" : "Route"}
                              </span>
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Tab: threat triage */}
              {activeTab === "threats" && (
                <div className="space-y-3">
                  {(!selectedRun.triaged_defects || selectedRun.triaged_defects.length === 0) ? (
                    <div className="p-8 text-center text-xs text-rh-muted bg-rh-surface rounded-[10px] border border-rh-line">
                      {selectedLedger
                        ? "The backend triaged no defects for this run, so there is nothing to fix."
                        : "This run was not evaluated, so there are no triaged defects. Re-run it from Agent Studio to get a triage."}
                    </div>
                  ) : (
                    selectedRun.triaged_defects.map((d, idx) => (
                      <div key={d.case_id || d.id || idx} className="p-4 rounded-[10px] bg-rh-surface border border-rh-line space-y-2 text-xs">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-2 py-0.5 rounded-[6px] text-xs font-semibold ${severityTone(d.severity)}`}
                            >
                              {sentence(d.severity || "Unknown")}
                            </span>
                            <span className="text-rh-muted font-semibold">{d.owasp_category}</span>
                          </div>
                          <span className="text-rh-muted text-xs font-mono">#{d.case_id || d.id}</span>
                        </div>
                        <h4 className="text-sm font-semibold text-rh-text">{d.title}</h4>
                        {d.evidence_snippet && (
                          <div className="p-2.5 rounded-[6px] bg-rh-bg border border-rh-line text-rh-text whitespace-pre-wrap">
                            {d.evidence_snippet}
                          </div>
                        )}
                        {(d.remediation_patch || d.remediation_patch_suggestion || d.recommended_fix || d.remediation_explanation || d.reproduction_script) ? (
                          <AutoRemediationCard
                            patch={d.remediation_patch || d.remediation_patch_suggestion || d.recommended_fix}
                            explanation={d.remediation_explanation}
                            reproScript={d.reproduction_script || d.reproduction}
                          />
                        ) : null}
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab: swarm execution trace */}
              {activeTab === "steps" && (
                <div className="rounded-[10px] bg-rh-surface border border-rh-line divide-y divide-rh-line overflow-hidden text-xs">
                  {(selectedRun.steps?.length ?? 0) === 0 ? (
                    <div className="p-8 text-center text-rh-muted">
                      No agent steps were recorded for this run.
                    </div>
                  ) : (
                    selectedRun.steps?.map((st, idx) => (
                      <div key={st.timestamp + idx} className="px-4 py-3 flex items-start gap-3">
                        <span className="px-2 py-0.5 rounded-[6px] text-xs font-semibold shrink-0 bg-rh-raised text-rh-text">
                          {st.agent}
                        </span>
                        <div className="min-w-0 flex-1 space-y-0.5">
                          <div className="font-semibold text-rh-text flex items-center justify-between gap-2">
                            <span>{st.action}</span>
                            <span className="text-xs text-rh-muted font-normal tabular-nums shrink-0">
                              {st.timestamp ? new Date(st.timestamp).toLocaleTimeString() : "-"}
                            </span>
                          </div>
                          <p className="text-rh-muted text-xs">{st.details}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Embedded HTML report modal */}
      {showReportModal && selectedRun && (
        <div className="fixed inset-0 z-50 bg-rh-bg/80 flex items-center justify-center p-4">
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Executive QA and security gate report"
            className="bg-rh-surface border border-rh-line rounded-[10px] shadow-lg w-full max-w-5xl h-[90vh] max-h-full flex flex-col overflow-hidden"
          >
            <div className="px-5 py-3 border-b border-rh-line flex flex-wrap items-center justify-between gap-2 bg-rh-raised shrink-0">
              <div className="flex items-center gap-2.5 min-w-0">
                <FileText className="w-4 h-4 text-rh-muted shrink-0" aria-hidden="true" />
                <span className="text-sm font-semibold text-rh-text">Executive QA and security gate report</span>
                <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-bg text-rh-muted font-mono truncate">
                  {selectedId}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <ReportButton
                  path={`/api/agent/runs/${selectedId}/report/html`}
                  mode="tab"
                  className={BTN_SECONDARY}
                  title="Open the report in a new browser tab"
                >
                  <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                  New tab
                </ReportButton>
                <ReportButton
                  path={`/api/agent/runs/${selectedId}/report/markdown`}
                  mode="download"
                  filename={`readyhai-agent-report-${selectedId}.md`}
                  className={BTN_SECONDARY}
                  title="Download a Markdown summary"
                >
                  <FileCode className="w-3.5 h-3.5" aria-hidden="true" />
                  Markdown
                </ReportButton>
                <button
                  type="button"
                  onClick={() => setShowReportModal(false)}
                  className={`p-1.5 rounded-[6px] text-rh-muted hover:text-rh-text hover:bg-rh-line transition-colors cursor-pointer ${FOCUS}`}
                  title="Close report"
                  aria-label="Close report"
                >
                  <X className="w-4 h-4" aria-hidden="true" />
                </button>
              </div>
            </div>
            <div className="flex-1 min-h-0 w-full bg-rh-bg relative">
              <ReportFrame
                path={`/api/agent/runs/${selectedId}/report/html`}
                title="ReadyHai executive QA report"
                className="w-full h-full border-0"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
