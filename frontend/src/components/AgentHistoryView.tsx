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
  X,
} from "lucide-react";
import type {
  AgentRunRecord,
  TestCaseResult,
} from "@/types/agent";
import { apiRequest, notify, useApiTokenVersion } from "@/lib/api";
import {
  buildLedger,
  getPillars,
  isGateVerdict,
  ledgerScore,
  ledgerVerdict,
  normalizeVerdict,
  numOrNull,
  runCases,
  runDefectCount,
} from "@/lib/runs";
import { ReportButton, ReportFrame } from "./ReportButton";
import { VerdictBadge } from "./VerdictBadge";

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
  const [isSigning, setIsSigning] = useState(false);
  const [signOffError, setSignOffError] = useState<string | null>(null);

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

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleSignOff = async (action: "approve" | "reject") => {
    if (!selectedRun?.id) return;
    const runId = selectedRun.id;
    setIsSigning(true);
    setSignOffError(null);
    // Only the backend's confirmed response changes the displayed approval state.
    const r = await apiRequest<AgentRunRecord>(`/api/agent/runs/${encodeURIComponent(runId)}/${action}`, {
      method: "POST",
      json: { user: operatorName.trim(), notes: approvalNotes.trim() },
      label: action === "approve" ? "Approve" : "Reject",
    });
    if (!r.ok) {
      setSignOffError(r.error);
      setIsSigning(false);
      return;
    }
    const confirmed = r.data;
    setSignedOff((prev) => ({
      ...prev,
      [runId]: {
        approval_status: confirmed?.approval_status || (action === "approve" ? "approved" : "rejected"),
        approved_by: confirmed?.approved_by || operatorName.trim(),
        approval_notes: confirmed?.approval_notes ?? approvalNotes.trim(),
      },
    }));
    fetchRuns();
    setIsSigning(false);
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
    switch (status) {
      case "PASS":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-600/50">
            PASS
          </span>
        );
      case "FAIL":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-600/50">
            FAIL
          </span>
        );
      case "WARN":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-600/50">
            WARN
          </span>
        );
      case "PLANNED":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-700/50">
            PLANNED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-700">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-[#06080e] overflow-hidden">
      {/* Top Subbar */}
      <div className="h-11 px-6 border-b border-[#161f30] bg-[#0a0f1b] flex items-center justify-between text-xs text-slate-400 shrink-0">
        <div className="flex items-center gap-2 font-mono">
          <Bot className="w-4 h-4 text-cyan-400" />
          <span className="text-slate-200 font-semibold">Autonomous QA Swarm History</span>
          <span className="text-slate-600">/</span>
          <span>4-Agent Adversarial Runs</span>
          <span className="ml-2 px-2 py-0.5 rounded-full bg-cyan-950/60 text-cyan-300 border border-cyan-800/40 text-[11px]">
            {runs.length} Swarms Executed
          </span>
        </div>
        <div className="flex items-center gap-2">
          {onBackToStudio && (
            <button
              onClick={onBackToStudio}
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#0d1527] hover:bg-[#121f38] border border-cyan-800/50 text-cyan-300 transition-colors cursor-pointer font-mono text-xs"
              title="Return to Agent Studio"
            >
              <span>← Back to Studio</span>
            </button>
          )}
          <button
            onClick={fetchRuns}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#10192a] hover:bg-[#16233b] border border-[#1e2d48] text-slate-300 transition-colors cursor-pointer text-xs font-mono"
            title="Refresh agent runs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Master-Detail Split Container */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* LEFT MASTER PANE: Agent Swarm Sessions */}
        <div className="w-80 lg:w-96 border-r border-[#161f30] bg-[#080d17] flex flex-col shrink-0 min-h-0">
          {/* Filters & Search */}
          <div className="p-3 border-b border-[#161f30] space-y-2.5 shrink-0 bg-[#080d17]">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Filter by URL or run ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-[#0e1626] border border-[#1c283f] rounded-md text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
              />
            </div>

            {/* Verdict Filter */}
            <div className="flex items-center gap-1 bg-[#0c1322] p-1 rounded-md border border-[#19243a]">
              {(['ALL', 'GO', 'CONDITIONAL_GO', 'NO_GO'] as const).map((v) => (
                <button
                  key={v}
                  onClick={() => setVerdictFilter(v)}
                  className={`flex-1 py-1 text-[10px] font-mono rounded transition-colors text-center cursor-pointer ${
                    verdictFilter === v
                      ? "bg-cyan-950/80 text-cyan-300 font-semibold border border-cyan-800/60 shadow-sm"
                      : "text-slate-400 hover:text-slate-200 hover:bg-[#141e33]"
                  }`}
                >
                  {v === 'CONDITIONAL_GO' ? 'COND' : v}
                </button>
              ))}
            </div>
          </div>

          {/* Sessions List Scroll Area */}
          <div className="flex-1 overflow-y-auto divide-y divide-[#131b2c] min-h-0">
            {isLoading && runs.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 space-y-2">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto text-cyan-400" />
                <p>Loading agent sessions...</p>
              </div>
            ) : listError ? (
              <div className="p-6 text-center text-xs text-rose-300 font-mono space-y-1" role="alert">
                <p className="font-medium">Could not load agent runs</p>
                <p className="text-[11px] break-words">{listError}</p>
              </div>
            ) : filteredRuns.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                <p className="font-medium text-slate-400">No agent runs found</p>
                <p className="mt-1 text-[11px]">Launch a swarm from Agent Studio</p>
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

                return (
                  <div
                    key={run.id}
                    onClick={() => setSelectedRunId(run.id ?? null)}
                    className={`p-3.5 cursor-pointer transition-all border-l-2 ${
                      isSelected
                        ? "bg-[#101b2f] border-l-cyan-400 shadow-[inset_0_0_12px_rgba(6,182,212,0.1)]"
                        : "border-l-transparent hover:bg-[#0c1424]"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <Radar className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                          <h4 className="text-xs font-semibold text-slate-200 truncate font-mono" title={run.target}>
                            {run.target}
                          </h4>
                        </div>
                        <div className="flex items-center gap-2 mt-1.5">
                          <span className="text-[10px] font-mono text-slate-500">#{(run.id ?? "").slice(-8)}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#131e33] text-cyan-300 border border-[#1e2e4c]">
                            {run.profile || "profile unknown"}
                          </span>
                        </div>
                      </div>
                      <div className="shrink-0 flex flex-col items-end gap-1">
                        <VerdictBadge verdict={gate} />
                        <span className="text-[11px] font-mono font-bold text-slate-200 mt-0.5">
                          {readiness === null ? <span className="text-slate-500 font-normal">not evaluated</span> : `${readiness}/100`}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between mt-2.5 pt-2 border-t border-[#162238] text-[10px] text-slate-500 font-mono">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-600" />
                        <span>{dateStr}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-400">{routesCount} routes · {casesCount} tests</span>
                        {run.requester_ip && (
                          <span className="text-[10px] text-cyan-400/90 font-mono hidden md:inline">🌐 {run.requester_ip}</span>
                        )}
                        {defectsCount > 0 && (
                          <span className="px-1.5 py-0.2 rounded bg-amber-950/70 text-amber-400 border border-amber-800/40 text-[9px] font-semibold">
                            {defectsCount} defects
                          </span>
                        )}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedRunId(run.id ?? null);
                            setShowReportModal(true);
                          }}
                          className="px-2 py-0.5 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/60 text-cyan-300 text-[10px] font-mono flex items-center gap-1 transition-colors cursor-pointer"
                          title="View Executive HTML Report"
                        >
                          <Eye className="w-2.5 h-2.5" />
                          Report
                        </button>
                        <button
                          onClick={(e) => handleDelete(run.id ?? "", e)}
                          className="text-slate-600 hover:text-red-400 transition-colors p-1 cursor-pointer"
                          title="Delete run"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* RIGHT DETAIL PANE: Swarm Session Inspector */}
        <div className="flex-1 flex flex-col bg-[#070b14] min-h-0 overflow-y-auto">
          {!selectedRunId ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-500">
              <Bot className="w-12 h-12 text-slate-700 mb-3 stroke-[1.5]" />
              <h3 className="text-base font-semibold text-slate-300">Select an Agent QA Swarm</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Choose a session on the left to inspect multi-agent test execution, reproduction cURLs, discovered attack surfaces, and sign off the gate evidence ledger.
              </p>
            </div>
          ) : !selectedRun ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-xs font-mono">
              {detailError ? (
                <p className="text-rose-300 max-w-md break-words" role="alert">{detailError}</p>
              ) : (
                <p className="text-slate-500 flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" /> Loading run details...
                </p>
              )}
            </div>
          ) : (
            <div className="p-6 space-y-5 max-w-6xl w-full mx-auto">
              {/* Hero Banner */}
              <div className="p-5 rounded-xl bg-gradient-to-br from-[#0c1527] to-[#080d19] border border-[#1b2a45] shadow-lg relative overflow-hidden">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-700/50 text-cyan-300 font-semibold uppercase tracking-wider">
                        4-Agent QA Swarm
                      </span>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#142036] border border-[#213454] text-slate-300 font-medium">
                        profile: {selectedRun.profile || "unknown"}
                      </span>
                      <VerdictBadge verdict={selectedVerdict} />
                      <span className="text-xs font-mono text-slate-500">
                        ID: {selectedRun.id}
                      </span>
                      <button
                        onClick={() => handleCopy(selectedId, "id")}
                        className="text-slate-500 hover:text-cyan-300 cursor-pointer p-0.5"
                        title="Copy Session ID"
                      >
                        {copiedId === "id" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>

                    <h2 className="text-lg font-bold text-white font-mono break-all flex items-center gap-2">
                      {selectedRun.target}
                      <button
                        onClick={() => handleCopy(selectedRun.target ?? "", "target")}
                        className="text-slate-500 hover:text-cyan-300 cursor-pointer"
                        title="Copy target URL"
                      >
                        {copiedId === "target" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </h2>

                    <div className="flex items-center gap-4 text-xs font-mono text-slate-400 pt-1 flex-wrap">
                      <span>Started: {selectedRun.started_at ? new Date(selectedRun.started_at).toLocaleString() : "-"}</span>
                      <span className="flex items-center gap-1.5 text-slate-300">
                        <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                        {selectedRun.model || "model not reported"} · {selectedRun.provider || "provider not reported"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* REQUESTER PUBLIC IP & PRIVATE NETWORK ALLOWLIST CLEARANCE */}
              <div className="p-3.5 rounded-xl bg-[#080e1c] border border-cyan-900/60 flex flex-wrap items-center justify-between gap-3 shadow-md">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400 shrink-0">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[11px] font-mono uppercase font-bold text-slate-400">
                        Requester Egress Public IP:
                      </span>
                      <span className="text-xs font-mono font-bold text-cyan-300 bg-[#0d1627] px-2 py-0.5 rounded border border-cyan-700/60">
                        {selectedRun.requester_ip || "unknown"}
                      </span>
                      {selectedRun.requester_ip_type && (
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                          {selectedRun.requester_ip_type}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      {selectedRun.requester_ip
                        ? selectedRun.allowlist_guidance ||
                          "Whitelist this IP on your target firewall, AWS Security Group, or Cloudflare WAF if testing private networks."
                        : "No requester IP was recorded for this run."}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={!selectedRun.requester_ip}
                  onClick={() => handleCopy(selectedRun.requester_ip ?? "", "ip")}
                  className="px-2.5 py-1.5 rounded text-xs font-mono bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 transition-colors flex items-center gap-1.5 cursor-pointer shrink-0 disabled:opacity-40 disabled:cursor-not-allowed"
                  title="Copy Requester Egress IP for firewall whitelisting"
                >
                  {copiedId === "ip" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedId === "ip" ? "Copied Allowlist IP" : "Copy IP"}
                </button>
              </div>

              {/* GENERATED REPORTS & EXECUTIVE ARTIFACTS ACTION BAR */}
              <div className="p-3.5 rounded-xl bg-[#090f1d] border border-cyan-800/50 flex flex-wrap items-center justify-between gap-3 shadow-lg">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                    Executive Reports & Compliance Artifacts:
                  </span>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  {onLoadRunInStudio && (
                    <button
                      onClick={() => onLoadRunInStudio(selectedRun)}
                      className="px-3 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-600/70 text-emerald-300 font-mono text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-[0_0_10px_rgba(16,185,129,0.2)]"
                      title="Load this run into Agent Studio"
                    >
                      <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                      Open in Studio
                    </button>
                  )}

                  {/* View HTML Report in Embedded Modal */}
                  <button
                    onClick={() => setShowReportModal(true)}
                    className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-semibold flex items-center gap-1.5 shadow-[0_0_12px_rgba(6,182,212,0.3)] transition-all cursor-pointer"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    View Executive Report (HTML)
                  </button>

                  {/* Open in New Tab */}
                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/html`}
                    mode="tab"
                    className="px-2.5 py-1.5 rounded-lg bg-[#111c2e] hover:bg-[#17263d] border border-[#213553] text-cyan-300 font-mono text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                    title="Open HTML report in full browser tab"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Open Tab
                  </ReportButton>

                  {/* Download Markdown Report */}
                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/markdown`}
                    mode="download"
                    filename={`readyhai-agent-report-${selectedId}.md`}
                    className="px-2.5 py-1.5 rounded-lg bg-[#111c2e] hover:bg-[#17263d] border border-[#213553] text-purple-300 hover:text-white font-mono text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                    title="Download Markdown summary for Pull Requests"
                  >
                    <FileCode className="w-3.5 h-3.5 text-purple-400" />
                    Markdown (PR)
                  </ReportButton>

                  {/* Download SARIF Report */}
                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/sarif`}
                    mode="download"
                    filename={`readyhai-agent-report-${selectedId}.sarif`}
                    className="px-2.5 py-1.5 rounded-lg bg-[#111c2e] hover:bg-[#17263d] border border-[#213553] text-amber-300 hover:text-white font-mono text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                    title="Download OASIS SARIF v2.1.0 for GitHub/GitLab Security tab"
                  >
                    <Shield className="w-3.5 h-3.5 text-amber-400" />
                    SARIF
                  </ReportButton>

                  {/* Download JSON Report */}
                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/json`}
                    mode="download"
                    filename={`readyhai-agent-report-${selectedId}.json`}
                    className="px-2.5 py-1.5 rounded-lg bg-[#111c2e] hover:bg-[#17263d] border border-[#213553] text-emerald-300 hover:text-white font-mono text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                    title="Download Complete Execution Data (JSON)"
                  >
                    <FileText className="w-3.5 h-3.5 text-emerald-400" />
                    JSON
                  </ReportButton>

                  {/* Download JUnit XML Report */}
                  <ReportButton
                    path={`/api/agent/runs/${selectedId}/report/junit`}
                    mode="download"
                    filename={`readyhai-agent-report-${selectedId}.junit.xml`}
                    className="px-2.5 py-1.5 rounded-lg bg-[#111c2e] hover:bg-[#17263d] border border-[#213553] text-sky-300 hover:text-white font-mono text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                    title="Download JUnit XML for CI/CD test results"
                  >
                    <Terminal className="w-3.5 h-3.5 text-sky-400" />
                    JUnit
                  </ReportButton>
                </div>
              </div>

              {/* KPI Cards Row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
                <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2a45] shadow-sm">
                  <div className="text-[11px] font-mono text-slate-400 uppercase">Adversarial Tests</div>
                  <div className="text-2xl font-bold font-mono text-white mt-1">
                    {allCases.length}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                    {allCases.filter(c => c.status === 'PASS').length} passing
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2a45] shadow-sm">
                  <div className="text-[11px] font-mono text-slate-400 uppercase">Discovered Routes</div>
                  <div className="text-2xl font-bold font-mono text-cyan-300 mt-1">
                    {selectedRun.discovered_routes?.length || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                    {selectedRun.discovered_routes?.filter(r => r.is_api).length || 0} APIs identified
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2a45] shadow-sm">
                  <div className="text-[11px] font-mono text-slate-400 uppercase">OWASP Defects</div>
                  <div className={`text-2xl font-bold font-mono mt-1 ${
                    (runDefectCount(selectedRun) ?? 0) > 0 ? 'text-amber-400' : isGateVerdict(selectedVerdict) ? 'text-emerald-400' : 'text-slate-300'
                  }`}>
                    {runDefectCount(selectedRun) ?? "n/a"}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">Triaged vulnerabilities</div>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2a45] shadow-sm">
                  <div className="text-[11px] font-mono text-slate-400 uppercase">Agent Steps</div>
                  <div className="text-2xl font-bold font-mono text-purple-300 mt-1">
                    {selectedRun.steps?.length || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">Supervisor/Planner traces</div>
                </div>
              </div>

              {/* Detail Tabs */}
              <div className="border-b border-[#18263e] flex items-center gap-2 overflow-x-auto">
                <button
                  onClick={() => setActiveTab("scenarios")}
                  className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer shrink-0 ${
                    activeTab === "scenarios"
                      ? "border-cyan-400 text-cyan-300 font-semibold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Sliders className="w-3.5 h-3.5" />
                  Adversarial Scenarios ({allCases.length})
                </button>
                <button
                  onClick={() => setActiveTab("ledger")}
                  className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer shrink-0 ${
                    activeTab === "ledger"
                      ? "border-cyan-400 text-cyan-300 font-semibold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Evidence Ledger (4 Pillars)
                </button>
                <button
                  onClick={() => setActiveTab("routes")}
                  className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer shrink-0 ${
                    activeTab === "routes"
                      ? "border-cyan-400 text-cyan-300 font-semibold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Radar className="w-3.5 h-3.5" />
                  Discovered Routes ({selectedRun.discovered_routes?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab("threats")}
                  className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer shrink-0 ${
                    activeTab === "threats"
                      ? "border-cyan-400 text-cyan-300 font-semibold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Threat Triage ({selectedRun.triaged_defects?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab("steps")}
                  className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer shrink-0 ${
                    activeTab === "steps"
                      ? "border-cyan-400 text-cyan-300 font-semibold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  Swarm Execution Trace ({selectedRun.steps?.length || 0})
                </button>
              </div>

              {/* TAB 1: ADVERSARIAL SCENARIOS */}
              {activeTab === "scenarios" && (
                <div className="space-y-4">
                  {/* Scenario status filters */}
                  <div className="flex items-center gap-1 bg-[#0a101d] p-1.5 rounded-lg border border-[#162238] font-mono text-xs">
                    <span className="text-slate-500 px-2">Status:</span>
                    {(['ALL', 'PASS', 'FAIL', 'WARN', 'BLOCKED', 'SKIPPED', 'PLANNED'] as const).map((s) => (
                      <button
                        key={s}
                        onClick={() => setScenarioFilter(s)}
                        className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${
                          scenarioFilter === s
                            ? "bg-cyan-950 text-cyan-300 font-semibold border border-cyan-800/60"
                            : "text-slate-400 hover:bg-[#121c2e]"
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>

                  {filteredCases.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 bg-[#0a101d] rounded-lg border border-[#162238]">
                      No test scenarios match filter.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {filteredCases.map((tc) => {
                        const isExpanded = expandedCaseId === tc.id;
                        return (
                          <div
                            key={tc.id}
                            className="rounded-xl bg-[#0c1424] border border-[#1b2b46] hover:border-[#273d63] transition-colors overflow-hidden shadow-sm"
                          >
                            <div
                              onClick={() => setExpandedCaseId(isExpanded ? null : tc.id)}
                              className="p-3.5 flex items-center justify-between gap-3 cursor-pointer select-none"
                            >
                              <div className="flex items-center gap-3 min-w-0">
                                <span className="font-mono text-xs font-bold text-cyan-400 w-16 shrink-0">
                                  {tc.id}
                                </span>
                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase shrink-0 ${
                                  tc.method === 'POST' ? 'bg-indigo-950 text-indigo-300 border border-indigo-700/50' :
                                  tc.method === 'PUT' ? 'bg-amber-950 text-amber-300 border border-amber-700/50' :
                                  tc.method === 'DELETE' ? 'bg-red-950 text-red-300 border border-red-700/50' :
                                  'bg-emerald-950 text-emerald-300 border border-emerald-700/50'
                                }`}>
                                  {tc.method}
                                </span>
                                <div className="min-w-0">
                                  <div className="text-xs font-mono font-semibold text-slate-200 truncate">
                                    {tc.title}
                                  </div>
                                  <div className="text-[11px] font-mono text-slate-500 truncate mt-0.5">
                                    {tc.component} · technique: {tc.technique}
                                  </div>
                                </div>
                              </div>

                              <div className="flex items-center gap-3 shrink-0">
                                {tc.latency_ms != null && tc.latency_ms > 0 && (
                                  <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
                                    {tc.latency_ms}ms
                                  </span>
                                )}
                                {getCaseStatusBadge(tc.status)}
                                {isExpanded ? (
                                  <ChevronUp className="w-4 h-4 text-slate-500" />
                                ) : (
                                  <ChevronDown className="w-4 h-4 text-slate-500" />
                                )}
                              </div>
                            </div>

                            {/* Expanded Details */}
                            {isExpanded && (
                              <div className="p-4 pt-1 border-t border-[#162238] bg-[#090e1a] space-y-3 font-mono text-xs">
                                {tc.assertion_details && (
                                  <div>
                                    <span className="text-[11px] text-slate-500 uppercase font-semibold">Expected Behavior:</span>
                                    <p className="text-slate-300 mt-0.5">{tc.assertion_details}</p>
                                  </div>
                                )}

                                {tc.curl && (
                                  <div>
                                    <div className="flex items-center justify-between text-[11px] text-slate-500 uppercase font-semibold mb-1">
                                      <span>Reproduction cURL:</span>
                                      <button
                                        onClick={() => handleCopy(tc.curl, tc.id + "-curl")}
                                        className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 cursor-pointer"
                                      >
                                        {copiedId === tc.id + "-curl" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                        Copy cURL
                                      </button>
                                    </div>
                                    <pre className="p-2.5 rounded bg-[#060a12] border border-[#16243a] text-cyan-300/90 overflow-x-auto">
                                      {tc.curl}
                                    </pre>
                                  </div>
                                )}

                                {tc.response_body && (
                                  <div>
                                    <span className="text-[11px] text-slate-500 uppercase font-semibold">Response Body Snippet:</span>
                                    <pre className="p-2.5 rounded bg-[#060a12] border border-[#16243a] text-slate-300 overflow-x-auto max-h-48 mt-1">
                                      {tc.response_body}
                                    </pre>
                                  </div>
                                )}

                                {onRetestCase && (
                                  <div className="pt-1 flex justify-end">
                                    <button
                                      onClick={() => onRetestCase(tc)}
                                      className="flex items-center gap-1.5 px-3 py-1 rounded bg-[#132238] hover:bg-cyan-950 border border-[#203658] hover:border-cyan-600/60 text-cyan-300 text-xs font-mono transition-colors cursor-pointer"
                                    >
                                      <RotateCw className="w-3 h-3" />
                                      Retest Adversarial Case
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

              {/* TAB 2: EVIDENCE LEDGER (4 PILLARS) */}
              {activeTab === "ledger" && (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-[#0c1424] border border-[#1b2b46] flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <VerdictBadge verdict={selectedVerdict} />
                      <span className="text-xs font-mono text-slate-400">
                        Composite score:{" "}
                        {ledgerScore(selectedLedger) === null || selectedVerdict === "SCANNED" ? (
                          <span className="text-slate-500">not evaluated</span>
                        ) : (
                          <span className="text-cyan-300 font-bold">{ledgerScore(selectedLedger)}/100</span>
                        )}
                      </span>
                    </div>
                    {selectedLedger?.executive_summary && (
                      <p className="text-xs text-slate-300 w-full leading-relaxed">{selectedLedger.executive_summary}</p>
                    )}
                    {!selectedLedger && (
                      <p className="text-xs text-slate-500 w-full font-mono">
                        This run has no evidence ledger: it was not evaluated.
                      </p>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {selectedPillars.map((pillar, idx) => (
                      <div key={pillar.key} className="p-4 rounded-xl bg-[#0c1424] border border-[#1b2b46] space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono font-bold text-slate-200 uppercase">
                            {idx + 1}. {pillar.short}
                          </span>
                          {pillar.status && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-300 border border-slate-700 uppercase">
                              {pillar.status}
                            </span>
                          )}
                        </div>
                        {pillar.score === null ? (
                          <div className="text-sm font-mono text-slate-500">not evaluated</div>
                        ) : (
                          <div className="text-2xl font-bold font-mono text-cyan-300">{pillar.score}/100</div>
                        )}
                        <p className="text-xs font-mono text-slate-400">
                          {pillar.evidence ?? "No evidence text was reported for this pillar."}
                        </p>
                      </div>
                    ))}
                  </div>

                  {selectedLedger?.exit_criteria_checklist && selectedLedger.exit_criteria_checklist.length > 0 && (
                    <div className="p-4 rounded-xl bg-[#0c1424] border border-[#1b2b46] space-y-1.5">
                      <span className="text-xs font-mono font-bold text-slate-200 uppercase">Exit criteria</span>
                      {selectedLedger.exit_criteria_checklist.map((c, i) => (
                        <div key={i} className="flex items-start gap-2 text-[11px] font-mono">
                          <span className={c.met ? "text-emerald-400" : "text-rose-400"}>{c.met ? "met" : "NOT MET"}</span>
                          <span className="text-slate-200">{c.criterion}</span>
                          {c.details && <span className="text-slate-500">- {c.details}</span>}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Sign-off Form */}
                  <div className="p-5 rounded-xl bg-[#0c1424] border border-[#1b2b46] space-y-3">
                    <h4 className="text-xs font-mono font-bold text-white uppercase flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-cyan-400" />
                      Production Gate Sign-off Certificate
                    </h4>
                    {(() => {
                      const status = (selectedRun.approval_status || "").toLowerCase();
                      if (status === "approved" || status === "rejected") {
                        return (
                          <div className="p-3 bg-[#090e1a] rounded-lg border border-[#162033] text-xs font-mono text-slate-300">
                            {status === "approved" ? "Approved" : "Rejected"} by{" "}
                            <strong className="text-cyan-300">{selectedRun.approved_by || "unknown operator"}</strong>
                            {selectedRun.approval_notes ? ` · ${selectedRun.approval_notes}` : ""}
                          </div>
                        );
                      }
                      return (
                        <>
                          {!isGateVerdict(selectedVerdict) && (
                            <p className="text-[11px] font-mono text-amber-300">
                              The backend reported no gate verdict for this run, so it cannot be approved.
                            </p>
                          )}
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                            <div>
                              <label className="text-slate-400 block mb-1">Operator / Role (required):</label>
                              <input
                                type="text"
                                value={operatorName}
                                onChange={(e) => setOperatorName(e.target.value)}
                                className="w-full px-3 py-1.5 rounded bg-[#090e1a] border border-[#1d2d46] text-slate-200 focus:outline-none focus:border-cyan-500/60"
                              />
                            </div>
                            <div>
                              <label className="text-slate-400 block mb-1">Audit Notes:</label>
                              <input
                                type="text"
                                value={approvalNotes}
                                onChange={(e) => setApprovalNotes(e.target.value)}
                                className="w-full px-3 py-1.5 rounded bg-[#090e1a] border border-[#1d2d46] text-slate-200 focus:outline-none focus:border-cyan-500/60"
                              />
                            </div>
                          </div>
                          {signOffError && (
                            <p className="text-xs font-mono text-rose-300 break-words" role="alert">
                              {signOffError}
                            </p>
                          )}
                          <div className="pt-2 flex items-center justify-end gap-2.5">
                            <button
                              onClick={() => handleSignOff("reject")}
                              disabled={isSigning || !operatorName.trim()}
                              className="px-4 py-1.5 rounded bg-red-950/80 hover:bg-red-900 border border-red-700/60 text-red-300 text-xs font-mono font-semibold cursor-pointer transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                              Reject Gate
                            </button>
                            <button
                              onClick={() => handleSignOff("approve")}
                              disabled={isSigning || !operatorName.trim() || !isGateVerdict(selectedVerdict)}
                              title={isGateVerdict(selectedVerdict) ? undefined : "No backend gate verdict: approval is unavailable"}
                              className="px-5 py-1.5 rounded bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-mono font-semibold shadow-md cursor-pointer transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                              Approve Production Gate
                            </button>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* TAB 3: DISCOVERED ROUTES */}
              {activeTab === "routes" && (
                <div className="rounded-xl bg-[#0c1424] border border-[#1b2b46] overflow-hidden shadow-sm font-mono text-xs">
                  <div className="px-4 py-3 bg-[#0f192d] border-b border-[#1b2b46] flex items-center justify-between text-slate-300 font-semibold">
                    <span>Endpoint Path</span>
                    <div className="flex items-center gap-6">
                      <span>Method</span>
                      <span>Status</span>
                      <span>Classification</span>
                    </div>
                  </div>
                  <div className="divide-y divide-[#152238]">
                    {selectedRun.discovered_routes?.map((r, idx) => (
                      <div key={r.path + idx} className="p-3.5 flex items-center justify-between gap-4 hover:bg-[#0e172a] transition-colors">
                        <span className="text-slate-200 font-medium truncate">{r.path}</span>
                        <div className="flex items-center gap-6 shrink-0">
                          <span className="text-cyan-400 font-semibold w-12 text-right">{r.method}</span>
                          <span className="text-slate-400 w-12 text-right">{r.status_code ?? "n/a"}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-semibold ${
                            r.is_api ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/40' : 'bg-purple-950 text-purple-300 border border-purple-800/40'
                          }`}>
                            {r.is_api ? 'API Route' : r.is_spa_shell ? 'SPA Shell' : 'Route'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 4: THREAT TRIAGE */}
              {activeTab === "threats" && (
                <div className="space-y-3">
                  {(!selectedRun.triaged_defects || selectedRun.triaged_defects.length === 0) ? (
                    <div className="p-8 text-center text-xs text-slate-500 bg-[#0a101d] rounded-lg border border-[#162238] font-mono">
                      {selectedLedger
                        ? "The backend triaged no defects for this session."
                        : "This run was not evaluated, so there are no triaged defects to show."}
                    </div>
                  ) : (
                    selectedRun.triaged_defects.map((d, idx) => (
                      <div key={d.case_id || d.id || idx} className="p-4 rounded-xl bg-[#0c1424] border border-[#1b2b46] space-y-2 font-mono text-xs">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-950 text-amber-400 border border-amber-600/50">
                              {d.severity}
                            </span>
                            <span className="text-cyan-400 font-semibold">{d.owasp_category}</span>
                          </div>
                          <span className="text-slate-500 text-[11px]">#{d.case_id || d.id}</span>
                        </div>
                        <h4 className="text-sm font-semibold text-slate-100">{d.title}</h4>
                        {d.evidence_snippet && (
                          <div className="p-2 rounded bg-[#090e1a] border border-[#152136] text-slate-300 whitespace-pre-wrap">
                            {d.evidence_snippet}
                          </div>
                        )}
                        {(d.remediation_patch_suggestion || d.recommended_fix) && (
                          <div className="p-2 rounded bg-emerald-950/20 border border-emerald-900/40 text-emerald-300">
                            <span className="font-bold">Patch suggestion: </span>
                            {d.remediation_patch_suggestion || d.recommended_fix}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* TAB 5: SWARM TRACE STEPS */}
              {activeTab === "steps" && (
                <div className="rounded-xl bg-[#0c1424] border border-[#1b2b46] divide-y divide-[#152238] overflow-hidden font-mono text-xs">
                  {selectedRun.steps?.map((st, idx) => (
                    <div key={st.timestamp + idx} className="p-3.5 flex items-start gap-3 hover:bg-[#0e172a] transition-colors">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 bg-[#121c2e] text-cyan-300 border border-[#1f2e4a]">
                        {st.agent}
                      </span>
                      <div className="min-w-0 flex-1 space-y-0.5">
                        <div className="font-semibold text-slate-200 flex items-center justify-between">
                          <span>{st.action}</span>
                          <span className="text-[10px] text-slate-500 font-normal">
                            {st.timestamp ? new Date(st.timestamp).toLocaleTimeString() : "-"}
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px]">{st.details}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      {/* EMBEDDED HTML REPORT FULLSCREEN MODAL */}
      {showReportModal && selectedRun && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b101b] border border-[#1e2f4a] rounded-xl w-full max-w-5xl h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-[#1b2b46] flex items-center justify-between bg-[#0e172a]">
              <div className="flex items-center gap-2.5">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-bold text-white font-mono">
                  ReadyHai Executive QA & Security Gate Report (HTML)
                </span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {selectedId}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <ReportButton
                  path={`/api/agent/runs/${selectedId}/report/html`}
                  mode="tab"
                  className="px-2.5 py-1 rounded bg-[#16233a] hover:bg-[#1f304f] border border-[#273d63] text-cyan-300 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                  title="Open report in new browser tab"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  New Tab
                </ReportButton>
                <ReportButton
                  path={`/api/agent/runs/${selectedId}/report/markdown`}
                  mode="download"
                  filename={`readyhai-agent-report-${selectedId}.md`}
                  className="px-2.5 py-1 rounded bg-[#16233a] hover:bg-[#1f304f] border border-[#273d63] text-purple-300 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                  title="Download Markdown summary"
                >
                  <FileCode className="w-3.5 h-3.5" />
                  Markdown
                </ReportButton>
                <button
                  onClick={() => setShowReportModal(false)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[#16233a] transition-colors cursor-pointer"
                  title="Close report modal"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="flex-1 w-full h-full bg-[#070b14] relative">
              <ReportFrame
                path={`/api/agent/runs/${selectedId}/report/html`}
                title="ReadyHai Executive QA Report"
                className="w-full h-full border-0"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}