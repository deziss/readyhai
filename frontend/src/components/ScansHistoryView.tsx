"use client";

import { useState, useEffect, useMemo } from "react";
import {
  ShieldCheck,
  AlertTriangle,
  XCircle,
  CheckCircle2,
  FileCode2,
  Download,
  ExternalLink,
  Search,
  RefreshCw,
  Trash2,
  Copy,
  Check,
  Maximize2,
  X,
  FileText,
  Clock,
  Layers,
  GitBranch,
  Box,
  Terminal,
} from "lucide-react";
import type { ScanSummary, ScanDetail } from "@/types/scans";

interface ScansHistoryViewProps {
  onSelectTarget?: (target: string) => void;
}

export function ScansHistoryView({ onSelectTarget }: ScansHistoryViewProps) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [selectedScanDetail, setSelectedScanDetail] = useState<ScanDetail | null>(null);
  const [isLoadingList, setIsLoadingList] = useState(true);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<"ALL" | "PASS" | "WARN" | "FAIL">("ALL");
  const [kindFilter, setKindFilter] = useState<string>("ALL");
  const [activeTab, setActiveTab] = useState<"findings" | "checks" | "raw">("findings");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [findingSearch, setFindingSearch] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showHtmlModal, setShowHtmlModal] = useState(false);

  // Fetch scans list
  const fetchScans = async () => {
    setIsLoadingList(true);
    try {
      const res = await fetch("/api/scans");
      if (res.ok) {
        const data = await res.json();
        const list: ScanSummary[] = data.scans || [];
        setScans(list);
        if (list.length > 0 && !selectedScanId) {
          setSelectedScanId(list[0].id);
        }
      }
    } catch (e) {
      console.error("Failed to fetch scans:", e);
    } finally {
      setIsLoadingList(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  // Fetch scan detail when selectedScanId changes
  useEffect(() => {
    if (!selectedScanId) {
      setSelectedScanDetail(null);
      return;
    }
    let isCancelled = false;
    const fetchDetail = async () => {
      setIsLoadingDetail(true);
      try {
        const res = await fetch(`/api/scans/${selectedScanId}`);
        if (res.ok) {
          const data: ScanDetail = await res.json();
          if (!isCancelled) {
            setSelectedScanDetail(data);
          }
        }
      } catch (e) {
        console.error("Failed to fetch scan detail:", e);
      } finally {
        if (!isCancelled) setIsLoadingDetail(false);
      }
    };
    fetchDetail();
    return () => {
      isCancelled = true;
    };
  }, [selectedScanId]);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete scan session ${id}?`)) return;
    try {
      const res = await fetch(`/api/scans/${id}`, { method: "DELETE" });
      if (res.ok) {
        setScans((prev) => prev.filter((s) => s.id !== id));
        if (selectedScanId === id) {
          const remaining = scans.filter((s) => s.id !== id);
          setSelectedScanId(remaining.length > 0 ? remaining[0].id : null);
        }
      }
    } catch (err) {
      console.error("Failed to delete scan:", err);
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredScans = useMemo(() => {
    return scans.filter((s) => {
      if (verdictFilter !== "ALL" && s.verdict !== verdictFilter) return false;
      if (kindFilter !== "ALL" && s.kind !== kindFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTarget = s.target.toLowerCase().includes(q);
        const matchId = s.id.toLowerCase().includes(q);
        if (!matchTarget && !matchId) return false;
      }
      return true;
    });
  }, [scans, verdictFilter, kindFilter, searchQuery]);

  const filteredFindings = useMemo(() => {
    if (!selectedScanDetail?.findings) return [];
    return selectedScanDetail.findings.filter((f) => {
      if (severityFilter !== "ALL" && f.severity?.toLowerCase() !== severityFilter.toLowerCase()) {
        return false;
      }
      if (categoryFilter !== "ALL" && f.category?.toLowerCase() !== categoryFilter.toLowerCase()) {
        return false;
      }
      if (findingSearch.trim()) {
        const q = findingSearch.toLowerCase();
        const matchTitle = f.title?.toLowerCase().includes(q);
        const matchRule = f.rule?.toLowerCase().includes(q);
        const matchLoc = f.location?.toLowerCase().includes(q);
        const matchDet = f.detail?.toLowerCase().includes(q);
        if (!matchTitle && !matchRule && !matchLoc && !matchDet) return false;
      }
      return true;
    });
  }, [selectedScanDetail, severityFilter, categoryFilter, findingSearch]);

  const availableCategories = useMemo(() => {
    if (!selectedScanDetail?.findings) return [];
    const set = new Set<string>();
    for (const f of selectedScanDetail.findings) {
      if (f.category) set.add(f.category);
    }
    return Array.from(set);
  }, [selectedScanDetail]);

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case "PASS":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-500/40">
            <CheckCircle2 className="w-3 h-3" /> PASS
          </span>
        );
      case "WARN":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-400 border border-amber-500/40">
            <AlertTriangle className="w-3 h-3" /> WARN
          </span>
        );
      case "FAIL":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950/80 text-red-400 border border-red-500/40">
            <XCircle className="w-3 h-3" /> FAIL
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-900 text-slate-400 border border-slate-700">
            {verdict || "UNKNOWN"}
          </span>
        );
    }
  };

  const getSeverityBadge = (severity?: string) => {
    const s = (severity || "low").toLowerCase();
    switch (s) {
      case "critical":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-950/90 text-red-400 border border-red-600/60">
            Critical
          </span>
        );
      case "high":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-orange-950/90 text-orange-400 border border-orange-500/50">
            High
          </span>
        );
      case "medium":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-950/90 text-amber-400 border border-amber-500/50">
            Medium
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-900 text-slate-400 border border-slate-700">
            {severity || "Low"}
          </span>
        );
    }
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-[#06080e] overflow-hidden">
      {/* Top Breadcrumb & Status Subbar */}
      <div className="h-11 px-6 border-b border-[#161f30] bg-[#0a0f1b] flex items-center justify-between text-xs text-slate-400 shrink-0">
        <div className="flex items-center gap-2 font-mono">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <span className="text-slate-200 font-semibold">Security & Codebase Audits</span>
          <span className="text-slate-600">/</span>
          <span>Static Scans & SAST Sessions</span>
          <span className="ml-2 px-2 py-0.5 rounded-full bg-cyan-950/60 text-cyan-300 border border-cyan-800/40 text-[11px]">
            {scans.length} Sessions Recorded
          </span>
        </div>
        <button
          onClick={fetchScans}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#10192a] hover:bg-[#16233b] border border-[#1e2d48] text-slate-300 transition-colors cursor-pointer"
          title="Refresh scans"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoadingList ? "animate-spin text-cyan-400" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Master-Detail Split Container */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* LEFT MASTER PANE: Sessions List */}
        <div className="w-80 lg:w-96 border-r border-[#161f30] bg-[#080d17] flex flex-col shrink-0 min-h-0">
          {/* Filters & Search Header */}
          <div className="p-3 border-b border-[#161f30] space-y-2.5 shrink-0 bg-[#080d17]">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Filter by repo or run ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-[#0e1626] border border-[#1c283f] rounded-md text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
              />
            </div>

            {/* Verdict Filter Buttons */}
            <div className="flex items-center gap-1 bg-[#0c1322] p-1 rounded-md border border-[#19243a]">
              {(['ALL', 'PASS', 'WARN', 'FAIL'] as const).map((v) => (
                <button
                  key={v}
                  onClick={() => setVerdictFilter(v)}
                  className={`flex-1 py-1 text-[11px] font-mono rounded transition-colors text-center cursor-pointer ${
                    verdictFilter === v
                      ? "bg-cyan-950/80 text-cyan-300 font-semibold border border-cyan-800/60 shadow-sm"
                      : "text-slate-400 hover:text-slate-200 hover:bg-[#141e33]"
                  }`}
                >
                  {v}
                </button>
              ))}
            </div>

            {/* Kind Filter */}
            <div className="flex items-center gap-1 text-[11px] font-mono text-slate-400 overflow-x-auto pb-0.5">
              <span className="text-slate-500 pl-0.5">Type:</span>
              {(['ALL', 'repo', 'image', 'host'] as const).map((k) => (
                <button
                  key={k}
                  onClick={() => setKindFilter(k)}
                  className={`px-2 py-0.5 rounded text-[10px] uppercase cursor-pointer ${
                    kindFilter === k
                      ? "bg-[#18263e] text-cyan-300 border border-cyan-700/50"
                      : "hover:bg-[#111a2d] text-slate-400"
                  }`}
                >
                  {k}
                </button>
              ))}
            </div>
          </div>

          {/* Sessions List Scroll Area */}
          <div className="flex-1 overflow-y-auto divide-y divide-[#131b2c] min-h-0">
            {isLoadingList && scans.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 space-y-2">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto text-cyan-400" />
                <p>Loading scan sessions...</p>
              </div>
            ) : filteredScans.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                <p className="font-medium text-slate-400">No scan sessions found</p>
                <p className="mt-1 text-[11px]">Try adjusting your search query or filters</p>
              </div>
            ) : (
              filteredScans.map((scan) => {
                const isSelected = selectedScanId === scan.id;
                const dateStr = scan.started ? new Date(scan.started).toLocaleString() : "Unknown";
                const isGit = scan.target.includes("github.com") || scan.target.includes("git:");
                const displayName = scan.target.replace(/^git:/, "").replace(/^https?:\/\//, "");

                return (
                  <div
                    key={scan.id}
                    onClick={() => setSelectedScanId(scan.id)}
                    className={`p-3.5 cursor-pointer transition-all border-l-2 ${
                      isSelected
                        ? "bg-[#101b2f] border-l-cyan-400 shadow-[inset_0_0_12px_rgba(6,182,212,0.1)]"
                        : "border-l-transparent hover:bg-[#0c1424]"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          {isGit ? (
                            <GitBranch className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                          ) : (
                            <Box className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          )}
                          <h4 className="text-xs font-semibold text-slate-200 truncate font-mono" title={scan.target}>
                            {displayName}
                          </h4>
                        </div>
                        <div className="flex items-center gap-2 mt-1.5">
                          <span className="text-[10px] font-mono text-slate-500">#{scan.id.slice(-8)}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#131e33] text-slate-400 border border-[#1e2e4c]">
                            {scan.kind}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#131e33] text-slate-400 border border-[#1e2e4c]">
                            {scan.profile}
                          </span>
                        </div>
                      </div>
                      <div className="shrink-0 flex flex-col items-end gap-1">
                        {getVerdictBadge(scan.verdict)}
                        <span className="text-[10px] font-mono text-slate-400 mt-0.5">
                          {scan.findings_count} findings
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between mt-2.5 pt-2 border-t border-[#162238] text-[10px] text-slate-500 font-mono">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-600" />
                        <span>{dateStr}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        {scan.hard_fail_count > 0 && (
                          <span className="px-1.5 py-0.2 rounded bg-red-950/70 text-red-400 border border-red-800/40 text-[9px] font-semibold">
                            {scan.hard_fail_count} CRITICAL
                          </span>
                        )}
                        <button
                          onClick={(e) => handleDelete(scan.id, e)}
                          className="text-slate-600 hover:text-red-400 transition-colors p-1 cursor-pointer"
                          title="Delete scan"
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

        {/* RIGHT DETAIL PANE: Scan Inspector & Generated Reports */}
        <div className="flex-1 flex flex-col bg-[#070b14] min-h-0 overflow-y-auto">
          {!selectedScanId ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-500">
              <ShieldCheck className="w-12 h-12 text-slate-700 mb-3 stroke-[1.5]" />
              <h3 className="text-base font-semibold text-slate-300">Select a Scan Session</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Choose a session from the list on the left to inspect SAST findings, dependency audits, security checks, and download generated SARIF/HTML reports.
              </p>
            </div>
          ) : isLoadingDetail && !selectedScanDetail ? (
            <div className="flex-1 flex items-center justify-center p-8">
              <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            </div>
          ) : selectedScanDetail ? (
            <div className="p-6 space-y-5 max-w-6xl w-full mx-auto">
              {/* Top Hero Banner */}
              <div className="p-5 rounded-xl bg-gradient-to-br from-[#0c1527] to-[#080d19] border border-[#1b2a45] shadow-lg relative overflow-hidden">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-700/50 text-cyan-300 font-semibold uppercase tracking-wider">
                        {selectedScanDetail.target.kind || "repo"} audit
                      </span>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#142036] border border-[#213454] text-slate-300 font-medium">
                        profile: {selectedScanDetail.profile}
                      </span>
                      <span className="text-xs font-mono text-slate-500">
                        ID: {selectedScanDetail.id}
                      </span>
                      <button
                        onClick={() => handleCopy(selectedScanDetail.id, "id")}
                        className="text-slate-500 hover:text-cyan-300 cursor-pointer p-0.5"
                        title="Copy Session ID"
                      >
                        {copiedId === "id" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>

                    <h2 className="text-lg font-bold text-white font-mono break-all flex items-center gap-2">
                      {selectedScanDetail.target.raw}
                      <button
                        onClick={() => handleCopy(selectedScanDetail.target.raw, "target")}
                        className="text-slate-500 hover:text-cyan-300 cursor-pointer"
                        title="Copy target URL"
                      >
                        {copiedId === "target" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </h2>

                    <div className="flex items-center gap-4 text-xs font-mono text-slate-400 pt-1 flex-wrap">
                      <span>Started: {selectedScanDetail.started ? new Date(selectedScanDetail.started).toLocaleString() : "-"}</span>
                      {selectedScanDetail.finished && (
                        <span>Finished: {new Date(selectedScanDetail.finished).toLocaleTimeString()}</span>
                      )}
                    </div>
                  </div>

                  <div className="shrink-0 flex flex-col items-start md:items-end gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400">Verdict:</span>
                      {getVerdictBadge(selectedScanDetail.verdict)}
                    </div>
                    {selectedScanDetail.reasons && selectedScanDetail.reasons.length > 0 && (
                      <div className="text-[11px] font-mono text-amber-300/90 bg-amber-950/40 border border-amber-800/40 px-2.5 py-1 rounded-md max-w-xs text-right">
                        {selectedScanDetail.reasons.join(", ")}
                      </div>
                    )}
                  </div>
                </div>

                {/* GENERATED REPORTS ACTION BAR (PRIMARY FEATURE) */}
                <div className="mt-5 pt-4 border-t border-[#182640] flex flex-wrap items-center justify-between gap-3 bg-[#0a1222]/80 -mx-5 -mb-5 px-5 py-3">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold text-slate-200 tracking-wide uppercase font-mono">
                      Generated Reports & Artifacts:
                    </span>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    {/* View HTML Report */}
                    <button
                      onClick={() => setShowHtmlModal(true)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-950/40 transition-all cursor-pointer"
                    >
                      <Maximize2 className="w-3.5 h-3.5" />
                      View HTML Report
                    </button>

                    {/* Download SARIF 2.1.0 */}
                    <a
                      href={`/api/scans/${selectedScanDetail.id}/report/sarif`}
                      download={`readyhai-${selectedScanDetail.id}.sarif`}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#14223b] hover:bg-[#1a2d4f] border border-[#233a63] text-cyan-300 text-xs font-mono font-medium transition-colors cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-cyan-400" />
                      SARIF 2.1.0
                    </a>

                    {/* Download JSON */}
                    <a
                      href={`/api/scans/${selectedScanDetail.id}/report/json`}
                      download={`readyhai-${selectedScanDetail.id}.json`}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#14223b] hover:bg-[#1a2d4f] border border-[#233a63] text-slate-200 text-xs font-mono font-medium transition-colors cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-slate-400" />
                      JSON
                    </a>

                    {/* Download JUnit XML */}
                    <a
                      href={`/api/scans/${selectedScanDetail.id}/report/junit`}
                      download={`readyhai-${selectedScanDetail.id}.junit.xml`}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#14223b] hover:bg-[#1a2d4f] border border-[#233a63] text-slate-200 text-xs font-mono font-medium transition-colors cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-slate-400" />
                      JUnit XML
                    </a>

                    {/* Direct Tab Link */}
                    <a
                      href={`/api/scans/${selectedScanDetail.id}/report/html`}
                      target="_blank"
                      rel="noreferrer"
                      className="p-1.5 rounded-lg bg-[#14223b] hover:bg-[#1a2d4f] border border-[#233a63] text-slate-400 hover:text-white transition-colors cursor-pointer"
                      title="Open HTML Report in new tab"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                </div>
              </div>

              {/* KPI Cards Row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
                <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2a45] shadow-sm">
                  <div className="text-[11px] font-mono text-slate-400 uppercase">Total Findings</div>
                  <div className="text-2xl font-bold font-mono text-white mt-1">
                    {selectedScanDetail.findings?.length || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">Identified defects</div>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2a45] shadow-sm">
                  <div className="text-[11px] font-mono text-slate-400 uppercase">Critical / Hard Fails</div>
                  <div className={`text-2xl font-bold font-mono mt-1 ${
                    (selectedScanDetail.findings?.filter(f => f.severity === 'critical').length || 0) > 0 ? 'text-red-400' : 'text-emerald-400'
                  }`}>
                    {selectedScanDetail.findings?.filter(f => f.severity === 'critical').length || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">Gate blockers</div>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2a45] shadow-sm">
                  <div className="text-[11px] font-mono text-slate-400 uppercase">Security Checks</div>
                  <div className="text-2xl font-bold font-mono text-cyan-300 mt-1">
                    {selectedScanDetail.checks?.length || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                    {selectedScanDetail.checks?.filter(c => c.status.state === 'passed').length || 0} passed
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0c1424] border border-[#1b2a45] shadow-sm">
                  <div className="text-[11px] font-mono text-slate-400 uppercase">Categories Scanned</div>
                  <div className="text-2xl font-bold font-mono text-purple-300 mt-1">
                    {selectedScanDetail.categories?.length || availableCategories.length || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">SAST, Secrets, Deps...</div>
                </div>
              </div>

              {/* Detail Navigation Tabs */}
              <div className="border-b border-[#18263e] flex items-center gap-2">
                <button
                  onClick={() => setActiveTab("findings")}
                  className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer ${
                    activeTab === "findings"
                      ? "border-cyan-400 text-cyan-300 font-semibold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Findings & Vulnerabilities ({selectedScanDetail.findings?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab("checks")}
                  className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer ${
                    activeTab === "checks"
                      ? "border-cyan-400 text-cyan-300 font-semibold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" />
                  Check Execution Grid ({selectedScanDetail.checks?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab("raw")}
                  className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors cursor-pointer ${
                    activeTab === "raw"
                      ? "border-cyan-400 text-cyan-300 font-semibold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  Raw JSON Payload
                </button>
              </div>

              {/* TAB 1: FINDINGS EXPLORER */}
              {activeTab === "findings" && (
                <div className="space-y-4">
                  {/* Filters Bar */}
                  <div className="p-3 rounded-lg bg-[#0a101d] border border-[#162238] flex flex-wrap items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-2 flex-1 min-w-[200px]">
                      <Search className="w-3.5 h-3.5 text-slate-500" />
                      <input
                        type="text"
                        placeholder="Search findings by rule, title, or file location..."
                        value={findingSearch}
                        onChange={(e) => setFindingSearch(e.target.value)}
                        className="w-full bg-transparent border-0 text-slate-200 placeholder-slate-500 focus:outline-none font-mono text-xs"
                      />
                    </div>

                    <div className="flex items-center gap-2 flex-wrap font-mono text-[11px]">
                      {/* Severity pills */}
                      <span className="text-slate-500">Severity:</span>
                      {(['ALL', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
                        <button
                          key={sev}
                          onClick={() => setSeverityFilter(sev)}
                          className={`px-2 py-0.5 rounded uppercase cursor-pointer ${
                            severityFilter === sev
                              ? "bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-semibold"
                              : "bg-[#111a2c] text-slate-400 hover:bg-[#16243d]"
                          }`}
                        >
                          {sev}
                        </button>
                      ))}

                      {/* Category filter */}
                      {availableCategories.length > 0 && (
                        <div className="flex items-center gap-1.5 pl-2 border-l border-[#1a2842]">
                          <span className="text-slate-500">Category:</span>
                          <select
                            value={categoryFilter}
                            onChange={(e) => setCategoryFilter(e.target.value)}
                            className="bg-[#111a2c] border border-[#1f3050] text-slate-300 rounded px-2 py-0.5 text-[11px] focus:outline-none cursor-pointer"
                          >
                            <option value="ALL">ALL CATEGORIES</option>
                            {availableCategories.map((c) => (
                              <option key={c} value={c}>{c.toUpperCase()}</option>
                            ))}
                          </select>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Findings Cards List */}
                  {filteredFindings.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 bg-[#0a101d] rounded-lg border border-[#162238]">
                      No findings match current filters.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {filteredFindings.map((f, idx) => (
                        <div
                          key={f.fingerprint || f.rule + idx}
                          className="p-4 rounded-xl bg-[#0c1424] border border-[#1b2b46] hover:border-[#273d63] transition-colors space-y-2.5 shadow-sm"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="space-y-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                {getSeverityBadge(f.severity)}
                                <span className="font-mono text-xs text-cyan-400 font-semibold">
                                  {f.rule}
                                </span>
                                <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-[#131f36] text-slate-400 border border-[#1e3052]">
                                  {f.category}
                                </span>
                                {f.check && (
                                  <span className="font-mono text-[10px] text-slate-500">
                                    via {f.check}
                                  </span>
                                )}
                              </div>
                              <h4 className="text-sm font-semibold text-slate-100 font-mono mt-1">
                                {f.title}
                              </h4>
                            </div>

                            {f.location && (
                              <div className="shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#101c30] border border-[#1d3154] text-xs font-mono text-cyan-300 max-w-xs truncate">
                                <FileCode2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                                <span className="truncate" title={f.location}>{f.location}</span>
                              </div>
                            )}
                          </div>

                          {f.detail && (
                            <div className="p-2.5 rounded bg-[#090e1a] border border-[#152136] text-xs font-mono text-slate-300 whitespace-pre-wrap">
                              {f.detail}
                            </div>
                          )}

                          {f.remediation && (
                            <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-900/40 text-xs font-mono text-emerald-300 flex items-start gap-2">
                              <span className="text-emerald-500 font-bold shrink-0">Remediation:</span>
                              <span className="text-slate-300">{f.remediation}</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: CHECKS EXECUTION GRID */}
              {activeTab === "checks" && (
                <div className="rounded-xl bg-[#0c1424] border border-[#1b2b46] overflow-hidden shadow-sm">
                  <div className="px-4 py-3 bg-[#0f192d] border-b border-[#1b2b46] flex items-center justify-between text-xs font-mono text-slate-300 font-semibold">
                    <span>Security Check Name</span>
                    <div className="flex items-center gap-6">
                      <span>Duration</span>
                      <span>Findings</span>
                      <span>Execution State</span>
                    </div>
                  </div>
                  <div className="divide-y divide-[#152238]">
                    {selectedScanDetail.checks?.map((chk) => {
                      const state = chk.status?.state || "unknown";
                      const isPassed = state === "passed";
                      const isFailed = state === "failed";
                      return (
                        <div key={chk.id} className="p-3.5 flex items-center justify-between gap-4 text-xs font-mono hover:bg-[#0e172a] transition-colors">
                          <div className="space-y-0.5 min-w-0">
                            <div className="font-semibold text-slate-200 flex items-center gap-2">
                              <span>{chk.title}</span>
                              <span className="text-[10px] text-slate-500">({chk.id})</span>
                            </div>
                            {chk.status?.reason && (
                              <div className="text-[11px] text-slate-500">Reason: {chk.status.reason}</div>
                            )}
                          </div>

                          <div className="flex items-center gap-6 shrink-0">
                            <span className="text-slate-400 w-16 text-right">{chk.duration_ms} ms</span>
                            <span className={`w-12 text-right font-bold ${chk.findings > 0 ? "text-amber-400" : "text-slate-500"}`}>
                              {chk.findings}
                            </span>
                            <div className="w-28 flex justify-end">
                              {isPassed ? (
                                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-700/50 uppercase">
                                  Passed
                                </span>
                              ) : isFailed ? (
                                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-950 text-red-400 border border-red-700/50 uppercase">
                                  Failed
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-900 text-slate-400 border border-slate-700 uppercase">
                                  {state}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* TAB 3: RAW JSON */}
              {activeTab === "raw" && (
                <div className="rounded-xl bg-[#080d17] border border-[#162238] p-4 relative">
                  <button
                    onClick={() => handleCopy(JSON.stringify(selectedScanDetail, null, 2), "raw")}
                    className="absolute right-4 top-4 px-2.5 py-1 rounded bg-[#131f36] hover:bg-[#1a2a47] border border-[#203254] text-xs font-mono text-slate-300 flex items-center gap-1.5 cursor-pointer"
                  >
                    {copiedId === "raw" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    Copy JSON
                  </button>
                  <pre className="text-xs font-mono text-cyan-300/90 overflow-x-auto p-2 max-h-[600px]">
                    {JSON.stringify(selectedScanDetail, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : null}
        </div>
      </div>

      {/* EMBEDDED HTML REPORT FULLSCREEN MODAL */}
      {showHtmlModal && selectedScanDetail && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex flex-col p-4 md:p-8 animate-in fade-in duration-200">
          <div className="flex-1 flex flex-col bg-[#090d16] border border-[#1e2e4a] rounded-xl overflow-hidden shadow-2xl">
            {/* Modal Header */}
            <div className="h-13 px-5 border-b border-[#1b2b46] bg-[#0c1424] flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2.5 font-mono">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-bold text-white">ReadyHai Security Audit Report (HTML)</span>
                <span className="text-xs text-slate-500">·</span>
                <span className="text-xs text-cyan-300 font-semibold">#{selectedScanDetail.id}</span>
              </div>
              <div className="flex items-center gap-3">
                <a
                  href={`/api/scans/${selectedScanDetail.id}/report/html`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#14223b] hover:bg-[#1a2d4f] border border-[#233a63] text-xs font-mono text-cyan-300 transition-colors cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  Open in New Tab
                </a>
                <button
                  onClick={() => setShowHtmlModal(false)}
                  className="p-1.5 rounded-lg bg-[#14223b] hover:bg-red-950 hover:text-red-400 text-slate-400 border border-[#233a63] transition-colors cursor-pointer"
                  title="Close report"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* IFrame Container */}
            <div className="flex-1 bg-white relative">
              <iframe
                src={`/api/scans/${selectedScanDetail.id}/report/html`}
                title="ReadyHai HTML Report"
                className="w-full h-full border-0"
                sandbox="allow-same-origin allow-scripts"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
