"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import {
  Play,
  Globe,
  Plus,
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
import { apiRequest, notify, useApiTokenVersion } from "@/lib/api";
import { copyTextSafely } from "@/lib/clipboard";
import { ReportButton, ReportFrame } from "./ReportButton";

interface ScansHistoryViewProps {
  onSelectTarget?: (target: string) => void;
}

export function ScansHistoryView({ onSelectTarget }: ScansHistoryViewProps) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  // Detail result is keyed by scan id, so switching scans never shows another scan's data.
  const [detailResult, setDetailResult] = useState<{ id: string; detail: ScanDetail | null; error: string | null } | null>(
    null
  );
  const [isLoadingList, setIsLoadingList] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const tokenVersion = useApiTokenVersion();
  const [searchQuery, setSearchQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<"ALL" | "PASS" | "WARN" | "FAIL">("ALL");
  const [kindFilter, setKindFilter] = useState<string>("ALL");
  const [activeTab, setActiveTab] = useState<"findings" | "checks" | "raw">("findings");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [findingSearch, setFindingSearch] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showHtmlModal, setShowHtmlModal] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [newScanTarget, setNewScanTarget] = useState("");
  const [newScanProfile, setNewScanProfile] = useState<"quick" | "standard" | "deep">("quick");
  const [isSubmittingScan, setIsSubmittingScan] = useState(false);
  const [scanSubmitError, setScanSubmitError] = useState<string | null>(null);

  // Fetch scans list
  const loadScans = useCallback(
    () =>
      apiRequest<{ scans?: ScanSummary[] }>("/api/scans", { label: "Loading scans" }).then((r) => {
        if (r.ok && r.data) {
          const list: ScanSummary[] = r.data.scans || [];
          setScans(list);
          setListError(null);
          setSelectedScanId((cur) => cur ?? list[0]?.id ?? null);
        } else {
          setListError(r.ok ? "Loading scans failed: empty response." : r.error);
        }
        setIsLoadingList(false);
      }),
    []
  );

  // Manual refresh (button / after starting a scan): shows the spinner.
  const fetchScans = () => {
    setIsLoadingList(true);
    return loadScans();
  };

  // Auto-refresh when any scan is queued or running (silent: a 401 raises the token banner)
  useEffect(() => {
    const hasPending = scans.some((s) => s.state === "queued" || s.state === "running");
    if (!hasPending) return;
    const interval = setInterval(() => {
      loadScans();
      if (selectedScanId) {
        apiRequest<ScanDetail>(`/api/scans/${encodeURIComponent(selectedScanId)}`, { label: "Refreshing scan" }).then(
          (r) => {
            if (r.ok && r.data) setDetailResult({ id: selectedScanId, detail: r.data, error: null });
          }
        );
      }
    }, 2500);
    return () => clearInterval(interval);
  }, [scans, selectedScanId, loadScans]);

  const handleLaunchScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const trimmed = newScanTarget.trim();
    if (!trimmed) {
      setScanSubmitError("Enter a repository URL or path, for example https://github.com/org/repo, then start the scan again.");
      return;
    }
    setIsSubmittingScan(true);
    setScanSubmitError(null);
    const r = await apiRequest<{ id?: string }>("/api/scans", {
      method: "POST",
      json: { target: trimmed, profile: newScanProfile },
      label: "Start scan",
    });
    if (!r.ok) {
      setScanSubmitError(r.error);
      setIsSubmittingScan(false);
      return;
    }
    setShowScanModal(false);
    setNewScanTarget("");
    await fetchScans();
    if (r.data?.id) {
      setSelectedScanId(r.data.id);
    }
    setIsSubmittingScan(false);
  };

  useEffect(() => {
    loadScans();
  }, [loadScans, tokenVersion]);

  // Fetch scan detail when selectedScanId changes
  useEffect(() => {
    if (!selectedScanId) return;
    let isCancelled = false;
    apiRequest<ScanDetail>(`/api/scans/${encodeURIComponent(selectedScanId)}`, {
      label: "Loading scan detail",
    }).then((r) => {
      if (isCancelled) return;
      if (r.ok && r.data) {
        setDetailResult({ id: selectedScanId, detail: r.data, error: null });
      } else {
        setDetailResult({
          id: selectedScanId,
          detail: null,
          error: r.ok ? "Scan detail was empty." : r.error,
        });
      }
    });
    return () => {
      isCancelled = true;
    };
  }, [selectedScanId, tokenVersion]);

  const currentDetail = detailResult && detailResult.id === selectedScanId ? detailResult : null;
  const selectedScanDetail: ScanDetail | null = currentDetail?.detail ?? null;
  const detailError = currentDetail?.error ?? null;
  const isLoadingDetail = !!selectedScanId && currentDetail === null;

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete scan session ${id}?`)) return;
    const r = await apiRequest<unknown>(`/api/scans/${encodeURIComponent(id)}`, {
      method: "DELETE",
      label: "Delete scan",
    });
    if (!r.ok) {
      notify(r.error);
      return;
    }
    setScans((prev) => prev.filter((s) => s.id !== id));
    if (selectedScanId === id) {
      const remaining = scans.filter((s) => s.id !== id);
      setSelectedScanId(remaining.length > 0 ? remaining[0].id : null);
    }
  };

  const handleCopy = async (text: string, id: string) => {
    if (!(await copyTextSafely(text))) return;
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
    const chip = "inline-flex items-center gap-1 px-2 py-0.5 rounded-[6px] text-xs font-semibold whitespace-nowrap";
    switch (verdict) {
      case "PASS":
        return (
          <span className={`${chip} bg-rh-go/15 text-rh-go`}>
            <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" /> Pass
          </span>
        );
      case "WARN":
        return (
          <span className={`${chip} bg-rh-cond/15 text-rh-cond`}>
            <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" /> Warn
          </span>
        );
      case "FAIL":
        return (
          <span className={`${chip} bg-rh-nogo/15 text-rh-nogo`}>
            <XCircle className="w-3.5 h-3.5" aria-hidden="true" /> Fail
          </span>
        );
      default:
        return (
          <span className={`${chip} bg-rh-raised text-rh-muted`}>
            {verdict ? verdict.charAt(0).toUpperCase() + verdict.slice(1).toLowerCase() : "Unknown"}
          </span>
        );
    }
  };

  const getSeverityBadge = (severity?: string) => {
    const s = (severity || "low").toLowerCase();
    const chip = "px-2 py-0.5 rounded-[6px] text-xs font-semibold";
    switch (s) {
      case "critical":
        return <span className={`${chip} bg-rh-nogo/15 text-rh-nogo`}>Critical</span>;
      case "high":
        return <span className={`${chip} bg-rh-cond/15 text-rh-cond`}>High</span>;
      case "medium":
        return <span className={`${chip} bg-rh-cond/15 text-rh-cond`}>Medium</span>;
      case "low":
        return <span className={`${chip} bg-rh-info/15 text-rh-info`}>Low</span>;
      default:
        return <span className={`${chip} bg-rh-raised text-rh-muted`}>{severity}</span>;
    }
  };

  const sentence = (v: string) => (v ? v.charAt(0).toUpperCase() + v.slice(1) : v);
  const focusRing = "focus-visible:outline-2 focus-visible:outline-rh-primary";
  const inputRing =
    "focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
  const criticalCount = selectedScanDetail?.findings?.filter((f) => f.severity === "critical").length || 0;

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-rh-bg overflow-hidden">
      {/* Breadcrumb and actions */}
      <div className="min-h-12 px-6 py-2 border-b border-rh-line bg-rh-surface flex flex-wrap items-center justify-between gap-2 text-xs text-rh-muted shrink-0">
        <div className="flex items-center gap-2 flex-wrap">
          <ShieldCheck className="w-4 h-4 text-rh-muted" aria-hidden="true" />
          <h2 className="text-rh-text font-semibold text-sm">Security and codebase audits</h2>
          <span aria-hidden="true">/</span>
          <span>Static scans and SAST sessions</span>
          <span className="ml-2 px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted text-xs tabular-nums">
            {scans.length} {scans.length === 1 ? "session" : "sessions"} recorded
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            id="btn-open-scan-modal"
            onClick={() => setShowScanModal(true)}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold transition-colors cursor-pointer ${focusRing}`}
          >
            <Play className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
            <span>Scan repository</span>
          </button>
          <button
            type="button"
            onClick={fetchScans}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text transition-colors cursor-pointer text-xs ${focusRing}`}
            title="Refresh scans"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingList ? "animate-spin" : ""}`} aria-hidden="true" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Master-detail split */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Sessions list */}
        <div className="w-80 lg:w-96 border-r border-rh-line bg-rh-surface flex flex-col shrink-0 min-h-0">
          <div className="p-3 border-b border-rh-line space-y-2.5 shrink-0">
            <button
              type="button"
              id="btn-quick-new-scan"
              onClick={() => setShowScanModal(true)}
              className={`w-full py-1.5 px-3 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer ${focusRing}`}
            >
              <Plus className="w-3.5 h-3.5" aria-hidden="true" />
              <span>New repository scan</span>
            </button>

            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-rh-muted" aria-hidden="true" />
              <input
                type="text"
                placeholder="Filter by repository or run ID"
                aria-label="Filter scans by repository or run ID"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={`w-full pl-9 pr-3 py-1.5 bg-rh-bg border border-rh-line rounded-[6px] text-xs text-rh-text placeholder:text-rh-muted ${inputRing}`}
              />
            </div>

            <div
              role="group"
              aria-label="Filter by verdict"
              className="flex items-center gap-1 bg-rh-bg p-1 rounded-[6px] border border-rh-line"
            >
              {(["ALL", "PASS", "WARN", "FAIL"] as const).map((v) => (
                <button
                  type="button"
                  key={v}
                  onClick={() => setVerdictFilter(v)}
                  aria-pressed={verdictFilter === v}
                  className={`flex-1 py-1 text-xs rounded-[6px] transition-colors text-center cursor-pointer ${focusRing} ${
                    verdictFilter === v
                      ? "bg-rh-raised text-rh-text font-semibold"
                      : "text-rh-muted hover:text-rh-text hover:bg-rh-raised"
                  }`}
                >
                  {v === "ALL" ? "All" : sentence(v.toLowerCase())}
                </button>
              ))}
            </div>

            <div role="group" aria-label="Filter by scan type" className="flex items-center gap-1 text-xs text-rh-muted overflow-x-auto pb-0.5">
              <span className="pl-0.5">Type:</span>
              {(["ALL", "repo", "image", "host"] as const).map((k) => (
                <button
                  type="button"
                  key={k}
                  onClick={() => setKindFilter(k)}
                  aria-pressed={kindFilter === k}
                  className={`px-2 py-1 rounded-[6px] text-xs cursor-pointer transition-colors ${focusRing} ${
                    kindFilter === k
                      ? "bg-rh-raised text-rh-text font-semibold"
                      : "hover:bg-rh-raised text-rh-muted"
                  }`}
                >
                  {k === "ALL" ? "All" : sentence(k)}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto divide-y divide-rh-line">
            {isLoadingList && scans.length === 0 ? (
              <div className="p-6 text-center text-xs text-rh-muted space-y-2">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto text-rh-muted" aria-hidden="true" />
                <p>Loading scan sessions...</p>
              </div>
            ) : listError ? (
              <div className="p-6 text-center text-xs space-y-1" role="alert">
                <p className="font-semibold text-rh-nogo">Could not load scans</p>
                <p className="text-rh-muted break-words">{listError}</p>
                <p className="text-rh-muted">Select Refresh to try again.</p>
              </div>
            ) : filteredScans.length === 0 ? (
              <div className="p-6 text-center text-xs text-rh-muted">
                {scans.length === 0 ? (
                  <>
                    <p className="font-semibold text-rh-text">No scan sessions yet</p>
                    <p className="mt-1">Select Scan repository to run your first static analysis.</p>
                  </>
                ) : (
                  <>
                    <p className="font-semibold text-rh-text">No scans match these filters</p>
                    <p className="mt-1">Clear the search text or set the verdict and type filters back to All.</p>
                  </>
                )}
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
                    role="button"
                    tabIndex={0}
                    aria-current={isSelected ? "true" : undefined}
                    onClick={() => setSelectedScanId(scan.id)}
                    onKeyDown={(e) => {
                      if (e.target !== e.currentTarget) return;
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelectedScanId(scan.id);
                      }
                    }}
                    className={`px-3.5 py-3 cursor-pointer transition-colors border-l-2 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-rh-primary ${
                      isSelected ? "bg-rh-raised border-l-rh-primary" : "border-l-transparent hover:bg-rh-raised"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          {isGit ? (
                            <GitBranch className="w-3.5 h-3.5 text-rh-muted shrink-0" aria-hidden="true" />
                          ) : (
                            <Box className="w-3.5 h-3.5 text-rh-muted shrink-0" aria-hidden="true" />
                          )}
                          <h3 className="text-sm font-semibold text-rh-text truncate" title={scan.target}>
                            {displayName}
                          </h3>
                        </div>
                        <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                          <span className="text-xs text-rh-muted font-mono">#{scan.id.slice(-8)}</span>
                          <span className="text-xs px-1.5 py-0.5 rounded-[6px] bg-rh-bg text-rh-muted">{scan.kind}</span>
                          <span className="text-xs px-1.5 py-0.5 rounded-[6px] bg-rh-bg text-rh-muted">{scan.profile}</span>
                        </div>
                      </div>
                      <div className="shrink-0 flex flex-col items-end gap-1">
                        {scan.state === "queued" || scan.state === "running" ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-info/15 text-rh-info">
                            <RefreshCw className="w-3 h-3 animate-spin" aria-hidden="true" /> {sentence(scan.state)}
                          </span>
                        ) : (
                          getVerdictBadge(scan.verdict)
                        )}
                        <span className="text-xs text-rh-muted tabular-nums">{scan.findings_count} findings</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between mt-2.5 pt-2 border-t border-rh-line text-xs text-rh-muted">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5" aria-hidden="true" />
                        <span className="tabular-nums">{dateStr}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        {scan.hard_fail_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded-[6px] bg-rh-nogo/15 text-rh-nogo text-xs font-semibold tabular-nums">
                            {scan.hard_fail_count} critical
                          </span>
                        )}
                        <button
                          type="button"
                          onClick={(e) => handleDelete(scan.id, e)}
                          className={`text-rh-muted hover:text-rh-nogo transition-colors p-1.5 rounded-[6px] cursor-pointer ${focusRing}`}
                          title="Delete scan"
                          aria-label={`Delete scan ${scan.id}`}
                        >
                          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Scan inspector */}
        <div className="flex-1 flex flex-col bg-rh-bg min-h-0 overflow-y-auto">
          {!selectedScanId ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
              <ShieldCheck className="w-10 h-10 text-rh-muted mb-3" aria-hidden="true" />
              <h3 className="text-base font-semibold text-rh-text">Select a scan session</h3>
              <p className="text-sm text-rh-muted max-w-sm mt-1">
                Pick a session from the list to inspect its findings, security checks and generated SARIF or HTML
                reports. No sessions yet? Start with a repository scan.
              </p>
              <button
                type="button"
                onClick={() => setShowScanModal(true)}
                className={`mt-4 flex items-center gap-2 px-3.5 py-1.5 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold transition-colors cursor-pointer ${focusRing}`}
              >
                <Play className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
                <span>Scan repository</span>
              </button>
            </div>
          ) : isLoadingDetail && !selectedScanDetail ? (
            <div className="flex-1 flex items-center justify-center p-8" role="status" aria-label="Loading scan detail">
              <RefreshCw className="w-6 h-6 animate-spin text-rh-muted" aria-hidden="true" />
            </div>
          ) : detailError && !selectedScanDetail ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-xs gap-1" role="alert">
              <p className="font-semibold text-rh-nogo text-sm">Could not load this scan</p>
              <p className="max-w-md break-words text-rh-muted">{detailError}</p>
              <p className="text-rh-muted">Pick the session again or select Refresh to retry.</p>
            </div>
          ) : selectedScanDetail ? (
            <div className="p-6 space-y-5 max-w-6xl w-full mx-auto">
              {/* Summary panel */}
              <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text font-semibold">
                        {sentence(selectedScanDetail.target.kind || "repo")} audit
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted font-medium">
                        Profile: {selectedScanDetail.profile}
                      </span>
                      <span className="text-xs text-rh-muted">
                        ID: <span className="font-mono">{selectedScanDetail.id}</span>
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy(selectedScanDetail.id, "id")}
                        className={`text-rh-muted hover:text-rh-text cursor-pointer p-1 rounded-[6px] ${focusRing}`}
                        title="Copy session ID"
                        aria-label="Copy session ID"
                      >
                        {copiedId === "id" ? (
                          <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                        )}
                      </button>
                    </div>

                    <h2 className="text-lg font-semibold text-rh-text break-all flex items-center gap-2">
                      <span className="font-mono text-base">{selectedScanDetail.target.raw}</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(selectedScanDetail.target.raw, "target")}
                        className={`text-rh-muted hover:text-rh-text cursor-pointer p-1 rounded-[6px] shrink-0 ${focusRing}`}
                        title="Copy target URL"
                        aria-label="Copy target URL"
                      >
                        {copiedId === "target" ? (
                          <Check className="w-4 h-4 text-rh-go" aria-hidden="true" />
                        ) : (
                          <Copy className="w-4 h-4" aria-hidden="true" />
                        )}
                      </button>
                      {onSelectTarget && /^https?:\/\//.test(selectedScanDetail.target.raw) && (
                        <button
                          type="button"
                          onClick={() => onSelectTarget(selectedScanDetail.target.raw)}
                          className={`ml-1 px-2 py-1 text-xs font-sans font-medium text-rh-text border border-rh-line hover:bg-rh-raised rounded-[6px] cursor-pointer shrink-0 ${focusRing}`}
                        >
                          Test in studio
                        </button>
                      )}
                    </h2>

                    <div className="flex items-center gap-4 text-xs text-rh-muted pt-1 flex-wrap tabular-nums">
                      <span>Started: {selectedScanDetail.started ? new Date(selectedScanDetail.started).toLocaleString() : "-"}</span>
                      {selectedScanDetail.finished && (
                        <span>Finished: {new Date(selectedScanDetail.finished).toLocaleTimeString()}</span>
                      )}
                    </div>
                  </div>

                  <div className="shrink-0 flex flex-col items-start md:items-end gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-rh-muted">Verdict:</span>
                      {getVerdictBadge(selectedScanDetail.verdict)}
                    </div>
                    {selectedScanDetail.reasons && selectedScanDetail.reasons.length > 0 && (
                      <div className="text-xs text-rh-cond bg-rh-cond/15 px-2.5 py-1 rounded-[6px] max-w-xs md:text-right">
                        {selectedScanDetail.reasons.join(", ")}
                      </div>
                    )}
                  </div>
                </div>

                {/* Generated reports */}
                <div className="mt-5 pt-4 border-t border-rh-line flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                    <span className="text-xs font-semibold text-rh-text">Generated reports</span>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      type="button"
                      onClick={() => setShowHtmlModal(true)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold transition-colors cursor-pointer ${focusRing}`}
                    >
                      <Maximize2 className="w-3.5 h-3.5" aria-hidden="true" />
                      View HTML report
                    </button>

                    <ReportButton
                      path={`/api/scans/${selectedScanDetail.id}/report/sarif`}
                      mode="download"
                      filename={`readyhai-${selectedScanDetail.id}.sarif`}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer ${focusRing}`}
                    >
                      <Download className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                      SARIF 2.1.0
                    </ReportButton>

                    <ReportButton
                      path={`/api/scans/${selectedScanDetail.id}/report/json`}
                      mode="download"
                      filename={`readyhai-${selectedScanDetail.id}.json`}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer ${focusRing}`}
                    >
                      <Download className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                      JSON
                    </ReportButton>

                    <ReportButton
                      path={`/api/scans/${selectedScanDetail.id}/report/junit`}
                      mode="download"
                      filename={`readyhai-${selectedScanDetail.id}.junit.xml`}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer ${focusRing}`}
                    >
                      <Download className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                      JUnit XML
                    </ReportButton>

                    <ReportButton
                      path={`/api/scans/${selectedScanDetail.id}/report/html`}
                      mode="tab"
                      className={`p-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-muted hover:text-rh-text transition-colors cursor-pointer ${focusRing}`}
                      title="Open HTML report in a new tab"
                    >
                      <ExternalLink className="w-3.5 h-3.5" aria-label="Open HTML report in a new tab" />
                    </ReportButton>
                  </div>
                </div>
              </div>

              {/* KPI cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
                <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line">
                  <div className="text-xs text-rh-muted">Total findings</div>
                  <div className="text-2xl font-semibold text-rh-text mt-1 tabular-nums">
                    {selectedScanDetail.findings?.length || 0}
                  </div>
                  <div className="text-xs text-rh-muted mt-0.5">Identified defects</div>
                </div>

                <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line">
                  <div className="text-xs text-rh-muted">Critical / hard fails</div>
                  <div className={`text-2xl font-semibold mt-1 tabular-nums ${criticalCount > 0 ? "text-rh-nogo" : "text-rh-go"}`}>
                    {criticalCount}
                  </div>
                  <div className="text-xs text-rh-muted mt-0.5">Gate blockers</div>
                </div>

                <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line">
                  <div className="text-xs text-rh-muted">Security checks</div>
                  <div className="text-2xl font-semibold text-rh-text mt-1 tabular-nums">
                    {selectedScanDetail.checks?.length || 0}
                  </div>
                  <div className="text-xs text-rh-muted mt-0.5 tabular-nums">
                    {selectedScanDetail.checks?.filter((c) => c.status.state === "passed").length || 0} passed
                  </div>
                </div>

                <div className="p-3.5 rounded-[10px] bg-rh-surface border border-rh-line">
                  <div className="text-xs text-rh-muted">Categories scanned</div>
                  <div className="text-2xl font-semibold text-rh-text mt-1 tabular-nums">
                    {selectedScanDetail.categories?.length || availableCategories.length || 0}
                  </div>
                  <div className="text-xs text-rh-muted mt-0.5">SAST, secrets, dependencies</div>
                </div>
              </div>

              {/* Tabs */}
              <div role="tablist" aria-label="Scan detail sections" className="border-b border-rh-line flex items-center gap-1 overflow-x-auto">
                {(
                  [
                    { id: "findings", icon: AlertTriangle, label: `Findings and vulnerabilities (${selectedScanDetail.findings?.length || 0})` },
                    { id: "checks", icon: Layers, label: `Check execution (${selectedScanDetail.checks?.length || 0})` },
                    { id: "raw", icon: Terminal, label: "Raw JSON" },
                  ] as const
                ).map((t) => {
                  const Icon = t.icon;
                  const active = activeTab === t.id;
                  return (
                    <button
                      type="button"
                      key={t.id}
                      role="tab"
                      aria-selected={active}
                      onClick={() => setActiveTab(t.id)}
                      className={`pb-2.5 pt-1 px-3 text-xs font-medium flex items-center gap-2 border-b-2 whitespace-nowrap transition-colors cursor-pointer ${focusRing} ${
                        active
                          ? "border-rh-primary text-rh-text font-semibold"
                          : "border-transparent text-rh-muted hover:text-rh-text"
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" aria-hidden="true" />
                      {t.label}
                    </button>
                  );
                })}
              </div>

              {/* Findings */}
              {activeTab === "findings" && (
                <div className="space-y-4" role="tabpanel">
                  <div className="p-3 rounded-[10px] bg-rh-surface border border-rh-line flex flex-wrap items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-2 flex-1 min-w-[200px]">
                      <Search className="w-3.5 h-3.5 text-rh-muted shrink-0" aria-hidden="true" />
                      <input
                        type="text"
                        placeholder="Search findings by rule, title or file location"
                        aria-label="Search findings"
                        value={findingSearch}
                        onChange={(e) => setFindingSearch(e.target.value)}
                        className={`w-full bg-transparent border border-transparent rounded-[6px] px-1.5 py-1 text-rh-text placeholder:text-rh-muted text-xs ${inputRing}`}
                      />
                    </div>

                    <div className="flex items-center gap-2 flex-wrap text-xs">
                      <span className="text-rh-muted">Severity:</span>
                      <div role="group" aria-label="Filter by severity" className="flex items-center gap-1 flex-wrap">
                        {(["ALL", "critical", "high", "medium", "low"] as const).map((sev) => (
                          <button
                            type="button"
                            key={sev}
                            onClick={() => setSeverityFilter(sev)}
                            aria-pressed={severityFilter === sev}
                            className={`px-2 py-1 rounded-[6px] cursor-pointer transition-colors ${focusRing} ${
                              severityFilter === sev
                                ? "bg-rh-raised text-rh-text font-semibold"
                                : "text-rh-muted hover:bg-rh-raised hover:text-rh-text"
                            }`}
                          >
                            {sev === "ALL" ? "All" : sentence(sev)}
                          </button>
                        ))}
                      </div>

                      {availableCategories.length > 0 && (
                        <div className="flex items-center gap-1.5 pl-2 border-l border-rh-line">
                          <label htmlFor="finding-category-filter" className="text-rh-muted">
                            Category:
                          </label>
                          <select
                            id="finding-category-filter"
                            value={categoryFilter}
                            onChange={(e) => setCategoryFilter(e.target.value)}
                            className={`bg-rh-bg border border-rh-line text-rh-text rounded-[6px] px-2 py-1 text-xs cursor-pointer ${inputRing}`}
                          >
                            <option value="ALL">All categories</option>
                            {availableCategories.map((c) => (
                              <option key={c} value={c}>
                                {sentence(c)}
                              </option>
                            ))}
                          </select>
                        </div>
                      )}
                    </div>
                  </div>

                  {filteredFindings.length === 0 ? (
                    <div className="p-8 text-center text-xs text-rh-muted bg-rh-surface rounded-[10px] border border-rh-line">
                      <p className="font-semibold text-rh-text text-sm">
                        {(selectedScanDetail.findings?.length || 0) === 0
                          ? "This scan reported no findings"
                          : "No findings match the current filters"}
                      </p>
                      <p className="mt-1">
                        {(selectedScanDetail.findings?.length || 0) === 0
                          ? "Check the Check execution tab to confirm which checks ran."
                          : "Clear the search text, or set severity and category back to All."}
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {filteredFindings.map((f, idx) => (
                        <div
                          key={f.fingerprint || f.rule + idx}
                          className="p-4 rounded-[10px] bg-rh-surface border border-rh-line space-y-2.5"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="space-y-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                {getSeverityBadge(f.severity)}
                                <span className="text-xs text-rh-muted font-mono">{f.rule}</span>
                                <span className="text-xs px-1.5 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted">
                                  {f.category}
                                </span>
                                {f.check && <span className="text-xs text-rh-muted">via {f.check}</span>}
                              </div>
                              <h4 className="text-sm font-semibold text-rh-text mt-1">{f.title}</h4>
                            </div>

                            {f.location && (
                              <div className="shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded-[6px] bg-rh-bg border border-rh-line text-xs text-rh-text max-w-xs">
                                <FileCode2 className="w-3.5 h-3.5 text-rh-muted shrink-0" aria-hidden="true" />
                                <span className="truncate font-mono" title={f.location}>{f.location}</span>
                              </div>
                            )}
                          </div>

                          {f.detail && (
                            <div className="p-2.5 rounded-[6px] bg-rh-bg border border-rh-line text-xs text-rh-text whitespace-pre-wrap">
                              {f.detail}
                            </div>
                          )}

                          {f.remediation && (
                            <div className="p-2.5 rounded-[6px] bg-rh-go/10 text-xs flex items-start gap-2">
                              <span className="text-rh-go font-semibold shrink-0">Remediation:</span>
                              <span className="text-rh-text">{f.remediation}</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Checks */}
              {activeTab === "checks" && (
                <div role="tabpanel" className="rounded-[10px] bg-rh-surface border border-rh-line overflow-hidden">
                  {!selectedScanDetail.checks || selectedScanDetail.checks.length === 0 ? (
                    <div className="p-8 text-center text-xs text-rh-muted">
                      <p className="font-semibold text-rh-text text-sm">No check results were reported</p>
                      <p className="mt-1">Start a new scan to see which security checks ran.</p>
                    </div>
                  ) : (
                    <div className="min-h-0 max-h-[70vh] overflow-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-left text-rh-muted">
                            <th scope="col" className="sticky top-0 z-10 bg-rh-raised px-4 py-2.5 font-semibold">
                              Security check
                            </th>
                            <th scope="col" className="sticky top-0 z-10 bg-rh-raised px-4 py-2.5 font-semibold text-right">
                              Duration
                            </th>
                            <th scope="col" className="sticky top-0 z-10 bg-rh-raised px-4 py-2.5 font-semibold text-right">
                              Findings
                            </th>
                            <th scope="col" className="sticky top-0 z-10 bg-rh-raised px-4 py-2.5 font-semibold text-right">
                              State
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-rh-line">
                          {selectedScanDetail.checks.map((chk) => {
                            const state = chk.status?.state || "unknown";
                            const isPassed = state === "passed";
                            const isFailed = state === "failed";
                            return (
                              <tr key={chk.id} className="hover:bg-rh-raised transition-colors">
                                <td className="px-4 py-3 align-top">
                                  <div className="font-semibold text-rh-text flex items-center gap-2 flex-wrap">
                                    <span>{chk.title}</span>
                                    <span className="text-xs text-rh-muted font-mono font-normal">{chk.id}</span>
                                  </div>
                                  {chk.status?.reason && (
                                    <div className="text-xs text-rh-muted mt-0.5">Reason: {chk.status.reason}</div>
                                  )}
                                </td>
                                <td className="px-4 py-3 text-right text-rh-muted tabular-nums whitespace-nowrap align-top">
                                  {chk.duration_ms} ms
                                </td>
                                <td
                                  className={`px-4 py-3 text-right font-semibold tabular-nums align-top ${
                                    chk.findings > 0 ? "text-rh-cond" : "text-rh-muted"
                                  }`}
                                >
                                  {chk.findings}
                                </td>
                                <td className="px-4 py-3 text-right align-top">
                                  {isPassed ? (
                                    <span className="px-2 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-go/15 text-rh-go">
                                      Passed
                                    </span>
                                  ) : isFailed ? (
                                    <span className="px-2 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-nogo/15 text-rh-nogo">
                                      Failed
                                    </span>
                                  ) : (
                                    <span className="px-2 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-raised text-rh-muted">
                                      {sentence(state)}
                                    </span>
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* Raw JSON */}
              {activeTab === "raw" && (
                <div role="tabpanel" className="rounded-[10px] bg-rh-surface border border-rh-line p-4 flex flex-col gap-3 min-h-0">
                  <div className="flex justify-end">
                    <button
                      type="button"
                      onClick={() => handleCopy(JSON.stringify(selectedScanDetail, null, 2), "raw")}
                      className={`px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-xs text-rh-text flex items-center gap-1.5 cursor-pointer transition-colors ${focusRing}`}
                    >
                      {copiedId === "raw" ? (
                        <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                      )}
                      Copy JSON
                    </button>
                  </div>
                  <pre className="font-mono text-xs text-rh-text bg-rh-bg border border-rh-line rounded-[6px] overflow-auto p-3 max-h-[60vh]">
                    {JSON.stringify(selectedScanDetail, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : null}
        </div>
      </div>

      {/* Fullscreen HTML report */}
      {showHtmlModal && selectedScanDetail && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="HTML audit report"
          className="fixed inset-0 z-50 bg-rh-bg/80 flex flex-col p-4 md:p-8"
        >
          <div className="flex-1 min-h-0 flex flex-col bg-rh-surface border border-rh-line rounded-[10px] overflow-hidden shadow-lg">
            <div className="min-h-12 px-5 py-2 border-b border-rh-line bg-rh-surface flex items-center justify-between gap-3 shrink-0">
              <div className="flex items-center gap-2.5 min-w-0">
                <FileText className="w-4 h-4 text-rh-muted shrink-0" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-rh-text truncate">ReadyHai security audit report (HTML)</h3>
                <span className="text-xs text-rh-muted font-mono truncate">#{selectedScanDetail.id}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <ReportButton
                  path={`/api/scans/${selectedScanDetail.id}/report/html`}
                  mode="tab"
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-xs text-rh-text transition-colors cursor-pointer ${focusRing}`}
                >
                  <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                  Open in new tab
                </ReportButton>
                <button
                  type="button"
                  onClick={() => setShowHtmlModal(false)}
                  className={`p-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-nogo/15 hover:text-rh-nogo text-rh-muted transition-colors cursor-pointer ${focusRing}`}
                  title="Close report"
                  aria-label="Close report"
                >
                  <X className="w-4 h-4" aria-hidden="true" />
                </button>
              </div>
            </div>

            <div className="flex-1 min-h-0 bg-white relative">
              <ReportFrame
                path={`/api/scans/${selectedScanDetail.id}/report/html`}
                title="ReadyHai HTML Report"
                className="w-full h-full border-0"
              />
            </div>
          </div>
        </div>
      )}

      {/* New scan dialog */}
      {showScanModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Scan a repository"
          className="fixed inset-0 z-50 bg-rh-bg/80 flex items-center justify-center p-4"
        >
          <div className="w-full max-w-lg max-h-full overflow-y-auto bg-rh-surface border border-rh-line rounded-[10px] shadow-lg">
            <div className="p-5 border-b border-rh-line flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-[6px] bg-rh-raised flex items-center justify-center shrink-0">
                  <GitBranch className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-rh-text">Scan a repository</h3>
                  <p className="text-xs text-rh-muted">Static analysis, secret leakage, CI checks and vulnerability audit</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowScanModal(false)}
                className={`text-rh-muted hover:text-rh-text p-1.5 rounded-[6px] hover:bg-rh-raised cursor-pointer ${focusRing}`}
                title="Close"
                aria-label="Close dialog"
              >
                <X className="w-4 h-4" aria-hidden="true" />
              </button>
            </div>

            <form onSubmit={handleLaunchScan} className="p-5 space-y-4 text-xs">
              <div className="space-y-1.5">
                <label htmlFor="input-scan-target" className="text-rh-text font-semibold">
                  Git repository URL or path
                </label>
                <div className="relative">
                  <Globe className="w-4 h-4 text-rh-muted absolute left-3 top-2.5" aria-hidden="true" />
                  <input
                    id="input-scan-target"
                    type="text"
                    value={newScanTarget}
                    onChange={(e) => {
                      setNewScanTarget(e.target.value);
                      setScanSubmitError(null);
                    }}
                    placeholder="https://github.com/org/repo"
                    className={`w-full pl-9 pr-3 py-2 bg-rh-bg border border-rh-line rounded-[6px] text-rh-text placeholder:text-rh-muted font-mono text-xs ${inputRing}`}
                    autoFocus
                  />
                </div>
                <div className="flex items-center gap-x-3 gap-y-1 pt-1 text-xs text-rh-muted flex-wrap">
                  <span>Examples:</span>
                  {[
                    { label: "deziss/prism", url: "https://github.com/deziss/prism" },
                    { label: "deziss/readyhai", url: "https://github.com/deziss/readyhai" },
                    { label: "expressjs/express", url: "https://github.com/expressjs/express" },
                  ].map((s) => (
                    <button
                      key={s.url}
                      type="button"
                      onClick={() => setNewScanTarget(s.url)}
                      className={`text-rh-primary hover:text-rh-primary-hover hover:underline rounded-[6px] cursor-pointer font-mono ${focusRing}`}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5" role="group" aria-labelledby="scan-profile-label">
                <div id="scan-profile-label" className="text-rh-text font-semibold">
                  Scan profile
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { id: "quick", label: "Quick", desc: "SAST and CI checks (about 2s)" },
                    { id: "standard", label: "Standard", desc: "Full rules and dependencies" },
                    { id: "deep", label: "Deep", desc: "Exhaustive matrix" },
                  ].map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => setNewScanProfile(p.id as "quick" | "standard" | "deep")}
                      aria-pressed={newScanProfile === p.id}
                      className={`p-2.5 rounded-[6px] border text-left cursor-pointer transition-colors ${focusRing} ${
                        newScanProfile === p.id
                          ? "bg-rh-primary/15 border-rh-primary text-rh-text"
                          : "bg-rh-bg border-rh-line text-rh-muted hover:bg-rh-raised"
                      }`}
                    >
                      <div className="font-semibold text-xs text-rh-text">{p.label}</div>
                      <div className="text-xs text-rh-muted mt-0.5">{p.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {scanSubmitError && (
                <div role="alert" className="p-3 rounded-[6px] bg-rh-nogo/15 text-rh-nogo text-xs">
                  {scanSubmitError}
                </div>
              )}

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-rh-line">
                <button
                  type="button"
                  onClick={() => setShowScanModal(false)}
                  className={`px-4 py-2 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text cursor-pointer transition-colors ${focusRing}`}
                >
                  Cancel
                </button>
                <button
                  id="btn-submit-scan"
                  type="submit"
                  disabled={isSubmittingScan}
                  className={`flex items-center gap-2 px-5 py-2 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg font-semibold transition-colors cursor-pointer disabled:opacity-50 ${focusRing}`}
                >
                  {isSubmittingScan ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                      <span>Cloning and scanning...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
                      <span>Start scan</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
