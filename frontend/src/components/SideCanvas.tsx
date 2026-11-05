"use client";

import { useMemo, useState } from "react";
import {
  Bot,
  ArrowRight,
  ListFilter,
  Network,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Copy,
  Trash2,
  RotateCw,
  Check,
  ChevronDown,
  ChevronUp,
  FileCode2,
  ExternalLink,
  Eye,
  FileText,
  FileCode,
  X,
  Search,
  Play,
} from "lucide-react";
import type {
  AgentRunRecord,
  TestCaseResult,
  DiscoveredRoute,
  ThreatFinding,
  EvidenceLedger,
} from "@/types/agent";
import {
  getPillars,
  ledgerScore,
  ledgerVerdict,
  normalizeVerdict,
  numOrNull,
  runDefectCount,
  runId as getRunId,
} from "@/lib/runs";
import { ReportButton, ReportFrame } from "./ReportButton";
import { VerdictBadge } from "./VerdictBadge";
import { Scenarios } from "./Scenarios";
import { AutoRemediationCard } from "./AutoRemediationCard";

interface SideCanvasProps {
  testCases: TestCaseResult[];
  discoveredRoutes: DiscoveredRoute[];
  threats: ThreatFinding[];
  evidenceLedger: EvidenceLedger | null;
  isSpa: boolean;
  appArchitecture?: string;
  onRetestCase: (testCase: TestCaseResult) => Promise<void>;
  runsHistory: AgentRunRecord[];
  onLoadRun: (run: AgentRunRecord) => void;
  onDeleteRun?: (runId: string) => Promise<void>;
  onCrawlSite?: () => Promise<void>;
  isCrawling?: boolean;
  onTestEndpoint?: (path: string, method?: string) => Promise<void>;
  onOpenAgentHistory?: () => void;
}

export function SideCanvas({
  testCases,
  discoveredRoutes,
  threats,
  evidenceLedger,
  isSpa,
  appArchitecture,
  onRetestCase,
  runsHistory,
  onLoadRun,
  onDeleteRun,
  onCrawlSite,
  isCrawling = false,
  onTestEndpoint,
  onOpenAgentHistory,
}: SideCanvasProps) {
  const [activeTab, setActiveTab] = useState<"scenarios" | "routes" | "ledger" | "triage" | "history">("scenarios");
  const [testingPath, setTestingPath] = useState<string | null>(null);
  const [isTestingAll, setIsTestingAll] = useState(false);
  const [testAllProgress, setTestAllProgress] = useState<{ current: number; total: number; path: string } | null>(null);
  const [routeSearch, setRouteSearch] = useState<string>("");
  const [reportModalRunId, setReportModalRunId] = useState<string | null>(null);
  const [historySearch, setHistorySearch] = useState<string>("");
  const [historyVerdict, setHistoryVerdict] = useState<string>("ALL");

  const filteredRoutes = useMemo(() => {
    const q = routeSearch.trim().toLowerCase();
    if (!q) return discoveredRoutes;
    return discoveredRoutes.filter(
      (r) =>
        r.path.toLowerCase().includes(q) ||
        (r.title && r.title.toLowerCase().includes(q)) ||
        r.method.toLowerCase().includes(q) ||
        (r.content_type && r.content_type.toLowerCase().includes(q))
    );
  }, [discoveredRoutes, routeSearch]);

  async function handleTestAll() {
    if (!onTestEndpoint || discoveredRoutes.length === 0 || isTestingAll) return;
    setIsTestingAll(true);
    setTestAllProgress({ current: 0, total: discoveredRoutes.length, path: "" });
    try {
      for (let i = 0; i < discoveredRoutes.length; i++) {
        const r = discoveredRoutes[i];
        setTestAllProgress({ current: i + 1, total: discoveredRoutes.length, path: r.path });
        setTestingPath(r.path);
        try {
          await onTestEndpoint(r.path, r.method || "GET");
        } catch (err) {
          console.error("Test endpoint failed for", r.path, err);
        }
      }
    } finally {
      setTestingPath(null);
      setIsTestingAll(false);
      setTestAllProgress(null);
    }
  }

  const filteredHistory = useMemo(() => {
    const q = historySearch.trim().toLowerCase();
    return runsHistory
      .map((run, idx) => ({
        run,
        runId: getRunId(run) || `run-${idx}`,
        // Only what the backend reported; no default verdict.
        verdict: ledgerVerdict(run.evidence_ledger) ?? normalizeVerdict(run.gate_verdict) ?? normalizeVerdict(run.verdict),
      }))
      .filter(({ run, runId, verdict }) => {
        if (q && !(run.target ?? "").toLowerCase().includes(q) && !runId.toLowerCase().includes(q)) return false;
        if (historyVerdict === "NONE") return verdict === null;
        if (historyVerdict !== "ALL" && verdict !== historyVerdict) return false;
        return true;
      });
  }, [runsHistory, historySearch, historyVerdict]);

  return (
    <div className="bg-[#0b101a] border border-[#1a2436] rounded-xl flex flex-col h-full shadow-2xl overflow-hidden">
      {/* Sleek Canvas Tab Bar */}
      <div className="flex items-center gap-1.5 p-2 border-b border-[#162033] bg-[#07090e]/80 shrink-0 overflow-x-auto">
        <button
          type="button"
          id="tab-scenarios" onClick={() => setActiveTab("scenarios")}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all whitespace-nowrap cursor-pointer ${
            activeTab === "scenarios"
              ? "bg-[#111827] text-cyan-300 border border-cyan-500/40 shadow-sm font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#0e1524]"
          }`}
        >
          <ListFilter className="w-3.5 h-3.5 text-cyan-400" />
          Scenarios & Inspector
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-[#1e2a40] text-slate-300">
            {testCases.length}
          </span>
        </button>

        <button
          type="button"
          id="tab-routes" onClick={() => setActiveTab("routes")}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all whitespace-nowrap cursor-pointer ${
            activeTab === "routes"
              ? "bg-[#111827] text-cyan-300 border border-cyan-500/40 shadow-sm font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#0e1524]"
          }`}
        >
          <Network className="w-3.5 h-3.5 text-cyan-400" />
          Discovered Routes
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-[#1e2a40] text-slate-300">
            {discoveredRoutes.length}
          </span>
        </button>

        <button
          type="button"
          id="tab-ledger" onClick={() => setActiveTab("ledger")}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all whitespace-nowrap cursor-pointer ${
            activeTab === "ledger"
              ? "bg-[#111827] text-cyan-300 border border-cyan-500/40 shadow-sm font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#0e1524]"
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          Evidence Ledger
        </button>

        <button
          type="button"
          id="tab-triage" onClick={() => setActiveTab("triage")}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all whitespace-nowrap cursor-pointer ${
            activeTab === "triage"
              ? "bg-[#111827] text-cyan-300 border border-cyan-500/40 shadow-sm font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#0e1524]"
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
          Threat Triage
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-rose-950/80 text-rose-300 border border-rose-800/60 font-bold">
            {threats.length}
          </span>
        </button>

        <button
          type="button"
          id="tab-history" onClick={() => setActiveTab("history")}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all whitespace-nowrap cursor-pointer ${
            activeTab === "history"
              ? "bg-[#111827] text-cyan-300 border border-cyan-500/40 shadow-sm font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#0e1524]"
          }`}
        >
          <Clock className="w-3.5 h-3.5 text-slate-400" />
          Runs History
        </button>

        {onOpenAgentHistory && (
          <button
            type="button"
            id="tab-btn-open-qa-reports"
            onClick={onOpenAgentHistory}
            className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-xs font-mono font-bold transition-all cursor-pointer shadow-sm group shrink-0"
            title="Open QA Agent Reports & Swarm History"
          >
            <Bot className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
            <span>QA Agent Reports</span>
            <ArrowRight className="w-3 h-3 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </button>
        )}
      </div>

      {/* Tab 1: Scenarios & Deep Payload Inspector */}
      {activeTab === "scenarios" && (
        <div className="p-4 overflow-y-auto flex-1 flex flex-col gap-3">
          <Scenarios testCases={testCases} onRetestCase={onRetestCase} />
        </div>
      )}

      {/* Tab 2: Discovered Routes */}
      {activeTab === "routes" && (
        <div className="p-4 flex-1 min-h-0 flex flex-col gap-3 overflow-hidden">
          {/* Header Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[#162033] shrink-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-bold tracking-wider text-slate-300 uppercase">Target Endpoint Discovery</span>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                  appArchitecture?.includes("PHP")
                    ? "bg-indigo-950 text-indigo-300 border border-indigo-800"
                    : isSpa
                    ? "bg-purple-950 text-purple-300 border border-purple-800"
                    : "bg-emerald-950 text-emerald-300 border border-emerald-800"
                }`}
              >
                {appArchitecture || (isSpa ? "SPA shell detected" : "Architecture not reported")}
              </span>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {/* Quick Route Filter */}
              <div className="relative">
                <Search className="w-3 h-3 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={routeSearch}
                  onChange={(e) => setRouteSearch(e.target.value)}
                  placeholder="Filter routes..."
                  className="pl-7 pr-2 py-1 text-xs font-mono bg-[#07090e] border border-[#1a2436] rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 w-36"
                />
              </div>

              <span className="text-[11px] font-mono text-slate-500 whitespace-nowrap">
                {filteredRoutes.length} of {discoveredRoutes.length} real routes
              </span>

              {/* Test All Endpoints Button */}
              {onTestEndpoint && (
                <button
                  type="button"
                  onClick={handleTestAll}
                  disabled={isTestingAll || isCrawling || discoveredRoutes.length === 0}
                  className="px-2.5 py-1 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-600/70 text-cyan-300 text-xs font-mono font-bold flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 shadow-sm"
                  title="Probe and verify all discovered endpoint URLs for liveness, 5xx errors, stack trace leaks, and response latency"
                >
                  {isTestingAll ? (
                    <>
                      <RotateCw className="w-3 h-3 animate-spin text-cyan-400" />
                      <span>Testing ({testAllProgress?.current || 0}/{discoveredRoutes.length})...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3 h-3 text-cyan-400 fill-cyan-400" />
                      <span>⚡ Test All ({discoveredRoutes.length})</span>
                    </>
                  )}
                </button>
              )}

              {onCrawlSite && (
                <button
                  type="button"
                  onClick={onCrawlSite}
                  disabled={isCrawling || isTestingAll}
                  className="px-2.5 py-1 rounded bg-purple-950/80 hover:bg-purple-900 border border-purple-700/80 text-purple-300 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                >
                  {isCrawling ? (
                    <>
                      <RotateCw className="w-3 h-3 animate-spin text-purple-400" />
                      Crawling...
                    </>
                  ) : (
                    <>
                      🕷️ Deep Crawl Site
                    </>
                  )}
                </button>
              )}
            </div>
          </div>

          {/* Scrollable Table View with Sticky Header */}
          <div className="border border-[#1a2436] rounded-lg bg-[#07090e]/60 flex-1 min-h-0 overflow-y-auto overflow-x-auto shadow-inner scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead className="sticky top-0 z-10 bg-[#090d16] border-b border-[#1a2436] shadow-sm">
                <tr className="text-slate-400 text-[11px]">
                  <th className="p-3 bg-[#090d16]">Method</th>
                  <th className="p-3 bg-[#090d16]">Real Route & Page Title</th>
                  <th className="p-3 bg-[#090d16]">Status</th>
                  <th className="p-3 bg-[#090d16]">Content-Type</th>
                  <th className="p-3 bg-[#090d16]">Classification</th>
                  <th className="p-3 bg-[#090d16]">Verification</th>
                  <th className="p-3 text-right bg-[#090d16]">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#162033]">
                {filteredRoutes.map((route, idx) => {
                  const matchingTest = testCases.find(
                    (tc) => tc.component === route.path || tc.title.includes(route.path)
                  );
                  const isCurrentlyTesting =
                    testingPath === route.path ||
                    (isTestingAll && testAllProgress?.path === route.path);

                  return (
                    <tr key={idx} className="hover:bg-[#0e1524]/50 transition-colors">
                      <td className="p-3 text-cyan-400 font-bold">{route.method}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-200 font-mono font-medium">{route.path}</span>
                          {route.has_form && (
                            <span className="px-1.5 py-0.2 rounded bg-amber-950/80 text-amber-300 border border-amber-800/60 text-[9px] font-mono font-bold">
                              📝 Form
                            </span>
                          )}
                        </div>
                        {route.title && (
                          <div className="text-[11px] text-slate-400 truncate max-w-[280px] font-sans mt-0.5">
                            {route.title}
                          </div>
                        )}
                      </td>
                      <td className="p-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            route.status_code >= 200 && route.status_code < 300
                              ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                              : route.status_code === 401 || route.status_code === 403
                              ? "bg-blue-950 text-blue-300 border border-blue-800"
                              : "bg-amber-950 text-amber-300 border border-amber-800"
                          }`}
                        >
                          {route.status_code}
                        </span>
                      </td>
                      <td className="p-3 text-slate-400 text-[11px] truncate max-w-[130px]">
                        {route.content_type || "unknown"}
                      </td>
                      <td className="p-3">
                        {route.is_spa_shell ? (
                          <span className="px-2 py-0.5 rounded bg-purple-950/70 text-purple-300 border border-purple-800/60 text-[10px] font-bold">
                            SPA HTML Shell
                          </span>
                        ) : route.is_api ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-950/70 text-emerald-300 border border-emerald-800/60 text-[10px] font-bold">
                            API route
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                            Route Endpoint
                          </span>
                        )}
                      </td>
                      <td className="p-3">
                        {isCurrentlyTesting ? (
                          <span className="inline-flex items-center gap-1 text-[10px] text-cyan-400 font-mono font-bold">
                            <RotateCw className="w-2.5 h-2.5 animate-spin" />
                            Probing...
                          </span>
                        ) : matchingTest ? (
                          <span
                            className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold font-mono ${
                              matchingTest.status === "PASS"
                                ? "bg-emerald-950/90 text-emerald-300 border border-emerald-800"
                                : matchingTest.status === "FAIL"
                                ? "bg-rose-950/90 text-rose-300 border border-rose-800"
                                : matchingTest.status === "WARN"
                                ? "bg-amber-950/90 text-amber-300 border border-amber-800"
                                : "bg-cyan-950/90 text-cyan-300 border border-cyan-800"
                            }`}
                          >
                            {matchingTest.status === "PASS" && <Check className="w-2.5 h-2.5" />}
                            {matchingTest.status === "FAIL" && <AlertTriangle className="w-2.5 h-2.5" />}
                            <span>{matchingTest.status}</span>
                            {matchingTest.latency_ms !== null && (
                              <span className="text-[9px] opacity-80">({matchingTest.latency_ms}ms)</span>
                            )}
                          </span>
                        ) : (
                          <span className="text-slate-600 text-[10px] italic">Not Tested</span>
                        )}
                      </td>
                      <td className="p-3 text-right">
                        {onTestEndpoint && (
                          <button
                            type="button"
                            onClick={async () => {
                              setTestingPath(route.path);
                              try {
                                await onTestEndpoint(route.path, route.method);
                              } finally {
                                setTestingPath(null);
                              }
                            }}
                            disabled={isCurrentlyTesting || isTestingAll}
                            className="px-2 py-0.5 rounded bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-[10px] font-mono inline-flex items-center gap-1 transition-colors cursor-pointer disabled:opacity-50"
                          >
                            {isCurrentlyTesting ? (
                              <>
                                <RotateCw className="w-2.5 h-2.5 animate-spin text-cyan-400" />
                                Testing
                              </>
                            ) : matchingTest ? (
                              <>⚡ Retest</>
                            ) : (
                              <>⚡ Test URL</>
                            )}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: Evidence Ledger */}
      {activeTab === "ledger" && (
        <div className="p-4 overflow-y-auto flex-1 flex flex-col gap-4">
          <div className="flex items-center justify-between pb-2 border-b border-[#162033]">
            <span className="text-xs font-bold tracking-wider text-slate-300 uppercase">
              4-Pillar Quality & Security Evidence Ledger
            </span>
            <div className="flex items-center gap-2">
              <VerdictBadge verdict={ledgerVerdict(evidenceLedger)} />
              {ledgerScore(evidenceLedger) === null ? (
                <span className="text-xs font-mono font-bold text-slate-500">Composite score: not evaluated</span>
              ) : (
                <span className="text-xs font-mono font-bold text-cyan-400">
                  Composite Score: {ledgerScore(evidenceLedger)}%
                </span>
              )}
            </div>
          </div>

          {!evidenceLedger && (
            <div className="p-3 rounded-lg border border-slate-700 bg-slate-900/60 text-xs font-mono text-slate-400">
              No evidence ledger is loaded. Run an agent swarm (or load a stored run) to evaluate the four pillars.
            </div>
          )}

          {evidenceLedger?.executive_summary && (
            <p className="text-xs text-slate-300 leading-relaxed bg-[#07090e] border border-[#1a2436] rounded-lg p-3">
              {evidenceLedger.executive_summary}
            </p>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {getPillars(evidenceLedger).map((pillar) => (
              <div key={pillar.key} className="bg-[#07090e] border border-[#1a2436] rounded-lg p-3.5 flex flex-col gap-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-200">{pillar.title}</span>
                  {pillar.status && (
                    <span className="text-[10px] font-mono text-slate-300 bg-slate-900 border border-slate-700 px-1.5 py-0.5 rounded font-bold uppercase">
                      {pillar.status}
                    </span>
                  )}
                </div>
                {pillar.score === null ? (
                  <div className="text-xs font-mono text-slate-500">not evaluated</div>
                ) : (
                  <div className="flex items-center gap-2.5">
                    <div className="flex-1 bg-[#04060a] border border-[#162033] rounded-full h-2 overflow-hidden">
                      <div
                        className="bg-gradient-to-r from-cyan-500 to-cyan-300 h-full rounded-full transition-all duration-500"
                        style={{ width: `${Math.max(0, Math.min(100, pillar.score))}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono font-bold text-slate-200">{pillar.score}%</span>
                  </div>
                )}
                <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                  {pillar.evidence ?? "No evidence text was reported for this pillar."}
                </p>
              </div>
            ))}
          </div>

          {evidenceLedger?.exit_criteria_checklist && evidenceLedger.exit_criteria_checklist.length > 0 && (
            <div className="bg-[#07090e] border border-[#1a2436] rounded-lg p-3.5 flex flex-col gap-2">
              <span className="text-[11px] font-bold tracking-wider text-slate-300 uppercase">Exit criteria</span>
              {evidenceLedger.exit_criteria_checklist.map((c, idx) => (
                <div key={idx} className="flex items-start gap-2 text-[11px] font-mono">
                  <span className={c.met ? "text-emerald-400" : "text-rose-400"}>{c.met ? "met" : "NOT MET"}</span>
                  <span className="text-slate-200">{c.criterion}</span>
                  {c.details && <span className="text-slate-500">- {c.details}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Threat Triage */}
      {activeTab === "triage" && (
        <div className="p-4 overflow-y-auto flex-1 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#162033]">
            <span className="text-xs font-bold tracking-wider text-slate-300 uppercase">
              OWASP API Threat Triage & Blast Radius
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              {threats.length} findings triaged
            </span>
          </div>

          {threats.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs font-mono">
              {evidenceLedger
                ? "The backend triaged no defects for this run."
                : "No evaluated run is loaded, so there are no findings to show."}
            </div>
          ) : (
            <div className="flex flex-col gap-2.5">
              {threats.map((threat, idx) => (
                <div
                  key={idx}
                  className="bg-[#07090e] border border-[#1a2436] rounded-lg p-3.5 flex flex-col gap-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-rose-300 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                      {threat.title}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                      {threat.owasp_category} · {threat.severity}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">
                    <span className="text-slate-500">Affected: </span>
                    {threat.affected_routes.length > 0 ? threat.affected_routes.join(", ") : "not reported"}
                  </div>
                  {(threat.remediation_patch || threat.remediation_explanation || threat.reproduction_script) ? (
                    <AutoRemediationCard
                      patch={threat.remediation_patch}
                      explanation={threat.remediation_explanation}
                      reproScript={threat.reproduction_script}
                    />
                  ) : (
                    <div className="p-2.5 rounded bg-[#04060a] border border-[#162033] text-[11px] text-slate-300 leading-relaxed">
                      <strong className="text-cyan-400 block mb-1">Recommended Remediation:</strong>
                      {threat.remediation || "No remediation was reported."}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 5: Runs History & Reports */}
      {activeTab === "history" && (
        <div className="p-4 overflow-y-auto flex-1 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#162033]">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold tracking-wider text-slate-300 uppercase">
                Global Scans & Reports History
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40 text-cyan-300 font-bold">
                AUDIT ARCHIVE
              </span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              {runsHistory.length} runs stored
            </span>
          </div>

          {/* Search & Filter Bar */}
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                placeholder="Filter by target or run ID..."
                className="w-full bg-[#0a0f1d] border border-[#1b2b46] rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500/60"
              />
            </div>
            <select
              value={historyVerdict}
              onChange={(e) => setHistoryVerdict(e.target.value)}
              className="bg-[#0a0f1d] border border-[#1b2b46] rounded-lg px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500/60"
            >
              <option value="ALL">All Verdicts</option>
              <option value="GO">GO</option>
              <option value="CONDITIONAL_GO">Conditional</option>
              <option value="NO_GO">NO-GO</option>
              <option value="SCANNED">Scanned</option>
              <option value="NONE">No verdict</option>
            </select>
          </div>

          <div className="flex flex-col gap-2.5">
            {filteredHistory.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs font-mono">
                No matching runs found in audit history.
              </div>
            ) : (
              filteredHistory.map(({ run, runId, verdict }, idx) => {
                const isScan =
                  run.profile === "discovery-scan" ||
                  run.profile === "scan" ||
                  (run.approval_status || "").toLowerCase() === "scanned" ||
                  (!run.executed_results?.length &&
                    ((run.discovered_routes?.length ?? 0) > 0 || (run.planned_cases?.length ?? 0) > 0));
                // Scan runs carry no real gate score; only show a score the backend actually evaluated.
                const rawScore = numOrNull(run.evidence_ledger?.overall_readiness) ?? numOrNull(run.readiness_score);
                const score = verdict === "SCANNED" ? null : rawScore;
                const routesCount = run.discovered_routes?.length || 0;
                const casesCount =
                  run.executed_results?.length || run.planned_cases?.length || run.test_cases?.length || run.cases_count || 0;
                const defectsCount = runDefectCount(run);
                const timeStr = run.started_at ? new Date(run.started_at).toLocaleString() : "unknown time";

                return (
                  <div
                    key={runId + idx}
                    onClick={() => {
                      onLoadRun(run);
                      setActiveTab(isScan && (!run.executed_results || run.executed_results.length === 0) ? "routes" : "scenarios");
                    }}
                    className="p-3.5 bg-[#07090e] hover:bg-[#0e1524] border border-[#1a2436] hover:border-cyan-500/50 rounded-lg flex flex-col gap-2 cursor-pointer transition-all shadow-sm group"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold tracking-wider shrink-0 ${
                            isScan
                              ? "bg-cyan-950/80 text-cyan-300 border border-cyan-700/60"
                              : "bg-purple-950/80 text-purple-300 border border-purple-700/60"
                          }`}
                        >
                          {isScan ? "SCAN" : "AGENT SWARM"}
                        </span>
                        <span className="text-xs font-mono font-bold text-cyan-400 group-hover:text-cyan-300 transition-colors shrink-0">
                          {runId}
                        </span>
                        <span className="text-xs text-slate-200 font-medium truncate max-w-[200px]" title={run.target}>
                          {run.target}
                        </span>
                        {run.requester_ip && (
                          <span className="text-[10px] font-mono text-cyan-400/90 bg-[#0c1424] px-1.5 py-0.2 rounded border border-cyan-800/40 shrink-0 hidden sm:inline" title="Requester Egress Public IP for firewall allowlisting">
                            🌐 {run.requester_ip}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <VerdictBadge verdict={verdict} />

                        {/* Quick Report Viewer Button */}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setReportModalRunId(runId);
                          }}
                          className="px-2 py-0.5 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-[10px] font-mono flex items-center gap-1 transition-colors cursor-pointer"
                          title="View Executive HTML Report"
                        >
                          <Eye className="w-2.5 h-2.5" />
                          Report
                        </button>

                        {/* Quick Download Markdown */}
                        <ReportButton
                          path={`/api/agent/runs/${runId}/report/markdown`}
                          mode="download"
                          filename={`readyhai-agent-report-${runId}.md`}
                          stopPropagation
                          className="px-2 py-0.5 rounded bg-[#111c2e] hover:bg-[#1a2b47] border border-[#233758] text-purple-300 text-[10px] font-mono flex items-center gap-1 transition-colors cursor-pointer"
                          title="Download Markdown summary"
                        >
                          <FileCode className="w-2.5 h-2.5" />
                          MD
                        </ReportButton>

                        {onDeleteRun && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onDeleteRun(runId);
                            }}
                            title="Delete run from history"
                            className="p-1 text-slate-500 hover:text-rose-400 hover:bg-rose-950/40 rounded transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center justify-between pt-1 border-t border-[#162033] text-[11px] font-mono text-slate-400">
                      <div className="flex items-center gap-3">
                        <span>
                          Score:{" "}
                          {score === null ? (
                            <strong className="text-slate-500">not evaluated</strong>
                          ) : (
                            <strong className="text-cyan-400">{score}%</strong>
                          )}
                        </span>
                        {routesCount > 0 && (
                          <span>
                            Routes: <strong className="text-slate-300">{routesCount}</strong>
                          </span>
                        )}
                        <span>
                          Tests: <strong className="text-slate-300">{casesCount}</strong>
                        </span>
                        <span>
                          Defects:{" "}
                          {defectsCount === null ? (
                            <strong className="text-slate-500">unknown</strong>
                          ) : (
                            <strong className={defectsCount === 0 ? "text-slate-300" : "text-rose-400"}>
                              {defectsCount}
                            </strong>
                          )}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 text-[10px]">{timeStr}</span>
                        <span className="text-[10px] text-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity font-semibold">
                          Load ➔
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* EMBEDDED REPORT MODAL IN SIDE CANVAS */}
      {reportModalRunId && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b101b] border border-[#1e2f4a] rounded-xl w-full max-w-5xl h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-[#1b2b46] flex items-center justify-between bg-[#0e172a]">
              <div className="flex items-center gap-2.5">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-bold text-white font-mono">
                  ReadyHai Executive QA & Security Gate Report (HTML)
                </span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {reportModalRunId}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <ReportButton
                  path={`/api/agent/runs/${reportModalRunId}/report/html`}
                  mode="tab"
                  className="px-2.5 py-1 rounded bg-[#16233a] hover:bg-[#1f304f] border border-[#273d63] text-cyan-300 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                  title="Open report in new tab"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  New Tab
                </ReportButton>
                <ReportButton
                  path={`/api/agent/runs/${reportModalRunId}/report/markdown`}
                  mode="download"
                  filename={`readyhai-agent-report-${reportModalRunId}.md`}
                  className="px-2.5 py-1 rounded bg-[#16233a] hover:bg-[#1f304f] border border-[#273d63] text-purple-300 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                  title="Download Markdown report"
                >
                  <FileCode className="w-3.5 h-3.5" />
                  Markdown
                </ReportButton>
                <button
                  type="button"
                  onClick={() => setReportModalRunId(null)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[#16233a] transition-colors cursor-pointer"
                  title="Close report modal"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="flex-1 w-full h-full bg-[#070b14] relative">
              <ReportFrame
                path={`/api/agent/runs/${reportModalRunId}/report/html`}
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