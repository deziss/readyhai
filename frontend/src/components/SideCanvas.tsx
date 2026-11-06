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
  Trash2,
  RotateCw,
  Check,
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
  blockReasonLabel,
  getPillars,
  ledgerBlockers,
  ledgerConfidence,
  ledgerScore,
  ledgerVerdict,
  normalizeVerdict,
  numOrNull,
  runDefectCount,
  runId as getRunId,
} from "@/lib/runs";
import { ReportButton, ReportFrame } from "./ReportButton";
import { VerdictBadge } from "./VerdictBadge";
import { NextStepsCard, PillarCard } from "./LedgerPanels";
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

/** "NO_GO" / "PASS" / "critical" -> "No go" / "Pass" / "Critical". */
function humanize(v: string): string {
  const t = (v || "").replace(/_/g, " ").trim().toLowerCase();
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : t;
}

function severityTone(severity: string): string {
  const s = (severity || "").toUpperCase();
  if (s === "CRITICAL") return "bg-rh-nogo/15 text-rh-nogo";
  if (s === "HIGH" || s === "MEDIUM") return "bg-rh-cond/15 text-rh-cond";
  if (s === "LOW") return "bg-rh-info/15 text-rh-info";
  return "bg-rh-raised text-rh-muted";
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

  const focusRing = "focus-visible:outline-2 focus-visible:outline-rh-primary";
  const inputRing =
    "focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
  const tabs: { id: typeof activeTab; label: string; icon: typeof ListFilter; count?: number; countTone?: string }[] = [
    { id: "scenarios", label: "Scenarios and inspector", icon: ListFilter, count: testCases.length },
    { id: "routes", label: "Discovered routes", icon: Network, count: discoveredRoutes.length },
    { id: "ledger", label: "Evidence ledger", icon: ShieldCheck },
    { id: "triage", label: "Threat triage", icon: AlertTriangle, count: threats.length, countTone: "bg-rh-nogo/15 text-rh-nogo" },
    { id: "history", label: "Runs history", icon: Clock },
  ];

  return (
    <div className="bg-rh-surface border border-rh-line rounded-[10px] flex flex-col h-full min-h-0 overflow-hidden">
      <div role="tablist" aria-label="Results sections" className="flex items-center gap-1.5 p-2 border-b border-rh-line bg-rh-surface shrink-0 overflow-x-auto">
        {tabs.map((t) => {
          const Icon = t.icon;
          const active = activeTab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={active}
              onClick={() => setActiveTab(t.id)}
              className={`flex items-center gap-2 px-3 py-2 rounded-[6px] text-xs transition-colors whitespace-nowrap cursor-pointer ${focusRing} ${
                active ? "bg-rh-raised text-rh-text font-semibold" : "text-rh-muted hover:text-rh-text hover:bg-rh-raised"
              }`}
            >
              <Icon className="w-3.5 h-3.5" aria-hidden="true" />
              {t.label}
              {t.count !== undefined && (
                <span
                  className={`text-xs px-1.5 py-0.5 rounded-[6px] font-semibold tabular-nums ${
                    t.countTone ?? "bg-rh-bg text-rh-muted"
                  }`}
                >
                  {t.count}
                </span>
              )}
            </button>
          );
        })}

        {onOpenAgentHistory && (
          <button
            type="button"
            id="tab-btn-open-qa-reports"
            onClick={onOpenAgentHistory}
            className={`ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-primary/15 hover:bg-rh-primary/25 text-rh-primary text-xs font-semibold transition-colors cursor-pointer shrink-0 ${focusRing}`}
            title="Open QA agent reports and swarm history"
          >
            <Bot className="w-3.5 h-3.5" aria-hidden="true" />
            <span>QA agent reports</span>
            <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
        )}
      </div>

      {/* Scenarios and payload inspector */}
      {activeTab === "scenarios" && (
        <div className="px-4 pb-4 pt-0 min-h-0 overflow-y-auto flex-1 flex flex-col gap-3" role="tabpanel">
          <Scenarios testCases={testCases} onRetestCase={onRetestCase} />
        </div>
      )}

      {/* Discovered routes */}
      {activeTab === "routes" && (
        <div className="p-4 flex-1 min-h-0 flex flex-col gap-3 overflow-hidden" role="tabpanel">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-rh-line shrink-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-rh-text">Target endpoint discovery</h3>
              <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text font-semibold">
                {appArchitecture || (isSpa ? "SPA shell detected" : "Architecture not reported")}
              </span>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-rh-muted absolute left-2.5 top-1/2 -translate-y-1/2" aria-hidden="true" />
                <input
                  type="text"
                  value={routeSearch}
                  onChange={(e) => setRouteSearch(e.target.value)}
                  placeholder="Filter routes"
                  aria-label="Filter routes"
                  className={`pl-8 pr-2 py-1.5 text-xs bg-rh-bg border border-rh-line rounded-[6px] text-rh-text placeholder:text-rh-muted w-40 ${inputRing}`}
                />
              </div>

              <span className="text-xs text-rh-muted whitespace-nowrap tabular-nums">
                {filteredRoutes.length} of {discoveredRoutes.length} real routes
              </span>

              {onTestEndpoint && (
                <button
                  type="button"
                  onClick={handleTestAll}
                  disabled={isTestingAll || isCrawling || discoveredRoutes.length === 0}
                  className={`px-2.5 py-1.5 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 ${focusRing}`}
                  title="Probe every discovered endpoint for liveness, 5xx errors, stack trace leaks and response latency"
                >
                  {isTestingAll ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                      <span className="tabular-nums">
                        Testing ({testAllProgress?.current || 0}/{discoveredRoutes.length})...
                      </span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
                      <span>Test all ({discoveredRoutes.length})</span>
                    </>
                  )}
                </button>
              )}

              {onCrawlSite && (
                <button
                  type="button"
                  onClick={onCrawlSite}
                  disabled={isCrawling || isTestingAll}
                  className={`px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 ${focusRing}`}
                >
                  {isCrawling ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                      Crawling...
                    </>
                  ) : (
                    <>Deep crawl site</>
                  )}
                </button>
              )}
            </div>
          </div>

          {filteredRoutes.length === 0 ? (
            <div className="flex-1 min-h-0 border border-dashed border-rh-line rounded-[10px] p-8 text-center text-xs text-rh-muted">
              <p className="text-sm font-semibold text-rh-text">
                {discoveredRoutes.length === 0 ? "No routes discovered yet" : "No routes match this filter"}
              </p>
              <p className="mt-1">
                {discoveredRoutes.length === 0
                  ? onCrawlSite
                    ? "Select Deep crawl site, or run an audit, to discover the target's routes."
                    : "Run an audit to discover the target's routes."
                  : "Clear the filter to see all routes again."}
              </p>
            </div>
          ) : (
            <div className="border border-rh-line rounded-[10px] bg-rh-bg flex-1 min-h-0 overflow-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="sticky top-0 z-10">
                  <tr className="text-rh-muted text-xs">
                    <th scope="col" className="px-3 py-2.5 bg-rh-raised font-semibold">Method</th>
                    <th scope="col" className="px-3 py-2.5 bg-rh-raised font-semibold">Route and page title</th>
                    <th scope="col" className="px-3 py-2.5 bg-rh-raised font-semibold text-right">Status</th>
                    <th scope="col" className="px-3 py-2.5 bg-rh-raised font-semibold">Content type</th>
                    <th scope="col" className="px-3 py-2.5 bg-rh-raised font-semibold">Classification</th>
                    <th scope="col" className="px-3 py-2.5 bg-rh-raised font-semibold">Verification</th>
                    <th scope="col" className="px-3 py-2.5 bg-rh-raised font-semibold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-rh-line">
                  {filteredRoutes.map((route, idx) => {
                    const matchingTest = testCases.find(
                      (tc) => tc.component === route.path || tc.title.includes(route.path)
                    );
                    const isCurrentlyTesting =
                      testingPath === route.path ||
                      (isTestingAll && testAllProgress?.path === route.path);

                    return (
                      <tr key={idx} className="hover:bg-rh-raised transition-colors">
                        <td className="px-3 py-2.5 text-rh-text font-mono font-semibold">{route.method}</td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <span className="text-rh-text font-mono break-all">{route.path}</span>
                            {route.has_form && (
                              <span className="px-1.5 py-0.5 rounded-[6px] bg-rh-info/15 text-rh-info text-xs font-semibold shrink-0">
                                Form
                              </span>
                            )}
                          </div>
                          {route.title && (
                            <div className="text-xs text-rh-muted truncate max-w-[280px] mt-0.5">{route.title}</div>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-right">
                          <span
                            className={`px-1.5 py-0.5 rounded-[6px] text-xs font-semibold tabular-nums ${
                              route.status_code >= 200 && route.status_code < 300
                                ? "bg-rh-go/15 text-rh-go"
                                : route.status_code === 401 || route.status_code === 403
                                ? "bg-rh-info/15 text-rh-info"
                                : route.status_code >= 500
                                ? "bg-rh-nogo/15 text-rh-nogo"
                                : "bg-rh-cond/15 text-rh-cond"
                            }`}
                          >
                            {route.status_code}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-rh-muted text-xs truncate max-w-[130px]">
                          {route.content_type || "unknown"}
                        </td>
                        <td className="px-3 py-2.5">
                          {route.is_spa_shell ? (
                            <span className="px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text text-xs font-semibold">
                              SPA HTML shell
                            </span>
                          ) : route.is_api ? (
                            <span className="px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text text-xs font-semibold">
                              API route
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted text-xs">
                              Route endpoint
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          {isCurrentlyTesting ? (
                            <span className="inline-flex items-center gap-1 text-xs text-rh-info font-semibold">
                              <RotateCw className="w-3 h-3 animate-spin" aria-hidden="true" />
                              Probing...
                            </span>
                          ) : matchingTest ? (
                            <span
                              title={blockReasonLabel(matchingTest.blocked_reason) ?? undefined}
                              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-[6px] text-xs font-semibold ${
                                matchingTest.status === "PASS"
                                  ? "bg-rh-go/15 text-rh-go"
                                  : matchingTest.status === "FAIL"
                                  ? "bg-rh-nogo/15 text-rh-nogo"
                                  : matchingTest.status === "WARN"
                                  ? "bg-rh-cond/15 text-rh-cond"
                                  : "bg-rh-raised text-rh-muted"
                              }`}
                            >
                              {matchingTest.status === "PASS" && <Check className="w-3 h-3" aria-hidden="true" />}
                              {matchingTest.status === "FAIL" && <AlertTriangle className="w-3 h-3" aria-hidden="true" />}
                              <span>{humanize(matchingTest.status)}</span>
                              {matchingTest.latency_ms !== null && (
                                <span className="text-xs font-normal tabular-nums">({matchingTest.latency_ms}ms)</span>
                              )}
                            </span>
                          ) : (
                            <span className="text-rh-muted text-xs">Not tested</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-right">
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
                              className={`px-2.5 py-1 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs inline-flex items-center gap-1 transition-colors cursor-pointer disabled:opacity-50 ${focusRing}`}
                            >
                              {isCurrentlyTesting ? (
                                <>
                                  <RotateCw className="w-3 h-3 animate-spin" aria-hidden="true" />
                                  Testing
                                </>
                              ) : matchingTest ? (
                                <>Retest</>
                              ) : (
                                <>Test URL</>
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
          )}
        </div>
      )}

      {/* Evidence ledger */}
      {activeTab === "ledger" && (
        <div className="p-4 min-h-0 overflow-y-auto flex-1 flex flex-col gap-4" role="tabpanel">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-rh-line">
            <h3 className="text-sm font-semibold text-rh-text">Quality and security evidence ledger</h3>
            <div className="flex items-center gap-2">
              <VerdictBadge verdict={ledgerVerdict(evidenceLedger)} />
              {ledgerScore(evidenceLedger) === null ? (
                <span className="text-xs font-semibold text-rh-muted">Composite score: not evaluated</span>
              ) : (
                <span className="text-xs font-semibold text-rh-text tabular-nums">
                  Composite score: {ledgerScore(evidenceLedger)}%
                </span>
              )}
              {ledgerConfidence(evidenceLedger) !== null && (
                <span
                  className="text-xs text-rh-muted bg-rh-raised px-1.5 py-0.5 rounded-[6px] font-medium tabular-nums"
                  title="Share of the applicable cases that gave a conclusive result"
                >
                  confidence {ledgerConfidence(evidenceLedger)}%
                </span>
              )}
            </div>
          </div>

          {!evidenceLedger && (
            <div className="p-4 rounded-[10px] border border-dashed border-rh-line text-xs text-rh-muted">
              <p className="text-sm font-semibold text-rh-text">No evidence ledger is loaded</p>
              <p className="mt-1">Run an agent swarm, or load a stored run from Runs history, to evaluate the four pillars.</p>
            </div>
          )}

          {evidenceLedger?.executive_summary && (
            <p className="text-xs text-rh-text leading-relaxed bg-rh-bg border border-rh-line rounded-[6px] p-3">
              {evidenceLedger.executive_summary}
            </p>
          )}

          <NextStepsCard blockers={ledgerBlockers(evidenceLedger)} />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {getPillars(evidenceLedger).map((pillar) => (
              <PillarCard key={pillar.key} pillar={pillar} />
            ))}
          </div>

          {evidenceLedger?.exit_criteria_checklist && evidenceLedger.exit_criteria_checklist.length > 0 && (
            <div className="bg-rh-bg border border-rh-line rounded-[10px] p-3.5 flex flex-col gap-2">
              <span className="text-sm font-semibold text-rh-text">Exit criteria</span>
              {evidenceLedger.exit_criteria_checklist.map((c, idx) => (
                <div key={idx} className="flex items-start gap-2 text-xs">
                  <span
                    className={`px-1.5 py-0.5 rounded-[6px] font-semibold shrink-0 ${
                      c.met ? "bg-rh-go/15 text-rh-go" : "bg-rh-nogo/15 text-rh-nogo"
                    }`}
                  >
                    {c.met ? "Met" : "Not met"}
                  </span>
                  <span className="text-rh-text py-0.5">{c.criterion}</span>
                  {c.details && <span className="text-rh-muted py-0.5">- {c.details}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Threat triage */}
      {activeTab === "triage" && (
        <div className="p-4 min-h-0 overflow-y-auto flex-1 flex flex-col gap-3" role="tabpanel">
          <div className="flex items-center justify-between pb-3 border-b border-rh-line">
            <h3 className="text-sm font-semibold text-rh-text">Threat triage and blast radius</h3>
            <span className="text-xs text-rh-muted tabular-nums">{threats.length} findings triaged</span>
          </div>

          {threats.length === 0 ? (
            <div className="p-8 text-center text-rh-muted text-xs border border-dashed border-rh-line rounded-[10px]">
              <p className="text-sm font-semibold text-rh-text">
                {evidenceLedger ? "No defects were triaged for this run" : "No evaluated run is loaded"}
              </p>
              <p className="mt-1">
                {evidenceLedger
                  ? "The backend triaged no defects, so there is nothing to remediate."
                  : "Run an audit, or load a stored run from Runs history, to see triaged findings."}
              </p>
            </div>
          ) : (
            <div className="flex flex-col gap-2.5">
              {threats.map((threat, idx) => (
                <div
                  key={idx}
                  className="bg-rh-bg border border-rh-line rounded-[10px] p-3.5 flex flex-col gap-2"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-rh-text flex items-center gap-2 min-w-0">
                      <AlertTriangle className="w-4 h-4 text-rh-nogo shrink-0" aria-hidden="true" />
                      {threat.title}
                    </span>
                    <span className="flex items-center gap-1.5 shrink-0">
                      <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted font-medium">
                        {threat.owasp_category}
                      </span>
                      <span className={`text-xs px-2 py-0.5 rounded-[6px] font-semibold ${severityTone(threat.severity)}`}>
                        {humanize(threat.severity)}
                      </span>
                    </span>
                  </div>
                  <div className="text-xs text-rh-muted">
                    <span>Affected: </span>
                    <span className="text-rh-text font-mono break-all">
                      {threat.affected_routes.length > 0 ? threat.affected_routes.join(", ") : "not reported"}
                    </span>
                  </div>
                  {(threat.remediation_patch || threat.remediation_explanation || threat.reproduction_script) ? (
                    <AutoRemediationCard
                      patch={threat.remediation_patch}
                      explanation={threat.remediation_explanation}
                      reproScript={threat.reproduction_script}
                    />
                  ) : (
                    <div className="p-2.5 rounded-[6px] bg-rh-surface border border-rh-line text-xs text-rh-text leading-relaxed">
                      <strong className="text-rh-text block mb-1 font-semibold">Recommended remediation</strong>
                      {threat.remediation || "No remediation was reported."}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Runs history and reports */}
      {activeTab === "history" && (
        <div className="p-4 flex-1 min-h-0 flex flex-col gap-3 overflow-hidden" role="tabpanel">
          <div className="flex items-center justify-between pb-3 border-b border-rh-line shrink-0">
            <h3 className="text-sm font-semibold text-rh-text">Scan and report history</h3>
            <span className="text-xs text-rh-muted tabular-nums">{runsHistory.length} runs stored</span>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-rh-muted absolute left-2.5 top-1/2 -translate-y-1/2" aria-hidden="true" />
              <input
                type="text"
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                placeholder="Filter by target or run ID"
                aria-label="Filter runs by target or run ID"
                className={`w-full bg-rh-bg border border-rh-line rounded-[6px] pl-8 pr-3 py-1.5 text-xs text-rh-text placeholder:text-rh-muted ${inputRing}`}
              />
            </div>
            <select
              value={historyVerdict}
              onChange={(e) => setHistoryVerdict(e.target.value)}
              aria-label="Filter runs by verdict"
              className={`bg-rh-bg border border-rh-line rounded-[6px] px-2.5 py-1.5 text-xs text-rh-text cursor-pointer ${inputRing}`}
            >
              <option value="ALL">All verdicts</option>
              <option value="GO">GO</option>
              <option value="CONDITIONAL_GO">Conditional go</option>
              <option value="NO_GO">No go</option>
              <option value="NOT_EVALUATED">Not evaluated</option>
              <option value="SCANNED">Scanned</option>
              <option value="NONE">No verdict</option>
            </select>
          </div>

          <div className="flex flex-col gap-2.5 flex-1 min-h-0 overflow-y-auto">
            {filteredHistory.length === 0 ? (
              <div className="p-8 text-center text-rh-muted text-xs border border-dashed border-rh-line rounded-[10px]">
                <p className="text-sm font-semibold text-rh-text">
                  {runsHistory.length === 0 ? "No runs stored yet" : "No runs match these filters"}
                </p>
                <p className="mt-1">
                  {runsHistory.length === 0
                    ? "Run an agent audit or a scan and it will appear here."
                    : "Clear the search text or set the verdict filter back to All verdicts."}
                </p>
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
                const score = verdict === "SCANNED" || verdict === "NOT_EVALUATED" ? null : rawScore;
                const routesCount = run.discovered_routes?.length || 0;
                const casesCount =
                  run.executed_results?.length || run.planned_cases?.length || run.test_cases?.length || run.cases_count || 0;
                const defectsCount = runDefectCount(run);
                const timeStr = run.started_at ? new Date(run.started_at).toLocaleString() : "unknown time";
                const loadRun = () => {
                  onLoadRun(run);
                  setActiveTab(isScan && (!run.executed_results || run.executed_results.length === 0) ? "routes" : "scenarios");
                };

                return (
                  <div
                    key={runId + idx}
                    role="button"
                    tabIndex={0}
                    onClick={loadRun}
                    onKeyDown={(e) => {
                      if (e.target !== e.currentTarget) return;
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        loadRun();
                      }
                    }}
                    className="p-3.5 bg-rh-bg hover:bg-rh-raised border border-rh-line rounded-[10px] flex flex-col gap-2 cursor-pointer transition-colors group focus-visible:outline-2 focus-visible:outline-rh-primary"
                    aria-label={`Load run ${runId} for ${run.target}`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="px-1.5 py-0.5 rounded-[6px] text-xs font-semibold shrink-0 bg-rh-raised text-rh-text">
                          {isScan ? "Scan" : "Agent swarm"}
                        </span>
                        <span className="text-xs font-mono text-rh-muted shrink-0">{runId}</span>
                        <span className="text-xs font-mono text-rh-text truncate max-w-[200px]" title={run.target}>
                          {run.target}
                        </span>
                        {run.requester_ip && (
                          <span
                            className="text-xs text-rh-muted bg-rh-raised px-1.5 py-0.5 rounded-[6px] shrink-0 hidden sm:inline"
                            title="Requester egress public IP, for firewall allowlisting"
                          >
                            Egress IP <span className="font-mono text-rh-text">{run.requester_ip}</span>
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <VerdictBadge verdict={verdict} />

                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setReportModalRunId(runId);
                          }}
                          className={`px-2 py-1 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs flex items-center gap-1 transition-colors cursor-pointer ${focusRing}`}
                          title="View executive HTML report"
                        >
                          <Eye className="w-3.5 h-3.5" aria-hidden="true" />
                          Report
                        </button>

                        <ReportButton
                          path={`/api/agent/runs/${runId}/report/markdown`}
                          mode="download"
                          filename={`readyhai-agent-report-${runId}.md`}
                          stopPropagation
                          className={`px-2 py-1 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs flex items-center gap-1 transition-colors cursor-pointer ${focusRing}`}
                          title="Download Markdown summary"
                        >
                          <FileCode className="w-3.5 h-3.5" aria-hidden="true" />
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
                            aria-label={`Delete run ${runId}`}
                            className={`p-1.5 text-rh-muted hover:text-rh-nogo hover:bg-rh-nogo/15 rounded-[6px] transition-colors cursor-pointer ${focusRing}`}
                          >
                            <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-rh-line text-xs text-rh-muted">
                      <div className="flex items-center gap-4 flex-wrap tabular-nums">
                        <span>
                          Score:{" "}
                          {score === null ? (
                            <strong className="text-rh-muted font-semibold">not evaluated</strong>
                          ) : (
                            <strong className="text-rh-text font-semibold">{score}%</strong>
                          )}
                        </span>
                        {routesCount > 0 && (
                          <span>
                            Routes: <strong className="text-rh-text font-semibold">{routesCount}</strong>
                          </span>
                        )}
                        <span>
                          Tests: <strong className="text-rh-text font-semibold">{casesCount}</strong>
                        </span>
                        <span>
                          Defects:{" "}
                          {defectsCount === null ? (
                            <strong className="text-rh-muted font-semibold">unknown</strong>
                          ) : (
                            <strong className={`font-semibold ${defectsCount === 0 ? "text-rh-text" : "text-rh-nogo"}`}>
                              {defectsCount}
                            </strong>
                          )}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-rh-muted text-xs tabular-nums">{timeStr}</span>
                        <span className="text-xs text-rh-muted group-hover:text-rh-primary font-semibold transition-colors">
                          Load run
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

      {/* Report dialog */}
      {reportModalRunId && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Executive QA and security gate report"
          className="fixed inset-0 z-50 bg-rh-bg/80 flex items-center justify-center p-4"
        >
          <div className="bg-rh-surface border border-rh-line rounded-[10px] w-full max-w-5xl h-full max-h-[90vh] flex flex-col overflow-hidden shadow-lg">
            <div className="px-5 py-3 border-b border-rh-line flex flex-wrap items-center justify-between gap-2 bg-rh-surface shrink-0">
              <div className="flex items-center gap-2.5 min-w-0">
                <FileText className="w-4 h-4 text-rh-muted shrink-0" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-rh-text">
                  ReadyHai executive QA and security gate report (HTML)
                </h3>
                <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted font-mono truncate">
                  {reportModalRunId}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <ReportButton
                  path={`/api/agent/runs/${reportModalRunId}/report/html`}
                  mode="tab"
                  className={`px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs flex items-center gap-1.5 transition-colors cursor-pointer ${focusRing}`}
                  title="Open report in a new tab"
                >
                  <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                  New tab
                </ReportButton>
                <ReportButton
                  path={`/api/agent/runs/${reportModalRunId}/report/markdown`}
                  mode="download"
                  filename={`readyhai-agent-report-${reportModalRunId}.md`}
                  className={`px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs flex items-center gap-1.5 transition-colors cursor-pointer ${focusRing}`}
                  title="Download Markdown report"
                >
                  <FileCode className="w-3.5 h-3.5" aria-hidden="true" />
                  Markdown
                </ReportButton>
                <button
                  type="button"
                  onClick={() => setReportModalRunId(null)}
                  className={`p-1.5 rounded-[6px] text-rh-muted hover:text-rh-text hover:bg-rh-raised transition-colors cursor-pointer ${focusRing}`}
                  title="Close report"
                  aria-label="Close report"
                >
                  <X className="w-4 h-4" aria-hidden="true" />
                </button>
              </div>
            </div>
            <div className="flex-1 min-h-0 w-full bg-rh-bg relative">
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
