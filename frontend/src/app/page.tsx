"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Header, SaaSViewMode } from "@/components/Header";
import { Composer } from "@/components/Composer";
import { ToolCallList, StageState } from "@/components/ToolCallList";
import { SideCanvas } from "@/components/SideCanvas";
import { ApprovalCard, type SignOffAction } from "@/components/ApprovalCard";
import { GlobalNotices } from "@/components/GlobalNotices";
import { ScansHistoryView } from "@/components/ScansHistoryView";
import { AgentHistoryView } from "@/components/AgentHistoryView";
import { NetworkLabView } from "@/components/NetworkLabView";
import { FloatingTaskWidget, ActiveTaskItem } from "@/components/FloatingTaskWidget";
import { apiRequest, errorText, notify, useApiTokenVersion } from "@/lib/api";
import {
  buildLedger,
  isGateVerdict,
  ledgerScore,
  ledgerVerdict,
  mergeRetestResult,
  runCases,
  runDefectCount,
  runId as getRunId,
  runThreats,
  strOrNull,
} from "@/lib/runs";
import type {
  AgentRunRecord,
  ModelTier,
  RawCaseResult,
  TestCaseResult,
  ThreatFinding,
  EvidenceLedger,
  DiscoveredTarget,
} from "@/types/agent";

export default function Home() {
  const [activeView, setActiveView] = useState<SaaSViewMode>("studio");
  const [scansCount, setScansCount] = useState<number>(0);
  const [agentRunsCount, setAgentRunsCount] = useState<number>(0);

  // Studio Form state
  const [target, setTarget] = useState("http://readyhai:8080");
  const [specUrl, setSpecUrl] = useState("");
  const [directives, setDirectives] = useState("Strict QA and verify resilience, contracts, and authz");
  const [profile, setProfile] = useState("discovery-scan");
  const [maxSteps, setMaxSteps] = useState(15);
  const [thinking, setThinking] = useState(true);
  const [modelTier, setModelTier] = useState<ModelTier>("high");
  const [thinkingBudget, setThinkingBudget] = useState(8192);

  // Discovered Routes
  const [discoveredData, setDiscoveredData] = useState<DiscoveredTarget | null>(null);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [isCrawling, setIsCrawling] = useState(false);

  // Execution Stages
  const [stages, setStages] = useState<StageState[]>([
    { id: "discovery", label: "Supervisor & Recon", subtext: "Model connectivity & target health check", status: "standby" },
    { id: "planner", label: "Discovery Engine", subtext: "Endpoint inspection & route mapping", status: "standby" },
    { id: "explorer", label: "Adversarial Planner", subtext: "Synthesis of negative & boundary cases", status: "standby" },
    { id: "triager", label: "Critic & Triager", subtext: "OWASP vulnerability triage & Evidence Ledger", status: "standby" },
  ]);
  const [isRunning, setIsRunning] = useState(false);

  // Results State
  const [testCases, setTestCases] = useState<TestCaseResult[]>([]);
  const [threats, setThreats] = useState<ThreatFinding[]>([]);
  const [evidenceLedger, setEvidenceLedger] = useState<EvidenceLedger | null>(null);
  const [defectCount, setDefectCount] = useState<number | null>(null);
  const [runsHistory, setRunsHistory] = useState<AgentRunRecord[]>([]);
  const [currentRunId, setCurrentRunId] = useState<string | null>(null);
  const [activeTasks, setActiveTasks] = useState<ActiveTaskItem[]>([]);

  const tokenVersion = useApiTokenVersion();
  const stageTimers = useRef<number[]>([]);
  const loadSeq = useRef(0);

  // Fetch counts and history (polled). Errors are not surfaced here: a 401 raises the
  // "set your API token" banner via the API helper, and a flaky poll should not spam notices.
  const fetchCountsAndHistory = useCallback(
    () =>
      Promise.all([
        apiRequest<AgentRunRecord[] | { runs?: AgentRunRecord[] }>("/api/agent/runs", { label: "Runs list" }),
        apiRequest<{ scans?: unknown[] }>("/api/scans", { label: "Scans list" }),
      ]).then(([agentRes, scansRes]) => {
        if (agentRes.ok && agentRes.data) {
          const d = agentRes.data;
          const runsList: AgentRunRecord[] = Array.isArray(d) ? d : d.runs || [];
          setRunsHistory(runsList);
          setAgentRunsCount(runsList.length);
        }
        if (scansRes.ok && scansRes.data) {
          setScansCount((scansRes.data.scans || []).length);
        }
      }),
    []
  );

  useEffect(() => {
    fetchCountsAndHistory();
    const interval = setInterval(fetchCountsAndHistory, 12000);
    return () => clearInterval(interval);
  }, [fetchCountsAndHistory, tokenVersion]);

  // The simulated stage-progress timers must never outlive the launch (or the page).
  const clearStageTimers = useCallback(() => {
    stageTimers.current.forEach((id) => window.clearTimeout(id));
    stageTimers.current = [];
  }, []);
  useEffect(() => clearStageTimers, [clearStageTimers]);

  async function handleDiscover() {
    if (!target) return;
    setIsDiscovering(true);
    try {
      const r = await apiRequest<DiscoveredTarget>("/api/agent/discover", {
        method: "POST",
        json: { target },
        label: "Discovery",
      });
      if (r.ok && r.data) setDiscoveredData(r.data);
      else notify(r.ok ? "Discovery returned no data." : r.error);
    } finally {
      setIsDiscovering(false);
    }
  }

  async function handleCrawl() {
    if (!target) return;
    setIsCrawling(true);
    try {
      const r = await apiRequest<DiscoveredTarget>("/api/agent/crawl", {
        method: "POST",
        json: { target, max_pages: 35 },
        label: "Crawl",
      });
      if (r.ok && r.data) setDiscoveredData(r.data);
      else notify(r.ok ? "Crawl returned no data." : r.error);
    } finally {
      setIsCrawling(false);
    }
  }

  async function handleTestEndpoint(path: string, method: string = "GET") {
    if (!target) return;
    const testId = `CRAWL-${Math.floor(100 + Math.random() * 900)}`;
    const newCase: TestCaseResult = {
      id: testId,
      title: `Direct Probe: ${path}`,
      component: path,
      technique: "crawled_url_probe",
      method: method,
      status: "PENDING",
      latency_ms: null,
      curl: `curl -i -X ${method} "${target.replace(/\/$/, "")}${path}"`,
      assertion_details: "Active verification of crawled real URL",
    };
    setTestCases((prev) => [newCase, ...prev.filter((c) => c.id !== testId)]);

    const r = await apiRequest<RawCaseResult>("/api/agent/retest", {
      method: "POST",
      json: {
        target,
        case: {
          id: testId,
          title: `Direct Probe: ${path}`,
          component: path,
          method: method,
          technique: "crawled_url_probe",
          input_hint: "Target crawl verification",
          payload: null,
          expected_behavior: "Returns valid HTTP response (non-500)",
          expected_status: 200,
          risk_level: "low",
        },
        run_id: currentRunId || null,
      },
      label: "Endpoint probe",
    });

    if (r.ok && r.data) {
      const result = r.data;
      setTestCases((prev) => prev.map((c) => (c.id === testId ? mergeRetestResult(c, result) : c)));
      return;
    }
    // The probe itself did not run: do not report it as a pass or as a target failure.
    const msg = r.ok ? "Endpoint probe returned no result." : r.error;
    setTestCases((prev) =>
      prev.map((c) =>
        c.id === testId ? { ...c, status: "SKIPPED", assertion_details: `Probe did not run: ${msg}` } : c
      )
    );
    notify(msg);
  }

  async function handleLaunch() {
    if (isRunning) return;
    clearStageTimers();
    setIsRunning(true);
    setActiveTasks((prev) => [
      ...prev.filter((t) => t.id !== "agent_swarm"),
      {
        id: "agent_swarm",
        title: "Autonomous Agent QA Swarm",
        target,
        view: "studio",
        status: "running",
        detail: "Adversarial Synthesis & OWASP Triage",
        startTime: Date.now(),
      },
    ]);
    setStages([
      { id: "discovery", label: "Supervisor & Recon", subtext: "Connecting to model & initial health probes", status: "running" },
      { id: "planner", label: "Discovery Engine", subtext: "Probing root and discovering candidate paths", status: "standby" },
      { id: "explorer", label: "Adversarial Planner", subtext: "Synthesizing adversarial test scenarios", status: "standby" },
      { id: "triager", label: "Critic & Triager", subtext: "Triaging OWASP defects and compiling Evidence Ledger", status: "standby" },
    ]);

    // Cosmetic progress only (the run endpoint is synchronous); cleared as soon as the
    // request settles and on unmount.
    stageTimers.current.push(
      window.setTimeout(() => {
        setStages((prev) =>
          prev.map((s, idx) =>
            idx === 0 ? { ...s, status: "succeeded" } : idx === 1 ? { ...s, status: "running" } : s
          )
        );
      }, 800),
      window.setTimeout(() => {
        setStages((prev) =>
          prev.map((s, idx) =>
            idx <= 1 ? { ...s, status: "succeeded" } : idx === 2 ? { ...s, status: "running" } : s
          )
        );
      }, 1500)
    );

    const failLaunch = (message: string) => {
      clearStageTimers();
      // Every stage that had started is marked failed; untouched stages stay on standby.
      setStages((prev) => prev.map((s) => (s.status === "standby" ? s : { ...s, status: "failed" })));
      setActiveTasks((prev) =>
        prev.map((t) => (t.id === "agent_swarm" ? { ...t, status: "failed", detail: message } : t))
      );
      notify(message);
    };

    try {
      const payload = {
        target,
        spec_url: specUrl || null,
        directives,
        profile,
        max_steps: maxSteps,
        thinking,
        model_tier: modelTier,
        thinking_budget_tokens: thinkingBudget,
      };

      const r = await apiRequest<AgentRunRecord & { report?: AgentRunRecord }>("/api/agent/run", {
        method: "POST",
        json: payload,
        label: "Agent run",
      });
      clearStageTimers();

      if (!r.ok) {
        failLaunch(r.error);
        return;
      }
      const rep = r.data?.report ?? r.data;
      if (!rep) {
        failLaunch("Agent run failed: the backend returned an empty response.");
        return;
      }

      await handleLoadRun(rep);

      if (rep.status === "failed" || rep.error) {
        failLaunch(`Agent run failed: ${rep.error || "the backend reported status \"failed\""}`);
        return;
      }

      setStages((prev) => prev.map((s) => ({ ...s, status: "succeeded" })));
      setActiveTasks((prev) =>
        prev.map((t) =>
          t.id === "agent_swarm"
            ? { ...t, status: "completed", detail: "Completed - Evidence Ledger Ready" }
            : t
        )
      );
      fetchCountsAndHistory();
    } catch (err) {
      failLaunch(`Agent run failed: ${errorText(err)}`);
    } finally {
      setIsRunning(false);
    }
  }

  async function handleRetestCase(tc: TestCaseResult) {
    const r = await apiRequest<RawCaseResult>("/api/agent/retest", {
      method: "POST",
      json: {
        target,
        case: {
          id: tc.id,
          title: tc.title,
          component: tc.component,
          method: tc.method,
          technique: tc.technique,
          input_hint: "Interactive verification",
          payload: tc.request_payload || null,
          expected_behavior: tc.assertion_details || "Valid response",
          expected_status: tc.response_status || 200,
          risk_level: "medium",
        },
        run_id: currentRunId || null,
      },
      label: "Retest",
    });

    if (!r.ok) {
      notify(r.error);
      return;
    }
    if (!r.data) {
      notify("Retest returned no result.");
      return;
    }
    const result = r.data;
    setTestCases((prev) => prev.map((item) => (item.id === tc.id ? mergeRetestResult(item, result) : item)));
  }

  async function handleLoadRun(run: AgentRunRecord | null | undefined) {
    if (!run) return;
    const seq = ++loadSeq.current;

    // Reset every piece of result state first so nothing from the previous run can leak into this one.
    setTestCases([]);
    setThreats([]);
    setEvidenceLedger(null);
    setDefectCount(null);
    setDiscoveredData(null);

    const id = getRunId(run);
    setCurrentRunId(id);
    if (run.target) setTarget(run.target);

    // If shallow summary, fetch full report details
    let fullRun: AgentRunRecord = run;
    if (id && (!run.executed_results || run.executed_results.length === 0) && (!run.steps || run.steps.length === 0)) {
      const r = await apiRequest<AgentRunRecord>(`/api/agent/runs/${encodeURIComponent(id)}`, {
        label: `Loading run ${id}`,
      });
      if (r.ok && r.data) fullRun = r.data;
      else notify(r.ok ? `Loading run ${id} failed: empty response. Showing the summary only.` : `${r.error} Showing the summary only.`);
    }

    // A newer load started while we were fetching: drop this one.
    if (seq !== loadSeq.current) return;

    setTestCases(runCases(fullRun));

    const routes = fullRun.discovered_routes ?? [];
    if (routes.length > 0) {
      setDiscoveredData({
        target: fullRun.target ?? run.target ?? "",
        is_spa: routes.some((r) => r.is_spa_shell),
        app_architecture: fullRun.app_architecture,
        framework: fullRun.framework,
        detected_tech: fullRun.detected_tech,
        count: routes.length,
        routes,
      });
    }

    setThreats(runThreats(fullRun));
    setDefectCount(runDefectCount(fullRun));

    // Evidence ledger: only what the backend reported. No default score, verdict or pillar text.
    setEvidenceLedger(buildLedger(fullRun));
  }

  function handleLoadIntoStudio(run: AgentRunRecord) {
    handleLoadRun(run);
    setActiveView("studio");
  }

  async function handleDeleteRun(runId: string) {
    const r = await apiRequest<unknown>(`/api/agent/runs/${encodeURIComponent(runId)}`, {
      method: "DELETE",
      label: "Delete run",
    });
    if (!r.ok) {
      notify(r.error);
      return;
    }
    setRunsHistory((prev) => prev.filter((x) => getRunId(x) !== runId));
    setAgentRunsCount((prev) => Math.max(0, prev - 1));
    // The deleted run can no longer be signed off.
    setCurrentRunId((prev) => (prev === runId ? null : prev));
  }

  function handleNetworkRunningChange(running: boolean, detail: string, failed = false) {
    if (running) {
      setActiveTasks((prev) => [
        ...prev.filter((t) => t.id !== "network_test"),
        {
          id: "network_test",
          title: "Regressive Network Lab",
          target,
          view: "network_lab",
          status: "running",
          detail,
          startTime: Date.now(),
        },
      ]);
    } else {
      setActiveTasks((prev) =>
        prev.map((t) =>
          t.id === "network_test"
            ? { ...t, status: failed ? "failed" : "completed", detail }
            : t
        )
      );
    }
  }

  function handleDismissTask(id: string) {
    setActiveTasks((prev) => prev.filter((t) => t.id !== id));
  }

  /** Resolves to an error message when the sign-off failed (state is NOT changed), or null on success. */
  async function handleSignOff(action: SignOffAction, operator: string, notes: string): Promise<string | null> {
    if (!currentRunId) return "No stored run is loaded, so there is nothing to sign off.";
    const r = await apiRequest<AgentRunRecord>(`/api/agent/runs/${encodeURIComponent(currentRunId)}/${action}`, {
      method: "POST",
      json: { user: operator, notes },
      label: action === "approve" ? "Approve" : "Reject",
    });
    if (!r.ok) return r.error;

    // Prefer what the backend confirmed over what we sent.
    const confirmed = r.data;
    const status = strOrNull(confirmed?.approval_status) ?? (action === "approve" ? "approved" : "rejected");
    setEvidenceLedger((prev) =>
      prev
        ? {
            ...prev,
            approval_status: status.toUpperCase(),
            approved_by: strOrNull(confirmed?.approved_by) ?? operator,
            approval_notes: confirmed?.approval_notes ?? notes,
          }
        : prev
    );
    fetchCountsAndHistory();
    return null;
  }

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#06080e]">
      {/* SaaS Global Navigation Header */}
      <Header
        currentTarget={target}
        activeView={activeView}
        onViewChange={setActiveView}
        scansCount={scansCount}
        agentRunsCount={agentRunsCount}
      />

      {/* API-token prompt (after a 401) and error notices */}
      <GlobalNotices />

      {/* 1. Agent Studio (Persistent Background Mount) */}
      <div className={`flex-1 min-h-0 overflow-hidden ${activeView === "studio" ? "flex flex-col" : "hidden"}`}>
        <main className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-4 p-4 min-h-0 overflow-hidden max-w-[1920px] w-full mx-auto">
          {/* Left Pane: Command Center & Tool Timeline (5 cols) */}
          <div className="lg:col-span-5 flex flex-col gap-3.5 h-full overflow-y-auto pr-1">
            <Composer
              target={target}
              setTarget={setTarget}
              specUrl={specUrl}
              setSpecUrl={setSpecUrl}
              directives={directives}
              setDirectives={setDirectives}
              profile={profile}
              setProfile={setProfile}
              maxSteps={maxSteps}
              setMaxSteps={setMaxSteps}
              onDiscover={handleDiscover}
              isDiscovering={isDiscovering}
              onCrawl={handleCrawl}
              isCrawling={isCrawling}
              discoveredData={discoveredData}
              onLaunch={handleLaunch}
              isRunning={isRunning}
              thinking={thinking}
              setThinking={setThinking}
              modelTier={modelTier}
              setModelTier={setModelTier}
              thinkingBudget={thinkingBudget}
              setThinkingBudget={setThinkingBudget}
              onOpenAgentHistory={() => setActiveView("agent_history")}
            />

            <ToolCallList stages={stages} currentRunningIndex={0} />

            {evidenceLedger && (
              <ApprovalCard
                key={currentRunId ?? "no-run"}
                runId={currentRunId}
                evidenceLedger={evidenceLedger}
                defectCount={defectCount}
                onSignOff={handleSignOff}
              />
            )}
          </div>

          {/* Right Pane: Dynamic Side Canvas (7 cols) */}
          <div className="lg:col-span-7 flex flex-col h-full min-h-0 overflow-hidden">
            <SideCanvas
              testCases={testCases}
              discoveredRoutes={discoveredData?.routes || []}
              threats={threats}
              evidenceLedger={evidenceLedger}
              isSpa={discoveredData?.is_spa ?? false}
              appArchitecture={discoveredData?.app_architecture}
              onRetestCase={handleRetestCase}
              runsHistory={runsHistory}
              onLoadRun={handleLoadRun}
              onDeleteRun={handleDeleteRun}
              onCrawlSite={handleCrawl}
              isCrawling={isCrawling}
              onTestEndpoint={handleTestEndpoint}
              onOpenAgentHistory={() => setActiveView("agent_history")}
            />
          </div>
        </main>
      </div>

      {/* 2. Agent QA Swarms History (Persistent Background Mount) */}
      <div className={`flex-1 min-h-0 overflow-hidden ${activeView === "agent_history" ? "flex flex-col" : "hidden"}`}>
        <AgentHistoryView
          onLoadRunInStudio={handleLoadIntoStudio}
          onRetestCase={handleRetestCase}
          onBackToStudio={() => setActiveView("studio")}
        />
      </div>

      {/* 3. Codebase & Security Scans History (Persistent Background Mount) */}
      <div className={`flex-1 min-h-0 overflow-hidden ${activeView === "scans_history" ? "flex flex-col" : "hidden"}`}>
        <ScansHistoryView
          onSelectTarget={(t) => {
            setTarget(t);
            setActiveView("studio");
          }}
        />
      </div>

      {/* 4. Regressive Network Lab (Persistent Background Mount) */}
      <div className={`flex-1 min-h-0 overflow-hidden ${activeView === "network_lab" ? "flex flex-col" : "hidden"}`}>
        <NetworkLabView
          initialTarget={target}
          onRunningChange={handleNetworkRunningChange}
          ledgerScore={
            isGateVerdict(ledgerVerdict(evidenceLedger)) ? ledgerScore(evidenceLedger) : null
          }
        />
      </div>

      {/* 5. Global Floating Task Status Window */}
      <FloatingTaskWidget
        tasks={activeTasks}
        currentView={activeView}
        onJumpToView={(view) => setActiveView(view)}
        onDismiss={handleDismissTask}
      />
    </div>
  );
}
