"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Header, SaaSViewMode } from "@/components/Header";
import { Composer } from "@/components/Composer";
import { ToolCallList, buildStages, type StageState } from "@/components/ToolCallList";
import { SideCanvas } from "@/components/SideCanvas";
import { ApprovalCard, type SignOffAction } from "@/components/ApprovalCard";
import { GlobalNotices } from "@/components/GlobalNotices";
import { ScansHistoryView } from "@/components/ScansHistoryView";
import { AgentHistoryView } from "@/components/AgentHistoryView";
import { NetworkLabView } from "@/components/NetworkLabView";
import { FloatingTaskWidget, ActiveTaskItem, newTaskInstanceId } from "@/components/FloatingTaskWidget";
import { apiRequest, errorText, notify, useApiTokenVersion } from "@/lib/api";
import {
  buildLedger,
  canApproveVerdict,
  confirmedSignOffStatus,
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
  const [target, setTarget] = useState("https://app-prod.nuhire.in/");
  const [specUrl, setSpecUrl] = useState("");
  const [directives, setDirectives] = useState("Strict QA and verify resilience, contracts, and authz");
  const [profile, setProfile] = useState("standard");
  const [maxSteps, setMaxSteps] = useState(15);
  const [thinking, setThinking] = useState(true);
  const [modelTier, setModelTier] = useState<ModelTier>("high");
  const [thinkingBudget, setThinkingBudget] = useState(8192);

  // Discovered Routes
  const [discoveredData, setDiscoveredData] = useState<DiscoveredTarget | null>(null);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [isCrawling, setIsCrawling] = useState(false);

  // Execution Stages
  const [stages, setStages] = useState<StageState[]>(() => buildStages());
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
  // Mirrors currentRunId synchronously so async handlers can tell whether the run they started
  // with is still the one on screen.
  const currentRunIdRef = useRef<string | null>(null);

  const updateCurrentRunId = useCallback((id: string | null) => {
    currentRunIdRef.current = id;
    setCurrentRunId(id);
  }, []);

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
    setTestCases((prev) => [newCase, ...prev.filter((c) => c.component !== path && c.id !== testId)]);

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
        instanceId: newTaskInstanceId(),
        title: "Agent QA run",
        target,
        view: "studio",
        status: "running",
        detail: "Planning, running and verifying test cases",
        startTime: Date.now(),
      },
    ]);
    setStages(buildStages((idx) => (idx === 0 ? "running" : "standby")));

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
      const directivesBytes = typeof TextEncoder !== "undefined" ? new TextEncoder().encode(directives).length : directives.length;
      if (directivesBytes > 32768) {
        failLaunch(`Agent directives are ${directivesBytes.toLocaleString()} bytes, which exceeds the 32,768 bytes limit. Please shorten your directives.`);
        return;
      }

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

      if (rep.status === "cancelled") {
        // Stopped on request: partial results are loaded, but this is neither a failure nor a finished gate run.
        setStages((prev) => prev.map((s) => (s.status === "running" ? { ...s, status: "standby" } : s)));
        setActiveTasks((prev) =>
          prev.map((t) =>
            t.id === "agent_swarm" ? { ...t, status: "cancelled", detail: "Cancelled. Partial results only" } : t
          )
        );
        notify("Agent run was cancelled. Partial results are shown; no gate decision was made.", "info");
        fetchCountsAndHistory();
        return;
      }

      setStages((prev) => prev.map((s) => ({ ...s, status: "succeeded" })));
      setActiveTasks((prev) =>
        prev.map((t) =>
          t.id === "agent_swarm"
            ? { ...t, status: "completed", detail: "Done. The evidence ledger is ready" }
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
    updateCurrentRunId(id);
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
    if (currentRunIdRef.current === runId) updateCurrentRunId(null);
  }

  function handleNetworkRunningChange(running: boolean, detail: string, failed = false) {
    if (running) {
      setActiveTasks((prev) => [
        ...prev.filter((t) => t.id !== "network_test"),
        {
          id: "network_test",
          instanceId: newTaskInstanceId(),
          title: "Network lab",
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

  // Dismissal is by task instance, so a stale timer or click can never remove a relaunched task of the same type.
  function handleDismissTask(instanceId: string) {
    setActiveTasks((prev) => prev.filter((t) => t.instanceId !== instanceId));
  }

  /** Resolves to an error message when the sign-off failed (state is NOT changed), or null on success. */
  async function handleSignOff(action: SignOffAction, operator: string, notes: string): Promise<string | null> {
    const runId = currentRunIdRef.current;
    if (!runId) return "No stored run is loaded, so there is nothing to sign off.";
    if (action === "approve" && !canApproveVerdict(ledgerVerdict(evidenceLedger))) {
      return "Only a GO or CONDITIONAL_GO run can be approved for deployment. A NO_GO run can only be blocked.";
    }
    const seq = loadSeq.current;

    const r = await apiRequest<AgentRunRecord>(`/api/agent/runs/${encodeURIComponent(runId)}/${action}`, {
      method: "POST",
      json: { user: operator, notes },
      label: action === "approve" ? "Approve" : "Reject",
    });
    if (!r.ok) return r.error;

    // The backend recorded a sign-off: refresh the lists whatever is on screen now.
    fetchCountsAndHistory();

    // Only the status the backend echoed back is shown; never the action that was clicked.
    const confirmedStatus = confirmedSignOffStatus(r.data?.approval_status);
    if (!confirmedStatus) {
      return "The backend did not confirm the sign-off status, so the review state was not changed. Reload the run to check it.";
    }

    // The operator switched to another run (or reloaded) while the request was in flight: the result
    // belongs to the run it was sent for, so it must not touch what is displayed now.
    if (currentRunIdRef.current !== runId || loadSeq.current !== seq) {
      notify(`Run ${runId} was ${confirmedStatus}. Open it again to see the updated review state.`, "info");
      return null;
    }

    const confirmed = r.data;
    setEvidenceLedger((prev) =>
      prev
        ? {
            ...prev,
            approval_status: confirmedStatus.toUpperCase(),
            approved_by: strOrNull(confirmed?.approved_by) ?? undefined,
            approval_notes: strOrNull(confirmed?.approval_notes) ?? undefined,
          }
        : prev
    );
    return null;
  }

  return (
    <div className="flex h-dvh w-screen flex-col overflow-hidden bg-rh-bg text-rh-text">
      {/* Global navigation */}
      <Header
        currentTarget={target}
        activeView={activeView}
        onViewChange={setActiveView}
        scansCount={scansCount}
        agentRunsCount={agentRunsCount}
      />

      {/* API-token prompt (after a 401) and error notices */}
      <GlobalNotices />

      {/* 1. Agent studio (persistent background mount) */}
      <div className={`min-h-0 flex-1 overflow-hidden ${activeView === "studio" ? "flex flex-col" : "hidden"}`}>
        {/*
          Layout: below 1024px the two columns stack and the page scrolls once (this <main>).
          From 1024px up the page itself never scrolls: each column is a flex column with min-h-0
          and scrolls inside its own panel. min-h-0 is lg-only on purpose: on a grid item in a
          fixed-height grid it would let the stacked rows shrink and overlap.
        */}
        <main className="relative mx-auto grid min-h-0 w-full max-w-[1920px] flex-1 grid-cols-1 gap-4 overflow-y-auto p-4 lg:grid-cols-12 lg:grid-rows-1 lg:overflow-hidden">
          {/* Left: command center. Mode tabs pinned top, Run agent pinned bottom, controls scroll between. */}
          <div className="flex flex-col lg:col-span-5 lg:min-h-0 lg:overflow-y-auto">
            <div className="flex flex-col lg:min-h-[24rem] lg:flex-1 lg:[&>*]:min-h-0 lg:[&>*]:flex-1">
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
            </div>
          </div>

          {/* Right: workspace. Pipeline, release gate, then the evidence tabs. */}
          <div className="flex flex-col gap-3 lg:col-span-7 lg:min-h-0 lg:overflow-y-auto">
            <ToolCallList stages={stages} verdict={ledgerVerdict(evidenceLedger)} />

            {evidenceLedger && (
              <ApprovalCard
                key={currentRunId ?? "no-run"}
                runId={currentRunId}
                evidenceLedger={evidenceLedger}
                defectCount={defectCount}
                onSignOff={handleSignOff}
              />
            )}

            {/* SideCanvas fills its parent (h-full), so this wrapper gives it a definite height. */}
            <div className="flex min-h-[28rem] flex-1 flex-col lg:min-h-[24rem] [&>*]:min-h-0 [&>*]:flex-1">
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
          </div>
        </main>
      </div>

      {/* 2. Agent run history (persistent background mount) */}
      <div className={`flex-1 min-h-0 overflow-hidden ${activeView === "agent_history" ? "flex flex-col" : "hidden"}`}>
        <AgentHistoryView
          onLoadRunInStudio={handleLoadIntoStudio}
          onRetestCase={handleRetestCase}
          onBackToStudio={() => setActiveView("studio")}
        />
      </div>

      {/* 3. Scans history (persistent background mount) */}
      <div className={`flex-1 min-h-0 overflow-hidden ${activeView === "scans_history" ? "flex flex-col" : "hidden"}`}>
        <ScansHistoryView
          onSelectTarget={(t) => {
            setTarget(t);
            setActiveView("studio");
          }}
        />
      </div>

      {/* 4. Network lab (persistent background mount) */}
      <div className={`flex-1 min-h-0 overflow-hidden ${activeView === "network_lab" ? "flex flex-col" : "hidden"}`}>
        <NetworkLabView
          initialTarget={target}
          onRunningChange={handleNetworkRunningChange}
          ledgerScore={
            isGateVerdict(ledgerVerdict(evidenceLedger)) ? ledgerScore(evidenceLedger) : null
          }
        />
      </div>

      {/* 5. Floating task status window */}
      <FloatingTaskWidget
        tasks={activeTasks}
        currentView={activeView}
        onJumpToView={(view) => setActiveView(view)}
        onDismiss={handleDismissTask}
      />
    </div>
  );
}
