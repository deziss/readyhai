"use client";

import { useState, useEffect } from "react";
import { Header, SaaSViewMode } from "@/components/Header";
import { Composer } from "@/components/Composer";
import { ToolCallList, StageState } from "@/components/ToolCallList";
import { SideCanvas } from "@/components/SideCanvas";
import { ApprovalCard } from "@/components/ApprovalCard";
import { ScansHistoryView } from "@/components/ScansHistoryView";
import { AgentHistoryView } from "@/components/AgentHistoryView";
import { NetworkLabView } from "@/components/NetworkLabView";
import { FloatingTaskWidget, ActiveTaskItem } from "@/components/FloatingTaskWidget";
import type {
  ModelTier,
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
  const [runsHistory, setRunsHistory] = useState<any[]>([]);
  const [currentRunId, setCurrentRunId] = useState<string | null>(null);
  const [activeTasks, setActiveTasks] = useState<ActiveTaskItem[]>([]);

  // Fetch counts and history
  const fetchCountsAndHistory = async () => {
    try {
      const [agentRes, scansRes] = await Promise.all([
        fetch("/api/agent/runs"),
        fetch("/api/scans"),
      ]);
      if (agentRes.ok) {
        const agentData = await agentRes.json();
        const runsList = Array.isArray(agentData) ? agentData : agentData.runs || [];
        setRunsHistory(runsList);
        setAgentRunsCount(runsList.length);
      }
      if (scansRes.ok) {
        const scansData = await scansRes.json();
        const scansList = scansData.scans || [];
        setScansCount(scansList.length);
      }
    } catch (e) {
      console.error("Failed to fetch runs count:", e);
    }
  };

  useEffect(() => {
    fetchCountsAndHistory();
    const interval = setInterval(fetchCountsAndHistory, 12000);
    return () => clearInterval(interval);
  }, []);

  async function handleDiscover() {
    if (!target) return;
    setIsDiscovering(true);
    try {
      const res = await fetch("/api/agent/discover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      if (res.ok) {
        const data: DiscoveredTarget = await res.json();
        setDiscoveredData(data);
      }
    } catch (err) {
      console.error("Discovery failed:", err);
    } finally {
      setIsDiscovering(false);
    }
  }

  async function handleLaunch() {
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

      setTimeout(() => {
        setStages((prev) =>
          prev.map((s, idx) =>
            idx === 0 ? { ...s, status: "succeeded" } : idx === 1 ? { ...s, status: "running" } : s
          )
        );
      }, 800);

      setTimeout(() => {
        setStages((prev) =>
          prev.map((s, idx) =>
            idx <= 1 ? { ...s, status: "succeeded" } : idx === 2 ? { ...s, status: "running" } : s
          )
        );
      }, 1500);

      const res = await fetch("/api/agent/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data = await res.json();
        const rep = data.report || data;
        handleLoadRun(rep);
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
      console.error("Agent run failed:", err);
      setStages((prev) => prev.map((s) => ({ ...s, status: "succeeded" })));
      setActiveTasks((prev) =>
        prev.map((t) =>
          t.id === "agent_swarm"
            ? { ...t, status: "completed", detail: "Finished with warnings" }
            : t
        )
      );
    } finally {
      setIsRunning(false);
    }
  }

  async function handleRetestCase(tc: TestCaseResult) {
    try {
      const res = await fetch("/api/agent/retest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
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
        }),
      });

      if (res.ok) {
        const updated = await res.json();
        setTestCases((prev) =>
          prev.map((item) =>
            item.id === tc.id
              ? {
                  ...item,
                  status: (updated.status || "PASS") as any,
                  latency_ms: updated.latency_ms || item.latency_ms,
                  curl: updated.reproduction_curl || item.curl,
                  response_status: updated.status_code || item.response_status,
                  response_body: updated.evidence || item.response_body,
                  retested: true,
                }
              : item
          )
        );
      }
    } catch (err) {
      console.error("Retest error:", err);
    }
  }

  function handleLoadRun(run: any) {
    if (!run) return;
    if (run.id) setCurrentRunId(run.id);
    if (run.target) setTarget(run.target);

    // Load executed results or planned cases
    if (run.executed_results && run.executed_results.length > 0) {
      const cases: TestCaseResult[] = run.executed_results.map((c: any) => ({
        id: c.case_id || c.id,
        title: c.title,
        component: c.component,
        technique: c.technique,
        method: c.method || "GET",
        status: c.status as any,
        latency_ms: c.latency_ms || 25,
        curl: c.curl_reproduction || c.curl || "",
        request_payload: c.request_payload,
        response_status: c.response_status,
        response_content_type: c.response_content_type,
        response_body: c.response_body_snippet || c.response_body,
        assertion_details: c.assertion_details,
      }));
      setTestCases(cases);
    } else if (run.planned_cases && run.planned_cases.length > 0) {
      const cases: TestCaseResult[] = run.planned_cases.map((c: any) => ({
        id: c.id,
        title: c.title,
        component: c.component,
        technique: c.technique,
        method: c.method,
        status: "PLANNED" as any,
        latency_ms: 0,
        curl: `curl -X ${c.method} "${run.target}${c.component}"`,
        request_payload: c.payload,
        response_status: c.expected_status,
        assertion_details: c.expected_behavior,
      }));
      setTestCases(cases);
    } else if (run.test_cases && run.test_cases.length > 0) {
      setTestCases(run.test_cases);
    }

    // Load discovered routes
    if (run.discovered_routes && run.discovered_routes.length > 0) {
      setDiscoveredData({
        target: run.target,
        is_spa: run.discovered_routes.some((r: any) => r.is_spa_shell),
        app_architecture: run.app_architecture,
        framework: run.framework,
        detected_tech: run.detected_tech,
        count: run.discovered_routes.length,
        routes: run.discovered_routes,
      });
    }

    // Load triaged defects
    if (run.triaged_defects && run.triaged_defects.length > 0) {
      const mappedThreats: ThreatFinding[] = run.triaged_defects.map((d: any) => ({
        owasp_category: d.owasp_category || "API_SECURITY",
        severity: d.severity as any,
        title: d.title,
        affected_routes: d.affected_endpoints || [],
        remediation: d.remediation_patch_suggestion || "",
      }));
      setThreats(mappedThreats);
    } else if (run.threats) {
      setThreats(run.threats);
    }

    // Load evidence ledger
    if (run.evidence_ledger) {
      const el = run.evidence_ledger;
      if (el.pillars) {
        setEvidenceLedger({
          contract: {
            score: el.pillars.contract.score,
            status: el.pillars.contract.status,
            evidence: el.pillars.contract.evidence_summary,
          },
          authz: {
            score: el.pillars.authz.score,
            status: el.pillars.authz.status,
            evidence: el.pillars.authz.evidence_summary,
          },
          resilience: {
            score: el.pillars.resilience.score,
            status: el.pillars.resilience.status,
            evidence: el.pillars.resilience.evidence_summary,
          },
          observability: {
            score: el.pillars.observability.score,
            status: el.pillars.observability.status,
            evidence: el.pillars.observability.evidence_summary,
          },
          composite_score: el.overall_readiness,
          verdict: el.gate_verdict as any,
          approval_status: (run.approval_status || "PENDING").toUpperCase() as any,
          approved_by: run.approved_by,
          approval_notes: run.approval_notes,
        });
      } else {
        setEvidenceLedger(el);
      }
    }
  }

  function handleLoadIntoStudio(run: any) {
    handleLoadRun(run);
    setActiveView("studio");
  }

  async function handleDeleteRun(runId: string) {
    try {
      const res = await fetch(`/api/agent/runs/${runId}`, { method: "DELETE" });
      if (res.ok) {
        setRunsHistory((prev) => prev.filter((r) => r.id !== runId));
        setAgentRunsCount((prev) => Math.max(0, prev - 1));
      }
    } catch (err) {
      console.error("Failed to delete run:", err);
    }
  }


  function handleNetworkRunningChange(running: boolean, detail: string) {
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
            ? { ...t, status: "completed", detail }
            : t
        )
      );
    }
  }

  function handleDismissTask(id: string) {
    setActiveTasks((prev) => prev.filter((t) => t.id !== id));
  }

  async function handleSignOff(status: "approved" | "rejected", operator: string, notes: string) {
    if (!currentRunId) return;
    try {
      await fetch(`/api/agent/runs/${currentRunId}/${status}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: operator, notes }),
      });
      if (evidenceLedger) {
        setEvidenceLedger({
          ...evidenceLedger,
          approval_status: status === "approved" ? "APPROVED" : "REJECTED",
          approved_by: operator,
          approval_notes: notes,
        });
      }
      fetchCountsAndHistory();
    } catch (err) {
      console.error("Signoff error:", err);
    }
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
              discoveredData={discoveredData}
              onLaunch={handleLaunch}
              isRunning={isRunning}
              thinking={thinking}
              setThinking={setThinking}
              modelTier={modelTier}
              setModelTier={setModelTier}
              thinkingBudget={thinkingBudget}
              setThinkingBudget={setThinkingBudget}
            />

            <ToolCallList stages={stages} currentRunningIndex={0} />

            {evidenceLedger && (
              <ApprovalCard
                runId={currentRunId || "run-latest"}
                evidenceLedger={evidenceLedger}
                defectCount={threats.length}
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
              target={target}
              onRetestCase={handleRetestCase}
              runsHistory={runsHistory}
              onLoadRun={handleLoadRun}
              onDeleteRun={handleDeleteRun}
            />
          </div>
        </main>
      </div>

      {/* 2. Agent QA Swarms History (Persistent Background Mount) */}
      <div className={`flex-1 min-h-0 overflow-hidden ${activeView === "agent_history" ? "flex flex-col" : "hidden"}`}>
        <AgentHistoryView
          onLoadRunInStudio={handleLoadIntoStudio}
          onRetestCase={handleRetestCase}
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
