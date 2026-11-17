"use client";

import { useState, useEffect } from "react";
import { apiRequest, notify, useApiTokenVersion } from "@/lib/api";
import { copyTextSafely } from "@/lib/clipboard";
import {
  deepAuditKey,
  isDeepAuditFresh,
  readDeepAuditCache,
  writeDeepAuditCache,
  type DeepAuditEntry,
} from "@/lib/deepAuditCache";
import type {
  RegressRequest,
  RegressReport,
  IterationResult,
  CurlTestResponse,
  DeepAuditReport,
  MultiRegionReport,
  PrCommentResponse,
} from "@/types/network";
import {
  exportHar,
  LabHeader,
  RegressConfigPanel,
  RegressResultsView,
  DeepAuditView,
  MultiRegionView,
  PrGateView,
  CurlProbeCard,
} from "./network-lab";

export interface NetworkLabViewProps {
  initialTarget?: string;
  /** `failed` is true when the run ended in an error rather than a result. */
  onRunningChange?: (running: boolean, detail: string, failed?: boolean) => void;
  /** Score of the currently loaded agent run's evidence ledger, or null when there is no real one. */
  ledgerScore?: number | null;
}

export function NetworkLabView({
  initialTarget = "https://app-prod.nuhire.in/",
  onRunningChange,
  ledgerScore = null,
}: NetworkLabViewProps) {
  // Mode selection
  const [activeTab, setActiveTab] = useState<"regress" | "deep_audit" | "multi_region" | "pr_gate">("regress");

  // Common target
  const [target, setTarget] = useState(initialTarget);
  const targetKey = deepAuditKey(target);
  const [timeoutMs, setTimeoutMs] = useState(5000);

  // Keep target in sync when initialTarget changes from outside
  useEffect(() => {
    if (initialTarget && initialTarget.trim() && initialTarget !== target) {
      setTarget(initialTarget.trim());
    }
  }, [initialTarget]);

  // Regressive test configuration
  const [method, setMethod] = useState("GET");
  const [iterations, setIterations] = useState(10);
  const [isCustomIterations, setIsCustomIterations] = useState(false);
  const [throttleProfile, setThrottleProfile] = useState("unthrottled");
  const [customLatency] = useState(120);
  const [separateSessions, setSeparateSessions] = useState(true);
  const [delayBetweenMs, setDelayBetweenMs] = useState(25);
  const [customHeaders, setCustomHeaders] = useState("");
  const [showAdvancedHeaders, setShowAdvancedHeaders] = useState(false);
  const [customPayload] = useState("");

  // Regressive Results
  const [isRegressRunning, setIsRegressRunning] = useState(false);
  const [regressReport, setRegressReport] = useState<RegressReport | null>(null);
  const [selectedIteration, setSelectedIteration] = useState<IterationResult | null>(null);

  // Deep Audit Results
  const [isDeepAuditRunning, setIsDeepAuditRunning] = useState(false);
  const [deepAuditEntries, setDeepAuditEntries] = useState<Record<string, DeepAuditEntry>>({});
  const deepAuditEntry: DeepAuditEntry | null = deepAuditEntries[targetKey] ?? null;
  const deepAuditReport: DeepAuditReport | null = deepAuditEntry?.report ?? null;
  const [deepAuditError, setDeepAuditError] = useState<string | null>(null);
  const [showRemediation, setShowRemediation] = useState(false);

  // Restore this target's cached deep audit when the target changes
  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) return;
      const cached = readDeepAuditCache(targetKey);
      if (cached) setDeepAuditEntries((prev) => (prev[targetKey] ? prev : { ...prev, [targetKey]: cached }));
    });
    return () => {
      cancelled = true;
    };
  }, [targetKey]);

  // cURL Runner & Multi-Region
  const [isCurlRunning, setIsCurlRunning] = useState(false);
  const [curlResult, setCurlResult] = useState<CurlTestResponse | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [isMultiRegionRunning, setIsMultiRegionRunning] = useState(false);
  const [multiRegionReport, setMultiRegionReport] = useState<MultiRegionReport | null>(null);

  // PR Comment Entry
  const [prCommentEntry, setPrCommentEntry] = useState<{
    key: string;
    auditTs: number;
    data: PrCommentResponse;
  } | null>(null);
  const [prLoadingKey, setPrLoadingKey] = useState<string | null>(null);
  const prCommentData =
    prCommentEntry && prCommentEntry.key === targetKey && prCommentEntry.auditTs === deepAuditEntry?.ts
      ? prCommentEntry.data
      : null;
  const isPrCommentLoading = prLoadingKey === targetKey;

  const [, setLabError] = useState<string | null>(null);
  const [probeIp, setProbeIp] = useState<string | null>(null);
  const tokenVersion = useApiTokenVersion();

  // Requester egress IP lookup
  useEffect(() => {
    let cancelled = false;
    apiRequest<{ egress_public_ip?: string }>("/api/network/requester-ip", { label: "Requester IP lookup" }).then((r) => {
      if (cancelled) return;
      setProbeIp(r.ok && r.data?.egress_public_ip ? r.data.egress_public_ip : null);
    });
    return () => {
      cancelled = true;
    };
  }, [tokenVersion]);

  const requesterIp = regressReport?.requester_ip || deepAuditReport?.requester_ip || probeIp;

  // Header parsing helper
  const getParsedHeaders = (): Record<string, string> => {
    const res: Record<string, string> = {};
    if (!customHeaders.trim()) return res;
    for (const line of customHeaders.split("\n")) {
      const idx = line.indexOf(":");
      if (idx !== -1) {
        const k = line.substring(0, idx).trim();
        const v = line.substring(idx + 1).trim();
        if (k) res[k] = v;
      }
    }
    return res;
  };

  function validTarget(): string | null {
    const t = target.trim();
    if (!t) {
      return "Enter a target URL first (e.g. http://host.docker.internal:3000 or https://app.example.com).";
    }
    let u: URL;
    try {
      u = new URL(t);
    } catch {
      return `"${t}" is not a valid URL. Include the scheme, e.g. https://${t}.`;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return "Target must be an http:// or https:// URL.";
    }
    return null;
  }

  async function handleRunRegress() {
    const bad = validTarget();
    if (bad) {
      setLabError(bad);
      notify(bad);
      return;
    }
    setIsRegressRunning(true);
    setCurlResult(null);
    setLabError(null);
    onRunningChange?.(true, `Regressive network test (${iterations}x iterations)`);
    let failure: string | null = null;
    {
      const payload: RegressRequest = {
        target,
        method,
        headers: getParsedHeaders(),
        payload: customPayload.trim() ? customPayload.trim() : null,
        iterations,
        timeout_ms: timeoutMs,
        throttle_profile: throttleProfile,
        simulated_latency_ms: throttleProfile === "custom" ? customLatency : 0,
        separate_sessions: separateSessions,
        delay_between_ms: delayBetweenMs,
      };

      const r = await apiRequest<RegressReport>("/api/network/regress", {
        method: "POST",
        json: payload,
        label: "Regressive test",
      });

      if (r.ok && r.data) {
        setRegressReport(r.data);
        if (r.data.iterations && r.data.iterations.length > 0) {
          setSelectedIteration(r.data.iterations[0]);
        }
      } else {
        failure = r.ok ? "Regressive test failed: empty response." : r.error;
      }
    }
    if (failure) {
      setLabError(failure);
      notify(failure);
    }
    setIsRegressRunning(false);
    onRunningChange?.(false, failure ? "Regressive test failed" : `Completed ${iterations}x regressive test`, !!failure);
  }

  async function handleRunDeepAudit() {
    const bad = validTarget();
    if (bad) {
      setDeepAuditError(bad);
      notify(bad);
      return;
    }
    const auditKey = targetKey;
    setIsDeepAuditRunning(true);
    setDeepAuditError(null);
    onRunningChange?.(true, "6-pillar deep network and protocol audit");
    const r = await apiRequest<DeepAuditReport>("/api/network/deep-audit", {
      method: "POST",
      json: { target: auditKey, timeout_ms: timeoutMs },
      label: "Deep audit",
    });
    let failed = false;
    if (r.ok && r.data) {
      const entry: DeepAuditEntry = { key: auditKey, ts: Date.now(), report: r.data };
      setDeepAuditEntries((prev) => ({ ...prev, [auditKey]: entry }));
      writeDeepAuditCache(entry);
    } else {
      failed = true;
      setDeepAuditError(r.ok ? "Deep audit failed: empty response." : r.error);
    }
    setIsDeepAuditRunning(false);
    onRunningChange?.(false, failed ? "6-pillar deep protocol audit failed" : "Completed 6-pillar deep protocol audit", failed);
  }

  async function handleRunCurl() {
    const bad = validTarget();
    if (bad) {
      setLabError(bad);
      notify(bad);
      return;
    }
    setIsCurlRunning(true);
    setLabError(null);
    const r = await apiRequest<CurlTestResponse>("/api/network/curl", {
      method: "POST",
      json: {
        target,
        method,
        headers: getParsedHeaders(),
        payload: customPayload.trim() ? customPayload.trim() : null,
        timeout_ms: timeoutMs,
      },
      label: "cURL probe",
    });
    if (r.ok && r.data) {
      setCurlResult(r.data);
    } else {
      const msg = r.ok ? "cURL probe failed: empty response." : r.error;
      setLabError(msg);
      notify(msg);
    }
    setIsCurlRunning(false);
  }

  async function handleRunMultiRegion() {
    const bad = validTarget();
    if (bad) {
      setLabError(bad);
      notify(bad);
      return;
    }
    setIsMultiRegionRunning(true);
    setLabError(null);
    onRunningChange?.(true, `Probing 4-region edge mesh (${target})`);
    const r = await apiRequest<MultiRegionReport>("/api/network/multi-region", {
      method: "POST",
      json: { target, timeout_ms: timeoutMs },
      label: "Multi-region probe",
    });
    let failed = false;
    if (r.ok && r.data) {
      setMultiRegionReport(r.data);
    } else {
      failed = true;
      const msg = r.ok ? "Multi-region probe failed: empty response." : r.error;
      setLabError(msg);
      notify(msg);
    }
    setIsMultiRegionRunning(false);
    onRunningChange?.(false, failed ? "4-region edge mesh probe failed" : "Completed 4-region edge mesh probe", failed);
  }

  async function handleFetchPrComment() {
    if (!deepAuditEntry) {
      setLabError(`Run the 6-pillar protocol audit for ${targetKey || "this target"} first: the PR comment needs its measured verdict and score.`);
      return;
    }
    if (!isDeepAuditFresh(deepAuditEntry)) {
      setLabError(
        `The 6-pillar audit for ${targetKey} is from ${new Date(deepAuditEntry.ts).toLocaleString()} and is too old to post. Re-run it first.`
      );
      return;
    }
    const { key, ts, report } = deepAuditEntry;
    setPrLoadingKey(key);
    setLabError(null);
    const r = await apiRequest<PrCommentResponse>("/api/github/pr-comment", {
      method: "POST",
      json: {
        target: key,
        verdict: report.overall_verdict,
        score: report.health_score,
      },
      label: "PR comment",
    });
    if (r.ok && r.data) {
      setPrCommentEntry({ key, auditTs: ts, data: r.data });
    } else {
      const msg = r.ok ? "PR comment failed: empty response." : r.error;
      setLabError(msg);
      notify(msg);
    }
    setPrLoadingKey((cur) => (cur === key ? null : cur));
  }

  function handleExportHar() {
    if (!regressReport || regressReport.iterations.length === 0) {
      const msg = "Nothing to export: run a regressive test first (the HAR is built from its measured iterations).";
      setLabError(msg);
      notify(msg);
      return;
    }
    exportHar(regressReport, method);
  }

  const copyToClipboard = async (text: string, id: string) => {
    if (!(await copyTextSafely(text))) return;
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  return (
    <div className="flex-1 min-h-0 flex flex-col h-full overflow-hidden bg-rh-bg text-rh-text">
      {/* Sub-header navigation tabs */}
      <LabHeader
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        deepAuditReport={deepAuditReport}
        isDeepAuditRunning={isDeepAuditRunning}
        handleRunDeepAudit={handleRunDeepAudit}
        multiRegionReport={multiRegionReport}
        isMultiRegionRunning={isMultiRegionRunning}
        handleRunMultiRegion={handleRunMultiRegion}
        isDeepAuditFreshEntry={isDeepAuditFresh(deepAuditEntry)}
        prCommentData={prCommentData}
        isPrCommentLoading={isPrCommentLoading}
        handleFetchPrComment={handleFetchPrComment}
        target={target}
        requesterIp={requesterIp}
        copyToClipboard={copyToClipboard}
        copiedText={copiedText}
        handleExportHar={handleExportHar}
      />

      {/* Main Content Area */}
      <div
        className={`flex-1 min-h-0 ${
          activeTab === "regress"
            ? "grid grid-cols-1 xl:grid-cols-12 xl:grid-rows-1 overflow-y-auto xl:overflow-hidden"
            : "flex flex-col overflow-hidden bg-rh-bg"
        }`}
      >
        {/* Left config sidebar (regressive lab only) */}
        {activeTab === "regress" && (
          <RegressConfigPanel
            target={target}
            setTarget={setTarget}
            method={method}
            setMethod={setMethod}
            iterations={iterations}
            setIterations={setIterations}
            isCustomIterations={isCustomIterations}
            setIsCustomIterations={setIsCustomIterations}
            throttleProfile={throttleProfile}
            setThrottleProfile={setThrottleProfile}
            timeoutMs={timeoutMs}
            setTimeoutMs={setTimeoutMs}
            delayBetweenMs={delayBetweenMs}
            setDelayBetweenMs={setDelayBetweenMs}
            customHeaders={customHeaders}
            setCustomHeaders={setCustomHeaders}
            showAdvancedHeaders={showAdvancedHeaders}
            setShowAdvancedHeaders={setShowAdvancedHeaders}
            isRegressRunning={isRegressRunning}
            isCurlRunning={isCurlRunning}
            onRunRegress={handleRunRegress}
            onRunCurl={handleRunCurl}
          />
        )}

        {/* Right visualization / subtab pane */}
        <main
          className={`${
            activeTab === "regress"
              ? "xl:col-span-8 xl:min-h-0 xl:overflow-y-auto"
              : "flex-1 min-h-0 overflow-y-auto"
          } p-6 space-y-6`}
        >
          <div className="max-w-6xl mx-auto space-y-6">
            {/* TAB 1: REGRESS */}
            {activeTab === "regress" && (
              <RegressResultsView
                regressReport={regressReport}
                isRegressRunning={isRegressRunning}
                selectedIteration={selectedIteration}
                setSelectedIteration={setSelectedIteration}
                copiedText={copiedText}
                copyToClipboard={copyToClipboard}
              />
            )}

            {/* TAB 2: DEEP AUDIT */}
            {activeTab === "deep_audit" && (
              <DeepAuditView
                target={target}
                setTarget={setTarget}
                isDeepAuditRunning={isDeepAuditRunning}
                deepAuditError={deepAuditError}
                deepAuditReport={deepAuditReport}
                deepAuditEntry={deepAuditEntry}
                showRemediation={showRemediation}
                setShowRemediation={setShowRemediation}
                onRunDeepAudit={handleRunDeepAudit}
              />
            )}

            {/* TAB 3: MULTI-REGION */}
            {activeTab === "multi_region" && (
              <MultiRegionView
                target={target}
                multiRegionReport={multiRegionReport}
                isMultiRegionRunning={isMultiRegionRunning}
                handleRunMultiRegion={handleRunMultiRegion}
              />
            )}

            {/* TAB 4: PR GATE */}
            {activeTab === "pr_gate" && (
              <PrGateView
                target={target}
                deepAuditReport={deepAuditReport}
                multiRegionReport={multiRegionReport}
                ledgerScore={ledgerScore}
                prCommentData={prCommentData}
                isPrCommentLoading={isPrCommentLoading}
                handleFetchPrComment={handleFetchPrComment}
                copyToClipboard={copyToClipboard}
                copiedText={copiedText}
              />
            )}

            {/* cURL diagnostic probe */}
            {(activeTab === "regress" || curlResult) && (
              <CurlProbeCard
                target={target}
                curlResult={curlResult}
                isCurlRunning={isCurlRunning}
                handleRunCurl={handleRunCurl}
                copyToClipboard={copyToClipboard}
                copiedText={copiedText}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
export default NetworkLabView;
