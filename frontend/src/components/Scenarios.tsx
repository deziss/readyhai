"use client";

import { useState } from "react";
import {
  FileCode2,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  RotateCw,
  Copy,
  Check,
  Zap,
  Link2,
  Rocket,
  Search,
  Filter,
} from "lucide-react";
import type { TestCaseResult } from "@/types/agent";
import { StatefulChainFlow } from "./StatefulChainFlow";
import { ConcurrencyBurstMeter } from "./ConcurrencyBurstMeter";
import { AutoRemediationCard } from "./AutoRemediationCard";

export interface ScenariosProps {
  testCases: TestCaseResult[];
  onRetestCase?: (testCase: TestCaseResult) => Promise<void>;
  className?: string;
  defaultExpandedId?: string | null;
}

export function Scenarios({
  testCases,
  onRetestCase,
  className = "",
  defaultExpandedId,
}: ScenariosProps) {
  const [expandedRowId, setExpandedRowId] = useState<string | null>(
    defaultExpandedId ?? (testCases[0]?.id || null)
  );
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [retestingId, setRetestingId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  function copyCurl(curlText: string, id: string) {
    navigator.clipboard.writeText(curlText);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  async function handleRetest(tc: TestCaseResult) {
    if (!onRetestCase) return;
    setRetestingId(tc.id);
    try {
      await onRetestCase(tc);
    } finally {
      setRetestingId(null);
    }
  }

  // Filter cases
  const filteredCases = testCases.filter((tc) => {
    if (statusFilter !== "ALL" && tc.status !== statusFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = tc.id.toLowerCase().includes(q);
      const matchTitle = tc.title.toLowerCase().includes(q);
      const matchComp = tc.component.toLowerCase().includes(q);
      const matchTech = tc.technique.toLowerCase().includes(q);
      if (!matchId && !matchTitle && !matchComp && !matchTech) return false;
    }
    return true;
  });

  return (
    <div className={`flex flex-col gap-3 ${className}`}>
      {/* Top Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[#162033]">
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold tracking-wider text-slate-300 uppercase">
            Adversarial Scenarios & Chains
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold">
            {testCases.length} Total
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3 h-3 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search scenarios..."
              className="pl-7 pr-2 py-1 text-xs font-mono bg-[#07090e] border border-[#1a2436] rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 w-36 sm:w-44"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-[#07090e] border border-[#1a2436] rounded px-2 py-1 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/60 cursor-pointer"
          >
            <option value="ALL">All Status</option>
            <option value="PASS">PASS</option>
            <option value="FAIL">FAIL</option>
            <option value="INCONCLUSIVE">INCONCLUSIVE</option>
            <option value="WARN">WARN</option>
            <option value="PLANNED">PLANNED</option>
            <option value="SKIPPED">SKIPPED</option>
          </select>
        </div>
      </div>

      {/* Scenarios List */}
      {filteredCases.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-xs font-mono border border-dashed border-[#1a2436] rounded-lg">
          No adversarial scenarios match the filter criteria.
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {filteredCases.map((tc) => {
            const isExpanded = expandedRowId === tc.id;

            // Scenario badge flags
            const isBola =
              tc.technique?.toLowerCase().includes("bola") ||
              (tc.stateful_steps && tc.stateful_steps.some((s) => s.actor.toLowerCase() === "bob"));

            const isStateful =
              (tc.stateful_chain && tc.stateful_chain.length > 0) ||
              (tc.stateful_steps && tc.stateful_steps.length > 0) ||
              tc.technique?.toLowerCase().includes("stateful");

            const isConcurrency =
              tc.concurrency_burst != null ||
              (tc.concurrency_burst_results && tc.concurrency_burst_results.length > 0) ||
              tc.technique?.toLowerCase().includes("toctou") ||
              tc.technique?.toLowerCase().includes("burst") ||
              tc.technique?.toLowerCase().includes("race");

            return (
              <div
                key={tc.id}
                className="border border-[#1a2436] rounded-lg bg-[#07090e]/70 overflow-hidden transition-all hover:border-[#24324a]"
              >
                {/* Scenario Summary Row */}
                <div
                  onClick={() => setExpandedRowId(isExpanded ? null : tc.id)}
                  className="p-3 flex items-center justify-between cursor-pointer hover:bg-[#0e1524]/60 transition-colors"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="text-xs font-mono font-bold text-cyan-400 w-16 shrink-0">
                      {tc.id}
                    </span>

                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded shrink-0 ${
                        tc.method === "POST"
                          ? "bg-emerald-950/80 text-emerald-300 border border-emerald-800"
                          : tc.method === "PUT" || tc.method === "PATCH"
                          ? "bg-amber-950/80 text-amber-300 border border-amber-800"
                          : tc.method === "DELETE"
                          ? "bg-rose-950/80 text-rose-300 border border-rose-800"
                          : "bg-sky-950/80 text-sky-300 border border-sky-800"
                      }`}
                    >
                      {tc.method || "GET"}
                    </span>

                    <div className="flex flex-col min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-semibold text-slate-200 truncate">
                          {tc.title}
                        </span>

                        {/* COMPACT BADGES ON STATEFUL CASES */}
                        {isBola && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-amber-950/90 text-amber-300 border border-amber-500/70 shadow-[0_0_8px_rgba(245,158,11,0.2)] flex items-center gap-1 shrink-0">
                            <span>⚡</span>
                            <span>BOLA Test</span>
                          </span>
                        )}

                        {isStateful && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-cyan-950/90 text-cyan-300 border border-cyan-500/70 shadow-[0_0_8px_rgba(6,182,212,0.2)] flex items-center gap-1 shrink-0">
                            <span>🔗</span>
                            <span>Stateful Chain</span>
                          </span>
                        )}

                        {isConcurrency && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-orange-950/90 text-orange-300 border border-orange-500/70 shadow-[0_0_8px_rgba(249,115,22,0.2)] flex items-center gap-1 shrink-0">
                            <span>🚀</span>
                            <span>TOCTOU Burst</span>
                          </span>
                        )}

                        {tc.adaptive_mutation && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-purple-950/90 text-purple-300 border border-purple-600/70 shadow-[0_0_8px_rgba(168,85,247,0.2)] flex items-center gap-1 shrink-0">
                            <span>⚡</span>
                            <span>Mutated</span>
                          </span>
                        )}
                      </div>

                      <span className="text-[10px] font-mono text-slate-400 truncate">
                        {tc.component} · <span className="text-slate-500">{tc.technique}</span>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 font-mono text-xs shrink-0">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 ${
                        tc.status === "PASS"
                          ? "bg-emerald-950/80 text-emerald-300 border border-emerald-700/60"
                          : tc.status === "FAIL"
                          ? "bg-rose-950/80 text-rose-300 border border-rose-700/60"
                          : tc.status === "PLANNED" || tc.status === "PENDING"
                          ? "bg-cyan-950/80 text-cyan-300 border border-cyan-700/60"
                          : tc.status === "SKIPPED"
                          ? "bg-slate-900 text-slate-400 border border-slate-700"
                          : "bg-amber-950/80 text-amber-300 border border-amber-700/60"
                      }`}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          tc.status === "PASS"
                            ? "bg-emerald-400"
                            : tc.status === "FAIL"
                            ? "bg-rose-400"
                            : tc.status === "PLANNED" || tc.status === "PENDING"
                            ? "bg-cyan-400"
                            : tc.status === "SKIPPED"
                            ? "bg-slate-500"
                            : "bg-amber-400"
                        }`}
                      />
                      {tc.status}
                    </span>

                    <span
                      className={`text-[11px] font-mono hidden sm:inline ${
                        tc.latency_ms == null
                          ? "text-slate-500"
                          : tc.latency_ms < 50
                          ? "text-emerald-400"
                          : tc.latency_ms < 150
                          ? "text-amber-400"
                          : "text-rose-400"
                      }`}
                    >
                      {tc.latency_ms == null ? "n/a" : `${tc.latency_ms}ms`}
                    </span>

                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expandable Deep Inspector */}
                {isExpanded && (
                  <div className="p-4 border-t border-[#1a2436] bg-[#05070c] flex flex-col gap-3.5">
                    {/* 1. Stateful Scenario Chain Flow (Phase 2) */}
                    {(tc.stateful_chain || tc.stateful_steps) && (
                      <StatefulChainFlow
                        steps={tc.stateful_steps}
                        chain={tc.stateful_chain}
                        caseStatus={tc.status}
                      />
                    )}

                    {/* 2. TOCTOU Concurrency Burst Meter (Phase 2) */}
                    {(tc.concurrency_burst != null || tc.concurrency_burst_results) && (
                      <ConcurrencyBurstMeter
                        burstCount={tc.concurrency_burst}
                        burstResults={tc.concurrency_burst_results}
                        technique={tc.technique}
                        caseStatus={tc.status}
                      />
                    )}

                    {/* 3. Auto-Remediation Git Patch Card (Phase 2) */}
                    {(tc.remediation_patch || tc.remediation_explanation || tc.reproduction_script) && (
                      <AutoRemediationCard
                        patch={tc.remediation_patch}
                        explanation={tc.remediation_explanation}
                        reproScript={tc.reproduction_script}
                      />
                    )}

                    {/* Adaptive Mutation Panel */}
                    {tc.adaptive_mutation && (
                      <div className="bg-gradient-to-r from-purple-950/30 via-[#0d1222] to-cyan-950/20 border border-purple-500/40 rounded-lg p-3 text-xs flex flex-col gap-2.5">
                        <div className="font-mono text-[11px] uppercase font-bold text-purple-300 flex items-center gap-1.5">
                          ⚡ Adaptive Schema Feedback & Mutation Probe
                        </div>
                        <div className="flex flex-col gap-1.5 font-mono text-[11px]">
                          <div>
                            <span className="text-slate-400">Framework: </span>
                            <span className="text-purple-200 font-semibold">
                              {tc.adaptive_mutation.framework || "REST Validation"}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-400">Discovered Required Fields: </span>
                            <span className="text-purple-200 font-semibold">
                              {tc.adaptive_mutation.required_fields?.join(", ") || "None"}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-slate-400">Status: </span>
                            {tc.adaptive_mutation.penetrated_validation ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-500/70 shadow-[0_0_8px_rgba(16,185,129,0.25)]">
                                Penetrated Schema Validation (HTTP {tc.adaptive_mutation.mutated_status ?? tc.response_status ?? 200})
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-700/60">
                                Rejected by Validator
                              </span>
                            )}
                          </div>
                        </div>
                        {tc.adaptive_mutation.mutated_payload && (
                          <div className="flex flex-col gap-1">
                            <span className="text-slate-400 text-[10px] font-mono font-semibold">
                              Mutated Payload:
                            </span>
                            <pre className="bg-[#05070c] p-2 rounded text-[10px] font-mono text-purple-200 overflow-x-auto">
                              {tc.adaptive_mutation.mutated_payload}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Request & Response Split Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {/* Request Panel */}
                      <div className="bg-[#0b101a] border border-[#1a2436] rounded-lg p-3 text-xs flex flex-col gap-2">
                        <span className="font-mono text-[10px] uppercase font-bold text-cyan-400 flex items-center gap-1.5">
                          <FileCode2 className="w-3.5 h-3.5" />
                          Request Details
                        </span>
                        <div className="font-mono text-[11px] text-slate-300">
                          <span className="text-slate-500">Method: </span>
                          <strong className="text-cyan-300">{tc.method || "GET"}</strong>
                        </div>
                        <div className="font-mono text-[11px] text-slate-300 truncate">
                          <span className="text-slate-500">Component: </span>
                          {tc.component}
                        </div>
                        <div>
                          <span className="text-slate-500 text-[10px] block font-mono mb-1 font-semibold">
                            Request Payload:
                          </span>
                          <pre className="bg-[#04060a] border border-[#162033] p-2.5 rounded text-[10px] font-mono text-slate-300 overflow-x-auto max-h-24">
                            {tc.request_payload || "(None - Empty Request Body)"}
                          </pre>
                        </div>
                      </div>

                      {/* Response Panel */}
                      <div className="bg-[#0b101a] border border-[#1a2436] rounded-lg p-3 text-xs flex flex-col gap-2">
                        <span className="font-mono text-[10px] uppercase font-bold text-cyan-400 flex items-center gap-1.5">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          Observed Server Response
                        </span>
                        <div className="flex items-center gap-3 font-mono text-[11px]">
                          <div>
                            <span className="text-slate-500">Status: </span>
                            <strong
                              className={
                                tc.response_status == null
                                  ? "text-slate-500 font-bold"
                                  : tc.response_status >= 200 && tc.response_status < 400
                                  ? "text-emerald-400 font-bold"
                                  : "text-amber-400 font-bold"
                              }
                            >
                              {tc.response_status ?? "not captured"}
                            </strong>
                          </div>
                          <div className="truncate">
                            <span className="text-slate-500">Type: </span>
                            <span className="text-slate-300">
                              {tc.response_content_type || "unknown"}
                            </span>
                          </div>
                        </div>
                        <div>
                          <span className="text-slate-500 text-[10px] block font-mono mb-1 font-semibold">
                            Response Body Snippet:
                          </span>
                          <pre className="bg-[#04060a] border border-[#162033] p-2.5 rounded text-[10px] font-mono text-slate-300 overflow-x-auto max-h-24">
                            {tc.response_body || "(no response body captured)"}
                          </pre>
                        </div>
                      </div>
                    </div>

                    {/* Semantic Assertion Proof */}
                    <div className="p-3 rounded-lg bg-cyan-950/25 border border-cyan-800/40 text-xs">
                      <span className="text-cyan-400 font-bold block mb-1 font-mono text-[11px] uppercase tracking-wider">
                        Semantic Assertion Proof:
                      </span>
                      <span className="text-slate-300 text-xs leading-relaxed">
                        {tc.assertion_details || "No assertion detail was reported for this case."}
                      </span>
                    </div>

                    {/* Reproduction cURL & Retest Actions */}
                    <div className="flex flex-col gap-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-slate-400 uppercase font-bold">
                          Exact Reproduction cURL
                        </span>
                        <div className="flex items-center gap-2">
                          {onRetestCase && (
                            <button
                              type="button"
                              onClick={() => handleRetest(tc)}
                              disabled={retestingId === tc.id}
                              className="px-2.5 py-1 rounded bg-[#111827] hover:bg-[#162033] border border-[#1e2a40] text-slate-300 text-[11px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                            >
                              <RotateCw className={`w-3 h-3 text-cyan-400 ${retestingId === tc.id ? "animate-spin" : ""}`} />
                              Re-Test in Browser
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => copyCurl(tc.curl, tc.id)}
                            className="px-2.5 py-1 rounded bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-[11px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                          >
                            {copiedId === tc.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                Copied!
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                Copy cURL
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                      <pre className="p-2.5 rounded bg-black/80 border border-[#1a2436] font-mono text-[11px] text-cyan-300 overflow-x-auto select-all">
                        {tc.curl}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
