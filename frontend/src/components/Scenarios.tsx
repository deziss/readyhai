"use client";

import { useMemo, useState } from "react";
import {
  FileCode2,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  RotateCw,
  Copy,
  Check,
  Search,
  Terminal,
  SlidersHorizontal,
} from "lucide-react";
import type { TestCaseResult } from "@/types/agent";
import { StatefulChainFlow } from "./StatefulChainFlow";
import { ConcurrencyBurstMeter } from "./ConcurrencyBurstMeter";
import { AutoRemediationCard } from "./AutoRemediationCard";

export interface OwaspClassification {
  category: string;
  categoryName: string;
  cwe: string;
  cweName: string;
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
}

export function getOwaspClassification(tc: TestCaseResult): OwaspClassification {
  const combined = (
    (tc.title || "") + " " +
    (tc.technique || "") + " " +
    (tc.component || "") + " " +
    (tc.request_payload || "")
  ).toLowerCase();

  // API1: BOLA / IDOR
  if (
    combined.includes("bola") ||
    combined.includes("tenant isolation") ||
    combined.includes("idor") ||
    (tc.stateful_steps && tc.stateful_steps.some((s) => s.actor.toLowerCase() === "bob"))
  ) {
    return {
      category: "API1:2023",
      categoryName: "Broken Object Level Authorization (BOLA)",
      cwe: "CWE-639",
      cweName: "Authorization Bypass Through User-Controlled Key",
      risk: "CRITICAL",
      description: "Detects unauthorized horizontal access across tenant or user object boundaries.",
    };
  }

  // API3: BOPLA / Mass Assignment
  if (
    combined.includes("mass assignment") ||
    combined.includes("bopla") ||
    combined.includes("is_admin") ||
    combined.includes("role escalation") ||
    combined.includes("property escalation")
  ) {
    return {
      category: "API3:2023",
      categoryName: "Broken Object Property Level Authorization",
      cwe: "CWE-915",
      cweName: "Improper Modification of Intrinsic Attributes",
      risk: "HIGH",
      description: "Validates sensitive internal fields cannot be manipulated via mass assignment.",
    };
  }

  // API7: SSRF
  if (
    combined.includes("ssrf") ||
    combined.includes("169.254") ||
    combined.includes("metadata") ||
    combined.includes("localhost probe")
  ) {
    return {
      category: "API7:2023",
      categoryName: "Server-Side Request Forgery (SSRF)",
      cwe: "CWE-918",
      cweName: "Server-Side Request Forgery",
      risk: "CRITICAL",
      description: "Evaluates resistance to cloud metadata exfiltration and internal network scanning.",
    };
  }

  // API4: Unrestricted Resource Consumption & Race Conditions
  if (
    combined.includes("toctou") ||
    combined.includes("burst") ||
    combined.includes("race") ||
    combined.includes("overflow") ||
    combined.includes("oversized") ||
    combined.includes("numeric boundary") ||
    combined.includes("concurrency") ||
    tc.concurrency_burst != null
  ) {
    return {
      category: "API4:2023",
      categoryName: "Unrestricted Resource & Concurrency Spikes",
      cwe: "CWE-400",
      cweName: "Uncontrolled Resource Consumption & Race Conditions",
      risk: "MEDIUM",
      description: "Exercises concurrency locks, numeric thresholds, and query memory bounds.",
    };
  }

  // Traversal (CWE-22)
  if (
    combined.includes("traversal") ||
    combined.includes("passwd") ||
    combined.includes("..%2f") ||
    combined.includes("%2e%2e")
  ) {
    return {
      category: "API8:2023",
      categoryName: "Path Traversal & Arbitrary File Access",
      cwe: "CWE-22",
      cweName: "Improper Limitation of a Pathname to a Restricted Directory",
      risk: "HIGH",
      description: "Probes for canonicalization escapes and local filesystem file disclosure.",
    };
  }

  // SQL Injection (CWE-89)
  if (combined.includes("sqli") || combined.includes("sql injection") || combined.includes("' or '1'='1'")) {
    return {
      category: "API8:2023",
      categoryName: "SQL Injection Vector",
      cwe: "CWE-89",
      cweName: "Improper Neutralization of Special Elements used in an SQL Command",
      risk: "CRITICAL",
      description: "Inspects query parsing for unescaped SQL syntax injection and error leakage.",
    };
  }

  // XSS (CWE-79)
  if (combined.includes("xss") || combined.includes("<script>") || combined.includes("script alert")) {
    return {
      category: "API8:2023",
      categoryName: "Reflected/Stored Cross-Site Scripting",
      cwe: "CWE-79",
      cweName: "Improper Neutralization of Input During Web Page Generation",
      risk: "MEDIUM",
      description: "Ensures dangerous script markup in queries and headers is sanitized or encoded.",
    };
  }

  // NoSQL Injection (CWE-943)
  if (combined.includes("nosql") || combined.includes("[$ne]") || combined.includes("[$gt]")) {
    return {
      category: "API8:2023",
      categoryName: "NoSQL Operator Injection",
      cwe: "CWE-943",
      cweName: "Improper Neutralization of Special Elements in Data Query Logic",
      risk: "HIGH",
      description: "Injects NoSQL dictionary selectors to ensure queries reject non-scalar types.",
    };
  }

  // Prototype Pollution (CWE-1321)
  if (combined.includes("prototype") || combined.includes("__proto__")) {
    return {
      category: "API8:2023",
      categoryName: "Object Prototype Pollution",
      cwe: "CWE-1321",
      cweName: "Improperly Controlled Modification of Object Prototype Attributes",
      risk: "HIGH",
      description: "Verifies recursive object merges refuse object prototypes and dangerous keys.",
    };
  }

  // API2: Broken Authentication
  if (
    combined.includes("bearer") ||
    combined.includes("token") ||
    combined.includes("unauthenticated") ||
    combined.includes("env") ||
    combined.includes("git/config") ||
    tc.technique === "authz"
  ) {
    return {
      category: "API2:2023",
      categoryName: "Broken Authentication & Identity Verification",
      cwe: "CWE-287",
      cweName: "Improper Authentication",
      risk: "HIGH",
      description: "Verifies endpoints reject missing, forged, or unprivileged credentials.",
    };
  }

  // API8: CORS & Security Misconfiguration
  if (
    combined.includes("cors") ||
    combined.includes("preflight") ||
    tc.method === "OPTIONS" ||
    tc.method === "HEAD"
  ) {
    return {
      category: "API8:2023",
      categoryName: "Security Misconfiguration & Permissive CORS",
      cwe: "CWE-942",
      cweName: "Permissive Cross-Origin Resource Sharing Policy",
      risk: "MEDIUM",
      description: "Inspects HTTP headers, permissive wildcards, and preflight verb handling.",
    };
  }

  // API6: State Transition
  if (tc.technique === "state_transition") {
    return {
      category: "API6:2023",
      categoryName: "Unrestricted Business Flow & State Transitions",
      cwe: "CWE-840",
      cweName: "Business Logic Errors",
      risk: "MEDIUM",
      description: "Ensures intermediate workflow stages cannot be skipped or tampered with.",
    };
  }

  // Injection fallback
  if (tc.technique === "injection") {
    return {
      category: "API8:2023",
      categoryName: "Adversarial Input Fuzzing & Injection Defense",
      cwe: "CWE-20",
      cweName: "Improper Input Validation",
      risk: "HIGH",
      description: "Evaluates server resilience when fed hostile input payloads.",
    };
  }

  // Boundary fallback
  if (tc.technique === "boundary") {
    return {
      category: "API4:2023",
      categoryName: "Boundary Limit & Buffer Resilience",
      cwe: "CWE-1284",
      cweName: "Improper Validation of Specified Quantity in Input",
      risk: "MEDIUM",
      description: "Verifies stability against edge numbers, large values, and length bounds.",
    };
  }

  return {
    category: "OWASP-API",
    categoryName: "Contractual & Invariant Verification",
    cwe: "CWE-20",
    cweName: "Improper Input Validation",
    risk: "LOW",
    description: "Evaluates standard protocol conformance and robust negative response handling.",
  };
}

function getStatusBadge(status: string) {
  switch (status) {
    case "PASS":
      return {
        bg: "bg-emerald-950/80 text-emerald-300 border-emerald-700/60",
        dot: "bg-emerald-400",
        text: "PASS",
      };
    case "FAIL":
      return {
        bg: "bg-rose-950/80 text-rose-300 border-rose-700/60",
        dot: "bg-rose-400",
        text: "FAIL",
      };
    case "INCONCLUSIVE":
      return {
        bg: "bg-amber-950/90 text-amber-300 border-amber-600/70",
        dot: "bg-amber-400",
        text: "INCONCLUSIVE",
      };
    case "WARN":
      return {
        bg: "bg-amber-950/80 text-amber-300 border-amber-700/60",
        dot: "bg-amber-400",
        text: "WARN",
      };
    case "PLANNED":
    case "PENDING":
      return {
        bg: "bg-cyan-950/80 text-cyan-300 border-cyan-700/60",
        dot: "bg-cyan-400",
        text: "PLANNED",
      };
    case "SKIPPED":
    default:
      return {
        bg: "bg-slate-900 text-slate-400 border-slate-700",
        dot: "bg-slate-500",
        text: status || "SKIPPED",
      };
  }
}

function getHttpStatusLabel(status: number | null | undefined): string {
  if (status == null) return "No Response";
  const map: Record<number, string> = {
    200: "200 OK",
    201: "201 Created",
    204: "204 No Content",
    301: "301 Moved Permanently",
    302: "302 Found",
    304: "304 Not Modified",
    400: "400 Bad Request",
    401: "401 Unauthorized",
    403: "403 Forbidden",
    404: "404 Not Found",
    405: "405 Method Not Allowed",
    409: "409 Conflict",
    422: "422 Unprocessable Entity",
    429: "429 Too Many Requests",
    500: "500 Internal Server Error",
    502: "502 Bad Gateway",
    503: "503 Service Unavailable",
  };
  return map[status] || `HTTP ${status}`;
}

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
    defaultExpandedId !== undefined ? defaultExpandedId : testCases[0]?.id || null
  );
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [retestingId, setRetestingId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [techniqueFilter, setTechniqueFilter] = useState<string>("ALL");

  function copyText(text: string, identifier: string, isField = false) {
    navigator.clipboard.writeText(text);
    if (isField) {
      setCopiedField(identifier);
      setTimeout(() => setCopiedField(null), 1800);
    } else {
      setCopiedId(identifier);
      setTimeout(() => setCopiedId(null), 2000);
    }
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

  // Summary Metrics
  const stats = useMemo(() => {
    let pass = 0;
    let fail = 0;
    let inconclusive = 0;
    let other = 0;
    for (const tc of testCases) {
      if (tc.status === "PASS") pass++;
      else if (tc.status === "FAIL") fail++;
      else if (tc.status === "INCONCLUSIVE") inconclusive++;
      else other++;
    }
    return { total: testCases.length, pass, fail, inconclusive, other };
  }, [testCases]);

  // Filter cases
  const filteredCases = useMemo(() => {
    return testCases.filter((tc) => {
      if (statusFilter !== "ALL" && tc.status !== statusFilter) return false;
      if (techniqueFilter !== "ALL" && tc.technique !== techniqueFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const owasp = getOwaspClassification(tc);
        const matchId = tc.id.toLowerCase().includes(q);
        const matchTitle = tc.title.toLowerCase().includes(q);
        const matchComp = tc.component.toLowerCase().includes(q);
        const matchTech = tc.technique.toLowerCase().includes(q);
        const matchOwasp = owasp.category.toLowerCase().includes(q) || owasp.cwe.toLowerCase().includes(q);
        if (!matchId && !matchTitle && !matchComp && !matchTech && !matchOwasp) return false;
      }
      return true;
    });
  }, [testCases, statusFilter, techniqueFilter, searchQuery]);

  return (
    <div className={`flex flex-col gap-3.5 ${className}`}>
      {/* Top Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#162033]">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-bold tracking-wider text-slate-300 uppercase flex items-center gap-1.5">
            <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
            Adversarial Scenarios & Threat Inspector
          </span>
          <div className="flex items-center gap-1.5 text-[11px] font-mono">
            <span className="px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold">
              {stats.total} Total
            </span>
            {stats.pass > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-800 font-semibold">
                {stats.pass} Pass
              </span>
            )}
            {stats.fail > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-rose-950/80 text-rose-300 border border-rose-800 font-semibold">
                {stats.fail} Fail
              </span>
            )}
            {stats.inconclusive > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-amber-950/80 text-amber-300 border border-amber-800 font-semibold">
                {stats.inconclusive} Inconclusive
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <Search className="w-3 h-3 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search ID, route, CWE, OWASP..."
              className="pl-7 pr-2 py-1 text-xs font-mono bg-[#07090e] border border-[#1a2436] rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 w-48 sm:w-56 transition-all"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-[#07090e] border border-[#1a2436] rounded px-2.5 py-1 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/60 cursor-pointer"
          >
            <option value="ALL">All Statuses</option>
            <option value="PASS">PASS</option>
            <option value="FAIL">FAIL</option>
            <option value="INCONCLUSIVE">INCONCLUSIVE</option>
            <option value="WARN">WARN</option>
            <option value="SKIPPED">SKIPPED</option>
            <option value="PLANNED">PLANNED</option>
          </select>

          <select
            value={techniqueFilter}
            onChange={(e) => setTechniqueFilter(e.target.value)}
            className="bg-[#07090e] border border-[#1a2436] rounded px-2.5 py-1 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/60 cursor-pointer"
          >
            <option value="ALL">All Techniques</option>
            <option value="authz">authz (Authentication & BOLA)</option>
            <option value="injection">injection (SQLi / XSS / Traversal)</option>
            <option value="boundary">boundary (Overflows & Limits)</option>
            <option value="negative">negative (Malformed Inputs)</option>
            <option value="state_transition">state_transition (Workflow Integrity)</option>
          </select>

          <button
            type="button"
            onClick={() => setExpandedRowId(expandedRowId ? null : filteredCases[0]?.id || null)}
            className="px-2 py-1 rounded bg-[#0f172a] hover:bg-[#1e293b] border border-[#1e293b] text-slate-400 hover:text-slate-200 text-xs font-mono transition-colors cursor-pointer"
            title="Toggle scenario details"
          >
            {expandedRowId ? "Collapse" : "Expand"}
          </button>
        </div>
      </div>

      {/* Scenarios List */}
      {filteredCases.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-xs font-mono border border-dashed border-[#1a2436] rounded-lg">
          No adversarial scenarios match the search query or filter criteria.
        </div>
      ) : (
        <div className="flex flex-col gap-2.5">
          {filteredCases.map((tc) => {
            const isExpanded = expandedRowId === tc.id;
            const owasp = getOwaspClassification(tc);
            const statusBadge = getStatusBadge(tc.status);

            // Badges
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

            const isMutated = Boolean(tc.adaptive_mutation);

            return (
              <div
                key={tc.id}
                className={`border rounded-lg bg-[#07090e]/80 overflow-hidden transition-all ${
                  isExpanded
                    ? "border-cyan-600/50 shadow-[0_0_15px_rgba(6,182,212,0.1)]"
                    : "border-[#1a2436] hover:border-[#2a3852]"
                }`}
              >
                {/* Scenario Summary Row */}
                <div
                  onClick={() => setExpandedRowId(isExpanded ? null : tc.id)}
                  className={`p-3 flex items-center justify-between cursor-pointer transition-colors ${
                    isExpanded ? "bg-[#0c1424]" : "hover:bg-[#0c1322]/70"
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
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
                          : tc.method === "OPTIONS" || tc.method === "HEAD"
                          ? "bg-purple-950/80 text-purple-300 border border-purple-800"
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

                        {isMutated && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-purple-950/90 text-purple-300 border border-purple-600/70 shadow-[0_0_8px_rgba(168,85,247,0.2)] flex items-center gap-1 shrink-0">
                            <span>⚡</span>
                            <span>Mutated</span>
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400 truncate mt-0.5">
                        <span className="text-slate-300 font-semibold">{tc.component}</span>
                        <span className="text-slate-600">·</span>
                        <span className="text-slate-400">{tc.technique}</span>
                        <span className="text-slate-600">·</span>
                        <span className="text-cyan-400/90 font-medium">{owasp.category}</span>
                        <span className="text-slate-500 hidden sm:inline">({owasp.cwe})</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 font-mono text-xs shrink-0">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 border ${statusBadge.bg}`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${statusBadge.dot}`} />
                      {statusBadge.text}
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
                      <ChevronUp className="w-4 h-4 text-cyan-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expandable Deep Payload & Threat Inspector */}
                {isExpanded && (
                  <div className="p-4 border-t border-[#1a2436] bg-[#05070c] flex flex-col gap-4">
                    {/* Threat Classification & CWE Banner */}
                    <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 p-3 rounded-lg bg-[#0b101b] border border-[#1d2b45] text-xs">
                      <div>
                        <span className="text-[10px] font-mono uppercase text-slate-500 block">
                          OWASP API Classification
                        </span>
                        <div className="font-semibold text-cyan-300 font-mono text-[11px] mt-0.5">
                          {owasp.category} · {owasp.categoryName}
                        </div>
                      </div>

                      <div>
                        <span className="text-[10px] font-mono uppercase text-slate-500 block">
                          CWE Reference
                        </span>
                        <div className="font-semibold text-indigo-300 font-mono text-[11px] mt-0.5">
                          {owasp.cwe}: {owasp.cweName}
                        </div>
                      </div>

                      <div>
                        <span className="text-[10px] font-mono uppercase text-slate-500 block">
                          Threat Severity
                        </span>
                        <div className="mt-0.5">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border inline-block ${
                              owasp.risk === "CRITICAL"
                                ? "bg-rose-950/90 text-rose-300 border-rose-600/80 shadow-[0_0_8px_rgba(244,63,94,0.3)]"
                                : owasp.risk === "HIGH"
                                ? "bg-amber-950/90 text-amber-300 border-amber-600/80"
                                : owasp.risk === "MEDIUM"
                                ? "bg-yellow-950/80 text-yellow-300 border-yellow-700/60"
                                : "bg-slate-900 text-slate-400 border-slate-700"
                            }`}
                          >
                            {owasp.risk} RISK
                          </span>
                        </div>
                      </div>

                      <div>
                        <span className="text-[10px] font-mono uppercase text-slate-500 block">
                          Execution Vector
                        </span>
                        <div className="font-mono text-[11px] text-slate-300 mt-0.5">
                          {tc.technique} · {tc.method || "GET"}
                        </div>
                      </div>
                    </div>

                    {/* Description & Threat Scope */}
                    <div className="text-xs text-slate-400 leading-relaxed font-mono bg-[#070b14] p-2.5 rounded border border-[#141e30]">
                      <span className="text-slate-500 uppercase text-[10px] font-bold block mb-0.5">
                        Threat Scope & Attack Vector:
                      </span>
                      {owasp.description}
                    </div>

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

                    {/* Dual-Pane Wire Inspector */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                      {/* Request Panel */}
                      <div className="bg-[#0b101a] border border-[#1a2436] rounded-lg p-3 text-xs flex flex-col gap-2.5">
                        <div className="flex items-center justify-between pb-1 border-b border-[#162033]">
                          <span className="font-mono text-[10px] uppercase font-bold text-cyan-400 flex items-center gap-1.5">
                            <FileCode2 className="w-3.5 h-3.5" />
                            HTTP Request Wire Evidence
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">
                            Client Ingress
                          </span>
                        </div>

                        <div className="font-mono text-[11px] text-slate-300 flex items-center gap-2">
                          <span className="text-slate-500">Method & Route:</span>
                          <span className="text-cyan-300 font-bold">{tc.method || "GET"}</span>
                          <span className="text-slate-200">{tc.component}</span>
                        </div>

                        {tc.request_payload && (
                          <div className="flex flex-col gap-1">
                            <div className="flex items-center justify-between">
                              <span className="text-slate-500 text-[10px] font-mono font-semibold">
                                Request Payload / Parameters:
                              </span>
                              <button
                                type="button"
                                onClick={() => copyText(tc.request_payload || "", `req-${tc.id}`, true)}
                                className="text-[10px] font-mono text-slate-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                              >
                                {copiedField === `req-${tc.id}` ? (
                                  <>
                                    <Check className="w-3 h-3 text-emerald-400" />
                                    <span>Copied!</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3" />
                                    <span>Copy</span>
                                  </>
                                )}
                              </button>
                            </div>
                            <pre className="bg-[#04060a] border border-[#162033] p-2.5 rounded text-[10px] font-mono text-cyan-200 overflow-x-auto max-h-36 whitespace-pre-wrap break-all">
                              {tc.request_payload}
                            </pre>
                          </div>
                        )}
                        {!tc.request_payload && (
                          <div className="text-[10px] font-mono text-slate-500 italic p-2 bg-[#04060a] rounded border border-[#162033]">
                            (No query string or body payload supplied for this probe)
                          </div>
                        )}
                      </div>

                      {/* Response Panel */}
                      <div className="bg-[#0b101a] border border-[#1a2436] rounded-lg p-3 text-xs flex flex-col gap-2.5">
                        <div className="flex items-center justify-between pb-1 border-b border-[#162033]">
                          <span className="font-mono text-[10px] uppercase font-bold text-cyan-400 flex items-center gap-1.5">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            Observed Server Response
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">
                            Server Wire Egress
                          </span>
                        </div>

                        <div className="flex items-center justify-between font-mono text-[11px]">
                          <div className="flex items-center gap-2">
                            <span className="text-slate-500">Status:</span>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                tc.response_status == null
                                  ? "bg-slate-900 text-slate-500 border-slate-700"
                                  : tc.response_status >= 200 && tc.response_status < 300
                                  ? "bg-emerald-950/80 text-emerald-300 border-emerald-700/60"
                                  : tc.response_status >= 400 && tc.response_status < 500
                                  ? "bg-amber-950/80 text-amber-300 border-amber-700/60"
                                  : "bg-rose-950/80 text-rose-300 border-rose-700/60"
                              }`}
                            >
                              {getHttpStatusLabel(tc.response_status)}
                            </span>
                          </div>

                          <div className="text-slate-400 text-[10px]">
                            {tc.latency_ms != null ? `${tc.latency_ms}ms latency` : "latency n/a"}
                          </div>
                        </div>

                        <div className="font-mono text-[10px] text-slate-400 truncate">
                          <span className="text-slate-500">Content-Type: </span>
                          <span className="text-slate-300">{tc.response_content_type || "unspecified"}</span>
                        </div>

                        <div className="flex flex-col gap-1">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px] font-mono font-semibold">
                              Response Body Snippet:
                            </span>
                            {tc.response_body && (
                              <button
                                type="button"
                                onClick={() => copyText(tc.response_body || "", `res-${tc.id}`, true)}
                                className="text-[10px] font-mono text-slate-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                              >
                                {copiedField === `res-${tc.id}` ? (
                                  <>
                                    <Check className="w-3 h-3 text-emerald-400" />
                                    <span>Copied!</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3" />
                                    <span>Copy</span>
                                  </>
                                )}
                              </button>
                            )}
                          </div>
                          <pre className="bg-[#04060a] border border-[#162033] p-2.5 rounded text-[10px] font-mono text-slate-300 overflow-x-auto max-h-36 whitespace-pre-wrap break-all">
                            {tc.response_body || "(no response body captured)"}
                          </pre>
                        </div>
                      </div>
                    </div>

                    {/* Semantic Invariant & Assertion Proof */}
                    <div className="p-3 rounded-lg bg-cyan-950/25 border border-cyan-800/40 text-xs flex flex-col gap-1">
                      <span className="text-cyan-400 font-bold font-mono text-[11px] uppercase tracking-wider flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5" />
                        Semantic Assertion & Security Proof
                      </span>
                      <span className="text-slate-300 text-xs leading-relaxed font-mono">
                        {tc.assertion_details || "No assertion detail was reported for this case."}
                      </span>
                    </div>

                    {/* Reproduction cURL & Retest Actions Bar */}
                    <div className="flex flex-col gap-1.5 pt-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-slate-400 uppercase font-bold flex items-center gap-1.5">
                          <Terminal className="w-3 h-3 text-cyan-400" />
                          Reproduction cURL Command
                        </span>
                        <div className="flex items-center gap-2">
                          {onRetestCase && (
                            <button
                              type="button"
                              onClick={() => handleRetest(tc)}
                              disabled={retestingId === tc.id}
                              className="px-2.5 py-1 rounded bg-[#111827] hover:bg-[#162033] border border-[#1e2a40] text-slate-300 text-[11px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer hover:border-cyan-500/50"
                            >
                              <RotateCw className={`w-3 h-3 text-cyan-400 ${retestingId === tc.id ? "animate-spin" : ""}`} />
                              <span>Re-Test in Browser</span>
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => copyText(tc.curl, tc.id)}
                            className="px-2.5 py-1 rounded bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-[11px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                          >
                            {copiedId === tc.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span>Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy cURL</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                      <pre className="p-2.5 rounded bg-black/90 border border-[#1a2436] font-mono text-[11px] text-cyan-300 overflow-x-auto select-all leading-normal">
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
