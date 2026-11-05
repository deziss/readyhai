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
import { copyTextSafely } from "@/lib/clipboard";
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
      return { bg: "bg-rh-go/15 text-rh-go", dot: "bg-rh-go", text: "Pass" };
    case "FAIL":
      return { bg: "bg-rh-nogo/15 text-rh-nogo", dot: "bg-rh-nogo", text: "Fail" };
    case "INCONCLUSIVE":
      return { bg: "bg-rh-cond/15 text-rh-cond", dot: "bg-rh-cond", text: "Inconclusive" };
    case "WARN":
      return { bg: "bg-rh-cond/15 text-rh-cond", dot: "bg-rh-cond", text: "Warn" };
    case "PLANNED":
    case "PENDING":
      return { bg: "bg-rh-info/15 text-rh-info", dot: "bg-rh-info", text: "Planned" };
    case "SKIPPED":
    default:
      return {
        bg: "bg-rh-raised text-rh-muted",
        dot: "bg-rh-muted",
        text: status ? status.charAt(0) + status.slice(1).toLowerCase() : "Skipped",
      };
  }
}

function riskLabel(risk: string): string {
  return risk.charAt(0) + risk.slice(1).toLowerCase();
}

function methodChipClass(method: string | undefined): string {
  switch (method) {
    case "POST":
      return "bg-rh-info/15 text-rh-info";
    case "PUT":
    case "PATCH":
      return "bg-rh-cond/15 text-rh-cond";
    case "DELETE":
      return "bg-rh-nogo/15 text-rh-nogo";
    default:
      return "bg-rh-raised text-rh-text";
  }
}

function latencyClass(ms: number | null | undefined): string {
  if (ms == null) return "text-rh-muted";
  if (ms < 50) return "text-rh-go";
  if (ms < 150) return "text-rh-cond";
  return "text-rh-nogo";
}

const FOCUS = "focus-visible:outline-2 focus-visible:outline-rh-primary";
const INPUT_CLS =
  "bg-rh-bg border border-rh-line rounded-[6px] px-2.5 py-1.5 text-xs text-rh-text placeholder:text-rh-muted focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
const GHOST_BTN = `flex items-center gap-1 text-xs text-rh-muted hover:text-rh-text cursor-pointer rounded-[6px] px-1.5 py-1 transition-colors ${FOCUS}`;

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

  async function copyText(text: string, identifier: string, isField = false) {
    if (!(await copyTextSafely(text))) return;
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

  const copyLabel = (active: boolean) =>
    active ? (
      <>
        <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
        <span>Copied!</span>
      </>
    ) : (
      <>
        <Copy className="w-3.5 h-3.5" aria-hidden="true" />
        <span>Copy</span>
      </>
    );

  return (
    <div className={`flex flex-col gap-3 ${className}`}>
      <div className="sticky top-0 z-10 bg-rh-surface flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-rh-line">
        <div className="flex items-center gap-3 flex-wrap">
          <h3 className="text-sm font-semibold text-rh-text flex items-center gap-2">
            <SlidersHorizontal className="w-4 h-4 text-rh-muted" aria-hidden="true" />
            Adversarial scenarios
          </h3>
          <div className="flex items-center gap-1.5 text-xs tabular-nums">
            <span className="px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-text font-semibold">{stats.total} total</span>
            {stats.pass > 0 && (
              <span className="px-2 py-0.5 rounded-[6px] bg-rh-go/15 text-rh-go font-semibold">{stats.pass} pass</span>
            )}
            {stats.fail > 0 && (
              <span className="px-2 py-0.5 rounded-[6px] bg-rh-nogo/15 text-rh-nogo font-semibold">{stats.fail} fail</span>
            )}
            {stats.inconclusive > 0 && (
              <span className="px-2 py-0.5 rounded-[6px] bg-rh-cond/15 text-rh-cond font-semibold">
                {stats.inconclusive} inconclusive
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-rh-muted absolute left-2.5 top-1/2 -translate-y-1/2" aria-hidden="true" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search ID, route, CWE or OWASP"
              aria-label="Search scenarios"
              className={`${INPUT_CLS} pl-8 w-52 sm:w-64`}
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by status"
            className={`${INPUT_CLS} cursor-pointer`}
          >
            <option value="ALL">All statuses</option>
            <option value="PASS">Pass</option>
            <option value="FAIL">Fail</option>
            <option value="INCONCLUSIVE">Inconclusive</option>
            <option value="WARN">Warn</option>
            <option value="SKIPPED">Skipped</option>
            <option value="PLANNED">Planned</option>
          </select>

          <select
            value={techniqueFilter}
            onChange={(e) => setTechniqueFilter(e.target.value)}
            aria-label="Filter by technique"
            className={`${INPUT_CLS} cursor-pointer`}
          >
            <option value="ALL">All techniques</option>
            <option value="authz">authz (authentication and BOLA)</option>
            <option value="injection">injection (SQLi, XSS, traversal)</option>
            <option value="boundary">boundary (overflows and limits)</option>
            <option value="negative">negative (malformed inputs)</option>
            <option value="state_transition">state_transition (workflow integrity)</option>
          </select>

          <button
            type="button"
            onClick={() => setExpandedRowId(expandedRowId ? null : filteredCases[0]?.id || null)}
            className={`px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer ${FOCUS}`}
            title="Toggle scenario details"
          >
            {expandedRowId ? "Collapse" : "Expand"}
          </button>
        </div>
      </div>

      {filteredCases.length === 0 ? (
        <div className="p-8 text-center text-rh-muted text-sm border border-dashed border-rh-line rounded-[10px]">
          {testCases.length === 0
            ? "No scenarios have been planned yet. Run an audit to generate adversarial test cases."
            : "No scenarios match your search or filters. Clear the search box or choose All statuses and All techniques."}
        </div>
      ) : (
        <div className="flex flex-col gap-2.5">
          {filteredCases.map((tc) => {
            const isExpanded = expandedRowId === tc.id;
            const owasp = getOwaspClassification(tc);
            const statusBadge = getStatusBadge(tc.status);

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
            const tag = "px-1.5 py-0.5 rounded-[6px] text-xs font-semibold shrink-0";

            return (
              <div
                key={tc.id}
                className={`border rounded-[10px] bg-rh-surface overflow-hidden ${
                  isExpanded ? "border-rh-muted" : "border-rh-line"
                }`}
              >
                <button
                  type="button"
                  onClick={() => setExpandedRowId(isExpanded ? null : tc.id)}
                  aria-expanded={isExpanded}
                  className={`w-full text-left px-3.5 py-3 flex items-center justify-between gap-3 cursor-pointer transition-colors hover:bg-rh-raised ${FOCUS} ${
                    isExpanded ? "bg-rh-raised" : ""
                  }`}
                >
                  <span className="flex items-center gap-3 min-w-0">
                    <span className="text-xs font-semibold text-rh-text font-mono w-16 shrink-0 tabular-nums">{tc.id}</span>

                    <span className={`text-xs font-mono font-semibold px-1.5 py-0.5 rounded-[6px] shrink-0 ${methodChipClass(tc.method)}`}>
                      {tc.method || "GET"}
                    </span>

                    <span className="flex flex-col min-w-0">
                      <span className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold text-rh-text truncate">{tc.title}</span>
                        {isBola && <span className={`${tag} bg-rh-cond/15 text-rh-cond`}>BOLA test</span>}
                        {isStateful && <span className={`${tag} bg-rh-info/15 text-rh-info`}>Stateful chain</span>}
                        {isConcurrency && <span className={`${tag} bg-rh-cond/15 text-rh-cond`}>TOCTOU burst</span>}
                        {isMutated && <span className={`${tag} bg-rh-raised text-rh-muted`}>Mutated</span>}
                      </span>

                      <span className="flex items-center gap-2 text-xs text-rh-muted truncate mt-0.5">
                        <span className="font-mono text-rh-text truncate">{tc.component}</span>
                        <span aria-hidden="true">·</span>
                        <span>{tc.technique}</span>
                        <span aria-hidden="true">·</span>
                        <span className="font-medium">{owasp.category}</span>
                        <span className="hidden sm:inline">({owasp.cwe})</span>
                      </span>
                    </span>
                  </span>

                  <span className="flex items-center gap-3 text-xs shrink-0">
                    <span className={`px-2 py-0.5 rounded-[6px] text-xs font-semibold flex items-center gap-1.5 ${statusBadge.bg}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${statusBadge.dot}`} aria-hidden="true" />
                      {statusBadge.text}
                    </span>

                    <span className={`text-xs tabular-nums w-14 text-right hidden sm:inline ${latencyClass(tc.latency_ms)}`}>
                      {tc.latency_ms == null ? "n/a" : `${tc.latency_ms}ms`}
                    </span>

                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                    )}
                  </span>
                </button>

                {isExpanded && (
                  <div className="p-4 border-t border-rh-line flex flex-col gap-4">
                    <dl className="grid grid-cols-1 sm:grid-cols-4 gap-3 p-3 rounded-[6px] bg-rh-bg border border-rh-line text-xs">
                      <div>
                        <dt className="text-xs text-rh-muted">OWASP API classification</dt>
                        <dd className="font-semibold text-rh-text text-xs mt-0.5">
                          {owasp.category} · {owasp.categoryName}
                        </dd>
                      </div>

                      <div>
                        <dt className="text-xs text-rh-muted">CWE reference</dt>
                        <dd className="font-semibold text-rh-text text-xs mt-0.5">
                          {owasp.cwe}: {owasp.cweName}
                        </dd>
                      </div>

                      <div>
                        <dt className="text-xs text-rh-muted">Threat severity</dt>
                        <dd className="mt-0.5">
                          <span
                            className={`px-2 py-0.5 rounded-[6px] text-xs font-semibold inline-block ${
                              owasp.risk === "CRITICAL"
                                ? "bg-rh-nogo/15 text-rh-nogo"
                                : owasp.risk === "HIGH" || owasp.risk === "MEDIUM"
                                ? "bg-rh-cond/15 text-rh-cond"
                                : "bg-rh-raised text-rh-muted"
                            }`}
                          >
                            {riskLabel(owasp.risk)} risk
                          </span>
                        </dd>
                      </div>

                      <div>
                        <dt className="text-xs text-rh-muted">Execution vector</dt>
                        <dd className="text-xs text-rh-text mt-0.5">
                          {tc.technique} · <span className="font-mono">{tc.method || "GET"}</span>
                        </dd>
                      </div>
                    </dl>

                    <div className="text-xs text-rh-muted leading-relaxed">
                      <span className="text-rh-text text-xs font-semibold block mb-0.5">Threat scope and attack vector</span>
                      {owasp.description}
                    </div>

                    {(tc.stateful_chain || tc.stateful_steps) && (
                      <StatefulChainFlow
                        steps={tc.stateful_steps}
                        chain={tc.stateful_chain}
                        caseStatus={tc.status}
                      />
                    )}

                    {(tc.concurrency_burst != null || tc.concurrency_burst_results) && (
                      <ConcurrencyBurstMeter
                        burstCount={tc.concurrency_burst}
                        burstResults={tc.concurrency_burst_results}
                        technique={tc.technique}
                        caseStatus={tc.status}
                      />
                    )}

                    {(tc.remediation_patch || tc.remediation_explanation || tc.reproduction_script) && (
                      <AutoRemediationCard
                        patch={tc.remediation_patch}
                        explanation={tc.remediation_explanation}
                        reproScript={tc.reproduction_script}
                      />
                    )}

                    {tc.adaptive_mutation && (
                      <div className="bg-rh-bg border border-rh-line rounded-[10px] p-3 text-xs flex flex-col gap-2.5">
                        <div className="text-xs font-semibold text-rh-text">Adaptive schema feedback and mutation probe</div>
                        <div className="flex flex-col gap-1.5 text-xs">
                          <div>
                            <span className="text-rh-muted">Framework: </span>
                            <span className="text-rh-text font-semibold">
                              {tc.adaptive_mutation.framework || "REST validation"}
                            </span>
                          </div>
                          <div>
                            <span className="text-rh-muted">Discovered required fields: </span>
                            <span className="text-rh-text font-semibold font-mono">
                              {tc.adaptive_mutation.required_fields?.join(", ") || "None"}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-rh-muted">Status: </span>
                            {tc.adaptive_mutation.penetrated_validation ? (
                              <span className="px-2 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-go/15 text-rh-go tabular-nums">
                                Penetrated schema validation (HTTP {tc.adaptive_mutation.mutated_status ?? tc.response_status ?? 200})
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded-[6px] text-xs font-semibold bg-rh-nogo/15 text-rh-nogo">
                                Rejected by validator
                              </span>
                            )}
                          </div>
                        </div>
                        {tc.adaptive_mutation.mutated_payload && (
                          <div className="flex flex-col gap-1">
                            <span className="text-rh-muted text-xs font-semibold">Mutated payload</span>
                            <pre className="bg-rh-surface border border-rh-line p-2 rounded-[6px] font-mono text-xs text-rh-text overflow-x-auto">
                              {tc.adaptive_mutation.mutated_payload}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                      <div className="bg-rh-bg border border-rh-line rounded-[10px] p-3 text-xs flex flex-col gap-2.5 min-w-0">
                        <div className="flex items-center justify-between pb-2 border-b border-rh-line">
                          <span className="text-xs font-semibold text-rh-text flex items-center gap-1.5">
                            <FileCode2 className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                            HTTP request
                          </span>
                          <span className="text-xs text-rh-muted">Sent to target</span>
                        </div>

                        <div className="text-xs text-rh-text flex items-center gap-2 flex-wrap">
                          <span className="text-rh-muted">Method and route:</span>
                          <span className="font-mono font-semibold">{tc.method || "GET"}</span>
                          <span className="font-mono break-all">{tc.component}</span>
                        </div>

                        {tc.request_payload ? (
                          <div className="flex flex-col gap-1">
                            <div className="flex items-center justify-between">
                              <span className="text-rh-muted text-xs font-semibold">Request payload or parameters</span>
                              <button
                                type="button"
                                onClick={() => copyText(tc.request_payload || "", `req-${tc.id}`, true)}
                                className={GHOST_BTN}
                                aria-label="Copy request payload"
                              >
                                {copyLabel(copiedField === `req-${tc.id}`)}
                              </button>
                            </div>
                            <pre className="bg-rh-surface border border-rh-line p-2.5 rounded-[6px] font-mono text-xs text-rh-text overflow-auto max-h-36 whitespace-pre-wrap break-all">
                              {tc.request_payload}
                            </pre>
                          </div>
                        ) : (
                          <div className="text-xs text-rh-muted p-2 bg-rh-surface rounded-[6px] border border-rh-line">
                            No query string or body payload was supplied for this probe.
                          </div>
                        )}
                      </div>

                      <div className="bg-rh-bg border border-rh-line rounded-[10px] p-3 text-xs flex flex-col gap-2.5 min-w-0">
                        <div className="flex items-center justify-between pb-2 border-b border-rh-line">
                          <span className="text-xs font-semibold text-rh-text flex items-center gap-1.5">
                            <ShieldCheck className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
                            Observed server response
                          </span>
                          <span className="text-xs text-rh-muted">Returned by target</span>
                        </div>

                        <div className="flex items-center justify-between text-xs gap-2">
                          <div className="flex items-center gap-2">
                            <span className="text-rh-muted">Status:</span>
                            <span
                              className={`px-2 py-0.5 rounded-[6px] text-xs font-semibold tabular-nums ${
                                tc.response_status == null
                                  ? "bg-rh-raised text-rh-muted"
                                  : tc.response_status >= 200 && tc.response_status < 300
                                  ? "bg-rh-go/15 text-rh-go"
                                  : tc.response_status >= 400 && tc.response_status < 500
                                  ? "bg-rh-cond/15 text-rh-cond"
                                  : "bg-rh-nogo/15 text-rh-nogo"
                              }`}
                            >
                              {getHttpStatusLabel(tc.response_status)}
                            </span>
                          </div>

                          <div className="text-rh-muted text-xs tabular-nums">
                            {tc.latency_ms != null ? `${tc.latency_ms}ms latency` : "latency n/a"}
                          </div>
                        </div>

                        <div className="text-xs text-rh-muted truncate">
                          <span>Content type: </span>
                          <span className="text-rh-text font-mono">{tc.response_content_type || "unspecified"}</span>
                        </div>

                        <div className="flex flex-col gap-1">
                          <div className="flex items-center justify-between">
                            <span className="text-rh-muted text-xs font-semibold">Response body snippet</span>
                            {tc.response_body && (
                              <button
                                type="button"
                                onClick={() => copyText(tc.response_body || "", `res-${tc.id}`, true)}
                                className={GHOST_BTN}
                                aria-label="Copy response body"
                              >
                                {copyLabel(copiedField === `res-${tc.id}`)}
                              </button>
                            )}
                          </div>
                          <pre className="bg-rh-surface border border-rh-line p-2.5 rounded-[6px] font-mono text-xs text-rh-text overflow-auto max-h-36 whitespace-pre-wrap break-all">
                            {tc.response_body || "No response body was captured."}
                          </pre>
                        </div>
                      </div>
                    </div>

                    <div className="p-3 rounded-[6px] bg-rh-info/10 text-xs flex flex-col gap-1">
                      <span className="text-rh-info font-semibold text-xs flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                        Semantic assertion and security proof
                      </span>
                      <span className="text-rh-text text-xs leading-relaxed">
                        {tc.assertion_details || "No assertion detail was reported for this case."}
                      </span>
                    </div>

                    <div className="flex flex-col gap-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs text-rh-muted font-semibold flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                          Reproduction cURL command
                        </span>
                        <div className="flex items-center gap-2">
                          {onRetestCase && (
                            <button
                              type="button"
                              onClick={() => handleRetest(tc)}
                              disabled={retestingId === tc.id}
                              className={`px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS}`}
                            >
                              <RotateCw className={`w-3.5 h-3.5 ${retestingId === tc.id ? "animate-spin" : ""}`} aria-hidden="true" />
                              <span>{retestingId === tc.id ? "Re-testing..." : "Re-test in browser"}</span>
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => copyText(tc.curl, tc.id)}
                            className={`px-2.5 py-1.5 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${FOCUS}`}
                          >
                            {copiedId === tc.id ? (
                              <>
                                <Check className="w-3.5 h-3.5" aria-hidden="true" />
                                <span>Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                                <span>Copy cURL</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                      <pre className="p-2.5 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-xs text-rh-text overflow-x-auto select-all leading-normal">
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
