"use client";

import { useState } from "react";
import { AlertTriangle, ShieldAlert, Search, Filter } from "lucide-react";
import type { ThreatFinding, TriagedDefect, RawDefect, EvidenceLedger } from "@/types/agent";
import { AutoRemediationCard } from "./AutoRemediationCard";

export interface ThreatTriageProps {
  threats?: ThreatFinding[];
  defects?: (TriagedDefect | RawDefect)[];
  evidenceLedger?: EvidenceLedger | null;
  className?: string;
}

interface NormalizedFinding {
  id?: string;
  title: string;
  owasp_category: string;
  severity: string;
  affected_routes: string[];
  evidence_snippet?: string;
  remediation?: string;
  remediation_patch?: string;
  remediation_explanation?: string;
  reproduction_script?: string;
}

function getSeverityBadge(severity: string) {
  const s = (severity || "UNKNOWN").toUpperCase();
  if (s === "CRITICAL") return "bg-rose-950 text-rose-300 border-rose-700 font-bold shadow-[0_0_8px_rgba(244,63,94,0.3)]";
  if (s === "HIGH") return "bg-amber-950 text-amber-300 border-amber-700 font-bold";
  if (s === "MEDIUM") return "bg-yellow-950 text-yellow-300 border-yellow-700 font-semibold";
  if (s === "LOW") return "bg-blue-950 text-blue-300 border-blue-700";
  return "bg-slate-900 text-slate-300 border-slate-700";
}

export function ThreatTriage({
  threats,
  defects,
  evidenceLedger,
  className = "",
}: ThreatTriageProps) {
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  // Normalize input from either threats or defects
  const findings: NormalizedFinding[] = [];

  if (threats && threats.length > 0) {
    threats.forEach((t, idx) => {
      findings.push({
        id: `threat-${idx}`,
        title: t.title,
        owasp_category: t.owasp_category,
        severity: t.severity,
        affected_routes: t.affected_routes,
        remediation: t.remediation,
        remediation_patch: t.remediation_patch,
        remediation_explanation: t.remediation_explanation,
        reproduction_script: t.reproduction_script,
      });
    });
  } else if (defects && defects.length > 0) {
    defects.forEach((d, idx) => {
      const raw = d as RawDefect & TriagedDefect;
      const caseId = raw.case_id || raw.id;
      findings.push({
        id: caseId || `defect-${idx}`,
        title: raw.title || "(Untitled Defect)",
        owasp_category: raw.owasp_category || "Unclassified",
        severity: raw.severity || "HIGH",
        affected_routes: raw.affected_endpoints || (raw.component ? [raw.component] : []),
        evidence_snippet: raw.evidence_snippet,
        remediation: raw.remediation_patch_suggestion || raw.recommended_fix,
        remediation_patch: raw.remediation_patch || raw.remediation_patch_suggestion || raw.recommended_fix,
        remediation_explanation: raw.remediation_explanation,
        reproduction_script: raw.reproduction_script || raw.reproduction,
      });
    });
  }

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== "ALL" && f.severity.toUpperCase() !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchCat = f.owasp_category.toLowerCase().includes(q);
      const matchRoutes = f.affected_routes.some((r) => r.toLowerCase().includes(q));
      if (!matchTitle && !matchCat && !matchRoutes) return false;
    }
    return true;
  });

  return (
    <div className={`p-4 overflow-y-auto flex-1 flex flex-col gap-3 ${className}`}>
      {/* Header & Filters */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[#162033]">
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold tracking-wider text-slate-300 uppercase">
            OWASP API Threat Triage & Blast Radius
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-950/80 text-rose-300 border border-rose-800 font-bold">
            {findings.length} findings triaged
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3 h-3 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings..."
              className="pl-7 pr-2 py-1 text-xs font-mono bg-[#07090e] border border-[#1a2436] rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 w-36 sm:w-44"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#07090e] border border-[#1a2436] rounded px-2 py-1 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/60"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-xs font-mono border border-dashed border-[#1a2436] rounded-lg">
          {findings.length === 0
            ? evidenceLedger
              ? "The backend triaged no defects for this run."
              : "No evaluated run is loaded, so there are no findings to show."
            : "No findings match the selected filter."}
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {filteredFindings.map((finding, idx) => (
            <div
              key={finding.id || idx}
              className="bg-[#07090e] border border-[#1a2436] rounded-lg p-3.5 flex flex-col gap-3 shadow-md hover:border-[#283854] transition-colors"
            >
              {/* Finding Title & Severity */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-bold text-rose-300 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                  {finding.title}
                </span>

                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
                    {finding.owasp_category}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getSeverityBadge(
                      finding.severity
                    )}`}
                  >
                    {finding.severity}
                  </span>
                </div>
              </div>

              {/* Affected Endpoints */}
              <div className="text-[11px] font-mono text-slate-400">
                <span className="text-slate-500">Affected Endpoints: </span>
                {finding.affected_routes.length > 0
                  ? finding.affected_routes.join(", ")
                  : "not reported"}
              </div>

              {/* Evidence Snippet */}
              {finding.evidence_snippet && (
                <div className="p-2.5 rounded bg-[#04060a] border border-[#162033] text-[11px] font-mono text-slate-300 whitespace-pre-wrap max-h-32 overflow-y-auto">
                  <strong className="text-slate-400 block mb-1 uppercase text-[10px]">
                    Observed Evidence Snippet:
                  </strong>
                  {finding.evidence_snippet}
                </div>
              )}

              {/* Auto-Remediation Git Patch Card (Requirement 3) */}
              {(finding.remediation_patch || finding.remediation_explanation || finding.reproduction_script) ? (
                <AutoRemediationCard
                  patch={finding.remediation_patch}
                  explanation={finding.remediation_explanation}
                  reproScript={finding.reproduction_script}
                />
              ) : finding.remediation ? (
                <div className="p-2.5 rounded bg-[#04060a] border border-[#162033] text-[11px] text-slate-300 leading-relaxed font-mono">
                  <strong className="text-cyan-400 block mb-1">Recommended Remediation:</strong>
                  {finding.remediation}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
