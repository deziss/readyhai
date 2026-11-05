"use client";

import { useState } from "react";
import { AlertTriangle, Search } from "lucide-react";
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
  if (s === "CRITICAL") return "bg-rh-nogo/15 text-rh-nogo";
  if (s === "HIGH") return "bg-rh-cond/15 text-rh-cond";
  if (s === "MEDIUM") return "bg-rh-cond/15 text-rh-cond";
  if (s === "LOW") return "bg-rh-info/15 text-rh-info";
  return "bg-rh-raised text-rh-muted";
}

function sentenceCase(v: string) {
  const t = (v || "Unknown").trim();
  return t ? t.charAt(0).toUpperCase() + t.slice(1).toLowerCase() : "Unknown";
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
    <div className={`p-4 min-h-0 overflow-y-auto flex-1 flex flex-col gap-3 ${className}`}>
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-rh-line">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-rh-text">Threat triage and blast radius</h3>
          <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-nogo/15 text-rh-nogo font-semibold tabular-nums">
            {findings.length} findings triaged
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-rh-muted absolute left-2.5 top-1/2 -translate-y-1/2" aria-hidden="true" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings"
              aria-label="Search findings"
              className="pl-8 pr-2 py-1.5 text-xs bg-rh-bg border border-rh-line rounded-[6px] text-rh-text placeholder:text-rh-muted focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary w-36 sm:w-44"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            aria-label="Filter by severity"
            className="bg-rh-bg border border-rh-line rounded-[6px] px-2 py-1.5 text-xs text-rh-text focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary"
          >
            <option value="ALL">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {filteredFindings.length === 0 ? (
        <div className="p-8 text-center text-rh-muted text-sm border border-dashed border-rh-line rounded-[10px]">
          {findings.length === 0
            ? evidenceLedger
              ? "The backend triaged no defects for this run."
              : "No evaluated run is loaded, so there are no findings to show. Run an audit or open a past run to see them here."
            : "No findings match the current filters. Clear the search or choose All severities."}
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {filteredFindings.map((finding, idx) => (
            <div
              key={finding.id || idx}
              className="bg-rh-surface border border-rh-line rounded-[10px] p-4 flex flex-col gap-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-semibold text-rh-text flex items-center gap-2 min-w-0">
                  <AlertTriangle className="w-4 h-4 text-rh-nogo shrink-0" aria-hidden="true" />
                  {finding.title}
                </span>

                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted font-medium">
                    {finding.owasp_category}
                  </span>
                  <span className={`text-xs px-2 py-0.5 rounded-[6px] font-semibold ${getSeverityBadge(finding.severity)}`}>
                    {sentenceCase(finding.severity)}
                  </span>
                </div>
              </div>

              <div className="text-xs text-rh-muted">
                <span>Affected endpoints: </span>
                <span className="text-rh-text font-mono break-all">
                  {finding.affected_routes.length > 0 ? finding.affected_routes.join(", ") : "not reported"}
                </span>
              </div>

              {finding.evidence_snippet && (
                <div className="p-3 rounded-[6px] bg-rh-bg border border-rh-line text-xs text-rh-text whitespace-pre-wrap max-h-32 overflow-y-auto">
                  <strong className="text-rh-muted block mb-1 text-xs font-semibold">Observed evidence</strong>
                  {finding.evidence_snippet}
                </div>
              )}

              {(finding.remediation_patch || finding.remediation_explanation || finding.reproduction_script) ? (
                <AutoRemediationCard
                  patch={finding.remediation_patch}
                  explanation={finding.remediation_explanation}
                  reproScript={finding.reproduction_script}
                />
              ) : finding.remediation ? (
                <div className="p-3 rounded-[6px] bg-rh-bg border border-rh-line text-xs text-rh-text leading-relaxed">
                  <strong className="text-rh-text block mb-1 font-semibold">Recommended remediation</strong>
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
