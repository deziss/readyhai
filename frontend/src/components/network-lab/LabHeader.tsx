import React from "react";
import {
  Activity,
  Network,
  Compass,
  GitPullRequest,
  Globe,
  Copy,
  Check,
  Download,
} from "lucide-react";
import type { DeepAuditReport, MultiRegionReport, PrCommentResponse } from "@/types/network";
import { BTN_SECONDARY, FOCUS, tabClass } from "./types";

export interface LabHeaderProps {
  activeTab: "regress" | "deep_audit" | "multi_region" | "pr_gate";
  setActiveTab: (tab: "regress" | "deep_audit" | "multi_region" | "pr_gate") => void;
  deepAuditReport: DeepAuditReport | null;
  isDeepAuditRunning: boolean;
  handleRunDeepAudit: () => void;
  multiRegionReport: MultiRegionReport | null;
  isMultiRegionRunning: boolean;
  handleRunMultiRegion: () => void;
  isDeepAuditFreshEntry: boolean;
  prCommentData: PrCommentResponse | null;
  isPrCommentLoading: boolean;
  handleFetchPrComment: () => void;
  target: string;
  requesterIp: string | null;
  copyToClipboard: (text: string, id: string) => void;
  copiedText: string | null;
  handleExportHar: () => void;
}

export function LabHeader({
  activeTab,
  setActiveTab,
  deepAuditReport,
  isDeepAuditRunning,
  handleRunDeepAudit,
  multiRegionReport,
  isMultiRegionRunning,
  handleRunMultiRegion,
  isDeepAuditFreshEntry,
  prCommentData,
  isPrCommentLoading,
  handleFetchPrComment,
  target,
  requesterIp,
  copyToClipboard,
  copiedText,
  handleExportHar,
}: LabHeaderProps) {
  return (
    <div className="border-b border-rh-line bg-rh-surface px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 shrink-0">
      <div className="flex items-center gap-3">
        <div className="flex flex-wrap items-center gap-1 p-1 bg-rh-bg rounded-[10px] border border-rh-line">
          <button
            id="tab-regress-stress"
            onClick={() => setActiveTab("regress")}
            type="button"
            aria-pressed={activeTab === "regress"}
            className={tabClass(activeTab === "regress")}
          >
            <Activity className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Regressive lab</span>
          </button>

          <button
            id="tab-deep-audit"
            onClick={() => {
              setActiveTab("deep_audit");
              if (!deepAuditReport && !isDeepAuditRunning) {
                handleRunDeepAudit();
              }
            }}
            type="button"
            aria-pressed={activeTab === "deep_audit"}
            className={tabClass(activeTab === "deep_audit")}
          >
            <Network className="w-3.5 h-3.5" aria-hidden="true" />
            <span>6-pillar protocol audit</span>
          </button>

          <button
            id="tab-multi-region"
            onClick={() => {
              setActiveTab("multi_region");
              if (!multiRegionReport && !isMultiRegionRunning) {
                handleRunMultiRegion();
              }
            }}
            type="button"
            aria-pressed={activeTab === "multi_region"}
            className={tabClass(activeTab === "multi_region")}
          >
            <Compass className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Multi-region mesh</span>
          </button>

          <button
            id="tab-pr-gate"
            onClick={() => {
              setActiveTab("pr_gate");
              if (isDeepAuditFreshEntry && !prCommentData && !isPrCommentLoading) {
                handleFetchPrComment();
              }
            }}
            type="button"
            aria-pressed={activeTab === "pr_gate"}
            className={tabClass(activeTab === "pr_gate")}
          >
            <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
            <span>PR status gate</span>
          </button>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 px-3 py-1 rounded-[6px] bg-rh-surface border border-rh-line text-xs">
          <Globe className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
          <span className="text-rh-muted">Active URL</span>
          <span className="text-rh-text font-mono truncate max-w-[18rem]">{target}</span>
        </div>

        {/* Requester egress IP */}
        <div
          className="flex items-center gap-1.5 px-3 py-1 rounded-[6px] bg-rh-surface border border-rh-line text-xs"
          title="Requester public egress IP. Add this IP to your target firewall or cloud security group allowlist for private network testing."
        >
          <span className="text-rh-muted">Requester IP</span>
          <span className="text-rh-text font-mono tabular-nums">{requesterIp || "unknown"}</span>
          <button
            type="button"
            disabled={!requesterIp}
            onClick={() => requesterIp && copyToClipboard(requesterIp, "probe-ip")}
            className={`text-rh-muted hover:text-rh-text ml-1 p-1 rounded-[6px] cursor-pointer transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
            title="Copy IP for firewall allowlist"
            aria-label="Copy requester IP"
          >
            {copiedText === "probe-ip" ? (
              <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
            ) : (
              <Copy className="w-3.5 h-3.5" aria-hidden="true" />
            )}
          </button>
        </div>

        {/* Export HAR */}
        <button
          id="btn-export-har"
          type="button"
          onClick={handleExportHar}
          className={BTN_SECONDARY}
          title="Download an HTTP Archive (HAR 1.2) for Chrome DevTools or support tickets"
        >
          <Download className="w-3.5 h-3.5" aria-hidden="true" />
          <span>Export HAR</span>
        </button>
      </div>
    </div>
  );
}
