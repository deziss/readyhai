import React from "react";
import { Globe, RotateCw, GitPullRequest, Check, Copy } from "lucide-react";
import type { DeepAuditReport, MultiRegionReport, PrCommentResponse } from "@/types/network";
import { BTN_PRIMARY, BTN_SECONDARY, FOCUS } from "./types";
import {
  BADGE_LABEL_BG,
  BADGE_LEDGER,
  BADGE_NONE,
  badgeColorForVerdict,
} from "./badgePreview";

export interface PrGateViewProps {
  target: string;
  deepAuditReport: DeepAuditReport | null;
  multiRegionReport: MultiRegionReport | null;
  ledgerScore?: number | null;
  prCommentData: PrCommentResponse | null;
  isPrCommentLoading: boolean;
  handleFetchPrComment: () => void;
  copyToClipboard: (text: string, id: string) => void;
  copiedText: string | null;
}

const badgeBase = () => (typeof window === "undefined" ? "" : window.location.origin);

const WORKFLOW_SNIPPET = `name: ReadyHai Production Readiness Gate
on: [pull_request, push]

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ReadyHai
        run: |
          curl -sSfL https://github.com/deziss/readyhai/releases/latest/download/readyhai-linux-x86_64.tar.gz | sudo tar xz -C /usr/local/bin

      - name: Execute Quality & Network Gate
        run: |
          readyhai scan . --profile quick --format sarif,html --out readyhai-report

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: readyhai-report/readyhai-report.sarif`;

export function PrGateView({
  target,
  deepAuditReport,
  multiRegionReport,
  ledgerScore = null,
  prCommentData,
  isPrCommentLoading,
  handleFetchPrComment,
  copyToClipboard,
  copiedText,
}: PrGateViewProps) {
  const gateStatus = deepAuditReport?.overall_verdict
    ? deepAuditReport.overall_verdict.toUpperCase()
    : null;
  const gateBadgeText = gateStatus ?? "not evaluated";
  const gateBadgeColor = badgeColorForVerdict(gateStatus);

  const meshTotal = multiRegionReport?.regions.length ?? 0;
  const meshOptimal = multiRegionReport
    ? multiRegionReport.regions.filter((r) => r.status === "OPTIMAL").length
    : 0;
  const meshBadgeText = meshTotal > 0 ? `${meshOptimal}/${meshTotal} optimal` : null;
  // The mesh endpoint takes the same PASS/WARN/FAIL vocabulary as the gate, so the colour follows
  // the verdict rather than how pleasing the ratio looks. all-optimal is PASS, none is FAIL.
  const meshVerdict =
    meshTotal === 0 ? null : meshOptimal === meshTotal ? "PASS" : meshOptimal === 0 ? "FAIL" : "WARN";
  const meshBadgeColor = badgeColorForVerdict(meshVerdict);

  return (
    <div className="space-y-6">
      {/* Target bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-2.5 rounded-[10px] bg-rh-surface border border-rh-line">
        <div className="flex items-center gap-2 text-xs min-w-0">
          <Globe className="w-3.5 h-3.5 text-rh-muted shrink-0" aria-hidden="true" />
          <span className="text-rh-muted">Target URL</span>
          <span className="text-rh-text font-mono truncate">{target}</span>
        </div>
        <button
          id="btn-refresh-pr-comment"
          type="button"
          onClick={handleFetchPrComment}
          disabled={isPrCommentLoading}
          className={BTN_PRIMARY}
        >
          <RotateCw
            className={`w-3.5 h-3.5 ${isPrCommentLoading ? "animate-spin" : ""}`}
            aria-hidden="true"
          />
          <span>Refresh PR checks</span>
        </button>
      </div>

      {/* SVG badges */}
      <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <GitPullRequest className="w-4 h-4 text-rh-muted" aria-hidden="true" />
            <h4 className="text-sm font-semibold text-rh-text">Embeddable SVG badges</h4>
          </div>
          <span className="text-xs text-rh-muted">
            Built from measured results only. Badges without a measurement stay neutral.
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Badge 1: Quality Gate */}
          <div className="p-3.5 rounded-[6px] bg-rh-bg border border-rh-line space-y-2.5">
            <span className="text-xs font-medium text-rh-text block">Quality gate verdict</span>
            <div className="flex items-center justify-between">
              <div className="inline-flex rounded-[6px] overflow-hidden text-xs font-semibold">
                <span className="px-2.5 py-1 text-white" style={{ backgroundColor: BADGE_LABEL_BG }}>ReadyHai</span>
                <span
                  className="text-white px-2.5 py-1"
                  style={{ backgroundColor: gateBadgeColor }}
                >
                  {gateBadgeText}
                </span>
              </div>
              <button
                disabled={!gateStatus}
                onClick={() =>
                  copyToClipboard(
                    `![ReadyHai Gate](${badgeBase()}/api/badges/gate?status=${encodeURIComponent(
                      (gateStatus || "").toLowerCase()
                    )})`,
                    "badge-gate"
                  )
                }
                type="button"
                aria-label="Copy quality gate badge markdown"
                className={`text-xs text-rh-primary hover:text-rh-primary-hover flex items-center gap-1 rounded-[6px] px-1 py-0.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
              >
                {copiedText === "badge-gate" ? (
                  <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                ) : (
                  <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                )}
                <span>{copiedText === "badge-gate" ? "Copied" : "Copy"}</span>
              </button>
            </div>
            {!gateStatus && (
              <p className="text-xs text-rh-muted">
                Run the 6-pillar protocol audit to get a verdict.
              </p>
            )}
          </div>

          {/* Badge 2: Evidence Ledger */}
          <div className="p-3.5 rounded-[6px] bg-rh-bg border border-rh-line space-y-2.5">
            <span className="text-xs font-medium text-rh-text block">
              4-pillar evidence ledger
            </span>
            <div className="flex items-center justify-between">
              <div className="inline-flex rounded-[6px] overflow-hidden text-xs font-semibold">
                <span className="px-2.5 py-1 text-white" style={{ backgroundColor: BADGE_LABEL_BG }}>Evidence Ledger</span>
                <span
                  className="text-white px-2.5 py-1"
                  style={{ backgroundColor: ledgerScore === null ? BADGE_NONE : BADGE_LEDGER }}
                >
                  {ledgerScore === null ? "not evaluated" : `${ledgerScore}/100`}
                </span>
              </div>
              <button
                disabled={ledgerScore === null}
                onClick={() =>
                  copyToClipboard(
                    `![Evidence Ledger](${badgeBase()}/api/badges/ledger?score=${encodeURIComponent(
                      `${ledgerScore}/100`
                    )})`,
                    "badge-ledger"
                  )
                }
                type="button"
                aria-label="Copy evidence ledger badge markdown"
                className={`text-xs text-rh-primary hover:text-rh-primary-hover flex items-center gap-1 rounded-[6px] px-1 py-0.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
              >
                {copiedText === "badge-ledger" ? (
                  <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                ) : (
                  <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                )}
                <span>{copiedText === "badge-ledger" ? "Copied" : "Copy"}</span>
              </button>
            </div>
            {ledgerScore === null && (
              <p className="text-xs text-rh-muted">
                Open an evaluated run in Agent studio to get a ledger score.
              </p>
            )}
          </div>

          {/* Badge 3: Network Mesh */}
          <div className="p-3.5 rounded-[6px] bg-rh-bg border border-rh-line space-y-2.5">
            <span className="text-xs font-medium text-rh-text block">Global network mesh</span>
            <div className="flex items-center justify-between">
              <div className="inline-flex rounded-[6px] overflow-hidden text-xs font-semibold">
                <span className="px-2.5 py-1 text-white" style={{ backgroundColor: BADGE_LABEL_BG }}>Network Mesh</span>
                <span className="text-white px-2.5 py-1" style={{ backgroundColor: meshBadgeColor }}>
                  {meshBadgeText ?? "not evaluated"}
                </span>
              </div>
              <button
                disabled={!meshBadgeText}
                onClick={() =>
                  meshBadgeText &&
                  copyToClipboard(
                    `![Network Mesh](${badgeBase()}/api/badges/network?status=${encodeURIComponent(
                      meshVerdict ?? ""
                    )})`,
                    "badge-mesh"
                  )
                }
                type="button"
                aria-label="Copy network mesh badge markdown"
                className={`text-xs text-rh-primary hover:text-rh-primary-hover flex items-center gap-1 rounded-[6px] px-1 py-0.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS}`}
              >
                {copiedText === "badge-mesh" ? (
                  <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                ) : (
                  <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                )}
                <span>{copiedText === "badge-mesh" ? "Copied" : "Copy"}</span>
              </button>
            </div>
            {!meshBadgeText && (
              <p className="text-xs text-rh-muted">
                Run the multi-region mesh probe to get a status.
              </p>
            )}
          </div>
        </div>
      </div>

      {/* PR Status Comment Preview & Copy */}
      <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rh-line pb-3">
          <div>
            <h4 className="text-sm font-semibold text-rh-text">Pull request comment markdown</h4>
            <span className="text-xs text-rh-muted">
              Post it to a GitHub PR with the CLI or a GitHub Action step
            </span>
          </div>
          {prCommentData && (
            <button
              type="button"
              onClick={() => copyToClipboard(prCommentData.markdown, "pr-comment-md")}
              className={BTN_SECONDARY}
            >
              {copiedText === "pr-comment-md" ? (
                <>
                  <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                  <span>Copied markdown</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Copy PR comment</span>
                </>
              )}
            </button>
          )}
        </div>

        {prCommentData ? (
          <>
            <p className="text-xs text-rh-cond bg-rh-cond/15 p-3 rounded-[6px]">
              Only the verdict and score above come from this audit. The pillar table and overview
              lines in the generated comment are the backend&apos;s template text and were not
              measured here.
            </p>
            <div className="p-4 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-xs text-rh-text overflow-auto whitespace-pre-wrap max-h-72 min-h-0 leading-relaxed">
              {prCommentData.markdown}
            </div>
          </>
        ) : (
          <div className="p-4 rounded-[6px] bg-rh-bg border border-rh-line text-rh-muted text-xs flex flex-wrap items-center justify-between gap-3">
            <span>
              {deepAuditReport
                ? `Generate a PR comment for ${target} from the 6-pillar audit verdict and score.`
                : "Run the 6-pillar protocol audit first: the PR comment needs a measured verdict and score."}
            </span>
            <button
              type="button"
              onClick={handleFetchPrComment}
              disabled={isPrCommentLoading || !deepAuditReport}
              className={BTN_SECONDARY}
            >
              {isPrCommentLoading ? "Generating..." : "Generate comment"}
            </button>
          </div>
        )}
      </div>

      {/* GitHub Actions workflow */}
      <div className="p-5 rounded-[10px] bg-rh-surface border border-rh-line space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rh-line pb-3">
          <div>
            <h4 className="text-sm font-semibold text-rh-text">
              GitHub Actions workflow snippet (
              <span className="font-mono">.github/workflows/readyhai.yml</span>)
            </h4>
            <span className="text-xs text-rh-muted">
              Enforce a blocking readiness gate and SARIF code scanning on every commit
            </span>
          </div>
          <button
            type="button"
            onClick={() => copyToClipboard(WORKFLOW_SNIPPET, "action-yaml")}
            className={BTN_SECONDARY}
          >
            {copiedText === "action-yaml" ? (
              <>
                <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                <span>Copied YAML</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Copy workflow YAML</span>
              </>
            )}
          </button>
        </div>

        <pre className="p-4 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-xs text-rh-text overflow-auto leading-relaxed">
          {WORKFLOW_SNIPPET}
        </pre>
      </div>
    </div>
  );
}
