"use client";

import { useState } from "react";
import { CheckCircle2, XCircle, ShieldCheck, UserCheck, FileText, ExternalLink } from "lucide-react";
import type { EvidenceLedger } from "@/types/agent";
import { isGateVerdict, ledgerScore, ledgerVerdict } from "@/lib/runs";
import { ReportButton } from "./ReportButton";
import { VerdictBadge } from "./VerdictBadge";

export type SignOffAction = "approve" | "reject";

interface ApprovalCardProps {
  /** Backend run id; null when the displayed results are not tied to a stored run. */
  runId: string | null;
  evidenceLedger: EvidenceLedger;
  /** Number of triaged defects, or null when unknown. */
  defectCount: number | null;
  /** Resolves to an error message when the backend rejected the sign-off, or null on success. */
  onSignOff: (action: SignOffAction, operator: string, notes: string) => Promise<string | null>;
}

export function ApprovalCard({ runId, evidenceLedger, defectCount, onSignOff }: ApprovalCardProps) {
  const [operator, setOperator] = useState("");
  const [notes, setNotes] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Only what the backend reported: no default score, no default verdict.
  const score = ledgerScore(evidenceLedger);
  const verdict = ledgerVerdict(evidenceLedger);
  const hasGateVerdict = isGateVerdict(verdict);

  // The sign-off state always comes from the backend-confirmed ledger, never from a local guess.
  const rawStatus = (evidenceLedger.approval_status || "").toLowerCase();
  const signStatus: "pending" | "approved" | "rejected" =
    rawStatus === "approved" ? "approved" : rawStatus === "rejected" ? "rejected" : "pending";

  const canSubmit = !!runId && operator.trim().length > 0 && !isSubmitting;

  async function handleAction(action: SignOffAction) {
    if (!runId) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const err = await onSignOff(action, operator.trim(), notes.trim());
      if (err) setError(err);
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div
      className={`border rounded-xl p-4 shadow-xl transition-all ${
        signStatus === "approved"
          ? "bg-emerald-950/20 border-emerald-500/50 shadow-[0_0_20px_rgba(16,185,129,0.15)]"
          : signStatus === "rejected"
          ? "bg-rose-950/20 border-rose-500/50 shadow-[0_0_20px_rgba(244,63,94,0.15)]"
          : "bg-[#0b101a] border-[#1a2436]"
      }`}
    >
      <div className="flex items-start justify-between pb-2.5 border-b border-[#162033] mb-3">
        <div className="flex items-center gap-2.5">
          <div
            className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              signStatus === "approved"
                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                : signStatus === "rejected"
                ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                : "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[10px] font-bold tracking-wider text-slate-400 uppercase block font-mono">
              Governance Gate Review
            </span>
            <span className="text-xs font-semibold text-slate-100">
              Human-in-the-Loop Release Approval
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {runId && (
            <ReportButton
              path={`/api/agent/runs/${runId}/report/html`}
              mode="tab"
              className="px-2.5 py-1 rounded text-[11px] font-mono font-medium bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800/60 flex items-center gap-1 transition-colors cursor-pointer"
              title="Open full executive HTML audit report"
            >
              <FileText className="w-3 h-3 text-cyan-400" />
              Audit Report
              <ExternalLink className="w-2.5 h-2.5 opacity-70" />
            </ReportButton>
          )}
          <VerdictBadge verdict={verdict} />
        </div>
      </div>

      <p className="text-xs text-slate-300 mb-3 leading-relaxed">
        {hasGateVerdict
          ? "Review the Evidence Ledger score and sign off for production deployment:"
          : "The backend did not report a gate verdict (GO / CONDITIONAL GO / NO GO) for this run, so it cannot be approved for deployment."}
      </p>

      {/* Stats Metric Strip */}
      <div className="grid grid-cols-3 gap-2 p-2.5 bg-[#07090e] rounded-lg border border-[#162033] mb-3 text-xs font-mono">
        <div>
          <span className="text-slate-500 block text-[10px] uppercase font-bold">Score</span>
          {score === null ? (
            <span className="text-slate-500 font-bold text-xs">not evaluated</span>
          ) : (
            <span className="text-cyan-400 font-bold text-sm">{score}%</span>
          )}
        </div>
        <div>
          <span className="text-slate-500 block text-[10px] uppercase font-bold">Defects</span>
          {defectCount === null ? (
            <span className="text-slate-500 font-bold text-xs">unknown</span>
          ) : (
            <span
              className={`font-bold text-sm ${
                defectCount > 0 ? "text-rose-400" : hasGateVerdict ? "text-emerald-400" : "text-slate-300"
              }`}
            >
              {defectCount}
            </span>
          )}
        </div>
        <div>
          <span className="text-slate-500 block text-[10px] uppercase font-bold">Review</span>
          <span
            className={`font-bold text-xs uppercase ${
              signStatus === "approved"
                ? "text-emerald-400"
                : signStatus === "rejected"
                ? "text-rose-400"
                : "text-amber-400"
            }`}
          >
            {signStatus === "approved" ? "Approved" : signStatus === "rejected" ? "Blocked" : "Pending Sign-Off"}
          </span>
        </div>
      </div>

      {/* Operator Sign-Off Action */}
      {signStatus === "pending" ? (
        <div className="flex flex-col gap-2">
          <input
            type="text"
            value={operator}
            onChange={(e) => setOperator(e.target.value)}
            placeholder="Operator sign-off ID (required, e.g. secops@readyhai.io)"
            className="bg-[#07090e] border border-[#1e2a40] rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          />
          <input
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Audit notes"
            className="bg-[#07090e] border border-[#1e2a40] rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
          {!runId && (
            <p className="text-[11px] text-amber-300 font-mono">
              These results are not tied to a stored run, so they cannot be signed off.
            </p>
          )}
          {error && (
            <p className="text-[11px] text-rose-300 font-mono break-words" role="alert">
              {error}
            </p>
          )}
          <div className="grid grid-cols-2 gap-2 mt-1">
            <button
              type="button"
              disabled={!canSubmit || !hasGateVerdict}
              onClick={() => handleAction("approve")}
              title={hasGateVerdict ? undefined : "No backend gate verdict: approval is unavailable"}
              className="py-2 px-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 shadow-[0_0_15px_rgba(16,185,129,0.3)] transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              Approve for Deployment
            </button>
            <button
              type="button"
              disabled={!canSubmit}
              onClick={() => handleAction("reject")}
              className="py-2 px-3 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 shadow-[0_0_15px_rgba(244,63,94,0.3)] transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
            >
              <XCircle className="w-3.5 h-3.5" />
              Block Release
            </button>
          </div>
        </div>
      ) : (
        <div className="p-3 bg-[#07090e] rounded-lg border border-[#162033] flex items-center gap-2.5 text-xs font-mono">
          <UserCheck className="w-4 h-4 text-cyan-400 shrink-0" />
          <span className="text-slate-300 leading-normal">
            {signStatus === "approved" ? "Approved" : "Blocked"} by{" "}
            <strong className="text-cyan-300">{evidenceLedger.approved_by || "unknown operator"}</strong>
            {evidenceLedger.approval_notes ? ` · ${evidenceLedger.approval_notes}` : ""}
          </span>
        </div>
      )}
    </div>
  );
}
