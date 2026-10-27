"use client";

import { useState } from "react";
import { CheckCircle2, XCircle, ShieldCheck, UserCheck, AlertTriangle } from "lucide-react";
import type { EvidenceLedger } from "@/types/agent";

interface ApprovalCardProps {
  runId: string;
  evidenceLedger: EvidenceLedger;
  defectCount: number;
  onSignOff: (status: "approved" | "rejected", operator: string, notes: string) => Promise<void>;
}

export function ApprovalCard({ runId, evidenceLedger, defectCount, onSignOff }: ApprovalCardProps) {
  const [operator, setOperator] = useState("SecOps Lead (Anshu)");
  const [notes, setNotes] = useState("All critical exit criteria validated against real API routes.");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [signStatus, setSignStatus] = useState<"pending" | "approved" | "rejected">(
    evidenceLedger.approval_status === "APPROVED"
      ? "approved"
      : evidenceLedger.approval_status === "REJECTED"
      ? "rejected"
      : "pending"
  );

  async function handleAction(action: "approved" | "rejected") {
    setIsSubmitting(true);
    try {
      await onSignOff(action, operator, notes);
      setSignStatus(action);
    } finally {
      setIsSubmitting(false);
    }
  }

  const isGo = evidenceLedger.verdict === "GO";

  return (
    <div
      className={`border rounded-xl p-5 shadow-xl transition-all ${
        signStatus === "approved"
          ? "bg-emerald-950/20 border-emerald-500/40"
          : signStatus === "rejected"
          ? "bg-rose-950/20 border-rose-500/40"
          : "bg-[#0e1526] border-slate-800"
      }`}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div
            className={`w-9 h-9 rounded-lg flex items-center justify-center ${
              signStatus === "approved"
                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                : signStatus === "rejected"
                ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                : "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
            }`}
          >
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <span className="text-[10px] font-bold tracking-wider text-slate-400 uppercase block font-mono">
              Governance Gate Review
            </span>
            <span className="text-sm font-semibold text-slate-100">
              Human-in-the-Loop Release Approval
            </span>
          </div>
        </div>

        <span
          className={`px-3 py-1 rounded-full text-xs font-mono font-bold border tracking-wider ${
            isGo
              ? "bg-emerald-950/60 text-emerald-300 border-emerald-600/60"
              : "bg-rose-950/60 text-rose-300 border-rose-600/60"
          }`}
        >
          {evidenceLedger.verdict}
        </span>
      </div>

      <p className="text-xs text-slate-400 mb-3 leading-relaxed">
        Autonomous QA verification complete. Review the Evidence Ledger score and sign off for production deployment:
      </p>

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-2 p-2.5 bg-slate-900/80 rounded-lg border border-slate-800/80 mb-3 text-xs font-mono">
        <div>
          <span className="text-slate-500 block text-[10px]">COMPOSITE SCORE</span>
          <span className="text-cyan-400 font-bold text-sm">{evidenceLedger.composite_score}%</span>
        </div>
        <div>
          <span className="text-slate-500 block text-[10px]">DEFECT COUNT</span>
          <span className={defectCount === 0 ? "text-emerald-400 font-bold text-sm" : "text-rose-400 font-bold text-sm"}>
            {defectCount}
          </span>
        </div>
        <div>
          <span className="text-slate-500 block text-[10px]">OPERATOR STATUS</span>
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

      {/* Operator Inputs */}
      {signStatus === "pending" ? (
        <div className="flex flex-col gap-2 mb-3">
          <input
            type="text"
            value={operator}
            onChange={(e) => setOperator(e.target.value)}
            placeholder="Operator Sign-Off ID (e.g. secops@nuhire.in)"
            className="bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 font-mono"
          />
          <input
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Audit notes"
            className="bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200"
          />
          <div className="grid grid-cols-2 gap-2 mt-1">
            <button
              type="button"
              disabled={isSubmitting}
              onClick={() => handleAction("approved")}
              className="py-2 px-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              Approve for Deployment
            </button>
            <button
              type="button"
              disabled={isSubmitting}
              onClick={() => handleAction("rejected")}
              className="py-2 px-3 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 shadow-[0_0_15px_rgba(244,63,94,0.2)] transition-all"
            >
              <XCircle className="w-3.5 h-3.5" />
              Block Release
            </button>
          </div>
        </div>
      ) : (
        <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 flex items-center gap-2 text-xs font-mono">
          <UserCheck className="w-4 h-4 text-cyan-400" />
          <span className="text-slate-300">
            Signed off by <strong className="text-cyan-300">{operator}</strong> · {notes}
          </span>
        </div>
      )}
    </div>
  );
}
