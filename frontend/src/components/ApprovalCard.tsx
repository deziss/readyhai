"use client";

import { useId, useState } from "react";
import { CheckCircle2, ChevronDown, ChevronRight, ExternalLink, FileText, ShieldCheck, UserCheck, XCircle } from "lucide-react";
import type { EvidenceLedger } from "@/types/agent";
import { canApproveVerdict, isGateVerdict, ledgerScore, ledgerVerdict } from "@/lib/runs";
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

const FIELD =
  "w-full rounded-sm border border-rh-line bg-rh-bg px-3 py-2 text-ui text-rh-text placeholder:text-rh-muted";

/**
 * The "Release gate" panel: shows the run's gate verdict and lets an operator approve or block the
 * release. It lives in the workspace column (not the command center) so it can never push the run
 * controls out of reach. The body collapses to a one-line header to give the evidence more room.
 */
export function ApprovalCard({ runId, evidenceLedger, defectCount, onSignOff }: ApprovalCardProps) {
  const [operator, setOperator] = useState("");
  const [notes, setNotes] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const bodyId = useId();
  const operatorId = useId();
  const notesId = useId();
  const hintId = useId();

  // Only what the backend reported: no default score, no default verdict.
  const score = ledgerScore(evidenceLedger);
  const verdict = ledgerVerdict(evidenceLedger);
  const hasGateVerdict = isGateVerdict(verdict);
  // Approval is only ever offered for GO / CONDITIONAL_GO. A NO_GO run can only be blocked.
  const canApprove = canApproveVerdict(verdict);

  // The sign-off state always comes from the backend-confirmed ledger, never from a local guess.
  const rawStatus = (evidenceLedger.approval_status || "").toLowerCase();
  const signStatus: "pending" | "approved" | "rejected" =
    rawStatus === "approved" ? "approved" : rawStatus === "rejected" ? "rejected" : "pending";

  // Open while a decision is still needed; the operator can collapse it to see more evidence.
  const [open, setOpen] = useState(signStatus === "pending");

  const canSubmit = !!runId && operator.trim().length > 0 && !isSubmitting;
  const needsOperator = !!runId && operator.trim().length === 0;

  async function handleAction(action: SignOffAction) {
    if (!runId) return;
    if (action === "approve" && !canApprove) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const err = await onSignOff(action, operator.trim(), notes.trim());
      if (err) setError(err);
    } finally {
      setIsSubmitting(false);
    }
  }

  const statusChip =
    signStatus === "approved"
      ? { text: "Approved", cls: "bg-rh-go/15 text-rh-go" }
      : signStatus === "rejected"
      ? { text: "Blocked", cls: "bg-rh-nogo/10 text-rh-nogo" }
      : { text: "Pending sign-off", cls: "bg-rh-cond/15 text-rh-cond" };

  return (
    <section
      aria-labelledby={titleId}
      className={`shrink-0 rounded-md border bg-rh-surface ${
        signStatus === "approved" ? "border-rh-go/50" : signStatus === "rejected" ? "border-rh-nogo/50" : "border-rh-line"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-3">
        <h2 id={titleId} className="min-w-0 text-sm font-semibold text-rh-text">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={bodyId}
            onClick={() => setOpen((o) => !o)}
            className="flex min-w-0 cursor-pointer items-center gap-2 rounded-sm text-left hover:text-rh-primary-hover"
          >
            {open ? (
              <ChevronDown className="h-4 w-4 shrink-0 text-rh-muted" aria-hidden="true" />
            ) : (
              <ChevronRight className="h-4 w-4 shrink-0 text-rh-muted" aria-hidden="true" />
            )}
            <ShieldCheck className="h-4 w-4 shrink-0 text-rh-primary" aria-hidden="true" />
            <span>Release gate</span>
          </button>
        </h2>

        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded-sm px-2 py-0.5 text-xs font-medium ${statusChip.cls}`}>{statusChip.text}</span>
          <VerdictBadge verdict={verdict} />
          {runId && (
            <ReportButton
              path={`/api/agent/runs/${runId}/report/html`}
              mode="tab"
              className="inline-flex cursor-pointer items-center gap-1.5 rounded-sm border border-rh-line px-2.5 py-1 text-xs font-medium text-rh-text hover:bg-rh-raised"
              title="Open the full audit report in a new tab"
            >
              <FileText className="h-3.5 w-3.5" aria-hidden="true" />
              Audit report
              <ExternalLink className="h-3 w-3 text-rh-muted" aria-hidden="true" />
            </ReportButton>
          )}
        </div>
      </div>

      <div id={bodyId} className={open ? "flex flex-col gap-4 border-t border-rh-line p-4" : "hidden"}>
        {/* What the backend decided */}
        <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-start">
          <p className="text-ui leading-relaxed text-rh-muted">
            {canApprove
              ? "Review the evidence and the score, then approve this release or block it."
              : hasGateVerdict
              ? "The backend reported NO GO for this run, so it can't be approved. You can only block the release."
              : "The backend did not report a gate verdict (GO, CONDITIONAL GO or NO GO) for this run, so it can't be approved."}
          </p>

          <dl className="grid grid-cols-2 gap-6 rounded-sm border border-rh-line bg-rh-bg px-3 py-2">
            <div>
              <dt className="text-xs text-rh-muted">Score</dt>
              <dd>
                {score === null ? (
                  <span className="text-ui text-rh-muted">not evaluated</span>
                ) : (
                  <span className="text-xl font-semibold tabular-nums text-rh-text">{score}%</span>
                )}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-rh-muted">Defects</dt>
              <dd>
                {defectCount === null ? (
                  <span className="text-ui text-rh-muted">unknown</span>
                ) : (
                  <span
                    className={`text-xl font-semibold tabular-nums ${
                      defectCount > 0 ? "text-rh-nogo" : hasGateVerdict ? "text-rh-go" : "text-rh-text"
                    }`}
                  >
                    {defectCount}
                  </span>
                )}
              </dd>
            </div>
          </dl>
        </div>

        {/* Operator sign-off */}
        {signStatus === "pending" ? (
          <>
            <div className="grid gap-3 md:grid-cols-2">
              <div className="flex flex-col gap-1.5">
                <label htmlFor={operatorId} className="text-ui font-medium text-rh-text">
                  Operator ID <span className="font-normal text-rh-muted">(required)</span>
                </label>
                <input
                  id={operatorId}
                  type="text"
                  value={operator}
                  onChange={(e) => setOperator(e.target.value)}
                  placeholder="e.g. secops@readyhai.io"
                  autoComplete="off"
                  aria-describedby={hintId}
                  className={`${FIELD} font-mono placeholder:font-sans`}
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label htmlFor={notesId} className="text-ui font-medium text-rh-text">
                  Audit notes <span className="font-normal text-rh-muted">(optional)</span>
                </label>
                <input
                  id={notesId}
                  type="text"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Why you approved or blocked this release"
                  className={FIELD}
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <div id={hintId} className="flex min-w-0 flex-1 basis-48 flex-col gap-1">
                {!runId && (
                  <p className="text-ui text-rh-cond">
                    These results are not tied to a stored run, so they cannot be signed off.
                  </p>
                )}
                {needsOperator && <p className="text-ui text-rh-muted">Enter your operator ID to approve or block.</p>}
                {error && (
                  <p className="break-words text-ui text-rh-nogo" role="alert">
                    {error}
                  </p>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={!canSubmit || !canApprove}
                  onClick={() => handleAction("approve")}
                  title={
                    canApprove
                      ? undefined
                      : hasGateVerdict
                      ? "NO_GO verdict: approval is unavailable"
                      : "No backend gate verdict: approval is unavailable"
                  }
                  className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-sm bg-rh-primary px-4 py-2 text-ui font-semibold text-rh-bg hover:bg-rh-primary-hover disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-rh-primary"
                >
                  <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                  Approve release
                </button>
                <button
                  type="button"
                  disabled={!canSubmit}
                  onClick={() => handleAction("reject")}
                  className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-sm border border-rh-nogo px-4 py-2 text-ui font-semibold text-rh-nogo hover:bg-rh-nogo/10 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent"
                >
                  <XCircle className="h-4 w-4" aria-hidden="true" />
                  Block release
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex items-start gap-2.5 rounded-sm border border-rh-line bg-rh-bg p-3 text-ui">
            <UserCheck className="mt-0.5 h-4 w-4 shrink-0 text-rh-primary" aria-hidden="true" />
            <span className="leading-normal text-rh-muted">
              {signStatus === "approved" ? "Approved" : "Blocked"} by{" "}
              <strong className="font-medium text-rh-text">{evidenceLedger.approved_by || "unknown operator"}</strong>
              {evidenceLedger.approval_notes ? ` · ${evidenceLedger.approval_notes}` : ""}
            </span>
          </div>
        )}
      </div>
    </section>
  );
}
