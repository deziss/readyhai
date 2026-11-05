import { Ban, Loader2, XCircle } from "lucide-react";
import { RUN_STATUS_LABEL, normalizeRunStatus } from "@/lib/runs";

interface RunStatusBadgeProps {
  /** Run status exactly as the backend reported it. */
  status?: string | null;
  className?: string;
}

/**
 * Lifecycle chip for a run that is not (or not normally) finished: running, cancelled or failed.
 * A completed run, a legacy report without a status and an unknown status render nothing: the
 * gate verdict badge already describes a finished run, and nothing is guessed.
 */
export function RunStatusBadge({ status, className = "" }: RunStatusBadgeProps) {
  const lifecycle = normalizeRunStatus(status);
  const base = `inline-flex items-center gap-1 px-2 py-0.5 rounded-[6px] text-xs font-semibold whitespace-nowrap ${className}`;
  switch (lifecycle) {
    case "running":
      return (
        <span className={`${base} bg-rh-info/15 text-rh-info`} title="The run is still executing">
          <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> {RUN_STATUS_LABEL.running}
        </span>
      );
    case "cancelled":
      return (
        <span
          className={`${base} bg-rh-cond/15 text-rh-cond`}
          title="The run was stopped before it finished; its results are partial"
        >
          <Ban className="w-3.5 h-3.5" aria-hidden="true" /> {RUN_STATUS_LABEL.cancelled}
        </span>
      );
    case "failed":
      return (
        <span className={`${base} bg-rh-nogo/15 text-rh-nogo`} title="The run ended with an error">
          <XCircle className="w-3.5 h-3.5" aria-hidden="true" /> {RUN_STATUS_LABEL.failed}
        </span>
      );
    default:
      return null;
  }
}
