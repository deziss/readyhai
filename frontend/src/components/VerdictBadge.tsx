import { AlertTriangle, CheckCircle2, HelpCircle, XCircle, Radar } from "lucide-react";

interface VerdictBadgeProps {
  /** Gate verdict exactly as the backend reported it; null/undefined = not evaluated. */
  verdict?: string | null;
  className?: string;
}

/**
 * Gate verdict chip. Only a backend-reported GO is ever green; a missing or
 * unrecognised verdict renders neutral ("not evaluated"). A backend NOT_EVALUATED (too little
 * conclusive evidence) is neutral too: it is not a failure, so it is never red.
 */
export function VerdictBadge({ verdict, className = "" }: VerdictBadgeProps) {
  const base = `inline-flex items-center gap-1 px-2 py-0.5 rounded-[6px] text-xs font-semibold whitespace-nowrap ${className}`;
  switch (verdict) {
    case "GO":
      return (
        <span className={`${base} bg-rh-go/15 text-rh-go`}>
          <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" /> GO
        </span>
      );
    case "CONDITIONAL_GO":
      return (
        <span className={`${base} bg-rh-cond/15 text-rh-cond`}>
          <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" /> Conditional go
        </span>
      );
    case "NO_GO":
      return (
        <span className={`${base} bg-rh-nogo/15 text-rh-nogo`}>
          <XCircle className="w-3.5 h-3.5" aria-hidden="true" /> No go
        </span>
      );
    case "NOT_EVALUATED":
      return (
        <span
          className={`${base} bg-rh-raised text-rh-muted`}
          title="Not enough conclusive evidence for a verdict. This is not a failure: see what to provide next."
        >
          <HelpCircle className="w-3.5 h-3.5" aria-hidden="true" /> Not evaluated
        </span>
      );
    case "SCANNED":
      return (
        <span
          className={`${base} bg-rh-info/15 text-rh-info`}
          title="Reconnaissance scan only: no gate verdict was produced"
        >
          <Radar className="w-3.5 h-3.5" aria-hidden="true" /> Scanned
        </span>
      );
    default:
      return (
        <span
          className={`${base} bg-rh-raised text-rh-muted`}
          title="The backend did not report a gate verdict for this run"
        >
          <HelpCircle className="w-3.5 h-3.5" aria-hidden="true" />{" "}
          {verdict ? verdict.replace(/_/g, " ") : "Not evaluated"}
        </span>
      );
  }
}
