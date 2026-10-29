import { AlertTriangle, CheckCircle2, HelpCircle, XCircle, Radar } from "lucide-react";

interface VerdictBadgeProps {
  /** Gate verdict exactly as the backend reported it; null/undefined = not evaluated. */
  verdict?: string | null;
  className?: string;
}

/**
 * Gate verdict pill. Only a backend-reported GO is ever green; a missing or
 * unrecognised verdict renders neutral ("not evaluated").
 */
export function VerdictBadge({ verdict, className = "" }: VerdictBadgeProps) {
  const base = `inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border tracking-wider ${className}`;
  switch (verdict) {
    case "GO":
      return (
        <span className={`${base} bg-emerald-950/80 text-emerald-300 border-emerald-600/70`}>
          <CheckCircle2 className="w-3 h-3" /> GO
        </span>
      );
    case "CONDITIONAL_GO":
      return (
        <span className={`${base} bg-amber-950/80 text-amber-300 border-amber-600/70`}>
          <AlertTriangle className="w-3 h-3" /> CONDITIONAL GO
        </span>
      );
    case "NO_GO":
      return (
        <span className={`${base} bg-rose-950/80 text-rose-300 border-rose-600/70`}>
          <XCircle className="w-3 h-3" /> NO GO
        </span>
      );
    case "SCANNED":
      return (
        <span
          className={`${base} bg-cyan-950/60 text-cyan-300 border-cyan-700/60`}
          title="Reconnaissance scan only: no gate verdict was produced"
        >
          <Radar className="w-3 h-3" /> SCANNED
        </span>
      );
    default:
      return (
        <span
          className={`${base} bg-slate-900 text-slate-400 border-slate-700`}
          title="The backend did not report a gate verdict for this run"
        >
          <HelpCircle className="w-3 h-3" /> {verdict ? verdict.replace(/_/g, " ") : "NOT EVALUATED"}
        </span>
      );
  }
}
