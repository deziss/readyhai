import { AlertTriangle, ArrowRight } from "lucide-react";
import type { BlockerView, PillarView } from "@/lib/runs";

/** "partial" / "not_evaluated" -> "Partial" / "Not evaluated". */
function humanize(v: string): string {
  const t = (v || "").replace(/_/g, " ").trim().toLowerCase();
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : t;
}

function statusTone(status: string): string {
  if (status === "pass") return "bg-rh-go/15 text-rh-go";
  if (status === "fail") return "bg-rh-nogo/15 text-rh-nogo";
  if (status === "partial") return "bg-rh-cond/15 text-rh-cond";
  return "bg-rh-raised text-rh-text";
}

interface PillarCardProps {
  pillar: PillarView;
  /** Zero-based position, shown as "1. Name" when given. */
  index?: number;
  /** Card background: the page background (inside a surface) or the surface colour (on the page). */
  surface?: "bg" | "surface";
}

/**
 * One evidence pillar as the backend reported it: its own name, score, status, claim and confidence.
 * A pillar without enough conclusive evidence says so instead of showing a score.
 */
export function PillarCard({ pillar, index, surface = "bg" }: PillarCardProps) {
  const score = pillar.score === null ? null : Math.max(0, Math.min(100, pillar.score));
  return (
    <div
      data-pillar={pillar.key}
      className={`${surface === "bg" ? "bg-rh-bg" : "bg-rh-surface"} border border-rh-line rounded-[10px] p-3.5 flex flex-col gap-2.5`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-sm font-semibold text-rh-text">
          {index === undefined ? "" : `${index + 1}. `}
          {pillar.title}
        </span>
        <span className="flex items-center gap-1.5 shrink-0">
          {pillar.confidence !== null && (
            <span
              className="text-xs text-rh-muted bg-rh-raised px-1.5 py-0.5 rounded-[6px] font-medium tabular-nums whitespace-nowrap"
              title="Share of the applicable cases that gave a conclusive result (pass, warn or fail)"
            >
              confidence {pillar.confidence}%
            </span>
          )}
          {!pillar.notEvaluated && pillar.status && (
            <span className={`text-xs px-1.5 py-0.5 rounded-[6px] font-semibold ${statusTone(pillar.status)}`}>
              {humanize(pillar.status)}
            </span>
          )}
        </span>
      </div>

      {score === null || pillar.notEvaluated ? (
        <div className="text-xs font-medium text-rh-muted">Not evaluated: insufficient evidence</div>
      ) : (
        <div className="flex items-center gap-2.5">
          <div
            className="flex-1 bg-rh-raised rounded-full h-2 overflow-hidden"
            role="progressbar"
            aria-label={`${pillar.title} score`}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={score}
          >
            <div className="bg-rh-primary h-full rounded-full" style={{ width: `${score}%` }} />
          </div>
          <span className="text-xs font-semibold text-rh-text tabular-nums">{score}%</span>
        </div>
      )}

      <p className="text-xs text-rh-muted leading-relaxed">
        {pillar.evidence ?? "No evidence text was reported for this pillar."}
      </p>
      {pillar.caseCount > 0 && (
        <span className="text-xs text-rh-muted tabular-nums">
          {pillar.caseCount} {pillar.caseCount === 1 ? "case" : "cases"}
        </span>
      )}
    </div>
  );
}

interface NextStepsCardProps {
  blockers: BlockerView[];
  surface?: "bg" | "surface";
}

/**
 * "What to provide next": every blocker the backend found (auth wall, no API surface, out-of-scope
 * host, ...) with what it means and the exact step that would unblock it. Renders nothing without blockers.
 */
export function NextStepsCard({ blockers, surface = "bg" }: NextStepsCardProps) {
  if (blockers.length === 0) return null;
  return (
    <section
      aria-label="What to provide next"
      className={`${surface === "bg" ? "bg-rh-bg" : "bg-rh-surface"} border border-rh-cond/40 rounded-[10px] p-3.5 flex flex-col gap-3`}
    >
      <div className="flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-rh-cond shrink-0" aria-hidden="true" />
        <h4 className="text-sm font-semibold text-rh-text">What to provide next</h4>
      </div>
      <ul className="flex flex-col gap-3">
        {blockers.map((b, i) => (
          <li key={`${b.reason}-${i}`} className="flex flex-col gap-1 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-1.5 py-0.5 rounded-[6px] bg-rh-cond/15 text-rh-cond font-semibold">{b.label}</span>
              {b.caseCount > 0 && (
                <span className="text-rh-muted tabular-nums">
                  {b.caseCount} {b.caseCount === 1 ? "case" : "cases"} blocked
                </span>
              )}
            </div>
            {b.detail && <p className="text-rh-text leading-relaxed">{b.detail}</p>}
            {b.nextStep && (
              <p className="flex items-start gap-1.5 text-rh-muted leading-relaxed">
                <ArrowRight className="w-3.5 h-3.5 mt-0.5 shrink-0 text-rh-primary" aria-hidden="true" />
                <span>{b.nextStep}</span>
              </p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
