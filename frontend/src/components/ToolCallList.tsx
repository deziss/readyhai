"use client";

import { useId, useState } from "react";
import { AlertTriangle, Check, HelpCircle, Loader2, X } from "lucide-react";
import { VerdictBadge } from "./VerdictBadge";

export type PipelineStage = "recon" | "discovery" | "plan" | "execute" | "verify" | "gate";
export type StageStatus = "standby" | "running" | "succeeded" | "failed";

export interface StageState {
  id: PipelineStage;
  label: string;
  subtext: string;
  status: StageStatus;
}

/** The six pipeline stages in run order, ending with the gate verdict. */
export const PIPELINE_STAGES: ReadonlyArray<Pick<StageState, "id" | "label" | "subtext">> = [
  {
    id: "recon",
    label: "Recon",
    subtext: "Checks the model connection and the target's health before anything else runs.",
  },
  {
    id: "discovery",
    label: "Discovery",
    subtext: "Probes the target root and maps the endpoints and routes the agent can test.",
  },
  {
    id: "plan",
    label: "Plan",
    subtext: "Writes negative, boundary and authorization test cases for what it found.",
  },
  {
    id: "execute",
    label: "Execute",
    subtext: "Runs the planned cases against the target and records every request and response.",
  },
  {
    id: "verify",
    label: "Verify",
    subtext: "Triages failures into defects, maps them to OWASP categories and builds the evidence ledger.",
  },
  {
    id: "gate",
    label: "Gate",
    subtext: "Scores the evidence and issues the release verdict: go, conditional go or no go.",
  },
];

/** Builds the full stage list; `statusAt` decides each stage's status by index (default: all on standby). */
export function buildStages(statusAt: (index: number) => StageStatus = () => "standby"): StageState[] {
  return PIPELINE_STAGES.map((s, i) => ({ ...s, status: statusAt(i) }));
}

interface ToolCallListProps {
  stages: StageState[];
  /** Gate verdict exactly as the backend reported it; null/undefined when there is none. */
  verdict?: string | null;
}

const STATUS_LABEL: Record<StageStatus, string> = {
  standby: "Waiting",
  running: "Running",
  succeeded: "Done",
  failed: "Failed",
};

const VERDICT_LABEL: Record<string, string> = {
  GO: "Go",
  CONDITIONAL_GO: "Conditional go",
  NO_GO: "No go",
};

type Tone = "neutral" | "active" | "go" | "cond" | "nogo";

const TONE_RING: Record<Tone, string> = {
  neutral: "border-rh-line text-rh-muted",
  active: "border-rh-primary bg-rh-primary/10 text-rh-primary",
  go: "border-rh-go bg-rh-go/10 text-rh-go",
  cond: "border-rh-cond bg-rh-cond/10 text-rh-cond",
  nogo: "border-rh-nogo bg-rh-nogo/10 text-rh-nogo",
};

const TONE_CHIP: Record<Tone, string> = {
  neutral: "bg-rh-raised text-rh-muted",
  active: "bg-rh-primary/15 text-rh-primary",
  go: "bg-rh-go/15 text-rh-go",
  cond: "bg-rh-cond/15 text-rh-cond",
  nogo: "bg-rh-nogo/10 text-rh-nogo",
};

/** Tone and label for one stage. The gate stage reports the backend verdict once it has finished. */
function stageView(stage: StageState, verdict: string | null | undefined) {
  if (stage.id === "gate" && stage.status === "succeeded") {
    if (verdict === "GO") return { tone: "go" as Tone, text: "Verdict: go" };
    if (verdict === "CONDITIONAL_GO") return { tone: "cond" as Tone, text: "Verdict: conditional go" };
    if (verdict === "NO_GO") return { tone: "nogo" as Tone, text: "Verdict: no go" };
    return { tone: "neutral" as Tone, text: "No verdict reported" };
  }
  const tone: Tone =
    stage.status === "running" ? "active" : stage.status === "succeeded" ? "go" : stage.status === "failed" ? "nogo" : "neutral";
  return { tone, text: STATUS_LABEL[stage.status] };
}

function StageMarker({ stage, index, verdict }: { stage: StageState; index: number; verdict?: string | null }) {
  if (stage.status === "running") return <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />;
  if (stage.status === "failed") return <X className="h-3.5 w-3.5" aria-hidden="true" />;
  if (stage.status === "succeeded") {
    if (stage.id === "gate") {
      if (verdict === "NO_GO") return <X className="h-3.5 w-3.5" aria-hidden="true" />;
      if (verdict === "CONDITIONAL_GO") return <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />;
      if (verdict !== "GO") return <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />;
    }
    return <Check className="h-3.5 w-3.5" aria-hidden="true" />;
  }
  return <span className="text-xs font-medium tabular-nums">{index + 1}</span>;
}

/**
 * Stable pipeline stepper: Recon, Discovery, Plan, Execute, Verify, Gate.
 *
 * Nothing here reacts to hover except colour. Every stage button and marker has a fixed size and
 * border in every state, and stage details open on click or keyboard into a fixed-height area, so
 * the layout never shifts.
 */
export function ToolCallList({ stages, verdict = null }: ToolCallListProps) {
  const [selectedId, setSelectedId] = useState<PipelineStage | null>(null);
  const detailId = useId();
  const titleId = useId();

  const runningStage = stages.find((s) => s.status === "running");
  const failedStage = stages.find((s) => s.status === "failed");
  const allSucceeded = stages.length > 0 && stages.every((s) => s.status === "succeeded");
  const selectedStage = stages.find((s) => s.id === selectedId) ?? null;

  const headline = runningStage
    ? `Running ${runningStage.label}`
    : failedStage
    ? `${failedStage.label} failed`
    : allSucceeded
    ? "All stages complete"
    : "Idle";
  const headlineTone = runningStage
    ? "text-rh-primary"
    : failedStage
    ? "text-rh-nogo"
    : allSucceeded
    ? "text-rh-go"
    : "text-rh-muted";

  // What the fixed-height detail area shows when no stage is selected.
  const summary = runningStage
    ? `${runningStage.label} is running. ${runningStage.subtext}`
    : failedStage
    ? `The run stopped at ${failedStage.label}. The error is shown in the notice at the top of the page.`
    : allSucceeded
    ? verdict && VERDICT_LABEL[verdict]
      ? `The run finished with a ${VERDICT_LABEL[verdict].toLowerCase()} verdict. Select a stage to see what it did.`
      : "The run finished without a gate verdict. Select a stage to see what it did."
    : "Run the agent from the command center to start the pipeline. Select a stage to see what it does.";

  const selectedView = selectedStage ? stageView(selectedStage, verdict) : null;

  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-3 rounded-md border border-rh-line bg-rh-surface p-4">
      <div className="flex min-h-6 items-center justify-between gap-3">
        <div className="flex min-w-0 items-baseline gap-2">
          <h2 id={titleId} className="shrink-0 text-sm font-semibold text-rh-text">
            Agent pipeline
          </h2>
          <span className={`truncate text-ui font-medium ${headlineTone}`}>{headline}</span>
        </div>
        <div className="shrink-0">
          {verdict ? <VerdictBadge verdict={verdict} /> : <span className="text-xs text-rh-muted">No verdict yet</span>}
        </div>
      </div>

      <ol className="flex items-start">
        {stages.map((stage, i) => {
          const view = stageView(stage, verdict);
          const selected = selectedId === stage.id;
          const doneBefore = i > 0 && stages[i - 1].status === "succeeded";
          return (
            <li key={stage.id} className={`flex items-start ${i === 0 ? "flex-none" : "min-w-0 flex-1"}`}>
              {i > 0 && (
                <span
                  aria-hidden="true"
                  className={`mt-[18px] h-0.5 min-w-1 flex-1 ${doneBefore ? "bg-rh-go/60" : "bg-rh-line"}`}
                />
              )}
              <button
                type="button"
                aria-expanded={selected}
                aria-controls={detailId}
                onClick={() => setSelectedId(selected ? null : stage.id)}
                className={`group flex shrink-0 cursor-pointer flex-col items-center gap-1 rounded-sm border px-1 py-1.5 sm:px-2 ${
                  selected ? "border-rh-primary bg-rh-raised" : "border-transparent"
                }`}
              >
                <span
                  className={`flex h-6 w-6 items-center justify-center rounded-full border ${TONE_RING[view.tone]} ${
                    stage.status === "standby" ? "group-hover:border-rh-muted group-hover:text-rh-text" : ""
                  }`}
                >
                  <StageMarker stage={stage} index={i} verdict={verdict} />
                </span>
                <span
                  className={`text-xs font-medium ${
                    selected ? "text-rh-text" : "text-rh-muted group-hover:text-rh-text"
                  }`}
                >
                  {stage.label}
                </span>
                <span className="sr-only">{view.text}</span>
              </button>
            </li>
          );
        })}
      </ol>

      <div
        id={detailId}
        role="region"
        aria-label="Stage details"
        aria-live="polite"
        className="h-20 overflow-y-auto rounded-sm border sm:h-16 border-rh-line bg-rh-bg px-3 py-2"
      >
        {selectedStage && selectedView ? (
          <>
            <div className="flex items-center gap-2">
              <span className="text-ui font-medium text-rh-text">{selectedStage.label}</span>
              <span className={`rounded-sm px-1.5 text-xs font-medium ${TONE_CHIP[selectedView.tone]}`}>
                {selectedView.text}
              </span>
            </div>
            <p className="text-ui text-rh-muted">{selectedStage.subtext}</p>
          </>
        ) : (
          <p className="text-ui text-rh-muted">{summary}</p>
        )}
      </div>
    </section>
  );
}
