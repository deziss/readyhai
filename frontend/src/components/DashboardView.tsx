"use client";

import { useCallback, useMemo, type ReactNode } from "react";
import {
  Activity,
  CheckCircle2,
  Clock,
  FileSearch,
  PlayCircle,
  ShieldAlert,
  ShieldQuestion,
  Waypoints,
  XCircle,
} from "lucide-react";
import { useCachedApi } from "@/lib/cache";
import { pollIntervalMs, setPref, usePrefs } from "@/lib/prefs";
import {
  asList,
  CACHE_KEYS,
  gateLight,
  gateSummary,
  ledgerSummary,
  targetsFrom,
  type GateLight,
  type TargetRow,
} from "@/lib/dashboard";
import { runId } from "@/lib/runs";
import type { AgentRunRecord } from "@/types/agent";
import type { ScanSummary } from "@/types/scans";
import type { VulnsResponse } from "./VulnsView";
import { AgeStamp, EmptyState, Fact, FactList, Panel, Skeleton, formatAge, useNow, useReveal } from "./ui";

/**
 * The operator's front page: what the release gate says right now, which targets sit behind it, and
 * how much of that answer is measured rather than assumed. Every number here comes from a backend
 * field; where a field is absent the panel says so instead of drawing a zero.
 */

const BTN =
  "inline-flex items-center gap-1.5 rounded-[6px] border border-rh-line bg-rh-raised px-2.5 py-1 text-xs font-medium text-rh-text transition-colors hover:bg-rh-line focus-visible:outline-2 focus-visible:outline-rh-primary disabled:cursor-not-allowed disabled:opacity-50";

type Focus = "gate" | "targets" | "evidence";

interface Props {
  /** Starts a run for a target; the shell wires this to the Studio. */
  onRunTarget?: (target: string) => void;
  onSelectRun?: (runId: string) => void;
  onSelectScan?: (id: string) => void;
  onOpenView?: (view: string) => void;
}

export default function DashboardView({ onRunTarget, onSelectRun, onSelectScan, onOpenView }: Props) {
  const prefs = usePrefs();
  const pollMs = pollIntervalMs(prefs);
  const focus = prefs.dashboardFocus;
  // One clock per render pass, passed down, so every age on screen agrees and render stays pure.
  const now = useNow();

  // Neither endpoint promises an envelope in the shared types, so both are unwrapped via asList.
  const runs = useCachedApi<unknown>(CACHE_KEYS.runs, { label: "agent runs", pollMs });
  const scans = useCachedApi<unknown>(CACHE_KEYS.scans, { label: "scans", pollMs });
  const vulns = useCachedApi<VulnsResponse>(`${CACHE_KEYS.vulns}?status=open`, {
    label: "open findings",
    pollMs,
  });

  const rows = useMemo(
    () =>
      targetsFrom({
        runs: asList<AgentRunRecord>(runs.data, "runs"),
        scans: asList<ScanSummary>(scans.data, "scans"),
        vulns: vulns.data?.vulns ?? [],
      }),
    [runs.data, scans.data, vulns.data]
  );
  const summary = useMemo(() => gateSummary(rows), [rows]);
  const reveal = useReveal(!runs.loading && !scans.loading);

  const refreshAll = useCallback(
    () => void Promise.allSettled([runs.refresh(), scans.refresh(), vulns.refresh()]),
    [runs, scans, vulns]
  );

  const loading = runs.loading && !runs.data;
  const failed = !runs.data && runs.error !== null;

  return (
    <div className={`mx-auto flex w-full max-w-[1400px] flex-col gap-[var(--rh-gap)] ${reveal}`}>
      <Panel
        title="Release gate"
        note={summary.latest?.label}
        actions={
          <>
            {prefs.showFreshness ? (
              <AgeStamp
                ts={runs.ts ?? scans.ts}
                cached={runs.cached || scans.cached}
                stale={runs.stale || scans.stale}
                updating={runs.loading || scans.loading}
              />
            ) : null}
            <button type="button" className={BTN} onClick={refreshAll} disabled={runs.loading || scans.loading}>
              <Activity className="h-3.5 w-3.5" aria-hidden="true" />
              Refresh
            </button>
            {onRunTarget && summary.latest ? (
              <button type="button" className={BTN} onClick={() => onRunTarget(summary.latest!.target)}>
                <PlayCircle className="h-3.5 w-3.5" aria-hidden="true" />
                Re-run
              </button>
            ) : null}
          </>
        }
      >
        {loading ? (
          <Skeleton rows={5} />
        ) : failed ? (
          <EmptyState
            title="No data from the API"
            detail={runs.error ?? "The scanner did not answer the runs request."}
            action={
              <button type="button" className={BTN} onClick={refreshAll}>
                Try again
              </button>
            }
          />
        ) : summary.nothingMeasured ? (
          <EmptyState
            title="Nothing has been measured yet"
            detail="A run has to finish before a release decision exists. Scans on their own do not produce a gate verdict."
            action={
              onOpenView ? (
                <button type="button" className={BTN} onClick={() => onOpenView("studio")}>
                  Open Studio and start a run
                </button>
              ) : undefined
            }
          />
        ) : (
          <GateBlock row={summary.latest} onSelectRun={onSelectRun} focus={focus} now={now} />
        )}
      </Panel>

      <div
        className={`grid gap-[var(--rh-gap)] ${
          prefs.reduceColumns ? "" : "lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]"
        }`}
      >
        <Panel
          title="Targets"
          note={`${summary.targetsWithRuns} of ${summary.targetsTotal} with a run`}
          flush
          className={focus === "targets" ? "ring-1 ring-rh-primary/30" : ""}
        >
          {loading ? (
            <div className="p-[var(--rh-pad-panel)]">
              <Skeleton rows={6} />
            </div>
          ) : rows.length === 0 ? (
            <div className="p-[var(--rh-pad-panel)]">
              <EmptyState title="No targets yet" detail="Run a scan or an agent pass and the target shows up here." />
            </div>
          ) : (
            <TargetTable
              rows={rows}
              now={now}
              showFreshness={prefs.showFreshness}
              onSelectRun={onSelectRun}
              onSelectScan={onSelectScan}
            />
          )}
        </Panel>

        <Panel
          title="Evidence integrity"
          note={summary.latest ? `newest run on ${summary.latest.label}` : undefined}
          className={focus === "evidence" ? "ring-1 ring-rh-primary/30" : ""}
        >
          {loading ? (
            <Skeleton rows={5} />
          ) : (
            <EvidenceBlock row={summary.latest} />
          )}
        </Panel>
      </div>

      <Panel
        title="Open findings"
        note={vulns.data ? `${vulns.data.count} open` : undefined}
        hint="Verified means exploitation was demonstrated. Unverified means a rule matched and nobody has run an exploit template against it."
        actions={
          onOpenView ? (
            <button type="button" className={BTN} onClick={() => onOpenView("vulns")}>
              <FileSearch className="h-3.5 w-3.5" aria-hidden="true" />
              Triage
            </button>
          ) : null
        }
      >
        {vulns.loading && !vulns.data ? (
          <Skeleton rows={3} />
        ) : vulns.data && summary.verifiedOpen + summary.unverifiedOpen === 0 ? (
          <p className="text-ui text-rh-muted">
            No open findings across {summary.targetsTotal} target{summary.targetsTotal === 1 ? "" : "s"}.
          </p>
        ) : (
          <div className="flex flex-wrap gap-x-10 gap-y-3">
            <FindingCount
              icon={<ShieldAlert className="h-4 w-4 text-rh-nogo" aria-hidden="true" />}
              value={summary.verifiedOpen}
              label="Exploit demonstrated"
            />
            <FindingCount
              icon={<ShieldQuestion className="h-4 w-4 text-rh-muted" aria-hidden="true" />}
              value={summary.unverifiedOpen}
              label="Rule match, unverified"
            />
            <FindingCount
              icon={<XCircle className="h-4 w-4 text-rh-nogo" aria-hidden="true" />}
              value={summary.failingScans}
              label="Scans failing"
            />
          </div>
        )}
      </Panel>

      {summary.awaitingSignOff.length > 0 ? (
        <Panel title="Awaiting sign-off" note="A verdict becomes a release decision when someone signs it">
          <ul className="flex flex-col divide-y divide-rh-line/60">
            {summary.awaitingSignOff.map((row) => (
              <li key={row.key} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5">
                <GateDot light={gateLight(row)} />
                <span className="min-w-0 flex-1 truncate text-ui text-rh-text">{row.label}</span>
                <span className="text-xs text-rh-muted">{row.verdict?.toLowerCase().replace("_", " ")}</span>
                {prefs.showFreshness && row.runTs ? (
                  <span className="text-micro text-rh-faint tabular-nums">{formatAge(now - row.runTs)}</span>
                ) : null}
                {onOpenView ? (
                  <button type="button" className={BTN} onClick={() => onOpenView("agent_history")}>
                    Review
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

const FOCUS_OPTIONS: { id: Focus; label: string }[] = [
  { id: "gate", label: "gate" },
  { id: "targets", label: "targets" },
  { id: "evidence", label: "evidence" },
];

function GateBlock({
  row,
  onSelectRun,
  focus,
  now,
}: {
  row: TargetRow | null;
  onSelectRun?: (id: string) => void;
  focus: Focus;
  now: number;
}) {
  if (!row) {
    return <p className="text-ui text-rh-muted">A finished run shows up here.</p>;
  }
  const light = gateLight(row);
  const gateRun = row.finishedRun ?? row.run;
  const id = gateRun ? runId(gateRun) : null;
  const ledger = ledgerSummary(gateRun);
  const blockers = ledger?.blockers ?? [];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div
          className={`flex items-center gap-2.5 rounded-md border px-3.5 py-2 ${
            light === "go"
              ? "border-rh-go/40 bg-rh-go/10"
              : light === "conditional"
                ? "border-rh-cond/40 bg-rh-cond/10"
                : light === "no_go"
                  ? "border-rh-nogo/40 bg-rh-nogo/10"
                  : "border-rh-line bg-rh-raised"
          }`}
        >
          {light === "go" ? (
            <CheckCircle2 className="h-5 w-5 text-rh-go" aria-hidden="true" />
          ) : light === "conditional" ? (
            <ShieldAlert className="h-5 w-5 text-rh-cond" aria-hidden="true" />
          ) : light === "no_go" ? (
            <XCircle className="h-5 w-5 text-rh-nogo" aria-hidden="true" />
          ) : (
            <ShieldQuestion className="h-5 w-5 text-rh-muted" aria-hidden="true" />
          )}
          <span
            className={`text-lg font-semibold tracking-[-0.015em] ${
              light === "go"
                ? "text-rh-go"
                : light === "conditional"
                  ? "text-rh-cond"
                  : light === "no_go"
                    ? "text-rh-nogo"
                    : "text-rh-muted"
            }`}
          >
            {gateText(row, light)}
          </span>
        </div>

        <div className="min-w-0">
          <p className="truncate text-ui font-semibold text-rh-text">{row.label}</p>
          <p className="text-xs text-rh-muted">
            {row.finishedRunTs
              ? `Run finished its pass ${formatAge(now - row.finishedRunTs)}`
              : "Run has no reported start time"}
            {id ? ` · ${id}` : ""}
          </p>
        </div>

        <div className="ml-auto flex gap-1" role="group" aria-label="Which section to highlight">
          {FOCUS_OPTIONS.map((option) => (
            <button
              key={option.id}
              type="button"
              onClick={() => setPref("dashboardFocus", option.id)}
              aria-pressed={focus === option.id}
              className={`rounded-[6px] border px-2 py-1 text-micro font-medium transition-colors focus-visible:outline-2 focus-visible:outline-rh-primary ${
                focus === option.id
                  ? "border-rh-primary/50 bg-rh-primary/12 text-rh-text"
                  : "border-rh-line text-rh-muted hover:bg-rh-raised hover:text-rh-text"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {ledger && !ledger.evaluated ? (
        <p className="rounded-[6px] border border-rh-line-strong bg-rh-raised px-3 py-2 text-xs text-rh-muted">
          The ledger could not evaluate this run, so there is no readiness score to show. What follows is
          what the run collected, not a verdict on the target.
        </p>
      ) : null}

      <FactList>
        <Fact
          label="Readiness score"
          value={row.score === null ? null : row.score}
          missing="not evaluated"
          tone={row.score === null ? "muted" : row.score >= 70 ? "go" : row.score >= 40 ? "cond" : "nogo"}
          hint="Backend overall_readiness. Absent when no pillar could be evaluated."
        />
        <Fact
          label="Evidence confidence"
          value={ledger?.confidence == null ? null : `${ledger.confidence}%`}
          missing="no conclusive cases"
          hint="Share of applicable cases that reached a conclusive result."
        />
        <Fact label="Defects" value={row.defects} missing="not reported" tone={row.defects ? "nogo" : "default"} />
        <Fact
          label="Sign-off"
          value={row.approval === "approved" ? "Approved" : row.approval === "rejected" ? "Rejected" : "Unsigned"}
          tone={row.approval === "approved" ? "go" : row.approval === "rejected" ? "nogo" : "muted"}
        />
        <Fact
          label="Blocking reasons"
          value={blockers.length || null}
          missing="none recorded"
          tone={blockers.length ? "cond" : "muted"}
        />
      </FactList>

      {blockers.length > 0 ? (
        <ul className="flex flex-col gap-1.5 border-t border-rh-line pt-2.5">
          {blockers.slice(0, 4).map((b, i) => (
            <li key={`${b.reason}-${i}`} className="flex gap-2 text-xs">
              <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-rh-cond" aria-hidden="true" />
              <span className="min-w-0">
                <span className="font-semibold text-rh-text">{b.label}</span>
                {b.detail ? <span className="text-rh-muted"> {b.detail}</span> : null}
                {b.nextStep ? <span className="text-rh-faint"> Next step: {b.nextStep}</span> : null}
              </span>
            </li>
          ))}
        </ul>
      ) : null}

      {ledger?.basis ? (
        <p className="border-t border-rh-line pt-2 text-xs leading-relaxed text-rh-muted">{ledger.basis}</p>
      ) : null}

      {id && onSelectRun ? (
        <button type="button" className={`${BTN} self-start`} onClick={() => onSelectRun(id)}>
          <Waypoints className="h-3.5 w-3.5" aria-hidden="true" />
          Open the run
        </button>
      ) : null}
    </div>
  );
}

function gateText(row: TargetRow, light: GateLight): string {
  if (light === "go") return row.approval === "approved" ? "Go, signed off" : "Go, unsigned";
  if (light === "conditional") return "Conditional go";
  if (light === "no_go") return "No go";
  if (row.verdict === "SCANNED") return "Scanned, no verdict";
  return "No verdict yet";
}

// ---------------------------------------------------------------------------
// Targets table
// ---------------------------------------------------------------------------

function TargetTable({
  rows,
  now,
  showFreshness,
  onSelectRun,
  onSelectScan,
}: {
  rows: TargetRow[];
  now: number;
  showFreshness: boolean;
  onSelectRun?: (id: string) => void;
  onSelectScan?: (id: string) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="border-b border-rh-line text-micro text-rh-faint">
            <th scope="col" className="py-1.5 pl-[var(--rh-pad-panel)] pr-2 text-left font-medium">
              Target
            </th>
            <th scope="col" className="px-2 py-1.5 text-left font-medium">
              Gate
            </th>
            <th scope="col" className="px-2 py-1.5 text-right font-medium">
              Score
            </th>
            <th scope="col" className="px-2 py-1.5 text-right font-medium">
              Defects
            </th>
            <th scope="col" className="px-2 py-1.5 text-right font-medium">
              Open
            </th>
            <th scope="col" className="py-1.5 pl-2 pr-[var(--rh-pad-panel)] text-right font-medium">
              Age
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 12).map((row) => {
            const light = gateLight(row);
            const id = row.run ? runId(row.run) : null;
            return (
              <tr
                key={row.key}
                className="border-b border-rh-line/60 transition-colors last:border-b-0 hover:bg-rh-raised"
                style={{ height: "var(--rh-row-h)" }}
              >
                <th
                  scope="row"
                  className="max-w-[280px] truncate py-0 pl-[var(--rh-pad-panel)] pr-2 text-left font-normal"
                >
                  <button
                    type="button"
                    className="block max-w-full truncate text-left text-ui text-rh-text focus-visible:outline-2 focus-visible:outline-rh-primary disabled:cursor-default disabled:text-rh-muted"
                    disabled={!id || !onSelectRun}
                    onClick={() => id && onSelectRun?.(id)}
                    title={row.target}
                  >
                    {row.label}
                  </button>
                  {row.active ? (
                    <span className="rh-live text-micro text-rh-primary">running</span>
                  ) : row.scan && !row.run && onSelectScan ? (
                    <button
                      type="button"
                      className="text-micro text-rh-faint underline-offset-2 hover:text-rh-text hover:underline focus-visible:outline-2 focus-visible:outline-rh-primary"
                      onClick={() => row.scan && onSelectScan(row.scan.id)}
                    >
                      {row.scan.verdict.toLowerCase()} scan
                    </button>
                  ) : null}
                </th>
                <td className="px-2 py-0">
                  <span className="flex items-center gap-1.5">
                    <GateDot light={light} />
                    <span className="text-xs text-rh-muted">
                      {light === "unknown" ? "no verdict" : light.replace("_", " ")}
                    </span>
                  </span>
                </td>
                <td className="px-2 py-0 text-right text-ui text-rh-text tabular-nums">
                  {row.score === null ? <span className="text-rh-faint">n/a</span> : row.score}
                </td>
                <td className="px-2 py-0 text-right text-ui tabular-nums">
                  {row.defects === null ? (
                    <span className="text-rh-faint">n/r</span>
                  ) : (
                    <span className={row.defects > 0 ? "text-rh-nogo" : "text-rh-muted"}>{row.defects}</span>
                  )}
                </td>
                <td className="px-2 py-0 text-right text-ui tabular-nums">
                  {row.openVulns === 0 ? (
                    <span className="text-rh-muted">0</span>
                  ) : (
                    <span className="text-rh-text">
                      {row.openVulns}
                      {row.verifiedOpen > 0 ? <span className="text-rh-nogo"> ·{row.verifiedOpen}</span> : null}
                    </span>
                  )}
                </td>
                <td className="py-0 pl-2 pr-[var(--rh-pad-panel)] text-right">
                  {showFreshness && row.lastSeen ? (
                    <span className="inline-flex items-center gap-1 text-micro text-rh-faint tabular-nums">
                      <Clock className="h-3 w-3" aria-hidden="true" />
                      {formatAge(now - row.lastSeen)}
                    </span>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function GateDot({ light }: { light: GateLight }) {
  const tone =
    light === "go"
      ? "bg-rh-go"
      : light === "conditional"
        ? "rh-hatch bg-rh-cond"
        : light === "no_go"
          ? "bg-rh-nogo"
          : "bg-rh-line-strong";
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${tone}`} aria-hidden="true" />;
}

// ---------------------------------------------------------------------------
// Evidence integrity
// ---------------------------------------------------------------------------

function EvidenceBlock({ row }: { row: TargetRow | null }) {
  const ledger = ledgerSummary(row?.finishedRun ?? row?.run ?? null);
  if (!row || !row.finishedRun) {
    return (
      <EmptyState
        title="No finished run to inspect"
        detail="Pillar scores come from the evidence ledger of the newest finished run. A pass that is still running has no ledger yet."
      />
    );
  }
  if (!ledger) {
    return (
      <EmptyState
        title="This run carried no evidence ledger"
        detail="Runs older than the ledger report raw cases only. Open the run to read them."
      />
    );
  }
  const pillars = ledger.pillars;
  if (pillars.length === 0) {
    return (
      <EmptyState
        title="No pillar was evaluated"
        detail={ledger.basis ?? "The backend reported no conclusive results, so it scored no pillar."}
      />
    );
  }

  return (
    <div className="flex flex-col gap-1">
      {pillars.map((p) => {
        const unevaluated = p.score === null || p.status === "not_evaluated";
        const tone =
          p.status === "pass"
            ? "bg-rh-go"
            : p.status === "fail"
              ? "bg-rh-nogo"
              : p.status === "partial"
                ? "bg-rh-cond"
                : "bg-rh-line-strong";
        return (
          <div key={p.id} className="flex items-center gap-3 py-1">
            <span className="w-[112px] shrink-0 truncate text-xs text-rh-text" title={p.claim || p.name}>
              {p.name}
            </span>
            <span className="relative h-1.5 min-w-[60px] flex-1 overflow-hidden rounded-full bg-rh-raised">
              <span
                className={`absolute inset-y-0 left-0 rounded-full ${tone}`}
                style={{ width: `${unevaluated ? 0 : Math.max(2, Math.min(100, p.score ?? 0))}%` }}
              />
            </span>
            <span
              className={`w-[86px] shrink-0 text-right text-xs tabular-nums ${
                unevaluated ? "text-rh-faint" : "text-rh-text"
              }`}
            >
              {unevaluated ? "not evaluated" : p.score}
            </span>
          </div>
        );
      })}
      <p className="pt-1.5 text-micro leading-relaxed text-rh-faint">
        A bar is drawn only where the backend returned a score. &ldquo;Not evaluated&rdquo; means the run
        gathered nothing conclusive for that pillar, so there is nothing to draw.
      </p>
    </div>
  );
}

function FindingCount({ icon, value, label }: { icon: ReactNode; value: number; label: string }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="translate-y-0.5">{icon}</span>
      <span className="text-xl font-semibold tabular-nums text-rh-text">{value}</span>
      <span className="text-xs text-rh-muted">{label}</span>
    </div>
  );
}
