"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { RefreshCw } from "lucide-react";

/**
 * Shared building blocks for the dashboard and history views.
 *
 * The house rules here come from the design system: panels take a 1px line and no shadow (the only
 * shadow in the system is for popovers), data aligns in rows rather than in grids of equal cards,
 * "we have not measured this" is always an available answer, and relative timestamps say which
 * value they describe instead of animating for its own sake.
 */

// ---------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------

interface PanelProps {
  title: string;
  /** Optional trailing note next to the title, e.g. the target a panel belongs to. */
  note?: ReactNode;
  actions?: ReactNode;
  /** One-line explanation under the heading. Use it for scope, not for marketing. */
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Removes inner padding for panels whose content sets its own rhythm (tables). */
  flush?: boolean;
}

export function Panel({
  title,
  note,
  actions,
  hint,
  children,
  className = "",
  flush = false,
}: PanelProps) {
  return (
    <section
      className={`flex min-h-0 flex-col overflow-hidden rounded-md border border-rh-line bg-rh-surface ${className}`}
    >
      <header className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-b border-rh-line px-[var(--rh-pad-panel)] py-2">
        <h2 className="text-ui font-semibold tracking-[-0.01em] text-rh-text">{title}</h2>
        {note ? <span className="min-w-0 truncate text-xs text-rh-muted">{note}</span> : null}
        {actions ? <div className="ml-auto flex items-center gap-1.5">{actions}</div> : null}
      </header>
      {hint ? (
        <p className="border-b border-rh-line px-[var(--rh-pad-panel)] py-1.5 text-xs text-rh-muted">{hint}</p>
      ) : null}
      <div className={flush ? "min-h-0 flex-1" : "min-h-0 flex-1 overflow-y-auto p-[var(--rh-pad-panel)]"}>
        {children}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Loading and empty states
// ---------------------------------------------------------------------------

/**
 * Blocks shaped like the content that is coming. `rows` renders the label/value pattern the
 * dashboard uses; `lines` is for prose. A skeleton is shown only when the panel has nothing to
 * show, never on top of data that is already there.
 */
export function Skeleton({ rows = 3, lines = 0 }: { rows?: number; lines?: number }) {
  return (
    <div className="flex flex-col gap-2" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={`row-${i}`} className="flex items-center gap-3">
          <span className="rh-skeleton h-3.5 w-[38%]" />
          <span className="rh-skeleton ml-auto h-3.5 w-16" />
        </div>
      ))}
      {Array.from({ length: lines }, (_, i) => (
        <span key={`line-${i}`} className="rh-skeleton h-3 w-full" />
      ))}
    </div>
  );
}

interface EmptyProps {
  title: string;
  /** What is missing, in the product's own words. */
  detail?: ReactNode;
  /** The control that fixes it. An empty state without a next step is a dead end. */
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ title, detail, action, className = "" }: EmptyProps) {
  return (
    <div className={`flex flex-col items-start gap-2 py-4 ${className}`}>
      <p className="text-ui font-semibold text-rh-text">{title}</p>
      {detail ? <p className="max-w-[60ch] text-xs leading-relaxed text-rh-muted">{detail}</p> : null}
      {action}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Relative time
// ---------------------------------------------------------------------------

/** Whole units below these thresholds, so "12 min ago" never becomes "743 s ago". */
export function formatAge(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "just now";
  const s = Math.floor(ms / 1000);
  if (s < 45) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d} d ago`;
  return `${Math.floor(d / 30)} mo ago`;
}

export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}

interface AgeStampProps {
  /** Epoch ms of the value being described. */
  ts: number | null;
  /** Data came from the cache rather than a request made now. */
  cached?: boolean;
  /** The cached copy is older than the freshness window. */
  stale?: boolean;
  /** A request is in flight; the existing value stays on screen behind this hint. */
  updating?: boolean;
  /** Show the absolute time in the title. */
  absolute?: number | string;
  className?: string;
}

/**
 * Says how old the number on screen is. Kept deliberately quiet: it is a footnote that prevents an
 * operator from reading a 40-minute-old verdict as current, and nothing more.
 */
export function AgeStamp({ ts, cached, stale, updating, absolute, className = "" }: AgeStampProps) {
  const now = useNow();
  if (ts === null) return null;
  const label = cached ? `Cached, ${formatAge(now - ts)}` : `Updated ${formatAge(now - ts)}`;
  const title =
    absolute !== undefined
      ? `${label}. ${typeof absolute === "number" ? new Date(absolute).toLocaleString() : absolute}`
      : label;
  return (
    <span
      className={`inline-flex items-center gap-1 text-micro tabular-nums ${
        stale ? "text-rh-cond" : "text-rh-faint"
      } ${className}`}
      title={title}
    >
      {updating ? (
        <RefreshCw className="rh-spin h-3 w-3" aria-hidden="true" />
      ) : stale ? (
        <span className="h-1.5 w-1.5 rounded-full bg-rh-cond" aria-hidden="true" />
      ) : null}
      {label}
      {updating ? <span className="text-rh-muted">refreshing</span> : null}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Label / value rows
// ---------------------------------------------------------------------------

interface FactProps {
  label: ReactNode;
  value: ReactNode;
  /** Text shown when the backend did not report a value. Never a made-up zero. */
  missing?: string;
  hint?: string;
  tone?: "default" | "go" | "cond" | "nogo" | "muted";
}

const TONE: Record<NonNullable<FactProps["tone"]>, string> = {
  default: "text-rh-text",
  go: "text-rh-go",
  cond: "text-rh-cond",
  nogo: "text-rh-nogo",
  muted: "text-rh-muted",
};

/** One measured fact: label on the left, value on the right, aligned in a column with its siblings. */
export function Fact({ label, value, missing = "not evaluated", hint, tone = "default" }: FactProps) {
  const empty = value === null || value === undefined || value === "";
  return (
    <div className="flex items-baseline justify-between gap-4 py-1" title={hint}>
      <dt className="min-w-0 truncate text-xs text-rh-muted">{label}</dt>
      <dd
        className={`shrink-0 text-right text-ui font-semibold tabular-nums ${empty ? "font-normal text-rh-faint" : TONE[tone]}`}
      >
        {empty ? missing : value}
      </dd>
    </div>
  );
}

/** A column of Facts. Uses <dl> so a screen reader reads label and value together. */
export function FactList({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <dl className={`flex flex-col divide-y divide-rh-line/60 ${className}`}>{children}</dl>;
}

// ---------------------------------------------------------------------------
// Section heading
// ---------------------------------------------------------------------------

/**
 * Heading for a dashboard band. No eyebrow or kicker above it: the heading carries the weight, and
 * the count that follows is real data (how many items the band holds), not decoration.
 */
export function BandHeading({
  children,
  count,
  trailing,
  id,
}: {
  children: ReactNode;
  count?: number;
  trailing?: ReactNode;
  id?: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 pb-1">
      <h2 id={id} className="text-sm font-semibold tracking-[-0.01em] text-rh-text">
        {children}
      </h2>
      {typeof count === "number" ? (
        <span className="rounded-sm bg-rh-raised px-1.5 py-px text-micro font-medium text-rh-muted tabular-nums">
          {count}
        </span>
      ) : null}
      {trailing ? <div className="ml-auto flex items-center gap-2">{trailing}</div> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reveal on first data
// ---------------------------------------------------------------------------

/**
 * One authored entrance: the panel content rises out of a blur the first time real data arrives,
 * and stays put afterwards. Re-revealing on every poll would be the "scattered effects" failure, so
 * the trigger latches.
 */
export function useReveal(active: boolean): string {
  const [revealed, setRevealed] = useState(false);
  const done = useRef(false);
  useEffect(() => {
    if (active && !done.current) {
      done.current = true;
      setRevealed(true);
    }
  }, [active]);
  return revealed ? "rh-rise" : "";
}
