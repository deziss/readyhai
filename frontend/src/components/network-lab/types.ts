export type NetworkLabTab = "regress" | "deep_audit" | "multi_region" | "pr_gate";

export interface NetworkLabViewProps {
  initialTarget?: string;
  /** `failed` is true when the run ended in an error rather than a result. */
  onRunningChange?: (running: boolean, detail: string, failed?: boolean) => void;
  /** Score of the currently loaded agent run's evidence ledger, or null when there is no real one. */
  ledgerScore?: number | null;
}

// Badge URLs are origin-relative and go through the Next.js /api proxy.
export const badgeBase = () => (typeof window === "undefined" ? "" : window.location.origin);

export const FOCUS = "focus-visible:outline-2 focus-visible:outline-rh-primary";
export const BTN_PRIMARY = `inline-flex items-center justify-center gap-2 px-4 py-2 rounded-[6px] bg-rh-primary hover:bg-rh-primary-hover text-rh-bg text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS}`;
export const BTN_SECONDARY = `inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS}`;
export const INPUT_CLS =
  "bg-rh-bg border border-rh-line rounded-[6px] text-xs text-rh-text placeholder:text-rh-muted focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
export const PANEL = "p-4 rounded-[10px] bg-rh-surface border border-rh-line";
export const KPI_CARD = "p-4 rounded-[10px] bg-rh-surface border border-rh-line flex flex-col justify-between";
export const PILLAR_TITLE = "text-sm font-semibold text-rh-text flex items-center gap-2";
export const KV_ROW = "flex justify-between gap-3";
export const CHIP = "text-xs font-semibold px-2 py-0.5 rounded-[6px]";

/** "CRITICAL" -> "Critical". Backend enum values are shown in sentence case. */
export const sentence = (s: string | null | undefined) =>
  s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "";

export function tabClass(active: boolean) {
  return `flex items-center gap-2 px-3.5 py-1.5 rounded-[6px] text-xs font-medium transition-colors cursor-pointer ${FOCUS} ${
    active ? "bg-rh-primary/15 text-rh-primary font-semibold" : "text-rh-muted hover:text-rh-text hover:bg-rh-raised"
  }`;
}
