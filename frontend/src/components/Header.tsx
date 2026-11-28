"use client";

import { LayoutDashboard } from "lucide-react";
import { Activity, BookOpen, Bug, Cpu, Globe, Settings, ShieldCheck } from "lucide-react";
import { useCachedApi } from "@/lib/cache";
import { pollIntervalMs, usePrefs } from "@/lib/prefs";
import { ApiTokenSettings } from "./ApiTokenSettings";
import { QuickToggles } from "./QuickToggles";

export type SaaSViewMode =
  | "dashboard"
  | "studio"
  | "agent_history"
  | "scans_history"
  | "network_lab"
  | "vulns"
  | "settings";

interface HeaderProps {
  currentTarget: string;
  activeView: SaaSViewMode;
  onViewChange: (view: SaaSViewMode) => void;
  scansCount?: number;
}

const NAV_ITEMS: { id: string; view: SaaSViewMode; label: string; icon: typeof Cpu }[] = [
  { id: "nav-tab-dashboard", view: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "nav-tab-studio", view: "studio", label: "Agent studio", icon: Cpu },
  { id: "nav-tab-scans-history", view: "scans_history", label: "Scans", icon: ShieldCheck },
  { id: "nav-tab-network-lab", view: "network_lab", label: "Network lab", icon: Activity },
  { id: "nav-tab-vulns", view: "vulns", label: "Vulns", icon: Bug },
  { id: "nav-tab-settings", view: "settings", label: "Settings", icon: Settings },
];

export function Header({
  currentTarget,
  activeView,
  onViewChange,
  scansCount = 0,
}: HeaderProps) {
  const prefs = usePrefs();
  // null = status unknown (never reached the backend, or the last probe failed). The cache means a
  // remount or a view switch paints the last known status instead of flashing "unknown".
  const status = useCachedApi<{ model?: string; provider?: string; status?: string; latency_ms?: number }>(
    "/api/agent/status",
    { label: "Model status", pollMs: pollIntervalMs(prefs) ?? 15000 }
  );
  const modelStatus = status.data;

  const isOnline = modelStatus?.status === "online";
  const statusKnown = !!modelStatus?.status;
  const dotClass = !statusKnown ? "bg-rh-muted" : isOnline ? "bg-rh-go" : "bg-rh-cond";
  const latency = typeof modelStatus?.latency_ms === "number" ? ` · ${modelStatus.latency_ms} ms` : "";

  return (
    <header className="z-50 flex h-14 shrink-0 items-center justify-between gap-4 border-b border-rh-line bg-rh-surface px-4">
      {/* Brand */}
      <div className="flex shrink-0 items-center gap-2.5">
        <span
          className="flex h-8 w-8 items-center justify-center overflow-hidden rounded-md border border-rh-line bg-rh-raised"
          aria-hidden="true"
        >
          <img src="/icon.svg" alt="ReadyHai Logo" className="h-7 w-7 object-contain" />
        </span>
        <div className="leading-tight">
          <span className="block text-base font-semibold text-rh-text">ReadyHai</span>
          <span className="hidden text-xs text-rh-muted sm:block">QA and release readiness</span>
        </div>
      </div>

      {/* Views */}
      {/* The nav takes the remaining space and scrolls horizontally when the viewport is too
          narrow for every tab, so it can never spill over the status cluster at its side. */}
      <nav
        aria-label="Views"
        className="flex h-full min-w-0 flex-1 items-stretch gap-1 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      >
        {NAV_ITEMS.map(({ id, view, label, icon: Icon }) => {
          const active = activeView === view;
          return (
            <button
              key={view}
              id={id}
              type="button"
              onClick={() => onViewChange(view)}
              aria-current={active ? "page" : undefined}
              title={label}
              className={`inline-flex cursor-pointer items-center gap-2 border-b-2 px-3 text-ui font-medium [--rh-focus-offset:-3px] ${
                active
                  ? "border-rh-primary text-rh-text"
                  : "border-transparent text-rh-muted hover:bg-rh-raised hover:text-rh-text"
              }`}
            >
              <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span className="max-md:sr-only">{label}</span>
              {view === "scans_history" && scansCount > 0 && (
                <span className="rounded-sm bg-rh-primary/15 px-1.5 text-xs font-medium tabular-nums text-rh-primary">
                  {scansCount}
                </span>
              )}
            </button>
          );
        })}
        {/* Docs is a real route, not a studio view: plain anchor, outside the tab logic. */}
        <a
          id="nav-link-docs"
          href="/docs"
          title="Documentation"
          aria-label="Documentation"
          className="inline-flex cursor-pointer items-center gap-2 self-center border border-rh-line px-2.5 py-1 text-ui font-medium text-rh-muted transition-colors hover:bg-rh-raised hover:text-rh-text [--rh-focus-offset:-3px]"
        >
          <BookOpen className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span className="max-md:sr-only">Docs</span>
        </a>
      </nav>

      {/* Context and settings */}
      <div className="flex shrink-0 items-center gap-2">
        <div className="hidden max-w-[260px] items-center gap-2 rounded-sm border border-rh-line bg-rh-raised px-2.5 py-1 text-xs 2xl:flex">
          <Globe className="h-3.5 w-3.5 shrink-0 text-rh-muted" aria-hidden="true" />
          <span className="text-rh-muted">Target</span>
          <span className="truncate font-mono text-rh-text" title={currentTarget}>
            {currentTarget || "not set"}
          </span>
        </div>

        <div
          className="hidden items-center gap-2 rounded-sm border border-rh-line bg-rh-raised px-2.5 py-1 text-xs md:flex"
          title={`Model status: ${statusKnown ? modelStatus?.status : "unknown"}`}
        >
          <span className={`h-2 w-2 shrink-0 rounded-full ${dotClass}`} aria-hidden="true" />
          {/* Below lg only the dot survives: at tablet width the nav needs the room more than the
              latency readout does. */}
          <span className="hidden text-rh-text lg:inline">
            {statusKnown ? `Model ${modelStatus?.status}${latency}` : "Model status unknown"}
          </span>
          {modelStatus?.model && (
            <span className="hidden border-l border-rh-line pl-2 font-mono text-rh-muted lg:inline">
              {modelStatus.model}
              {modelStatus.provider ? ` · ${modelStatus.provider}` : ""}
            </span>
          )}
        </div>

        <QuickToggles />
        <ApiTokenSettings />
      </div>
    </header>
  );
}
