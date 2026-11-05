"use client";

import { useEffect, useState } from "react";
import { Activity, Cpu, Globe, ShieldCheck } from "lucide-react";
import { apiRequest, useApiTokenVersion } from "@/lib/api";
import { ApiTokenSettings } from "./ApiTokenSettings";

export type SaaSViewMode = "studio" | "agent_history" | "scans_history" | "network_lab";

interface HeaderProps {
  currentTarget: string;
  activeView: SaaSViewMode;
  onViewChange: (view: SaaSViewMode) => void;
  scansCount?: number;
  agentRunsCount?: number;
}

const NAV_ITEMS: { id: string; view: SaaSViewMode; label: string; icon: typeof Cpu }[] = [
  { id: "nav-tab-studio", view: "studio", label: "Agent studio", icon: Cpu },
  { id: "nav-tab-scans-history", view: "scans_history", label: "Scans", icon: ShieldCheck },
  { id: "nav-tab-network-lab", view: "network_lab", label: "Network lab", icon: Activity },
];

export function Header({
  currentTarget,
  activeView,
  onViewChange,
  scansCount = 0,
}: HeaderProps) {
  // null = status unknown (never reached the backend, or the last probe failed).
  const [modelStatus, setModelStatus] = useState<{
    model?: string;
    provider?: string;
    status?: string;
    latency_ms?: number;
  } | null>(null);
  const tokenVersion = useApiTokenVersion();

  useEffect(() => {
    let cancelled = false;
    async function checkStatus() {
      const r = await apiRequest<{ model?: string; provider?: string; status?: string; latency_ms?: number }>(
        "/api/agent/status",
        { label: "Model status" }
      );
      if (cancelled) return;
      setModelStatus(r.ok ? r.data : null);
    }
    checkStatus();
    const interval = setInterval(checkStatus, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [tokenVersion]);

  const isOnline = modelStatus?.status === "online";
  const statusKnown = !!modelStatus?.status;
  const dotClass = !statusKnown ? "bg-rh-muted" : isOnline ? "bg-rh-go" : "bg-rh-cond";
  const latency = typeof modelStatus?.latency_ms === "number" ? ` · ${modelStatus.latency_ms} ms` : "";

  return (
    <header className="z-50 flex h-14 shrink-0 items-center justify-between gap-4 border-b border-rh-line bg-rh-surface px-4">
      {/* Brand */}
      <div className="flex shrink-0 items-center gap-2.5">
        <span
          className="flex h-8 w-8 items-center justify-center rounded-sm border border-rh-line bg-rh-raised text-rh-primary"
          aria-hidden="true"
        >
          <ShieldCheck className="h-4 w-4" />
        </span>
        <div className="leading-tight">
          <span className="block text-base font-semibold text-rh-text">ReadyHai</span>
          <span className="hidden text-xs text-rh-muted sm:block">QA and release readiness</span>
        </div>
      </div>

      {/* Views */}
      <nav aria-label="Views" className="flex h-full min-w-0 items-stretch gap-1">
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
      </nav>

      {/* Context and settings */}
      <div className="flex shrink-0 items-center gap-2">
        <div className="hidden max-w-[260px] items-center gap-2 rounded-sm border border-rh-line bg-rh-raised px-2.5 py-1 text-xs xl:flex">
          <Globe className="h-3.5 w-3.5 shrink-0 text-rh-muted" aria-hidden="true" />
          <span className="text-rh-muted">Target</span>
          <span className="truncate font-mono text-rh-text" title={currentTarget}>
            {currentTarget || "not set"}
          </span>
        </div>

        <div className="hidden items-center gap-2 rounded-sm border border-rh-line bg-rh-raised px-2.5 py-1 text-xs sm:flex">
          <span className={`h-2 w-2 shrink-0 rounded-full ${dotClass}`} aria-hidden="true" />
          <span className="text-rh-text">
            {statusKnown ? `Model ${modelStatus?.status}${latency}` : "Model status unknown"}
          </span>
          {modelStatus?.model && (
            <span className="hidden border-l border-rh-line pl-2 font-mono text-rh-muted lg:inline">
              {modelStatus.model}
              {modelStatus.provider ? ` · ${modelStatus.provider}` : ""}
            </span>
          )}
        </div>

        <ApiTokenSettings />
      </div>
    </header>
  );
}
