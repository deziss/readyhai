"use client";

import { useEffect, useState } from "react";
import { Shield, Globe, Activity, ShieldCheck, Cpu } from "lucide-react";
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

export function Header({
  currentTarget,
  activeView,
  onViewChange,
  scansCount = 0,
  agentRunsCount = 0,
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
  const dotClass = !statusKnown ? "bg-slate-500" : isOnline ? "bg-emerald-500" : "bg-amber-500";
  const pingClass = !statusKnown ? "bg-slate-400" : isOnline ? "bg-emerald-400" : "bg-amber-400";

  return (
    <header className="h-14 border-b border-[#152033] bg-[#070b16]/90 backdrop-blur-xl px-5 flex items-center justify-between z-50 shrink-0 gap-4 shadow-[0_4px_24px_rgba(0,0,0,0.6)]">
      {/* Brand Shield & Title */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-950/80 via-[#0a1829] to-[#041221] border border-cyan-500/50 flex items-center justify-center text-cyan-400 shadow-[0_0_16px_rgba(6,182,212,0.3)] transition-transform hover:scale-105">
          <Shield className="w-4 h-4 text-cyan-300 drop-shadow-[0_0_6px_rgba(34,211,238,0.6)]" />
        </div>
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <span className="font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-cyan-200 text-base">
              ReadyHai
            </span>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-500/40 text-cyan-300 font-bold uppercase tracking-wider shadow-[0_0_8px_rgba(6,182,212,0.2)]">
              Super Agent Suite
            </span>
          </div>
          <span className="text-[10px] text-slate-400 font-medium tracking-tight">Autonomous QA & Formal Security Gate</span>
        </div>
      </div>

      {/* Central Hierarchical View Switcher */}
      <nav className="flex items-center p-1 rounded-xl bg-[#090f1d]/90 border border-[#17263d] shadow-[inset_0_1px_3px_rgba(0,0,0,0.6)] gap-1">
        <button
          id="nav-tab-studio"
          onClick={() => onViewChange("studio")}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all duration-200 cursor-pointer ${
            activeView === "studio"
              ? "bg-gradient-to-r from-cyan-950 via-[#0e213b] to-[#122849] text-cyan-200 border border-cyan-500/60 shadow-[0_0_14px_rgba(6,182,212,0.25)] font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#0f172a]/70"
          }`}
        >
          <Cpu className={`w-3.5 h-3.5 ${activeView === "studio" ? "text-cyan-400 animate-pulse" : "text-slate-400"}`} />
          <span>Agent Studio</span>
        </button>

        <button
          id="nav-tab-scans-history"
          onClick={() => onViewChange("scans_history")}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all duration-200 cursor-pointer ${
            activeView === "scans_history"
              ? "bg-gradient-to-r from-cyan-950 via-[#0e213b] to-[#122849] text-cyan-200 border border-cyan-500/60 shadow-[0_0_14px_rgba(6,182,212,0.25)] font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#0f172a]/70"
          }`}
        >
          <ShieldCheck className={`w-3.5 h-3.5 ${activeView === "scans_history" ? "text-cyan-400" : "text-slate-400"}`} />
          <span>Codebase & Security Scans</span>
          {scansCount > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-cyan-900/70 text-cyan-200 border border-cyan-700/50 font-bold">
              {scansCount}
            </span>
          )}
        </button>

        <button
          id="nav-tab-network-lab"
          onClick={() => onViewChange("network_lab")}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all duration-200 cursor-pointer ${
            activeView === "network_lab"
              ? "bg-gradient-to-r from-cyan-950 via-[#0e213b] to-[#122849] text-cyan-200 border border-cyan-500/60 shadow-[0_0_14px_rgba(6,182,212,0.25)] font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#0f172a]/70"
          }`}
        >
          <Activity className={`w-3.5 h-3.5 ${activeView === "network_lab" ? "text-cyan-400" : "text-slate-400"}`} />
          <span>Regressive Network Lab</span>
        </button>
      </nav>

      {/* Right Indicators */}
      <div className="flex items-center gap-2.5 shrink-0">
        {/* Target Host Badge */}
        <div className="hidden xl:flex items-center gap-2 px-3 py-1 rounded-lg bg-[#0a1120] border border-[#1b2b46] text-xs font-mono text-slate-300 shadow-sm">
          <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-slate-500 font-normal">Target:</span>
          <span className="text-cyan-300 font-semibold truncate max-w-[200px]">{currentTarget}</span>
        </div>

        {/* Model Health Pill */}
        <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-[#0a1120] border border-[#1b2b46] text-xs shadow-sm">
          <span className="relative flex h-2 w-2">
            {isOnline && <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${pingClass}`}></span>}
            <span className={`relative inline-flex rounded-full h-2 w-2 ${dotClass}`}></span>
          </span>
          <span className="font-mono text-slate-300 text-[11px] font-medium hidden sm:inline">
            {modelStatus?.model
              ? `${modelStatus.model}${modelStatus.provider ? ` · ${modelStatus.provider}` : ""}`
              : "model status unknown"}
          </span>
          <span className="text-[10px] font-mono text-slate-400 pl-1.5 border-l border-slate-800">
            {statusKnown ? `${modelStatus?.status}${typeof modelStatus?.latency_ms === "number" ? ` · ${modelStatus.latency_ms}ms` : ""}` : "unknown"}
          </span>
        </div>

        {/* API token settings */}
        <ApiTokenSettings />

        {/* Section label */}
        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#0a1120] border border-cyan-900/40 text-[11px] font-mono text-cyan-300/80 font-semibold tracking-wider shadow-sm">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          PRODUCTION GATE
        </div>
      </div>
    </header>
  );
}
