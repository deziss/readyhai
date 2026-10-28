"use client";

import { useEffect, useState } from "react";
import { Shield, Globe, Activity, Bot, ShieldCheck, Cpu } from "lucide-react";

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
  const [modelStatus, setModelStatus] = useState<{
    model: string;
    status: string;
    latency_ms: number;
  }>({
    model: "qwen3.8-flash-next",
    status: "online",
    latency_ms: 18,
  });

  useEffect(() => {
    async function checkStatus() {
      try {
        const res = await fetch("/api/agent/status");
        if (res.ok) {
          const data = await res.json();
          setModelStatus(data);
        }
      } catch {
        // keep fallback online state
      }
    }
    checkStatus();
    const interval = setInterval(checkStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-14 border-b border-[#1a2436] bg-[#090d16]/95 backdrop-blur-md px-6 flex items-center justify-between z-50 shrink-0 gap-4">
      {/* Brand Shield & Title */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="w-8 h-8 rounded-lg bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.25)]">
          <Shield className="w-4 h-4" />
        </div>
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <span className="font-bold tracking-tight text-white text-base">ReadyHai</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-semibold uppercase tracking-wider">
              SaaS Suite
            </span>
          </div>
          <span className="text-[10px] text-slate-400 font-medium">Autonomous QA & Security Gate</span>
        </div>
      </div>

      {/* Central Hierarchical View Switcher (SaaS Standard) */}
      <nav className="flex items-center p-1 rounded-xl bg-[#0d1424] border border-[#1d2b44] shadow-inner gap-1">
        <button
          id="nav-tab-studio"
          onClick={() => onViewChange("studio")}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
            activeView === "studio"
              ? "bg-gradient-to-r from-cyan-950/90 to-[#12233f] text-cyan-300 border border-cyan-600/60 shadow-[0_0_10px_rgba(6,182,212,0.2)] font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#111b2e]"
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>Agent Studio</span>
        </button>



        <button
          id="nav-tab-scans-history"
          onClick={() => onViewChange("scans_history")}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
            activeView === "scans_history"
              ? "bg-gradient-to-r from-cyan-950/90 to-[#12233f] text-cyan-300 border border-cyan-600/60 shadow-[0_0_10px_rgba(6,182,212,0.2)] font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#111b2e]"
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          <span>Codebase & Security Scans</span>
          {scansCount > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-cyan-900/60 text-cyan-200 border border-cyan-700/40">
              {scansCount}
            </span>
          )}
        </button>

        <button
          id="nav-tab-network-lab"
          onClick={() => onViewChange("network_lab")}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
            activeView === "network_lab"
              ? "bg-gradient-to-r from-cyan-950/90 to-[#12233f] text-cyan-300 border border-cyan-600/60 shadow-[0_0_10px_rgba(6,182,212,0.2)] font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#111b2e]"
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>Regressive Network Lab</span>
        </button>
      </nav>

      {/* Right Indicators */}
      <div className="flex items-center gap-3 shrink-0">
        {/* Target Host Badge */}
        <div className="hidden xl:flex items-center gap-2 px-3 py-1 rounded-md bg-[#0e1524] border border-[#1e2a40] text-xs font-mono text-slate-300">
          <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-slate-500 font-normal">Target:</span>
          <span className="text-cyan-300 font-semibold truncate max-w-[200px]">{currentTarget}</span>
        </div>

        {/* Model Health Pill */}
        <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-[#0e1524] border border-[#1e2a40] text-xs">
          <span className="relative flex h-2 w-2">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${modelStatus.status === "online" ? "bg-emerald-400" : "bg-amber-400"}`}></span>
            <span className={`relative inline-flex rounded-full h-2 w-2 ${modelStatus.status === "online" ? "bg-emerald-500" : "bg-amber-500"}`}></span>
          </span>
          <span className="font-mono text-slate-300 text-[11px] font-medium hidden sm:inline">
            {modelStatus.model} · vllm
          </span>
          <span className="text-[10px] font-mono text-slate-500 pl-1 border-l border-slate-800">
            {modelStatus.latency_ms}ms
          </span>
        </div>

        {/* Gate Ready Pill */}
        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/40 border border-emerald-800/40 text-[11px] font-mono text-emerald-400 font-medium">
          <Activity className="w-3.5 h-3.5" />
          PRODUCTION GATE
        </div>
      </div>
    </header>
  );
}
