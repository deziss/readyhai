"use client";

import { useEffect, useState } from "react";
import { Shield, Cpu, Globe, CheckCircle2, Terminal, ExternalLink, Activity } from "lucide-react";

interface HeaderProps {
  currentTarget: string;
}

export function Header({ currentTarget }: HeaderProps) {
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
    <header className="h-14 border-b border-[#1a2436] bg-[#090d16]/95 backdrop-blur-md px-6 flex items-center justify-between z-50 shrink-0">
      <div className="flex items-center gap-4">
        {/* Brand Shield & Title */}
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.25)]">
            <Shield className="w-4 h-4" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-tight text-white text-base">ReadyHai</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-semibold uppercase tracking-wider">
                Agent Studio 2026
              </span>
            </div>
            <span className="text-[10px] text-slate-400 font-medium">Autonomous QA & Production Gate</span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Target Host Badge */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-md bg-[#0e1524] border border-[#1e2a40] text-xs font-mono text-slate-300">
          <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-slate-500 font-normal">Target:</span>
          <span className="text-cyan-300 font-semibold truncate max-w-[240px]">{currentTarget}</span>
        </div>

        {/* Model Health Pill */}
        <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-[#0e1524] border border-[#1e2a40] text-xs">
          <span className="relative flex h-2 w-2">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${modelStatus.status === "online" ? "bg-emerald-400" : "bg-amber-400"}`}></span>
            <span className={`relative inline-flex rounded-full h-2 w-2 ${modelStatus.status === "online" ? "bg-emerald-500" : "bg-amber-500"}`}></span>
          </span>
          <span className="font-mono text-slate-300 text-[11px] font-medium">
            {modelStatus.model} · vllm
          </span>
          <span className="text-[10px] font-mono text-slate-500 pl-1 border-l border-slate-800">
            {modelStatus.latency_ms}ms
          </span>
        </div>

        {/* Console / Status Mode */}
        <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/40 border border-emerald-800/40 text-[11px] font-mono text-emerald-400 font-medium">
          <Activity className="w-3.5 h-3.5" />
          GATE READY
        </div>
      </div>
    </header>
  );
}
