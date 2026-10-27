"use client";

import { useEffect, useState } from "react";
import { Shield, Cpu, Globe, CheckCircle2, AlertCircle } from "lucide-react";

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
    <header className="h-14 border-b border-slate-800/80 bg-[#0c1220]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-bold tracking-tight text-white text-lg">ReadyHai</span>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-800/60 text-cyan-300 font-medium">
          AGENT STUDIO 2026
        </span>
      </div>

      <div className="flex items-center gap-3">
        {/* Active Target Indicator */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
          <Globe className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-500">Target:</span>
          <span className="text-cyan-300 font-semibold truncate max-w-[200px]">{currentTarget}</span>
        </div>

        {/* Model Status Pill */}
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs">
          <span className="relative flex h-2 w-2">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${modelStatus.status === "online" ? "bg-emerald-400" : "bg-amber-400"}`}></span>
            <span className={`relative inline-flex rounded-full h-2 w-2 ${modelStatus.status === "online" ? "bg-emerald-500" : "bg-amber-500"}`}></span>
          </span>
          <span className="font-mono text-slate-300 text-[11px]">
            {modelStatus.model} · vllm · {modelStatus.latency_ms}ms
          </span>
        </div>
      </div>
    </header>
  );
}
