"use client";

import { useState } from "react";
import { Zap, ShieldAlert, FileCode, Search, Loader2, Sparkles, Play, Globe, Check } from "lucide-react";
import type { DiscoveredTarget } from "@/types/agent";

interface ComposerProps {
  target: string;
  setTarget: (url: string) => void;
  specUrl: string;
  setSpecUrl: (url: string) => void;
  directives: string;
  setDirectives: (d: string) => void;
  profile: string;
  setProfile: (p: string) => void;
  maxSteps: number;
  setMaxSteps: (n: number) => void;
  onDiscover: () => Promise<void>;
  isDiscovering: boolean;
  discoveredData: DiscoveredTarget | null;
  onLaunch: () => Promise<void>;
  isRunning: boolean;
}

export function Composer({
  target,
  setTarget,
  specUrl,
  setSpecUrl,
  directives,
  setDirectives,
  profile,
  setProfile,
  maxSteps,
  setMaxSteps,
  onDiscover,
  isDiscovering,
  discoveredData,
  onLaunch,
  isRunning,
}: ComposerProps) {
  const [activeMode, setActiveMode] = useState<"autonomous" | "adversarial" | "contract">("autonomous");

  function handleModeChange(mode: "autonomous" | "adversarial" | "contract") {
    setActiveMode(mode);
    if (mode === "adversarial") {
      setDirectives("Focus heavily on authorization bypass, BOLA, IDOR, token forgery, and prompt injection canaries.");
    } else if (mode === "contract") {
      setDirectives("Focus on OpenAPI contract compliance, boundary values, negative JSON parsing, and HTTP status codes.");
    } else {
      setDirectives("");
    }
  }

  function appendDirective(text: string) {
    setDirectives(directives ? `${directives}; ${text}` : text);
  }

  return (
    <div className="bg-[#0b101a] border border-[#1a2436] rounded-xl p-4 shadow-xl flex flex-col gap-3.5">
      {/* Title Bar */}
      <div className="flex items-center justify-between pb-2 border-b border-[#162033]">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <Sparkles className="w-3 h-3" />
          </div>
          <span className="text-xs font-bold tracking-wider uppercase text-slate-200">
            Agent Command Composer
          </span>
        </div>
        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/50 px-2 py-0.5 rounded font-semibold">
          NuHire Reference Mode
        </span>
      </div>

      {/* Segmented Mode Switcher */}
      <div className="grid grid-cols-3 gap-1 p-1 bg-[#07090e] rounded-lg border border-[#162033]">
        <button
          type="button"
          onClick={() => handleModeChange("autonomous")}
          className={`py-1.5 px-2 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 cursor-pointer ${
            activeMode === "autonomous"
              ? "bg-[#111827] text-cyan-300 border border-cyan-500/50 shadow-sm font-semibold"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Zap className="w-3.5 h-3.5 text-cyan-400" />
          Autonomous QA
        </button>
        <button
          type="button"
          onClick={() => handleModeChange("adversarial")}
          className={`py-1.5 px-2 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 cursor-pointer ${
            activeMode === "adversarial"
              ? "bg-[#111827] text-rose-300 border border-rose-500/50 shadow-sm font-semibold"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          Adversarial & Auth
        </button>
        <button
          type="button"
          onClick={() => handleModeChange("contract")}
          className={`py-1.5 px-2 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 cursor-pointer ${
            activeMode === "contract"
              ? "bg-[#111827] text-emerald-300 border border-emerald-500/50 shadow-sm font-semibold"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <FileCode className="w-3.5 h-3.5 text-emerald-400" />
          Contract & Spec
        </button>
      </div>

      {/* Target URL with Architecture Badge */}
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center justify-between">
          <label className="text-[11px] font-mono uppercase font-bold text-slate-400">
            Target Host or URL
          </label>
          {discoveredData && (
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold tracking-tight ${
                discoveredData.is_spa
                  ? "bg-purple-950/80 text-purple-300 border border-purple-700/60"
                  : "bg-emerald-950/80 text-emerald-300 border border-emerald-700/60"
              }`}
            >
              {discoveredData.is_spa ? "SPA DETECTED (Next.js/React)" : "REST API"} ({discoveredData.count} routes)
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://api.example.com or http://localhost:3000"
            className="flex-1 bg-[#07090e] border border-[#1e2a40] rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
          />
          <button
            type="button"
            onClick={onDiscover}
            disabled={isDiscovering || isRunning}
            className="px-3 py-2 bg-[#111827] hover:bg-[#162033] border border-[#1e2a40] text-slate-200 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
          >
            {isDiscovering ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                Probing...
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5 text-cyan-400" />
                Discover
              </>
            )}
          </button>
        </div>

        {/* Quick Domain Triggers */}
        <div className="flex flex-wrap gap-1.5">
          {["https://api.example.com", "http://localhost:3000", "http://127.0.0.1:8080"].map((url) => (
            <button
              key={url}
              type="button"
              onClick={() => setTarget(url)}
              className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#07090e] hover:bg-[#111827] border border-[#1a2436] text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
            >
              {url}
            </button>
          ))}
        </div>
      </div>

      {/* OpenAPI Spec URL */}
      <div className="flex flex-col gap-1.5">
        <label className="text-[11px] font-mono uppercase font-bold text-slate-400">
          OpenAPI Specification URL <span className="text-slate-500 font-normal lowercase">(optional)</span>
        </label>
        <input
          type="text"
          value={specUrl}
          onChange={(e) => setSpecUrl(e.target.value)}
          placeholder="/openapi.json or leave blank for auto-discovery"
          className="bg-[#07090e] border border-[#1e2a40] rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
        />
      </div>

      {/* Directives & Suggestion Chips */}
      <div className="flex flex-col gap-1.5">
        <label className="text-[11px] font-mono uppercase font-bold text-slate-400">
          Agent Directives & Focus
        </label>
        <textarea
          rows={3}
          value={directives}
          onChange={(e) => setDirectives(e.target.value)}
          placeholder="e.g. Focus on unauthenticated session access, IDOR tenant boundaries, and prompt injection canaries"
          className="bg-[#07090e] border border-[#1e2a40] rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors resize-none leading-relaxed"
        />
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => appendDirective("Check unauthenticated access to /api/auth/session")}
            className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-800/50 text-cyan-300 transition-colors cursor-pointer"
          >
            + Auth Session Check
          </button>
          <button
            type="button"
            onClick={() => appendDirective("Probe 100KB boundary size on chat input")}
            className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-800/50 text-cyan-300 transition-colors cursor-pointer"
          >
            + 100KB Boundary
          </button>
          <button
            type="button"
            onClick={() => appendDirective("Inject prompt override canary on chat")}
            className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-800/50 text-cyan-300 transition-colors cursor-pointer"
          >
            + Prompt Injection
          </button>
        </div>
      </div>

      {/* Profile & Max Steps */}
      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <label className="text-[11px] font-mono uppercase font-bold text-slate-400">Profile</label>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            className="bg-[#07090e] border border-[#1e2a40] rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="standard">Standard (Multi-Agent)</option>
            <option value="quick">Quick (Contract/Smoke)</option>
            <option value="deep">Deep (Chaos & Adversarial)</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[11px] font-mono uppercase font-bold text-slate-400">Max Steps</label>
          <input
            type="number"
            min={1}
            max={20}
            value={maxSteps}
            onChange={(e) => setMaxSteps(Number(e.target.value))}
            className="bg-[#07090e] border border-[#1e2a40] rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Launch Action */}
      <button
        type="button"
        onClick={onLaunch}
        disabled={isRunning}
        className="w-full mt-1 py-2.5 px-4 bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:via-blue-500 hover:to-indigo-500 text-white rounded-lg font-bold text-xs tracking-wider uppercase flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(6,182,212,0.35)] transition-all disabled:opacity-50 cursor-pointer active:scale-[0.99]"
      >
        {isRunning ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Synthesizing & Executing Scenarios...
          </>
        ) : (
          <>
            <Play className="w-3.5 h-3.5 fill-white" />
            Launch Multi-Agent Swarm
          </>
        )}
      </button>
    </div>
  );
}
