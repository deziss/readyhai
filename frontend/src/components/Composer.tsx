"use client";

import { useState } from "react";
import { Zap, ShieldAlert, FileText, Search, Loader2, Sparkles, Play } from "lucide-react";
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
    <div className="bg-[#0e1526] border border-slate-800/80 rounded-xl p-5 shadow-xl flex flex-col gap-4">
      {/* Title */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-cyan-400 font-bold text-sm tracking-wide uppercase flex items-center gap-1.5">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            Agent Command Composer
          </span>
        </div>
        <span className="text-[11px] font-mono text-cyan-400/80 bg-cyan-950/40 border border-cyan-800/40 px-2 py-0.5 rounded">
          NuHire Reference Mode
        </span>
      </div>

      {/* Mode Switcher */}
      <div className="grid grid-cols-3 gap-1.5 p-1 bg-slate-900/90 rounded-lg border border-slate-800">
        <button
          type="button"
          onClick={() => handleModeChange("autonomous")}
          className={`py-1.5 px-2 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 ${
            activeMode === "autonomous"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Zap className="w-3.5 h-3.5" />
          Autonomous QA
        </button>
        <button
          type="button"
          onClick={() => handleModeChange("adversarial")}
          className={`py-1.5 px-2 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 ${
            activeMode === "adversarial"
              ? "bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          Adversarial & Auth
        </button>
        <button
          type="button"
          onClick={() => handleModeChange("contract")}
          className={`py-1.5 px-2 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 ${
            activeMode === "contract"
              ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          Contract & Spec
        </button>
      </div>

      {/* Target URL */}
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold text-slate-300">Target URL or Host</label>
          {discoveredData && (
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                discoveredData.is_spa
                  ? "bg-purple-950/80 text-purple-300 border border-purple-700/60"
                  : "bg-emerald-950/80 text-emerald-300 border border-emerald-700/60"
              }`}
            >
              {discoveredData.is_spa ? "SPA DETECTED (Next.js/React)" : "REST API DETECTED"} ({discoveredData.count} routes)
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://agent-prod.nuhire.in or http://localhost:3000"
            className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
          />
          <button
            type="button"
            onClick={onDiscover}
            disabled={isDiscovering || isRunning}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
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

        {/* Quick Target Chips */}
        <div className="flex flex-wrap gap-1.5 mt-1">
          {["https://agent-prod.nuhire.in", "http://localhost:3000", "http://127.0.0.1:8080"].map((url) => (
            <button
              key={url}
              type="button"
              onClick={() => setTarget(url)}
              className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-cyan-300 transition-colors"
            >
              {url}
            </button>
          ))}
        </div>
      </div>

      {/* OpenAPI Spec URL */}
      <div className="flex flex-col gap-1.5">
        <label className="text-xs font-semibold text-slate-300">
          OpenAPI Specification URL <span className="text-slate-500 font-normal">(Optional)</span>
        </label>
        <input
          type="text"
          value={specUrl}
          onChange={(e) => setSpecUrl(e.target.value)}
          placeholder="e.g. /openapi.json (leave blank for auto-discovery)"
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
        />
      </div>

      {/* Directives & Focus */}
      <div className="flex flex-col gap-1.5">
        <label className="text-xs font-semibold text-slate-300">Agent Directives & Focus</label>
        <textarea
          rows={3}
          value={directives}
          onChange={(e) => setDirectives(e.target.value)}
          placeholder="e.g. Focus on unauthenticated session access, boundary limits, and prompt injection canaries"
          className="bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors resize-none"
        />
        <div className="flex flex-wrap gap-1.5 mt-1">
          <button
            type="button"
            onClick={() => appendDirective("Check unauthenticated access to /api/auth/session")}
            className="text-[11px] px-2 py-0.5 rounded bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-800/40 text-cyan-300 transition-colors"
          >
            + Auth Session Check
          </button>
          <button
            type="button"
            onClick={() => appendDirective("Probe 100KB boundary size on chat input")}
            className="text-[11px] px-2 py-0.5 rounded bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-800/40 text-cyan-300 transition-colors"
          >
            + 100KB Boundary
          </button>
          <button
            type="button"
            onClick={() => appendDirective("Inject prompt override canary on chat")}
            className="text-[11px] px-2 py-0.5 rounded bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-800/40 text-cyan-300 transition-colors"
          >
            + Prompt Injection
          </button>
        </div>
      </div>

      {/* Profile & Max Steps */}
      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-slate-300">Execution Profile</label>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="standard">Standard (Multi-Agent)</option>
            <option value="quick">Quick (Contract/Smoke)</option>
            <option value="deep">Deep (Chaos & Adversarial)</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-slate-300">Max Steps</label>
          <input
            type="number"
            min={1}
            max={20}
            value={maxSteps}
            onChange={(e) => setMaxSteps(Number(e.target.value))}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Launch Action */}
      <button
        type="button"
        onClick={onLaunch}
        disabled={isRunning}
        className="w-full mt-2 py-2.5 px-4 bg-gradient-to-r from-blue-600 via-cyan-600 to-teal-500 hover:from-blue-500 hover:via-cyan-500 hover:to-teal-400 text-white rounded-lg font-bold text-xs tracking-wide uppercase flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(6,182,212,0.3)] transition-all disabled:opacity-50"
      >
        {isRunning ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Synthesizing & Executing Scenarios...
          </>
        ) : (
          <>
            <Play className="w-4 h-4 fill-white" />
            Launch Multi-Agent Swarm
          </>
        )}
      </button>
    </div>
  );
}
