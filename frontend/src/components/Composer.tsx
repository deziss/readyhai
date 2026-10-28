"use client";

import { useState } from "react";
import {
  Zap,
  ShieldAlert,
  FileCode,
  Search,
  Loader2,
  Sparkles,
  Play,
  Globe,
  BrainCircuit,
  Sliders,
} from "lucide-react";
import type { DiscoveredTarget, ModelTier } from "@/types/agent";

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
  onCrawl?: () => Promise<void>;
  isCrawling?: boolean;
  discoveredData: DiscoveredTarget | null;
  onLaunch: () => Promise<void>;
  isRunning: boolean;
  thinking: boolean;
  setThinking: (t: boolean) => void;
  modelTier: ModelTier;
  setModelTier: (tier: ModelTier) => void;
  thinkingBudget: number;
  setThinkingBudget: (b: number) => void;
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
  onCrawl,
  isCrawling,
  discoveredData,
  onLaunch,
  isRunning,
  thinking,
  setThinking,
  modelTier,
  setModelTier,
  thinkingBudget,
  setThinkingBudget,
}: ComposerProps) {
  const [activeMode, setActiveMode] = useState<"autonomous" | "adversarial" | "contract">("autonomous");

  function handleModeChange(mode: "autonomous" | "adversarial" | "contract") {
    setActiveMode(mode);
    if (mode === "adversarial") {
      setDirectives("Focus heavily on authorization bypass, BOLA, IDOR, token forgery, and prompt injection canaries.");
    } else if (mode === "contract") {
      setDirectives("Focus on OpenAPI contract compliance, boundary values, negative JSON parsing, and HTTP status codes.");
    } else {
      setDirectives("Strict QA and verify resilience, contracts, and authz");
    }
  }

  function appendDirective(hint: string) {
    if (!directives.includes(hint)) {
      setDirectives(directives ? `${directives}; ${hint}` : hint);
    }
  }

  return (
    <div className="bg-[#0b101a] border border-[#1a2436] rounded-xl p-4 shadow-xl flex flex-col gap-4">
      {/* Mode Selector Header */}
      <div className="grid grid-cols-3 gap-1 p-1 bg-[#06080e] rounded-lg border border-[#162033]">
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
                discoveredData.app_architecture?.includes("PHP")
                  ? "bg-indigo-950/90 text-indigo-300 border border-indigo-600/80 shadow-[0_0_10px_rgba(99,102,241,0.2)]"
                  : discoveredData.is_spa
                  ? "bg-purple-950/80 text-purple-300 border border-purple-700/60"
                  : "bg-emerald-950/80 text-emerald-300 border border-emerald-700/60"
              }`}
            >
              {discoveredData.app_architecture || (discoveredData.is_spa ? "SPA (Next.js/React)" : "REST API")} ({discoveredData.count} routes)
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <input
            id="composer-target-url"
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://api.example.com or http://localhost:3000"
            className="flex-1 bg-[#07090e] border border-[#1e2a40] rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
          />
          <button
            id="composer-btn-discover"
            type="button"
            onClick={onDiscover}
            disabled={isDiscovering || isCrawling || isRunning}
            title="Fast inspection & architecture discovery"
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
          <button
            id="composer-btn-crawl"
            type="button"
            onClick={onCrawl}
            disabled={isCrawling || isDiscovering || isRunning}
            title="Deep crawl target website to map all real internal links and forms"
            className="px-3 py-2 bg-[#19152e] hover:bg-[#251f45] border border-purple-700/60 text-purple-200 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer shadow-[0_0_12px_rgba(168,85,247,0.15)]"
          >
            {isCrawling ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-purple-400" />
                Crawling...
              </>
            ) : (
              <>
                <Globe className="w-3.5 h-3.5 text-purple-400" />
                Crawl Site
              </>
            )}
          </button>
        </div>

        {/* Quick Domain Triggers */}
        <div className="flex flex-wrap gap-1.5">
          {["https://myvapi.com", "https://api.example.com", "http://localhost:3000", "http://127.0.0.1:8080"].map((url) => (
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
          rows={2}
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

      {/* NEW: Agent Thinking & Intelligence Tier Section */}
      <div className="p-3 bg-[#080d19] rounded-xl border border-[#1a263d] space-y-3 shadow-inner">
        {/* Thinking Toggle */}
        <div className="flex items-center justify-between pb-2 border-b border-[#141f33]">
          <div className="flex items-center gap-2">
            <div
              className={`p-1.5 rounded-lg border transition-colors ${
                thinking
                  ? "bg-cyan-950/80 border-cyan-500/50 text-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.3)]"
                  : "bg-slate-900 border-slate-700 text-slate-500"
              }`}
            >
              <BrainCircuit className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white tracking-wide">Extended Thinking (CoT)</span>
                <span
                  className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${
                    thinking
                      ? "bg-cyan-900/60 text-cyan-300 border border-cyan-600/50 shadow-[0_0_8px_rgba(6,182,212,0.2)]"
                      : "bg-slate-800 text-slate-400"
                  }`}
                >
                  {thinking ? "ACTIVE" : "DISABLED"}
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-sans leading-tight mt-0.5">
                Autonomous multi-pass reasoning before test synthesis and triage
              </p>
            </div>
          </div>

          <label className="relative inline-flex items-center cursor-pointer">
            <input
              id="toggle-thinking"
              type="checkbox"
              checked={thinking}
              onChange={(e) => setThinking(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
          </label>
        </div>

        {/* Model Intelligence Tier Buttons (low, medium, high, max, max_pro) */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-400 font-semibold uppercase flex items-center gap-1.5">
              <Sliders className="w-3 h-3 text-cyan-400" />
              <span>Agent Model Tier</span>
            </span>
            <span className="text-cyan-300 font-bold uppercase tracking-wider">
              {modelTier.replace("_", " ")}
            </span>
          </div>

          <div className="grid grid-cols-5 gap-1.5 text-xs font-mono">
            {[
              { id: "low", label: "Low", tokens: "1k", desc: "Fast probe & basic reconnaissance" },
              { id: "medium", label: "Medium", tokens: "4k", desc: "Standard QA & contract fidelity" },
              { id: "high", label: "High", tokens: "8k", desc: "Deep OWASP & boundary analysis (Recommended)" },
              { id: "max", label: "Max", tokens: "16k", desc: "Exhaustive mutation & state invariants" },
              { id: "max_pro", label: "Max Pro", tokens: "32k", desc: "Frontier swarm & adversarial canaries" },
            ].map((t) => {
              const isSelected = modelTier === t.id;
              return (
                <button
                  key={t.id}
                  id={`tier-btn-${t.id}`}
                  type="button"
                  onClick={() => {
                    setModelTier(t.id as ModelTier);
                    if (t.id === "low") setThinkingBudget(1024);
                    else if (t.id === "medium") setThinkingBudget(4096);
                    else if (t.id === "high") setThinkingBudget(8192);
                    else if (t.id === "max") setThinkingBudget(16384);
                    else if (t.id === "max_pro") setThinkingBudget(32768);
                  }}
                  className={`p-1.5 rounded-lg border text-center transition-all cursor-pointer flex flex-col items-center justify-between gap-1 ${
                    isSelected
                      ? "bg-gradient-to-b from-cyan-950 to-[#12223c] border-cyan-500/80 text-cyan-200 shadow-[0_0_10px_rgba(6,182,212,0.25)] ring-1 ring-cyan-500/40"
                      : "bg-[#0b1220] border-[#18253b] text-slate-400 hover:text-slate-200 hover:border-slate-700"
                  }`}
                  title={t.desc}
                >
                  <span className="font-bold text-[11px] leading-tight">{t.label}</span>
                  <span
                    className={`text-[9px] px-1 py-0.2 rounded font-mono ${
                      isSelected
                        ? "bg-cyan-900/60 text-cyan-300 border border-cyan-700/50"
                        : "bg-slate-800 text-slate-500"
                    }`}
                  >
                    {t.tokens}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Thinking Budget Slider when Thinking is Enabled */}
        {thinking && (
          <div className="pt-1 space-y-1">
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
              <span className="flex items-center gap-1.5">
                <Sparkles className="w-3 h-3 text-cyan-400" />
                <span>Reasoning Budget Tokens:</span>
              </span>
              <span className="text-cyan-300 font-bold">{thinkingBudget.toLocaleString()} tokens</span>
            </div>
            <input
              type="range"
              min={1024}
              max={32768}
              step={1024}
              value={thinkingBudget}
              onChange={(e) => setThinkingBudget(Number(e.target.value))}
              className="w-full accent-cyan-500 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
            />
            <div className="flex justify-between text-[9px] font-mono text-slate-500">
              <span>1k (Fast)</span>
              <span>8k (High / Default)</span>
              <span>32k (Frontier Max Pro)</span>
            </div>
          </div>
        )}
      </div>

      {/* Profile & Max Steps */}
      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <label className="text-[11px] font-mono uppercase font-bold text-slate-400">Execution Profile</label>
          <select
            id="composer-select-profile"
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
            id="composer-max-steps"
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
        id="btn-launch-swarm"
        type="button"
        onClick={onLaunch}
        disabled={isRunning}
        className="w-full mt-1 py-2.5 px-4 bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:via-blue-500 hover:to-indigo-500 text-white rounded-lg font-bold text-xs tracking-wider uppercase flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(6,182,212,0.35)] transition-all disabled:opacity-50 cursor-pointer active:scale-[0.99]"
      >
        {isRunning ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Synthesizing & Executing Scenarios ({modelTier.toUpperCase()})...
          </>
        ) : (
          <>
            <Play className="w-3.5 h-3.5 fill-white" />
            Launch Multi-Agent Swarm ({modelTier.toUpperCase()})
          </>
        )}
      </button>
    </div>
  );
}
