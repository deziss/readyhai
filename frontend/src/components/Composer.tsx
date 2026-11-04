"use client";

import { useState, useEffect } from "react";
import {
  ArrowRight,
  Bot,
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
  Copy,
  Check,
} from "lucide-react";
import type { DiscoveredTarget, ModelTier } from "@/types/agent";
import { apiRequest, useApiTokenVersion } from "@/lib/api";

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
  onOpenAgentHistory?: () => void;
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
  onOpenAgentHistory,
}: ComposerProps) {
  const [activeMode, setActiveMode] = useState<"autonomous" | "adversarial" | "contract">("autonomous");
  const [requesterIpInfo, setRequesterIpInfo] = useState<{
    egress_public_ip: string;
    ip_type: string;
    allowlist_guidance: string;
  } | null>(null);
  const [copiedIp, setCopiedIp] = useState(false);

  const STEP_PRESETS = [5, 10, 15, 25, 50];
  const [isCustomSteps, setIsCustomSteps] = useState(!STEP_PRESETS.includes(maxSteps));
  const [customInputValue, setCustomInputValue] = useState(String(maxSteps));

  const TIERS: { id: ModelTier; label: string; tokens: string; tokensNum: number; desc: string }[] = [
    { id: "low", label: "Low", tokens: "1k", tokensNum: 1024, desc: "Fast probe & reconnaissance" },
    { id: "medium", label: "Med", tokens: "4k", tokensNum: 4096, desc: "Standard QA & contracts" },
    { id: "high", label: "High", tokens: "8k", tokensNum: 8192, desc: "Deep OWASP & boundary analysis (Recommended)" },
    { id: "max", label: "Max", tokens: "16k", tokensNum: 16384, desc: "Exhaustive mutation & state invariants" },
    { id: "max_pro", label: "Max Pro", tokens: "32k", tokensNum: 32768, desc: "Frontier swarm & adversarial canaries" },
  ];

  const tierDisplayName = {
    low: "Low",
    medium: "Medium",
    high: "High",
    max: "Max",
    max_pro: "Max Pro",
  }[modelTier] || "High";

  useEffect(() => {
    setCustomInputValue(String(maxSteps));
    if (!STEP_PRESETS.includes(maxSteps)) {
      setIsCustomSteps(true);
    }
  }, [maxSteps]);

  const tokenVersion = useApiTokenVersion();

  useEffect(() => {
    let cancelled = false;
    apiRequest<{ egress_public_ip: string; ip_type: string; allowlist_guidance: string }>(
      "/api/agent/requester-ip",
      { label: "Requester IP lookup" }
    ).then((r) => {
      if (cancelled) return;
      // No fallback IP: if the lookup failed the IP is simply unknown.
      setRequesterIpInfo(r.ok && r.data ? r.data : null);
    });
    return () => {
      cancelled = true;
    };
  }, [tokenVersion]);

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
      {/* Top Command Bar & QA Reports Shortcut */}
      <div className="flex items-center justify-between pb-1 border-b border-[#162033]">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            Agent Command Center
          </span>
        </div>
        {onOpenAgentHistory && (
          <button
            id="btn-goto-qa-reports-top"
            type="button"
            onClick={onOpenAgentHistory}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0e1726] hover:bg-[#132238] border border-cyan-800/50 hover:border-cyan-500 text-cyan-300 text-[11px] font-mono font-semibold transition-all cursor-pointer shadow-sm group shrink-0"
            title="Open QA Agent Reports & Swarm History"
          >
            <Bot className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
            <span>QA Agent Reports</span>
            <ArrowRight className="w-3 h-3 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </button>
        )}
      </div>

      {/* Mode Switch */}
      <div
        role="radiogroup"
        aria-label="Testing Mode Switch"
        className="flex items-center p-0.5 bg-[#060912] rounded-lg border border-[#162033]"
      >
        {([
          { id: "autonomous", label: "Autonomous QA", icon: Zap, activeColor: "text-cyan-300 border-cyan-500/40 bg-[#0f172a]" },
          { id: "adversarial", label: "Adversarial & Auth", icon: ShieldAlert, activeColor: "text-rose-300 border-rose-500/40 bg-[#1a0f19]" },
          { id: "contract", label: "Contract & Spec", icon: FileCode, activeColor: "text-emerald-300 border-emerald-500/40 bg-[#0c1a16]" },
        ] as const).map((mode) => {
          const isSelected = activeMode === mode.id;
          const Icon = mode.icon;
          return (
            <button
              key={mode.id}
              type="button"
              role="radio"
              aria-checked={isSelected}
              onClick={() => handleModeChange(mode.id)}
              className={`flex-1 py-1.5 px-2 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 cursor-pointer border ${
                isSelected
                  ? `${mode.activeColor} shadow-sm font-semibold`
                  : "text-slate-400 hover:text-slate-200 border-transparent hover:bg-[#0c111e]"
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isSelected ? "" : "opacity-70"}`} />
              <span className="truncate">{mode.label}</span>
            </button>
          );
        })}
      </div>

      {/* Requester Public IP & Private Network Whitelist Banner */}
      <div className="flex items-center justify-between gap-2 p-2 rounded-lg bg-[#070b14] border border-[#162238] text-[11px] font-mono text-slate-300">
        <div className="flex items-center gap-2 min-w-0">
          <span className="flex items-center gap-1.5 text-cyan-400 font-bold shrink-0">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            Requester Public IP:
          </span>
          <span className="text-cyan-200 font-bold bg-[#0d1627] px-2 py-0.5 rounded border border-cyan-800/60 font-mono">
            {requesterIpInfo?.egress_public_ip || "unknown"}
          </span>
          <span className="text-[10px] text-slate-400 hidden sm:inline truncate">
            {requesterIpInfo ? `(${requesterIpInfo.ip_type || "type unknown"}) · ` : "(lookup unavailable) · "}
            Whitelist for Private Networks / AWS VPC
          </span>
        </div>
        <button
          type="button"
          disabled={!requesterIpInfo?.egress_public_ip}
          onClick={() => {
            const ip = requesterIpInfo?.egress_public_ip;
            if (!ip) return;
            navigator.clipboard.writeText(ip);
            setCopiedIp(true);
            setTimeout(() => setCopiedIp(false), 2000);
          }}
          className="px-2 py-0.5 rounded text-[10px] bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 transition-colors flex items-center gap-1 shrink-0 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
          title={requesterIpInfo?.allowlist_guidance || "Copy public IP for firewall allowlist"}
        >
          {copiedIp ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          {copiedIp ? "Copied" : "Copy IP"}
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
              {discoveredData.app_architecture || (discoveredData.is_spa ? "SPA shell detected" : "architecture not reported")} ({discoveredData.count} routes)
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

      {/* Compact Agent Thinking & Intelligence Tier Section */}
      <div className="p-2.5 bg-[#080d19] rounded-xl border border-[#18263d] space-y-2 shadow-inner">
        {/* Thinking Toggle */}
        <div className="flex items-center justify-between pb-1.5 border-b border-[#141f33]/80">
          <div className="flex items-center gap-2">
            <div
              className={`p-1 rounded-md border transition-colors ${
                thinking
                  ? "bg-cyan-950/80 border-cyan-500/50 text-cyan-400 shadow-[0_0_6px_rgba(6,182,212,0.3)]"
                  : "bg-slate-900 border-slate-700 text-slate-500"
              }`}
            >
              <BrainCircuit className="w-3.5 h-3.5" />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-white tracking-wide">Extended Thinking (CoT)</span>
              <span
                className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${
                  thinking
                    ? "bg-cyan-900/60 text-cyan-300 border border-cyan-600/50"
                    : "bg-slate-800 text-slate-400"
                }`}
              >
                {thinking ? "ACTIVE" : "OFF"}
              </span>
            </div>
          </div>

          <label className="relative inline-flex items-center cursor-pointer" title="Toggle autonomous multi-pass chain-of-thought reasoning">
            <input
              id="toggle-thinking"
              type="checkbox"
              checked={thinking}
              onChange={(e) => setThinking(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-8 h-4.5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-3.5 peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-3.5 after:w-3.5 after:transition-all peer-checked:bg-cyan-600"></div>
          </label>
        </div>

        {/* Radio Button Switch for Model Tier */}
        <div className="space-y-1">
          <div className="flex items-center justify-between text-[10px] font-mono">
            <span className="text-slate-400 font-semibold uppercase flex items-center gap-1">
              <Sliders className="w-3 h-3 text-cyan-400" />
              <span>Agent Model Tier</span>
            </span>
            <span className="text-cyan-300 font-bold uppercase tracking-wider">
              {tierDisplayName}
            </span>
          </div>

          <div role="radiogroup" aria-label="Agent Model Tier" className="grid grid-cols-5 gap-1">
            {TIERS.map((t) => {
              const isSelected = modelTier === t.id;
              return (
                <label
                  key={t.id}
                  id={`tier-radio-${t.id}`}
                  className={`relative flex items-center justify-between px-1.5 py-1 rounded-md text-[11px] font-mono cursor-pointer transition-all border ${
                    isSelected
                      ? "bg-gradient-to-b from-cyan-950/80 to-[#101e36] border-cyan-500/70 text-cyan-200 shadow-[0_0_8px_rgba(6,182,212,0.2)] font-semibold"
                      : "bg-[#090f1d] border-[#162238] text-slate-400 hover:text-slate-200 hover:border-slate-700"
                  }`}
                  title={t.desc}
                >
                  <input
                    type="radio"
                    name="agent-model-tier"
                    value={t.id}
                    checked={isSelected}
                    onChange={() => {
                      setModelTier(t.id);
                      setThinkingBudget(t.tokensNum);
                    }}
                    className="sr-only"
                  />
                  <div className="flex items-center gap-1 min-w-0">
                    <span
                      className={`w-2.5 h-2.5 rounded-full border flex items-center justify-center shrink-0 transition-colors ${
                        isSelected ? "border-cyan-400 bg-cyan-950" : "border-slate-600 bg-slate-900"
                      }`}
                    >
                      {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_3px_#22d3ee]" />}
                    </span>
                    <span className="truncate">{t.label}</span>
                  </div>
                  <span
                    className={`text-[9px] px-1 py-0.2 rounded font-mono shrink-0 ml-0.5 ${
                      isSelected
                        ? "bg-cyan-900/70 text-cyan-300 border border-cyan-700/60"
                        : "bg-slate-800/80 text-slate-500"
                    }`}
                  >
                    {t.tokens}
                  </span>
                </label>
              );
            })}
          </div>
        </div>

        {/* Reasoning Budget Tokens Slider when Thinking is Enabled */}
        {thinking && (
          <div className="pt-0.5 space-y-1">
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span className="flex items-center gap-1 text-slate-400">
                <Sparkles className="w-3 h-3 text-cyan-400" />
                <span>Reasoning Budget Tokens:</span>
              </span>
              <span className="text-cyan-300 font-bold">{thinkingBudget.toLocaleString()} tokens</span>
            </div>
            <input
              id="composer-thinking-budget-slider"
              type="range"
              min={1024}
              max={32768}
              step={1024}
              value={thinkingBudget}
              onChange={(e) => setThinkingBudget(Number(e.target.value))}
              className="w-full accent-cyan-500 h-1 bg-slate-800 rounded-lg cursor-pointer"
            />
            <div className="flex justify-between text-[9px] font-mono text-slate-500">
              <span>1k (Fast)</span>
              <span>8k (Default)</span>
              <span>32k (Max Pro)</span>
            </div>
          </div>
        )}
      </div>

      {/* Profile & Max Steps */}
      <div className="grid grid-cols-2 gap-2.5">
        <div className="flex flex-col gap-1">
          <label className="text-[11px] font-mono uppercase font-bold text-slate-400">
            Execution Profile
          </label>
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
          <div className="flex items-center justify-between">
            <label className="text-[11px] font-mono uppercase font-bold text-slate-400">
              Max Steps
            </label>
            {isCustomSteps && (
              <span className="text-[9px] font-mono text-cyan-400 font-semibold uppercase">
                Custom ({maxSteps})
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <select
              id="composer-max-steps-preset"
              value={isCustomSteps ? "custom" : String(maxSteps)}
              onChange={(e) => {
                const val = e.target.value;
                if (val === "custom") {
                  setIsCustomSteps(true);
                } else {
                  setIsCustomSteps(false);
                  const n = Number(val);
                  setMaxSteps(n);
                  setCustomInputValue(String(n));
                }
              }}
              className={`${
                isCustomSteps ? "w-1/2" : "w-full"
              } bg-[#07090e] border border-[#1e2a40] rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer transition-all`}
            >
              <option value="5">5 Steps (Quick)</option>
              <option value="10">10 Steps (Standard)</option>
              <option value="15">15 Steps (Balanced)</option>
              <option value="25">25 Steps (Deep)</option>
              <option value="50">50 Steps (Exhaustive)</option>
              <option value="custom">Custom...</option>
            </select>

            {isCustomSteps && (
              <div className="relative w-1/2">
                <input
                  id="composer-max-steps"
                  type="number"
                  min={1}
                  max={50}
                  value={customInputValue}
                  onChange={(e) => {
                    const text = e.target.value;
                    setCustomInputValue(text);
                    const parsed = parseInt(text, 10);
                    if (!isNaN(parsed) && parsed >= 1 && parsed <= 50) {
                      setMaxSteps(parsed);
                    }
                  }}
                  onBlur={() => {
                    const parsed = parseInt(customInputValue, 10);
                    if (isNaN(parsed) || parsed < 1) {
                      setMaxSteps(1);
                      setCustomInputValue("1");
                    } else if (parsed > 50) {
                      setMaxSteps(50);
                      setCustomInputValue("50");
                    } else {
                      setMaxSteps(parsed);
                      setCustomInputValue(String(parsed));
                    }
                  }}
                  placeholder="1-50"
                  className="w-full bg-[#07090e] border border-cyan-500/60 rounded-lg pl-2.5 pr-8 py-1.5 text-xs font-mono text-cyan-200 focus:outline-none focus:ring-1 focus:ring-cyan-500 text-center"
                />
                <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] font-mono text-slate-500 pointer-events-none">
                  steps
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Launch Action */}
      <button
        id="btn-launch-swarm"
        type="button"
        onClick={onLaunch}
        disabled={isRunning}
        className="w-full h-10 py-2 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 active:from-cyan-700 active:to-blue-700 border border-cyan-400/40 text-white rounded-lg font-semibold text-xs tracking-wide flex items-center justify-center gap-2 shadow-[0_0_12px_rgba(6,182,212,0.22)] hover:shadow-[0_0_18px_rgba(6,182,212,0.32)] transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer active:scale-[0.99]"
      >
        {isRunning ? (
          <>
            <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-200 shrink-0" />
            <span>Executing Swarm</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/35 border border-white/20 text-cyan-200 uppercase font-bold tracking-wider">
              {tierDisplayName}
            </span>
          </>
        ) : (
          <>
            <Play className="w-3.5 h-3.5 fill-white shrink-0" />
            <span>Launch Multi-Agent Swarm</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/35 border border-white/20 text-cyan-200 uppercase font-bold tracking-wider">
              {tierDisplayName}
            </span>
          </>
        )}
      </button>
    </div>
  );
}
