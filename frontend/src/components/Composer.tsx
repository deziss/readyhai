"use client";

import { useState, useEffect, useRef } from "react";
import {
  Bot,
  BrainCircuit,
  Check,
  Copy,
  FileCode,
  Globe,
  Loader2,
  Play,
  Plus,
  Search,
  ShieldAlert,
  Zap,
} from "lucide-react";
import type { DiscoveredTarget, ModelTier } from "@/types/agent";
import { apiRequest, useApiTokenVersion } from "@/lib/api";
import { copyTextSafely } from "@/lib/clipboard";

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

type Mode = "autonomous" | "adversarial" | "contract";

const MODES: { id: Mode; label: string; icon: typeof Zap }[] = [
  { id: "autonomous", label: "Autonomous QA", icon: Zap },
  { id: "adversarial", label: "Adversarial & auth", icon: ShieldAlert },
  { id: "contract", label: "Contract & spec", icon: FileCode },
];

const STEP_PRESETS = [5, 10, 15, 25, 50];

const TIERS: { id: ModelTier; label: string; tokens: string; tokensNum: number; desc: string }[] = [
  { id: "low", label: "Low", tokens: "1k", tokensNum: 1024, desc: "Fast probe and reconnaissance" },
  { id: "medium", label: "Med", tokens: "4k", tokensNum: 4096, desc: "Standard QA and contracts" },
  { id: "high", label: "High", tokens: "8k", tokensNum: 8192, desc: "Deep OWASP and boundary analysis (recommended)" },
  { id: "max", label: "Max", tokens: "16k", tokensNum: 16384, desc: "Exhaustive mutation and state invariants" },
  { id: "max_pro", label: "Max Pro", tokens: "32k", tokensNum: 32768, desc: "Frontier swarm and adversarial canaries" },
];

const DIRECTIVE_HINTS: { label: string; text: string }[] = [
  { label: "Auth session check", text: "Check unauthenticated access to /api/auth/session" },
  { label: "100 KB boundary", text: "Probe 100KB boundary size on chat input" },
  { label: "Prompt injection", text: "Inject prompt override canary on chat" },
];

const QUICK_TARGETS = ["https://myvapi.com", "https://api.example.com", "http://localhost:3000", "http://127.0.0.1:8080"];

const FIELD = "rounded-sm border border-rh-line bg-rh-bg px-3 py-2 text-ui text-rh-text placeholder:text-rh-muted";
const LABEL = "text-ui font-medium text-rh-text";
const SECONDARY_BTN =
  "inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-sm border border-rh-line px-3 py-2 text-ui font-medium text-rh-text hover:bg-rh-raised disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-transparent";

/**
 * The agent command center. The header and mode switch are pinned at the top, the Launch button is
 * pinned at the bottom, and only the controls in between scroll, so nothing can be pushed out of reach.
 */
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
  const [activeMode, setActiveMode] = useState<Mode>("autonomous");
  const [requesterIpInfo, setRequesterIpInfo] = useState<{
    egress_public_ip: string;
    ip_type: string;
    allowlist_guidance: string;
  } | null>(null);
  const [copiedIp, setCopiedIp] = useState(false);
  const modeRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const [isCustomSteps, setIsCustomSteps] = useState(!STEP_PRESETS.includes(maxSteps));
  const [customInputValue, setCustomInputValue] = useState(String(maxSteps));

  const tierDisplayName =
    {
      low: "Low",
      medium: "Medium",
      high: "High",
      max: "Max",
      max_pro: "Max Pro",
    }[modelTier] || "High";
  const tierDesc = TIERS.find((t) => t.id === modelTier)?.desc;

  // Keep the custom field in sync when maxSteps changes from outside (adjusting state during render,
  // not in an effect, so there is no extra cascading render).
  const [syncedMaxSteps, setSyncedMaxSteps] = useState(maxSteps);
  if (syncedMaxSteps !== maxSteps) {
    setSyncedMaxSteps(maxSteps);
    setCustomInputValue(String(maxSteps));
    if (!STEP_PRESETS.includes(maxSteps)) {
      setIsCustomSteps(true);
    }
  }

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

  function handleModeChange(mode: Mode) {
    setActiveMode(mode);
    if (mode === "adversarial") {
      setDirectives("Focus heavily on authorization bypass, BOLA, IDOR, token forgery, and prompt injection canaries.");
    } else if (mode === "contract") {
      setDirectives("Focus on OpenAPI contract compliance, boundary values, negative JSON parsing, and HTTP status codes.");
    } else {
      setDirectives("Strict QA and verify resilience, contracts, and authz");
    }
  }

  // Arrow keys move between modes (roving tabindex), as expected for a radio group.
  function handleModeKeyDown(e: React.KeyboardEvent, index: number) {
    let next: number;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") next = (index + 1) % MODES.length;
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = (index - 1 + MODES.length) % MODES.length;
    else return;
    e.preventDefault();
    handleModeChange(MODES[next].id);
    modeRefs.current[next]?.focus();
  }

  function appendDirective(hint: string) {
    if (!directives.includes(hint)) {
      setDirectives(directives ? `${directives}; ${hint}` : hint);
    }
  }

  return (
    <section
      aria-label="Agent command center"
      className="flex flex-col overflow-hidden rounded-md border border-rh-line bg-rh-surface lg:h-full lg:min-h-0"
    >
      {/* Pinned top: title and mode switch */}
      <div className="flex shrink-0 flex-col gap-3 border-b border-rh-line p-4">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-base font-semibold text-rh-text">Agent command center</h2>
          {onOpenAgentHistory && (
            <button
              id="btn-goto-qa-reports-top"
              type="button"
              onClick={onOpenAgentHistory}
              className="inline-flex shrink-0 cursor-pointer items-center gap-1.5 rounded-sm border border-rh-line px-2.5 py-1 text-xs font-medium text-rh-text hover:bg-rh-raised"
              title="Open QA agent reports and run history"
            >
              <Bot className="h-3.5 w-3.5 text-rh-primary" aria-hidden="true" />
              QA agent reports
            </button>
          )}
        </div>

        <div
          role="radiogroup"
          aria-label="Testing mode"
          className="@container flex items-center gap-1 rounded-sm border border-rh-line bg-rh-bg p-1"
        >
          {MODES.map((mode, i) => {
            const isSelected = activeMode === mode.id;
            const Icon = mode.icon;
            return (
              <button
                key={mode.id}
                ref={(el) => {
                  modeRefs.current[i] = el;
                }}
                type="button"
                role="radio"
                aria-checked={isSelected}
                tabIndex={isSelected ? 0 : -1}
                onClick={() => handleModeChange(mode.id)}
                onKeyDown={(e) => handleModeKeyDown(e, i)}
                title={mode.label}
                className={`flex min-w-0 flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-sm border px-2 py-1.5 text-ui font-medium ${
                  isSelected
                    ? "border-rh-primary bg-rh-raised text-rh-text"
                    : "border-transparent text-rh-muted hover:text-rh-text"
                }`}
              >
                <Icon className={`hidden h-3.5 w-3.5 shrink-0 @md:block ${isSelected ? "text-rh-primary" : ""}`} aria-hidden="true" />
                <span className="truncate">{mode.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Scrolling controls. From 1024px up this is the only part of the panel that scrolls; when the columns stack, the page scrolls instead. */}
      {/* `relative` keeps the visually hidden radio inputs inside this scroller instead of growing the page. */}
      <div className="relative flex flex-col gap-5 p-4 lg:min-h-0 lg:flex-1 lg:overflow-y-auto">
        {/* Target */}
        <div className="flex flex-col gap-2.5">
          <div className="flex items-center justify-between gap-2">
            <label htmlFor="composer-target-url" className={LABEL}>
              Target URL
            </label>
            {discoveredData && (
              <span className="truncate rounded-sm bg-rh-info/10 px-2 py-0.5 text-xs font-medium text-rh-info">
                {discoveredData.app_architecture || (discoveredData.is_spa ? "SPA shell detected" : "Architecture not reported")} ·{" "}
                {discoveredData.count} routes
              </span>
            )}
          </div>
          <input
            id="composer-target-url"
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://api.example.com or http://localhost:3000"
            spellCheck={false}
            className={`${FIELD} w-full font-mono placeholder:font-sans`}
          />
          <div className="flex flex-wrap gap-2">
            <button
              id="composer-btn-discover"
              type="button"
              onClick={onDiscover}
              disabled={isDiscovering || isCrawling || isRunning}
              title="Quick inspection of the target and its architecture"
              className={SECONDARY_BTN}
            >
              {isDiscovering ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-rh-primary" aria-hidden="true" />
                  Probing...
                </>
              ) : (
                <>
                  <Search className="h-3.5 w-3.5 text-rh-primary" aria-hidden="true" />
                  Discover
                </>
              )}
            </button>
            <button
              id="composer-btn-crawl"
              type="button"
              onClick={onCrawl}
              disabled={isCrawling || isDiscovering || isRunning}
              title="Crawl the site to map real internal links and forms"
              className={SECONDARY_BTN}
            >
              {isCrawling ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-rh-primary" aria-hidden="true" />
                  Crawling...
                </>
              ) : (
                <>
                  <Globe className="h-3.5 w-3.5 text-rh-primary" aria-hidden="true" />
                  Crawl site
                </>
              )}
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Example targets">
            <span className="text-xs text-rh-muted">Try</span>
            {QUICK_TARGETS.map((url) => (
              <button
                key={url}
                type="button"
                onClick={() => setTarget(url)}
                className="cursor-pointer rounded-sm border border-rh-line bg-rh-bg px-2 py-0.5 font-mono text-xs text-rh-muted hover:text-rh-text"
              >
                {url}
              </button>
            ))}
          </div>

          {/* Requester public IP, for allowlisting on private networks */}
          <div className="flex items-center justify-between gap-2 rounded-sm border border-rh-line bg-rh-bg px-3 py-2">
            <div className="min-w-0">
              <p className="text-xs text-rh-muted">
                Requester public IP {requesterIpInfo ? `(${requesterIpInfo.ip_type || "type unknown"})` : "(lookup unavailable)"}
              </p>
              <p className="truncate font-mono text-ui text-rh-text">{requesterIpInfo?.egress_public_ip || "unknown"}</p>
            </div>
            <button
              type="button"
              disabled={!requesterIpInfo?.egress_public_ip}
              onClick={async () => {
                const ip = requesterIpInfo?.egress_public_ip;
                if (!ip) return;
                if (!(await copyTextSafely(ip, "The IP address"))) return;
                setCopiedIp(true);
                setTimeout(() => setCopiedIp(false), 2000);
              }}
              className="inline-flex shrink-0 cursor-pointer items-center gap-1.5 rounded-sm border border-rh-line px-2.5 py-1 text-xs font-medium text-rh-text hover:bg-rh-raised disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent"
              title={requesterIpInfo?.allowlist_guidance || "Copy the public IP for your firewall allowlist"}
            >
              {copiedIp ? (
                <Check className="h-3.5 w-3.5 text-rh-go" aria-hidden="true" />
              ) : (
                <Copy className="h-3.5 w-3.5" aria-hidden="true" />
              )}
              {copiedIp ? "Copied" : "Copy IP"}
            </button>
          </div>
          <p className="-mt-1 text-xs text-rh-muted">Allowlist this address if the target is on a private network or AWS VPC.</p>
        </div>

        {/* Spec and focus */}
        <div className="flex flex-col gap-2">
          <label htmlFor="composer-spec-url" className={LABEL}>
            OpenAPI spec URL <span className="font-normal text-rh-muted">(optional)</span>
          </label>
          <input
            id="composer-spec-url"
            type="text"
            value={specUrl}
            onChange={(e) => setSpecUrl(e.target.value)}
            placeholder="/openapi.json, or leave blank to auto-discover"
            spellCheck={false}
            className={`${FIELD} font-mono placeholder:font-sans`}
          />
        </div>

        <div className="flex flex-col gap-2">
          <label htmlFor="composer-directives" className={LABEL}>
            Agent directives
          </label>
          <textarea
            id="composer-directives"
            rows={3}
            value={directives}
            onChange={(e) => setDirectives(e.target.value)}
            placeholder="e.g. Focus on unauthenticated session access, IDOR tenant boundaries, and prompt injection canaries"
            className={`${FIELD} resize-none leading-relaxed`}
          />
          <div className="flex flex-wrap gap-1.5">
            {DIRECTIVE_HINTS.map((hint) => (
              <button
                key={hint.label}
                type="button"
                onClick={() => appendDirective(hint.text)}
                title={hint.text}
                className="inline-flex cursor-pointer items-center gap-1 rounded-sm border border-rh-line bg-rh-bg px-2 py-0.5 text-xs text-rh-muted hover:text-rh-text"
              >
                <Plus className="h-3 w-3" aria-hidden="true" />
                {hint.label}
              </button>
            ))}
          </div>
        </div>

        {/* Agent settings */}
        <div className="flex flex-col gap-4 rounded-sm border border-rh-line bg-rh-bg p-3">
          <label
            htmlFor="toggle-thinking"
            className="flex cursor-pointer items-center justify-between gap-3"
            title="Let the agent reason through several passes before each step"
          >
            <span className="flex min-w-0 items-center gap-2">
              <BrainCircuit className={`h-4 w-4 shrink-0 ${thinking ? "text-rh-primary" : "text-rh-muted"}`} aria-hidden="true" />
              <span className="flex flex-col">
                <span className={LABEL}>Extended thinking</span>
                <span className="text-xs text-rh-muted">{thinking ? "On: multi-pass reasoning" : "Off: single-pass answers"}</span>
              </span>
            </span>
            <span className="relative inline-flex h-5 w-9 shrink-0 items-center">
              <input
                id="toggle-thinking"
                type="checkbox"
                role="switch"
                checked={thinking}
                onChange={(e) => setThinking(e.target.checked)}
                className="peer sr-only"
              />
              <span
                aria-hidden="true"
                className="absolute inset-0 rounded-full bg-rh-line peer-checked:bg-rh-primary peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-rh-primary"
              />
              <span
                aria-hidden="true"
                className="absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-rh-text peer-checked:translate-x-4 peer-checked:bg-rh-bg"
              />
            </span>
          </label>

          <div className="flex min-w-0 flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className={LABEL}>Model tier</span>
              <span className="text-xs font-medium text-rh-primary">{tierDisplayName}</span>
            </div>
            <div role="radiogroup" aria-label="Agent model tier" className="grid grid-cols-5 gap-1.5">
              {TIERS.map((t) => {
                const isSelected = modelTier === t.id;
                return (
                  <label
                    key={t.id}
                    id={`tier-radio-${t.id}`}
                    title={t.desc}
                    className={`relative flex cursor-pointer flex-col items-center rounded-sm border px-1 py-1.5 text-center has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-rh-primary ${
                      isSelected
                        ? "border-rh-primary bg-rh-raised text-rh-text"
                        : "border-rh-line text-rh-muted hover:text-rh-text"
                    }`}
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
                    <span className="text-ui font-medium leading-tight">{t.label}</span>
                    <span className={`text-xs tabular-nums ${isSelected ? "text-rh-primary" : ""}`}>{t.tokens}</span>
                  </label>
                );
              })}
            </div>
            {tierDesc && <p className="text-xs text-rh-muted">{tierDesc}</p>}
          </div>

          {thinking && (
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between gap-2">
                <label htmlFor="composer-thinking-budget-slider" className={LABEL}>
                  Reasoning budget
                </label>
                <span className="text-xs font-medium tabular-nums text-rh-primary">{thinkingBudget.toLocaleString()} tokens</span>
              </div>
              <input
                id="composer-thinking-budget-slider"
                type="range"
                min={1024}
                max={32768}
                step={1024}
                value={thinkingBudget}
                onChange={(e) => setThinkingBudget(Number(e.target.value))}
                className="h-1 w-full cursor-pointer accent-rh-primary"
              />
              <div className="flex justify-between text-xs text-rh-muted">
                <span>1k fast</span>
                <span>8k default</span>
                <span>32k max</span>
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div className="flex min-w-0 flex-col gap-1.5">
              <label htmlFor="composer-select-profile" className={LABEL}>
                Execution profile
              </label>
              <select
                id="composer-select-profile"
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                className={`${FIELD} cursor-pointer py-1.5`}
              >
                <option value="standard">Standard (multi-agent)</option>
                <option value="quick">Quick (contract and smoke)</option>
                <option value="deep">Deep (chaos and adversarial)</option>
              </select>
            </div>

            <div className="flex min-w-0 flex-col gap-1.5">
              <label htmlFor="composer-max-steps-preset" className={LABEL}>
                Max steps
              </label>
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
                  className={`${FIELD} min-w-0 cursor-pointer py-1.5 ${isCustomSteps ? "w-1/2" : "w-full"}`}
                >
                  <option value="5">5 (quick)</option>
                  <option value="10">10 (standard)</option>
                  <option value="15">15 (balanced)</option>
                  <option value="25">25 (deep)</option>
                  <option value="50">50 (exhaustive)</option>
                  <option value="custom">Custom...</option>
                </select>

                {isCustomSteps && (
                  <input
                    id="composer-max-steps"
                    type="number"
                    min={1}
                    max={50}
                    value={customInputValue}
                    aria-label="Custom max steps (1 to 50)"
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
                    className={`${FIELD} w-1/2 min-w-0 py-1.5 text-center tabular-nums`}
                  />
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Pinned bottom: launch */}
      <div className="flex shrink-0 flex-col gap-2 border-t border-rh-line p-4">
        <p className="truncate text-xs text-rh-muted">
          {tierDisplayName} tier · {maxSteps} steps · {profile} profile · thinking {thinking ? "on" : "off"}
        </p>
        <button
          id="btn-launch-swarm"
          type="button"
          onClick={onLaunch}
          disabled={isRunning}
          aria-busy={isRunning}
          className="inline-flex h-11 w-full cursor-pointer items-center justify-center gap-2 rounded-sm bg-rh-primary px-4 text-sm font-semibold text-rh-bg hover:bg-rh-primary-hover disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:bg-rh-primary"
        >
          {isRunning ? (
            <>
              <Loader2 className="h-4 w-4 shrink-0 animate-spin" aria-hidden="true" />
              Running agent...
            </>
          ) : (
            <>
              <Play className="h-4 w-4 shrink-0 fill-current" aria-hidden="true" />
              Run agent
            </>
          )}
        </button>
      </div>
    </section>
  );
}
