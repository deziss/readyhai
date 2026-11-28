"use client";

import { useCallback, useMemo } from "react";
import { Eraser } from "lucide-react";
import {
  ACCENTS,
  PREF_CHOICES,
  resetPrefs,
  setPref,
  usePrefs,
  type Prefs,
} from "@/lib/prefs";
import { cacheStatus, clearCache, useCacheVersion } from "@/lib/cache";
import { formatAge, useNow } from "./ui";

/**
 * How the console looks and behaves. These are stored in the browser, not on the server: an
 * operator on a shared scanner still gets their own density, colour mode and cache policy. Server
 * settings live on the cards below and follow the deployment instead.
 */

const FOCUS = "focus-visible:outline-2 focus-visible:outline-rh-primary";
const BTN_SECONDARY = `inline-flex items-center gap-1.5 rounded-[6px] bg-rh-raised px-2.5 py-1.5 text-xs font-medium text-rh-text transition-colors hover:bg-rh-line cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${FOCUS}`;
const BTN_DANGER = `inline-flex items-center gap-1.5 rounded-[6px] border border-rh-nogo/60 px-2.5 py-1.5 text-xs font-medium text-rh-nogo transition-colors hover:bg-rh-nogo/10 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${FOCUS}`;

/** Human wording for each stored value, keyed the way prefs stores it. */
const VALUE_LABEL: Record<string, string> = {
  dark: "Dark",
  light: "Light",
  system: "System",
  compact: "Compact",
  comfortable: "Comfortable",
  sm: "Small",
  md: "Medium",
  lg: "Large",
  standard: "Standard",
  cb_safe: "Colour-blind safe",
  gate: "The gate",
  targets: "Targets",
  evidence: "Evidence",
  off: "Off",
  "15s": "15 s",
  "30s": "30 s",
  "60s": "60 s",
  dashboard: "Dashboard",
  studio: "Agent studio",
};

interface RowSpec {
  key: keyof Prefs;
  label: string;
  help: string;
  choices: readonly string[];
}

export const PREF_ROWS: RowSpec[] = [
  {
    key: "theme",
    label: "Theme",
    help: "System follows the browser. Nothing flashes on reload either way.",
    choices: PREF_CHOICES.theme,
  },
  {
    key: "density",
    label: "Row height",
    help: "Compact fits roughly twice as many rows per screen.",
    choices: PREF_CHOICES.density,
  },
  {
    key: "typeScale",
    label: "Text size",
    help: "Scales all body text, not just one panel.",
    choices: PREF_CHOICES.typeScale,
  },
  {
    key: "accent",
    label: "Accent",
    help: "Used for actions and selection. Never used for a verdict, so a verdict always reads as a verdict.",
    choices: PREF_CHOICES.accent,
  },
  {
    key: "verdictPalette",
    label: "Verdict colours",
    help: "Colour-blind safe uses blue, yellow and vermillion. A conditional verdict always carries a hatch and a word too.",
    choices: PREF_CHOICES.verdictPalette,
  },
  {
    key: "landingView",
    label: "Opens on",
    help: "The view the console shows when you load it.",
    choices: PREF_CHOICES.landingView,
  },
  {
    key: "dashboardFocus",
    label: "Dashboard focus",
    help: "Which dashboard section is highlighted.",
    choices: PREF_CHOICES.dashboardFocus,
  },
  {
    key: "pollInterval",
    label: "Refresh in background",
    help: "Off means data updates when you load the page or press Refresh.",
    choices: PREF_CHOICES.pollInterval,
  },
];

const TOGGLES: { key: keyof Prefs; label: string; help: string }[] = [
  {
    key: "showFreshness",
    label: "Show how old each number is",
    help: "Adds a quiet timestamp to cached panels, so a 40 minute-old verdict is not read as current.",
  },
  {
    key: "reduceColumns",
    label: "One column per section",
    help: "Stacks the dashboard instead of placing panels side by side.",
  },
  {
    key: "motion",
    label: "Animation",
    help: "Your operating system's reduced-motion setting turns this off regardless.",
  },
];

export function AppearanceSettings() {
  const prefs = usePrefs();
  // Re-read when the cache changes; the 30 s clock keeps the "oldest" age honest without polling storage.
  const cacheVersion = useCacheVersion();
  const now = useNow();
  const status = useMemo(() => {
    void cacheVersion; // the value itself is not shown; it marks "the cache changed"
    return cacheStatus(now);
  }, [cacheVersion, now]);

  const clear = useCallback(() => clearCache(), []);

  const kb = Math.round(status.bytes / 1024);

  return (
    <section className="rounded-md border border-rh-line bg-rh-surface">
      <div className="border-b border-rh-line px-4 py-3">
        <h3 className="text-sm font-semibold text-rh-text">This browser</h3>
        <p className="mt-0.5 text-xs text-rh-muted">
          Saved on this device only, so it does not change what other operators see.
        </p>
      </div>

      <div className="divide-y divide-rh-line">
        {PREF_ROWS.map((row) => (
          <div key={row.key} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
            <div className="min-w-[200px] flex-1">
              <p className="text-xs font-semibold text-rh-text">{row.label}</p>
              <p className="mt-0.5 text-xs text-rh-muted">{row.help}</p>
              {row.key === "accent" ? (
                <p className="mt-1 text-xs text-rh-faint">
                  {ACCENTS.find((a) => a.id === prefs.accent)?.note}
                </p>
              ) : null}
            </div>
            <div className="flex flex-wrap gap-1" role="group" aria-label={row.label}>
              {row.choices.map((choice) => {
                const active = String(prefs[row.key]) === choice;
                return (
                  <button
                    key={choice}
                    type="button"
                    aria-pressed={active}
                    onClick={() => setChoice(row.key, choice)}
                    className={`rounded-[6px] border px-2.5 py-1 text-xs font-medium transition-colors ${FOCUS} ${
                      active
                        ? "border-rh-primary/60 bg-rh-primary/12 text-rh-text"
                        : "border-rh-line text-rh-muted hover:bg-rh-raised hover:text-rh-text"
                    }`}
                  >
                    {row.key === "accent"
                      ? (ACCENTS.find((a) => a.id === choice)?.label ?? choice)
                      : (VALUE_LABEL[choice] ?? choice)}
                  </button>
                );
              })}
            </div>
          </div>
        ))}

        {TOGGLES.map((row) => (
          <label key={row.key} className="flex cursor-pointer items-start gap-3 px-4 py-3">
            <input
              type="checkbox"
              checked={Boolean(prefs[row.key])}
              onChange={(e) => setPref(row.key, e.target.checked as Prefs[typeof row.key])}
              className={`mt-0.5 h-3.5 w-3.5 accent-[var(--color-rh-primary)] ${FOCUS}`}
            />
            <span>
              <span className="block text-xs font-semibold text-rh-text">{row.label}</span>
              <span className="mt-0.5 block max-w-[70ch] text-xs text-rh-muted">{row.help}</span>
            </span>
          </label>
        ))}

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
          <div className="min-w-[200px] flex-1">
            <p className="text-xs font-semibold text-rh-text">Cached data</p>
            <p className="mt-0.5 max-w-[70ch] text-xs text-rh-muted">
              {status.keys === 0
                ? "Nothing cached yet. Views fill this as you load them, which is what lets a refresh show your data instead of a spinner."
                : `${status.keys} stored ${status.keys === 1 ? "response" : "responses"}, about ${kb} KB, oldest ${formatAge(status.oldest ?? 0)}. Clearing it costs you the instant first paint, nothing more.`}
            </p>
          </div>
          <button type="button" className={BTN_DANGER} onClick={clear} disabled={status.keys === 0}>
            <Eraser className="h-3.5 w-3.5" aria-hidden="true" />
            Clear cached data
          </button>
        </div>
      </div>

      <div className="flex items-center gap-2 border-t border-rh-line px-4 py-3">
        <button type="button" className={BTN_SECONDARY} onClick={resetPrefs}>
          Restore defaults
        </button>
        <span className="text-xs text-rh-faint">Only changes this browser.</span>
      </div>
    </section>
  );
}

/** Narrows a stored choice back to its preference key before writing. */
function setChoice<K extends keyof Prefs>(key: K, choice: string): void {
  const value = choice as Prefs[K];
  setPref(key, value);
}
