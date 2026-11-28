import { useSyncExternalStore } from "react";

/**
 * User interface preferences: theme, density, type scale, accent, verdict colour mode and what the
 * dashboard leads with. Everything lives in localStorage under one key and is published onto the
 * document element as data-* attributes, which is what the token blocks in globals.css key off.
 *
 * Reading and writing never throw: a browser that blocks storage (private mode, enterprise policy)
 * still gets working preferences for the current page.
 */

export type ThemeMode = "dark" | "light" | "system";
export type Density = "compact" | "comfortable";
export type TypeScale = "sm" | "md" | "lg";
export type AccentName = "saffron" | "signal" | "kelp" | "plum";
export type VerdictPalette = "standard" | "cb_safe";
export type DashboardFocus = "gate" | "targets" | "evidence";
export type PollInterval = "off" | "15s" | "30s" | "60s";
/** Which view the app opens on. Teams that live in the Studio can keep it there. */
export type LandingView = "dashboard" | "studio";

export interface Prefs {
  theme: ThemeMode;
  density: Density;
  typeScale: TypeScale;
  accent: AccentName;
  verdictPalette: VerdictPalette;
  dashboardFocus: DashboardFocus;
  /** How often live views revalidate in the background. "off" means only on navigation or refresh. */
  pollInterval: PollInterval;
  /** Show the relative "cached 3 min ago" indicator on cached panels. */
  showFreshness: boolean;
  /** One column per dashboard section instead of the wide layout. */
  reduceColumns: boolean;
  /** Motion is on unless the user or the OS turns it off. */
  motion: boolean;
  landingView: LandingView;
}

export const PREFS_STORAGE_KEY = "readyhai_prefs_v1";

export const ACCENTS: { id: AccentName; label: string; note: string }[] = [
  { id: "saffron", label: "Saffron", note: "Default. Amber-metal, reads on graphite and bone." },
  { id: "signal", label: "Signal red", note: "Warm brick. Strongest presence on actions." },
  { id: "kelp", label: "Kelp", note: "Desaturated green-teal, farthest from verdict green." },
  { id: "plum", label: "Plum", note: "Muted wine. Quietest of the four." },
];

export const DEFAULT_PREFS: Prefs = {
  theme: "dark",
  density: "comfortable",
  typeScale: "md",
  accent: "saffron",
  verdictPalette: "standard",
  dashboardFocus: "gate",
  pollInterval: "30s",
  landingView: "dashboard",
  showFreshness: true,
  reduceColumns: false,
  motion: true,
};

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/** Values the UI offers, also the allowlist a tampered or older stored file is checked against. */
export const PREF_CHOICES = {
  theme: ["dark", "light", "system"],
  density: ["compact", "comfortable"],
  typeScale: ["sm", "md", "lg"],
  accent: ["saffron", "signal", "kelp", "plum"],
  verdictPalette: ["standard", "cb_safe"],
  dashboardFocus: ["gate", "targets", "evidence"],
  pollInterval: ["off", "15s", "30s", "60s"],
  landingView: ["dashboard", "studio"],
} as const;

/** The preference keys whose values come from a fixed list. */
type PrefEnumKey = keyof typeof PREF_CHOICES;

/** One field's stored value, or the default when it is missing or not a known choice. */
function pick<K extends PrefEnumKey>(src: Record<string, unknown>, key: K): Prefs[K] {
  const allowed: readonly string[] = PREF_CHOICES[key];
  const raw = src[key];
  return typeof raw === "string" && allowed.includes(raw) ? (raw as Prefs[K]) : DEFAULT_PREFS[key];
}

/** Merges whatever is stored over the defaults, dropping unknown or malformed values. */
export function normalizePrefs(raw: unknown): Prefs {
  if (!raw || typeof raw !== "object") return { ...DEFAULT_PREFS };
  const src = raw as Record<string, unknown>;
  const bool = (key: "showFreshness" | "reduceColumns" | "motion"): boolean =>
    typeof src[key] === "boolean" ? (src[key] as boolean) : DEFAULT_PREFS[key];
  return {
    theme: pick(src, "theme"),
    density: pick(src, "density"),
    typeScale: pick(src, "typeScale"),
    accent: pick(src, "accent"),
    verdictPalette: pick(src, "verdictPalette"),
    dashboardFocus: pick(src, "dashboardFocus"),
    pollInterval: pick(src, "pollInterval"),
    landingView: pick(src, "landingView"),
    showFreshness: bool("showFreshness"),
    reduceColumns: bool("reduceColumns"),
    motion: bool("motion"),
  };
}

function readStored(): Prefs {
  try {
    const raw = window.localStorage.getItem(PREFS_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_PREFS };
    return normalizePrefs(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_PREFS };
  }
}

function writeStored(prefs: Prefs): void {
  try {
    window.localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // Storage blocked: the in-memory copy still drives this page.
  }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

let current: Prefs | null = null;
const listeners = new Set<() => void>();

function snapshot(): Prefs {
  if (typeof window === "undefined") return DEFAULT_PREFS;
  if (current === null) current = readStored();
  return current;
}

function apply(prefs: Prefs): void {
  if (typeof document === "undefined") return;
  const el = document.documentElement;
  el.dataset.theme = prefs.theme;
  el.dataset.density = prefs.density;
  el.dataset.scale = prefs.typeScale;
  el.dataset.accent = prefs.accent;
  el.dataset.verdicts = prefs.verdictPalette;
  el.dataset.motion = prefs.motion ? "on" : "off";
}

/** Reads persisted prefs and writes them onto the document element. Safe to call twice. */
export function initPrefs(): Prefs {
  const prefs = snapshot();
  apply(prefs);
  if (prefs.theme === "system" && typeof window.matchMedia === "function") {
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const sync = () => {
      document.documentElement.dataset.resolved = mq.matches ? "light" : "dark";
    };
    sync();
    mq.addEventListener?.("change", sync);
  }
  return prefs;
}

function set(next: Prefs): void {
  current = next;
  writeStored(next);
  apply(next);
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

export function getPrefs(): Prefs {
  return snapshot();
}

export function setPref<K extends keyof Prefs>(key: K, value: Prefs[K]): void {
  const merged = { ...snapshot(), [key]: value };
  set(normalizePrefs(merged));
}

export function resetPrefs(): void {
  set({ ...DEFAULT_PREFS });
}

export function usePrefs(): Prefs {
  return useSyncExternalStore(subscribe, snapshot, () => DEFAULT_PREFS);
}

/** Milliseconds between background revalidations, or null when polling is off. */
export function pollIntervalMs(prefs: Prefs): number | null {
  switch (prefs.pollInterval) {
    case "15s":
      return 15_000;
    case "30s":
      return 30_000;
    case "60s":
      return 60_000;
    default:
      return null;
  }
}
