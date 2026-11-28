"use client";

import { Columns2, Moon, Rows3, Sun, MonitorSmartphone } from "lucide-react";
import { setPref, usePrefs, type Density, type ThemeMode } from "@/lib/prefs";

/**
 * Two header toggles for the settings an operator reaches for without wanting a settings page:
 * light or dark, and how much vertical space a row claims. Both persist, and both apply before the
 * next paint through the bootstrap script in the layout.
 */

const BTN =
  "inline-flex h-7 cursor-pointer items-center justify-center gap-1 rounded-[6px] border border-rh-line text-rh-muted transition-colors hover:bg-rh-raised hover:text-rh-text focus-visible:outline-2 focus-visible:outline-rh-primary";

const THEME_ORDER: { id: ThemeMode; label: string }[] = [
  { id: "dark", label: "Dark" },
  { id: "light", label: "Light" },
  { id: "system", label: "Follow the system" },
];

const THEME_ICON: Record<ThemeMode, typeof Sun> = {
  dark: Moon,
  light: Sun,
  system: MonitorSmartphone,
};

export function QuickToggles() {
  const prefs = usePrefs();
  const themeIndex = THEME_ORDER.findIndex((t) => t.id === prefs.theme);
  const theme = THEME_ORDER[themeIndex] ?? THEME_ORDER[0];
  const ThemeIcon = THEME_ICON[theme.id];
  const compact = prefs.density === "compact";
  const DensityIcon = compact ? Rows3 : Columns2;

  const nextTheme = () => setPref("theme", THEME_ORDER[(themeIndex + 1) % THEME_ORDER.length].id);
  const nextDensity = () => setPref("density", (compact ? "comfortable" : "compact") satisfies Density);

  return (
    // Hidden below md: the same two controls are on the Settings page, and at tablet
    // width the header has no room for them.
    <div className="hidden items-center gap-1 md:flex">
      <button
        type="button"
        className={BTN}
        onClick={nextTheme}
        title={`${theme.label}. Click to change.`}
        aria-label={`Colour theme: ${theme.label}`}
      >
        <ThemeIcon className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
      <button
        type="button"
        className={BTN}
        onClick={nextDensity}
        title={compact ? "Compact rows. Click for comfortable spacing." : "Comfortable rows. Click for compact spacing."}
        aria-label={`Row density: ${prefs.density}`}
      >
        <DensityIcon className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
    </div>
  );
}
