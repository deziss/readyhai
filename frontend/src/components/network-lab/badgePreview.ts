/**
 * Colours for the badge previews on this page.
 *
 * These chips imitate the SVG the scanner serves at `/api/badges/*`, which an operator pastes into
 * a README or a pull request. That SVG is rendered by GitHub, on GitHub's own background, so it
 * cannot follow this app's theme or a user's colour preferences: the palette here is deliberately
 * pinned to `src/serve/badges.rs`. Change a colour there and change it here, or the preview stops
 * being a preview.
 *
 * Nothing on this list is a theme token, and none of it should be swapped for a `rh-` variable.
 */

/** Label half of the badge: `#1e293b` in `badge_svg`. */
export const BADGE_LABEL_BG = "#1e293b";

/** Verdict colour for PASS: `verdict_color` in the backend. */
export const BADGE_PASS = "#22c55e";
/** Verdict colour for WARN. */
export const BADGE_WARN = "#eab308";
/** Verdict colour for FAIL. */
export const BADGE_FAIL = "#ef4444";
/** The score half of the ledger badge: `#3b82f6` in `ledger_svg`. */
export const BADGE_LEDGER = "#3b82f6";
/** Anything not measured renders grey rather than a reassuring colour. */
export const BADGE_NONE = "#6b7280";

/** Colour for a scan verdict, using the same mapping the badge endpoint applies. */
export function badgeColorForVerdict(verdict: string | null): string {
  switch (verdict) {
    case "PASS":
      return BADGE_PASS;
    case "WARN":
      return BADGE_WARN;
    case "FAIL":
      return BADGE_FAIL;
    default:
      return BADGE_NONE;
  }
}
