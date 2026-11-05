import { notify } from "@/lib/api";

/**
 * Last-resort copy for pages where `navigator.clipboard` does not exist (plain http on a
 * non-localhost host) or rejected the write. Uses a hidden, selected textarea + execCommand.
 */
function legacyCopy(text: string): boolean {
  if (typeof document === "undefined" || !document.body || typeof document.execCommand !== "function") {
    return false;
  }
  const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.setAttribute("aria-hidden", "true");
  ta.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;pointer-events:none;";
  document.body.appendChild(ta);
  try {
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, text.length);
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    ta.remove();
    try {
      previous?.focus();
    } catch {
      // ignore: focus restoration is best effort
    }
  }
}

/**
 * Copy text to the clipboard without ever throwing.
 *
 * 1. `navigator.clipboard.writeText` when it exists (secure contexts only).
 * 2. Otherwise, or if it rejects (permission denied, document not focused), the execCommand fallback.
 * 3. If both fail, a notice tells the user to copy manually.
 *
 * Resolves to true only when the text really reached the clipboard, so callers can show their
 * "Copied" state conditionally.
 */
export async function copyTextSafely(text: string, what = "Text"): Promise<boolean> {
  try {
    const clip = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
    if (clip && typeof clip.writeText === "function") {
      await clip.writeText(text);
      return true;
    }
  } catch {
    // fall through to the legacy path
  }
  if (legacyCopy(text)) return true;
  notify(
    `${what} could not be copied automatically: the clipboard is unavailable here (it needs https or localhost) or the browser blocked it. Select the text and copy it manually.`
  );
  return false;
}
