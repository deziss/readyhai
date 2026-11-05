"use client";

import { useEffect, useId, useState } from "react";
import { Eye, EyeOff, KeyRound, X } from "lucide-react";
import {
  OPEN_SETTINGS_EVENT,
  clearApiToken,
  isValidTokenFormat,
  setApiToken,
  useApiToken,
} from "@/lib/api";

/**
 * Header key button + dialog for entering the backend bearer token.
 * The token is stored in localStorage (see lib/api.ts) and attached to every request.
 */
export function ApiTokenSettings() {
  const token = useApiToken();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState("");
  const [reveal, setReveal] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();

  useEffect(() => {
    const onOpen = () => {
      setDraft("");
      setError(null);
      setOpen(true);
    };
    window.addEventListener(OPEN_SETTINGS_EVENT, onOpen);
    return () => window.removeEventListener(OPEN_SETTINGS_EVENT, onOpen);
  }, []);

  // Escape closes the dialog while it is open.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  function openDialog() {
    setDraft("");
    setError(null);
    setReveal(false);
    setOpen(true);
  }

  function save() {
    const clean = draft.trim();
    if (!clean) {
      setError("Enter the token, or use Clear token to remove the saved one.");
      return;
    }
    if (!isValidTokenFormat(clean)) {
      setError("The token may only contain printable ASCII characters with no spaces.");
      return;
    }
    setApiToken(clean);
    setOpen(false);
  }

  function clear() {
    clearApiToken();
    setDraft("");
    setError(null);
  }

  const hasToken = token.length > 0;

  return (
    <>
      <button
        type="button"
        id="btn-api-token-settings"
        onClick={openDialog}
        className={`inline-flex cursor-pointer items-center gap-1.5 rounded-sm border px-2.5 py-1 text-xs font-medium ${
          hasToken
            ? "border-rh-line text-rh-text hover:bg-rh-raised"
            : "border-rh-cond/50 bg-rh-cond/10 text-rh-cond hover:bg-rh-cond/15"
        }`}
        title={hasToken ? "An API token is saved. Select to change it." : "No API token is saved. Select to add one."}
      >
        <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
        <span className="hidden sm:inline">{hasToken ? "API token" : "Set API token"}</span>
        <span className="sr-only sm:hidden">{hasToken ? "API token" : "Set API token"}</span>
      </button>

      {open && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4"
          role="dialog"
          aria-modal="true"
          aria-label="API token settings"
        >
          <div className="w-full max-w-md rounded-md border border-rh-line bg-rh-surface shadow-popover">
            <div className="flex items-center justify-between border-b border-rh-line p-4">
              <div className="flex items-center gap-2.5">
                <KeyRound className="h-4 w-4 text-rh-primary" aria-hidden="true" />
                <h2 className="text-base font-semibold text-rh-text">API token</h2>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="cursor-pointer rounded-sm p-1 text-rh-muted hover:bg-rh-raised hover:text-rh-text"
                aria-label="Close"
                title="Close"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>

            <form
              className="space-y-3 p-4"
              onSubmit={(e) => {
                e.preventDefault();
                save();
              }}
            >
              <p className="text-ui leading-relaxed text-rh-muted">
                The ReadyHai backend needs a bearer token on every API request. The token is saved in this browser
                (localStorage) and sent as <code className="text-rh-text">Authorization: Bearer ...</code>.
              </p>

              <p className="text-ui">
                <span className="text-rh-muted">Status: </span>
                {hasToken ? (
                  <span className="text-rh-go">a token is saved in this browser</span>
                ) : (
                  <span className="text-rh-cond">no token saved</span>
                )}
              </p>

              <div className="flex flex-col gap-1.5">
                <label htmlFor={inputId} className="text-ui font-medium text-rh-text">
                  {hasToken ? "New token" : "Token"}
                </label>
                <div className="relative">
                  <input
                    id={inputId}
                    type={reveal ? "text" : "password"}
                    value={draft}
                    onChange={(e) => {
                      setDraft(e.target.value);
                      setError(null);
                    }}
                    placeholder={hasToken ? "Enter a new token to replace the saved one" : "Paste your API token"}
                    autoComplete="off"
                    spellCheck={false}
                    autoFocus
                    className="w-full rounded-sm border border-rh-line bg-rh-bg py-2 pl-3 pr-10 font-mono text-ui text-rh-text placeholder:font-sans placeholder:text-rh-muted"
                  />
                  <button
                    type="button"
                    onClick={() => setReveal((r) => !r)}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 cursor-pointer rounded-sm p-1 text-rh-muted hover:text-rh-text"
                    aria-label={reveal ? "Hide token" : "Show token"}
                    aria-pressed={reveal}
                    title={reveal ? "Hide token" : "Show token"}
                  >
                    {reveal ? <EyeOff className="h-3.5 w-3.5" aria-hidden="true" /> : <Eye className="h-3.5 w-3.5" aria-hidden="true" />}
                  </button>
                </div>
              </div>

              {error && (
                <p className="text-ui text-rh-nogo" role="alert">
                  {error}
                </p>
              )}

              <div className="flex items-center justify-between pt-1">
                <button
                  type="button"
                  onClick={clear}
                  disabled={!hasToken}
                  className="cursor-pointer rounded-sm border border-rh-nogo/60 px-3 py-1.5 text-ui font-medium text-rh-nogo hover:bg-rh-nogo/10 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Clear token
                </button>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setOpen(false)}
                    className="cursor-pointer rounded-sm border border-rh-line px-3 py-1.5 text-ui font-medium text-rh-text hover:bg-rh-raised"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="cursor-pointer rounded-sm bg-rh-primary px-4 py-1.5 text-ui font-semibold text-rh-bg hover:bg-rh-primary-hover"
                  >
                    Save token
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
