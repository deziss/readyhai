"use client";

import { useEffect, useState } from "react";
import { KeyRound, X, Eye, EyeOff } from "lucide-react";
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

  useEffect(() => {
    const onOpen = () => {
      setDraft("");
      setError(null);
      setOpen(true);
    };
    window.addEventListener(OPEN_SETTINGS_EVENT, onOpen);
    return () => window.removeEventListener(OPEN_SETTINGS_EVENT, onOpen);
  }, []);

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
        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] font-mono font-medium transition-colors cursor-pointer ${
          hasToken
            ? "bg-[#0e1524] border-[#1e2a40] text-slate-300 hover:text-white"
            : "bg-amber-950/40 border-amber-700/60 text-amber-300 hover:bg-amber-950/70"
        }`}
        title={hasToken ? "API token is set. Click to change it." : "No API token set. Click to enter it."}
      >
        <KeyRound className={`w-3.5 h-3.5 ${hasToken ? "text-cyan-400" : "text-amber-400"}`} />
        <span className="hidden sm:inline">{hasToken ? "API token" : "Set API token"}</span>
      </button>

      {open && (
        <div
          className="fixed inset-0 z-[60] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-label="API token settings"
        >
          <div className="w-full max-w-md bg-[#090e1a] border border-[#1b2b48] rounded-2xl shadow-2xl">
            <div className="p-4 border-b border-[#182338] flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <KeyRound className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Settings: API token</h3>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-[#16233a] cursor-pointer"
                title="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form
              className="p-4 space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                save();
              }}
            >
              <p className="text-xs text-slate-400 leading-relaxed">
                The ReadyHai backend requires a bearer token on every API request. The token is stored in this
                browser (localStorage) and sent as <code className="text-cyan-300">Authorization: Bearer ...</code>.
              </p>

              <div className="text-[11px] font-mono">
                Status:{" "}
                {hasToken ? (
                  <span className="text-emerald-400">a token is saved in this browser</span>
                ) : (
                  <span className="text-amber-400">no token saved</span>
                )}
              </div>

              <div className="relative">
                <input
                  type={reveal ? "text" : "password"}
                  value={draft}
                  onChange={(e) => {
                    setDraft(e.target.value);
                    setError(null);
                  }}
                  placeholder={hasToken ? "Enter a new token to replace the saved one" : "Paste API token"}
                  autoComplete="off"
                  spellCheck={false}
                  autoFocus
                  className="w-full bg-[#07090e] border border-[#1e2a40] rounded px-3 py-2 pr-9 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="button"
                  onClick={() => setReveal((r) => !r)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 cursor-pointer"
                  title={reveal ? "Hide token" : "Show token"}
                >
                  {reveal ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>

              {error && <p className="text-xs text-rose-300 font-mono">{error}</p>}

              <div className="flex items-center justify-between pt-1">
                <button
                  type="button"
                  onClick={clear}
                  disabled={!hasToken}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono text-rose-300 border border-rose-800/60 hover:bg-rose-950/50 disabled:opacity-40 cursor-pointer"
                >
                  Clear token
                </button>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setOpen(false)}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono text-slate-300 border border-[#1e2a40] hover:bg-[#111b2e] cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded-lg text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-slate-950 cursor-pointer"
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
