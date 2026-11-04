"use client";

import { useState } from "react";
import { Copy, Check, Terminal, Sparkles, FileCode2, ChevronDown, ChevronUp } from "lucide-react";

export interface AutoRemediationCardProps {
  patch?: string;
  explanation?: string;
  reproScript?: string;
  className?: string;
  defaultExpanded?: boolean;
}

export function AutoRemediationCard({
  patch,
  explanation,
  reproScript,
  className = "",
  defaultExpanded = true,
}: AutoRemediationCardProps) {
  const [copiedPatch, setCopiedPatch] = useState(false);
  const [copiedRepro, setCopiedRepro] = useState(false);
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  const [showRepro, setShowRepro] = useState(false);

  if (!patch && !explanation && !reproScript) {
    return null;
  }

  function handleCopyPatch() {
    if (!patch) return;
    navigator.clipboard.writeText(patch);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  }

  function handleCopyRepro() {
    if (!reproScript) return;
    navigator.clipboard.writeText(reproScript);
    setCopiedRepro(true);
    setTimeout(() => setCopiedRepro(false), 2000);
  }

  function renderDiffLine(line: string, index: number) {
    if (line.startsWith("+++") || line.startsWith("---")) {
      return (
        <div key={index} className="text-slate-400 font-semibold bg-[#0d172a]/70 px-2.5 py-0.5 font-mono text-[11px] select-text">
          {line}
        </div>
      );
    }
    if (line.startsWith("+")) {
      return (
        <div key={index} className="bg-emerald-950/40 text-emerald-300 border-l-2 border-emerald-500 px-2.5 py-0.5 font-mono text-[11px] select-text">
          {line}
        </div>
      );
    }
    if (line.startsWith("-")) {
      return (
        <div key={index} className="bg-rose-950/40 text-rose-300 border-l-2 border-rose-500 px-2.5 py-0.5 font-mono text-[11px] select-text">
          {line}
        </div>
      );
    }
    if (line.startsWith("@@")) {
      return (
        <div key={index} className="bg-cyan-950/40 text-cyan-400 font-bold border-l-2 border-cyan-500 px-2.5 py-0.5 font-mono text-[11px] select-text">
          {line}
        </div>
      );
    }
    if (line.startsWith("diff ") || line.startsWith("index ")) {
      return (
        <div key={index} className="text-slate-500 font-semibold bg-[#070b14] px-2.5 py-0.5 font-mono text-[11px] select-text">
          {line}
        </div>
      );
    }
    return (
      <div key={index} className="text-slate-300 px-2.5 py-0.5 font-mono text-[11px] select-text">
        {line}
      </div>
    );
  }

  return (
    <div className={`rounded-lg border border-emerald-700/50 bg-[#061019] overflow-hidden shadow-lg ${className}`}>
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 bg-gradient-to-r from-emerald-950/40 via-[#071321] to-[#070c18] border-b border-emerald-900/40">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-emerald-950 border border-emerald-600/60 text-emerald-400">
            <Sparkles className="w-3.5 h-3.5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-emerald-300 tracking-wide">
                Auto-Remediation Git Patch
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold">
                Verified Fix
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              One-click unified diff ready to apply to repository
            </span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          {patch && (
            <button
              type="button"
              onClick={handleCopyPatch}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-600/70 text-emerald-300 text-[11px] font-mono font-semibold transition-colors cursor-pointer shadow-sm"
              title="Copy unified git diff patch to clipboard"
            >
              {copiedPatch ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  <span>Copied Patch!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy Git Patch</span>
                </>
              )}
            </button>
          )}

          {reproScript && (
            <button
              type="button"
              onClick={handleCopyRepro}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-[11px] font-mono font-semibold transition-colors cursor-pointer shadow-sm"
              title="Copy reproduction script to clipboard"
            >
              {copiedRepro ? (
                <>
                  <Check className="w-3 h-3 text-cyan-400" />
                  <span>Copied Repro!</span>
                </>
              ) : (
                <>
                  <Terminal className="w-3 h-3" />
                  <span>Copy Repro Script</span>
                </>
              )}
            </button>
          )}

          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            title={isExpanded ? "Collapse Patch" : "Expand Patch"}
          >
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Main Body */}
      {isExpanded && (
        <div className="p-3.5 flex flex-col gap-3 bg-[#040810]">
          {/* Explanation Section */}
          {explanation && (
            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/50 text-xs">
              <div className="flex items-center gap-1.5 font-mono text-[11px] font-bold text-emerald-400 uppercase tracking-wider mb-1">
                <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                Explanation & Root-Cause Mitigation
              </div>
              <p className="text-slate-300 text-xs leading-relaxed font-sans">
                {explanation}
              </p>
            </div>
          )}

          {/* Diff Viewer */}
          {patch && (
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 font-semibold uppercase">
                <span className="flex items-center gap-1">
                  <FileCode2 className="w-3 h-3 text-emerald-400" />
                  Unified Diff Preview
                </span>
                <span className="text-slate-500">git apply --check</span>
              </div>
              <div className="rounded border border-[#1b2b46] bg-[#03060c] overflow-x-auto max-h-64 py-1">
                {patch.split("\n").map((line, idx) => renderDiffLine(line, idx))}
              </div>
            </div>
          )}

          {/* Repro Script Toggle & View */}
          {reproScript && (
            <div className="flex flex-col gap-1.5">
              <button
                type="button"
                onClick={() => setShowRepro(!showRepro)}
                className="flex items-center justify-between text-[11px] font-mono text-cyan-400 hover:text-cyan-300 font-semibold cursor-pointer py-1"
              >
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  {showRepro ? "Hide Autonomous Reproduction Script" : "Show Autonomous Reproduction Script"}
                </span>
                {showRepro ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>

              {showRepro && (
                <div className="relative">
                  <pre className="p-3 rounded bg-black/90 border border-cyan-900/40 font-mono text-[11px] text-cyan-200 overflow-x-auto max-h-48 select-all">
                    {reproScript}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
