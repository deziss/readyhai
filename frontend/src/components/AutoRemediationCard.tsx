"use client";

import { useState } from "react";
import { Copy, Check, Terminal, Sparkles, FileCode2, ChevronDown, ChevronUp } from "lucide-react";
import { copyTextSafely } from "@/lib/clipboard";

/** Remediation text is a suggestion, never a verified fix: the wording must not claim otherwise. */
export const REMEDIATION_TITLE = "Example remediation \u2014 adapt to your code";

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

  async function handleCopyPatch() {
    if (!patch) return;
    if (!(await copyTextSafely(patch, "The example diff"))) return;
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  }

  async function handleCopyRepro() {
    if (!reproScript) return;
    if (!(await copyTextSafely(reproScript, "The reproduction script"))) return;
    setCopiedRepro(true);
    setTimeout(() => setCopiedRepro(false), 2000);
  }

  function renderDiffLine(line: string, index: number) {
    const base = "px-2.5 py-0.5 text-xs font-mono whitespace-pre select-text";
    if (line.startsWith("+++") || line.startsWith("---")) {
      return (
        <div key={index} className={`${base} text-rh-muted font-semibold bg-rh-raised`}>
          {line}
        </div>
      );
    }
    if (line.startsWith("+")) {
      return (
        <div key={index} className={`${base} bg-rh-go/15 text-rh-go border-l-2 border-rh-go`}>
          {line}
        </div>
      );
    }
    if (line.startsWith("-")) {
      return (
        <div key={index} className={`${base} bg-rh-nogo/15 text-rh-nogo border-l-2 border-rh-nogo`}>
          {line}
        </div>
      );
    }
    if (line.startsWith("@@")) {
      return (
        <div key={index} className={`${base} bg-rh-info/15 text-rh-info font-semibold border-l-2 border-rh-info`}>
          {line}
        </div>
      );
    }
    if (line.startsWith("diff ") || line.startsWith("index ")) {
      return (
        <div key={index} className={`${base} text-rh-muted font-semibold bg-rh-raised`}>
          {line}
        </div>
      );
    }
    return (
      <div key={index} className={`${base} text-rh-text`}>
        {line}
      </div>
    );
  }

  return (
    <div className={`rounded-[10px] border border-rh-line bg-rh-surface overflow-hidden ${className}`}>
      <div className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-3 border-b border-rh-line">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-1.5 rounded-[6px] bg-rh-go/15 text-rh-go shrink-0" aria-hidden="true">
            <Sparkles className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-semibold text-rh-text">{REMEDIATION_TITLE}</div>
            <div className="text-xs text-rh-muted">
              Illustrative suggestion generated from the finding. It has not been applied or tested against your code.
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {patch && (
            <button
              type="button"
              onClick={handleCopyPatch}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-rh-primary"
              title="Copy the example diff to the clipboard"
            >
              {copiedPatch ? (
                <>
                  <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Copy example diff</span>
                </>
              )}
            </button>
          )}

          {reproScript && (
            <button
              type="button"
              onClick={handleCopyRepro}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-[6px] bg-rh-raised hover:bg-rh-line text-rh-text text-xs font-medium transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-rh-primary"
              title="Copy reproduction script to clipboard"
            >
              {copiedRepro ? (
                <>
                  <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                  <span>Copied repro!</span>
                </>
              ) : (
                <>
                  <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Copy repro script</span>
                </>
              )}
            </button>
          )}

          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1.5 rounded-[6px] hover:bg-rh-raised text-rh-muted hover:text-rh-text transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-rh-primary"
            title={isExpanded ? "Collapse example" : "Expand example"}
            aria-label={isExpanded ? "Collapse example remediation" : "Expand example remediation"}
            aria-expanded={isExpanded}
          >
            {isExpanded ? <ChevronUp className="w-4 h-4" aria-hidden="true" /> : <ChevronDown className="w-4 h-4" aria-hidden="true" />}
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="p-3.5 flex flex-col gap-3">
          {explanation && (
            <div className="p-3 rounded-[6px] bg-rh-go/10 text-xs">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-rh-go mb-1">
                <Sparkles className="w-3.5 h-3.5" aria-hidden="true" />
                Explanation and root-cause mitigation
              </div>
              <p className="text-rh-text text-xs leading-relaxed">{explanation}</p>
            </div>
          )}

          {patch && (
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between text-xs text-rh-muted font-semibold">
                <span className="flex items-center gap-1.5">
                  <FileCode2 className="w-3.5 h-3.5" aria-hidden="true" />
                  Example diff
                </span>
                <span className="font-normal">Illustrative only</span>
              </div>
              <div className="rounded-[6px] border border-rh-line bg-rh-bg overflow-auto max-h-64 py-1">
                {patch.split("\n").map((line, idx) => renderDiffLine(line, idx))}
              </div>
            </div>
          )}

          {reproScript && (
            <div className="flex flex-col gap-1.5">
              <button
                type="button"
                onClick={() => setShowRepro(!showRepro)}
                aria-expanded={showRepro}
                className="flex items-center justify-between text-xs text-rh-primary hover:text-rh-primary-hover font-semibold cursor-pointer py-1 rounded-[6px] focus-visible:outline-2 focus-visible:outline-rh-primary"
              >
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                  {showRepro ? "Hide reproduction script" : "Show reproduction script"}
                </span>
                {showRepro ? <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" /> : <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />}
              </button>

              {showRepro && (
                <pre className="p-3 rounded-[6px] bg-rh-bg border border-rh-line font-mono text-xs text-rh-text overflow-auto max-h-48 select-all">
                  {reproScript}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
