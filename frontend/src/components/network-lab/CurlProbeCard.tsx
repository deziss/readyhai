import React from "react";
import { Terminal, Check, Copy } from "lucide-react";
import type { CurlTestResponse } from "@/types/network";
import { PANEL, BTN_SECONDARY } from "./types";

export interface CurlProbeCardProps {
  target: string;
  curlResult: CurlTestResponse | null;
  isCurlRunning: boolean;
  handleRunCurl: () => void;
  copyToClipboard: (text: string, id: string) => void;
  copiedText: string | null;
}

export function CurlProbeCard({
  target,
  curlResult,
  isCurlRunning,
  handleRunCurl,
  copyToClipboard,
  copiedText,
}: CurlProbeCardProps) {
  return (
    <div className={`${PANEL} space-y-3`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-semibold text-rh-text flex items-center gap-2">
          <Terminal className="w-4 h-4 text-rh-muted" aria-hidden="true" />
          <span>cURL diagnostic probe</span>
        </span>

        {curlResult && (
          <button
            type="button"
            onClick={() => copyToClipboard(curlResult.command, "curl-command")}
            className={BTN_SECONDARY}
          >
            {copiedText === "curl-command" ? (
              <>
                <Check className="w-3.5 h-3.5 text-rh-go" aria-hidden="true" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Copy cURL</span>
              </>
            )}
          </button>
        )}
      </div>

      {curlResult ? (
        <div className="space-y-3 text-xs">
          {/* Generated cURL command */}
          <div className="p-3 bg-rh-bg rounded-[6px] border border-rh-line font-mono text-rh-text break-all select-all">
            {curlResult.command}
          </div>

          {/* Sub-millisecond timing chips */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
            <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
              <span className="text-xs text-rh-muted block">DNS lookup</span>
              <span className="font-semibold text-rh-text tabular-nums">
                {(curlResult.dns_lookup_s * 1000).toFixed(1)}ms
              </span>
            </div>
            <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
              <span className="text-xs text-rh-muted block">TCP connect</span>
              <span className="font-semibold text-rh-text tabular-nums">
                {(curlResult.connect_s * 1000).toFixed(1)}ms
              </span>
            </div>
            <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
              <span className="text-xs text-rh-muted block">TLS / app connect</span>
              <span className="font-semibold text-rh-text tabular-nums">
                {(curlResult.appconnect_s * 1000).toFixed(1)}ms
              </span>
            </div>
            <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
              <span className="text-xs text-rh-muted block">TTFB</span>
              <span className="font-semibold text-rh-text tabular-nums">
                {(curlResult.starttransfer_s * 1000).toFixed(1)}ms
              </span>
            </div>
            <div className="p-2 rounded-[6px] bg-rh-bg border border-rh-line text-center">
              <span className="text-xs text-rh-muted block">Total RTT</span>
              <span className="font-semibold text-rh-text tabular-nums">
                {(curlResult.total_s * 1000).toFixed(1)}ms
              </span>
            </div>
          </div>

          {/* Output text */}
          {curlResult.stdout && (
            <div className="p-3 bg-rh-bg rounded-[6px] border border-rh-line font-mono text-rh-text max-h-40 min-h-0 overflow-y-auto whitespace-pre-wrap">
              {curlResult.stdout}
            </div>
          )}
        </div>
      ) : (
        <div className="p-4 rounded-[6px] bg-rh-bg border border-rh-line text-rh-muted text-xs flex flex-wrap items-center justify-between gap-3">
          <span>
            No cURL probe has run yet. Run one to time DNS, TCP, TLS and TTFB against{" "}
            <span className="font-mono text-rh-text">{target}</span>.
          </span>
          <button
            type="button"
            onClick={handleRunCurl}
            disabled={isCurlRunning}
            className={BTN_SECONDARY}
          >
            {isCurlRunning ? "Running..." : "Run probe"}
          </button>
        </div>
      )}
    </div>
  );
}
