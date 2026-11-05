"use client";

import { useMemo } from "react";
import { Zap, ShieldCheck, AlertTriangle, Activity } from "lucide-react";

export interface ConcurrencyBurstMeterProps {
  burstCount?: number;
  burstResults?: number[];
  className?: string;
  technique?: string;
  caseStatus?: string;
}

const CHIP_GO = { bg: "bg-rh-go/15 text-rh-go", dot: "bg-rh-go" };
const CHIP_COND = { bg: "bg-rh-cond/15 text-rh-cond", dot: "bg-rh-cond" };
const CHIP_NOGO = { bg: "bg-rh-nogo/15 text-rh-nogo", dot: "bg-rh-nogo" };
const CHIP_INFO = { bg: "bg-rh-info/15 text-rh-info", dot: "bg-rh-info" };

function getStatusChipInfo(status: number) {
  if (status === 200) return { label: "200 OK", ...CHIP_GO };
  if (status === 201) return { label: "201 Created", ...CHIP_GO };
  if (status === 204) return { label: "204 No Content", ...CHIP_GO };
  if (status === 409) return { label: "409 Conflict", ...CHIP_COND };
  if (status === 429) return { label: "429 Too Many Requests", ...CHIP_COND };
  if (status === 400) return { label: "400 Bad Request", ...CHIP_COND };
  if (status === 401) return { label: "401 Unauthorized", ...CHIP_COND };
  if (status === 403) return { label: "403 Forbidden", ...CHIP_INFO };
  if (status === 422) return { label: "422 Unprocessable", ...CHIP_COND };
  if (status >= 500) return { label: `${status} Server Error`, ...CHIP_NOGO };
  return { label: `HTTP ${status}`, bg: "bg-rh-raised text-rh-text", dot: "bg-rh-muted" };
}

export function ConcurrencyBurstMeter({
  burstCount,
  burstResults,
  className = "",
  technique,
  caseStatus,
}: ConcurrencyBurstMeterProps) {
  const count = burstResults?.length || burstCount || 0;

  const stats = useMemo(() => {
    if (!burstResults || burstResults.length === 0) return null;
    const distribution: Record<number, number> = {};
    let successes = 0;
    let conflicts = 0;
    let rateLimits = 0;
    let errors = 0;

    burstResults.forEach((code) => {
      distribution[code] = (distribution[code] || 0) + 1;
      if (code >= 200 && code < 300) successes++;
      else if (code === 409) conflicts++;
      else if (code === 429) rateLimits++;
      else if (code >= 500) errors++;
    });

    // In a TOCTOU race test, if multiple concurrent requests succeeded (e.g. 2+ 200s), that's a race breach!
    const isRaceVulnerability = successes > 1;

    return {
      distribution,
      successes,
      conflicts,
      rateLimits,
      errors,
      isRaceVulnerability,
    };
  }, [burstResults]);

  if (!count) return null;

  return (
    <div className={`p-4 rounded-[10px] border border-rh-line bg-rh-bg flex flex-col gap-3 ${className}`}>
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-rh-line">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-[6px] bg-rh-cond/15 text-rh-cond" aria-hidden="true">
            <Zap className="w-4 h-4" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-rh-text">TOCTOU concurrency burst</span>
              <span className="text-xs px-2 py-0.5 rounded-[6px] bg-rh-cond/15 text-rh-cond font-semibold tabular-nums">
                {count}x concurrent burst
              </span>
            </div>
            <span className="text-xs text-rh-muted">Parallel HTTP requests that probe for a race condition</span>
          </div>
        </div>

        {stats ? (
          stats.isRaceVulnerability ? (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-[6px] bg-rh-nogo/15 text-rh-nogo text-xs font-semibold">
              <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Race condition vulnerability</span>
            </span>
          ) : (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-[6px] bg-rh-go/15 text-rh-go text-xs font-semibold">
              <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Mutex lock enforced</span>
            </span>
          )
        ) : (
          <span className="px-2 py-0.5 rounded-[6px] bg-rh-raised text-rh-muted text-xs">Planned micro-burst</span>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <div className="text-xs text-rh-muted font-semibold flex flex-wrap items-center justify-between gap-2">
          <span className="flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-rh-muted" aria-hidden="true" />
            Parallel request outcomes ({count} concurrent threads)
          </span>
          {stats && (
            <span className="tabular-nums">
              {stats.successes} succeeded · {stats.conflicts} blocked or conflicting
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 p-2.5 rounded-[6px] bg-rh-surface border border-rh-line">
          {burstResults && burstResults.length > 0 ? (
            burstResults.map((code, index) => {
              const chip = getStatusChipInfo(code);
              return (
                <div
                  key={index}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-[6px] text-xs font-semibold tabular-nums ${chip.bg}`}
                  title={`Thread #${index + 1}: ${chip.label}`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${chip.dot}`} aria-hidden="true" />
                  <span>#{index + 1}:</span>
                  <span>{chip.label}</span>
                </div>
              );
            })
          ) : (
            Array.from({ length: Math.min(count, 8) }).map((_, idx) => (
              <div
                key={idx}
                className="flex items-center gap-1.5 px-2 py-1 rounded-[6px] text-xs bg-rh-raised text-rh-muted"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-rh-muted" aria-hidden="true" />
                <span>Thread #{idx + 1} (planned)</span>
              </div>
            ))
          )}
        </div>
      </div>

      {stats && (
        <div
          className={`p-3 rounded-[6px] text-xs flex items-start gap-2 ${
            stats.isRaceVulnerability ? "bg-rh-nogo/15 text-rh-text" : "bg-rh-go/15 text-rh-text"
          }`}
        >
          {stats.isRaceVulnerability ? (
            <>
              <AlertTriangle className="w-4 h-4 text-rh-nogo shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <strong className="text-rh-nogo block">Critical TOCTOU finding</strong>
                <span>
                  {stats.successes} concurrent requests succeeded at the same time. The endpoint lacks atomic transaction
                  isolation (for example SELECT FOR UPDATE or optimistic concurrency checks), which permits double-spending
                  or duplicate state transitions.
                </span>
              </div>
            </>
          ) : (
            <>
              <ShieldCheck className="w-4 h-4 text-rh-go shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <strong className="text-rh-go block">Concurrency gate passed</strong>
                <span>
                  Exactly {stats.successes} request succeeded while the other concurrent attempts were rejected with HTTP{" "}
                  {stats.conflicts > 0 ? "409 Conflict" : "429/400"}. Database concurrency boundaries are enforced.
                </span>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
