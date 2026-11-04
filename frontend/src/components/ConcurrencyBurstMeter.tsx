"use client";

import { useMemo } from "react";
import { Zap, ShieldCheck, AlertTriangle, Layers, Activity } from "lucide-react";

export interface ConcurrencyBurstMeterProps {
  burstCount?: number;
  burstResults?: number[];
  className?: string;
  technique?: string;
  caseStatus?: string;
}

function getStatusChipInfo(status: number) {
  if (status === 200) return { label: "200 OK", bg: "bg-emerald-950/80 text-emerald-300 border-emerald-600/70", dot: "bg-emerald-400" };
  if (status === 201) return { label: "201 Created", bg: "bg-emerald-950/80 text-emerald-300 border-emerald-600/70", dot: "bg-emerald-400" };
  if (status === 204) return { label: "204 No Content", bg: "bg-emerald-950/80 text-emerald-300 border-emerald-600/70", dot: "bg-emerald-400" };
  if (status === 409) return { label: "409 Conflict", bg: "bg-amber-950/80 text-amber-300 border-amber-600/70", dot: "bg-amber-400" };
  if (status === 429) return { label: "429 Too Many Requests", bg: "bg-purple-950/80 text-purple-300 border-purple-600/70", dot: "bg-purple-400" };
  if (status === 400) return { label: "400 Bad Request", bg: "bg-amber-950/80 text-amber-300 border-amber-600/70", dot: "bg-amber-400" };
  if (status === 401) return { label: "401 Unauthorized", bg: "bg-amber-950/80 text-amber-300 border-amber-600/70", dot: "bg-amber-400" };
  if (status === 403) return { label: "403 Forbidden", bg: "bg-sky-950/80 text-sky-300 border-sky-600/70", dot: "bg-sky-400" };
  if (status === 422) return { label: "422 Unprocessable", bg: "bg-amber-950/80 text-amber-300 border-amber-600/70", dot: "bg-amber-400" };
  if (status >= 500) return { label: `${status} Server Error`, bg: "bg-rose-950/80 text-rose-300 border-rose-600/70", dot: "bg-rose-400" };
  return { label: `HTTP ${status}`, bg: "bg-slate-900 text-slate-300 border-slate-700", dot: "bg-slate-400" };
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
    <div className={`p-4 rounded-xl border border-amber-800/40 bg-[#0c0e18] flex flex-col gap-3 shadow-xl ${className}`}>
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[#1f2338]">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-amber-950 border border-amber-600/60 text-amber-400">
            <Zap className="w-3.5 h-3.5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-amber-200 tracking-wider uppercase font-mono">
                TOCTOU Concurrency Burst Meter
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-950/80 text-amber-300 border border-amber-700 font-bold">
                {count}x Concurrent Burst
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              Sub-millisecond parallel HTTP race condition probe
            </span>
          </div>
        </div>

        {stats ? (
          stats.isRaceVulnerability ? (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-950/80 text-rose-300 border border-rose-600 font-mono text-xs font-bold shadow-[0_0_12px_rgba(244,63,94,0.3)]">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
              <span>RACE CONDITION VULNERABILITY</span>
            </span>
          ) : (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-600 font-mono text-xs font-bold">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>MUTEX LOCK ENFORCED</span>
            </span>
          )
        ) : (
          <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-700 font-mono text-[10px]">
            Planned Micro-Burst
          </span>
        )}
      </div>

      {/* Burst Meter Visual Row of Status Chips */}
      <div className="flex flex-col gap-2">
        <div className="text-[10px] font-mono text-slate-400 font-semibold uppercase flex items-center justify-between">
          <span className="flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-amber-400" />
            Parallel Request Outcomes ({count} concurrent threads)
          </span>
          {stats && (
            <span className="text-slate-500">
              {stats.successes} Succeeded · {stats.conflicts} Blocked/Conflicts
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 p-2.5 rounded-lg bg-[#070912] border border-[#1a1f33]">
          {burstResults && burstResults.length > 0 ? (
            burstResults.map((code, index) => {
              const chip = getStatusChipInfo(code);
              return (
                <div
                  key={index}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold border transition-all hover:scale-105 shadow-sm ${chip.bg}`}
                  title={`Thread #${index + 1}: ${chip.label}`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${chip.dot}`} />
                  <span>#{index + 1}:</span>
                  <span>{chip.label}</span>
                </div>
              );
            })
          ) : (
            // Visual placeholder chips for planned burst
            Array.from({ length: Math.min(count, 8) }).map((_, idx) => (
              <div
                key={idx}
                className="flex items-center gap-1.5 px-2 py-1 rounded text-xs font-mono bg-[#0f1424] text-slate-400 border border-slate-700/60"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400/60 animate-ping" />
                <span>Thread #{idx + 1} (Burst)</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Analysis Diagnostic Box */}
      {stats && (
        <div
          className={`p-2.5 rounded-lg text-xs font-mono flex items-start gap-2 border ${
            stats.isRaceVulnerability
              ? "bg-rose-950/30 border-rose-700/60 text-rose-200"
              : "bg-emerald-950/20 border-emerald-700/50 text-emerald-200"
          }`}
        >
          {stats.isRaceVulnerability ? (
            <>
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-rose-300 block">Critical TOCTOU Finding:</strong>
                <span>
                  {stats.successes} concurrent requests succeeded simultaneously. The endpoint lacks atomic transaction
                  isolation (e.g. `SELECT FOR UPDATE` or optimistic concurrency checks), permitting double-spending or duplicate state transitions.
                </span>
              </div>
            </>
          ) : (
            <>
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-emerald-300 block">Concurrency Gate Passed:</strong>
                <span>
                  Exactly {stats.successes} request succeeded while other concurrent attempts were rejected with HTTP {stats.conflicts > 0 ? "409 Conflict" : "429/400"}. Database concurrency boundaries are properly enforced.
                </span>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
