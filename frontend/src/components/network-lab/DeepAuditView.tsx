import React from "react";
import {
  Globe,
  RotateCw,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Network,
  FileCode,
  Layers,
  Lock,
  Unlock,
  Flame,
} from "lucide-react";
import type { DeepAuditReport } from "@/types/network";
import type { DeepAuditEntry } from "@/lib/deepAuditCache";
import {
  BTN_PRIMARY,
  CHIP,
  FOCUS,
  INPUT_CLS,
  KV_ROW,
  PANEL,
  PILLAR_TITLE,
  sentence,
} from "./types";

interface DeepAuditViewProps {
  target: string;
  setTarget: (target: string) => void;
  isDeepAuditRunning: boolean;
  deepAuditError: string | null;
  deepAuditReport: DeepAuditReport | null;
  deepAuditEntry: DeepAuditEntry | null;
  showRemediation: boolean;
  setShowRemediation: (show: boolean) => void;
  onRunDeepAudit: () => void;
}

export function DeepAuditView({
  target,
  setTarget,
  isDeepAuditRunning,
  deepAuditError,
  deepAuditReport,
  deepAuditEntry,
  showRemediation,
  setShowRemediation,
  onRunDeepAudit,
}: DeepAuditViewProps) {
  return (
    <div className="space-y-6">
      {/* Target and action bar */}
      <div className="flex flex-wrap items-center gap-3 p-2.5 rounded-[10px] bg-rh-surface border border-rh-line">
        <div className="relative flex-1 min-w-[16rem]">
          <Globe className="w-4 h-4 text-rh-muted absolute left-3 top-2.5" aria-hidden="true" />
          <input
            id="input-deep-audit-target"
            type="text"
            aria-label="Target URL"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://app.example.com"
            className={`w-full pl-9 pr-3 py-2 font-mono ${INPUT_CLS}`}
          />
        </div>

        <button
          id="btn-run-deep-audit"
          type="button"
          onClick={onRunDeepAudit}
          disabled={isDeepAuditRunning}
          className={`${BTN_PRIMARY} shrink-0`}
        >
          {isDeepAuditRunning ? (
            <>
              <RotateCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
              <span>Auditing 6 pillars...</span>
            </>
          ) : (
            <>
              <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Run complete deep audit</span>
            </>
          )}
        </button>
      </div>

      {/* Health banner, live progress, or launch prompt */}
      {isDeepAuditRunning ? (
        <div role="status" className="p-7 rounded-[10px] bg-rh-surface border border-rh-line text-center space-y-4">
          <RotateCw className="w-7 h-7 text-rh-info animate-spin mx-auto" aria-hidden="true" />
          <div className="space-y-1">
            <h3 className="text-base font-semibold text-rh-text flex items-center justify-center gap-2 flex-wrap">
              <span>Probing all 6 network and protocol pillars</span>
              <span className="text-xs font-normal font-mono text-rh-text bg-rh-raised px-2 py-0.5 rounded-[6px] break-all">
                {target}
              </span>
            </h3>
            <p className="text-xs text-rh-muted max-w-lg mx-auto">
              Running parallel protocol sweeps: IPv4/IPv6 Happy Eyeballs, sub-resource cascade, HTTP/2 ALPN, TLS 1.3 chain, CORS preflight and path MTU black holes. This usually takes 4 to 8 seconds.
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 gap-2 max-w-xl mx-auto pt-2 text-left text-xs">
            {[
              "IPv4 / IPv6 Happy Eyeballs",
              "Sub-resource cascade",
              "HTTP/2 and HTTP/3 matrix",
              "TLS 1.3 chain check",
              "CORS preflight check",
              "MTU size sweep",
            ].map((label, i) => (
              <div key={label} className="p-2 rounded-[6px] bg-rh-bg border border-rh-line flex items-center gap-2 text-rh-text">
                <span className="w-1.5 h-1.5 rounded-full bg-rh-info shrink-0" aria-hidden="true" />
                <span>{i + 1}. {label}</span>
              </div>
            ))}
          </div>
        </div>
      ) : deepAuditError ? (
        <div role="alert" className="p-6 rounded-[10px] bg-rh-surface border border-rh-line border-l-4 border-l-rh-nogo space-y-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rh-nogo shrink-0" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-rh-text">The deep audit did not complete</h3>
          </div>
          <p className="text-xs text-rh-text break-words">{deepAuditError}</p>
          <p className="text-xs text-rh-muted">
            Check that the target URL is reachable from the ReadyHai backend, then retry.
          </p>
          <button
            type="button"
            onClick={onRunDeepAudit}
            className={BTN_PRIMARY}
          >
            Retry audit
          </button>
        </div>
      ) : deepAuditReport ? (
        <div className={`p-5 rounded-[10px] bg-rh-surface border border-rh-line border-l-4 space-y-4 ${
          deepAuditReport.overall_verdict === "PASS"
            ? "border-l-rh-go"
            : deepAuditReport.overall_verdict === "WARN"
            ? "border-l-rh-cond"
            : deepAuditReport.overall_verdict === "FAIL"
            ? "border-l-rh-nogo"
            : "border-l-rh-line"
        }`}>
          {/* Verdict, evaluated target and health score */}
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="space-y-1.5 min-w-0 flex-1">
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className={`px-2.5 py-0.5 rounded-[6px] text-xs font-semibold ${
                  deepAuditReport.overall_verdict === "PASS" ? "bg-rh-go/15 text-rh-go" :
                  deepAuditReport.overall_verdict === "WARN" ? "bg-rh-cond/15 text-rh-cond" :
                  deepAuditReport.overall_verdict === "FAIL" ? "bg-rh-nogo/15 text-rh-nogo" :
                  "bg-rh-raised text-rh-muted"
                }`}>
                  Verdict: {sentence(deepAuditReport.overall_verdict) || "not evaluated"}
                </span>
                <span className="text-xs text-rh-muted truncate max-w-sm">
                  Evaluated <span className="font-mono">{deepAuditReport.target}</span>
                  {deepAuditEntry && ` · audited ${new Date(deepAuditEntry.ts).toLocaleString()}`}
                </span>
              </div>
              <p className="text-sm font-semibold text-rh-text leading-relaxed">
                {deepAuditReport.executive_summary}
              </p>
            </div>

            <div className="flex flex-col items-center justify-center p-3 px-5 rounded-[10px] bg-rh-bg border border-rh-line shrink-0">
              <span className="text-xs text-rh-muted">Health score</span>
              <span className={`text-3xl font-semibold tabular-nums ${
                deepAuditReport.health_score >= 90 ? "text-rh-go" :
                deepAuditReport.health_score >= 70 ? "text-rh-cond" : "text-rh-nogo"
              }`}>
                {deepAuditReport.health_score}
                <span className="text-sm text-rh-muted font-normal">/100</span>
              </span>
            </div>
          </div>

          {/* Identified risks */}
          {deepAuditReport.identified_risks.length > 0 && (
            <div className="pt-3 border-t border-rh-line space-y-2">
              <div className="flex items-center gap-2 text-rh-text text-xs font-semibold">
                <ShieldAlert className="w-3.5 h-3.5 text-rh-nogo" aria-hidden="true" />
                <span>Identified flakiness and network risks ({deepAuditReport.identified_risks.length})</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {deepAuditReport.identified_risks.map((risk, idx) => (
                  <div key={idx} className="flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] bg-rh-nogo/15 text-xs text-rh-nogo">
                    <span className="w-1.5 h-1.5 rounded-full bg-rh-nogo shrink-0" aria-hidden="true" />
                    <span>{risk}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Expandable remediation */}
          {deepAuditReport.remediation_checklist.length > 0 && (
            <div className="pt-3 border-t border-rh-line">
              <button
                type="button"
                onClick={() => setShowRemediation(!showRemediation)}
                aria-expanded={showRemediation}
                className={`flex items-center gap-2 text-xs font-medium text-rh-text hover:text-rh-primary transition-colors cursor-pointer rounded-[6px] ${FOCUS}`}
              >
                {showRemediation ? <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" /> : <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />}
                <span>{showRemediation ? "Hide" : "Show"} remediation steps ({deepAuditReport.remediation_checklist.length} actions)</span>
              </button>

              {showRemediation && (
                <ol className="mt-2.5 space-y-1.5 pl-8 list-decimal text-xs text-rh-text bg-rh-bg p-3 rounded-[6px] border border-rh-line">
                  {deepAuditReport.remediation_checklist.map((rem, idx) => (
                    <li key={idx} className="leading-relaxed">{rem}</li>
                  ))}
                </ol>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="p-8 rounded-[10px] bg-rh-surface border border-dashed border-rh-line text-center space-y-3">
          <Network className="w-10 h-10 text-rh-muted mx-auto" aria-hidden="true" />
          <h3 className="text-base font-semibold text-rh-text">No deep audit yet for this target</h3>
          <p className="text-xs text-rh-muted max-w-md mx-auto">
            The audit checks IPv4 vs IPv6 Happy Eyeballs, the sub-resource cascade (MIME and SPA fallbacks), HTTP/1.1 vs HTTP/2 vs HTTP/3, the TLS certificate chain, CORS preflight and MTU black holes.
          </p>
          <button
            type="button"
            onClick={onRunDeepAudit}
            disabled={isDeepAuditRunning}
            className={BTN_PRIMARY}
          >
            Run 6-pillar audit
          </button>
        </div>
      )}

      {/* The 6 pillars */}
      {deepAuditReport && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* Pillar 1: dual-stack IPv4 vs IPv6 */}
          <div className={`${PANEL} space-y-3`}>
            <div className="flex items-center justify-between gap-2">
              <span className={PILLAR_TITLE}>
                <Globe className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                <span>1. Dual-stack and Happy Eyeballs</span>
              </span>
              <span className={`${CHIP} ${
                deepAuditReport.dual_stack.happy_eyeballs_risk ? "bg-rh-nogo/15 text-rh-nogo" :
                deepAuditReport.dual_stack.has_ipv4 ? "bg-rh-go/15 text-rh-go" : "bg-rh-raised text-rh-muted"
              }`}>
                {deepAuditReport.dual_stack.ipv6_status}
              </span>
            </div>

            <div className="space-y-2 text-xs text-rh-text">
              <div className={KV_ROW}>
                <span className="text-rh-muted">IPv4 address</span>
                <span className="text-rh-text font-mono tabular-nums">{deepAuditReport.dual_stack.ipv4_addresses[0] || "None"}</span>
              </div>
              <div className={KV_ROW}>
                <span className="text-rh-muted">IPv4 latency</span>
                <span className="text-rh-text tabular-nums">{deepAuditReport.dual_stack.ipv4_latency_ms ?? "--"}ms</span>
              </div>
              <div className={KV_ROW}>
                <span className="text-rh-muted">IPv6 AAAA record</span>
                <span className={`font-mono break-all text-right ${deepAuditReport.dual_stack.has_ipv6 ? "text-rh-text" : "text-rh-muted font-sans"}`}>
                  {deepAuditReport.dual_stack.has_ipv6 ? deepAuditReport.dual_stack.ipv6_addresses[0] : "None published"}
                </span>
              </div>
            </div>
            <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
              {deepAuditReport.dual_stack.diagnosis}
            </p>
          </div>

          {/* Pillar 2: sub-resource cascade and SPA mismatch */}
          <div className={`${PANEL} space-y-3`}>
            <div className="flex items-center justify-between gap-2">
              <span className={PILLAR_TITLE}>
                <FileCode className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                <span>2. Sub-resource cascade (SPA and assets)</span>
              </span>
              <span className={`${CHIP} tabular-nums ${
                deepAuditReport.subresources.spa_fallback_mismatches > 0 ? "bg-rh-nogo/15 text-rh-nogo" :
                deepAuditReport.subresources.broken_count > 0 ? "bg-rh-cond/15 text-rh-cond" :
                "bg-rh-go/15 text-rh-go"
              }`}>
                {deepAuditReport.subresources.successful_count}/{deepAuditReport.subresources.total_discovered} OK
              </span>
            </div>

            <div className="space-y-2 text-xs text-rh-text">
              <div className={KV_ROW}>
                <span className="text-rh-muted">Total assets probed</span>
                <span className="text-rh-text tabular-nums">{deepAuditReport.subresources.total_discovered} files ({deepAuditReport.subresources.total_size_kb.toFixed(1)} KB)</span>
              </div>
              <div className={KV_ROW}>
                <span className="text-rh-muted">Broken assets (4xx/5xx)</span>
                <span className={`tabular-nums ${deepAuditReport.subresources.broken_count > 0 ? "text-rh-nogo font-semibold" : "text-rh-text"}`}>
                  {deepAuditReport.subresources.broken_count}
                </span>
              </div>
              <div className={KV_ROW}>
                <span className="text-rh-muted">SPA fallback mismatch (JS served as HTML)</span>
                <span className={`tabular-nums ${deepAuditReport.subresources.spa_fallback_mismatches > 0 ? "text-rh-nogo font-semibold" : "text-rh-text"}`}>
                  {deepAuditReport.subresources.spa_fallback_mismatches}
                </span>
              </div>
            </div>
            <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
              {deepAuditReport.subresources.diagnosis}
            </p>
          </div>

          {/* Pillar 3: HTTP protocol matrix */}
          <div className={`${PANEL} space-y-3`}>
            <div className="flex items-center justify-between gap-2">
              <span className={PILLAR_TITLE}>
                <Layers className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                <span>3. HTTP protocol matrix</span>
              </span>
              <span className={`${CHIP} bg-rh-raised text-rh-text`}>
                {deepAuditReport.protocol_matrix.active_protocol}
              </span>
            </div>

            <div className="space-y-2 text-xs">
              {deepAuditReport.protocol_matrix.protocols.map((p, idx) => (
                <div key={idx} className="flex items-center justify-between gap-3 px-3 py-2 rounded-[6px] bg-rh-bg">
                  <span className="font-semibold text-rh-text">{p.protocol}</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded-[6px] font-semibold tabular-nums ${
                    p.supported ? "bg-rh-go/15 text-rh-go" : "bg-rh-raised text-rh-muted"
                  }`}>
                    {p.supported ? `Supported (${p.negotiation_time_ms}ms)` : "Unavailable"}
                  </span>
                </div>
              ))}
            </div>
            <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
              {deepAuditReport.protocol_matrix.diagnosis}
            </p>
          </div>

          {/* Pillar 4: TLS and certificate chain */}
          <div className={`${PANEL} space-y-3`}>
            <div className="flex items-center justify-between gap-2">
              <span className={PILLAR_TITLE}>
                {deepAuditReport.tls_chain.is_https ? (
                  <Lock className="w-4 h-4 text-rh-go" aria-hidden="true" />
                ) : (
                  <Unlock className="w-4 h-4 text-rh-cond" aria-hidden="true" />
                )}
                <span>4. TLS and certificate chain</span>
              </span>
              <span className={`${CHIP} bg-rh-raised text-rh-text`}>
                {deepAuditReport.tls_chain.tls_version}
              </span>
            </div>

            <div className="space-y-2 text-xs text-rh-text">
              <div className={KV_ROW}>
                <span className="text-rh-muted">Cipher suite</span>
                <span className="text-rh-text font-mono truncate max-w-[200px]" title={deepAuditReport.tls_chain.cipher}>{deepAuditReport.tls_chain.cipher}</span>
              </div>
              <div className={KV_ROW}>
                <span className="text-rh-muted">Issuer</span>
                <span className="text-rh-text text-right">{deepAuditReport.tls_chain.cert_issuer}</span>
              </div>
              <div className={KV_ROW}>
                <span className="text-rh-muted">Intermediate chain</span>
                <span className={deepAuditReport.tls_chain.is_intermediate_missing ? "text-rh-nogo font-semibold" : "text-rh-text"}>
                  {deepAuditReport.tls_chain.is_intermediate_missing ? "Incomplete bundle" : "Complete"}
                </span>
              </div>
            </div>
            <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
              {deepAuditReport.tls_chain.diagnosis}
            </p>
          </div>

          {/* Pillar 5: CORS preflight */}
          <div className={`${PANEL} space-y-3`}>
            <div className="flex items-center justify-between gap-2">
              <span className={PILLAR_TITLE}>
                <ShieldAlert className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                <span>5. CORS preflight boundary (OPTIONS)</span>
              </span>
              <span className={`${CHIP} tabular-nums ${
                deepAuditReport.cors_preflight.preflight_passed ? "bg-rh-go/15 text-rh-go" : "bg-rh-nogo/15 text-rh-nogo"
              }`}>
                HTTP {deepAuditReport.cors_preflight.preflight_status_code}
              </span>
            </div>

            <div className="space-y-2 text-xs text-rh-text">
              <div className={KV_ROW}>
                <span className="text-rh-muted">Allow-Origin</span>
                <span className="text-rh-text font-mono break-all text-right">{deepAuditReport.cors_preflight.allow_origin || "None"}</span>
              </div>
              <div className={KV_ROW}>
                <span className="text-rh-muted">Allow-Methods</span>
                <span className="text-rh-text font-mono break-all text-right">{deepAuditReport.cors_preflight.allow_methods || "None"}</span>
              </div>
              <div className={KV_ROW}>
                <span className="text-rh-muted">Preflight accepted</span>
                <span className={deepAuditReport.cors_preflight.preflight_passed ? "text-rh-go font-semibold" : "text-rh-nogo font-semibold"}>
                  {deepAuditReport.cors_preflight.preflight_passed ? "Yes (200/204)" : "No (blocked)"}
                </span>
              </div>
            </div>
            <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
              {deepAuditReport.cors_preflight.diagnosis}
            </p>
          </div>

          {/* Pillar 6: MTU and packet size sweep */}
          <div className={`${PANEL} space-y-3`}>
            <div className="flex items-center justify-between gap-2">
              <span className={PILLAR_TITLE}>
                <Flame className="w-4 h-4 text-rh-muted" aria-hidden="true" />
                <span>6. MTU and packet black hole sweep</span>
              </span>
              <span className={`${CHIP} tabular-nums ${
                deepAuditReport.mtu_sweep.black_hole_detected ? "bg-rh-nogo/15 text-rh-nogo" : "bg-rh-go/15 text-rh-go"
              }`}>
                Max safe: {deepAuditReport.mtu_sweep.maximum_safe_bytes}B
              </span>
            </div>

            <div className="grid grid-cols-4 gap-2 text-center text-xs">
              {deepAuditReport.mtu_sweep.sweep_results.map((m, idx) => (
                <div key={idx} className={`p-2 rounded-[6px] tabular-nums ${
                  m.success ? "bg-rh-go/15 text-rh-go" : "bg-rh-nogo/15 text-rh-nogo"
                }`}>
                  <div className="font-semibold text-xs">{m.payload_bytes}B</div>
                  <div className="text-xs text-rh-muted">{m.duration_ms}ms</div>
                </div>
              ))}
            </div>
            <p className="text-xs text-rh-muted leading-relaxed pt-2 border-t border-rh-line">
              {deepAuditReport.mtu_sweep.diagnosis}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
