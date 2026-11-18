use std::collections::HashSet;
use serde_json::{Value, json};

use super::models::{
    BrowserSecReport, path_of_url, target_url_for_component,
};
use super::redact::redact_secret_preview;
use crate::agent::exec::evidence_rel_path;
use crate::agent::oracle::{OracleCheck, OracleOutcome, Severity, Verdict};
use crate::agent::types::{CaseExecutionResult, PlannedCase, ProbeOracle};
use crate::llm::untrusted::redact_then_truncate;

pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub(crate) fn fail_result_for(
    case: &PlannedCase,
    code: &str,
    severity: Severity,
    detail: String,
    evidence: String,
    repro_curl: String,
    extra_detail: Value,
) -> CaseExecutionResult {
    let outcome = OracleOutcome {
        verdict: Verdict::Fail,
        checks: vec![OracleCheck {
            code: code.to_string(),
            verdict: Verdict::Fail,
            severity: Some(severity),
            detail: detail.clone(),
        }],
        warnings: Vec::new(),
        exploratory: false,
    };
    CaseExecutionResult {
        case_id: case.id.clone(),
        title: case.title.clone(),
        component: case.component.clone(),
        method: case.method.clone(),
        technique: case.technique.clone(),
        status: "FAIL".into(),
        status_code: Some(200),
        latency_ms: 1,
        reproduction_curl: repro_curl,
        request_payload: case.payload.clone(),
        evidence,
        content_type: Some("text/html".into()),
        is_spa_shell: false,
        failure_reason: Some(detail),
        blocked_reason: None,
        expected_status: None,
        oracle: Some(outcome),
        flaky: false,
        attempts: Vec::new(),
        evidence_file: Some(evidence_rel_path(&case.id)),
        evidence_detail: Some(extra_detail),
        stateful_chain: None,
        concurrency_burst_results: None,
        redirect_chain: Vec::new(),
        response_status: Some(200),
        response_body: None,
    }
}

/// Convert a Chromium `agent_browser.mjs` JSON report into planned cases and oracle-backed results.
pub fn results_from_browser_report(
    rep: &BrowserSecReport,
    target: &str,
) -> (Vec<PlannedCase>, Vec<CaseExecutionResult>) {
    let mut cases = Vec::new();
    let mut results = Vec::new();
    let mut dedup: HashSet<(String, String)> = HashSet::new();
    let mut seq = 0usize;

    let mut push_finding = |code: &str,
                            severity: Severity,
                            title: String,
                            component: String,
                            detail: String,
                            evidence: String,
                            probe_oracle: Option<ProbeOracle>,
                            extra_detail: Value| {
        if !dedup.insert((code.to_string(), component.clone())) {
            return;
        }
        seq += 1;
        let id = format!("PW{seq:03}");
        let risk = match severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        };
        let case = PlannedCase {
            id,
            title,
            component: component.clone(),
            method: "GET".into(),
            technique: "browser_security".into(),
            input_hint: format!("Verified in headless Chromium ({code})"),
            payload: None,
            headers: Vec::new(),
            content_type: None,
            probe_oracle,
            expected_behavior: format!("Client/browser security control '{code}' must hold"),
            expected_status: None,
            risk_level: risk.into(),
            role: Some("anon".into()),
            secured: None,
            route_status: Some(200),
            expect_fields: Vec::new(),
            expected_content_type: None,
            source: Some("playwright_browser_security".into()),
            stateful_steps: None,
            concurrency_burst: None,
            contract: None,
            changed_ops: Vec::new(),
            area: "ui".into(),
            regression_of: Vec::new(),
            history_priority: false,
        };
        let url = target_url_for_component(target, &component);
        let curl = format!("curl -sS {}", shell_quote(&url));
        let res = fail_result_for(
            &case,
            code,
            severity,
            redact_then_truncate(&detail, 260),
            redact_then_truncate(&evidence, 300),
            curl,
            extra_detail,
        );
        cases.push(case);
        results.push(res);
    };

    for hit in &rep.xss_hits {
        let comp = path_of_url(&hit.url);
        let safe_detail = redact_then_truncate(&hit.detail, 200);
        let safe_probe = redact_then_truncate(&hit.probe_url, 220);
        if hit.kind == "stored_xss" {
            push_finding(
                "stored_xss",
                Severity::High,
                format!("Stored XSS executed in Chromium on {comp}"),
                comp,
                format!("Chromium executed stored XSS canary: {safe_detail}"),
                format!("url={safe_probe}; {safe_detail}"),
                None,
                json!({
                    "browser": "chromium",
                    "kind": hit.kind,
                    "id": redact_then_truncate(&hit.id, 64),
                    "probe_url": safe_probe,
                }),
            );
        } else {
            push_finding(
                "dom_xss",
                Severity::High,
                format!("DOM XSS executed in Chromium on {comp} ({})", hit.kind),
                comp,
                format!(
                    "Chromium executed DOM XSS canary via {}: {safe_detail}",
                    hit.kind
                ),
                format!("probe={safe_probe}; {safe_detail}"),
                None,
                json!({
                    "browser": "chromium",
                    "kind": hit.kind,
                    "id": redact_then_truncate(&hit.id, 64),
                    "probe_url": safe_probe,
                }),
            );
        }
    }

    // Only promote sink calls where a test canary/HTML tag actually reached the runtime sink
    // (avoids noisy false positives from bundled frameworks calling `new Function("return this")`).
    for sink in &rep.dom_sinks {
        let low = sink.sample.to_ascii_lowercase();
        let tainted_sample = low.contains("__rh_xss_hit")
            || low.contains("<img")
            || low.contains("<script")
            || low.contains("onerror=")
            || low.contains("javascript:");
        if !tainted_sample {
            continue;
        }
        let comp = path_of_url(&sink.url);
        let safe_sample = redact_then_truncate(&sink.sample, 160);
        push_finding(
            "dom_xss",
            Severity::High,
            format!("Tainted DOM sink `{}` observed on {comp}", sink.sink),
            comp,
            format!(
                "Untrusted/canary input reached `{}` sink in Chromium",
                sink.sink
            ),
            format!("sink={} sample={safe_sample}", sink.sink),
            None,
            json!({
                "browser": "chromium",
                "sink": sink.sink,
                "sample": safe_sample,
            }),
        );
    }

    for leak in &rep.storage_leaks {
        let comp = path_of_url(&leak.url);
        let safe_store = redact_then_truncate(&leak.store, 40);
        let safe_key = redact_then_truncate(&leak.key, 64);
        let safe_kind = redact_then_truncate(&leak.kind, 40);
        let safe_preview = redact_secret_preview(&leak.preview, &safe_kind);
        let sev = if safe_kind.eq_ignore_ascii_case("jwt") {
            Severity::High
        } else {
            Severity::Medium
        };
        push_finding(
            "client_secret_leak",
            sev,
            format!(
                "Sensitive credential exposed in browser {safe_store} (`{safe_key}`) on {comp}"
            ),
            comp,
            format!("Chromium detected `{safe_kind}` (`{safe_key}`) in `{safe_store}`"),
            format!("store={safe_store} key={safe_key} kind={safe_kind} preview={safe_preview}"),
            None,
            json!({
                "browser": "chromium",
                "store": safe_store,
                "key": safe_key,
                "kind": safe_kind,
                "preview": safe_preview,
            }),
        );
    }

    for ck in &rep.cookie_issues {
        if ck.missing.is_empty() {
            continue;
        }
        let comp = path_of_url(&ck.url);
        let safe_name = redact_then_truncate(&ck.name, 64);
        let missing_str = ck.missing.join(", ");
        let sev = if ck
            .missing
            .iter()
            .any(|m| m.eq_ignore_ascii_case("HttpOnly"))
        {
            Severity::Medium
        } else {
            Severity::Low
        };
        push_finding(
            "cookie_hygiene",
            sev,
            format!("Auth/session cookie `{safe_name}` missing flag(s): {missing_str}"),
            comp,
            format!("Cookie `{safe_name}` observed in Chromium without {missing_str}"),
            format!("cookie={safe_name} missing={missing_str}"),
            None,
            json!({
                "browser": "chromium",
                "cookie_name": safe_name,
                "missing": ck.missing,
            }),
        );
    }

    for sm in &rep.sourcemaps {
        let comp = path_of_url(&sm.url);
        push_finding(
            "sourcemap_exposure",
            Severity::Medium,
            format!("JavaScript source map publicly accessible at {comp}"),
            comp,
            format!(
                "Public `.js.map` exposed ({} bytes) allowing full source reconstruction",
                sm.size_bytes
            ),
            format!("sourcemap bytes={}", sm.size_bytes),
            None,
            json!({
                "browser": "chromium",
                "size_bytes": sm.size_bytes,
            }),
        );
    }

    for cj in &rep.clickjacking {
        let comp = path_of_url(&cj.url);
        let safe_reason = redact_then_truncate(&cj.reason, 200);
        push_finding(
            "clickjacking",
            Severity::Medium,
            format!("Page frameable in cross-origin iframe (clickjacking) on {comp}"),
            comp,
            safe_reason.clone(),
            safe_reason,
            None,
            json!({
                "browser": "chromium",
                "frameable": true,
            }),
        );
    }

    (cases, results)
}
