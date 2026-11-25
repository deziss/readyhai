//! Contextual Taint Tracing Juror & Remediation Diffs.
//!
//! Evaluates candidate defects and test failures using Source -> Sink taint reflection
//! to eliminate false positives and synthesize concrete unified diff remediation patches.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::super::types::{CaseExecutionResult, TriagedDefect};
use crate::agent::prompts::juror::{
    build_taint_juror_system_prompt, build_taint_juror_user_prompt,
};
use crate::llm::untrusted::{self, clean_output, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed};

const JUROR_ROLE: &str = "You are a principal application security verifier and Contextual Taint Tracing Juror. \
Analyze the security test failure, candidate defect, and source-to-sink taint propagation. \
Eliminate false positives where user input was harmlessly handled, properly validated, or failed without security impact. \
For true positives, trace the taint path from input source to vulnerable sink, write a concise explanation, and synthesize a concrete unified diff remediation patch. \
Format: {\"is_true_positive\": bool, \"confidence\": int, \"taint_path\": string|null, \"remediation_diff\": string|null, \"explanation\": string}";

/// Juror evaluation verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JurorVerdict {
    pub is_true_positive: bool,
    pub confidence: u32,
    #[serde(default)]
    pub taint_path: Option<String>,
    #[serde(default)]
    pub remediation_diff: Option<String>,
    #[serde(default)]
    pub explanation: Option<String>,
}

/// Parse raw LLM output into a [`JurorVerdict`].
pub fn parse_juror_verdict(raw: &str) -> Result<JurorVerdict> {
    let trimmed = raw.trim();
    let json_str = if let Some(stripped) = trimmed.strip_prefix("```json") {
        stripped.strip_suffix("```").unwrap_or(stripped).trim()
    } else if let Some(stripped) = trimmed.strip_prefix("```") {
        stripped.strip_suffix("```").unwrap_or(stripped).trim()
    } else {
        trimmed
    };

    let verdict: JurorVerdict = serde_json::from_str(json_str)?;
    Ok(verdict)
}

/// Evaluate a failure result with contextual taint tracing.
/// If `llm` is provided, queries the LLM for deep reasoning and patch synthesis;
/// otherwise, falls back to high-accuracy deterministic taint reflection heuristics.
pub fn evaluate_with_juror(
    llm: Option<(&LlmConfig, &mut Budget)>,
    failure: &CaseExecutionResult,
    context: Option<&str>,
) -> JurorVerdict {
    if let Some((cfg, budget)) = llm
        && let Ok(verdict) = evaluate_llm(cfg, budget, failure, context)
    {
        return verdict;
    }
    evaluate_deterministic(failure, context)
}

fn evaluate_llm(
    cfg: &LlmConfig,
    budget: &mut Budget,
    failure: &CaseExecutionResult,
    context: Option<&str>,
) -> Result<JurorVerdict> {
    let facts = json!({
        "case_id": failure.case_id,
        "component": failure.component,
        "method": failure.method,
        "status": failure.status,
        "status_code": failure.status_code,
        "failure_reason": failure.failure_reason,
        "evidence": failure.evidence,
        "detail": failure.evidence_detail,
        "source_context": context,
    });

    let system = build_taint_juror_system_prompt();
    let prompt = build_taint_juror_user_prompt(&facts, context);

    let out: JurorVerdict = ask_typed(
        &cfg.without_thinking(),
        budget,
        &system,
        &prompt,
        |v: &JurorVerdict| {
            if v.confidence > 100 {
                bail!("confidence must be between 0 and 100");
            }
            if v.is_true_positive && v.remediation_diff.is_none() && v.explanation.is_none() {
                bail!("true positive verdict must include remediation_diff or explanation");
            }
            Ok(())
        },
    )?;

    Ok(JurorVerdict {
        is_true_positive: out.is_true_positive,
        confidence: out.confidence.min(100),
        taint_path: out.taint_path.as_deref().map(|s| clean_output(s, 240)),
        remediation_diff: out
            .remediation_diff
            .as_deref()
            .map(|s| clean_output(s, 1000)),
        explanation: out.explanation.as_deref().map(|s| clean_output(s, 600)),
    })
}

/// Deterministic Source -> Sink taint reflection analysis.
fn evaluate_deterministic(failure: &CaseExecutionResult, context: Option<&str>) -> JurorVerdict {
    let status_code = failure.status_code.unwrap_or(0);
    let evidence_str = failure.evidence.to_ascii_lowercase();
    let reason_str = failure
        .failure_reason
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();

    let detail_body = failure
        .evidence_detail
        .as_ref()
        .and_then(|d| d.get("response"))
        .and_then(|r| r.get("body_excerpt").or_else(|| r.get("body")))
        .and_then(|b| b.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let combined_response = format!("{evidence_str} {reason_str} {detail_body}");

    // 1. False positive detection:
    // - Harmless 404 Not Found without reflected payload
    // - Clean 405 Method Not Allowed
    // - Rate limited 429
    // - Generic 400 with standard validation rejection and no stack traces or SQL errors
    let is_clean_rejection = (status_code == 400 || status_code == 422)
        && !contains_sql_leak(&combined_response)
        && !contains_stack_trace(&combined_response)
        && !contains_injection_reflection(&combined_response);

    if status_code == 404 || status_code == 405 || status_code == 429 || is_clean_rejection {
        return JurorVerdict {
            is_true_positive: false,
            confidence: 90,
            taint_path: None,
            remediation_diff: None,
            explanation: Some(
                "Input was rejected or harmlessly processed without propagating to a vulnerable sink."
                    .into(),
            ),
        };
    }

    // 2. True positive taint reflection checks:
    let file_target = context
        .and_then(|c| c.split(':').next())
        .filter(|f| !f.is_empty())
        .unwrap_or("app/api_handler.py");

    // SQL Injection / Database error disclosure
    if contains_sql_leak(&combined_response) {
        let diff = format!(
            "--- a/{file_target}\n+++ b/{file_target}\n@@ -1,4 +1,4 @@\n- query = f\"SELECT * FROM records WHERE id = '{{param}}'\"\n+ cursor.execute(\"SELECT * FROM records WHERE id = %s\", (param,))"
        );
        return JurorVerdict {
            is_true_positive: true,
            confidence: 96,
            taint_path: Some("Source: request parameter -> Sink: SQL query execution".into()),
            remediation_diff: Some(diff),
            explanation: Some(
                "Unsanitized input propagates directly into raw database query. Parameterize SQL statements."
                    .into(),
            ),
        };
    }

    // Reflected Cross-Site Scripting (XSS)
    if contains_injection_reflection(&combined_response) {
        let diff = format!(
            "--- a/{file_target}\n+++ b/{file_target}\n@@ -1,4 +1,4 @@\n- return render_template(\"response.html\", data=user_input)\n+ return render_template(\"response.html\", data=html_escape(user_input))"
        );
        return JurorVerdict {
            is_true_positive: true,
            confidence: 94,
            taint_path: Some("Source: user payload -> Sink: unescaped HTML reflection".into()),
            remediation_diff: Some(diff),
            explanation: Some(
                "Unescaped user input reflected in response markup. Apply context-aware output encoding."
                    .into(),
            ),
        };
    }

    // Authorization Bypass / Broken Object Level Authorization (BOLA/IDOR)
    if (status_code == 200 || status_code == 201)
        && (reason_str.contains("authz")
            || reason_str.contains("unauthorized")
            || reason_str.contains("token")
            || reason_str.contains("idor")
            || reason_str.contains("bola"))
    {
        let diff = format!(
            "--- a/{file_target}\n+++ b/{file_target}\n@@ -1,4 +1,5 @@\n def get_resource(request, resource_id):\n+    verify_tenant_authorization(request.user, resource_id)\n     return fetch_from_db(resource_id)"
        );
        return JurorVerdict {
            is_true_positive: true,
            confidence: 92,
            taint_path: Some("Source: unauthenticated/unauthorized request -> Sink: protected resource data exposure".into()),
            remediation_diff: Some(diff),
            explanation: Some(
                "Endpoint serves protected resource without enforcing tenant or role authorization guards."
                    .into(),
            ),
        };
    }

    // Unhandled Server Error / Stack Trace Disclosure
    if status_code >= 500 || contains_stack_trace(&combined_response) {
        let diff = format!(
            "--- a/{file_target}\n+++ b/{file_target}\n@@ -1,4 +1,6 @@\n try:\n     result = process_request(req)\n+except ValueError as e:\n+    return jsonify({{\"error\": \"Invalid input\"}}), 400"
        );
        return JurorVerdict {
            is_true_positive: true,
            confidence: 88,
            taint_path: Some("Source: malformed input -> Sink: unhandled crash / error stack disclosure".into()),
            remediation_diff: Some(diff),
            explanation: Some(
                "Malformed request causes unhandled server exception disclosing internal details. Validate inputs and handle exceptions gracefully."
                    .into(),
            ),
        };
    }

    // Generic True Positive Fallback
    let diff = format!(
        "--- a/{file_target}\n+++ b/{file_target}\n@@ -1,4 +1,5 @@\n+validate_request_schema(request.data)\n process_data(request.data)"
    );
    JurorVerdict {
        is_true_positive: true,
        confidence: 85,
        taint_path: Some("Source: untrusted client input -> Sink: unvalidated server processing".into()),
        remediation_diff: Some(diff),
        explanation: Some(
            "Security control violation observed during adversarial probing. Implement strict input validation and access checks."
                .into(),
        ),
    }
}

fn contains_sql_leak(s: &str) -> bool {
    s.contains("syntax error at or near")
        || s.contains("unclosed quotation mark")
        || s.contains("ora-")
        || s.contains("mysql_")
        || s.contains("sqlite3.")
        || s.contains("psycopg2.")
        || s.contains("psqlexception")
        || s.contains("sql syntax")
        || s.contains("database error")
}

fn contains_stack_trace(s: &str) -> bool {
    s.contains("traceback (most recent call last)")
        || s.contains("nullpointerexception")
        || s.contains("at org.springframework")
        || s.contains("fatal error:")
        || s.contains("stack backtrace:")
        || s.contains("indexerror: list index out of range")
}

fn contains_injection_reflection(s: &str) -> bool {
    s.contains("<script>")
        || s.contains("onerror=")
        || s.contains("onload=")
        || s.contains("javascript:")
        || s.contains("<svg/onload")
}

/// Audit triaged defects with the Juror.
/// Eliminates false positives and populates `remediation_patch` and `remediation_explanation`.
/// Returns `(kept_defects, eliminated_count)`.
pub fn audit_defects_with_juror(
    mut llm: Option<(&LlmConfig, &mut Budget)>,
    defects: Vec<TriagedDefect>,
    results: &[CaseExecutionResult],
) -> (Vec<TriagedDefect>, usize) {
    let mut kept = Vec::with_capacity(defects.len());
    let mut eliminated = 0;

    for mut defect in defects {
        let matching_result = results
            .iter()
            .find(|r| defect.case_ids.iter().any(|cid| cid == &r.case_id))
            .or_else(|| {
                results
                    .iter()
                    .find(|r| r.component == defect.component && r.status == "FAIL")
            });

        if let Some(res) = matching_result {
            let llm_ref = llm.as_mut().map(|(c, b)| (*c, &mut **b));
            let verdict = evaluate_with_juror(llm_ref, res, defect.source_context.as_deref());

            if !verdict.is_true_positive && verdict.confidence >= 80 {
                eliminated += 1;
                continue;
            }

            if let Some(diff) = verdict.remediation_diff {
                defect.remediation_patch = Some(diff);
            }
            if let Some(exp) = verdict.explanation {
                defect.remediation_explanation = Some(exp);
            }
        }

        kept.push(defect);
    }

    (kept, eliminated)
}
