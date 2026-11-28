//! Contextual Taint Tracing Juror & Remediation Diffs.
//!
//! Evaluates candidate defects and test failures using Source -> Sink taint reflection.
//!
//! The juror is an *opinion* (a model's, or a pattern matcher's). Reproduction is a measurement.
//! So an opinion can downgrade or annotate a finding, but it can never delete one that
//! reproduced: see [`audit_defects_with_juror`], where evidence-backed defects survive a
//! false-positive verdict and the disagreement is recorded instead.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::super::types::{CaseExecutionResult, TriagedDefect};
use crate::agent::prompts::juror::{
    build_taint_juror_system_prompt, build_taint_juror_user_prompt,
};
use crate::llm::untrusted::{self, clean_output, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed};

/// Provenance label on a diff that came from the model, not from a fixer that read the file.
pub const MODEL_PATCH_LABEL: &str = "# model-proposed patch — written from the recorded response and a source snippet; verify it against the file";

const JUROR_ROLE: &str = "You are a principal application security verifier and Contextual Taint Tracing Juror. \
Analyze the security test failure, candidate defect, and source-to-sink taint propagation. \
Call a false positive ONLY where the evidence shows input was harmlessly handled, properly validated, or failed without security impact; if the evidence is insufficient to judge, say so with \"evaluated\": false and confidence 0 instead of guessing. \
For true positives, trace the taint path from input source to vulnerable sink and write a concise explanation. Do not invent a unified diff: you have not read the file. \
Format: {\"is_true_positive\": bool, \"confidence\": int, \"evaluated\": bool, \"taint_path\": string|null, \"remediation_diff\": string|null, \"explanation\": string}";

/// Juror evaluation verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JurorVerdict {
    pub is_true_positive: bool,
    /// The model's or heuristic's own 0..=100 confidence. Never a harness measurement, and
    /// therefore never able to overrule a failure that reproduced under k-replay.
    pub confidence: u32,
    /// False when the juror reached no evidence-backed conclusion. Distinct from
    /// `is_true_positive: false`, which is an affirmative false-positive finding.
    #[serde(default = "default_evaluated")]
    pub evaluated: bool,
    #[serde(default)]
    pub taint_path: Option<String>,
    #[serde(default)]
    pub remediation_diff: Option<String>,
    #[serde(default)]
    pub explanation: Option<String>,
}

fn default_evaluated() -> bool {
    true
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

    let mut verdict: JurorVerdict = serde_json::from_str(json_str)?;
    verdict.confidence = verdict.confidence.min(100);
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
        evaluated: out.evaluated,
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
            evaluated: true,
            taint_path: None,
            remediation_diff: None,
            explanation: Some(
                "Input was rejected or harmlessly processed without propagating to a vulnerable sink."
                    .into(),
            ),
        };
    }

    // 2. True positive taint reflection checks.
    //
    // The deterministic juror has NOT read the target's source: `source_context` is a `file:line`
    // pointer produced by AST analysis. A unified diff claims to apply to real lines of a real
    // file, so emitting one here would be fabrication. The verdict therefore reports the taint
    // path and the class of fix, and leaves `remediation_diff` to the verified Fixer pipeline
    // (`agent::remediation`), which reads the file before proposing a patch.
    let _ = context;

    // SQL Injection / Database error disclosure
    if contains_sql_leak(&combined_response) {
        return JurorVerdict {
            is_true_positive: true,
            confidence: 96,
            evaluated: true,
            taint_path: Some("Source: request parameter -> Sink: SQL query execution".into()),
            remediation_diff: None,
            explanation: Some(
                "Unsanitized input propagates directly into raw database query. Parameterize SQL statements."
                    .into(),
            ),
        };
    }

    // Reflected Cross-Site Scripting (XSS)
    if contains_injection_reflection(&combined_response) {
        return JurorVerdict {
            is_true_positive: true,
            confidence: 94,
            evaluated: true,
            taint_path: Some("Source: user payload -> Sink: unescaped HTML reflection".into()),
            remediation_diff: None,
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
        return JurorVerdict {
            is_true_positive: true,
            confidence: 92,
            evaluated: true,
            taint_path: Some("Source: unauthenticated/unauthorized request -> Sink: protected resource data exposure".into()),
            remediation_diff: None,
            explanation: Some(
                "Endpoint serves protected resource without enforcing tenant or role authorization guards."
                    .into(),
            ),
        };
    }

    // Unhandled Server Error / Stack Trace Disclosure
    if status_code >= 500 || contains_stack_trace(&combined_response) {
        return JurorVerdict {
            is_true_positive: true,
            confidence: 88,
            evaluated: true,
            taint_path: Some("Source: malformed input -> Sink: unhandled crash / error stack disclosure".into()),
            remediation_diff: None,
            explanation: Some(
                "Malformed request causes unhandled server exception disclosing internal details. Validate inputs and handle exceptions gracefully."
                    .into(),
            ),
        };
    }

    // Nothing matched a source->sink pattern. This is NOT a false positive and it is not an
    // adjudicated true positive either: the finding stays as reported, at zero juror confidence,
    // with `evaluated: false` so no caller can read it as a verdict.
    JurorVerdict {
        is_true_positive: true,
        confidence: 0,
        evaluated: false,
        taint_path: None,
        remediation_diff: None,
        explanation: Some(
            "No source-to-sink pattern matched the recorded response; the finding is kept as              reported and was not adjudicated by the juror."
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
/// What [`audit_defects_with_juror`] did, reported separately because they mean different things
/// to a reader of the report.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JurorAudit {
    /// Findings removed, because nothing about them ever produced a measurement.
    pub eliminated: usize,
    /// Evidence-backed findings the juror called a false positive. Kept, with the disagreement
    /// recorded on the defect.
    pub disagreed: usize,
    /// Findings the juror could not adjudicate (no matching result, or an explicit
    /// "insufficient evidence" verdict).
    pub not_evaluated: usize,
}

/// True when something about the finding was *measured* rather than asserted: the independent
/// verifier ran it, it reproduced (possibly flakily), or raw evidence was captured.
///
/// This is the line the juror may not cross. Model disagreement is an opinion; these are
/// observations about the target. Deleting an observed failure on the strength of an opinion is
/// how a scanner quietly loses real vulnerabilities.
fn evidence_backed(defect: &TriagedDefect) -> bool {
    defect.verified
        || defect.reproduced.is_some()
        || matches!(
            defect.verification.as_deref(),
            Some("confirmed") | Some("flaky")
        )
        || !defect.evidence_files.is_empty()
}

/// Adjudicate candidate defects with the juror.
///
/// A false-positive verdict may remove a finding that was never reproduced. It may **not** remove
/// one that was: that finding is kept and carries the disagreement in `juror_opinion`, so a human
/// can see both the reproduced failure and the doubt about it.
pub fn audit_defects_with_juror(
    mut llm: Option<(&LlmConfig, &mut Budget)>,
    defects: Vec<TriagedDefect>,
    results: &[CaseExecutionResult],
) -> (Vec<TriagedDefect>, JurorAudit) {
    let mut kept = Vec::with_capacity(defects.len());
    let mut audit = JurorAudit::default();

    for mut defect in defects {
        let matching_result = results
            .iter()
            .find(|r| defect.case_ids.iter().any(|cid| cid == &r.case_id))
            .or_else(|| {
                results
                    .iter()
                    .find(|r| r.component == defect.component && r.status == "FAIL")
            });

        let Some(res) = matching_result else {
            audit.not_evaluated += 1;
            kept.push(defect);
            continue;
        };

        let llm_ref = llm.as_mut().map(|(c, b)| (*c, &mut **b));
        let verdict = evaluate_with_juror(llm_ref, res, defect.source_context.as_deref());
        defect.juror_evaluated = verdict.evaluated;

        if !verdict.evaluated {
            audit.not_evaluated += 1;
        } else if !verdict.is_true_positive {
            let confident = verdict.confidence >= 80;
            if evidence_backed(&defect) {
                // Reproduced, and the juror disagrees. Record it; do not delete it.
                if confident {
                    audit.disagreed += 1;
                    defect.juror_opinion = Some(format!(
                        "juror: possible false positive ({}% confidence, judged from the recorded                          response only) — kept because the failure was reproduced with                          evidence. {}",
                        verdict.confidence,
                        verdict.explanation.as_deref().unwrap_or("No reason given.")
                    ));
                }
            } else if confident {
                audit.eliminated += 1;
                continue;
            } else {
                audit.not_evaluated += 1;
            }
        }

        // Only an adjudicated true positive can supply remediation text, and only a model that
        // was actually given source can supply a diff.
        if verdict.is_true_positive && verdict.evaluated {
            if let Some(diff) = verdict.remediation_diff
                && defect.source_context.is_some()
            {
                defect.remediation_patch = Some(format!(
                    "{MODEL_PATCH_LABEL}\n{}",
                    clean_output(&diff, 1000)
                ));
            }
            if let Some(exp) = verdict.explanation {
                defect.remediation_explanation = Some(clean_output(&exp, 600));
            }
        }

        kept.push(defect);
    }

    (kept, audit)
}
