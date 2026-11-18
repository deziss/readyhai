//! Contextual Taint Tracing Juror Prompt Templates for False Positive Elimination and Diff Patch Generation.

use super::{PromptBuilder, TAINT_JUROR_ROLE, system_with_fencing_preamble};

/// JSON schema expected from the Contextual Taint Juror.
pub const TAINT_JUROR_JSON_SCHEMA: &str = r#"{
  "is_true_positive": true,
  "confidence": 95,
  "taint_path": "req.query.id -> db.query('SELECT * FROM users WHERE id = ' + id)",
  "remediation_diff": "--- a/src/routes/users.js\n+++ b/src/routes/users.js\n@@ -12,1 +12,1 @@\n- db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n+ db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);",
  "explanation": "Direct interpolation of unsanitized query parameter into SQL query string constitutes exploitable SQL injection."
}"#;

/// Builds the system prompt for the Taint Juror.
pub fn build_taint_juror_system_prompt() -> String {
    let mut sys = system_with_fencing_preamble(TAINT_JUROR_ROLE);
    sys.push_str("\n\nReturn ONLY valid JSON matching this schema:\n");
    sys.push_str(TAINT_JUROR_JSON_SCHEMA);
    sys
}

/// Builds the user prompt for evaluating candidate defects with Source -> Sink taint analysis.
pub fn build_taint_juror_user_prompt(
    failure_facts: &serde_json::Value,
    source_context: Option<&str>,
) -> String {
    let mut builder = PromptBuilder::new(
        TAINT_JUROR_ROLE,
        "Analyze the security test failure, raw HTTP exchange, and candidate defect. \
        Perform Contextual Taint Tracing from input source to vulnerable execution sink. \
        Eliminate false positives where user input was harmlessly handled, properly validated, \
        or failed safely (e.g. clean 400 Bad Request, unprivileged 404, or standard 405). \
        For true positive defects, trace the taint path, explain the root cause, and produce a unified diff patch.",
    )
    .with_fenced_json_capped("SECURITY TEST FAILURE FACTS", failure_facts, 500)
    .with_guideline("Eliminate false positives where no vulnerable sink was reached.")
    .with_guideline("Confidence score must be an integer between 0 and 100.")
    .with_guideline("For true positives, provide a minimal, production-grade unified diff remediation patch.")
    .with_guideline("Ensure the patch fixes the vulnerability without altering intended business logic.")
    .with_schema(TAINT_JUROR_JSON_SCHEMA);

    if let Some(src) = source_context {
        builder = builder.with_fenced_target_capped("SOURCE CODE CONTEXT", src, 3000);
    }

    builder.build_user()
}
