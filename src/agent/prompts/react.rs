//! Adaptive Mutator Prompt Templates for OODA Anomaly Payload Synthesis.

use super::{ADAPTIVE_MUTATOR_ROLE, PromptBuilder, system_with_fencing_preamble};

/// JSON schema expected from the Adaptive Mutator.
pub const ADAPTIVE_MUTATOR_JSON_SCHEMA: &str = r#"{
  "hypothesis": "string explaining root cause hypothesis of observed anomaly",
  "cases": [
    {
      "title": "SQL Injection probe on search query parameter",
      "component": "/api/v1/search",
      "method": "GET",
      "technique": "sqli",
      "input_hint": "q",
      "payload": { "q": "' UNION SELECT 1,2,3--" },
      "expected_behavior": "Should sanitize input and return 400 Bad Request instead of 500 internal database error",
      "risk_level": "high",
      "role": "anonymous"
    }
  ]
}"#;

/// Builds the system prompt for the Adaptive Mutator.
pub fn build_adaptive_mutator_system_prompt() -> String {
    let mut sys = system_with_fencing_preamble(ADAPTIVE_MUTATOR_ROLE);
    sys.push_str("\n\nReturn ONLY valid JSON matching this schema:\n");
    sys.push_str(ADAPTIVE_MUTATOR_JSON_SCHEMA);
    sys
}

/// Builds the user prompt for synthesizing precision mutation probes from observed anomalies.
pub fn build_adaptive_mutator_user_prompt(
    wave: usize,
    known_routes: &[serde_json::Value],
    anomalies: &[serde_json::Value],
    canary_token: Option<&str>,
    max_cases: usize,
) -> String {
    let observation = serde_json::json!({
        "wave": wave,
        "anomalies_count": anomalies.len(),
    });

    let mut builder = PromptBuilder::new(
        ADAPTIVE_MUTATOR_ROLE,
        format!(
            "In wave {}, execution observed HTTP anomalies (e.g. 500 error stack traces, 403 authorization leaks, \
            422 schema validation details, or canary reflections). Formulate an exploitation hypothesis \
            and synthesize up to {} precision mutation follow-up probes.",
            wave, max_cases
        ),
    )
    .with_fenced_json("WAVE EXECUTION METRICS", &observation)
    .with_fenced_json_capped("OBSERVED ANOMALIES & RAW ERROR RESPONSES", &serde_json::json!(anomalies), 400)
    .with_fenced_json_capped("KNOWN ROUTE INVENTORY", &serde_json::json!(known_routes), 150)
    .with_guideline("All proposed cases MUST strictly target known route components.")
    .with_guideline("Use SSTI payload '{{1337*79}}' when server-side template rendering anomalies are observed.")
    .with_guideline("Use '{{OAST_URL}}' when potential out-of-band SSRF or DNS resolution is suspected.")
    .with_guideline("Focus payloads on parameter locations identified in schema validation error details.")
    .with_schema(ADAPTIVE_MUTATOR_JSON_SCHEMA);

    if let Some(canary) = canary_token {
        builder = builder.with_canary(canary);
    }

    builder.build_user()
}
