//! Reconnaissance Profiler & Dynamic Directives Prompt Templates.

use super::{
    DIRECTIVES_SYNTHESIZER_ROLE, PromptBuilder, RECON_PROFILER_ROLE, system_with_fencing_preamble,
};

/// JSON schema expected from the dynamic directives synthesis engine.
pub const DIRECTIVES_JSON_SCHEMA: &str = r#"{
  "focus_areas": ["string"],
  "boundary_rules": ["string"],
  "rules_of_engagement": "string",
  "canary_token": "string"
}"#;

/// JSON schema expected from the target reconnaissance profiler.
pub const RECON_PROFILER_JSON_SCHEMA: &str = r#"{
  "server": "string | null",
  "tech_signals": ["string"],
  "missing_security_headers": ["string"],
  "cookies": ["string"],
  "risk_posture": "LOW | MEDIUM | HIGH | CRITICAL",
  "summary": "string"
}"#;

/// Builds the system prompt for dynamic directives synthesis.
pub fn build_directives_system_prompt() -> String {
    let mut sys = system_with_fencing_preamble(DIRECTIVES_SYNTHESIZER_ROLE);
    sys.push_str("\n\nReturn ONLY valid JSON matching this schema:\n");
    sys.push_str(DIRECTIVES_JSON_SCHEMA);
    sys
}

/// Builds the system prompt for target reconnaissance profiling.
pub fn build_recon_profiler_system_prompt() -> String {
    let mut sys = system_with_fencing_preamble(RECON_PROFILER_ROLE);
    sys.push_str("\n\nReturn ONLY valid JSON matching this schema:\n");
    sys.push_str(RECON_PROFILER_JSON_SCHEMA);
    sys
}

/// Builds the user prompt for dynamic directives synthesis using target facts.
pub fn build_directives_user_prompt(
    target: &str,
    tech_signals: &[String],
    missing_headers: &[String],
    cookies: &[String],
    spec_url: Option<&str>,
    canary_token: &str,
    operator_notes: Option<&str>,
) -> String {
    let target_data = serde_json::json!({
        "target": target,
        "tech_signals": tech_signals,
        "missing_security_headers": missing_headers,
        "cookies": cookies,
        "spec_url": spec_url,
    });

    let mut builder = PromptBuilder::new(
        DIRECTIVES_SYNTHESIZER_ROLE,
        "Analyze the target reconnaissance data and synthesize dynamic operational directives, \
        including testing focus areas (e.g. BOLA, IDOR, SQLi, Auth bypass), boundary rules, and rules of engagement.",
    )
    .with_fenced_json("TARGET RECONNAISSANCE DATA", &target_data)
    .with_canary(canary_token)
    .with_guideline("Preserve and output the exact canary_token provided.")
    .with_guideline("Generate at least 3 concrete focus_areas tailored to the detected tech stack.")
    .with_guideline("Define strict boundary_rules to protect non-target systems and avoid irreversible mutations.")
    .with_guideline("Formulate clear rules_of_engagement detailing testing intensity and scope.")
    .with_schema(DIRECTIVES_JSON_SCHEMA);

    if let Some(notes) = operator_notes {
        builder = builder.with_fenced_target("OPERATOR CUSTOM INSTRUCTIONS", notes);
    }

    builder.build_user()
}

/// Builds the user prompt for target reconnaissance profiling.
pub fn build_recon_profiler_user_prompt(
    target: &str,
    headers: &[String],
    body_preview: Option<&str>,
) -> String {
    let mut builder = PromptBuilder::new(
        RECON_PROFILER_ROLE,
        "Analyze the observed HTTP headers and server response body to profile the target's \
        technology stack, server software, defensive header posture, and initial attack surface.",
    )
    .with_fenced_target("TARGET URL", target)
    .with_fenced_json("OBSERVED HEADERS", &serde_json::json!(headers))
    .with_guideline("Identify web servers (nginx, Apache, Caddy, Cloudflare, etc.).")
    .with_guideline("Identify application frameworks (Django, Express, FastAPI, Spring, Laravel, etc.).")
    .with_guideline("List all missing security headers (CSP, HSTS, X-Frame-Options, etc.).")
    .with_schema(RECON_PROFILER_JSON_SCHEMA);

    if let Some(body) = body_preview {
        builder = builder.with_fenced_target_capped("RESPONSE BODY PREVIEW", body, 2000);
    }

    builder.build_user()
}
