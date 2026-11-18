//! Semantic Discoverer Prompt Templates for Shadow API and Parameter Schema Prediction.

use super::{PromptBuilder, SEMANTIC_DISCOVERER_ROLE, system_with_fencing_preamble};

/// JSON schema expected from the semantic route discoverer.
pub const SEMANTIC_ROUTES_JSON_SCHEMA: &str = r#"[
  {
    "path": "/api/v1/admin/users",
    "method": "GET | POST | PUT | PATCH | DELETE",
    "reasoning": "Reasoning for predicting this shadow route based on tech signals",
    "input_surface": "query | body | header | path | null",
    "suggested_params": ["id", "role", "limit"]
  }
]"#;

/// Builds the system prompt for semantic route discovery.
pub fn build_semantic_discovery_system_prompt() -> String {
    let mut sys = system_with_fencing_preamble(SEMANTIC_DISCOVERER_ROLE);
    sys.push_str("\n\nReturn ONLY a valid JSON array matching this schema:\n");
    sys.push_str(SEMANTIC_ROUTES_JSON_SCHEMA);
    sys
}

/// Builds the user prompt for predicting undocumented shadow endpoints and parameter schemas.
pub fn build_semantic_discovery_user_prompt(
    target: &str,
    architecture: &str,
    framework: &str,
    detected_signals: &[String],
    known_endpoints: &[serde_json::Value],
    focus_areas: &[String],
    limit: usize,
) -> String {
    let tech_facts = serde_json::json!({
        "target": target,
        "architecture": architecture,
        "framework": framework,
        "detected_signals": detected_signals,
        "focus_areas": focus_areas,
    });

    PromptBuilder::new(
        SEMANTIC_DISCOVERER_ROLE,
        format!(
            "Predict up to {} high-probability shadow, actuator, internal, or administrative endpoints \
            and expected parameter schemas characteristic of this technology stack and architecture.",
            limit
        ),
    )
    .with_fenced_json("TARGET TECH PROFILE & DIRECTIVES", &tech_facts)
    .with_fenced_json_capped("SAMPLED KNOWN ENDPOINTS", &serde_json::json!(known_endpoints), 200)
    .with_guideline("Every predicted path must start with a leading slash ('/').")
    .with_guideline("Do NOT duplicate endpoints already listed in known endpoints.")
    .with_guideline("Methods must be valid HTTP verbs (GET, POST, PUT, DELETE, PATCH).")
    .with_guideline("Include suggested parameter schemas for fuzzing input boundaries.")
    .with_schema(SEMANTIC_ROUTES_JSON_SCHEMA)
    .build_user()
}
