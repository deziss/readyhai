//! Attack DAG Planner Prompt Templates for Stateful Multi-Step Scenario Synthesis.

use super::{DAG_PLANNER_ROLE, PromptBuilder, system_with_fencing_preamble};

/// JSON schema expected from the DagPlanner.
pub const ATTACK_DAG_JSON_SCHEMA: &str = r#"{
  "nodes": [
    {
      "id": "step_1",
      "dependencies": [],
      "action": "register_low_priv_user",
      "component": "/api/v1/auth/register",
      "method": "POST",
      "payload": { "username": "alice", "role": "user" },
      "expected_status": 201
    },
    {
      "id": "step_2",
      "dependencies": ["step_1"],
      "action": "escalate_privilege_tamper_token",
      "component": "/api/v1/users/alice/role",
      "method": "PATCH",
      "payload": { "role": "admin" },
      "expected_status": 200
    }
  ]
}"#;

/// Builds the system prompt for Attack DAG synthesis.
pub fn build_dag_planner_system_prompt() -> String {
    let mut sys = system_with_fencing_preamble(DAG_PLANNER_ROLE);
    sys.push_str("\n\nReturn ONLY valid JSON matching this schema:\n");
    sys.push_str(ATTACK_DAG_JSON_SCHEMA);
    sys
}

/// Builds the user prompt for synthesizing a stateful Attack DAG workflow.
pub fn build_dag_planner_user_prompt(
    target: &str,
    endpoints: &[serde_json::Value],
    directives: Option<&str>,
    focus_areas: &[String],
    max_nodes: usize,
) -> String {
    let context_data = serde_json::json!({
        "target": target,
        "focus_areas": focus_areas,
    });

    let mut builder = PromptBuilder::new(
        DAG_PLANNER_ROLE,
        format!(
            "Synthesize a stateful Attack DAG containing 3 to {} interdependent attack nodes. \
            Model multi-step privilege escalation, BOLA/IDOR object references, or authentication boundary tampering.",
            max_nodes
        ),
    )
    .with_fenced_json("TARGET CONTEXT & FOCUS AREAS", &context_data)
    .with_fenced_json_capped("DISCOVERED TARGET ENDPOINTS", &serde_json::json!(endpoints), 250)
    .with_guideline("The graph MUST be strictly Directed Acyclic (no dependency cycles or self-loops).")
    .with_guideline("Dependencies must only reference earlier declared node IDs.")
    .with_guideline("Each node must specify a concrete HTTP method, component path, and optional JSON payload.")
    .with_guideline("Focus on authorization boundaries, role transitions, and horizontal/vertical tenant isolation.")
    .with_schema(ATTACK_DAG_JSON_SCHEMA);

    if let Some(d) = directives {
        builder = builder.with_fenced_target("OPERATIONAL DIRECTIVES", d);
    }

    builder.build_user()
}
