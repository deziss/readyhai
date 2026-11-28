//! Software Factory Attestation and Readiness Gate Prompt Templates.

use super::{
    FACTORY_ATTESTER_ROLE, PromptBuilder, READINESS_GATE_ROLE, system_with_fencing_preamble,
};

/// JSON schema expected from the Software Factory Attestation Officer.
pub const FACTORY_ATTESTATION_JSON_SCHEMA: &str = r#"{
  "advisory_summary": "Advisory software factory record: Release readiness 94/100, verdict GO. No critical or high defect observed by evidence-backed cases. Areas no case tested are reported as not evaluated.",
  "directives": [
    "Enforce HSTS preload on production load balancer",
    "Monitor rate-limiting telemetry on /api/v1/auth/login"
  ]
}"#;

/// JSON schema expected from the advisory readiness gate reviewer.
pub const READINESS_GATE_JSON_SCHEMA: &str = r#"{
  "executive_summary": "Autonomous security assessment completed across all target routes with conclusive evidence.",
  "gate_verdict": "GO | CONDITIONAL_GO | NO_GO",
  "overall_readiness": 90,
  "value_score": 95,
  "authority_score": 90,
  "safety_score": 92,
  "evidence_score": 88
}"#;

/// Builds the system prompt for the Software Factory Attestation Officer.
pub fn build_factory_attestation_system_prompt() -> String {
    let mut sys = system_with_fencing_preamble(FACTORY_ATTESTER_ROLE);
    sys.push_str("\n\nReturn ONLY valid JSON matching this schema:\n");
    sys.push_str(FACTORY_ATTESTATION_JSON_SCHEMA);
    sys
}

/// Builds the system prompt for the Readiness Gate Reviewer.
pub fn build_readiness_gate_system_prompt() -> String {
    let mut sys = system_with_fencing_preamble(READINESS_GATE_ROLE);
    sys.push_str("\n\nReturn ONLY valid JSON matching this schema:\n");
    sys.push_str(READINESS_GATE_JSON_SCHEMA);
    sys
}

/// What the attestation officer is told about a release. There are deliberately no compliance or
/// certification booleans here: each one describes defects that evidence-backed cases observed, and
/// `basis` states that limitation to the model. `release_readiness_score` is `None` when readiness
/// was not evaluated, which serializes as `null` instead of a plausible number.
#[derive(Debug, Clone)]
pub struct FactoryObservedFacts {
    pub evaluated: bool,
    pub release_readiness_score: Option<u32>,
    pub gate_verdict: String,
    pub no_critical_or_high_findings: bool,
    pub no_high_or_medium_above_threshold: bool,
    pub no_observed_findings: bool,
    pub basis: String,
}

/// Builds the user prompt for generating formal Software Factory Attestation and deployment directives.
pub fn build_factory_attestation_user_prompt(
    facts: &FactoryObservedFacts,
    area_breakdown: &[serde_json::Value],
    defects: &[serde_json::Value],
) -> String {
    let attestation_facts = serde_json::json!({
        "evaluated": facts.evaluated,
        "release_readiness_score": facts.release_readiness_score,
        "gate_verdict": facts.gate_verdict,
        "no_critical_or_high_findings": facts.no_critical_or_high_findings,
        "no_high_or_medium_above_threshold": facts.no_high_or_medium_above_threshold,
        "no_observed_findings": facts.no_observed_findings,
        "basis": facts.basis,
        "defects_count": defects.len(),
    });

    PromptBuilder::new(
        FACTORY_ATTESTER_ROLE,
        "Given the computed release readiness score, the observed-findings breakdown for the ASVS-shaped areas \
        (V2 Authentication through V14 Configuration), and the remaining defects, formulate a concise formal release \
        attestation summary and advisory deployment directives. Report not evaluated for anything these facts do not measure.",
    )
    .with_fenced_json("RELEASE READINESS & OBSERVED-FINDINGS FACTS", &attestation_facts)
    .with_fenced_json_capped("OBSERVED-FINDINGS AREA BREAKDOWN", &serde_json::json!(area_breakdown), 200)
    .with_fenced_json_capped("TRIAGED DEFECTS SUMMARY", &serde_json::json!(defects), 200)
    .with_guideline("Advisory summary should be formal, concise, and suitable for audit logging.")
    .with_guideline("Never claim compliance, certification or coverage the facts above do not state.")
    .with_guideline("Directives should provide actionable post-deployment hardening recommendations.")
    .with_schema(FACTORY_ATTESTATION_JSON_SCHEMA)
    .build_user()
}

/// Builds the user prompt for the advisory production-readiness gate review.
pub fn build_readiness_gate_user_prompt(
    target: &str,
    computed_verdict: &str,
    overall_readiness: i64,
    verdict_basis: &str,
    pillars: &[serde_json::Value],
    defects: &[serde_json::Value],
) -> String {
    let facts = serde_json::json!({
        "target": target,
        "computed_verdict": computed_verdict,
        "overall_readiness": overall_readiness,
        "verdict_basis": verdict_basis,
        "pillars": pillars,
    });

    PromptBuilder::new(
        READINESS_GATE_ROLE,
        "Review the computed evidence ledger facts, four-pillar quality breakdown (Value, Authority, Safety, Evidence), \
        and triaged defects to provide an executive summary and advisory readiness opinion.",
    )
    .with_fenced_json("COMPUTED READINESS & FOUR-PILLAR EVIDENCE", &facts)
    .with_fenced_json_capped("TRIAGED DEFECTS", &serde_json::json!(defects), 200)
    .with_guideline("Your opinion is strictly advisory and recorded separately from the computed verdict.")
    .with_guideline("The gate_verdict must be exactly one of 'GO', 'CONDITIONAL_GO', or 'NO_GO'.")
    .with_guideline("Scores must be integer values between 0 and 100.")
    .with_schema(READINESS_GATE_JSON_SCHEMA)
    .build_user()
}
