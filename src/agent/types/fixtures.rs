//! Test fixtures for agent data structures.

use serde_json::json;

use super::execution::CaseExecutionResult;
use super::planning::PlannedCase;
use super::reports::AgentRunReport;

pub fn planned(id: &str, technique: &str, method: &str, component: &str) -> PlannedCase {
    serde_json::from_value(json!({
        "id": id, "title": format!("case {id}"), "component": component, "method": method,
        "technique": technique, "input_hint": "", "expected_behavior": "", "risk_level": "medium"
    }))
    .unwrap()
}

/// A finished result that carries stored evidence (status 200, evidence file, curl).
pub fn result(id: &str, technique: &str, status: &str) -> CaseExecutionResult {
    let mut r = CaseExecutionResult::not_run(&planned(id, technique, "GET", "/x"), "");
    r.status = status.into();
    r.failure_reason = (status == "FAIL").then(|| "expected 401, got 200".into());
    r.status_code = Some(200);
    r.reproduction_curl = "curl -sS -i -X GET 'http://h/x'".into();
    r.evidence_file = Some(format!("evidence/{id}.json"));
    r.evidence = "ok".into();
    r
}

pub fn report(id: &str) -> AgentRunReport {
    serde_json::from_value(json!({
        "id": id, "target": "http://127.0.0.1:1/", "profile": "standard", "model": "none",
        "provider": "deterministic", "started_at": "2026-01-01T00:00:00Z", "finished_at": null,
        "status": "completed", "steps": [], "planned_cases": [], "executed_results": [],
        "triaged_defects": [], "evidence_ledger": null, "approval_status": "pending",
        "approved_by": null, "approval_notes": null, "approved_at": null, "error": null
    }))
    .unwrap()
}
