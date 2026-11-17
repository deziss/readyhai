use super::super::exec::NEXT_STEP_AUTH_WALL;
use super::super::types::{
    BlockReason, Blocker, CaseExecutionResult, CoverageCell, EvidenceLedger, ExitCheckItem,
    TriagedDefect,
};
use super::constants::INPUT_TECHNIQUES;

/// Ledger for a run that executed nothing (discovery only, rejected target...). Never carries scores.
pub fn not_evaluated(
    verdict: &str,
    summary: impl Into<String>,
    checklist: Vec<ExitCheckItem>,
) -> EvidenceLedger {
    EvidenceLedger {
        confidence: None,
        blockers: vec![],
        value_score: None,
        authority_score: None,
        safety_score: None,
        evidence_score: None,
        overall_readiness: 0,
        gate_verdict: verdict.to_string(),
        executive_summary: summary.into(),
        exit_criteria_checklist: checklist,
        composite_score: None,
        verdict: Some(verdict.to_string()),
        evaluated: false,
        computed_verdict: verdict.to_string(),
        verdict_basis: "no test case was executed".into(),
        pillars: vec![],
        coverage: vec![],
        claims: vec![],
        llm_advisory: None,
        ai_summary: None,
        verification: None,
    }
}

/// An LLM-proposed case that no deterministic oracle failed: its outcome is not evidence either
/// way (a PASS against an LLM-written expectation proves nothing), so it is not scored.
pub fn is_unconfirmed_exploratory(r: &CaseExecutionResult) -> bool {
    r.status != "FAIL" && r.oracle.as_ref().is_some_and(|o| o.exploratory)
}

/// Whether a defect counts toward the gate. The verifier decides which failures are real:
/// * no verification data (an older run, verification off): counts, as before the verifier existed;
/// * confirmed (every replay reproduced it): counts;
/// * flaky: counts when high/critical (a flaky Medium/Low is a WARN and never reaches the gate as a
///   defect);
/// * unverified (not replayable: a write on a real record, a burst, a stopped budget): counts when
///   high/critical. A failure the verifier could not examine is not evidence that it is gone, so it
///   is never allowed to soften the gate; it is listed as unverified for a person to confirm.
///
/// A failure that did not reproduce is INCONCLUSIVE and is not a defect at all.
pub fn is_blocking(d: &TriagedDefect) -> bool {
    if d.accepted.is_some() {
        return false; // an unexpired acceptance (memory): listed, not blocking
    }
    let severe = matches!(d.severity.as_str(), "critical" | "high");
    match d.verification.as_deref() {
        Some("flaky") | Some("unverified") => severe,
        _ => true,
    }
}

/// What kept evidence from being gathered, and what to do about it: from the results themselves.
pub fn blockers_of(results: &[CaseExecutionResult], coverage: &[CoverageCell]) -> Vec<Blocker> {
    let ids = |f: &dyn Fn(&CaseExecutionResult) -> bool| -> Vec<String> {
        results
            .iter()
            .filter(|r| f(r))
            .map(|r| r.case_id.clone())
            .collect()
    };
    let mut out = vec![];
    let wall = ids(&|r| r.blocked_reason == Some(BlockReason::AuthWall));
    if !wall.is_empty() {
        out.push(Blocker {
            reason: BlockReason::AuthWall,
            detail: format!(
                "{} case(s) ran into a login wall (HTTP 401, a redirect to a login page or a password form) with no credential, so what sits behind the login was not tested",
                wall.len()
            ),
            next_step: NEXT_STEP_AUTH_WALL.to_string(),
            case_ids: wall,
        });
    }
    let input: Vec<&CoverageCell> = coverage
        .iter()
        .filter(|c| INPUT_TECHNIQUES.contains(&c.technique.as_str()))
        .collect();
    let (input_planned, input_na): (usize, usize) = input
        .iter()
        .fold((0, 0), |(p, n), c| (p + c.planned, n + c.not_applicable));
    if input_na > 0 && input_na * 2 >= input_planned {
        out.push(Blocker {
            reason: BlockReason::NoSurface,
            detail: format!(
                "no input surface (query parameters, forms or API endpoints) was found for the injection, boundary and negative tests: {input_na} of {input_planned} such case(s) are not applicable, so those techniques were not exercised"
            ),
            next_step: "provide the OpenAPI spec (the spec URL of the run, e.g. /openapi.json) or use the deep profile so that API endpoints and forms are discovered, then re-run".into(),
            case_ids: ids(&|r| {
                r.status == "NOT_APPLICABLE" && r.blocked_reason == Some(BlockReason::NoSurface)
            }),
        });
    }
    let transport = ids(&|r| {
        r.status == "BLOCKED"
            && (r.blocked_reason == Some(BlockReason::Transport)
                || (r.blocked_reason.is_none()
                    && r.failure_reason
                        .as_deref()
                        .is_some_and(|f| f.starts_with("Connection error"))))
    });
    if !transport.is_empty() {
        out.push(Blocker {
            reason: BlockReason::Transport,
            detail: format!(
                "{} case(s) got no HTTP answer from the target (connection error or timeout)",
                transport.len()
            ),
            next_step: "check that the target is reachable from where ReadyHai runs (DNS, network, TLS certificate, firewall), then re-run".into(),
            case_ids: transport,
        });
    }
    let scope = ids(&|r| r.blocked_reason == Some(BlockReason::OutOfScope));
    if !scope.is_empty() {
        out.push(Blocker {
            reason: BlockReason::OutOfScope,
            detail: format!(
                "{} case(s) would have left the allowed scope and were not sent",
                scope.len()
            ),
            next_step: "add the host to scope.toml if it is yours to test, then re-run".into(),
            case_ids: scope,
        });
    }
    out
}

pub fn blocker_label(r: BlockReason) -> &'static str {
    match r {
        BlockReason::AuthWall => "auth wall",
        BlockReason::OutOfScope => "out of scope",
        BlockReason::NoSurface => "no input surface",
        BlockReason::Transport => "target not reachable",
    }
}
