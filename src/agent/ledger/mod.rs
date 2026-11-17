//! Readiness ledger. Everything here is computed from results: a technique-coverage matrix feeds
//! four pillars, the pillars feed the verdict, and every claim cites case ids and evidence files.
//! A pillar nobody exercised is "not evaluated" (None) -- there are no default scores. The LLM may
//! add prose and an advisory opinion, which is stored next to the verdict and never changes it: the
//! gate is the deterministic one. LLM-proposed (exploratory) cases are listed but not scored unless a
//! deterministic oracle failed them.

pub mod blockers;
pub mod constants;
pub mod enrich;
pub mod scoring;
pub mod types;

#[cfg(test)]
mod tests;

pub use blockers::{is_blocking, not_evaluated};
pub use enrich::{apply_llm, attach_verification};
pub use types::LedgerInput;

use super::types::{CaseExecutionResult, EvidenceLedger, LedgerClaim, TriagedDefect};
use scoring::compute_scored;

/// The ledger of a run. A defect that carries an unexpired acceptance (`TriagedDefect::accepted`,
/// set from the agent's memory by an explicit operator decision) does not block: its failing cases
/// are run and listed but not scored, like unconfirmed exploratory cases, and the verdict basis says
/// what the computed verdict would be without the acceptance. Nothing else in a run is waived.
pub fn compute(inp: &LedgerInput) -> EvidenceLedger {
    let waived: Vec<&TriagedDefect> = inp
        .defects
        .iter()
        .filter(|d| d.accepted.is_some())
        .collect();
    if waived.is_empty() {
        return compute_scored(inp);
    }
    let waived_cases: std::collections::BTreeSet<&str> = waived
        .iter()
        .flat_map(|d| d.case_ids.iter().map(String::as_str))
        .collect();
    let kept: Vec<CaseExecutionResult> = inp
        .results
        .iter()
        .filter(|r| !(r.status == "FAIL" && waived_cases.contains(r.case_id.as_str())))
        .cloned()
        .collect();
    let live: Vec<TriagedDefect> = inp
        .defects
        .iter()
        .filter(|d| d.accepted.is_none())
        .cloned()
        .collect();
    let mut l = compute_scored(&LedgerInput {
        results: &kept,
        defects: &live,
        dry_run: inp.dry_run,
        budget_stop: inp.budget_stop,
    });
    let unwaived: Vec<TriagedDefect> = inp
        .defects
        .iter()
        .map(|d| TriagedDefect {
            accepted: None,
            ..d.clone()
        })
        .collect();
    let without = compute_scored(&LedgerInput {
        results: inp.results,
        defects: &unwaived,
        dry_run: inp.dry_run,
        budget_stop: inp.budget_stop,
    })
    .computed_verdict;
    for d in &waived {
        let a = d.accepted.as_ref();
        l.claims.push(LedgerClaim {
            claim: format!(
                "{} [{}] {} is accepted by {} until {} ({}): it does not block the gate and its failing case(s) are not scored",
                d.id,
                d.severity,
                d.title,
                a.map(|a| a.by.as_str()).unwrap_or("?"),
                a.map(|a| a.expires.as_str()).unwrap_or("?"),
                a.map(|a| a.reason.as_str()).unwrap_or("")
            ),
            status: "partial".into(),
            case_ids: d.case_ids.clone(),
            evidence_files: d.evidence_files.clone(),
        });
    }
    let note = format!(
        "{} defect(s) covered by an unexpired acceptance do not block; without the acceptance the computed verdict would be {without}",
        waived.len()
    );
    l.verdict_basis = format!("{}; {note}", l.verdict_basis);
    l.executive_summary.push_str(&format!(" {note}."));
    l
}
