use std::collections::BTreeSet;

use crate::agent::exec::is_mutating;
use crate::agent::oracle::{OracleOutcome, Severity, Verdict};
use crate::agent::types::{CaseExecutionResult, PlannedCase, StatefulStep, is_creation};

/// An id that no record has: what the planner puts into write cases (`plan::fill_path`) and what the
/// adaptive mutation uses for integers, so a write there cannot modify or delete real data.
pub fn targets_unlikely_id(component: &str) -> bool {
    let path = component.split(['?', '#']).next().unwrap_or("");
    path.split('/').any(|seg| {
        let s = seg.to_ascii_lowercase();
        s.contains("nonexistent")
            || (s.len() >= 6 && s.chars().all(|c| c == '9'))
            || s.ends_with("-000000999999")
    })
}

pub(crate) enum Plan {
    Http(PlannedCase),
    Chain(PlannedCase, Vec<StatefulStep>),
    Skip(String),
}

pub(crate) fn plan_for(r: &CaseExecutionResult, cases: &[PlannedCase], dry_run: bool) -> Plan {
    let mutated = |base: &PlannedCase| {
        // the same shape `exec::run_mutation` judged: the base case with the mutated payload
        let mut m = base.clone();
        m.id = r.case_id.clone();
        m.title = r.title.clone();
        m.payload = r.request_payload.clone();
        m.expected_status = None;
        m.expected_behavior =
            "Schema-conforming adversarial input is handled without a server error".into();
        m.concurrency_burst = None;
        m.stateful_steps = None;
        m.contract = None;
        m
    };
    let case = if let Some(c) = cases.iter().find(|c| c.id == r.case_id) {
        c.clone()
    } else if let Some(base) = r
        .case_id
        .strip_suffix("-M1")
        .and_then(|b| cases.iter().find(|c| c.id == b))
    {
        mutated(base)
    } else if r.case_id.ends_with("-B") {
        return Plan::Skip(
            "concurrency burst: replaying it would fire N more requests at the target, so it was not repeated"
                .into(),
        );
    } else {
        return Plan::Skip(
            "no planned case matches this result, so the request cannot be rebuilt".into(),
        );
    };
    if let Some(steps) = case.stateful_steps.clone().filter(|s| !s.is_empty()) {
        // a chain builds its own resource and acts on that one only
        return if dry_run && steps.iter().any(|s| is_mutating(&s.method)) {
            Plan::Skip("dry-run: state-changing chain not replayed".into())
        } else {
            Plan::Chain(case, steps)
        };
    }
    if is_mutating(&case.method) {
        if dry_run {
            return Plan::Skip("dry-run: state-changing request not replayed".into());
        }
        let created_own = is_creation(&case.method, r.status_code.unwrap_or(0));
        if !created_own && !targets_unlikely_id(&case.component) {
            return Plan::Skip(format!(
                "unverified-write: {} {} changes state on a resource this case did not create and whose id is not a throw-away one, so it was not replayed",
                case.method.to_ascii_uppercase(),
                case.component.split(['?', '#']).next().unwrap_or("")
            ));
        }
    }
    Plan::Http(case)
}

// ---------------------------------------------------------------- judging a replay

pub(crate) fn severity_of(r: &CaseExecutionResult) -> Severity {
    r.oracle
        .as_ref()
        .and_then(|o| o.max_fail_severity())
        .unwrap_or(Severity::High)
}

pub(crate) fn fail_codes(o: &OracleOutcome) -> BTreeSet<String> {
    o.checks
        .iter()
        .filter(|c| c.verdict == Verdict::Fail)
        .map(|c| c.code.clone())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vote {
    Reproduced,
    NotReproduced,
    /// Could not be judged: not a vote either way.
    Indeterminate,
}

/// How a replay's judgement counts. `same_status`: the replay got the same HTTP status the original
/// failure had.
/// * a fail with at least one of the original failing checks: reproduced;
/// * a PASS: not reproduced;
/// * INCONCLUSIVE: the checks that failed originally no longer fail, but the oracle has no
///   assertion left to pass (e.g. a 200 where a 500 was seen, on a case with no stated
///   expectation). That is a non-reproduction when the status moved, and unjudgeable when the
///   server said the same thing again (the same answer judged differently is not a vote);
/// * a failure of a different kind: not a vote (something else is wrong; do not dismiss it).
pub(crate) fn vote(orig: &BTreeSet<String>, o: &OracleOutcome, same_status: bool) -> Vote {
    match o.verdict {
        Verdict::Fail if orig.is_empty() || !fail_codes(o).is_disjoint(orig) => Vote::Reproduced,
        Verdict::Pass => Vote::NotReproduced,
        Verdict::Inconclusive if !same_status => Vote::NotReproduced,
        _ => Vote::Indeterminate,
    }
}

pub(crate) fn spa_shell(ct: &str, body: &str, is_spa_target: bool) -> bool {
    ct.to_ascii_lowercase().contains("html")
        && is_spa_target
        && [
            "__NEXT_DATA__",
            "/_next/static/",
            "__NUXT__",
            "ng-version",
            "data-reactroot",
            "<app-root",
            "id=\"root\"",
            "id=\"app\"",
            "/@vite/client",
        ]
        .iter()
        .any(|m| body.contains(m))
}
