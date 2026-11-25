//! Exit criteria definitions and automated gate validation.

use std::collections::BTreeSet;

use super::super::model::{ExitCriterion, ResultCounts};
use super::evidence::EVIDENCE_CRITERION;
use crate::model::Verdict;

pub fn crit(name: &str, met: bool, blocking: bool, detail: String) -> ExitCriterion {
    ExitCriterion {
        name: name.into(),
        met,
        blocking,
        detail,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_exit_criteria(
    open_p1: usize,
    new_sec: usize,
    verdict: Verdict,
    counts: &ResultCounts,
    pct: f64,
    evidence_ok: bool,
    evidence_gaps: &[String],
    failed_unexplained: usize,
    failed_open: usize,
    authz_roles: &BTreeSet<String>,
    roles: &[String],
    contract: usize,
) -> Vec<ExitCriterion> {
    vec![
        crit(
            "No open P1 defects",
            open_p1 == 0,
            true,
            format!("{open_p1} open P1 defect(s)"),
        ),
        crit(
            "No new critical/high security findings",
            new_sec == 0,
            true,
            format!("{new_sec} new critical/high security finding(s)"),
        ),
        crit(
            "Gate verdict not FAIL",
            verdict != Verdict::Fail,
            true,
            format!("verdict {verdict:?}"),
        ),
        crit(
            "≥90% of planned cases executed",
            counts.planned > 0 && pct >= 90.0,
            false,
            format!(
                "{}/{} executed ({pct:.0}%)",
                counts.executed, counts.planned
            ),
        ),
        crit(
            EVIDENCE_CRITERION,
            evidence_ok,
            true,
            if evidence_ok {
                format!(
                    "{}/{} executed ({pct:.0}%)",
                    counts.executed, counts.planned
                )
            } else {
                evidence_gaps.join("; ")
            },
        ),
        crit(
            "Every failed case is traced to a defect",
            failed_unexplained == 0,
            true,
            format!("{failed_unexplained} failed case(s) without a recorded defect"),
        ),
        crit(
            "No failed test cases",
            failed_open == 0,
            false,
            format!(
                "{failed_open} open failed case(s) of {} failed",
                counts.failed
            ),
        ),
        crit(
            "No flaky tests",
            counts.flaky == 0,
            false,
            format!("{} flaky", counts.flaky),
        ),
        crit(
            "Authorization tested with ≥2 roles",
            authz_roles.len() >= 2,
            false,
            format!(
                "{} distinct role(s) executed role-specific authorization cases ({}); {} configured",
                authz_roles.len(),
                authz_roles.iter().cloned().collect::<Vec<_>>().join(", "),
                roles.len()
            ),
        ),
        crit(
            "API contract violations = 0",
            contract == 0,
            false,
            format!("{contract} violation(s)"),
        ),
    ]
}
