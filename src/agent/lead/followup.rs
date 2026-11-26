//! Result merging and deterministic wave-2 follow-up planning.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use super::area::Area;
use crate::agent::exec::{is_safe_method, normalize_component};
use crate::agent::oracle::is_sensitive_path;
use crate::agent::types::{BlockReason, CaseExecutionResult, PlannedCase};

/// Order by case id the way a person reads it: `TC-009` before `TC-010`, `TC-003` before
/// `TC-003-M1`.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() && !b.is_empty() {
        let (da, db) = (a[0].is_ascii_digit(), b[0].is_ascii_digit());
        if da && db {
            let (na, nb) = (
                a.iter().take_while(|c| c.is_ascii_digit()).count(),
                b.iter().take_while(|c| c.is_ascii_digit()).count(),
            );
            let (xa, xb) = (
                std::str::from_utf8(&a[..na])
                    .unwrap_or("0")
                    .trim_start_matches('0'),
                std::str::from_utf8(&b[..nb])
                    .unwrap_or("0")
                    .trim_start_matches('0'),
            );
            let o = xa.len().cmp(&xb.len()).then_with(|| xa.cmp(xb));
            if o != Ordering::Equal {
                return o;
            }
            a = &a[na..];
            b = &b[nb..];
        } else {
            if a[0] != b[0] {
                return a[0].cmp(&b[0]);
            }
            a = &a[1..];
            b = &b[1..];
        }
    }
    a.len().cmp(&b.len())
}

/// Stable merge: results of all areas in case-id order, never in the order the threads finished.
pub fn merge_results(mut all: Vec<CaseExecutionResult>) -> Vec<CaseExecutionResult> {
    all.sort_by(|a, b| natural_cmp(&a.case_id, &b.case_id));
    all
}

/// The planned case a result belongs to: its own id, or the id of the case its sub-case
/// (`TC-003-M1`, `TC-003-B`) came from.
pub(super) fn base_id<'a>(known: &HashMap<String, usize>, id: &'a str) -> Option<&'a str> {
    let mut cur = id;
    loop {
        if known.contains_key(cur) {
            return Some(cur);
        }
        cur = &cur[..cur.rfind('-')?];
    }
}

// ---------------------------------------------------------------- wave 2

/// A case wave 2 adds (or resumes), and the rule that wanted it.
#[derive(Debug, Clone)]
pub struct FollowUp {
    pub rule: &'static str,
    pub origin: String,
    pub reason: String,
    pub case: PlannedCase,
    /// The case was in the plan already (its result was SKIPPED by an area budget): its new result
    /// replaces the old one.
    pub resume: bool,
}

pub const RULE_AUTH_TO_CONTRACT: &str = "auth-to-contract";
pub const RULE_REPROBE: &str = "inconclusive-reprobe";
pub const RULE_RESUME: &str = "budget-resume";

/// A SKIPPED result whose case an area budget (not the whole run, not a dry run) kept from running.
fn is_budget_skip(r: &CaseExecutionResult) -> bool {
    r.status == "SKIPPED" && r.failure_reason.as_deref().is_some_and(is_resumable)
}

pub(super) fn is_resumable(reason: &str) -> bool {
    reason.starts_with("request budget exhausted") || reason.starts_with("step budget exhausted")
}

/// A result whose cause may be gone on a second send: no answer (a timeout or any transport error),
/// a 5xx, or a rate limit / request timeout (429, 408). Everything else that ends INCONCLUSIVE is
/// deterministic: a redirect that was not followed, "no class evidence", a CORS 405, an auth wall.
pub fn is_transient(r: &CaseExecutionResult) -> bool {
    match r.status.as_str() {
        "BLOCKED" => {
            r.blocked_reason == Some(BlockReason::Transport)
                || (r.blocked_reason.is_none()
                    && r.failure_reason
                        .as_deref()
                        .is_some_and(|f| f.starts_with("Connection error")))
        }
        "INCONCLUSIVE" => matches!(r.status_code, Some(408 | 429 | 500..=599)),
        _ => false,
    }
}

fn transient_cause(r: &CaseExecutionResult) -> String {
    match r.status_code {
        Some(c) => format!("HTTP {c}"),
        None => "no answer".into(),
    }
}

/// Same operation: same number of path segments, equal except where both look like record ids.
fn same_endpoint(a: &str, b: &str) -> bool {
    let path = |s: &str| s.split(['?', '#']).next().unwrap_or("").to_string();
    let (a, b) = (path(a), path(b));
    let (sa, sb): (Vec<&str>, Vec<&str>) = (a.split('/').collect(), b.split('/').collect());
    let idish = |s: &str| !s.is_empty() && s.chars().any(|c| c.is_ascii_digit());
    sa.len() == sb.len()
        && sa
            .iter()
            .zip(&sb)
            .all(|(x, y)| x == y || (idish(x) && idish(y)))
}

fn follow_up_key(c: &PlannedCase) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        c.method,
        c.component,
        c.technique,
        c.payload.as_deref().unwrap_or(""),
        c.role.as_deref().unwrap_or("")
    )
}

/// The deterministic wave-2 rules, from the plan and the merged results of wave 1:
///
/// 1. `auth-to-contract`: a read that failed an access-control check (an endpoint that answers
///    without credentials, or to a forged token) gets a contract check on the same endpoint as the
///    identity that was let in: does what it exposes still honour its documented contract and stay
///    free of internal detail? The contract comes from the plan's own case for that operation.
/// 2. `budget-resume`: a case an area budget cut off (SKIPPED) runs now from the reclaimed pool.
/// 3. `inconclusive-reprobe`: a safe read whose result may be a hiccup is sent once more: a
///    timeout or network error, a 5xx, a 429/408 (see [`is_transient`]). A deterministic
///    INCONCLUSIVE (a redirect, "no class evidence", a CORS 405, an auth wall) answers the same
///    way every time and is never re-sent.
///
/// Rules apply in that order, within a rule by case id; at most `limit` follow-ups are returned. Nothing
/// that writes is ever added: a resumed write is the plan's own.
pub fn plan_follow_ups(
    cases: &[PlannedCase],
    results: &[CaseExecutionResult],
    limit: usize,
) -> Vec<FollowUp> {
    let by_id: HashMap<&str, &PlannedCase> = cases.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut seen: HashSet<String> = cases.iter().map(follow_up_key).collect();
    let mut reprobed: HashSet<String> = HashSet::new();
    let taken_ids: HashSet<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    let single_read = |c: &PlannedCase| {
        matches!(c.method.as_str(), "GET" | "HEAD")
            && c.stateful_steps.as_ref().is_none_or(|s| s.is_empty())
            && !c.concurrency_burst.is_some_and(|b| b > 1)
    };
    let (mut a, mut c_resume, mut b) = (vec![], vec![], vec![]);
    for r in results {
        let Some(origin) = by_id.get(r.case_id.as_str()).copied() else {
            continue; // a sub-case: its base case speaks for it
        };
        let fid = format!("{}-F1", origin.id);
        if taken_ids.contains(fid.as_str()) {
            continue;
        }
        match r.status.as_str() {
            "FAIL"
                if Area::of(origin) == Area::Auth
                    && single_read(origin)
                    && normalize_component(&origin.component).is_ok()
                    && !is_sensitive_path(&origin.component) =>
            {
                let sibling = cases.iter().find(|s| {
                    s.id != origin.id
                        && s.contract.is_some()
                        && same_endpoint(&s.component, &origin.component)
                });
                let mut f = origin.clone();
                f.id = fid;
                f.title = format!(
                    "Contract check on {} {} after an access-control failure",
                    origin.method, origin.component
                );
                f.method = "GET".into();
                f.technique = "state_transition".into();
                f.area = Area::Contract.as_str().into();
                f.source = Some("followup".into());
                f.input_hint =
                    "Read the endpoint as the identity that was let in and check what it exposes"
                        .into();
                f.expected_status = None;
                f.expected_behavior =
                    "Handled without a server error and honours the documented response contract"
                        .into();
                f.risk_level = "medium".into();
                f.role = Some(origin.role.clone().unwrap_or_else(|| "anon".into()));
                f.changed_ops = vec![];
                // a follow-up is the lead's own case, not a re-test of a remembered defect
                f.regression_of = vec![];
                f.history_priority = false;
                f.intel_note = String::new();
                if let Some(s) = sibling {
                    f.contract = s.contract.clone();
                    f.expect_fields = s.expect_fields.clone();
                    f.expected_content_type = s.expected_content_type.clone();
                }
                if seen.insert(follow_up_key(&f)) {
                    a.push(FollowUp {
                        rule: RULE_AUTH_TO_CONTRACT,
                        origin: origin.id.clone(),
                        reason: format!(
                            "{} {} failed an access-control check: contract check on the same endpoint",
                            origin.method, origin.component
                        ),
                        case: f,
                        resume: false,
                    });
                }
            }
            "SKIPPED" if is_budget_skip(r) => c_resume.push(FollowUp {
                rule: RULE_RESUME,
                origin: origin.id.clone(),
                reason: format!(
                    "{} was cut off by its area's budget: run from the reclaimed pool",
                    origin.id
                ),
                case: origin.clone(),
                resume: true,
            }),
            "INCONCLUSIVE" | "BLOCKED"
                if is_transient(r)
                    && is_safe_method(&origin.method)
                    && single_read(origin)
                    && !origin.id.ends_with("-F1") =>
            {
                let mut f = origin.clone();
                f.id = fid;
                f.title = format!("{} [re-probe]", origin.title);
                f.changed_ops = vec![];
                f.regression_of = vec![];
                f.history_priority = false;
                f.intel_note = String::new();
                if f.source.as_deref() != Some("llm") {
                    // an LLM case stays exploratory for the oracle; anything else is the lead's own
                    f.source = Some("followup".into());
                }
                if reprobed.insert(follow_up_key(&f)) {
                    b.push(FollowUp {
                        rule: RULE_REPROBE,
                        origin: origin.id.clone(),
                        reason: format!(
                            "{} was {} ({}): sent once more",
                            origin.id,
                            r.status,
                            transient_cause(r)
                        ),
                        case: f,
                        resume: false,
                    });
                }
            }
            _ => {}
        }
    }
    a.into_iter().chain(c_resume).chain(b).take(limit).collect()
}
