//! Plan ordering and truncation logic.

use super::super::types::{PlannedCase, any_prioritised, plan_order};

/// Order the plan so the cases that matter most are the ones that run, then cut it to `hard_limit`.
/// Returns (kept, dropped); ids are renumbered over kept-then-dropped. The plan is only reordered
/// when something has to give (more cases than `hard_limit` or than the executor's step budget
/// `exec_cap`), so an untruncated plan keeps the planner's order.
pub(crate) fn order_and_trim(
    mut cases: Vec<PlannedCase>,
    hard_limit: Option<usize>,
    exec_cap: usize,
) -> (Vec<PlannedCase>, Vec<PlannedCase>) {
    let cap = hard_limit.unwrap_or(usize::MAX).min(exec_cap);
    if cases.len() <= cap {
        return (cases, vec![]);
    }
    let key = plan_order(any_prioritised(&cases));
    cases.sort_by_key(|c| key(c)); // stable: ties keep the planner's order
    let mut dropped = match hard_limit {
        Some(l) if cases.len() > l => cases.split_off(l),
        _ => vec![],
    };
    for (i, c) in cases.iter_mut().chain(dropped.iter_mut()).enumerate() {
        c.id = format!("TC-{:03}", i + 1);
    }
    (cases, dropped)
}
