//! Report construction, quota math, and metric aggregation.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::alloc::{Available, allocate};
use super::area::{Area, AreaNeed, MAX_WORKERS, case_weight, request_demand};
use super::followup::base_id;
use super::schedule::{LeadConfig, Task, bump};
use crate::agent::budget::BudgetUsage;
use crate::agent::types::{
    AgentsReport, AreaReport, CaseExecutionResult, PlannedCase, Quota, TriagedDefect,
};

pub(super) fn quota_of(u: &BudgetUsage) -> Quota {
    Quota {
        steps: u.steps,
        requests: u.requests,
        wall_ms: u.elapsed_ms,
        llm_calls: u.llm_calls,
    }
}

pub(super) fn skeleton(by_area: &BTreeMap<Area, Vec<PlannedCase>>, workers: usize) -> AgentsReport {
    AgentsReport {
        workers,
        status: "running".into(),
        waves: 1,
        areas: Area::ALL
            .iter()
            .map(|a| {
                let cases = by_area.get(a).map(Vec::as_slice).unwrap_or(&[]);
                AreaReport {
                    area: a.as_str().into(),
                    status: if cases.is_empty() { "idle" } else { "pending" }.into(),
                    cases: cases.len(),
                    case_ids: cases.iter().map(|c| c.id.clone()).collect(),
                    ..Default::default()
                }
            })
            .collect(),
        ..Default::default()
    }
}

pub(super) fn tasks_for(
    by_area: &BTreeMap<Area, Vec<PlannedCase>>,
    cfg: &LeadConfig,
    avail: &Available,
    reserve_requests: usize,
) -> Vec<Task> {
    let needs: Vec<AreaNeed> = by_area
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(a, v)| {
            // Burst and stateful-chain cases need ~7-10 requests each; weight them accordingly
            // in the lead pool so small State slices don't starve TOCTOU bursts.
            let area_weight: u64 = v
                .iter()
                .map(|c| {
                    let mult = if c.concurrency_burst.is_some_and(|n| n > 1)
                        || c.stateful_steps.as_ref().is_some_and(|s| !s.is_empty())
                    {
                        3
                    } else {
                        1
                    };
                    case_weight(c) * mult
                })
                .sum();
            AreaNeed {
                area: *a,
                weight: area_weight,
                cases: v.len(),
                requests: v.iter().map(|c| request_demand(c, cfg.opts.reruns)).sum(),
            }
        })
        .collect();
    allocate(
        &needs,
        avail,
        reserve_requests,
        cfg.workers.clamp(1, MAX_WORKERS),
    )
    .into_iter()
    .map(|g| Task {
        area: g.area,
        cases: by_area[&g.area].clone(),
        grant: g,
    })
    .collect()
}

pub(super) fn sum_quota(it: impl Iterator<Item = Quota>) -> Quota {
    it.fold(Quota::default(), |a, q| Quota {
        steps: a.steps + q.steps,
        requests: a.requests + q.requests,
        wall_ms: a.wall_ms + q.wall_ms,
        llm_calls: a.llm_calls + q.llm_calls,
    })
}

/// Recompute each area's counters and defect ids from `results` and `defects`: what the area's
/// cases (and their sub-cases) ended as. Called when the lead is done, after verification and
/// triage have changed some statuses, and after a retest.
pub fn recount(a: &mut AgentsReport, results: &[CaseExecutionResult], defects: &[TriagedDefect]) {
    let mut owner: HashMap<String, usize> = HashMap::new();
    for (i, ar) in a.areas.iter().enumerate() {
        for id in &ar.case_ids {
            owner.insert(id.clone(), i);
        }
    }
    for ar in a.areas.iter_mut() {
        ar.executed = 0;
        ar.pass = 0;
        ar.warn = 0;
        ar.fail = 0;
        ar.inconclusive = 0;
        ar.blocked = 0;
        ar.skipped = 0;
        ar.defect_ids.clear();
    }
    for r in results {
        if let Some(i) = base_id(&owner, &r.case_id).map(|b| owner[b]) {
            bump(&mut a.areas[i], std::slice::from_ref(r));
        }
    }
    for d in defects {
        let mut hit: BTreeSet<usize> = BTreeSet::new();
        for id in &d.case_ids {
            if let Some(i) = base_id(&owner, id).map(|b| owner[b]) {
                hit.insert(i);
            }
        }
        for i in hit {
            if !a.areas[i].defect_ids.contains(&d.id) {
                a.areas[i].defect_ids.push(d.id.clone());
            }
        }
    }
}

/// One line per area for the run log.
pub fn summary_lines(a: &AgentsReport) -> String {
    a.areas
        .iter()
        .filter(|x| x.cases > 0 || !x.wave2_added.is_empty())
        .map(|x| {
            format!(
                "{}: {} case(s), {} sent, {} fail, requests {}/{}{}",
                x.area,
                x.cases + x.wave2_added.len(),
                x.executed,
                x.fail,
                x.budget.used.requests + x.wave2_budget.map_or(0, |b| b.used.requests),
                x.budget.allocated.requests + x.wave2_budget.map_or(0, |b| b.allocated.requests),
                if x.wave2_added.is_empty() {
                    String::new()
                } else {
                    format!(", +{} in wave 2", x.wave2_added.len())
                }
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}
