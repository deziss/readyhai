//! The lead: orchestrator-worker structure inside one agent run.
//!
//! The planner tags every case with an [`Area`] (`auth`, `contract`, `state`, `ui`). The lead splits
//! the plan by area, gives every area a [`RunBudget`] slice (steps, requests, wall clock, LLM calls,
//! weighted by the risk of its cases and by change impact), runs the areas on worker threads and
//! merges what they found. Then it plans at most one follow-up wave from deterministic rules and
//! runs it from what is left of the budget. Verification, cleanup, triage and the ledger run on the
//! merged results exactly as before.

pub mod alloc;
pub mod area;
pub mod followup;
pub mod report;
pub mod schedule;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub use alloc::{Available, Grant, allocate, is_write, share_capped};
pub use area::{
    Area, AreaNeed, DEFAULT_WORKERS, MAX_WAVE2_CASES, MAX_WORKERS, case_weight, parse_workers,
    request_demand, workers_from_env,
};
pub use followup::{
    FollowUp, RULE_AUTH_TO_CONTRACT, RULE_REPROBE, RULE_RESUME, is_transient, merge_results,
    natural_cmp, plan_follow_ups,
};
pub use report::{recount, summary_lines};
pub use schedule::LeadConfig;

use area::{LLM_RESERVE, PROGRESS_EVERY, RESERVE_PCT, WAVE1_WALL_PCT};
use followup::is_resumable;
use report::{quota_of, skeleton, sum_quota, tasks_for};
use schedule::{Live, run_wave};

use crate::agent::budget::RunBudget;
use crate::agent::types::{
    AgentsReport, AreaBudget, CaseExecutionResult, PlannedCase, Quota, WaveTwoCase,
};

pub struct LeadOutcome {
    /// Every result, merged in case-id order.
    pub results: Vec<CaseExecutionResult>,
    /// The cases wave 2 added to the plan (a resumed case is not new and is not listed).
    pub follow_ups: Vec<PlannedCase>,
    pub agents: AgentsReport,
}

/// Run the plan: partition, allocate, run the areas in parallel, merge, and (once) a follow-up
/// wave from what is left. `budget` is charged with everything the workers used.
pub fn run(cfg: &LeadConfig, cases: &[PlannedCase], budget: &mut RunBudget) -> LeadOutcome {
    let workers = cfg.workers.clamp(1, MAX_WORKERS);
    let mut by_area: BTreeMap<Area, Vec<PlannedCase>> = BTreeMap::new();
    for c in cases {
        by_area.entry(Area::of(c)).or_default().push(c.clone());
    }
    let live = Live {
        report: Mutex::new(skeleton(&by_area, workers)),
        observer: cfg.on_progress,
        emit: Mutex::new(
            Instant::now()
                .checked_sub(PROGRESS_EVERY)
                .unwrap_or_else(Instant::now),
        ),
    };
    live.update(true, |_| {});

    // ---- wave 1
    let window = budget.wall_left().mul_f64(WAVE1_WALL_PCT as f64 / 100.0);
    let requests_left = budget.requests_left();
    let avail = Available {
        steps: budget.steps_left(),
        requests: requests_left,
        wall: window,
        llm_calls: budget
            .llm_calls_left()
            .min(cfg.llm_calls_left)
            .saturating_sub(LLM_RESERVE),
    };
    let reserve = requests_left * RESERVE_PCT / 100;
    let tasks = tasks_for(&by_area, cfg, &avail, reserve);
    let granted = sum_quota(tasks.iter().map(|t| t.grant.quota()));
    live.update(true, |r| {
        r.pool_reserve = Quota {
            steps: avail.steps.saturating_sub(granted.steps),
            requests: requests_left.saturating_sub(granted.requests),
            wall_ms: budget.wall_left().saturating_sub(window).as_millis() as u64,
            llm_calls: avail.llm_calls.saturating_sub(granted.llm_calls),
        };
        for t in &tasks {
            if let Some(a) = r.areas.iter_mut().find(|a| a.area == t.area.as_str()) {
                a.budget.allocated = t.grant.quota();
            }
        }
    });
    let parent_snapshot = budget.clone();
    let wave1_started = Instant::now();
    let dones = run_wave(cfg, &tasks, &parent_snapshot, &live);
    let wave1_elapsed = wave1_started.elapsed();
    let mut all_stops: Vec<String> = vec![];
    let mut results: Vec<CaseExecutionResult> = vec![];
    let mut used_total = Quota::default();
    for d in dones {
        budget.absorb(&d.usage);
        all_stops.extend(d.usage.stopped.clone());
        let used = quota_of(&d.usage);
        used_total = sum_quota([used_total, used].into_iter());
        live.update(true, |r| {
            if let Some(a) = r.areas.iter_mut().find(|a| a.area == d.area.as_str()) {
                a.budget.used = used;
                a.stopped = d.usage.stopped.clone();
                a.error = d.error.clone();
                a.status = if d.error.is_some() {
                    "failed"
                } else if d.results.iter().any(|x| {
                    x.status == "SKIPPED" && x.failure_reason.as_deref() == Some("run cancelled")
                }) {
                    "cancelled"
                } else {
                    "done"
                }
                .into();
            }
        });
        results.extend(d.results);
    }
    results = merge_results(results);
    live.update(true, |r| {
        r.pool_reclaimed = Quota {
            steps: granted.steps.saturating_sub(used_total.steps),
            requests: granted.requests.saturating_sub(used_total.requests),
            wall_ms: window.saturating_sub(wave1_elapsed).as_millis() as u64,
            llm_calls: granted.llm_calls.saturating_sub(used_total.llm_calls),
        };
        recount(r, &results, &[]);
    });

    // ---- wave 2
    let mut follow_ups: Vec<PlannedCase> = vec![];
    if !budget.is_cancelled() && budget.wall_left() > Duration::from_millis(500) {
        let avail2 = Available {
            steps: budget.steps_left(),
            // a third of what is left stays for verification and teardown
            requests: budget.requests_left() * 2 / 3,
            wall: budget.wall_left() / 2,
            llm_calls: 0,
        };
        let limit = MAX_WAVE2_CASES.min(avail2.steps).min(avail2.requests / 2);
        let plan = plan_follow_ups(cases, &results, limit);
        if !plan.is_empty() {
            let mut by2: BTreeMap<Area, Vec<PlannedCase>> = BTreeMap::new();
            for f in &plan {
                by2.entry(Area::of(&f.case))
                    .or_default()
                    .push(f.case.clone());
            }
            let tasks2 = tasks_for(&by2, cfg, &avail2, 0);
            let granted2 = sum_quota(tasks2.iter().map(|t| t.grant.quota()));
            live.update(true, |r| {
                r.waves = 2;
                r.pool_granted_wave2 = granted2;
                for f in &plan {
                    r.wave2.push(WaveTwoCase {
                        case_id: f.case.id.clone(),
                        area: Area::of(&f.case).as_str().into(),
                        rule: f.rule.into(),
                        origin: f.origin.clone(),
                        reason: f.reason.clone(),
                    });
                    if !f.resume
                        && let Some(a) = r
                            .areas
                            .iter_mut()
                            .find(|a| a.area == Area::of(&f.case).as_str())
                    {
                        a.wave2_added.push(f.case.id.clone());
                        a.case_ids.push(f.case.id.clone());
                    }
                }
                for t in &tasks2 {
                    if let Some(a) = r.areas.iter_mut().find(|a| a.area == t.area.as_str()) {
                        a.wave2_budget = Some(AreaBudget {
                            allocated: t.grant.quota(),
                            used: Quota::default(),
                        });
                        if a.status == "idle" {
                            a.status = "pending".into();
                        }
                    }
                }
            });
            let snapshot2 = budget.clone();
            let dones2 = run_wave(cfg, &tasks2, &snapshot2, &live);
            let cancelled_now = budget.is_cancelled();
            let resumed: HashSet<String> = plan
                .iter()
                .filter(|f| f.resume)
                .map(|f| f.case.id.clone())
                .collect();
            results.retain(|r| !resumed.contains(&r.case_id));
            for d in dones2 {
                budget.absorb(&d.usage);
                all_stops.extend(d.usage.stopped.clone());
                let used = quota_of(&d.usage);
                live.update(true, |r| {
                    if let Some(a) = r.areas.iter_mut().find(|a| a.area == d.area.as_str()) {
                        if let Some(b) = a.wave2_budget.as_mut() {
                            b.used = used;
                        }
                        if a.stopped.is_none() {
                            a.stopped = d.usage.stopped.clone();
                        }
                        if let Some(e) = &d.error {
                            a.error = Some(e.clone());
                            a.status = "failed".into();
                        } else if a.status != "failed" {
                            a.status = if cancelled_now { "cancelled" } else { "done" }.into();
                        }
                    }
                });
                results.extend(d.results);
            }
            results = merge_results(results);
            follow_ups = plan
                .into_iter()
                .filter(|f| !f.resume)
                .map(|f| f.case)
                .collect();
        }
    }

    // ---- what stopped the run, as the run's own budget reports it
    for s in all_stops.iter().filter(|s| !is_resumable(s)) {
        budget.note_stopped(s.clone());
    }
    if let Some(r) = results
        .iter()
        .filter(|r| r.status == "SKIPPED")
        .find_map(|r| r.failure_reason.as_deref().filter(|m| is_resumable(m)))
    {
        budget.note_stopped(r.to_string());
    }
    let cancelled = budget.is_cancelled();
    live.update(true, |r| {
        r.status = if cancelled { "cancelled" } else { "done" }.into();
        r.pool_left = Quota {
            steps: budget.steps_left(),
            requests: budget.requests_left(),
            wall_ms: budget.wall_left().as_millis() as u64,
            llm_calls: budget.llm_calls_left(),
        };
        if r.waves == 2 {
            r.notes.push(format!(
                "wave 2 added {} follow-up case(s) and resumed {} case(s) from the pool",
                r.wave2.iter().filter(|w| w.rule != RULE_RESUME).count(),
                r.wave2.iter().filter(|w| w.rule == RULE_RESUME).count()
            ));
        }
        if workers == 1 {
            r.notes
                .push("one worker: the areas ran one after another".into());
        }
        recount(r, &results, &[]);
    });
    let agents = live.report.into_inner().unwrap_or_else(|e| e.into_inner());
    LeadOutcome {
        results,
        follow_ups,
        agents,
    }
}
