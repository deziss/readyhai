//! Write turn synchronization, live progress tracking, and wave worker scheduling.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use super::alloc::{Grant, is_write};
use super::area::{Area, MAX_WORKERS, PROGRESS_EVERY};
use crate::agent::budget::{BudgetUsage, RunBudget};
use crate::agent::exec::{CaseGate, ExecOptions, execute_cases_gated};
use crate::agent::types::{
    AgentsReport, AreaReport, CancelToken, CaseExecutionResult, CreatedLedger, PlannedCase,
};

/// What the lead needs from its caller.
pub struct LeadConfig<'a> {
    pub target: &'a str,
    pub opts: &'a ExecOptions,
    /// Worker threads (see [`workers_from_env`]); 1 runs the areas one after another.
    pub workers: usize,
    /// The run's created-resource ledger; every worker records into it.
    pub created: &'a CreatedLedger,
    /// LLM calls the run has left (the workers' slices are carved out of it).
    pub llm_calls_left: usize,
    /// Gets a copy of the [`AgentsReport`] while the run is going.
    pub on_progress: Option<&'a (dyn Fn(&AgentsReport) + Sync)>,
}

/// The one order in which writes reach the target, whatever the worker count.
pub(super) struct Turns {
    index: HashMap<String, usize>,
    state: Mutex<(Vec<bool>, usize)>,
    cv: Condvar,
    cancel: CancelToken,
}

impl Turns {
    pub(super) fn new(order: Vec<String>, cancel: CancelToken) -> Self {
        let n = order.len();
        Turns {
            index: order
                .into_iter()
                .enumerate()
                .map(|(i, id)| (id, i))
                .collect(),
            state: Mutex::new((vec![false; n], 0)),
            cv: Condvar::new(),
            cancel,
        }
    }

    /// Block until every write before `id` is done (or the run is cancelled).
    pub(super) fn wait(&self, id: &str) {
        let Some(&i) = self.index.get(id) else { return };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while st.1 < i && !self.cancel.is_cancelled() {
            st = self
                .cv
                .wait_timeout(st, Duration::from_millis(25))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// `id` is finished (or will never run). Idempotent.
    pub(super) fn done(&self, id: &str) {
        let Some(&i) = self.index.get(id) else { return };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.0[i] = true;
        while st.1 < st.0.len() && st.0[st.1] {
            st.1 += 1;
        }
        self.cv.notify_all();
    }
}

// ---------------------------------------------------------------- live progress

/// The report as it grows, and the observer that gets a copy of it now and then.
pub(super) struct Live<'a> {
    pub(super) report: Mutex<AgentsReport>,
    pub(super) observer: Option<&'a (dyn Fn(&AgentsReport) + Sync)>,
    pub(super) emit: Mutex<Instant>,
}

impl Live<'_> {
    pub(super) fn update(&self, force: bool, f: impl FnOnce(&mut AgentsReport)) {
        f(&mut self.report.lock().unwrap_or_else(|e| e.into_inner()));
        let Some(obs) = self.observer else { return };
        let mut last = self.emit.lock().unwrap_or_else(|e| e.into_inner());
        if !force && last.elapsed() < PROGRESS_EVERY {
            return;
        }
        *last = Instant::now();
        let snap = self
            .report
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        obs(&snap); // under the emit lock: observers never see snapshots out of order
    }
}

pub(super) fn bump(a: &mut AreaReport, results: &[CaseExecutionResult]) {
    for r in results {
        match r.status.as_str() {
            "PASS" => a.pass += 1,
            "WARN" => a.warn += 1,
            "FAIL" => a.fail += 1,
            "INCONCLUSIVE" => a.inconclusive += 1,
            "BLOCKED" => a.blocked += 1,
            "SKIPPED" => {
                a.skipped += 1;
                continue;
            }
            "NOT_APPLICABLE" => continue, // nothing was sent and nothing was skipped
            _ => {}
        }
        a.executed += 1;
    }
}

struct AreaGate<'a> {
    turns: &'a Turns,
    live: &'a Live<'a>,
    area: &'static str,
}

impl CaseGate for AreaGate<'_> {
    fn enter(&self, c: &PlannedCase) {
        if is_write(c) {
            self.turns.wait(&c.id);
        }
    }

    fn leave(&self, c: &PlannedCase, results: &[CaseExecutionResult]) {
        if is_write(c) {
            self.turns.done(&c.id);
        }
        self.live.update(false, |r| {
            if let Some(a) = r.areas.iter_mut().find(|a| a.area == self.area) {
                bump(a, results);
            }
        });
    }
}

// ---------------------------------------------------------------- one wave

pub(super) struct Task {
    pub(super) area: Area,
    pub(super) cases: Vec<PlannedCase>,
    pub(super) grant: Grant,
}

pub(super) struct Done {
    pub(super) area: Area,
    pub(super) grant: Grant,
    pub(super) results: Vec<CaseExecutionResult>,
    pub(super) usage: BudgetUsage,
    pub(super) error: Option<String>,
}

fn run_task(cfg: &LeadConfig, task: &Task, parent: &RunBudget, turns: &Turns, live: &Live) -> Done {
    let name = task.area.as_str();
    live.update(true, |r| {
        if let Some(a) = r.areas.iter_mut().find(|a| a.area == name) {
            a.status = "running".into();
        }
    });
    let mut slice = parent.slice(name, task.grant.limits());
    let gate = AreaGate {
        turns,
        live,
        area: name,
    };
    let out = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _installed = cfg.created.install();
        execute_cases_gated(&task.cases, cfg.target, cfg.opts, &mut slice, Some(&gate))
    }));
    // whatever happened, nobody waits for this area's turns any more
    for c in task.cases.iter().filter(|c| is_write(c)) {
        turns.done(&c.id);
    }
    let usage = slice.usage();
    match out {
        Ok(results) => Done {
            area: task.area,
            grant: task.grant,
            results,
            usage,
            error: None,
        },
        Err(p) => {
            let why = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            let why = format!("the {name} worker panicked: {why}");
            Done {
                area: task.area,
                grant: task.grant,
                results: task
                    .cases
                    .iter()
                    .map(|c| {
                        let mut r = CaseExecutionResult::not_run(c, why.clone());
                        r.status = "BLOCKED".into();
                        r
                    })
                    .collect(),
                usage,
                error: Some(why),
            }
        }
    }
}

/// Run the areas of one wave on up to `workers` threads, taken from the front of the (canonical)
/// task list: a worker only ever waits for an area that is already running or finished.
pub(super) fn run_wave(
    cfg: &LeadConfig,
    tasks: &[Task],
    parent: &RunBudget,
    live: &Live,
) -> Vec<Done> {
    let order: Vec<String> = tasks
        .iter()
        .flat_map(|t| t.cases.iter().filter(|c| is_write(c)).map(|c| c.id.clone()))
        .collect();
    let turns = Turns::new(order, parent.cancel_token().clone());
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Done>>> = tasks.iter().map(|_| Mutex::new(None)).collect();
    let work = || {
        loop {
            let i = next.fetch_add(1, AtomicOrdering::SeqCst);
            let Some(task) = tasks.get(i) else { break };
            let d = run_task(cfg, task, parent, &turns, live);
            *slots[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(d);
        }
    };
    let threads = cfg.workers.clamp(1, MAX_WORKERS).min(tasks.len());
    if threads <= 1 {
        work();
    } else {
        std::thread::scope(|s| {
            for k in 0..threads {
                let spawned = std::thread::Builder::new()
                    .name(format!("readyhai-lead-worker-{k}"))
                    .spawn_scoped(s, work);
                if spawned.is_err() && k == 0 {
                    work(); // no thread could be started at all: run here
                }
            }
        });
    }
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
        .map(|d| d.expect("every area of the wave was run"))
        .collect()
}
