//! The lead: orchestrator-worker structure inside one agent run.
//!
//! The planner tags every case with an [`Area`] (`auth`, `contract`, `state`, `ui`). The lead splits
//! the plan by area, gives every area a [`RunBudget`] slice (steps, requests, wall clock, LLM calls,
//! weighted by the risk of its cases and by change impact), runs the areas on worker threads and
//! merges what they found. Then it plans at most one follow-up wave from deterministic rules and
//! runs it from what is left of the budget. Verification, cleanup, triage and the ledger run on the
//! merged results exactly as before.
//!
//! Rules that keep it deterministic and safe:
//! * **One politeness limit.** The per-host rate lives in the run's [`HostLimiter`](super::budget::HostLimiter),
//!   which every slice shares: N workers together never exceed the configured rate.
//! * **One cancellation flag.** Slices share the run's cancel token (the marker file included); a
//!   worker waiting for a request slot or for its turn wakes up and stops.
//! * **Writes take turns.** Cases that change the target (a write method, a stateful chain, a
//!   burst) run in one fixed order: area order, then plan order. Reads run in parallel. So what the
//!   target hands out (ids, counters) and the order of the created-resource ledger do not depend on
//!   the worker count or on thread timing.
//! * **No dynamic borrowing in a wave.** Slice limits are fixed before the wave starts; what an area
//!   leaves unused is reclaimed after the wave and only wave 2 can spend it.
//! * **Stable merge.** Results are merged by case id (natural order), never by completion time.
//! * **No LLM needed.** Allocation, partition and the wave-2 rules are plain functions of the plan
//!   and the results.
//!
//! Known limit: a read that observes records another area is creating at that moment (a list of
//! orders) can see a different list from run to run; its verdict is judged on its own response and
//! the lists of the fixtures do not feed a verdict. Wall-clock limits that bind cut a run at a time
//! that depends on the machine, with one worker or eight.
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use super::budget::{BudgetUsage, RunBudget, SliceLimits};
use super::exec::normalize_component;
use super::exec::{
    CaseGate, ExecOptions, MAX_REDIRECTS, execute_cases_gated, follows_redirects, is_mutating,
    is_safe_method,
};
use super::oracle::{Technique, is_sensitive_path};
use super::types::{
    AgentsReport, AreaBudget, AreaReport, BlockReason, CancelToken, CaseExecutionResult,
    CreatedLedger, PlannedCase, Quota, TriagedDefect, WaveTwoCase,
};

/// Worker threads when `READYHAI_AGENT_WORKERS` is not set.
pub const DEFAULT_WORKERS: usize = 4;
/// Upper bound for `READYHAI_AGENT_WORKERS`.
pub const MAX_WORKERS: usize = 8;
/// Share of the remaining requests that is not handed to any area in wave 1 (percent). It is the
/// lead's reserve for wave 2 and for what verification and cleanup still need.
const RESERVE_PCT: usize = 15;
/// Share of the remaining wall clock that wave 1 may use (percent).
const WAVE1_WALL_PCT: u32 = 85;
/// No area's wall-clock slice is shorter than this (or than the whole window, when that is shorter).
const MIN_AREA_WALL: Duration = Duration::from_secs(20);
/// LLM calls kept back for the stages after the workers (triage notes, gate advisory, a spare).
const LLM_RESERVE: usize = 3;
/// Most cases wave 2 adds.
pub const MAX_WAVE2_CASES: usize = 12;
/// How often the live progress is handed to the observer at most (unless forced).
const PROGRESS_EVERY: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------- areas

/// A slice of the plan that one worker runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Area {
    /// Access control: authz, BOLA, unauthenticated and forged-token access, sensitive files, CORS.
    Auth,
    /// What the API promises: contract, boundary, negative, injection and latency cases.
    Contract,
    /// What changes the target: stateful chains, bursts, create/update/delete lifecycle.
    State,
    /// Crawl-grounded page and route smoke checks and the SPA checks.
    Ui,
}

impl Area {
    /// The canonical order: partition, allocation, write turns and reports all use it.
    pub const ALL: [Area; 4] = [Area::Auth, Area::Contract, Area::State, Area::Ui];

    pub fn as_str(self) -> &'static str {
        match self {
            Area::Auth => "auth",
            Area::Contract => "contract",
            Area::State => "state",
            Area::Ui => "ui",
        }
    }

    pub fn parse(s: &str) -> Option<Area> {
        Area::ALL
            .into_iter()
            .find(|a| a.as_str().eq_ignore_ascii_case(s.trim()))
    }

    /// The area a case belongs to by what it is (what the planner records in `PlannedCase.area`).
    pub fn classify(c: &PlannedCase) -> Area {
        if c.is_ledger_row() {
            return Area::Ui; // a row of the crawl baseline: what the crawl found, and could not test
        }
        let tech = Technique::parse(&c.technique);
        let chain = c.stateful_steps.as_ref().is_some_and(|s| !s.is_empty());
        let burst = c.concurrency_burst.is_some_and(|n| n > 1);
        if tech == Technique::Authz
            || c.role
                .as_deref()
                .is_some_and(|r| r.trim().eq_ignore_ascii_case("forged"))
        {
            Area::Auth
        } else if chain || burst || (tech == Technique::StateTransition && is_mutating(&c.method)) {
            Area::State
        } else if c.source.as_deref() == Some("deterministic") {
            // the baseline the crawl grounds: page liveness and the probes of discovered pages
            Area::Ui
        } else {
            Area::Contract
        }
    }

    /// The area a case runs in: the planner's tag, else [`Area::classify`] (plans from older builds).
    pub fn of(c: &PlannedCase) -> Area {
        Area::parse(&c.area).unwrap_or_else(|| Area::classify(c))
    }
}

/// `READYHAI_AGENT_WORKERS` text to a worker count: unset or unparsable = 4, clamped to 1..=8.
pub fn parse_workers(raw: Option<&str>) -> usize {
    match raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<usize>().ok())
    {
        Some(n) => n.clamp(1, MAX_WORKERS),
        None => DEFAULT_WORKERS,
    }
}

pub fn workers_from_env() -> usize {
    parse_workers(std::env::var("READYHAI_AGENT_WORKERS").ok().as_deref())
}

// ---------------------------------------------------------------- weights and allocation

fn risk_weight(c: &PlannedCase) -> u64 {
    match c.risk_level.trim().to_ascii_lowercase().as_str() {
        "critical" => 8,
        "high" => 4,
        "low" => 1,
        _ => 2,
    }
}

/// How much a case counts when the budget is shared out: its risk, three times that when it tests
/// an operation the code diff changed.
pub fn case_weight(c: &PlannedCase) -> u64 {
    risk_weight(c) * if c.changed_ops.is_empty() { 1 } else { 3 }
}

/// The most requests a case can cost (every re-run, an adaptive-mutation probe, the reads around a
/// burst, every step of a chain and its controls). An upper bound, so a slice sized from it never
/// binds while the run has requests to give.
pub fn request_demand(c: &PlannedCase, reruns: u32) -> usize {
    if c.is_ledger_row() {
        return 0; // a row of the ledger: nothing is sent
    }
    if let Some(steps) = c.stateful_steps.as_ref().filter(|s| !s.is_empty()) {
        return steps.len() * 3 + 4;
    }
    let attempts = if is_safe_method(&c.method) {
        1 + reruns as usize
    } else {
        1
    };
    let mut n = attempts * 2;
    if follows_redirects(c) {
        n += attempts * MAX_REDIRECTS; // every hop of a followed redirect is a request
    }
    if let Some(b) = c.concurrency_burst.filter(|b| *b > 1) {
        n += (b as usize).min(10) + 2;
    }
    n
}

/// What one area asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AreaNeed {
    pub area: Area,
    pub weight: u64,
    pub cases: usize,
    pub requests: usize,
}

/// What is there to share out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Available {
    pub steps: usize,
    pub requests: usize,
    pub wall: Duration,
    pub llm_calls: usize,
}

/// What one area is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    pub area: Area,
    pub steps: usize,
    pub requests: usize,
    pub wall: Duration,
    pub llm_calls: usize,
}

impl Grant {
    fn limits(&self) -> SliceLimits {
        SliceLimits {
            steps: self.steps,
            requests: self.requests,
            wall: self.wall,
            llm_calls: self.llm_calls,
        }
    }

    fn quota(&self) -> Quota {
        Quota {
            steps: self.steps,
            requests: self.requests,
            wall_ms: self.wall.as_millis() as u64,
            llm_calls: self.llm_calls,
        }
    }
}

/// Share `total` units by `weights`, no one above its cap; what the caps leave is not given out.
/// Integer arithmetic with the largest-remainder rule (ties to the earlier index), repeated while
/// capped shares free units for the others: the same inputs always give the same answer.
pub fn share_capped(total: usize, weights: &[u64], caps: &[usize]) -> Vec<usize> {
    let n = weights.len();
    let mut out = vec![0usize; n];
    let mut left = total;
    while left > 0 {
        let active: Vec<usize> = (0..n).filter(|&i| out[i] < caps[i]).collect();
        if active.is_empty() {
            break;
        }
        let wsum: u128 = active.iter().map(|&i| weights[i].max(1) as u128).sum();
        let mut give = vec![0usize; n];
        let mut rem: Vec<(u128, usize)> = vec![];
        let mut given = 0usize;
        for &i in &active {
            let exact = left as u128 * weights[i].max(1) as u128;
            let q = ((exact / wsum) as usize).min(caps[i] - out[i]);
            give[i] = q;
            given += q;
            rem.push((exact % wsum, i));
        }
        rem.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut spare = left - given;
        for &(_, i) in &rem {
            if spare == 0 {
                break;
            }
            if out[i] + give[i] < caps[i] {
                give[i] += 1;
                spare -= 1;
            }
        }
        let moved: usize = give.iter().sum();
        if moved == 0 {
            break;
        }
        for i in 0..n {
            out[i] += give[i];
        }
        left -= moved;
    }
    out
}

/// Split `avail` over the areas. Steps are capped at the area's case count, requests at its demand
/// (and `reserve_requests` of them are held back), wall clock is the area's weighted share of the
/// window times the worker count (so a lone worker gets its fair share and parallel ones may each
/// use most of the window), never below [`MIN_AREA_WALL`] and never above the window.
pub fn allocate(
    needs: &[AreaNeed],
    avail: &Available,
    reserve_requests: usize,
    workers: usize,
) -> Vec<Grant> {
    let weights: Vec<u64> = needs.iter().map(|n| n.weight).collect();
    let steps = share_capped(
        avail.steps,
        &weights,
        &needs.iter().map(|n| n.cases).collect::<Vec<_>>(),
    );
    let requests = share_capped(
        avail.requests.saturating_sub(reserve_requests),
        &weights,
        &needs.iter().map(|n| n.requests).collect::<Vec<_>>(),
    );
    let llm = share_capped(
        avail.llm_calls,
        &weights,
        &vec![avail.llm_calls; needs.len()],
    );
    let window = avail.wall.as_millis();
    let wsum: u128 = weights
        .iter()
        .map(|w| (*w).max(1) as u128)
        .sum::<u128>()
        .max(1);
    let floor = MIN_AREA_WALL.as_millis().min(window);
    needs
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let raw = window * workers.max(1) as u128 * n.weight.max(1) as u128 / wsum;
            Grant {
                area: n.area,
                steps: steps[i],
                requests: requests[i],
                wall: Duration::from_millis(raw.clamp(floor, window) as u64),
                llm_calls: llm[i],
            }
        })
        .collect()
}

// ---------------------------------------------------------------- write turns

/// A case that may change the target: a write method, a chain with a write step, a burst.
pub fn is_write(c: &PlannedCase) -> bool {
    is_mutating(&c.method)
        || c.concurrency_burst.is_some_and(|n| n > 1)
        || c.stateful_steps
            .as_ref()
            .is_some_and(|s| s.iter().any(|st| is_mutating(&st.method)))
}

/// The one order in which writes reach the target, whatever the worker count.
struct Turns {
    index: HashMap<String, usize>,
    state: Mutex<(Vec<bool>, usize)>,
    cv: Condvar,
    cancel: CancelToken,
}

impl Turns {
    fn new(order: Vec<String>, cancel: CancelToken) -> Self {
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
    fn wait(&self, id: &str) {
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
    fn done(&self, id: &str) {
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
struct Live<'a> {
    report: Mutex<AgentsReport>,
    observer: Option<&'a (dyn Fn(&AgentsReport) + Sync)>,
    emit: Mutex<Instant>,
}

impl Live<'_> {
    fn update(&self, force: bool, f: impl FnOnce(&mut AgentsReport)) {
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

fn bump(a: &mut AreaReport, results: &[CaseExecutionResult]) {
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

struct Task {
    area: Area,
    cases: Vec<PlannedCase>,
    grant: Grant,
}

struct Done {
    area: Area,
    grant: Grant,
    results: Vec<CaseExecutionResult>,
    usage: BudgetUsage,
    error: Option<String>,
}

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

pub struct LeadOutcome {
    /// Every result, merged in case-id order.
    pub results: Vec<CaseExecutionResult>,
    /// The cases wave 2 added to the plan (a resumed case is not new and is not listed).
    pub follow_ups: Vec<PlannedCase>,
    pub agents: AgentsReport,
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
fn run_wave(cfg: &LeadConfig, tasks: &[Task], parent: &RunBudget, live: &Live) -> Vec<Done> {
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

// ---------------------------------------------------------------- merge

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
fn base_id<'a>(known: &HashMap<String, usize>, id: &'a str) -> Option<&'a str> {
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

fn is_resumable(reason: &str) -> bool {
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

// ---------------------------------------------------------------- the run

fn quota_of(u: &BudgetUsage) -> Quota {
    Quota {
        steps: u.steps,
        requests: u.requests,
        wall_ms: u.elapsed_ms,
        llm_calls: u.llm_calls,
    }
}

fn skeleton(by_area: &BTreeMap<Area, Vec<PlannedCase>>, workers: usize) -> AgentsReport {
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

fn tasks_for(
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

fn sum_quota(it: impl Iterator<Item = Quota>) -> Quota {
    it.fold(Quota::default(), |a, q| Quota {
        steps: a.steps + q.steps,
        requests: a.requests + q.requests,
        wall_ms: a.wall_ms + q.wall_ms,
        llm_calls: a.llm_calls + q.llm_calls,
    })
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

// ---------------------------------------------------------------- report bookkeeping

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::exec::Credentials;
    use crate::agent::types::fixtures::planned;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    /// A target that answers 200 to every read, hands out ids to every POST in arrival order, and
    /// logs when each request arrived. `delay` decides how long a request is held.
    struct Stub {
        base: String,
        log: Arc<Mutex<Vec<(Instant, String)>>>,
    }

    impl Stub {
        fn arrivals(&self) -> Vec<Instant> {
            let mut v: Vec<Instant> = self.log.lock().unwrap().iter().map(|(t, _)| *t).collect();
            v.sort();
            v
        }
        fn count(&self) -> usize {
            self.log.lock().unwrap().len()
        }
        fn paths(&self) -> Vec<String> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(_, p)| p.clone())
                .collect()
        }
    }

    fn stub(delay: impl Fn(&str, &str) -> u64 + Send + Sync + 'static) -> Stub {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log: Arc<Mutex<Vec<(Instant, String)>>> = Arc::new(Mutex::new(vec![]));
        let (lg, ids, delay) = (log.clone(), Arc::new(AtomicU64::new(1)), Arc::new(delay));
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let (lg, ids, delay) = (lg.clone(), ids.clone(), delay.clone());
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let head_end = loop {
                        let n = s.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let mut first = head.lines().next().unwrap_or("").split_whitespace();
                    let (method, target) = (
                        first.next().unwrap_or("").to_string(),
                        first.next().unwrap_or("/").to_string(),
                    );
                    let clen: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + clen {
                        let n = s.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let path = target.split('?').next().unwrap_or("/").to_string();
                    lg.lock()
                        .unwrap()
                        .push((Instant::now(), format!("{method} {path}")));
                    let ms = delay(&method, &path);
                    if ms > 0 {
                        std::thread::sleep(Duration::from_millis(ms));
                    }
                    let (code, body) = if method == "POST" {
                        let id = ids.fetch_add(1, AtomicOrdering::SeqCst);
                        (201, format!("{{\"id\": {id}, \"made_at\": \"{path}\"}}"))
                    } else {
                        (200, format!("{{\"ok\": true, \"path\": \"{path}\"}}"))
                    };
                    let _ = s.write_all(
                        format!(
                            "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        Stub { base, log }
    }

    fn case(id: &str, area: &str, method: &str, path: &str, risk: &str) -> PlannedCase {
        let mut c = planned(id, "state_transition", method, path);
        c.area = area.into();
        c.risk_level = risk.into();
        c.role = Some("anon".into());
        c.expected_behavior = "Handled without a server error".into();
        if method == "GET" {
            c.expected_status = Some(200); // the stub answers every read with 200: a PASS
        }
        if method == "POST" {
            c.payload = Some(format!("{{\"n\": \"{id}\"}}"));
        }
        c
    }

    fn opts(reruns: u32) -> ExecOptions {
        ExecOptions {
            dry_run: false,
            is_spa_target: false,
            credentials: Credentials::none(),
            reruns,
            timeout: Duration::from_secs(10),
        }
    }

    fn lead(
        target: &str,
        o: &ExecOptions,
        workers: usize,
        created: &CreatedLedger,
        cases: &[PlannedCase],
        budget: &mut RunBudget,
    ) -> LeadOutcome {
        let cfg = LeadConfig {
            target,
            opts: o,
            workers,
            created,
            llm_calls_left: 0,
            on_progress: None,
        };
        run(&cfg, cases, budget)
    }

    fn shape(r: &[CaseExecutionResult]) -> Vec<(String, String, Option<u16>, String)> {
        r.iter()
            .map(|r| {
                (
                    r.case_id.clone(),
                    r.status.clone(),
                    r.status_code,
                    r.evidence.clone(),
                )
            })
            .collect()
    }

    // ------------------------------------------------------------ pure functions

    #[test]
    fn workers_come_from_the_environment_text_with_a_default_and_a_cap() {
        assert_eq!(parse_workers(None), 4);
        assert_eq!(parse_workers(Some("")), 4);
        assert_eq!(parse_workers(Some("nonsense")), 4);
        assert_eq!(parse_workers(Some("1")), 1);
        assert_eq!(parse_workers(Some(" 6 ")), 6);
        assert_eq!(parse_workers(Some("0")), 1, "never zero threads");
        assert_eq!(parse_workers(Some("64")), 8, "capped at 8");
        assert_eq!(parse_workers(Some("-3")), 4);
    }

    #[test]
    fn areas_follow_what_a_case_is_and_the_planners_tag_wins() {
        let mut bola = planned("a", "authz", "POST", "/orders");
        bola.stateful_steps = Some(vec![]);
        assert_eq!(
            Area::classify(&bola),
            Area::Auth,
            "authz stays auth, chain or not"
        );
        let forged = {
            let mut c = planned("b", "negative", "GET", "/x");
            c.role = Some("forged".into());
            c
        };
        assert_eq!(Area::classify(&forged), Area::Auth);
        let mut burst = planned("c", "boundary", "POST", "/orders");
        burst.concurrency_burst = Some(5);
        assert_eq!(Area::classify(&burst), Area::State);
        assert_eq!(
            Area::classify(&planned("d", "state_transition", "DELETE", "/orders/9")),
            Area::State
        );
        let mut crawl = planned("e", "state_transition", "GET", "/");
        crawl.source = Some("deterministic".into());
        assert_eq!(Area::classify(&crawl), Area::Ui);
        let mut spec = planned("f", "boundary", "POST", "/orders");
        spec.source = Some("openapi".into());
        assert_eq!(Area::classify(&spec), Area::Contract);
        assert_eq!(
            Area::classify(&planned("g", "injection", "GET", "/s")),
            Area::Contract
        );
        // the tag is what runs; an unknown tag falls back to the classification
        let mut tagged = planned("h", "boundary", "GET", "/s");
        tagged.area = "ui".into();
        assert_eq!(Area::of(&tagged), Area::Ui);
        tagged.area = "bogus".into();
        assert_eq!(Area::of(&tagged), Area::Contract);
        assert_eq!(Area::parse(" AUTH "), Some(Area::Auth));
        assert_eq!(
            Area::ALL.map(Area::as_str),
            ["auth", "contract", "state", "ui"]
        );
    }

    #[test]
    fn the_budget_is_shared_by_risk_and_change_impact_with_caps_and_a_reserve() {
        let mut critical = planned("a", "authz", "GET", "/a");
        critical.risk_level = "critical".into();
        let mut changed = planned("b", "boundary", "GET", "/b");
        changed.risk_level = "low".into();
        changed.changed_ops = vec!["GET /b".into()];
        let low = {
            let mut c = planned("c", "boundary", "GET", "/c");
            c.risk_level = "low".into();
            c
        };
        assert_eq!(
            (
                case_weight(&critical),
                case_weight(&changed),
                case_weight(&low)
            ),
            (8, 3, 1)
        );

        // 90 requests, three areas that need a lot: shares follow the weights 8 : 3 : 1
        let needs = [
            AreaNeed {
                area: Area::Auth,
                weight: 8,
                cases: 10,
                requests: 100,
            },
            AreaNeed {
                area: Area::Contract,
                weight: 3,
                cases: 10,
                requests: 100,
            },
            AreaNeed {
                area: Area::State,
                weight: 1,
                cases: 10,
                requests: 100,
            },
        ];
        let avail = Available {
            steps: 100,
            requests: 100,
            wall: Duration::from_secs(120),
            llm_calls: 12,
        };
        let g = allocate(&needs, &avail, 10, 1);
        let req: Vec<usize> = g.iter().map(|g| g.requests).collect();
        assert_eq!(
            req.iter().sum::<usize>(),
            90,
            "everything but the reserve is handed out"
        );
        assert!(req[0] > req[1] && req[1] > req[2], "{req:?}");
        assert_eq!(req, [60, 23, 7]);
        assert_eq!(g.iter().map(|g| g.llm_calls).sum::<usize>(), 12);
        assert_eq!(
            g.iter().map(|g| g.steps).collect::<Vec<_>>(),
            [10, 10, 10],
            "steps are capped at the cases"
        );
        // the same inputs, the same answer
        assert_eq!(allocate(&needs, &avail, 10, 1), g);

        // a small area is never given more than it can use; the rest goes to the others
        let needs = [
            AreaNeed {
                area: Area::Auth,
                weight: 1,
                cases: 2,
                requests: 4,
            },
            AreaNeed {
                area: Area::Contract,
                weight: 1,
                cases: 50,
                requests: 200,
            },
        ];
        let g = allocate(&needs, &avail, 0, 1);
        assert_eq!(
            (g[0].requests, g[1].requests),
            (4, 96),
            "cap, then the others"
        );
        assert_eq!(g[0].steps, 2);
        // not enough requests for the demand: the pool keeps what the caps leave
        let rich = Available {
            requests: 1000,
            ..avail
        };
        let g = allocate(&needs, &rich, 0, 1);
        assert_eq!((g[0].requests, g[1].requests), (4, 200));
        // wall clock: a lone worker gets its weighted share, parallel workers share the window,
        // nobody gets less than 20 s or more than the window
        let needs = [
            AreaNeed {
                area: Area::Auth,
                weight: 9,
                cases: 1,
                requests: 1,
            },
            AreaNeed {
                area: Area::Contract,
                weight: 1,
                cases: 1,
                requests: 1,
            },
        ];
        let one = allocate(&needs, &avail, 0, 1);
        assert_eq!(one[0].wall, Duration::from_millis(108_000));
        assert_eq!(one[1].wall, Duration::from_secs(20), "the floor");
        let four = allocate(&needs, &avail, 0, 4);
        assert_eq!(four[0].wall, Duration::from_secs(120), "the window");
    }

    #[test]
    fn share_capped_is_exact_and_deterministic() {
        assert_eq!(
            share_capped(10, &[1, 1, 1], &[100; 3]),
            [4, 3, 3],
            "ties go to the earlier area"
        );
        assert_eq!(share_capped(10, &[1, 1, 1], &[2, 100, 100]), [2, 4, 4]);
        assert_eq!(share_capped(0, &[1, 1], &[5, 5]), [0, 0]);
        assert_eq!(
            share_capped(100, &[1, 1], &[3, 4]),
            [3, 4],
            "units the caps refuse are not handed out"
        );
        assert_eq!(
            share_capped(7, &[0, 0], &[9, 9]),
            [4, 3],
            "a zero weight counts as one"
        );
    }

    #[test]
    fn results_merge_in_case_id_order_whatever_order_they_arrive_in() {
        use crate::agent::types::fixtures::result;
        let ids = [
            "TC-010",
            "TC-002",
            "TC-002-M1",
            "TC-002-B",
            "TC-009",
            "TC-002-F1",
            "TC-100",
            "CLEANUP-001",
        ];
        let mk = |order: &[&str]| -> Vec<String> {
            merge_results(
                order
                    .iter()
                    .map(|i| result(i, "boundary", "PASS"))
                    .collect(),
            )
            .into_iter()
            .map(|r| r.case_id)
            .collect()
        };
        let want = [
            "CLEANUP-001",
            "TC-002",
            "TC-002-B",
            "TC-002-F1",
            "TC-002-M1",
            "TC-009",
            "TC-010",
            "TC-100",
        ];
        assert_eq!(mk(&ids), want);
        let mut rev = ids;
        rev.reverse();
        assert_eq!(mk(&rev), want);
        assert_eq!(natural_cmp("TC-9", "TC-10"), Ordering::Less);
        assert_eq!(natural_cmp("TC-007", "TC-7"), Ordering::Equal);
    }

    #[test]
    fn wave_two_rules_are_deterministic_and_bounded() {
        use crate::agent::types::fixtures::result;
        let mut admin = case("TC-001", "auth", "GET", "/admin/stats", "critical");
        admin.technique = "authz".into();
        admin.role = Some("anon".into());
        admin.expected_status = Some(401);
        let mut sibling = case("TC-002", "contract", "GET", "/admin/stats", "medium");
        sibling.role = Some("user".into());
        sibling.contract = Some(crate::agent::types::ResponseContract {
            latency: true,
            ..Default::default()
        });
        sibling.expect_fields = vec!["total".into()];
        let mut env = case("TC-003", "auth", "GET", "/.env", "critical");
        env.technique = "authz".into();
        let mut write = case("TC-004", "auth", "POST", "/orders", "critical");
        write.technique = "authz".into();
        let reread = case("TC-005", "contract", "GET", "/orders/1", "medium");
        let post_inc = case("TC-006", "contract", "POST", "/orders", "medium");
        let cut = case("TC-007", "contract", "GET", "/orders/2", "medium");
        let cases = vec![admin, sibling, env, write, reread, post_inc, cut];
        let mut skipped = result("TC-007", "boundary", "SKIPPED");
        skipped.failure_reason =
            Some("request budget exhausted (area 'contract' allocation: 4 requests)".into());
        // TC-005 was rate-limited: that may be gone on a second send
        let mut limited = result("TC-005", "boundary", "INCONCLUSIVE");
        limited.status_code = Some(429);
        let mut limited_sub = result("TC-005-M1", "boundary", "INCONCLUSIVE");
        limited_sub.status_code = Some(429);
        let mut limited_write = result("TC-006", "boundary", "INCONCLUSIVE");
        limited_write.status_code = Some(429);
        let results = vec![
            result("TC-001", "authz", "FAIL"),
            result("TC-002", "boundary", "PASS"),
            result("TC-003", "authz", "FAIL"),
            result("TC-004", "authz", "FAIL"),
            limited,
            limited_sub,
            limited_write,
            skipped,
        ];
        let f = plan_follow_ups(&cases, &results, 10);
        let got: Vec<(&str, &str, bool)> = f
            .iter()
            .map(|f| (f.rule, f.case.id.as_str(), f.resume))
            .collect();
        assert_eq!(
            got,
            [
                (RULE_AUTH_TO_CONTRACT, "TC-001-F1", false),
                (RULE_RESUME, "TC-007", true),
                (RULE_REPROBE, "TC-005-F1", false),
            ],
            "a sensitive file, a write and a sub-case get no follow-up; a write that was INCONCLUSIVE is not repeated"
        );
        let c = &f[0].case;
        assert_eq!(
            (c.method.as_str(), c.component.as_str(), c.area.as_str()),
            ("GET", "/admin/stats", "contract")
        );
        assert_eq!(
            c.role.as_deref(),
            Some("anon"),
            "as the identity that was let in"
        );
        assert!(
            c.contract.is_some() && c.expect_fields == ["total"],
            "the plan's own contract for that endpoint"
        );
        assert!(c.changed_ops.is_empty());
        assert_eq!(Area::of(&f[2].case), Area::Contract);
        // bounded and repeatable
        assert_eq!(plan_follow_ups(&cases, &results, 2).len(), 2);
        assert_eq!(plan_follow_ups(&cases, &results, 0).len(), 0);
        let ids = |l: usize| -> Vec<String> {
            plan_follow_ups(&cases, &results, l)
                .into_iter()
                .map(|f| f.case.id)
                .collect()
        };
        assert_eq!(
            ids(10),
            ids(10),
            "the same plan and results always give the same follow-ups"
        );
        // a follow-up that the plan already holds is not planned twice
        let mut same = cases.clone();
        same[1].role = Some("anon".into());
        assert!(
            plan_follow_ups(&same, &results, 10)
                .iter()
                .all(|f| f.rule != RULE_AUTH_TO_CONTRACT),
            "the plan already reads /admin/stats as anon with that technique"
        );
    }

    #[test]
    fn only_transient_causes_are_reprobed() {
        use crate::agent::types::fixtures::result;
        let cases: Vec<PlannedCase> = (1..=12)
            .map(|i| {
                case(
                    &format!("TC-{i:03}"),
                    "contract",
                    "GET",
                    &format!("/r/{i}"),
                    "medium",
                )
            })
            .collect();
        let inconclusive = |i: usize, code: u16| {
            let mut r = result(&format!("TC-{i:03}"), "boundary", "INCONCLUSIVE");
            r.status_code = Some(code);
            r
        };
        let mut transport = result("TC-009", "boundary", "BLOCKED");
        transport.status_code = None;
        transport.blocked_reason = Some(BlockReason::Transport);
        let mut legacy = result("TC-010", "boundary", "BLOCKED");
        legacy.status_code = None;
        legacy.failure_reason = Some("Connection error: operation timed out".into());
        let mut wall = result("TC-011", "boundary", "BLOCKED");
        wall.blocked_reason = Some(BlockReason::AuthWall);
        wall.status_code = Some(401);
        let mut crashed = result("TC-012", "boundary", "BLOCKED");
        crashed.status_code = None;
        crashed.failure_reason = Some("area worker failed".into());
        let results = vec![
            inconclusive(1, 429), // rate limited
            inconclusive(2, 503), // upstream hiccup
            inconclusive(3, 408), // timeout
            inconclusive(4, 307), // a redirect: the same every time
            inconclusive(5, 200), // no class evidence: the same every time
            inconclusive(6, 405), // a CORS probe on a route that does not serve OPTIONS
            inconclusive(7, 401), // an auth wall
            inconclusive(8, 404),
            transport, // no answer at all
            legacy,    // an older run's transport error
            wall,      // BLOCKED by the wall
            crashed,   // BLOCKED, but not a transport error
        ];
        let follow_ups = plan_follow_ups(&cases, &results, 20);
        let got: Vec<&str> = follow_ups.iter().map(|f| f.origin.as_str()).collect();
        assert_eq!(
            got,
            ["TC-001", "TC-002", "TC-003", "TC-009", "TC-010"],
            "429, 5xx, 408 and a missing answer are re-probed; a redirect, no class evidence, a 405, an auth wall and a 404 are not"
        );
        assert!(
            follow_ups
                .iter()
                .all(|f| f.rule == RULE_REPROBE && f.case.id.ends_with("-F1"))
        );
        for (r, want) in [
            (inconclusive(1, 500), true),
            (inconclusive(1, 599), true),
            (inconclusive(1, 600), false),
            (inconclusive(1, 302), false),
        ] {
            assert_eq!(is_transient(&r), want, "{:?}", r.status_code);
        }
        // a PASS or a FAIL is never "transient"
        assert!(!is_transient(&result("TC-001", "boundary", "PASS")));
        assert!(!is_transient(&result("TC-001", "boundary", "FAIL")));
    }

    #[test]
    fn a_ledger_row_asks_for_no_requests_and_a_followed_redirect_asks_for_more() {
        let mut row = case("TC-001", "ui", "GET", "/", "low");
        row.technique = "injection".into();
        row.source = Some(crate::agent::types::SRC_NOT_APPLICABLE.into());
        assert_eq!(request_demand(&row, 2), 0);
        assert_eq!(
            Area::classify(&row),
            Area::Ui,
            "the rows of the crawl baseline"
        );
        let mut wall = row.clone();
        wall.source = Some(crate::agent::types::SRC_AUTH_WALL.into());
        assert_eq!(request_demand(&wall, 2), 0);
        // a read that follows redirects: every hop of every attempt is a request
        let mut read = case("TC-002", "contract", "GET", "/page", "low");
        read.technique = "state_transition".into();
        assert_eq!(request_demand(&read, 2), 3 * 2 + 3 * MAX_REDIRECTS);
        // an authorization case keeps the raw status, so it never redirects
        let mut authz = case("TC-003", "auth", "GET", "/admin", "low");
        authz.technique = "authz".into();
        assert_eq!(request_demand(&authz, 2), 3 * 2);
        // a write is sent once and never redirected
        let write = case("TC-004", "state", "POST", "/orders", "low");
        assert_eq!(request_demand(&write, 2), 2);
    }

    // ------------------------------------------------------------ the workers

    #[test]
    fn every_area_is_held_to_its_own_budget() {
        let s = stub(|_, _| 0);
        let o = opts(0);
        let created = CreatedLedger::new();
        // 12 critical reads in one area, 2 low ones in another, and only 10 requests for the run
        let mut cases: Vec<PlannedCase> = (1..=12)
            .map(|i| {
                case(
                    &format!("TC-{i:03}"),
                    "auth",
                    "GET",
                    &format!("/a/{i}"),
                    "critical",
                )
            })
            .collect();
        cases.extend((13..=14).map(|i| {
            case(
                &format!("TC-{i:03}"),
                "contract",
                "GET",
                &format!("/c/{i}"),
                "low",
            )
        }));
        let mut budget = RunBudget::new(100, 10, Duration::from_secs(60), 0.0);
        let out = lead(&s.base, &o, 4, &created, &cases, &mut budget);
        for a in &out.agents.areas {
            assert!(
                a.budget.used.requests <= a.budget.allocated.requests
                    && a.budget.used.steps <= a.budget.allocated.steps,
                "{a:?}"
            );
            if let Some(w) = a.wave2_budget {
                assert!(w.used.requests <= w.allocated.requests, "{a:?}");
            }
        }
        assert!(
            s.count() <= 10,
            "the run asked for at most 10 requests, the target saw {}",
            s.count()
        );
        assert_eq!(
            budget.requests_used(),
            s.count(),
            "what the workers used is charged to the run"
        );
        let cut: Vec<&CaseExecutionResult> = out
            .results
            .iter()
            .filter(|r| r.status == "SKIPPED")
            .collect();
        assert!(!cut.is_empty());
        assert!(
            cut.iter().all(|r| {
                let m = r.failure_reason.as_deref().unwrap();
                m.starts_with("request budget exhausted") && m.contains("allocation")
            }),
            "{:?}",
            cut.iter().map(|r| &r.failure_reason).collect::<Vec<_>>()
        );
        let auth = out.agents.areas.iter().find(|a| a.area == "auth").unwrap();
        assert!(auth.budget.allocated.requests < 12, "{auth:?}");
        assert!(
            budget
                .stopped()
                .unwrap()
                .starts_with("request budget exhausted")
        );
    }

    #[test]
    fn what_an_area_leaves_unused_goes_to_a_pool_that_resumes_the_cases_another_area_ran_out_for() {
        let s = stub(|_, _| 0);
        let o = opts(2); // a read may cost 6 requests in the worst case, it costs 1
        let created = CreatedLedger::new();
        let mut cases: Vec<PlannedCase> = (1..=10)
            .map(|i| {
                case(
                    &format!("TC-{i:03}"),
                    "auth",
                    "GET",
                    &format!("/a/{i}"),
                    "critical",
                )
            })
            .collect();
        cases.extend((11..=20).map(|i| {
            case(
                &format!("TC-{i:03}"),
                "contract",
                "GET",
                &format!("/c/{i}"),
                "low",
            )
        }));
        let mut budget = RunBudget::new(100, 40, Duration::from_secs(60), 0.0);
        let out = lead(&s.base, &o, 2, &created, &cases, &mut budget);
        let a = &out.agents;
        let auth = a.areas.iter().find(|x| x.area == "auth").unwrap();
        let con = a.areas.iter().find(|x| x.area == "contract").unwrap();
        // the heavy area was given far more than it needed, the light one was cut short
        assert!(
            auth.budget.allocated.requests >= 20 && auth.budget.used.requests == 10,
            "{auth:?}"
        );
        assert!(
            con.budget.used.requests == con.budget.allocated.requests
                && con.budget.used.requests < 10,
            "{con:?}"
        );
        assert!(a.pool_reclaimed.requests >= 20, "{a:?}");
        // wave 2 runs what was cut off from the pool
        assert_eq!(a.waves, 2);
        assert!(
            con.wave2_budget.is_some_and(|b| b.used.requests > 0),
            "{con:?}"
        );
        assert!(
            !a.wave2.is_empty()
                && a.wave2
                    .iter()
                    .all(|w| w.rule == RULE_RESUME && w.area == "contract")
        );
        assert!(
            out.follow_ups.is_empty(),
            "a resumed case is not a new case"
        );
        assert_eq!(out.results.len(), 20);
        assert!(
            out.results.iter().all(|r| r.status != "SKIPPED"),
            "{:?}",
            shape(&out.results)
        );
        assert_eq!(s.count(), 20, "every case was sent exactly once");
        assert!(budget.stopped().is_none(), "nothing is left cut off");
        assert!(a.pool_left.requests == 40 - 20);
    }

    #[test]
    fn cancelling_the_run_stops_every_worker() {
        let s = stub(|_, _| 120);
        let o = opts(0);
        let created = CreatedLedger::new();
        let mut cases = vec![];
        for (k, area) in ["auth", "contract", "state", "ui"].iter().enumerate() {
            for i in 0..20 {
                cases.push(case(
                    &format!("TC-{:03}", k * 20 + i + 1),
                    area,
                    "GET",
                    &format!("/{area}/{i}"),
                    "medium",
                ));
            }
        }
        let mut budget = RunBudget::new(1000, 5000, Duration::from_secs(120), 0.0);
        let token = budget.cancel_token().clone();
        let t0 = Instant::now();
        let out = std::thread::scope(|sc| {
            let h = sc.spawn(|| lead(&s.base, &o, 4, &created, &cases, &mut budget));
            std::thread::sleep(Duration::from_millis(300));
            token.cancel();
            h.join().unwrap()
        });
        let took = t0.elapsed();
        assert!(
            took < Duration::from_millis(1800),
            "20 cases x 120 ms per area would take 2.4 s: {took:?}"
        );
        assert!(s.count() < 4 * 20 / 2, "{} requests were sent", s.count());
        assert_eq!(out.agents.status, "cancelled");
        assert_eq!(out.agents.waves, 1, "no wave 2 for a cancelled run");
        for a in &out.agents.areas {
            assert_eq!(a.status, "cancelled", "{a:?}");
            assert!(a.skipped > 0 && a.executed > 0, "{a:?}");
        }
        assert!(
            out.results
                .iter()
                .filter(|r| r.status == "SKIPPED")
                .all(|r| r.failure_reason.as_deref() == Some("run cancelled"))
        );
        assert_eq!(
            out.results.len(),
            cases.len(),
            "every case still has a result"
        );
    }

    #[test]
    fn writes_take_turns_so_one_worker_and_four_give_the_same_results_and_ledger() {
        // The slow area's POSTs arrive last unless the lead orders them: without the turns, the
        // fast areas would hand out the low ids.
        let mut cases = vec![];
        let mut n = 0;
        for (area, base) in [
            ("auth", "/slow"),
            ("contract", "/fast"),
            ("state", "/fast"),
            ("ui", "/fast"),
        ] {
            for i in 0..3 {
                n += 1;
                cases.push(case(
                    &format!("TC-{n:03}"),
                    area,
                    "POST",
                    &format!("{base}/{area}{i}"),
                    "medium",
                ));
                n += 1;
                cases.push(case(
                    &format!("TC-{n:03}"),
                    area,
                    "GET",
                    &format!("/read/{area}{i}"),
                    "low",
                ));
            }
        }
        let run_with = |workers: usize| {
            let s = stub(|_, p| if p.starts_with("/slow") { 60 } else { 0 });
            let created = CreatedLedger::new();
            let mut budget = RunBudget::new(200, 2000, Duration::from_secs(60), 0.0);
            let out = lead(&s.base, &opts(2), workers, &created, &cases, &mut budget);
            (
                shape(&out.results),
                created.entries(),
                out.agents
                    .areas
                    .iter()
                    .map(|a| (a.area.clone(), a.executed, a.pass, a.fail))
                    .collect::<Vec<_>>(),
                s.count(),
            )
        };
        let one = run_with(1);
        assert_eq!(one.3, 24);
        assert_eq!(one.1.len(), 12, "every POST was recorded for teardown");
        let ids: Vec<&str> = one.1.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"
            ],
            "the ledger is in write order"
        );
        assert!(
            one.1[0].path.starts_with("/slow/"),
            "auth writes come first: {:?}",
            one.1[0]
        );
        for workers in [4, 4, 8] {
            let many = run_with(workers);
            assert_eq!(many.0, one.0, "results with {workers} workers");
            assert_eq!(
                many.1, one.1,
                "created-resource ledger with {workers} workers"
            );
            assert_eq!(many.2, one.2, "per-area counts with {workers} workers");
        }
    }

    #[test]
    fn a_failed_access_check_triggers_one_contract_follow_up_wave_within_the_pool() {
        let s = stub(|_, _| 0);
        let o = opts(0);
        let created = CreatedLedger::new();
        // /admin/stats answers 200 to a request without credentials: the access check fails
        let mut admin = case("TC-001", "auth", "GET", "/admin/stats", "critical");
        admin.technique = "authz".into();
        admin.expected_status = Some(401);
        admin.secured = Some(true);
        let ok = case("TC-002", "contract", "GET", "/health", "low");
        let cases = vec![admin, ok];
        let mut budget = RunBudget::new(50, 100, Duration::from_secs(60), 0.0);
        let out = lead(&s.base, &o, 4, &created, &cases, &mut budget);
        let a = &out.agents;
        assert_eq!(a.waves, 2);
        assert_eq!(out.follow_ups.len(), 1);
        let f = &out.follow_ups[0];
        assert_eq!(
            (f.id.as_str(), f.area.as_str(), f.component.as_str()),
            ("TC-001-F1", "contract", "/admin/stats")
        );
        assert_eq!(a.wave2.len(), 1);
        assert_eq!(
            (a.wave2[0].rule.as_str(), a.wave2[0].origin.as_str()),
            (RULE_AUTH_TO_CONTRACT, "TC-001")
        );
        let contract = a.areas.iter().find(|x| x.area == "contract").unwrap();
        assert_eq!(contract.wave2_added, ["TC-001-F1"]);
        assert!(contract.case_ids.contains(&"TC-001-F1".to_string()));
        assert!(
            contract
                .wave2_budget
                .is_some_and(|b| b.used.requests == 1 && b.allocated.requests >= 1)
        );
        let ids: Vec<&str> = out.results.iter().map(|r| r.case_id.as_str()).collect();
        assert_eq!(
            ids,
            ["TC-001", "TC-001-F1", "TC-002"],
            "merged in case-id order, the follow-up next to its origin"
        );
        assert_eq!(out.results[0].status, "FAIL");
        assert_eq!(
            s.paths()
                .iter()
                .filter(|p| *p == "GET /admin/stats")
                .count(),
            2,
            "the original and the follow-up"
        );
        assert_eq!(budget.requests_used(), 3);
        // no third wave, ever: the follow-up's own outcome plans nothing
        assert_eq!(a.waves, 2);
        // a run with nothing to follow up has one wave and an empty wave-2 list
        let s2 = stub(|_, _| 0);
        let mut b2 = RunBudget::new(50, 100, Duration::from_secs(60), 0.0);
        let calm = lead(&s2.base, &o, 4, &CreatedLedger::new(), &cases[1..], &mut b2);
        assert_eq!(
            (
                calm.agents.waves,
                calm.agents.wave2.len(),
                calm.follow_ups.len()
            ),
            (1, 0, 0)
        );
        // an exhausted step allowance leaves no pool for wave 2
        let s3 = stub(|_, _| 0);
        let mut b3 = RunBudget::new(2, 100, Duration::from_secs(60), 0.0);
        let tight = lead(&s3.base, &o, 4, &CreatedLedger::new(), &cases, &mut b3);
        assert_eq!(
            tight.agents.waves, 1,
            "the plan used every step: nothing left for follow-ups"
        );
    }

    #[test]
    fn the_global_rate_limit_holds_while_workers_run_in_parallel() {
        let s = stub(|_, _| 0);
        let o = opts(0);
        let created = CreatedLedger::new();
        let mut cases = vec![];
        for (k, area) in ["auth", "contract", "state", "ui"].iter().enumerate() {
            for i in 0..8 {
                cases.push(case(
                    &format!("TC-{:03}", k * 8 + i + 1),
                    area,
                    "GET",
                    &format!("/{area}/{i}"),
                    "medium",
                ));
            }
        }
        let gap = Duration::from_millis(25); // 40 requests per second for the host, for all workers together
        let mut budget = RunBudget::new(200, 2000, Duration::from_secs(60), 40.0);
        let t0 = Instant::now();
        let out = lead(&s.base, &o, 4, &created, &cases, &mut budget);
        let took = t0.elapsed();
        assert_eq!(out.results.len(), 32);
        let t = s.arrivals();
        assert_eq!(t.len(), 32);
        assert!(
            t[31].duration_since(t[0]) >= gap * 31 * 8 / 10,
            "32 requests at 40/s arrived within {:?}: each worker paced itself, not the run",
            t[31].duration_since(t[0])
        );
        for w in t.windows(5) {
            assert!(
                w[4].duration_since(w[0]) >= gap * 2,
                "5 requests in {:?}",
                w[4].duration_since(w[0])
            );
        }
        assert!(took >= gap * 31 * 8 / 10, "{took:?}");
    }

    #[test]
    fn progress_is_visible_while_the_areas_run_and_ends_complete() {
        let s = stub(|_, _| 150);
        let o = opts(0);
        let created = CreatedLedger::new();
        let mut cases = vec![];
        for (k, area) in ["auth", "contract"].iter().enumerate() {
            for i in 0..6 {
                cases.push(case(
                    &format!("TC-{:03}", k * 6 + i + 1),
                    area,
                    "GET",
                    &format!("/{area}/{i}"),
                    "medium",
                ));
            }
        }
        let seen: Mutex<Vec<AgentsReport>> = Mutex::new(vec![]);
        let observe = |a: &AgentsReport| seen.lock().unwrap().push(a.clone());
        let cfg = LeadConfig {
            target: &s.base,
            opts: &o,
            workers: 2,
            created: &created,
            llm_calls_left: 0,
            on_progress: Some(&observe),
        };
        let mut budget = RunBudget::new(100, 500, Duration::from_secs(60), 0.0);
        let out = run(&cfg, &cases, &mut budget);
        let seen = seen.into_inner().unwrap();
        assert!(seen.len() >= 4, "{} snapshots", seen.len());
        assert!(
            seen.iter()
                .any(|a| a.areas.iter().any(|x| x.status == "running")),
            "an area was seen running"
        );
        assert!(
            seen.iter().any(|a| a
                .areas
                .iter()
                .any(|x| x.area == "auth" && x.executed > 0 && x.executed < 6)),
            "a snapshot in the middle of an area"
        );
        assert_eq!(seen[0].status, "running");
        assert_eq!(out.agents.status, "done");
        assert!(
            out.agents
                .areas
                .iter()
                .filter(|a| a.cases > 0)
                .all(|a| a.status == "done" && a.executed == 6)
        );
        assert_eq!(
            out.agents
                .areas
                .iter()
                .find(|a| a.area == "ui")
                .unwrap()
                .status,
            "idle"
        );
    }

    #[test]
    fn a_panicking_worker_is_reported_and_does_not_take_the_others_down() {
        use std::sync::atomic::AtomicBool;
        let s = stub(|_, _| 100);
        let o = opts(0);
        let created = CreatedLedger::new();
        let mut cases = vec![];
        for (k, area) in ["auth", "contract"].iter().enumerate() {
            for i in 0..3 {
                cases.push(case(
                    &format!("TC-{:03}", k * 3 + i + 1),
                    area,
                    "GET",
                    &format!("/{area}/{i}"),
                    "medium",
                ));
            }
        }
        // the progress observer runs inside the workers: make it panic once, mid-run
        let boom = AtomicBool::new(false);
        let observe = |a: &AgentsReport| {
            if a.areas.iter().any(|x| x.executed > 0) && !boom.swap(true, AtomicOrdering::SeqCst) {
                panic!("observer boom");
            }
        };
        let cfg = LeadConfig {
            target: &s.base,
            opts: &o,
            workers: 2,
            created: &created,
            llm_calls_left: 0,
            on_progress: Some(&observe),
        };
        let mut budget = RunBudget::new(100, 500, Duration::from_secs(60), 0.0);
        let out = run(&cfg, &cases, &mut budget);
        let failed: Vec<&AreaReport> = out
            .agents
            .areas
            .iter()
            .filter(|a| a.status == "failed")
            .collect();
        assert_eq!(failed.len(), 1, "{:?}", out.agents.areas);
        assert!(
            failed[0].error.as_deref().unwrap().contains("panicked"),
            "{failed:?}"
        );
        let healthy = out
            .agents
            .areas
            .iter()
            .find(|a| a.cases > 0 && a.status != "failed")
            .unwrap();
        assert!(
            healthy.status == "done" && healthy.executed == 3,
            "{healthy:?}"
        );
        assert_eq!(
            out.results.len(),
            6,
            "the failed area's cases are BLOCKED, not lost"
        );
        assert_eq!(
            out.results.iter().filter(|r| r.status == "BLOCKED").count(),
            3
        );
        assert_eq!(out.agents.status, "done");
    }

    #[test]
    fn the_reports_show_an_agents_section_per_area_with_budgets_and_wave_two_escaped() {
        use crate::agent::types::fixtures::{report, result};
        let mut rep = report("run-agents-report");
        let mut a = AgentsReport {
            workers: 4,
            status: "done".into(),
            waves: 2,
            areas: vec![
                AreaReport {
                    area: "auth".into(),
                    status: "done".into(),
                    cases: 14,
                    case_ids: vec!["TC-001".into(), "TC-002".into()],
                    budget: AreaBudget {
                        allocated: Quota {
                            steps: 14,
                            requests: 64,
                            wall_ms: 90_000,
                            llm_calls: 2,
                        },
                        used: Quota {
                            steps: 14,
                            requests: 20,
                            wall_ms: 2_500,
                            llm_calls: 0,
                        },
                    },
                    ..Default::default()
                },
                AreaReport {
                    area: "contract".into(),
                    status: "done".into(),
                    cases: 26,
                    case_ids: vec!["TC-003".into(), "TC-001-F1".into()],
                    budget: AreaBudget {
                        allocated: Quota {
                            steps: 26,
                            requests: 116,
                            ..Default::default()
                        },
                        used: Quota {
                            steps: 26,
                            requests: 32,
                            ..Default::default()
                        },
                    },
                    wave2_budget: Some(AreaBudget {
                        allocated: Quota {
                            steps: 1,
                            requests: 6,
                            ..Default::default()
                        },
                        used: Quota {
                            steps: 1,
                            requests: 1,
                            ..Default::default()
                        },
                    }),
                    wave2_added: vec!["TC-001-F1".into()],
                    stopped: Some("<script>alert(1)</script> stopped".into()),
                    ..Default::default()
                },
            ],
            wave2: vec![WaveTwoCase {
                case_id: "TC-001-F1".into(),
                area: "contract".into(),
                rule: RULE_AUTH_TO_CONTRACT.into(),
                origin: "TC-001".into(),
                reason: "GET /<img src=x onerror=alert(1)> failed an access-control check".into(),
            }],
            ..Default::default()
        };
        let mut fail = result("TC-001", "authz", "FAIL");
        fail.failure_reason = Some("expected 401".into());
        let mut d = TriagedDefect::default();
        d.id = "DEF-001".into();
        d.case_ids = vec!["TC-001".into()];
        recount(
            &mut a,
            &[
                fail,
                result("TC-003", "boundary", "PASS"),
                result("TC-001-F1", "boundary", "PASS"),
            ],
            &[d],
        );
        let auth = &a.areas[0];
        assert_eq!(
            (auth.executed, auth.fail, auth.defect_ids.clone()),
            (1, 1, vec!["DEF-001".to_string()])
        );
        let contract = &a.areas[1];
        assert_eq!(
            (contract.executed, contract.pass),
            (2, 2),
            "a follow-up counts for its area"
        );
        rep.agents = Some(a);
        let md = crate::agent::generate_agent_markdown_report(&rep);
        assert!(
            md.contains("## Agents") && md.contains("**4** worker(s) over **2** wave(s)"),
            "{md}"
        );
        assert!(md.contains("| `auth` | done | 14 | 1 | 0 | 1 | 0 | 14/14 | 20/64 | 2.5s/90.0s | 0/2 | DEF-001 |"), "{md}");
        assert!(
            md.contains("1/1 + w2 1/6") || md.contains("32/116 + w2 1/6"),
            "{md}"
        );
        assert!(
            md.contains("### Wave 2 additions")
                && md.contains("`TC-001-F1`")
                && md.contains(RULE_AUTH_TO_CONTRACT)
        );
        assert!(
            !md.contains("<script>") && !md.contains("<img"),
            "markdown text is escaped"
        );
        let html = crate::agent::generate_agent_html_report(&rep);
        assert!(html.contains("<h2>Agents</h2>") && html.contains("<h3>Wave 2 additions</h3>"));
        assert!(
            html.contains("<code>auth</code>") && html.contains("20/64"),
            "{html}"
        );
        assert!(
            !html.contains("<script>alert(1)</script>") && !html.contains("<img src=x"),
            "html text is escaped"
        );
        // the JSON report carries the same data, and a report without it still loads
        let json = serde_json::to_string(&rep).unwrap();
        let back: crate::agent::AgentRunReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agents, rep.agents);
        let mut old = serde_json::to_value(&rep).unwrap();
        old.as_object_mut().unwrap().remove("agents");
        let old: crate::agent::AgentRunReport = serde_json::from_value(old).unwrap();
        assert!(old.agents.is_none());
        assert!(!crate::agent::generate_agent_markdown_report(&old).contains("## Agents"));
    }
}
