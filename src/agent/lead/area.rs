//! Area definition, classification, and workload weighting.

use std::time::Duration;

use crate::agent::exec::{MAX_REDIRECTS, follows_redirects, is_mutating, is_safe_method};
use crate::agent::oracle::Technique;
use crate::agent::types::PlannedCase;

/// Worker threads when `READYHAI_AGENT_WORKERS` is not set.
pub const DEFAULT_WORKERS: usize = 4;
/// Upper bound for `READYHAI_AGENT_WORKERS`.
pub const MAX_WORKERS: usize = 8;
/// Share of the remaining requests that is not handed to any area in wave 1 (percent). It is the
/// lead's reserve for wave 2 and for what verification and cleanup still need.
pub(super) const RESERVE_PCT: usize = 15;
/// Share of the remaining wall clock that wave 1 may use (percent).
pub(super) const WAVE1_WALL_PCT: u32 = 85;
/// No area's wall-clock slice is shorter than this (or than the whole window, when that is shorter).
pub(super) const MIN_AREA_WALL: Duration = Duration::from_secs(20);
/// LLM calls kept back for the stages after the workers (triage notes, gate advisory, a spare).
pub(super) const LLM_RESERVE: usize = 3;
/// Most cases wave 2 adds.
pub const MAX_WAVE2_CASES: usize = 12;
/// How often the live progress is handed to the observer at most (unless forced).
pub(super) const PROGRESS_EVERY: Duration = Duration::from_millis(250);

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
        } else if c.source.as_deref() == Some("deterministic")
            || c.source.as_deref() == Some("directives")
            || (tech == Technique::Injection
                && matches!(
                    c.source.as_deref(),
                    Some("attacks") | Some("llm") | Some("directives")
                ))
        {
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
