//! Run budget: how much a single agent run may do to the target.
//!
//! * steps: executed test cases (a flaky re-run is a request, not a step) -- `--max-steps`
//! * requests: every HTTP request sent to the target, discovery and re-runs included
//! * wall clock: the whole run (LLM time included)
//! * per-host rate: minimum gap between two requests to the same host
//! * LLM calls and LLM time: every provider call the run makes is counted here (see [`RunBudget::llm_budget`])
//! * cancellation: checked wherever a step or a request is taken, so a run stops between steps
//! * slices: the lead hands every area worker a [`RunBudget::slice`] of the run's allowance. A slice
//!   has its own counters and limits but shares the run's cancellation token and its per-host
//!   [`HostLimiter`], so politeness toward the target is global, not per worker.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::types::CancelToken;

/// Default cap on provider calls per run.
pub const DEFAULT_MAX_LLM_CALLS: usize = 20;
/// No single LLM stage may keep the run busy longer than this, whatever wall clock is left.
const LLM_TIME_CAP: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetUsage {
    pub steps: usize,
    pub max_steps: usize,
    pub requests: usize,
    pub max_requests: usize,
    pub elapsed_ms: u64,
    pub max_wall_ms: u64,
    pub rate_per_host_per_sec: f64,
    /// Set when a limit cut the run short.
    pub stopped: Option<String>,
    /// Provider calls made (cache hits are free and not counted).
    #[serde(default)]
    pub llm_calls: usize,
    #[serde(default)]
    pub max_llm_calls: usize,
    /// Wall time spent inside provider calls.
    #[serde(default)]
    pub llm_ms: u64,
}

/// The per-host pacing of a run: one schedule of request slots per host, shared by every clone of
/// the budget and every slice of it, so N parallel workers together never exceed the configured
/// rate. A slot is reserved under the lock and waited for outside it; the schedule never moves back.
#[derive(Debug)]
pub struct HostLimiter {
    gap: Option<Duration>,
    next: Mutex<HashMap<String, Instant>>,
}

impl HostLimiter {
    /// `rate_per_host`: requests per second per host; 0 or less disables pacing.
    pub fn new(rate_per_host: f64) -> Self {
        HostLimiter {
            gap: (rate_per_host > 0.0).then(|| Duration::from_secs_f64(1.0 / rate_per_host)),
            next: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve the next slot for `host`. `Err` when the slot would only come after `deadline`
    /// (nothing is reserved then).
    fn reserve(&self, host: &str, deadline: Instant) -> Result<Instant, ()> {
        let Some(gap) = self.gap else {
            return Ok(Instant::now());
        };
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let slot = next.get(host).map_or(now, |n| (*n).max(now));
        if slot > now && slot >= deadline {
            return Err(());
        }
        next.insert(host.to_string(), slot + gap);
        Ok(slot)
    }
}

/// What a worker's [`RunBudget::slice`] may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceLimits {
    pub steps: usize,
    pub requests: usize,
    pub wall: Duration,
    pub llm_calls: usize,
}

#[derive(Debug, Clone)]
pub struct RunBudget {
    max_steps: usize,
    max_requests: usize,
    max_wall: Duration,
    rate: f64,
    started: Instant,
    steps: usize,
    requests: usize,
    limiter: Arc<HostLimiter>,
    stopped: Option<String>,
    max_llm_calls: usize,
    llm_calls: usize,
    llm_time: Duration,
    cancel: CancelToken,
    /// Set on a slice: the area it belongs to, named in its limit messages.
    label: Option<String>,
}

impl Default for RunBudget {
    fn default() -> Self {
        Self::new(60, 600, Duration::from_secs(900), 10.0)
    }
}

impl RunBudget {
    /// `rate_per_host`: requests per second per host; 0 or less disables pacing.
    pub fn new(
        max_steps: usize,
        max_requests: usize,
        max_wall: Duration,
        rate_per_host: f64,
    ) -> Self {
        RunBudget {
            max_steps,
            max_requests,
            max_wall,
            rate: rate_per_host,
            started: Instant::now(),
            steps: 0,
            requests: 0,
            limiter: Arc::new(HostLimiter::new(rate_per_host)),
            stopped: None,
            max_llm_calls: DEFAULT_MAX_LLM_CALLS,
            llm_calls: 0,
            llm_time: Duration::ZERO,
            cancel: CancelToken::new(),
            label: None,
        }
    }

    /// Defaults, overridden by READYHAI_AGENT_MAX_STEPS / _MAX_REQUESTS / _MAX_SECONDS / _RATE_PER_HOST
    /// / _MAX_LLM_CALLS.
    pub fn from_env() -> Self {
        fn num<T: std::str::FromStr>(k: &str) -> Option<T> {
            std::env::var(k).ok().and_then(|v| v.trim().parse().ok())
        }
        let d = Self::default();
        Self::new(
            num("READYHAI_AGENT_MAX_STEPS").unwrap_or(d.max_steps),
            num("READYHAI_AGENT_MAX_REQUESTS").unwrap_or(d.max_requests),
            Duration::from_secs(num("READYHAI_AGENT_MAX_SECONDS").unwrap_or(d.max_wall.as_secs())),
            num("READYHAI_AGENT_RATE_PER_HOST").unwrap_or(d.rate),
        )
        .with_max_llm_calls(num("READYHAI_AGENT_MAX_LLM_CALLS").unwrap_or(d.max_llm_calls))
    }

    /// What `readyhai agent --max-steps N` should pass.
    pub fn with_max_steps(mut self, n: usize) -> Self {
        self.max_steps = n;
        self
    }

    pub fn with_max_requests(mut self, n: usize) -> Self {
        self.max_requests = n;
        self
    }

    pub fn with_max_wall(mut self, d: Duration) -> Self {
        self.max_wall = d;
        self
    }

    pub fn with_rate(mut self, per_host_per_sec: f64) -> Self {
        self.rate = per_host_per_sec;
        self.limiter = Arc::new(HostLimiter::new(per_host_per_sec));
        self
    }

    pub fn with_max_llm_calls(mut self, n: usize) -> Self {
        self.max_llm_calls = n;
        self
    }

    /// Stop the run at its next step/request when `token` is cancelled.
    pub fn with_cancel(mut self, token: CancelToken) -> Self {
        self.cancel = token;
        self
    }

    pub fn cancel_token(&self) -> &CancelToken {
        &self.cancel
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub fn max_steps(&self) -> usize {
        self.max_steps
    }

    pub fn max_requests(&self) -> usize {
        self.max_requests
    }

    pub fn max_llm_calls(&self) -> usize {
        self.max_llm_calls
    }

    pub fn steps_left(&self) -> usize {
        self.max_steps.saturating_sub(self.steps)
    }

    pub fn requests_left(&self) -> usize {
        self.max_requests.saturating_sub(self.requests)
    }

    pub fn wall_left(&self) -> Duration {
        self.max_wall.saturating_sub(self.started.elapsed())
    }

    pub fn llm_calls_left(&self) -> usize {
        self.max_llm_calls.saturating_sub(self.llm_calls)
    }

    /// A budget for one area worker: its own counters and limits, but the run's cancellation token
    /// and the run's per-host limiter, so every worker is paced together. The wall clock of the
    /// slice starts now and never outlives what is left of the run.
    pub fn slice(&self, label: &str, l: SliceLimits) -> RunBudget {
        RunBudget {
            max_steps: l.steps,
            max_requests: l.requests,
            max_wall: l.wall.min(self.wall_left()),
            rate: self.rate,
            started: Instant::now(),
            steps: 0,
            requests: 0,
            limiter: Arc::clone(&self.limiter),
            stopped: None,
            max_llm_calls: l.llm_calls,
            llm_calls: 0,
            llm_time: Duration::ZERO,
            cancel: self.cancel.clone(),
            label: Some(label.to_string()),
        }
    }

    /// Charge what workers used (their slices' usage) to the run.
    pub fn absorb(&mut self, u: &BudgetUsage) {
        self.steps += u.steps;
        self.requests += u.requests;
        self.llm_calls += u.llm_calls;
        self.llm_time += Duration::from_millis(u.llm_ms);
    }

    /// Where a limit message says whose limit it was.
    fn whose(&self) -> String {
        self.label
            .as_ref()
            .map(|l| format!("area '{l}' allocation: "))
            .unwrap_or_default()
    }

    /// Note that a limit cut the run short (first reason wins). Used for plan truncation too.
    pub fn note_stopped(&mut self, why: impl Into<String>) {
        self.stopped.get_or_insert(why.into());
    }

    /// Instant after which the wall-clock budget is exhausted.
    pub fn deadline(&self) -> Instant {
        self.started
            .checked_add(self.max_wall)
            .unwrap_or_else(|| self.started + Duration::from_secs(86_400))
    }

    /// The per-stage LLM budget for what is left of this run: the remaining call allowance and
    /// no more time than the remaining wall clock (capped at five minutes).
    pub fn llm_budget(&self) -> crate::llm::Budget {
        let left = self.max_wall.saturating_sub(self.started.elapsed());
        crate::llm::Budget::new(
            self.max_llm_calls.saturating_sub(self.llm_calls),
            left.min(LLM_TIME_CAP),
        )
        .with_deadline(self.deadline())
    }

    /// Record what an LLM [`Budget`](crate::llm::Budget) handed out by [`Self::llm_budget`] used.
    /// Idempotent for one budget per run: it replaces the counters rather than adding to them.
    pub fn sync_llm(&mut self, b: &crate::llm::Budget) {
        self.llm_calls = b.calls;
        self.llm_time = b.elapsed;
    }

    pub fn llm_calls_used(&self) -> usize {
        self.llm_calls
    }

    pub fn llm_time_used(&self) -> Duration {
        self.llm_time
    }

    fn wall_check(&mut self) -> Result<(), String> {
        if self.cancel.is_cancelled() {
            let m = "run cancelled".to_string();
            self.stopped.get_or_insert(m.clone());
            return Err(m);
        }
        if self.started.elapsed() >= self.max_wall {
            let m = format!(
                "wall-clock budget exhausted ({}{}s)",
                self.whose(),
                self.max_wall.as_secs()
            );
            self.stopped.get_or_insert(m.clone());
            return Err(m);
        }
        Ok(())
    }

    /// One more test case may start.
    pub fn take_step(&mut self) -> Result<(), String> {
        self.wall_check()?;
        if self.steps >= self.max_steps {
            let m = if self.label.is_some() {
                format!(
                    "step budget exhausted ({}{} step(s))",
                    self.whose(),
                    self.max_steps
                )
            } else {
                format!("step budget exhausted (--max-steps {})", self.max_steps)
            };
            self.stopped.get_or_insert(m.clone());
            return Err(m);
        }
        self.steps += 1;
        Ok(())
    }

    /// One more HTTP request to `host` may be sent; sleeps to honour the per-host rate (a schedule
    /// shared with every other holder of this run's limiter) and wakes up when the run is cancelled.
    pub fn take_request(&mut self, host: &str) -> Result<(), String> {
        self.wall_check()?;
        if self.requests >= self.max_requests {
            let m = format!(
                "request budget exhausted ({}{} requests)",
                self.whose(),
                self.max_requests
            );
            self.stopped.get_or_insert(m.clone());
            return Err(m);
        }
        let deadline = self.deadline();
        let Ok(slot) = self.limiter.reserve(host, deadline) else {
            return self.wall_check().and(Err(
                "wall-clock budget would be exceeded by rate limiting".into(),
            ));
        };
        loop {
            let now = Instant::now();
            if now >= slot {
                break;
            }
            if self.cancel.is_cancelled() {
                return self.wall_check();
            }
            std::thread::sleep((slot - now).min(Duration::from_millis(25)));
        }
        self.wall_check()?;
        self.requests += 1;
        Ok(())
    }

    pub fn steps_used(&self) -> usize {
        self.steps
    }

    pub fn requests_used(&self) -> usize {
        self.requests
    }

    pub fn stopped(&self) -> Option<&str> {
        self.stopped.as_deref()
    }

    pub fn usage(&self) -> BudgetUsage {
        BudgetUsage {
            steps: self.steps,
            max_steps: self.max_steps,
            requests: self.requests,
            max_requests: self.max_requests,
            elapsed_ms: self.started.elapsed().as_millis() as u64,
            max_wall_ms: self.max_wall.as_millis() as u64,
            rate_per_host_per_sec: self.rate,
            stopped: self.stopped.clone(),
            llm_calls: self.llm_calls,
            max_llm_calls: self.max_llm_calls,
            llm_ms: self.llm_time.as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_and_requests_are_capped() {
        let mut b = RunBudget::new(2, 3, Duration::from_secs(60), 0.0);
        assert!(b.take_step().is_ok() && b.take_step().is_ok());
        assert!(b.take_step().unwrap_err().contains("step budget"));
        assert!(
            b.take_request("h").is_ok()
                && b.take_request("h").is_ok()
                && b.take_request("h").is_ok()
        );
        assert!(b.take_request("h").unwrap_err().contains("request budget"));
        assert_eq!(b.usage().steps, 2);
        assert!(b.usage().stopped.is_some());
    }

    #[test]
    fn per_host_rate_is_paced_but_hosts_are_independent() {
        let mut b = RunBudget::new(10, 100, Duration::from_secs(60), 20.0); // 50 ms gap
        let t = Instant::now();
        for _ in 0..4 {
            b.take_request("a").unwrap();
        }
        assert!(
            t.elapsed() >= Duration::from_millis(140),
            "4 requests at 20/s need >= 150ms, took {:?}",
            t.elapsed()
        );
        let t = Instant::now();
        b.take_request("b").unwrap();
        assert!(
            t.elapsed() < Duration::from_millis(40),
            "a different host is not paced by host a"
        );
    }

    #[test]
    fn wall_clock_stops_everything() {
        let mut b = RunBudget::new(10, 100, Duration::from_millis(1), 0.0);
        std::thread::sleep(Duration::from_millis(5));
        assert!(b.take_step().unwrap_err().contains("wall-clock"));
        assert!(b.take_request("h").unwrap_err().contains("wall-clock"));
    }

    #[test]
    fn llm_calls_and_time_count_against_the_run_budget() {
        use crate::llm::{ask_json, mock};
        let dir = std::env::temp_dir().join(format!("rh-budget-llm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let m = mock::start(|_| {
            std::thread::sleep(Duration::from_millis(25));
            "{\"ok\": true}".into()
        });
        let cfg = mock::cfg(&m.base, &dir);
        let mut run = RunBudget::new(10, 100, Duration::from_secs(60), 0.0).with_max_llm_calls(2);
        let mut llm = run.llm_budget();
        assert_eq!(llm.remaining_calls(), 2);
        ask_json(&cfg, &mut llm, "s", "p1").unwrap();
        ask_json(&cfg, &mut llm, "s", "p2").unwrap();
        ask_json(&cfg, &mut llm, "s", "p1").unwrap(); // cache hit: free
        let e = ask_json(&cfg, &mut llm, "s", "p3").unwrap_err().to_string();
        assert!(e.contains("call budget"), "{e}");
        run.sync_llm(&llm);
        run.sync_llm(&llm); // idempotent
        let u = run.usage();
        assert_eq!((u.llm_calls, u.max_llm_calls), (2, 2));
        assert!(
            u.llm_ms >= 45,
            "two 25 ms calls were timed, got {} ms",
            u.llm_ms
        );
        assert_eq!(m.chat_hits.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            run.llm_budget().remaining_calls(),
            0,
            "what was used is not handed out again"
        );
        // old reports without the new fields still load
        let old: BudgetUsage = serde_json::from_str(
            r#"{"steps":1,"max_steps":2,"requests":3,"max_requests":4,"elapsed_ms":5,"max_wall_ms":6,"rate_per_host_per_sec":1.0,"stopped":null}"#,
        )
        .unwrap();
        assert_eq!((old.llm_calls, old.llm_ms), (0, 0));
    }

    #[test]
    fn llm_calls_stop_at_the_run_wall_clock() {
        use crate::llm::{ask_json, mock};
        let dir = std::env::temp_dir().join(format!("rh-budget-wall-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let m = mock::start(|_| "{}".into());
        let cfg = mock::cfg(&m.base, &dir);
        let run = RunBudget::new(10, 100, Duration::from_millis(1), 0.0);
        std::thread::sleep(Duration::from_millis(5));
        let mut llm = run.llm_budget();
        let e = ask_json(&cfg, &mut llm, "s", "p").unwrap_err().to_string();
        assert!(e.contains("wall-clock") || e.contains("time budget"), "{e}");
        assert_eq!(
            m.chat_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no call after the deadline"
        );
    }

    #[test]
    fn cancellation_stops_steps_and_requests_and_is_recorded() {
        let token = CancelToken::new();
        let mut b =
            RunBudget::new(10, 100, Duration::from_secs(60), 0.0).with_cancel(token.clone());
        assert!(b.take_step().is_ok() && b.take_request("h").is_ok());
        token.cancel();
        assert!(b.is_cancelled());
        assert_eq!(b.take_step().unwrap_err(), "run cancelled");
        assert_eq!(b.take_request("h").unwrap_err(), "run cancelled");
        assert_eq!(b.usage().stopped.as_deref(), Some("run cancelled"));
        // a cancelled budget cut the first step short, not the second request
        assert_eq!(b.usage().steps, 1);
    }

    #[test]
    fn a_slice_has_its_own_limits_names_its_area_and_is_charged_only_when_absorbed() {
        let mut parent = RunBudget::new(50, 100, Duration::from_secs(60), 0.0);
        let mut s = parent.slice(
            "auth",
            SliceLimits {
                steps: 1,
                requests: 2,
                wall: Duration::from_secs(5),
                llm_calls: 3,
            },
        );
        assert!(s.take_step().is_ok());
        let e = s.take_step().unwrap_err();
        assert!(
            e.starts_with("step budget exhausted") && e.contains("area 'auth' allocation"),
            "{e}"
        );
        s.take_request("h").unwrap();
        s.take_request("h").unwrap();
        let e = s.take_request("h").unwrap_err();
        assert!(
            e.starts_with("request budget exhausted") && e.contains("area 'auth' allocation: 2"),
            "{e}"
        );
        assert_eq!((parent.steps_used(), parent.requests_used()), (0, 0));
        assert_eq!(s.llm_budget().remaining_calls(), 3);
        parent.absorb(&s.usage());
        assert_eq!((parent.steps_used(), parent.requests_used()), (1, 2));
        assert_eq!((parent.steps_left(), parent.requests_left()), (49, 98));
        // a slice never outlives what is left of the run
        let short = RunBudget::new(1, 1, Duration::from_millis(80), 0.0).slice(
            "x",
            SliceLimits {
                steps: 1,
                requests: 1,
                wall: Duration::from_secs(60),
                llm_calls: 0,
            },
        );
        assert!(short.wall_left() <= Duration::from_millis(80));
    }

    #[test]
    fn one_limiter_paces_every_slice_of_a_run() {
        // 4 workers, 5 requests each, 25 requests/s for the run: 20 requests need >= 19 gaps of 40 ms
        let parent = RunBudget::new(100, 100, Duration::from_secs(60), 25.0);
        let stamps = Mutex::new(Vec::new());
        let t0 = Instant::now();
        std::thread::scope(|sc| {
            for _ in 0..4 {
                sc.spawn(|| {
                    let mut s = parent.slice(
                        "w",
                        SliceLimits {
                            steps: 10,
                            requests: 10,
                            wall: Duration::from_secs(30),
                            llm_calls: 0,
                        },
                    );
                    for _ in 0..5 {
                        s.take_request("host:80").unwrap();
                        stamps.lock().unwrap().push(Instant::now());
                    }
                });
            }
        });
        let mut t = stamps.into_inner().unwrap();
        t.sort();
        let span = t[19].duration_since(t[0]);
        assert!(
            span >= Duration::from_millis(19 * 40 * 9 / 10),
            "20 requests at 25/s took {span:?}: the workers were not paced together ({:?})",
            t0.elapsed()
        );
        for w in t.windows(5) {
            assert!(
                w[4].duration_since(w[0]) >= Duration::from_millis(2 * 40),
                "5 requests inside {:?}",
                w[4].duration_since(w[0])
            );
        }
    }

    #[test]
    fn cancelling_the_run_wakes_a_worker_waiting_for_its_request_slot() {
        let token = CancelToken::new();
        let parent =
            RunBudget::new(10, 10, Duration::from_secs(60), 0.5).with_cancel(token.clone());
        let mut s = parent.slice(
            "w",
            SliceLimits {
                steps: 10,
                requests: 10,
                wall: Duration::from_secs(60),
                llm_calls: 0,
            },
        );
        s.take_request("h").unwrap(); // the second one would wait 2 s for its slot
        let t0 = Instant::now();
        let stopper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            token.cancel();
        });
        assert_eq!(s.take_request("h").unwrap_err(), "run cancelled");
        stopper.join().unwrap();
        assert!(
            t0.elapsed() < Duration::from_millis(1500),
            "{:?}",
            t0.elapsed()
        );
        assert_eq!(
            s.usage().requests,
            1,
            "the slot that was waited for was not used"
        );
    }

    #[test]
    fn note_stopped_keeps_the_first_reason() {
        let mut b = RunBudget::new(1, 1, Duration::from_secs(60), 0.0);
        b.note_stopped("plan truncated");
        let _ = b.take_step();
        let _ = b.take_step();
        assert_eq!(b.stopped(), Some("plan truncated"));
    }
}
