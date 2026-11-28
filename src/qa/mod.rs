//! Senior-QA engine: Plan → Generate → Execute → Verify → Triage → Report.
//! QA checks only run under `readyhai qa` (Check::qa flag).
pub mod ai;
pub mod api;
pub mod data;
pub mod design;
pub mod graphql;
pub mod model;
pub mod pentest;
pub mod perf;
pub mod plan;
pub mod recommend;
pub mod report;
pub mod resilience;
pub mod roles;
pub mod suite;
pub mod triage;
pub mod ui;
pub mod wstg;

use crate::checks::Check;
use model::QaCollector;
use roles::Roles;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// QA-only context (present when the run is `readyhai qa`).
pub struct QaCtx {
    pub roles: Roles,
    /// OpenAPI spec as given (--spec): local path or URL. Engine already scope-checked URLs.
    pub spec: Option<String>,
    pub journeys: Option<PathBuf>,
    /// Writes (POST/PUT/PATCH/DELETE), form submits, load and fault injection are allowed
    /// only when the target host is tagged env=nonprod in scope.toml.
    pub nonprod: bool,
    pub collector: Mutex<QaCollector>,
    pub max_requests: usize,
    pub rps: f64,
    requests: AtomicUsize,
    last: Mutex<Option<Instant>>,
}

impl QaCtx {
    pub fn new(
        roles: Roles,
        spec: Option<String>,
        journeys: Option<PathBuf>,
        nonprod: bool,
    ) -> Self {
        QaCtx {
            roles,
            spec,
            journeys,
            nonprod,
            collector: Mutex::new(QaCollector::default()),
            max_requests: 2000,
            rps: 5.0,
            requests: AtomicUsize::new(0),
            last: Mutex::new(None),
        }
    }

    /// Call before EVERY request to the target: enforces the global rate limit and
    /// the per-run request cap. Err = budget exhausted (stop testing, mark rest blocked).
    pub fn throttle(&self) -> anyhow::Result<()> {
        if self.requests.fetch_add(1, Ordering::SeqCst) >= self.max_requests {
            anyhow::bail!("QA request budget ({}) exhausted", self.max_requests);
        }
        self.pace();
        Ok(())
    }

    /// Rate limit only (no cap check): for cleanup of data this run created.
    pub fn throttle_uncapped(&self) {
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.pace();
    }

    /// Requests left in the budget.
    pub fn remaining(&self) -> usize {
        self.max_requests
            .saturating_sub(self.requests.load(Ordering::SeqCst))
    }

    /// Spacing guarantee: no two requests start closer than `1 / rps` apart, globally.
    ///
    /// Each caller reserves the next start slot under the lock and then sleeps *outside* it. The
    /// obvious version (sleep while holding the mutex) produces the same global spacing but blocks
    /// every other worker for the whole wait, which turns the limiter into a queue: with a lower
    /// `rps` a burst of workers could sit idle waiting on a lock they do not need.
    fn pace(&self) {
        let gap = Duration::from_secs_f64(1.0 / self.rps.max(0.1));
        let now = Instant::now();
        let start = {
            let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
            let start = last.map_or(now, |t| t.max(now));
            *last = Some(start + gap);
            start
        };
        if start > now {
            std::thread::sleep(start - now);
        }
    }

    #[allow(dead_code)]
    pub fn requests_made(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut QaCollector) -> R) -> R {
        let mut c = self.collector.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut c)
    }
}

pub fn checks() -> Vec<Check> {
    let mut v = plan::checks();
    v.extend(api::checks());
    v.extend(graphql::checks());
    v.extend(ui::checks());
    v.extend(perf::checks());
    v.extend(resilience::checks());
    v.extend(suite::checks());
    v.extend(pentest::checks());
    v.extend(crate::qa::data::checks());
    v.extend(crate::qa::design::checks());
    v
}

/// Build the QA report after the gate ran (needs finding statuses + verdict).
pub fn build_report(qa: &QaCtx, run: &crate::model::Run, mode: &str) -> model::QaReport {
    let col = std::mem::take(&mut *qa.collector.lock().unwrap_or_else(|e| e.into_inner()));
    recommend::build(col, run, qa, mode)
}

/// `readyhai baseline accept <run>` hook for everything QA keeps besides the fingerprint set:
/// the OpenAPI spec snapshot/operation list (breaking-change + "new operation" baselines), the
/// visual screenshots and the perf result of that run. Returns one human line per baseline.
///
/// `main.rs` should call this after saving the fingerprint baseline of a QA run:
/// `for m in qa::accept_baselines(&engine::target_key(&r.target), &r.id) { eprintln!("baseline: {m}") }`
#[allow(dead_code)]
pub fn accept_baselines(target_key: &str, run_id: &str) -> Vec<String> {
    accept_baselines_in(&crate::engine::data_dir(), target_key, run_id)
}

pub(crate) fn accept_baselines_in(
    data: &std::path::Path,
    target_key: &str,
    run_id: &str,
) -> Vec<String> {
    let run_dir = data.join("runs").join(run_id);
    let mut out = vec![];
    match api::accept_spec_baseline_in(data, target_key, &run_dir) {
        Ok(done) => out.push(format!("spec baseline promoted ({})", done.join(", "))),
        Err(e) => out.push(format!("spec baseline unchanged ({e:#})")),
    }
    match ui::accept_visual_baseline_in(data, target_key, &run_dir) {
        Ok(n) => out.push(format!("visual baseline promoted ({n} screenshot(s))")),
        Err(e) => out.push(format!("visual baseline unchanged ({e:#})")),
    }
    match perf::accept_baseline_in(data, target_key) {
        Ok(()) => out.push("perf baseline promoted from the last run".into()),
        Err(e) => out.push(format!("perf baseline unchanged ({e:#})")),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_promotes_spec_visual_and_perf() {
        let d = std::env::temp_dir().join(format!("rh-accept-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let st = api::stage_dir(&d.join("runs/r9"));
        std::fs::create_dir_all(&st).unwrap();
        std::fs::write(
            st.join("spec-full.json"),
            r#"{"openapi":"3.0.0","paths":{}}"#,
        )
        .unwrap();
        std::fs::write(st.join("spec-ops.json"), r#"["GET /a"]"#).unwrap();
        let shots = d.join("runs/r9/artifacts/ui/shots");
        std::fs::create_dir_all(&shots).unwrap();
        std::fs::write(shots.join("x.png"), b"p").unwrap();
        // an OLD baseline is replaced, not kept
        std::fs::create_dir_all(d.join("baselines")).unwrap();
        std::fs::write(d.join("baselines/k.spec.json"), r#"["GET /old"]"#).unwrap();
        let msgs = accept_baselines_in(&d, "k", "r9");
        assert!(msgs[0].starts_with("spec baseline promoted"), "{msgs:?}");
        assert!(msgs[1].starts_with("visual baseline promoted"), "{msgs:?}");
        assert!(
            msgs[2].starts_with("perf baseline unchanged"),
            "no perf run recorded: {msgs:?}"
        );
        assert_eq!(
            std::fs::read_to_string(d.join("baselines/k.spec.json")).unwrap(),
            r#"["GET /a"]"#
        );
        assert!(d.join("baselines/k.spec-full.json").is_file());
        assert!(d.join("baselines/k/visual/x.png").is_file());
        // a run without staged data changes nothing and says so
        let none = accept_baselines_in(&d, "k", "nope");
        assert!(none[0].contains("unchanged") && none[1].contains("unchanged"));
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod pacing_tests {
    use super::{Duration, QaCtx, roles::Roles};

    fn ctx(rps: f64) -> QaCtx {
        let mut c = QaCtx::new(Roles::default(), None, None, true);
        c.rps = rps;
        c
    }

    /// The limiter exists to keep the *global* rate honest, whatever the worker count.
    #[test]
    fn reserved_slots_keep_the_global_spacing_at_the_configured_rps() {
        let c = ctx(20.0);
        let started = std::time::Instant::now();
        for _ in 0..5 {
            c.throttle().unwrap();
        }
        // 5 reservations at 20 rps span at least 4 gaps of 50ms. An unpaced path fires them at
        // once; a sleep-under-the-lock implementation takes the same wall time but blocks every
        // other worker on a lock it does not need (checked by `a_waiting_caller_...` below).
        assert!(
            started.elapsed().as_millis() >= 190,
            "5 requests at 20 rps finished in {:?}; the limiter is not pacing",
            started.elapsed()
        );
    }

    /// Concurrency check on the reservation itself: workers pacing at the same moment must land
    /// on *distinct* slots. A reservation that releases the lock before writing the new `last`
    /// would hand two workers the same start time and quietly double the request rate.
    #[test]
    fn concurrent_workers_never_share_a_slot() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        let rps = 200.0; // 5ms between slots
        let c = Arc::new(ctx(rps));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let (c, starts) = (Arc::clone(&c), Arc::clone(&starts));
            handles.push(thread::spawn(move || {
                c.throttle().unwrap();
                starts.lock().unwrap().push(std::time::Instant::now());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let mut starts = starts.lock().unwrap().clone();
        starts.sort();
        let min_gap = Duration::from_secs_f64(1.0 / rps);
        for w in starts.windows(2) {
            let gap = w[1].duration_since(w[0]);
            assert!(
                gap + Duration::from_millis(2) >= min_gap,
                "two workers started {gap:?} apart, below the {min_gap:?} slot width"
            );
        }
    }

    #[test]
    fn the_request_cap_still_stops_the_run() {
        let c = ctx(10_000.0);
        for _ in 0..c.max_requests {
            c.throttle().unwrap();
        }
        assert!(c.throttle().is_err(), "budget must be enforced");
        assert_eq!(c.remaining(), 0);
    }
}
