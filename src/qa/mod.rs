//! Senior-QA engine: Plan → Generate → Execute → Verify → Triage → Report.
//! QA checks only run under `readyhai qa` (Check::qa flag).
pub mod ai;
pub mod api;
pub mod model;
pub mod perf;
pub mod plan;
pub mod recommend;
pub mod report;
pub mod resilience;
pub mod roles;
pub mod suite;
pub mod triage;
pub mod ui;

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
    pub fn new(roles: Roles, spec: Option<String>, journeys: Option<PathBuf>, nonprod: bool) -> Self {
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
        let gap = Duration::from_secs_f64(1.0 / self.rps.max(0.1));
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = *last {
            let el = t.elapsed();
            if el < gap {
                std::thread::sleep(gap - el);
            }
        }
        *last = Some(Instant::now());
        Ok(())
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
    v.extend(ui::checks());
    v.extend(perf::checks());
    v.extend(resilience::checks());
    v.extend(suite::checks());
    v
}

/// Build the QA report after the gate ran (needs finding statuses + verdict).
pub fn build_report(qa: &QaCtx, run: &crate::model::Run, mode: &str) -> model::QaReport {
    let col = std::mem::take(&mut *qa.collector.lock().unwrap_or_else(|e| e.into_inner()));
    recommend::build(col, run, qa, mode)
}
