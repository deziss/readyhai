//! Run execution deadline registry and RAII deadline guards.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

static DEADLINES: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(Default::default);

/// Wall-clock deadline registered for a running scan (see `ScanOpts::deadline`).
pub fn run_deadline(run_id: &str) -> Option<Instant> {
    DEADLINES.lock().ok()?.get(run_id).copied()
}

pub fn deadline_passed(run_id: &str) -> bool {
    run_deadline(run_id).is_some_and(|d| Instant::now() >= d)
}

/// Registers the deadline for the lifetime of a scan, whatever way it exits.
pub struct DeadlineGuard(String);

impl DeadlineGuard {
    pub fn new(run_id: &str, at: Option<Instant>) -> Self {
        if let (Some(at), Ok(mut m)) = (at, DEADLINES.lock()) {
            m.insert(run_id.to_string(), at);
        }
        DeadlineGuard(run_id.to_string())
    }
}

impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = DEADLINES.lock() {
            m.remove(&self.0);
        }
    }
}
