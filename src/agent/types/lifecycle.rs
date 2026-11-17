//! Run lifecycle registry, cancellation tokens, and background execution control.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Cooperative cancellation: an in-process flag plus an optional marker file (so another process,
/// e.g. the CLI or a second server worker, can ask a running run to stop). Checked between steps
/// and before every request by the run budget.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
    file: Option<PathBuf>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_file(mut self, path: PathBuf) -> Self {
        self.file = Some(path);
        self
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst) || self.file.as_deref().is_some_and(Path::exists)
    }
}

fn registry() -> &'static Mutex<HashMap<String, CancelToken>> {
    static R: OnceLock<Mutex<HashMap<String, CancelToken>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Keeps a run cancellable by id for as long as it is alive.
pub struct RunRegistration {
    id: String,
}

impl Drop for RunRegistration {
    fn drop(&mut self) {
        registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

pub fn register_run(id: &str, token: &CancelToken) -> RunRegistration {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.to_string(), token.clone());
    RunRegistration { id: id.to_string() }
}

/// Ids of the runs executing in this process.
pub fn running_run_ids() -> Vec<String> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect()
}

/// Ask a run to stop at its next step. A run of this process is flagged directly; for a run whose
/// checkpoint says `running` a `CANCEL` marker is written into its directory, which a run in
/// another process honours too. Returns whether anything was asked to stop.
pub fn request_cancel(run_id: &str) -> bool {
    if !crate::engine::valid_run_id(run_id) {
        return false;
    }
    let mut hit = false;
    if let Some(t) = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(run_id)
    {
        t.cancel();
        hit = true;
    }
    let dir = crate::agent::store::agent_runs_dir().join(run_id);
    if crate::agent::store::checkpoint_status(&dir).as_deref() == Some("running") {
        hit |= std::fs::write(dir.join("CANCEL"), b"cancel requested").is_ok();
    }
    hit
}
