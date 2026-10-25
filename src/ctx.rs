//! Per-run context handed to every check.
use crate::facts::Facts;
use crate::model::{Profile, Target};
use crate::snapshot::Snapshot;
use crate::tools::Docker;
use crate::config::TargetConfig;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Ctx {
    pub run_id: String,
    pub target: Target,
    #[allow(dead_code)]
    pub profile: Profile,
    /// runs/<id>/ — holds `src/` (snapshot), `out/` (tool outputs), `artifacts/`.
    pub run_dir: PathBuf,
    /// Present for Repo targets (and Image: holds image.tar).
    pub snapshot: Option<Snapshot>,
    pub facts: Facts,
    pub docker: Docker,
    pub cfg: TargetConfig,
    /// Raw error lines checks collected; the engine clusters them (crate::logs).
    pub error_lines: Mutex<Vec<(String, String)>>,
    /// Target host tagged env=nonprod in scope.toml (writes/intrusive allowed).
    #[allow(dead_code)]
    pub nonprod: bool,
    /// Present only for `readyhai qa` runs.
    pub qa: Option<crate::qa::QaCtx>,
}

impl Ctx {
    /// Record a runtime error line (source, line) for clustering. Redact before calling.
    pub fn error_line(&self, source: &str, line: &str) {
        if let Ok(mut v) = self.error_lines.lock() {
            if v.len() < 20_000 {
                v.push((source.to_string(), line.to_string()));
            }
        }
    }

    pub fn out_dir(&self) -> PathBuf {
        self.run_dir.join("out")
    }
    pub fn src_dir(&self) -> PathBuf {
        self.run_dir.join("src")
    }
}
