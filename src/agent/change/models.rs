use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use crate::agent::types::ChangeImpact;

/// Most changed files named in the report (the total is always shown).
pub const MAX_LISTED_FILES: usize = 200;
/// Most diff entries considered at all.
pub const MAX_FILES: usize = 5000;
/// Most source files read for routes.
pub const MAX_SCANNED: usize = 400;
/// A handler file bigger than this is not read (the file still counts as changed).
pub const MAX_READ: u64 = 1024 * 1024;
pub const MAX_DIFF_OUTPUT: usize = 4 * 1024 * 1024;
pub const MAX_FILES_PER_OP: usize = 5;

pub const APPLIED: &str = "applied";
pub const NO_CHANGES: &str = "no_changes";
pub const UNMAPPED: &str = "unmapped";
pub const SKIPPED: &str = "skipped";
pub const FAILED: &str = "failed";

/// The operations (`GET /search`) the diff touched; what the planner reads.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChangeSet {
    pub(crate) ops: BTreeSet<String>,
}

impl ChangeSet {
    pub fn from_labels<I: IntoIterator<Item = String>>(labels: I) -> Self {
        ChangeSet {
            ops: labels.into_iter().collect(),
        }
    }
    pub fn contains(&self, op: &crate::qa::plan::Op) -> bool {
        self.ops.contains(&op.component())
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    pub fn len(&self) -> usize {
        self.ops.len()
    }
    pub fn labels(&self) -> impl Iterator<Item = &String> {
        self.ops.iter()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Analysis {
    pub impact: ChangeImpact,
    pub set: ChangeSet,
}

/// Where the retriever's index and command are. Tests build it directly; production reads the
/// environment (`retriever_from_env`).
#[derive(Debug, Clone)]
pub struct Retriever {
    pub index_dir: PathBuf,
    /// Program and leading arguments; `query ...` follows.
    pub command: Vec<String>,
    /// Working directory of the command (the checkout that holds `runners/`).
    pub cwd: Option<PathBuf>,
    pub timeout: Duration,
}
