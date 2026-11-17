//! Atomic transaction lifecycle for end-of-run memory updates.

use anyhow::Result;
use std::path::{Path, PathBuf};

use super::observe::Observation;
use super::reconcile::{Reconciled, reconcile};
use super::sanitize::clean_ident;
use super::store::{
    canonical_target, memory_path, quarantine, read_strict, target_key, write_memory,
};
use super::types::{MAX_IDENT, Memory};
use crate::agent::store::RunLock;

/// The end-of-run update of one target's memory, holding the per-target lock from the moment the
/// current state is read until the new one is written, so two runs of one target cannot lose each
/// other's update.
pub struct Update {
    _lock: RunLock,
    dir: PathBuf,
    pub prior: Memory,
    /// Notes the report must carry (a corrupt file set aside, ...).
    pub notes: Vec<String>,
}

impl Update {
    pub fn begin(dir: &Path, target: &str, tag: &str, now: &str) -> Result<Update> {
        let key = target_key(target);
        let lock = RunLock::acquire(dir, &key)?;
        // the lock is ours: `load` would try to take it again, so read and set aside by hand
        let (prior, notes) = match read_strict(dir, &key) {
            Ok(Some(m)) => (m, vec![]),
            Ok(None) => (Memory::fresh(&key, &canonical_target(target), now), vec![]),
            Err(why) => {
                let note = match quarantine(dir, &key, tag) {
                    Ok(bak) => format!(
                        "agent memory {} {why}: it was moved to {} and ignored; this run starts with an empty memory",
                        memory_path(dir, &key).display(),
                        bak.display()
                    ),
                    Err(e) => format!(
                        "agent memory {} {why} and could not be moved aside ({e}); it is ignored for this run",
                        memory_path(dir, &key).display()
                    ),
                };
                (
                    Memory::fresh(&key, &canonical_target(target), now),
                    vec![note],
                )
            }
        };
        Ok(Update {
            _lock: lock,
            dir: dir.to_path_buf(),
            prior,
            notes,
        })
    }

    /// Fold the run into the state read under the lock (nothing is written yet).
    pub fn reconcile(&self, obs: &Observation, today: &str, now: &str) -> Reconciled {
        reconcile(&self.prior, obs, today, now)
    }

    /// Write the reconciled memory (with the run's gate verdict) atomically, then release the lock.
    pub fn commit(self, rec: &Reconciled, now: &str) -> Result<()> {
        let mut m = rec.memory.clone();
        write_memory(&self.dir, &mut m, now)
    }
}
