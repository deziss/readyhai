//! Agent memory integration: recalling historical target run facts and committing updates.

use std::path::{Path, PathBuf};

use super::super::memory::{self, PlanHints, RunFacts, SinceLastRun};
use super::super::types::{AgentRunReport, AgentRunRequest, CleanupReport};
use super::options::log;

/// The planner's view of the target's memory, plus what the report must say about it (a file that
/// was set aside as corrupt). Never fails: no memory, an unreadable file or a first run all plan
/// from the profile alone.
pub(crate) fn recall(
    dir: Option<&Path>,
    target: &str,
    rep: &mut AgentRunReport,
    today: &str,
) -> (Option<PlanHints>, Vec<String>) {
    let Some(dir) = dir else {
        return (None, vec![]);
    };
    let l = memory::load(
        dir,
        &memory::target_key(target),
        &memory::canonical_target(target),
        &rep.id,
        &crate::engine::now(),
    );
    let h = PlanHints::from_memory(&l.memory, today);
    let open = l
        .memory
        .defects
        .values()
        .filter(|d| d.status != memory::DefectStatus::Fixed)
        .count();
    log(
        &mut rep.steps,
        "Memory",
        "Recall",
        &if l.existed {
            format!(
                "remembered {} earlier run(s) of this target: {open} known open defect(s), {} flaky case class(es), {} operation(s); {} case class(es) will be re-tested first",
                l.memory.runs.len(),
                l.memory.flaky.values().filter(|f| f.flaky > 0).count(),
                l.memory.operations.len(),
                h.regression.len()
            )
        } else if l.notes.is_empty() {
            "no earlier run of this target is remembered: planning from the profile alone".into()
        } else {
            "the memory of this target cannot be used: planning from the profile alone".into()
        },
        if l.notes.is_empty() {
            "completed"
        } else {
            "warning"
        },
        Some("deterministic"),
    );
    rep.notes.extend(l.notes.iter().cloned());
    (Some(h).filter(|h| !h.is_empty()), l.notes)
}

/// A run's pending memory update. The state it was folded into is read WITHOUT the lock (a gate
/// step can take minutes when an LLM is slow, and a lock held that long would go stale); the lock is
/// taken only to write, and when the memory changed in between (another run, an operator) the run is
/// folded into the newer state again.
pub(crate) struct Remembered {
    dir: PathBuf,
    target: String,
    tag: String,
    obs: memory::Observation,
    /// Digest of the memory file this was folded into ("" when there was none).
    prior_digest: String,
    rec: memory::Reconciled,
    now: String,
    today: String,
}

impl Remembered {
    /// Write the memory (a completed run only) and return the "since last run" section.
    pub(crate) fn finish(
        self,
        verdict: &str,
        commit: bool,
        mut notes: Vec<String>,
    ) -> SinceLastRun {
        let Remembered {
            dir,
            target,
            tag,
            obs,
            prior_digest,
            mut rec,
            now,
            today,
        } = self;
        if !commit {
            notes.push("the run was cancelled: the agent memory was not updated".into());
            rec.set_verdict(verdict);
            let mut since = rec.since;
            since.notes = notes;
            return since;
        }
        match memory::Update::begin(&dir, &target, &tag, &now) {
            Ok(update) => {
                notes.extend(update.notes.iter().cloned());
                if update.prior.digest != prior_digest {
                    rec = update.reconcile(&obs, &today, &now);
                    notes.push("the agent memory of this target changed while the run was going (another run or an operator): the since-last-run section was recomputed from the newer state".into());
                }
                rec.set_verdict(verdict);
                let mut since = rec.since.clone();
                match update.commit(&rec, &now) {
                    Ok(()) => since.committed = true,
                    Err(e) => notes.push(format!("agent memory was not updated: {e:#}")),
                }
                notes.dedup();
                since.notes = notes;
                since
            }
            Err(e) => {
                notes.push(format!("agent memory was not updated: {e:#}"));
                rec.set_verdict(verdict);
                let mut since = rec.since;
                since.notes = notes;
                since
            }
        }
    }
}

/// Fold the run into the memory as it is now and apply unexpired acceptances to the triaged
/// defects (so the ledger does not count them as blocking). None when memory is off.
pub(crate) fn remember(
    dir: Option<&Path>,
    req: &AgentRunRequest,
    rep: &mut AgentRunReport,
    cleanup: &CleanupReport,
    today: &str,
) -> Option<Remembered> {
    let dir = dir?;
    let now = crate::engine::now();
    let (prior, _) = memory::peek(dir, &req.target, &now);
    let obs = memory::observe(&RunFacts {
        run_id: &rep.id,
        dry_run: rep.dry_run,
        cases: &rep.planned_cases,
        results: &rep.executed_results,
        defects: &rep.triaged_defects,
        cleanup: Some(cleanup),
        baselines: Some(memory::observe_baselines(
            dir.parent().unwrap_or(dir),
            &req.target,
        )),
    });
    let rec = memory::reconcile(&prior, &obs, today, &now);
    rec.apply_waivers(&mut rep.triaged_defects);
    let waived = rep
        .triaged_defects
        .iter()
        .filter(|d| d.accepted.is_some())
        .count();
    if waived > 0 {
        rep.notes.push(format!(
            "{waived} known defect(s) are covered by an unexpired acceptance (readyhai agent-memory accept): they are listed and do not block the gate"
        ));
    }
    Some(Remembered {
        dir: dir.to_path_buf(),
        target: req.target.clone(),
        tag: rep.id.clone(),
        obs,
        prior_digest: prior.digest.clone(),
        rec,
        now,
        today: today.to_string(),
    })
}
