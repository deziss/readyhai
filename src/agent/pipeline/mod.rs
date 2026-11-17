//! The agent loop: Discovery -> Planner -> Explorer -> Verifier -> Cleanup -> Triager -> Readiness gate -> save.
//! Deterministic code decides every verdict; the LLM (when configured AND reachable) adds extra
//! planned cases, prose notes and an advisory opinion, and every stage records which one produced it.
//!
//! Lifecycle: `report.json` is checkpointed after every stage with status `running` and ends as
//! `completed`, `failed` or `cancelled`. Cancellation (`request_cancel`, a `CancelToken` on the
//! budget) is honoured between steps. A plan longer than the step allowance is ordered so access
//! control, stateful and OpenAPI cases survive, and what is dropped is recorded (a note, SKIPPED
//! results that lower coverage). Whatever the run created on the target is recorded in a
//! `CreatedLedger` and deleted again at the end on nonprod targets; leftovers are reported.

pub mod change;
pub mod cleanup;
pub mod discovery;
pub mod gate;
pub mod memory;
pub mod options;
pub mod order;
pub mod stages;

#[cfg(test)]
pub(crate) mod tests;

use anyhow::{bail, Result};
use std::path::Path;

pub use discovery::run_discovery_scan;
pub(crate) use discovery::run_discovery_in;
pub use options::{LlmMode, RunOptions};
pub(crate) use cleanup::{
    delete_check_results, harvest_created, teardown, DELETE_NOT_EFFECTIVE, TEARDOWN_MAX,
    TEARDOWN_WALL,
};
pub(crate) use options::{blank_report, checkpoint, log, panic_text, require_http};
pub(crate) use order::order_and_trim;
pub(crate) use stages::agent_stages;

use super::ledger;
use super::store::{
    agent_runs_dir, checkpoint_agent_run_in, now_iso, save_agent_run_in,
};
use super::types::{register_run, AgentRunReport, AgentRunRequest, RunRegistration};

pub fn run_agentic_loop(req: &AgentRunRequest, run_id: &str) -> Result<AgentRunReport> {
    run_agentic_loop_with(req, run_id, RunOptions::default())
}

pub fn run_agentic_loop_with(
    req: &AgentRunRequest,
    run_id: &str,
    opts: RunOptions,
) -> Result<AgentRunReport> {
    run_in(&agent_runs_dir(), req, run_id, opts)
}

pub(crate) fn run_in(
    base: &Path,
    req: &AgentRunRequest,
    run_id: &str,
    opts: RunOptions,
) -> Result<AgentRunReport> {
    run_with(base, req, run_id, opts, None)
}

/// `nonprod`: None consults the scope file for the target; tests pin it.
pub(crate) fn run_with(
    base: &Path,
    req: &AgentRunRequest,
    run_id: &str,
    mut opts: RunOptions,
    nonprod: Option<bool>,
) -> Result<AgentRunReport> {
    if !crate::engine::valid_run_id(run_id) {
        bail!("invalid run id");
    }
    require_http(&req.target)?;
    let mut rep = blank_report(run_id, &req.target, &req.profile, req.dry_run);
    // cancellation: an in-process flag (request_cancel) plus a marker file for other processes
    let marker = base.join(run_id).join("CANCEL");
    let token = opts.budget.cancel_token().clone().with_file(marker.clone());
    opts.budget = opts.budget.clone().with_cancel(token.clone());
    let registration = (register_run(run_id, &token), marker);
    log(
        &mut rep.steps,
        "Supervisor",
        "Session Init",
        &format!(
            "Autonomous session for {}{}",
            req.target,
            if req.dry_run {
                " (dry-run: no state-changing requests)"
            } else {
                ""
            }
        ),
        "running",
        None,
    );
    let first = {
        let mut r = rep.clone();
        r.budget = Some(opts.budget.usage());
        checkpoint_agent_run_in(base, &r)
    };
    first?;
    run_guarded(base, rep, registration, |rep| {
        agent_stages(base, req, rep, opts, nonprod)
    })
}

/// Run `stages` over `rep`; on an error or a panic, record the run as `failed` (kept on disk, with
/// the error) and return the error. The run's cancel marker and registry entry are cleaned up.
pub(crate) fn run_guarded(
    base: &Path,
    mut rep: AgentRunReport,
    registration: (RunRegistration, std::path::PathBuf),
    stages: impl FnOnce(&mut AgentRunReport) -> Result<()>,
) -> Result<AgentRunReport> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stages(&mut rep)))
        .unwrap_or_else(|p| Err(anyhow::anyhow!(panic_text(p))));
    let (_reg, cancel_marker) = registration;
    let _ = std::fs::remove_file(&cancel_marker);
    match outcome {
        Ok(()) => Ok(rep),
        Err(e) => {
            let msg = format!("{e:#}");
            rep.status = "failed".into();
            rep.finished_at = Some(now_iso());
            rep.error = Some(msg.clone());
            log(
                &mut rep.steps,
                "Supervisor",
                "Run failed",
                &msg,
                "error",
                Some("deterministic"),
            );
            if rep.evidence_ledger.is_none() {
                rep.evidence_ledger = Some(ledger::not_evaluated(
                    "NOT_EVALUATED",
                    format!("The run failed before a verdict could be computed: {msg}"),
                    vec![],
                ));
            }
            // report.json first (so `failed` survives even if rendering fails), then the renderings
            let _ = checkpoint_agent_run_in(base, &rep);
            let _ = save_agent_run_in(base, &rep);
            Err(e)
        }
    }
}
