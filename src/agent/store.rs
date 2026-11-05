//! Persistence of agent runs under <data_dir>/agent-runs/<id>/ : report.json (atomic), evidence/*.json,
//! report/* renderings, cleanup.json. Plus the read side used by the REST API and sign-off actions.
//!
//! A running run checkpoints `report.json` with status `running`; it ends as `completed`, `failed`
//! or `cancelled`. Every load-modify-save (retest, sign-off, delete) holds a per-run lock file
//! (`<runs>/.locks/<id>.lock`, created exclusively, removed on drop, stale after 60 s) so two
//! writers cannot interleave and lose an update.
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::report::generate_agent_report_formats;
use super::types::*;
use crate::llm::write_atomic;

pub fn now_iso() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
}

pub fn agent_runs_dir() -> PathBuf {
    crate::engine::data_dir().join("agent-runs")
}

fn check_id(id: &str) -> Result<()> {
    if !crate::engine::valid_run_id(id) {
        bail!("invalid run id");
    }
    Ok(())
}

const ALL_FORMATS: [&str; 5] = ["html", "markdown", "sarif", "json", "junit"];

pub fn save_agent_run(rep: &AgentRunReport) -> Result<()> {
    save_agent_run_in(&agent_runs_dir(), rep)
}

fn write_evidence_files(run_dir: &Path, rep: &AgentRunReport) -> Result<()> {
    for r in &rep.executed_results {
        if let (Some(detail), Some(rel)) = (&r.evidence_detail, &r.evidence_file)
            && rel.starts_with("evidence/")
            && !rel.contains("..")
        {
            write_atomic(
                &run_dir.join(rel),
                serde_json::to_string_pretty(detail)?.as_bytes(),
            )?;
        }
    }
    Ok(())
}

/// Write the run into `base/<id>/`. `report.json` is replaced atomically (a reader or a crash never
/// sees a half-written file); evidence files are written for results that carry fresh detail.
pub(crate) fn save_agent_run_in(base: &Path, rep: &AgentRunReport) -> Result<()> {
    check_id(&rep.id)?;
    let run_dir = base.join(&rep.id);
    let rep_dir = run_dir.join("report");
    std::fs::create_dir_all(&rep_dir)?;
    write_evidence_files(&run_dir, rep)?;
    write_atomic(
        &run_dir.join("report.json"),
        serde_json::to_string_pretty(rep)?.as_bytes(),
    )?;
    let _ = generate_agent_report_formats(rep, &rep_dir, &ALL_FORMATS.map(String::from));
    Ok(())
}

/// Persist an in-progress run: `report.json` (atomic) and the evidence written so far, without the
/// rendered report formats. A crash, a kill or a reader in the middle of the run still finds the
/// stages that completed, with status `running`.
pub(crate) fn checkpoint_agent_run_in(base: &Path, rep: &AgentRunReport) -> Result<()> {
    check_id(&rep.id)?;
    let run_dir = base.join(&rep.id);
    std::fs::create_dir_all(&run_dir)?;
    write_evidence_files(&run_dir, rep)?;
    write_atomic(
        &run_dir.join("report.json"),
        serde_json::to_string_pretty(rep)?.as_bytes(),
    )?;
    Ok(())
}

/// `status` recorded in a run directory's `report.json`, without parsing the whole report.
pub(crate) fn checkpoint_status(run_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(run_dir.join("report.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("status")?.as_str().map(str::to_string)
}

/// Structured result of the end-of-run teardown, next to the report.
pub(crate) fn save_cleanup_in(base: &Path, id: &str, c: &CleanupReport) -> Result<()> {
    check_id(id)?;
    write_atomic(
        &base.join(id).join("cleanup.json"),
        serde_json::to_string_pretty(c)?.as_bytes(),
    )?;
    Ok(())
}

pub(crate) fn load_cleanup_in(base: &Path, id: &str) -> Option<CleanupReport> {
    check_id(id).ok()?;
    serde_json::from_str(&std::fs::read_to_string(base.join(id).join("cleanup.json")).ok()?).ok()
}

// ---------------------------------------------------------------- per-run lock

/// Exclusive lock on one run for a load-modify-save. A lock file older than `STALE` belongs to a
/// crashed writer and is taken over; waiting longer than `WAIT` is an error, never a lost update.
pub(crate) struct RunLock {
    path: PathBuf,
}

impl RunLock {
    const STALE: Duration = Duration::from_secs(60);
    const WAIT: Duration = Duration::from_secs(10);

    pub(crate) fn acquire(base: &Path, id: &str) -> Result<RunLock> {
        use std::io::Write;
        check_id(id)?;
        let dir = base.join(".locks");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{id}.lock"));
        let give_up = Instant::now() + Self::WAIT;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(RunLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > Self::STALE);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if Instant::now() >= give_up {
                        bail!("run {id} is being modified by another operation; try again");
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn delete_agent_run(id: &str) -> Result<()> {
    delete_agent_run_in(&agent_runs_dir(), id)
}

pub(crate) fn delete_agent_run_in(base: &Path, id: &str) -> Result<()> {
    check_id(id)?;
    let _lock = RunLock::acquire(base, id)?;
    let run_dir = base.join(id);
    if run_dir.exists() {
        std::fs::remove_dir_all(&run_dir)?;
    }
    // Also remove from core runs if present
    let core_dir = crate::engine::data_dir().join("runs").join(id);
    if core_dir.exists() {
        let _ = std::fs::remove_dir_all(&core_dir);
    }
    Ok(())
}

pub fn update_run_case_result(id: &str, res: &CaseExecutionResult) -> Result<AgentRunReport> {
    update_run_case_result_in(&agent_runs_dir(), id, res)
}

pub(crate) fn update_run_case_result_in(
    base: &Path,
    id: &str,
    res: &CaseExecutionResult,
) -> Result<AgentRunReport> {
    check_id(id)?;
    let _lock = RunLock::acquire(base, id)?;
    let mut rep = load_agent_run_in(base, id)?;
    if rep.status == "running" {
        bail!("run {id} is still running; retest it once it has finished");
    }
    if let Some(pos) = rep
        .executed_results
        .iter()
        .position(|c| c.case_id == res.case_id)
    {
        rep.executed_results[pos] = res.clone();
    } else {
        rep.executed_results.push(res.clone());
    }
    // the stored verdict must follow the evidence: recompute defects and the ledger from the new results
    refresh_derived(&mut rep);
    save_agent_run_in(base, &rep)?;
    Ok(rep)
}

/// A sign-off is a statement about one specific verdict. When the verdict changes, the statement no
/// longer applies: back to pending, with the reason on record.
fn reset_approval(rep: &mut AgentRunReport, old: Option<&str>, new: &str) {
    let signed = matches!(
        rep.approval_status.as_deref(),
        Some("approved") | Some("rejected")
    );
    if signed {
        rep.notes.push(format!(
            "sign-off reset: a retest changed the gate verdict from {} to {new}; the earlier decision ({} by {}) no longer applies and the run is pending review again",
            old.unwrap_or("none"),
            rep.approval_status.as_deref().unwrap_or("?"),
            rep.approved_by.as_deref().unwrap_or("unknown"),
        ));
        rep.approval_status = Some("pending".into());
        rep.approved_by = None;
        rep.approval_notes = None;
        rep.approved_at = None;
    }
}

/// Re-derive defects and the ledger from `executed_results` (after a retest). The LLM advisory
/// and prose are dropped: they described the previous results. A changed gate verdict resets the
/// approval state.
fn refresh_derived(rep: &mut AgentRunReport) {
    use super::{ledger, triage};
    if rep
        .evidence_ledger
        .as_ref()
        .is_some_and(|l| l.computed_verdict.is_empty())
    {
        return; // legacy / engine-derived run: nothing to recompute from
    }
    let before = rep.evidence_ledger.as_ref().map(|l| l.gate_verdict.clone());
    let mut defects = triage::derive_defects(&rep.executed_results);
    // an acceptance that still holds today keeps covering the same defect (same fingerprint);
    // one that has expired does not
    let today = crate::engine::today();
    for d in defects.iter_mut() {
        d.accepted = rep
            .triaged_defects
            .iter()
            .find(|o| !o.fingerprint.is_empty() && o.fingerprint == d.fingerprint)
            .and_then(|o| o.accepted.clone())
            .filter(|a| a.is_effective(&today));
    }
    let l = ledger::compute(&ledger::LedgerInput {
        results: &rep.executed_results,
        defects: &defects,
        dry_run: rep.dry_run,
        budget_stop: rep.budget.as_ref().and_then(|b| b.stopped.as_deref()),
    });
    let after = l.gate_verdict.clone();
    rep.triaged_defects = defects;
    if let Some(a) = rep.agents.as_mut() {
        super::lead::recount(a, &rep.executed_results, &rep.triaged_defects);
    }
    rep.evidence_ledger = Some(l);
    rep.notes.push(
        "results were changed by a retest; defects and ledger were recomputed deterministically"
            .into(),
    );
    if before.as_deref() != Some(after.as_str()) {
        reset_approval(rep, before.as_deref(), &after);
    }
}

/// Reports written by older builds carried constant scores and had no computed verdict. They
/// still load, labelled as such.
fn normalize(mut rep: AgentRunReport) -> AgentRunReport {
    if let Some(l) = rep.evidence_ledger.as_mut() {
        if l.composite_score.is_none() && l.evaluated {
            l.composite_score = Some(l.overall_readiness);
        }
        if l.verdict.is_none() {
            l.verdict = Some(l.gate_verdict.clone());
        }
        if l.computed_verdict.is_empty()
            && matches!(l.gate_verdict.as_str(), "GO" | "NO_GO" | "CONDITIONAL_GO")
        {
            l.evaluated = true;
            l.composite_score = Some(l.overall_readiness);
            l.verdict_basis = "legacy report: scores were not computed from a coverage matrix and have no cited evidence".into();
        }
    }
    rep
}

pub fn convert_engine_run_to_agent_report(r: &crate::model::Run) -> AgentRunReport {
    use crate::model::{CheckStatus, Severity as Sev, Verdict};
    let target_str = match &r.target.path {
        Some(p) => p.to_string_lossy().to_string(),
        None => "local-target".to_string(),
    };
    let executed: Vec<CaseExecutionResult> = r
        .checks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let status = match &c.status {
                CheckStatus::Passed => "PASS",
                CheckStatus::Failed => "FAIL",
                CheckStatus::Partial(_) => "WARN",
                CheckStatus::Skipped(_) | CheckStatus::NotApplicable(_) => "SKIPPED",
                CheckStatus::Errored(_) => "BLOCKED",
            };
            let why = match &c.status {
                CheckStatus::Partial(m)
                | CheckStatus::Skipped(m)
                | CheckStatus::NotApplicable(m)
                | CheckStatus::Errored(m) => Some(m.clone()),
                _ if c.findings > 0 => {
                    Some(format!("{} reported {} finding(s)", c.title, c.findings))
                }
                _ => None,
            };
            CaseExecutionResult {
                case_id: format!("CHK-{:03}", i + 1),
                title: c.title.clone(),
                component: c.id.clone(),
                method: "SCAN".into(),
                technique: "engine_rule".into(),
                status: status.into(),
                status_code: None,
                latency_ms: c.duration_ms as u64,
                reproduction_curl: String::new(),
                request_payload: None,
                evidence: format!("{} finding(s)", c.findings),
                content_type: None,
                is_spa_shell: false,
                failure_reason: why,
                expected_status: None,
                oracle: None,
                flaky: false,
                attempts: vec![],
                evidence_file: None,
                evidence_detail: None,
                stateful_chain: None,
                concurrency_burst_results: None,
            }
        })
        .collect();
    let triaged: Vec<TriagedDefect> = r
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let (sev, prio) = match f.severity {
                Sev::Critical => ("critical", "P0"),
                Sev::High => ("high", "P1"),
                Sev::Medium => ("medium", "P2"),
                Sev::Low => ("low", "P3"),
                Sev::Info => ("info", "P3"),
            };
            TriagedDefect {
                id: format!("DEF-{:03}", i + 1),
                title: f.title.clone(),
                severity: sev.into(),
                priority: prio.into(),
                component: f.location.clone(),
                root_cause_hypothesis: f.detail.clone(),
                blast_radius: "service".into(),
                owasp_category: format!("{:?}", f.category),
                recommended_fix: f.remediation.clone(),
                reproduction: String::new(),
                case_ids: vec![],
                evidence_files: vec![],
                ai_note: None,
                remediation_patch: None,
                remediation_explanation: None,
                reproduction_script: None,
                ..Default::default()
            }
        })
        .collect();
    let n = |s: &str| executed.iter().filter(|c| c.status == s).count();
    let (pass, fail, warn, errored) = (n("PASS"), n("FAIL"), n("WARN"), n("BLOCKED"));
    let conclusive = pass + fail + warn + errored;
    let overall = if conclusive == 0 {
        0
    } else {
        (100.0 * (pass as f64 + 0.5 * warn as f64) / conclusive as f64).round() as u32
    };
    let verdict = match r.verdict {
        Verdict::Pass => "GO",
        Verdict::Warn => "CONDITIONAL_GO",
        Verdict::Fail => "NO_GO",
    };
    let ledger = EvidenceLedger {
        value_score: None, authority_score: None, safety_score: None, evidence_score: None, overall_readiness: overall, gate_verdict: verdict.into(),
        executive_summary: format!("Core engine executed {} checks: {pass} passed, {fail} failed, {warn} partial, {errored} errored.", r.checks.len()),
        exit_criteria_checklist: vec![ExitCheckItem { criterion: "Engine verdict is PASS".into(), met: matches!(r.verdict, Verdict::Pass), details: r.reasons.join("; "), case_ids: vec![], evidence_files: vec![] }],
        composite_score: Some(overall), verdict: Some(verdict.into()), evaluated: conclusive > 0, computed_verdict: verdict.into(),
        verdict_basis: "engine verdict of a readyhai scan; this is not an agent run, so there are no pillar scores".into(), pillars: vec![], coverage: vec![], claims: vec![], llm_advisory: None, ai_summary: None, verification: None,
    };
    AgentRunReport {
        id: r.id.clone(),
        target: target_str,
        profile: format!("{:?}", r.profile),
        model: "none".into(),
        provider: "core-engine".into(),
        started_at: r.started.clone(),
        finished_at: Some(r.finished.clone()),
        status: "completed".into(),
        steps: vec![AgentStepLog {
            timestamp: r.started.clone(),
            agent: "CoreEngine".into(),
            action: "Execution".into(),
            details: format!("Run {} completed with verdict: {:?}", r.id, r.verdict),
            status: "completed".into(),
            source: Some("engine".into()),
        }],
        discovered_routes: vec![],
        planned_cases: vec![],
        executed_results: executed,
        triaged_defects: triaged,
        evidence_ledger: Some(ledger),
        approval_status: Some("pending".into()),
        approved_by: None,
        approval_notes: None,
        approved_at: None,
        error: None,
        thinking: false,
        model_tier: "medium".into(),
        thinking_budget_tokens: 0,
        app_architecture: None,
        framework: None,
        detected_tech: vec![],
        requester_ip: None,
        requester_ip_type: None,
        allowlist_guidance: None,
        dry_run: false,
        stage_sources: Default::default(),
        llm_status: Some("not used: core engine run".into()),
        budget: None,
        notes: vec![],
        change_impact: None,
        agents: None,
        since_last_run: None,
    }
}

fn read_report(path: &Path) -> Option<AgentRunReport> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<AgentRunReport>(&text)
        .ok()
        .map(normalize)
}

pub fn list_agent_full_runs() -> Vec<AgentRunReport> {
    list_runs_in(&agent_runs_dir())
}

pub(crate) fn list_runs_in(dir: &Path) -> Vec<AgentRunReport> {
    let mut out: Vec<AgentRunReport> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| read_report(&e.path().join("report.json")))
        .collect();
    out.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    out
}

pub fn list_agent_runs() -> Vec<AgentRunSummary> {
    list_agent_full_runs()
        .into_iter()
        .map(|r| AgentRunSummary {
            id: r.id.clone(),
            target: r.target.clone(),
            status: r.status.clone(),
            started_at: r.started_at.clone(),
            readiness_score: r
                .evidence_ledger
                .as_ref()
                .filter(|l| l.evaluated)
                .map(|l| l.overall_readiness),
            gate_verdict: r.evidence_ledger.as_ref().map(|l| l.gate_verdict.clone()),
            defects_count: r.triaged_defects.len(),
            cases_count: if !r.executed_results.is_empty() {
                r.executed_results.len()
            } else {
                r.planned_cases.len()
            },
            approval_status: r.approval_status.clone(),
            app_architecture: r.app_architecture.clone(),
            requester_ip: r.requester_ip.clone(),
        })
        .collect()
}

pub fn load_agent_run(id: &str) -> Result<AgentRunReport> {
    load_agent_run_in(&agent_runs_dir(), id)
}

pub(crate) fn load_agent_run_in(base: &Path, id: &str) -> Result<AgentRunReport> {
    check_id(id)?;
    let path = base.join(id).join("report.json");
    if path.exists() {
        return Ok(normalize(serde_json::from_str(&std::fs::read_to_string(
            path,
        )?)?));
    }
    // Fallback: core engine run
    let engine_path = crate::engine::run_dir(id).join("run.json");
    if engine_path.exists()
        && let Ok(run) =
            serde_json::from_str::<crate::model::Run>(&std::fs::read_to_string(engine_path)?)
    {
        return Ok(convert_engine_run_to_agent_report(&run));
    }
    bail!("Run {id} not found")
}

/// A sign-off the run's state does not allow: the request is refused (409), not a server fault.
#[derive(Debug)]
pub struct SignOffRefused(pub String);

impl std::fmt::Display for SignOffRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SignOffRefused {}

pub(crate) fn sign_off_in(
    base: &Path,
    id: &str,
    status: &str,
    user: &str,
    notes: &str,
) -> Result<AgentRunReport> {
    check_id(id)?;
    let _lock = RunLock::acquire(base, id)?;
    let mut rep = load_agent_run_in(base, id)?;
    // A decision is about a finished verdict: nothing to sign while the run is still going, an
    // incomplete (failed / cancelled) run can be rejected but never approved, and only a GO or
    // CONDITIONAL_GO verdict can be approved (a NO_GO run can only be blocked, as in the UI).
    if rep.status == "running" {
        return Err(SignOffRefused(format!(
            "run {id} is still running; it cannot be signed off yet"
        ))
        .into());
    }
    if status == "approved" && rep.status != "completed" {
        return Err(SignOffRefused(format!(
            "run {id} ended as {}; only a completed run can be approved",
            rep.status
        ))
        .into());
    }
    let verdict = rep
        .evidence_ledger
        .as_ref()
        .map_or("none", |l| l.gate_verdict.as_str());
    if status == "approved" && !matches!(verdict, "GO" | "CONDITIONAL_GO") {
        return Err(SignOffRefused(format!(
            "run {id} has gate verdict {verdict}; only GO or CONDITIONAL_GO can be approved"
        ))
        .into());
    }
    rep.approval_status = Some(status.to_string());
    rep.approved_by = Some(user.to_string());
    rep.approval_notes = Some(notes.to_string());
    rep.approved_at = Some(now_iso());
    save_agent_run_in(base, &rep)?;
    Ok(rep)
}

pub fn approve_agent_run(id: &str, user: &str, notes: &str) -> Result<AgentRunReport> {
    sign_off_in(&agent_runs_dir(), id, "approved", user, notes)
}

pub fn reject_agent_run(id: &str, user: &str, notes: &str) -> Result<AgentRunReport> {
    sign_off_in(&agent_runs_dir(), id, "rejected", user, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::ledger::{self, LedgerInput};
    use crate::agent::triage;
    use crate::agent::types::fixtures::{planned, report, result};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rh-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// A stored, computed run whose only case fails an authz check (NO_GO).
    fn failing_run(base: &Path, id: &str) -> AgentRunReport {
        let mut rep = report(id);
        rep.executed_results = vec![result("TC-001", "authz", "FAIL")];
        rep.planned_cases = vec![planned("TC-001", "authz", "GET", "/x")];
        rep.triaged_defects = triage::derive_defects(&rep.executed_results);
        rep.evidence_ledger = Some(ledger::compute(&LedgerInput {
            results: &rep.executed_results,
            defects: &rep.triaged_defects,
            dry_run: false,
            budget_stop: None,
        }));
        save_agent_run_in(base, &rep).unwrap();
        rep
    }

    #[test]
    fn a_retest_that_changes_the_verdict_resets_the_approval_state() {
        let base = tmp("approval");
        let rep = failing_run(&base, "run-appr");
        let before = rep.evidence_ledger.as_ref().unwrap().gate_verdict.clone();
        assert_eq!(before, "NO_GO");
        // a NO_GO run cannot be approved, only blocked
        let refused = sign_off_in(&base, "run-appr", "approved", "alice", "ship it").unwrap_err();
        assert!(
            refused.downcast_ref::<SignOffRefused>().is_some(),
            "{refused}"
        );
        assert!(refused.to_string().contains("NO_GO"), "{refused}");
        assert_eq!(
            load_agent_run_in(&base, "run-appr")
                .unwrap()
                .approval_status
                .as_deref(),
            Some("pending"),
            "a refused sign-off leaves the run pending"
        );
        let signed = sign_off_in(&base, "run-appr", "rejected", "alice", "not yet").unwrap();
        assert_eq!(signed.approval_status.as_deref(), Some("rejected"));

        // a retest that fails the same way: same verdict, the decision stands
        let mut same = result("TC-001", "authz", "FAIL");
        same.latency_ms = 99;
        let r = update_run_case_result_in(&base, "run-appr", &same).unwrap();
        assert_eq!(r.evidence_ledger.as_ref().unwrap().gate_verdict, before);
        assert_eq!(
            (r.approval_status.as_deref(), r.approved_by.as_deref()),
            (Some("rejected"), Some("alice")),
            "an unchanged verdict keeps its sign-off"
        );

        // the case now passes: the verdict changes, so the sign-off no longer applies
        let r = update_run_case_result_in(&base, "run-appr", &result("TC-001", "authz", "PASS"))
            .unwrap();
        let after = r.evidence_ledger.as_ref().unwrap().gate_verdict.clone();
        assert_ne!(after, before);
        assert_eq!(r.approval_status.as_deref(), Some("pending"));
        assert!(r.approved_by.is_none() && r.approval_notes.is_none() && r.approved_at.is_none());
        let note = r
            .notes
            .iter()
            .find(|n| n.contains("sign-off reset"))
            .expect("reset is on record");
        assert!(
            note.contains(&before) && note.contains(&after) && note.contains("alice"),
            "{note}"
        );
        // and on disk, not just in the returned value
        let disk = load_agent_run_in(&base, "run-appr").unwrap();
        assert_eq!(disk.approval_status.as_deref(), Some("pending"));
        assert!(disk.approved_by.is_none());

        // the verdict is now approvable: GO / CONDITIONAL_GO can be approved, and that decision is
        // reset the same way when a later retest flips the verdict back
        sign_off_in(&base, "run-appr", "approved", "bob", "ok").unwrap();
        let r = update_run_case_result_in(&base, "run-appr", &result("TC-001", "authz", "FAIL"))
            .unwrap();
        assert_eq!(
            r.approval_status.as_deref(),
            Some("pending"),
            "{:?}",
            r.notes
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_running_run_cannot_be_signed_off_or_retested_and_an_incomplete_one_cannot_be_approved() {
        let base = tmp("running");
        let mut rep = failing_run(&base, "run-live");
        rep.status = "running".into();
        checkpoint_agent_run_in(&base, &rep).unwrap();
        assert_eq!(
            checkpoint_status(&base.join("run-live")).as_deref(),
            Some("running")
        );
        for st in ["approved", "rejected"] {
            let e = sign_off_in(&base, "run-live", st, "a", "n")
                .unwrap_err()
                .to_string();
            assert!(e.contains("still running"), "{e}");
        }
        let e = update_run_case_result_in(&base, "run-live", &result("TC-001", "authz", "PASS"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("still running"), "{e}");
        rep.status = "cancelled".into();
        checkpoint_agent_run_in(&base, &rep).unwrap();
        assert!(
            sign_off_in(&base, "run-live", "approved", "a", "n")
                .unwrap_err()
                .to_string()
                .contains("only a completed run")
        );
        assert_eq!(
            sign_off_in(&base, "run-live", "rejected", "a", "n")
                .unwrap()
                .approval_status
                .as_deref(),
            Some("rejected")
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_per_run_lock_serialises_writers_and_loses_no_update() {
        let base = tmp("lock");
        let mut rep = report("run-lock");
        rep.executed_results = (1..=8)
            .map(|i| result(&format!("TC-{i:03}"), "boundary", "PASS"))
            .collect();
        rep.evidence_ledger = Some(ledger::compute(&LedgerInput {
            results: &rep.executed_results,
            defects: &[],
            dry_run: false,
            budget_stop: None,
        }));
        save_agent_run_in(&base, &rep).unwrap();
        // 8 concurrent retests, each changing its own case: without the lock the last writer wins
        let handles: Vec<_> = (1..=8u64)
            .map(|i| {
                let base = base.clone();
                std::thread::spawn(move || {
                    let mut r = result(&format!("TC-{i:03}"), "boundary", "PASS");
                    r.latency_ms = i * 100;
                    update_run_case_result_in(&base, "run-lock", &r).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let disk = load_agent_run_in(&base, "run-lock").unwrap();
        for i in 1..=8u64 {
            let r = disk
                .executed_results
                .iter()
                .find(|r| r.case_id == format!("TC-{i:03}"))
                .unwrap();
            assert_eq!(r.latency_ms, i * 100, "update {i} was lost");
        }
        assert!(
            !base.join(".locks").join("run-lock.lock").exists(),
            "the lock file is removed after use"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_lock_blocks_a_second_holder_and_a_stale_lock_is_taken_over() {
        let base = tmp("lock2");
        let first = RunLock::acquire(&base, "run-a").unwrap();
        let lock_file = base.join(".locks").join("run-a.lock");
        assert!(lock_file.exists());
        // a different run is not blocked
        drop(RunLock::acquire(&base, "run-b").unwrap());
        let (b2, t0) = (base.clone(), Instant::now());
        let waiter = std::thread::spawn(move || {
            let _l = RunLock::acquire(&b2, "run-a").unwrap();
            t0.elapsed()
        });
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !waiter.is_finished(),
            "the second holder waits for the first"
        );
        drop(first);
        assert!(waiter.join().unwrap() >= Duration::from_millis(140));
        // a lock left by a crashed writer is stale after 60 s
        let _ = std::fs::remove_file(&lock_file);
        std::fs::write(&lock_file, "99999\n").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(120);
        std::fs::File::options()
            .write(true)
            .open(&lock_file)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let t = Instant::now();
        let _l = RunLock::acquire(&base, "run-a").unwrap();
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "stale lock must not be waited out"
        );
        assert!(
            RunLock::acquire(&base, "../escape").is_err(),
            "ids are validated"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn checkpoint_writes_report_json_without_the_renderings() {
        let base = tmp("ckpt");
        let mut rep = report("run-ck");
        rep.status = "running".into();
        checkpoint_agent_run_in(&base, &rep).unwrap();
        let run = base.join("run-ck");
        assert!(run.join("report.json").exists());
        assert!(
            !run.join("report").exists(),
            "renderings are written when the run ends"
        );
        let back = load_agent_run_in(&base, "run-ck").unwrap();
        assert_eq!(back.status, "running");
        assert_eq!(list_runs_in(&base).len(), 1, "a running run is listed");
        // cleanup sidecar round trip
        let c = CleanupReport {
            created: 2,
            deleted: 1,
            leftovers: vec![Leftover {
                method: "POST".into(),
                path: "/a/1".into(),
                id: "1".into(),
                reason: "HTTP 405".into(),
            }],
            ..Default::default()
        };
        save_cleanup_in(&base, "run-ck", &c).unwrap();
        assert_eq!(load_cleanup_in(&base, "run-ck"), Some(c));
        assert_eq!(load_cleanup_in(&base, "nope"), None);
        let _ = std::fs::remove_dir_all(&base);
    }
}
