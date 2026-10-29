//! Persistence of agent runs under <data_dir>/agent-runs/<id>/ : report.json (atomic), evidence/*.json,
//! report/* renderings. Plus the read side used by the REST API and sign-off actions.
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use super::report::generate_agent_report_formats;
use super::types::*;
use crate::llm::write_atomic;

pub fn now_iso() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| now.unix_timestamp().to_string())
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

/// Write the run into `base/<id>/`. `report.json` is replaced atomically (a reader or a crash never
/// sees a half-written file); evidence files are written for results that carry fresh detail.
pub(crate) fn save_agent_run_in(base: &Path, rep: &AgentRunReport) -> Result<()> {
    check_id(&rep.id)?;
    let run_dir = base.join(&rep.id);
    let rep_dir = run_dir.join("report");
    std::fs::create_dir_all(&rep_dir)?;
    for r in &rep.executed_results {
        if let (Some(detail), Some(rel)) = (&r.evidence_detail, &r.evidence_file) {
            if rel.starts_with("evidence/") && !rel.contains("..") {
                write_atomic(&run_dir.join(rel), serde_json::to_string_pretty(detail)?.as_bytes())?;
            }
        }
    }
    write_atomic(&run_dir.join("report.json"), serde_json::to_string_pretty(rep)?.as_bytes())?;
    let _ = generate_agent_report_formats(rep, &rep_dir, &ALL_FORMATS.map(String::from));
    Ok(())
}

pub fn delete_agent_run(id: &str) -> Result<()> {
    check_id(id)?;
    let run_dir = agent_runs_dir().join(id);
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
    let mut rep = load_agent_run(id)?;
    if let Some(pos) = rep.executed_results.iter().position(|c| c.case_id == res.case_id) {
        rep.executed_results[pos] = res.clone();
    } else {
        rep.executed_results.push(res.clone());
    }
    // the stored verdict must follow the evidence: recompute defects and the ledger from the new results
    refresh_derived(&mut rep);
    save_agent_run(&rep)?;
    Ok(rep)
}

/// Re-derive defects and the ledger from `executed_results` (after a retest). The LLM advisory
/// and prose are dropped: they described the previous results.
fn refresh_derived(rep: &mut AgentRunReport) {
    use super::{ledger, triage};
    if rep.evidence_ledger.as_ref().is_some_and(|l| l.computed_verdict.is_empty()) {
        return; // legacy / engine-derived run: nothing to recompute from
    }
    let defects = triage::derive_defects(&rep.executed_results);
    let l = ledger::compute(&ledger::LedgerInput { results: &rep.executed_results, defects: &defects, dry_run: rep.dry_run, budget_stop: rep.budget.as_ref().and_then(|b| b.stopped.as_deref()) });
    rep.triaged_defects = defects;
    rep.evidence_ledger = Some(l);
    rep.notes.push("results were changed by a retest; defects and ledger were recomputed deterministically".into());
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
        if l.computed_verdict.is_empty() && matches!(l.gate_verdict.as_str(), "GO" | "NO_GO" | "CONDITIONAL_GO") {
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
                CheckStatus::Partial(m) | CheckStatus::Skipped(m) | CheckStatus::NotApplicable(m) | CheckStatus::Errored(m) => Some(m.clone()),
                _ if c.findings > 0 => Some(format!("{} reported {} finding(s)", c.title, c.findings)),
                _ => None,
            };
            CaseExecutionResult {
                case_id: format!("CHK-{:03}", i + 1), title: c.title.clone(), component: c.id.clone(), method: "SCAN".into(), technique: "engine_rule".into(), status: status.into(),
                status_code: None, latency_ms: c.duration_ms as u64, reproduction_curl: String::new(), request_payload: None, evidence: format!("{} finding(s)", c.findings), content_type: None,
                is_spa_shell: false, failure_reason: why, expected_status: None, oracle: None, flaky: false, attempts: vec![], evidence_file: None, evidence_detail: None,
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
                id: format!("DEF-{:03}", i + 1), title: f.title.clone(), severity: sev.into(), priority: prio.into(), component: f.location.clone(), root_cause_hypothesis: f.detail.clone(),
                blast_radius: "service".into(), owasp_category: format!("{:?}", f.category), recommended_fix: f.remediation.clone(), reproduction: String::new(),
                case_ids: vec![], evidence_files: vec![], ai_note: None,
            }
        })
        .collect();
    let n = |s: &str| executed.iter().filter(|c| c.status == s).count();
    let (pass, fail, warn, errored) = (n("PASS"), n("FAIL"), n("WARN"), n("BLOCKED"));
    let conclusive = pass + fail + warn + errored;
    let overall = if conclusive == 0 { 0 } else { (100.0 * (pass as f64 + 0.5 * warn as f64) / conclusive as f64).round() as u32 };
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
        verdict_basis: "engine verdict of a readyhai scan; this is not an agent run, so there are no pillar scores".into(), pillars: vec![], coverage: vec![], claims: vec![], llm_advisory: None, ai_summary: None,
    };
    AgentRunReport {
        id: r.id.clone(), target: target_str, profile: format!("{:?}", r.profile), model: "none".into(), provider: "core-engine".into(), started_at: r.started.clone(), finished_at: Some(r.finished.clone()),
        status: "completed".into(),
        steps: vec![AgentStepLog { timestamp: r.started.clone(), agent: "CoreEngine".into(), action: "Execution".into(), details: format!("Run {} completed with verdict: {:?}", r.id, r.verdict), status: "completed".into(), source: Some("engine".into()) }],
        discovered_routes: vec![], planned_cases: vec![], executed_results: executed, triaged_defects: triaged, evidence_ledger: Some(ledger),
        approval_status: Some("pending".into()), approved_by: None, approval_notes: None, approved_at: None, error: None,
        thinking: false, model_tier: "medium".into(), thinking_budget_tokens: 0, app_architecture: None, framework: None, detected_tech: vec![],
        requester_ip: None, requester_ip_type: None, allowlist_guidance: None, dry_run: false, stage_sources: Default::default(), llm_status: Some("not used: core engine run".into()), budget: None, notes: vec![],
    }
}

fn read_report(path: &Path) -> Option<AgentRunReport> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<AgentRunReport>(&text).ok().map(normalize)
}

pub fn list_agent_full_runs() -> Vec<AgentRunReport> {
    list_runs_in(&agent_runs_dir())
}

pub(crate) fn list_runs_in(dir: &Path) -> Vec<AgentRunReport> {
    let mut out: Vec<AgentRunReport> = std::fs::read_dir(dir).into_iter().flatten().flatten().filter_map(|e| read_report(&e.path().join("report.json"))).collect();
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
            readiness_score: r.evidence_ledger.as_ref().filter(|l| l.evaluated).map(|l| l.overall_readiness),
            gate_verdict: r.evidence_ledger.as_ref().map(|l| l.gate_verdict.clone()),
            defects_count: r.triaged_defects.len(),
            cases_count: if !r.executed_results.is_empty() { r.executed_results.len() } else { r.planned_cases.len() },
            approval_status: r.approval_status.clone(),
            app_architecture: r.app_architecture.clone(),
            requester_ip: r.requester_ip.clone(),
        })
        .collect()
}

pub fn load_agent_run(id: &str) -> Result<AgentRunReport> {
    check_id(id)?;
    let path = agent_runs_dir().join(id).join("report.json");
    if path.exists() {
        return Ok(normalize(serde_json::from_str(&std::fs::read_to_string(path)?)?));
    }
    // Fallback: core engine run
    let engine_path = crate::engine::run_dir(id).join("run.json");
    if engine_path.exists() {
        if let Ok(run) = serde_json::from_str::<crate::model::Run>(&std::fs::read_to_string(engine_path)?) {
            return Ok(convert_engine_run_to_agent_report(&run));
        }
    }
    bail!("Run {id} not found")
}

fn sign_off(id: &str, status: &str, user: &str, notes: &str) -> Result<AgentRunReport> {
    let mut rep = load_agent_run(id)?;
    rep.approval_status = Some(status.to_string());
    rep.approved_by = Some(user.to_string());
    rep.approval_notes = Some(notes.to_string());
    rep.approved_at = Some(now_iso());
    save_agent_run(&rep)?;
    Ok(rep)
}

pub fn approve_agent_run(id: &str, user: &str, notes: &str) -> Result<AgentRunReport> {
    sign_off(id, "approved", user, notes)
}

pub fn reject_agent_run(id: &str, user: &str, notes: &str) -> Result<AgentRunReport> {
    sign_off(id, "rejected", user, notes)
}
