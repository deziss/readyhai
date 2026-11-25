use std::path::Path;

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use super::protocol::{MAX_AGENT_JOBS, jobs};
use super::scanner::{mcp_allowed_roots, trunc};
use crate::engine;

/// Arguments of `readyhai_agent_swarm`. Unknown fields are an error (a model that invents a
/// parameter such as `skip_scope` must be told, not silently ignored).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmArgs {
    pub target: Option<String>,
    #[serde(default, alias = "custom_instructions")]
    pub directives: Option<String>,
    pub profile: Option<String>,
    pub max_steps: Option<i64>,
    pub thinking: Option<bool>,
    pub model_tier: Option<String>,
    pub thinking_budget_tokens: Option<u64>,
    pub dry_run: Option<bool>,
    pub spec_url: Option<String>,
    pub repo: Option<String>,
    pub diff_base: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverArgs {
    pub target: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIdArgs {
    pub id: Option<String>,
}

pub fn parse_args<T: serde::de::DeserializeOwned>(tool: &str, args: &Value) -> Result<T> {
    serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("invalid arguments for {tool}: {e}"))
}

/// Typed, validated agent request. Over MCP a run is a dry run unless the caller says otherwise AND
/// the server operator allowed writes; the reasoning budget is clamped.
pub fn swarm_request(args: &Value) -> Result<crate::agent::AgentRunRequest> {
    let a: SwarmArgs = parse_args("readyhai_agent_swarm", args)?;
    let target = a.target.unwrap_or_default();
    if target.trim().is_empty() {
        bail!("target is required and cannot be empty");
    }
    let profile = a.profile.unwrap_or_else(|| "standard".into());
    if !["quick", "standard", "deep"].contains(&profile.as_str()) {
        bail!("profile must be quick|standard|deep");
    }
    let model_tier = a.model_tier.unwrap_or_else(|| "high".into());
    if !["low", "medium", "high", "max", "max_pro"].contains(&model_tier.as_str()) {
        bail!("model_tier must be low|medium|high|max|max_pro");
    }
    let max_steps = match a.max_steps {
        None => 15,
        Some(n) if (1..=50).contains(&n) => n as usize,
        Some(_) => bail!("max_steps must be between 1 and 50"),
    };
    let dry_run = a.dry_run.unwrap_or(true);
    if !dry_run && std::env::var("READYHAI_MCP_ALLOW_WRITES").as_deref() != Ok("1") {
        bail!(
            "dry_run=false is refused over MCP: state-changing requests need the operator to set READYHAI_MCP_ALLOW_WRITES=1 on the server (and the target must be nonprod in scope.toml)"
        );
    }
    let max_ci_bytes = crate::serve::max_custom_instructions_bytes();
    if a.directives
        .as_deref()
        .is_some_and(|d| d.len() > max_ci_bytes)
    {
        bail!("directives is limited to {max_ci_bytes} bytes");
    }
    let budget = a
        .thinking_budget_tokens
        .unwrap_or(8192)
        .min(u32::MAX as u64) as u32;
    let (repo, diff_base) = match (
        a.repo.filter(|s| !s.trim().is_empty()),
        a.diff_base.filter(|s| !s.trim().is_empty()),
    ) {
        (None, None) => (None, None),
        (Some(_), None) | (None, Some(_)) => bail!("repo and diff_base must be given together"),
        (Some(r), Some(b)) => {
            let (root, base) =
                crate::agent::change::validate_request(&r, Some(&b), Some(&mcp_allowed_roots()?))
                    .map_err(|e| anyhow::anyhow!(e))?;
            (Some(root.display().to_string()), base)
        }
    };
    Ok(crate::agent::AgentRunRequest {
        target,
        profile,
        spec_url: a.spec_url.filter(|s| !s.trim().is_empty()),
        custom_instructions: a.directives.filter(|s| !s.trim().is_empty()),
        max_steps: Some(max_steps),
        dry_run,
        thinking: a.thinking.unwrap_or(true),
        model_tier,
        thinking_budget_tokens: crate::llm::clamp_thinking_budget(budget),
        repo,
        diff_base,
    })
}

/// Removes a run from the job list when its worker thread ends, however it ends.
pub struct JobGuard(pub String);

impl Drop for JobGuard {
    fn drop(&mut self) {
        jobs().retain(|j| j != &self.0);
    }
}

pub type Runner = Box<
    dyn FnOnce(&crate::agent::AgentRunRequest, &str) -> Result<crate::agent::AgentRunReport> + Send,
>;

/// Start the run on a worker thread and return at once: the server keeps answering `ping` and
/// every other request, and nothing but JSON-RPC ever reaches stdout. The result is read with
/// `readyhai_agent_status`.
pub fn start_swarm(
    mut req: crate::agent::AgentRunRequest,
    scope: Option<&crate::scope::Scope>,
    run: Runner,
) -> Result<String> {
    // writes and attack payloads: the target must be allowed for intrusive actions (nonprod)
    req.target = crate::scope::egress_guard(&req.target, scope, true)?.url;
    if let Some(spec) = &req.spec_url {
        req.spec_url = Some(crate::scope::egress_guard(spec, scope, false)?.url);
    }
    let run_id = engine::new_run_id();
    {
        let mut j = jobs();
        if j.len() >= MAX_AGENT_JOBS {
            bail!(
                "{} agent runs are already in progress (limit {MAX_AGENT_JOBS}); poll them with readyhai_agent_status or stop one with readyhai_agent_cancel",
                j.len()
            );
        }
        j.push(run_id.clone());
    }
    let guard = JobGuard(run_id.clone());
    let (id2, req2) = (run_id.clone(), req.clone());
    eprintln!(
        "readyhai mcp: agent run {run_id} against {} (dry_run={})",
        req.target, req.dry_run
    );
    std::thread::Builder::new()
        .name("readyhai-agent-run".into())
        .spawn(move || {
            let _guard = guard;
            if let Err(e) = run(&req2, &id2) {
                eprintln!("readyhai mcp: agent run {id2} failed: {e:#}");
            }
        })
        .map_err(|e| {
            jobs().retain(|j| j != &run_id);
            anyhow::anyhow!("cannot start the agent run: {e}")
        })?;
    Ok(serde_json::to_string_pretty(&json!({
        "run_id": run_id,
        "status": "running",
        "target": req.target,
        "dry_run": req.dry_run,
        "max_steps": req.max_steps,
        "next": format!("poll readyhai_agent_status with {{\"id\": \"{run_id}\"}}; stop it with readyhai_agent_cancel"),
    }))?)
}

pub fn run_id_arg(tool: &str, args: &Value) -> Result<String> {
    let a: RunIdArgs = parse_args(tool, args)?;
    let id = a.id.unwrap_or_default();
    if !engine::valid_run_id(&id) {
        bail!("id is required and must be a run id returned by readyhai_agent_swarm");
    }
    Ok(id)
}

pub fn agent_cancel(id: &str) -> Result<String> {
    Ok(if crate::agent::request_cancel(id) {
        format!(
            "cancel requested for run {id}; it stops at its next step, then records what it did. Poll readyhai_agent_status."
        )
    } else {
        format!("run {id} is not running (it may have finished: see readyhai_agent_status)")
    })
}

/// Compact status of a run read from its (checkpointed) `report.json`.
pub fn agent_status_in(base: &Path, id: &str) -> Result<String> {
    let path = base.join(id).join("report.json");
    let text = std::fs::read_to_string(&path).map_err(|_| {
        anyhow::anyhow!(
            "no agent run '{id}' (it may not have written its first checkpoint yet; try again in a moment)"
        )
    })?;
    let rep: crate::agent::AgentRunReport =
        serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("run {id} is unreadable: {e}"))?;
    let ledger = rep.evidence_ledger.as_ref();
    let last = rep.steps.last().map(|s| {
        format!(
            "{} / {} ({})",
            trunc(&s.agent, 60),
            trunc(&s.action, 80),
            trunc(&s.status, 20)
        )
    });
    let defects: Vec<Value> = rep
        .triaged_defects
        .iter()
        .take(25)
        .map(|d| {
            json!({
                "id": d.id, "severity": d.severity, "priority": d.priority,
                "title": trunc(&d.title, 200), "component": trunc(&d.component, 200),
                "owasp_category": trunc(&d.owasp_category, 120),
                "case_ids": d.case_ids.iter().take(20).collect::<Vec<_>>(),
                "recommended_fix": trunc(&d.recommended_fix, 300),
            })
        })
        .collect();
    let running = rep.status == "running";
    let out = json!({
        "run_id": rep.id,
        "status": rep.status,
        "target": trunc(&rep.target, 300),
        "dry_run": rep.dry_run,
        "started_at": rep.started_at,
        "finished_at": rep.finished_at,
        "progress": {
            "last_step": last,
            "log_entries": rep.steps.len(),
            "planned_cases": rep.planned_cases.len(),
            "executed_cases": rep.executed_results.iter().filter(|r| r.status != "SKIPPED").count(),
            "defects": rep.triaged_defects.len(),
        },
        "gate_verdict": ledger.map(|l| l.gate_verdict.clone()),
        "overall_readiness_score": ledger.filter(|l| l.evaluated).map(|l| l.overall_readiness),
        "executive_summary": ledger.map(|l| trunc(&l.executive_summary, 600)),
        "pillars": ledger.map(|l| l.pillars.iter().map(|p| json!({"id": p.id, "score": p.score, "status": p.status, "claim": trunc(&p.claim, 200)})).collect::<Vec<_>>()),
        "budget": rep.budget,
        "agents": rep.agents.as_ref().map(agents_brief),
        "since_last_run": rep.since_last_run.as_ref().map(since_brief),
        "defects": defects,
        "notes": rep.notes.iter().take(15).map(|n| trunc(n, 400)).collect::<Vec<_>>(),
        "error": rep.error.as_deref().map(|e| trunc(e, 400)),
        "next": if running { "still running: poll again in a few seconds" } else { "finished" },
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

/// What changed since the previous run against the target, compact: the counts and, per list, the
/// first few defects (`fingerprint` is what `readyhai agent-memory accept` takes).
pub fn since_brief(s: &crate::agent::memory::SinceLastRun) -> Value {
    let lines = |v: &[crate::agent::memory::DefectLine]| -> Vec<Value> {
        v.iter()
            .take(10)
            .map(|l| {
                json!({
                    "fingerprint": l.fingerprint,
                    "rule": trunc(&l.rule, 64),
                    "endpoint": trunc(&l.endpoint, 200),
                    "severity": l.severity,
                    "defect": l.defect_id,
                    "first_seen": l.first_seen,
                    "runs_seen": l.runs_seen,
                    "accepted_until": l.accepted.as_ref().map(|a| a.expires.clone()),
                    "accepted_by": l.accepted.as_ref().map(|a| trunc(&a.by, 80)),
                })
            })
            .collect()
    };
    json!({
        "summary": s.summary_line(),
        "first_run": s.first_run,
        "previous_run": s.previous_run,
        "runs_remembered": s.runs_remembered,
        "counts": {
            "new": s.new.len(), "still_open": s.still_open.len(), "fixed": s.fixed.len(),
            "regressed": s.regressed.len(), "known_flaky": s.known_flaky.len(),
            "accepted": s.accepted.len(), "expired": s.expired.len(), "not_retested": s.not_retested.len(),
        },
        "new": lines(&s.new),
        "still_open": lines(&s.still_open),
        "fixed": lines(&s.fixed),
        "regressed": lines(&s.regressed),
        "accepted": lines(&s.accepted),
        "acceptance_expired": lines(&s.expired),
        "not_retested": lines(&s.not_retested),
        "known_flaky": s.known_flaky.iter().take(10).map(|f| json!({"case_class": trunc(&f.class, 260), "pass": f.pass, "fail": f.fail, "flaky": f.flaky})).collect::<Vec<_>>(),
        "regression_probes": s.regression_probes.iter().take(10).map(|p| json!({"case": p.case_id, "class": trunc(&p.class, 260), "defects": p.defects})).collect::<Vec<_>>(),
        "memory_updated": s.committed,
        "notes": s.notes.iter().take(5).map(|n| trunc(n, 400)).collect::<Vec<_>>(),
    })
}

/// Per-area progress of the lead's workers, compact (what `readyhai_agent_status` shows).
pub fn agents_brief(a: &crate::agent::AgentsReport) -> Value {
    json!({
        "status": a.status,
        "workers": a.workers,
        "waves": a.waves,
        "areas": a.areas.iter().map(|x| json!({
            "area": x.area,
            "status": x.status,
            "cases": x.cases,
            "sent": x.executed,
            "pass": x.pass,
            "fail": x.fail,
            "other": x.warn + x.inconclusive + x.blocked + x.skipped,
            "requests": {"used": x.budget.used.requests, "allocated": x.budget.allocated.requests},
            "steps": {"used": x.budget.used.steps, "allocated": x.budget.allocated.steps},
            "wave2_added": x.wave2_added,
            "defects": x.defect_ids,
            "stopped": x.stopped.as_deref().map(|s| trunc(s, 200)),
            "error": x.error.as_deref().map(|s| trunc(s, 200)),
        })).collect::<Vec<_>>(),
        "wave2": a.wave2.iter().take(20).map(|w| json!({"case": w.case_id, "area": w.area, "rule": w.rule, "origin": w.origin})).collect::<Vec<_>>(),
    })
}

pub fn agent_discover(args: &Value, scope: Option<&crate::scope::Scope>) -> Result<String> {
    let a: DiscoverArgs = parse_args("readyhai_agent_discover", args)?;
    let target = a
        .target
        .ok_or_else(|| anyhow::anyhow!("target is required"))?;
    if target.trim().is_empty() {
        bail!("target is required and cannot be empty");
    }
    let egress = crate::scope::egress_guard(&target, scope, false)?;
    eprintln!("readyhai mcp: agent discover on {}", egress.url);
    let (mut routes, tech_profile) = crate::agent::discover_routes(&egress.url, None, 20);
    let count = routes.len();
    for r in &mut routes {
        r.path = trunc(&r.path, 300);
        r.title = r.title.take().map(|t| trunc(&t, 200));
    }
    let out = json!({
        "target": egress.url,
        "count": count,
        "framework": trunc(&tech_profile.primary_framework, 100),
        "tech_profile": tech_profile,
        "routes": routes,
    });
    Ok(serde_json::to_string_pretty(&out)?)
}
