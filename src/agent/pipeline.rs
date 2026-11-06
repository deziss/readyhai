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
use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::budget::RunBudget;
use super::change;
use super::discover::{discover, harvest_ids};
use super::exec::{
    Auth, Bearer, Clients, Credentials, DeleteCheck, ExecOptions, auth_for, confirm_deleted_as,
    curl_auth_arg, evidence_rel_path, execute_cases_with,
};
use super::lead;
use super::ledger::{self, LedgerInput};
use super::memory::{self, PlanHints, RunFacts, SinceLastRun};
use super::plan::{plan_cases_remembered, plan_cases_seeded, plans_from_spec, seed_from_run_id};
use super::store::{
    agent_runs_dir, checkpoint_agent_run_in, now_iso, save_agent_run_in, save_cleanup_in,
};
use super::triage::{add_llm_notes, derive_defects_verified};
use super::types::*;
use super::verify::{self, VerifyOptions};
use crate::llm::untrusted::{self, clean_output, fence_capped};
use crate::llm::{
    Budget, LatencyReport, LlmConfig, ask_typed, call_params, clamp_thinking_budget,
    latency_report, probe, probe_latency,
};

/// How the run decides whether to use an LLM.
#[derive(Debug, Clone, Default)]
pub enum LlmMode {
    /// READYHAI_LLM_* environment, probed once; unreachable => deterministic.
    #[default]
    Env,
    /// Deterministic only.
    Off,
    /// An explicit config (probed once as well).
    Use(Box<LlmConfig>),
}

/// Everything a run needs beyond the request itself.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub budget: RunBudget,
    /// Test credentials per role (default: RH_<ROLE>_TOKEN environment variables).
    pub credentials: Credentials,
    pub llm: LlmMode,
    /// Re-runs of a failing case to detect flakiness.
    pub reruns: u32,
    /// Independent replays of every FAIL before it becomes a defect (`READYHAI_VERIFY_K`, default 2,
    /// at most 5; 0 turns the verifier off).
    pub verify_k: u32,
    pub request_timeout: Duration,
    /// Resolve the requester's egress IP (contacts public IP echo services unless READYHAI_PUBLIC_IP is set).
    pub lookup_requester_ip: bool,
    /// Area worker threads of the lead (`READYHAI_AGENT_WORKERS`, default 4, at most 8; 1 runs the
    /// areas one after another with the same results).
    pub workers: usize,
    /// Where the agent remembers its targets (`<data_dir>/memory`; None = no memory: the run plans
    /// from the profile alone and writes nothing). `READYHAI_AGENT_MEMORY=off` turns it off.
    pub memory_dir: Option<PathBuf>,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            budget: RunBudget::from_env(),
            credentials: Credentials::from_env(),
            llm: LlmMode::Env,
            reruns: 2,
            verify_k: verify::k_from_env(),
            request_timeout: Duration::from_secs(10),
            lookup_requester_ip: true,
            workers: super::lead::workers_from_env(),
            memory_dir: memory::default_dir(),
        }
    }
}

impl RunOptions {
    /// What `readyhai agent --max-steps N` should call.
    pub fn with_max_steps(mut self, n: usize) -> Self {
        self.budget = self.budget.with_max_steps(n);
        self
    }

    pub fn with_workers(mut self, n: usize) -> Self {
        self.workers = n.clamp(1, super::lead::MAX_WORKERS);
        self
    }

    /// Keep the target's memory in `dir` (None: no memory).
    pub fn with_memory_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.memory_dir = dir;
        self
    }
}

fn log(
    steps: &mut Vec<AgentStepLog>,
    agent: &str,
    action: &str,
    details: &str,
    status: &str,
    source: Option<&str>,
) {
    steps.push(AgentStepLog {
        timestamp: now_iso(),
        agent: agent.into(),
        action: action.into(),
        details: details.into(),
        status: status.into(),
        source: source.map(String::from),
    });
}

fn require_http(target: &str) -> Result<()> {
    match reqwest::Url::parse(target) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => Ok(()),
        _ => bail!(
            "target must be an http(s) URL (the agent probes over HTTP only), got '{}'",
            target.chars().take(80).collect::<String>()
        ),
    }
}

/// Resolve the LLM once per run. Err(reason) is logged and the run continues deterministically.
fn resolve_llm(mode: &LlmMode) -> std::result::Result<LlmConfig, String> {
    match mode {
        LlmMode::Off => Err("disabled for this run".into()),
        LlmMode::Env => LlmConfig::connect_from_env(),
        LlmMode::Use(c) => {
            if probe(c) {
                Ok((**c).clone())
            } else {
                Err(format!("LLM {} unreachable", c.describe()))
            }
        }
    }
}

/// The LLM's answer to a real 1-token completion (`/models` answering only says the server is up).
/// Its words go into `llm_status`, e.g. "connected: vllm/m (latency 840 ms)".
fn measure_llm(c: &LlmConfig) -> LatencyReport {
    latency_report(&probe_latency(c))
}

/// A slow endpoint (answers in more than 10 s, or not at all in time) cannot serve long reasoning
/// calls: hold the planner at the High tier (8192 tokens) and say so in the run notes.
fn cap_if_slow(c: &mut LlmConfig, latency: &LatencyReport, notes: &mut Vec<String>) {
    if !latency.slow {
        return;
    }
    let mut note = format!("LLM endpoint is slow ({})", latency.summary);
    if let Some(capped) = c.capped_to_high_tier() {
        note.push_str(&format!(
            "; planner thinking is capped at the High tier ({} tokens) instead of tier '{}' ({} tokens) so its calls fit the timeout",
            capped.thinking_budget_tokens, c.model_tier, c.thinking_budget_tokens
        ));
        *c = capped;
    }
    notes.push(note);
}

/// Move what the LLM layer noted (a call that timed out and was retried smaller, ...) into the run's notes.
fn take_llm_notes(rep: &mut AgentRunReport, llm: &mut Budget) {
    for n in llm.notes.drain(..) {
        if !rep.notes.contains(&n) {
            rep.notes.push(n);
        }
    }
}

// ---------------------------------------------------------------- gate prose (advisory)

const GATE_ROLE: &str = "You are a production-readiness reviewer. You receive facts that deterministic code computed from real HTTP test results. \
Write a short summary for a release manager and give an advisory opinion. Your opinion is advisory: it is recorded separately and never changes the verdict. \
Format: {\"executive_summary\": string, \"gate_verdict\": \"GO\"|\"CONDITIONAL_GO\"|\"NO_GO\", \"overall_readiness\": int, \"value_score\": int, \"authority_score\": int, \"safety_score\": int, \"evidence_score\": int}";

#[derive(Debug, Deserialize)]
struct GateOut {
    #[serde(default)]
    executive_summary: Option<String>,
    #[serde(default)]
    gate_verdict: Option<String>,
    #[serde(default)]
    overall_readiness: Option<i64>,
    #[serde(default)]
    value_score: Option<i64>,
    #[serde(default)]
    authority_score: Option<i64>,
    #[serde(default)]
    safety_score: Option<i64>,
    #[serde(default)]
    evidence_score: Option<i64>,
}

fn llm_gate(
    cfg: &LlmConfig,
    budget: &mut Budget,
    target: &str,
    l: &mut EvidenceLedger,
    defects: &[TriagedDefect],
) -> Result<()> {
    let facts = json!({
        "target": target, "computed_verdict": l.computed_verdict, "overall_readiness": l.overall_readiness, "verdict_basis": l.verdict_basis,
        "pillars": l.pillars.iter().map(|p| json!({"id": p.id, "score": p.score, "status": p.status, "claim": p.claim})).collect::<Vec<_>>(),
        "defects": defects.iter().take(20).map(|d| json!({"id": d.id, "severity": d.severity, "title": d.title, "component": d.component})).collect::<Vec<_>>(),
    });
    let prompt = format!(
        "Computed readiness facts:\n{}\nWrite the summary and your advisory opinion.",
        fence_capped(&facts, 240)
    );
    // a summary of facts already computed: 2048 tokens and no reasoning, whatever tier the planner runs at
    let out: GateOut = ask_typed(
        &cfg.without_thinking(),
        budget,
        &untrusted::system(GATE_ROLE),
        &prompt,
        |o: &GateOut| {
            if let Some(v) = o.gate_verdict.as_deref()
                && !matches!(v, "GO" | "CONDITIONAL_GO" | "NO_GO")
            {
                bail!(
                    "gate_verdict '{}' is not one of GO, CONDITIONAL_GO, NO_GO",
                    v.chars().take(20).collect::<String>()
                );
            }
            if o.gate_verdict.is_none()
                && o.executive_summary
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
            {
                bail!("neither a verdict nor a summary");
            }
            Ok(())
        },
    )?;
    let summary = out
        .executive_summary
        .as_deref()
        .map(|s| clean_output(s, 900))
        .filter(|s| !s.is_empty());
    ledger::apply_llm(
        l,
        out.gate_verdict.as_deref(),
        [
            out.overall_readiness,
            out.value_score,
            out.authority_score,
            out.safety_score,
            out.evidence_score,
        ],
        summary,
    );
    Ok(())
}

// ---------------------------------------------------------------- plan ordering and truncation

/// Order the plan so the cases that matter most are the ones that run, then cut it to `hard_limit`.
/// Returns (kept, dropped); ids are renumbered over kept-then-dropped. The plan is only reordered
/// when something has to give (more cases than `hard_limit` or than the executor's step budget
/// `exec_cap`), so an untruncated plan keeps the planner's order.
pub(crate) fn order_and_trim(
    mut cases: Vec<PlannedCase>,
    hard_limit: Option<usize>,
    exec_cap: usize,
) -> (Vec<PlannedCase>, Vec<PlannedCase>) {
    let cap = hard_limit.unwrap_or(usize::MAX).min(exec_cap);
    if cases.len() <= cap {
        return (cases, vec![]);
    }
    let key = plan_order(any_prioritised(&cases));
    cases.sort_by_key(|c| key(c)); // stable: ties keep the planner's order
    let mut dropped = match hard_limit {
        Some(l) if cases.len() > l => cases.split_off(l),
        _ => vec![],
    };
    for (i, c) in cases.iter_mut().chain(dropped.iter_mut()).enumerate() {
        c.id = format!("TC-{:03}", i + 1);
    }
    (cases, dropped)
}

// ---------------------------------------------------------------- created resources and teardown

/// Record what the run created, from the results themselves: a POST that answered 2xx (or a PUT
/// that answered 201) with an id or a Location header, and every POST step of a stateful chain.
/// Anything created but not identifiable (no id, repeated attempts) goes to `unidentified`.
/// The executor already calls [`record_created`]-style recording on every 2xx creation while it
/// runs (tagged with the case id); what it recorded counts as identified here and duplicates are
/// ignored, so a resource is neither recorded twice nor also reported as unidentified.
pub(crate) fn harvest_created(
    results: &[CaseExecutionResult],
    cases: &[PlannedCase],
    ledger: &CreatedLedger,
) -> Vec<Leftover> {
    let mut unidentified = vec![];
    let ids: std::collections::HashSet<&str> = results.iter().map(|r| r.case_id.as_str()).collect();
    for r in results.iter().filter(|r| r.status != "SKIPPED") {
        // `<id>-B` is the concurrency burst as a sub-case; its first response is one of the burst's
        // requests, not a separate attempt, and the main result carries a copy of its codes
        let is_burst_sub = r.case_id.ends_with("-B")
            && r.evidence_detail
                .as_ref()
                .is_some_and(|d| d.get("burst_of").is_some());
        let role = cases
            .iter()
            .find(|c| c.id == r.case_id)
            .and_then(|c| match auth_for(c) {
                Auth::Role(role) => Some(role),
                _ => None,
            });
        // creations the executor recorded itself for this very result (tagged with its case id)
        let by_executor = ledger.recorded_for_case(&r.case_id);
        let mut identified = if r.stateful_chain.is_none() && !is_burst_sub {
            by_executor
        } else {
            0
        };
        if let (Some(code), Some(d)) = (r.status_code, r.evidence_detail.as_ref())
            && r.stateful_chain.is_none()
            && !is_burst_sub
            && by_executor == 0
            && is_creation(&r.method, code)
        {
            let url = d["request"]["url"].as_str().unwrap_or("");
            let req_path = path_of_url(url).unwrap_or_else(|| r.component.clone());
            let location = d["response"]["headers"]
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|h| {
                    (h[0].as_str().map(str::to_ascii_lowercase).as_deref() == Some("location"))
                        .then(|| h[1].as_str().map(str::to_string))
                        .flatten()
                })
                .and_then(|loc| {
                    reqwest::Url::parse(url)
                        .ok()?
                        .join(&loc)
                        .ok()
                        .filter(|l| {
                            Some(l.origin()) == reqwest::Url::parse(url).ok().map(|u| u.origin())
                        })
                        .map(|l| l.path().to_string())
                });
            let body_id = id_from_body(d["response"]["body_excerpt"].as_str().unwrap_or(""));
            let ok = match (&location, &body_id) {
                (Some(loc), _) => {
                    let last = loc
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    ledger.record_resource(CreatedResource {
                        method: r.method.to_ascii_uppercase(),
                        path: req_path.clone(),
                        id: body_id.clone().unwrap_or(last),
                        delete_path: Some(loc.clone()),
                        role: role.clone(),
                        case_id: Some(r.case_id.clone()),
                    })
                }
                (None, Some(id)) => {
                    ledger.record_with(&r.method, &req_path, id, role.as_deref(), Some(&r.case_id))
                }
                (None, None) => false,
            };
            if ok {
                identified += 1;
            }
        }
        let mut chain_recorded = if r.stateful_chain.is_some() {
            by_executor
        } else {
            0
        };
        for s in r.stateful_chain.iter().flatten() {
            if is_creation(&s.method, s.status_code) {
                if chain_recorded > 0 {
                    chain_recorded -= 1; // the executor recorded this creation with its real id
                    continue;
                }
                let id = s
                    .extracted_values
                    .iter()
                    .filter(|(k, _)| {
                        let k = k.to_ascii_lowercase();
                        k == "id" || k == "_id" || k == "uuid" || k.ends_with("_id")
                    })
                    .min_by_key(|(k, _)| k.len())
                    .map(|(_, v)| v.clone());
                let path = s
                    .resolved_path
                    .split(['?', '#'])
                    .next()
                    .unwrap_or("")
                    .to_string();
                match id {
                    Some(id) if ledger.record_with(&s.method, &path, &id, Some(&s.actor), Some(&r.case_id)) => {
                        identified += 1
                    }
                    Some(_) => {}
                    None => unidentified.push(Leftover {
                        method: s.method.to_ascii_uppercase(),
                        path,
                        id: "(unknown)".into(),
                        reason: "created by a stateful step but the response carried no id, so it cannot be deleted automatically".into(),
                    }),
                }
            }
        }
        // a concurrency burst fires N more requests; only their status codes are stored
        let counted_in_sub = !is_burst_sub && ids.contains(format!("{}-B", r.case_id).as_str());
        if r.stateful_chain.is_none() && !counted_in_sub {
            let burst_created = r
                .concurrency_burst_results
                .iter()
                .flatten()
                .filter(|c| is_creation(&r.method, **c))
                .count();
            // the executor records each burst response under the sub-case's id (`<id>-B`)
            let burst_id = if is_burst_sub {
                r.case_id.clone()
            } else {
                format!("{}-B", r.case_id)
            };
            let burst_recorded = ledger.recorded_for_case(&burst_id);
            for _ in 0..burst_created.saturating_sub(burst_recorded) {
                unidentified.push(Leftover {
                    method: r.method.to_ascii_uppercase(),
                    path: r.component.split(['?', '#']).next().unwrap_or("").to_string(),
                    id: "(unknown)".into(),
                    reason: format!("{}: a concurrency-burst request created a resource and only its status code was stored, so it cannot be deleted automatically", r.case_id),
                });
            }
        }
        // 2xx creations beyond the identified one (flaky re-runs, adaptive mutation probes) left
        // resources whose ids were not stored
        if r.stateful_chain.is_none()
            && !is_burst_sub
            && is_creation(&r.method, r.status_code.unwrap_or(0))
        {
            let created_attempts = r
                .attempts
                .iter()
                .filter(|a| a.status_code.is_some_and(|c| is_creation(&r.method, c)))
                .count();
            let missing = created_attempts.max(1).saturating_sub(identified);
            for _ in 0..missing {
                unidentified.push(Leftover {
                    method: r.method.to_ascii_uppercase(),
                    path: r.component.split(['?', '#']).next().unwrap_or("").to_string(),
                    id: "(unknown)".into(),
                    reason: format!("{} answered 2xx without an id in the stored response (or on a re-run / mutation probe), so the created resource cannot be deleted automatically", r.case_id),
                });
            }
        }
    }
    unidentified
}

const TEARDOWN_MAX: usize = 200;
const TEARDOWN_WALL: Duration = Duration::from_secs(60);

/// Prefix of the leftover reason (and the oracle check code) for a resource that a 2xx DELETE did
/// not remove.
pub(crate) const DELETE_NOT_EFFECTIVE: &str = "delete_not_effective";

/// DELETE what the run created, newest first, on the run's own origin only. `nonprod` must come
/// from the scope check: on anything not confirmed nonprod nothing is sent and every resource is
/// listed as left over. The run budget is deliberately not consulted: cleanup matters most when the
/// budget ran out. A 2xx DELETE is not trusted: a follow-up GET (`exec::confirm_deleted_as`, with
/// the creating role's credential) must find the resource gone (404/410). One that is still there
/// is a leftover with reason `delete_not_effective` (and becomes a defect of that name); a read-back
/// that proves nothing (401/403/5xx/transport error) keeps the DELETE's word and is counted as
/// unconfirmed. Returns what was deleted and what is left.
pub(crate) fn teardown(
    target: &str,
    ledger: &CreatedLedger,
    unidentified: Vec<Leftover>,
    creds: &Credentials,
    nonprod: bool,
    dry_run: bool,
    timeout: Duration,
) -> CleanupReport {
    let resources = ledger.entries();
    let mut rep = CleanupReport {
        created: resources.len() + unidentified.len(),
        resources: resources.clone(),
        leftovers: unidentified,
        ..Default::default()
    };
    let left = |r: &CreatedResource, why: String| Leftover {
        method: r.method.clone(),
        path: r.teardown_path(),
        id: r.id.clone(),
        reason: why,
    };
    if resources.is_empty() {
        rep.skipped = Some(
            if rep.created > 0 {
                "no created resource could be identified for deletion"
            } else if dry_run {
                "dry-run: no state-changing request was sent"
            } else {
                "the run created nothing"
            }
            .into(),
        );
        return rep;
    }
    if dry_run {
        rep.skipped = Some("dry-run".into());
        rep.leftovers.extend(
            resources
                .iter()
                .map(|r| left(r, "dry-run: teardown not attempted".into())),
        );
        return rep;
    }
    if !nonprod {
        rep.skipped =
            Some("target is not confirmed nonprod by the scope file, so no DELETE was sent".into());
        rep.leftovers.extend(
            resources
                .iter()
                .map(|r| left(r, "target not confirmed nonprod: delete it by hand".into())),
        );
        return rep;
    }
    let Some(origin) = reqwest::Url::parse(target)
        .ok()
        .map(|u| u.origin().ascii_serialization())
        .filter(|o| o.starts_with("http"))
    else {
        rep.skipped = Some("target is not an http(s) URL".into());
        rep.leftovers.extend(
            resources
                .iter()
                .map(|r| left(r, "no origin to delete from".into())),
        );
        return rep;
    };
    let client = match reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("ReadyHai-Agent/1.0 teardown")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            rep.skipped = Some(format!("could not build the HTTP client: {e}"));
            rep.leftovers.extend(
                resources
                    .iter()
                    .map(|r| left(r, "teardown not attempted".into())),
            );
            return rep;
        }
    };
    // read-back client: same target, same credential rules as every other request of the run
    let readback = reqwest::Url::parse(target)
        .ok()
        .and_then(|u| Clients::new(timeout, &u).ok());
    let t0 = Instant::now();
    for (n, r) in resources.iter().rev().enumerate() {
        if n >= TEARDOWN_MAX || t0.elapsed() >= TEARDOWN_WALL {
            rep.leftovers.push(left(r, "teardown limit reached".into()));
            continue;
        }
        let url = format!("{origin}{}", r.teardown_path());
        let token = r
            .role
            .as_deref()
            .and_then(|role| creds.token(role))
            .or_else(|| creds.token("admin"))
            .or_else(|| creds.token("user"));
        let mut rq = client.delete(&url);
        if let Some(t) = token {
            rq = rq.bearer_auth(t);
        }
        rep.attempted += 1;
        match rq.send() {
            Ok(resp) => {
                let c = resp.status().as_u16();
                if c == 404 || c == 410 {
                    rep.deleted += 1;
                    rep.confirmed_gone += 1;
                } else if (200..300).contains(&c) {
                    let bearer = token.map(|t| Bearer {
                        header: format!("Bearer {t}"),
                        real: true,
                    });
                    let check = readback
                        .as_ref()
                        .map(|cl| {
                            confirm_deleted_as(cl, target, &r.teardown_path(), bearer.as_ref())
                        })
                        .unwrap_or(DeleteCheck::Unknown);
                    match check {
                        DeleteCheck::Gone => {
                            rep.deleted += 1;
                            rep.confirmed_gone += 1;
                        }
                        DeleteCheck::StillPresent(g) => {
                            rep.still_present += 1;
                            rep.leftovers.push(left(
                                r,
                                format!(
                                    "{DELETE_NOT_EFFECTIVE}: DELETE answered HTTP {c}, but a follow-up GET still answers HTTP {g}: the resource was not removed"
                                ),
                            ));
                        }
                        DeleteCheck::Unknown => {
                            rep.deleted += 1;
                            rep.unconfirmed += 1;
                        }
                    }
                } else {
                    rep.leftovers
                        .push(left(r, format!("DELETE answered HTTP {c}")));
                }
            }
            Err(e) => rep.leftovers.push(left(
                r,
                format!(
                    "DELETE failed: {}",
                    crate::llm::untrusted::clean(&e.to_string(), 160)
                ),
            )),
        }
    }
    rep
}

fn http_codes(s: &str) -> Vec<u16> {
    s.split("HTTP ")
        .skip(1)
        .filter_map(|t| t.get(..3)?.parse().ok())
        .collect()
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// One FAIL result (`CLEANUP-NNN`) per resource a 2xx DELETE did not remove, so the triager turns
/// each into a `delete_not_effective` defect (Medium, quality) with its own evidence file. The
/// request/response pair is the teardown's DELETE and the confirming GET.
pub(crate) fn delete_check_results(
    target: &str,
    cleanup: &CleanupReport,
) -> Vec<CaseExecutionResult> {
    use super::oracle::{OracleCheck, OracleOutcome, Severity, Verdict};
    let origin = reqwest::Url::parse(target)
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_default();
    cleanup
        .leftovers
        .iter()
        .filter(|l| l.reason.starts_with(DELETE_NOT_EFFECTIVE))
        .enumerate()
        .map(|(i, l)| {
            let id = format!("CLEANUP-{:03}", i + 1);
            let made = cleanup
                .resources
                .iter()
                .find(|r| r.teardown_path() == l.path && r.id == l.id);
            let codes = http_codes(&l.reason);
            let (del, get) = (codes.first().copied(), codes.get(1).copied());
            let url = format!("{origin}{}", l.path);
            let auth = made
                .and_then(|r| r.role.as_deref())
                .and_then(|role| curl_auth_arg(&Auth::Role(role.to_string())))
                .map(|a| format!(" {a}"))
                .unwrap_or_default();
            let curl = format!(
                "curl -sS -i -X DELETE{auth} {u} && curl -sS -i{auth} {u}",
                u = shell_quote(&url)
            );
            let title = format!("Teardown: DELETE {} did not remove the resource", l.path);
            let outcome = OracleOutcome {
                verdict: Verdict::Fail,
                checks: vec![OracleCheck {
                    code: DELETE_NOT_EFFECTIVE.into(),
                    verdict: Verdict::Fail,
                    severity: Some(Severity::Medium),
                    detail: l.reason.clone(),
                }],
                warnings: vec![],
                exploratory: false,
            };
            let evidence_file = evidence_rel_path(&id);
            let detail = json!({
                "case_id": id, "title": title, "technique": "state_transition",
                "request": {"method": "DELETE", "url": url, "curl": curl, "created_by": made.and_then(|r| r.case_id.clone()), "auth": made.and_then(|r| r.role.as_ref()).map(|r| format!("role:{r} (token not recorded)")).unwrap_or_else(|| "none".into())},
                "response": {"delete_status": del, "readback_get_status": get, "note": "the resource is still readable after the DELETE"},
                "oracle": serde_json::to_value(&outcome).unwrap_or(Value::Null),
            });
            CaseExecutionResult { blocked_reason: None, redirect_chain: vec![],
                case_id: id,
                title,
                component: l.path.clone(),
                method: "DELETE".into(),
                technique: "state_transition".into(),
                status: "FAIL".into(),
                status_code: get,
                latency_ms: 0,
                reproduction_curl: curl,
                request_payload: None,
                evidence: format!("DELETE {} answered HTTP {}; GET still answers HTTP {}", l.path, del.unwrap_or(0), get.unwrap_or(0)),
                content_type: None,
                is_spa_shell: false,
                failure_reason: Some(l.reason.clone()),
                expected_status: None,
                oracle: Some(outcome),
                flaky: false,
                attempts: vec![],
                evidence_file: Some(evidence_file),
                evidence_detail: Some(detail),
                stateful_chain: None,
                concurrency_burst_results: None,
            }
        })
        .collect()
}

fn target_is_nonprod(target: &str) -> bool {
    match crate::scope::active() {
        Ok(scope) => crate::scope::check(target, scope.as_ref()).unwrap_or(false),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------- run

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

fn ip_fields(
    lookup: bool,
    steps: &mut Vec<AgentStepLog>,
) -> (Option<String>, Option<String>, Option<String>) {
    if !lookup {
        return (None, None, None);
    }
    let ip = crate::network::detect_requester_public_ip();
    log(
        steps,
        "Supervisor",
        "Requester Egress IP Check",
        &format!(
            "Requester outbound IP: {} ({}); {}",
            ip.egress_public_ip, ip.ip_type, ip.allowlist_guidance
        ),
        "completed",
        Some("deterministic"),
    );
    (
        Some(ip.egress_public_ip),
        Some(ip.ip_type),
        Some(ip.allowlist_guidance),
    )
}

fn blank_report(run_id: &str, target: &str, profile: &str, dry_run: bool) -> AgentRunReport {
    AgentRunReport {
        id: run_id.to_string(),
        target: target.to_string(),
        profile: profile.to_string(),
        model: "none".into(),
        provider: "deterministic".into(),
        started_at: now_iso(),
        finished_at: None,
        status: "running".into(),
        steps: vec![],
        discovered_routes: vec![],
        planned_cases: vec![],
        executed_results: vec![],
        triaged_defects: vec![],
        evidence_ledger: None,
        approval_status: Some("pending".into()),
        approved_by: None,
        approval_notes: None,
        approved_at: None,
        error: None,
        thinking: false,
        model_tier: default_model_tier(),
        thinking_budget_tokens: 0,
        app_architecture: None,
        framework: None,
        detected_tech: vec![],
        requester_ip: None,
        requester_ip_type: None,
        allowlist_guidance: None,
        dry_run,
        stage_sources: BTreeMap::new(),
        llm_status: None,
        budget: None,
        notes: vec![],
        change_impact: None,
        agents: None,
        since_last_run: None,
    }
}

/// Persist the run as it stands (status `running`). A failed checkpoint never fails the run.
fn checkpoint(base: &Path, rep: &mut AgentRunReport, budget: &RunBudget, llm: &Budget) {
    let mut usage = budget.usage();
    usage.llm_calls = llm.calls;
    usage.llm_ms = llm.elapsed_ms();
    rep.budget = Some(usage);
    if let Err(e) = checkpoint_agent_run_in(base, rep) {
        eprintln!("readyhai agent: checkpoint of run {} failed: {e}", rep.id);
    }
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    let s = p
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into());
    format!("agent run panicked: {s}")
}

/// Run `stages` over `rep`; on an error or a panic, record the run as `failed` (kept on disk, with
/// the error) and return the error. The run's cancel marker and registry entry are cleaned up.
fn run_guarded(
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

/// The change analysis of a run that has a `repo` and a `diff_base`: the changed files, the spec
/// operations they map to, and (when there is an index) advisory context. It never fails the
/// run: whatever goes wrong is a note and the plan stays what the profile gives. The result is
/// also stored on the report (`change_impact`), coverage filled in after the run.
fn analyze_change(
    req: &AgentRunRequest,
    spec: Option<&super::discover::SpecDoc>,
    rep: &mut AgentRunReport,
) -> Option<change::Analysis> {
    let (repo, base) = match (req.repo.as_deref(), req.diff_base.as_deref()) {
        (None, None) => return None,
        (Some(_), None) | (None, Some(_)) => {
            rep.notes.push(
                "change-aware planning needs both repo and diff_base; the plan is what the profile gives"
                    .into(),
            );
            return None;
        }
        (Some(r), Some(b)) => (r, b),
    };
    let (root, base) = match change::validate_request(repo, Some(base), None) {
        Ok((root, Some(base))) => (root, base),
        Ok((_, None)) => return None,
        Err(e) => {
            rep.notes.push(format!(
                "change-aware planning skipped: {e}; the plan is what the profile gives"
            ));
            return None;
        }
    };
    let mut a = change::analyze(&root, &base, spec);
    if a.impact.status == change::APPLIED {
        match change::retriever_from_env(&root)
            .and_then(|r| change::retrieve_context(&r, &a.impact.operations))
        {
            Ok(notes) => a.impact.context_notes = notes,
            Err(why) => a
                .impact
                .notes
                .push(format!("context retriever skipped: {why}")),
        }
    }
    let i = &a.impact;
    log(
        &mut rep.steps,
        "Discovery",
        "Change Analysis",
        &format!(
            "git diff {}...HEAD: {} changed file(s), {} mapped to {} operation(s) ({}), {} unmapped{}",
            i.diff_base,
            i.changed_files_total,
            i.changed_files_total.saturating_sub(i.unmapped_total),
            i.operations.len(),
            i.status,
            i.unmapped_total,
            if i.status == change::FAILED {
                format!("; {}", i.notes.first().map(String::as_str).unwrap_or(""))
            } else {
                String::new()
            }
        ),
        if i.status == change::FAILED {
            "warning"
        } else {
            "completed"
        },
        Some("deterministic"),
    );
    rep.change_impact = Some(a.impact.clone());
    Some(a)
}

fn agent_stages(
    base: &Path,
    req: &AgentRunRequest,
    rep: &mut AgentRunReport,
    opts: RunOptions,
    nonprod_pin: Option<bool>,
) -> Result<()> {
    let RunOptions {
        mut budget,
        credentials,
        llm,
        reruns,
        verify_k,
        request_timeout,
        lookup_requester_ip,
        workers,
        memory_dir,
    } = opts;
    let mut llm_budget = budget.llm_budget();
    let (ip, ip_type, guidance) = ip_fields(lookup_requester_ip, &mut rep.steps);
    rep.requester_ip = ip;
    rep.requester_ip_type = ip_type;
    rep.allowlist_guidance = guidance;

    // LLM: resolved and probed once; every LLM step is skipped when it is not reachable
    let llm_cfg = match resolve_llm(&llm) {
        Ok(mut c) => {
            let latency = measure_llm(&c);
            if req.thinking {
                c = c.with_thinking(true, &req.model_tier, req.thinking_budget_tokens);
            }
            cap_if_slow(&mut c, &latency, &mut rep.notes);
            if req.thinking {
                let p = call_params(&c);
                let sent = p.anthropic_thinking.is_some() || p.reasoning_effort.is_some();
                log(
                    &mut rep.steps,
                    "Supervisor",
                    "Extended Thinking (CoT)",
                    &format!(
                        "Thinking requested: tier '{}', budget {} tokens (clamped to {}..={}). What {} receives: {}",
                        c.model_tier,
                        c.thinking_budget_tokens,
                        crate::llm::MIN_THINKING_BUDGET,
                        crate::llm::MAX_THINKING_BUDGET,
                        c.describe(),
                        c.thinking_summary()
                    ),
                    if sent { "completed" } else { "warning" },
                    Some("llm"),
                );
            }
            log(
                &mut rep.steps,
                "Supervisor",
                "Model Connectivity",
                &format!("Connected to {}", c.describe()),
                "completed",
                Some("llm"),
            );
            rep.llm_status = Some(format!("connected: {} ({})", c.describe(), latency.summary));
            rep.model = c.model.clone();
            rep.provider = c.provider.id.to_string();
            Some(c)
        }
        Err(why) => {
            log(
                &mut rep.steps,
                "Supervisor",
                "Model Connectivity",
                &format!("{why}; every LLM step is skipped and the deterministic path is used"),
                "warning",
                Some("deterministic"),
            );
            rep.llm_status = Some(format!("unavailable: {why}"));
            None
        }
    };
    rep.thinking = req.thinking;
    rep.model_tier = req.model_tier.clone();
    rep.thinking_budget_tokens = clamp_thinking_budget(req.thinking_budget_tokens);
    if let Some(c) = llm_cfg.as_ref().filter(|_| req.thinking) {
        // what the planner really runs at (a slow endpoint holds it at the High tier)
        rep.model_tier = c.model_tier.clone();
        rep.thinking_budget_tokens = c.thinking_budget_tokens;
    }
    checkpoint(base, rep, &budget, &llm_budget);

    // 1. discovery
    log(
        &mut rep.steps,
        "Discovery",
        "Route Inspection",
        "Fingerprinting the target, crawling same-host links, loading the OpenAPI spec when available",
        "running",
        Some("deterministic"),
    );
    let mut disc = discover(&req.target, req.spec_url.as_deref(), 20, &mut budget);
    // headless XHR capture (standard/deep, SPA, Docker + runner image present; a note otherwise)
    super::discover::run_xhr_discovery(
        &mut disc,
        &req.target,
        &req.profile,
        &base.join(&rep.id),
        &rep.id,
        &mut budget,
        !req.dry_run && nonprod_pin.unwrap_or_else(|| target_is_nonprod(&req.target)),
    );
    log(
        &mut rep.steps,
        "Discovery",
        "Route Inspection",
        &format!(
            "{} ({}); {} route(s){}",
            disc.tech.app_architecture,
            disc.tech.primary_framework,
            disc.routes.len(),
            if disc.spec.is_some() {
                ", OpenAPI spec loaded"
            } else {
                ""
            }
        ),
        "completed",
        Some("deterministic"),
    );
    if disc.routes.is_empty() {
        rep.notes.push("no routes were discovered (target unreachable or empty); only root and sensitive-file probes are planned".into());
    }
    rep.notes.extend(disc.notes.iter().cloned());
    // 1b. what did the code change? (only when the caller gave a checkout and a base ref)
    let change = analyze_change(req, disc.spec.as_ref(), rep);
    let change_ops = change.as_ref().is_some_and(|a| !a.set.is_empty());
    // a changed read of one record (`GET /orders/{id}`) is planned against real ids, even at quick
    let change_needs_ids = change
        .as_ref()
        .is_some_and(|a| a.set.labels().any(|l| l.contains('{')));
    // the ids of records that exist (read-only GETs of the spec's collection endpoints), so the
    // plan reads and validates real ones
    let harvested = disc
        .spec
        .as_ref()
        .filter(|_| plans_from_spec(&req.profile) || change_needs_ids)
        .map(|spec| {
            harvest_ids(
                spec,
                &req.target,
                &credentials,
                request_timeout,
                &mut budget,
            )
        });
    if let Some((ids, notes)) = harvested {
        disc.ids = ids;
        rep.notes.extend(notes);
    }
    rep.stage_sources
        .insert("discovery".into(), "deterministic".into());
    rep.discovered_routes = disc.routes.clone();
    rep.app_architecture = Some(disc.tech.app_architecture.clone());
    rep.framework = Some(disc.tech.primary_framework.clone());
    rep.detected_tech = disc.tech.detected_signals.clone();
    checkpoint(base, rep, &budget, &llm_budget);

    // 1c. what the agent remembers about this target (deterministic: a file, no LLM, no request)
    let today = crate::engine::today();
    let (hints, memory_notes) = recall(memory_dir.as_deref(), &req.target, rep, &today);
    checkpoint(base, rep, &budget, &llm_budget);

    // 2. planner
    log(
        &mut rep.steps,
        "Planner",
        "Test Synthesis",
        "Building the deterministic plan (and asking the LLM for extra cases when available)",
        "running",
        None,
    );
    let planner_llm = llm_cfg.as_ref().filter(|_| !budget.is_cancelled());
    let mut plan = plan_cases_remembered(
        planner_llm.map(|c| (c, &mut llm_budget)),
        &req.target,
        &req.profile,
        &disc,
        req.custom_instructions.as_deref(),
        &credentials,
        seed_from_run_id(&rep.id),
        change.as_ref().map(|a| &a.set),
        hints.as_ref(),
    );
    take_llm_notes(rep, &mut llm_budget);
    // Never plan more than the allowance, and make sure what is cut is not what matters most
    let (limit, limit_why) = {
        let by_request = req.max_steps.filter(|&n| n > 0);
        let by_profile = profile_case_cap(&req.profile);
        match (by_request, by_profile) {
            (Some(a), Some(b)) if b < a => (Some(b), format!("the '{}' profile cap", req.profile)),
            (Some(a), _) => (Some(a), "max_steps".to_string()),
            (None, Some(b)) => (Some(b), format!("the '{}' profile cap", req.profile)),
            (None, None) => (None, String::new()),
        }
    };
    let planned_total = plan.cases.len();
    let (kept, dropped) =
        order_and_trim(std::mem::take(&mut plan.cases), limit, budget.max_steps());
    plan.cases = kept;
    if !dropped.is_empty() {
        let n = dropped.len();
        let l = limit.unwrap_or(plan.cases.len());
        let first: Vec<String> = dropped
            .iter()
            .take(5)
            .map(|c| format!("{} {}", c.method, c.component))
            .collect();
        rep.notes.push(format!(
            "plan truncated: {n} of {planned_total} planned case(s) were dropped to fit {limit_why} = {l}. {} were kept first; the dropped cases are listed as SKIPPED and lower coverage (e.g. {}{})",
            if change_ops {
                "Cases of changed operations, then authorization, stateful and OpenAPI cases"
            } else {
                "Authorization, stateful and OpenAPI cases"
            },
            first.join(", "),
            if n > first.len() { ", ..." } else { "" }
        ));
        budget.note_stopped(format!(
            "plan truncated to {l} case(s) by {limit_why}: {n} of {planned_total} not run"
        ));
    }
    log(
        &mut rep.steps,
        "Planner",
        "Test Synthesis",
        &format!(
            "{} planned case(s) ({}), {} from the LLM{}",
            planned_total,
            plan.source,
            plan.llm_cases,
            if dropped.is_empty() {
                String::new()
            } else {
                format!("; {} dropped by {limit_why}", dropped.len())
            }
        ),
        if dropped.is_empty() {
            "completed"
        } else {
            "warning"
        },
        Some(if plan.llm_cases > 0 {
            "llm+deterministic"
        } else {
            "deterministic"
        }),
    );
    rep.notes.extend(plan.notes.iter().cloned());
    rep.stage_sources
        .insert("planner".into(), plan.source.clone());
    rep.planned_cases = plan.cases.iter().chain(dropped.iter()).cloned().collect();
    checkpoint(base, rep, &budget, &llm_budget);

    // 3. explorer
    log(
        &mut rep.steps,
        "Explorer",
        "Execution & Probing",
        "Sending real HTTP requests; failures are re-run to detect flakiness",
        "running",
        Some("deterministic"),
    );
    let exec_opts = ExecOptions {
        dry_run: req.dry_run,
        is_spa_target: disc.tech.is_spa,
        credentials: credentials.clone(),
        reruns,
        timeout: request_timeout,
    };
    let created = CreatedLedger::new();
    // the lead splits the plan by area and runs the area workers; its progress is checkpointed
    // into report.json while the workers go, so a status poll sees every area
    let mut executed = {
        let live = Mutex::new(rep.clone());
        let observe = |a: &AgentsReport| {
            let mut snap = live.lock().unwrap_or_else(|e| e.into_inner());
            snap.agents = Some(a.clone());
            let _ = checkpoint_agent_run_in(base, &snap);
        };
        let cfg = lead::LeadConfig {
            target: &req.target,
            opts: &exec_opts,
            workers,
            created: &created,
            llm_calls_left: llm_budget.remaining_calls(),
            on_progress: Some(&observe),
        };
        let out = lead::run(&cfg, &plan.cases, &mut budget);
        log(
            &mut rep.steps,
            "Lead",
            "Area Workers",
            &format!(
                "{} worker(s), {} wave(s): {}",
                out.agents.workers,
                out.agents.waves,
                lead::summary_lines(&out.agents)
            ),
            if out.agents.areas.iter().any(|a| a.error.is_some()) {
                "warning"
            } else {
                "completed"
            },
            Some("deterministic"),
        );
        if !out.follow_ups.is_empty() {
            log(
                &mut rep.steps,
                "Lead",
                "Wave 2",
                &format!(
                    "{} follow-up case(s) planned by rule: {}",
                    out.follow_ups.len(),
                    out.agents
                        .wave2
                        .iter()
                        .filter(|w| w.rule != lead::RULE_RESUME)
                        .map(|w| format!("{} <- {} ({})", w.case_id, w.origin, w.rule))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                "completed",
                Some("deterministic"),
            );
        }
        // follow-up cases are part of the plan from here on (verification replays them by id)
        plan.cases.extend(out.follow_ups.iter().cloned());
        rep.planned_cases.extend(out.follow_ups.iter().cloned());
        rep.agents = Some(out.agents);
        out.results
    };
    let drop_reason = format!(
        "dropped: the plan was truncated to {} case(s) by {limit_why}; not sent",
        limit.unwrap_or(0)
    );
    executed.extend(
        dropped
            .iter()
            .map(|c| CaseExecutionResult::not_run(c, drop_reason.clone())),
    );
    let n = |s: &str| executed.iter().filter(|r| r.status == s).count();
    let mutations_count = executed
        .iter()
        .filter_map(|r| r.evidence_detail.as_ref())
        .filter(|d| !d.get("adaptive_mutation").unwrap_or(&Value::Null).is_null())
        .count();
    let penetrated_count = executed
        .iter()
        .filter_map(|r| r.evidence_detail.as_ref())
        .filter_map(|d| d.get("adaptive_mutation"))
        .filter(|m| {
            m.get("penetrated_validation")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    if mutations_count > 0 {
        log(
            &mut rep.steps,
            "Explorer",
            "Adaptive Schema Mutation",
            &format!(
                "Triggered {mutations_count} adaptive mutation probe(s) from schema feedback; {penetrated_count} penetrated validation filters"
            ),
            "completed",
            Some("deterministic"),
        );
    }
    log(
        &mut rep.steps,
        "Explorer",
        "Execution & Probing",
        &format!(
            "{} PASS, {} FAIL, {} WARN, {} INCONCLUSIVE, {} BLOCKED, {} SKIPPED",
            n("PASS"),
            n("FAIL"),
            n("WARN"),
            n("INCONCLUSIVE"),
            n("BLOCKED"),
            n("SKIPPED")
        ),
        if n("BLOCKED") > 0 {
            "warning"
        } else {
            "completed"
        },
        Some("deterministic"),
    );
    if let Some(stop) = budget.stopped() {
        log(
            &mut rep.steps,
            "Explorer",
            "Budget",
            stop,
            "warning",
            Some("deterministic"),
        );
        rep.notes.push(format!("run budget: {stop}"));
    }
    // A plain case whose role has no token is still sent (without Authorization); a stateful chain
    // needs the token of every actor and is SKIPPED, nothing sent, when one is missing.
    let is_chain = |c: &PlannedCase| c.stateful_steps.as_ref().is_some_and(|s| !s.is_empty());
    let roles_missing: Vec<String> = {
        let mut r: Vec<String> = plan
            .cases
            .iter()
            .filter(|c| !is_chain(c))
            .filter_map(|c| match auth_for(c) {
                Auth::Role(r) if !credentials.has_role(&r) => Some(r),
                _ => None,
            })
            .collect();
        r.sort();
        r.dedup();
        r
    };
    for r in roles_missing {
        rep.notes.push(format!("no credential for role '{r}': requests for it were sent without Authorization (set {})", Credentials::env_var(&r)));
    }
    for c in plan.cases.iter().filter(|c| is_chain(c)) {
        if let Some(steps) = &c.stateful_steps
            && let Err(why) = super::stateful::preflight(steps, &credentials)
            && why.contains("missing credential")
        {
            rep.notes.push(format!(
                "{}: stateful chain skipped, nothing was sent: {why}",
                c.id
            ));
        }
    }
    rep.executed_results = executed;
    checkpoint(base, rep, &budget, &llm_budget);

    // 3a. verifier: replay every FAIL independently, so only what reproduces reaches triage. Replays
    // are charged to the run budget; what a replay creates lands on the same ledger as the rest
    // and is torn down below.
    // failures of cases that were flaky in earlier runs get the maximum number of replays
    let raise_k = hints
        .as_ref()
        .map(|h| h.flaky_case_ids(&plan.cases))
        .unwrap_or_default();
    let vopts = VerifyOptions {
        k: verify_k,
        raise_k: &raise_k,
        dry_run: req.dry_run,
        is_spa_target: disc.tech.is_spa,
        credentials: &credentials,
        timeout: request_timeout,
    };
    let verified = {
        let _scope = created.install();
        verify::verify_failures(
            &mut rep.executed_results,
            &plan.cases,
            &req.target,
            &vopts,
            &mut budget,
        )
    };
    {
        let v = &verified.summary;
        let (text, status) = if v.k == 0 {
            (
                "verification is off (READYHAI_VERIFY_K=0): failures were not replayed".to_string(),
                "completed",
            )
        } else if v.candidates == 0 {
            ("no FAIL to verify".to_string(), "completed")
        } else {
            (
                format!(
                    "{} FAIL(s) replayed up to {}x with fresh credentials and the same oracle: {} confirmed, {} flaky, {} not reproduced (now INCONCLUSIVE, not defects), {} unverified; pass^{} {}; {} replay request(s){}",
                    v.candidates,
                    v.k,
                    v.confirmed,
                    v.flaky,
                    v.not_reproduced,
                    v.unverified,
                    v.k,
                    v.pass_k_text(),
                    v.replay_requests,
                    v.stopped
                        .as_ref()
                        .map(|s| format!("; stopped: {s}"))
                        .unwrap_or_default()
                ),
                if v.unverified > 0 || v.stopped.is_some() {
                    "warning"
                } else {
                    "completed"
                },
            )
        };
        log(
            &mut rep.steps,
            "Verifier",
            "Independent Replay",
            &text,
            status,
            Some("deterministic"),
        );
        if v.k > 0 {
            for r in v
                .records
                .iter()
                .filter(|r| r.verdict == super::types::VerifyVerdict::NotReproduced)
                .take(10)
            {
                rep.notes.push(format!(
                    "verification: {} {} {} failed on the original run but 0 of {} independent replay(s) reproduced it: reported as INCONCLUSIVE, not a defect",
                    r.case_id, r.method, r.component, r.k
                ));
            }
            for r in v
                .records
                .iter()
                .filter(|r| r.verdict == super::types::VerifyVerdict::Unverified)
                .take(10)
            {
                rep.notes.push(format!(
                    "verification: {} {} {} was not verified{}; it stays FAIL",
                    r.case_id,
                    r.method,
                    r.component,
                    r.note
                        .as_ref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                ));
            }
            if let Some(s) = &v.stopped {
                rep.notes.push(format!("verification stopped early: {s}"));
            }
        }
        let raised = v.records.iter().filter(|r| r.k > v.k).count();
        if raised > 0 {
            rep.notes.push(format!(
                "agent memory: {raised} failed case(s) were flaky in earlier runs and were replayed {} times instead of {}",
                super::verify::MAX_K,
                v.k
            ));
        }
        rep.stage_sources.insert(
            "verifier".into(),
            if v.k == 0 {
                "off".to_string()
            } else {
                format!("deterministic, k={}", v.k)
            },
        );
    }
    checkpoint(base, rep, &budget, &llm_budget);

    // 3b. cleanup: delete what the run created (nonprod only), confirm it is gone, report what is left
    let mut unidentified = harvest_created(&rep.executed_results, &plan.cases, &created);
    unidentified.extend(verified.unidentified.iter().cloned());
    let nonprod = nonprod_pin.unwrap_or_else(|| target_is_nonprod(&req.target));
    let cleanup = teardown(
        &req.target,
        &created,
        unidentified,
        &credentials,
        nonprod,
        req.dry_run,
        request_timeout,
    );
    if cleanup.created > 0
        || cleanup.skipped.as_deref().is_some_and(|s| {
            !s.starts_with("the run created nothing") && !s.starts_with("dry-run: no state")
        })
    {
        log(
            &mut rep.steps,
            "Cleanup",
            "Teardown",
            &format!(
                "{}{}",
                cleanup.summary(),
                if cleanup.leftovers.is_empty() {
                    String::new()
                } else {
                    format!(
                        ". Left over: {}",
                        cleanup
                            .leftovers
                            .iter()
                            .take(10)
                            .map(|l| format!("{} {} ({})", l.method, l.path, l.reason))
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                }
            ),
            if cleanup.leftovers.is_empty() {
                "completed"
            } else {
                "warning"
            },
            Some("deterministic"),
        );
        if !cleanup.leftovers.is_empty() {
            rep.notes.push(format!(
                "cleanup: {} resource(s) created by this run were NOT removed from {} (see cleanup.json): {}",
                cleanup.leftovers.len(),
                req.target,
                cleanup
                    .leftovers
                    .iter()
                    .take(10)
                    .map(|l| format!("{} {} [{}]", l.method, l.path, l.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        } else {
            rep.notes.push(format!("cleanup: {}", cleanup.summary()));
        }
    }
    rep.stage_sources.insert(
        "cleanup".into(),
        match (&cleanup.skipped, cleanup.created) {
            (Some(_), 0) => "not needed".to_string(),
            (Some(why), _) => format!("skipped: {why}"),
            (None, _) => format!("deleted {} of {}", cleanup.deleted, cleanup.created),
        },
    );
    if cleanup.created > 0 {
        let _ = save_cleanup_in(base, &rep.id, &cleanup);
    }
    // a DELETE that answered 2xx while the resource stayed is a defect, not a clean teardown
    let not_deleted = delete_check_results(&req.target, &cleanup);
    if !not_deleted.is_empty() {
        log(
            &mut rep.steps,
            "Cleanup",
            "Delete Verification",
            &format!(
                "{} resource(s) were still present after a 2xx DELETE (follow-up GET): reported as defects",
                not_deleted.len()
            ),
            "warning",
            Some("deterministic"),
        );
        rep.executed_results.extend(not_deleted);
    }

    // how the changed operations were covered, from the final statuses
    if let (Some(a), Some(ci)) = (change.as_ref(), rep.change_impact.as_mut()) {
        let labels: Vec<String> = a.set.labels().cloned().collect();
        ci.coverage = change::coverage(&labels, &rep.planned_cases, &rep.executed_results);
        let (sent, planned) = change::coverage_totals(&ci.coverage);
        log(
            &mut rep.steps,
            "Planner",
            "Change Impact",
            &format!(
                "{} changed operation(s): {sent} of {planned} planned case(s) sent",
                labels.len()
            ),
            if sent < planned {
                "warning"
            } else {
                "completed"
            },
            Some("deterministic"),
        );
    }

    // 4. triager: deterministic defects, LLM prose only
    log(
        &mut rep.steps,
        "Triager",
        "Root Cause Analysis",
        "Deriving defects from failed assertions",
        "running",
        Some("deterministic"),
    );
    let mut defects = derive_defects_verified(&rep.executed_results, Some(&verified.summary));
    let mut triage_src = "deterministic".to_string();
    if let (Some(cfg), false) = (
        llm_cfg.as_ref().filter(|_| !budget.is_cancelled()),
        defects.is_empty(),
    ) {
        // short prose over defects found already: 2048 tokens and no reasoning, whatever the planner's tier
        let light = cfg.without_thinking();
        match add_llm_notes(&light, &mut llm_budget, &mut defects, &rep.executed_results) {
            Ok(k) if k > 0 => triage_src = "deterministic+llm-notes".into(),
            Ok(_) => rep.notes.push("LLM triage notes: none usable".into()),
            Err(e) => rep.notes.push(format!("LLM triage notes skipped: {e}")),
        }
        take_llm_notes(rep, &mut llm_budget);
    }
    let failed = rep
        .executed_results
        .iter()
        .filter(|r| r.status == "FAIL")
        .count();
    log(
        &mut rep.steps,
        "Triager",
        "Root Cause Analysis",
        &format!(
            "{} defect(s) cover {} failed case(s)",
            defects.len(),
            failed
        ),
        "completed",
        Some(if triage_src == "deterministic" {
            "deterministic"
        } else {
            "llm+deterministic"
        }),
    );
    rep.stage_sources.insert("triage".into(), triage_src);
    rep.triaged_defects = defects;
    // 4b. memory: fold this run into what the agent knew; an unexpired acceptance of a known
    // defect is applied here, so the ledger below does not count it as blocking
    let mut remembered = remember(memory_dir.as_deref(), req, rep, &cleanup, &today);
    // what each area ended as, after verification and triage changed some statuses
    if let Some(a) = rep.agents.as_mut() {
        lead::recount(a, &rep.executed_results, &rep.triaged_defects);
    }
    checkpoint(base, rep, &budget, &llm_budget);

    // 5. readiness gate: the verdict is the computed one; the LLM's opinion is recorded beside it, advisory only
    log(
        &mut rep.steps,
        "ReadinessGate",
        "Evidence Ledger",
        "Computing the technique-coverage matrix, pillars and verdict",
        "running",
        Some("deterministic"),
    );
    let mut led = ledger::compute(&LedgerInput {
        results: &rep.executed_results,
        defects: &rep.triaged_defects,
        dry_run: req.dry_run,
        budget_stop: budget.stopped(),
    });
    ledger::attach_verification(&mut led, verified.summary.clone(), &rep.triaged_defects);
    let mut gate_src = "computed".to_string();
    if let Some(cfg) = llm_cfg.as_ref().filter(|_| !budget.is_cancelled()) {
        match llm_gate(
            cfg,
            &mut llm_budget,
            &req.target,
            &mut led,
            &rep.triaged_defects,
        ) {
            Ok(()) => gate_src = "computed+llm-advisory".into(),
            Err(e) => rep.notes.push(format!("LLM gate advisory skipped: {e}")),
        }
        take_llm_notes(rep, &mut llm_budget);
    }
    log(
        &mut rep.steps,
        "ReadinessGate",
        "Evidence Ledger",
        &format!("Gate verdict {} ({})", led.gate_verdict, led.verdict_basis),
        "completed",
        Some(if gate_src == "computed" {
            "deterministic"
        } else {
            "llm+deterministic"
        }),
    );
    rep.stage_sources.insert("gate".into(), gate_src);
    let gate_verdict = led.gate_verdict.clone();
    rep.evidence_ledger = Some(led);

    budget.sync_llm(&llm_budget);
    rep.budget = Some(budget.usage());
    let cancelled = budget.is_cancelled();
    rep.status = if cancelled {
        "cancelled".into()
    } else {
        "completed".into()
    };
    rep.finished_at = Some(now_iso());
    // a cancelled run did not test everything it planned: it must not mark a defect fixed
    rep.since_last_run = remembered
        .take()
        .map(|r| r.finish(&gate_verdict, !cancelled, memory_notes));
    if let Some(s) = &rep.since_last_run {
        log(
            &mut rep.steps,
            "Memory",
            "Since Last Run",
            &s.summary_line(),
            "completed",
            Some("deterministic"),
        );
        let fresh: Vec<String> = s
            .notes
            .iter()
            .filter(|n| !rep.notes.contains(*n))
            .cloned()
            .collect();
        rep.notes.extend(fresh);
    }
    save_agent_run_in(base, rep)?;
    Ok(())
}

/// The planner's view of the target's memory, plus what the report must say about it (a file that
/// was set aside as corrupt). Never fails: no memory, an unreadable file or a first run all plan
/// from the profile alone.
fn recall(
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
struct Remembered {
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
    fn finish(self, verdict: &str, commit: bool, mut notes: Vec<String>) -> SinceLastRun {
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
fn remember(
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

/// Discovery + planning only (no case is executed). The ledger says so instead of inventing scores.
pub fn run_discovery_scan(target: &str, spec_url: Option<&str>) -> Result<AgentRunReport> {
    run_discovery_in(
        &agent_runs_dir(),
        target,
        spec_url,
        RunOptions::default(),
        &crate::engine::new_run_id(),
    )
}

pub(crate) fn run_discovery_in(
    base: &Path,
    target: &str,
    spec_url: Option<&str>,
    mut opts: RunOptions,
    run_id: &str,
) -> Result<AgentRunReport> {
    if !crate::engine::valid_run_id(run_id) {
        bail!("invalid run id");
    }
    require_http(target)?;
    let mut rep = blank_report(run_id, target, "discovery-scan", false);
    rep.approval_status = Some("scanned".into());
    rep.model_tier = default_model_tier();
    let marker = base.join(run_id).join("CANCEL");
    let token = opts.budget.cancel_token().clone().with_file(marker.clone());
    opts.budget = opts.budget.clone().with_cancel(token.clone());
    let registration = (register_run(run_id, &token), marker);
    log(
        &mut rep.steps,
        "Supervisor",
        "Session Init",
        &format!("URL discovery and attack-surface scan for {target}"),
        "running",
        None,
    );
    {
        let mut r = rep.clone();
        r.budget = Some(opts.budget.usage());
        checkpoint_agent_run_in(base, &r)?;
    }
    run_guarded(base, rep, registration, |rep| {
        let RunOptions {
            mut budget,
            credentials,
            llm,
            lookup_requester_ip,
            ..
        } = opts;
        let mut llm_budget = budget.llm_budget();
        let (ip, ip_type, guidance) = ip_fields(lookup_requester_ip, &mut rep.steps);
        rep.requester_ip = ip;
        rep.requester_ip_type = ip_type;
        rep.allowlist_guidance = guidance;
        let llm_cfg = match resolve_llm(&llm) {
            Ok(c) => {
                let latency = measure_llm(&c);
                log(
                    &mut rep.steps,
                    "Supervisor",
                    "Model Connectivity",
                    &format!("Connected to {}", c.describe()),
                    "completed",
                    Some("llm"),
                );
                rep.llm_status = Some(format!("connected: {} ({})", c.describe(), latency.summary));
                rep.model = c.model.clone();
                rep.provider = c.provider.id.to_string();
                Some(c)
            }
            Err(why) => {
                log(
                    &mut rep.steps,
                    "Supervisor",
                    "Model Connectivity",
                    &format!("{why}; deterministic planning"),
                    "warning",
                    Some("deterministic"),
                );
                rep.llm_status = Some(format!("unavailable: {why}"));
                None
            }
        };
        let disc = discover(target, spec_url, 20, &mut budget);
        log(
            &mut rep.steps,
            "Discovery",
            "Route Inspection",
            &format!(
                "{} ({}); {} route(s)",
                disc.tech.app_architecture,
                disc.tech.primary_framework,
                disc.routes.len()
            ),
            "completed",
            Some("deterministic"),
        );
        rep.notes.extend(disc.notes.iter().cloned());
        rep.discovered_routes = disc.routes.clone();
        rep.app_architecture = Some(disc.tech.app_architecture.clone());
        rep.framework = Some(disc.tech.primary_framework.clone());
        rep.detected_tech = disc.tech.detected_signals.clone();
        checkpoint(base, rep, &budget, &llm_budget);
        let plan = plan_cases_seeded(
            llm_cfg
                .as_ref()
                .filter(|_| !budget.is_cancelled())
                .map(|c| (c, &mut llm_budget)),
            target,
            "discovery-scan",
            &disc,
            None,
            &credentials,
            seed_from_run_id(run_id),
        );
        log(
            &mut rep.steps,
            "Planner",
            "Test Synthesis",
            &format!(
                "{} planned scenario(s) ({}), none executed",
                plan.cases.len(),
                plan.source
            ),
            "completed",
            Some(if plan.llm_cases > 0 {
                "llm+deterministic"
            } else {
                "deterministic"
            }),
        );
        rep.notes.extend(plan.notes.iter().cloned());
        take_llm_notes(rep, &mut llm_budget);
        rep.stage_sources
            .insert("discovery".into(), "deterministic".into());
        rep.stage_sources
            .insert("planner".into(), plan.source.clone());

        let checklist = vec![
            ExitCheckItem {
                criterion: "Attack surface discovered".into(),
                met: !disc.routes.is_empty(),
                details: format!(
                    "{} route(s), {} ({})",
                    disc.routes.len(),
                    disc.tech.app_architecture,
                    disc.tech.primary_framework
                ),
                case_ids: vec![],
                evidence_files: vec![],
            },
            ExitCheckItem {
                criterion: "Test scenarios synthesized".into(),
                met: !plan.cases.is_empty(),
                details: format!("{} planned scenario(s)", plan.cases.len()),
                case_ids: plan.cases.iter().map(|c| c.id.clone()).collect(),
                evidence_files: vec![],
            },
        ];
        rep.evidence_ledger = Some(ledger::not_evaluated(
            "SCANNED",
            format!(
                "Discovery only: {} route(s) found, {} scenario(s) planned. No test was executed, so nothing is scored.",
                disc.routes.len(),
                plan.cases.len()
            ),
            checklist,
        ));
        rep.planned_cases = plan.cases;
        budget.sync_llm(&llm_budget);
        rep.budget = Some(budget.usage());
        rep.status = if budget.is_cancelled() {
            "cancelled".into()
        } else {
            "completed".into()
        };
        rep.finished_at = Some(now_iso());
        save_agent_run_in(base, rep)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::store::{checkpoint_status, load_cleanup_in};
    use crate::agent::types::fixtures::{planned, result};
    use crate::llm::mock;
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    // ------------------------------------------------------------ fixture server

    /// (method, path, authorization)
    type Seen = (String, String, Option<String>);

    struct Srv {
        base: String,
        log: Arc<Mutex<Vec<Seen>>>,
        /// Orders that exist right now (created by POST, removed by DELETE).
        orders: Arc<Mutex<BTreeSet<u64>>>,
        created_total: Arc<AtomicU64>,
    }

    impl Srv {
        fn seen(&self, method: &str) -> Vec<Seen> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.0 == method)
                .cloned()
                .collect()
        }
    }

    /// POST /orders (needs `Bearer tok-user`) creates `{"id": N}`; DELETE /orders/N removes it.
    /// `delay_ms` slows every answer; `delete_status` forces the DELETE answer.
    fn start_srv(delay_ms: u64, delete_status: Option<u16>) -> Srv {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let orders: Arc<Mutex<BTreeSet<u64>>> = Arc::default();
        let next = Arc::new(AtomicU64::new(100));
        let created_total = Arc::new(AtomicU64::new(0));
        let (lg, od, ct) = (log.clone(), orders.clone(), created_total.clone());
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (lg, od, ct, next) = (lg.clone(), od.clone(), ct.clone(), next.clone());
                std::thread::spawn(move || {
                    let mut s = s;
                    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let head_end = loop {
                        let n = s.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let mut first = head.lines().next().unwrap_or("").split_whitespace();
                    let (method, target) = (
                        first.next().unwrap_or("").to_string(),
                        first.next().unwrap_or("/").to_string(),
                    );
                    let path = target.split('?').next().unwrap_or("/").to_string();
                    let auth = head.lines().find_map(|l| {
                        l.to_ascii_lowercase()
                            .starts_with("authorization:")
                            .then(|| l["authorization:".len()..].trim().to_string())
                    });
                    let clen = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + clen {
                        let n = s.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
                    lg.lock()
                        .unwrap()
                        .push((method.clone(), path.clone(), auth.clone()));
                    if delay_ms > 0 {
                        std::thread::sleep(Duration::from_millis(delay_ms));
                    }
                    let authed = auth.as_deref() == Some("Bearer tok-user");
                    let (code, ctype, rbody): (u16, &str, String) = match (method.as_str(), path.as_str()) {
                        ("GET", "/") => (200, "text/html", "<html><head><title>fixture</title></head><body><a href=\"/about\">a</a></body></html>".into()),
                        ("GET", "/about") => (200, "text/html", "<html><head><title>About</title></head></html>".into()),
                        ("GET", "/openapi.json") => (200, "application/json", include_str!("../../tests/fixtures/qa-api/openapi.json").to_string()),
                        ("POST", "/orders") if !authed => (401, "application/json", "{\"error\":\"unauthorized\"}".into()),
                        ("POST", "/orders") => match serde_json::from_str::<Value>(&body) {
                            Ok(v) if v.is_object() => {
                                let id = next.fetch_add(1, Ordering::SeqCst);
                                od.lock().unwrap().insert(id);
                                ct.fetch_add(1, Ordering::SeqCst);
                                (201, "application/json", format!("{{\"id\": {id}}}"))
                            }
                            _ => (400, "application/json", "{\"error\":\"invalid json\"}".into()),
                        },
                        ("GET", p) if p.starts_with("/orders/") => {
                            let id = p["/orders/".len()..].parse::<u64>().unwrap_or(0);
                            if !authed {
                                (401, "application/json", "{}".into())
                            } else if od.lock().unwrap().contains(&id) {
                                (200, "application/json", format!("{{\"id\": {id}}}"))
                            } else {
                                (404, "application/json", "{}".into())
                            }
                        }
                        ("DELETE", p) if p.starts_with("/orders/") => {
                            let id = p["/orders/".len()..].parse::<u64>().unwrap_or(0);
                            if !authed {
                                (401, "application/json", "{}".into())
                            } else if let Some(c) = delete_status {
                                (c, "application/json", "{}".into())
                            } else if od.lock().unwrap().remove(&id) {
                                (204, "application/json", String::new())
                            } else {
                                (404, "application/json", "{}".into())
                            }
                        }
                        _ => (404, "application/json", "{\"error\":\"no such route\"}".into()),
                    };
                    let _ = write!(
                        s,
                        "HTTP/1.1 {code} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{rbody}",
                        rbody.len()
                    );
                });
            }
        });
        Srv {
            base,
            log,
            orders,
            created_total,
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rh-pipe-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn opts() -> RunOptions {
        RunOptions {
            budget: RunBudget::new(80, 800, Duration::from_secs(120), 0.0),
            credentials: Credentials::none().with("user", "tok-user"),
            llm: LlmMode::Off,
            reruns: 0,
            verify_k: 0,
            request_timeout: Duration::from_secs(5),
            lookup_requester_ip: false,
            workers: 4,
            memory_dir: None,
        }
    }

    fn req(target: &str, dry_run: bool) -> AgentRunRequest {
        AgentRunRequest {
            target: target.into(),
            profile: "standard".into(),
            spec_url: Some(format!("{target}/openapi.json")),
            custom_instructions: None,
            max_steps: None,
            dry_run,
            thinking: true,
            model_tier: "high".into(),
            thinking_budget_tokens: 8192,
            repo: None,
            diff_base: None,
        }
    }

    fn post_result(id: &str, comp: &str, code: u16, detail: Value) -> CaseExecutionResult {
        let mut r = result(id, "boundary", "PASS");
        r.method = "POST".into();
        r.component = comp.into();
        r.status_code = Some(code);
        r.evidence_detail = Some(detail);
        r
    }

    fn creds() -> Credentials {
        Credentials::none()
            .with("user", "tok-user")
            .with("alice", "tok-alice")
    }

    // ------------------------------------------------------------ memory: the end-of-run update

    #[test]
    fn a_run_folds_itself_in_again_when_the_memory_changed_while_it_was_going() {
        use crate::agent::memory::{DefectStatus, KnownDefect, Memory};
        let dir = tmp("mem-race").join("memory");
        let target = "http://127.0.0.1:9";
        let key = memory::target_key(target);
        let now = crate::engine::now();
        let mut m0 = Memory::fresh(&key, target, &now);
        memory::write_memory(&dir, &mut m0, &now).unwrap();
        // the run reads the memory when its gate stage starts ...
        let mut rep = crate::agent::types::fixtures::report("run-race");
        rep.target = target.into();
        let rq = req(target, false);
        let r = remember(
            Some(&dir),
            &rq,
            &mut rep,
            &CleanupReport::default(),
            "2026-03-02",
        )
        .unwrap();
        // ... and while it finishes, an operator-side writer adds a known defect
        let mut m1 = memory::read_strict(&dir, &key).unwrap().unwrap();
        let fp = memory::fingerprint("authz", "/admin");
        m1.defects.insert(
            fp.clone(),
            KnownDefect {
                rule: "authz".into(),
                endpoint: "/admin".into(),
                methods: vec!["GET".into()],
                technique: "authz".into(),
                severity: "critical".into(),
                first_seen: "2026-03-01".into(),
                last_seen: "2026-03-01".into(),
                fixed_at: None,
                status: DefectStatus::Open,
                runs_seen: 1,
                accepted: None,
                repro: vec!["authz|GET|/admin|anon".into()],
            },
        );
        memory::write_memory(&dir, &mut m1, &now).unwrap();
        let since = r.finish("GO", true, vec![]);
        assert!(since.committed, "{:?}", since.notes);
        assert!(
            since
                .notes
                .iter()
                .any(|n| n.contains("changed while the run was going")),
            "{:?}",
            since.notes
        );
        // the other writer's defect was neither lost nor called fixed (the run never re-tested it)
        assert!(
            since.not_retested.iter().any(|l| l.fingerprint == fp),
            "{since:?}"
        );
        let after = memory::read_strict(&dir, &key).unwrap().unwrap();
        assert!(after.defects.contains_key(&fp));
        assert_eq!(after.runs.len(), 1);
        assert_eq!(after.runs[0].verdict, "GO");
        // nothing changed in between: the run keeps what it computed, and a cancelled run writes nothing
        let mut rep2 = crate::agent::types::fixtures::report("run-race-2");
        rep2.target = target.into();
        let r2 = remember(
            Some(&dir),
            &rq,
            &mut rep2,
            &CleanupReport::default(),
            "2026-03-03",
        )
        .unwrap();
        let s2 = r2.finish("NO_GO", false, vec![]);
        assert!(!s2.committed && s2.notes.iter().any(|n| n.contains("cancelled")));
        assert_eq!(
            memory::read_strict(&dir, &key).unwrap().unwrap().runs.len(),
            1
        );
        let r3 = remember(
            Some(&dir),
            &rq,
            &mut rep2,
            &CleanupReport::default(),
            "2026-03-03",
        )
        .unwrap();
        let s3 = r3.finish("NO_GO", true, vec![]);
        assert!(
            s3.committed && !s3.notes.iter().any(|n| n.contains("changed while")),
            "{:?}",
            s3.notes
        );
        assert_eq!(
            memory::read_strict(&dir, &key).unwrap().unwrap().runs.len(),
            2
        );
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    // ------------------------------------------------------------ plan truncation

    #[test]
    fn order_and_trim_drops_generic_probes_first_and_renumbers() {
        let mut cases: Vec<PlannedCase> = (0..10)
            .map(|i| {
                planned(
                    &format!("TC-{:03}", i + 1),
                    "boundary",
                    "GET",
                    &format!("/g{i}"),
                )
            })
            .collect();
        let mut openapi = planned("TC-011", "boundary", "POST", "/orders");
        openapi.source = Some("openapi".into());
        let mut stateful = planned("TC-012", "state_transition", "POST", "/items");
        stateful.concurrency_burst = Some(5);
        cases.extend([
            openapi,
            stateful,
            planned("TC-013", "authz", "GET", "/admin"),
            planned("TC-014", "authz", "GET", "/admin/stats"),
        ]);

        let (kept, dropped) = order_and_trim(cases.clone(), Some(4), 60);
        let comps: BTreeSet<&str> = kept.iter().map(|c| c.component.as_str()).collect();
        assert_eq!(
            comps,
            ["/admin", "/admin/stats", "/items", "/orders"]
                .into_iter()
                .collect(),
            "auth, stateful and OpenAPI survive"
        );
        assert_eq!(dropped.len(), 10);
        assert!(dropped.iter().all(|c| c.component.starts_with("/g")));
        let ids: BTreeSet<&str> = kept
            .iter()
            .chain(dropped.iter())
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(ids.len(), 14, "ids stay unique");
        assert_eq!(kept[0].id, "TC-001");
        assert_eq!(dropped[0].id, "TC-005");

        // nothing to cut: the planner's order is untouched
        let (kept, dropped) = order_and_trim(cases.clone(), None, 60);
        assert!(dropped.is_empty() && kept[0].component == "/g0" && kept.len() == 14);
        // more cases than the executor's step budget but no hard limit: reordered, none dropped
        let (kept, dropped) = order_and_trim(cases, None, 5);
        assert!(dropped.is_empty() && kept.len() == 14);
        assert!(
            kept[..2].iter().all(|c| c.technique == "authz"),
            "the cases that will run first are the important ones"
        );
    }

    #[test]
    fn a_cut_plan_drops_unchanged_operations_before_changed_ones() {
        let mut cases: Vec<PlannedCase> = (0..6)
            .map(|i| {
                let mut c = planned(
                    &format!("TC-{:03}", i + 1),
                    "boundary",
                    "GET",
                    &format!("/u{i}"),
                );
                c.source = Some("openapi".into());
                c
            })
            .collect();
        // a changed operation's weakest case (a generic boundary probe) outranks an unchanged authz case
        let mut weak = planned("TC-007", "boundary", "GET", "/changed");
        weak.changed_ops = vec!["GET /changed".into()];
        cases.push(weak);
        cases.push(planned("TC-008", "authz", "GET", "/admin"));
        cases.push(planned("TC-009", "state_transition", "GET", "/"));
        let (kept, dropped) = order_and_trim(cases.clone(), Some(3), 60);
        let comps: BTreeSet<&str> = kept.iter().map(|c| c.component.as_str()).collect();
        assert_eq!(
            comps,
            ["/", "/changed", "/admin"].into_iter().collect(),
            "root probe and changed op first"
        );
        assert!(dropped.iter().all(|c| c.component.starts_with("/u")));
        // with no changed operation the order is the old one: authz, then OpenAPI
        cases.retain(|c| c.changed_ops.is_empty());
        let (kept, _) = order_and_trim(cases, Some(3), 60);
        assert!(kept.iter().any(|c| c.component == "/admin"));
    }

    fn git_ok(dir: &std::path::Path) -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .current_dir(dir)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn a_change_aware_run_plans_the_changed_operation_first_and_reports_how_it_was_covered() {
        use crate::agent::change::testkit::repo_with;
        if !git_ok(&std::env::temp_dir()) {
            return;
        }
        let repo = repo_with(
            "pipe-change",
            &[
                ("app/orders.py", "@app.get('/orders')\ndef a(): pass\n"),
                ("app/health.py", "@app.get('/health')\ndef h(): pass\n"),
            ],
            &[
                ("app/orders.py", "@app.get('/orders')\ndef a(): return []\n"),
                ("README.md", "notes"),
            ],
        );
        let srv = start_srv(0, None);
        let base = tmp("change");
        let mut rq = req(&srv.base, true);
        rq.profile = "quick".into();
        rq.repo = Some(repo.display().to_string());
        rq.diff_base = Some("base".into());
        let rep = run_with(&base, &rq, "run-change", opts(), Some(true)).unwrap();
        let ci = rep.change_impact.as_ref().expect("change impact");
        assert_eq!(ci.status, "applied", "{ci:?}");
        assert_eq!(ci.changed_files, ["README.md", "app/orders.py"]);
        assert_eq!(ci.unmapped_files, ["README.md"]);
        assert_eq!(ci.unmapped_total, 1);
        assert_eq!(ci.operations.len(), 1);
        assert_eq!(ci.operations[0].operation, "GET /orders");
        // quick plans no spec case, except for the changed operation, which leads the plan
        let spec_cases: Vec<_> = rep
            .planned_cases
            .iter()
            .filter(|c| c.source.as_deref() == Some("openapi"))
            .collect();
        assert!(spec_cases.len() >= 5, "{}", spec_cases.len());
        assert!(spec_cases.iter().all(|c| c.changed_ops == ["GET /orders"]));
        assert_eq!(rep.planned_cases[0].changed_ops, ["GET /orders"]);
        assert!(rep.planned_cases.iter().all(|c| c.component != "/health"));
        // coverage is computed from what was sent
        let cov = &ci.coverage[0];
        assert_eq!(cov.operation, "GET /orders");
        assert_eq!(cov.planned, spec_cases.len());
        assert_eq!(cov.executed, cov.planned, "nothing was cut");
        assert!(
            cov.techniques.contains(&"authz".to_string()),
            "{:?}",
            cov.techniques
        );
        assert!(rep.steps.iter().any(|s| s.action == "Change Impact"));
        // the persisted report carries it, and both renderings show the section
        let loaded = crate::agent::store::load_agent_run_in(&base, "run-change").unwrap();
        assert_eq!(loaded.change_impact.as_ref(), Some(ci));
        let md = crate::agent::generate_agent_markdown_report(&rep);
        assert!(
            md.contains("## Change impact") && md.contains("`GET /orders`"),
            "{md}"
        );
        assert!(md.contains("Unmapped files (1)") && md.contains("`README.md`"));
        let html = crate::agent::generate_agent_html_report(&rep);
        assert!(html.contains("<h2>Change impact</h2>") && html.contains("GET /orders"));
    }

    #[test]
    fn an_unusable_diff_never_fails_the_run_and_leaves_the_plan_alone() {
        use crate::agent::change::testkit::repo_with;
        if !git_ok(&std::env::temp_dir()) {
            return;
        }
        let repo = repo_with("pipe-nochange", &[("a.py", "x=1\n")], &[("a.py", "x=2\n")]);
        let srv = start_srv(0, None);
        let plain = {
            let base = tmp("plain-plan");
            let mut rq = req(&srv.base, true);
            rq.profile = "quick".into();
            run_with(&base, &rq, "run-plain", opts(), Some(true)).unwrap()
        };
        for (i, diff_base) in ["no-such-ref", "--output=/tmp/x"].into_iter().enumerate() {
            let base = tmp(&format!("badref{i}"));
            let mut rq = req(&srv.base, true);
            rq.profile = "quick".into();
            rq.repo = Some(repo.display().to_string());
            rq.diff_base = Some(diff_base.into());
            let rep = run_with(&base, &rq, &format!("run-bad{i}"), opts(), Some(true)).unwrap();
            assert_eq!(rep.status, "completed");
            let keys = |r: &AgentRunReport| {
                r.planned_cases
                    .iter()
                    .map(|c| (c.method.clone(), c.component.clone(), c.technique.clone()))
                    .collect::<Vec<_>>()
            };
            assert_eq!(keys(&rep), keys(&plain), "{diff_base}");
            assert!(rep.planned_cases.iter().all(|c| c.changed_ops.is_empty()));
            match (i, &rep.change_impact) {
                (0, Some(ci)) => assert_eq!(ci.status, "failed"),
                (1, None) => assert!(
                    rep.notes
                        .iter()
                        .any(|n| n.contains("change-aware planning skipped"))
                ),
                other => panic!("{other:?}"),
            }
        }
        // repo without a base: noted, not applied
        let base = tmp("nobase");
        let mut rq = req(&srv.base, true);
        rq.profile = "quick".into();
        rq.repo = Some(repo.display().to_string());
        let rep = run_with(&base, &rq, "run-nobase", opts(), Some(true)).unwrap();
        assert!(rep.change_impact.is_none());
        assert!(
            rep.notes
                .iter()
                .any(|n| n.contains("needs both repo and diff_base"))
        );
    }

    #[test]
    fn a_truncated_plan_is_noted_with_the_dropped_count_and_lowers_coverage() {
        let srv = start_srv(0, None);
        let base = tmp("trunc");
        let mut rq = req(&srv.base, false);
        rq.max_steps = Some(3);
        let rep = run_with(&base, &rq, "run-trunc", opts(), Some(true)).unwrap();
        let ran = rep
            .executed_results
            .iter()
            .filter(|r| r.status != "SKIPPED")
            .count();
        let dropped: Vec<&CaseExecutionResult> = rep
            .executed_results
            .iter()
            .filter(|r| {
                r.failure_reason
                    .as_deref()
                    .is_some_and(|f| f.starts_with("dropped:"))
            })
            .collect();
        assert_eq!(ran, 3);
        assert!(
            dropped.len() >= 5,
            "the spec plan has well over 3 cases, {} dropped",
            dropped.len()
        );
        assert!(
            dropped
                .iter()
                .all(|r| r.status == "SKIPPED" && r.status_code.is_none())
        );
        // a visible note with the exact count
        let n = dropped.len();
        let total = rep.planned_cases.len();
        let note = rep
            .notes
            .iter()
            .find(|n| n.contains("plan truncated"))
            .expect("note");
        assert!(
            note.contains(&format!("{n} of {total} planned case(s) were dropped"))
                && note.contains("max_steps = 3"),
            "{note}"
        );
        assert_eq!(
            rep.executed_results.len(),
            total,
            "every planned case has a result, none vanishes"
        );
        // the budget block and the ledger say so too, and coverage is lowered by the skipped cases
        assert!(
            rep.budget
                .as_ref()
                .unwrap()
                .stopped
                .as_deref()
                .unwrap()
                .contains("plan truncated")
        );
        let l = rep.evidence_ledger.as_ref().unwrap();
        assert!(
            l.executive_summary.contains("stopped early")
                && l.executive_summary.contains("plan truncated"),
            "{}",
            l.executive_summary
        );
        assert!(
            l.coverage.iter().map(|c| c.skipped).sum::<usize>() >= n,
            "coverage matrix counts them as not run"
        );
        assert!(l.gate_verdict != "GO", "{}", l.verdict_basis);
        // what ran first is what matters: access control is in the kept set when the plan has any
        let kept_ids: BTreeSet<&str> = rep
            .executed_results
            .iter()
            .filter(|r| r.status != "SKIPPED")
            .map(|r| r.technique.as_str())
            .collect();
        assert!(kept_ids.contains("authz"), "{kept_ids:?}");
        // the saved report agrees
        let disk = crate::agent::store::load_agent_run_in(&base, "run-trunc").unwrap();
        assert!(disk.notes.iter().any(|n| n.contains("plan truncated")));
        let _ = std::fs::remove_dir_all(&base);
    }

    // ------------------------------------------------------------ created resources

    #[test]
    fn harvest_records_created_resources_from_the_stored_responses() {
        let cases = vec![
            {
                let mut c = planned("TC-001", "boundary", "POST", "/orders");
                c.role = Some("user".into());
                c
            },
            planned("TC-002", "boundary", "POST", "/orders"),
        ];
        let ledger = CreatedLedger::new();
        let mut results = vec![
            post_result(
                "TC-001",
                "/orders",
                201,
                json!({"request": {"url": "http://h.test/orders?x=1"}, "response": {"headers": [], "body_excerpt": "{\"id\": 7}"}}),
            ),
            // Location wins for the delete path; the id comes from the body when there is one
            post_result(
                "TC-002",
                "/orders",
                201,
                json!({"request": {"url": "http://h.test/orders"}, "response": {"headers": [["Location", "/v2/orders/9"], ["content-type", "x"]], "body_excerpt": "{}"}}),
            ),
            // an excerpt cut in the middle of the JSON still yields the id
            post_result(
                "TC-003",
                "/things",
                200,
                json!({"request": {"url": "http://h.test/things"}, "response": {"headers": [], "body_excerpt": "{\"id\": \"abc-1\", \"name\": \"xxxxxxxxx"}}),
            ),
            // created, but nothing says what: cannot be deleted automatically
            post_result(
                "TC-004",
                "/blobs",
                201,
                json!({"request": {"url": "http://h.test/blobs"}, "response": {"headers": [], "body_excerpt": "ok"}}),
            ),
            // not creations: a failed POST, a PUT that updated, a PATCH, a GET that shows an id
            post_result(
                "TC-005",
                "/orders",
                500,
                json!({"request": {"url": "http://h.test/orders"}, "response": {"headers": [], "body_excerpt": "{\"id\": 1}"}}),
            ),
        ];
        for (id, m, code) in [
            ("TC-006", "PUT", 200u16),
            ("TC-007", "PATCH", 200),
            ("TC-008", "GET", 200),
        ] {
            let mut r = post_result(
                id,
                "/orders/1",
                code,
                json!({"request": {"url": "http://h.test/orders/1"}, "response": {"headers": [], "body_excerpt": "{\"id\": 1}"}}),
            );
            r.method = m.into();
            results.push(r);
        }
        // a PUT that answered 201 did create
        let mut put = post_result(
            "TC-009",
            "/pets/5",
            201,
            json!({"request": {"url": "http://h.test/pets/5"}, "response": {"headers": [], "body_excerpt": "{\"id\": 5}"}}),
        );
        put.method = "PUT".into();
        results.push(put);
        // a stateful chain: alice creates, bob reads
        let mut chain = result("TC-010", "authz", "FAIL");
        chain.method = "POST".into();
        let step = |n: u32, actor: &str, m: &str, code: u16, vars: &[(&str, &str)]| {
            StatefulStepExecution {
                step_number: n,
                actor: actor.into(),
                method: m.into(),
                resolved_path: "/api/items".into(),
                status_code: code,
                latency_ms: 1,
                extracted_values: vars
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                passed: true,
                violation_triggered: false,
                error_detail: None,
            }
        };
        chain.stateful_chain = Some(vec![
            step(
                1,
                "alice",
                "POST",
                201,
                &[("id", "item_secret_99"), ("token", "do-not-record")],
            ),
            step(2, "bob", "GET", 200, &[]),
        ]);
        results.push(chain);

        let unidentified = harvest_created(&results, &cases, &ledger);
        let got: Vec<(String, String, Option<String>, Option<String>)> = ledger
            .entries()
            .iter()
            .map(|e| {
                (
                    e.teardown_path(),
                    e.id.clone(),
                    e.role.clone(),
                    e.case_id.clone(),
                )
            })
            .collect();
        assert_eq!(got.len(), 5, "{got:?}");
        assert!(
            got.contains(&(
                "/orders/7".into(),
                "7".into(),
                Some("user".into()),
                Some("TC-001".into())
            )),
            "{got:?}"
        );
        assert!(
            got.iter()
                .any(|g| g.0 == "/v2/orders/9" && g.3.as_deref() == Some("TC-002")),
            "{got:?}"
        );
        assert!(got.iter().any(|g| g.0 == "/things/abc-1"), "{got:?}");
        assert!(got.iter().any(|g| g.0 == "/pets/5"), "{got:?}");
        assert!(
            got.contains(&(
                "/api/items/item_secret_99".into(),
                "item_secret_99".into(),
                Some("alice".into()),
                Some("TC-010".into())
            )),
            "{got:?}"
        );
        assert!(
            !got.iter().any(|g| g.1 == "do-not-record"),
            "only id-like values are recorded"
        );
        assert_eq!(unidentified.len(), 1, "{unidentified:?}");
        assert!(unidentified[0].path == "/blobs" && unidentified[0].id == "(unknown)");
    }

    #[test]
    fn teardown_deletes_newest_first_with_the_creating_role_and_only_on_nonprod() {
        let srv = start_srv(0, None);
        for id in [11u64, 12, 13] {
            srv.orders.lock().unwrap().insert(id);
        }
        let ledger = CreatedLedger::new();
        assert!(ledger.record_with("POST", "/orders", "11", Some("user"), None));
        assert!(ledger.record_with("POST", "/orders", "12", Some("alice"), None)); // alice has her own token
        assert!(ledger.record_with("POST", "/orders", "13", None, None)); // no role: falls back to a configured one
        let unknown = vec![Leftover {
            method: "POST".into(),
            path: "/blobs".into(),
            id: "(unknown)".into(),
            reason: "no id".into(),
        }];

        // not confirmed nonprod: nothing is sent, everything is listed
        let c = teardown(
            &srv.base,
            &ledger,
            unknown.clone(),
            &creds(),
            false,
            false,
            Duration::from_secs(5),
        );
        assert!(srv.seen("DELETE").is_empty());
        assert_eq!(
            (c.created, c.attempted, c.deleted, c.leftovers.len()),
            (4, 0, 0, 4)
        );
        assert!(
            c.skipped
                .as_deref()
                .unwrap()
                .contains("not confirmed nonprod")
        );
        assert_eq!(srv.orders.lock().unwrap().len(), 3);
        // dry-run: nothing is sent either
        let c = teardown(
            &srv.base,
            &ledger,
            vec![],
            &creds(),
            true,
            true,
            Duration::from_secs(5),
        );
        assert!(
            srv.seen("DELETE").is_empty()
                && c.skipped.as_deref() == Some("dry-run")
                && c.leftovers.len() == 3
        );

        // nonprod: newest first, authenticated, on the target's own origin
        let c = teardown(
            &srv.base,
            &ledger,
            unknown,
            &creds(),
            true,
            false,
            Duration::from_secs(5),
        );
        let d = srv.seen("DELETE");
        assert_eq!(
            d.iter().map(|s| s.1.as_str()).collect::<Vec<_>>(),
            ["/orders/13", "/orders/12", "/orders/11"]
        );
        // user and "no role" resolve to tok-user (accepted); alice's token is not the fixture's user token -> 401 left over
        assert_eq!(d[0].2.as_deref(), Some("Bearer tok-user"));
        assert_eq!(d[1].2.as_deref(), Some("Bearer tok-alice"));
        assert_eq!((c.attempted, c.deleted), (3, 2), "{c:?}");
        let reasons: Vec<&str> = c.leftovers.iter().map(|l| l.reason.as_str()).collect();
        assert!(
            c.leftovers
                .iter()
                .any(|l| l.id == "12" && l.reason == "DELETE answered HTTP 401"),
            "{reasons:?}"
        );
        assert!(c.leftovers.iter().any(|l| l.id == "(unknown)"));
        assert_eq!(
            srv.orders
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [12],
            "exactly the failed one remains"
        );
        assert!(
            c.summary()
                .contains("4 resource(s) created, 2 deleted, 2 left"),
            "{}",
            c.summary()
        );

        // an unreachable target: the failure is a leftover, not a panic
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_url = format!("http://{}", dead.local_addr().unwrap());
        drop(dead);
        let l2 = CreatedLedger::new();
        l2.record("/orders", "1");
        let c = teardown(
            &dead_url,
            &l2,
            vec![],
            &creds(),
            true,
            false,
            Duration::from_secs(2),
        );
        assert_eq!((c.deleted, c.leftovers.len()), (0, 1));
        assert!(c.leftovers[0].reason.starts_with("DELETE failed"), "{c:?}");
        // nothing created: nothing to say
        let c = teardown(
            &srv.base,
            &CreatedLedger::new(),
            vec![],
            &creds(),
            true,
            false,
            Duration::from_secs(2),
        );
        assert_eq!(c.created, 0);
        assert!(c.summary().contains("no cleanup needed"));
    }

    #[test]
    fn teardown_confirms_a_delete_with_a_get_and_catches_a_no_op_delete() {
        // the fixture answers every DELETE 204 and removes nothing (the qa-api server's bug #6)
        let srv = start_srv(0, Some(204));
        {
            let mut o = srv.orders.lock().unwrap();
            o.insert(7); // really there, DELETE will not remove it
        }
        let ledger = CreatedLedger::new();
        assert!(ledger.record_with("POST", "/orders", "7", Some("user"), Some("TC-004")));
        assert!(ledger.record_with("POST", "/orders", "8", Some("user"), Some("TC-005"))); // already gone: 404 on the read-back
        let c = teardown(
            &srv.base,
            &ledger,
            vec![],
            &creds(),
            true,
            false,
            Duration::from_secs(5),
        );
        assert_eq!(c.attempted, 2);
        assert_eq!(
            (c.deleted, c.confirmed_gone, c.still_present, c.unconfirmed),
            (1, 1, 1, 0),
            "{c:?}"
        );
        let stuck: Vec<_> = c
            .leftovers
            .iter()
            .filter(|l| l.reason.starts_with(DELETE_NOT_EFFECTIVE))
            .collect();
        assert_eq!(stuck.len(), 1, "{c:?}");
        assert_eq!(
            (stuck[0].id.as_str(), stuck[0].path.as_str()),
            ("7", "/orders/7")
        );
        assert!(
            stuck[0].reason.contains("DELETE answered HTTP 204")
                && stuck[0].reason.contains("GET still answers HTTP 200"),
            "{}",
            stuck[0].reason
        );
        // the read-back carried the creating role's credential
        let gets = srv.seen("GET");
        assert_eq!(gets.len(), 2);
        assert!(
            gets.iter()
                .all(|g| g.2.as_deref() == Some("Bearer tok-user")),
            "{gets:?}"
        );
        assert!(
            c.summary().contains("1 still present after a 2xx DELETE"),
            "{}",
            c.summary()
        );
        // the defect results derived from it
        let r = delete_check_results(&srv.base, &c);
        assert_eq!(r.len(), 1);
        assert_eq!(
            (
                r[0].case_id.as_str(),
                r[0].status.as_str(),
                r[0].method.as_str()
            ),
            ("CLEANUP-001", "FAIL", "DELETE")
        );
        assert_eq!(r[0].status_code, Some(200));
        assert!(
            r[0].reproduction_curl.contains("-X DELETE")
                && r[0].reproduction_curl.contains("RH_USER_TOKEN"),
            "{}",
            r[0].reproduction_curl
        );
        assert!(!r[0].reproduction_curl.contains("tok-user"));
        let d = crate::agent::triage::derive_defects(&r);
        assert_eq!(d.len(), 1);
        assert_eq!(
            (d[0].severity.as_str(), d[0].component.as_str()),
            ("medium", "/orders/7")
        );
        assert!(
            d[0].title
                .starts_with("DELETE reports success but the resource remains")
        );
        // an honest delete is confirmed gone and a read-back that proves nothing keeps the DELETE's word
        let ok = start_srv(0, None);
        ok.orders.lock().unwrap().insert(5);
        let l2 = CreatedLedger::new();
        l2.record_with("POST", "/orders", "5", Some("user"), None);
        let c2 = teardown(
            &ok.base,
            &l2,
            vec![],
            &creds(),
            true,
            false,
            Duration::from_secs(5),
        );
        assert_eq!(
            (c2.deleted, c2.confirmed_gone, c2.still_present),
            (1, 1, 0),
            "{c2:?}"
        );
        assert!(delete_check_results(&ok.base, &c2).is_empty());
        let l3 = CreatedLedger::new();
        l3.record_with("POST", "/orders", "5", Some("alice"), None); // alice's token is not accepted: 401 on DELETE, nothing to confirm
        let c3 = teardown(
            &ok.base,
            &l3,
            vec![],
            &creds(),
            true,
            false,
            Duration::from_secs(5),
        );
        assert_eq!(c3.still_present, 0);
    }

    #[test]
    fn a_run_reports_a_delete_that_does_nothing_as_a_defect_and_updates_cleanup_json() {
        let srv = start_srv(0, Some(204));
        let base = tmp("noop-delete");
        let rep = run_with(
            &base,
            &req(&srv.base, false),
            "run-noop",
            opts(),
            Some(true),
        )
        .unwrap();
        let created = srv.created_total.load(Ordering::SeqCst);
        assert!(created >= 1, "the plan posts to /orders");
        let c = load_cleanup_in(&base, "run-noop").expect("cleanup.json");
        assert!(c.still_present >= 1 && c.confirmed_gone == 0, "{c:?}");
        assert_eq!(
            c.still_present,
            c.leftovers
                .iter()
                .filter(|l| l.reason.starts_with(DELETE_NOT_EFFECTIVE))
                .count()
        );
        assert_eq!(
            c.deleted, 0,
            "a 2xx DELETE that left the resource is not a deletion: {c:?}"
        );
        // the leftovers are in the report, and each is a Medium quality defect with its own evidence file
        assert!(
            rep.notes
                .iter()
                .any(|n| n.contains("were NOT removed") && n.contains(DELETE_NOT_EFFECTIVE)),
            "{:?}",
            rep.notes
        );
        let fails: Vec<&CaseExecutionResult> = rep
            .executed_results
            .iter()
            .filter(|r| r.case_id.starts_with("CLEANUP-"))
            .collect();
        assert_eq!(fails.len(), c.still_present);
        assert!(
            fails
                .iter()
                .all(|r| r.status == "FAIL" && r.evidence_file.is_some())
        );
        let defects: Vec<&TriagedDefect> = rep
            .triaged_defects
            .iter()
            .filter(|d| d.title.starts_with("DELETE reports success"))
            .collect();
        assert!(
            !defects.is_empty(),
            "{:?}",
            rep.triaged_defects
                .iter()
                .map(|d| &d.title)
                .collect::<Vec<_>>()
        );
        assert!(
            defects
                .iter()
                .all(|d| d.severity == "medium" && d.owasp_category.starts_with("Quality"))
        );
        assert!(
            base.join("run-noop")
                .join(fails[0].evidence_file.as_ref().unwrap())
                .exists()
        );
        assert!(
            rep.steps
                .iter()
                .any(|s| s.agent == "Cleanup" && s.action == "Delete Verification")
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_run_deletes_what_it_created_on_a_nonprod_target_and_reports_leftovers_otherwise() {
        // nonprod + live: every created order is deleted again, the report says so
        let srv = start_srv(0, None);
        let base = tmp("cleanup");
        let rep = run_with(
            &base,
            &req(&srv.base, false),
            "run-clean",
            opts(),
            Some(true),
        )
        .unwrap();
        let created = srv.created_total.load(Ordering::SeqCst);
        assert!(
            created >= 1,
            "the plan posts to /orders with the user token (planned {} cases)",
            rep.planned_cases.len()
        );
        let c = load_cleanup_in(&base, "run-clean").expect("cleanup.json");
        // every resource the server created is accounted for: deleted, or listed as left over
        assert_eq!(c.created as u64, created, "{c:?}");
        assert_eq!(c.deleted + c.leftovers.len(), c.created, "{c:?}");
        assert!(c.deleted >= 1 && srv.seen("DELETE").len() >= c.deleted);
        // the executor records every creation (burst requests included) with its id, so all of it
        // is deleted; whatever could not be identified is listed, and is exactly what remains
        assert!(c.leftovers.iter().all(|l| l.id == "(unknown)"), "{c:?}");
        assert!(
            c.leftovers.is_empty() && srv.orders.lock().unwrap().is_empty(),
            "{c:?} / left: {:?}",
            srv.orders.lock().unwrap()
        );
        assert_eq!(
            srv.orders.lock().unwrap().len(),
            c.leftovers.len(),
            "left on the target: {:?}",
            srv.orders.lock().unwrap()
        );
        assert_eq!(
            rep.stage_sources["cleanup"],
            format!("deleted {} of {}", c.deleted, c.created)
        );
        let cleanup_note = rep
            .notes
            .iter()
            .find(|n| n.starts_with("cleanup:"))
            .expect("cleanup note");
        assert!(
            cleanup_note.contains("NOT removed") || cleanup_note.contains("deleted"),
            "{cleanup_note}"
        );
        assert!(rep.steps.iter().any(|s| s.agent == "Cleanup"));

        // not confirmed nonprod: nothing is deleted and the leftovers are in the report
        let srv = start_srv(0, None);
        let rep = run_with(
            &base,
            &req(&srv.base, false),
            "run-keep",
            opts(),
            Some(false),
        )
        .unwrap();
        let created = srv.created_total.load(Ordering::SeqCst);
        assert!(created >= 1);
        // the plan's own DELETE test cases hit made-up ids; none touched an order this run created
        assert!(
            srv.seen("DELETE").iter().all(|d| {
                d.1.rsplit('/')
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .is_none_or(|n| !(100..100 + created).contains(&n))
            }),
            "{:?}",
            srv.seen("DELETE")
        );
        assert_eq!(srv.orders.lock().unwrap().len() as u64, created);
        let note = rep
            .notes
            .iter()
            .find(|n| n.contains("were NOT removed"))
            .expect("leftovers in the report");
        assert!(
            note.contains("/orders/") && note.contains("nonprod"),
            "{note}"
        );
        assert!(
            rep.steps
                .iter()
                .any(|s| s.agent == "Cleanup" && s.status == "warning")
        );
        let c = load_cleanup_in(&base, "run-keep").unwrap();
        assert_eq!(c.leftovers.len() as u64, created);

        // a DELETE the target refuses is a leftover with the reason
        let srv = start_srv(0, Some(405));
        let rep = run_with(&base, &req(&srv.base, false), "run-405", opts(), Some(true)).unwrap();
        assert!(
            rep.notes
                .iter()
                .any(|n| n.contains("were NOT removed") && n.contains("HTTP 405")),
            "{:?}",
            rep.notes
        );

        // dry-run: no state-changing request at all, nothing to clean
        let srv = start_srv(0, None);
        let rep = run_with(&base, &req(&srv.base, true), "run-dry", opts(), Some(true)).unwrap();
        assert!(srv.seen("POST").is_empty() && srv.seen("DELETE").is_empty());
        assert_eq!(rep.stage_sources["cleanup"], "not needed");
        assert!(load_cleanup_in(&base, "run-dry").is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_executor_records_every_2xx_creation_and_the_teardown_deletes_them() {
        use crate::agent::exec::{ExecOptions, execute_cases_with};
        let srv = start_srv(0, None);
        let ledger = CreatedLedger::new();
        // a normal POST, a POST with a 3-request concurrency burst (threads: the thread-local
        // ledger does not reach them), and a stateful chain whose first step creates an order
        let mut plain = planned("TC-001", "boundary", "POST", "/orders");
        plain.role = Some("user".into());
        plain.payload = Some("{\"item\": \"a\"}".into());
        let mut burst = planned("TC-002", "boundary", "POST", "/orders");
        burst.role = Some("user".into());
        burst.payload = Some("{\"item\": \"b\"}".into());
        burst.concurrency_burst = Some(3);
        let mut chain = planned("TC-003", "authz", "POST", "/orders");
        chain.role = Some("user".into());
        let step = |n: u32, actor: &str, method: &str, path: &str| StatefulStep {
            step_number: n,
            actor: actor.into(),
            method: method.into(),
            path: path.into(),
            payload: None,
            extract_vars: None,
            expected_status: None,
            violation_condition: None,
        };
        let mut create = step(1, "user", "POST", "/orders");
        create.payload = Some("{\"item\": \"c\"}".into());
        create.extract_vars = Some(vec!["id".into()]);
        let mut read = step(2, "anon", "GET", "/orders/{{id}}");
        read.violation_condition = Some("status == 200".into());
        chain.stateful_steps = Some(vec![create, read]);
        let cases = vec![plain, burst, chain];

        let o = ExecOptions {
            dry_run: false,
            is_spa_target: false,
            credentials: Credentials::none().with("user", "tok-user"),
            reruns: 0,
            timeout: Duration::from_secs(5),
        };
        let results = {
            let _scope = ledger.install();
            execute_cases_with(
                &cases,
                &srv.base,
                &o,
                &mut RunBudget::new(50, 500, Duration::from_secs(60), 0.0),
            )
        };
        assert!(
            results.iter().any(|r| r.case_id == "TC-002-B"),
            "the burst ran as a sub-case"
        );
        // 1 plain + 1 chain step + (1 base + 3 burst) = 6 orders exist, and every one is recorded
        let on_target = srv.orders.lock().unwrap().clone();
        assert_eq!(on_target.len(), 6, "{on_target:?}");
        let recorded = ledger.entries();
        assert_eq!(
            recorded
                .iter()
                .map(|e| e.id.parse::<u64>().unwrap())
                .collect::<BTreeSet<_>>(),
            on_target,
            "the ledger holds exactly the orders the server created: {recorded:?}"
        );
        let n = |case: &str| ledger.recorded_for_case(case);
        assert_eq!(
            (n("TC-001"), n("TC-002"), n("TC-002-B"), n("TC-003")),
            (1, 1, 3, 1),
            "{recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .all(|e| e.role.as_deref() == Some("user") && e.path == "/orders")
        );

        // the pipeline's own harvest adds nothing and reports nothing as unidentified: what the
        // executor recorded is not counted twice, and not as a leftover either
        let unidentified = harvest_created(&results, &cases, &ledger);
        assert!(unidentified.is_empty(), "{unidentified:?}");
        assert_eq!(ledger.len(), 6);

        // teardown deletes them all (nonprod), authenticated as the creating role
        let c = teardown(
            &srv.base,
            &ledger,
            unidentified,
            &creds(),
            true,
            false,
            Duration::from_secs(5),
        );
        assert_eq!(
            (c.created, c.attempted, c.deleted, c.leftovers.len()),
            (6, 6, 6, 0),
            "{c:?}"
        );
        assert!(srv.orders.lock().unwrap().is_empty(), "nothing left behind");
        let d = srv.seen("DELETE");
        assert_eq!(d.len(), 6);
        assert!(
            d.iter().all(|x| x.2.as_deref() == Some("Bearer tok-user")),
            "{d:?}"
        );
    }

    #[test]
    fn nothing_is_recorded_without_an_installed_ledger_and_non_creations_are_ignored() {
        use crate::agent::exec::{ExecOptions, execute_cases_with};
        let srv = start_srv(0, None);
        let mut plain = planned("TC-001", "boundary", "POST", "/orders");
        plain.role = Some("user".into());
        plain.payload = Some("{\"item\": \"a\"}".into());
        let mut get = planned("TC-002", "boundary", "GET", "/about");
        get.role = Some("anon".into());
        let o = ExecOptions {
            dry_run: false,
            is_spa_target: false,
            credentials: Credentials::none().with("user", "tok-user"),
            reruns: 0,
            timeout: Duration::from_secs(5),
        };
        let budget = || RunBudget::new(50, 500, Duration::from_secs(60), 0.0);
        // no ledger installed on this thread: the executor records nothing and does not fail
        let _ = execute_cases_with(&[plain.clone()], &srv.base, &o, &mut budget());
        assert_eq!(srv.orders.lock().unwrap().len(), 1);
        // a GET is not a creation
        let ledger = CreatedLedger::new();
        {
            let _scope = ledger.install();
            let _ = execute_cases_with(&[get], &srv.base, &o, &mut budget());
        }
        assert!(ledger.is_empty());
    }

    #[test]
    fn the_executor_can_record_created_resources_without_any_plumbing() {
        // what exec/stateful do: call `record_created` while the run's ledger is installed
        let ledger = CreatedLedger::new();
        let _g = ledger.install();
        assert!(record_created("/api/widgets", "w-1"));
        assert!(record_created_with(
            "POST",
            "/api/widgets",
            "w-2",
            Some("admin"),
            Some("TC-007")
        ));
        drop(_g);
        let srv = start_srv(0, None);
        srv.orders.lock().unwrap().insert(1);
        let l = CreatedLedger::new();
        l.record("/orders", "1");
        let c = teardown(
            &srv.base,
            &l,
            vec![],
            &creds(),
            true,
            false,
            Duration::from_secs(5),
        );
        assert_eq!((c.deleted, c.leftovers.len()), (1, 0));
        assert_eq!(ledger.entries().len(), 2);
    }

    // ------------------------------------------------------------ lifecycle

    #[test]
    fn a_run_checkpoints_while_running_and_honours_cancellation_between_steps() {
        let srv = start_srv(60, None);
        let base = tmp("cancel");
        let (b2, t2) = (base.clone(), srv.base.clone());
        let worker =
            std::thread::spawn(move || run_in(&b2, &req(&t2, true), "run-cancel", opts()).unwrap());
        // the first checkpoint appears at once, status running
        let started = Instant::now();
        let mut saw_running_with_plan = false;
        while started.elapsed() < Duration::from_secs(30) {
            if let Ok(r) = crate::agent::store::load_agent_run_in(&base, "run-cancel") {
                assert_eq!(r.status, "running", "a run in flight says so");
                if !r.planned_cases.is_empty() {
                    saw_running_with_plan = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            saw_running_with_plan,
            "the plan was checkpointed before execution"
        );
        // wait until the executor is sending, then cancel
        let at_plan = srv.log.lock().unwrap().len();
        while srv.log.lock().unwrap().len() < at_plan + 3
            && started.elapsed() < Duration::from_secs(30)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(crate::agent::request_cancel("run-cancel"));
        let rep = worker.join().unwrap();
        assert_eq!(rep.status, "cancelled");
        let skipped: Vec<_> = rep
            .executed_results
            .iter()
            .filter(|r| r.status == "SKIPPED")
            .collect();
        let ran = rep.executed_results.len() - skipped.len();
        assert!(
            ran >= 1 && !skipped.is_empty(),
            "stopped between steps: {ran} ran, {} skipped",
            skipped.len()
        );
        assert!(
            skipped
                .iter()
                .any(|r| r.failure_reason.as_deref() == Some("run cancelled"))
        );
        assert!(rep.notes.iter().any(|n| n.contains("run cancelled")));
        assert_eq!(
            rep.budget.as_ref().unwrap().stopped.as_deref(),
            Some("run cancelled")
        );
        // the verdict is still computed from what ran, and the final state is on disk
        assert!(rep.evidence_ledger.is_some() && rep.finished_at.is_some());
        let disk = crate::agent::store::load_agent_run_in(&base, "run-cancel").unwrap();
        assert_eq!(disk.status, "cancelled");
        assert!(
            !crate::agent::running_run_ids().contains(&"run-cancel".to_string()),
            "no longer cancellable once finished"
        );
        assert!(!base.join("run-cancel").join("CANCEL").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_cancel_marker_file_stops_a_run_of_another_process() {
        let srv = start_srv(40, None);
        let base = tmp("marker");
        let (b2, t2) = (base.clone(), srv.base.clone());
        let worker =
            std::thread::spawn(move || run_in(&b2, &req(&t2, true), "run-marker", opts()).unwrap());
        let started = Instant::now();
        while checkpoint_status(&base.join("run-marker")).is_none()
            && started.elapsed() < Duration::from_secs(10)
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::write(base.join("run-marker").join("CANCEL"), b"stop").unwrap();
        let rep = worker.join().unwrap();
        assert_eq!(rep.status, "cancelled");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_run_that_errors_after_its_first_checkpoint_is_saved_as_failed() {
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = format!("http://{}", dead.local_addr().unwrap());
        drop(dead);
        let base = tmp("failed");
        // make the final save fail: `report` exists as a file where the renderings directory goes
        std::fs::create_dir_all(base.join("run-fail")).unwrap();
        std::fs::write(base.join("run-fail").join("report"), b"in the way").unwrap();
        let mut rq = req(&target, true);
        rq.spec_url = None;
        let e = run_in(&base, &rq, "run-fail", opts()).unwrap_err();
        let disk = crate::agent::store::load_agent_run_in(&base, "run-fail").unwrap();
        assert_eq!(disk.status, "failed", "{e:#}");
        assert!(disk.error.as_deref().is_some_and(|m| !m.is_empty()));
        assert!(
            disk.finished_at.is_some()
                && disk.evidence_ledger.as_ref().is_some_and(|l| !l.evaluated)
        );
        assert!(
            disk.steps
                .iter()
                .any(|s| s.action == "Run failed" && s.status == "error")
        );
        // a run that is rejected up front leaves nothing behind (no checkpoint, no failed stub)
        let base2 = tmp("rejected");
        assert!(run_in(&base2, &req("ftp://x.test", true), "run-nope", opts()).is_err());
        assert!(!base2.exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_slow_llm_holds_the_planner_at_the_high_tier_and_says_so() {
        let base = mock::cfg("http://127.0.0.1:1/v1", &tmp("slow-cap-cfg"));
        let mut c = base.with_thinking(true, "max_pro", 32_768);
        let mut notes = Vec::new();
        let fast = latency_report(&Ok(Duration::from_millis(840)));
        cap_if_slow(&mut c, &fast, &mut notes);
        assert!(notes.is_empty() && c.model_tier == "max_pro", "{notes:?}");
        assert_eq!(fast.summary, "latency 840 ms");
        let slow = latency_report(&Ok(Duration::from_secs(11)));
        cap_if_slow(&mut c, &slow, &mut notes);
        assert_eq!(
            (c.model_tier.as_str(), c.thinking_budget_tokens),
            ("high", 8192)
        );
        assert!(
            notes.len() == 1
                && notes[0].contains("slow")
                && notes[0].contains("High tier")
                && notes[0].contains("max_pro"),
            "{notes:?}"
        );
        // already at High: slow is noted, nothing to cap
        let mut notes = Vec::new();
        cap_if_slow(&mut c, &slow, &mut notes);
        assert_eq!(c.thinking_budget_tokens, 8192);
        assert!(
            notes.len() == 1 && !notes[0].contains("capped"),
            "{notes:?}"
        );
    }

    #[test]
    fn a_run_against_a_slow_llm_is_capped_and_reports_the_probe() {
        let srv = start_srv(0, None);
        // the 1-token probe outlasts the timeout; /models and every real call answer at once
        let m = mock::start_status(|_, body| {
            let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            if v["max_tokens"] == 1 {
                std::thread::sleep(Duration::from_millis(450));
            }
            (
                200,
                json!({"choices": [{"message": {"role": "assistant", "content":
                    "{\"cases\": [], \"notes\": [], \"executive_summary\": \"fine\", \"gate_verdict\": \"GO\"}"}}]})
                .to_string(),
            )
        });
        let mut cfg = mock::cfg(&m.base, &tmp("slow-llm-cache"));
        cfg.timeout_override = Some(Duration::from_millis(300));
        let mut o = opts();
        o.llm = LlmMode::Use(Box::new(cfg));
        let mut rq = req(&srv.base, true);
        rq.model_tier = "max_pro".into();
        rq.thinking_budget_tokens = 32_768;
        let rep = run_in(&tmp("slow-llm-run"), &rq, "run-llm-slow", o).unwrap();
        let st = rep.llm_status.as_deref().unwrap();
        assert!(
            st.starts_with("connected: ") && st.contains("timed out"),
            "{st}"
        );
        assert!(
            rep.notes
                .iter()
                .any(|n| n.contains("LLM endpoint is slow") && n.contains("High tier")),
            "{:?}",
            rep.notes
        );
        assert_eq!(
            (rep.model_tier.as_str(), rep.thinking_budget_tokens),
            ("high", 8192)
        );
        // the planner ran with the capped budget, the gate and the triager without reasoning
        let sent: Vec<serde_json::Value> = m
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| serde_json::from_str(r.split("\r\n\r\n").nth(1).unwrap()).unwrap())
            .collect();
        let mut light = 0;
        for b in &sent {
            let max = b["max_tokens"].as_u64().unwrap();
            assert!(max <= 10_240, "no call above the High tier: {b}");
            let is_gate_or_triage = b["messages"][0]["content"].as_str().is_some_and(|c| {
                c.contains("readiness reviewer") || c.contains("root-cause analyst")
            });
            if is_gate_or_triage {
                light += 1;
                assert_eq!(max, 2048, "{b}");
                assert!(b.get("reasoning_effort").is_none(), "{b}");
            }
        }
        assert!(light >= 1, "the gate call was made: {sent:?}");
    }

    #[test]
    fn llm_calls_count_against_the_run_budget_and_the_thinking_log_is_honest() {
        let srv = start_srv(0, None);
        let m = mock::start(|_| {
            "{\"cases\": [], \"notes\": [], \"executive_summary\": \"fine\", \"gate_verdict\": \"GO\"}".into()
        });
        let dir = tmp("llm-cache");
        let mut o = opts();
        o.llm = LlmMode::Use(Box::new(mock::cfg(&m.base, &dir)));
        o.budget = RunBudget::new(80, 800, Duration::from_secs(120), 0.0).with_max_llm_calls(1);
        let mut rq = req(&srv.base, true);
        rq.thinking_budget_tokens = u32::MAX; // hostile
        let rep = run_in(&tmp("llm-run"), &rq, "run-llm-budget", o).unwrap();
        let b = rep.budget.as_ref().unwrap();
        assert_eq!(
            (b.llm_calls, b.max_llm_calls),
            (1, 1),
            "one call allowed, one made: {:?}",
            rep.notes
        );
        assert_eq!(
            m.chat_hits.load(Ordering::SeqCst),
            2,
            "the 1-token latency probe plus the one budgeted call"
        );
        assert!(
            rep.llm_status
                .as_deref()
                .is_some_and(|s| s.starts_with("connected: ") && s.contains("(latency ")),
            "{:?}",
            rep.llm_status
        );
        assert!(
            rep.notes
                .iter()
                .any(|n| n.contains("LLM") && n.contains("budget exhausted")),
            "{:?}",
            rep.notes
        );
        assert_eq!(rep.thinking_budget_tokens, crate::llm::MAX_THINKING_BUDGET);
        let think = rep
            .steps
            .iter()
            .find(|s| s.action == "Extended Thinking (CoT)")
            .expect("thinking step");
        assert!(
            think.details.contains("reasoning_effort=high") && !think.details.contains("forwarded"),
            "{}",
            think.details
        );
        assert!(
            think.details.contains("32768"),
            "the clamped budget is reported: {}",
            think.details
        );
    }
}
