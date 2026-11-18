//! Agent Studio HTTP & SSE endpoint handlers (runs, memory, approvals, discovery).

use super::guards::{blocking, err, guard, guard_repo, guard_spec, offload, same_target};
use super::types::{
    App, ApprovalPayload, CancelOutcome, CrawlBody, CrawlQuery, DirectivesSynthesizeBody,
    DiscoverBody, DiscoverQuery, MemoryAccept, MemoryQuery, Principal, RetestError, RetestPayload,
    clamp_pages, clip_notes, MAX_LISTED_RUNS, MAX_RUN_JSON_BYTES, MODEL_TIERS, PROFILES,
};
use super::worker::run_in_progress;
use crate::{network, scope};
use super::worker::{max_custom_instructions_bytes, worker_count};
use anyhow::Result;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{StatusCode, header, HeaderMap};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use crate::engine;

pub async fn api_index() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "name": "ReadyHai QA Engine & Production Gate API",
            "version": env!("CARGO_PKG_VERSION"),
            "workers": worker_count(),
            "status": "online",
            "frontend_url": "http://localhost:3000",
            "endpoints": {
                "health": "/health",
                "agent_status": "/api/agent/status",
                "agent_discover": "/api/agent/discover",
                "agent_run": "/api/agent/run",
                "agent_runs": "/api/agent/runs",
                "agent_run_detail": "/api/agent/runs/{id}",
                "agent_run_approve": "/api/agent/runs/{id}/approve",
                "agent_run_reject": "/api/agent/runs/{id}/reject",
                "agent_run_cancel": "/api/agent/runs/{id}/cancel",
                "agent_retest": "/api/agent/retest",
                "agent_memory": "/api/agent/memory?target=",
                "agent_memory_accept": "/api/agent/memory/accept"
            }
        })),
    )
}

/// The LLM status body: reachability, latency, and what is configured. Carries whether a key is set,
/// never the key.
pub(crate) fn llm_status_json(cfg: &crate::llm::LlmConfig) -> serde_json::Value {
    let t0 = std::time::Instant::now();
    let is_ok = crate::llm::probe(cfg);
    let latency = t0.elapsed().as_millis();
    let models_val = crate::llm::query_models(cfg).unwrap_or(json!({}));
    json!({
        "status": if is_ok { "online" } else { "offline" },
        "model": cfg.model,
        // every configured model, primary first; the rest are tried in order when a call fails
        "configured_models": cfg.model_chain(),
        "provider": cfg.provider.id,
        "base_url": cfg.base_url().unwrap_or_default(),
        "api_key_configured": crate::llm::key_configured(cfg),
        "latency_ms": latency,
        "models_list": models_val,
        "capabilities": ["multi_agent", "planner", "explorer", "triager", "readiness_gate", "owasp_agentic"]
    })
}

pub async fn agent_status() -> Response {
    let res = tokio::task::spawn_blocking(move || {
        let cfg = match crate::llm::LlmConfig::from_env() {
            Ok(c) => c,
            Err(e) => {
                return (
                    StatusCode::OK,
                    Json(json!({"status": "offline", "error": e.to_string()})),
                );
            }
        };
        (StatusCode::OK, Json(llm_status_json(&cfg)))
    })
    .await;

    match res {
        Ok((code, json)) => (code, json).into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "status probe failed"),
    }
}

// ------------------------------------------------------------------ agent routes

/// Bounds on a REST agent run, the same ones the MCP tool enforces: known profile and model tier,
/// a capped reasoning budget, bounded free-text instructions. (`max_steps` is clamped separately.)
pub(crate) fn clamp_agent_request(req: &mut crate::agent::AgentRunRequest) -> Result<(), String> {
    if req.target.trim().is_empty() {
        return Err("target is required and cannot be empty".into());
    }
    if !PROFILES.contains(&req.profile.as_str()) {
        return Err("profile must be quick|standard|deep".into());
    }
    if !MODEL_TIERS.contains(&req.model_tier.as_str()) {
        return Err("model_tier must be low|medium|high|max|max_pro".into());
    }
    req.thinking_budget_tokens = crate::llm::clamp_thinking_budget(req.thinking_budget_tokens);
    if let Some(ci) = &req.custom_instructions {
        // Refuse rather than cut: instructions silently truncated mid-sentence change their meaning.
        let max_bytes = max_custom_instructions_bytes();
        if ci.len() > max_bytes {
            return Err(format!(
                "custom_instructions is {} bytes; the limit is {max_bytes} (configure via READYHAI_MAX_CUSTOM_INSTRUCTIONS_BYTES)",
                ci.len()
            ));
        }
        if ci.trim().is_empty() {
            req.custom_instructions = None;
        }
    }
    Ok(())
}

pub async fn agent_run(
    State(app): State<Arc<App>>,
    Json(mut req): Json<crate::agent::AgentRunRequest>,
) -> Response {
    if let Err(m) = clamp_agent_request(&mut req) {
        return err(StatusCode::BAD_REQUEST, m);
    }
    // The agent sends attack payloads and write methods: prod hosts are refused outright.
    match guard(&app, &req.target, true).await {
        Ok(e) => req.target = e.url,
        Err(r) => return r,
    }
    match guard_spec(&app, req.spec_url.take()).await {
        Ok(s) => req.spec_url = s,
        Err(r) => return r,
    }
    // a checkout read from the server's disk: confined like every other server-side path
    if let Err(m) = guard_repo(&app, &mut req) {
        return err(StatusCode::BAD_REQUEST, m);
    }
    let id = engine::new_run_id();
    let mut opts = crate::agent::RunOptions::default();
    if let Some(n) = req.max_steps {
        opts = opts.with_max_steps(n.clamp(1, 50));
    }
    match blocking(&app, move || {
        crate::agent::run_agentic_loop_with(&req, &id, opts)
    })
    .await
    {
        Ok(Ok(rep)) => (StatusCode::OK, Json(rep)).into_response(),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(r) => r,
    }
}

/// Newest [`MAX_LISTED_RUNS`] agent runs. Run ids start with a UTC timestamp, so the newest are
/// found from the directory names alone: only those reports are read, not every run ever made.
pub(crate) fn list_agent_runs_capped() -> Vec<crate::agent::AgentRunReport> {
    let base = crate::agent::agent_runs_dir();
    let Ok(rd) = std::fs::read_dir(&base) else {
        return vec![];
    };
    let mut ids: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| engine::valid_run_id(n) && base.join(n).join("report.json").is_file())
        .collect();
    ids.sort_unstable_by(|a, b| b.cmp(a));
    ids.truncate(MAX_LISTED_RUNS);
    let mut out: Vec<crate::agent::AgentRunReport> = ids
        .iter()
        .filter_map(|id| crate::agent::load_agent_run(id).ok())
        .collect();
    out.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    out
}

pub async fn agent_runs_list() -> Response {
    match offload(list_agent_runs_capped).await {
        Ok(list) => Json(json!({"runs": list})).into_response(),
        Err(r) => r,
    }
}

pub async fn agent_run_get(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    match offload(move || crate::agent::load_agent_run(&id)).await {
        Ok(Ok(rep)) => Json(rep).into_response(),
        Ok(Err(_)) => err(StatusCode::NOT_FOUND, "agent run not found"),
        Err(r) => r,
    }
}


/// Ask a running agent run to stop (blocking: reads the run's checkpoint). A run of this process
/// is flagged directly; a run whose checkpoint says `running` gets a `CANCEL` marker that a run in
/// another process honours too (see `agent::request_cancel`).
pub(crate) fn cancel_agent_run(id: &str) -> CancelOutcome {
    let registered = crate::agent::running_run_ids().iter().any(|r| r == id);
    let status = match crate::agent::load_agent_run(id) {
        Ok(rep) => Some(rep.status),
        Err(_) if registered => Some("running".to_string()),
        Err(_) => None,
    };
    match status {
        None => CancelOutcome::Unknown,
        Some(st) if (registered || st == "running") && crate::agent::request_cancel(id) => {
            CancelOutcome::Requested
        }
        // finished between the check and the request, or never running
        Some(st) => CancelOutcome::NotRunning(st),
    }
}

/// `POST /api/agent/runs/{id}/cancel`: cooperative cancellation. The run stops at its next step,
/// still triages what it already did and ends with status `cancelled`. 404 for an unknown run,
/// 409 when it is not running.
pub async fn agent_run_cancel(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    let rid = id.clone();
    match offload(move || cancel_agent_run(&rid)).await {
        Ok(CancelOutcome::Requested) => (
            StatusCode::ACCEPTED,
            Json(json!({"id": id, "status": "cancelling"})),
        )
            .into_response(),
        Ok(CancelOutcome::Unknown) => err(StatusCode::NOT_FOUND, "agent run not found"),
        Ok(CancelOutcome::NotRunning(st)) => err(
            StatusCode::CONFLICT,
            format!("run is not running (status: {st})"),
        ),
        Err(r) => r,
    }
}

/// Generate report files for a run that still exists, into `rep_dir`, atomically.
///
/// GET handlers regenerate missing reports on demand. Writing straight into `rep_dir` lets a
/// concurrent reader see half a report, and `create_dir_all` on a run that was deleted meanwhile
/// brings its directory back. So: refuse when no run directory is left (`parents` = the places the
/// run may live), render into a temp directory beside it, then move each finished file into place
/// with `rename` (atomic on one filesystem). A failure leaves no partial files behind.
pub fn regenerate_reports(
    parents: &[PathBuf],
    rep_dir: &FsPath,
    generate: impl FnOnce(&FsPath) -> Result<()>,
) -> std::io::Result<()> {
    let Some(base) = parents.iter().find(|p| p.is_dir()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "run directory is gone",
        ));
    };
    let tmp = base.join(format!(".report-{:08x}.tmp", rand::random::<u32>()));
    std::fs::create_dir(&tmp)?;
    let moved = (|| -> std::io::Result<()> {
        generate(&tmp).map_err(std::io::Error::other)?;
        std::fs::create_dir_all(rep_dir)?;
        for e in std::fs::read_dir(&tmp)? {
            let e = e?;
            std::fs::rename(e.path(), rep_dir.join(e.file_name()))?;
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    moved
}

pub(crate) fn agent_report_blocking(id: &str, fmt: &str) -> Response {
    let (file, ctype) = match fmt {
        "html" => ("readyhai-report.html", "text/html; charset=utf-8"),
        "json" => ("readyhai-report.json", "application/json"),
        "markdown" | "md" => ("readyhai-report.md", "text/markdown; charset=utf-8"),
        "sarif" => ("readyhai-report.sarif", "application/sarif+json"),
        "junit" | "xml" => ("readyhai-report.junit.xml", "application/xml"),
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                "format: html|json|markdown|sarif|junit",
            );
        }
    };
    let rep_dir = crate::agent::agent_runs_dir().join(id).join("report");
    let rep_file = rep_dir.join(file);
    if !rep_file.exists()
        && let Ok(rep) = crate::agent::load_agent_run(id)
    {
        let _ = regenerate_reports(
            &[crate::agent::agent_runs_dir().join(id), engine::run_dir(id)],
            &rep_dir,
            |tmp| {
                crate::agent::generate_agent_report_formats(
                    &rep,
                    tmp,
                    &[
                        "html".into(),
                        "markdown".into(),
                        "sarif".into(),
                        "json".into(),
                        "junit".into(),
                    ],
                )
                .map(|_| ())
            },
        );
    }
    match read_report_file(&rep_file) {
        Some(b) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, ctype.parse().unwrap());
            if fmt == "html" {
                // The report is static HTML + CSS: no scripts of any kind.
                headers.insert(
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
                        .parse()
                        .unwrap(),
                );
            } else {
                let ext = if fmt == "junit" || fmt == "xml" {
                    "xml"
                } else if fmt == "markdown" || fmt == "md" {
                    "md"
                } else {
                    fmt
                };
                headers.insert(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"readyhai-agent-report-{id}.{ext}\"")
                        .parse()
                        .unwrap(),
                );
            }
            (StatusCode::OK, headers, b).into_response()
        }
        None => err(StatusCode::NOT_FOUND, "report not found"),
    }
}

/// A generated report, unless it is absurdly large (then it is not served from memory).
pub fn read_report_file(p: &FsPath) -> Option<Vec<u8>> {
    if std::fs::metadata(p).ok()?.len() > MAX_RUN_JSON_BYTES {
        return None;
    }
    std::fs::read(p).ok()
}

pub async fn agent_run_report(Path((id, fmt)): Path<(String, String)>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    match offload(move || agent_report_blocking(&id, &fmt)).await {
        Ok(r) => r,
        Err(r) => r,
    }
}

pub async fn agent_run_delete(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    // `delete_agent_run` also removes runs/<id>; do not pull the directory out from under the worker.
    if run_in_progress(&app, &id) {
        return err(
            StatusCode::CONFLICT,
            "run is in progress; delete it after it finishes",
        );
    }
    let rid = id.clone();
    let res = offload(move || {
        crate::agent::delete_agent_run(&rid).map_err(|e| e.to_string())?;
        // delete_agent_run ignores a failure to remove the core run directory: do not report
        // success while data is still there.
        for d in [
            crate::agent::agent_runs_dir().join(&rid),
            engine::run_dir(&rid),
        ] {
            if d.exists() {
                return Err(format!("could not remove the run directory of {rid}"));
            }
        }
        Ok(())
    })
    .await;
    match res {
        Ok(Ok(())) => Json(json!({"deleted": id, "status": "ok"})).into_response(),
        Ok(Err(m)) => err(StatusCode::INTERNAL_SERVER_ERROR, m),
        Err(r) => r,
    }
}

/// Sign-off body. There is deliberately no `user` field: the approver is the authenticated
/// principal. Unknown fields (an old client still sending `user`) are ignored, never recorded.
pub async fn agent_approve(
    Extension(who): Extension<Principal>,
    Path(id): Path<String>,
    Json(body): Json<ApprovalPayload>,
) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    match crate::agent::approve_agent_run(&id, &who.0, &clip_notes(&body.notes)) {
        Ok(rep) => Json(rep).into_response(),
        Err(e) => signoff_err(e),
    }
}

/// An unknown run id is the caller's mistake (404), anything else is ours (500).
pub(crate) fn signoff_err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let status = if e.downcast_ref::<crate::agent::SignOffRefused>().is_some() {
        StatusCode::CONFLICT
    } else if msg.ends_with("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    err(status, msg)
}

pub async fn agent_reject(
    Extension(who): Extension<Principal>,
    Path(id): Path<String>,
    Json(body): Json<ApprovalPayload>,
) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    match crate::agent::reject_agent_run(&id, &who.0, &clip_notes(&body.notes)) {
        Ok(rep) => Json(rep).into_response(),
        Err(e) => signoff_err(e),
    }
}

// ------------------------------------------------------------------ agent memory



/// The memory of a target is per http(s) URL. Reading or changing it sends nothing to the target,
/// so no scope check applies; the bearer token does.
pub(crate) fn memory_target(raw: &str) -> Result<String, Response> {
    scope::parse_web_url(raw)
        .map(|_| raw.trim().to_string())
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("target: {e}")))
}

/// 404 for what is not there, 409 for a defect that is fixed, 400 for a bad request, 500 for a
/// memory file that cannot be read.
pub(crate) fn memory_err(e: anyhow::Error) -> Response {
    let m = format!("{e:#}");
    let code = if m.starts_with("no agent memory") || m.starts_with("no known defect") {
        StatusCode::NOT_FOUND
    } else if m.contains("is fixed") {
        StatusCode::CONFLICT
    } else if m.starts_with("agent memory") {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    err(code, m)
}

/// `GET /api/agent/memory?target=URL`: what the agent remembers about the target (known defects
/// with their fingerprints, flaky history, operations, baselines). `exists: false` before the
/// first run.
pub async fn agent_memory_get(Query(q): Query<MemoryQuery>) -> Response {
    let target = match memory_target(&q.target) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let t2 = target.clone();
    match offload(move || crate::agent::memory::inspect(&crate::agent::memory::dir(), &t2)).await {
        Ok(Ok(Some(m))) => {
            Json(json!({"exists": true, "target": target, "memory": m})).into_response()
        }
        Ok(Ok(None)) => Json(json!({"exists": false, "target": target})).into_response(),
        Ok(Err(e)) => memory_err(e),
        Err(r) => r,
    }
}

/// `POST /api/agent/memory/accept`: accept a known open defect until `expires`. It stays listed
/// in every report and stops blocking the gate; afterwards it blocks again. Recorded as the
/// authenticated principal, never as client-supplied text.
pub async fn agent_memory_accept(
    Extension(who): Extension<Principal>,
    Json(b): Json<MemoryAccept>,
) -> Response {
    let target = match memory_target(&b.target) {
        Ok(t) => t,
        Err(r) => return r,
    };
    match offload(move || {
        crate::agent::memory::accept(
            &crate::agent::memory::dir(),
            &target,
            &b.fingerprint,
            &who.0,
            &b.reason,
            &b.expires,
            &engine::today(),
            &engine::now(),
        )
    })
    .await
    {
        Ok(Ok(a)) => Json(a).into_response(),
        Ok(Err(e)) => memory_err(e),
        Err(r) => r,
    }
}

/// `DELETE /api/agent/memory?target=URL`: forget the target (the next run plans from the profile alone).
pub async fn agent_memory_forget(Query(q): Query<MemoryQuery>) -> Response {
    let target = match memory_target(&q.target) {
        Ok(t) => t,
        Err(r) => return r,
    };
    match offload(move || crate::agent::memory::forget(&crate::agent::memory::dir(), &target)).await
    {
        Ok(Ok(existed)) => Json(json!({"forgotten": existed})).into_response(),
        Ok(Err(e)) => memory_err(e),
        Err(r) => r,
    }
}



/// A discovery scan runs no tests, so it has no readiness score. `agent::run_discovery_scan`
/// still stamps a ledger with every score at 100 and verdict "SCANNED" (agent.rs owns that);
/// until it stops, the API does not repeat the number: scores go out as null.
pub(crate) fn strip_discovery_scores(report: &mut serde_json::Value) {
    let Some(ledger) = report
        .get_mut("evidence_ledger")
        .and_then(|l| l.as_object_mut())
    else {
        return;
    };
    if ledger.get("gate_verdict").and_then(|v| v.as_str()) != Some("SCANNED") {
        return;
    }
    for k in [
        "overall_readiness",
        "composite_score",
        "value_score",
        "authority_score",
        "safety_score",
        "evidence_score",
    ] {
        if ledger.contains_key(k) {
            ledger.insert(k.to_string(), serde_json::Value::Null);
        }
    }
}

pub(crate) fn discovery_json(report: &crate::agent::AgentRunReport) -> serde_json::Value {
    let is_spa = report.discovered_routes.iter().any(|r| r.is_spa_shell);
    let mut report_json = serde_json::to_value(report).unwrap_or(serde_json::Value::Null);
    strip_discovery_scores(&mut report_json);
    json!({
        "target": report.target,
        "is_spa": is_spa,
        "app_architecture": report.app_architecture,
        "framework": report.framework,
        "detected_tech": report.detected_tech,
        "routes": report.discovered_routes,
        "count": report.discovered_routes.len(),
        "run_id": report.id,
        "report": report_json,
    })
}

async fn discover(app: &App, target: String, spec: Option<String>) -> Response {
    // Read-only crawl: the target (and any spec URL) must be in scope, prod is fine.
    let eg = match guard(app, &target, false).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let spec = match guard_spec(app, spec).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match blocking(app, move || {
        crate::agent::run_discovery_scan(&eg.url, spec.as_deref())
    })
    .await
    {
        Ok(Ok(report)) => Json(discovery_json(&report)).into_response(),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(r) => r,
    }
}

pub async fn agent_discover(State(app): State<Arc<App>>, Query(q): Query<DiscoverQuery>) -> Response {
    discover(&app, q.target, q.spec).await
}

pub async fn agent_discover_post(State(app): State<Arc<App>>, Json(b): Json<DiscoverBody>) -> Response {
    discover(&app, b.target, b.spec_url).await
}

pub async fn agent_directives_post(
    State(app): State<Arc<App>>,
    Json(b): Json<DirectivesSynthesizeBody>,
) -> Response {
    let eg = match guard(&app, &b.target, false).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let spec = match guard_spec(&app, b.spec_url).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let url = eg.url.clone();
    match blocking(&app, move || {
        let llm_cfg = crate::llm::LlmConfig::from_env().ok();
        let mut budget = crate::llm::Budget::new(3, std::time::Duration::from_secs(30));
        let directives = if let Some(ref cfg) = llm_cfg {
            crate::agent::recon::synthesize_directives(Some((cfg, &mut budget)), &url, spec.as_deref(), None)
        } else {
            crate::agent::recon::synthesize_directives(None, &url, spec.as_deref(), None)
        };
        (url, directives)
    })
    .await
    {
        Ok((target, directives)) => {
            let custom_instructions = directives.as_custom_instructions();
            (
                StatusCode::OK,
                Json(json!({
                    "target": target,
                    "directives": directives,
                    "custom_instructions": custom_instructions,
                    "focus_areas": directives.focus_areas,
                    "boundary_rules": directives.boundary_rules,
                    "rules_of_engagement": directives.rules_of_engagement,
                    "canary_token": directives.canary_token,
                })),
            )
                .into_response()
        }
        Err(r) => r,
    }
}



async fn crawl(app: &App, target: String, max_pages: Option<usize>) -> Response {
    let eg = match guard(app, &target, false).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let max = clamp_pages(max_pages);
    let url = eg.url.clone();
    match blocking(app, move || {
        crate::agent::crawl_and_discover_routes(&url, None, max)
    })
    .await
    {
        Ok((routes, tech_profile)) => Json(json!({
            "target": eg.url,
            "crawled_count": routes.len(),
            "routes": routes,
            "app_architecture": tech_profile.app_architecture,
            "framework": tech_profile.primary_framework,
            "detected_tech": tech_profile.detected_signals,
            "is_spa": tech_profile.is_spa,
        }))
        .into_response(),
        Err(r) => r,
    }
}

pub async fn agent_crawl_get(State(app): State<Arc<App>>, Query(q): Query<CrawlQuery>) -> Response {
    crawl(&app, q.target, q.max_pages).await
}

pub async fn agent_crawl_post(State(app): State<Arc<App>>, Json(b): Json<CrawlBody>) -> Response {
    crawl(&app, b.target, b.max_pages).await
}


pub(crate) fn retest_blocking(
    case: crate::agent::PlannedCase,
    url: String,
    is_spa: bool,
    run_id: Option<String>,
) -> Result<Option<crate::agent::CaseExecutionResult>, RetestError> {
    // Before anything is sent or written: the run being updated must be a run of this target.
    // Otherwise a (low-intrusion-checked) request for host A could overwrite the stored results
    // of a run that tested host B.
    if let Some(rid) = &run_id {
        let stored = crate::agent::load_agent_run(rid).map_err(|_| RetestError::NoSuchRun)?;
        if !same_target(&stored.target, &url) {
            return Err(RetestError::TargetMismatch);
        }
    }
    // A case can yield sub-results (`<id>-M1` mutation, `<id>-B` burst): store all of them so
    // none go stale; the primary result is the one returned.
    let results = crate::agent::execute_cases(&[case], &url, is_spa);
    if let Some(rid) = &run_id {
        for r in &results {
            // The result is still returned to the caller if it cannot be stored.
            if let Err(e) = crate::agent::update_run_case_result(rid, r) {
                eprintln!("retest: could not store the result on run {rid}: {e}");
            }
        }
    }
    Ok(results.into_iter().next())
}

pub async fn agent_retest(State(app): State<Arc<App>>, Json(body): Json<RetestPayload>) -> Response {
    // A planned case with a write method, a payload or an injection technique is intrusive.
    // Stateful chains and concurrency bursts send writes too.
    let intrusive = !network::is_safe_method(&body.case.method)
        || body.case.payload.is_some()
        || body.case.technique == "injection"
        || body
            .case
            .stateful_steps
            .as_ref()
            .is_some_and(|s| !s.is_empty())
        || body.case.concurrency_burst.is_some_and(|n| n > 0);
    // `run_id` becomes a path component under the data dir.
    if body
        .run_id
        .as_deref()
        .is_some_and(|r| !engine::valid_run_id(r))
    {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    let eg = match guard(&app, &body.target, intrusive).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let RetestPayload {
        case,
        is_spa,
        run_id,
        ..
    } = body;
    let res = blocking(&app, move || retest_blocking(case, eg.url, is_spa, run_id)).await;
    match res {
        Ok(Ok(Some(r))) => Json(r).into_response(),
        Ok(Ok(None)) => err(StatusCode::INTERNAL_SERVER_ERROR, "No execution result"),
        Ok(Err(RetestError::NoSuchRun)) => err(StatusCode::NOT_FOUND, "agent run not found"),
        Ok(Err(RetestError::TargetMismatch)) => err(
            StatusCode::CONFLICT,
            "target does not match the target stored on that run; nothing was sent or written",
        ),
        Err(r) => r,
    }
}

