//! REST API + single in-process job worker. Run state lives under
//! <data>/runs/<id>/ (status.json while queued/running, run.json when done).
//!
//! Every route except `GET /health` and the GET badge routes sits behind one bearer-token middleware ([`require_auth`]).
//! Every outbound HTTP action goes through [`guard`] (scope check, plus the nonprod gate for
//! intrusive actions) before it touches the network.
use crate::engine::{self, ScanOpts};
use crate::model::Profile;
use crate::network;
use crate::scope::{self, Scope};
use anyhow::{Result, bail};
use axum::Json;
use axum::Router;
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::future::IntoFuture;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, mpsc};

const MIN_TOKEN_CHARS: usize = 16;
/// Tokens that shipped in earlier versions or docs: refused even though they are long enough.
const BANNED_TOKENS: &[&str] = &["rh-dev-token-9f8e7d6c5b4a3210"];
/// Concurrent blocking probes (agent run/discover/crawl, network lab) before `429`.
const MAX_CONCURRENT_PROBES: usize = 4;
/// `max_pages` bounds for the crawler routes.
const DEFAULT_CRAWL_PAGES: usize = 25;
const MAX_CRAWL_PAGES: usize = 100;
const MAX_NOTES_CHARS: usize = 2000;

struct App {
    /// SHA-256 of the bearer token. Compared digest-to-digest so the comparison is constant-time
    /// and independent of the token length.
    token_digest: [u8; 32],
    /// Identity recorded on sign-offs: the server-assigned name of the credential, never client text.
    principal: String,
    tx: mpsc::Sender<(String, ScanOpts)>,
    allowed_roots: Vec<PathBuf>,
    scope: Option<PathBuf>,
    plugins: Option<PathBuf>,
    /// Run the worker is executing right now.
    active: Mutex<Option<String>>,
    /// Bounds concurrent blocking probes so a request loop cannot exhaust the blocking pool.
    probes: Arc<Semaphore>,
}

/// Authenticated caller, injected by the auth middleware.
#[derive(Clone, Debug)]
struct Principal(String);

// ------------------------------------------------------------------ run files

fn read_json(id: &str, file: &str) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(engine::run_dir(id).join(file)).ok()?).ok()
}

/// Update status.json atomically. Never creates the run directory: when a run was deleted
/// underneath the worker the write simply fails instead of resurrecting the directory.
fn write_status(id: &str, state: &str, error: Option<&str>) {
    let dir = engine::run_dir(id);
    let prev: serde_json::Value = std::fs::read_to_string(dir.join("status.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let target = prev
        .get("target")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let body = json!({"id": id, "state": state, "error": error, "target": target}).to_string();
    let _ = engine::write_atomic(&dir.join("status.json"), body.as_bytes());
}

fn write_queued(id: &str, target: &str) -> std::io::Result<()> {
    let dir = engine::run_dir(id);
    std::fs::create_dir_all(&dir)?;
    let body = json!({"id": id, "state": "queued", "error": null, "target": target}).to_string();
    engine::write_atomic(&dir.join("status.json"), body.as_bytes())
}

/// Queue lives in memory: anything queued/running when the server died is lost.
/// Returns the ids it marked.
fn mark_stale_runs() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(engine::data_dir().join("runs")) else {
        return vec![];
    };
    let mut stale = vec![];
    for e in rd.flatten() {
        let id = e.file_name().to_string_lossy().to_string();
        let Ok(t) = std::fs::read_to_string(e.path().join("status.json")) else {
            continue;
        };
        let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
        if matches!(v["state"].as_str(), Some("queued" | "running")) {
            write_status(
                &id,
                "error",
                Some("server restarted before the run finished"),
            );
            stale.push(id);
        }
    }
    stale
}

/// Is this run queued behind a worker or executing right now?
fn run_in_progress(app: &App, id: &str) -> bool {
    if app.active.lock().ok().and_then(|g| g.clone()).as_deref() == Some(id) {
        return true;
    }
    read_json(id, "status.json").is_some_and(|s| s["state"].as_str() == Some("running"))
}

// ------------------------------------------------------------------ startup

/// Token policy: no token, no server. There is deliberately no development fallback.
fn validate_token(raw: Option<&str>) -> Result<String> {
    let t = raw.unwrap_or("");
    if t.chars().count() < MIN_TOKEN_CHARS {
        bail!(
            "READYHAI_TOKEN is not set or shorter than {MIN_TOKEN_CHARS} characters; refusing to start an unauthenticated API (try: openssl rand -hex 24)"
        );
    }
    if !t.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        bail!(
            "READYHAI_TOKEN must be printable ASCII without spaces (it travels in an HTTP header)"
        );
    }
    if BANNED_TOKENS.contains(&t) {
        bail!("READYHAI_TOKEN is a publicly known example token; generate your own");
    }
    Ok(t.to_string())
}

fn validate_principal(raw: Option<&str>) -> Result<String> {
    let p = raw.unwrap_or("api-token");
    if p.is_empty()
        || p.len() > 64
        || !p
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._@:-".contains(c))
    {
        bail!("READYHAI_PRINCIPAL must be 1-64 characters of [A-Za-z0-9._@:-]");
    }
    Ok(p.to_string())
}

fn run_timeout() -> Duration {
    let secs = std::env::var("READYHAI_RUN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3600);
    Duration::from_secs(secs.clamp(60, 86_400))
}

pub fn serve(bind: &str) -> Result<()> {
    let token = validate_token(std::env::var("READYHAI_TOKEN").ok().as_deref())?;
    let principal = validate_principal(std::env::var("READYHAI_PRINCIPAL").ok().as_deref())?;
    let allowed_roots: Vec<PathBuf> = std::env::var("READYHAI_ALLOWED_ROOTS")
        .unwrap_or_default()
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    let scope = std::env::var("READYHAI_SCOPE").ok().map(PathBuf::from);
    let plugins = std::env::var("READYHAI_PLUGINS").ok().map(PathBuf::from);
    let limit = run_timeout();

    let stale = mark_stale_runs();
    // Containers of runs that died with the previous server would otherwise live on forever.
    let reaped = crate::tools::reap_dead_runs(&|id| {
        engine::valid_run_id(id)
            && (stale.iter().any(|s| s == id)
                || !engine::run_dir(id).exists()
                || engine::run_dir(id).join("run.json").exists())
    });
    if reaped > 0 {
        eprintln!("reaped {reaped} orphaned scanner container(s) from dead runs");
    }

    // One worker: scanner containers are memory-heavy; queue the rest.
    let (tx, rx) = mpsc::channel::<(String, ScanOpts)>(64);
    let app = Arc::new(App {
        token_digest: Sha256::digest(token.as_bytes()).into(),
        principal,
        tx,
        allowed_roots,
        scope,
        plugins,
        active: Mutex::new(None),
        probes: Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES)),
    });

    let rt = tokio::runtime::Runtime::new()?;
    let app2 = app.clone();
    let res: Result<()> = rt.block_on(async move {
        tokio::spawn(worker(app2.clone(), rx, limit));
        let router = build_router(app2);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        eprintln!("readyhai API on http://{bind}");

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = stop_tx.send(true);
        });
        let mut graceful = stop_rx.clone();
        let serving = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = graceful.wait_for(|v| *v).await;
            })
            .into_future();
        // Idle keep-alive connections must not hold the process up after SIGTERM/Ctrl-C.
        let mut forced = stop_rx;
        let forced = async move {
            let _ = forced.wait_for(|v| *v).await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        };
        tokio::select! {
            r = serving => r?,
            _ = forced => eprintln!("shutdown: connections did not drain within 10s, exiting"),
        }
        Ok(())
    });

    // Shutting down mid-scan: say so in the run's status and stop its containers now.
    if let Some(id) = app.active.lock().ok().and_then(|mut g| g.take()) {
        write_status(
            &id,
            "error",
            Some("server shut down before the run finished"),
        );
        crate::tools::reap_run(&id);
    }
    rt.shutdown_timeout(Duration::from_secs(3));
    res
}

/// Ctrl-C or SIGTERM (what `docker stop` and systemd send).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

async fn worker(app: Arc<App>, mut rx: mpsc::Receiver<(String, ScanOpts)>, limit: Duration) {
    while let Some((id, mut opts)) = rx.recv().await {
        // Deleted while it was still queued: nothing to run, nothing to recreate.
        if !engine::run_dir(&id).join("status.json").exists() {
            continue;
        }
        if let Ok(mut a) = app.active.lock() {
            *a = Some(id.clone());
        }
        write_status(&id, "running", None);
        opts.deadline = Some(Instant::now() + limit);
        let id2 = id.clone();
        let task = tokio::task::spawn_blocking(move || -> Result<()> {
            let run = engine::scan(&opts, &id2)?;
            crate::report::write(
                &run,
                &engine::run_dir(&id2).join("report"),
                &["html".into(), "json".into(), "sarif".into(), "junit".into()],
            )?;
            Ok(())
        });
        // The scan enforces the deadline itself (skips late checks, caps running tools); the
        // extra minute is its grace to wind down before the worker gives up on it.
        match tokio::time::timeout(limit + Duration::from_secs(60), task).await {
            Ok(Ok(Ok(()))) => write_status(&id, "done", None),
            Ok(Ok(Err(e))) => write_status(&id, "error", Some(&format!("{e:#}"))),
            Ok(Err(_)) => write_status(&id, "error", Some("worker panicked")),
            Err(_) => {
                let rid = id.clone();
                let _ = tokio::task::spawn_blocking(move || crate::tools::reap_run(&rid)).await;
                write_status(
                    &id,
                    "error",
                    Some(&format!(
                        "run exceeded the {}s wall-clock limit (READYHAI_RUN_TIMEOUT_SECS)",
                        limit.as_secs()
                    )),
                );
            }
        }
        if let Ok(mut a) = app.active.lock() {
            *a = None;
        }
    }
}

// ------------------------------------------------------------------ router and auth

fn build_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(api_index))
        .route("/ui", get(api_index))
        .route("/api/agent/status", get(agent_status))
        .route(
            "/api/agent/discover",
            get(agent_discover).post(agent_discover_post),
        )
        .route(
            "/api/agent/crawl",
            get(agent_crawl_get).post(agent_crawl_post),
        )
        .route("/api/agent/run", post(agent_run))
        .route("/api/agent/runs", get(agent_runs_list))
        .route(
            "/api/agent/runs/{id}",
            get(agent_run_get).delete(agent_run_delete),
        )
        .route("/api/agent/runs/{id}/approve", post(agent_approve))
        .route("/api/agent/runs/{id}/reject", post(agent_reject))
        .route("/api/agent/runs/{id}/report/{fmt}", get(agent_run_report))
        .route("/api/agent/retest", post(agent_retest))
        .route("/api/scans", get(api_scans_list).post(api_scans_create))
        .route("/api/scans/{id}", get(api_scan_get).delete(api_scan_delete))
        .route("/api/scans/{id}/report/{fmt}", get(api_scan_report))
        .route("/api/agent/requester-ip", get(get_requester_ip))
        .route("/api/network/requester-ip", get(get_requester_ip))
        .route("/api/network/regress", post(network_regress))
        .route("/api/network/curl", post(network_curl))
        .route("/api/network/deep-audit", post(network_deep_audit))
        .route("/api/network/multi-region", post(network_multi_region))
        .route("/api/network/export-har", post(network_export_har))
        .route("/api/github/pr-comment", post(github_pr_comment))
        .route("/api/badges/gate", get(badge_gate))
        .route("/api/badges/ledger", get(badge_ledger))
        .route("/api/badges/network", get(badge_network))
        .route(
            "/health",
            get(|| async { Json(json!({"status": "ok", "version": engine::VERSION})) }),
        )
        .route("/checks", get(list_checks))
        .route("/runs", post(create_run).get(list_runs))
        .route("/runs/{id}", get(get_run))
        .route("/runs/{id}/findings", get(get_findings))
        .route("/runs/{id}/report/{fmt}", get(get_report))
        // The fallback is added BEFORE the layer so unknown paths are authenticated too (a 404
        // for an anonymous caller would map the surface).
        .fallback(|| async { err(StatusCode::NOT_FOUND, "not found") })
        .layer(middleware::from_fn_with_state(app.clone(), require_auth))
        .with_state(app)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(json!({"error": "missing or bad bearer token"})),
    )
        .into_response()
}

fn bearer_ok(app: &App, h: &HeaderMap) -> bool {
    let Some(v) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some((scheme, tok)) = v.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    let got: [u8; 32] = Sha256::digest(tok.as_bytes()).into();
    got.iter()
        .zip(app.token_digest.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Paths served without a token (GET only): the health probe and the SVG status badges, which are
/// read-only and render only a sanitised status/score from the query string (no run data, no secrets).
const PUBLIC_GET: &[&str] = &[
    "/health",
    "/api/badges/gate",
    "/api/badges/ledger",
    "/api/badges/network",
];

fn is_public_get(path: &str) -> bool {
    PUBLIC_GET.contains(&path)
}

/// The single authentication point: `Authorization: Bearer <token>` on everything except
/// the public GETs in [`PUBLIC_GET`] (/health and the badges).
/// Handlers never check credentials themselves, so a new route cannot forget to.
async fn require_auth(State(app): State<Arc<App>>, mut req: Request, next: Next) -> Response {
    let public = req.method() == Method::GET && is_public_get(req.uri().path());
    if !public {
        if !bearer_ok(&app, req.headers()) {
            return unauthorized();
        }
        req.extensions_mut()
            .insert(Principal(app.principal.clone()));
    }
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    resp
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({"error": msg.into()}))).into_response()
}

// ------------------------------------------------------------------ shared guards

/// THE egress guard for server-initiated HTTP: scope check plus, for `intrusive` actions, the
/// nonprod gate. Returns the normalised URL to use (the one whose host was approved).
fn guard(app: &App, url: &str, intrusive: bool) -> Result<scope::Egress, Response> {
    let sc = match &app.scope {
        Some(p) => match Scope::load(p) {
            Ok(s) => Some(s),
            Err(_) => {
                return Err(err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "READYHAI_SCOPE file cannot be read",
                ));
            }
        },
        None => None,
    };
    scope::egress_guard(url, sc.as_ref(), intrusive)
        .map_err(|e| err(StatusCode::FORBIDDEN, format!("{e:#}")))
}

/// Optional spec/OpenAPI URL: blank means none, anything else must pass the guard too.
fn guard_spec(app: &App, spec: Option<String>) -> Result<Option<String>, Response> {
    match spec.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => Ok(Some(guard(app, s, false)?.url)),
    }
}

/// Run blocking work on the blocking pool, at most [`MAX_CONCURRENT_PROBES`] at a time. The
/// permit travels with the work, so a client that hangs up does not leak it.
async fn blocking<T: Send + 'static>(
    app: &App,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Response> {
    let permit = app.probes.clone().try_acquire_owned().map_err(|_| {
        err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent probes; retry when one finishes",
        )
    })?;
    tokio::task::spawn_blocking(move || {
        let out = f();
        drop(permit);
        out
    })
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))
}

/// Server-mode options + the same precheck for `/runs` and `/api/scans`: allowed roots, scope.
fn prepare_scan(app: &App, opts: &mut ScanOpts) -> Result<(), Response> {
    opts.server = true;
    opts.allowed_roots = app.allowed_roots.clone();
    opts.scope = app.scope.clone();
    opts.plugins = app.plugins.clone();
    // Cheap synchronous validation: reject with 400 before any run dir exists.
    crate::mcp::precheck(opts).map_err(|e| err(StatusCode::BAD_REQUEST, format!("{e:#}")))
}

/// Create the run directory + queued status and hand the job to the worker.
fn enqueue(app: &App, opts: ScanOpts) -> Result<String, Response> {
    let id = engine::new_run_id();
    if write_queued(&id, &opts.target).is_err() {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot create run directory",
        ));
    }
    if app.tx.try_send((id.clone(), opts)).is_err() {
        write_status(&id, "error", Some("queue full"));
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "queue full"));
    }
    Ok(id)
}

// ------------------------------------------------------------------ index, status

async fn api_index() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "name": "ReadyHai QA Engine & Production Gate API",
            "version": env!("CARGO_PKG_VERSION"),
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
                "agent_retest": "/api/agent/retest"
            }
        })),
    )
}

async fn agent_status() -> Response {
    let res = tokio::task::spawn_blocking(move || {
        let cfg = match crate::llm::LlmConfig::from_env() {
            Ok(c) => c,
            Err(e) => return (StatusCode::OK, Json(json!({"status": "offline", "error": e.to_string()}))),
        };
        let t0 = std::time::Instant::now();
        let is_ok = crate::llm::probe(&cfg);
        let latency = t0.elapsed().as_millis();
        let models_val = crate::llm::query_models(&cfg).unwrap_or(json!({}));
        (
            StatusCode::OK,
            Json(json!({
                "status": if is_ok { "online" } else { "offline" },
                "model": cfg.model,
                "provider": cfg.provider.id,
                "base_url": cfg.base_url().unwrap_or_default(),
                "latency_ms": latency,
                "models_list": models_val,
                "capabilities": ["multi_agent", "planner", "explorer", "triager", "readiness_gate", "owasp_agentic"]
            })),
        )
    })
    .await;

    match res {
        Ok((code, json)) => (code, json).into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "status probe failed"),
    }
}

// ------------------------------------------------------------------ agent routes

async fn agent_run(
    State(app): State<Arc<App>>,
    Json(mut req): Json<crate::agent::AgentRunRequest>,
) -> Response {
    // The agent sends attack payloads and write methods: prod hosts are refused outright.
    match guard(&app, &req.target, true) {
        Ok(e) => req.target = e.url,
        Err(r) => return r,
    }
    match guard_spec(&app, req.spec_url.take()) {
        Ok(s) => req.spec_url = s,
        Err(r) => return r,
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

async fn agent_runs_list() -> Response {
    let list = crate::agent::list_agent_full_runs();
    Json(json!({"runs": list})).into_response()
}

async fn agent_run_get(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    match crate::agent::load_agent_run(&id) {
        Ok(rep) => Json(rep).into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "agent run not found"),
    }
}

async fn agent_run_report(Path((id, fmt)): Path<(String, String)>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    let (file, ctype) = match fmt.as_str() {
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
    let rep_dir = crate::agent::agent_runs_dir().join(&id).join("report");
    let rep_file = rep_dir.join(file);
    if !rep_file.exists()
        && let Ok(rep) = crate::agent::load_agent_run(&id)
    {
        let _ = crate::agent::generate_agent_report_formats(
            &rep,
            &rep_dir,
            &[
                "html".into(),
                "markdown".into(),
                "sarif".into(),
                "json".into(),
                "junit".into(),
            ],
        );
    }
    match std::fs::read(&rep_file) {
        Ok(b) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, ctype.parse().unwrap());
            if fmt == "html" {
                headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline'".parse().unwrap());
            } else {
                let ext = if fmt == "junit" || fmt == "xml" {
                    "xml"
                } else if fmt == "markdown" || fmt == "md" {
                    "md"
                } else {
                    &fmt
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
        Err(_) => err(StatusCode::NOT_FOUND, "report not found"),
    }
}

async fn agent_run_delete(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
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
    match crate::agent::delete_agent_run(&id) {
        Ok(_) => Json(json!({"deleted": id, "status": "ok"})).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Sign-off body. There is deliberately no `user` field: the approver is the authenticated
/// principal. Unknown fields (an old client still sending `user`) are ignored, never recorded.
#[derive(Deserialize)]
struct ApprovalPayload {
    #[serde(default)]
    notes: String,
}

fn clip_notes(s: &str) -> String {
    s.chars().take(MAX_NOTES_CHARS).collect()
}

async fn agent_approve(
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
fn signoff_err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let status = if msg.ends_with("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    err(status, msg)
}

async fn agent_reject(
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

#[derive(Deserialize)]
struct DiscoverQuery {
    target: String,
    #[serde(default, alias = "spec_url")]
    spec: Option<String>,
}

#[derive(Deserialize)]
struct DiscoverBody {
    target: String,
    #[serde(default, alias = "spec")]
    spec_url: Option<String>,
}

/// A discovery scan runs no tests, so it has no readiness score. `agent::run_discovery_scan`
/// still stamps a ledger with every score at 100 and verdict "SCANNED" (agent.rs owns that);
/// until it stops, the API does not repeat the number: scores go out as null.
fn strip_discovery_scores(report: &mut serde_json::Value) {
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

fn discovery_json(report: &crate::agent::AgentRunReport) -> serde_json::Value {
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
    let eg = match guard(app, &target, false) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let spec = match guard_spec(app, spec) {
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

async fn agent_discover(State(app): State<Arc<App>>, Query(q): Query<DiscoverQuery>) -> Response {
    discover(&app, q.target, q.spec).await
}

async fn agent_discover_post(State(app): State<Arc<App>>, Json(b): Json<DiscoverBody>) -> Response {
    discover(&app, b.target, b.spec_url).await
}

#[derive(Deserialize)]
struct CrawlQuery {
    target: String,
    #[serde(default)]
    max_pages: Option<usize>,
}

#[derive(Deserialize)]
struct CrawlBody {
    target: String,
    #[serde(default)]
    max_pages: Option<usize>,
}

/// `max_pages` default 25, hard maximum 100 (also bounds the work per request).
fn clamp_pages(p: Option<usize>) -> usize {
    p.unwrap_or(DEFAULT_CRAWL_PAGES).clamp(1, MAX_CRAWL_PAGES)
}

async fn crawl(app: &App, target: String, max_pages: Option<usize>) -> Response {
    let eg = match guard(app, &target, false) {
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

async fn agent_crawl_get(State(app): State<Arc<App>>, Query(q): Query<CrawlQuery>) -> Response {
    crawl(&app, q.target, q.max_pages).await
}

async fn agent_crawl_post(State(app): State<Arc<App>>, Json(b): Json<CrawlBody>) -> Response {
    crawl(&app, b.target, b.max_pages).await
}

#[derive(Deserialize)]
struct RetestPayload {
    target: String,
    case: crate::agent::PlannedCase,
    #[serde(default)]
    is_spa: bool,
    #[serde(default)]
    run_id: Option<String>,
}

async fn agent_retest(State(app): State<Arc<App>>, Json(body): Json<RetestPayload>) -> Response {
    // A planned case with a write method, a payload or an injection technique is intrusive.
    let intrusive = !network::is_safe_method(&body.case.method)
        || body.case.payload.is_some()
        || body.case.technique == "injection";
    let eg = match guard(&app, &body.target, intrusive) {
        Ok(e) => e,
        Err(r) => return r,
    };
    // `run_id` becomes a path component under the data dir.
    if body
        .run_id
        .as_deref()
        .is_some_and(|r| !engine::valid_run_id(r))
    {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    let RetestPayload {
        case,
        is_spa,
        run_id,
        ..
    } = body;
    let res = blocking(&app, move || {
        let results = crate::agent::execute_cases(&[case], &eg.url, is_spa);
        let first = results.into_iter().next();
        if let (Some(r), Some(run_id)) = (&first, &run_id) {
            let _ = crate::agent::update_run_case_result(run_id, r);
        }
        first
    })
    .await;
    match res {
        Ok(Some(r)) => Json(r).into_response(),
        Ok(None) => err(StatusCode::INTERNAL_SERVER_ERROR, "No execution result"),
        Err(r) => r,
    }
}

async fn get_requester_ip(headers: HeaderMap) -> Response {
    // First call may reach out to IP-echo services: keep it off the async threads.
    let Ok(info) = tokio::task::spawn_blocking(network::detect_requester_public_ip).await else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "ip detection failed");
    };
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string());

    (
        StatusCode::OK,
        Json(json!({
            "egress_public_ip": info.egress_public_ip,
            "ip_type": info.ip_type,
            "is_private": info.is_private,
            "allowlist_guidance": info.allowlist_guidance,
            "detected_via": info.detected_via,
            "detected_at": info.detected_at,
            "client_inbound_ip": client_ip,
        })),
    )
        .into_response()
}

// ------------------------------------------------------------------ network lab routes

/// Shared shape of the network routes: guard (scope; nonprod when intrusive), normalise the
/// target, run the probe on the bounded blocking pool, map validation errors to 400.
async fn network_route<T: serde::Serialize + Send + 'static>(
    app: &App,
    target: &str,
    intrusive: bool,
    run: impl FnOnce(String) -> Result<T> + Send + 'static,
) -> Response {
    let eg = match guard(app, target, intrusive) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match blocking(app, move || run(eg.url)).await {
        Ok(Ok(report)) => Json(report).into_response(),
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
        Err(r) => r,
    }
}

async fn network_regress(
    State(app): State<Arc<App>>,
    Json(req): Json<network::RegressRequest>,
) -> Response {
    let (intrusive, target) = (req.is_intrusive(), req.target.clone());
    network_route(&app, &target, intrusive, move |url| {
        let mut req = req;
        req.target = url;
        network::run_regress_test(&req)
    })
    .await
}

async fn network_curl(
    State(app): State<Arc<App>>,
    Json(req): Json<network::CurlTestRequest>,
) -> Response {
    let (intrusive, target) = (req.is_intrusive(), req.target.clone());
    network_route(&app, &target, intrusive, move |url| {
        let mut req = req;
        req.target = url;
        network::execute_curl_test(&req)
    })
    .await
}

async fn network_deep_audit(
    State(app): State<Arc<App>>,
    Json(req): Json<network::DeepAuditRequest>,
) -> Response {
    let target = req.target.clone();
    network_route(&app, &target, false, move |url| {
        let mut req = req;
        req.target = url;
        network::run_deep_audit(&req)
    })
    .await
}

async fn network_multi_region(
    State(app): State<Arc<App>>,
    Json(req): Json<network::MultiRegionRequest>,
) -> Response {
    let target = req.target.clone();
    network_route(&app, &target, false, move |url| {
        let mut req = req;
        req.target = url;
        network::run_multi_region_audit(&req)
    })
    .await
}

/// Pure transformation of a report the caller already holds: no egress, so no guard.
async fn network_export_har(Json(report): Json<network::RegressReport>) -> Response {
    Json(network::generate_har_from_regress(&report)).into_response()
}

// ------------------------------------------------------------------ scans (/runs and /api/scans)

async fn list_checks(State(app): State<Arc<App>>) -> Response {
    let list: Vec<_> = crate::checks::all(app.plugins.as_deref())
        .into_iter()
        .map(|c| json!({"id": c.id, "title": c.title, "kinds": c.kinds, "min_profile": c.min_profile, "tool": c.tool, "intrusive": c.intrusive}))
        .collect();
    Json(list).into_response()
}

async fn create_run(State(app): State<Arc<App>>, Json(mut opts): Json<ScanOpts>) -> Response {
    if let Err(r) = prepare_scan(&app, &mut opts) {
        return r;
    }
    match enqueue(&app, opts) {
        Ok(id) => (
            StatusCode::ACCEPTED,
            Json(json!({"id": id, "state": "queued"})),
        )
            .into_response(),
        Err(r) => r,
    }
}

async fn get_run(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    let Some(status) = read_json(&id, "status.json") else {
        return err(StatusCode::NOT_FOUND, "no such run");
    };
    let mut out = status;
    if let Some(mut run) = read_json(&id, "run.json") {
        run.as_object_mut().map(|o| o.remove("findings"));
        out["state"] = json!("done");
        for k in ["verdict", "reasons", "categories", "checks"] {
            out[k] = run[k].clone();
        }
        out["run"] = run;
    }
    Json(out).into_response()
}

async fn get_findings(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    match read_json(&id, "run.json") {
        Some(r) => Json(r["findings"].clone()).into_response(),
        None => err(StatusCode::NOT_FOUND, "run not finished or not found"),
    }
}

async fn get_report(Path((id, fmt)): Path<(String, String)>) -> Response {
    let (file, ctype) = match fmt.as_str() {
        "html" => ("readyhai-report.html", "text/html; charset=utf-8"),
        "json" => ("readyhai-report.json", "application/json"),
        "sarif" => ("readyhai-report.sarif", "application/sarif+json"),
        "junit" => ("readyhai-report.junit.xml", "application/xml"),
        _ => return err(StatusCode::BAD_REQUEST, "format: html|json|sarif|junit"),
    };
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    match std::fs::read(engine::run_dir(&id).join("report").join(file)) {
        Ok(b) => (
            [
                (header::CONTENT_TYPE, ctype),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
                ),
            ],
            b,
        )
            .into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "report not ready"),
    }
}

#[derive(serde::Deserialize)]
struct TriggerScanReq {
    target: String,
    #[serde(default = "default_profile_str")]
    profile: String,
}
fn default_profile_str() -> String {
    "quick".into()
}

async fn api_scans_create(
    State(app): State<Arc<App>>,
    Json(req): Json<TriggerScanReq>,
) -> Response {
    let target = req.target.trim().to_string();
    if target.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "Target repository or directory cannot be empty",
        );
    }
    let (profile, profile_name) = match req.profile.to_lowercase().as_str() {
        "quick" => (Profile::Quick, "quick"),
        "standard" => (Profile::Standard, "standard"),
        "deep" => (Profile::Deep, "deep"),
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                "profile must be quick|standard|deep",
            );
        }
    };
    let mut opts = ScanOpts {
        target: target.clone(),
        profile: Some(profile),
        ..Default::default()
    };
    // Same precheck as POST /runs: allowed roots for paths, scope for every network destination.
    if let Err(r) = prepare_scan(&app, &mut opts) {
        return r;
    }
    match enqueue(&app, opts) {
        Ok(id) => (
            StatusCode::ACCEPTED,
            Json(json!({"id": id, "state": "queued", "target": target, "profile": profile_name})),
        )
            .into_response(),
        Err(r) => r,
    }
}

async fn api_scans_list() -> Response {
    let Ok(rd) = std::fs::read_dir(engine::data_dir().join("runs")) else {
        return Json(json!({"scans": []})).into_response();
    };
    let mut ids: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| engine::valid_run_id(n))
        .collect();
    ids.sort_unstable_by(|a, b| b.cmp(a));
    ids.truncate(50);

    let scans: Vec<serde_json::Value> = ids
        .into_iter()
        .map(|id| {
            let run_val = read_json(&id, "run.json");
            let st = read_json(&id, "status.json");
            let target_raw = run_val
                .as_ref()
                .and_then(|r| r["target"]["raw"].as_str())
                .or_else(|| st.as_ref().and_then(|s| s["target"].as_str()))
                .unwrap_or_default();

            let rep_dir = engine::run_dir(&id).join("report");
            let has_html = rep_dir.join("readyhai-report.html").exists() || run_val.is_some();
            let has_json = rep_dir.join("readyhai-report.json").exists() || run_val.is_some();
            let has_sarif = rep_dir.join("readyhai-report.sarif").exists() || run_val.is_some();
            let has_junit = rep_dir.join("readyhai-report.junit.xml").exists() || run_val.is_some();

            let findings_count = run_val
                .as_ref()
                .and_then(|r| r["findings"].as_array())
                .map(|f| f.len())
                .unwrap_or(0);
            let hard_fail_count = run_val
                .as_ref()
                .and_then(|r| r["findings"].as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("critical"))
                        .count()
                })
                .unwrap_or(0);

            let kind = run_val
                .as_ref()
                .and_then(|r| r["target"]["kind"].as_str())
                .unwrap_or("repo");
            let profile = run_val
                .as_ref()
                .and_then(|r| r["profile"].as_str())
                .unwrap_or("quick");
            let verdict = run_val
                .as_ref()
                .and_then(|r| r["verdict"].as_str())
                .unwrap_or("UNKNOWN");
            let state = st
                .as_ref()
                .and_then(|s| s["state"].as_str())
                .unwrap_or(if run_val.is_some() { "done" } else { "unknown" });
            let started = run_val
                .as_ref()
                .and_then(|r| r["started"].as_str())
                .or_else(|| st.as_ref().and_then(|s| s["started"].as_str()));
            let finished = run_val.as_ref().and_then(|r| r["finished"].as_str());
            let reasons = run_val
                .as_ref()
                .and_then(|r| r["reasons"].as_array())
                .cloned()
                .unwrap_or_default();
            let categories = run_val
                .as_ref()
                .and_then(|r| r["categories"].as_object())
                .cloned()
                .unwrap_or_default();

            json!({
                "id": id,
                "target": target_raw,
                "kind": kind,
                "profile": profile,
                "verdict": verdict,
                "state": state,
                "started": started,
                "finished": finished,
                "reasons": reasons,
                "findings_count": findings_count,
                "hard_fail_count": hard_fail_count,
                "categories": categories,
                "reports": {
                    "html": has_html,
                    "json": has_json,
                    "sarif": has_sarif,
                    "junit": has_junit,
                }
            })
        })
        .collect();

    Json(json!({"scans": scans})).into_response()
}

async fn api_scan_get(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    let st = read_json(&id, "status.json");
    let Some(run_val) = read_json(&id, "run.json") else {
        if let Some(status) = st {
            let target = status["target"].as_str().unwrap_or_default();
            return Json(json!({
                "id": id,
                "version": engine::VERSION,
                "target": { "kind": "repo", "raw": target, "path": "" },
                "profile": "quick",
                "started": engine::now(),
                "finished": null,
                "verdict": if status["state"].as_str() == Some("error") { "FAIL" } else { "RUNNING" },
                "state": status["state"],
                "reasons": if status["state"].as_str() == Some("error") { vec![status["error"].as_str().unwrap_or("scan error").to_string()] } else { vec!["Scan in progress...".to_string()] },
                "findings": [],
                "checks": [],
                "categories": []
            })).into_response();
        }
        return err(StatusCode::NOT_FOUND, "scan run not found");
    };
    let rep_dir = engine::run_dir(&id).join("report");
    if !rep_dir.join("readyhai-report.html").exists()
        && let Ok(run_struct) = serde_json::from_value::<crate::model::Run>(run_val.clone())
    {
        let _ = crate::report::write(
            &run_struct,
            &rep_dir,
            &["html".into(), "json".into(), "sarif".into(), "junit".into()],
        );
    }
    Json(run_val).into_response()
}

async fn api_scan_report(Path((id, fmt)): Path<(String, String)>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    let (file, ctype) = match fmt.as_str() {
        "html" => ("readyhai-report.html", "text/html; charset=utf-8"),
        "json" => ("readyhai-report.json", "application/json"),
        "sarif" => ("readyhai-report.sarif", "application/sarif+json"),
        "junit" => ("readyhai-report.junit.xml", "application/xml"),
        _ => return err(StatusCode::BAD_REQUEST, "format: html|json|sarif|junit"),
    };
    let rep_dir = engine::run_dir(&id).join("report");
    let rep_file = rep_dir.join(file);
    if !rep_file.exists()
        && let Some(run_val) = read_json(&id, "run.json")
        && let Ok(run_struct) = serde_json::from_value::<crate::model::Run>(run_val)
    {
        let _ = crate::report::write(
            &run_struct,
            &rep_dir,
            &["html".into(), "json".into(), "sarif".into(), "junit".into()],
        );
    }
    match std::fs::read(&rep_file) {
        Ok(b) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, ctype.parse().unwrap());
            if fmt == "html" {
                headers.insert(
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
                        .parse()
                        .unwrap(),
                );
            } else {
                let ext = if fmt == "junit" { "xml" } else { &fmt };
                headers.insert(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"readyhai-{}-{}.{}\"", id, fmt, ext)
                        .parse()
                        .unwrap(),
                );
            }
            (headers, b).into_response()
        }
        Err(_) => err(StatusCode::NOT_FOUND, "report not ready or not found"),
    }
}

/// Deleting a queued run cancels it (the worker skips runs whose directory is gone); a running
/// one is refused with 409 rather than having its directory removed underneath the scan.
async fn api_scan_delete(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    if run_in_progress(&app, &id) {
        return err(
            StatusCode::CONFLICT,
            "run is in progress; delete it after it finishes",
        );
    }
    let dir = engine::run_dir(&id);
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
        (StatusCode::OK, Json(json!({"deleted": id}))).into_response()
    } else {
        err(StatusCode::NOT_FOUND, "run not found")
    }
}

/// Last 50 runs (newest first): id, state, target, verdict.
fn list_runs_json() -> Vec<serde_json::Value> {
    let Ok(rd) = std::fs::read_dir(engine::data_dir().join("runs")) else {
        return vec![];
    };
    let mut ids: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| engine::valid_run_id(n))
        .collect();
    ids.sort_unstable_by(|a, b| b.cmp(a)); // ids start with a UTC timestamp
    ids.truncate(50);
    ids.into_iter()
        .map(|id| {
            let st = read_json(&id, "status.json");
            let run = read_json(&id, "run.json");
            json!({
                "id": id,
                "state": st.as_ref().and_then(|s| s["state"].as_str()).unwrap_or(if run.is_some() { "done" } else { "unknown" }),
                "target": run.as_ref().and_then(|r| r["target"]["raw"].as_str()),
                "verdict": run.as_ref().and_then(|r| r["verdict"].as_str()),
            })
        })
        .collect()
}

async fn list_runs() -> Response {
    Json(list_runs_json()).into_response()
}

// ------------------------------------------------------------------ PR comment and badges

#[derive(Deserialize)]
struct PrCommentPayload {
    /// Accepted for compatibility with older clients; the comment heading is fixed.
    #[serde(default)]
    #[allow(dead_code)]
    title: Option<String>,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    score: Option<i32>,
    #[serde(default)]
    commit_sha: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    findings_count: Option<usize>,
    #[serde(default)]
    ledger_conformance: Option<i32>,
    #[serde(default)]
    ledger_rbac: Option<i32>,
    #[serde(default)]
    ledger_resilience: Option<i32>,
    #[serde(default)]
    ledger_observability: Option<i32>,
}

/// Escape text for XML/SVG (text nodes and attribute values), after cutting it to `max` chars.
fn xml_escape(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control()).take(max) {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Inline value for a markdown code span: nothing that can close the span or start a new line.
fn md_code(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '`' { '\'' } else { c })
        .take(max)
        .collect()
}

fn pillar(score: Option<i32>) -> String {
    match score {
        Some(s) => format!("{}/100", s.clamp(0, 100)),
        None => "not evaluated".to_string(),
    }
}

/// Build the PR comment from what the caller supplied and nothing else. Missing data is shown as
/// "not evaluated"; there are no default scores and no canned "all checks passed" prose.
fn pr_comment_markdown(p: &PrCommentPayload) -> (String, String) {
    let verdict = p.verdict.as_deref().map(|v| v.trim().to_uppercase());
    let known = verdict
        .as_deref()
        .filter(|v| matches!(*v, "PASS" | "WARN" | "FAIL"));
    let (label, badge, color, status) = match known {
        Some("PASS") => ("PASS", "PASS", "brightgreen", "🟢 **READY FOR MERGE**"),
        Some("WARN") => ("WARN", "WARN", "yellow", "🟡 **MERGE WITH CAUTION**"),
        Some(_) => ("FAIL", "FAIL", "red", "🔴 **BLOCKED: QUALITY GATE FAILED**"),
        None => (
            "NOT EVALUATED",
            "not%20evaluated",
            "lightgrey",
            "⚪ **NOT EVALUATED: no gate verdict was supplied**",
        ),
    };
    let score = match (known, p.score) {
        (Some(_), Some(s)) => format!(" ({}/100)", s.clamp(0, 100)),
        _ => String::new(),
    };
    let target = p
        .target
        .as_deref()
        .map(|t| md_code(t, 200))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "not provided".into());
    let commit = p
        .commit_sha
        .as_deref()
        .map(|t| md_code(t, 64))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "not provided".into());
    let findings = p
        .findings_count
        .map(|n| format!("{n} unresolved blocking finding(s)"))
        .unwrap_or_else(|| "not evaluated".into());
    let note = match (&verdict, known) {
        (Some(v), None) if !v.is_empty() => format!(
            "\n> Unrecognised verdict `{}`; expected PASS, WARN or FAIL.\n",
            md_code(v, 40)
        ),
        _ => String::new(),
    };

    let md = format!(
        "## 🛡️ ReadyHai Quality Gate: {label}{score}\n\n![ReadyHai Status](https://img.shields.io/badge/ReadyHai-{badge}-{color}.svg)\n> **Target:** `{target}` | **Commit:** `{commit}` | **Status:** {status}\n{note}\n### 📊 4-Pillar Evidence Ledger\n| Pillar | Score |\n|---|---|\n| **Contract Conformance** | {} |\n| **RBAC Authorization** | {} |\n| **Failure Resilience** | {} |\n| **Observability & Tracing** | {} |\n\n**Findings:** {findings}\n\n<details>\n<summary><b>🛠️ Run Verification Locally via ReadyHai CLI</b></summary>\n\n```bash\n# Verify PR locally with the exact gate parameters\nreadyhai scan . --profile quick --format sarif,html --out readyhai-report\n```\n</details>\n\n*Automated quality gate posted by [ReadyHai](https://github.com/deziss/readyhai) · Self-hosted QA tester & readiness gate.*\n",
        pillar(p.ledger_conformance),
        pillar(p.ledger_rbac),
        pillar(p.ledger_resilience),
        pillar(p.ledger_observability),
    );
    let badge_md =
        format!("![ReadyHai](https://img.shields.io/badge/ReadyHai-{badge}-{color}.svg)");
    (md, badge_md)
}

async fn github_pr_comment(Json(p): Json<PrCommentPayload>) -> Response {
    let (md, badge_md) = pr_comment_markdown(&p);

    let workflow_yaml = "name: ReadyHai Production Readiness Gate\non: [pull_request, push]\n\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n\n      - name: Install ReadyHai\n        run: |\n          curl -sSfL https://github.com/deziss/readyhai/releases/latest/download/readyhai-linux-x86_64.tar.gz | sudo tar xz -C /usr/local/bin\n\n      - name: Execute Quality & Network Gate\n        run: |\n          readyhai scan . --profile quick --format sarif,html --out readyhai-report\n\n      - name: Upload SARIF to GitHub Code Scanning\n        if: always()\n        uses: github/codeql-action/upload-sarif@v3\n        with:\n          sarif_file: readyhai-report/readyhai-report.sarif\n";

    Json(json!({
        "markdown": md,
        "github_action_yaml": workflow_yaml,
        "badge_markdown": badge_md,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct BadgeQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    score: Option<String>,
}

const BADGE_VALUE_MAX: usize = 24;

fn svg_response(svg: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'",
            ),
        ],
        svg,
    )
        .into_response()
}

fn gate_svg(status: Option<&str>) -> String {
    let (color, text) = match status.map(|s| s.trim().to_uppercase()).as_deref() {
        Some("PASS") => ("#22c55e", "PASS"),
        Some("WARN") => ("#eab308", "WARN"),
        Some("FAIL") => ("#ef4444", "FAIL"),
        // missing or unrecognised input is never shown as a pass (or as a made-up fail)
        _ => ("#6b7280", "n/a"),
    };
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="128" height="20" role="img" aria-label="ReadyHai: {text}">
  <linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="a"><rect width="128" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)">
    <rect width="68" height="20" fill="#1e293b"/>
    <rect x="68" width="60" height="20" fill="{color}"/>
    <rect width="128" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="350" y="140" transform="scale(.1)" fill="#fff">ReadyHai</text>
    <text x="980" y="140" transform="scale(.1)" fill="#fff" font-weight="bold">{text}</text>
  </g>
</svg>"##
    )
}

fn ledger_svg(score: Option<&str>) -> String {
    let score = xml_escape(score.unwrap_or("n/a"), BADGE_VALUE_MAX);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="148" height="20" role="img" aria-label="Ledger: {score}">
  <clipPath id="a"><rect width="148" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)">
    <rect width="88" height="20" fill="#0f172a"/>
    <rect x="88" width="60" height="20" fill="#3b82f6"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="450" y="140" transform="scale(.1)" fill="#fff">Evidence Ledger</text>
    <text x="1180" y="140" transform="scale(.1)" fill="#fff" font-weight="bold">{score}</text>
  </g>
</svg>"##
    )
}

fn network_svg(status: Option<&str>) -> String {
    let status = xml_escape(status.unwrap_or("n/a"), BADGE_VALUE_MAX);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="156" height="20" role="img" aria-label="Network: {status}">
  <clipPath id="a"><rect width="156" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)">
    <rect width="84" height="20" fill="#18181b"/>
    <rect x="84" width="72" height="20" fill="#10b981"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="430" y="140" transform="scale(.1)" fill="#fff">Network Mesh</text>
    <text x="1200" y="140" transform="scale(.1)" fill="#fff" font-weight="bold">{status}</text>
  </g>
</svg>"##
    )
}

async fn badge_gate(Query(q): Query<BadgeQuery>) -> Response {
    svg_response(gate_svg(q.status.as_deref()))
}

async fn badge_ledger(Query(q): Query<BadgeQuery>) -> Response {
    svg_response(ledger_svg(q.score.as_deref()))
}

async fn badge_network(Query(q): Query<BadgeQuery>) -> Response {
    svg_response(network_svg(q.status.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::engine::ENV_LOCK;
    const TOKEN: &str = "test-token-0123456789abcdef";

    fn test_app() -> Arc<App> {
        let (tx, _rx) = mpsc::channel(4);
        Arc::new(App {
            token_digest: Sha256::digest(TOKEN.as_bytes()).into(),
            principal: "qa-lead".into(),
            tx,
            allowed_roots: vec![],
            scope: None,
            plugins: None,
            active: Mutex::new(None),
            probes: Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES)),
        })
    }

    fn data_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("readyhai-serve-{name}-{}", std::process::id()));
        std::fs::create_dir_all(d.join("runs")).unwrap();
        unsafe { std::env::set_var("READYHAI_DATA", &d) };
        d
    }

    fn body_text(resp: Response) -> String {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let b = rt
            .block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
            .unwrap();
        String::from_utf8_lossy(&b).into_owned()
    }

    #[test]
    fn list_runs_reads_dirs() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = data_dir("list");
        let rd = d.join("runs/20990101-000000-abcd");
        std::fs::create_dir_all(&rd).unwrap();
        std::fs::write(rd.join("status.json"), r#"{"id":"x","state":"queued"}"#).unwrap();
        let l = list_runs_json();
        assert_eq!(l[0]["state"], "queued");
        assert!(l[0]["verdict"].is_null());
        let _ = std::fs::remove_dir_all(d);
    }

    // ---------------------------------------------------------------- auth

    /// Every route the router serves. The drift test below fails when `build_router` gains a
    /// route that is not listed here, so the 401 sweep cannot silently miss one.
    const ROUTES: &[(&str, &str)] = &[
        ("GET", "/"),
        ("GET", "/ui"),
        ("GET", "/api/agent/status"),
        ("GET", "/api/agent/discover"),
        ("POST", "/api/agent/discover"),
        ("GET", "/api/agent/crawl"),
        ("POST", "/api/agent/crawl"),
        ("POST", "/api/agent/run"),
        ("GET", "/api/agent/runs"),
        ("GET", "/api/agent/runs/{id}"),
        ("DELETE", "/api/agent/runs/{id}"),
        ("POST", "/api/agent/runs/{id}/approve"),
        ("POST", "/api/agent/runs/{id}/reject"),
        ("GET", "/api/agent/runs/{id}/report/{fmt}"),
        ("POST", "/api/agent/retest"),
        ("GET", "/api/scans"),
        ("POST", "/api/scans"),
        ("GET", "/api/scans/{id}"),
        ("DELETE", "/api/scans/{id}"),
        ("GET", "/api/scans/{id}/report/{fmt}"),
        ("GET", "/api/agent/requester-ip"),
        ("GET", "/api/network/requester-ip"),
        ("POST", "/api/network/regress"),
        ("POST", "/api/network/curl"),
        ("POST", "/api/network/deep-audit"),
        ("POST", "/api/network/multi-region"),
        ("POST", "/api/network/export-har"),
        ("POST", "/api/github/pr-comment"),
        ("GET", "/api/badges/gate"),
        ("GET", "/api/badges/ledger"),
        ("GET", "/api/badges/network"),
        ("GET", "/checks"),
        ("POST", "/runs"),
        ("GET", "/runs"),
        ("GET", "/runs/{id}"),
        ("GET", "/runs/{id}/findings"),
        ("GET", "/runs/{id}/report/{fmt}"),
        // /health is public for GET only; any other method is authenticated
        ("POST", "/health"),
        // unknown paths are authenticated too
        ("GET", "/no/such/route"),
        ("GET", "/health/"),
    ];

    fn test_server() -> (tokio::runtime::Runtime, String) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let router = build_router(test_app());
        rt.spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        (rt, format!("http://{addr}"))
    }

    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
    }

    fn concrete(path: &str) -> String {
        path.replace("{id}", "abc").replace("{fmt}", "json")
    }

    #[test]
    fn every_route_returns_401_without_a_valid_bearer_token() {
        let (_rt, base) = test_server();
        let c = client();
        let bad: [(&str, Option<String>); 6] = [
            ("no credentials", None),
            (
                "wrong token",
                Some("Bearer not-the-right-token-xxxxxxxx".into()),
            ),
            (
                "token prefix",
                Some(format!("Bearer {}", &TOKEN[..TOKEN.len() - 1])),
            ),
            ("token plus suffix", Some(format!("Bearer {TOKEN}x"))),
            ("basic scheme", Some(format!("Basic {TOKEN}"))),
            ("bare token", Some(TOKEN.to_string())),
        ];
        for (method, pattern) in ROUTES {
            if *method == "GET" && is_public_get(pattern) {
                continue; // public by design, see badge_routes_are_public
            }
            for (what, auth) in &bad {
                let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
                let mut rb = c.request(m, format!("{base}{}", concrete(pattern)));
                if *method == "POST" {
                    rb = rb.header("content-type", "application/json").body("{}");
                }
                if let Some(a) = auth {
                    rb = rb.header("authorization", a);
                }
                let r = rb.send().unwrap();
                assert_eq!(r.status().as_u16(), 401, "{method} {pattern} ({what})");
                assert_eq!(
                    r.headers().get("www-authenticate").unwrap(),
                    "Bearer",
                    "{method} {pattern}"
                );
                let body = r.text().unwrap();
                assert!(
                    body.contains("missing or bad bearer token"),
                    "{method} {pattern}: {body}"
                );
            }
            // the old header-based token is gone
            let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
            let r = c
                .request(m, format!("{base}{}", concrete(pattern)))
                .header("x-readyhai-token", TOKEN)
                .send()
                .unwrap();
            assert_eq!(
                r.status().as_u16(),
                401,
                "{method} {pattern} (x-readyhai-token)"
            );
        }
    }

    #[test]
    fn routes_table_matches_the_router() {
        let src = include_str!("serve.rs");
        let start = src.find("fn build_router").unwrap();
        let end = start + src[start..].find(".fallback(").unwrap();
        let mut in_router: Vec<&str> = vec![];
        for part in src[start..end].split(".route(\"").skip(1) {
            in_router.push(part.split('"').next().unwrap());
        }
        assert!(in_router.len() > 25, "parsed {} routes", in_router.len());
        for p in &in_router {
            assert!(
                ROUTES.iter().any(|(_, t)| t == p),
                "route {p} is missing from the ROUTES 401 table"
            );
        }
    }

    #[test]
    fn health_is_public_and_a_valid_token_gets_through() {
        let (_rt, base) = test_server();
        let c = client();
        let r = c.get(format!("{base}/health")).send().unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(
            r.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert!(r.text().unwrap().contains("\"ok\""));
        // authenticated: passes the middleware (any non-401 answer proves it); scheme is case-insensitive
        for auth in [format!("Bearer {TOKEN}"), format!("bearer {TOKEN}")] {
            let r = c
                .get(format!("{base}/checks"))
                .header("authorization", auth)
                .send()
                .unwrap();
            assert_eq!(r.status().as_u16(), 200);
            let r = c
                .get(format!("{base}/runs/not_a_valid_id"))
                .header("authorization", format!("Bearer {TOKEN}"))
                .send()
                .unwrap();
            assert_eq!(r.status().as_u16(), 400);
        }
    }

    #[test]
    fn badge_routes_are_public_get_only() {
        let (_rt, base) = test_server();
        let c = client();
        for p in [
            "/api/badges/gate?status=PASS",
            "/api/badges/ledger?score=90",
            "/api/badges/network?status=ok",
        ] {
            let r = c.get(format!("{base}{p}")).send().unwrap();
            assert_eq!(r.status().as_u16(), 200, "{p}");
            assert!(
                r.headers()
                    .get("content-type")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("image/svg+xml")
            );
        }
        // everything near them stays authenticated
        for p in ["/api/badges/gate", "/api/badges/other", "/api/scans"] {
            let r = c.post(format!("{base}{p}")).body("{}").send().unwrap();
            assert_eq!(r.status().as_u16(), 401, "POST {p}");
        }
        assert_eq!(
            c.get(format!("{base}/api/badges/other"))
                .send()
                .unwrap()
                .status()
                .as_u16(),
            401
        );
    }

    #[test]
    fn signoff_of_an_unknown_run_is_404_not_500() {
        assert_eq!(
            signoff_err(anyhow::anyhow!(
                "Run 20261029-000000-aaaaaaaaaaaaaaaa not found"
            ))
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            signoff_err(anyhow::anyhow!("disk full")).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn token_policy() {
        assert!(validate_token(None).is_err());
        assert!(validate_token(Some("")).is_err());
        assert!(validate_token(Some("short-token")).is_err());
        assert!(validate_token(Some("exactly-15-chars")).is_ok()); // 16 chars
        assert!(validate_token(Some("fifteen-chars-x")).is_err()); // 15 chars
        assert!(
            validate_token(Some("rh-dev-token-9f8e7d6c5b4a3210")).is_err(),
            "the old hard-coded token must stay refused"
        );
        assert!(validate_token(Some("has a space in it here")).is_err());
        assert!(validate_token(Some("  leading-space-token-1234")).is_err());
        assert_eq!(validate_principal(None).unwrap(), "api-token");
        assert_eq!(
            validate_principal(Some("qa-lead@example.com")).unwrap(),
            "qa-lead@example.com"
        );
        assert!(validate_principal(Some("bad name")).is_err());
        assert!(validate_principal(Some("")).is_err());
    }

    #[test]
    fn sign_off_body_has_no_user_field() {
        // a client that still sends `user` is tolerated but cannot choose the recorded approver
        let p: ApprovalPayload = serde_json::from_str(r#"{"user":"CEO","notes":"ok"}"#).unwrap();
        assert_eq!(p.notes, "ok");
        assert_eq!(
            clip_notes(&"x".repeat(MAX_NOTES_CHARS + 50))
                .chars()
                .count(),
            MAX_NOTES_CHARS
        );
    }

    // ---------------------------------------------------------------- limits

    #[test]
    fn crawl_pages_are_clamped() {
        assert_eq!(clamp_pages(None), DEFAULT_CRAWL_PAGES);
        assert_eq!(clamp_pages(Some(0)), 1);
        assert_eq!(clamp_pages(Some(7)), 7);
        assert_eq!(clamp_pages(Some(usize::MAX)), MAX_CRAWL_PAGES);
    }

    // ---------------------------------------------------------------- run files

    #[test]
    fn delete_refuses_running_and_worker_never_resurrects_the_dir() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = data_dir("delete");
        let app = test_app();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // running: 409 and the directory stays
        let running = "20990101-000000-0000000000000001";
        write_queued(running, "/t").unwrap();
        write_status(running, "running", None);
        let r = rt.block_on(api_scan_delete(State(app.clone()), Path(running.into())));
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert!(engine::run_dir(running).exists());

        // queued: deletable (acts as cancel), and a late worker write does not bring it back
        let queued = "20990101-000000-0000000000000002";
        write_queued(queued, "/t").unwrap();
        let r = rt.block_on(api_scan_delete(State(app.clone()), Path(queued.into())));
        assert_eq!(r.status(), StatusCode::OK);
        assert!(!engine::run_dir(queued).exists());
        write_status(queued, "running", None);
        write_status(queued, "done", None);
        assert!(
            !engine::run_dir(queued).exists(),
            "write_status resurrected a deleted run"
        );

        // the worker's active run is protected even before status.json says "running"
        *app.active.lock().unwrap() = Some("20990101-000000-0000000000000003".into());
        write_queued("20990101-000000-0000000000000003", "/t").unwrap();
        let r = rt.block_on(api_scan_delete(
            State(app.clone()),
            Path("20990101-000000-0000000000000003".into()),
        ));
        assert_eq!(r.status(), StatusCode::CONFLICT);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn status_file_is_written_atomically() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = data_dir("atomic");
        let id = "20990101-000000-0000000000000009";
        write_queued(id, "http://t/").unwrap();
        write_status(id, "running", None);
        let v = read_json(id, "status.json").unwrap();
        assert_eq!(v["state"], "running");
        assert_eq!(v["target"], "http://t/");
        // no temp files left behind
        let leftovers: Vec<_> = std::fs::read_dir(engine::run_dir(id))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftovers, vec!["status.json".to_string()]);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn stale_runs_are_marked_on_startup() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = data_dir("stale");
        let id = "20990101-000000-000000000000000a";
        write_queued(id, "/t").unwrap();
        write_status(id, "running", None);
        let stale = mark_stale_runs();
        assert!(stale.contains(&id.to_string()));
        assert_eq!(read_json(id, "status.json").unwrap()["state"], "error");
        let _ = std::fs::remove_dir_all(d);
    }

    // ---------------------------------------------------------------- guard

    #[test]
    fn guard_allows_public_blocks_internal_without_a_scope_file() {
        let app = test_app();
        // no scope file: a public host is allowed (relaxed policy)...
        assert!(guard(&app, "http://app.example/", false).is_ok());
        // ...but an internal/metadata host still needs an explicit entry
        assert_eq!(
            guard(&app, "http://169.254.169.254/latest/", false)
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            guard(&app, "http://127.0.0.1:9000/", false)
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        // non-http schemes are always refused
        assert_eq!(
            guard(&app, "ftp://app.example/", false)
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn guard_enforces_scope_and_nonprod_gate_from_the_file() {
        let d = std::env::temp_dir().join(format!("readyhai-serve-guard-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("scope.toml");
        std::fs::write(&f, "[[hosts]]\nhost='qa.example'\nenv='nonprod'\n[[hosts]]\nhost='www.example'\nenv='prod'\n").unwrap();
        let mut app = test_app();
        Arc::get_mut(&mut app).unwrap().scope = Some(f);
        assert!(guard(&app, "https://qa.example/a", true).is_ok());
        assert!(guard(&app, "https://www.example/", false).is_ok());
        // www.example is listed prod → intrusive refused
        assert_eq!(
            guard(&app, "https://www.example/", true)
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        // an unlisted public host is allowed for non-intrusive actions only (read-only)
        assert!(guard(&app, "https://other.example/", false).is_ok());
        assert_eq!(
            guard(&app, "https://other.example/", true)
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert!(guard(&app, "https://agent-prod.nuhire.in/", false).is_ok());
        assert_eq!(guard_spec(&app, Some("  ".into())).unwrap(), None);
        assert_eq!(
            guard_spec(&app, Some("https://other.example/openapi.json".into()))
                .unwrap()
                .unwrap(),
            "https://other.example/openapi.json"
        );
        // an internal spec host still needs an entry
        assert!(guard_spec(&app, Some("http://10.0.0.5/openapi.json".into())).is_err());
        // scans go through the same precheck: an unlisted internal URL is refused
        let mut opts = ScanOpts {
            target: "http://10.0.0.5:8080/".into(),
            ..Default::default()
        };
        assert_eq!(
            prepare_scan(&app, &mut opts).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        let mut opts = ScanOpts {
            target: "/etc".into(),
            ..Default::default()
        };
        assert_eq!(
            prepare_scan(&app, &mut opts).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        let mut opts = ScanOpts {
            target: "https://qa.example/".into(),
            ..Default::default()
        };
        assert!(prepare_scan(&app, &mut opts).is_ok());
        assert!(opts.server);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn discovery_scores_are_not_reported() {
        let mut v = json!({"evidence_ledger": {"gate_verdict": "SCANNED", "overall_readiness": 100, "composite_score": 100,
            "value_score": 100, "authority_score": 100, "safety_score": 100, "evidence_score": 100, "executive_summary": "x"}});
        strip_discovery_scores(&mut v);
        for k in [
            "overall_readiness",
            "composite_score",
            "value_score",
            "authority_score",
            "safety_score",
            "evidence_score",
        ] {
            assert!(v["evidence_ledger"][k].is_null(), "{k}");
        }
        assert_eq!(v["evidence_ledger"]["gate_verdict"], "SCANNED");
        // a real agent-run ledger is left alone
        let mut real = json!({"evidence_ledger": {"gate_verdict": "GO", "overall_readiness": 88}});
        strip_discovery_scores(&mut real);
        assert_eq!(real["evidence_ledger"]["overall_readiness"], 88);
    }

    // ---------------------------------------------------------------- badges and PR comment

    #[test]
    fn badge_values_are_escaped() {
        let evil = "\"><script>alert(1)</script>&'";
        for svg in [ledger_svg(Some(evil)), network_svg(Some(evil))] {
            assert!(!svg.contains("<script"), "{svg}");
            assert!(!svg.contains("alert(1)</script>"), "{svg}");
            assert!(
                svg.contains("&lt;script&gt;") || svg.contains("&quot;&gt;&lt;"),
                "{svg}"
            );
            assert_eq!(svg.matches('<').count(), svg.matches('>').count());
        }
        // long values are cut
        assert!(!ledger_svg(Some(&"A".repeat(500))).contains(&"A".repeat(BADGE_VALUE_MAX + 1)));
        assert!(xml_escape("a\u{0}b\nc", 10) == "abc");
    }

    #[test]
    fn badges_do_not_invent_a_pass() {
        assert!(gate_svg(None).contains("n/a"));
        assert!(!gate_svg(None).contains("PASS"));
        assert!(gate_svg(Some("banana")).contains("n/a"));
        assert!(gate_svg(Some("pass")).contains(">PASS<"));
        assert!(gate_svg(Some("FAIL")).contains(">FAIL<"));
        assert!(ledger_svg(None).contains("n/a") && !ledger_svg(None).contains("94"));
    }

    #[test]
    fn pr_comment_without_data_says_not_evaluated() {
        let resp = futures_lite_block(github_pr_comment(Json(serde_json::from_str("{}").unwrap())));
        let v: serde_json::Value = serde_json::from_str(&body_text(resp)).unwrap();
        let md = v["markdown"].as_str().unwrap();
        assert!(md.contains("NOT EVALUATED"), "{md}");
        assert!(md.contains("not evaluated"));
        assert!(
            !md.contains("PASS") && !md.contains("94") && !md.contains("READY FOR MERGE"),
            "{md}"
        );
        assert!(!md.contains("96/100") && !md.contains("98/100"), "{md}");
        let badge = v["badge_markdown"].as_str().unwrap();
        assert!(
            badge.contains("not%20evaluated") && !badge.contains("PASS"),
            "{badge}"
        );
    }

    #[test]
    fn pr_comment_reports_only_supplied_data() {
        let p: PrCommentPayload = serde_json::from_str(
            r#"{"verdict":"warn","score":71,"target":"a`b\nc","commit_sha":"abc123","findings_count":3,"ledger_rbac":55}"#,
        )
        .unwrap();
        let (md, badge) = pr_comment_markdown(&p);
        assert!(md.contains("WARN (71/100)"), "{md}");
        assert!(md.contains("| **RBAC Authorization** | 55/100 |"), "{md}");
        assert!(
            md.contains("| **Contract Conformance** | not evaluated |"),
            "{md}"
        );
        assert!(md.contains("3 unresolved blocking finding(s)"));
        assert!(
            md.contains("`a'bc`"),
            "backtick and newline must not break the code span: {md}"
        );
        assert!(badge.contains("ReadyHai-WARN-yellow"));
        // unrecognised verdicts are not rendered into the badge URL
        let p: PrCommentPayload =
            serde_json::from_str(r#"{"verdict":"x)](http://evil)"}"#).unwrap();
        let (md, badge) = pr_comment_markdown(&p);
        assert!(
            !badge.contains("evil") && !md.contains("](http://evil"),
            "{md}"
        );
        assert!(md.contains("NOT EVALUATED"));
    }

    /// Drive a handler future to completion without an ambient runtime.
    fn futures_lite_block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }
}
