//! REST API + single in-process job worker. Run state lives under
//! <data>/runs/<id>/ (status.json while queued/running, run.json when done).
use crate::engine::{self, ScanOpts};
use crate::report;
use anyhow::{Result, bail};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

struct App {
    token: String,
    tx: mpsc::Sender<(String, ScanOpts)>,
    allowed_roots: Vec<PathBuf>,
    scope: Option<PathBuf>,
    plugins: Option<PathBuf>,
}

fn write_status(id: &str, state: &str, error: Option<&str>) {
    let dir = engine::run_dir(id);
    let _ = std::fs::create_dir_all(&dir);
    let prev: serde_json::Value = std::fs::read_to_string(dir.join("status.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let target = prev.get("target").cloned().unwrap_or(serde_json::Value::Null);
    let _ = std::fs::write(dir.join("status.json"), json!({"id": id, "state": state, "error": error, "target": target}).to_string());
}

fn write_queued(id: &str, target: &str) {
    let dir = engine::run_dir(id);
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("status.json"), json!({"id": id, "state": "queued", "error": null, "target": target}).to_string());
}

/// Queue lives in memory: anything queued/running when the server died is lost.
fn mark_stale_runs() {
    let Ok(rd) = std::fs::read_dir(engine::data_dir().join("runs")) else { return };
    for e in rd.flatten() {
        let id = e.file_name().to_string_lossy().to_string();
        let Ok(t) = std::fs::read_to_string(e.path().join("status.json")) else { continue };
        let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
        if matches!(v["state"].as_str(), Some("queued" | "running")) {
            write_status(&id, "error", Some("server restarted before the run finished"));
        }
    }
}

pub fn serve(bind: &str) -> Result<()> {
    let token = std::env::var("READYHAI_TOKEN").unwrap_or_default();
    if token.len() < 16 {
        bail!("READYHAI_TOKEN must be set (>= 16 chars) to run the API");
    }
    let allowed_roots: Vec<PathBuf> = std::env::var("READYHAI_ALLOWED_ROOTS")
        .unwrap_or_default()
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    let scope = std::env::var("READYHAI_SCOPE").ok().map(PathBuf::from);
    let plugins = std::env::var("READYHAI_PLUGINS").ok().map(PathBuf::from);
    mark_stale_runs();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        // One worker: scanner containers are memory-heavy; queue the rest.
        let (tx, mut rx) = mpsc::channel::<(String, ScanOpts)>(64);
        tokio::spawn(async move {
            while let Some((id, opts)) = rx.recv().await {
                write_status(&id, "running", None);
                let id2 = id.clone();
                let res = tokio::task::spawn_blocking(move || -> Result<()> {
                    let run = engine::scan(&opts, &id2)?;
                    report::write(&run, &engine::run_dir(&id2).join("report"), &["html".into(), "json".into(), "sarif".into(), "junit".into()])?;
                    Ok(())
                })
                .await;
                match res {
                    Ok(Ok(())) => write_status(&id, "done", None),
                    Ok(Err(e)) => write_status(&id, "error", Some(&format!("{e:#}"))),
                    Err(_) => write_status(&id, "error", Some("worker panicked")),
                }
            }
        });
        let app = Arc::new(App { token, tx, allowed_roots, scope, plugins });
        let router = Router::new()
            .route("/health", get(|| async { Json(json!({"status": "ok", "version": engine::VERSION})) }))
            .route("/checks", get(list_checks))
            .route("/runs", post(create_run).get(list_runs))
            .route("/runs/{id}", get(get_run))
            .route("/runs/{id}/findings", get(get_findings))
            .route("/runs/{id}/report/{fmt}", get(get_report))
            .with_state(app);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        eprintln!("readyhai API on http://{bind}");
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
        Ok(())
    })
}

fn authorized(app: &App, h: &HeaderMap) -> bool {
    let Some(v) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else { return false };
    let Some(t) = v.strip_prefix("Bearer ") else { return false };
    // constant-time compare
    t.len() == app.token.len() && t.bytes().zip(app.token.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({"error": msg.into()}))).into_response()
}

macro_rules! auth {
    ($app:expr, $h:expr) => {
        if !authorized(&$app, &$h) {
            return err(StatusCode::UNAUTHORIZED, "missing or bad bearer token");
        }
    };
}

async fn list_checks(State(app): State<Arc<App>>, h: HeaderMap) -> Response {
    auth!(app, h);
    let list: Vec<_> = crate::checks::all(app.plugins.as_deref())
        .into_iter()
        .map(|c| json!({"id": c.id, "title": c.title, "kinds": c.kinds, "min_profile": c.min_profile, "tool": c.tool, "intrusive": c.intrusive}))
        .collect();
    Json(list).into_response()
}

async fn create_run(State(app): State<Arc<App>>, h: HeaderMap, Json(mut opts): Json<ScanOpts>) -> Response {
    auth!(app, h);
    opts.server = true;
    opts.allowed_roots = app.allowed_roots.clone();
    opts.scope = app.scope.clone();
    opts.plugins = app.plugins.clone();
    // Cheap synchronous validation: reject with 400 before any run dir exists.
    if let Err(e) = crate::mcp::precheck(&opts) {
        return err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    let id = engine::new_run_id();
    write_queued(&id, &opts.target);
    if app.tx.try_send((id.clone(), opts)).is_err() {
        write_status(&id, "error", Some("queue full"));
        return err(StatusCode::SERVICE_UNAVAILABLE, "queue full");
    }
    (StatusCode::ACCEPTED, Json(json!({"id": id, "state": "queued"}))).into_response()
}

fn read_json(id: &str, file: &str) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(engine::run_dir(id).join(file)).ok()?).ok()
}

async fn get_run(State(app): State<Arc<App>>, h: HeaderMap, Path(id): Path<String>) -> Response {
    auth!(app, h);
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    let Some(status) = read_json(&id, "status.json") else { return err(StatusCode::NOT_FOUND, "no such run") };
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

async fn get_findings(State(app): State<Arc<App>>, h: HeaderMap, Path(id): Path<String>) -> Response {
    auth!(app, h);
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    match read_json(&id, "run.json") {
        Some(r) => Json(r["findings"].clone()).into_response(),
        None => err(StatusCode::NOT_FOUND, "run not finished or not found"),
    }
}

async fn get_report(State(app): State<Arc<App>>, h: HeaderMap, Path((id, fmt)): Path<(String, String)>) -> Response {
    auth!(app, h);
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
        Ok(b) => ([(header::CONTENT_TYPE, ctype), (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; img-src data:")], b).into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "report not ready"),
    }
}

/// Last 50 runs (newest first): id, state, target, verdict.
fn list_runs_json() -> Vec<serde_json::Value> {
    let Ok(rd) = std::fs::read_dir(engine::data_dir().join("runs")) else { return vec![] };
    let mut ids: Vec<String> = rd.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| engine::valid_run_id(n)).collect();
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

async fn list_runs(State(app): State<Arc<App>>, h: HeaderMap) -> Response {
    auth!(app, h);
    Json(list_runs_json()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_runs_reads_dirs() {
        let d = std::env::temp_dir().join(format!("readyhai-serve-test-{}", std::process::id()));
        let rd = d.join("runs/20990101-000000-abcd");
        std::fs::create_dir_all(&rd).unwrap();
        std::fs::write(rd.join("status.json"), r#"{"id":"x","state":"queued"}"#).unwrap();
        // READYHAI_DATA is process-global; only this test sets it in this module.
        unsafe { std::env::set_var("READYHAI_DATA", &d) };
        let l = list_runs_json();
        assert_eq!(l[0]["state"], "queued");
        assert!(l[0]["verdict"].is_null());
        let _ = std::fs::remove_dir_all(d);
    }
}
