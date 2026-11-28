//! Background job worker, execution queue, and server lifecycle crash recovery.

use super::guards::err;
use super::types::{App, DEFAULT_MAX_CUSTOM_INSTRUCTIONS_BYTES, GUARD_TIMEOUT, MAX_RUN_JSON_BYTES};
use crate::engine::{self, ScanOpts};
use anyhow::Result;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub static SERVER_ID: OnceLock<String> = OnceLock::new();

pub fn max_custom_instructions_bytes() -> usize {
    std::env::var("READYHAI_MAX_CUSTOM_INSTRUCTIONS_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CUSTOM_INSTRUCTIONS_BYTES)
        .clamp(4096, 131_072)
}

pub fn worker_count() -> usize {
    std::env::var("READYHAI_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .clamp(1, 16)
}

pub fn read_json(id: &str, file: &str) -> Option<serde_json::Value> {
    let p = engine::run_dir(id).join(file);
    if std::fs::metadata(&p).ok()?.len() > MAX_RUN_JSON_BYTES {
        return None;
    }
    serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
}

pub fn status_body(
    id: &str,
    state: &str,
    error: Option<&str>,
    target: serde_json::Value,
    server: Option<&str>,
) -> String {
    let mut v = json!({"id": id, "state": state, "error": error, "target": target});
    if let Some(sv) = server {
        v["server"] = json!(sv);
    }
    v.to_string()
}

pub fn write_status(id: &str, state: &str, error: Option<&str>) {
    let dir = engine::run_dir(id);
    let prev: serde_json::Value = std::fs::read_to_string(dir.join("status.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let target = prev
        .get("target")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let server = prev
        .get("server")
        .and_then(|v| v.as_str())
        .or_else(|| SERVER_ID.get().map(String::as_str));
    let body = status_body(id, state, error, target, server);
    let _ = engine::write_atomic(&dir.join("status.json"), body.as_bytes());
}

pub fn write_queued(id: &str, target: &str) -> std::io::Result<()> {
    let dir = engine::run_dir(id);
    std::fs::create_dir_all(&dir)?;
    let body = status_body(
        id,
        "queued",
        None,
        json!(target),
        SERVER_ID.get().map(String::as_str),
    );
    engine::write_atomic(&dir.join("status.json"), body.as_bytes())
}

pub fn init_server_id() -> Result<String> {
    let data = engine::data_dir();
    std::fs::create_dir_all(&data)?;
    let p = data.join("server-id");
    let id = match std::fs::read_to_string(&p) {
        Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => {
            let id = format!("{:032x}", rand::random::<u128>());
            engine::write_atomic(&p, id.as_bytes())?;
            id
        }
    };
    let _ = SERVER_ID.set(id.clone());
    Ok(id)
}

pub fn created_by_this_server(id: &str) -> bool {
    let Some(mine) = SERVER_ID.get() else {
        return false;
    };
    read_json(id, "status.json")
        .and_then(|s| s["server"].as_str().map(|v| v == mine))
        .unwrap_or(false)
}

pub fn handle_startup_runs(tx: &mpsc::Sender<(String, ScanOpts)>) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(engine::data_dir().join("runs")) else {
        return vec![];
    };
    let mut stale = vec![];
    let mut resumed = 0;
    for e in rd.flatten() {
        let id = e.file_name().to_string_lossy().to_string();
        let Ok(t) = std::fs::read_to_string(e.path().join("status.json")) else {
            continue;
        };
        let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
        if v["state"].as_str() == Some("running") {
            write_status(
                &id,
                "error",
                Some("server restarted before the run finished"),
            );
            stale.push(id);
        } else if v["state"].as_str() == Some("queued") {
            let opts_path = e.path().join("opts.json");
            let mut requeued = false;
            if let Ok(opts_str) = std::fs::read_to_string(&opts_path)
                && let Ok(opts) = serde_json::from_str::<ScanOpts>(&opts_str)
                && tx.try_send((id.clone(), opts)).is_ok()
            {
                requeued = true;
                resumed += 1;
            }
            if !requeued {
                write_status(
                    &id,
                    "error",
                    Some("server restarted before the run started"),
                );
                stale.push(id);
            }
        }
    }
    if resumed > 0 {
        eprintln!("resumed {resumed} persistent queued run(s) across server restart");
    }
    stale
}

#[allow(dead_code)]
pub fn mark_stale_runs() -> Vec<String> {
    let (tx, _rx) = mpsc::channel(1);
    handle_startup_runs(&tx)
}

pub fn claims_run(stale: &[String], id: &str) -> bool {
    engine::valid_run_id(id) && (stale.iter().any(|s| s == id) || created_by_this_server(id))
}

/// The active-run registry, recovered if a panic poisoned the lock: dropping the registry
/// would hide running scans from shutdown draining and leak their containers.
pub(crate) fn active(app: &App) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
    app.active.lock().unwrap_or_else(|e| e.into_inner())
}

fn active_contains(app: &App, id: &str) -> bool {
    active(app).contains(id)
}

pub fn run_in_progress(app: &App, id: &str) -> bool {
    if active_contains(app, id) {
        return true;
    }
    read_json(id, "status.json").is_some_and(|s| s["state"].as_str() == Some("running"))
}

pub fn run_timeout() -> Duration {
    let secs = std::env::var("READYHAI_RUN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(20 * 60)
        .clamp(60, 2 * 3600);
    Duration::from_secs(secs)
}

pub async fn worker(
    app: Arc<App>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(String, ScanOpts)>>>,
    limit: Duration,
) {
    loop {
        let item = {
            let mut lock = rx.lock().await;
            lock.recv().await
        };
        let Some((id, mut opts)) = item else {
            break;
        };
        if !engine::run_dir(&id).join("status.json").exists() {
            continue;
        }
        active(&app).insert(id.clone());
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
        active(&app).remove(&id);
    }
}

pub async fn prepare_scan(app: &App, mut opts: ScanOpts) -> Result<ScanOpts, Response> {
    opts.server = true;
    opts.allowed_roots = app.allowed_roots.clone();
    opts.scope = app.scope.clone();
    opts.plugins = app.plugins.clone();
    let job = tokio::task::spawn_blocking(move || crate::mcp::precheck(&opts).map(|_| opts));
    match tokio::time::timeout(GUARD_TIMEOUT, job).await {
        Ok(Ok(Ok(opts))) => Ok(opts),
        Ok(Ok(Err(e))) => Err(err(StatusCode::BAD_REQUEST, format!("{e:#}"))),
        Ok(Err(_)) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, "precheck failed")),
        Err(_) => Err(err(
            StatusCode::GATEWAY_TIMEOUT,
            "scope check timed out while resolving a host; refusing",
        )),
    }
}

pub fn enqueue(app: &App, opts: ScanOpts) -> Result<String, Response> {
    let id = engine::new_run_id();
    if write_queued(&id, &opts.target).is_err() {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot create run directory",
        ));
    }
    if let Ok(opts_str) = serde_json::to_string_pretty(&opts) {
        let _ = std::fs::write(engine::run_dir(&id).join("opts.json"), opts_str);
    }
    if app.tx.try_send((id.clone(), opts)).is_err() {
        write_status(&id, "error", Some("queue full"));
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "queue full"));
    }
    Ok(id)
}
