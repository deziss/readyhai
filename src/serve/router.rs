//! HTTP router assembly, static asset delivery, and graceful server bootstrap.

use super::agent_api::*;
use super::auth::{require_auth, validate_principal, validate_scope_path, validate_token, whoami};
use super::badges::*;
use super::eval_api::*;
use super::guards::err;
use super::network_api::*;
use super::scans::*;
use super::types::{App, FORCED_SHUTDOWN, MAX_CONCURRENT_PROBES, SHUTDOWN_REAP_PER_CALL};
use super::worker::{claims_run, handle_startup_runs, init_server_id, run_timeout, worker, worker_count, write_status};
use anyhow::Result;
use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::future::IntoFuture;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use crate::engine::{self, ScanOpts};

pub fn serve(bind: &str) -> Result<()> {
    let token = validate_token(std::env::var("READYHAI_TOKEN").ok().as_deref())?;
    let principal = validate_principal(std::env::var("READYHAI_PRINCIPAL").ok().as_deref())?;
    let allowed_roots: Vec<PathBuf> = std::env::var("READYHAI_ALLOWED_ROOTS")
        .unwrap_or_default()
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    let scope = validate_scope_path(std::env::var("READYHAI_SCOPE").ok().as_deref())?;
    let plugins = std::env::var("READYHAI_PLUGINS").ok().map(PathBuf::from);
    let rbac_file = std::env::var("READYHAI_RBAC_FILE").ok().map(PathBuf::from);
    let rbac = super::rbac::Rbac::load(rbac_file.as_deref())?;
    eprintln!(
        "rbac: {}",
        if rbac.enabled {
            format!("ON, {} key(s)", rbac.keys.len())
        } else {
            "OFF (single boot token, legacy mode)".to_string()
        }
    );
    let limit = run_timeout();
    init_server_id()?;

    // Multi-worker task queue: workers pull jobs concurrently from rx.
    let (tx, rx) = mpsc::channel::<(String, ScanOpts)>(128);
    let stale = handle_startup_runs(&tx);
    // Containers of runs that died with the previous server would otherwise live on forever.
    // Only this server's own runs are claimed (see `claims_run`), never a CLI scan's.
    let reaped = crate::tools::reap_dead_runs(&|id| claims_run(&stale, id));
    if reaped > 0 {
        eprintln!("reaped {reaped} orphaned scanner container(s) from dead runs");
    }

    let app = Arc::new(App {
        token_digest: Sha256::digest(token.as_bytes()).into(),
        principal,
        rbac,
        tx,
        allowed_roots,
        scope,
        plugins,
        active: Mutex::new(HashSet::new()),
        probes: Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES)),
    });

    let rt = tokio::runtime::Runtime::new()?;
    let app2 = app.clone();
    let res: Result<()> = rt.block_on(async move {
        let workers = worker_count();
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        for _ in 0..workers {
            tokio::spawn(worker(app2.clone(), rx.clone(), limit));
        }
        let router = build_router(app2);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        eprintln!("readyhai API on http://{bind} ({workers} worker(s))");

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
            tokio::time::sleep(FORCED_SHUTDOWN).await;
        };
        tokio::select! {
            r = serving => r?,
            _ = forced => eprintln!(
                "shutdown: connections did not drain within {}s, exiting",
                FORCED_SHUTDOWN.as_secs()
            ),
        }
        Ok(())
    });

    // Shutting down mid-scan: say so in all active runs' status and stop their containers now.
    if let Ok(mut g) = app.active.lock() {
        for id in g.drain() {
            write_status(
                &id,
                "error",
                Some("server shut down before the run finished"),
            );
            crate::tools::reap_run_within(&id, SHUTDOWN_REAP_PER_CALL);
        }
    }
    rt.shutdown_timeout(Duration::from_secs(2));
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


pub fn build_router(app: Arc<App>) -> Router {
    Router::new()        .route("/", get(api_index))
        .route("/ui", get(api_index))
        .route("/api/agent/status", get(agent_status))
        .route(
            "/api/agent/discover",
            get(agent_discover).post(agent_discover_post),
        )
        .route(
            "/api/agent/directives/synthesize",
            post(agent_directives_post),
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
        .route("/api/agent/runs/{id}/cancel", post(agent_run_cancel))
        .route("/api/agent/runs/{id}/report/{fmt}", get(agent_run_report))
        .route("/api/agent/retest", post(agent_retest))
        .route(
            "/api/agent/memory",
            get(agent_memory_get).delete(agent_memory_forget),
        )
        .route("/api/agent/memory/accept", post(agent_memory_accept))
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
        .route("/api/eval-ai", post(api_eval_ai))
        .route("/api/fix", post(api_fix))
        .route("/api/mutate", post(api_mutate))
        .route("/api/github/pr-comment", post(github_pr_comment))
        .route("/api/badges/gate", get(badge_gate))
        .route("/api/badges/ledger", get(badge_ledger))
        .route("/api/badges/network", get(badge_network))
        .route(
            "/health",
            get(|| async { Json(json!({"status": "ok", "version": engine::VERSION})) }),
        )
        .route("/api/whoami", get(whoami))
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

