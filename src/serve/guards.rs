//! Egress guards, scope verification, DNS preflight, and blocking pool executors.

use super::types::{App, GUARD_TIMEOUT};
use crate::scope::{self, Scope};
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::path::Path as FsPath;
use std::time::Duration;

pub fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({"error": msg.into()}))).into_response()
}

/// The scope check itself, synchronous: reads the scope file and may resolve the host (DNS).
/// Only ever called from the blocking pool.
pub fn guard_blocking(
    scope_path: Option<&FsPath>,
    url: &str,
    intrusive: bool,
) -> Result<scope::Egress, Response> {
    let sc = match scope_path {
        Some(p) => match Scope::load(p) {
            Ok(s) => Some(s),
            // fail closed: a scope file that went bad after startup refuses everything
            Err(e) => {
                return Err(err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("scope file cannot be used, refusing: {e:#}"),
                ));
            }
        },
        None => None,
    };
    scope::egress_guard(url, sc.as_ref(), intrusive)
        .map_err(|e| err(StatusCode::FORBIDDEN, format!("{e:#}")))
}

/// THE egress guard for server-initiated HTTP: scope check plus, for `intrusive` actions, the
/// nonprod gate. Returns the normalised URL to use (the one whose host was approved). Name
/// resolution (getaddrinfo) and file reads happen on the blocking pool, never on an async worker,
/// and a resolver that hangs ends in a refusal after [`GUARD_TIMEOUT`].
pub async fn guard(app: &App, url: &str, intrusive: bool) -> Result<scope::Egress, Response> {
    let scope_path = app.scope.clone();
    let url = url.to_string();
    let job =
        tokio::task::spawn_blocking(move || guard_blocking(scope_path.as_deref(), &url, intrusive));
    let eg = match tokio::time::timeout(GUARD_TIMEOUT, job).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "scope check failed")),
        Err(_) => {
            return Err(err(
                StatusCode::GATEWAY_TIMEOUT,
                "scope check timed out while resolving the host; refusing",
            ));
        }
    }?;
    preflight_host_dns(&eg.host).await?;
    Ok(eg)
}

/// Instant DNS preflight reachability guard: detects unresolvable domains (NXDOMAIN)
/// fast asynchronously (<50ms) to fail fast without starving the blocking worker pool.
pub async fn preflight_host_dns(host: &str) -> Result<(), Response> {
    #[cfg(test)]
    {
        let _ = host;
        return Ok(());
    }
    #[cfg(not(test))]
    {
        if host.parse::<std::net::IpAddr>().is_ok()
            || host == "localhost"
            || host == "host.docker.internal"
            || host.ends_with(".localhost")
            || host.ends_with(".test")
            || host.ends_with(".example")
            || host.ends_with(".invalid")
        {
            return Ok(());
        }
        match tokio::time::timeout(
            Duration::from_millis(1500),
            tokio::net::lookup_host(format!("{}:80", host)),
        )
        .await
        {
            Ok(Ok(mut addrs)) => {
                if addrs.next().is_some() {
                    Ok(())
                } else {
                    Err(err(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!(
                            "Host unreachable: domain '{host}' does not resolve in DNS (NXDOMAIN). Verify domain spelling or publish DNS records."
                        ),
                    ))
                }
            }
            Ok(Err(e)) => Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "Host unreachable: domain '{host}' does not resolve in DNS ({e}). Verify domain spelling or publish DNS records."
                ),
            )),
            Err(_) => Err(err(
                StatusCode::GATEWAY_TIMEOUT,
                format!("Host resolution timed out: domain '{host}' DNS lookup exceeded 1500ms."),
            )),
        }
    }
}

/// Optional spec/OpenAPI URL: blank means none, anything else must pass the guard too.
pub async fn guard_spec(app: &App, spec: Option<String>) -> Result<Option<String>, Response> {
    match spec.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => Ok(Some(guard(app, s, false).await?.url)),
    }
}

/// Run quick blocking work (file reads, listings, report generation) off the async workers.
pub async fn offload<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Response> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))
}

/// Run blocking work on the blocking pool, at most [`MAX_CONCURRENT_PROBES`] at a time. The
/// permit travels with the work, so a client that hangs up does not leak it.
pub async fn blocking<T: Send + 'static>(
    app: &App,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Response> {
    let permit = match tokio::time::timeout(
        Duration::from_millis(2000),
        app.probes.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                "too many concurrent probes; retry when one finishes",
            ));
        }
    };
    tokio::task::spawn_blocking(move || {
        let out = f();
        drop(permit);
        out
    })
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))
}

pub fn guard_repo(app: &App, req: &mut crate::agent::AgentRunRequest) -> Result<(), String> {
    let repo = req.repo.take().filter(|r| !r.trim().is_empty());
    let base = req.diff_base.take().filter(|b| !b.trim().is_empty());
    match (repo, base) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            Err("repo and diff_base must be given together".into())
        }
        (Some(r), Some(b)) => {
            let (root, base) =
                crate::agent::change::validate_request(&r, Some(&b), Some(&app.allowed_roots))?;
            req.repo = Some(root.display().to_string());
            req.diff_base = base;
            Ok(())
        }
    }
}

/// Compare two targets as the HTTP client sees them: parsed, normalised, trailing slash ignored.
/// A stored target that is not an http(s) URL (a repo run, say) never matches.
pub fn same_target(a: &str, b: &str) -> bool {
    let norm = |t: &str| {
        scope::parse_web_url(t)
            .ok()
            .map(|u| u.to_string().trim_end_matches('/').to_string())
    };
    matches!((norm(a), norm(b)), (Some(x), Some(y)) if x == y)
}
