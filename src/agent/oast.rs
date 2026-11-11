//! Ephemeral out-of-band application security testing (OAST) HTTP callback collector.
//!
//! Binds a dedicated OS thread with a single-threaded Tokio + Axum HTTP server (`127.0.0.1:0` by
//! default, overridable via `READYHAI_OAST_BIND` / `READYHAI_OAST_URL`) so synchronous executors,
//! verifiers, and tests can issue unique callback URLs and deterministically detect SSRF / blind
//! XXE / blind RCE callbacks without external network dependencies.

use axum::{
    Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    routing::any,
};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::llm::untrusted::redact_then_truncate;

const MAX_TOKENS: usize = 512;
const MAX_HITS_PER_TOKEN: usize = 8;

/// Recorded callback hit on [`OastCollector`].
#[derive(Debug, Clone)]
pub struct OastHit {
    pub token: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub remote: String,
    pub user_agent: String,
    pub ts_ms: u64,
}

impl OastHit {
    /// Short non-secret summary suitable for defect evidence.
    pub fn summary(&self) -> String {
        format!(
            "{} {} from {} (ua: {})",
            self.method, self.path, self.remote, self.user_agent
        )
    }
}

#[derive(Default)]
struct Registry {
    hits: HashMap<String, Vec<OastHit>>,
}

#[derive(Clone)]
struct SharedState {
    registry: Arc<Mutex<Registry>>,
    cv: Arc<Condvar>,
}

/// Active OAST callback HTTP listener. Shut down gracefully when dropped.
pub struct OastCollector {
    base_url: String,
    shared: SharedState,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl OastCollector {
    /// Start listening using `READYHAI_OAST_BIND` (default `127.0.0.1:0`) and `READYHAI_OAST_URL`
    /// if provided.
    pub fn start() -> Result<Self, String> {
        let bind = std::env::var("READYHAI_OAST_BIND")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "127.0.0.1:0".to_string());
        let advertise = std::env::var("READYHAI_OAST_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty());
        Self::start_on(&bind, advertise.as_deref())
    }

    /// Start listening on `bind_addr`, advertising `advertise_base` (or `http://127.0.0.1:<port>`).
    pub fn start_on(bind_addr: &str, advertise_base: Option<&str>) -> Result<Self, String> {
        let addr_str = bind_addr.to_string();
        let adv = advertise_base.map(|s| s.trim_end_matches('/').to_string());
        let shared = SharedState {
            registry: Arc::new(Mutex::new(Registry::default())),
            cv: Arc::new(Condvar::new()),
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread_shared = shared.clone();

        let handle = std::thread::Builder::new()
            .name("readyhai-oast".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("oast runtime error: {e}")));
                        return;
                    }
                };
                rt.block_on(async move {
                    let listener = match tokio::net::TcpListener::bind(&addr_str).await {
                        Ok(l) => l,
                        Err(e) => {
                            let _ =
                                ready_tx.send(Err(format!("oast bind '{addr_str}' failed: {e}")));
                            return;
                        }
                    };
                    let local_addr = match listener.local_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            let _ = ready_tx.send(Err(format!("oast local_addr failed: {e}")));
                            return;
                        }
                    };
                    let _ = ready_tx.send(Ok(local_addr));

                    let app = Router::new()
                        .route("/oast/{token}", any(handle_hit))
                        .route("/oast/{token}/{*rest}", any(handle_hit_rest))
                        .with_state(thread_shared);

                    let _ = axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(async move {
                        let _ = stop_rx.await;
                    })
                    .await;
                });
            })
            .map_err(|e| format!("failed to spawn oast thread: {e}"))?;

        let local_addr = ready_rx
            .recv_timeout(Duration::from_secs(3))
            .map_err(|e| format!("oast listener startup timed out: {e}"))??;
        let base_url = adv.unwrap_or_else(|| {
            let host = match local_addr.ip() {
                ip if ip.is_unspecified() => "127.0.0.1".to_string(),
                ip if ip.is_ipv6() => format!("[{ip}]"),
                ip => ip.to_string(),
            };
            format!("http://{host}:{}", local_addr.port())
        });

        Ok(OastCollector {
            base_url,
            shared,
            shutdown: Some(stop_tx),
            handle: Some(handle),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Generate a fresh unguessable correlation token and full HTTP callback URL.
    pub fn issue_token(&self) -> (String, String) {
        let bytes: [u8; 12] = rand::rng().random();
        let token = hex::encode(bytes);
        if let Ok(mut reg) = self.shared.registry.lock()
            && reg.hits.len() < MAX_TOKENS
        {
            reg.hits.entry(token.clone()).or_default();
        }
        let url = format!("{}/oast/{token}", self.base_url);
        (token, url)
    }

    pub fn hits_for(&self, token: &str) -> Vec<OastHit> {
        self.shared
            .registry
            .lock()
            .ok()
            .and_then(|reg| reg.hits.get(token).cloned())
            .unwrap_or_default()
    }

    /// Block until at least one callback for `token` is observed or `timeout` elapses.
    pub fn wait_for_hit(&self, token: &str, timeout: Duration) -> Option<OastHit> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.shared.registry.lock().ok()?;
        loop {
            if let Some(hit) = guard.hits.get(token).and_then(|v| v.first()).cloned() {
                return Some(hit);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let rem = deadline.saturating_duration_since(now);
            let (g, res) = self.shared.cv.wait_timeout(guard, rem).ok()?;
            guard = g;
            if res.timed_out() {
                return guard.hits.get(token).and_then(|v| v.first()).cloned();
            }
        }
    }
}

impl Drop for OastCollector {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

async fn handle_hit(
    State(state): State<SharedState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    Path(token): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> (StatusCode, &'static str) {
    record_hit(state, remote, method, token, String::new(), query, headers)
}

async fn handle_hit_rest(
    State(state): State<SharedState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    method: Method,
    Path((token, rest)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> (StatusCode, &'static str) {
    record_hit(state, remote, method, token, rest, query, headers)
}

fn record_hit(
    state: SharedState,
    remote: SocketAddr,
    method: Method,
    token: String,
    rest: String,
    query: HashMap<String, String>,
    headers: HeaderMap,
) -> (StatusCode, &'static str) {
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| redact_then_truncate(s, 80))
        .unwrap_or_else(|| "-".into());
    let q_str = query
        .into_iter()
        .take(8)
        .map(|(k, v)| {
            format!(
                "{}={}",
                redact_then_truncate(&k, 32),
                redact_then_truncate(&v, 64)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let path = if rest.is_empty() {
        format!("/oast/{}", redact_then_truncate(&token, 32))
    } else {
        format!(
            "/oast/{}/{}",
            redact_then_truncate(&token, 32),
            redact_then_truncate(&rest, 64)
        )
    };
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if let Ok(mut reg) = state.registry.lock()
        && let Some(list) = reg.hits.get_mut(&token)
        && list.len() < MAX_HITS_PER_TOKEN
    {
        list.push(OastHit {
            token,
            method: method.as_str().to_string(),
            path,
            query: q_str,
            remote: remote.ip().to_string(),
            user_agent: ua,
            ts_ms,
        });
        state.cv.notify_all();
    }
    (StatusCode::OK, "ok")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oast_collector_captures_issued_token_and_ignores_unknown_tokens() {
        let oast = OastCollector::start_on("127.0.0.1:0", None).unwrap();
        let (tok, url) = oast.issue_token();
        assert!(url.starts_with("http://127.0.0.1:"));

        // Unknown token is ignored cleanly
        let bogus = format!("{}/oast/nonexistent-token-123", oast.base_url());
        let r = reqwest::blocking::get(&bogus).unwrap();
        assert_eq!(r.status(), 200);
        assert!(oast.hits_for("nonexistent-token-123").is_empty());

        // Real issued token triggers immediate wakeup
        let url2 = url.clone();
        std::thread::spawn(move || {
            let _ = reqwest::blocking::get(&url2);
        });
        let hit = oast
            .wait_for_hit(&tok, Duration::from_secs(2))
            .expect("must capture issued callback");
        assert_eq!(hit.token, tok);
        assert_eq!(hit.method, "GET");
        assert!(hit.summary().contains("GET /oast/"));
    }
}
