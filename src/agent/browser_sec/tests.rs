use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::net::TcpListener;

use super::models::BrowserSecReport;
use super::report_parser::results_from_browser_report;
use crate::agent::budget::RunBudget;
use crate::agent::exec::Credentials;
use crate::agent::pipeline::{LlmMode, RunOptions, run_with};
use crate::agent::types::AgentRunRequest;

#[test]
fn parses_playwright_browser_sec_report_with_dom_xss_storage_secrets_sourcemaps_cookies_and_clickjacking()
 {
    let raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInNlY3JldCI6Imh1bnRlcjIifQ.sig1234567890";
    let rep: BrowserSecReport = serde_json::from_value(json!({
        "base_url": "https://app.example.test",
        "xss_hits": [
            {
                "kind": "dom_hash",
                "id": "dom-hash-0",
                "url": "https://app.example.test/dom",
                "probe_url": "https://app.example.test/dom#<img src=x onerror=\"window.__rh_xss_hit('dom-hash-0','hash')\">",
                "detail": "hash"
            },
            {
                "kind": "stored_xss",
                "id": "stored-form-1-0",
                "url": "https://app.example.test/comments",
                "probe_url": "https://app.example.test/comments",
                "detail": "Stored XSS canary executed for role 'bob'"
            }
        ],
        "storage_leaks": [
            {
                "url": "https://app.example.test/dashboard",
                "store": "localStorage",
                "key": "auth_token",
                "kind": "jwt",
                "preview": raw_jwt
            }
        ],
        "cookie_issues": [
            {
                "url": "https://app.example.test/",
                "name": "session_id",
                "missing": ["HttpOnly", "Secure"]
            }
        ],
        "sourcemaps": [
            {
                "url": "https://app.example.test/assets/app.js.map",
                "size_bytes": 4096
            }
        ],
        "clickjacking": [
            {
                "url": "https://app.example.test/transfer",
                "reason": "Page loaded inside <iframe> without X-Frame-Options or CSP frame-ancestors"
            }
        ]
    }))
    .unwrap();

    let (cases, results) = results_from_browser_report(&rep, "https://app.example.test");
    assert!(
        results.len() >= 6,
        "expected all 6 browser security findings, got {}",
        results.len()
    );
    assert_eq!(cases.len(), results.len());

    let codes: Vec<&str> = results
        .iter()
        .filter_map(|r| r.oracle.as_ref())
        .flat_map(|o| o.checks.iter().map(|c| c.code.as_str()))
        .collect();
    for expected in [
        "dom_xss",
        "stored_xss",
        "client_secret_leak",
        "cookie_hygiene",
        "sourcemap_exposure",
        "clickjacking",
    ] {
        assert!(
            codes.contains(&expected),
            "missing check code {expected} in {codes:?}"
        );
    }

    let serialized = serde_json::to_string(&results).unwrap();
    assert!(
        !serialized.contains(raw_jwt),
        "raw JWT leaked into BrowserSec result JSON!"
    );
    assert!(
        !serialized.contains("eyJhbGciOiJIUzI1NiIs"),
        "JWT header/payload leaked without redaction!"
    );
}

#[test]
fn agent_detects_dom_xss_and_stored_xss_with_clean_control_and_verifies_k() {
    let comments: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel();
    let comments_bg = Arc::clone(&comments);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let app = Router::new()
                .route(
                    "/",
                    get(|| async {
                        Html(
                            r#"<!doctype html><html><body>
                            <a href="/dom">DOM Viewer</a>
                            <a href="/comments">Comments</a>
                            <a href="/safe">Safe Viewer</a>
                            </body></html>"#,
                        )
                    }),
                )
                .route(
                    "/dom",
                    get(|| async {
                        Html(
                            r#"<!doctype html><html><body>
                            <div id="out"></div>
                            <script>document.getElementById('out').innerHTML = location.hash;</script>
                            </body></html>"#,
                        )
                    }),
                )
                .route(
                    "/safe",
                    get(|| async {
                        Html(
                            r#"<!doctype html><html><body>
                            <div id="safe"></div>
                            <script>document.getElementById('safe').textContent = location.hash;</script>
                            </body></html>"#,
                        )
                    }),
                )
                .route(
                    "/comments",
                    get(|State(store): State<Arc<Mutex<Vec<String>>>>| async move {
                        let list = store.lock().unwrap().join("</li><li>");
                        Html(format!(
                            r#"<!doctype html><html><body>
                            <form method="POST" action="/comments">
                              <input type="text" name="comment" />
                              <button type="submit">Post</button>
                            </form>
                            <ul><li>{list}</li></ul>
                            </body></html>"#
                        ))
                    })
                    .post(
                        |State(store): State<Arc<Mutex<Vec<String>>>>,
                         headers: HeaderMap,
                         body: axum::body::Bytes| async move {
                            let auth = headers
                                .get(axum::http::header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            if auth != "Bearer alice-token" && auth != "Bearer bob-token" {
                                return (
                                    StatusCode::UNAUTHORIZED,
                                    Html("Unauthorized".to_string()),
                                )
                                    .into_response();
                            }
                            let raw = String::from_utf8_lossy(&body);
                            let text = if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                                v.get("comment")
                                    .or_else(|| v.get("message"))
                                    .or_else(|| v.get("body"))
                                    .or_else(|| v.get("text"))
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string()
                            } else {
                                reqwest::Url::parse(&format!("http://localhost/?{raw}"))
                                    .ok()
                                    .and_then(|u| {
                                        u.query_pairs()
                                            .find(|(k, _)| {
                                                k == "comment" || k == "message" || k == "body"
                                            })
                                            .map(|(_, v)| v.into_owned())
                                    })
                                    .unwrap_or_default()
                            };
                            store.lock().unwrap().push(text);
                            (StatusCode::CREATED, Html("Stored".to_string())).into_response()
                        },
                    )
                )
                .with_state(comments_bg);

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(format!("http://127.0.0.1:{}", addr.port())).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    let base_url = rx.recv().unwrap();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let run_base = std::env::temp_dir().join(format!("rh-browsersec-{nonce}"));
    std::fs::create_dir_all(&run_base).unwrap();

    let req = AgentRunRequest {
        target: base_url,
        profile: "standard".into(),
        spec_url: None,
        custom_instructions: None,
        max_steps: None,
        dry_run: false,
        thinking: false,
        model_tier: "balanced".into(),
        thinking_budget_tokens: 1024,
        repo: None,
        diff_base: None,
    };
    let budget = RunBudget::new(90, 240, Duration::from_secs(60), 0.0);
    let opts = RunOptions {
        budget,
        credentials: Credentials::none()
            .with("alice", "alice-token")
            .with("bob", "bob-token"),
        llm: LlmMode::Off,
        reruns: 0,
        verify_k: 2,
        request_timeout: Duration::from_secs(5),
        lookup_requester_ip: false,
        workers: 2,
        memory_dir: None,
        data_dir: Some(std::env::temp_dir().join(format!("rh-bsec-data-{}", std::process::id()))),
    };

    let rep = run_with(&run_base, &req, "browser-sec-test", opts, Some(true)).unwrap();
    let _ = std::fs::remove_dir_all(&run_base);

    assert!(
        rep.stage_sources.contains_key("browser_security"),
        "expected browser_security in stage_sources: {:?}",
        rep.stage_sources
    );
    assert!(
        rep.triaged_defects
            .iter()
            .any(|d| d.rule == "dom_xss" && d.component.contains("/dom") && d.verified),
        "expected verified dom_xss defect on /dom, got: {:?}",
        rep.triaged_defects
    );
    assert!(
        rep.triaged_defects
            .iter()
            .any(|d| d.rule == "stored_xss" && d.component.contains("/comments") && d.verified),
        "expected verified stored_xss defect on /comments, got: {:?}",
        rep.triaged_defects
    );
    assert!(
        rep.triaged_defects
            .iter()
            .all(|d| !d.component.contains("/safe")),
        "clean control /safe produced a false positive defect: {:?}",
        rep.triaged_defects
    );
}
