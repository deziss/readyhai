#![allow(unused_imports)]
//! Unit test suite for the serve module.

use super::*;
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
use std::collections::HashSet;
use std::future::IntoFuture;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, mpsc};

use crate::engine::ENV_LOCK;
const TOKEN: &str = "test-token-0123456789abcdef";

fn test_app() -> Arc<App> {
    let (tx, _rx) = mpsc::channel(4);
    Arc::new(App {
        token_digest: Sha256::digest(TOKEN.as_bytes()).into(),
        principal: "qa-lead".into(),
        rbac: crate::serve::rbac::Rbac {
            enabled: false,
            keys: vec![],
        },
        tx,
        allowed_roots: vec![],
        scope: None,
        plugins: None,
        active: Mutex::new(HashSet::new()),
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
        .enable_time()
        .build()
        .unwrap();
    let b = rt
        .block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
        .unwrap();
    String::from_utf8_lossy(&b).into_owned()
}

#[test]
fn llm_status_lists_the_configured_models_and_never_the_key() {
    let m = crate::llm::mock::start(|_| "{}".into());
    let mut cfg = crate::llm::mock::cfg(&m.base, &std::env::temp_dir());
    cfg.models = crate::llm::parse_model_list("primary, backup-1,backup-2");
    cfg.model = cfg.models[0].clone();
    let v = llm_status_json(&cfg);
    assert_eq!(v["status"], "online");
    assert_eq!(v["model"], "primary");
    assert_eq!(
        v["configured_models"],
        json!(["primary", "backup-1", "backup-2"])
    );
    assert_eq!(v["api_key_configured"], false);
    cfg.api_key = Some(crate::llm::ApiKey::new("status-test-key-0123456789"));
    let v = llm_status_json(&cfg);
    assert_eq!(v["api_key_configured"], true);
    assert!(!v.to_string().contains("status-test-key"), "{v}");
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
    ("POST", "/api/agent/directives/synthesize"),
    ("GET", "/api/agent/crawl"),
    ("POST", "/api/agent/crawl"),
    ("POST", "/api/agent/run"),
    ("GET", "/api/agent/runs"),
    ("GET", "/api/agent/runs/{id}"),
    ("DELETE", "/api/agent/runs/{id}"),
    ("POST", "/api/agent/runs/{id}/approve"),
    ("POST", "/api/agent/runs/{id}/reject"),
    ("POST", "/api/agent/runs/{id}/cancel"),
    ("GET", "/api/agent/runs/{id}/report/{fmt}"),
    ("POST", "/api/agent/retest"),
    ("GET", "/api/agent/memory"),
    ("DELETE", "/api/agent/memory"),
    ("POST", "/api/agent/memory/accept"),
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
    ("POST", "/api/eval-ai"),
    ("POST", "/api/fix"),
    ("POST", "/api/mutate"),
    ("POST", "/api/github/pr-comment"),
    ("GET", "/api/whoami"),
    ("GET", "/api/settings"),
    ("GET", "/api/settings/checks"),
    ("GET", "/api/rbac"),
    ("GET", "/api/vulns"),
    ("POST", "/api/vulns/{fp}"),
    ("GET", "/api/exploits/templates"),
    ("POST", "/api/exploits/run"),
    ("GET", "/api/badges/gate"),
    ("GET", "/api/badges/ledger"),
    ("GET", "/api/badges/network"),
    ("GET", "/api/badges/gate/{id}"),
    ("GET", "/api/badges/ledger/{id}"),
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
    let src = include_str!("router.rs");
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
fn agent_memory_routes_read_accept_and_forget_for_the_authenticated_principal() {
    use crate::agent::memory::{self, DefectStatus, KnownDefect, Memory};
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("agent-memory");
    let target = "http://127.0.0.1:9";
    let key = memory::target_key(target);
    let (_rt, base) = test_server();
    let c = client();
    let auth = format!("Bearer {TOKEN}");
    let q = |t: &str| format!("{base}/api/agent/memory?target={t}");
    // nothing remembered yet; a target that is not an http(s) URL is refused
    let r = c
        .get(q(target))
        .header("authorization", &auth)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(r.json::<serde_json::Value>().unwrap()["exists"], false);
    let r = c
        .get(q("not-a-url"))
        .header("authorization", &auth)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    // one known open defect
    let fp = memory::fingerprint("authz", "/admin");
    let mut m = Memory::fresh(&key, target, "2026-03-01T00:00:00Z");
    m.defects.insert(
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
            repro: vec![],
        },
    );
    memory::write_memory(&memory::dir(), &mut m, "2026-03-01T00:00:00Z").unwrap();
    let v: serde_json::Value = c
        .get(q(target))
        .header("authorization", &auth)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(v["exists"], true);
    assert_eq!(v["memory"]["defects"][&fp]["status"], "open");
    // accept: validation first, then the principal is recorded (never client text)
    let post = |body: serde_json::Value| {
        c.post(format!("{base}/api/agent/memory/accept"))
            .header("authorization", &auth)
            .json(&body)
            .send()
            .unwrap()
    };
    let body = |fp: &str, reason: &str, exp: &str| serde_json::json!({"target": target, "fingerprint": fp, "reason": reason, "expires": exp, "by": "mallory"});
    assert_eq!(post(body(&fp, "", "2099-12-31")).status().as_u16(), 400);
    assert_eq!(post(body(&fp, "ok", "2000-01-01")).status().as_u16(), 400);
    assert_eq!(
        post(body("deadbeefdead", "ok", "2099-12-31"))
            .status()
            .as_u16(),
        404
    );
    let r = post(body(&fp[..10], "tracked in OPS-7", "2099-12-31"));
    assert_eq!(r.status().as_u16(), 200);
    let a: serde_json::Value = r.json().unwrap();
    assert_eq!(a["fingerprint"], fp.as_str());
    assert_eq!(
        a["acceptance"]["by"], "qa-lead",
        "the authenticated principal, not the body"
    );
    let v: serde_json::Value = c
        .get(q(target))
        .header("authorization", &auth)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        v["memory"]["defects"][&fp]["accepted"]["expires"],
        "2099-12-31"
    );
    // forget
    let del = || {
        c.delete(q(target))
            .header("authorization", &auth)
            .send()
            .unwrap()
    };
    assert_eq!(
        del().json::<serde_json::Value>().unwrap()["forgotten"],
        true
    );
    assert_eq!(
        del().json::<serde_json::Value>().unwrap()["forgotten"],
        false
    );
    let _ = std::fs::remove_dir_all(d);
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
fn test_agent_directives_synthesize_endpoint() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_rt, base) = test_server();
    let c = client();
    let auth = format!("Bearer {TOKEN}");
    let resp = c
        .post(format!("{base}/api/agent/directives/synthesize"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(r#"{"target":"https://example.com"}"#)
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let val: serde_json::Value = resp.json().unwrap();
    assert!(
        val["target"]
            .as_str()
            .unwrap()
            .starts_with("https://example.com")
    );
    assert!(val["directives"]["focus_areas"].is_array());
    assert!(
        !val["directives"]["focus_areas"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(val["custom_instructions"].is_string());
    assert!(val["canary_token"].is_string());
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
    assert_eq!(
        signoff_err(crate::agent::SignOffRefused("NO_GO".into()).into()).status(),
        StatusCode::CONFLICT
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
        .enable_time()
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
    app.active
        .lock()
        .unwrap()
        .insert("20990101-000000-0000000000000003".into());
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

#[test]
fn persistent_queue_resumes_on_startup() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("resume");
    let id = "20990101-000000-000000000000000b";
    write_queued(id, "http://t/").unwrap();
    let opts = ScanOpts {
        target: "http://t/".into(),
        ..Default::default()
    };
    std::fs::write(
        engine::run_dir(id).join("opts.json"),
        serde_json::to_string(&opts).unwrap(),
    )
    .unwrap();

    let (tx, mut rx) = mpsc::channel(10);
    let stale = handle_startup_runs(&tx);
    assert!(
        !stale.contains(&id.to_string()),
        "queued run with opts.json was not marked stale"
    );
    let recvd = rx.try_recv();
    assert!(recvd.is_ok(), "queued run was resumed into channel");
    assert_eq!(recvd.unwrap().0, id);
    let _ = std::fs::remove_dir_all(d);
}

// ---------------------------------------------------------------- lifecycle

#[test]
fn startup_reaping_claims_only_runs_this_server_created() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("reap");
    init_server_id().unwrap();
    let mine = SERVER_ID.get().unwrap().clone();
    // a finished run of this server
    let ours = "20990101-000000-00000000000000a1";
    write_queued(ours, "http://t/").unwrap();
    write_status(ours, "done", None);
    assert_eq!(
        read_json(ours, "status.json").unwrap()["server"],
        json!(mine)
    );
    // a run that was queued/running when the previous process died (found by mark_stale_runs)
    let died = "20990101-000000-00000000000000a2";
    write_queued(died, "http://t/").unwrap();
    write_status(died, "running", None);
    let stale = mark_stale_runs();
    assert_eq!(stale, vec![died.to_string()]);
    // a run whose status.json was stamped by some other server
    let foreign = "20990101-000000-00000000000000a3";
    std::fs::create_dir_all(engine::run_dir(foreign)).unwrap();
    std::fs::write(
        engine::run_dir(foreign).join("status.json"),
        r#"{"id":"x","state":"done","server":"someone-else"}"#,
    )
    .unwrap();
    // a CLI scan: run.json but never a status.json
    let cli = "20990101-000000-00000000000000a4";
    std::fs::create_dir_all(engine::run_dir(cli)).unwrap();
    std::fs::write(engine::run_dir(cli).join("run.json"), "{}").unwrap();
    // a status.json from before the marker existed, not stale
    let legacy = "20990101-000000-00000000000000a5";
    std::fs::create_dir_all(engine::run_dir(legacy)).unwrap();
    std::fs::write(
        engine::run_dir(legacy).join("status.json"),
        r#"{"id":"x","state":"done"}"#,
    )
    .unwrap();
    // a run with no directory at all (someone else's data dir, or already deleted)
    let nodir = "20990101-000000-00000000000000a6";

    assert!(claims_run(&stale, ours));
    assert!(claims_run(&stale, died));
    for (what, id) in [
        ("foreign marker", foreign),
        ("CLI scan", cli),
        ("legacy, not stale", legacy),
        ("no run directory", nodir),
    ] {
        assert!(!claims_run(&stale, id), "{what} must be left alone");
    }
    assert!(
        !claims_run(&stale, "../../etc"),
        "invalid ids are never claimed"
    );
    // the marker is stable across restarts of the same data dir
    assert_eq!(init_server_id().unwrap(), mine);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn forced_shutdown_fits_inside_the_compose_stop_grace_period() {
    let compose = include_str!("../../docker-compose.yml");
    let grace: u64 = compose
        .lines()
        .find_map(|l| l.trim().strip_prefix("stop_grace_period:"))
        .and_then(|v| v.trim().trim_end_matches('s').parse().ok())
        .expect("docker-compose.yml sets stop_grace_period on readyhai");
    // 8 s drain + two bounded docker calls + runtime teardown must finish before SIGKILL
    let worst = FORCED_SHUTDOWN.as_secs() + 2 * SHUTDOWN_REAP_PER_CALL.as_secs() + 2;
    assert!(
        FORCED_SHUTDOWN.as_secs() < 10,
        "shorter than Docker's default 10 s grace"
    );
    assert!(
        worst < grace,
        "worst case {worst}s vs stop_grace_period {grace}s"
    );
    assert!(
        compose.contains("init: true"),
        "a real PID 1 so SIGTERM and zombies are handled"
    );
}

#[test]
fn deleting_a_run_that_cannot_be_removed_is_an_error() {
    use std::os::unix::fs::PermissionsExt;
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("delfail");
    let app = test_app();
    let id = "20990101-000000-00000000000000b1";
    write_queued(id, "/t").unwrap();
    write_status(id, "done", None);
    // a read-only `runs/` makes removing a run directory fail
    let runs = d.join("runs");
    std::fs::set_permissions(&runs, std::fs::Permissions::from_mode(0o555)).unwrap();
    let writable = std::fs::File::create(runs.join(".probe")).is_ok();
    let r = futures_lite_block(api_scan_delete(State(app.clone()), Path(id.into())));
    std::fs::set_permissions(&runs, std::fs::Permissions::from_mode(0o755)).unwrap();
    if writable {
        // running as root: permissions do not apply, so there is nothing to observe
        let _ = std::fs::remove_dir_all(d);
        return;
    }
    assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(engine::run_dir(id).exists(), "the data is still there");
    assert!(body_text(r).contains("could not delete"));
    // once it can be removed, the delete reports success
    let r = futures_lite_block(api_scan_delete(State(app), Path(id.into())));
    assert_eq!(r.status(), StatusCode::OK);
    let _ = std::fs::remove_dir_all(d);
}

// ---------------------------------------------------------------- agent routes

fn agent_req(v: serde_json::Value) -> crate::agent::AgentRunRequest {
    serde_json::from_value(v).unwrap()
}

#[test]
fn rest_agent_repo_is_confined_to_the_allowed_roots_and_needs_a_plain_ref() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("rh-guard-repo-{}", std::process::id()));
    std::fs::create_dir_all(root.join("svc")).unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let app = App {
        token_digest: Sha256::digest(TOKEN.as_bytes()).into(),
        principal: "qa-lead".into(),
        rbac: crate::serve::rbac::Rbac {
            enabled: false,
            keys: vec![],
        },
        tx,
        allowed_roots: vec![root.clone()],
        scope: None,
        plugins: None,
        active: Mutex::new(HashSet::new()),
        probes: Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES)),
    };
    let svc = root.join("svc");
    let mut r =
        agent_req(json!({"target": "https://a.example/", "repo": svc, "diff_base": "origin/main"}));
    guard_repo(&app, &mut r).unwrap();
    assert_eq!(r.repo.as_deref(), svc.to_str());
    assert_eq!(r.diff_base.as_deref(), Some("origin/main"));
    // a symlink out of the root does not smuggle another directory in
    let other = std::env::temp_dir().join(format!("rh-guard-other-{}", std::process::id()));
    std::fs::create_dir_all(&other).unwrap();
    let link = root.join("link");
    let _ = std::os::unix::fs::symlink(&other, &link);
    for repo in [other.clone(), link, root.join("missing")] {
        let mut r =
            agent_req(json!({"target": "https://a.example/", "repo": repo, "diff_base": "main"}));
        assert!(guard_repo(&app, &mut r).is_err(), "{repo:?}");
    }
    for body in [
        json!({"target": "https://a.example/", "repo": svc}),
        json!({"target": "https://a.example/", "diff_base": "main"}),
        json!({"target": "https://a.example/", "repo": svc, "diff_base": "--output=x"}),
        json!({"target": "https://a.example/", "repo": svc, "diff_base": "a..b"}),
    ] {
        assert!(
            guard_repo(&app, &mut agent_req(body.clone())).is_err(),
            "{body}"
        );
    }
    // no roots configured: no repo is accepted, the way /runs treats a path
    let mut r =
        agent_req(json!({"target": "https://a.example/", "repo": svc, "diff_base": "main"}));
    let e = guard_repo(&test_app(), &mut r).unwrap_err();
    assert!(e.contains("outside READYHAI_ALLOWED_ROOTS"), "{e}");
    // neither field: nothing to do
    let mut r = agent_req(json!({"target": "https://a.example/"}));
    guard_repo(&app, &mut r).unwrap();
    assert!(r.repo.is_none() && r.diff_base.is_none());
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&other);
}

#[test]
fn rest_agent_run_is_clamped_like_mcp() {
    // defaults pass
    let mut r = agent_req(json!({"target": "https://app.example/"}));
    assert!(clamp_agent_request(&mut r).is_ok());
    assert!(r.thinking_budget_tokens <= crate::llm::MAX_THINKING_BUDGET);
    // unknown profile / model tier are refused
    let mut r = agent_req(json!({"target": "https://a.example/", "profile": "yolo"}));
    assert!(clamp_agent_request(&mut r).unwrap_err().contains("profile"));
    let mut r = agent_req(json!({"target": "https://a.example/", "model_tier": "ultra"}));
    assert!(
        clamp_agent_request(&mut r)
            .unwrap_err()
            .contains("model_tier")
    );
    for p in PROFILES {
        let mut r = agent_req(json!({"target": "https://a.example/", "profile": p}));
        assert!(clamp_agent_request(&mut r).is_ok(), "{p}");
    }
    for t in MODEL_TIERS {
        let mut r = agent_req(json!({"target": "https://a.example/", "model_tier": t}));
        assert!(clamp_agent_request(&mut r).is_ok(), "{t}");
    }
    // an oversized reasoning budget is capped, not passed on
    let mut r = agent_req(
        json!({"target": "https://a.example/", "thinking_budget_tokens": 4_000_000_000u64}),
    );
    clamp_agent_request(&mut r).unwrap();
    assert_eq!(r.thinking_budget_tokens, crate::llm::MAX_THINKING_BUDGET);
    // custom instructions: configured limit (default 32 KB) is fine, more is refused (never silently cut)
    let max_ci = max_custom_instructions_bytes();
    let mut r = agent_req(
        json!({"target": "https://a.example/", "custom_instructions": "x".repeat(max_ci)}),
    );
    assert!(clamp_agent_request(&mut r).is_ok());
    let mut r =
        agent_req(json!({"target": "https://a.example/", "directives": "x".repeat(max_ci + 1)}));
    assert!(
        clamp_agent_request(&mut r)
            .unwrap_err()
            .contains(&format!("the limit is {max_ci}"))
    );
    // blank target / blank instructions
    let mut r = agent_req(json!({"target": "  "}));
    assert!(clamp_agent_request(&mut r).is_err());
    let mut r = agent_req(json!({"target": "https://a.example/", "custom_instructions": "   "}));
    clamp_agent_request(&mut r).unwrap();
    assert!(r.custom_instructions.is_none());
}

/// Minimal stored agent run (what `agent-runs/<id>/report.json` holds).
fn write_agent_run(id: &str, target: &str, started: &str) {
    let dir = crate::agent::agent_runs_dir().join(id);
    std::fs::create_dir_all(&dir).unwrap();
    let rep = json!({
        "id": id, "target": target, "profile": "standard", "model": "none",
        "provider": "deterministic", "started_at": started, "finished_at": null,
        "status": "completed", "steps": [], "planned_cases": [], "executed_results": [],
        "triaged_defects": [], "evidence_ledger": null, "approval_status": null,
        "approved_by": null, "approval_notes": null, "approved_at": null, "error": null
    });
    std::fs::write(dir.join("report.json"), rep.to_string()).unwrap();
}

#[test]
fn cancel_route_is_authenticated_and_answers_404_409_and_202() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("cancel");
    let done = "20990101-000000-00000000000000e1";
    let live = "20990101-000000-00000000000000e2";
    let in_process = "20990101-000000-00000000000000e3";
    let unknown = "20990101-000000-00000000000000e4";
    write_agent_run(done, "https://a.example/", "2099-01-01T00:00:00Z");
    write_agent_run(live, "https://a.example/", "2099-01-01T00:00:01Z");
    // the checkpoint of a run that is still going says "running"
    let live_report = crate::agent::agent_runs_dir()
        .join(live)
        .join("report.json");
    let text = std::fs::read_to_string(&live_report).unwrap();
    std::fs::write(
        &live_report,
        text.replace("\"status\":\"completed\"", "\"status\":\"running\""),
    )
    .unwrap();
    assert_eq!(
        crate::agent::load_agent_run(live).unwrap().status,
        "running"
    );
    write_agent_run(in_process, "https://a.example/", "2099-01-01T00:00:02Z");

    let (_rt, base) = test_server();
    let c = client();
    let post = |id: &str, token: Option<&str>| {
        let mut rb = c
            .post(format!("{base}/api/agent/runs/{id}/cancel"))
            .header("content-type", "application/json")
            .body("{}");
        if let Some(t) = token {
            rb = rb.header("authorization", format!("Bearer {t}"));
        }
        rb.send().unwrap()
    };
    // without a valid token nothing is looked up or cancelled
    assert_eq!(post(live, None).status().as_u16(), 401);
    assert_eq!(
        post(live, Some("wrong-token-xxxxxxxxxxxxxxxx"))
            .status()
            .as_u16(),
        401
    );
    assert!(
        !crate::agent::agent_runs_dir()
            .join(live)
            .join("CANCEL")
            .exists()
    );

    // unknown id: 404; malformed id: 400; finished run: 409
    assert_eq!(post(unknown, Some(TOKEN)).status().as_u16(), 404);
    assert_eq!(post("not%20a%20run", Some(TOKEN)).status().as_u16(), 400);
    let r = post(done, Some(TOKEN));
    assert_eq!(r.status().as_u16(), 409);
    assert!(r.text().unwrap().contains("not running"));
    assert!(
        !crate::agent::agent_runs_dir()
            .join(done)
            .join("CANCEL")
            .exists()
    );

    // a run whose checkpoint says running: the cancel marker is written (other processes honour it)
    let r = post(live, Some(TOKEN));
    assert_eq!(r.status().as_u16(), 202);
    let v: serde_json::Value = r.json().unwrap();
    assert_eq!(
        (v["id"].as_str(), v["status"].as_str()),
        (Some(live), Some("cancelling"))
    );
    assert!(
        crate::agent::agent_runs_dir()
            .join(live)
            .join("CANCEL")
            .is_file()
    );

    // a run executing in this process is flagged directly through its cancel token
    let token = crate::agent::CancelToken::new();
    let _reg = crate::agent::register_run(in_process, &token);
    assert!(!token.is_cancelled());
    assert_eq!(post(in_process, Some(TOKEN)).status().as_u16(), 202);
    assert!(token.is_cancelled());
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn agent_runs_list_returns_only_the_newest_50() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("agentlist");
    for i in 0..60u32 {
        let id = format!("20990101-0000{:02}-{:016x}", i, i);
        write_agent_run(
            &id,
            "https://a.example/",
            &format!("2099-01-01T00:00:{i:02}Z"),
        );
    }
    let l = list_agent_runs_capped();
    assert_eq!(l.len(), MAX_LISTED_RUNS);
    assert!(
        l[0].id.starts_with("20990101-000059-"),
        "newest first: {}",
        l[0].id
    );
    // the ten oldest (seconds 00..09) are the ones left out
    assert!(
        l.iter().all(|r| !r.id.starts_with("20990101-00000")),
        "oldest runs listed"
    );
    // the route does the work off the async threads
    let r = futures_lite_block(agent_runs_list());
    assert_eq!(r.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_text(r)).unwrap();
    assert_eq!(v["runs"].as_array().unwrap().len(), MAX_LISTED_RUNS);
    let _ = std::fs::remove_dir_all(d);
}

/// A stub HTTP server that counts the connections it gets.
fn counting_stub() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/", l.local_addr().unwrap());
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                let _ = c.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
            });
        }
    });
    (base, hits)
}

fn retest_body(target: &str, run_id: Option<&str>) -> RetestPayload {
    serde_json::from_value(json!({
        "target": target,
        "run_id": run_id,
        "case": {
            "id": "case-1", "title": "root responds", "component": "/",
            "method": "GET", "technique": "boundary", "input_hint": "",
            "expected_behavior": "200", "expected_status": 200, "risk_level": "low"
        }
    }))
    .unwrap()
}

#[test]
fn retest_with_a_mismatched_target_is_rejected_and_nothing_is_sent_or_written() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("retest");
    let (stored_target, stored_hits) = counting_stub();
    let (other_target, other_hits) = counting_stub();
    // scope: loopback is internal, so list it (nonprod) for the stubs
    let scope_file = d.join("scope.toml");
    std::fs::write(&scope_file, "[[hosts]]\nhost='127.0.0.1'\nenv='nonprod'\n").unwrap();
    let mut app = test_app();
    Arc::get_mut(&mut app).unwrap().scope = Some(scope_file);

    let id = "20990101-000000-00000000000000c1";
    write_agent_run(id, &stored_target, "2099-01-01T00:00:00Z");
    let report = crate::agent::agent_runs_dir().join(id).join("report.json");
    let before = std::fs::read(&report).unwrap();

    // another target: refused with 409 before any request is made or any file is touched
    let r = futures_lite_block(agent_retest(
        State(app.clone()),
        Json(retest_body(&other_target, Some(id))),
    ));
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert!(body_text(r).contains("does not match"));
    assert_eq!(other_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(stored_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(&report).unwrap(),
        before,
        "the stored run was modified"
    );

    // an unknown run: 404, still nothing sent
    let r = futures_lite_block(agent_retest(
        State(app.clone()),
        Json(retest_body(
            &stored_target,
            Some("20990101-000000-00000000000000c2"),
        )),
    ));
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(stored_hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    // the run's own target: executed, and the result lands on the run
    let r = futures_lite_block(agent_retest(
        State(app.clone()),
        Json(retest_body(&stored_target, Some(id))),
    ));
    assert_eq!(r.status(), StatusCode::OK, "{}", body_text(r));
    assert!(stored_hits.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    let rep = crate::agent::load_agent_run(id).unwrap();
    assert!(rep.executed_results.iter().any(|c| c.case_id == "case-1"));
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn retest_targets_compare_as_the_client_sees_them() {
    assert!(same_target("https://App.Example/", "https://app.example"));
    assert!(same_target(
        "https://app.example/a/",
        "https://app.example/a"
    ));
    assert!(same_target("http://127.0.0.1:80/", "http://127.0.0.1/"));
    assert!(!same_target(
        "https://app.example/",
        "https://other.example/"
    ));
    assert!(!same_target("https://app.example/", "http://app.example/"));
    assert!(!same_target(
        "https://app.example:8443/",
        "https://app.example/"
    ));
    assert!(!same_target(
        "https://app.example/a",
        "https://app.example/b"
    ));
    // a stored target that is not a web URL (a repo run) never matches
    assert!(!same_target("/srv/repo", "https://app.example/"));
    assert!(!same_target("/srv/repo", "/srv/repo"));
}

#[test]
fn report_regeneration_is_atomic_and_never_recreates_a_deleted_run() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("regen");
    let id = "20990101-000000-00000000000000d1";
    write_agent_run(id, "https://a.example/", "2099-01-01T00:00:00Z");
    let run_dir = crate::agent::agent_runs_dir().join(id);

    // first GET renders the reports; the HTML CSP has no script-src at all
    let r = agent_report_blocking(id, "html");
    assert_eq!(r.status(), StatusCode::OK);
    let csp = r.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_string();
    assert!(!csp.contains("script-src"), "{csp}");
    assert!(csp.contains("default-src 'none'") && csp.contains("style-src 'unsafe-inline'"));
    for f in [
        "readyhai-report.html",
        "readyhai-report.json",
        "readyhai-report.md",
    ] {
        assert!(run_dir.join("report").join(f).is_file(), "{f}");
    }
    // no temp directories or half-written files are left behind
    let names: Vec<String> = std::fs::read_dir(&run_dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.contains(".tmp")), "{names:?}");

    // a failing generator leaves the report directory as it was (no partial files)
    let rep_dir = run_dir.join("report2");
    let e = regenerate_reports(std::slice::from_ref(&run_dir), &rep_dir, |tmp| {
        std::fs::write(tmp.join("half.html"), "<html>").unwrap();
        anyhow::bail!("render failed")
    });
    assert!(e.is_err());
    assert!(!rep_dir.exists());
    assert!(
        std::fs::read_dir(&run_dir)
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().contains(".tmp"))
    );

    // the run is deleted: regenerating (or serving a report for) it must not bring it back
    std::fs::remove_dir_all(&run_dir).unwrap();
    let e = regenerate_reports(
        std::slice::from_ref(&run_dir),
        &run_dir.join("report"),
        |tmp| {
            std::fs::write(tmp.join("x.html"), "x").unwrap();
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    assert!(!run_dir.exists(), "regeneration recreated a deleted run");
    let r = agent_report_blocking(id, "html");
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert!(
        !run_dir.exists(),
        "serving a report recreated a deleted run"
    );

    // same for core runs served through /api/scans
    let core = "20990101-000000-00000000000000d2";
    let r = api_scan_report_blocking(core, "html", "readyhai-report.html", "text/html");
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert!(!engine::run_dir(core).exists());
    let _ = std::fs::remove_dir_all(d);
}

// ---------------------------------------------------------------- guard

fn guard_sync(app: &App, url: &str, intrusive: bool) -> Result<scope::Egress, Response> {
    futures_lite_block(guard(app, url, intrusive))
}

#[test]
fn guard_allows_public_blocks_internal_without_a_scope_file() {
    let app = test_app();
    // no scope file: a public host is allowed (relaxed policy)...
    assert!(guard_sync(&app, "http://app.example/", false).is_ok());
    // ...but an internal/metadata host still needs an explicit entry
    assert_eq!(
        guard_sync(&app, "http://169.254.169.254/latest/", false)
            .unwrap_err()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        guard_sync(&app, "http://127.0.0.1:9000/", false)
            .unwrap_err()
            .status(),
        StatusCode::FORBIDDEN
    );
    // internal names are internal whatever DNS says
    for u in [
        "http://localhost:9000/",
        "http://api.localhost/",
        "http://host.docker.internal/",
    ] {
        assert_eq!(
            guard_sync(&app, u, false).unwrap_err().status(),
            StatusCode::FORBIDDEN,
            "{u}"
        );
    }
    // a name that does not resolve: fine to read, refused for intrusive actions (fail closed)
    assert!(guard_sync(&app, "http://nx.invalid/", false).is_ok());
    assert_eq!(
        guard_sync(&app, "http://nx.invalid/", true)
            .unwrap_err()
            .status(),
        StatusCode::FORBIDDEN
    );
    // non-http schemes are always refused
    assert_eq!(
        guard_sync(&app, "ftp://app.example/", false)
            .unwrap_err()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn guard_resolves_names_off_the_async_threads() {
    // On a current-thread runtime a blocking lookup on the async thread would stall every
    // other task. Run the guard next to a ticking task: the ticker keeps running while the
    // (slow) resolver works.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let app = test_app();
    rt.block_on(async {
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(5)).await;
                t.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let r = guard(&app, "http://slow-resolver.example/", true).await;
        ticker.abort();
        assert!(r.is_ok());
        let n = ticks.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            n >= 10,
            "the async thread was blocked during the lookup (only {n} ticks)"
        );
    });
}

#[test]
fn guard_enforces_scope_and_nonprod_gate_from_the_file() {
    let d = std::env::temp_dir().join(format!("readyhai-serve-guard-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("scope.toml");
    std::fs::write(
        &f,
        "[[hosts]]\nhost='qa.example'\nenv='nonprod'\n[[hosts]]\nhost='www.example'\nenv='prod'\n",
    )
    .unwrap();
    let mut app = test_app();
    Arc::get_mut(&mut app).unwrap().scope = Some(f);
    assert!(guard_sync(&app, "https://qa.example/a", true).is_ok());
    assert!(guard_sync(&app, "https://www.example/", false).is_ok());
    // www.example is listed prod → intrusive refused
    assert_eq!(
        guard_sync(&app, "https://www.example/", true)
            .unwrap_err()
            .status(),
        StatusCode::FORBIDDEN
    );
    // an unlisted public host is allowed (defaults to nonprod for full testing)
    assert!(guard_sync(&app, "https://other.example/", false).is_ok());
    assert!(guard_sync(&app, "https://other.example/", true).is_ok());
    assert!(guard_sync(&app, "https://agent-prod.nuhire.in/", false).is_ok());
    assert_eq!(
        futures_lite_block(guard_spec(&app, Some("  ".into()))).unwrap(),
        None
    );
    assert_eq!(
        futures_lite_block(guard_spec(
            &app,
            Some("https://other.example/openapi.json".into())
        ))
        .unwrap()
        .unwrap(),
        "https://other.example/openapi.json"
    );
    // an internal spec host still needs an entry
    assert!(
        futures_lite_block(guard_spec(
            &app,
            Some("http://10.0.0.5/openapi.json".into())
        ))
        .is_err()
    );
    // scans go through the same precheck: an unlisted internal URL is refused
    let opts = ScanOpts {
        target: "http://10.0.0.5:8080/".into(),
        ..Default::default()
    };
    assert_eq!(
        futures_lite_block(prepare_scan(&app, opts))
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let opts = ScanOpts {
        target: "/etc".into(),
        ..Default::default()
    };
    assert_eq!(
        futures_lite_block(prepare_scan(&app, opts))
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let opts = ScanOpts {
        target: "https://qa.example/".into(),
        ..Default::default()
    };
    let opts = futures_lite_block(prepare_scan(&app, opts)).unwrap();
    assert!(opts.server);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn a_scope_file_that_went_bad_refuses_every_request() {
    let d = std::env::temp_dir().join(format!("readyhai-serve-badscope-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let mut app = test_app();
    // a directory where the file should be (compose's bind mount of a missing scope.toml)
    Arc::get_mut(&mut app).unwrap().scope = Some(d.clone());
    let e = guard_sync(&app, "https://app.example/", false).unwrap_err();
    assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body_text(e).contains("directory"));
    // never "no scope": not even a public read goes through
    std::fs::write(d.join("s.toml"), "not toml [").unwrap();
    Arc::get_mut(&mut app).unwrap().scope = Some(d.join("s.toml"));
    assert_eq!(
        guard_sync(&app, "https://app.example/", false)
            .unwrap_err()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn startup_validates_the_scope_path() {
    let d = std::env::temp_dir().join(format!("readyhai-serve-startup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("adir")).unwrap();
    // not configured / blank: no scope file
    assert_eq!(validate_scope_path(None).unwrap(), None);
    assert_eq!(validate_scope_path(Some("  ")).unwrap(), None);
    // configured: it must exist, be a file and parse
    let e = format!(
        "{:#}",
        validate_scope_path(Some(d.join("missing.toml").to_str().unwrap())).unwrap_err()
    );
    assert!(
        e.contains("READYHAI_SCOPE") && e.contains("scope.example.toml"),
        "{e}"
    );
    let e = format!(
        "{:#}",
        validate_scope_path(Some(d.join("adir").to_str().unwrap())).unwrap_err()
    );
    assert!(
        e.contains("is a directory") && e.contains("cp scope.example.toml scope.toml"),
        "{e}"
    );
    std::fs::write(d.join("bad.toml"), "[[hosts]\n").unwrap();
    assert!(validate_scope_path(Some(d.join("bad.toml").to_str().unwrap())).is_err());
    std::fs::write(
        d.join("ok.toml"),
        "[[hosts]]\nhost='a.example'\nenv='nonprod'\n",
    )
    .unwrap();
    let ok = d.join("ok.toml");
    assert_eq!(
        validate_scope_path(Some(ok.to_str().unwrap())).unwrap(),
        Some(ok)
    );
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
fn badge_values_cannot_be_injected() {
    let evil = "\"><script>alert(1)</script>&'";
    for svg in [ledger_svg(Some(evil)), network_svg(Some(evil))] {
        assert!(!svg.contains("<script"), "{svg}");
        assert!(!svg.contains("alert(1)"), "{svg}");
        assert!(svg.contains("n/a"), "arbitrary text renders n/a: {svg}");
        assert_eq!(svg.matches('<').count(), svg.matches('>').count());
    }
    // a score-shaped string in the status slot, or a number out of range, never renders verbatim
    assert!(gate_svg(Some("97")).contains("n/a"));
    assert!(network_svg(Some("<svg-onload>alert(1)")).contains("n/a"));
    assert!(ledger_svg(Some(&"A".repeat(500))).contains("n/a"));
    // scores clamp to 0..=100
    assert!(ledger_svg(Some("150")).contains(">100<"));
    assert!(ledger_svg(Some("88/100")).contains(">88<"));
    assert!(ledger_svg(Some("-5")).contains("n/a"));
    assert!(ledger_svg(Some("")).contains("n/a"));
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
fn a_self_reported_badge_says_it_is_self_reported() {
    // The public badges take their text from the query string, so a green one must never read as
    // ReadyHai's own attestation. The /{id} badges, which read a stored run, carry the real label.
    for svg in [
        gate_svg(Some("PASS")),
        ledger_svg(Some("94")),
        network_svg(Some("PASS")),
    ] {
        assert!(
            svg.contains("reported"),
            "unverified badge self-labels: {svg}"
        );
        assert!(!svg.contains("ReadyHai"), "{svg}");
    }
    let verified = badge_svg("ReadyHai", verdict_color(Some("PASS")), "PASS");
    assert!(verified.contains("ReadyHai") && !verified.contains("reported"));
}

#[test]
fn run_badges_read_a_stored_run_instead_of_the_query_string() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _d = data_dir("badges-run");
    let auth = format!("Bearer {TOKEN}");
    let id = "20990101-000000-00000000000000b1";
    std::fs::create_dir_all(crate::engine::run_dir(id)).unwrap();
    std::fs::write(
        crate::engine::run_dir(id).join("run.json"),
        json!({ "id": id, "verdict": "WARN" }).to_string(),
    )
    .unwrap();
    write_agent_run(id, "https://a.example/", "2099-01-01T00:00:00Z");
    let (_rt, base) = test_server();
    let c = client();
    let get = |p: &str| {
        c.get(format!("{base}{p}"))
            .header("authorization", &auth)
            .send()
            .unwrap()
    };
    let svg = |p: &str| {
        let r = get(p);
        assert_eq!(r.status().as_u16(), 200, "{p}");
        r.text().unwrap()
    };
    assert!(svg(&format!("/api/badges/gate/{id}")).contains(">WARN<"));
    // the agent run has no ledger at all, so its score badge is not measured
    assert!(svg(&format!("/api/badges/ledger/{id}")).contains("n/a"));
    let id2 = "20990101-000000-00000000000000b2";
    write_agent_run(id2, "https://a.example/", "2099-01-01T00:00:01Z");
    let rep = crate::agent::agent_runs_dir().join(id2).join("report.json");
    let text = std::fs::read_to_string(&rep).unwrap();
    std::fs::write(
        &rep,
        text.replace(
            "\"evidence_ledger\":null",
            "\"evidence_ledger\":{\"overall_readiness\":0,\"gate_verdict\":\"SCANNED\",\
             \"executive_summary\":\"\",\"exit_criteria_checklist\":[],\"evaluated\":false}",
        ),
    )
    .unwrap();
    // a discovery-only ledger scores nothing, so the badge must not show 0 as if it were measured
    assert!(svg(&format!("/api/badges/ledger/{id2}")).contains("n/a"));
    assert_eq!(
        get("/api/badges/gate/no-such-run-9").status().as_u16(),
        404,
        "unknown run"
    );
    // traversal-shaped ids never reach the filesystem as a badge
    assert_eq!(
        get("/api/badges/gate/..%2F..%2Fetc").status().as_u16(),
        400,
        "encoded traversal"
    );
    let r = get("/api/badges/gate/%2e%2e").status().as_u16();
    assert!(r == 400 || r == 404, "dot-dot: {r}");
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
    let p: PrCommentPayload = serde_json::from_str(r#"{"verdict":"x)](http://evil)"}"#).unwrap();
    let (md, badge) = pr_comment_markdown(&p);
    assert!(
        !badge.contains("evil") && !md.contains("](http://evil"),
        "{md}"
    );
    assert!(md.contains("NOT EVALUATED"));
}

#[test]
fn eval_ai_route_evaluates_rag_payload() {
    let (_rt, base) = test_server();
    let c = client();
    let auth = format!("Bearer {TOKEN}");
    let payload = serde_json::json!({
        "query": "What is the capital of France?",
        "context": "Paris is the capital and most populous city of France.",
        "response": "The capital of France is Paris.",
        "threshold": 0.70
    });
    let r = c
        .post(format!("{base}/api/eval-ai"))
        .header("authorization", &auth)
        .json(&payload)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let res: serde_json::Value = r.json().unwrap();
    assert_eq!(res["total_cases"], 1);
    assert_eq!(res["passed_cases"], 1);
    assert_eq!(res["results"][0]["passed"], true);
}

#[test]
fn fix_route_synthesizes_remediation() {
    let (_rt, base) = test_server();
    let c = client();
    let auth = format!("Bearer {TOKEN}");
    let payload = serde_json::json!({
        "repo": ".",
        "dry_run": true,
        "verify": false
    });
    let r = c
        .post(format!("{base}/api/fix"))
        .header("authorization", &auth)
        .json(&payload)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let res: serde_json::Value = r.json().unwrap();
    assert!(res.get("patches").is_some());
    assert!(res.get("pr_title").is_some());
    assert!(res.get("pr_body").is_some());
}

#[test]
fn mutate_route_caps_max_mutants_and_refuses_missing_repos() {
    let (_rt, base) = test_server();
    let c = client();
    let auth = format!("Bearer {TOKEN}");
    // A hostile usize::MAX must not turn into an unbounded repo walk: the request is answered
    // from the clamped budget instead of hanging.
    let dir =
        std::env::temp_dir().join(format!("readyhai-serve-mutate-cap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("app.py"),
        "def f(x):\n    if x > 3:\n        return x + 1\n    return 0\n",
    )
    .unwrap();
    let r = c
        .post(format!("{base}/api/mutate"))
        .header("authorization", &auth)
        .json(&serde_json::json!({"repo": dir, "max_mutants": usize::MAX}))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let res: serde_json::Value = r.json().unwrap();
    assert!(
        res["total_mutants"].as_u64().unwrap() <= 200,
        "mutants must respect the server ceiling"
    );
    // A repo that does not exist is a 400, not an empty success pretending to be a preview.
    let r = c
        .post(format!("{base}/api/mutate"))
        .header("authorization", &auth)
        .json(&serde_json::json!({"repo": "/nonexistent/readyhai-repo"}))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
}

#[test]
fn mutate_route_generates_semantic_mutants() {
    let (_rt, base) = test_server();
    let c = client();
    let auth = format!("Bearer {TOKEN}");
    let payload = serde_json::json!({
        "repo": ".",
        "max_mutants": 5
    });
    let r = c
        .post(format!("{base}/api/mutate"))
        .header("authorization", &auth)
        .json(&payload)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let res: serde_json::Value = r.json().unwrap();
    assert!(res.get("mutants").is_some());
    assert!(res.get("total_mutants").is_some());
}

/// Drive a handler future to completion without an ambient runtime.
fn futures_lite_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

// ---------------------------------------------------------------- rbac

/// RBAC end-to-end through the real router over TCP: keyring auth, the
/// role×action matrix, /api/whoami, and the toggle back to legacy mode.
fn test_server_with(app: Arc<App>) -> (tokio::runtime::Runtime, String) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router(app);
    rt.spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (rt, format!("http://{addr}"))
}

/// (status, body) for a request against a RBAC-enabled server.
#[test]
fn rbac_roles_govern_the_api_and_the_toggle_restores_legacy_mode() {
    let _g = crate::engine::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = data_dir("rbac");
    unsafe { std::env::remove_var("READYHAI_RBAC") }; // auto: file exists => ON
    let f = std::env::temp_dir().join(format!("rh-rbac-e2e-{}.toml", std::process::id()));
    std::fs::write(
            &f,
            "[[key]]\nname = \"ro-bot\"\nrole = \"viewer\"\nkey = \"rh-view-key-Vk3xQm7zP9wL2nB4\"\n[[key]]\nname = \"ci-runner\"\nrole = \"operator\"\nkey = \"rh-oper-key-Xd8fH2tR6yU1sK5m\"\n[[key]]\nname = \"dash\"\nrole = \"admin\"\nkey = \"rh-adm-key-Zq4vN7cX9jE3bW8g\"\n",
        )
        .unwrap();
    let rbac = crate::serve::rbac::Rbac::load(Some(&f)).expect("key file loads");
    assert!(rbac.enabled && rbac.keys.len() == 2 + 1);
    let (tx, _rx) = mpsc::channel(4);
    let app = Arc::new(App {
        token_digest: Sha256::digest(TOKEN.as_bytes()).into(),
        principal: "qa-lead".into(),
        rbac,
        tx,
        allowed_roots: vec![],
        scope: None,
        plugins: None,
        active: Mutex::new(HashSet::new()),
        probes: Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES)),
    });
    let (_rt, base) = test_server_with(app);
    let c = client();
    let send = |method: reqwest::Method, path: &str, key: &str, body: serde_json::Value| {
        let mut r = c
            .request(method, format!("{base}{path}"))
            .header("authorization", format!("Bearer {key}"));
        if !body.is_null() {
            r = r
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let resp = r.send().unwrap();
        let st = resp.status().as_u16();
        (st, resp.text().unwrap_or_default())
    };
    let view_key = "rh-view-key-Vk3xQm7zP9wL2nB4";
    let oper_key = "rh-oper-key-Xd8fH2tR6yU1sK5m";
    let adm_key = "rh-adm-key-Zq4vN7cX9jE3bW8g";

    // Viewer: reads fine.
    let (st, _) = send(
        reqwest::Method::GET,
        "/checks",
        view_key,
        serde_json::Value::Null,
    );
    assert_eq!(st, 200, "viewer may read /checks");
    // Viewer: work + governance refused by the RBAC gate (distinct body).
    let (st, b) = send(
        reqwest::Method::POST,
        "/api/scans",
        view_key,
        json!({"target": "https://x.example/"}),
    );
    assert_eq!(st, 403, "viewer POST /api/scans: {b}");
    assert!(b.contains("needs operator"), "{b}");
    let (st, b) = send(reqwest::Method::POST, "/api/fix", view_key, json!({}));
    assert_eq!(st, 403);
    assert!(b.contains("needs admin"), "{b}");

    // Operator: cancel reaches the handler (unknown run id is the handler's 404,
    // not the middleware's 403).
    let (st, b) = send(
        reqwest::Method::POST,
        "/api/agent/runs/r1/cancel",
        oper_key,
        json!({}),
    );
    assert!(
        st != 403 && st != 401,
        "operator cancel reached the handler, got {st}: {b}"
    );
    // Operator: governance refused.
    let (st, _) = send(
        reqwest::Method::POST,
        "/api/agent/memory/accept",
        oper_key,
        json!({"target": "https://x.example/", "fingerprint": "f", "reason": "r", "expires": "2099-01-01"}),
    );
    assert_eq!(st, 403, "operator may not accept memory");
    let (st, _) = send(
        reqwest::Method::DELETE,
        "/api/scans/r1",
        oper_key,
        serde_json::Value::Null,
    );
    assert_eq!(st, 403, "operator may not delete");

    // whoami: identity + resolved permissions for the caller's key.
    let (st, b) = send(
        reqwest::Method::GET,
        "/api/whoami",
        oper_key,
        serde_json::Value::Null,
    );
    assert_eq!(st, 200);
    let who: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(who["name"], "ci-runner");
    assert_eq!(who["role"], "operator");
    assert_eq!(who["rbac"], "on");
    assert_eq!(who["permissions"]["operate"], true);
    assert_eq!(who["permissions"]["govern"], false);

    // Admin key passes the governance gate (handler output is irrelevant).
    let (st, b2) = send(
        reqwest::Method::POST,
        "/api/agent/memory/accept",
        adm_key,
        json!({"target": "https://x.example/", "fingerprint": "f", "reason": "r", "expires": "2099-01-01"}),
    );
    assert!(
        !b2.contains("needs admin"),
        "admin passed the gate? {st}: {b2}"
    );
    // Break-glass boot token: Admin even with RBAC on.
    let (st, b2) = send(reqwest::Method::POST, "/api/fix", TOKEN, json!({}));
    assert!(
        !b2.contains("needs admin"),
        "boot break-glass must be admin: {st}: {b2}"
    );
    // Unknown key: 401.
    let (st, _) = send(
        reqwest::Method::GET,
        "/checks",
        "rh-unknown-key-0000000000",
        serde_json::Value::Null,
    );
    assert_eq!(st, 401);

    // Toggle: READYHAI_RBAC=off makes the SAME key file inert — legacy mode.
    unsafe { std::env::set_var("READYHAI_RBAC", "off") };
    let off = crate::serve::rbac::Rbac::load(Some(&f)).expect("toggle off");
    unsafe { std::env::remove_var("READYHAI_RBAC") };
    assert!(!off.enabled);
    // (viewer key is now simply an unknown key => 401; boot token = full legacy access)
    let _ = std::fs::remove_file(f);
    let _ = std::fs::remove_dir_all(d);
}

/// Settings REST: GET defaults, PUT validation + atomic write, checks
/// catalog honors the toggle, DELETE restores defaults, RBAC panel gates.
#[test]
fn settings_api_roundtrips_and_gates() {
    let _g = crate::engine::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = data_dir("settings-api");
    unsafe { std::env::remove_var("READYHAI_SETTINGS") };
    let (_rt, base) = test_server();
    let c = client();
    let auth = format!("Bearer {TOKEN}");

    // GET with no file anywhere: defaults, exists=false.
    let r = c
        .get(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let g: serde_json::Value = r.json().unwrap();
    assert_eq!(g["effective"]["integrations"]["plugins"], "auto");
    assert_eq!(g["exists"], false);
    assert_eq!(g["shadowing_env"], false);
    assert_eq!(
        g["effective"]["vulndb"]["enabled"], true,
        "the vulndb is on by default"
    );
    assert_eq!(g["effective"]["vulndb"]["path"], serde_json::Value::Null);

    // PUT a valid doc -> file appears in the data dir, GET reflects it.
    let put = c
        .put(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .json(&serde_json::json!({
            "integrations": {"tools": "auto", "plugins": "off", "intrusive": "auto"},
            "toggle": [{"id": "readiness.deps", "enabled": "off"}]
        }))
        .send()
        .unwrap();
    assert_eq!(put.status().as_u16(), 200);
    let g: serde_json::Value = put.json().unwrap();
    assert_eq!(g["effective"]["integrations"]["plugins"], "off");
    assert_eq!(g["override_count"], 2); // toggle + plugins switch
    let f = crate::serve::settings_api::data_settings_path();
    assert!(f.is_file(), "wrote {}", f.display());
    assert!(
        std::fs::read_to_string(&f)
            .unwrap()
            .contains("readiness.deps")
    );

    // Checks catalog: the toggled check reports the settings decision.
    let r = c
        .get(format!("{base}/api/settings/checks"))
        .header("authorization", &auth)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let all: serde_json::Value = r.json().unwrap();
    let deps = all["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "readiness.deps")
        .expect("catalog lists readiness.deps");
    assert_eq!(deps["enabled"], false);
    assert_eq!(deps["decided_by"], "settings");

    // `[vulndb]`: PUT turns recording off, and a later PUT that only touches
    // integrations carries the section over instead of silently re-enabling it.
    let put = c
        .put(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .json(&serde_json::json!({"vulndb": {"enabled": false, "path": "/srv/vulns.jsonl"}}))
        .send()
        .unwrap();
    assert_eq!(put.status().as_u16(), 200);
    let g: serde_json::Value = put.json().unwrap();
    assert_eq!(g["effective"]["vulndb"]["enabled"], false);
    assert_eq!(g["effective"]["vulndb"]["path"], "/srv/vulns.jsonl");
    assert!(std::fs::read_to_string(&f).unwrap().contains("[vulndb]"));
    let put = c
        .put(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .json(&serde_json::json!({"integrations": {"plugins": "off"}}))
        .send()
        .unwrap();
    assert_eq!(put.status().as_u16(), 200);
    let g: serde_json::Value = put.json().unwrap();
    assert_eq!(
        g["effective"]["vulndb"]["enabled"], false,
        "carry-over keeps it off"
    );
    assert_eq!(g["effective"]["vulndb"]["path"], "/srv/vulns.jsonl");
    assert_eq!(g["effective"]["integrations"]["plugins"], "off");
    // an explicit null clears the path; an empty path is a 400
    let put = c
        .put(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .json(&serde_json::json!({"vulndb": {"enabled": true, "path": null}}))
        .send()
        .unwrap();
    assert_eq!(put.status().as_u16(), 200);
    let g: serde_json::Value = put.json().unwrap();
    assert_eq!(g["effective"]["vulndb"]["enabled"], true);
    assert_eq!(g["effective"]["vulndb"]["path"], serde_json::Value::Null);
    let r = c
        .put(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .json(&serde_json::json!({"vulndb": {"path": ""}}))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    // Invalid values are 400 with a message, and intrusive=on never lands.
    let r = c
        .put(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .json(&serde_json::json!({"integrations": {"intrusive": "on"}}))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let r = c
        .put(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .json(&serde_json::json!({"toggle": [{"id": "x", "enabled": "maybe"}]}))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    // DELETE -> defaults again; file gone.
    let r = c
        .delete(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert!(!f.is_file());
    let r = c
        .get(format!("{base}/api/settings"))
        .header("authorization", &auth)
        .send()
        .unwrap();
    let g: serde_json::Value = r.json().unwrap();
    assert_eq!(g["override_count"], 0);

    // RBAC panel: off-mode legacy token sees enabled=false, mode auto.
    let r = c
        .get(format!("{base}/api/rbac"))
        .header("authorization", &auth)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let g: serde_json::Value = r.json().unwrap();
    assert_eq!(g["enabled"], false);
    assert_eq!(g["mode"], "auto");
    let _ = d;
}

// ---------------------------------------------------------------- vulns api

/// GET/POST /api/vulns over the real router: listing, filters, triage, 400/404.
/// The database file comes from `vulndb::path()`, which follows `READYHAI_DATA`
/// set by `data_dir` (same trick as the agent-memory test above).
#[test]
fn vulns_api_lists_filters_and_triages() {
    use crate::vulndb::{self, VulnEntry};
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("vulns-api");
    unsafe {
        std::env::remove_var("READYHAI_SETTINGS"); // path() must follow the temp data dir
        std::env::remove_var("READYHAI_RBAC");
    }
    let (_rt, base) = test_server();
    let c = client();
    let auth = format!("Bearer {TOKEN}");
    let get = |q: &str| -> (u16, serde_json::Value) {
        let r = c
            .get(format!("{base}/api/vulns{q}"))
            .header("authorization", &auth)
            .send()
            .unwrap();
        let st = r.status().as_u16();
        (st, r.json().unwrap_or_default())
    };

    // empty database: count 0 and an empty array, not a 404
    let (st, v) = get("");
    assert_eq!(st, 200);
    assert_eq!(v["count"], 0);
    assert_eq!(v["vulns"].as_array().unwrap().len(), 0);
    assert!(!vulndb::path().exists()); // nothing written until the first record

    // seed through the storage API itself: two findings on one target, one on another
    let a = "http://a.example/";
    let b = "http://b.example/";
    vulndb::record_findings(
        a,
        &[
            VulnEntry {
                kind: "scan.http",
                rule: "http.server-header-missing",
                title: "Missing security header",
                severity: "high",
                resource: "/",
                message: "no CSP",
            },
            VulnEntry {
                kind: "scan.http",
                rule: "http.cookie-flags",
                title: "Cookie without Secure",
                severity: "medium",
                resource: "/",
                message: "session cookie",
            },
        ],
    )
    .unwrap();
    vulndb::record_findings(
        b,
        &[VulnEntry {
            kind: "plugin.nmap",
            rule: "port.open-21",
            title: "FTP open",
            severity: "low",
            resource: "21",
            message: "ftp exposed",
        }],
    )
    .unwrap();
    let fp_high = vulndb::fingerprint(a, "scan.http", "http.server-header-missing", "/");

    let (st, v) = get("");
    assert_eq!(st, 200);
    assert_eq!(v["count"], 3);
    // sorted severity desc first: high, medium, low
    let sev: Vec<&str> = v["vulns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["severity"].as_str().unwrap())
        .collect();
    assert_eq!(sev, ["high", "medium", "low"]);
    assert_eq!(v["vulns"][0]["fingerprint"], fp_high);
    assert_eq!(v["vulns"][0]["target"], "http://a.example"); // stored canonical, no trailing slash

    // filters: exact status, exact severity, target match (canonical form)
    let (st, v) = get("?severity=low");
    assert_eq!(st, 200);
    assert_eq!(v["count"], 1);
    assert_eq!(v["vulns"][0]["target"], "http://b.example");
    let (st, v) = get("?target=http://a.example/");
    assert_eq!(st, 200);
    assert_eq!(v["count"], 2);
    // invalid filter values are a 400 with a message, never a silent empty list
    let (st, v) = get("?status=bogus");
    assert_eq!(st, 400);
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("status must be one of")
    );
    let (st, _) = get("?severity=nope");
    assert_eq!(st, 400);

    // triage: accept the high finding, then it shows up as accepted
    let r = c
        .post(format!("{base}/api/vulns/{fp_high}"))
        .header("authorization", &auth)
        .json(&json!({"status": "accepted"}))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(r.json::<serde_json::Value>().unwrap()["ok"], true);
    let (st, v) = get("?status=accepted");
    assert_eq!(st, 200);
    assert_eq!(v["count"], 1);
    assert_eq!(v["vulns"][0]["fingerprint"], fp_high);

    // unknown fingerprint: 404; invalid status in body: 400
    let r = c
        .post(format!("{base}/api/vulns/deadbeefcafebabe12345678"))
        .header("authorization", &auth)
        .json(&json!({"status": "forgotten"}))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let r = c
        .post(format!("{base}/api/vulns/{fp_high}"))
        .header("authorization", &auth)
        .json(&json!({"status": "wontfix"}))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    let _ = std::fs::remove_dir_all(d);
}

/// With RBAC on, triage is governance: a viewer may list but not decide (the
/// fail-closed route classification makes POST /api/vulns/{fp} admin-only).
#[test]
fn vulns_api_triage_requires_admin_when_rbac_is_on() {
    use crate::vulndb::{self, VulnEntry};
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = data_dir("vulns-rbac");
    unsafe {
        std::env::remove_var("READYHAI_SETTINGS");
        std::env::remove_var("READYHAI_RBAC"); // auto: file exists => ON
    }
    let f = std::env::temp_dir().join(format!("rh-rbac-vulns-{}.toml", std::process::id()));
    std::fs::write(
        &f,
        "[[key]]\nname = \"ro-bot\"\nrole = \"viewer\"\nkey = \"rh-view-key-Vk3xQm7zP9wL2nB4\"\n[[key]]\nname = \"dash\"\nrole = \"admin\"\nkey = \"rh-adm-key-Zq4vN7cX9jE3bW8g\"\n",
    )
    .unwrap();
    let rbac = crate::serve::rbac::Rbac::load(Some(&f)).expect("key file loads");
    let (tx, _rx) = mpsc::channel(4);
    let app = Arc::new(App {
        token_digest: Sha256::digest(TOKEN.as_bytes()).into(),
        principal: "qa-lead".into(),
        rbac,
        tx,
        allowed_roots: vec![],
        scope: None,
        plugins: None,
        active: Mutex::new(HashSet::new()),
        probes: Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES)),
    });
    let (_rt, base) = test_server_with(app);
    let c = client();
    vulndb::record_findings(
        "http://a.example/",
        &[VulnEntry {
            kind: "scan.http",
            rule: "r",
            title: "t",
            severity: "high",
            resource: "/",
            message: "m",
        }],
    )
    .unwrap();
    let fp = vulndb::fingerprint("http://a.example/", "scan.http", "r", "/");
    let post = |key: &str| -> (u16, String) {
        let r = c
            .post(format!("{base}/api/vulns/{fp}"))
            .header("authorization", format!("Bearer {key}"))
            .json(&json!({"status": "accepted"}))
            .send()
            .unwrap();
        let st = r.status().as_u16();
        (st, r.text().unwrap_or_default())
    };

    // viewer: reading the database is fine, deciding is not
    let r = c
        .get(format!("{base}/api/vulns"))
        .header("authorization", "Bearer rh-view-key-Vk3xQm7zP9wL2nB4")
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(r.json::<serde_json::Value>().unwrap()["count"], 1);
    let (st, b) = post("rh-view-key-Vk3xQm7zP9wL2nB4");
    assert_eq!(st, 403, "viewer POST /api/vulns/{{fp}}: {b}");
    assert!(b.contains("needs admin"), "{b}");

    // admin: the same request goes through
    let (st, _) = post("rh-adm-key-Zq4vN7cX9jE3bW8g");
    assert_eq!(st, 200);
    assert!(vulndb::list(&vulndb::Filter::default())[0].status == "accepted");

    let _ = std::fs::remove_file(f);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn offload_runs_the_job_and_hands_back_its_value() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let got = super::guards::offload(|| 40 + 2).await.unwrap();
        assert_eq!(got, 42);
    });
}
#[test]
fn a_full_offload_queue_is_shed_with_503_not_queued_forever() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // One slot, and it is already taken: the caller below must be turned away promptly
        // instead of queueing behind an unseen job.
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let started = std::time::Instant::now();
        let shed = super::guards::offload_bounded(
            slots.clone(),
            std::time::Duration::from_millis(120),
            || unreachable!("a shed job must never reach the pool"),
        )
        .await
        .unwrap_err();
        assert_eq!(shed.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "shedding took {:?}",
            started.elapsed()
        );
        let body = axum::body::to_bytes(shed.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("too many concurrent file jobs"),
            "shed body was {body:?}"
        );
        // And once the slot frees up again, work flows: shedding is not a permanent open circuit.
        drop(held);
        let ok = super::guards::offload_bounded(
            slots,
            std::time::Duration::from_millis(500),
            || "served",
        )
        .await
        .unwrap();
        assert_eq!(ok, "served");
    });
}
