use super::super::budget::RunBudget;
use super::super::exec::Credentials;
use super::super::memory;
use super::super::types::*;
use super::cleanup::*;
use super::memory::remember;
use super::options::*;
use super::order::*;
use super::*;
use crate::agent::store::{checkpoint_status, load_cleanup_in};
use crate::agent::types::fixtures::{planned, result};
use crate::llm::{latency_report, mock};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
                        ("GET", "/openapi.json") => (200, "application/json", include_str!("../../../tests/fixtures/qa-api/openapi.json").to_string()),
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
    let step =
        |n: u32, actor: &str, m: &str, code: u16, vars: &[(&str, &str)]| StatefulStepExecution {
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
    while srv.log.lock().unwrap().len() < at_plan + 3 && started.elapsed() < Duration::from_secs(30)
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
        disk.finished_at.is_some() && disk.evidence_ledger.as_ref().is_some_and(|l| !l.evaluated)
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
        let is_gate_or_triage = b["messages"][0]["content"]
            .as_str()
            .is_some_and(|c| c.contains("readiness reviewer") || c.contains("root-cause analyst"));
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
        "{\"cases\": [], \"notes\": [], \"executive_summary\": \"fine\", \"gate_verdict\": \"GO\"}"
            .into()
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

#[test]
fn test_pipeline_graph_state_transitions() {
    use super::graph::{PipelineState, StationNode};
    let mut station = StationNode::new(PipelineState::Recon);
    assert_eq!(station.current_state(), PipelineState::Recon);
    station
        .transition_to(PipelineState::Discovery)
        .expect("valid transition");
    assert_eq!(station.current_state(), PipelineState::Discovery);
    station
        .transition_to(PipelineState::Plan)
        .expect("valid transition");
    assert_eq!(station.current_state(), PipelineState::Plan);
    station
        .transition_to(PipelineState::Execute)
        .expect("valid transition");
    assert_eq!(station.current_state(), PipelineState::Execute);
    // Adaptive ReAct loop iteration
    station
        .transition_to(PipelineState::Execute)
        .expect("valid loop iteration");
    assert_eq!(station.current_state(), PipelineState::Execute);
    station
        .transition_to(PipelineState::Verify)
        .expect("valid transition");
    assert_eq!(station.current_state(), PipelineState::Verify);
    station
        .transition_to(PipelineState::Gate)
        .expect("valid transition");
    assert_eq!(station.current_state(), PipelineState::Gate);
    station
        .transition_to(PipelineState::Completed)
        .expect("valid transition");
    assert_eq!(station.current_state(), PipelineState::Completed);
}

#[test]
fn test_stategraph_conditional_routing_and_reentry() {
    use super::graph::{PipelineState, RoutingCondition, StationNode};
    let mut station = StationNode::new(PipelineState::Execute);
    // Anomaly observed routes back to Execute for another wave
    assert!(station.can_route(&RoutingCondition::AnomalyDetected));
    station
        .route(RoutingCondition::AnomalyDetected)
        .expect("valid route");
    assert_eq!(station.current_state(), PipelineState::Execute);
    assert_eq!(station.loop_iteration_count(PipelineState::Execute), 2);
}

#[test]
fn test_stategraph_loop_bounds_prevention() {
    use super::graph::{PipelineState, RoutingCondition, StationNode};
    let mut station = StationNode::new(PipelineState::Execute).with_max_loop_iterations(2);
    assert_eq!(station.max_loop_iterations(), 2);
    assert_eq!(station.loop_iteration_count(PipelineState::Execute), 1);

    // Second iteration succeeds (count becomes 2)
    station
        .route(RoutingCondition::AnomalyDetected)
        .expect("second iteration should succeed");
    assert_eq!(station.loop_iteration_count(PipelineState::Execute), 2);

    // Third iteration exceeds max loop bounds (2) and fails safely
    let err = station
        .route(RoutingCondition::AnomalyDetected)
        .expect_err("third iteration must be blocked by loop bounds guard");
    assert!(
        err.to_string().contains("loop bound exceeded"),
        "unexpected error message: {err}"
    );
    assert_eq!(station.telemetry().loop_bounds_exceeded_count, 1);
}

#[test]
fn test_stategraph_telemetry_and_transitions() {
    use super::graph::{PipelineState, RoutingCondition, StationNode};
    let mut station = StationNode::new(PipelineState::Recon);
    assert_eq!(station.telemetry().total_transitions, 0);

    station
        .route(RoutingCondition::NormalProgression)
        .expect("Recon -> Discovery");
    assert_eq!(station.current_state(), PipelineState::Discovery);

    station
        .route(RoutingCondition::NormalProgression)
        .expect("Discovery -> Plan");
    assert_eq!(station.current_state(), PipelineState::Plan);

    // Re-refine in Plan
    assert!(station.can_route(&RoutingCondition::AmbiguityRefine));
    station
        .route(RoutingCondition::AmbiguityRefine)
        .expect("Plan loop");
    assert_eq!(station.current_state(), PipelineState::Plan);
    assert_eq!(station.loop_iteration_count(PipelineState::Plan), 2);

    station
        .route(RoutingCondition::NormalProgression)
        .expect("Plan -> Execute");
    assert_eq!(station.current_state(), PipelineState::Execute);

    station
        .route(RoutingCondition::NormalProgression)
        .expect("Execute -> Verify");
    assert_eq!(station.current_state(), PipelineState::Verify);

    // Replay in Verify
    assert!(station.can_route(&RoutingCondition::ReplayRequired));
    station
        .route(RoutingCondition::ReplayRequired)
        .expect("Verify replay");
    assert_eq!(station.current_state(), PipelineState::Verify);

    station
        .route(RoutingCondition::NormalProgression)
        .expect("Verify -> Gate");
    assert_eq!(station.current_state(), PipelineState::Gate);

    station
        .route(RoutingCondition::NormalProgression)
        .expect("Gate -> Completed");
    assert_eq!(station.current_state(), PipelineState::Completed);

    let tel = station.telemetry();
    assert_eq!(tel.total_transitions, 8);
    assert_eq!(tel.routing_events.len(), 8);
    assert_eq!(tel.iterations_per_station.get("Plan"), Some(&2));
    assert_eq!(tel.iterations_per_station.get("Verify"), Some(&2));
    assert_eq!(tel.iterations_per_station.get("Completed"), Some(&1));

    // Terminal state cannot route further
    assert!(!station.can_route(&RoutingCondition::NormalProgression));
    assert!(station.route(RoutingCondition::NormalProgression).is_err());
}

#[test]
fn test_stategraph_fatal_error_routing() {
    use super::graph::{PipelineState, RoutingCondition, StationNode};
    let mut station = StationNode::new(PipelineState::Discovery);
    assert!(station.can_route(&RoutingCondition::FatalError));
    station
        .route(RoutingCondition::FatalError)
        .expect("fatal error transitions to Failed");
    assert_eq!(station.current_state(), PipelineState::Failed);
}

#[test]
fn test_software_factory_attestation_clean_release() {
    use super::gate::software_factory_attestation;
    use crate::agent::types::EvidenceLedger;

    let mut ledger = EvidenceLedger::default();
    ledger.overall_readiness = 95;
    ledger.computed_verdict = "GO".into();

    let attestation = software_factory_attestation(None, &ledger, &[]);
    assert_eq!(attestation.release_readiness_score, 95);
    assert_eq!(attestation.gate_verdict, "GO");
    assert!(attestation.asvs_breakdown.level_1_compliant);
    assert!(attestation.asvs_breakdown.level_2_compliant);
    assert!(attestation.asvs_breakdown.level_3_compliant);
    assert_eq!(attestation.asvs_breakdown.overall_coverage_pct, 100);
    assert!(!attestation.attestation_digest.is_empty());
    assert!(
        attestation
            .release_directives
            .iter()
            .any(|d| d.contains("ALLOW_DEPLOYMENT"))
    );
}

#[test]
fn test_software_factory_attestation_critical_block() {
    use super::gate::software_factory_attestation;
    use crate::agent::types::{EvidenceLedger, TriagedDefect};

    let mut ledger = EvidenceLedger::default();
    ledger.overall_readiness = 90;

    let defect = TriagedDefect {
        id: "DEF-CRIT-1".into(),
        title: "Remote Code Execution via deserialization".into(),
        severity: "CRITICAL".into(),
        owasp_category: "API8:2023 Security Misconfiguration".into(),
        component: "/api/v1/import".into(),
        ..Default::default()
    };

    let attestation = software_factory_attestation(None, &ledger, &[defect]);
    assert!(attestation.release_readiness_score <= 25);
    assert_eq!(attestation.gate_verdict, "NO_GO");
    assert!(!attestation.asvs_breakdown.level_1_compliant);
    assert!(!attestation.asvs_breakdown.level_2_compliant);
    assert!(
        attestation
            .release_directives
            .iter()
            .any(|d| d.contains("BLOCK_DEPLOYMENT"))
    );
}

#[test]
fn test_recon_quality_gate_validation() {
    use super::gates::{ReconGateInput, validate_recon_gate};
    let invalid_input = ReconGateInput {
        target_reachable: false,
        directives_present: false,
        focus_areas_count: 0,
    };
    assert!(validate_recon_gate(&invalid_input).is_err());

    let valid_input = ReconGateInput {
        target_reachable: true,
        directives_present: true,
        focus_areas_count: 3,
    };
    assert!(validate_recon_gate(&valid_input).is_ok());
}

#[test]
fn test_discovery_quality_gate_validation() {
    use super::gates::{DiscoveryGateInput, validate_discovery_gate};

    // Invalid: 0 routes and no verified fallback
    let invalid = DiscoveryGateInput {
        routes_count: 0,
        verified_empty_fallback: false,
        semantic_predictions_validated: true,
    };
    assert!(validate_discovery_gate(&invalid).is_err());

    // Invalid: semantic predictions not validated
    let invalid_preds = DiscoveryGateInput {
        routes_count: 5,
        verified_empty_fallback: false,
        semantic_predictions_validated: false,
    };
    assert!(validate_discovery_gate(&invalid_preds).is_err());

    // Valid: routes discovered > 0
    let valid_routes = DiscoveryGateInput {
        routes_count: 12,
        verified_empty_fallback: false,
        semantic_predictions_validated: true,
    };
    let verdict = validate_discovery_gate(&valid_routes).expect("should pass");
    assert!(verdict.passed);
    assert_eq!(verdict.checks.len(), 2);

    // Valid: 0 routes with verified empty fallback confirmed
    let valid_fallback = DiscoveryGateInput {
        routes_count: 0,
        verified_empty_fallback: true,
        semantic_predictions_validated: true,
    };
    assert!(validate_discovery_gate(&valid_fallback).is_ok());
}

#[test]
fn test_plan_quality_gate_validation() {
    use super::gates::{PlanGateInput, validate_plan_gate};

    // Invalid: cyclic DAG
    let cyclic = PlanGateInput {
        is_dag_acyclic: false,
        baseline_cases_count: 10,
        directives_covered: true,
    };
    assert!(validate_plan_gate(&cyclic).is_err());

    // Invalid: 0 baseline cases
    let zero_cases = PlanGateInput {
        is_dag_acyclic: true,
        baseline_cases_count: 0,
        directives_covered: true,
    };
    assert!(validate_plan_gate(&zero_cases).is_err());

    // Invalid: directives not covered
    let uncover = PlanGateInput {
        is_dag_acyclic: true,
        baseline_cases_count: 10,
        directives_covered: false,
    };
    assert!(validate_plan_gate(&uncover).is_err());

    // Valid
    let valid = PlanGateInput {
        is_dag_acyclic: true,
        baseline_cases_count: 15,
        directives_covered: true,
    };
    let verdict = validate_plan_gate(&valid).expect("valid plan gate");
    assert!(verdict.passed);
}

#[test]
fn test_execution_quality_gate_validation() {
    use super::gates::{ExecutionGateInput, validate_execution_gate};

    // Invalid: worker thread panic detected
    let panic_input = ExecutionGateInput {
        waves_completed: 3,
        budget_compliant: true,
        worker_panics: 1,
    };
    assert!(validate_execution_gate(&panic_input).is_err());

    // Invalid: budget exceeded
    let budget_fail = ExecutionGateInput {
        waves_completed: 3,
        budget_compliant: false,
        worker_panics: 0,
    };
    assert!(validate_execution_gate(&budget_fail).is_err());

    // Invalid: 0 waves completed
    let zero_waves = ExecutionGateInput {
        waves_completed: 0,
        budget_compliant: true,
        worker_panics: 0,
    };
    assert!(validate_execution_gate(&zero_waves).is_err());

    // Valid
    let valid = ExecutionGateInput {
        waves_completed: 2,
        budget_compliant: true,
        worker_panics: 0,
    };
    let verdict = validate_execution_gate(&valid).expect("valid execution gate");
    assert!(verdict.passed);
}

#[test]
fn test_verify_quality_gate_validation() {
    use super::gates::{VerifyGateInput, validate_verify_gate};

    // Invalid: k-replay not executed
    let no_replay = VerifyGateInput {
        k_replay_executed: false,
        juror_taint_evaluated: true,
        unverified_false_positives: 0,
    };
    assert!(validate_verify_gate(&no_replay).is_err());

    // Invalid: Juror taint not evaluated
    let no_juror = VerifyGateInput {
        k_replay_executed: true,
        juror_taint_evaluated: false,
        unverified_false_positives: 0,
    };
    assert!(validate_verify_gate(&no_juror).is_err());

    // Invalid: unverified false-positive defects remain
    let unverified_fps = VerifyGateInput {
        k_replay_executed: true,
        juror_taint_evaluated: true,
        unverified_false_positives: 2,
    };
    assert!(validate_verify_gate(&unverified_fps).is_err());

    // Valid
    let valid = VerifyGateInput {
        k_replay_executed: true,
        juror_taint_evaluated: true,
        unverified_false_positives: 0,
    };
    let verdict = validate_verify_gate(&valid).expect("valid verify gate");
    assert!(verdict.passed);
}

#[test]
fn test_release_quality_gate_validation() {
    use super::gates::{
        ReleaseGate, ReleaseGateInput, validate_release_gate, validate_release_gate_verdict,
    };
    use crate::agent::types::{EvidenceLedger, TriagedDefect};

    // Invalid: critical defect present
    let crit_input = ReleaseGateInput {
        value_score: 90,
        authority_score: 90,
        safety_score: 90,
        evidence_score: 90,
        min_threshold: 70,
        asvs_l1_compliant: true,
        critical_defects: 1,
    };
    assert!(validate_release_gate(&crit_input).is_err());

    // Invalid: ASVS L1 non-compliant
    let asvs_fail = ReleaseGateInput {
        value_score: 90,
        authority_score: 90,
        safety_score: 90,
        evidence_score: 90,
        min_threshold: 70,
        asvs_l1_compliant: false,
        critical_defects: 0,
    };
    assert!(validate_release_gate(&asvs_fail).is_err());

    // Invalid: safety score below threshold
    let low_safety = ReleaseGateInput {
        value_score: 85,
        authority_score: 85,
        safety_score: 65, // Below 70
        evidence_score: 85,
        min_threshold: 70,
        asvs_l1_compliant: true,
        critical_defects: 0,
    };
    assert!(validate_release_gate(&low_safety).is_err());

    // Valid: Clean release with high scores
    let valid_input = ReleaseGateInput {
        value_score: 95,
        authority_score: 90,
        safety_score: 85,
        evidence_score: 90,
        min_threshold: 70,
        asvs_l1_compliant: true,
        critical_defects: 0,
    };
    let attestation = validate_release_gate(&valid_input).expect("release gate should pass");
    assert_eq!(attestation.gate_verdict, "GO");
    assert!(attestation.release_readiness_score >= 80);
    assert!(attestation.asvs_breakdown.level_1_compliant);
    assert!(attestation.asvs_breakdown.level_2_compliant);
    assert!(!attestation.attestation_digest.is_empty());
    assert!(
        attestation
            .release_directives
            .iter()
            .any(|d| d.contains("ALLOW_DEPLOYMENT"))
    );

    // Valid: verdict representation
    let verdict = validate_release_gate_verdict(&valid_input).expect("release verdict");
    assert!(verdict.passed);
    assert_eq!(verdict.checks.len(), 6);

    // Evaluation directly from EvidenceLedger
    let mut ledger = EvidenceLedger::default();
    ledger.value_score = Some(88);
    ledger.authority_score = Some(85);
    ledger.safety_score = Some(92);
    ledger.evidence_score = Some(80);
    let ledger_attestation =
        ReleaseGate::evaluate_ledger(&ledger, &[], 70).expect("ledger evaluation");
    assert_eq!(ledger_attestation.gate_verdict, "GO");

    // Fails with critical defect
    let crit_defect = TriagedDefect {
        id: "DEF-CRIT-1".into(),
        title: "Remote Code Execution".into(),
        severity: "CRITICAL".into(),
        ..Default::default()
    };
    assert!(ReleaseGate::evaluate_ledger(&ledger, &[crit_defect], 70).is_err());
}

#[test]
fn test_quality_gates_entrance_checks() {
    use super::gates::{
        DiscoveryGate, ExecutionGate, PlanGate, ReconGate, ReleaseGate, VerifyGate,
    };

    // Recon entrance
    assert!(ReconGate::check_entrance("https://example.com/api", 100).is_ok());
    assert!(ReconGate::check_entrance("ftp://example.com", 100).is_err());
    assert!(ReconGate::check_entrance("not a url", 100).is_err());
    assert!(ReconGate::check_entrance("http://localhost:8080", 0).is_err());

    // Discovery entrance
    assert!(DiscoveryGate::check_entrance(true).is_ok());
    assert!(DiscoveryGate::check_entrance(false).is_err());

    // Plan entrance
    assert!(PlanGate::check_entrance(5, false).is_ok());
    assert!(PlanGate::check_entrance(0, true).is_ok());
    assert!(PlanGate::check_entrance(0, false).is_err());

    // Execution entrance
    assert!(ExecutionGate::check_entrance(10, 50).is_ok());
    assert!(ExecutionGate::check_entrance(0, 50).is_err());
    assert!(ExecutionGate::check_entrance(10, 0).is_err());

    // Verify entrance
    assert!(VerifyGate::check_entrance(10).is_ok());
    assert!(VerifyGate::check_entrance(0).is_err());

    // Release entrance
    assert!(ReleaseGate::check_entrance(true, true).is_ok());
    assert!(ReleaseGate::check_entrance(false, true).is_err());
    assert!(ReleaseGate::check_entrance(true, false).is_err());
}

#[test]
fn test_quality_gate_trait_dispatch() {
    use super::gates::{
        DiscoveryGate, DiscoveryGateInput, ExecutionGate, ExecutionGateInput, PlanGate,
        PlanGateInput, QualityGate, ReconGate, ReconGateInput, ReleaseGate, ReleaseGateInput,
        VerifyGate, VerifyGateInput,
    };

    let recon = ReconGate::default();
    assert_eq!(recon.gate_name(), "ReconGate");
    let recon_in = ReconGateInput {
        target_reachable: true,
        directives_present: true,
        focus_areas_count: 2,
    };
    assert!(recon.evaluate(&recon_in).is_ok());

    let disc = DiscoveryGate::default();
    assert_eq!(disc.gate_name(), "DiscoveryGate");
    let disc_in = DiscoveryGateInput {
        routes_count: 3,
        verified_empty_fallback: false,
        semantic_predictions_validated: true,
    };
    assert!(disc.evaluate(&disc_in).is_ok());

    let plan = PlanGate::default();
    assert_eq!(plan.gate_name(), "PlanGate");
    let plan_in = PlanGateInput {
        is_dag_acyclic: true,
        baseline_cases_count: 5,
        directives_covered: true,
    };
    assert!(plan.evaluate(&plan_in).is_ok());

    let exec = ExecutionGate::default();
    assert_eq!(exec.gate_name(), "ExecutionGate");
    let exec_in = ExecutionGateInput {
        waves_completed: 1,
        budget_compliant: true,
        worker_panics: 0,
    };
    assert!(exec.evaluate(&exec_in).is_ok());

    let verify = VerifyGate::default();
    assert_eq!(verify.gate_name(), "VerifyGate");
    let verify_in = VerifyGateInput {
        k_replay_executed: true,
        juror_taint_evaluated: true,
        unverified_false_positives: 0,
    };
    assert!(verify.evaluate(&verify_in).is_ok());

    let release = ReleaseGate::default();
    assert_eq!(release.gate_name(), "ReleaseGate");
    let release_in = ReleaseGateInput::default();
    assert!(release.evaluate(&release_in).is_ok());
}
