use super::*;
use crate::agent::budget::RunBudget;
use crate::agent::exec::{Credentials, ExecOptions, execute_cases_with};
use crate::agent::oracle::{self, Observation, OracleOutcome, Severity, Verdict};
use crate::agent::types::CreatedLedger;
use crate::agent::types::fixtures::planned;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// (method, path, auth) per request.
type Log = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

struct Srv {
    base: String,
    log: Log,
}

impl Srv {
    fn count(&self, method: &str, path: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, p, _)| m == method && p == path)
            .count()
    }
    fn total(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

/// `route(method, path, nth)` -> (status, content type, body); `nth` counts requests for
/// that method+path starting at 1.
fn serve(
    route: impl Fn(&str, &str, usize) -> (u16, &'static str, String) + Send + Sync + 'static,
) -> Srv {
    serve_auth(move |m, p, n, _| route(m, p, n))
}

/// Like [`serve`], with the request's `Authorization` header as a 4th argument.
fn serve_auth(
    route: impl Fn(&str, &str, usize, Option<&str>) -> (u16, &'static str, String)
    + Send
    + Sync
    + 'static,
) -> Srv {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let log: Log = Arc::default();
    let hits: Arc<Mutex<std::collections::HashMap<String, usize>>> = Arc::default();
    let route = Arc::new(route);
    let lg = log.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let (lg, hits, route) = (lg.clone(), hits.clone(), route.clone());
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
                let nth = {
                    let mut h = hits.lock().unwrap();
                    let e = h.entry(format!("{method} {path}")).or_insert(0);
                    *e += 1;
                    *e
                };
                lg.lock()
                    .unwrap()
                    .push((method.clone(), path.clone(), auth.clone()));
                let (code, ctype, body) = route(&method, &path, nth, auth.as_deref());
                let _ = write!(
                    s,
                    "HTTP/1.1 {code} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    Srv { base, log }
}

fn case(id: &str, tech: &str, method: &str, comp: &str) -> PlannedCase {
    let mut c = planned(id, tech, method, comp);
    c.role = Some("anon".into());
    c
}

fn exec_opts() -> ExecOptions {
    ExecOptions {
        dry_run: false,
        is_spa_target: false,
        credentials: Credentials::none(),
        reruns: 0, // the executor must not do the verifier's job here
        timeout: Duration::from_secs(5),
    }
}

fn vopts(creds: &Credentials, k: u32) -> VerifyOptions<'_> {
    VerifyOptions {
        k,
        raise_k: no_raise(),
        dry_run: false,
        is_spa_target: false,
        credentials: creds,
        timeout: Duration::from_secs(5),
    }
}

fn budget(max_requests: usize) -> RunBudget {
    RunBudget::new(100, max_requests, Duration::from_secs(60), 0.0)
}

/// Execute then verify with separate budgets; returns (results, outcome).
fn run(
    srv: &Srv,
    cases: &[PlannedCase],
    k: u32,
    verify_budget: &mut RunBudget,
) -> (Vec<CaseExecutionResult>, VerifyOutcome) {
    let mut results = execute_cases_with(cases, &srv.base, &exec_opts(), &mut budget(500));
    let creds = Credentials::none();
    let o = verify_failures(
        &mut results,
        cases,
        &srv.base,
        &vopts(&creds, k),
        verify_budget,
    );
    (results, o)
}

fn status<'a>(r: &'a [CaseExecutionResult], id: &str) -> &'a CaseExecutionResult {
    r.iter().find(|r| r.case_id == id).unwrap()
}

#[test]
fn k_comes_from_the_environment_text_with_a_default_and_a_cap() {
    assert_eq!(parse_k(None), 2);
    assert_eq!(parse_k(Some("")), 2);
    assert_eq!(parse_k(Some("banana")), 2);
    assert_eq!(parse_k(Some("-1")), 2);
    assert_eq!(parse_k(Some("3")), 3);
    assert_eq!(parse_k(Some(" 5 ")), 5);
    assert_eq!(parse_k(Some("99")), 5, "capped at 5");
    assert_eq!(parse_k(Some("0")), 0, "0 switches verification off");
}

#[test]
fn unlikely_ids_are_recognised() {
    for c in [
        "/orders/999999",
        "/o/999999999?x=1",
        "/x/readyhai-nonexistent",
        "/u/00000000-0000-4000-8000-000000999999",
    ] {
        assert!(targets_unlikely_id(c), "{c}");
    }
    for c in [
        "/orders/1",
        "/orders/99999",
        "/orders/12999999",
        "/orders",
        "/users/alice",
    ] {
        assert!(!targets_unlikely_id(c), "{c}");
    }
}

#[test]
fn a_deterministic_fail_is_confirmed_and_stays_a_defect() {
    let srv = serve(|_, p, _| match p {
        "/search" => (
            500,
            "text/plain",
            "Traceback (most recent call last):\n  File \"a.py\"".into(),
        ),
        _ => (404, "application/json", "{}".into()),
    });
    let mut c = case("TC-001", "injection", "GET", "/search");
    c.payload = Some("q='".into());
    let (results, o) = run(&srv, &[c], 2, &mut budget(50));
    let r = status(&results, "TC-001");
    assert_eq!(r.status, "FAIL");
    assert!(!r.flaky);
    let rec = o.summary.record("TC-001").unwrap();
    assert_eq!(rec.verdict, VerifyVerdict::Confirmed);
    assert_eq!((rec.k, rec.completed, rec.reproduced), (2, 2, 2));
    assert_eq!(rec.ratio().as_deref(), Some("2/2"));
    assert_eq!(rec.replays.len(), 2);
    assert!(
        rec.replays
            .iter()
            .all(|p| p.reproduced && p.status_code == Some(500))
    );
    assert_eq!(
        srv.count("GET", "/search"),
        3,
        "the original plus two replays"
    );
    assert_eq!(o.summary.replay_requests, 2);
    assert_eq!((o.summary.confirmed, o.summary.replayed), (1, 1));
    assert_eq!(o.summary.pass_k, Some(1.0));
    // the replays are written into the case's evidence file
    let v = &r.evidence_detail.as_ref().unwrap()["verification"];
    assert_eq!(v["verdict"], "confirmed");
    assert_eq!(v["replays"].as_array().unwrap().len(), 2);
    assert_eq!(v["replays"][0]["status_code"], 500);
    assert!(
        v["replays"][0]["response_excerpt"]
            .as_str()
            .unwrap()
            .contains("Traceback")
    );
    assert_eq!(rec.evidence_file, r.evidence_file);
}

#[test]
fn a_case_known_as_flaky_is_replayed_with_the_maximum_k() {
    let srv = serve(|_, p, _| match p {
        "/search" | "/find" => (
            500,
            "text/plain",
            "Traceback (most recent call last)".into(),
        ),
        _ => (404, "application/json", "{}".into()),
    });
    let mut a = case("TC-001", "injection", "GET", "/search");
    a.payload = Some("q='".into());
    let mut b = case("TC-002", "injection", "GET", "/find");
    b.payload = Some("q='".into());
    let cases = [a, b];
    let raise: BTreeSet<String> = ["TC-002".to_string()].into();
    let creds = Credentials::none();
    let mut results = execute_cases_with(&cases, &srv.base, &exec_opts(), &mut budget(500));
    let mut o = vopts(&creds, 2);
    o.raise_k = &raise;
    let out = verify_failures(&mut results, &cases, &srv.base, &o, &mut budget(100));
    let (ra, rb) = (
        out.summary.record("TC-001").unwrap(),
        out.summary.record("TC-002").unwrap(),
    );
    assert_eq!((ra.k, ra.replays.len()), (2, 2));
    assert_eq!((rb.k, rb.replays.len()), (MAX_K, MAX_K as usize));
    assert_eq!(rb.ratio().as_deref(), Some("5/5"));
    assert!(
        rb.note
            .as_deref()
            .unwrap()
            .contains("flaky in earlier runs")
    );
    assert!(ra.note.is_none());
    assert_eq!(out.summary.k, 2, "the run's own k is unchanged");
    // verification off stays off, whatever memory says
    let mut results = execute_cases_with(&cases, &srv.base, &exec_opts(), &mut budget(500));
    let mut o = vopts(&creds, 0);
    o.raise_k = &raise;
    let out = verify_failures(&mut results, &cases, &srv.base, &o, &mut budget(100));
    assert!(out.summary.records.is_empty());
}

#[test]
fn contract_and_latency_findings_are_confirmed_by_replays_and_a_one_off_slow_answer_is_not() {
    use crate::agent::types::ResponseContract;
    let srv = serve(|_, p, nth| match p {
        // bug 5 of the QA fixture: the required `total` is missing, every time
        "/orders/2" => (200, "application/json", r#"{"id":2}"#.into()),
        "/slow" => {
            std::thread::sleep(Duration::from_millis(1100));
            (200, "application/json", "{}".into())
        }
        "/once-slow" => {
            if nth == 1 {
                std::thread::sleep(Duration::from_millis(1100));
            }
            (200, "application/json", "{}".into())
        }
        _ => (404, "application/json", "{}".into()),
    });
    let order = serde_json::json!({"type":"object","required":["id","total"],"properties":{
        "id":{"type":"integer"},"total":{"type":"integer"}}});
    let read = |id: &str, comp: &str, schema: Option<Value>, latency: bool| {
        let mut c = case(id, "state_transition", "GET", comp);
        c.expected_status = Some(200);
        c.contract = Some(ResponseContract {
            responses: [("200".to_string(), schema)].into(),
            latency,
        });
        c
    };
    let cases = [
        read("TC-001", "/orders/2", Some(order), false),
        read("TC-002", "/slow", None, true),
        read("TC-003", "/once-slow", None, true),
    ];
    let (results, o) = run(&srv, &cases, 2, &mut budget(50));

    let c = status(&results, "TC-001");
    assert_eq!(c.status, "FAIL", "{:?}", c.failure_reason);
    assert_eq!(
        c.oracle.as_ref().unwrap().first_fail().unwrap().code,
        "contract_fields"
    );
    let rec = o.summary.record("TC-001").unwrap();
    assert_eq!(
        (rec.verdict, rec.ratio().as_deref()),
        (VerifyVerdict::Confirmed, Some("2/2"))
    );

    let c = status(&results, "TC-002");
    assert_eq!(c.status, "FAIL", "{:?}", c.failure_reason);
    assert_eq!(
        c.oracle.as_ref().unwrap().first_fail().unwrap().code,
        "slow_response"
    );
    let rec = o.summary.record("TC-002").unwrap();
    assert_eq!(
        (rec.verdict, rec.ratio().as_deref()),
        (VerifyVerdict::Confirmed, Some("2/2"))
    );
    assert!(
        rec.replays.iter().all(|p| p.latency_ms > 1000),
        "{:?}",
        rec.replays
    );

    // slow once, fast on both replays: not a slow endpoint, so not a defect
    let c = status(&results, "TC-003");
    assert_eq!(c.status, "INCONCLUSIVE", "{:?}", c.failure_reason);
    assert_eq!(
        o.summary.record("TC-003").unwrap().verdict,
        VerifyVerdict::NotReproduced
    );
}

#[test]
fn a_fail_the_fixture_serves_only_once_is_not_reproduced_and_becomes_inconclusive() {
    let srv = serve(|_, p, nth| match p {
        "/once" if nth == 1 => (500, "text/plain", "boom".into()),
        "/once" => (200, "application/json", "{\"ok\":true}".into()),
        _ => (404, "application/json", "{}".into()),
    });
    let c = case("TC-001", "boundary", "GET", "/once");
    let (results, o) = run(&srv, &[c], 2, &mut budget(50));
    let r = status(&results, "TC-001");
    assert_eq!(
        r.status, "INCONCLUSIVE",
        "{:?} {:?}",
        r.failure_reason, o.summary
    );
    assert!(
        r.failure_reason
            .as_deref()
            .unwrap()
            .starts_with("not reproduced")
    );
    assert!(
        r.failure_reason
            .as_deref()
            .unwrap()
            .contains("server error HTTP 500"),
        "the original failure stays in the note"
    );
    let rec = o.summary.record("TC-001").unwrap();
    assert_eq!(rec.verdict, VerifyVerdict::NotReproduced);
    assert_eq!(
        (rec.original_status.as_str(), rec.final_status.as_str()),
        ("FAIL", "INCONCLUSIVE")
    );
    assert_eq!(
        (
            o.summary.not_reproduced,
            o.summary.confirmed,
            o.summary.pass_k
        ),
        (1, 0, Some(0.0))
    );
    // the oracle verdict of the original run is kept as evidence
    assert!(r.oracle.as_ref().unwrap().first_fail().is_some());
}

#[test]
fn a_flaky_high_failure_stays_fail_with_the_flag_and_a_flaky_medium_one_becomes_warn() {
    // original + first replay fail, second replay passes: 1 of 2 reproduced
    let srv = serve(|_, p, nth| match p {
        // /search leaks a trace (high); /list is a bare 500 (medium)
        "/search" if nth <= 2 => (
            500,
            "text/plain",
            "Traceback (most recent call last):\n  x".into(),
        ),
        "/list" if nth <= 2 => (500, "text/plain", "boom".into()),
        "/search" | "/list" => (200, "application/json", "{\"results\":[]}".into()),
        _ => (404, "application/json", "{}".into()),
    });
    let mut high = case("TC-001", "injection", "GET", "/search");
    high.payload = Some("q='".into());
    let medium = case("TC-002", "boundary", "GET", "/list");
    let (results, o) = run(&srv, &[high, medium], 2, &mut budget(50));
    let h = status(&results, "TC-001");
    assert_eq!(
        h.status, "FAIL",
        "a high-severity failure is never demoted for flakiness"
    );
    assert!(h.flaky);
    assert!(
        h.failure_reason
            .as_deref()
            .unwrap()
            .contains("flaky: reproduced on 1 of 2")
    );
    let m = status(&results, "TC-002");
    assert_eq!(m.status, "WARN");
    assert!(m.flaky);
    let rec = o.summary.record("TC-001").unwrap();
    assert_eq!(rec.verdict, VerifyVerdict::Flaky);
    assert_eq!(rec.ratio().as_deref(), Some("1/2"));
    assert_eq!(rec.severity, "high");
    assert_eq!(o.summary.flaky, 2);
    assert_eq!(o.summary.pass_k, Some(0.0));
}

#[test]
fn replays_are_charged_to_the_budget_and_an_exhausted_budget_leaves_the_fail_unverified() {
    let srv = serve(|_, p, _| match p {
        "/search" => (
            500,
            "text/plain",
            "Traceback (most recent call last):\n  x".into(),
        ),
        _ => (404, "application/json", "{}".into()),
    });
    let mut c = case("TC-001", "injection", "GET", "/search");
    c.payload = Some("q='".into());
    let mut b = budget(1); // one replay request is all there is
    let (results, o) = run(&srv, &[c], 3, &mut b);
    assert_eq!(b.requests_used(), 1, "never more than the budget allows");
    assert_eq!(
        srv.count("GET", "/search"),
        2,
        "original + exactly one replay"
    );
    let r = status(&results, "TC-001");
    assert_eq!(
        r.status, "FAIL",
        "an unfinished verification never demotes a failure"
    );
    let rec = o.summary.record("TC-001").unwrap();
    assert_eq!(rec.verdict, VerifyVerdict::Unverified);
    assert_eq!((rec.completed, rec.reproduced), (1, 1));
    assert!(
        o.summary
            .stopped
            .as_deref()
            .unwrap()
            .contains("request budget exhausted"),
        "{:?}",
        o.summary.stopped
    );
    assert_eq!(o.summary.replay_requests, 1);
    assert_eq!(o.summary.pass_k, None, "nothing was fully replayed");
    // a budget with room for everything sends exactly k replays
    let mut b2 = budget(50);
    let c2 = {
        let mut c = case("TC-001", "injection", "GET", "/search");
        c.payload = Some("q='".into());
        c
    };
    let (_, o2) = run(&srv, &[c2], 3, &mut b2);
    assert_eq!(b2.requests_used(), 3);
    assert_eq!(
        o2.summary.record("TC-001").unwrap().verdict,
        VerifyVerdict::Confirmed
    );
}

#[test]
fn a_cancelled_run_sends_no_replay() {
    let srv = serve(|_, _, _| {
        (
            500,
            "text/plain",
            "Traceback (most recent call last):\n  x".into(),
        )
    });
    let mut c = case("TC-001", "injection", "GET", "/search");
    c.payload = Some("q='".into());
    let mut results =
        execute_cases_with(&[c.clone()], &srv.base, &exec_opts(), &mut budget(50));
    assert_eq!(results[0].status, "FAIL");
    let sent_before = srv.total();
    let token = crate::agent::types::CancelToken::new();
    token.cancel();
    let mut b = budget(50).with_cancel(token);
    let creds = Credentials::none();
    let o = verify_failures(&mut results, &[c], &srv.base, &vopts(&creds, 2), &mut b);
    assert_eq!(
        srv.total(),
        sent_before,
        "nothing was sent after cancellation"
    );
    assert_eq!(
        o.summary.record("TC-001").unwrap().verdict,
        VerifyVerdict::Unverified
    );
    assert_eq!(results[0].status, "FAIL");
    assert_eq!(o.summary.stopped.as_deref(), Some("run cancelled"));
}

#[test]
fn verification_off_or_nothing_failed_sends_nothing() {
    let srv = serve(|_, _, _| (200, "application/json", "{}".into()));
    let c = case("TC-001", "boundary", "GET", "/ok");
    let (_, o) = run(&srv, std::slice::from_ref(&c), 2, &mut budget(50));
    assert_eq!(o.summary.candidates, 0);
    assert_eq!(srv.total(), 1);
    let srv2 = serve(|_, _, _| (500, "text/plain", "x".into()));
    let (r, o2) = run(&srv2, &[c], 0, &mut budget(50));
    assert_eq!(srv2.total(), 1, "k = 0: no replay");
    assert_eq!(r[0].status, "FAIL");
    assert!(
        o2.summary
            .stopped
            .as_deref()
            .unwrap()
            .starts_with("disabled")
    );
    assert!(o2.summary.records.is_empty());
}

#[test]
fn a_write_fail_is_replayed_only_when_the_case_made_its_own_resource_or_uses_a_throwaway_id() {
    // POST /made answers 201 with an id but is judged a FAIL by an expected status; the
    // replays create more orders, which land on the run's ledger
    let n = Arc::new(AtomicUsize::new(100));
    let nn = n.clone();
    let srv = serve(move |m, p, _| match (m, p) {
        ("POST", "/made") => (
            201,
            "application/json",
            format!("{{\"id\": {}}}", nn.fetch_add(1, Ordering::SeqCst)),
        ),
        ("PUT", "/orders/999999") => (500, "application/json", "{\"error\":\"x\"}".into()),
        ("PUT", "/orders/7") => (500, "application/json", "{\"error\":\"x\"}".into()),
        _ => (404, "application/json", "{}".into()),
    });
    let mut made = case("TC-001", "boundary", "POST", "/made");
    made.payload = Some("{\"item\":\"a\"}".into());
    made.expected_status = Some(400);
    let throwaway = case("TC-002", "boundary", "PUT", "/orders/999999");
    let real = case("TC-003", "boundary", "PUT", "/orders/7");
    let ledger = CreatedLedger::new();
    let (results, o) = {
        let _scope = ledger.install();
        run(&srv, &[made, throwaway, real], 2, &mut budget(50))
    };
    assert_eq!(status(&results, "TC-001").status, "FAIL");
    let a = o.summary.record("TC-001").unwrap();
    assert_eq!((a.verdict, a.reproduced), (VerifyVerdict::Confirmed, 2));
    assert_eq!(srv.count("POST", "/made"), 3);
    let b = o.summary.record("TC-002").unwrap();
    assert_eq!(b.verdict, VerifyVerdict::Confirmed, "{:?}", b.note);
    assert_eq!(srv.count("PUT", "/orders/999999"), 3);
    let c = o.summary.record("TC-003").unwrap();
    assert_eq!(c.verdict, VerifyVerdict::Unverified);
    assert!(
        c.note.as_deref().unwrap().starts_with("unverified-write"),
        "{:?}",
        c.note
    );
    assert_eq!(c.replays.len(), 0);
    assert_eq!(
        srv.count("PUT", "/orders/7"),
        1,
        "a write on a real record is sent once, never repeated"
    );
    assert_eq!(status(&results, "TC-003").status, "FAIL", "not demoted");
    // the resources the replays created are on the ledger with the replay's case id, ready for teardown
    let made_by_replays: Vec<_> = ledger
        .entries()
        .into_iter()
        .filter(|r| {
            r.case_id
                .as_deref()
                .is_some_and(|c| c.starts_with("TC-001-V"))
        })
        .collect();
    assert_eq!(made_by_replays.len(), 2, "{:?}", ledger.entries());
    assert!(o.unidentified.is_empty());
}

#[test]
fn a_replay_that_creates_a_resource_without_an_id_is_reported_as_unidentified() {
    let srv = serve(|m, p, _| match (m, p) {
        ("POST", "/made") => (201, "application/json", "{}".into()),
        _ => (404, "application/json", "{}".into()),
    });
    let mut made = case("TC-001", "boundary", "POST", "/made");
    made.expected_status = Some(400);
    let ledger = CreatedLedger::new();
    let (_, o) = {
        let _scope = ledger.install();
        run(&srv, &[made], 2, &mut budget(50))
    };
    assert_eq!(o.unidentified.len(), 2, "one per replay");
    assert!(o.unidentified[0].reason.contains("TC-001-V1"));
}

#[test]
fn credentials_are_attached_afresh_and_only_to_the_target() {
    let srv = serve(|_, p, _| match p {
        "/me" => (
            500,
            "text/plain",
            "Traceback (most recent call last):\n  x".into(),
        ),
        _ => (404, "application/json", "{}".into()),
    });
    let mut c = case("TC-001", "injection", "GET", "/me");
    c.role = Some("user".into());
    c.payload = Some("q='".into());
    let creds = Credentials::none().with("user", "tok-user");
    let mut results = execute_cases_with(
        &[c.clone()],
        &srv.base,
        &ExecOptions {
            credentials: creds.clone(),
            ..exec_opts()
        },
        &mut budget(50),
    );
    let o = verify_failures(
        &mut results,
        &[c],
        &srv.base,
        &vopts(&creds, 2),
        &mut budget(50),
    );
    assert_eq!(
        o.summary.record("TC-001").unwrap().verdict,
        VerifyVerdict::Confirmed
    );
    let log = srv.log.lock().unwrap();
    assert_eq!(log.len(), 3);
    assert!(
        log.iter()
            .all(|(_, _, a)| a.as_deref() == Some("Bearer tok-user")),
        "{log:?}"
    );
    // nothing stored in the report carries the token
    let json = serde_json::to_string(&o.summary).unwrap();
    assert!(!json.contains("tok-user"));
    let detail = results[0].evidence_detail.as_ref().unwrap().to_string();
    assert!(!detail.contains("tok-user"), "{detail}");
}

#[test]
fn a_burst_result_is_not_replayed_and_stays_a_failure() {
    let mut r = crate::agent::types::fixtures::result("TC-001-B", "state_transition", "FAIL");
    r.method = "POST".into();
    r.component = "/orders".into();
    let c = case("TC-001", "state_transition", "POST", "/orders");
    let srv = serve(|_, _, _| (200, "application/json", "{}".into()));
    let creds = Credentials::none();
    let mut res = vec![r];
    let o = verify_failures(
        &mut res,
        &[c],
        &srv.base,
        &vopts(&creds, 2),
        &mut budget(50),
    );
    let rec = o.summary.record("TC-001-B").unwrap();
    assert_eq!(rec.verdict, VerifyVerdict::Unverified);
    assert!(rec.note.as_deref().unwrap().contains("concurrency burst"));
    assert_eq!(res[0].status, "FAIL");
    assert_eq!(srv.total(), 0);
}

#[test]
fn an_adaptive_mutation_sub_case_is_replayed_with_its_mutated_payload() {
    let srv = serve(|_, p, _| match p {
        "/search" => (
            500,
            "text/plain",
            "Traceback (most recent call last):\n  x".into(),
        ),
        _ => (404, "application/json", "{}".into()),
    });
    let mut base = case("TC-001", "injection", "GET", "/search");
    base.payload = Some("q=ok".into());
    let mut r = crate::agent::types::fixtures::result("TC-001-M1", "injection", "FAIL");
    r.method = "GET".into();
    r.component = "/search".into();
    r.request_payload = Some("q='mutated".into());
    r.oracle = Some(OracleOutcome {
        verdict: Verdict::Fail,
        checks: vec![crate::agent::oracle::OracleCheck {
            code: "server_error".into(),
            verdict: Verdict::Fail,
            severity: Some(Severity::High),
            detail: "server error".into(),
        }],
        warnings: vec![],
        exploratory: false,
    });
    let creds = Credentials::none();
    let mut res = vec![r];
    let o = verify_failures(
        &mut res,
        &[base],
        &srv.base,
        &vopts(&creds, 2),
        &mut budget(50),
    );
    assert_eq!(
        o.summary.record("TC-001-M1").unwrap().verdict,
        VerifyVerdict::Confirmed
    );
    let seen: Vec<String> = srv
        .log
        .lock()
        .unwrap()
        .iter()
        .map(|(_, p, _)| p.clone())
        .collect();
    assert_eq!(seen.len(), 2);
}
#[test]
fn replay_votes_follow_the_original_failing_checks() {
    use crate::agent::oracle::OracleCheck;
    let outcome = |v: Verdict, codes: &[&str]| OracleOutcome {
        verdict: v,
        checks: codes
            .iter()
            .map(|c| OracleCheck {
                code: (*c).into(),
                verdict: v,
                severity: Some(Severity::High),
                detail: String::new(),
            })
            .collect(),
        warnings: vec![],
        exploratory: false,
    };
    let orig: BTreeSet<String> = ["server_error".to_string()].into();
    assert_eq!(
        vote(&orig, &outcome(Verdict::Fail, &["server_error"]), true),
        Vote::Reproduced
    );
    assert_eq!(
        vote(
            &orig,
            &outcome(Verdict::Fail, &["server_error", "x"]),
            false
        ),
        Vote::Reproduced
    );
    assert_eq!(
        vote(&orig, &outcome(Verdict::Pass, &["ok"]), true),
        Vote::NotReproduced
    );
    // a different failure is neither a reproduction nor a clean bill
    assert_eq!(
        vote(&orig, &outcome(Verdict::Fail, &["expected_status"]), false),
        Vote::Indeterminate
    );
    // inconclusive: the status moved => the failure is gone; the same answer judged inconclusively is no vote
    assert_eq!(
        vote(
            &orig,
            &outcome(Verdict::Inconclusive, &["no_assertion"]),
            false
        ),
        Vote::NotReproduced
    );
    assert_eq!(
        vote(
            &orig,
            &outcome(Verdict::Inconclusive, &["no_assertion"]),
            true
        ),
        Vote::Indeterminate
    );
    // no original oracle: any failure reproduces
    assert_eq!(
        vote(
            &BTreeSet::new(),
            &outcome(Verdict::Fail, &["anything"]),
            true
        ),
        Vote::Reproduced
    );
}

// ------------------------------------------------------------ inside a whole run

fn run_opts(k: u32) -> crate::agent::pipeline::RunOptions {
    crate::agent::pipeline::RunOptions {
        budget: RunBudget::new(80, 800, Duration::from_secs(120), 0.0),
        credentials: Credentials::none(),
        llm: crate::agent::pipeline::LlmMode::Off,
        reruns: 0,
        verify_k: k,
        request_timeout: Duration::from_secs(5),
        lookup_requester_ip: false,
        workers: 4,
        memory_dir: None,
    }
}

fn run_req(target: &str) -> crate::agent::types::AgentRunRequest {
    crate::agent::types::AgentRunRequest {
        target: target.into(),
        profile: "standard".into(),
        spec_url: None,
        custom_instructions: None,
        max_steps: None,
        dry_run: false,
        thinking: false,
        model_tier: "high".into(),
        thinking_budget_tokens: 8192,
        repo: None,
        diff_base: None,
    }
}

/// `/.env` always leaks; `/.git/config` leaks on its 2nd request only (discovery probes it once,
/// the executor's request is the 2nd) and is a 404 otherwise, replays included.
fn leaky_srv() -> Srv {
    serve(|m, p, nth| match (m, p) {
        ("GET", "/") => (
            200,
            "text/html",
            "<html><head><title>fixture</title></head><body>hi</body></html>".into(),
        ),
        ("GET", "/.env") => (
            200,
            "text/plain",
            "DB_PASSWORD=hunter2\nSECRET_KEY=abc123\n".into(),
        ),
        ("GET", "/.git/config") if nth == 2 => (
            200,
            "text/plain",
            "[core]\n\trepositoryformatversion = 0\n".into(),
        ),
        _ => (404, "application/json", "{\"error\":\"not found\"}".into()),
    })
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rh-verify-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn a_run_verifies_before_triage_and_only_reproducible_failures_become_defects() {
    let srv = leaky_srv();
    let base = tmpdir("run");
    let rep = crate::agent::pipeline::run_with(
        &base,
        &run_req(&srv.base),
        "run-verify",
        run_opts(2),
        Some(false),
    )
    .unwrap();
    let by_component = |c: &str| {
        rep.executed_results
            .iter()
            .find(|r| r.component == c)
            .unwrap()
    };
    let env = by_component("/.env");
    let git = by_component("/.git/config");
    assert_eq!(env.status, "FAIL", "{:?}", env.failure_reason);
    assert_eq!(
        git.status, "INCONCLUSIVE",
        "served once: not a defect ({:?})",
        git.failure_reason
    );
    assert!(
        git.failure_reason
            .as_deref()
            .unwrap()
            .starts_with("not reproduced")
    );
    assert_eq!(
        srv.count("GET", "/.env"),
        4,
        "discovery + original + 2 replays"
    );
    assert_eq!(
        srv.count("GET", "/.git/config"),
        4,
        "discovery + original + 2 replays"
    );
    // defects: the leak is verified 2/2, the one-off is not a defect
    let d = rep
        .triaged_defects
        .iter()
        .find(|d| d.component == "/.env")
        .expect("defect for /.env");
    assert!(
        d.verified
            && d.reproduced.as_deref() == Some("2/2")
            && d.verification.as_deref() == Some("confirmed"),
        "{d:?}"
    );
    assert!(
        rep.triaged_defects
            .iter()
            .all(|d| d.component != "/.git/config")
    );
    // ledger: summary, pass^k, gate
    let l = rep.evidence_ledger.as_ref().unwrap();
    let v = l.verification.as_ref().expect("verification summary");
    assert_eq!(
        (v.k, v.confirmed, v.not_reproduced, v.unverified),
        (2, 1, 1, 0),
        "{v:?}"
    );
    assert_eq!(v.pass_k, Some(0.5));
    assert_eq!(
        l.gate_verdict, "NO_GO",
        "the confirmed critical leak blocks"
    );
    assert!(
        l.executive_summary.contains("pass^2 50%"),
        "{}",
        l.executive_summary
    );
    // the replays count against the run budget and are logged
    let b = rep.budget.as_ref().unwrap();
    assert!(b.requests >= 4 && b.requests <= b.max_requests, "{b:?}");
    assert!(
        rep.steps
            .iter()
            .any(|s| s.agent == "Verifier" && s.details.contains("1 confirmed")),
        "{:?}",
        rep.steps
            .iter()
            .map(|s| (&s.agent, &s.details))
            .collect::<Vec<_>>()
    );
    assert!(
        rep.notes
            .iter()
            .any(|n| n.starts_with("verification:") && n.contains("INCONCLUSIVE"))
    );
    assert_eq!(rep.stage_sources["verifier"], "deterministic, k=2");
    // evidence file carries the replays
    let ev = std::fs::read_to_string(
        base.join("run-verify")
            .join(env.evidence_file.as_ref().unwrap()),
    )
    .unwrap();
    let ev: Value = serde_json::from_str(&ev).unwrap();
    assert_eq!(ev["verification"]["verdict"], "confirmed");
    assert_eq!(ev["verification"]["replays"].as_array().unwrap().len(), 2);
    // reports: a Verification section and the per-defect status
    let html = crate::agent::report::generate_agent_html_report(&rep);
    assert!(
        html.contains("Verification (independent replay)")
            && html.contains("Verified 2/2")
            && html.contains("pass^k"),
        "html"
    );
    let md = crate::agent::report::generate_agent_markdown_report(&rep);
    assert!(
        md.contains("## Verification")
            && md.contains("Verified 2/2")
            && md.contains("Not reproduced"),
        "md"
    );
    // persisted report round-trips with the new fields
    let back = crate::agent::store::load_agent_run_in(&base, "run-verify").unwrap();
    let bd = back
        .triaged_defects
        .iter()
        .find(|d| d.component == "/.env")
        .unwrap();
    assert!(bd.verified && back.evidence_ledger.unwrap().verification.unwrap().replayed == 2);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn with_verification_off_the_run_behaves_as_before_and_says_so() {
    let srv = leaky_srv();
    let base = tmpdir("off");
    let rep = crate::agent::pipeline::run_with(
        &base,
        &run_req(&srv.base),
        "run-noverify",
        run_opts(0),
        Some(false),
    )
    .unwrap();
    assert_eq!(srv.count("GET", "/.env"), 2, "discovery + original");
    assert_eq!(srv.count("GET", "/.git/config"), 2, "discovery + original");
    assert!(
        rep.executed_results
            .iter()
            .filter(|r| r.status == "FAIL")
            .count()
            >= 2,
        "both leaks stay FAIL"
    );
    assert!(
        rep.triaged_defects
            .iter()
            .all(|d| !d.verified && d.verification.is_none())
    );
    let v = rep.evidence_ledger.unwrap().verification.unwrap();
    assert_eq!(v.k, 0);
    assert!(v.stopped.unwrap().starts_with("disabled"));
    assert_eq!(rep.stage_sources["verifier"], "off");
    let _ = std::fs::remove_dir_all(&base);
}
#[test]
fn a_stateful_chain_is_replayed_end_to_end_and_the_orders_it_made_are_torn_down_later() {
    use crate::agent::types::StatefulStep;
    // BOLA: anyone can read any order
    let next = Arc::new(AtomicUsize::new(300));
    let n2 = next.clone();
    let srv = serve_auth(move |m, p, _, auth| match (m, p, auth) {
        ("POST", "/orders", Some("Bearer tok-user")) => (
            201,
            "application/json",
            format!("{{\"id\": {}}}", n2.fetch_add(1, Ordering::SeqCst)),
        ),
        // owner and bob can read, strangers cannot: bob reading it is the isolation breach
        ("GET", p, Some("Bearer tok-user" | "Bearer tok-bob")) if p.starts_with("/orders/") => {
            (200, "application/json", "{\"id\": 1}".into())
        }
        ("GET", p, _) if p.starts_with("/orders/") => (401, "application/json", "{}".into()),
        _ => (404, "application/json", "{}".into()),
    });
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
    create.payload = Some("{\"item\": \"a\"}".into());
    create.extract_vars = Some(vec!["id".into()]);
    let mut read = step(2, "bob", "GET", "/orders/{{id}}");
    read.violation_condition = Some("status == 200".into());
    let mut chain = case("TC-001", "authz", "POST", "/orders");
    chain.role = Some("user".into());
    chain.stateful_steps = Some(vec![create, read]);
    let creds = Credentials::none()
        .with("user", "tok-user")
        .with("bob", "tok-bob");
    let ledger = CreatedLedger::new();
    let mut results = {
        let _scope = ledger.install();
        execute_cases_with(
            &[chain.clone()],
            &srv.base,
            &ExecOptions {
                credentials: creds.clone(),
                ..exec_opts()
            },
            &mut budget(100),
        )
    };
    assert_eq!(results[0].status, "FAIL", "{:?}", results[0].failure_reason);
    let made_by_exec = srv.count("POST", "/orders");
    let o = {
        let _scope = ledger.install();
        verify_failures(
            &mut results,
            &[chain],
            &srv.base,
            &vopts(&creds, 2),
            &mut budget(100),
        )
    };
    let rec = o.summary.record("TC-001").unwrap();
    assert_eq!(
        (rec.verdict, rec.reproduced),
        (VerifyVerdict::Confirmed, 2),
        "{rec:?}"
    );
    assert_eq!(
        srv.count("POST", "/orders"),
        made_by_exec + 2,
        "each replay builds its own order"
    );
    assert_eq!(results[0].status, "FAIL");
    assert!(
        o.summary.replay_requests >= 2 * 3,
        "a chain replay is charged per request: {}",
        o.summary.replay_requests
    );
    let by_replays = ledger
        .entries()
        .iter()
        .filter(|r| {
            r.case_id
                .as_deref()
                .is_some_and(|c| c.starts_with("TC-001-V"))
        })
        .count();
    assert_eq!(by_replays, 2, "{:?}", ledger.entries());
    assert!(o.unidentified.is_empty(), "{:?}", o.unidentified);
    // a chain whose credential is missing for the replay is unverified, not guessed
    let mut again = vec![results.remove(0)];
    again[0].status = "FAIL".into();
    let mut chain2 = case("TC-001", "authz", "POST", "/orders");
    chain2.stateful_steps = results_chain_steps();
    let none = Credentials::none();
    let o2 = verify_failures(
        &mut again,
        &[chain2],
        &srv.base,
        &vopts(&none, 2),
        &mut budget(100),
    );
    assert_eq!(
        o2.summary.record("TC-001").unwrap().verdict,
        VerifyVerdict::Unverified
    );
    assert!(
        o2.summary
            .record("TC-001")
            .unwrap()
            .note
            .as_deref()
            .unwrap()
            .contains("cannot be replayed")
    );
}

fn results_chain_steps() -> Option<Vec<crate::agent::types::StatefulStep>> {
    use crate::agent::types::StatefulStep;
    let mk = |n: u32, actor: &str, method: &str, path: &str| StatefulStep {
        step_number: n,
        actor: actor.into(),
        method: method.into(),
        path: path.into(),
        payload: Some("{\"item\": \"a\"}".into()).filter(|_| method == "POST"),
        extract_vars: (method == "POST").then(|| vec!["id".to_string()]),
        expected_status: None,
        violation_condition: (method == "GET").then(|| "status == 200".to_string()),
    };
    Some(vec![
        mk(1, "user", "POST", "/orders"),
        mk(2, "bob", "GET", "/orders/{{id}}"),
    ])
}

#[test]
fn verify_replays_blind_timing_open_redirect_and_oast_k_times() {
    use axum::{
        Router, extract::Query, http::StatusCode, response::IntoResponse, routing::get,
    };
    use std::collections::HashMap;
    use std::net::SocketAddr;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (base, _jh) = rt.block_on(async {
        let app = Router::new()
            .route(
                "/delay",
                get(|Query(q): Query<HashMap<String, String>>| async move {
                    if q.get("id").is_some_and(|v| v.contains("SLEEP")) {
                        tokio::time::sleep(Duration::from_millis(160)).await;
                    }
                    (StatusCode::OK, "ok")
                }),
            )
            .route(
                "/redir",
                get(|Query(q): Query<HashMap<String, String>>| async move {
                    let next = q.get("next").cloned().unwrap_or_else(|| "/".into());
                    ([(axum::http::header::LOCATION, next)], StatusCode::FOUND).into_response()
                }),
            )
            .route(
                "/fetch",
                get(|Query(q): Query<HashMap<String, String>>| async move {
                    if let Some(u) = q.get("url") {
                        let _ = tokio::task::spawn_blocking({
                            let u = u.clone();
                            move || reqwest::blocking::get(&u)
                        })
                        .await;
                    }
                    (StatusCode::OK, "fetched")
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let jh = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://127.0.0.1:{}", addr.port()), jh)
    });

    let mut c_delay = case("TC-TD1", "injection", "GET", "/delay");
    c_delay.payload = Some("id=' OR SLEEP(1)--".into());
    c_delay.probe_oracle = Some(crate::agent::types::ProbeOracle::TimeDelay {
        baseline_payload: "id=1".into(),
        min_delay_ms: 120,
    });

    let mut c_redir = case("TC-OR1", "negative", "GET", "/redir");
    c_redir.payload = Some("next=https://readyhai-redirect.invalid/x".into());
    c_redir.probe_oracle = Some(crate::agent::types::ProbeOracle::OpenRedirect {
        canary_host: "readyhai-redirect.invalid".into(),
    });

    let mut c_oast = case("TC-OA1", "injection", "GET", "/fetch");
    c_oast.payload = Some("url=__OAST_URL__".into());
    c_oast.probe_oracle = Some(crate::agent::types::ProbeOracle::OastCallback {
        placeholder: "__OAST_URL__".into(),
        wait_ms: 500,
    });

    let mut c_clean = case("TC-TD-SAFE", "injection", "GET", "/delay");
    c_clean.payload = Some("id=harmless".into());
    c_clean.probe_oracle = Some(crate::agent::types::ProbeOracle::TimeDelay {
        baseline_payload: "id=1".into(),
        min_delay_ms: 120,
    });

    let cases = vec![c_delay, c_redir, c_oast, c_clean];
    let mut results =
        crate::agent::exec::execute_cases_with(&cases, &base, &exec_opts(), &mut budget(100));
    assert_eq!(results[0].status, "FAIL", "time delay should fail");
    assert_eq!(results[1].status, "FAIL", "open redirect should fail");
    assert_eq!(results[2].status, "FAIL", "oast callback should fail");
    assert_eq!(results[3].status, "PASS", "safe baseline should pass");

    let creds = Credentials::none();
    let out = verify_failures(
        &mut results,
        &cases,
        &base,
        &vopts(&creds, 2),
        &mut budget(100),
    );
    assert_eq!(
        out.summary.record("TC-TD1").unwrap().verdict,
        VerifyVerdict::Confirmed
    );
    assert_eq!(
        out.summary.record("TC-OR1").unwrap().verdict,
        VerifyVerdict::Confirmed
    );
    assert_eq!(
        out.summary.record("TC-OA1").unwrap().verdict,
        VerifyVerdict::Confirmed
    );
}

#[test]
fn test_juror_verdict_parsing() {
    let raw = r#"{
        "is_true_positive": true,
        "confidence": 95,
        "taint_path": "request body 'user_id' -> SQL error in response body",
        "remediation_diff": "--- a/app.py\n+++ b/app.py\n- query = f'SELECT * FROM users WHERE id={id}'\n+ cursor.execute('SELECT * FROM users WHERE id=%s', (id,))",
        "explanation": "Unsanitized user_id parameter allows SQL syntax injection"
    }"#;
    let verdict = super::juror::parse_juror_verdict(raw).expect("parse juror verdict");
    assert!(verdict.is_true_positive);
    assert_eq!(verdict.confidence, 95);
    assert!(verdict.remediation_diff.unwrap().contains("cursor.execute"));
}

#[test]
fn test_juror_deterministic_taint_tracing_sql_injection() {
    use crate::agent::types::CaseExecutionResult;
    let mut failure = CaseExecutionResult::default();
    failure.case_id = "TC-SQL-1".into();
    failure.status = "FAIL".into();
    failure.status_code = Some(500);
    failure.evidence = "Server returned 500: syntax error at or near 'admin'".into();
    failure.failure_reason = Some("oracle failed: sql_syntax_error".into());

    let verdict = super::juror::evaluate_with_juror(None, &failure, Some("src/db/users.py:42"));
    assert!(verdict.is_true_positive);
    assert!(verdict.confidence >= 90);
    assert!(verdict.taint_path.unwrap().contains("SQL query execution"));
    let diff = verdict.remediation_diff.expect("diff should be generated");
    assert!(diff.contains("--- a/src/db/users.py"));
    assert!(diff.contains("cursor.execute"));
}

#[test]
fn test_juror_deterministic_false_positive_elimination() {
    use crate::agent::types::CaseExecutionResult;
    let mut failure = CaseExecutionResult::default();
    failure.case_id = "TC-FP-1".into();
    failure.status = "FAIL".into();
    failure.status_code = Some(404);
    failure.evidence = "404 Not Found: Cannot GET /api/v1/unknown".into();

    let verdict = super::juror::evaluate_with_juror(None, &failure, None);
    assert!(!verdict.is_true_positive);
    assert_eq!(verdict.confidence, 90);
    assert!(verdict.remediation_diff.is_none());
}

#[test]
fn test_audit_defects_with_juror() {
    use crate::agent::types::{CaseExecutionResult, TriagedDefect};
    let mut failure_tp = CaseExecutionResult::default();
    failure_tp.case_id = "TC-TP".into();
    failure_tp.component = "/api/v1/users".into();
    failure_tp.status = "FAIL".into();
    failure_tp.status_code = Some(500);
    failure_tp.evidence = "psycopg2.OperationalError: syntax error at or near SELECT".into();

    let mut failure_fp = CaseExecutionResult::default();
    failure_fp.case_id = "TC-FP".into();
    failure_fp.component = "/api/v1/nonexistent".into();
    failure_fp.status = "FAIL".into();
    failure_fp.status_code = Some(404);
    failure_fp.evidence = "Not found".into();

    let defect_tp = TriagedDefect {
        id: "DEF-001".into(),
        case_ids: vec!["TC-TP".into()],
        component: "/api/v1/users".into(),
        source_context: Some("src/routes/users.py:10".into()),
        ..Default::default()
    };

    let defect_fp = TriagedDefect {
        id: "DEF-002".into(),
        case_ids: vec!["TC-FP".into()],
        component: "/api/v1/nonexistent".into(),
        ..Default::default()
    };

    let defects = vec![defect_tp, defect_fp];
    let results = vec![failure_tp, failure_fp];

    let (kept, eliminated) = super::juror::audit_defects_with_juror(None, defects, &results);
    assert_eq!(eliminated, 1, "false positive defect should be eliminated");
    assert_eq!(kept.len(), 1, "only true positive should be retained");
    assert_eq!(kept[0].id, "DEF-001");
    assert!(kept[0].remediation_patch.as_ref().unwrap().contains("cursor.execute"));
    assert!(kept[0].remediation_explanation.is_some());
}
