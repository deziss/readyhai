use super::*;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::agent::budget::{BudgetUsage, RunBudget, SliceLimits};
use crate::agent::exec::Credentials;
use crate::agent::exec::normalize_component;
use crate::agent::exec::{
    CaseGate, ExecOptions, MAX_REDIRECTS, execute_cases_gated, follows_redirects, is_mutating,
    is_safe_method,
};
use crate::agent::oracle::{Technique, is_sensitive_path};
use crate::agent::types::fixtures::planned;
use crate::agent::types::{
    AgentsReport, AreaBudget, AreaReport, BlockReason, CancelToken, CaseExecutionResult,
    CreatedLedger, PlannedCase, Quota, TriagedDefect, WaveTwoCase,
};

/// A target that answers 200 to every read, hands out ids to every POST in arrival order, and
/// logs when each request arrived. `delay` decides how long a request is held.
struct Stub {
    base: String,
    log: Arc<Mutex<Vec<(Instant, String)>>>,
}

impl Stub {
    fn arrivals(&self) -> Vec<Instant> {
        let mut v: Vec<Instant> = self.log.lock().unwrap().iter().map(|(t, _)| *t).collect();
        v.sort();
        v
    }
    fn count(&self) -> usize {
        self.log.lock().unwrap().len()
    }
    fn paths(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .map(|(_, p)| p.clone())
            .collect()
    }
}

fn stub(delay: impl Fn(&str, &str) -> u64 + Send + Sync + 'static) -> Stub {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let log: Arc<Mutex<Vec<(Instant, String)>>> = Arc::new(Mutex::new(vec![]));
    let (lg, ids, delay) = (log.clone(), Arc::new(AtomicU64::new(1)), Arc::new(delay));
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let (lg, ids, delay) = (lg.clone(), ids.clone(), delay.clone());
            std::thread::spawn(move || {
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
                let clen: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + clen {
                    let n = s.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let path = target.split('?').next().unwrap_or("/").to_string();
                lg.lock()
                    .unwrap()
                    .push((Instant::now(), format!("{method} {path}")));
                let ms = delay(&method, &path);
                if ms > 0 {
                    std::thread::sleep(Duration::from_millis(ms));
                }
                let (code, body) = if method == "POST" {
                    let id = ids.fetch_add(1, AtomicOrdering::SeqCst);
                    (201, format!("{{\"id\": {id}, \"made_at\": \"{path}\"}}"))
                } else {
                    (200, format!("{{\"ok\": true, \"path\": \"{path}\"}}"))
                };
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    Stub { base, log }
}

fn case(id: &str, area: &str, method: &str, path: &str, risk: &str) -> PlannedCase {
    let mut c = planned(id, "state_transition", method, path);
    c.area = area.into();
    c.risk_level = risk.into();
    c.role = Some("anon".into());
    c.expected_behavior = "Handled without a server error".into();
    if method == "GET" {
        c.expected_status = Some(200); // the stub answers every read with 200: a PASS
    }
    if method == "POST" {
        c.payload = Some(format!("{{\"n\": \"{id}\"}}"));
    }
    c
}

fn opts(reruns: u32) -> ExecOptions {
    ExecOptions {
        dry_run: false,
        is_spa_target: false,
        credentials: Credentials::none(),
        reruns,
        timeout: Duration::from_secs(10),
    }
}

fn lead(
    target: &str,
    o: &ExecOptions,
    workers: usize,
    created: &CreatedLedger,
    cases: &[PlannedCase],
    budget: &mut RunBudget,
) -> LeadOutcome {
    let cfg = LeadConfig {
        target,
        opts: o,
        workers,
        created,
        llm_calls_left: 0,
        on_progress: None,
    };
    run(&cfg, cases, budget)
}

fn shape(r: &[CaseExecutionResult]) -> Vec<(String, String, Option<u16>, String)> {
    r.iter()
        .map(|r| {
            (
                r.case_id.clone(),
                r.status.clone(),
                r.status_code,
                r.evidence.clone(),
            )
        })
        .collect()
}

// ------------------------------------------------------------ pure functions

#[test]
fn workers_come_from_the_environment_text_with_a_default_and_a_cap() {
    assert_eq!(parse_workers(None), 4);
    assert_eq!(parse_workers(Some("")), 4);
    assert_eq!(parse_workers(Some("nonsense")), 4);
    assert_eq!(parse_workers(Some("1")), 1);
    assert_eq!(parse_workers(Some(" 6 ")), 6);
    assert_eq!(parse_workers(Some("0")), 1, "never zero threads");
    assert_eq!(parse_workers(Some("64")), 8, "capped at 8");
    assert_eq!(parse_workers(Some("-3")), 4);
}

#[test]
fn areas_follow_what_a_case_is_and_the_planners_tag_wins() {
    let mut bola = planned("a", "authz", "POST", "/orders");
    bola.stateful_steps = Some(vec![]);
    assert_eq!(
        Area::classify(&bola),
        Area::Auth,
        "authz stays auth, chain or not"
    );
    let forged = {
        let mut c = planned("b", "negative", "GET", "/x");
        c.role = Some("forged".into());
        c
    };
    assert_eq!(Area::classify(&forged), Area::Auth);
    let mut burst = planned("c", "boundary", "POST", "/orders");
    burst.concurrency_burst = Some(5);
    assert_eq!(Area::classify(&burst), Area::State);
    assert_eq!(
        Area::classify(&planned("d", "state_transition", "DELETE", "/orders/9")),
        Area::State
    );
    let mut crawl = planned("e", "state_transition", "GET", "/");
    crawl.source = Some("deterministic".into());
    assert_eq!(Area::classify(&crawl), Area::Ui);
    let mut spec = planned("f", "boundary", "POST", "/orders");
    spec.source = Some("openapi".into());
    assert_eq!(Area::classify(&spec), Area::Contract);
    assert_eq!(
        Area::classify(&planned("g", "injection", "GET", "/s")),
        Area::Contract
    );
    // the tag is what runs; an unknown tag falls back to the classification
    let mut tagged = planned("h", "boundary", "GET", "/s");
    tagged.area = "ui".into();
    assert_eq!(Area::of(&tagged), Area::Ui);
    tagged.area = "bogus".into();
    assert_eq!(Area::of(&tagged), Area::Contract);
    assert_eq!(Area::parse(" AUTH "), Some(Area::Auth));
    assert_eq!(
        Area::ALL.map(Area::as_str),
        ["auth", "contract", "state", "ui"]
    );
}

#[test]
fn the_budget_is_shared_by_risk_and_change_impact_with_caps_and_a_reserve() {
    let mut critical = planned("a", "authz", "GET", "/a");
    critical.risk_level = "critical".into();
    let mut changed = planned("b", "boundary", "GET", "/b");
    changed.risk_level = "low".into();
    changed.changed_ops = vec!["GET /b".into()];
    let low = {
        let mut c = planned("c", "boundary", "GET", "/c");
        c.risk_level = "low".into();
        c
    };
    assert_eq!(
        (
            case_weight(&critical),
            case_weight(&changed),
            case_weight(&low)
        ),
        (8, 3, 1)
    );

    // 90 requests, three areas that need a lot: shares follow the weights 8 : 3 : 1
    let needs = [
        AreaNeed {
            area: Area::Auth,
            weight: 8,
            cases: 10,
            requests: 100,
        },
        AreaNeed {
            area: Area::Contract,
            weight: 3,
            cases: 10,
            requests: 100,
        },
        AreaNeed {
            area: Area::State,
            weight: 1,
            cases: 10,
            requests: 100,
        },
    ];
    let avail = Available {
        steps: 100,
        requests: 100,
        wall: Duration::from_secs(120),
        llm_calls: 12,
    };
    let g = allocate(&needs, &avail, 10, 1);
    let req: Vec<usize> = g.iter().map(|g| g.requests).collect();
    assert_eq!(
        req.iter().sum::<usize>(),
        90,
        "everything but the reserve is handed out"
    );
    assert!(req[0] > req[1] && req[1] > req[2], "{req:?}");
    assert_eq!(req, [60, 23, 7]);
    assert_eq!(g.iter().map(|g| g.llm_calls).sum::<usize>(), 12);
    assert_eq!(
        g.iter().map(|g| g.steps).collect::<Vec<_>>(),
        [10, 10, 10],
        "steps are capped at the cases"
    );
    // the same inputs, the same answer
    assert_eq!(allocate(&needs, &avail, 10, 1), g);

    // a small area is never given more than it can use; the rest goes to the others
    let needs = [
        AreaNeed {
            area: Area::Auth,
            weight: 1,
            cases: 2,
            requests: 4,
        },
        AreaNeed {
            area: Area::Contract,
            weight: 1,
            cases: 50,
            requests: 200,
        },
    ];
    let g = allocate(&needs, &avail, 0, 1);
    assert_eq!(
        (g[0].requests, g[1].requests),
        (4, 96),
        "cap, then the others"
    );
    assert_eq!(g[0].steps, 2);
    // not enough requests for the demand: the pool keeps what the caps leave
    let rich = Available {
        requests: 1000,
        ..avail
    };
    let g = allocate(&needs, &rich, 0, 1);
    assert_eq!((g[0].requests, g[1].requests), (4, 200));
    // wall clock: a lone worker gets its weighted share, parallel workers share the window,
    // nobody gets less than 20 s or more than the window
    let needs = [
        AreaNeed {
            area: Area::Auth,
            weight: 9,
            cases: 1,
            requests: 1,
        },
        AreaNeed {
            area: Area::Contract,
            weight: 1,
            cases: 1,
            requests: 1,
        },
    ];
    let one = allocate(&needs, &avail, 0, 1);
    assert_eq!(one[0].wall, Duration::from_millis(108_000));
    assert_eq!(one[1].wall, Duration::from_secs(20), "the floor");
    let four = allocate(&needs, &avail, 0, 4);
    assert_eq!(four[0].wall, Duration::from_secs(120), "the window");
}

#[test]
fn share_capped_is_exact_and_deterministic() {
    assert_eq!(
        share_capped(10, &[1, 1, 1], &[100; 3]),
        [4, 3, 3],
        "ties go to the earlier area"
    );
    assert_eq!(share_capped(10, &[1, 1, 1], &[2, 100, 100]), [2, 4, 4]);
    assert_eq!(share_capped(0, &[1, 1], &[5, 5]), [0, 0]);
    assert_eq!(
        share_capped(100, &[1, 1], &[3, 4]),
        [3, 4],
        "units the caps refuse are not handed out"
    );
    assert_eq!(
        share_capped(7, &[0, 0], &[9, 9]),
        [4, 3],
        "a zero weight counts as one"
    );
}

#[test]
fn results_merge_in_case_id_order_whatever_order_they_arrive_in() {
    use crate::agent::types::fixtures::result;
    let ids = [
        "TC-010",
        "TC-002",
        "TC-002-M1",
        "TC-002-B",
        "TC-009",
        "TC-002-F1",
        "TC-100",
        "CLEANUP-001",
    ];
    let mk = |order: &[&str]| -> Vec<String> {
        merge_results(
            order
                .iter()
                .map(|i| result(i, "boundary", "PASS"))
                .collect(),
        )
        .into_iter()
        .map(|r| r.case_id)
        .collect()
    };
    let want = [
        "CLEANUP-001",
        "TC-002",
        "TC-002-B",
        "TC-002-F1",
        "TC-002-M1",
        "TC-009",
        "TC-010",
        "TC-100",
    ];
    assert_eq!(mk(&ids), want);
    let mut rev = ids;
    rev.reverse();
    assert_eq!(mk(&rev), want);
    assert_eq!(natural_cmp("TC-9", "TC-10"), Ordering::Less);
    assert_eq!(natural_cmp("TC-007", "TC-7"), Ordering::Equal);
}

#[test]
fn wave_two_rules_are_deterministic_and_bounded() {
    use crate::agent::types::fixtures::result;
    let mut admin = case("TC-001", "auth", "GET", "/admin/stats", "critical");
    admin.technique = "authz".into();
    admin.role = Some("anon".into());
    admin.expected_status = Some(401);
    let mut sibling = case("TC-002", "contract", "GET", "/admin/stats", "medium");
    sibling.role = Some("user".into());
    sibling.contract = Some(crate::agent::types::ResponseContract {
        latency: true,
        ..Default::default()
    });
    sibling.expect_fields = vec!["total".into()];
    let mut env = case("TC-003", "auth", "GET", "/.env", "critical");
    env.technique = "authz".into();
    let mut write = case("TC-004", "auth", "POST", "/orders", "critical");
    write.technique = "authz".into();
    let reread = case("TC-005", "contract", "GET", "/orders/1", "medium");
    let post_inc = case("TC-006", "contract", "POST", "/orders", "medium");
    let cut = case("TC-007", "contract", "GET", "/orders/2", "medium");
    let cases = vec![admin, sibling, env, write, reread, post_inc, cut];
    let mut skipped = result("TC-007", "boundary", "SKIPPED");
    skipped.failure_reason =
        Some("request budget exhausted (area 'contract' allocation: 4 requests)".into());
    // TC-005 was rate-limited: that may be gone on a second send
    let mut limited = result("TC-005", "boundary", "INCONCLUSIVE");
    limited.status_code = Some(429);
    let mut limited_sub = result("TC-005-M1", "boundary", "INCONCLUSIVE");
    limited_sub.status_code = Some(429);
    let mut limited_write = result("TC-006", "boundary", "INCONCLUSIVE");
    limited_write.status_code = Some(429);
    let results = vec![
        result("TC-001", "authz", "FAIL"),
        result("TC-002", "boundary", "PASS"),
        result("TC-003", "authz", "FAIL"),
        result("TC-004", "authz", "FAIL"),
        limited,
        limited_sub,
        limited_write,
        skipped,
    ];
    let f = plan_follow_ups(&cases, &results, 10);
    let got: Vec<(&str, &str, bool)> = f
        .iter()
        .map(|f| (f.rule, f.case.id.as_str(), f.resume))
        .collect();
    assert_eq!(
        got,
        [
            (RULE_AUTH_TO_CONTRACT, "TC-001-F1", false),
            (RULE_RESUME, "TC-007", true),
            (RULE_REPROBE, "TC-005-F1", false),
        ],
        "a sensitive file, a write and a sub-case get no follow-up; a write that was INCONCLUSIVE is not repeated"
    );
    let c = &f[0].case;
    assert_eq!(
        (c.method.as_str(), c.component.as_str(), c.area.as_str()),
        ("GET", "/admin/stats", "contract")
    );
    assert_eq!(
        c.role.as_deref(),
        Some("anon"),
        "as the identity that was let in"
    );
    assert!(
        c.contract.is_some() && c.expect_fields == ["total"],
        "the plan's own contract for that endpoint"
    );
    assert!(c.changed_ops.is_empty());
    assert_eq!(Area::of(&f[2].case), Area::Contract);
    // bounded and repeatable
    assert_eq!(plan_follow_ups(&cases, &results, 2).len(), 2);
    assert_eq!(plan_follow_ups(&cases, &results, 0).len(), 0);
    let ids = |l: usize| -> Vec<String> {
        plan_follow_ups(&cases, &results, l)
            .into_iter()
            .map(|f| f.case.id)
            .collect()
    };
    assert_eq!(
        ids(10),
        ids(10),
        "the same plan and results always give the same follow-ups"
    );
    // a follow-up that the plan already holds is not planned twice
    let mut same = cases.clone();
    same[1].role = Some("anon".into());
    assert!(
        plan_follow_ups(&same, &results, 10)
            .iter()
            .all(|f| f.rule != RULE_AUTH_TO_CONTRACT),
        "the plan already reads /admin/stats as anon with that technique"
    );
}

#[test]
fn only_transient_causes_are_reprobed() {
    use crate::agent::types::fixtures::result;
    let cases: Vec<PlannedCase> = (1..=12)
        .map(|i| {
            case(
                &format!("TC-{i:03}"),
                "contract",
                "GET",
                &format!("/r/{i}"),
                "medium",
            )
        })
        .collect();
    let inconclusive = |i: usize, code: u16| {
        let mut r = result(&format!("TC-{i:03}"), "boundary", "INCONCLUSIVE");
        r.status_code = Some(code);
        r
    };
    let mut transport = result("TC-009", "boundary", "BLOCKED");
    transport.status_code = None;
    transport.blocked_reason = Some(BlockReason::Transport);
    let mut legacy = result("TC-010", "boundary", "BLOCKED");
    legacy.status_code = None;
    legacy.failure_reason = Some("Connection error: operation timed out".into());
    let mut wall = result("TC-011", "boundary", "BLOCKED");
    wall.blocked_reason = Some(BlockReason::AuthWall);
    wall.status_code = Some(401);
    let mut crashed = result("TC-012", "boundary", "BLOCKED");
    crashed.status_code = None;
    crashed.failure_reason = Some("area worker failed".into());
    let results = vec![
        inconclusive(1, 429), // rate limited
        inconclusive(2, 503), // upstream hiccup
        inconclusive(3, 408), // timeout
        inconclusive(4, 307), // a redirect: the same every time
        inconclusive(5, 200), // no class evidence: the same every time
        inconclusive(6, 405), // a CORS probe on a route that does not serve OPTIONS
        inconclusive(7, 401), // an auth wall
        inconclusive(8, 404),
        transport, // no answer at all
        legacy,    // an older run's transport error
        wall,      // BLOCKED by the wall
        crashed,   // BLOCKED, but not a transport error
    ];
    let follow_ups = plan_follow_ups(&cases, &results, 20);
    let got: Vec<&str> = follow_ups.iter().map(|f| f.origin.as_str()).collect();
    assert_eq!(
        got,
        ["TC-001", "TC-002", "TC-003", "TC-009", "TC-010"],
        "429, 5xx, 408 and a missing answer are re-probed; a redirect, no class evidence, a 405, an auth wall and a 404 are not"
    );
    assert!(
        follow_ups
            .iter()
            .all(|f| f.rule == RULE_REPROBE && f.case.id.ends_with("-F1"))
    );
    for (r, want) in [
        (inconclusive(1, 500), true),
        (inconclusive(1, 599), true),
        (inconclusive(1, 600), false),
        (inconclusive(1, 302), false),
    ] {
        assert_eq!(is_transient(&r), want, "{:?}", r.status_code);
    }
    // a PASS or a FAIL is never "transient"
    assert!(!is_transient(&result("TC-001", "boundary", "PASS")));
    assert!(!is_transient(&result("TC-001", "boundary", "FAIL")));
}

#[test]
fn a_ledger_row_asks_for_no_requests_and_a_followed_redirect_asks_for_more() {
    let mut row = case("TC-001", "ui", "GET", "/", "low");
    row.technique = "injection".into();
    row.source = Some(crate::agent::types::SRC_NOT_APPLICABLE.into());
    assert_eq!(request_demand(&row, 2), 0);
    assert_eq!(
        Area::classify(&row),
        Area::Ui,
        "the rows of the crawl baseline"
    );
    let mut wall = row.clone();
    wall.source = Some(crate::agent::types::SRC_AUTH_WALL.into());
    assert_eq!(request_demand(&wall, 2), 0);
    // a read that follows redirects: every hop of every attempt is a request
    let mut read = case("TC-002", "contract", "GET", "/page", "low");
    read.technique = "state_transition".into();
    assert_eq!(request_demand(&read, 2), 3 * 2 + 3 * MAX_REDIRECTS);
    // an authorization case keeps the raw status, so it never redirects
    let mut authz = case("TC-003", "auth", "GET", "/admin", "low");
    authz.technique = "authz".into();
    assert_eq!(request_demand(&authz, 2), 3 * 2);
    // a write is sent once and never redirected
    let write = case("TC-004", "state", "POST", "/orders", "low");
    assert_eq!(request_demand(&write, 2), 2);
}

// ------------------------------------------------------------ the workers

#[test]
fn every_area_is_held_to_its_own_budget() {
    let s = stub(|_, _| 0);
    let o = opts(0);
    let created = CreatedLedger::new();
    // 12 critical reads in one area, 2 low ones in another, and only 10 requests for the run
    let mut cases: Vec<PlannedCase> = (1..=12)
        .map(|i| {
            case(
                &format!("TC-{i:03}"),
                "auth",
                "GET",
                &format!("/a/{i}"),
                "critical",
            )
        })
        .collect();
    cases.extend((13..=14).map(|i| {
        case(
            &format!("TC-{i:03}"),
            "contract",
            "GET",
            &format!("/c/{i}"),
            "low",
        )
    }));
    let mut budget = RunBudget::new(100, 10, Duration::from_secs(60), 0.0);
    let out = lead(&s.base, &o, 4, &created, &cases, &mut budget);
    for a in &out.agents.areas {
        assert!(
            a.budget.used.requests <= a.budget.allocated.requests
                && a.budget.used.steps <= a.budget.allocated.steps,
            "{a:?}"
        );
        if let Some(w) = a.wave2_budget {
            assert!(w.used.requests <= w.allocated.requests, "{a:?}");
        }
    }
    assert!(
        s.count() <= 10,
        "the run asked for at most 10 requests, the target saw {}",
        s.count()
    );
    assert_eq!(
        budget.requests_used(),
        s.count(),
        "what the workers used is charged to the run"
    );
    let cut: Vec<&CaseExecutionResult> = out
        .results
        .iter()
        .filter(|r| r.status == "SKIPPED")
        .collect();
    assert!(!cut.is_empty());
    assert!(
        cut.iter().all(|r| {
            let m = r.failure_reason.as_deref().unwrap();
            m.starts_with("request budget exhausted") && m.contains("allocation")
        }),
        "{:?}",
        cut.iter().map(|r| &r.failure_reason).collect::<Vec<_>>()
    );
    let auth = out.agents.areas.iter().find(|a| a.area == "auth").unwrap();
    assert!(auth.budget.allocated.requests < 12, "{auth:?}");
    assert!(
        budget
            .stopped()
            .unwrap()
            .starts_with("request budget exhausted")
    );
}

#[test]
fn what_an_area_leaves_unused_goes_to_a_pool_that_resumes_the_cases_another_area_ran_out_for() {
    let s = stub(|_, _| 0);
    let o = opts(2); // a read may cost 6 requests in the worst case, it costs 1
    let created = CreatedLedger::new();
    let mut cases: Vec<PlannedCase> = (1..=10)
        .map(|i| {
            case(
                &format!("TC-{i:03}"),
                "auth",
                "GET",
                &format!("/a/{i}"),
                "critical",
            )
        })
        .collect();
    cases.extend((11..=20).map(|i| {
        case(
            &format!("TC-{i:03}"),
            "contract",
            "GET",
            &format!("/c/{i}"),
            "low",
        )
    }));
    let mut budget = RunBudget::new(100, 40, Duration::from_secs(60), 0.0);
    let out = lead(&s.base, &o, 2, &created, &cases, &mut budget);
    let a = &out.agents;
    let auth = a.areas.iter().find(|x| x.area == "auth").unwrap();
    let con = a.areas.iter().find(|x| x.area == "contract").unwrap();
    // the heavy area was given far more than it needed, the light one was cut short
    assert!(
        auth.budget.allocated.requests >= 20 && auth.budget.used.requests == 10,
        "{auth:?}"
    );
    assert!(
        con.budget.used.requests == con.budget.allocated.requests && con.budget.used.requests < 10,
        "{con:?}"
    );
    assert!(a.pool_reclaimed.requests >= 20, "{a:?}");
    // wave 2 runs what was cut off from the pool
    assert_eq!(a.waves, 2);
    assert!(
        con.wave2_budget.is_some_and(|b| b.used.requests > 0),
        "{con:?}"
    );
    assert!(
        !a.wave2.is_empty()
            && a.wave2
                .iter()
                .all(|w| w.rule == RULE_RESUME && w.area == "contract")
    );
    assert!(
        out.follow_ups.is_empty(),
        "a resumed case is not a new case"
    );
    assert_eq!(out.results.len(), 20);
    assert!(
        out.results.iter().all(|r| r.status != "SKIPPED"),
        "{:?}",
        shape(&out.results)
    );
    assert_eq!(s.count(), 20, "every case was sent exactly once");
    assert!(budget.stopped().is_none(), "nothing is left cut off");
    assert!(a.pool_left.requests == 40 - 20);
}

#[test]
fn cancelling_the_run_stops_every_worker() {
    let s = stub(|_, _| 120);
    let o = opts(0);
    let created = CreatedLedger::new();
    let mut cases = vec![];
    for (k, area) in ["auth", "contract", "state", "ui"].iter().enumerate() {
        for i in 0..20 {
            cases.push(case(
                &format!("TC-{:03}", k * 20 + i + 1),
                area,
                "GET",
                &format!("/{area}/{i}"),
                "medium",
            ));
        }
    }
    let mut budget = RunBudget::new(1000, 5000, Duration::from_secs(120), 0.0);
    let token = budget.cancel_token().clone();
    let t0 = Instant::now();
    let out = std::thread::scope(|sc| {
        let h = sc.spawn(|| lead(&s.base, &o, 4, &created, &cases, &mut budget));
        std::thread::sleep(Duration::from_millis(300));
        token.cancel();
        h.join().unwrap()
    });
    let took = t0.elapsed();
    assert!(
        took < Duration::from_millis(1800),
        "20 cases x 120 ms per area would take 2.4 s: {took:?}"
    );
    assert!(s.count() < 4 * 20 / 2, "{} requests were sent", s.count());
    assert_eq!(out.agents.status, "cancelled");
    assert_eq!(out.agents.waves, 1, "no wave 2 for a cancelled run");
    for a in &out.agents.areas {
        assert_eq!(a.status, "cancelled", "{a:?}");
        assert!(a.skipped > 0, "{a:?}");
    }
    assert!(
        out.results
            .iter()
            .filter(|r| r.status == "SKIPPED")
            .all(|r| r.failure_reason.as_deref() == Some("run cancelled"))
    );
    assert_eq!(
        out.results.len(),
        cases.len(),
        "every case still has a result"
    );
}

#[test]
fn writes_take_turns_so_one_worker_and_four_give_the_same_results_and_ledger() {
    // The slow area's POSTs arrive last unless the lead orders them: without the turns, the
    // fast areas would hand out the low ids.
    let mut cases = vec![];
    let mut n = 0;
    for (area, base) in [
        ("auth", "/slow"),
        ("contract", "/fast"),
        ("state", "/fast"),
        ("ui", "/fast"),
    ] {
        for i in 0..3 {
            n += 1;
            cases.push(case(
                &format!("TC-{n:03}"),
                area,
                "POST",
                &format!("{base}/{area}{i}"),
                "medium",
            ));
            n += 1;
            cases.push(case(
                &format!("TC-{n:03}"),
                area,
                "GET",
                &format!("/read/{area}{i}"),
                "low",
            ));
        }
    }
    let run_with = |workers: usize| {
        let s = stub(|_, p| if p.starts_with("/slow") { 60 } else { 0 });
        let created = CreatedLedger::new();
        let mut budget = RunBudget::new(200, 2000, Duration::from_secs(60), 0.0);
        let out = lead(&s.base, &opts(2), workers, &created, &cases, &mut budget);
        (
            shape(&out.results),
            created.entries(),
            out.agents
                .areas
                .iter()
                .map(|a| (a.area.clone(), a.executed, a.pass, a.fail))
                .collect::<Vec<_>>(),
            s.count(),
        )
    };
    let one = run_with(1);
    assert_eq!(one.3, 24);
    assert_eq!(one.1.len(), 12, "every POST was recorded for teardown");
    let ids: Vec<&str> = one.1.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"
        ],
        "the ledger is in write order"
    );
    assert!(
        one.1[0].path.starts_with("/slow/"),
        "auth writes come first: {:?}",
        one.1[0]
    );
    for workers in [4, 4, 8] {
        let many = run_with(workers);
        assert_eq!(many.0, one.0, "results with {workers} workers");
        assert_eq!(
            many.1, one.1,
            "created-resource ledger with {workers} workers"
        );
        assert_eq!(many.2, one.2, "per-area counts with {workers} workers");
    }
}

#[test]
fn a_failed_access_check_triggers_one_contract_follow_up_wave_within_the_pool() {
    let s = stub(|_, _| 0);
    let o = opts(0);
    let created = CreatedLedger::new();
    // /admin/stats answers 200 to a request without credentials: the access check fails
    let mut admin = case("TC-001", "auth", "GET", "/admin/stats", "critical");
    admin.technique = "authz".into();
    admin.expected_status = Some(401);
    admin.secured = Some(true);
    let ok = case("TC-002", "contract", "GET", "/health", "low");
    let cases = vec![admin, ok];
    let mut budget = RunBudget::new(50, 100, Duration::from_secs(60), 0.0);
    let out = lead(&s.base, &o, 4, &created, &cases, &mut budget);
    let a = &out.agents;
    assert_eq!(a.waves, 2);
    assert_eq!(out.follow_ups.len(), 1);
    let f = &out.follow_ups[0];
    assert_eq!(
        (f.id.as_str(), f.area.as_str(), f.component.as_str()),
        ("TC-001-F1", "contract", "/admin/stats")
    );
    assert_eq!(a.wave2.len(), 1);
    assert_eq!(
        (a.wave2[0].rule.as_str(), a.wave2[0].origin.as_str()),
        (RULE_AUTH_TO_CONTRACT, "TC-001")
    );
    let contract = a.areas.iter().find(|x| x.area == "contract").unwrap();
    assert_eq!(contract.wave2_added, ["TC-001-F1"]);
    assert!(contract.case_ids.contains(&"TC-001-F1".to_string()));
    assert!(
        contract
            .wave2_budget
            .is_some_and(|b| b.used.requests == 1 && b.allocated.requests >= 1)
    );
    let ids: Vec<&str> = out.results.iter().map(|r| r.case_id.as_str()).collect();
    assert_eq!(
        ids,
        ["TC-001", "TC-001-F1", "TC-002"],
        "merged in case-id order, the follow-up next to its origin"
    );
    assert_eq!(out.results[0].status, "FAIL");
    assert_eq!(
        s.paths()
            .iter()
            .filter(|p| *p == "GET /admin/stats")
            .count(),
        2,
        "the original and the follow-up"
    );
    assert_eq!(budget.requests_used(), 3);
    // no third wave, ever: the follow-up's own outcome plans nothing
    assert_eq!(a.waves, 2);
    // a run with nothing to follow up has one wave and an empty wave-2 list
    let s2 = stub(|_, _| 0);
    let mut b2 = RunBudget::new(50, 100, Duration::from_secs(60), 0.0);
    let calm = lead(&s2.base, &o, 4, &CreatedLedger::new(), &cases[1..], &mut b2);
    assert_eq!(
        (
            calm.agents.waves,
            calm.agents.wave2.len(),
            calm.follow_ups.len()
        ),
        (1, 0, 0)
    );
    // an exhausted step allowance leaves no pool for wave 2
    let s3 = stub(|_, _| 0);
    let mut b3 = RunBudget::new(2, 100, Duration::from_secs(60), 0.0);
    let tight = lead(&s3.base, &o, 4, &CreatedLedger::new(), &cases, &mut b3);
    assert_eq!(
        tight.agents.waves, 1,
        "the plan used every step: nothing left for follow-ups"
    );
}

#[test]
fn the_global_rate_limit_holds_while_workers_run_in_parallel() {
    let s = stub(|_, _| 0);
    let o = opts(0);
    let created = CreatedLedger::new();
    let mut cases = vec![];
    for (k, area) in ["auth", "contract", "state", "ui"].iter().enumerate() {
        for i in 0..8 {
            cases.push(case(
                &format!("TC-{:03}", k * 8 + i + 1),
                area,
                "GET",
                &format!("/{area}/{i}"),
                "medium",
            ));
        }
    }
    let gap = Duration::from_millis(25); // 40 requests per second for the host, for all workers together
    let mut budget = RunBudget::new(200, 2000, Duration::from_secs(60), 40.0);
    let t0 = Instant::now();
    let out = lead(&s.base, &o, 4, &created, &cases, &mut budget);
    let took = t0.elapsed();
    assert_eq!(out.results.len(), 32);
    let t = s.arrivals();
    assert_eq!(t.len(), 32);
    assert!(
        t[31].duration_since(t[0]) >= gap * 31 * 8 / 10,
        "32 requests at 40/s arrived within {:?}: each worker paced itself, not the run",
        t[31].duration_since(t[0])
    );
    for w in t.windows(5) {
        assert!(
            w[4].duration_since(w[0]) >= gap * 2,
            "5 requests in {:?}",
            w[4].duration_since(w[0])
        );
    }
    assert!(took >= gap * 31 * 8 / 10, "{took:?}");
}

#[test]
fn progress_is_visible_while_the_areas_run_and_ends_complete() {
    let s = stub(|_, _| 150);
    let o = opts(0);
    let created = CreatedLedger::new();
    let mut cases = vec![];
    for (k, area) in ["auth", "contract"].iter().enumerate() {
        for i in 0..6 {
            cases.push(case(
                &format!("TC-{:03}", k * 6 + i + 1),
                area,
                "GET",
                &format!("/{area}/{i}"),
                "medium",
            ));
        }
    }
    let seen: Mutex<Vec<AgentsReport>> = Mutex::new(vec![]);
    let observe = |a: &AgentsReport| seen.lock().unwrap().push(a.clone());
    let cfg = LeadConfig {
        target: &s.base,
        opts: &o,
        workers: 2,
        created: &created,
        llm_calls_left: 0,
        on_progress: Some(&observe),
    };
    let mut budget = RunBudget::new(100, 500, Duration::from_secs(60), 0.0);
    let out = run(&cfg, &cases, &mut budget);
    let seen = seen.into_inner().unwrap();
    assert!(seen.len() >= 4, "{} snapshots", seen.len());
    assert!(
        seen.iter()
            .any(|a| a.areas.iter().any(|x| x.status == "running")),
        "an area was seen running"
    );
    assert!(
        seen.iter().any(|a| a
            .areas
            .iter()
            .any(|x| x.area == "auth" && x.executed > 0 && x.executed < 6)),
        "a snapshot in the middle of an area"
    );
    assert_eq!(seen[0].status, "running");
    assert_eq!(out.agents.status, "done");
    assert!(
        out.agents
            .areas
            .iter()
            .filter(|a| a.cases > 0)
            .all(|a| a.status == "done" && a.executed == 6)
    );
    assert_eq!(
        out.agents
            .areas
            .iter()
            .find(|a| a.area == "ui")
            .unwrap()
            .status,
        "idle"
    );
}

#[test]
fn a_panicking_worker_is_reported_and_does_not_take_the_others_down() {
    use std::sync::atomic::AtomicBool;
    let s = stub(|_, _| 100);
    let o = opts(0);
    let created = CreatedLedger::new();
    let mut cases = vec![];
    for (k, area) in ["auth", "contract"].iter().enumerate() {
        for i in 0..3 {
            cases.push(case(
                &format!("TC-{:03}", k * 3 + i + 1),
                area,
                "GET",
                &format!("/{area}/{i}"),
                "medium",
            ));
        }
    }
    // the progress observer runs inside the workers: make it panic once, mid-run
    let boom = AtomicBool::new(false);
    let observe = |a: &AgentsReport| {
        if a.areas.iter().any(|x| x.executed > 0) && !boom.swap(true, AtomicOrdering::SeqCst) {
            panic!("observer boom");
        }
    };
    let cfg = LeadConfig {
        target: &s.base,
        opts: &o,
        workers: 2,
        created: &created,
        llm_calls_left: 0,
        on_progress: Some(&observe),
    };
    let mut budget = RunBudget::new(100, 500, Duration::from_secs(60), 0.0);
    let out = run(&cfg, &cases, &mut budget);
    let failed: Vec<&AreaReport> = out
        .agents
        .areas
        .iter()
        .filter(|a| a.status == "failed")
        .collect();
    assert_eq!(failed.len(), 1, "{:?}", out.agents.areas);
    assert!(
        failed[0].error.as_deref().unwrap().contains("panicked"),
        "{failed:?}"
    );
    let healthy = out
        .agents
        .areas
        .iter()
        .find(|a| a.cases > 0 && a.status != "failed")
        .unwrap();
    assert!(
        healthy.status == "done" && healthy.executed == 3,
        "{healthy:?}"
    );
    assert_eq!(
        out.results.len(),
        6,
        "the failed area's cases are BLOCKED, not lost"
    );
    assert_eq!(
        out.results.iter().filter(|r| r.status == "BLOCKED").count(),
        3
    );
    assert_eq!(out.agents.status, "done");
}

#[test]
fn the_reports_show_an_agents_section_per_area_with_budgets_and_wave_two_escaped() {
    use crate::agent::types::fixtures::{report, result};
    let mut rep = report("run-agents-report");
    let mut a = AgentsReport {
        workers: 4,
        status: "done".into(),
        waves: 2,
        areas: vec![
            AreaReport {
                area: "auth".into(),
                status: "done".into(),
                cases: 14,
                case_ids: vec!["TC-001".into(), "TC-002".into()],
                budget: AreaBudget {
                    allocated: Quota {
                        steps: 14,
                        requests: 64,
                        wall_ms: 90_000,
                        llm_calls: 2,
                    },
                    used: Quota {
                        steps: 14,
                        requests: 20,
                        wall_ms: 2_500,
                        llm_calls: 0,
                    },
                },
                ..Default::default()
            },
            AreaReport {
                area: "contract".into(),
                status: "done".into(),
                cases: 26,
                case_ids: vec!["TC-003".into(), "TC-001-F1".into()],
                budget: AreaBudget {
                    allocated: Quota {
                        steps: 26,
                        requests: 116,
                        ..Default::default()
                    },
                    used: Quota {
                        steps: 26,
                        requests: 32,
                        ..Default::default()
                    },
                },
                wave2_budget: Some(AreaBudget {
                    allocated: Quota {
                        steps: 1,
                        requests: 6,
                        ..Default::default()
                    },
                    used: Quota {
                        steps: 1,
                        requests: 1,
                        ..Default::default()
                    },
                }),
                wave2_added: vec!["TC-001-F1".into()],
                stopped: Some("<script>alert(1)</script> stopped".into()),
                ..Default::default()
            },
        ],
        wave2: vec![WaveTwoCase {
            case_id: "TC-001-F1".into(),
            area: "contract".into(),
            rule: RULE_AUTH_TO_CONTRACT.into(),
            origin: "TC-001".into(),
            reason: "GET /<img src=x onerror=alert(1)> failed an access-control check".into(),
        }],
        ..Default::default()
    };
    let mut fail = result("TC-001", "authz", "FAIL");
    fail.failure_reason = Some("expected 401".into());
    let mut d = TriagedDefect::default();
    d.id = "DEF-001".into();
    d.case_ids = vec!["TC-001".into()];
    recount(
        &mut a,
        &[
            fail,
            result("TC-003", "boundary", "PASS"),
            result("TC-001-F1", "boundary", "PASS"),
        ],
        &[d],
    );
    let auth = &a.areas[0];
    assert_eq!(
        (auth.executed, auth.fail, auth.defect_ids.clone()),
        (1, 1, vec!["DEF-001".to_string()])
    );
    let contract = &a.areas[1];
    assert_eq!(
        (contract.executed, contract.pass),
        (2, 2),
        "a follow-up counts for its area"
    );
    rep.agents = Some(a);
    let md = crate::agent::generate_agent_markdown_report(&rep);
    assert!(
        md.contains("## Agents") && md.contains("**4** worker(s) over **2** wave(s)"),
        "{md}"
    );
    assert!(
        md.contains(
            "| `auth` | done | 14 | 1 | 0 | 1 | 0 | 14/14 | 20/64 | 2.5s/90.0s | 0/2 | DEF-001 |"
        ),
        "{md}"
    );
    assert!(
        md.contains("1/1 + w2 1/6") || md.contains("32/116 + w2 1/6"),
        "{md}"
    );
    assert!(
        md.contains("### Wave 2 additions")
            && md.contains("`TC-001-F1`")
            && md.contains(RULE_AUTH_TO_CONTRACT)
    );
    assert!(
        !md.contains("<script>") && !md.contains("<img"),
        "markdown text is escaped"
    );
    let html = crate::agent::generate_agent_html_report(&rep);
    assert!(html.contains("<h2>Agents</h2>") && html.contains("<h3>Wave 2 additions</h3>"));
    assert!(
        html.contains("<code>auth</code>") && html.contains("20/64"),
        "{html}"
    );
    assert!(
        !html.contains("<script>alert(1)</script>") && !html.contains("<img src=x"),
        "html text is escaped"
    );
    // the JSON report carries the same data, and a report without it still loads
    let json = serde_json::to_string(&rep).unwrap();
    let back: crate::agent::AgentRunReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.agents, rep.agents);
    let mut old = serde_json::to_value(&rep).unwrap();
    old.as_object_mut().unwrap().remove("agents");
    let old: crate::agent::AgentRunReport = serde_json::from_value(old).unwrap();
    assert!(old.agents.is_none());
    assert!(!crate::agent::generate_agent_markdown_report(&old).contains("## Agents"));
}
