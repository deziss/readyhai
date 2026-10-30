//! API QA logic against an in-process fixture server (`testsrv`, a port of
//! tests/fixtures/qa-api/server.py): functional (coverage, budget, flaky re-run, crash, leak),
//! auth matrix, stateful lifecycle, spec baselines.
use super::testsrv::*;
use super::*;
use crate::model::{Run, Target, TargetKind, Verdict};
use crate::qa::roles::Roles;
use serde_json::json;
use std::sync::Once;
use std::sync::atomic::AtomicUsize;

const FIXTURE_SPEC: &str = include_str!("../../../tests/fixtures/qa-api/openapi.json");
const FIXTURE_ROLES: &str = include_str!("../../../tests/fixtures/qa-api/roles.toml");
static SEQ: AtomicUsize = AtomicUsize::new(1);

fn init_env() {
    static O: Once = Once::new();
    // FAKE fixture tokens, identical in every test, so concurrent set_var calls are harmless.
    O.call_once(|| unsafe {
        std::env::set_var("RH_ALICE_TOKEN", "alice-token");
        std::env::set_var("RH_BOB_TOKEN", "bob-token");
        std::env::set_var("RH_ADMIN_TOKEN", "admin-token");
        std::env::set_var("RH_MALLORY_TOKEN", "wrong-token");
        std::env::remove_var("RH_GHOST_TOKEN");
    });
}

struct Env {
    ctx: Ctx,
    data: PathBuf,
    /// Scratch dir of this env (spec file, run dir); removed on drop.
    dir: PathBuf,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Env {
    fn qa(&self) -> &QaCtx {
        self.ctx.qa.as_ref().unwrap()
    }
    fn defects(&self) -> Vec<Defect> {
        self.qa().with(|c| c.defects.clone())
    }
    fn results(&self) -> Vec<TestResult> {
        self.qa().with(|c| c.results.clone())
    }
    fn cases(&self) -> Vec<TestCase> {
        self.qa().with(|c| c.cases.clone())
    }
    fn rules(&self) -> Vec<String> {
        self.defects().into_iter().map(|d| d.rule).collect()
    }
    fn cell(&self, row: &str, col: &str) -> Option<Cell> {
        self.qa().with(|c| {
            let (r, k) = (
                c.coverage.rows.iter().position(|x| x == row)?,
                c.coverage.columns.iter().position(|x| x == col)?,
            );
            c.coverage
                .cells
                .iter()
                .find(|x| x.0 == r && x.1 == k)
                .map(|x| x.2)
        })
    }
    fn notes(&self) -> Vec<String> {
        self.qa().with(|c| c.notes.clone())
    }
}

fn mk_env(base: &str, spec: &str, roles: &str, nonprod: bool, profile: Profile) -> Env {
    init_env();
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("rh-apitest-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let spec_path = dir.join("spec.json");
    std::fs::write(&spec_path, spec).unwrap();
    let roles: Roles = toml::from_str(roles).unwrap();
    let mut qa = QaCtx::new(roles, Some(spec_path.display().to_string()), None, nonprod);
    qa.rps = 100_000.0;
    let ctx = Ctx {
        run_id: format!("apitest-{}-{n}", std::process::id()),
        target: Target {
            kind: TargetKind::Web,
            raw: base.into(),
            path: None,
            image: None,
            url: Some(base.into()),
            openapi: None,
            host: None,
            apk: None,
            device: None,
        },
        profile,
        run_dir: dir.join("run"),
        snapshot: None,
        facts: Default::default(),
        docker: crate::tools::Docker {
            available: false,
            mode: crate::tools::MountMode::Bind,
            cache_dir: dir.join("cache"),
        },
        cfg: Default::default(),
        error_lines: Default::default(),
        nonprod,
        qa: Some(qa),
    };
    Env {
        ctx,
        data: dir.join("data"),
        dir,
    }
}

fn fixture_env(srv: &Server, nonprod: bool, profile: Profile) -> Env {
    mk_env(&srv.base, FIXTURE_SPEC, FIXTURE_ROLES, nonprod, profile)
}

fn spec_of(paths: Value) -> String {
    json!({"openapi": "3.0.0", "servers": [{"url": "/"}], "paths": paths}).to_string()
}

fn run_stub(v: Verdict) -> Run {
    Run {
        id: "r".into(),
        version: "t".into(),
        target: Target {
            kind: TargetKind::Web,
            raw: "http://x.test".into(),
            path: None,
            image: None,
            url: Some("http://x.test".into()),
            openapi: None,
            host: None,
            apk: None,
            device: None,
        },
        profile: Profile::Quick,
        started: String::new(),
        finished: String::new(),
        verdict: v,
        reasons: vec![],
        categories: vec![],
        checks: vec![],
        findings: vec![],
        fixed: 0,
        notes: vec![],
        errors: vec![],
        qa: None,
    }
}

fn dead_base() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", l.local_addr().unwrap())
}

// ------------------------------------------------------------------ order + planning

#[test]
fn authz_runs_before_functional_and_ops_follow_plan_risk() {
    let ids: Vec<String> = checks().into_iter().map(|c| c.id).collect();
    assert_eq!(
        ids,
        ["qa.api.authz", "qa.api.functional", "qa.api.stateful"]
    );
    let (srv, _) = orders_server(Opts::default());
    let e = fixture_env(&srv, true, Profile::Quick);
    crate::qa::plan::run_in(&e.ctx, &e.data).unwrap();
    let spec = spec::load(&e.ctx).unwrap().unwrap();
    let order = plan_order(e.qa(), &spec);
    assert_eq!(order.len(), spec.ops.len());
    assert!(
        order.windows(2).all(|w| w[0].risk >= w[1].risk),
        "{:?}",
        order
            .iter()
            .map(|p| (p.op.key(), p.risk))
            .collect::<Vec<_>>()
    );
    // risk comes from the plan: the destructive / sensitive operations lead, plain reads trail
    assert!(order[0].op.is_write());
    assert!(order[0].risk > order.last().unwrap().risk);
    assert!(!order.last().unwrap().op.is_write());
    assert!(order.iter().all(|p| p.budget >= 1));
}

// ------------------------------------------------------------------ functional

#[test]
fn functional_finds_the_seeded_bugs_and_every_failure_has_a_defect() {
    let (srv, _) = orders_server(Opts::default());
    let e = fixture_env(&srv, true, Profile::Quick);
    let out = functional_in(&e.ctx, &e.data).unwrap();
    let rules = e.rules();
    for want in [
        "qa.api.server_error",
        "qa.api.error_leak",
        "qa.api.contract_violation",
    ] {
        assert!(
            rules.iter().any(|r| r == want),
            "missing {want} in {rules:?}"
        );
    }
    // findings are grouped under the CHECK id (JUnit / SARIF), not the rule
    assert!(
        !out.findings.is_empty() && out.findings.iter().all(|f| f.check == "qa.api.functional")
    );
    // no failed case without a defect
    let res = e.results();
    assert!(res.iter().any(|r| r.status == ResultStatus::Fail));
    assert!(
        res.iter()
            .filter(|r| r.status == ResultStatus::Fail)
            .all(|r| r.defect_id.is_some()),
        "{:?}",
        res.iter()
            .filter(|r| r.status == ResultStatus::Fail && r.defect_id.is_none())
            .map(|r| &r.case_id)
            .collect::<Vec<_>>()
    );
    // planned == results (every generated case got a result)
    assert_eq!(e.cases().len(), res.len());
    // created records were cleaned up
    assert!(srv.count("DELETE /orders/") >= 1);
}

#[test]
fn leak_is_only_reported_on_error_responses() {
    let (srv, _) = orders_server(Opts::default());
    let spec = spec_of(json!({
        "/page": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        "/leaky": {"get": {"security": [], "responses": {"200": {"description": "ok"}, "404": {"description": "nf"}}}}
    }));
    let e = mk_env(&srv.base, &spec, "", false, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    let leaks: Vec<String> = e
        .defects()
        .into_iter()
        .filter(|d| d.rule == "qa.api.error_leak")
        .map(|d| d.component)
        .collect();
    assert_eq!(
        leaks,
        vec!["GET /leaky".to_string()],
        "the 200 page (nav links, 'stack trace' prose, a Traceback phrase) is not a leak"
    );
    // the failing positive case on /leaky has a defect too (no silent failure)
    assert!(
        e.results()
            .iter()
            .filter(|r| r.status == ResultStatus::Fail)
            .all(|r| r.defect_id.is_some())
    );
}

#[test]
fn budget_exhaustion_counts_as_planned_untested_never_pass() {
    let (srv, _) = orders_server(Opts::default());
    let mut e = fixture_env(&srv, true, Profile::Quick);
    e.ctx.qa.as_mut().unwrap().max_requests = 12;
    functional_in(&e.ctx, &e.data).unwrap();
    let res = e.results();
    let skipped_budget = res
        .iter()
        .filter(|r| r.status == ResultStatus::Skipped && r.actual.contains("budget"))
        .count();
    assert!(
        skipped_budget > 5,
        "unrun cases are recorded as planned+skipped, got {skipped_budget}"
    );
    // untested note per unrun operation
    assert!(
        e.qa()
            .with(|c| c.untested.iter().any(|u| u.contains("budget")))
    );
    // cell "functional": Pass only when something passed; Untested for operations that never ran
    let cases = e.cases();
    let mut untested_ops = 0;
    let spec = spec::load(&e.ctx).unwrap().unwrap();
    for op in spec
        .ops
        .iter()
        .filter(|o| !matches!(o.method.as_str(), "HEAD" | "OPTIONS"))
    {
        let k = op.key();
        let ran = |st: ResultStatus| {
            res.iter()
                .filter(|r| {
                    r.status == st && cases.iter().any(|c| c.id == r.case_id && c.component == k)
                })
                .count()
        };
        match e.cell(&k, "functional") {
            Some(Cell::Pass) => assert!(
                ran(ResultStatus::Pass) > 0,
                "{k} marked Pass without a passing case"
            ),
            Some(Cell::Untested) => {
                untested_ops += 1;
                assert_eq!(ran(ResultStatus::Pass) + ran(ResultStatus::Fail), 0, "{k}");
            }
            Some(Cell::Fail) => {}
            other => panic!(
                "{k}: no functional cell ({other:?}); every operation must show up in the matrix"
            ),
        }
    }
    assert!(untested_ops >= 2);
    // the report must see them as planned-but-not-executed -> the 90% criterion is unmet
    let r = crate::qa::build_report(e.qa(), &run_stub(Verdict::Pass), "t");
    assert!(r.counts.planned > r.counts.executed);
    assert!(
        r.exit_criteria
            .iter()
            .any(|c| c.name.starts_with("≥90%") && !c.met)
    );
}

#[test]
fn functional_is_not_pass_when_every_case_was_blocked() {
    let (srv, _) = orders_server(Opts::default());
    // no roles: every /orders call is a 401, so nothing about validation or contract was verified
    let e = mk_env(&srv.base, FIXTURE_SPEC, "", true, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    assert_eq!(e.cell("GET /orders", "functional"), Some(Cell::Untested));
    assert_eq!(e.cell("POST /orders", "functional"), Some(Cell::Untested));
    assert_eq!(e.cell("GET /health", "functional"), Some(Cell::Pass));
    let cases = e.cases();
    let bad = e
        .results()
        .into_iter()
        .filter(|r| {
            r.status == ResultStatus::Pass
                && cases
                    .iter()
                    .any(|c| c.id == r.case_id && c.component == "GET /orders")
        })
        .count();
    assert_eq!(bad, 0, "a 401 is not a validation pass");
    assert!(
        e.results()
            .iter()
            .any(|r| r.status == ResultStatus::Blocked)
    );
}

#[test]
fn failed_cases_are_rerun_and_flaky_is_recorded() {
    let (srv, _) = orders_server(Opts::default());
    let spec = spec_of(json!({
        "/flaky": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        "/broken": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}}
    }));
    let e = mk_env(&srv.base, &spec, "", false, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    let res = e.results();
    let flaky = res
        .iter()
        .find(|r| r.case_id == "api.GET./flaky.positive")
        .unwrap();
    assert_eq!((flaky.status, flaky.attempts), (ResultStatus::Flaky, 3));
    let broken = res
        .iter()
        .find(|r| r.case_id == "api.GET./broken.positive")
        .unwrap();
    assert_eq!((broken.status, broken.attempts), (ResultStatus::Fail, 3));
    // re-runs are bounded: 1 attempt + MAX_RERUN
    assert_eq!(srv.count("GET /broken"), 1 + MAX_RERUN as usize);
    let defects = e.defects();
    let d_flaky = defects
        .iter()
        .find(|d| d.component == "GET /flaky")
        .unwrap();
    assert_eq!(d_flaky.reproduced, (1, 3), "failed once of three attempts");
    let d_broken = defects
        .iter()
        .find(|d| d.component == "GET /broken")
        .unwrap();
    assert_eq!(d_broken.reproduced, (3, 3));
    // counted as flaky in the report -> "No flaky tests" is unmet
    let r = crate::qa::build_report(e.qa(), &run_stub(Verdict::Pass), "t");
    assert_eq!(r.counts.flaky, 1);
    assert!(
        r.exit_criteria
            .iter()
            .any(|c| c.name == "No flaky tests" && !c.met)
    );
}

#[test]
fn writes_are_never_rerun() {
    let (srv, _) = orders_server(Opts::default());
    let e = fixture_env(&srv, true, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    // POST /orders with a 101-char note fails with a 500 once; it must not be repeated
    let posts_with_500 = e
        .results()
        .into_iter()
        .filter(|r| {
            r.case_id.starts_with("api.POST./orders.boundary.maxlen")
                && r.status == ResultStatus::Fail
        })
        .collect::<Vec<_>>();
    assert!(
        posts_with_500.iter().all(|r| r.attempts == 1),
        "{posts_with_500:?}"
    );
}

#[test]
fn malformed_input_that_kills_the_connection_is_a_possible_crash_not_blocked() {
    let (srv, _) = orders_server(Opts::default());
    let spec = spec_of(json!({
        "/items": {"post": {"security": [], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}}}}, "responses": {"201": {"description": "ok"}}}}
    }));
    let e = mk_env(&srv.base, &spec, "", true, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    let crash: Vec<Defect> = e
        .defects()
        .into_iter()
        .filter(|d| d.rule == "qa.api.crash_on_input")
        .collect();
    assert!(!crash.is_empty(), "{:?}", e.rules());
    assert!(
        crash
            .iter()
            .all(|d| d.severity == Severity::High && d.category == Category::Reliability),
        "server still answers afterwards"
    );
    let res = e.results();
    for r in res
        .iter()
        .filter(|r| r.case_id.contains("negative.wrongtype"))
    {
        assert_eq!(r.status, ResultStatus::Fail, "{r:?}");
        assert!(r.defect_id.is_some());
    }
}

#[test]
fn an_unreachable_target_is_blocked_not_a_crash() {
    let spec = spec_of(json!({
        "/items": {"post": {"security": [], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}}}}, "responses": {"201": {"description": "ok"}}}},
        "/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}}
    }));
    let e = mk_env(&dead_base(), &spec, "", true, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    assert!(
        !e.rules().iter().any(|r| r == "qa.api.crash_on_input"),
        "{:?}",
        e.rules()
    );
    let res = e.results();
    assert!(
        !res.is_empty() && res.iter().all(|r| r.status == ResultStatus::Blocked),
        "{res:?}"
    );
    assert_eq!(e.cell("GET /health", "functional"), Some(Cell::Untested));
}

#[test]
fn cleanup_runs_even_when_the_baseline_step_fails() {
    let (srv, _) = orders_server(Opts::default());
    let e = fixture_env(&srv, true, Profile::Quick);
    // the data dir is a FILE: creating <data>/baselines fails
    let bad = e.data.with_extension("file");
    std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
    std::fs::write(&bad, "x").unwrap();
    let out = functional_in(&e.ctx, &bad).unwrap();
    assert!(
        !out.findings.is_empty(),
        "the check must still return its findings"
    );
    assert!(
        srv.count("DELETE /orders/") >= 1,
        "cleanup deleted the created records first"
    );
    assert!(
        e.notes()
            .iter()
            .any(|n| n.contains("spec baseline comparison skipped")),
        "{:?}",
        e.notes()
    );
    assert!(!e.notes().iter().any(|n| n.contains("could not be deleted")));
}

#[test]
fn spec_baseline_is_staged_and_promoted_on_accept() {
    let (srv, _) = orders_server(Opts::default());
    let v1 = spec_of(json!({
        "/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        "/search": {"get": {"security": [], "parameters": [{"name": "q", "in": "query", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}, "400": {"description": "bad"}, "500": {"description": "x"}}}}
    }));
    let v2 = spec_of(
        json!({"/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}}}),
    );
    let key = |e: &Env| crate::engine::target_key(&e.ctx.target);
    let e1 = mk_env(&srv.base, &v1, "", false, Profile::Quick);
    functional_in(&e1.ctx, &e1.data).unwrap();
    assert!(
        !e1.rules().iter().any(|r| r == "qa.api.breaking_change"),
        "first run only seeds"
    );
    assert!(stage_dir(&e1.ctx.run_dir).join("spec-full.json").is_file());
    // second run: /search disappeared -> breaking change against the seeded baseline
    let mut e2 = mk_env(&srv.base, &v2, "", false, Profile::Quick);
    e2.data = e1.data.clone();
    functional_in(&e2.ctx, &e2.data).unwrap();
    assert!(
        e2.defects()
            .iter()
            .any(|d| d.rule == "qa.api.breaking_change" && d.title.contains("operation removed")),
        "{:?}",
        e2.rules()
    );
    // accept the second run: the baseline moves, the next run is clean
    let done = accept_spec_baseline_in(&e2.data, &key(&e2), &e2.ctx.run_dir).unwrap();
    assert!(done.contains(&"spec snapshot"));
    let mut e3 = mk_env(&srv.base, &v2, "", false, Profile::Quick);
    e3.data = e1.data.clone();
    functional_in(&e3.ctx, &e3.data).unwrap();
    assert!(!e3.rules().iter().any(|r| r == "qa.api.breaking_change"));
    // a run that never loaded a spec has nothing to promote
    assert!(accept_spec_baseline_in(&e2.data, &key(&e2), &e2.data.join("none")).is_err());
}

// ------------------------------------------------------------------ exec

#[test]
fn large_json_is_parsed_from_the_full_body_and_only_the_stored_copy_is_cut() {
    let (srv, _) = orders_server(Opts::default());
    let qa = QaCtx::new(Roles::default(), None, None, false);
    let ex = exec::send(&qa, None, "GET", &format!("{}/big", srv.base), None, &[]).unwrap();
    assert_eq!(ex.status, 200);
    assert!(
        ex.body.len() <= exec::MAX_BODY && ex.body_len > 100_000,
        "{} / {}",
        ex.body.len(),
        ex.body_len
    );
    let j = ex.json().expect("a 200 KB JSON body must still parse");
    assert_eq!(j.as_array().unwrap().len(), 4000);
    // beyond the 1 MiB read cap the body is not parsed (and never silently half-parsed)
    let huge = exec::send(
        &qa,
        None,
        "GET",
        &format!("{}/big?n=40000", srv.base),
        None,
        &[],
    )
    .unwrap();
    assert!(huge.body_len > exec::MAX_PARSE);
    assert!(huge.json().is_none());
    assert!(huge.body.len() <= exec::MAX_BODY);
    // the helper used by unit tests follows the same rules
    let small = exec::Exchange::default().with_body(br#"{"a":1}"#);
    assert_eq!(small.json().unwrap()["a"], 1);
}

#[test]
fn contract_validation_sees_fields_beyond_the_first_8kb() {
    // `total` is serialised AFTER 400 padding items, i.e. beyond the 8 KB stored copy
    let items: Vec<Value> = (0..400)
        .map(|i| json!({"id": i, "name": "padding-padding-padding-padding-padding"}))
        .collect();
    let body = json!({"items": items, "total": "not-an-int"});
    let srv = serve(move |_| Resp::json(200, body.clone()));
    let spec = spec_of(
        json!({"/things": {"get": {"security": [], "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object", "required": ["total"], "properties": {"total": {"type": "integer"}}}}}}}}}}),
    );
    let e = mk_env(&srv.base, &spec, "", false, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    assert!(
        e.rules().iter().any(|r| r == "qa.api.contract_violation"),
        "{:?}",
        e.rules()
    );
}

// ------------------------------------------------------------------ auth matrix

#[test]
fn authz_matrix_finds_missing_auth_and_escalation_and_counts_distinct_roles() {
    let (srv, _) = orders_server(Opts::default());
    let roles = format!(
        "{FIXTURE_ROLES}\n[[role]]\nname = \"ghost\"\nauth = \"bearer\"\ntoken_env = \"RH_GHOST_TOKEN\"\nallow = [\"/**\"]\n"
    );
    let e = mk_env(&srv.base, FIXTURE_SPEC, &roles, true, Profile::Quick);
    let out = authz::run(&e.ctx).unwrap();
    let rules = e.rules();
    assert!(
        rules.iter().any(|r| r == "qa.api.authz_missing"),
        "{rules:?}"
    ); // GET /admin/stats needs no token
    assert!(
        rules.iter().any(|r| r == "qa.api.privilege_escalation"),
        "{rules:?}"
    ); // alice/bob reach /admin/stats
    assert!(out.findings.iter().all(|f| f.check == "qa.api.authz"));
    assert!(e.notes().iter().any(|n| n.contains("role 'ghost' skipped")));
    // anonymous / invalid cases carry no role; ghost never got a case
    let cases = e.cases();
    assert!(
        cases
            .iter()
            .any(|c| c.role.is_none() && c.technique == Technique::AuthMatrix)
    );
    assert!(!cases.iter().any(|c| c.role.as_deref() == Some("ghost")));
    // every failed case is explained
    assert!(
        e.results()
            .iter()
            .filter(|r| r.status == ResultStatus::Fail)
            .all(|r| r.defect_id.is_some())
    );
    // the report counts exactly the three roles that ran cases
    let r = crate::qa::build_report(e.qa(), &run_stub(Verdict::Pass), "t");
    let c = r
        .exit_criteria
        .iter()
        .find(|c| c.name.starts_with("Authorization tested"))
        .unwrap();
    assert!(c.met, "{c:?}");
    assert!(c.detail.starts_with("3 distinct role(s)"), "{}", c.detail);
    assert!(
        c.detail.contains("alice")
            && c.detail.contains("bob")
            && c.detail.contains("admin")
            && !c.detail.contains("ghost")
    );
}

#[test]
fn authz_allowed_role_that_is_denied_raises_a_defect() {
    let (srv, _) = orders_server(Opts::default());
    let roles = "[[role]]\nname = \"mallory\"\nauth = \"bearer\"\ntoken_env = \"RH_MALLORY_TOKEN\"\nallow = [\"/**\"]\n";
    let e = mk_env(&srv.base, FIXTURE_SPEC, roles, false, Profile::Quick);
    authz::run(&e.ctx).unwrap();
    let denied: Vec<Defect> = e
        .defects()
        .into_iter()
        .filter(|d| d.rule == "qa.api.access_denied")
        .collect();
    assert!(!denied.is_empty(), "{:?}", e.rules());
    let res = e.results();
    let failed: Vec<&TestResult> = res
        .iter()
        .filter(|r| r.status == ResultStatus::Fail)
        .collect();
    assert!(
        !failed.is_empty() && failed.iter().all(|r| r.defect_id.is_some()),
        "a failed authz case must never be defect-less"
    );
    // one role executed cases -> the 2-role criterion is unmet
    let r = crate::qa::build_report(e.qa(), &run_stub(Verdict::Pass), "t");
    assert!(
        r.exit_criteria
            .iter()
            .any(|c| c.name.starts_with("Authorization tested") && !c.met)
    );
}

#[test]
fn authz_transport_failures_are_blocked_never_pass() {
    let e = mk_env(
        &dead_base(),
        FIXTURE_SPEC,
        FIXTURE_ROLES,
        false,
        Profile::Quick,
    );
    authz::run(&e.ctx).unwrap();
    let res = e.results();
    assert!(!res.is_empty());
    assert!(
        res.iter()
            .all(|r| r.status == ResultStatus::Blocked || r.status == ResultStatus::Skipped),
        "{:?}",
        res.iter()
            .filter(|r| r.status == ResultStatus::Pass)
            .count()
    );
    assert_eq!(e.cell("GET /admin/stats", "anon"), Some(Cell::Untested));
}

#[test]
fn authz_budget_exhaustion_plans_and_skips_the_rest() {
    let (srv, _) = orders_server(Opts::default());
    let mut e = fixture_env(&srv, false, Profile::Quick);
    e.ctx.qa.as_mut().unwrap().max_requests = 15;
    authz::run(&e.ctx).unwrap();
    let res = e.results();
    assert!(
        res.iter().any(|r| r.status == ResultStatus::Skipped),
        "budget must have run out"
    );
    // skipped cases are still planned cases, and their cells are Untested
    assert_eq!(e.cases().len(), res.len());
    assert!(
        e.qa()
            .with(|c| c.coverage.cells.iter().any(|x| x.2 == Cell::Untested))
    );
    assert!(
        e.qa()
            .with(|c| c.untested.iter().any(|u| u.contains("auth matrix")))
    );
}

// ------------------------------------------------------------------ stateful

#[test]
fn stateful_handles_data_envelopes_and_finds_bola_and_noop_delete() {
    let (srv, _) = orders_server(Opts {
        envelope: true,
        ..Default::default()
    });
    let e = fixture_env(&srv, true, Profile::Standard);
    let out = stateful::run(&e.ctx).unwrap();
    let rules = e.rules();
    // {data:{...}} wrappers: a persisting server must NOT be reported as losing updates
    assert!(
        !rules.iter().any(|r| r == "qa.api.persistence_failure"),
        "false positive on a {{data:{{}}}} envelope: {:?}",
        e.defects()
            .iter()
            .map(|d| (&d.rule, &d.title))
            .collect::<Vec<_>>()
    );
    assert!(rules.iter().any(|r| r == "qa.api.bola"), "{rules:?}");
    assert!(
        rules.iter().any(|r| r == "qa.api.delete_not_effective"),
        "{rules:?}"
    );
    assert!(out.findings.iter().all(|f| f.check == "qa.api.stateful"));
    let bola = e
        .defects()
        .into_iter()
        .find(|d| d.rule == "qa.api.bola")
        .unwrap();
    assert_eq!(bola.severity, Severity::Critical);
    assert!(
        e.results()
            .iter()
            .filter(|r| r.status == ResultStatus::Fail)
            .all(|r| r.defect_id.is_some())
    );
}

#[test]
fn stateful_detects_updates_that_are_not_persisted_even_inside_an_envelope() {
    for envelope in [false, true] {
        let (srv, _) = orders_server(Opts {
            envelope,
            no_persist: true,
            ..Default::default()
        });
        let e = fixture_env(&srv, true, Profile::Standard);
        stateful::run(&e.ctx).unwrap();
        assert!(
            e.rules().iter().any(|r| r == "qa.api.persistence_failure"),
            "envelope={envelope}: {:?}",
            e.rules()
        );
    }
}

#[test]
fn stateful_failed_steps_always_get_a_defect() {
    let (srv, _) = orders_server(Opts {
        put_rejects: true,
        ..Default::default()
    });
    let e = fixture_env(&srv, true, Profile::Standard);
    stateful::run(&e.ctx).unwrap();
    let res = e.results();
    let update = res
        .iter()
        .find(|r| r.case_id.contains(".state.update"))
        .expect("update step ran");
    assert_eq!(update.status, ResultStatus::Fail);
    assert!(
        update.defect_id.is_some(),
        "a rejected valid update must not be a silent failure"
    );
    assert!(
        e.rules().iter().any(|r| r == "qa.api.case_failed"),
        "{:?}",
        e.rules()
    );
    assert!(
        res.iter()
            .filter(|r| r.status == ResultStatus::Fail)
            .all(|r| r.defect_id.is_some())
    );
    // the safety-net defect carries the case's own steps
    let d = e
        .defects()
        .into_iter()
        .find(|d| d.rule == "qa.api.case_failed")
        .unwrap();
    assert!(d.steps_to_reproduce.iter().any(|s| s.starts_with("curl")));
}

#[test]
fn stateful_create_without_an_id_is_blocked_not_failed() {
    let (srv, _) = orders_server(Opts {
        no_id: true,
        ..Default::default()
    });
    let e = fixture_env(&srv, true, Profile::Standard);
    stateful::run(&e.ctx).unwrap();
    let res = e.results();
    let create = res
        .iter()
        .find(|r| r.case_id.contains(".state.create"))
        .unwrap();
    assert_eq!(create.status, ResultStatus::Blocked, "{create:?}");
    assert!(!res.iter().any(|r| r.status == ResultStatus::Fail));
    assert_eq!(e.cell("POST /orders", "stateful"), Some(Cell::Untested));
}

#[test]
fn stateful_is_skipped_on_hosts_that_are_not_nonprod() {
    let (srv, _) = orders_server(Opts::default());
    let e = fixture_env(&srv, false, Profile::Standard);
    let out = stateful::run(&e.ctx).unwrap();
    assert!(matches!(out.status, Some(CheckStatus::Skipped(_))));
    assert!(
        srv.requests().iter().all(|l| l.starts_with("GET ")),
        "{:?}",
        srv.requests()
    );
}

#[test]
fn envelope_helpers() {
    let j = json!({"data": {"id": 7, "attributes": {"name": "n"}}});
    assert_eq!(field(&j, "id").unwrap(), 7);
    assert_eq!(field(&j, "name").unwrap(), "n");
    assert!(field(&j, "missing").is_none());
    assert_eq!(
        field(&json!({"id": 1, "data": {"id": 2}}), "id").unwrap(),
        1,
        "top level wins"
    );
    assert_eq!(list_items(&json!({"data": {"items": [1, 2]}})).len(), 2);
    assert_eq!(list_items(&json!({"results": [1]})).len(), 1);
    let ex = exec::Exchange::default().with_body(br#"{"data":{"id":"abc"}}"#);
    assert_eq!(created_id(&ex).as_deref(), Some("abc"));
}
