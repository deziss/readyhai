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

// ------------------------------------------------------------------ write safety, evidence status, BOLA, cleanup

/// Spec = the fixture with `f` applied to its JSON.
fn fixture_spec_with(f: impl FnOnce(&mut Value)) -> String {
    let mut v: Value = serde_json::from_str(FIXTURE_SPEC).unwrap();
    f(&mut v);
    v.to_string()
}

/// alice (valid) + mallory (the server answers 401 to her token).
fn roles_alice_mallory() -> String {
    let alice = FIXTURE_ROLES.split("[[role]]").nth(1).unwrap();
    format!(
        "[[role]]{alice}\n[[role]]\nname = \"mallory\"\nauth = \"bearer\"\ntoken_env = \"RH_MALLORY_TOKEN\"\nallow = [\"/**\"]\n"
    )
}

fn alice_only() -> String {
    format!(
        "[[role]]{}",
        FIXTURE_ROLES.split("[[role]]").nth(1).unwrap()
    )
}

/// The orders fixture with its "DELETE does nothing" bug fixed: a deleted order is gone.
fn orders_server_clean() -> Server {
    let o = Orders::new(Opts::default());
    let gone: Mutex<Vec<String>> = Mutex::new(vec![]);
    serve(move |r| {
        if r.user().is_some() && r.path.starts_with("/orders/") {
            if r.method == "DELETE" {
                gone.lock().unwrap().push(r.path.clone());
                return Resp::empty(204);
            }
            if gone.lock().unwrap().contains(&r.path) {
                return Resp::json(404, json!({"error": "not found"}));
            }
        }
        o.handle(r)
    })
}

#[test]
fn unlikely_ids_cover_every_path_param_and_never_default_to_one() {
    let op = |params: Vec<spec::Param>| Op {
        method: "PUT".into(),
        path: "/a/{aid}/b/{bid}".into(),
        params,
        body: None,
        body_required: false,
        responses: Default::default(),
        secured: true,
    };
    let p = |name: &str, schema: Value| spec::Param {
        name: name.into(),
        loc: "path".into(),
        required: true,
        schema,
    };
    let ids = unlikely_ids(&op(vec![
        p("aid", json!({"type": "integer"})),
        p("bid", json!({"type": "string", "format": "uuid"})),
    ]));
    assert_eq!(ids["aid"], UNLIKELY_ID);
    assert_eq!(ids["bid"], "00000000-0000-4000-8000-000000999999");
    // an enum cannot be invented: its first member
    let ids = unlikely_ids(&op(vec![p("aid", json!({"enum": ["users", "teams"]}))]));
    assert_eq!(ids["aid"], "users");
    assert!(ids.values().all(|v| v != "1"));
}

#[test]
fn functional_writes_never_touch_harvested_ids() {
    let (srv, _) = orders_server(Opts::default());
    let e = fixture_env(&srv, true, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    let reqs = srv.requests();
    // the seeded (real) orders are 1..=3; this run's own creations get 4 and up
    let id_of = |l: &str| -> Option<u64> { l.rsplit('/').next().and_then(|x| x.parse().ok()) };
    let mut put_ids = vec![];
    for l in &reqs {
        let (m, p) = l.split_once(' ').unwrap();
        if !p.starts_with("/orders/") {
            continue;
        }
        match m {
            "PUT" | "PATCH" | "DELETE" => {
                let id = id_of(p).unwrap_or(0);
                assert!(
                    id == 999_999 || id >= 4,
                    "a write reached the real record {p}: {reqs:?}"
                );
                if m == "PUT" {
                    put_ids.push(id);
                }
            }
            _ => {}
        }
    }
    assert!(!put_ids.is_empty(), "PUT cases must still run: {reqs:?}");
    // PUT cases ran against a resource this run created (validation is reachable)
    assert!(put_ids.iter().any(|i| *i >= 4), "{put_ids:?}");
    // reads still use the real, harvested ids
    assert!(srv.count("GET /orders/1") >= 1, "{reqs:?}");
    // ...and every created record was cleaned up
    assert!(srv.count("DELETE /orders/") >= 1);
}

#[test]
fn write_cases_without_a_scratch_resource_use_the_unlikely_id_and_a_404_is_blocked() {
    let (srv, _) = orders_server(Opts::default());
    // no POST for the collection: nothing this run could create -> the unlikely id
    let spec = fixture_spec_with(|v| {
        v["paths"]["/orders"]
            .as_object_mut()
            .unwrap()
            .remove("post");
    });
    let e = mk_env(&srv.base, &spec, FIXTURE_ROLES, true, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    for l in srv.requests() {
        let (m, p) = l.split_once(' ').unwrap();
        if matches!(m, "PUT" | "PATCH" | "DELETE") {
            assert_eq!(p, "/orders/999999", "{l}");
        }
    }
    let res = e.results();
    let put: Vec<&TestResult> = res
        .iter()
        .filter(|r| r.case_id.starts_with("api.PUT./orders/{id}."))
        .collect();
    assert!(!put.is_empty());
    assert!(
        put.iter().all(|r| r.status == ResultStatus::Blocked
            && r.actual.contains("no valid resource id")),
        "a 404 for the unknown id proves nothing: {put:?}"
    );
}

#[test]
fn functional_status_follows_the_evidence() {
    let (srv, _) = orders_server(Opts::default());
    // target down: nothing executed -> Errored
    let e = mk_env(
        &dead_base(),
        FIXTURE_SPEC,
        FIXTURE_ROLES,
        true,
        Profile::Quick,
    );
    let out = functional_in(&e.ctx, &e.data).unwrap();
    assert!(
        matches!(&out.status, Some(CheckStatus::Errored(r)) if r.contains("no case executed")),
        "{:?}",
        out.status
    );
    // no credentials: /health passes, every secured call is a 401 -> mostly blocked -> Partial
    let e = mk_env(&srv.base, FIXTURE_SPEC, "", true, Profile::Quick);
    let out = functional_in(&e.ctx, &e.data).unwrap();
    assert!(
        matches!(&out.status, Some(CheckStatus::Partial(r)) if r.contains("blocked")),
        "{:?}",
        out.status
    );
    // a healthy run keeps the findings-derived status (None = Passed / Failed by findings)
    let e = fixture_env(&srv, true, Profile::Quick);
    let out = functional_in(&e.ctx, &e.data).unwrap();
    assert!(out.status.is_none(), "{:?}", out.status);
    assert!(!out.findings.is_empty());
}

#[test]
fn a_read_only_host_with_only_write_operations_is_skipped_not_errored() {
    let (srv, _) = orders_server(Opts::default());
    let spec = spec_of(json!({
        "/items": {"post": {"security": [], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}}}}, "responses": {"201": {"description": "ok"}}}}
    }));
    let e = mk_env(&srv.base, &spec, "", false, Profile::Quick);
    let out = functional_in(&e.ctx, &e.data).unwrap();
    assert!(
        matches!(&out.status, Some(CheckStatus::Skipped(r)) if r.contains("read-only")),
        "{:?}",
        out.status
    );
    assert!(srv.requests().iter().all(|l| l.starts_with("GET ")));
}

#[test]
fn authz_status_follows_the_evidence() {
    let e = mk_env(
        &dead_base(),
        FIXTURE_SPEC,
        FIXTURE_ROLES,
        false,
        Profile::Quick,
    );
    let out = authz::run(&e.ctx).unwrap();
    assert!(
        matches!(&out.status, Some(CheckStatus::Errored(_))),
        "{:?}",
        out.status
    );
    let (srv, _) = orders_server(Opts::default());
    let e = fixture_env(&srv, true, Profile::Quick);
    let out = authz::run(&e.ctx).unwrap();
    assert!(out.status.is_none(), "{:?}", out.status);
}

#[test]
fn authz_anon_404_on_a_synthetic_id_is_blocked_not_pass() {
    // a server that answers 404 to everything: it never reaches an authentication decision
    let srv = serve(|_| Resp::json(404, json!({"error": "no such thing"})));
    let spec = spec_of(json!({
        "/things/{id}": {
            "get": {"security": [{"bearerAuth": []}], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}], "responses": {"200": {"description": "ok"}}},
            "delete": {"security": [{"bearerAuth": []}], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}], "responses": {"204": {"description": "ok"}}}
        }
    }));
    let e = mk_env(&srv.base, &spec, "", true, Profile::Quick);
    let out = authz::run(&e.ctx).unwrap();
    let res = e.results();
    assert!(!res.is_empty());
    assert!(
        res.iter().all(|r| r.status == ResultStatus::Blocked),
        "a 404 for a made-up id cannot prove protection: {res:?}"
    );
    assert_eq!(e.cell("GET /things/{id}", "anon"), Some(Cell::Untested));
    assert_eq!(
        e.cell("DELETE /things/{id}", "invalid"),
        Some(Cell::Untested)
    );
    assert!(e.defects().is_empty());
    assert!(
        matches!(&out.status, Some(CheckStatus::Errored(_))),
        "{:?}",
        out.status
    );
    // the write used the unlikely id, never a real one
    assert!(srv.requests().iter().any(|l| l == "DELETE /things/999999"));
}

#[test]
fn bola_role_b_401_is_blocked_and_is_not_a_tested_role() {
    let srv = orders_server_clean();
    let e = mk_env(
        &srv.base,
        FIXTURE_SPEC,
        &roles_alice_mallory(),
        true,
        Profile::Standard,
    );
    stateful::run(&e.ctx).unwrap();
    let res = e.results();
    let bola: Vec<&TestResult> = res
        .iter()
        .filter(|r| r.case_id.contains(".state.bola.mallory"))
        .collect();
    assert!(!bola.is_empty(), "{res:?}");
    assert!(
        bola.iter()
            .all(|r| r.status == ResultStatus::Blocked && r.actual.contains("401")),
        "{bola:?}"
    );
    assert!(!e.rules().iter().any(|r| r == "qa.api.bola"));
    // the lifecycle is not proven: coverage is Untested and the skipped steps are noted
    assert_eq!(e.cell("POST /orders", "stateful"), Some(Cell::Untested));
    assert!(
        e.notes()
            .iter()
            .any(|n| n.contains("lifecycle step(s) skipped") && n.contains("BOLA")),
        "{:?}",
        e.notes()
    );
    // mallory did not test authorization: she is not counted toward ">= 2 roles"
    let r = crate::qa::build_report(e.qa(), &run_stub(Verdict::Pass), "t");
    let c = r
        .exit_criteria
        .iter()
        .find(|c| c.name.starts_with("Authorization tested"))
        .unwrap();
    assert!(!c.met && !c.detail.contains("mallory"), "{c:?}");
}

#[test]
fn bola_is_skipped_for_a_get_that_is_public_in_the_spec() {
    let (srv, _) = orders_server(Opts {
        envelope: true,
        ..Default::default()
    });
    let spec = fixture_spec_with(|v| {
        v["paths"]["/orders/{id}"]["get"]["security"] = json!([]);
    });
    let e = mk_env(&srv.base, &spec, FIXTURE_ROLES, true, Profile::Standard);
    stateful::run(&e.ctx).unwrap();
    // the fixture's BOLA hole is on GET; a public GET is not a BOLA, so no defect and no GET case
    assert!(
        !e.rules().iter().any(|r| r == "qa.api.bola"),
        "{:?}",
        e.rules()
    );
    assert!(
        !e.cases()
            .iter()
            .any(|c| c.id.starts_with("api.GET./orders/{id}.state.bola"))
    );
    assert!(
        e.notes()
            .iter()
            .any(|n| n.contains("BOLA skipped for GET /orders/{id}") && n.contains("public")),
        "{:?}",
        e.notes()
    );
    // the (secured) PUT is still tested
    assert!(
        e.cases()
            .iter()
            .any(|c| c.id.starts_with("api.PUT./orders/{id}.state.bola"))
    );
}

#[test]
fn bola_is_skipped_for_a_get_an_anonymous_caller_can_read() {
    let o = Orders::new(Opts::default());
    // anonymous GET /orders/<id> is answered as admin: public by behaviour
    let srv = serve(move |r| {
        if r.method == "GET" && r.path.starts_with("/orders/") && r.user().is_none() {
            let mut headers = r.headers.clone();
            headers.insert("authorization".into(), "Bearer admin-token".into());
            return o.handle(&HReq {
                method: r.method.clone(),
                path: r.path.clone(),
                query: r.query.clone(),
                headers,
                body: r.body.clone(),
            });
        }
        o.handle(r)
    });
    let e = mk_env(
        &srv.base,
        FIXTURE_SPEC,
        FIXTURE_ROLES,
        true,
        Profile::Standard,
    );
    stateful::run(&e.ctx).unwrap();
    assert!(
        !e.rules().iter().any(|r| r == "qa.api.bola"),
        "{:?}",
        e.rules()
    );
    assert!(
        e.notes()
            .iter()
            .any(|n| n.contains("BOLA skipped for GET /orders/{id}") && n.contains("anonymous")),
        "{:?}",
        e.notes()
    );
}

#[test]
fn stateful_coverage_is_not_pass_when_steps_were_skipped() {
    let (srv, _) = orders_server(Opts::default());
    // one role only: BOLA cannot run (on a server whose DELETE works, so nothing else fails)
    let clean = orders_server_clean();
    let e = mk_env(
        &clean.base,
        FIXTURE_SPEC,
        &alice_only(),
        true,
        Profile::Standard,
    );
    stateful::run(&e.ctx).unwrap();
    assert_eq!(e.cell("POST /orders", "stateful"), Some(Cell::Untested));
    assert!(
        e.notes()
            .iter()
            .any(|n| n.contains("POST /orders") && n.contains("BOLA")),
        "{:?}",
        e.notes()
    );
    // with two real roles the same lifecycle runs fully (BOLA found by the fixture bug -> Fail)
    let e = fixture_env(&srv, true, Profile::Standard);
    stateful::run(&e.ctx).unwrap();
    assert_eq!(e.cell("POST /orders", "stateful"), Some(Cell::Fail));
}

#[test]
fn mutate_skips_body_keys_the_put_schema_does_not_declare() {
    let put = Op {
        method: "PUT".into(),
        path: "/orders/{id}".into(),
        params: vec![],
        body: Some(json!({"type": "object", "properties": {"item": {"type": "string"}}})),
        body_required: true,
        responses: Default::default(),
        secured: true,
    };
    // "extra" sorts before "item": it used to abort the whole mutation
    let body = json!({"extra": 7, "item": "keyboard"});
    let (nb, field, newv) = stateful::mutate(&body, &put).expect("the declared key is mutated");
    assert_eq!(field, "item");
    assert_eq!(newv, "keyboard-upd");
    assert_eq!(nb["extra"], 7);
    // nothing mutable at all: still None
    assert!(stateful::mutate(&json!({"extra": 7}), &put).is_none());
}

#[test]
fn stateful_cleanup_is_registered_at_create_even_if_the_lifecycle_never_deletes() {
    let (srv, _) = orders_server(Opts::default());
    let mut e = fixture_env(&srv, true, Profile::Standard);
    // the budget runs out right after create/read/update: the lifecycle DELETE is never sent
    e.ctx.qa.as_mut().unwrap().max_requests = 3;
    stateful::run(&e.ctx).unwrap();
    assert!(
        e.results()
            .iter()
            .any(|r| r.status == ResultStatus::Skipped && r.actual.contains("budget")),
        "{:?}",
        e.results()
    );
    assert_eq!(srv.count("DELETE /orders/4"), 1, "{:?}", srv.requests());
    assert!(
        !e.notes().iter().any(|n| n.contains("LEAKED")),
        "{:?}",
        e.notes()
    );
}

#[test]
fn a_resource_that_cannot_be_deleted_is_recorded_as_leaked() {
    let o = Orders::new(Opts::default());
    let srv = serve(move |r| {
        if r.method == "DELETE" && r.user().is_some() {
            return Resp::json(500, json!({"message": "cannot delete"}));
        }
        o.handle(r)
    });
    let e = fixture_env(&srv, true, Profile::Standard);
    stateful::run(&e.ctx).unwrap();
    // lifecycle DELETE + the cleanup retry
    assert!(srv.count("DELETE /orders/4") >= 2, "{:?}", srv.requests());
    let leak = e
        .notes()
        .into_iter()
        .find(|n| n.contains("LEAKED"))
        .expect("a leak note");
    assert!(leak.contains("/orders/4"), "{leak}");
    assert!(e.qa().with(|c| {
        c.risks
            .iter()
            .any(|r| r.title.starts_with("QA test data left"))
    }));
}

#[test]
fn a_create_without_a_delete_endpoint_is_recorded_as_leaked() {
    let (srv, _) = orders_server(Opts::default());
    let spec = fixture_spec_with(|v| {
        v["paths"]["/orders/{id}"]
            .as_object_mut()
            .unwrap()
            .remove("delete");
    });
    let e = mk_env(&srv.base, &spec, FIXTURE_ROLES, true, Profile::Standard);
    stateful::run(&e.ctx).unwrap();
    assert!(
        e.notes()
            .iter()
            .any(|n| n.contains("LEAKED") && n.contains("no DELETE endpoint")),
        "{:?}",
        e.notes()
    );
    assert!(e.qa().with(|c| {
        c.risks
            .iter()
            .any(|r| r.title.starts_with("QA test data left"))
    }));
}

#[test]
fn a_corrupt_baseline_spec_is_backed_up_not_silently_overwritten() {
    let (srv, _) = orders_server(Opts::default());
    let spec = spec_of(
        json!({"/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}}}),
    );
    let e = mk_env(&srv.base, &spec, "", false, Profile::Quick);
    let path = e.data.join("baselines").join(format!(
        "{}.spec-full.json",
        crate::engine::target_key(&e.ctx.target)
    ));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{ this is not json").unwrap();
    functional_in(&e.ctx, &e.data).unwrap();
    let bak = path.with_extension(format!("json.corrupt-{}", e.ctx.run_id));
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), "{ this is not json");
    assert!(
        e.notes()
            .iter()
            .any(|n| n.contains("corrupt") && n.contains("backup kept")),
        "{:?}",
        e.notes()
    );
    // a fresh, valid baseline replaced it only after the backup existed
    assert!(serde_json::from_str::<Value>(&std::fs::read_to_string(&path).unwrap()).is_ok());
    assert!(!e.rules().iter().any(|r| r == "qa.api.breaking_change"));
}

#[test]
fn p95_notes_of_the_api_checks_feed_the_dashboard() {
    let (srv, _) = orders_server(Opts::default());
    let e = fixture_env(&srv, true, Profile::Quick);
    functional_in(&e.ctx, &e.data).unwrap();
    let notes = e.notes();
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("latency ") && n.contains(" p95=")),
        "{notes:?}"
    );
    // the REAL notes, parsed by the real dashboard parser
    let p = crate::dashboard::parse_p95(&notes).expect("a p95 from the real latency notes");
    assert!(p >= 0.0);
    // the helper is the single source of the note shape
    assert_eq!(
        latency_note("GET /a", 230, 5),
        "latency GET /a p95=230ms (n=5)"
    );
    assert_eq!(
        crate::dashboard::parse_p95(&[latency_note("GET /a", 230, 5)]),
        Some(230.0)
    );
}

#[test]
fn the_pieces_the_agent_reuses_need_no_run_context() {
    // everything below is plain data in, plain data out: no Ctx, no QaCtx, no network
    let spec = spec::parse(serde_json::from_str(FIXTURE_SPEC).unwrap()).unwrap();
    let op = |m: &str, p: &str| {
        spec.ops
            .iter()
            .find(|o| o.method == m && o.path == p)
            .unwrap()
            .clone()
    };
    // the item path of a collection, and only that
    assert_eq!(
        collection_of(&op("GET", "/orders/{id}")),
        Some(("/orders".to_string(), "id".to_string()))
    );
    assert_eq!(collection_of(&op("GET", "/orders")), None);
    // ids come out of a list (or an envelope), by the parameter name, capped and de-duplicated
    let mut found = vec![];
    ids_in_list(
        &json!({"data": [{"id": 7}, {"id": 7}, {"uuid": "u-1"}, {"order_id": 9}, {"id": 8}, {"id": 9}]}),
        "order_id",
        &mut found,
    );
    assert_eq!(
        found,
        ["7", "u-1", "9"],
        "at most {MAX_IDS}, first seen first"
    );
    let mut none = vec![];
    ids_in_list(&json!({"error": "nope"}), "id", &mut none);
    assert!(none.is_empty());
    // case generation: the maxLength probe of POST /orders (bug 3 of the fixture)
    let cases = synth::generate(
        &op("POST", "/orders"),
        "readyhai-t-",
        false,
        &HashMap::new(),
    );
    let m = cases
        .iter()
        .find(|c| c.kind == "boundary.maxlen.note")
        .unwrap();
    assert_eq!(m.expect, Expect::Reject);
    assert_eq!(
        m.body.as_ref().unwrap()["note"].as_str().unwrap().len(),
        101
    );
    // response validation: bug 5 (GET /orders/2 omits `total`), judged from the response map alone
    let get = op("GET", "/orders/{id}");
    assert_eq!(
        contract::schema_mismatch(
            &get.responses,
            200,
            &json!({"id": 2, "item": "m", "qty": 1, "owner": "a"})
        )
        .as_deref(),
        Some("$.total: required property missing")
    );
    assert!(contract::undocumented(&get.responses, 201));
    assert!(!contract::undocumented(&get.responses, 404));
    // error leakage (bug 4) and latency (bug 7)
    assert_eq!(
        contract::leak_kind(
            "Traceback (most recent call last):\n  File \"/home/app/server.py\", line 88"
        ),
        Some("python_traceback")
    );
    assert!(latency::is_slow(latency::p95(&[1500, 1520, 1490])));
    // one outlier among many samples is not a slow endpoint
    let mut many: Vec<u128> = vec![25; 39];
    many.push(2000);
    assert!(!latency::is_slow(latency::p95(&many)));
}
