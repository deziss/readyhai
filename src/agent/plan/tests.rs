//! Unit and integration tests for planning.

#![allow(unused_imports)]

use super::baseline::*;
use super::directives::*;
use super::helpers::*;
use super::llm::*;
use super::openapi::*;
use super::surface::*;
use super::types::*;
use super::*;

use crate::agent::change::ChangeSet;
use crate::agent::discover::{Discovery, SpecDoc};
use crate::agent::exec::Credentials;
use crate::agent::memory::PlanHints;
use crate::agent::oracle::Technique;
use crate::agent::types::*;
use crate::agent::whitebox::WhiteboxAnalysis;
use crate::llm::{Budget, LlmConfig};
use crate::qa::api::spec::Op as ApiOp;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

fn route(path: &str, status: u16) -> DiscoveredRoute {
    DiscoveredRoute {
        final_url: None,
        redirect_chain: vec![],
        auth_wall: false,
        catch_all: false,
        input_surface: Default::default(),
        path: path.into(),
        method: "GET".into(),
        status_code: status,
        content_type: "text/html".into(),
        is_spa_shell: false,
        is_api: false,
        title: None,
        has_form: false,
        secured: None,
        has_body: false,
        source: "crawl".into(),
    }
}

#[test]
fn empty_discovery_yields_a_grounded_root_plan_and_never_panics() {
    let d = Discovery::default();
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    assert!(!out.cases.is_empty());
    assert!(
        out.cases
            .iter()
            .all(|c| c.component == "/" || c.component == "/.env" || c.component == "/.git/config"),
        "{:?}",
        out.cases.iter().map(|c| &c.component).collect::<Vec<_>>()
    );
    assert_eq!(out.cases[0].id, "TC-001");
    assert_eq!(out.source, "deterministic");
}

#[test]
fn new_baseline_security_scenarios_are_generated() {
    let mut d = Discovery::default();
    d.routes = vec![route("/", 200), route("/api/items", 200)];
    d.routes[1].has_form = true;
    let out = plan_cases(
        None,
        "http://readyhai:8080",
        "standard",
        &d,
        None,
        &Credentials::none(),
    );
    assert!(out.cases.iter().any(|c| c.title.contains("CORS preflight")));
    assert!(out.cases.iter().any(|c| c.title.contains("Path traversal")));
    assert!(out.cases.iter().any(|c| c.title.contains("NoSQL operator")));
    assert!(
        out.cases
            .iter()
            .any(|c| c.title.contains("Integer overflow"))
    );
    assert!(
        out.cases
            .iter()
            .any(|c| c.title.contains("Mass assignment"))
    );
}

#[test]
fn crawl_plan_is_grounded_on_real_routes() {
    let mut d = Discovery::default();
    d.routes = vec![
        route("/", 200),
        route("/events.php", 200),
        route("/history.php", 200),
        route("/admin", 401),
    ];
    d.routes[1].has_form = true;
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    let comps: HashSet<&str> = out.cases.iter().map(|c| c.component.as_str()).collect();
    for c in &comps {
        assert!(
            [
                "/",
                "/events.php",
                "/history.php",
                "/admin",
                "/.env",
                "/.git/config",
                "/phpinfo.php"
            ]
            .contains(c),
            "invented route {c}"
        );
    }
    assert!(out.cases.iter().any(|c| c.technique == "authz"
        && c.role.as_deref() == Some("forged")
        && c.component == "/admin"
        && c.secured == Some(true)));
    assert!(
        out.cases.iter().any(|c| c.technique == "boundary"
            && c.method == "POST"
            && c.component == "/events.php")
    );
    // GET payloads are plain k=v (the executor puts them in the query string)
    assert!(
        out.cases
            .iter()
            .filter(|c| c.method == "GET" && c.payload.is_some())
            .all(|c| c.payload.as_deref().unwrap().contains('='))
    );
    // ids are unique and sequential
    let ids: Vec<&str> = out.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
}

#[test]
fn sensitive_probes_are_never_targeted_for_bola_or_mutating_verbs() {
    let mut d = Discovery::default();
    d.routes = vec![
        route("/", 401),
        DiscoveredRoute {
            final_url: None,
            redirect_chain: vec![],
            auth_wall: false,
            catch_all: false,
            input_surface: Default::default(),
            path: "/.env".into(),
            method: "GET".into(),
            status_code: 401,
            content_type: "application/json".into(),
            is_spa_shell: false,
            is_api: false,
            title: Some("Sensitive file probe".into()),
            has_form: false,
            secured: None,
            has_body: false,
            source: "probe".into(),
        },
        DiscoveredRoute {
            final_url: None,
            redirect_chain: vec![],
            auth_wall: false,
            catch_all: false,
            input_surface: Default::default(),
            path: "/.git/config".into(),
            method: "GET".into(),
            status_code: 401,
            content_type: "application/json".into(),
            is_spa_shell: false,
            is_api: false,
            title: Some("Sensitive file probe".into()),
            has_form: false,
            secured: None,
            has_body: false,
            source: "probe".into(),
        },
    ];
    let out = plan_cases(
        None,
        "http://readyhai:8080",
        "standard",
        &d,
        None,
        &Credentials::none(),
    );
    // Must never target /.env or /.git/config for BOLA tenant isolation
    for c in &out.cases {
        if c.title.contains("BOLA") {
            assert_ne!(c.component, "/.env");
            assert_ne!(c.component, "/.git/config");
        }
        if c.component == "/.env" || c.component == "/.git/config" {
            assert!(matches!(c.method.as_str(), "GET" | "HEAD"));
        }
    }

    // Also test validate_raw rejects mutating verbs on sensitive probes
    let known = Known::new(&d.routes);
    let creds = Credentials::none();
    let raw_patch = RawCase {
        component: "/.git/config".into(),
        method: Some("PATCH".into()),
        technique: "state_transition".into(),
        title: "Attempt state change on git config via PATCH".into(),
        risk_level: Some("medium".into()),
        expected_status: Some(400),
        expected_behavior: None,
        input_hint: None,
        payload: None,
        headers: None,
        content_type: None,
    };
    let res = validate_raw(&raw_patch, &known, &creds);
    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .contains("mutating method 'PATCH' is not valid")
    );
}

#[test]
fn openapi_plan_uses_ops_from_doc_secured_and_contract_info() {
    let doc: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/qa-api/openapi.json")).unwrap();
    let ops = crate::qa::plan::ops_from_doc(&doc);
    assert!(!ops.is_empty());
    let spec = SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "fixture".into(),
    };
    let mut d = Discovery::default();
    d.routes = vec![route("/", 200)];
    d.spec = Some(spec);
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    assert_eq!(out.source, "openapi");
    // secured ops get an unauthenticated probe expecting denial, with the spec's knowledge attached
    let admin = out
        .cases
        .iter()
        .find(|c| c.component == "/admin/stats" && c.role.as_deref() == Some("anon"))
        .expect("authz probe for /admin/stats");
    assert_eq!(
        (
            admin.secured,
            admin.expected_status,
            admin.technique.as_str()
        ),
        (Some(true), Some(401), "authz")
    );
    // /orders/{id} path parameter is filled, never sent as a template
    assert!(out.cases.iter().any(|c| c.component == "/orders/1"));
    assert!(out.cases.iter().all(|c| !c.component.contains('{')));
    // injection through the declared query parameter
    assert!(out.cases.iter().any(|c| c.technique == "injection"
        && c.component == "/search"
        && c.payload.as_deref().is_some_and(|p| p.starts_with("q="))));
    // body ops get a malformed-JSON negative and an oversized boundary on a spec-declared field
    assert!(out.cases.iter().any(|c| c.technique == "negative"
        && c.method == "POST"
        && c.component == "/orders"
        && c.payload.as_deref() == Some("{\"")));
    let b = out
        .cases
        .iter()
        .find(|c| c.technique == "boundary" && c.method == "POST")
        .unwrap();
    assert!(
        b.payload.as_deref().unwrap().starts_with("{\"item\""),
        "first string property of OrderInput: {:?}",
        b.payload.as_deref().map(|p| &p[..20])
    );
    // no user token => the authenticated contract checks are not planned, and the plan says so
    assert!(out.notes.iter().any(|n| n.contains("RH_USER_TOKEN")));
    // with a token they are planned, with required fields from the Order schema
    let with = plan_cases(
        None,
        "http://h",
        "standard",
        &d,
        None,
        &Credentials::none().with("user", "t"),
    );
    let ord = with
        .cases
        .iter()
        .find(|c| {
            c.component == "/orders/1" && c.method == "GET" && c.technique == "state_transition"
        })
        .expect("contract case");
    assert!(ord.expect_fields.iter().any(|f| f == "total") && ord.role.as_deref() == Some("user"));
}

#[test]
fn llm_raw_cases_are_validated_against_discovered_routes() {
    let routes = vec![route("/", 200), route("/orders/{id}", 0)];
    let known = Known::new(&routes);
    let creds = Credentials::none();
    let ok = |j: &str| validate_raw(&serde_json::from_str::<RawCase>(j).unwrap(), &known, &creds);
    assert!(ok(r#"{"title":"t","component":"/","method":"post","technique":"boundary","payload":{"a":1},"expected_status":422}"#).is_ok());
    assert_eq!(
        ok(r#"{"title":"t","component":"/orders/42","technique":"authz"}"#)
            .unwrap()
            .role
            .as_deref(),
        Some("anon")
    );
    assert!(
        ok(r#"{"title":"t","component":"/api/chat","technique":"boundary"}"#)
            .unwrap_err()
            .contains("not a discovered route")
    );
    assert!(
        ok(r#"{"title":"t","component":"/","method":"TRACE","technique":"boundary"}"#)
            .unwrap_err()
            .contains("not allowed")
    );
    assert!(
        ok(r#"{"title":"t","component":"/","technique":"magic"}"#)
            .unwrap_err()
            .contains("unknown technique")
    );
    let c = ok(r#"{"title":"t","component":"/","technique":"boundary","expected_status":999,"risk_level":"apocalyptic"}"#).unwrap();
    assert_eq!((c.expected_status, c.risk_level.as_str()), (None, "medium"));
    assert!(
        serde_json::from_str::<PlannerOutput>(r#"{"cases":[{"title":1}]}"#).is_err(),
        "serde rejects wrong types"
    );
}

#[test]
fn llm_planner_extras_are_merged_after_the_baseline_and_bad_ones_dropped() {
    use crate::llm::mock;
    let m = mock::start(|_| {
        r#"{"cases":[{"title":"Probe admin with PUT","component":"/admin","method":"PUT","technique":"authz","expected_status":403,"risk_level":"high"},
                     {"title":"Invented","component":"/api/chat","method":"GET","technique":"boundary"},
                     {"title":"Bad verb","component":"/admin","method":"TRACE","technique":"negative"}]}"#.into()
    });
    let dir = std::env::temp_dir().join(format!("rh-plan-llm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = mock::cfg(&m.base, &dir);
    let mut d = Discovery::default();
    d.routes = vec![route("/", 200), route("/admin", 401)];
    let mut b = Budget::per_run();
    let out = plan_cases(
        Some((&cfg, &mut b)),
        "http://h",
        "standard",
        &d,
        Some("focus on admin"),
        &Credentials::none(),
    );
    assert_eq!(out.llm_cases, 1);
    assert_eq!(out.source, "deterministic+llm");
    assert_eq!(out.cases.last().unwrap().source.as_deref(), Some("llm"));
    assert!(
        out.notes.iter().any(|n| n.contains("/api/chat"))
            && out.notes.iter().any(|n| n.contains("not allowed"))
    );
    assert!(
        out.cases.iter().all(|c| c.component != "/api/chat"),
        "invented route must be dropped, not remapped"
    );
    // all-invalid output is an error and is not cached
    let m2 = mock::start(|_| {
        r#"{"cases":[{"title":"x","component":"/nope","technique":"boundary"}]}"#.into()
    });
    let dir2 = std::env::temp_dir().join(format!("rh-plan-llm2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir2);
    let cfg2 = mock::cfg(&m2.base, &dir2);
    let mut b2 = Budget::per_run();
    let out2 = plan_cases(
        Some((&cfg2, &mut b2)),
        "http://h",
        "standard",
        &d,
        None,
        &Credentials::none(),
    );
    assert_eq!(out2.llm_cases, 0);
    assert!(out2.notes.iter().any(|n| n.contains("skipped")));
    assert!(!dir2.exists() || std::fs::read_dir(&dir2).unwrap().count() == 0);
}

#[test]
fn synthesis_seed_derives_from_the_run_id_and_is_used_consistently() {
    use crate::llm::mock;
    assert_eq!(seed_from_run_id("run-a"), seed_from_run_id("run-a"));
    assert_ne!(seed_from_run_id("run-a"), seed_from_run_id("run-b"));
    let user_prompt = |seed: u64, tag: &str| -> (String, PlanOutcome) {
        let m = mock::start(|_| r#"{"cases":[]}"#.into());
        let dir = std::env::temp_dir().join(format!("rh-seed-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = mock::cfg(&m.base, &dir);
        let mut d = Discovery::default();
        d.routes = vec![route("/", 200), route("/admin", 401)];
        let mut b = Budget::per_run();
        let out = plan_cases_seeded(
            Some((&cfg, &mut b)),
            "http://h",
            "standard",
            &d,
            None,
            &Credentials::none(),
            seed,
        );
        let raw = m.requests.lock().unwrap()[0].clone();
        let body: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        (
            body["messages"][1]["content"].as_str().unwrap().to_string(),
            out,
        )
    };
    let seed = seed_from_run_id("run-a");
    let (p1, o1) = user_prompt(seed, "1");
    std::thread::sleep(std::time::Duration::from_millis(5)); // a clock-derived seed would differ now
    let (p2, o2) = user_prompt(seed, "2");
    assert_eq!(p1, p2, "same run id, same question");
    assert_eq!((o1.seed, o2.seed), (seed, seed));
    assert!(
        p1.contains(&format!("{seed:016x}")),
        "the seed is in the prompt"
    );
    // stored with the plan: a note carries it, so a persisted report can re-synthesise it
    assert!(
        o1.notes
            .iter()
            .any(|n| n.contains("seed") && n.contains(&format!("{seed:016x}")))
    );
    // another run, another exploration
    let (p3, o3) = user_prompt(seed_from_run_id("run-b"), "3");
    assert_ne!(p1, p3);
    assert_ne!(o3.seed, seed);
    // the entry point without a run id is deterministic too (never the clock)
    let d = Discovery::default();
    let a = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    let b = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    assert_eq!(a.seed, b.seed);
}

#[test]
fn methods_are_normalised_to_upper_case_at_plan_time() {
    let c = mk(
        "boundary",
        "t".into(),
        "post",
        "/x".into(),
        "h",
        None,
        "b",
        None,
        "low",
        "anon",
        "deterministic",
    );
    assert_eq!(c.method, "POST");
    let c = mk(
        "boundary",
        "t".into(),
        " Delete ",
        "/x".into(),
        "h",
        None,
        "b",
        None,
        "low",
        "anon",
        "deterministic",
    );
    assert_eq!(c.method, "DELETE");
    // an unknown verb stays visibly wrong (upper-cased) so the executor rejects it
    let c = mk(
        "boundary",
        "t".into(),
        "trace",
        "/x".into(),
        "h",
        None,
        "b",
        None,
        "low",
        "anon",
        "deterministic",
    );
    assert_eq!(c.method, "TRACE");
    assert!(normalize_method(&c.method).is_none());
    // every planned method, from any source, is canonical
    let doc: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/qa-api/openapi.json")).unwrap();
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.routes = vec![route("/", 200)];
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "fixture".into(),
    });
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    assert!(
        out.cases
            .iter()
            .all(|c| normalize_method(&c.method) == Some(c.method.as_str()))
    );
    for st in out
        .cases
        .iter()
        .flat_map(|c| c.stateful_steps.iter().flatten())
    {
        assert_eq!(normalize_method(&st.method), Some(st.method.as_str()));
    }
}

#[test]
fn the_cors_case_has_no_status_expectation_and_bursts_are_not_planned_for_generic_forms() {
    let mut d = Discovery::default();
    d.routes = vec![
        route("/", 200),
        route("/events.php", 200),
        route("/history.php", 200),
    ];
    d.routes[1].has_form = true;
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    let cors = out
        .cases
        .iter()
        .find(|c| c.title.contains("CORS"))
        .expect("cors case");
    assert_eq!(
        (cors.method.as_str(), cors.expected_status),
        ("OPTIONS", None)
    );
    assert!(crate::agent::oracle::is_cors_case(cors));
    assert!(
        out.cases.iter().all(|c| c.concurrency_burst.is_none()),
        "a generic form route declares no request schema, so it gets no burst"
    );
    // the mass-assignment probe on the form route is still planned
    assert!(
        out.cases
            .iter()
            .any(|c| c.title.contains("Mass assignment"))
    );
}

#[test]
fn openapi_bola_pairs_a_post_only_with_the_get_of_the_same_resource() {
    let build = |paths: Value| {
        let doc = serde_json::json!({"openapi": "3.0.0", "paths": paths});
        let ops = crate::qa::plan::ops_from_doc(&doc);
        let mut d = Discovery::default();
        d.routes = vec![route("/", 200)];
        d.spec = Some(SpecDoc {
            doc,
            ops,
            base_path: String::new(),
            source: "t".into(),
        });
        plan_cases(None, "http://h", "standard", &d, None, &Credentials::none())
    };
    let body = serde_json::json!({"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}}}}});
    // unrelated POST /orders and GET /users/{id}: no stateful case
    let out =
        build(serde_json::json!({"/orders": {"post": body.clone()}, "/users/{id}": {"get": {}}}));
    assert!(
        out.cases.iter().all(|c| c.stateful_steps.is_none()),
        "unrelated resources must not be paired"
    );
    // POST /orders with GET /orders/{id}: paired on the same path
    let out = build(
        serde_json::json!({"/users/{id}": {"get": {}}, "/orders": {"post": body.clone()}, "/orders/{id}": {"get": {}}}),
    );
    let c = out
        .cases
        .iter()
        .find(|c| c.stateful_steps.is_some())
        .expect("paired case");
    let steps = c.stateful_steps.as_ref().unwrap();
    assert_eq!(
        (steps[0].path.as_str(), steps[1].path.as_str()),
        ("/orders", "/orders/{{id}}")
    );
    assert_eq!(c.component, "/orders");
    // GET /orders/{id}/items is a different resource
    let out =
        build(serde_json::json!({"/orders": {"post": body}, "/orders/{id}/items": {"get": {}}}));
    assert!(out.cases.iter().all(|c| c.stateful_steps.is_none()));
    assert!(
        is_item_path_of("/orders", "/orders/{id}")
            && !is_item_path_of("/orders", "/orders/{id}/items")
            && !is_item_path_of("/orders", "/orders/latest")
    );
}

#[test]
fn write_cases_never_target_id_one_and_the_stateful_body_follows_the_schema() {
    let doc = serde_json::json!({"openapi": "3.0.0", "paths": {
        "/orders": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "required": ["item", "qty"],
            "properties": {"item": {"type": "string"}, "qty": {"type": "integer", "minimum": 1}}}}}}}},
        "/orders/{id}": {
            "get": {},
            "put": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}]},
            "delete": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}]}}}});
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "t".into(),
    });
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    for c in out
        .cases
        .iter()
        .filter(|c| matches!(c.method.as_str(), "PUT" | "DELETE"))
    {
        assert_eq!(c.component, "/orders/999999", "{}", c.title);
    }
    let spec = d.spec.as_ref().unwrap();
    let body: Value =
        serde_json::from_str(&synth_request_body(&spec.doc, "/orders", "POST").unwrap()).unwrap();
    assert!(body["item"].is_string() && body["qty"].is_i64(), "{body}");
    assert!(synth_request_body(&spec.doc, "/orders/{id}", "GET").is_none());
}

fn spec_discovery(n_paths: usize) -> Discovery {
    let paths: serde_json::Map<String, Value> = (0..n_paths)
        .map(|i| (format!("/r{i}"), serde_json::json!({"get": {}})))
        .collect();
    let doc = serde_json::json!({"openapi": "3.0.0", "paths": paths});
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.routes = vec![route("/", 200), route("/events.php", 200)];
    d.routes[1].has_form = true;
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "t".into(),
    });
    d
}

fn from_spec(out: &PlanOutcome) -> usize {
    out.cases
        .iter()
        .filter(|c| c.source.as_deref() == Some("openapi"))
        .count()
}

#[test]
fn the_profile_sets_the_planning_depth() {
    for (p, depth) in [
        ("quick", Depth::Quick),
        (" QUICK ", Depth::Quick),
        ("standard", Depth::Standard),
        ("deep", Depth::Deep),
        ("Deep", Depth::Deep),
        ("discovery-scan", Depth::Standard),
        ("", Depth::Standard),
    ] {
        assert_eq!(Depth::from_profile(p), depth, "{p:?}");
    }
}

#[test]
fn quick_plans_the_baseline_only_and_standard_adds_the_spec() {
    let d = spec_discovery(20);
    let creds = Credentials::none();
    let quick = plan_cases(None, "http://h", "quick", &d, None, &creds);
    let standard = plan_cases(None, "http://h", "standard", &d, None, &creds);
    assert_eq!(from_spec(&quick), 0, "quick uses no OpenAPI-derived case");
    assert!(
        quick
            .cases
            .iter()
            .all(|c| c.stateful_steps.is_none() && c.concurrency_burst.is_none()),
        "no stateful chain or burst at quick"
    );
    assert_eq!(quick.source, "deterministic");
    assert!(
        quick
            .notes
            .iter()
            .any(|n| n.starts_with("quick profile: baseline plan only"))
    );
    assert!(from_spec(&standard) > 0 && standard.cases.len() > quick.cases.len());
    // quick is exactly standard's baseline: nothing else is dropped or reordered
    let base: Vec<String> = standard
        .cases
        .iter()
        .filter(|c| c.source.as_deref() != Some("openapi"))
        .map(key_of)
        .collect();
    assert_eq!(quick.cases.iter().map(key_of).collect::<Vec<_>>(), base);
}

#[test]
fn deep_plans_more_of_the_spec_and_unknown_profiles_plan_like_standard() {
    let d = spec_discovery(40);
    let creds = Credentials::none();
    let standard = plan_cases(None, "http://h", "standard", &d, None, &creds);
    let deep = plan_cases(None, "http://h", "deep", &d, None, &creds);
    assert!(
        from_spec(&deep) > from_spec(&standard),
        "deep {} vs standard {}",
        from_spec(&deep),
        from_spec(&standard)
    );
    assert!(deep.cases.len() <= Depth::Deep.max_cases() && standard.cases.len() <= MAX_CASES);
    let scan = plan_cases(None, "http://h", "discovery-scan", &d, None, &creds);
    let keys = |o: &PlanOutcome| o.cases.iter().map(key_of).collect::<Vec<_>>();
    assert_eq!(keys(&scan), keys(&standard));
}

#[test]
fn the_seed_does_not_depend_on_the_depth_and_planning_is_deterministic() {
    let d = spec_discovery(20);
    let creds = Credentials::none();
    for profile in ["quick", "standard", "deep"] {
        let a = plan_cases_seeded(None, "http://h", profile, &d, None, &creds, 7);
        let b = plan_cases_seeded(None, "http://h", profile, &d, None, &creds, 7);
        assert_eq!(
            serde_json::to_string(&a.cases).unwrap(),
            serde_json::to_string(&b.cases).unwrap(),
            "{profile}"
        );
        assert_eq!(
            (a.seed, &a.notes[0]),
            (7, &format!("plan synthesis seed: {:016x}", 7u64))
        );
    }
    assert_eq!(
        seed_from_run_id("run-1"),
        seed_from_run_id("run-1"),
        "the seed comes from the run id alone"
    );
}

fn fixture_spec() -> SpecDoc {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/qa-api/openapi.json"
    ))
    .unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    let ops = crate::qa::plan::ops_from_doc(&doc);
    SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "fixture".into(),
    }
}

fn bursts(out: &PlanOutcome) -> Vec<&PlannedCase> {
    out.cases
        .iter()
        .filter(|c| c.concurrency_burst.is_some())
        .collect()
}

#[test]
fn no_spec_means_no_burst_at_any_depth() {
    let mut d = Discovery::default();
    d.routes = vec![route("/", 200), route("/events.php", 200)];
    d.routes[1].has_form = true;
    let creds = Credentials::none();
    for profile in ["quick", "standard", "deep"] {
        let out = plan_cases(None, "http://h", profile, &d, None, &creds);
        assert!(bursts(&out).is_empty(), "{profile}");
    }
    // the form route is still probed, just never with a made-up burst body
    let out = plan_cases(None, "http://h", "deep", &d, None, &creds);
    assert!(
        out.cases
            .iter()
            .any(|c| c.title.contains("Mass assignment"))
    );
    assert!(
        out.cases
            .iter()
            .all(|c| c.payload.as_deref() != Some("data=burst_test"))
    );
}

#[test]
fn plain_reads_carry_the_required_query_params_of_the_spec() {
    let mut d = Discovery::default();
    d.spec = Some(fixture_spec());
    let creds = Credentials::none().with("user", "alice-token");
    let out = plan_cases(None, "http://h", "standard", &d, None, &creds);
    // GET /search declares a required `q` (minLength 1): the contract read must send one
    let read = out
        .cases
        .iter()
        .find(|c| c.component == "/search" && c.title.contains("honours its contract"))
        .expect("plain read of /search");
    assert_eq!(read.payload.as_deref(), Some("q=test"));
    // an operation without required query params keeps a payload-less read
    let orders = out
        .cases
        .iter()
        .find(|c| {
            c.method == "GET"
                && c.title.contains("honours its contract")
                && c.component == "/orders"
        })
        .expect("plain read of /orders");
    assert_eq!(orders.payload, None);
    // the sample follows the schema: enum first, then a numeric minimum, then minLength
    let schema = |v: &str| serde_json::from_str::<Value>(v).unwrap();
    assert_eq!(
        sample_value(&schema(r#"{"enum":["b","a"]}"#), "string", ""),
        "b"
    );
    assert_eq!(
        sample_value(&schema(r#"{"minimum":5}"#), "integer", ""),
        "5"
    );
    assert_eq!(
        sample_value(&schema(r#"{"minLength":9}"#), "string", "").len(),
        12
    );
    // POST/DELETE carry their payload in a body, never in the query string
    let p = |loc: &str| Param {
        name: "k".into(),
        loc: loc.into(),
        ty: "string".into(),
        format: String::new(),
        required: true,
        sample: "v".into(),
    };
    assert_eq!(required_query(&[p("query")], "GET").as_deref(), Some("k=v"));
    assert_eq!(required_query(&[p("query")], "POST"), None);
    assert_eq!(required_query(&[p("header")], "GET"), None);
}

#[test]
fn the_burst_body_is_synthesised_from_the_spec_schema_and_the_fixture_accepts_it() {
    let mut d = Discovery::default();
    d.spec = Some(fixture_spec());
    let creds = Credentials::none().with("user", "alice-token");
    let out = plan_cases(None, "http://h", "standard", &d, None, &creds);
    let b = bursts(&out);
    assert_eq!(
        b.len(),
        1,
        "{:?}",
        out.cases.iter().map(|c| &c.title).collect::<Vec<_>>()
    );
    let c = b[0];
    assert_eq!(
        (c.method.as_str(), c.component.as_str(), c.source.as_deref()),
        ("POST", "/orders", Some("openapi"))
    );
    assert_eq!(c.concurrency_burst, Some(5));
    let body: Value = serde_json::from_str(c.payload.as_deref().unwrap()).unwrap();
    // OrderInput: item (string, minLength 1) and qty (integer 1..100) are required, note <= 100
    let o = body.as_object().unwrap();
    assert!(o["item"].as_str().is_some_and(|s| !s.is_empty()), "{body}");
    assert!(
        o["qty"].as_i64().is_some_and(|q| (1..=100).contains(&q)),
        "{body}"
    );
    assert!(
        o.get("note")
            .is_none_or(|n| n.as_str().is_some_and(|n| n.len() <= 100)),
        "{body}"
    );
    assert!(
        o.keys()
            .all(|k| ["item", "qty", "note"].contains(&k.as_str())),
        "{body}"
    );
    assert_eq!(
        super::super::exec::fixture::order_input_error(&body),
        None,
        "{body}"
    );
    // it is the same body the stateful BOLA step sends: one synthesis helper for both
    let bola = out
        .cases
        .iter()
        .find_map(|c| c.stateful_steps.as_ref())
        .unwrap();
    assert_eq!(bola[0].payload.as_deref(), c.payload.as_deref());
}

#[test]
fn the_planned_burst_is_accepted_by_the_fixture_end_to_end() {
    use super::super::exec::{ExecOptions, execute_cases_with, fixture};
    let mut d = Discovery::default();
    d.spec = Some(fixture_spec());
    let creds = Credentials::none().with("user", "alice-token");
    let out = plan_cases(None, "http://h", "standard", &d, None, &creds);
    let burst = bursts(&out)[0].clone();
    let api = fixture::start(false);
    let opts = ExecOptions {
        dry_run: false,
        is_spa_target: false,
        credentials: creds,
        reruns: 0,
        timeout: std::time::Duration::from_secs(5),
    };
    let mut budget =
        crate::agent::budget::RunBudget::new(50, 500, std::time::Duration::from_secs(60), 0.0);
    let r = execute_cases_with(&[burst], &api.base, &opts, &mut budget);
    assert_eq!(r.len(), 2, "the base request and its burst sub-case: {r:?}");
    assert_eq!(
        r[0].status_code,
        Some(201),
        "the base request is valid: {:?}",
        r[0]
    );
    assert_eq!(
        r[1].concurrency_burst_results.as_deref(),
        Some(&[201u16; 5][..]),
        "{:?}",
        r[1]
    );
    // 1 base + 5 burst creations, none bounced by validation
    assert_eq!(api.order_ids().len(), 3 + 6);
}

#[test]
fn a_create_operation_without_a_usable_json_schema_gets_no_burst() {
    let build = |post: Value| {
        let doc = serde_json::json!({"openapi": "3.0.0", "paths": {"/things": {"post": post}}});
        let ops = crate::qa::plan::ops_from_doc(&doc);
        let mut d = Discovery::default();
        d.spec = Some(SpecDoc {
            doc,
            ops,
            base_path: String::new(),
            source: "t".into(),
        });
        plan_cases(None, "http://h", "standard", &d, None, &Credentials::none())
    };
    // a form-encoded body and a body-less POST declare no JSON object schema
    let form = build(
        serde_json::json!({"requestBody": {"content": {"application/x-www-form-urlencoded": {
        "schema": {"type": "object", "properties": {"a": {"type": "string"}}}}}}}),
    );
    assert!(bursts(&form).is_empty());
    let none = build(serde_json::json!({"responses": {"200": {"description": "ok"}}}));
    assert!(bursts(&none).is_empty());
    // a JSON object schema, even through a $ref, does get one
    let doc = serde_json::json!({"openapi": "3.0.0",
        "components": {"schemas": {"Thing": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}}},
        "paths": {"/things": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Thing"}}}}}}}});
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "t".into(),
    });
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    let b = bursts(&out);
    assert_eq!(b.len(), 1);
    let body: Value = serde_json::from_str(b[0].payload.as_deref().unwrap()).unwrap();
    assert!(body["name"].is_string(), "{body}");
    // a credential flow with a perfectly good schema is still never hammered
    let login = serde_json::json!({"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "required": ["user"], "properties": {"user": {"type": "string"}}}}}}});
    let doc = serde_json::json!({"openapi": "3.0.0", "paths": {"/login": {"post": login}}});
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "t".into(),
    });
    assert!(
        bursts(&plan_cases(
            None,
            "http://h",
            "standard",
            &d,
            None,
            &Credentials::none()
        ))
        .is_empty()
    );
}

#[test]
fn the_llm_is_asked_for_extras_at_standard_and_deep_but_never_at_quick() {
    let m = crate::llm::mock::start(|_| {
        r#"{"cases":[{"title":"PUT on admin","component":"/admin","method":"PUT","technique":"authz","expected_status":403,"risk_level":"high"}]}"#.into()
    });
    let dir = std::env::temp_dir().join(format!("rh-plan-depth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut d = Discovery::default();
    d.routes = vec![route("/", 200), route("/admin", 401)];
    let creds = Credentials::none();
    let run = |profile: &str, cache: &str| {
        let cfg = crate::llm::mock::cfg(&m.base, &dir.join(cache));
        let mut b = Budget::new(5, std::time::Duration::from_secs(30));
        plan_cases_seeded(
            Some((&cfg, &mut b)),
            "http://h",
            profile,
            &d,
            None,
            &creds,
            3,
        )
    };
    let hits = || m.chat_hits.load(std::sync::atomic::Ordering::SeqCst);
    let quick = run("quick", "q");
    assert_eq!(
        (hits(), quick.llm_cases, quick.source.as_str()),
        (0, 0, "deterministic")
    );
    let standard = run("standard", "s");
    assert!(
        hits() >= 1 && standard.llm_cases == 1,
        "{:?}",
        standard.notes
    );
    assert_eq!(standard.source, "deterministic+llm");
    let before = hits();
    let deep = run("deep", "d");
    assert!(hits() > before && deep.llm_cases == 1, "{:?}", deep.notes);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn credential_flows_are_never_hammered_by_a_burst() {
    for p in [
        "/login",
        "/api/auth/token",
        "/users/reset-password",
        "/signup",
    ] {
        assert!(is_credential_flow(p), "{p}");
    }
    assert!(!is_credential_flow("/orders"));
}
// ---- the spec's contract, boundary probes and real records (shared QA generators)

fn alice() -> Credentials {
    Credentials::none().with("alice", "alice-token")
}

fn fixture_ids() -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([(
        "/orders".to_string(),
        vec!["1".to_string(), "2".to_string()],
    )])
}

fn fixture_discovery(ids: BTreeMap<String, Vec<String>>) -> Discovery {
    let mut d = Discovery::default();
    d.spec = Some(fixture_spec());
    d.ids = ids;
    d
}

fn plan_for(d: &Discovery, creds: &Credentials, profile: &str) -> PlanOutcome {
    plan_cases(None, "http://h", profile, d, None, creds)
}

#[test]
fn a_maxlength_probe_is_generated_from_the_spec_for_the_acting_role() {
    let out = plan_for(&fixture_discovery(BTreeMap::new()), &alice(), "standard");
    let probe = out
        .cases
        .iter()
        .find(|c| {
            c.method == "POST"
                && c.component == "/orders"
                && c.title.contains("note: maxlen violation")
        })
        .unwrap_or_else(|| {
            panic!(
                "no maxlen probe: {:?}",
                out.cases.iter().map(|c| &c.title).collect::<Vec<_>>()
            )
        });
    let body: Value = serde_json::from_str(probe.payload.as_deref().unwrap()).unwrap();
    assert_eq!(
        body["note"].as_str().unwrap().len(),
        101,
        "one over the spec's maxLength"
    );
    assert!(
        body["item"].is_string() && body["qty"].is_i64(),
        "the rest of the body is valid: {body}"
    );
    assert_eq!(
        (
            probe.technique.as_str(),
            probe.role.as_deref(),
            probe.source.as_deref()
        ),
        ("boundary", Some("alice"), Some("openapi"))
    );
    assert_eq!(probe.secured, Some(true));
    let contract = probe
        .contract
        .as_ref()
        .expect("the probe carries its response contract");
    assert!(contract.responses.contains_key("422") && !contract.latency);
    // a missing required field and an out-of-range number are planned too
    let titles: Vec<&str> = out.cases.iter().map(|c| c.title.as_str()).collect();
    assert!(
        titles.iter().any(|t| t.contains("missing required 'item'")),
        "{titles:?}"
    );
    assert!(
        titles.iter().any(|t| t.contains("qty: max violation")),
        "{titles:?}"
    );
    // query constraints go into the query string of the component
    assert!(
        out.cases
            .iter()
            .any(|c| c.method == "GET" && c.component == "/orders?page=0"),
        "{titles:?}"
    );
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("boundary/negative probe(s) planned"))
    );
}

#[test]
fn probes_never_write_to_a_record_that_exists_and_stay_inside_the_budget() {
    let d = fixture_discovery(fixture_ids());
    for profile in ["standard", "deep"] {
        let out = plan_for(&d, &alice(), profile);
        let probes: Vec<&PlannedCase> = out
            .cases
            .iter()
            .filter(|c| c.contract.as_ref().is_some_and(|k| !k.latency))
            .collect();
        assert!(!probes.is_empty(), "{profile}");
        for c in &probes {
            if c.method != "GET" && c.method != "POST" {
                assert!(
                    crate::agent::verify::targets_unlikely_id(&c.component),
                    "{profile}: {} {} must use the id nobody owns",
                    c.method,
                    c.component
                );
            }
            assert!(
                !c.component.contains("/orders/1") && !c.component.contains("/orders/2"),
                "{profile}: {}",
                c.component
            );
        }
        let depth = Depth::from_profile(profile);
        assert!(
            probes.len() <= depth.probes_total(),
            "{profile}: {}",
            probes.len()
        );
        let per_op = |m: &str, p: &str| {
            probes
                .iter()
                .filter(|c| c.method == m && c.component.split('?').next() == Some(p))
                .count()
        };
        assert!(
            per_op("POST", "/orders") <= depth.probes_per_op(),
            "{profile}"
        );
        assert!(
            per_op("PUT", "/orders/999999") <= depth.probes_per_op().div_ceil(2),
            "{profile}: a write on an id nobody owns meets a 404 first, so fewer"
        );
    }
    assert!(
        Depth::Deep.probes_per_op() > Depth::Standard.probes_per_op(),
        "deep probes more"
    );
}

#[test]
fn existing_records_are_read_with_their_contract_and_latency_limit() {
    let out = plan_for(&fixture_discovery(fixture_ids()), &alice(), "standard");
    let reads: Vec<&PlannedCase> = out
        .cases
        .iter()
        .filter(|c| c.contract.as_ref().is_some_and(|k| k.latency))
        .collect();
    let comps: Vec<(&str, &str)> = reads
        .iter()
        .map(|c| (c.method.as_str(), c.component.as_str()))
        .collect();
    for want in [
        "/orders/1",
        "/orders/2",
        "/orders",
        "/reports/slow",
        "/admin/stats",
    ] {
        assert!(comps.contains(&("GET", want)), "{want} not read: {comps:?}");
    }
    assert!(
        !comps.contains(&("GET", "/orders/{id}")),
        "no template placeholder is ever sent: {comps:?}"
    );
    let two = reads.iter().find(|c| c.component == "/orders/2").unwrap();
    assert_eq!(
        (two.role.as_deref(), two.expected_status),
        (Some("alice"), Some(200))
    );
    let k = two.contract.as_ref().unwrap();
    let schema = k
        .responses
        .get("200")
        .and_then(Option::as_ref)
        .expect("the 200 schema travels");
    assert!(
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "total")
    );
    assert!(
        k.responses.get("404").is_some_and(Option::is_none),
        "non-2xx responses carry their key only"
    );
    // a public operation is read without a credential, as before
    let health = reads.iter().find(|c| c.component == "/health").unwrap();
    assert_eq!(health.role.as_deref(), Some("anon"));
    // without harvested ids the stand-in id is read, as before
    let out = plan_for(&fixture_discovery(BTreeMap::new()), &alice(), "standard");
    assert!(
        out.cases
            .iter()
            .any(|c| c.method == "GET" && c.component == "/orders/1" && c.contract.is_some()),
    );
    assert!(!out.cases.iter().any(|c| c.component == "/orders/2"));
}

#[test]
fn a_harvested_id_cannot_smuggle_a_path_or_a_title() {
    let ids = BTreeMap::from([(
        "/orders".to_string(),
        vec!["../admin?x=1 y".to_string(), "7\nforged title".to_string()],
    )]);
    let out = plan_for(&fixture_discovery(ids), &alice(), "standard");
    let reads: Vec<&PlannedCase> = out
        .cases
        .iter()
        .filter(|c| {
            c.method == "GET" && c.component.starts_with("/orders/") && c.contract.is_some()
        })
        .collect();
    assert_eq!(reads.len(), 2, "one read per harvested id");
    for c in reads {
        let id = c.component.strip_prefix("/orders/").unwrap();
        assert!(
            !id.contains(['/', '?', '#', ' ', '\n']),
            "the id stays one encoded path segment: {}",
            c.component
        );
        assert!(super::super::exec::normalize_component(&c.component).is_ok());
        assert!(!c.title.contains('\n'), "{:?}", c.title);
    }
}

#[test]
fn without_a_usable_credential_nothing_authenticated_is_planned_from_the_spec() {
    let d = fixture_discovery(fixture_ids());
    for creds in [Credentials::none(), Credentials::none().with("admin", "t")] {
        let out = plan_for(&d, &creds, "standard");
        let sent_with_a_role = out
            .cases
            .iter()
            .filter(|c| c.contract.is_some())
            .filter(|c| c.secured == Some(true))
            .count();
        assert_eq!(
            sent_with_a_role, 0,
            "a secured operation needs the acting role"
        );
        assert!(
            out.notes.iter().any(|n| n.contains("credential")),
            "{:?}",
            out.notes
        );
        // public operations are still read and probed without a credential
        assert!(
            out.cases
                .iter()
                .any(|c| c.component == "/health" && c.contract.is_some())
        );
    }
}

#[test]
fn quick_plans_no_contract_reads_and_no_probes() {
    let out = plan_for(&fixture_discovery(fixture_ids()), &alice(), "quick");
    assert!(
        out.cases.iter().all(|c| c.contract.is_none()),
        "{:?}",
        out.cases
    );
    assert!(plans_from_spec("standard") && plans_from_spec("deep") && !plans_from_spec("Quick"));
}

#[test]
fn a_spec_that_is_not_openapi_3_falls_back_to_the_legacy_plan() {
    let doc = serde_json::json!({"swagger": "2.0", "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}});
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "t".into(),
    });
    let out = plan_for(&d, &alice(), "standard");
    assert!(out.cases.iter().all(|c| c.contract.is_none()));
    assert!(!out.cases.is_empty());
}

#[test]
fn oversized_response_schemas_are_not_carried_and_the_plan_says_so() {
    let big: Value =
        serde_json::json!({"type": "object", "description": "x".repeat(MAX_CONTRACT_SCHEMA + 1)});
    let doc = serde_json::json!({"openapi": "3.0.0", "paths": {"/a": {"get": {"responses": {
        "200": {"description": "ok", "content": {"application/json": {"schema": big}}},
        "404": {"description": "nf"}}}}}});
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "t".into(),
    });
    let out = plan_for(&d, &Credentials::none(), "standard");
    let read = out
        .cases
        .iter()
        .find(|c| c.component == "/a" && c.contract.is_some())
        .unwrap();
    let k = read.contract.as_ref().unwrap();
    assert_eq!(
        k.responses.get("200"),
        Some(&None),
        "the key stays so the status is documented"
    );
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("not carried into the plan")),
        "{:?}",
        out.notes
    );
}

#[test]
fn a_plan_over_the_cap_keeps_the_cases_that_matter_most() {
    // 80 plain reads fill the plan; the authorization case of the last operation must survive
    let paths: serde_json::Map<String, Value> = (0..80)
        .map(|i| (format!("/r{i}"), serde_json::json!({"get": {"security": [{"b": []}], "responses": {"200": {"description": "ok"}}}})))
        .collect();
    let doc = serde_json::json!({"openapi": "3.0.0", "paths": paths});
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "t".into(),
    });
    let out = plan_for(&d, &alice(), "deep");
    assert!(out.cases.len() <= Depth::Deep.max_cases());
    let authz = out.cases.iter().filter(|c| c.technique == "authz").count();
    let all_authz = 30; // deep plans the top 30 operations
    assert!(authz >= all_authz, "authz cases are cut last: kept {authz}");
}
// ------------------------------------------------------------ change-aware planning

fn changed(labels: &[&str]) -> ChangeSet {
    ChangeSet::from_labels(labels.iter().map(|s| s.to_string()))
}

fn plan_changed(profile: &str, change: Option<&ChangeSet>) -> PlanOutcome {
    let d = fixture_discovery(fixture_ids());
    plan_cases_changed(None, "http://h", profile, &d, None, &alice(), 7, change)
}

fn tagged<'a>(out: &'a PlanOutcome, op: &str) -> Vec<&'a PlannedCase> {
    out.cases
        .iter()
        .filter(|c| c.changed_ops.iter().any(|o| o == op))
        .collect()
}

#[test]
fn no_change_set_or_an_empty_one_plans_exactly_as_before() {
    let empty = changed(&[]);
    for profile in ["quick", "standard", "deep"] {
        let d = fixture_discovery(fixture_ids());
        let before = plan_cases_seeded(None, "http://h", profile, &d, None, &alice(), 7);
        for c in [None, Some(&empty)] {
            let now = plan_changed(profile, c);
            assert_eq!(
                serde_json::to_string(&before.cases).unwrap(),
                serde_json::to_string(&now.cases).unwrap(),
                "{profile}"
            );
            assert_eq!(before.notes, now.notes, "{profile}");
        }
        assert!(before.cases.iter().all(|c| c.changed_ops.is_empty()));
    }
}

#[test]
fn at_quick_a_changed_operation_still_gets_its_full_case_set_and_only_it() {
    let quick = plan_changed("quick", None);
    assert_eq!(from_spec(&quick), 0);
    let out = plan_changed("quick", Some(&changed(&["GET /orders"])));
    let mine = tagged(&out, "GET /orders");
    let tech = |t: &str| mine.iter().filter(|c| c.technique == t).count();
    assert!(
        tech("authz") >= 2,
        "unauthenticated and forged: {}",
        tech("authz")
    );
    assert!(tech("injection") >= 2, "script and SQL injection");
    assert!(tech("state_transition") >= 1, "the contract read");
    assert!(
        mine.iter()
            .any(|c| matches!(c.technique.as_str(), "boundary" | "negative")),
        "probes from the spec's own constraints"
    );
    // nothing else from the spec: every OpenAPI case belongs to the changed operation
    assert!(
        out.cases
            .iter()
            .filter(|c| c.source.as_deref() == Some("openapi"))
            .all(|c| c.changed_ops == ["GET /orders"]),
        "quick plans only the changed operation from the spec"
    );
    // the crawl baseline is untouched
    let base = |o: &PlanOutcome| {
        o.cases
            .iter()
            .filter(|c| c.source.as_deref() != Some("openapi"))
            .map(key_of)
            .collect::<Vec<_>>()
    };
    assert_eq!(base(&out), base(&quick));
    // changed first, then the baseline
    let first_other = out
        .cases
        .iter()
        .position(|c| c.changed_ops.is_empty())
        .unwrap();
    assert_eq!(first_other, mine.len());
    assert_eq!(out.cases[0].id, "TC-001");
    assert!(
        out.notes
            .iter()
            .any(|n| n.starts_with("change-aware plan: 1 changed operation(s) (GET /orders)"))
    );
}

#[test]
fn a_changed_create_brings_its_burst_and_tenant_chain_even_at_quick() {
    let out = plan_changed("quick", Some(&changed(&["POST /orders"])));
    let mine = tagged(&out, "POST /orders");
    assert!(mine.iter().any(|c| c.concurrency_burst.is_some()), "burst");
    assert!(
        mine.iter().any(|c| c.stateful_steps.is_some()),
        "BOLA chain"
    );
    assert!(
        mine.iter()
            .any(|c| c.technique == "boundary" && c.payload.is_some())
    );
    // the chain is also the read side's: changing only GET /orders/{id} plans it too
    let out = plan_changed("quick", Some(&changed(&["GET /orders/{id}"])));
    let chain = tagged(&out, "GET /orders/{id}")
        .into_iter()
        .find(|c| c.stateful_steps.is_some())
        .expect("chain");
    assert_eq!(chain.changed_ops, ["GET /orders/{id}"]);
    assert!(chain.title.contains("POST /orders -> GET /orders/{id}"));
    // a read-only change plans no burst
    assert!(
        tagged(&out, "GET /orders/{id}")
            .iter()
            .all(|c| c.concurrency_burst.is_none())
    );
}

#[test]
fn standard_keeps_every_baseline_case_and_puts_the_changed_ones_first() {
    let before = plan_changed("standard", None);
    let out = plan_changed(
        "standard",
        Some(&changed(&["GET /reports/slow", "DELETE /orders/{id}"])),
    );
    let mine: Vec<&PlannedCase> = out
        .cases
        .iter()
        .filter(|c| !c.changed_ops.is_empty())
        .collect();
    assert!(mine.len() >= 5, "{}", mine.len());
    assert!(
        out.cases[..mine.len()]
            .iter()
            .all(|c| !c.changed_ops.is_empty()),
        "the changed operations' cases lead the plan"
    );
    // nothing the profile planned is lost
    let keys: HashSet<String> = out.cases.iter().map(key_of).collect();
    assert!(before.cases.iter().all(|c| keys.contains(&key_of(c))));
    // and only its own operation tags a case
    for c in &mine {
        assert!(
            c.changed_ops
                .iter()
                .all(|o| o == "GET /reports/slow" || o == "DELETE /orders/{id}")
        );
    }
}

#[test]
fn a_changed_operation_is_not_rationed_by_the_baseline_limits() {
    // 60 secured operations; only the last, lowest-risk one changed. At quick nothing else is
    // planned from the spec; at standard it goes in on top of the top 15.
    let paths: serde_json::Map<String, Value> = (0..60)
        .map(|i| (format!("/r{i}"), serde_json::json!({"get": {"security": [{"b": []}], "responses": {"200": {"description": "ok"}}}})))
        .collect();
    let doc = serde_json::json!({"openapi": "3.0.0", "paths": paths});
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let last = "GET /r59".to_string();
    assert!(ops.iter().any(|o| o.component() == last));
    let mut d = Discovery::default();
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "t".into(),
    });
    let cs = ChangeSet::from_labels([last.clone()]);
    let std_plain = plan_cases_seeded(None, "http://h", "standard", &d, None, &alice(), 7);
    let std_changed = plan_cases_changed(
        None,
        "http://h",
        "standard",
        &d,
        None,
        &alice(),
        7,
        Some(&cs),
    );
    assert!(
        !std_plain
            .cases
            .iter()
            .any(|c| c.component.ends_with("/r59")),
        "outside the top 15"
    );
    let mine: Vec<_> = std_changed
        .cases
        .iter()
        .filter(|c| c.component.ends_with("/r59"))
        .collect();
    assert!(mine.len() >= 3, "{}", mine.len());
    assert!(mine.iter().all(|c| c.changed_ops == [last.clone()]));
    assert_eq!(
        std_changed.cases[0].changed_ops,
        std::slice::from_ref(&last)
    );
    // a plan cut to its cap loses unchanged cases first
    let cut = plan_cases_changed(None, "http://h", "deep", &d, None, &alice(), 7, Some(&cs));
    assert!(cut.cases.len() <= Depth::Deep.max_cases());
    assert!(
        cut.cases
            .iter()
            .any(|c| c.changed_ops == [last.clone()] && c.technique == "authz")
    );
}
// ------------------------------------------------------------ memory

fn remembered_defect(class: &str, rule: &str, endpoint: &str) -> crate::agent::memory::Memory {
    use crate::agent::memory::{DefectStatus, KnownDefect, Memory};
    let mut m = Memory::fresh("0123456789abcdef", "http://h", "2026-03-01T00:00:00Z");
    m.defects.insert(
        crate::agent::memory::fingerprint(rule, endpoint),
        KnownDefect {
            rule: rule.into(),
            endpoint: endpoint.into(),
            methods: vec!["GET".into()],
            technique: "authz".into(),
            severity: "critical".into(),
            first_seen: "2026-03-01".into(),
            last_seen: "2026-03-01".into(),
            fixed_at: None,
            status: DefectStatus::Open,
            runs_seen: 2,
            accepted: None,
            repro: vec![class.into()],
        },
    );
    m
}

#[test]
fn memory_plans_the_reproduction_of_known_defects_first_and_only_reorders() {
    use crate::agent::memory::{PlanHints, class_of};
    let mut d = Discovery::default();
    d.routes = vec![
        route("/", 200),
        route("/events.php", 200),
        route("/history.php", 200),
        route("/admin", 401),
        route("/about", 200),
    ];
    d.routes[1].has_form = true;
    let creds = Credentials::none();
    let plain = plan_cases_seeded(None, "http://h", "standard", &d, None, &creds, 7);
    // the last case of the plain plan, a generic probe nothing else would put early
    let victim = plain
        .cases
        .iter()
        .rev()
        .find(|c| c.component != "/" && c.technique != "authz")
        .unwrap()
        .clone();
    assert!(plain.cases[0].component != victim.component || plain.cases.len() < 3);
    let m = remembered_defect(&class_of(&victim), "server_error", &victim.component);
    let hints = PlanHints::from_memory(&m, "2026-03-02");
    assert!(!hints.is_empty());
    let with = plan_cases_remembered(
        None,
        "http://h",
        "standard",
        &d,
        None,
        &creds,
        7,
        None,
        Some(&hints),
    );
    // every case that re-tests the defect leads the plan, tagged with its fingerprint
    let fp = crate::agent::memory::fingerprint("server_error", &victim.component);
    let probes = with
        .cases
        .iter()
        .filter(|c| !c.regression_of.is_empty())
        .count();
    assert!(probes >= 1);
    assert!(
        with.cases[..probes]
            .iter()
            .all(|c| c.regression_of == [fp.clone()]),
        "{:?}",
        with.cases
            .iter()
            .map(|c| (&c.id, &c.regression_of))
            .collect::<Vec<_>>()
    );
    assert!(
        with.cases[probes..]
            .iter()
            .all(|c| c.regression_of.is_empty())
    );
    assert_eq!(with.cases[0].id, "TC-001");
    assert_eq!(class_of(&with.cases[0]), class_of(&victim));
    assert!(
        with.notes.iter().any(|n| n.contains("agent memory:")),
        "{:?}",
        with.notes
    );
    // nothing is added or dropped: the same cases, whatever passed before (baseline coverage stays)
    let keys = |p: &PlanOutcome| {
        let mut k: Vec<String> = p.cases.iter().map(key_of).collect();
        k.sort();
        k
    };
    assert_eq!(keys(&with), keys(&plain));
    // empty memory, or none: exactly the plan the profile gives
    let none = plan_cases_remembered(
        None, "http://h", "standard", &d, None, &creds, 7, None, None,
    );
    let empty = plan_cases_remembered(
        None,
        "http://h",
        "standard",
        &d,
        None,
        &creds,
        7,
        None,
        Some(&PlanHints::default()),
    );
    let json = |p: &PlanOutcome| serde_json::to_string(&p.cases).unwrap();
    assert_eq!(json(&none), json(&plain));
    assert_eq!(json(&empty), json(&plain));
    // the same memory orders the plan the same way every time
    let again = plan_cases_remembered(
        None,
        "http://h",
        "standard",
        &d,
        None,
        &creds,
        7,
        None,
        Some(&hints),
    );
    assert_eq!(json(&again), json(&with));
    // a cut plan keeps the probes: truncating by plan order never drops a regression probe first
    let key = plan_order(any_prioritised(&with.cases));
    let mut cut = with.cases.clone();
    cut.sort_by_key(|c| key(c));
    assert!(cut[..probes].iter().all(|c| !c.regression_of.is_empty()));
}
// ------------------------------------------------------------ input surface

fn plan_routes(routes: Vec<DiscoveredRoute>, creds: &Credentials) -> PlanOutcome {
    let mut d = Discovery::default();
    d.routes = routes;
    plan_cases(None, "http://h", "standard", &d, None, creds)
}

fn input_cases(out: &PlanOutcome) -> Vec<&PlannedCase> {
    out.cases
        .iter()
        .filter(|c| {
            matches!(c.technique.as_str(), "injection" | "boundary" | "negative")
                && !c.is_ledger_row()
        })
        .collect()
}

fn ledger_rows(out: &PlanOutcome) -> Vec<&PlannedCase> {
    out.cases.iter().filter(|c| c.is_ledger_row()).collect()
}

fn spa_shell(path: &str) -> DiscoveredRoute {
    let mut r = route(path, 200);
    r.is_spa_shell = true;
    r
}

#[test]
fn a_route_that_refuses_get_is_not_a_get_input_surface() {
    let mut r = route("/api/stt/transcribe", 405);
    r.is_api = true;
    r.input_surface = InputSurface::Json;
    r.source = "js".into();
    assert_eq!(surface_of(&r), InputSurface::None);
    // a spec operation keeps its declared surface
    r.source = "openapi".into();
    assert_eq!(surface_of(&r), InputSurface::Json);
}

#[test]
fn the_input_surface_of_a_route_is_recorded_or_derived() {
    let mut r = route("/page", 200);
    assert_eq!(
        surface_of(&r),
        InputSurface::None,
        "plain HTML takes nothing"
    );
    r.has_form = true;
    assert_eq!(surface_of(&r), InputSurface::Form);
    let mut r = route("/search?q=x", 200);
    assert_eq!(surface_of(&r), InputSurface::Query);
    r.is_api = true;
    assert_eq!(surface_of(&r), InputSurface::Json, "an API route");
    // what discovery recorded wins
    let mut r = route("/x", 200);
    r.input_surface = InputSurface::Spec;
    assert_eq!(surface_of(&r), InputSurface::Spec);
    // an SPA shell and a catch-all take nothing, whatever else is said about them
    let mut shell = spa_shell("/");
    shell.has_form = true;
    assert_eq!(surface_of(&shell), InputSurface::None);
    let mut ca = route("/anything", 200);
    ca.catch_all = true;
    ca.is_api = true;
    ca.input_surface = InputSurface::Json;
    assert_eq!(surface_of(&ca), InputSurface::None);
    // walls: 401, a recorded wall, a redirect to a login
    assert!(is_walled(&route("/a", 401)));
    let mut w = route("/b", 200);
    w.auth_wall = true;
    assert!(is_walled(&w));
    let mut l = route("/c", 307);
    l.redirect_chain = vec![crate::agent::types::RedirectHop {
        status: 307,
        location: "/login".into(),
    }];
    assert!(is_walled(&l));
    assert!(!is_walled(&route("/d", 200)));
}

#[test]
fn an_spa_shell_only_discovery_plans_no_input_case_and_says_why() {
    let mut probe = route("/.env", 200);
    probe.source = "probe".into();
    let mut ca = route("/zz-random", 200);
    ca.catch_all = true;
    let out = plan_routes(vec![spa_shell("/"), ca, probe], &Credentials::none());
    assert!(
        input_cases(&out).is_empty(),
        "no injection, boundary or negative case on a shell: {:?}",
        input_cases(&out)
            .iter()
            .map(|c| &c.title)
            .collect::<Vec<_>>()
    );
    // one NOT_APPLICABLE row per input technique, never sent
    let rows = ledger_rows(&out);
    let mut techs: Vec<&str> = rows.iter().map(|c| c.technique.as_str()).collect();
    techs.sort();
    assert_eq!(techs, ["boundary", "injection", "negative"]);
    assert!(
        rows.iter()
            .all(|c| c.source.as_deref() == Some(SRC_NOT_APPLICABLE)
                && c.title.contains("not applicable")
                && c.input_hint.contains("/ (SPA shell)")
                && c.input_hint.contains("/zz-random (catch-all)")),
        "{:?}",
        rows.iter()
            .map(|c| (&c.title, &c.input_hint))
            .collect::<Vec<_>>()
    );
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("no input test was planned"))
    );
    // the entry liveness and the sensitive-file probes stay, no CORS probe on a shell
    assert!(
        out.cases
            .iter()
            .any(|c| c.technique == "state_transition" && c.component == "/")
    );
    assert!(out.cases.iter().any(|c| c.component == "/.env"));
    assert!(!out.cases.iter().any(|c| c.title.contains("CORS")));
    // the rows are kept first when the plan is cut
    let key = plan_order(false);
    let r = rows[0];
    assert_eq!(
        key(r).1,
        0,
        "a ledger row is never the first thing a cut drops"
    );
}

#[test]
fn a_login_redirect_blocks_the_input_techniques_instead_of_calling_them_not_applicable() {
    let mut entry = route("/", 307);
    entry.final_url = Some("http://h/login".into());
    entry.redirect_chain = vec![crate::agent::types::RedirectHop {
        status: 307,
        location: "/login".into(),
    }];
    entry.auth_wall = true;
    entry.is_spa_shell = true;
    let out = plan_routes(vec![entry], &Credentials::none());
    assert!(input_cases(&out).is_empty());
    let rows = ledger_rows(&out);
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|c| c.source.as_deref() == Some(SRC_AUTH_WALL) && c.title.contains("login wall")),
        "{:?}",
        rows.iter().map(|c| &c.title).collect::<Vec<_>>()
    );
    assert!(out.notes.iter().any(|n| n.contains("login wall")));
    // liveness: the redirect is followed, so the final page is expected to answer 2xx, never
    // "expected 307" and never "expected 2xx, got 307"
    let live = out
        .cases
        .iter()
        .find(|c| c.technique == "state_transition" && c.component == "/")
        .unwrap();
    assert_eq!(live.expected_status, Some(200));
    assert!(live.expected_behavior.contains("redirect is followed"));
    assert_eq!(live.route_status, Some(307));
}

#[test]
fn a_redirect_without_a_recorded_chain_is_still_expected_to_redirect() {
    // discovery that does not record chains (an older report, a plain crawl): old behaviour
    let out = plan_routes(vec![route("/", 301)], &Credentials::none());
    let live = out
        .cases
        .iter()
        .find(|c| c.technique == "state_transition")
        .unwrap();
    assert_eq!(live.expected_status, Some(301));
    assert!(live.expected_behavior.contains("redirects as it did"));
    assert!(
        !crate::agent::exec::follows_redirects(live),
        "a case that expects a redirect is not redirected"
    );
    // while the one that expects the final page is
    let mut chained = route("/", 301);
    chained.redirect_chain = vec![crate::agent::types::RedirectHop {
        status: 301,
        location: "/home".into(),
    }];
    let out = plan_routes(vec![chained], &Credentials::none());
    let live = out
        .cases
        .iter()
        .find(|c| c.technique == "state_transition")
        .unwrap();
    assert!(crate::agent::exec::follows_redirects(live));
}

#[test]
fn routes_that_take_input_get_the_input_cases_and_xss_only_on_html_that_reads_parameters() {
    // a server-rendered page with a query string
    let mut page = route("/search?q=x", 200);
    page.input_surface = InputSurface::Query;
    let out = plan_routes(vec![route("/", 200), page], &Credentials::none());
    let titles: Vec<&str> = out.cases.iter().map(|c| c.title.as_str()).collect();
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("Reflected XSS probe (/search?q=x)"))
    );
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("SQL injection error probe (/search?q=x)"))
    );
    assert!(ledger_rows(&out).is_empty());
    // a JSON API route: the same cases, but nothing can reflect markup in a JSON body
    let mut api = route("/api/items", 200);
    api.is_api = true;
    api.content_type = "application/json".into();
    let out = plan_routes(vec![spa_shell("/"), api], &Credentials::none());
    let titles: Vec<&str> = out.cases.iter().map(|c| c.title.as_str()).collect();
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("SQL injection error probe (/api/items)")),
        "{titles:?}"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("Path traversal probe (/api/items)"))
    );
    assert!(
        !titles.iter().any(|t| t.contains("Reflected XSS")),
        "no XSS probe on a JSON route: {titles:?}"
    );
    assert!(ledger_rows(&out).is_empty());
    // a server-rendered form page: XSS and the form's POST cases
    let mut form = route("/contact", 200);
    form.has_form = true;
    let out = plan_routes(vec![route("/", 200), form], &Credentials::none());
    let titles: Vec<&str> = out.cases.iter().map(|c| c.title.as_str()).collect();
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("Reflected XSS probe (/contact)"))
    );
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("Oversized form value tolerance (/contact)"))
    );
    assert!(titles.iter().any(|t| t.starts_with("Mass assignment")));
    // the same page flagged as an SPA shell reflects nothing
    let mut shell_form = route("/contact", 200);
    shell_form.has_form = true;
    shell_form.is_spa_shell = true;
    shell_form.input_surface = InputSurface::Form; // discovery says there is a form
    let out = plan_routes(vec![route("/", 200), shell_form], &Credentials::none());
    assert!(!out.cases.iter().any(|c| c.title.contains("Reflected XSS")));
}

#[test]
fn a_route_behind_a_login_is_not_attacked_without_a_credential_and_is_with_one() {
    let mut api = route("/api/items", 401);
    api.is_api = true;
    api.auth_wall = true;
    api.content_type = "application/json".into();
    let routes = vec![spa_shell("/"), api];
    let out = plan_routes(routes.clone(), &Credentials::none());
    assert!(
        input_cases(&out)
            .iter()
            .all(|c| c.component != "/api/items"),
        "{:?}",
        input_cases(&out)
            .iter()
            .map(|c| &c.title)
            .collect::<Vec<_>>()
    );
    let rows = ledger_rows(&out);
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|c| c.source.as_deref() == Some(SRC_AUTH_WALL))
    );
    // what the wall does answer is still checked: a forged token must not open it
    assert!(out.cases.iter().any(|c| c.technique == "authz"
        && c.role.as_deref() == Some("forged")
        && c.component == "/api/items"));
    // with a credential the route is a target, and runs as that role
    let out = plan_routes(routes, &Credentials::none().with("user", "t"));
    assert!(ledger_rows(&out).is_empty());
    assert!(
        input_cases(&out)
            .iter()
            .any(|c| c.component == "/api/items" && c.role.as_deref() == Some("user"))
    );
}

/// spa-next: `/` is a 307 to /login, discovery records the login page's form on it.
fn walled_root() -> DiscoveredRoute {
    let mut r = spa_shell("/");
    r.status_code = 307;
    r.redirect_chain = vec![crate::agent::types::RedirectHop {
        status: 307,
        location: "/login?next=%2F".into(),
    }];
    r.auth_wall = true;
    r.has_form = true;
    r.input_surface = InputSurface::Form;
    r
}

#[test]
fn a_login_form_is_not_an_input_surface_and_the_api_is_the_target_once_there_is_a_credential() {
    let root = walled_root();
    assert_eq!(
        surface_of(&root),
        InputSurface::None,
        "its form is the login form"
    );
    let mut login = route("/login", 200);
    login.auth_wall = true;
    login.has_form = true;
    login.input_surface = InputSurface::Form;
    assert_eq!(surface_of(&login), InputSurface::None);
    let mut api = route("/api/orders", 401);
    api.is_api = true;
    api.auth_wall = true;
    api.source = "js".into();
    api.content_type = "application/json".into();
    api.input_surface = InputSurface::Json;
    // the 401 of an API route does not make its JSON surface a login form
    assert_eq!(surface_of(&api), InputSurface::Json);
    let routes = vec![root, login, api];
    // no credential: nothing to aim at, the wall is the blocker
    let out = plan_routes(routes.clone(), &Credentials::none());
    assert!(input_cases(&out).is_empty());
    assert_eq!(ledger_rows(&out).len(), 3);
    // with one: every input case goes to the API, as that role, never to `/`
    let creds = Credentials::none().with("alice", "t");
    let out = plan_routes(routes, &creds);
    assert!(ledger_rows(&out).is_empty());
    let input = input_cases(&out);
    assert!(!input.is_empty());
    assert!(
        input
            .iter()
            .all(|c| c.component == "/api/orders" && c.role.as_deref() == Some("alice")),
        "{:?}",
        input
            .iter()
            .map(|c| (&c.title, &c.role))
            .collect::<Vec<_>>()
    );
    assert!(
        input
            .iter()
            .any(|c| c.payload.as_deref().is_some_and(|p| p.starts_with("q=")))
            && input
                .iter()
                .any(|c| c.payload.as_deref().is_some_and(|p| p.contains("limit="))),
        "the SQL probe reaches ?q= and the numeric one ?limit="
    );
    assert!(!out.cases.iter().any(|c| c.title.contains("Reflected XSS")));
    // the entry liveness is made as the test account: anonymous it only meets the wall
    let live = out
        .cases
        .iter()
        .find(|c| c.technique == "state_transition" && c.component == "/")
        .unwrap();
    assert_eq!(live.role.as_deref(), Some("alice"));
    assert_eq!(live.expected_status, Some(200));
}

#[test]
fn a_catch_all_route_is_never_a_target() {
    let mut ca = route("/anything", 200);
    ca.catch_all = true;
    ca.has_form = true;
    ca.is_api = true;
    let mut ca2 = route("/other", 200);
    ca2.catch_all = true;
    let out = plan_routes(
        vec![route("/", 200), ca.clone(), ca2.clone()],
        &Credentials::none(),
    );
    assert!(
        out.cases
            .iter()
            .all(|c| c.component != "/anything" && c.component != "/other"),
        "{:?}",
        out.cases.iter().map(|c| &c.component).collect::<Vec<_>>()
    );
    // the LLM may not aim at one either
    let all = [route("/", 200), ca, ca2];
    let known = Known::new(&all);
    assert!(known.find("/anything").is_none() && known.find("/").is_some());
}

#[test]
fn with_a_spec_the_baseline_aims_at_pages_and_leaves_the_api_to_the_spec() {
    let doc: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/qa-api/openapi.json")).unwrap();
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let spec = SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "fixture".into(),
    };
    // the crawl found an API route at the root (an API-only target): no baseline input case
    // at it, the spec's operations are tested instead
    let mut root = route("/", 401);
    root.is_api = true;
    root.input_surface = InputSurface::Json;
    root.content_type = "application/json".into();
    let mut d = Discovery::default();
    d.routes = vec![root];
    d.spec = Some(spec.clone());
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    assert!(
        !out.cases.iter().any(|c| c.component == "/"
            && c.technique != "authz"
            && c.technique != "state_transition"),
        "{:?}",
        out.cases
            .iter()
            .filter(|c| c.component == "/")
            .map(|c| &c.title)
            .collect::<Vec<_>>()
    );
    assert!(ledger_rows(&out).is_empty());
    // a crawled page with a form is still a target
    let mut form = route("/contact", 200);
    form.has_form = true;
    d.routes = vec![route("/", 200), form];
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    assert!(
        out.cases
            .iter()
            .any(|c| c.component == "/contact" && c.technique == "injection")
    );
}

#[test]
fn with_a_spec_and_with_nothing_discovered_the_plan_is_as_before() {
    // nothing at all: the root is probed (nothing says a surface is missing)
    let out = plan_routes(vec![], &Credentials::none());
    assert!(ledger_rows(&out).is_empty());
    assert!(input_cases(&out).iter().any(|c| c.component == "/"));
    // a spec supplies the operations: no row claims there is no surface
    let doc: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/qa-api/openapi.json")).unwrap();
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let mut d = Discovery::default();
    d.routes = vec![spa_shell("/")];
    d.spec = Some(SpecDoc {
        doc,
        ops,
        base_path: String::new(),
        source: "fixture".into(),
    });
    let out = plan_cases(None, "http://h", "standard", &d, None, &Credentials::none());
    assert!(ledger_rows(&out).is_empty());
    assert!(
        out.cases
            .iter()
            .any(|c| c.technique == "injection" && c.component == "/search")
    );
}

#[test]
fn raw_cases_validate_headers_and_content_type_and_dedupe_distinctly() {
    let routes = vec![route("/admin", 403), route("/xml", 200)];
    let known = Known::new(&routes);
    let creds = Credentials::none().with("user", "tok");
    let parse = |j: &str| {
        let raw: RawCase = serde_json::from_str(j).unwrap();
        validate_raw(&raw, &known, &creds)
    };
    let c1 = parse(
        r#"{"title":"Bypass via X-Original-URL","component":"/admin","method":"GET","technique":"authz","headers":{"X-Original-URL":"/admin","X-Forwarded-For":"127.0.0.1"}}"#,
    )
    .unwrap();
    let c2 = parse(
        r#"{"title":"Bypass via X-Rewrite-URL","component":"/admin","method":"GET","technique":"authz","headers":{"X-Rewrite-URL":"/admin"}}"#,
    )
    .unwrap();
    assert_ne!(key_of(&c1), key_of(&c2));
    assert!(
        c1.headers
            .iter()
            .any(|(k, v)| k == "X-Original-URL" && v == "/admin")
    );

    let xml = parse(
        r#"{"title":"XXE probe","component":"/xml","method":"POST","technique":"injection","payload":"<a/>","content_type":"application/xml"}"#,
    )
    .unwrap();
    assert_eq!(xml.content_type.as_deref(), Some("application/xml"));

    // LLM cannot inject Authorization/Cookie/CRLF headers
    assert!(
        parse(r#"{"title":"bad","component":"/admin","technique":"authz","headers":{"Authorization":"Bearer steal"}}"#).is_err()
    );
    assert!(
        parse(r#"{"title":"bad","component":"/admin","technique":"authz","headers":{"X-Test":"a\r\nb"}}"#).is_err()
    );
}

#[test]
fn empty_discovery_with_operator_instructions_fallbacks_to_root_and_instruction_paths() {
    let d = Discovery::default();
    let mut routes = d.routes.clone();
    if routes.iter().all(|r| r.catch_all) {
        routes.push(DiscoveredRoute {
            path: "/".to_string(),
            method: "GET".to_string(),
            status_code: 200,
            content_type: "text/html".to_string(),
            source: "target".to_string(),
            title: Some("Root Endpoint".to_string()),
            ..Default::default()
        });
    }
    let instr = "Check unauthenticated access to /api/auth/session; Probe 100KB boundary size on chat input";
    let path_re =
        regex::Regex::new(r"(/[a-zA-Z0-9_\-\.\{\}]+(?:/[a-zA-Z0-9_\-\.\{\}]+)*)").unwrap();
    for cap in path_re.captures_iter(instr) {
        let p = cap[1].trim_end_matches(&['.', ',', ';', ':', ')', ']', '"', '\'', ' '][..]);
        if p.starts_with('/') && p.len() > 1 && !routes.iter().any(|r| r.path == p) {
            routes.push(DiscoveredRoute {
                path: p.to_string(),
                method: "GET".to_string(),
                status_code: 200,
                content_type: "application/json".to_string(),
                source: "operator_instructions".to_string(),
                title: Some(format!("Operator instruction endpoint: {p}")),
                ..Default::default()
            });
        }
    }
    let effective_known = Known::new(&routes);
    assert!(effective_known.find("/").is_some());
    assert!(effective_known.find("/api/auth/session").is_some());

    let creds = Credentials::none();
    let raw_url = RawCase {
        title: "Test Full URL".into(),
        component: "https://myvapi.com/api/auth/session".into(),
        method: Some("GET".into()),
        technique: "authz".into(),
        input_hint: None,
        payload: None,
        headers: None,
        content_type: None,
        expected_behavior: None,
        expected_status: Some(401),
        risk_level: Some("high".into()),
    };
    let c =
        validate_raw(&raw_url, &effective_known, &creds).expect("full URL should resolve to path");
    assert_eq!(c.component, "/api/auth/session");

    let raw_slash = RawCase {
        component: "/api/auth/session/".into(),
        ..raw_url.clone()
    };
    let c2 =
        validate_raw(&raw_slash, &effective_known, &creds).expect("trailing slash should resolve");
    assert_eq!(c2.component, "/api/auth/session");

    let raw_query = RawCase {
        component: "/api/auth/session?token=test".into(),
        ..raw_url
    };
    let c3 = validate_raw(&raw_query, &effective_known, &creds)
        .expect("query string should resolve to base path");
    assert_eq!(c3.component, "/api/auth/session");
}

#[test]
fn traditional_web_app_without_query_links_evaluates_injection_and_directives() {
    let mut d = Discovery::default();
    // 41 routes with no query parameters or forms, typical HTML5/SSR web app
    d.routes = vec![
        route("/", 200),
        route("/about", 200),
        route("/pricing", 200),
        route("/careers", 200),
    ];
    let instr = "Strict QA and verify resilience, contracts, and authz; Inject prompt override canary on chat; Check unauthenticated access to /api/auth/session; Probe 100KB boundary size on chat input";
    let out = plan_cases_remembered_with_whitebox(
        None,
        "https://app-prod.nuhire.in/",
        "standard",
        &d,
        Some(instr),
        &Credentials::none(),
        42,
        None,
        None,
        None,
    );
    // Directives and fallback baseline produce real injection cases
    let injection_cases: Vec<&PlannedCase> = out
        .cases
        .iter()
        .filter(|c| c.technique == "injection")
        .collect();
    assert!(!injection_cases.is_empty(), "must plan injection cases");
    // No dummy placeholder ledger rows remain for injection
    assert!(
        injection_cases.iter().all(|c| !c.is_ledger_row()),
        "all planned injection cases must be real tests, no placeholder rows"
    );
    // Directives case is present
    assert!(
        out.cases
            .iter()
            .any(|c| c.source.as_deref() == Some("directives") && c.technique == "injection"),
        "prompt override canary must be planned as a directives injection case"
    );
    // Directive cases have class 0 priority
    for c in out
        .cases
        .iter()
        .filter(|c| c.source.as_deref() == Some("directives"))
    {
        assert_eq!(
            crate::agent::types::case_priority(c).0,
            0,
            "directives cases must have class 0 priority"
        );
    }
}

#[test]
fn test_attack_dag_resolution() {
    use super::dag::{AttackDag, AttackDagNode};
    let mut dag = AttackDag::new();
    dag.add_node(AttackDagNode::new("setup_user", vec![]));
    dag.add_node(AttackDagNode::new(
        "escalate_role",
        vec!["setup_user".into()],
    ));
    dag.add_node(AttackDagNode::new(
        "exfiltrate_tenant",
        vec!["escalate_role".into()],
    ));
    let sorted = dag.topological_order().expect("cycle detected");
    assert_eq!(
        sorted,
        vec!["setup_user", "escalate_role", "exfiltrate_tenant"]
    );
}

#[test]
fn test_attack_dag_cycle_detection() {
    use super::dag::{AttackDag, AttackDagNode};
    let mut dag = AttackDag::new();
    dag.add_node(AttackDagNode::new("node_a", vec!["node_b".into()]));
    dag.add_node(AttackDagNode::new("node_b", vec!["node_a".into()]));
    assert!(dag.detect_cycle());
    assert!(dag.is_cyclic());
    assert!(dag.topological_order().is_err());
}

#[test]
fn test_attack_dag_self_loop() {
    use super::dag::{AttackDag, AttackDagNode};
    let mut dag = AttackDag::new();
    dag.add_node(AttackDagNode::new("node_a", vec!["node_a".into()]));
    assert!(dag.detect_cycle());
}

#[test]
fn test_attack_dag_conversion_to_stateful_steps() {
    use super::dag::{AttackDag, AttackDagNode};
    let mut dag = AttackDag::new();
    dag.add_node(
        AttackDagNode::new("step1", vec![])
            .with_component("/api/auth/register")
            .with_method("POST")
            .with_payload(serde_json::json!({"user": "test"}))
            .with_expected_status(201),
    );
    dag.add_node(
        AttackDagNode::new("step2", vec!["step1".into()])
            .with_component("/api/v1/tenant")
            .with_method("GET")
            .with_expected_status(403),
    );
    let steps = dag.to_stateful_steps().expect("valid steps");
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].step_number, 1);
    assert_eq!(steps[0].path, "/api/auth/register");
    assert_eq!(steps[1].step_number, 2);
    assert_eq!(steps[1].path, "/api/v1/tenant");

    let planned_case = dag
        .into_planned_case("Stateful Multi-step Attack", "/api/v1/tenant")
        .expect("valid case");
    assert_eq!(planned_case.technique, "state_transition");
    assert_eq!(planned_case.stateful_steps.as_ref().unwrap().len(), 2);
}

#[test]
fn test_synthesize_attack_dag_deterministic() {
    let routes = vec![
        route("/", 200),
        route("/api/auth/login", 200),
        route("/api/v1/tenant", 403),
    ];
    let dag = super::llm::synthesize_attack_dag(
        None,
        "https://target.local",
        &routes,
        Some("BOLA/IDOR on /api/v1/tenant"),
    );
    assert_eq!(dag.nodes.len(), 3);
    let order = dag.topological_order().expect("valid topological order");
    assert_eq!(
        order,
        vec!["setup_user", "escalate_role", "exfiltrate_tenant"]
    );
}

#[test]
fn test_dynamic_directives_json_parsing_and_synthesis() {
    let mut d = Discovery::default();
    d.routes = vec![
        route("/", 200),
        route("/api/auth/session", 401),
        route("/api/v1/tenant", 403),
        route("/chat", 200),
    ];
    let directives_json = r#"{
        "focus_areas": ["BOLA/IDOR on /api/v1/tenant", "JWT algorithm confusion", "Prompt injection canary"],
        "boundary_rules": ["Stay within /api paths", "Do not fuzz destructive deletion"],
        "rules_of_engagement": "Adversarial assessment targeting authorization boundaries and input sanitization",
        "canary_token": "CANARY_RECON_7A3B"
    }"#;
    let cases = super::directives::plan_directives(directives_json, &d, &Credentials::none());
    assert!(
        !cases.is_empty(),
        "expected synthesized cases from dynamic directives"
    );
    assert!(
        cases
            .iter()
            .any(|c| c.title.contains("BOLA/IDOR") && c.component == "/api/v1/tenant"),
        "expected BOLA/IDOR case on /api/v1/tenant"
    );
    assert!(
        cases
            .iter()
            .any(|c| c.title.contains("JWT algorithm confusion")),
        "expected JWT algorithm confusion case"
    );
    let canary_case = cases
        .iter()
        .find(|c| c.title.contains("CANARY_RECON_7A3B"))
        .expect("expected canary case with custom token");
    assert!(
        canary_case
            .payload
            .as_ref()
            .unwrap()
            .contains("CANARY_RECON_7A3B")
    );
}

#[test]
fn test_attack_dag_prerequisite_guard_execution_and_clean_defect_metrics() {
    use super::dag::{
        AttackDag, AttackDagNode, SKIPPED_PREREQUISITE_FAILED, is_prerequisite_skipped,
    };
    use crate::agent::triage::derive_defects;

    let mut dag = AttackDag::new();
    dag.add_node(
        AttackDagNode::new("setup_login", vec![])
            .with_component("/api/auth/login")
            .with_method("POST"),
    );
    dag.add_node(
        AttackDagNode::new("escalate_role", vec!["setup_login".into()])
            .with_component("/api/v1/roles")
            .with_method("POST"),
    );
    dag.add_node(
        AttackDagNode::new("exfiltrate_tenant", vec!["escalate_role".into()])
            .with_component("/api/v1/tenant/data")
            .with_method("GET"),
    );

    // Runner simulates a failure in the initial prerequisite step
    let results = dag
        .execute_guarded(|node| {
            let mut res = CaseExecutionResult::default();
            res.case_id = node.id.clone();
            res.component = node.component.clone().unwrap();
            res.method = node.method.clone().unwrap();

            if node.id == "setup_login" {
                // Prerequisite step fails
                res.status = "FAIL".into();
                res.status_code = Some(500);
                res.failure_reason = Some("Authentication service unavailable (HTTP 500)".into());
            } else {
                // Downstream steps should never reach here!
                res.status = "PASS".into();
                res.status_code = Some(200);
            }
            res
        })
        .expect("guarded execution succeeds");

    assert_eq!(results.len(), 3);

    // 1. First step failed as executed
    assert_eq!(results[0].case_id, "setup_login");
    assert_eq!(results[0].status, "FAIL");
    assert!(results[0].was_sent());
    assert!(!is_prerequisite_skipped(&results[0]));

    // 2. Downstream dependent step 2 marked SKIPPED (prerequisite failed)
    assert_eq!(results[1].case_id, "escalate_role");
    assert_eq!(results[1].status, SKIPPED_PREREQUISITE_FAILED);
    assert!(is_prerequisite_skipped(&results[1]));
    assert!(!results[1].was_sent());
    assert!(
        results[1]
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("node 'setup_login' did not succeed")
    );

    // 3. Downstream dependent step 3 marked SKIPPED (prerequisite failed)
    assert_eq!(results[2].case_id, "exfiltrate_tenant");
    assert_eq!(results[2].status, SKIPPED_PREREQUISITE_FAILED);
    assert!(is_prerequisite_skipped(&results[2]));
    assert!(!results[2].was_sent());
    assert!(
        results[2]
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("node 'escalate_role' did not succeed")
    );

    // 4. Defect metrics verification: exactly 1 defect from setup_login, 0 from downstream skipped nodes
    let defects = derive_defects(&results);
    assert_eq!(
        defects.len(),
        1,
        "defect metrics must not be polluted by prerequisite-skipped nodes"
    );
    assert_eq!(defects[0].component, "/api/auth/login");
}

#[test]
fn test_attack_dag_partition_independent_branches() {
    use super::dag::{AttackDag, AttackDagNode};

    let mut dag = AttackDag::new();

    // Branch 1: User privilege escalation chain
    dag.add_node(AttackDagNode::new("user_reg", vec![]));
    dag.add_node(AttackDagNode::new("user_auth", vec!["user_reg".into()]));
    dag.add_node(AttackDagNode::new(
        "user_escalate",
        vec!["user_auth".into()],
    ));

    // Branch 2: Admin settings injection chain (independent of Branch 1)
    dag.add_node(AttackDagNode::new("admin_login", vec![]));
    dag.add_node(AttackDagNode::new(
        "admin_inject",
        vec!["admin_login".into()],
    ));

    // Branch 3: Health probe (independent single-node branch)
    dag.add_node(AttackDagNode::new("ping_health", vec![]));

    let branches = dag.partition_independent_branches();
    assert_eq!(
        branches.len(),
        3,
        "expected 3 disjoint, parallel attack branches"
    );

    // Verify Branch 1
    let b1_ids: Vec<&str> = branches[0].iter().map(|n| n.id.as_str()).collect();
    assert_eq!(b1_ids, vec!["user_reg", "user_auth", "user_escalate"]);

    // Verify Branch 2
    let b2_ids: Vec<&str> = branches[1].iter().map(|n| n.id.as_str()).collect();
    assert_eq!(b2_ids, vec!["admin_login", "admin_inject"]);

    // Verify Branch 3
    let b3_ids: Vec<&str> = branches[2].iter().map(|n| n.id.as_str()).collect();
    assert_eq!(b3_ids, vec!["ping_health"]);

    // Test empty DAG
    let empty_dag = AttackDag::new();
    assert!(empty_dag.partition_independent_branches().is_empty());

    // Test single connected chain DAG
    let mut single_dag = AttackDag::new();
    single_dag.add_node(AttackDagNode::new("s1", vec![]));
    single_dag.add_node(AttackDagNode::new("s2", vec!["s1".into()]));
    let single_branches = single_dag.partition_independent_branches();
    assert_eq!(single_branches.len(), 1);
    assert_eq!(single_branches[0].len(), 2);
}
