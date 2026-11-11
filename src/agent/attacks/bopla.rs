//! BOPLA (OWASP API3:2023 Broken Object Property Level Authorization) probes:
//! - Excessive Data Exposure on GET API read endpoints (`ProbeOracle::ExcessiveDataExposure`).
//! - Stateful Mass Assignment on create/update API flows with read-back verification (`role=admin`,
//!   `is_admin=true`).

use std::collections::{BTreeSet, HashMap};

use serde_json::{Value, json};

use crate::agent::discover::Discovery;
use crate::agent::exec::Credentials;
use crate::agent::plan::{Depth, mk, user_or_anon};
use crate::agent::types::{PlannedCase, ProbeOracle, StatefulStep};
use crate::qa::api::synth;

fn is_sensitive_read_path(p: &str) -> u8 {
    let l = p.to_ascii_lowercase();
    if l.contains("/me") || l.contains("profile") || l.contains("user") || l.contains("account") {
        0
    } else if l.contains("admin") || l.contains("order") || l.contains("billing") {
        1
    } else {
        2
    }
}

fn is_credential_flow(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "login", "logout", "signin", "signup", "register", "auth", "token", "password", "reset",
        "verify", "otp",
    ]
    .iter()
    .any(|k| p.contains(k))
}

fn excessive_exposure_cases(d: &Discovery, creds: &Credentials, cap: usize) -> Vec<PlannedCase> {
    let acting = user_or_anon(creds);
    let has_actor = creds.actor().is_some();
    let mut candidates: Vec<(u8, String, String, bool, &'static str)> = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(spec) = &d.spec {
        for api in spec.api_ops().into_iter().filter(|a| {
            a.method == "GET" && (!a.secured || has_actor) && !is_credential_flow(&a.path)
        }) {
            let path_vals: HashMap<String, String> = crate::qa::api::collection_of(&api)
                .and_then(|(list, param)| {
                    d.ids
                        .get(&list)
                        .and_then(|v| v.first())
                        .map(|id| HashMap::from([(param, id.clone())]))
                })
                .unwrap_or_default();
            let comp = synth::build_url(&spec.base_path, &api.path, &path_vals, &[]);
            if !comp.contains('{') && seen.insert(comp.clone()) {
                candidates.push((
                    is_sensitive_read_path(&comp),
                    comp,
                    format!("GET {}", api.path),
                    api.secured,
                    "openapi",
                ));
            }
        }
    } else {
        for r in d.routes.iter().filter(|r| {
            r.method.eq_ignore_ascii_case("GET")
                && r.is_api
                && !r.catch_all
                && !r.is_spa_shell
                && !r.auth_wall
                && !r.path.contains(['{', '?'])
                && r.source != "probe"
                && (has_role(creds) || !matches!(r.status_code, 401 | 403))
        }) {
            if seen.insert(r.path.clone()) {
                candidates.push((
                    is_sensitive_read_path(&r.path),
                    r.path.clone(),
                    r.path.clone(),
                    matches!(r.status_code, 401 | 403),
                    "deterministic",
                ));
            }
        }
    }

    candidates.sort_by_key(|(prio, comp, _, _, _)| (*prio, comp.clone()));
    candidates
        .into_iter()
        .take(cap)
        .map(|(_, comp, label, secured, src)| {
            let role = if secured { acting.as_str() } else { "anon" };
            let mut c = mk(
                "state_transition",
                format!("Excessive data exposure check ({label})"),
                "GET",
                comp,
                "Read API object and verify secret/PII attributes are excluded from JSON output",
                None,
                "Response must exclude password hashes, salts, private keys, and sensitive PII tokens",
                None,
                "high",
                role,
                src,
            );
            c.secured = Some(secured);
            c.probe_oracle = Some(ProbeOracle::ExcessiveDataExposure);
            c
        })
        .collect()
}

fn has_role(creds: &Credentials) -> bool {
    creds.actor().is_some()
}

fn mass_assignment_cases(d: &Discovery, creds: &Credentials, cap: usize) -> Vec<PlannedCase> {
    let Some(spec) = &d.spec else {
        return Vec::new();
    };
    let acting = creds
        .non_admin_roles()
        .into_iter()
        .next()
        .or_else(|| creds.actor());
    let Some(actor_role) = acting else {
        return Vec::new();
    };

    let api_ops = spec.api_ops();
    let mut posts: Vec<_> = api_ops
        .iter()
        .filter(|a| {
            a.method == "POST"
                && !is_credential_flow(&a.path)
                && a.body.is_some()
                && !a.path.contains('{')
        })
        .collect();
    posts.sort_by_key(|a| is_sensitive_read_path(&a.path));

    let mut out = Vec::new();
    for post_op in posts.into_iter().take(cap) {
        let Some(body_schema) = &post_op.body else {
            continue;
        };
        let flat = synth::flatten(body_schema);
        let mut obj = match synth::synth(&flat, "body", "readyhai-", 0) {
            Value::Object(m) => m,
            _ => continue,
        };
        // Only inject fields that are not already part of the declared creation schema
        let declared = flat.get("properties").and_then(Value::as_object);
        let declares = |k: &str| declared.is_some_and(|p| p.contains_key(k));
        if !declares("role") {
            obj.insert("role".into(), json!("admin"));
        }
        if !declares("is_admin") {
            obj.insert("is_admin".into(), json!(true));
        }
        obj.entry("permissions".to_string())
            .or_insert_with(|| json!(["*"]));

        let comp = format!("{}{}", spec.base_path, post_op.path);
        let post_payload = Value::Object(obj).to_string();
        let violation = "mass_assignment:json_eq:role=admin || json_eq:is_admin=true";

        let item_get = spec.ops.iter().find(|g| {
            g.method == "GET"
                && g.path
                    .strip_prefix(post_op.path.trim_end_matches('/'))
                    .and_then(|r| r.strip_prefix('/'))
                    .is_some_and(|s| s.starts_with('{') && s.ends_with('}') && !s.contains('/'))
        });

        let mut steps = vec![StatefulStep {
            step_number: 1,
            actor: actor_role.clone(),
            method: "POST".into(),
            path: comp.clone(),
            payload: Some(post_payload),
            extract_vars: Some(vec![
                "id".into(),
                "uuid".into(),
                "user_id".into(),
                "item_id".into(),
            ]),
            expected_status: None,
            violation_condition: Some(violation.into()),
        }];

        if let Some(_g) = item_get {
            steps.push(StatefulStep {
                step_number: 2,
                actor: actor_role.clone(),
                method: "GET".into(),
                path: format!("{}/{{{{id}}}}", comp.trim_end_matches('/')),
                payload: None,
                extract_vars: None,
                expected_status: None,
                violation_condition: Some(violation.into()),
            });
        }

        let mut c = mk(
            "boundary",
            format!("BOPLA mass assignment check (POST {})", post_op.path),
            "POST",
            comp,
            "Inject unpermitted privilege fields (`role`, `is_admin`) alongside valid schema fields and read back",
            None,
            "Unpermitted privilege attributes are stripped or rejected with 4xx, never persisted as admin",
            None,
            "high",
            &actor_role,
            "openapi",
        );
        c.secured = Some(post_op.secured);
        c.stateful_steps = Some(steps);
        out.push(c);
    }
    out
}

/// Plan read excessive-exposure checks and write mass-assignment chains for API endpoints.
pub fn plan_bopla_attacks(d: &Discovery, creds: &Credentials, depth: Depth) -> Vec<PlannedCase> {
    let (read_cap, write_cap) = match depth {
        Depth::Quick => return Vec::new(),
        Depth::Standard => (3, 1),
        Depth::Deep => (6, 2),
    };
    let mut out = Vec::new();
    out.extend(excessive_exposure_cases(d, creds, read_cap));
    out.extend(mass_assignment_cases(d, creds, write_cap));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::budget::RunBudget;
    use crate::agent::discover::{Discovery, SpecDoc};
    use crate::agent::exec::{Credentials, ExecOptions, execute_cases_gated};
    use crate::agent::types::{DiscoveredRoute, InputSurface, ProbeOracle};
    use crate::qa::plan::Op;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[test]
    fn detects_excessive_data_exposure_and_stateful_mass_assignment_with_zero_fp_on_clean_create() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let store: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let store_w = store.clone();
        let store_r = store.clone();

        let url = rt.block_on(async move {
            let app = Router::new()
                .route(
                    "/api/me",
                    get(|| async {
                        (
                            StatusCode::OK,
                            Json(json!({
                                "id": 1,
                                "email": "alice@example.com",
                                "password_hash": "$2b$12$abcdefghijklmnopqrstuuVwxyz01234567890123456",
                                "totp_secret": "JBSWY3DPEHPK3PXP"
                            })),
                        )
                    }),
                )
                .route(
                    "/api/users",
                    post(move |Json(mut body): Json<serde_json::Value>| {
                        let st = store_w.clone();
                        async move {
                            let mut guard = st.lock().unwrap();
                            let id = guard.len() + 1;
                            if let Some(obj) = body.as_object_mut() {
                                obj.insert("id".into(), json!(id));
                            }
                            guard.push(body.clone());
                            (StatusCode::CREATED, Json(body))
                        }
                    }),
                )
                .route(
                    "/api/users/{id}",
                    get(move || {
                        let st = store_r.clone();
                        async move {
                            let guard = st.lock().unwrap();
                            if let Some(last) = guard.last() {
                                (StatusCode::OK, Json(last.clone()))
                            } else {
                                (StatusCode::NOT_FOUND, Json(json!({"error": "missing"})))
                            }
                        }
                    }),
                )
                .route(
                    "/api/clean-orders",
                    post(|Json(body): Json<serde_json::Value>| async move {
                        (
                            StatusCode::CREATED,
                            Json(json!({"id": 7, "item": body.get("item").cloned().unwrap_or(json!("x"))})),
                        )
                    }),
                )
                .route(
                    "/api/clean-profile",
                    get(|| async {
                        (StatusCode::OK, Json(json!({"sub": "user", "role": "user"})))
                    }),
                );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            format!("http://{addr}")
        });

        let doc = json!({
            "openapi": "3.0.3",
            "info": {"title": "BoplaTest", "version": "1"},
            "paths": {
                "/api/me": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/api/users": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "required": ["username"],
                                "properties": {"username": {"type": "string"}}
                            }}}
                        },
                        "responses": {"201": {"description": "created"}}
                    }
                },
                "/api/users/{id}": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/api/clean-orders": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "required": ["item"],
                                "properties": {"item": {"type": "string"}}
                            }}}
                        },
                        "responses": {"201": {"description": "created"}}
                    }
                },
                "/api/clean-profile": {
                    "get": {
                        "security": [{"bearer": []}],
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        });

        let mut d = Discovery::default();
        d.routes.push(DiscoveredRoute {
            path: "/api/me".into(),
            method: "GET".into(),
            status_code: 200,
            is_api: true,
            input_surface: InputSurface::None,
            ..Default::default()
        });
        d.spec = Some(SpecDoc {
            base_path: "".into(),
            source: "openapi.json".into(),
            doc,
            ops: vec![
                Op {
                    method: "GET".into(),
                    path: "/api/me".into(),
                    operation_id: None,
                    secured: false,
                    has_body: false,
                },
                Op {
                    method: "GET".into(),
                    path: "/api/clean-profile".into(),
                    operation_id: None,
                    secured: true,
                    has_body: false,
                },
                Op {
                    method: "POST".into(),
                    path: "/api/users".into(),
                    operation_id: None,
                    secured: false,
                    has_body: true,
                },
                Op {
                    method: "GET".into(),
                    path: "/api/users/{id}".into(),
                    operation_id: None,
                    secured: false,
                    has_body: false,
                },
                Op {
                    method: "POST".into(),
                    path: "/api/clean-orders".into(),
                    operation_id: None,
                    secured: false,
                    has_body: true,
                },
            ],
        });

        let creds = Credentials::default().with("user", "u-tok");
        assert!(plan_bopla_attacks(&d, &creds, Depth::Quick).is_empty());

        let mut cases = plan_bopla_attacks(&d, &creds, Depth::Deep);
        assert!(
            cases.iter().any(|c| matches!(
                c.probe_oracle,
                Some(ProbeOracle::ExcessiveDataExposure)
            ) && c.component == "/api/me"),
            "expected ExcessiveDataExposure probe on /api/me: {cases:?}"
        );
        assert!(
            cases.iter().any(|c| matches!(
                c.probe_oracle,
                Some(ProbeOracle::ExcessiveDataExposure)
            ) && c.component == "/api/clean-profile"),
            "expected ExcessiveDataExposure probe on secured /api/clean-profile: {cases:?}"
        );
        assert!(
            cases.iter().all(|c| !matches!(
                c.probe_oracle,
                Some(ProbeOracle::ExcessiveDataExposure)
            ) || c.technique != "authz"),
            "ExcessiveDataExposure cases must not use technique=authz (would expect denial): {cases:?}"
        );
        assert!(
            cases
                .iter()
                .any(|c| c.stateful_steps.is_some() && c.component == "/api/users"),
            "expected stateful mass-assignment chain on /api/users: {cases:?}"
        );
        for (i, c) in cases.iter_mut().enumerate() {
            c.id = format!("BOPLA-{:03}", i + 1);
        }
        let opts = ExecOptions {
            credentials: creds,
            ..Default::default()
        };
        let mut budget = RunBudget::new(100, 100, std::time::Duration::from_secs(30), 50.0);
        let results = execute_cases_gated(&cases, &url, &opts, &mut budget, None);

        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/api/me"),
            "expected FAIL for excessive_data_exposure on /api/me: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/api/clean-profile"),
            "secured clean profile read must not false-positive on authz: {results:?}"
        );
        assert!(
            results.iter().any(|r| {
                r.status == "FAIL"
                    && r.component == "/api/users"
                    && r.oracle
                        .as_ref()
                        .is_some_and(|o| o.checks.iter().any(|k| k.code == "mass_assignment"))
            }),
            "expected FAIL for persisted mass assignment on /api/users: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/api/clean-orders"),
            "clean DTO filtering endpoint must not false-positive: {results:?}"
        );
    }
}
