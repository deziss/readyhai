//! Business-logic, TOCTOU concurrency, HTTP Parameter Pollution (HPP), and GraphQL probes.

use std::collections::{BTreeSet, HashMap};

use serde_json::Value;

use crate::agent::discover::Discovery;
use crate::agent::exec::Credentials;
use crate::agent::plan::{Depth, mk, user_or_anon};
use crate::agent::types::{PlannedCase, ProbeOracle, StatefulStep};
use crate::qa::api::spec::Op as ApiOp;
use crate::qa::api::synth;

const SINGLE_USE_KEYWORDS: &[&str] = &[
    "redeem", "coupon", "voucher", "claim", "vote", "withdraw", "transfer", "checkout", "approve",
];

const SKIP_STEP_KEYWORDS: &[&str] = &[
    "checkout", "confirm", "approve", "complete", "finalize", "pay",
];

const FINANCIAL_KEYWORDS: &[&str] = &[
    "checkout", "pay", "payment", "transfer", "withdraw", "redeem", "coupon", "voucher", "refund",
];

const NEGATIVE_FIELD_NAMES: &[&str] = &[
    "quantity", "qty", "amount", "price", "credits", "units", "discount",
];

fn is_credential_flow(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "login", "logout", "signin", "signup", "register", "auth", "token", "password", "reset",
        "verify", "otp",
    ]
    .iter()
    .any(|k| p.contains(k))
}

fn contains_any(path: &str, keywords: &[&str]) -> bool {
    let p = path.to_ascii_lowercase();
    keywords.iter().any(|k| p.contains(k))
}

fn is_single_use_path(path: &str) -> bool {
    contains_any(path, SINGLE_USE_KEYWORDS)
}

fn is_skip_step_path(path: &str) -> bool {
    contains_any(path, SKIP_STEP_KEYWORDS)
}

fn is_financial_path(path: &str) -> bool {
    contains_any(path, FINANCIAL_KEYWORDS)
}

fn toctou_priority(path: &str) -> u8 {
    let p = path.to_ascii_lowercase();
    if [
        "withdraw", "redeem", "coupon", "voucher", "transfer", "checkout",
    ]
    .iter()
    .any(|k| p.contains(k))
    {
        0
    } else {
        1
    }
}

fn resolve_spec_url(base_path: &str, api: &ApiOp, d: &Discovery, prefer_unlikely: bool) -> String {
    let mut path_vals: HashMap<String, String> = if prefer_unlikely {
        crate::qa::api::unlikely_ids(api)
    } else {
        crate::qa::api::collection_of(api)
            .and_then(|(list, param)| {
                d.ids
                    .get(&list)
                    .and_then(|v| v.first())
                    .map(|id| HashMap::from([(param, id.clone())]))
            })
            .unwrap_or_default()
    };
    // Fill any remaining `{param}` segments deterministically when no harvested ID is available.
    for seg in api.path.split('/') {
        if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            path_vals
                .entry(name.to_string())
                .or_insert_with(|| if prefer_unlikely { "999999" } else { "1" }.to_string());
        }
    }
    synth::build_url(base_path, &api.path, &path_vals, &[])
}

fn synth_body_payload(api: &ApiOp) -> Option<String> {
    if let Some(schema) = &api.body {
        let flat = synth::flatten(schema);
        Some(synth::synth(&flat, "body", "readyhai-", 0).to_string())
    } else if api.body_required {
        Some("{}".into())
    } else {
        None
    }
}

fn toctou_cases(d: &Discovery, creds: &Credentials, cap: usize) -> Vec<PlannedCase> {
    if cap == 0 {
        return Vec::new();
    }
    let acting = user_or_anon(creds);
    let has_actor = creds.actor().is_some();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    if let Some(spec) = &d.spec {
        let mut ops: Vec<_> = spec
            .api_ops()
            .into_iter()
            .filter(|a| {
                matches!(a.method.as_str(), "POST" | "PUT" | "PATCH")
                    && (!a.secured || has_actor)
                    && !is_credential_flow(&a.path)
                    && is_single_use_path(&a.path)
            })
            .collect();
        ops.sort_by_key(|a| (toctou_priority(&a.path), a.path.clone()));

        for api in ops {
            let comp = resolve_spec_url(&spec.base_path, &api, d, false);
            if comp.contains('{') || !seen.insert((api.method.clone(), comp.clone())) {
                continue;
            }
            let role = if api.secured { acting.as_str() } else { "anon" };
            let mut c = mk(
                "race",
                format!("TOCTOU single-use race burst ({} {})", api.method, api.path),
                &api.method,
                comp,
                "Send concurrent requests to a single-use or balance-decrementing operation to detect double-spend/TOCTOU",
                synth_body_payload(&api),
                "At most one single-use execution succeeds and remaining balance never underflows below zero",
                None,
                "high",
                role,
                "openapi",
            );
            c.secured = Some(api.secured);
            c.concurrency_burst = Some(5);
            out.push(c);
            if out.len() >= cap {
                break;
            }
        }
        return out;
    }

    for r in d.routes.iter().filter(|r| {
        matches!(
            r.method.to_ascii_uppercase().as_str(),
            "POST" | "PUT" | "PATCH"
        ) && r.source != "probe"
            && !r.catch_all
            && !r.is_spa_shell
            && !r.auth_wall
            && !r.path.contains(['{', '?'])
            && !is_credential_flow(&r.path)
            && is_single_use_path(&r.path)
            && (has_actor || !matches!(r.status_code, 401 | 403))
    }) {
        let method = r.method.to_ascii_uppercase();
        if !seen.insert((method.clone(), r.path.clone())) {
            continue;
        }
        let secured = matches!(r.status_code, 401 | 403);
        let role = if secured { acting.as_str() } else { "anon" };
        let mut c = mk(
            "race",
            format!("TOCTOU single-use race burst ({method} {})", r.path),
            &method,
            r.path.clone(),
            "Send concurrent requests to a single-use operation to verify atomic state enforcement",
            Some("{}".into()),
            "At most one single-use execution succeeds and balance never goes negative",
            None,
            "high",
            role,
            "deterministic",
        );
        c.secured = Some(secured);
        c.route_status = Some(r.status_code);
        c.concurrency_burst = Some(5);
        out.push(c);
        if out.len() >= cap {
            break;
        }
    }
    out
}

fn negative_quantity_cases(d: &Discovery, creds: &Credentials, cap: usize) -> Vec<PlannedCase> {
    let Some(spec) = &d.spec else {
        return Vec::new();
    };
    if cap == 0 {
        return Vec::new();
    }
    let acting = user_or_anon(creds);
    let has_actor = creds.actor().is_some();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for api in spec.api_ops().into_iter().filter(|a| {
        matches!(a.method.as_str(), "POST" | "PUT" | "PATCH")
            && a.body.is_some()
            && (!a.secured || has_actor)
            && !is_credential_flow(&a.path)
    }) {
        let Some(body_schema) = &api.body else {
            continue;
        };
        let flat = synth::flatten(body_schema);
        let Value::Object(mut obj) = synth::synth(&flat, "body", "readyhai-", 0) else {
            continue;
        };
        let Some(props) = flat.get("properties").and_then(Value::as_object) else {
            continue;
        };
        let target_prop = props.keys().find(|k| {
            let kl = k.to_ascii_lowercase();
            NEGATIVE_FIELD_NAMES.contains(&kl.as_str())
        });
        let Some(prop_name) = target_prop else {
            continue;
        };
        let comp = resolve_spec_url(&spec.base_path, &api, d, false);
        if comp.contains('{') || !seen.insert((api.method.clone(), comp.clone(), prop_name.clone()))
        {
            continue;
        }
        obj.insert(prop_name.clone(), serde_json::json!(-1));
        let payload = Value::Object(obj).to_string();
        let role = if api.secured { acting.as_str() } else { "anon" };

        let violation = if is_financial_path(&api.path) {
            "business_logic:status in 200..=299 || json_lt:total=0 || json_lt:amount=0 || json_lt:balance=0 || json_lt:credits=0"
        } else {
            "business_logic:json_lt:total=0 || json_lt:amount=0 || json_lt:balance=0 || json_lt:credits=0"
        };

        let mut c = mk(
            "boundary",
            format!(
                "Negative `{prop_name}` business-logic check ({} {})",
                api.method, api.path
            ),
            &api.method,
            comp.clone(),
            "Submit a negative numeric quantity/amount/credit value and verify the server rejects it or avoids negative totals",
            None,
            "Negative numeric inputs are rejected with 4xx and never yield negative totals/balances",
            None,
            "high",
            role,
            "openapi",
        );
        c.secured = Some(api.secured);
        c.stateful_steps = Some(vec![StatefulStep {
            step_number: 1,
            actor: role.to_string(),
            method: api.method.clone(),
            path: comp,
            payload: Some(payload),
            extract_vars: None,
            expected_status: None,
            violation_condition: Some(violation.into()),
        }]);
        out.push(c);
        if out.len() >= cap {
            break;
        }
    }
    out
}

fn skip_step_cases(d: &Discovery, creds: &Credentials, cap: usize) -> Vec<PlannedCase> {
    let Some(spec) = &d.spec else {
        return Vec::new();
    };
    if cap == 0 {
        return Vec::new();
    }
    let acting = user_or_anon(creds);
    let has_actor = creds.actor().is_some();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for api in spec.api_ops().into_iter().filter(|a| {
        matches!(a.method.as_str(), "POST" | "PUT" | "PATCH")
            && (!a.secured || has_actor)
            && !is_credential_flow(&a.path)
            && is_skip_step_path(&a.path)
            && a.path.contains('{')
    }) {
        let comp = resolve_spec_url(&spec.base_path, &api, d, true);
        if comp.contains('{') || !seen.insert((api.method.clone(), comp.clone())) {
            continue;
        }
        let role = if api.secured { acting.as_str() } else { "anon" };
        let violation = "business_logic:status in 200..=299 && json_eq:status=approved || status in 200..=299 && json_eq:status=completed || status in 200..=299 && json_eq:status=confirmed || status in 200..=299 && json_eq:paid=true";

        let mut c = mk(
            "boundary",
            format!(
                "Workflow skip-step state-machine bypass ({} {})",
                api.method, api.path
            ),
            &api.method,
            comp.clone(),
            "Invoke terminal workflow transition on an uninitialized/nonexistent ID without prior steps",
            None,
            "Terminal workflow transition rejects nonexistent/unpaid prerequisite state cleanly with 4xx",
            None,
            "high",
            role,
            "openapi",
        );
        c.secured = Some(api.secured);
        c.stateful_steps = Some(vec![StatefulStep {
            step_number: 1,
            actor: role.to_string(),
            method: api.method.clone(),
            path: comp,
            payload: synth_body_payload(&api),
            extract_vars: None,
            expected_status: None,
            violation_condition: Some(violation.into()),
        }]);
        out.push(c);
        if out.len() >= cap {
            break;
        }
    }
    out
}

fn hpp_cases(d: &Discovery, creds: &Credentials, cap: usize) -> Vec<PlannedCase> {
    let Some(spec) = &d.spec else {
        return Vec::new();
    };
    if cap == 0 {
        return Vec::new();
    }
    let acting = user_or_anon(creds);
    let has_actor = creds.actor().is_some();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for api in spec
        .api_ops()
        .into_iter()
        .filter(|a| a.method == "GET" && (!a.secured || has_actor) && !is_credential_flow(&a.path))
    {
        let Some(qp) = api.params.iter().find(|p| p.loc == "query") else {
            continue;
        };
        let comp = resolve_spec_url(&spec.base_path, &api, d, false);
        if comp.contains('{') || !seen.insert((comp.clone(), qp.name.clone())) {
            continue;
        }
        let role = if api.secured { acting.as_str() } else { "anon" };
        let payload = format!("{}=1&{}=admin", qp.name, qp.name);
        let mut c = mk(
            "boundary",
            format!(
                "HTTP Parameter Pollution check (`{}` on {})",
                qp.name, api.path
            ),
            "GET",
            comp,
            "Send duplicate query parameter values to verify consistent parameter binding without server error or privilege override",
            Some(payload),
            "Consistent parameter validation without 5xx crash or unexpected privilege escalation",
            None,
            "low",
            role,
            "openapi",
        );
        c.secured = Some(api.secured);
        out.push(c);
        if out.len() >= cap {
            break;
        }
    }
    out
}

fn graphql_cases(d: &Discovery, creds: &Credentials, depth: Depth) -> Vec<PlannedCase> {
    let acting = user_or_anon(creds);
    let has_actor = creds.actor().is_some();
    let mut endpoints: Vec<(String, bool, &'static str, Option<u16>)> = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(spec) = &d.spec {
        for op in spec.ops.iter().filter(|o| {
            o.path.to_ascii_lowercase().contains("graphql")
                && (!o.secured || has_actor)
                && !o.path.contains('{')
        }) {
            let full = format!("{}{}", spec.base_path, op.path);
            if seen.insert(full.clone()) {
                endpoints.push((full, op.secured, "openapi", None));
            }
        }
    } else {
        for r in d.routes.iter().filter(|r| {
            r.path.to_ascii_lowercase().contains("graphql")
                && !r.catch_all
                && !r.is_spa_shell
                && !r.path.contains(['{', '?'])
                && (has_actor || !matches!(r.status_code, 401 | 403))
        }) {
            if seen.insert(r.path.clone()) {
                endpoints.push((
                    r.path.clone(),
                    matches!(r.status_code, 401 | 403),
                    "deterministic",
                    Some(r.status_code),
                ));
            }
        }
        if endpoints.is_empty() && depth == Depth::Deep {
            endpoints.push(("/graphql".into(), false, "deterministic", None));
        }
    }

    let mut out = Vec::new();
    for (comp, secured, src, st) in endpoints.into_iter().take(1) {
        let role = if secured { acting.as_str() } else { "anon" };
        let mut intro = mk(
            "authz",
            format!("GraphQL schema introspection exposure ({comp})"),
            "POST",
            comp.clone(),
            "Query `{__schema{queryType{name}types{name}}}` to check whether introspection is disabled in production",
            Some(r#"{"query":"{__schema{queryType{name}types{name}}}"}"#.into()),
            "GraphQL introspection is disabled or returns errors without full `__schema.types` metadata",
            None,
            "medium",
            role,
            src,
        );
        intro.secured = Some(secured);
        intro.route_status = st;
        intro.content_type = Some("application/json".into());
        intro.probe_oracle = Some(ProbeOracle::GraphqlIntrospection);
        out.push(intro);

        if depth == Depth::Deep {
            let aliases: Vec<String> = (0..12).map(|i| format!("a{i}:__typename")).collect();
            let batch_query = format!(r#"{{"query":"{{{}}}"}}"#, aliases.join(" "));
            let mut batch = mk(
                "boundary",
                format!("GraphQL alias batching check ({comp})"),
                "POST",
                comp,
                "Send 12 batched field aliases in one GraphQL query to verify alias/cost limits do not 5xx",
                Some(batch_query),
                "GraphQL enforces complexity limits or handles batched aliases cleanly without 5xx",
                None,
                "low",
                role,
                src,
            );
            batch.secured = Some(secured);
            batch.route_status = st;
            batch.content_type = Some("application/json".into());
            out.push(batch);
        }
    }
    out
}

/// Plan business-logic negative quantity, workflow skip-step, TOCTOU single-use bursts, HPP, and
/// GraphQL security probes.
pub fn plan_logic_attacks(d: &Discovery, creds: &Credentials, depth: Depth) -> Vec<PlannedCase> {
    let (toctou_cap, neg_cap, skip_cap, hpp_cap) = match depth {
        Depth::Quick => return Vec::new(),
        Depth::Standard => (2, 2, 2, 1),
        Depth::Deep => (3, 4, 3, 2),
    };
    let mut out = Vec::new();
    out.extend(toctou_cases(d, creds, toctou_cap));
    out.extend(negative_quantity_cases(d, creds, neg_cap));
    out.extend(skip_step_cases(d, creds, skip_cap));
    out.extend(hpp_cases(d, creds, hpp_cap));
    out.extend(graphql_cases(d, creds, depth));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::budget::RunBudget;
    use crate::agent::discover::{Discovery, SpecDoc};
    use crate::agent::exec::{Credentials, ExecOptions, execute_cases_gated};
    use crate::qa::plan::Op;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    };
    use tokio::net::TcpListener;

    #[test]
    fn detects_toctou_double_spend_negative_quantity_skip_step_and_graphql_with_clean_no_fp() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let balance = Arc::new(AtomicI64::new(100));
        let clean_redeemed = Arc::new(AtomicUsize::new(0));

        let url = rt.block_on(async move {
            let bal = balance.clone();
            let clean_r = clean_redeemed.clone();
            let app = Router::new()
                .route(
                    "/api/wallet/withdraw",
                    post(move || {
                        let bal = bal.clone();
                        async move {
                            // Deliberate TOCTOU: read balance, yield briefly, decrement without CAS
                            let cur = bal.load(Ordering::SeqCst);
                            if cur >= 40 {
                                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                                let after = bal.fetch_sub(40, Ordering::SeqCst) - 40;
                                return (StatusCode::OK, Json(json!({"ok": true, "balance": after})));
                            }
                            (StatusCode::BAD_REQUEST, Json(json!({"error": "insufficient"})))
                        }
                    }),
                )
                .route(
                    "/api/coupons/clean-redeem",
                    post(move || {
                        let c = clean_r.clone();
                        async move {
                            if c.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                                (StatusCode::OK, Json(json!({"redeemed": true})))
                            } else {
                                (StatusCode::CONFLICT, Json(json!({"error": "already redeemed"})))
                            }
                        }
                    }),
                )
                .route(
                    "/api/checkout",
                    post(|Json(body): Json<serde_json::Value>| async move {
                        let qty = body.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
                        let total = qty * 50;
                        (StatusCode::OK, Json(json!({"status": "completed", "total": total})))
                    }),
                )
                .route(
                    "/api/orders/{id}/approve",
                    post(|| async {
                        // Missing prerequisite check on nonexistent/uninitialized order
                        (StatusCode::OK, Json(json!({"status": "approved"})))
                    }),
                )
                .route(
                    "/graphql",
                    post(|Json(body): Json<serde_json::Value>| async move {
                        let q = body.get("query").and_then(|v| v.as_str()).unwrap_or("");
                        if q.contains("__schema") {
                            (
                                StatusCode::OK,
                                Json(json!({"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "User"}]}}})),
                            )
                        } else {
                            (StatusCode::OK, Json(json!({"data": {}})))
                        }
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
            "info": {"title": "LogicTest", "version": "1"},
            "paths": {
                "/api/wallet/withdraw": {
                    "post": {
                        "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"amount": {"type": "integer"}}}}}},
                        "responses": {"200": {"description": "ok"}}
                    }
                },
                "/api/coupons/clean-redeem": {
                    "post": {
                        "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"code": {"type": "string"}}}}}},
                        "responses": {"200": {"description": "ok"}}
                    }
                },
                "/api/checkout": {
                    "post": {
                        "requestBody": {"required": true, "content": {"application/json": {"schema": {
                            "type": "object", "required": ["quantity"], "properties": {"quantity": {"type": "integer"}}
                        }}}},
                        "responses": {"200": {"description": "ok"}}
                    }
                },
                "/api/orders/{id}/approve": {
                    "post": {"responses": {"200": {"description": "ok"}}}
                },
                "/graphql": {
                    "post": {"responses": {"200": {"description": "ok"}}}
                }
            }
        });
        let mut d = Discovery::default();
        d.spec = Some(SpecDoc {
            base_path: "".into(),
            source: "openapi.json".into(),
            doc,
            ops: vec![
                Op {
                    method: "POST".into(),
                    path: "/api/wallet/withdraw".into(),
                    operation_id: None,
                    secured: false,
                    has_body: true,
                },
                Op {
                    method: "POST".into(),
                    path: "/api/coupons/clean-redeem".into(),
                    operation_id: None,
                    secured: false,
                    has_body: true,
                },
                Op {
                    method: "POST".into(),
                    path: "/api/checkout".into(),
                    operation_id: None,
                    secured: false,
                    has_body: true,
                },
                Op {
                    method: "POST".into(),
                    path: "/api/orders/{id}/approve".into(),
                    operation_id: None,
                    secured: false,
                    has_body: false,
                },
                Op {
                    method: "POST".into(),
                    path: "/graphql".into(),
                    operation_id: None,
                    secured: false,
                    has_body: false,
                },
            ],
        });

        let creds = Credentials::default().with("user", "u-tok");
        assert!(plan_logic_attacks(&d, &creds, Depth::Quick).is_empty());

        let mut cases = plan_logic_attacks(&d, &creds, Depth::Deep);
        for (i, c) in cases.iter_mut().enumerate() {
            c.id = format!("LOG-{:03}", i + 1);
        }
        let opts = ExecOptions {
            credentials: creds,
            reruns: 0,
            ..Default::default()
        };
        let mut budget = RunBudget::new(200, 200, std::time::Duration::from_secs(30), 50.0);
        let results = execute_cases_gated(&cases, &url, &opts, &mut budget, None);

        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/api/wallet/withdraw"),
            "expected FAIL for TOCTOU double-spend on /api/wallet/withdraw: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/api/coupons/clean-redeem"),
            "atomic 409 coupon redemption must not false-positive: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/api/checkout"),
            "expected FAIL for negative quantity checkout: {results:?}"
        );
        assert!(
            results.iter().any(|r| r.status == "FAIL"
                && r.component.starts_with("/api/orders/")
                && r.component.ends_with("/approve")),
            "expected FAIL for skip-step order approval: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/graphql"),
            "expected FAIL for GraphQL __schema introspection: {results:?}"
        );
    }
}
