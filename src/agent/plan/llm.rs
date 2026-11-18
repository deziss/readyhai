//! LLM-assisted adversarial test case synthesis, validation against discovered routes, and JSON schema guards.

use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use super::super::discover::Discovery;
use super::super::exec::{Credentials, normalize_method};
use super::super::oracle::Technique;
use super::super::types::{DiscoveredRoute, InputSurface, PlannedCase, ResponseContract};
use super::dag::{AttackDag, AttackDagNode};
use super::helpers::{key_of, mk, template_regex, user_or_anon};
use super::surface::surface_of;
use super::types::SeededRng;
use crate::llm::untrusted::{self, clean, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed, clamp_thinking_budget};

const PLANNER_ROLE: &str = "You are a senior adversarial QA planner and principal security researcher. \
Propose creative, randomized, non-repetitive test cases for a web application exploring modern OWASP API Security 2023 vectors, \
unexpected encodings, boundary limits, and complex state attacks. \
Components MUST be copied exactly from the known_endpoints list; never invent routes. \
Allowed methods: GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE. \
Format: {\"cases\": [{\"title\": string, \"component\": string, \"method\": string, \"technique\": \"authz\"|\"boundary\"|\"injection\"|\"negative\"|\"state_transition\", \
\"input_hint\": string, \"payload\": string|null, \"headers\": {string: string}|null, \"content_type\": string|null, \"expected_behavior\": string, \"expected_status\": int|null, \"risk_level\": \"critical\"|\"high\"|\"medium\"|\"low\"}]}. \
For GET/HEAD/OPTIONS the payload becomes the query string (use k=v&k2=v2); for other methods it is the request body. \
Ensure high diversity across attack archetypes: BOPLA/Mass Assignment, SSRF, Unicode/Homoglyph normalization, NoSQL/Filter tampering, \
Prototype Pollution, Header injection/IP spoofing, XML/MIME confusion, Exponential boundaries, and Business logic bypasses.";

#[derive(Debug, Deserialize)]
pub(crate) struct PlannerOutput {
    pub(crate) cases: Vec<RawCase>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct RawCase {
    pub(crate) title: String,
    pub(crate) component: String,
    #[serde(default)]
    pub(crate) method: Option<String>,
    pub(crate) technique: String,
    #[serde(default)]
    pub(crate) input_hint: Option<String>,
    #[serde(default)]
    pub(crate) payload: Option<Value>,
    #[serde(default)]
    pub(crate) headers: Option<Value>,
    #[serde(default)]
    pub(crate) content_type: Option<String>,
    #[serde(default)]
    pub(crate) expected_behavior: Option<String>,
    #[serde(default)]
    pub(crate) expected_status: Option<i64>,
    #[serde(default)]
    pub(crate) risk_level: Option<String>,
}

pub(crate) struct Known<'a> {
    exact: HashMap<&'a str, &'a DiscoveredRoute>,
    templates: Vec<(regex::Regex, &'a DiscoveredRoute)>,
}

impl<'a> Known<'a> {
    pub(crate) fn new(routes: &'a [DiscoveredRoute]) -> Self {
        let mut exact = HashMap::new();
        let mut templates = vec![];
        for r in routes.iter().filter(|r| !r.catch_all) {
            if r.path.contains('{') {
                if let Some(re) = template_regex(&r.path) {
                    templates.push((re, r));
                }
            } else {
                exact.entry(r.path.as_str()).or_insert(r);
            }
        }
        Known { exact, templates }
    }
    pub(crate) fn find(&self, component: &str) -> Option<&'a DiscoveredRoute> {
        self.exact.get(component).copied().or_else(|| {
            self.templates
                .iter()
                .find(|(re, _)| re.is_match(component))
                .map(|(_, r)| *r)
        })
    }
}

pub(crate) fn validate_raw(
    raw: &RawCase,
    known: &Known,
    creds: &Credentials,
) -> Result<PlannedCase, String> {
    let method = normalize_method(raw.method.as_deref().unwrap_or("GET")).ok_or_else(|| {
        format!(
            "method '{}' not allowed",
            raw.method
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(12)
                .collect::<String>()
        )
    })?;
    let tech = Technique::parse(&raw.technique);
    if tech == Technique::Other {
        return Err(format!(
            "unknown technique '{}'",
            raw.technique.chars().take(20).collect::<String>()
        ));
    }
    let raw_comp = raw.component.trim();
    let path_part = if let Ok(u) = reqwest::Url::parse(raw_comp) {
        u.path().to_string()
    } else {
        raw_comp.to_string()
    };
    let base_part = path_part.split('?').next().unwrap_or(&path_part).trim();
    let norm_comp = if !base_part.starts_with('/') {
        format!("/{base_part}")
    } else {
        base_part.to_string()
    };
    let trimmed = if norm_comp.len() > 1 && norm_comp.ends_with('/') {
        norm_comp.trim_end_matches('/').to_string()
    } else {
        norm_comp.clone()
    };
    let route = known
        .find(&norm_comp)
        .or_else(|| known.find(&trimmed))
        .or_else(|| known.find(raw_comp))
        .or_else(|| {
            known
                .exact
                .iter()
                .find(|(k, _)| {
                    k.eq_ignore_ascii_case(&norm_comp) || k.eq_ignore_ascii_case(&trimmed)
                })
                .map(|(_, r)| *r)
        })
        .ok_or_else(|| {
            format!(
                "component '{}' is not a discovered route",
                raw_comp.chars().take(60).collect::<String>()
            )
        })?;
    let component = route.path.as_str();
    // Sensitive file probes and static files should never be targeted with mutating verbs (POST/PUT/PATCH/DELETE)
    if (route.source == "probe"
        || component.starts_with("/.")
        || component.ends_with(".env")
        || component.ends_with(".config"))
        && matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
    {
        return Err(format!(
            "mutating method '{method}' is not valid on sensitive file probe '{component}'"
        ));
    }
    let title = clean(&raw.title, 120);
    if title.is_empty() {
        return Err("empty title".into());
    }
    let payload = match &raw.payload {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
    .filter(|p| !p.is_empty());
    if payload.as_ref().is_some_and(|p| p.len() > 4096) {
        return Err("payload longer than 4096 bytes".into());
    }
    let raw_headers = match &raw.headers {
        None | Some(Value::Null) => vec![],
        Some(Value::Object(map)) => {
            let mut pairs = Vec::with_capacity(map.len());
            for (k, v) in map {
                let s = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(_) | Value::Bool(_) => v.to_string(),
                    _ => return Err(format!("header '{k}' value must be a string or scalar")),
                };
                pairs.push((k.clone(), s));
            }
            pairs
        }
        Some(_) => return Err("headers must be a JSON object".into()),
    };
    let headers = super::super::exec::sanitize_custom_headers(&raw_headers, false)?;
    let content_type = match raw
        .content_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(ct) => Some(super::super::exec::validate_content_type(ct)?),
        None => None,
    };
    let risk = match raw.risk_level.as_deref().map(|s| s.to_ascii_lowercase()) {
        Some(r) if ["critical", "high", "medium", "low"].contains(&r.as_str()) => r,
        _ => "medium".into(),
    };
    let status = raw
        .expected_status
        .filter(|s| (100..=599).contains(s))
        .map(|s| s as u16);
    let acting = user_or_anon(creds);
    let role = if tech == Technique::Authz {
        "anon"
    } else {
        acting.as_str()
    };
    let mut c = mk(
        tech.as_str(),
        title,
        method,
        component.to_string(),
        &clean(raw.input_hint.as_deref().unwrap_or(""), 200),
        payload,
        &clean(
            raw.expected_behavior
                .as_deref()
                .unwrap_or("Handled without a server error"),
            200,
        ),
        status,
        &risk,
        role,
        if route.source == "operator_instructions" {
            "directives"
        } else {
            "llm"
        },
    );
    c.headers = headers;
    c.content_type = content_type;
    c.secured = route.secured;
    c.route_status = Some(route.status_code).filter(|s| *s != 0);
    Ok(c)
}

pub(crate) fn llm_extras(
    cfg: &LlmConfig,
    budget: &mut Budget,
    target: &str,
    profile: &str,
    d: &Discovery,
    instructions: Option<&str>,
    creds: &Credentials,
    seed: u64,
    max_cases: usize,
    notes: &mut Vec<String>,
) -> Vec<PlannedCase> {
    let mut effective_routes = d.routes.clone();

    // Always ensure root endpoint '/' is available in known routes
    if !effective_routes
        .iter()
        .any(|r| r.path == "/" && !r.catch_all)
    {
        effective_routes.push(DiscoveredRoute {
            path: "/".to_string(),
            method: "GET".to_string(),
            status_code: 200,
            content_type: "text/html".to_string(),
            source: "target".to_string(),
            title: Some("Root Endpoint".to_string()),
            ..Default::default()
        });
    }

    // Extract any explicit URL paths from operator instructions (e.g. '/api/auth/session')
    if let Some(instr) = instructions {
        if let Ok(path_re) =
            regex::Regex::new(r"(/[a-zA-Z0-9_\-\.\{\}]+(?:/[a-zA-Z0-9_\-\.\{\}]+)*)")
        {
            for cap in path_re.captures_iter(instr) {
                let p =
                    cap[1].trim_end_matches(&['.', ',', ';', ':', ')', ']', '"', '\'', ' '][..]);
                if p.starts_with('/')
                    && p.len() > 1
                    && !effective_routes.iter().any(|r| r.path == p)
                {
                    effective_routes.push(DiscoveredRoute {
                        path: p.to_string(),
                        method: "GET".to_string(),
                        status_code: 200,
                        content_type: "application/json".to_string(),
                        source: "operator_instructions".to_string(),
                        title: Some(format!("Operator instruction endpoint: {p}")),
                        input_surface: InputSurface::Json,
                        has_body: true,
                        is_api: true,
                        ..Default::default()
                    });
                }
            }
        }
        let lower = instr.to_ascii_lowercase();
        let feature_words = [
            "chat", "prompt", "message", "query", "search", "comment", "feedback",
        ];
        for word in feature_words {
            if lower.contains(word) {
                for candidate in [format!("/{word}"), format!("/api/{word}")] {
                    if !effective_routes.iter().any(|r| r.path == candidate) {
                        effective_routes.push(DiscoveredRoute {
                            path: candidate.clone(),
                            method: "POST".to_string(),
                            status_code: 200,
                            content_type: "application/json".to_string(),
                            source: "operator_instructions".to_string(),
                            title: Some(format!("Operator instruction endpoint: {candidate}")),
                            input_surface: InputSurface::Json,
                            has_body: true,
                            is_api: true,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    let known = Known::new(&effective_routes);
    let endpoints: Vec<Value> = effective_routes
        .iter()
        .filter(|r| !r.catch_all)
        .take(60)
        .map(|r| serde_json::json!({"method": r.method, "path": r.path, "status": r.status_code, "secured": r.secured, "title": r.title.as_deref().map(|t| clean(t, 80))}))
        .collect();

    if endpoints.is_empty() {
        notes.push("no target endpoints available to synthesize adversarial attacks against; skipping LLM extras".into());
        return vec![];
    }
    let facts = serde_json::json!({
        "target": target, "profile": profile, "app_architecture": d.tech.app_architecture, "primary_framework": d.tech.primary_framework,
        "known_endpoints": endpoints, "operator_instructions": instructions.map(|i| clean(i, 8000)).unwrap_or_default(),
    });
    // The exploration seed picks and orders the attack archetypes. It comes from the run id, never
    // from the clock, so the same run (id) asks the model the same question.
    let entropy = format!("{seed:016x}");
    let archetypes_pool = [
        "BOPLA & Mass Assignment (e.g. injecting 'is_admin': true, 'role': 'superuser', 'account_tier': 'enterprise')",
        "SSRF & Cloud Metadata Probing (e.g. 'url=http://169.254.169.254/latest/meta-data/', 'target=http://127.0.0.1:8080/internal')",
        "Unicode Normalization & Homoglyphs (e.g. full-width '＜script＞', null byte '%00', zero-width spaces)",
        "NoSQL / JSON Filter Selector Injection (e.g. '$where', '$regex', '$gt', '[$ne]=null')",
        "Prototype Pollution & Object Key Tampering (e.g. '__proto__.isAdmin', 'constructor.prototype')",
        "Header Spoofing & Cache Poisoning (e.g. 'X-Forwarded-Host', 'X-Original-URL', 'X-Rewrite-URL')",
        "Boundary Spikes & Exponential Overflows (e.g. '1e309', negative numbers, massive arrays, deeply nested JSON)",
        "MIME & Strict Type Confusion (e.g. unexpected Content-Type, malformed schema types, float where int expected)",
        "JWT Algorithm Confusion & Weak Bearer Tokens (e.g. 'alg: none', empty bearer token, truncated signatures)",
        "Business Logic & State Sequencing Bypasses (e.g. skip intermediate steps, double-spend operations)",
    ];
    let mut archetypes: Vec<&str> = archetypes_pool.to_vec();
    SeededRng(seed).shuffle(&mut archetypes);
    archetypes.truncate(6);
    let prompt = format!(
        "Target under test:\n{}\n\
Random Exploration Seed: {}\n\
Synthesize up to {} unique, randomized adversarial test cases. Focus on high-entropy edge cases and modern attack archetypes:\n- {}\n\
Important rules:\n\
- Components must be copied EXACTLY from known_endpoints; never invent routes.\n\
- You can and should synthesize multiple unique test cases for the same endpoint using diverse parameters, payloads, encodings, and techniques.\n\
- Do not propose mutating HTTP methods (POST, PUT, PATCH, DELETE) on static files or sensitive file probes (e.g. /.env, /.git/config).\n\
- Strive for novel, unique vectors (vary parameter names, boundaries, encodings, and payloads across cases).\n\
- Allowed techniques: authz, boundary, injection, negative, state_transition.",
        fence_capped(&facts, 200),
        entropy,
        max_cases,
        archetypes.join("\n- ")
    );
    let out = ask_typed::<PlannerOutput>(
        cfg,
        budget,
        &untrusted::system(PLANNER_ROLE),
        &prompt,
        |o| {
            if o.cases
                .iter()
                .any(|c| validate_raw(c, &known, creds).is_ok())
            {
                Ok(())
            } else {
                anyhow::bail!("no valid case in planner output")
            }
        },
    );
    match out {
        Err(e) => {
            notes.push(format!("LLM planner extras skipped: {e}"));
            vec![]
        }
        Ok(o) => {
            let mut v = vec![];
            for (i, raw) in o.cases.iter().enumerate() {
                match validate_raw(raw, &known, creds) {
                    Ok(c) => v.push(c),
                    Err(e) => notes.push(format!("LLM case #{} dropped: {e}", i + 1)),
                }
            }
            v
        }
    }
}

const ATTACK_DAG_PLANNER_ROLE: &str = "You are a senior adversarial QA architect and offensive workflow planner. \
Given a target web application, known discovered endpoints, and operational directives, synthesize a stateful Attack DAG \
(Directed Acyclic Graph) representing a multi-step adversarial workflow (e.g. user setup/registration -> privilege escalation/token tampering -> unauthorized tenant access/data exfiltration). \
Format: {\"nodes\": [{\"id\": string, \"dependencies\": [string], \"action\": string, \"component\": string, \"method\": string, \"payload\": object|null, \"expected_status\": int|null}]}. \
Ensure there are no circular dependencies and all dependencies reference earlier node ids.";

#[derive(Debug, Deserialize)]
struct AttackDagOutput {
    nodes: Vec<RawAttackDagNode>,
}

#[derive(Debug, Deserialize)]
struct RawAttackDagNode {
    id: String,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    component: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    payload: Option<Value>,
    #[serde(default)]
    expected_status: Option<u16>,
}

pub fn synthesize_attack_dag(
    llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    routes: &[DiscoveredRoute],
    directives: Option<&str>,
) -> AttackDag {
    if let Some((cfg, budget)) = llm {
        let endpoints: Vec<Value> = routes
            .iter()
            .filter(|r| !r.catch_all)
            .take(40)
            .map(|r| serde_json::json!({"method": r.method, "path": r.path, "status": r.status_code, "secured": r.secured}))
            .collect();

        let prompt = format!(
            "Target under test: {}\nKnown endpoints: {}\nOperational Directives: {}\n\
            Synthesize an Attack DAG with 3 to 6 interdependent attack steps exploring authorization boundaries, \
            privilege escalation, and sensitive resource access. Ensure topological acyclicity.",
            target,
            serde_json::to_string(&endpoints).unwrap_or_default(),
            directives.unwrap_or("None")
        );

        let res = ask_typed::<AttackDagOutput>(
            cfg,
            budget,
            &untrusted::system(ATTACK_DAG_PLANNER_ROLE),
            &prompt,
            |out| {
                if out.nodes.is_empty() {
                    anyhow::bail!("empty nodes in attack dag output");
                }
                Ok(())
            },
        );

        if let Ok(out) = res {
            let mut dag = AttackDag::new();
            for raw in out.nodes {
                let mut node = AttackDagNode::new(raw.id, raw.dependencies);
                node.action = raw.action;
                node.component = raw.component;
                node.method = raw.method;
                node.payload = raw.payload;
                node.expected_status = raw.expected_status;
                dag.add_node(node);
            }
            if dag.topological_order().is_ok() && !dag.nodes.is_empty() {
                return dag;
            }
        }
    }

    // Deterministic fallback Attack DAG guided by discovered routes and directives
    let dir_str = directives.unwrap_or("").to_ascii_lowercase();

    let setup_path = routes
        .iter()
        .find(|r| {
            let p = r.path.to_ascii_lowercase();
            p.contains("register")
                || p.contains("signup")
                || p.contains("login")
                || p.contains("auth")
        })
        .map(|r| r.path.as_str())
        .unwrap_or("/api/auth/register");

    let escalate_path = routes
        .iter()
        .find(|r| {
            let p = r.path.to_ascii_lowercase();
            p.contains("user")
                || p.contains("session")
                || p.contains("profile")
                || p.contains("role")
        })
        .map(|r| r.path.as_str())
        .unwrap_or("/api/auth/session");

    let exfil_path = if dir_str.contains("/api/v1/tenant") {
        "/api/v1/tenant"
    } else {
        routes
            .iter()
            .find(|r| {
                let p = r.path.to_ascii_lowercase();
                p.contains("tenant")
                    || p.contains("admin")
                    || p.contains("internal")
                    || p.contains("data")
            })
            .map(|r| r.path.as_str())
            .unwrap_or("/api/v1/tenant")
    };

    let mut dag = AttackDag::new();
    dag.add_node(
        AttackDagNode::new("setup_user", vec![])
            .with_action("Initial user registration and identity provisioning")
            .with_component(setup_path)
            .with_method("POST")
            .with_payload(serde_json::json!({
                "username": "attacker_user",
                "email": "attacker@example.org",
                "password": "Password123!"
            }))
            .with_expected_status(201),
    );
    dag.add_node(
        AttackDagNode::new("escalate_role", vec!["setup_user".into()])
            .with_action("Role tampering and claim elevation injection")
            .with_component(escalate_path)
            .with_method("POST")
            .with_payload(serde_json::json!({
                "role": "admin",
                "is_admin": true,
                "tenant_id": "tenant-001"
            }))
            .with_expected_status(200),
    );
    dag.add_node(
        AttackDagNode::new("exfiltrate_tenant", vec!["escalate_role".into()])
            .with_action("Unauthorized cross-tenant resource access and data exfiltration probe")
            .with_component(exfil_path)
            .with_method("GET")
            .with_expected_status(403),
    );

    dag
}
