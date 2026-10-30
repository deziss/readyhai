//! Planner. The plan is deterministic and grounded: a baseline from the discovered routes, plus
//! OpenAPI-driven cases when a spec is available (reusing `qa::plan::ops_from_doc`). The LLM may
//! only ADD cases; its output is parsed with serde into typed structs, every case is validated
//! against the discovered routes (unknown route => dropped, never remapped), and it is skipped
//! entirely when the LLM is unavailable.
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::discover::{Discovery, SpecDoc};
use super::exec::{Credentials, normalize_method};
use super::oracle::Technique;
use super::types::{DiscoveredRoute, PlannedCase, TargetTechProfile};
use crate::llm::untrusted::{self, clean, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed};

static NULL: Value = Value::Null;

pub const MAX_CASES: usize = 40;
const MAX_LLM_CASES: usize = 8;
const XSS: &str = "\"><script>alert(1)</script>";
const SQLI: &str = "' OR '1'='1' --";

#[derive(Debug, Clone, Default)]
pub struct PlanOutcome {
    pub cases: Vec<PlannedCase>,
    /// deterministic | openapi | <either>+llm
    pub source: String,
    pub notes: Vec<String>,
    pub llm_cases: usize,
}

// ---------------------------------------------------------------- helpers

#[allow(clippy::too_many_arguments)]
fn mk(
    technique: &str,
    title: String,
    method: &str,
    component: String,
    hint: &str,
    payload: Option<String>,
    behavior: &str,
    status: Option<u16>,
    risk: &str,
    role: &str,
    source: &str,
) -> PlannedCase {
    PlannedCase {
        id: String::new(),
        title,
        component,
        method: method.to_string(),
        technique: technique.to_string(),
        input_hint: hint.to_string(),
        payload,
        expected_behavior: behavior.to_string(),
        expected_status: status,
        risk_level: risk.to_string(),
        role: Some(role.to_string()),
        secured: None,
        route_status: None,
        expect_fields: vec![],
        expected_content_type: None,
        source: Some(source.to_string()),
    }
}

fn user_or_anon(creds: &Credentials) -> &'static str {
    if creds.has_role("user") {
        "user"
    } else {
        "anon"
    }
}

fn key_of(c: &PlannedCase) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        c.method,
        c.component,
        c.technique,
        c.payload.as_deref().unwrap_or(""),
        c.role.as_deref().unwrap_or("")
    )
}

fn template_regex(tpl: &str) -> Option<regex::Regex> {
    let mut re = String::from("^");
    let mut rest = tpl;
    while let Some(i) = rest.find('{') {
        re.push_str(&regex::escape(&rest[..i]));
        let j = rest[i..].find('}')? + i;
        re.push_str("[^/]+");
        rest = &rest[j + 1..];
    }
    re.push_str(&regex::escape(rest));
    re.push('$');
    regex::Regex::new(&re).ok()
}

// ---------------------------------------------------------------- baseline (crawl-grounded)

fn baseline(d: &Discovery, creds: &Credentials) -> Vec<PlannedCase> {
    let routes: Vec<&DiscoveredRoute> = d.routes.iter().filter(|r| r.source != "openapi").collect();
    let tech: &TargetTechProfile = &d.tech;
    let user = user_or_anon(creds);
    let entry = routes
        .iter()
        .find(|r| r.path == "/")
        .map(|r| r.path.as_str())
        .or_else(|| routes.first().map(|r| r.path.as_str()))
        .unwrap_or("/")
        .to_string();
    let entry_status = routes
        .iter()
        .find(|r| r.path == entry)
        .map(|r| r.status_code);
    let content: Vec<&&DiscoveredRoute> = routes
        .iter()
        .filter(|r| r.path != "/" && r.source != "probe" && !r.path.starts_with("/api/"))
        .collect();
    let content_path = content.first().map(|r| r.path.clone());
    let secondary = content
        .iter()
        .map(|r| r.path.clone())
        .find(|p| Some(p) != content_path.as_ref());
    let form_path = routes
        .iter()
        .find(|r| r.source != "probe" && (r.has_form || r.path.ends_with(".php")))
        .map(|r| r.path.clone());

    let mut out = vec![];
    // liveness of the entry point (and its cookies / headers)
    let (live_status, live_behavior) = match entry_status {
        Some(200..=299) => (Some(200), "HTTP 200 OK with a valid response"),
        Some(300..=399) => (entry_status, "redirects as it did during discovery"),
        _ => (None, "responds without a server error"),
    };
    if !matches!(entry_status, Some(401 | 403)) {
        let t = if tech.is_php {
            "Entry page liveness and PHP session cookie hygiene"
        } else {
            "Entry page liveness and session cookie hygiene"
        };
        let mut c = mk(
            "state_transition",
            t.into(),
            "GET",
            entry.clone(),
            "Fetch the entry page without credentials and inspect status and cookies",
            None,
            live_behavior,
            live_status,
            "low",
            "anon",
            "deterministic",
        );
        c.route_status = entry_status;
        out.push(c);
    }
    // sensitive-file probes
    for (p, title) in [
        ("/.env", "Environment file is not publicly readable"),
        ("/.git/config", "Git metadata is not publicly readable"),
    ] {
        out.push(mk(
            "authz",
            title.into(),
            "GET",
            p.into(),
            "Direct GET for a sensitive file",
            None,
            "HTTP 403 or 404; no credentials or configuration in the response",
            Some(403),
            "critical",
            "anon",
            "deterministic",
        ));
    }
    if tech.is_php {
        out.push(mk(
            "authz",
            "phpinfo() page is not publicly readable".into(),
            "GET",
            "/phpinfo.php".into(),
            "Direct GET for phpinfo",
            None,
            "HTTP 403 or 404; no PHP configuration dump",
            Some(403),
            "high",
            "anon",
            "deterministic",
        ));
    }
    // routes that demanded credentials during discovery: a forged token must not open them
    for r in routes
        .iter()
        .filter(|r| matches!(r.status_code, 401 | 403) && r.source == "crawl")
        .take(3)
    {
        let mut c = mk(
            "authz",
            format!("Forged bearer token is rejected on {}", r.path),
            "GET",
            r.path.clone(),
            "Send a syntactically valid but forged bearer token",
            None,
            "HTTP 401 or 403",
            Some(401),
            "critical",
            "forged",
            "deterministic",
        );
        c.secured = Some(true);
        c.route_status = Some(r.status_code);
        out.push(c);
    }
    // content cases only when there is something to point them at
    let target_path = content_path.clone().unwrap_or_else(|| entry.clone());
    if content_path.is_some() || d.spec.is_none() {
        out.push(mk(
            "injection",
            format!("Reflected XSS probe ({target_path})"),
            "GET",
            target_path.clone(),
            "Inject a script vector into a query parameter",
            Some(format!("q={XSS}")),
            "Payload is not reflected unescaped and causes no server error",
            None,
            "high",
            user,
            "deterministic",
        ));
        out.push(mk(
            "injection",
            format!("SQL injection error probe ({target_path})"),
            "GET",
            target_path.clone(),
            "Inject a SQL tautology into a query parameter",
            Some(format!("q={SQLI}")),
            "No SQL error is disclosed and no server error occurs",
            None,
            "high",
            user,
            "deterministic",
        ));
        match &form_path {
            Some(f) => out.push(mk(
                "boundary",
                format!("Oversized form value tolerance ({f})"),
                "POST",
                f.clone(),
                "4000-character form value",
                Some(format!("data={}", "A".repeat(4000))),
                "Oversized input is handled without a server error",
                None,
                "medium",
                user,
                "deterministic",
            )),
            None => out.push(mk(
                "boundary",
                format!("Oversized query value tolerance ({target_path})"),
                "GET",
                target_path.clone(),
                "4000-character query value",
                Some(format!("q={}", "A".repeat(4000))),
                "Oversized input is handled without a server error",
                None,
                "medium",
                user,
                "deterministic",
            )),
        }
        out.push(mk(
            "negative",
            format!("HEAD verb handling ({target_path})"),
            "HEAD",
            target_path.clone(),
            "HEAD must behave like GET without leaking source or crashing",
            None,
            "HEAD is handled without a server error",
            None,
            "medium",
            user,
            "deterministic",
        ));
    }
    if let Some(s) = secondary {
        let st = routes.iter().find(|r| r.path == s).map(|r| r.status_code);
        let mut c = mk(
            "state_transition",
            format!("Page liveness ({s})"),
            "GET",
            s.clone(),
            "Fetch a second discovered page",
            None,
            if matches!(st, Some(200..=299)) {
                "HTTP 200 OK with a valid response"
            } else {
                "responds without a server error"
            },
            if matches!(st, Some(200..=299)) {
                Some(200)
            } else {
                None
            },
            "low",
            "anon",
            "deterministic",
        );
        c.route_status = st;
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------- OpenAPI-driven

fn resolve<'a>(doc: &'a Value, v: &'a Value) -> &'a Value {
    let mut cur = v;
    for _ in 0..6 {
        match cur
            .get("$ref")
            .and_then(|r| r.as_str())
            .and_then(|r| r.strip_prefix('#'))
        {
            Some(ptr) => match doc.pointer(ptr) {
                Some(t) => cur = t,
                None => return cur,
            },
            None => return cur,
        }
    }
    cur
}

fn op_value<'a>(doc: &'a Value, path: &str, method: &str) -> Option<&'a Value> {
    doc.get("paths")?
        .get(path)?
        .get(method.to_ascii_lowercase())
}

struct Param {
    name: String,
    loc: String,
    ty: String,
    format: String,
}

fn op_params(doc: &Value, path: &str, method: &str) -> Vec<Param> {
    let mut out = vec![];
    let item = doc.get("paths").and_then(|p| p.get(path));
    let op = op_value(doc, path, method);
    for list in [
        item.and_then(|i| i.get("parameters")),
        op.and_then(|o| o.get("parameters")),
    ]
    .into_iter()
    .flatten()
    {
        for p in list.as_array().into_iter().flatten() {
            let p = resolve(doc, p);
            let schema = resolve(doc, p.get("schema").unwrap_or(&NULL));
            out.push(Param {
                name: p["name"].as_str().unwrap_or("").to_string(),
                loc: p["in"].as_str().unwrap_or("").to_string(),
                ty: schema["type"].as_str().unwrap_or("string").to_string(),
                format: schema["format"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    out.retain(|p| !p.name.is_empty());
    out
}

fn fill_path(tpl: &str, params: &[Param]) -> String {
    let mut out = String::new();
    let mut rest = tpl;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find('}').map(|j| j + i) else {
            break;
        };
        let name = &rest[i + 1..j];
        let p = params.iter().find(|p| p.loc == "path" && p.name == name);
        let lname = name.to_ascii_lowercase();
        let v = match p {
            Some(p) if p.format == "uuid" => "00000000-0000-4000-8000-000000000001",
            Some(p) if p.ty == "integer" || p.ty == "number" => "1",
            _ if lname == "id" || lname.ends_with("id") => "1",
            _ => "test",
        };
        out.push_str(v);
        rest = &rest[j + 1..];
    }
    out.push_str(rest);
    out
}

fn schema_required(doc: &Value, schema: &Value) -> Vec<String> {
    let s = resolve(doc, schema);
    let s = if s["type"] == "array" {
        resolve(doc, s.get("items").unwrap_or(&NULL))
    } else {
        s
    };
    s["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .take(20)
        .map(String::from)
        .collect()
}

fn response_required_fields(doc: &Value, op: &Value) -> Vec<String> {
    let responses = &op["responses"];
    for code in ["200", "201", "2XX", "default"] {
        if let Some(r) = responses.get(code) {
            let r = resolve(doc, r);
            if let Some(schema) = r["content"]["application/json"].get("schema") {
                return schema_required(doc, schema);
            }
        }
    }
    vec![]
}

fn request_first_property(doc: &Value, op: &Value) -> Option<String> {
    let rb = resolve(doc, op.get("requestBody")?);
    let schema = resolve(doc, rb["content"]["application/json"].get("schema")?);
    let props = schema.get("properties")?.as_object()?;
    props
        .iter()
        .find(|(_, v)| resolve(doc, v)["type"] == "string")
        .map(|(k, _)| k.clone())
        .or_else(|| props.keys().next().cloned())
}

fn spec_cases(spec: &SpecDoc, creds: &Credentials) -> Vec<PlannedCase> {
    let user = user_or_anon(creds);
    let mut ops: Vec<&crate::qa::plan::Op> = spec.ops.iter().collect();
    ops.sort_by_key(|o| std::cmp::Reverse(crate::qa::plan::score(o, None, false).0)); // stable: ties keep spec order
    ops.truncate(15);
    let (mut authz, mut inj, mut neg, mut bound, mut forged, mut base) =
        (vec![], vec![], vec![], vec![], vec![], vec![]);
    let mut forged_n = 0;
    let mut inj_n = 0;
    for op in ops {
        let params = op_params(&spec.doc, &op.path, &op.method);
        let comp = format!("{}{}", spec.base_path, fill_path(&op.path, &params));
        let opv = op_value(&spec.doc, &op.path, &op.method)
            .cloned()
            .unwrap_or(Value::Null);
        let label = format!("{} {}", op.method, op.path);
        if op.secured {
            let mut c = mk(
                "authz",
                format!("Unauthenticated {label} is rejected"),
                &op.method,
                comp.clone(),
                "Call the operation without credentials",
                None,
                "HTTP 401 or 403",
                Some(401),
                "critical",
                "anon",
                "openapi",
            );
            c.secured = Some(true);
            authz.push(c);
            if forged_n < 3 {
                forged_n += 1;
                let mut c = mk(
                    "authz",
                    format!("Forged bearer token is rejected on {label}"),
                    &op.method,
                    comp.clone(),
                    "Send a syntactically valid but forged bearer token",
                    None,
                    "HTTP 401 or 403",
                    Some(401),
                    "critical",
                    "forged",
                    "openapi",
                );
                c.secured = Some(true);
                forged.push(c);
            }
        }
        let qparams: Vec<&Param> = params.iter().filter(|p| p.loc == "query").collect();
        if let (Some(q), true) = (qparams.first(), inj_n < 4 && !op.has_body) {
            inj_n += 1;
            let mut c = mk(
                "injection",
                format!("Script injection through ?{} on {label}", q.name),
                &op.method,
                comp.clone(),
                "Inject a script vector into a query parameter",
                Some(format!("{}={XSS}", q.name)),
                "Payload is not reflected unescaped and causes no server error",
                None,
                "high",
                user,
                "openapi",
            );
            c.secured = Some(op.secured);
            inj.push(c);
            let mut c = mk(
                "injection",
                format!("SQL injection through ?{} on {label}", q.name),
                &op.method,
                comp.clone(),
                "Inject a SQL tautology into a query parameter",
                Some(format!("{}={SQLI}", q.name)),
                "No SQL error is disclosed and no server error occurs",
                None,
                "high",
                user,
                "openapi",
            );
            c.secured = Some(op.secured);
            inj.push(c);
        }
        if op.has_body {
            let field = request_first_property(&spec.doc, &opv).unwrap_or_else(|| "name".into());
            let mut c = mk(
                "negative",
                format!("Malformed JSON body is rejected on {label}"),
                &op.method,
                comp.clone(),
                "Send syntactically invalid JSON",
                Some("{\"".into()),
                "Malformed input must be rejected with a 4xx client error",
                None,
                "high",
                user,
                "openapi",
            );
            c.secured = Some(op.secured);
            neg.push(c);
            let mut c = mk(
                "boundary",
                format!("Oversized `{field}` is handled on {label}"),
                &op.method,
                comp.clone(),
                "5000-character string in the first string field",
                Some(serde_json::json!({ field.clone(): "A".repeat(5000) }).to_string()),
                "Oversized input is handled without a server error",
                None,
                "medium",
                user,
                "openapi",
            );
            c.secured = Some(op.secured);
            bound.push(c);
        } else if op.method == "GET" {
            let fields = response_required_fields(&spec.doc, &opv);
            if !op.secured || creds.has_role("user") {
                let mut c = mk(
                    "state_transition",
                    format!("{label} answers 2xx and honours its contract"),
                    "GET",
                    comp.clone(),
                    "Plain read of the operation",
                    None,
                    "HTTP 2xx with the documented required fields",
                    Some(200),
                    "medium",
                    if op.secured { "user" } else { "anon" },
                    "openapi",
                );
                c.secured = Some(op.secured);
                c.expect_fields = fields;
                c.expected_content_type = Some("json".into())
                    .filter(|_| opv["responses"].to_string().contains("application/json"));
                base.push(c);
            }
        }
    }
    [authz, inj, neg, bound, forged, base].concat()
}

// ---------------------------------------------------------------- LLM additions

const PLANNER_ROLE: &str = "You are a senior adversarial QA planner. Propose EXTRA test cases for a web application. \
Components must be copied exactly from the known_endpoints list; never invent routes. Allowed methods: GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE. \
Format: {\"cases\": [{\"title\": string, \"component\": string, \"method\": string, \"technique\": \"authz\"|\"boundary\"|\"injection\"|\"negative\"|\"state_transition\", \
\"input_hint\": string, \"payload\": string|null, \"expected_behavior\": string, \"expected_status\": int|null, \"risk_level\": \"critical\"|\"high\"|\"medium\"|\"low\"}]}. \
For GET/HEAD/OPTIONS the payload becomes the query string (use k=v&k2=v2); for other methods it is the request body.";

#[derive(Debug, Deserialize)]
struct PlannerOutput {
    cases: Vec<RawCase>,
}

#[derive(Debug, Deserialize)]
struct RawCase {
    title: String,
    component: String,
    #[serde(default)]
    method: Option<String>,
    technique: String,
    #[serde(default)]
    input_hint: Option<String>,
    #[serde(default)]
    payload: Option<Value>,
    #[serde(default)]
    expected_behavior: Option<String>,
    #[serde(default)]
    expected_status: Option<i64>,
    #[serde(default)]
    risk_level: Option<String>,
}

struct Known<'a> {
    exact: HashMap<&'a str, &'a DiscoveredRoute>,
    templates: Vec<(regex::Regex, &'a DiscoveredRoute)>,
}

impl<'a> Known<'a> {
    fn new(routes: &'a [DiscoveredRoute]) -> Self {
        let mut exact = HashMap::new();
        let mut templates = vec![];
        for r in routes {
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
    fn find(&self, component: &str) -> Option<&'a DiscoveredRoute> {
        self.exact.get(component).copied().or_else(|| {
            self.templates
                .iter()
                .find(|(re, _)| re.is_match(component))
                .map(|(_, r)| *r)
        })
    }
}

fn validate_raw(raw: &RawCase, known: &Known, creds: &Credentials) -> Result<PlannedCase, String> {
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
    let component = raw.component.trim();
    let route = known.find(component).ok_or_else(|| {
        format!(
            "component '{}' is not a discovered route",
            component.chars().take(60).collect::<String>()
        )
    })?;
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
    let risk = match raw.risk_level.as_deref().map(|s| s.to_ascii_lowercase()) {
        Some(r) if ["critical", "high", "medium", "low"].contains(&r.as_str()) => r,
        _ => "medium".into(),
    };
    let status = raw
        .expected_status
        .filter(|s| (100..=599).contains(s))
        .map(|s| s as u16);
    let role = if tech == Technique::Authz {
        "anon"
    } else {
        user_or_anon(creds)
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
        "llm",
    );
    c.secured = route.secured;
    c.route_status = Some(route.status_code).filter(|s| *s != 0);
    Ok(c)
}

fn llm_extras(
    cfg: &LlmConfig,
    budget: &mut Budget,
    target: &str,
    profile: &str,
    d: &Discovery,
    instructions: Option<&str>,
    creds: &Credentials,
    notes: &mut Vec<String>,
) -> Vec<PlannedCase> {
    let known = Known::new(&d.routes);
    let endpoints: Vec<Value> = d
        .routes
        .iter()
        .take(60)
        .map(|r| serde_json::json!({"method": r.method, "path": r.path, "status": r.status_code, "secured": r.secured, "title": r.title.as_deref().map(|t| clean(t, 80))}))
        .collect();
    let facts = serde_json::json!({
        "target": target, "profile": profile, "app_architecture": d.tech.app_architecture, "primary_framework": d.tech.primary_framework,
        "known_endpoints": endpoints, "operator_instructions": instructions.map(|i| clean(i, 500)).unwrap_or_default(),
    });
    let prompt = format!(
        "Target under test:\n{}\nPropose up to {} additional adversarial test cases that complement the baseline (authz, boundary, injection, negative inputs, state transitions).",
        fence_capped(&facts, 200),
        MAX_LLM_CASES
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

// ---------------------------------------------------------------- entry point

/// Build the plan. `llm` is None when the LLM is not configured/reachable: then the plan is purely deterministic.
pub fn plan_cases(
    llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    profile: &str,
    d: &Discovery,
    instructions: Option<&str>,
    creds: &Credentials,
) -> PlanOutcome {
    let mut notes = vec![];
    let mut cases = baseline(d, creds);
    let mut spec_n = 0;
    if let Some(spec) = d.spec.as_ref().filter(|s| !s.ops.is_empty()) {
        let sc = spec_cases(spec, creds);
        spec_n = sc.len();
        cases.extend(sc);
        if spec.ops.iter().any(|o| o.secured) && !creds.has_role("user") {
            notes.push(format!("no {} credential: authenticated positive/contract checks were not planned; secured operations are probed without credentials only", Credentials::env_var("user")));
        }
    }
    // dedupe, cap
    let mut seen = HashSet::new();
    cases.retain(|c| seen.insert(key_of(c)));
    cases.truncate(MAX_CASES);

    let mut llm_cases = 0;
    if let Some((cfg, budget)) = llm {
        let room = MAX_CASES.saturating_sub(cases.len()).min(MAX_LLM_CASES);
        if room > 0 {
            for c in llm_extras(
                cfg,
                budget,
                target,
                profile,
                d,
                instructions,
                creds,
                &mut notes,
            ) {
                if llm_cases < room && seen.insert(key_of(&c)) {
                    cases.push(c);
                    llm_cases += 1;
                }
            }
        }
    }
    for (i, c) in cases.iter_mut().enumerate() {
        c.id = format!("TC-{:03}", i + 1);
    }
    let base = if spec_n > 0 {
        "openapi"
    } else {
        "deterministic"
    };
    PlanOutcome {
        source: if llm_cases > 0 {
            format!("{base}+llm")
        } else {
            base.to_string()
        },
        cases,
        notes,
        llm_cases,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(path: &str, status: u16) -> DiscoveredRoute {
        DiscoveredRoute {
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
            out.cases.iter().all(|c| c.component == "/"
                || c.component == "/.env"
                || c.component == "/.git/config"),
            "{:?}",
            out.cases.iter().map(|c| &c.component).collect::<Vec<_>>()
        );
        assert_eq!(out.cases[0].id, "TC-001");
        assert_eq!(out.source, "deterministic");
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
        assert!(out.cases.iter().any(|c| c.technique == "boundary"
            && c.method == "POST"
            && c.component == "/events.php"));
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
    fn openapi_plan_uses_ops_from_doc_secured_and_contract_info() {
        let doc: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/qa-api/openapi.json")).unwrap();
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
        assert!(
            ord.expect_fields.iter().any(|f| f == "total") && ord.role.as_deref() == Some("user")
        );
    }

    #[test]
    fn llm_raw_cases_are_validated_against_discovered_routes() {
        let routes = vec![route("/", 200), route("/orders/{id}", 0)];
        let known = Known::new(&routes);
        let creds = Credentials::none();
        let ok =
            |j: &str| validate_raw(&serde_json::from_str::<RawCase>(j).unwrap(), &known, &creds);
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
}
