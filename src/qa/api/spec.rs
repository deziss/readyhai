//! OpenAPI 3.x loader: local `$ref` resolution (depth <= 4, cycle guard, expansion budget),
//! operation extraction with a configurable operation cap.
use crate::ctx::Ctx;
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Operations planned and tested when `READYHAI_MAX_OPS` is not set.
pub const DEFAULT_MAX_OPS: usize = 2000;
/// Ceiling of `READYHAI_MAX_OPS`: a larger value is clamped (memory and run time stay bounded).
pub const HARD_MAX_OPS: usize = 10_000;
/// Name of the environment variable that raises or lowers the operation cap.
pub const MAX_OPS_ENV: &str = "READYHAI_MAX_OPS";
/// Kept for callers that only need the default.
#[allow(dead_code)]
pub const MAX_OPS: usize = DEFAULT_MAX_OPS;
pub const MAX_REF_DEPTH: usize = 4;
/// Nodes one path item may gain by expanding `$ref`s (a fan-out of refs multiplies per level, so
/// without this a handful of wide schemas would be copied thousands of times).
const ITEM_NODE_BUDGET: usize = 50_000;
/// Nodes all path items of a spec may gain by expanding `$ref`s: bounds memory and time of the
/// parse. Past it refs collapse to `{}` ("any") and the spec says so in `untested`.
const SPEC_NODE_BUDGET: usize = 6_000_000;
/// Largest OpenAPI document read (file or HTTP body).
pub const MAX_SPEC_BYTES: u64 = 64 * 1024 * 1024;
/// Operations over the cap that are named one by one in `untested` (the rest is one roll-up line).
const LISTED_OVER_CAP: usize = 25;
const METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    /// path | query | header | cookie
    pub loc: String,
    pub required: bool,
    pub schema: Value,
}

#[derive(Debug, Clone)]
pub struct Op {
    pub method: String,
    pub path: String,
    pub params: Vec<Param>,
    pub body: Option<Value>,
    #[allow(dead_code)]
    pub body_required: bool,
    /// status ("200", "2XX", "default") -> response JSON schema (None when undocumented content)
    pub responses: BTreeMap<String, Option<Value>>,
    /// True when auth is required (op-level, else global; an empty list = public).
    pub secured: bool,
}

impl Op {
    pub fn key(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
    pub fn is_write(&self) -> bool {
        super::exec::is_write(&self.method)
    }
    pub fn path_params(&self) -> impl Iterator<Item = &Param> {
        self.params.iter().filter(|p| p.loc == "path")
    }
}

#[derive(Debug, Clone, Default)]
pub struct Spec {
    /// Path of `servers[0].url` (no trailing slash), e.g. "/api/v1" or "".
    pub base_path: String,
    pub ops: Vec<Op>,
    pub untested: Vec<String>,
    pub raw: Value,
    /// Operation cap this parse used (`READYHAI_MAX_OPS`, default 2000, ceiling 10000).
    pub cap: usize,
    /// Keys ("GET /x") of the operations beyond the cap: not planned, not tested. At most
    /// `HARD_MAX_OPS` are listed; `over_cap_total` counts them all.
    pub over_cap: Vec<String>,
    pub over_cap_total: usize,
    /// Parse-time remarks for the run notes (cap setting clamped or invalid, schemas truncated).
    pub notes: Vec<String>,
}

/// The operation cap from `READYHAI_MAX_OPS`, plus a note when the value had to be corrected.
pub fn max_ops_setting() -> (usize, Option<String>) {
    parse_max_ops(std::env::var(MAX_OPS_ENV).ok().as_deref())
}

/// Pure form of [`max_ops_setting`]. Unset or blank = default; not a positive integer = default
/// (with a note); above the ceiling = the ceiling (with a note).
pub fn parse_max_ops(v: Option<&str>) -> (usize, Option<String>) {
    let Some(raw) = v.map(str::trim).filter(|s| !s.is_empty()) else {
        return (DEFAULT_MAX_OPS, None);
    };
    match raw.replace('_', "").parse::<usize>() {
        Ok(0) | Err(_) => (
            DEFAULT_MAX_OPS,
            Some(format!(
                "{MAX_OPS_ENV}={raw} is not a positive integer: using the default {DEFAULT_MAX_OPS}"
            )),
        ),
        Ok(n) if n > HARD_MAX_OPS => (
            HARD_MAX_OPS,
            Some(format!(
                "{MAX_OPS_ENV}={raw} is above the ceiling: using {HARD_MAX_OPS}"
            )),
        ),
        Ok(n) => (n, None),
    }
}

fn pointer_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 3 <= b.len()
            && let Some(Ok(v)) = s.get(i + 1..i + 3).map(|h| u8::from_str_radix(h, 16))
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out)
        .replace("~1", "/")
        .replace("~0", "~")
}

fn lookup<'a>(root: &'a Value, r: &str) -> Option<&'a Value> {
    let p = r.strip_prefix("#/")?;
    let mut cur = root;
    for seg in p.split('/') {
        let seg = pointer_unescape(seg);
        cur = match cur {
            Value::Object(m) => m.get(&seg)?,
            Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Nodes a resolution may gain by expanding `$ref`s. Once spent, further refs collapse to `{}`.
struct Budget {
    left: usize,
    spent: usize,
    exhausted: bool,
}

impl Budget {
    fn new(nodes: usize) -> Self {
        Budget {
            left: nodes,
            spent: 0,
            exhausted: false,
        }
    }
    fn charge(&mut self) {
        self.left = self.left.saturating_sub(1);
        self.spent += 1;
    }
}

/// Resolve local `$ref`s inside `v`. A ref chain deeper than MAX_REF_DEPTH, or a cycle,
/// collapses to `{}` (= "any") so generators/validators stay safe. So does every ref met after
/// the call has copied `ITEM_NODE_BUDGET` nodes out of `$ref` targets (a fan-out of refs would
/// otherwise multiply per level).
pub fn resolve(root: &Value, v: &Value) -> Value {
    resolve_inner(root, v, 0, &mut vec![], &mut Budget::new(ITEM_NODE_BUDGET))
}

fn resolve_inner(
    root: &Value,
    v: &Value,
    depth: usize,
    stack: &mut Vec<String>,
    b: &mut Budget,
) -> Value {
    if depth > 0 {
        b.charge();
    }
    match v {
        Value::Object(m) => {
            if let Some(Value::String(r)) = m.get("$ref") {
                if depth >= MAX_REF_DEPTH || stack.contains(r) {
                    return Value::Object(Map::new());
                }
                if b.left == 0 {
                    b.exhausted = true;
                    return Value::Object(Map::new());
                }
                return match lookup(root, r) {
                    Some(t) => {
                        stack.push(r.clone());
                        let out = resolve_inner(root, t, depth + 1, stack, b);
                        stack.pop();
                        out
                    }
                    None => Value::Object(Map::new()),
                };
            }
            Value::Object(
                m.iter()
                    .map(|(k, x)| (k.clone(), resolve_inner(root, x, depth, stack, b)))
                    .collect(),
            )
        }
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|x| resolve_inner(root, x, depth, stack, b))
                .collect(),
        ),
        _ => v.clone(),
    }
}

fn json_schema_of(content: Option<&Value>) -> Option<Value> {
    let c = content?.as_object()?;
    let m = c.iter().find(|(k, _)| k.contains("json")).map(|x| x.1)?;
    m.get("schema").cloned()
}

fn is_secured(op: &Value, global: &Value) -> bool {
    let sec = op.get("security").unwrap_or(global);
    match sec {
        Value::Array(a) => {
            !a.is_empty()
                && !a
                    .iter()
                    .any(|r| r.as_object().map(|o| o.is_empty()).unwrap_or(false))
        }
        _ => false,
    }
}

/// Path of `servers[0].url` (no trailing slash): "/api/v1", or "" when the server is the origin root.
pub fn base_path_of(doc: &Value) -> String {
    let base = doc
        .pointer("/servers/0/url")
        .and_then(|u| u.as_str())
        .map(|u| {
            let rest = u
                .split_once("://")
                .map(|x| {
                    x.1.split_once('/')
                        .map(|y| format!("/{}", y.1))
                        .unwrap_or_default()
                })
                .unwrap_or_else(|| u.to_string());
            rest.trim_end_matches('/').to_string()
        })
        .unwrap_or_default();
    if base.is_empty() || base.starts_with('/') {
        base
    } else {
        format!("/{base}")
    }
}

/// True when `v` has an `oneOf` / `anyOf` key anywhere (those are only partially exercised).
fn uses_one_of(v: &Value) -> bool {
    match v {
        Value::Object(m) => {
            m.contains_key("oneOf") || m.contains_key("anyOf") || m.values().any(uses_one_of)
        }
        Value::Array(a) => a.iter().any(uses_one_of),
        _ => false,
    }
}

/// Methods a raw path item declares (following a path-item `$ref`), without resolving anything
/// else: used to count and name the operations beyond the cap cheaply.
fn declared_methods(root: &Value, item: &Value) -> Vec<&'static str> {
    let mut cur = item;
    for _ in 0..MAX_REF_DEPTH {
        match cur
            .get("$ref")
            .and_then(|r| r.as_str())
            .and_then(|r| lookup(root, r))
        {
            Some(t) => cur = t,
            None => break,
        }
    }
    METHODS
        .iter()
        .copied()
        .filter(|m| cur.get(*m).is_some_and(Value::is_object))
        .collect()
}

/// Parse with the operation cap from `READYHAI_MAX_OPS` (default 2000, ceiling 10000).
pub fn parse(doc: Value) -> Result<Spec> {
    let (cap, note) = max_ops_setting();
    let mut spec = parse_with_cap(doc, cap)?;
    spec.notes.extend(note);
    Ok(spec)
}

/// Parse keeping the first `cap` operations (document order, clamped to 1..=HARD_MAX_OPS). The
/// rest are NOT planned or tested: they are named in `untested` and listed in `over_cap`.
pub fn parse_with_cap(doc: Value, cap: usize) -> Result<Spec> {
    if doc
        .get("openapi")
        .and_then(|v| v.as_str())
        .map(|s| s.starts_with('3'))
        != Some(true)
    {
        bail!("not an OpenAPI 3.x document");
    }
    let cap = cap.clamp(1, HARD_MAX_OPS);
    let global_sec = doc.get("security").cloned().unwrap_or(Value::Null);
    let base_path = base_path_of(&doc);
    let mut ops: Vec<Op> = vec![];
    let mut untested = vec![];
    let mut over_cap: Vec<String> = vec![];
    let mut over_cap_total = 0usize;
    let mut notes = vec![];
    let mut nodes_left = SPEC_NODE_BUDGET;
    let mut truncated_items = 0usize;
    if let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) {
        for (path, raw_item) in paths {
            if ops.len() >= cap {
                // Nothing of this item is planned: count and name its operations without
                // resolving a single schema.
                for m in declared_methods(&doc, raw_item) {
                    over_cap_total += 1;
                    if over_cap.len() < HARD_MAX_OPS {
                        over_cap.push(format!("{} {path}", m.to_uppercase()));
                    }
                }
                continue;
            }
            let mut budget = Budget::new(ITEM_NODE_BUDGET.min(nodes_left));
            let item = resolve_inner(&doc, raw_item, 0, &mut vec![], &mut budget);
            nodes_left = nodes_left.saturating_sub(budget.spent);
            if budget.exhausted {
                truncated_items += 1;
            }
            let shared: &[Value] = item
                .get("parameters")
                .and_then(|p| p.as_array())
                .map(Vec::as_slice)
                .unwrap_or_default();
            for m in METHODS {
                let Some(o) = item.get(m) else { continue };
                if ops.len() >= cap {
                    over_cap_total += 1;
                    if over_cap.len() < HARD_MAX_OPS {
                        over_cap.push(format!("{} {path}", m.to_uppercase()));
                    }
                    continue;
                }
                let mut params: Vec<Param> = vec![];
                let own: &[Value] = o
                    .get("parameters")
                    .and_then(|p| p.as_array())
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                for p in shared.iter().chain(own.iter()) {
                    let Some(name) = p.get("name").and_then(|n| n.as_str()) else {
                        continue;
                    };
                    let loc = p
                        .get("in")
                        .and_then(|n| n.as_str())
                        .unwrap_or("query")
                        .to_string();
                    let required = p.get("required").and_then(|b| b.as_bool()).unwrap_or(false)
                        || loc == "path";
                    let schema = p
                        .get("schema")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({"type": "string"}));
                    params.retain(|x| !(x.name == name && x.loc == loc));
                    params.push(Param {
                        name: name.to_string(),
                        loc,
                        required,
                        schema,
                    });
                }
                // Path template params without a declaration: assume string.
                for seg in path.split('/') {
                    if let Some(n) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
                        && !params.iter().any(|p| p.name == n && p.loc == "path")
                    {
                        params.push(Param {
                            name: n.into(),
                            loc: "path".into(),
                            required: true,
                            schema: serde_json::json!({"type":"string"}),
                        });
                    }
                }
                let rb = o.get("requestBody");
                let body = rb.and_then(|r| json_schema_of(r.get("content")));
                if rb.is_some() && body.is_none() {
                    untested.push(format!(
                        "{} {path}: non-JSON request body",
                        m.to_uppercase()
                    ));
                }
                let body_required = rb
                    .and_then(|r| r.get("required"))
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                let mut responses = BTreeMap::new();
                if let Some(rs) = o.get("responses").and_then(|r| r.as_object()) {
                    for (st, r) in rs {
                        responses.insert(st.to_ascii_uppercase(), json_schema_of(r.get("content")));
                    }
                }
                if uses_one_of(o) {
                    untested.push(format!(
                        "{} {path}: oneOf/anyOf only partially exercised",
                        m.to_uppercase()
                    ));
                }
                ops.push(Op {
                    method: m.to_uppercase(),
                    path: path.clone(),
                    params,
                    body,
                    body_required,
                    responses,
                    secured: is_secured(o, &global_sec),
                });
            }
        }
    }
    if over_cap_total > 0 {
        for k in over_cap.iter().take(LISTED_OVER_CAP) {
            untested.push(format!("{k}: over the {cap}-operation cap"));
        }
        untested.push(format!(
            "{over_cap_total} of {} operation(s) are over the {cap}-operation cap: not planned, not tested (raise {MAX_OPS_ENV}, ceiling {HARD_MAX_OPS})",
            ops.len() + over_cap_total
        ));
        notes.push(format!(
            "OpenAPI spec has {} operations: the first {cap} are tested, {over_cap_total} are reported as untested ({MAX_OPS_ENV} raises the cap, ceiling {HARD_MAX_OPS})",
            ops.len() + over_cap_total
        ));
    }
    if truncated_items > 0 {
        let line = format!(
            "{truncated_items} path item(s) hit the schema expansion budget: some $ref schemas were collapsed to 'any', so generated cases and response checks for them are weaker"
        );
        untested.push(line.clone());
        notes.push(line);
    }
    Ok(Spec {
        base_path,
        ops,
        untested,
        raw: doc,
        cap,
        over_cap,
        over_cap_total,
        notes,
    })
}

pub fn parse_text(text: &str) -> Result<Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(v) => Ok(v),
        Err(_) => serde_norway::from_str::<Value>(text).context("spec is neither JSON nor YAML"),
    }
}

/// Load the spec given via --spec / target.openapi. Ok(None) = none configured.
pub fn load(ctx: &Ctx) -> Result<Option<Spec>> {
    let qa = match &ctx.qa {
        Some(q) => q,
        None => return Ok(None),
    };
    let loc = match qa.spec.clone().or_else(|| ctx.target.openapi.clone()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let text = if loc.starts_with("http://") || loc.starts_with("https://") {
        qa.throttle()?;
        let c = super::exec::client()?;
        let r = c
            .get(&loc)
            .send()
            .with_context(|| format!("fetch spec {loc}"))?;
        if !r.status().is_success() {
            bail!("spec fetch {loc}: HTTP {}", r.status());
        }
        if r.content_length().is_some_and(|n| n > MAX_SPEC_BYTES) {
            bail!("spec {loc} is larger than {} MiB", MAX_SPEC_BYTES >> 20);
        }
        let t = r.text()?;
        if t.len() as u64 > MAX_SPEC_BYTES {
            bail!("spec {loc} is larger than {} MiB", MAX_SPEC_BYTES >> 20);
        }
        t
    } else {
        if std::fs::metadata(&loc).is_ok_and(|m| m.len() > MAX_SPEC_BYTES) {
            bail!("spec {loc} is larger than {} MiB", MAX_SPEC_BYTES >> 20);
        }
        std::fs::read_to_string(&loc).with_context(|| format!("read spec {loc}"))?
    };
    let doc = parse_text(&text)?;
    drop(text);
    let mut spec = parse(doc)?;
    spec.untested.sort();
    spec.untested.dedup();
    Ok(Some(spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ref_resolution_and_cycles() {
        let doc = json!({"components":{"schemas":{
            "A":{"type":"object","properties":{"b":{"$ref":"#/components/schemas/B"}}},
            "B":{"type":"object","properties":{"a":{"$ref":"#/components/schemas/A"}}},
            "S":{"type":"string"}}}});
        let r = resolve(&doc, &json!({"$ref":"#/components/schemas/S"}));
        assert_eq!(r, json!({"type":"string"}));
        let r = resolve(&doc, &json!({"$ref":"#/components/schemas/A"}));
        // cycle collapsed to {}
        assert_eq!(r["properties"]["b"]["properties"]["a"], json!({}));
        let r = resolve(&doc, &json!({"$ref":"#/components/schemas/Nope"}));
        assert_eq!(r, json!({}));
    }

    #[test]
    fn parses_ops_security_and_base_path() {
        let doc = json!({"openapi":"3.0.3","servers":[{"url":"http://x/api/v1/"}],"security":[{"b":[]}],
          "paths":{"/a/{id}":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object"}}}}}},
                              "post":{"security":[],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object"}}}},"responses":{}}}}});
        let s = parse(doc).unwrap();
        assert_eq!(s.base_path, "/api/v1");
        assert_eq!(s.ops.len(), 2);
        let g = s.ops.iter().find(|o| o.method == "GET").unwrap();
        assert!(g.secured);
        assert_eq!(g.path_params().count(), 1);
        let p = s.ops.iter().find(|o| o.method == "POST").unwrap();
        assert!(!p.secured && p.body.is_some() && p.body_required);
    }

    #[test]
    fn base_path_variants() {
        let bp = |u: &str| base_path_of(&json!({"servers":[{"url":u}]}));
        assert_eq!(bp("http://x/api/v1/"), "/api/v1");
        assert_eq!(bp("https://x"), "");
        assert_eq!(bp("/v2"), "/v2");
        assert_eq!(bp("v3"), "/v3");
        assert_eq!(base_path_of(&json!({})), "");
    }

    #[test]
    fn max_ops_setting_defaults_clamps_and_explains() {
        assert_eq!(parse_max_ops(None), (DEFAULT_MAX_OPS, None));
        assert_eq!(parse_max_ops(Some("  ")), (DEFAULT_MAX_OPS, None));
        assert_eq!(parse_max_ops(Some("1500")), (1500, None));
        assert_eq!(parse_max_ops(Some("1_500")), (1500, None));
        assert_eq!(parse_max_ops(Some("10000")), (HARD_MAX_OPS, None));
        let (n, note) = parse_max_ops(Some("999999"));
        assert_eq!(n, HARD_MAX_OPS);
        assert!(note.unwrap().contains("above the ceiling"));
        for bad in ["0", "-3", "lots", "1.5"] {
            let (n, note) = parse_max_ops(Some(bad));
            assert_eq!(n, DEFAULT_MAX_OPS, "{bad}");
            assert!(note.unwrap().contains("not a positive integer"), "{bad}");
        }
        assert_eq!((DEFAULT_MAX_OPS, HARD_MAX_OPS), (2000, 10_000));
    }

    #[test]
    fn the_cap_keeps_the_first_operations_and_names_the_rest() {
        let item = |n: &str| json!({"get": {"operationId": n}, "post": {}});
        let doc = json!({"openapi":"3.0.0","paths":{
            "/a": item("a"), "/b": item("b"), "/c": {"$ref": "#/components/pathItems/C"}, "/d": item("d")},
            "components": {"pathItems": {"C": item("c")}}});
        let s = parse_with_cap(doc.clone(), 3).unwrap();
        assert_eq!(s.ops.len(), 3);
        assert_eq!(
            s.ops.iter().map(Op::key).collect::<Vec<_>>(),
            ["GET /a", "POST /a", "GET /b"]
        );
        // a path item that is a `$ref` is counted too, without resolving its schemas
        assert_eq!(
            s.over_cap,
            ["POST /b", "GET /c", "POST /c", "GET /d", "POST /d"]
        );
        assert_eq!(s.over_cap_total, 5);
        assert!(
            s.untested
                .iter()
                .any(|u| u == "GET /c: over the 3-operation cap")
        );
        assert!(
            s.untested
                .iter()
                .any(|u| u.starts_with("5 of 8 operation(s) are over the 3-operation cap"))
        );
        // a cap of 0 still keeps one operation; the default parse keeps all 8
        assert_eq!(parse_with_cap(doc.clone(), 0).unwrap().ops.len(), 1);
        let all = parse_with_cap(doc, 100).unwrap();
        assert_eq!((all.ops.len(), all.over_cap_total), (8, 0));
        assert!(all.untested.is_empty() && all.notes.is_empty());
    }

    #[test]
    fn a_wide_ref_fan_out_is_cut_by_the_expansion_budget_not_by_memory() {
        // 12 schemas each pointing at the next 20 times: depth 4 would expand to ~8000 copies per ref
        let mut schemas = serde_json::Map::new();
        for i in 0..12 {
            let next = json!({"$ref": format!("#/components/schemas/S{}", (i + 1) % 12)});
            let props: serde_json::Map<String, Value> = (0..20)
                .map(|k| (format!("p{k}"), next.clone()))
                .chain([("id".to_string(), json!({"type": "string"}))])
                .collect();
            schemas.insert(
                format!("S{i}"),
                json!({"type": "object", "properties": props}),
            );
        }
        let mut paths = serde_json::Map::new();
        for i in 0..40 {
            paths.insert(
                format!("/r{i}"),
                json!({"post": {"requestBody": {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/S0"}}}}}}),
            );
        }
        let doc = json!({"openapi":"3.0.0","paths":paths,"components":{"schemas":schemas}});
        let t = std::time::Instant::now();
        let s = parse_with_cap(doc, 100).unwrap();
        assert!(
            t.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            t.elapsed()
        );
        assert_eq!(s.ops.len(), 40);
        // the schemas are still there (refs resolved) but cut off where the budget ran out
        let b = s.ops[0].body.as_ref().unwrap();
        assert!(b["properties"]["id"].is_object());
        assert!(b.to_string().len() < 6_000_000 * 20);
        // ...and the spec says so instead of pretending the schemas are complete
        assert!(
            s.untested.iter().any(|u| u.contains("expansion budget")),
            "{:?}",
            s.untested
        );
        assert!(s.notes.iter().any(|u| u.contains("expansion budget")));
    }

    #[test]
    fn pointers_keep_non_ascii_names() {
        let doc = json!({"components":{"schemas":{"Użytkownik":{"type":"string"},"a/b":{"type":"integer"}}}});
        assert_eq!(
            resolve(
                &doc,
                &json!({"$ref":"#/components/schemas/U%C5%BCytkownik"})
            ),
            json!({"type":"string"})
        );
        assert_eq!(
            resolve(&doc, &json!({"$ref":"#/components/schemas/Użytkownik"})),
            json!({"type":"string"})
        );
        assert_eq!(
            resolve(&doc, &json!({"$ref":"#/components/schemas/a~1b"})),
            json!({"type":"integer"})
        );
    }

    #[test]
    fn one_of_anywhere_in_an_operation_is_listed_as_partially_exercised() {
        let doc = json!({"openapi":"3.0.0","paths":{"/x":{"post":{"requestBody":{"content":{"application/json":{
            "schema":{"type":"object","properties":{"v":{"oneOf":[{"type":"string"},{"type":"integer"}]}}}}}}}}}});
        let s = parse(doc).unwrap();
        assert!(
            s.untested
                .iter()
                .any(|u| u == "POST /x: oneOf/anyOf only partially exercised")
        );
    }

    #[test]
    fn yaml_spec() {
        let v = parse_text("openapi: 3.0.0\npaths: {}\n").unwrap();
        assert!(parse(v).is_ok());
    }
}
