//! OpenAPI 3.x loader: local `$ref` resolution (depth <= 4, cycle guard), operation extraction.
use crate::ctx::Ctx;
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const MAX_OPS: usize = 500;
pub const MAX_REF_DEPTH: usize = 4;
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
}

fn pointer_unescape(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Some(Ok(v)) = s.get(i + 1..i + 3).map(|h| u8::from_str_radix(h, 16)) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out.replace("~1", "/").replace("~0", "~")
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

/// Resolve local `$ref`s inside `v`. A ref chain deeper than MAX_REF_DEPTH, or a cycle,
/// collapses to `{}` (= "any") so generators/validators stay safe.
pub fn resolve(root: &Value, v: &Value) -> Value {
    resolve_inner(root, v, 0, &mut vec![])
}

fn resolve_inner(root: &Value, v: &Value, depth: usize, stack: &mut Vec<String>) -> Value {
    match v {
        Value::Object(m) => {
            if let Some(Value::String(r)) = m.get("$ref") {
                if depth >= MAX_REF_DEPTH || stack.contains(r) {
                    return Value::Object(Map::new());
                }
                return match lookup(root, r) {
                    Some(t) => {
                        stack.push(r.clone());
                        let out = resolve_inner(root, t, depth + 1, stack);
                        stack.pop();
                        out
                    }
                    None => Value::Object(Map::new()),
                };
            }
            Value::Object(m.iter().map(|(k, x)| (k.clone(), resolve_inner(root, x, depth, stack))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| resolve_inner(root, x, depth, stack)).collect()),
        _ => v.clone(),
    }
}

fn json_schema_of(content: Option<&Value>) -> Option<Value> {
    let c = content?.as_object()?;
    let m = c
        .iter()
        .find(|(k, _)| k.contains("json"))
        .map(|x| x.1)?;
    m.get("schema").cloned()
}

fn is_secured(op: &Value, global: &Value) -> bool {
    let sec = op.get("security").unwrap_or(global);
    match sec {
        Value::Array(a) => !a.is_empty() && !a.iter().any(|r| r.as_object().map(|o| o.is_empty()).unwrap_or(false)),
        _ => false,
    }
}

/// Path of `servers[0].url` (no trailing slash): "/api/v1", or "" when the server is the origin root.
pub fn base_path_of(doc: &Value) -> String {
    let base = doc
        .pointer("/servers/0/url")
        .and_then(|u| u.as_str())
        .map(|u| {
            let rest = u.split_once("://").map(|x| x.1.split_once('/').map(|y| format!("/{}", y.1)).unwrap_or_default()).unwrap_or_else(|| u.to_string());
            rest.trim_end_matches('/').to_string()
        })
        .unwrap_or_default();
    if base.is_empty() || base.starts_with('/') { base } else { format!("/{base}") }
}

pub fn parse(doc: Value) -> Result<Spec> {
    if doc.get("openapi").and_then(|v| v.as_str()).map(|s| s.starts_with('3')) != Some(true) {
        bail!("not an OpenAPI 3.x document");
    }
    let paths = doc.get("paths").and_then(|p| p.as_object()).cloned().unwrap_or_default();
    let global_sec = doc.get("security").cloned().unwrap_or(Value::Null);
    let base_path = base_path_of(&doc);
    let mut ops = vec![];
    let mut untested = vec![];
    for (path, item) in &paths {
        let item = resolve(&doc, item);
        let shared: Vec<Value> = item.get("parameters").and_then(|p| p.as_array()).cloned().unwrap_or_default();
        for m in METHODS {
            let Some(o) = item.get(m) else { continue };
            if ops.len() >= MAX_OPS {
                untested.push(format!("{} {path}: over the {MAX_OPS}-operation cap", m.to_uppercase()));
                continue;
            }
            let mut params: Vec<Param> = vec![];
            let own = o.get("parameters").and_then(|p| p.as_array()).cloned().unwrap_or_default();
            for p in shared.iter().chain(own.iter()) {
                let Some(name) = p.get("name").and_then(|n| n.as_str()) else { continue };
                let loc = p.get("in").and_then(|n| n.as_str()).unwrap_or("query").to_string();
                let required = p.get("required").and_then(|b| b.as_bool()).unwrap_or(false) || loc == "path";
                let schema = p.get("schema").cloned().unwrap_or_else(|| serde_json::json!({"type": "string"}));
                params.retain(|x| !(x.name == name && x.loc == loc));
                params.push(Param { name: name.to_string(), loc, required, schema });
            }
            // Path template params without a declaration: assume string.
            for seg in path.split('/') {
                if let Some(n) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    if !params.iter().any(|p| p.name == n && p.loc == "path") {
                        params.push(Param { name: n.into(), loc: "path".into(), required: true, schema: serde_json::json!({"type":"string"}) });
                    }
                }
            }
            let rb = o.get("requestBody");
            let body = rb.and_then(|r| json_schema_of(r.get("content")));
            if rb.is_some() && body.is_none() {
                untested.push(format!("{} {path}: non-JSON request body", m.to_uppercase()));
            }
            let body_required = rb.and_then(|r| r.get("required")).and_then(|b| b.as_bool()).unwrap_or(false);
            let mut responses = BTreeMap::new();
            if let Some(rs) = o.get("responses").and_then(|r| r.as_object()) {
                for (st, r) in rs {
                    responses.insert(st.to_ascii_uppercase(), json_schema_of(r.get("content")));
                }
            }
            if o.to_string().contains("\"oneOf\"") || o.to_string().contains("\"anyOf\"") {
                untested.push(format!("{} {path}: oneOf/anyOf only partially exercised", m.to_uppercase()));
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
    Ok(Spec { base_path, ops, untested, raw: doc })
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
        let r = c.get(&loc).send().with_context(|| format!("fetch spec {loc}"))?;
        if !r.status().is_success() {
            bail!("spec fetch {loc}: HTTP {}", r.status());
        }
        r.text()?
    } else {
        std::fs::read_to_string(&loc).with_context(|| format!("read spec {loc}"))?
    };
    let doc = parse_text(&text)?;
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
    fn yaml_spec() {
        let v = parse_text("openapi: 3.0.0\npaths: {}\n").unwrap();
        assert!(parse(v).is_ok());
    }
}
