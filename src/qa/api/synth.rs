//! Value synthesis from JSON schema + positive/boundary/negative/inert-marker case generation.
use super::spec::{Op, Param};
use crate::qa::model::Technique;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

pub const MARKER: &str = "readyhai'\"<rh>{{7*7}}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Valid input: expect 2xx (anything but 5xx is checked; 4xx noted as a failed case).
    Success,
    /// Invalid input: expect 4xx (400/422...). 5xx = server_error, 2xx = validation_missing.
    Reject,
    /// Odd-but-maybe-accepted input: only 5xx / reflection is a defect.
    NoServerError,
}

#[derive(Debug, Clone)]
pub struct Case {
    /// Stable technique label, e.g. "positive", "boundary.maxlen.note".
    pub kind: String,
    pub technique: Technique,
    pub title: String,
    pub path_vals: HashMap<String, String>,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub expect: Expect,
    pub marker: bool,
}

/// Merge `allOf` members into one schema (properties/required unioned).
pub fn flatten(s: &Value) -> Value {
    let Some(all) = s.get("allOf").and_then(|a| a.as_array()) else { return s.clone() };
    let mut out = s.as_object().cloned().unwrap_or_default();
    out.remove("allOf");
    let mut props = out.get("properties").and_then(|p| p.as_object()).cloned().unwrap_or_default();
    let mut req: Vec<Value> = out.get("required").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    for m in all {
        let m = flatten(m);
        if let Some(p) = m.get("properties").and_then(|p| p.as_object()) {
            props.extend(p.clone());
        }
        if let Some(r) = m.get("required").and_then(|r| r.as_array()) {
            req.extend(r.clone());
        }
        if let Some(mo) = m.as_object() {
            for (k, v) in mo {
                if k != "properties" && k != "required" {
                    out.entry(k.clone()).or_insert(v.clone());
                }
            }
        }
    }
    if !props.is_empty() {
        out.insert("properties".into(), Value::Object(props));
    }
    if !req.is_empty() {
        out.insert("required".into(), Value::Array(req));
    }
    Value::Object(out)
}

fn first_of(s: &Value) -> Value {
    for k in ["oneOf", "anyOf"] {
        if let Some(f) = s.get(k).and_then(|a| a.as_array()).and_then(|a| a.first()) {
            return flatten(f);
        }
    }
    flatten(s)
}

pub fn schema_type(s: &Value) -> &str {
    if let Some(t) = s.get("type") {
        if let Some(t) = t.as_str() {
            return t;
        }
        if let Some(t) = t.as_array().and_then(|a| a.iter().filter_map(|x| x.as_str()).find(|x| *x != "null")) {
            return t;
        }
    }
    if s.get("properties").is_some() {
        "object"
    } else if s.get("items").is_some() {
        "array"
    } else {
        "string"
    }
}

fn num(s: &Value, k: &str) -> Option<f64> {
    s.get(k).and_then(|v| v.as_f64())
}

fn clip(mut v: String, s: &Value) -> String {
    if let Some(m) = num(s, "maxLength") {
        v.truncate(m as usize);
    }
    if let Some(m) = num(s, "minLength") {
        while v.len() < m as usize {
            v.push('x');
        }
    }
    v
}

/// Synthesize one valid value. `tag` prefixes free strings ("readyhai-<run>-") so created data is identifiable.
pub fn synth(schema: &Value, name: &str, tag: &str, depth: usize) -> Value {
    let s = first_of(schema);
    if depth > 5 {
        return Value::Null;
    }
    if let Some(e) = s.get("example") {
        return e.clone();
    }
    if let Some(d) = s.get("default") {
        return d.clone();
    }
    if let Some(e) = s.get("enum").and_then(|e| e.as_array()).and_then(|e| e.first()) {
        return e.clone();
    }
    match schema_type(&s) {
        "integer" => {
            let lo = num(&s, "minimum").unwrap_or(1.0).max(1.0).min(num(&s, "maximum").unwrap_or(f64::MAX));
            json!(lo as i64)
        }
        "number" => {
            let lo = num(&s, "minimum").unwrap_or(1.0).max(1.0).min(num(&s, "maximum").unwrap_or(f64::MAX));
            json!(lo)
        }
        "boolean" => json!(true),
        "array" => {
            let it = s.get("items").cloned().unwrap_or(json!({}));
            let n = num(&s, "minItems").unwrap_or(1.0).max(1.0) as usize;
            Value::Array((0..n.min(3)).map(|_| synth(&it, name, tag, depth + 1)).collect())
        }
        "object" => {
            let props = s.get("properties").and_then(|p| p.as_object()).cloned().unwrap_or_default();
            let req: Vec<String> =
                s.get("required").and_then(|r| r.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            let mut m = Map::new();
            for (k, v) in &props {
                if req.contains(k) || req.is_empty() {
                    m.insert(k.clone(), synth(v, k, tag, depth + 1));
                }
            }
            Value::Object(m)
        }
        _ => {
            let v = match s.get("format").and_then(|f| f.as_str()) {
                Some("email") => "readyhai-qa@example.com".to_string(),
                Some("uuid") => "00000000-0000-4000-8000-000000000001".into(),
                Some("date-time") => "2024-01-01T00:00:00Z".into(),
                Some("date") => "2024-01-01".into(),
                Some("uri") | Some("url") => "https://example.com/readyhai".into(),
                _ => format!("{tag}{name}"),
            };
            Value::String(clip(v, &s))
        }
    }
}

pub fn value_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        o => o.to_string(),
    }
}

pub fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Base URL + path template with values + query.
pub fn build_url(base: &str, path: &str, vals: &HashMap<String, String>, query: &[(String, String)]) -> String {
    let mut p = String::new();
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            p.push('/');
        }
        if let Some(n) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            p.push_str(&pct(vals.get(n).map(|s| s.as_str()).unwrap_or("1")));
        } else {
            p.push_str(seg);
        }
    }
    let mut u = format!("{}{}", base.trim_end_matches('/'), p);
    if !query.is_empty() {
        let q: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", pct(k), pct(v))).collect();
        u.push('?');
        u.push_str(&q.join("&"));
    }
    u
}

fn base_vals(op: &Op, tag: &str, ids: &HashMap<String, String>) -> (HashMap<String, String>, Vec<(String, String)>) {
    let mut pv = HashMap::new();
    let mut q = vec![];
    for p in &op.params {
        match p.loc.as_str() {
            "path" => {
                let v = ids.get(&p.name).cloned().unwrap_or_else(|| value_str(&synth(&p.schema, &p.name, "", 0)));
                pv.insert(p.name.clone(), v);
            }
            "query" if p.required => q.push((p.name.clone(), value_str(&synth(&p.schema, &p.name, tag, 0)))),
            _ => {}
        }
    }
    (pv, q)
}

fn body_props(op: &Op) -> (Value, Vec<String>, Map<String, Value>) {
    let s = op.body.as_ref().map(flatten).unwrap_or(json!({}));
    let req = s.get("required").and_then(|r| r.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let props = s.get("properties").and_then(|p| p.as_object()).cloned().unwrap_or_default();
    (s, req, props)
}

fn violations(p: &Value) -> Vec<(String, Value)> {
    let p = flatten(p);
    let mut v = vec![];
    match schema_type(&p) {
        "string" => {
            if let Some(m) = num(&p, "maxLength") {
                v.push(("maxlen".into(), Value::String("a".repeat(m as usize + 1))));
            }
            if num(&p, "minLength").unwrap_or(0.0) > 0.0 {
                v.push(("minlen".into(), Value::String(String::new())));
            }
            if p.get("enum").is_some() {
                v.push(("enum".into(), json!("readyhai-not-in-enum")));
            }
        }
        "integer" | "number" => {
            if let Some(m) = num(&p, "minimum") {
                v.push(("min".into(), json!(m as i64 - 1)));
            }
            if let Some(m) = num(&p, "maximum") {
                v.push(("max".into(), json!(m as i64 + 1)));
            }
        }
        _ => {}
    }
    v
}

fn wrong_type(p: &Value) -> Value {
    match schema_type(&flatten(p)) {
        "string" => json!(12345),
        "integer" | "number" => json!("not-a-number"),
        "boolean" => json!("maybe"),
        _ => json!("not-an-object"),
    }
}

/// Generate all cases for one operation.
pub fn generate(op: &Op, tag: &str, deep: bool, ids: &HashMap<String, String>) -> Vec<Case> {
    let (pv, q) = base_vals(op, tag, ids);
    let (bschema, req, props) = body_props(op);
    let base_body: Option<Value> = op.body.as_ref().map(|b| synth(b, "body", tag, 0));
    let mk = |kind: String, tech: Technique, title: String, q: Vec<(String, String)>, body: Option<Value>, expect: Expect, marker: bool| Case {
        kind,
        technique: tech,
        title,
        path_vals: pv.clone(),
        query: q,
        body,
        expect,
        marker,
    };
    let mut cases = vec![mk("positive".into(), Technique::Positive, "valid request".into(), q.clone(), base_body.clone(), Expect::Success, false)];
    let mut bcount = 0;
    // Body boundaries: optional props are added so their limits can be probed.
    if let (Some(Value::Object(bb)), true) = (&base_body, !props.is_empty()) {
        for (k, ps) in &props {
            for (kind, bad) in violations(ps) {
                if bcount >= 6 {
                    break;
                }
                bcount += 1;
                let mut b = bb.clone();
                b.insert(k.clone(), bad);
                cases.push(mk(format!("boundary.{kind}.{k}"), Technique::Boundary, format!("{k}: {kind} violation"), q.clone(), Some(Value::Object(b)), Expect::Reject, false));
            }
        }
    }
    for p in op.params.iter().filter(|p| p.loc == "query") {
        for (kind, bad) in violations(&p.schema) {
            if bcount >= 6 {
                break;
            }
            bcount += 1;
            let mut qq: Vec<_> = q.iter().filter(|x| x.0 != p.name).cloned().collect();
            qq.push((p.name.clone(), value_str(&bad)));
            cases.push(mk(format!("boundary.{kind}.{}", p.name), Technique::Boundary, format!("query {}: {kind} violation", p.name), qq, base_body.clone(), Expect::Reject, false));
        }
    }
    // Negative: missing required body props, wrong type, null, extra prop, 1MB (deep).
    if let Some(Value::Object(bb)) = &base_body {
        for k in req.iter().take(2) {
            let mut b = bb.clone();
            b.remove(k);
            cases.push(mk(format!("negative.missing.{k}"), Technique::Negative, format!("missing required '{k}'"), q.clone(), Some(Value::Object(b)), Expect::Reject, false));
        }
        if let Some((k, ps)) = props.iter().find(|(k, _)| req.contains(k)).or_else(|| props.iter().next()) {
            let mut b = bb.clone();
            b.insert(k.clone(), wrong_type(ps));
            cases.push(mk(format!("negative.wrongtype.{k}"), Technique::Negative, format!("'{k}' has the wrong type"), q.clone(), Some(Value::Object(b)), Expect::Reject, false));
            let mut b = bb.clone();
            b.insert(k.clone(), Value::Null);
            cases.push(mk(format!("negative.null.{k}"), Technique::Negative, format!("'{k}' is null"), q.clone(), Some(Value::Object(b)), Expect::Reject, false));
        }
        let mut b = bb.clone();
        b.insert("readyhai_extra".into(), json!("x"));
        cases.push(mk("negative.extra".into(), Technique::Negative, "unknown extra property".into(), q.clone(), Some(Value::Object(b)), Expect::NoServerError, false));
        if deep {
            if let Some((k, _)) = props.iter().find(|(_, p)| schema_type(&flatten(p)) == "string") {
                let mut b = bb.clone();
                b.insert(k.clone(), Value::String("A".repeat(1_000_000)));
                cases.push(mk(format!("negative.1mb.{k}"), Technique::Negative, format!("1 MB string in '{k}'"), q.clone(), Some(Value::Object(b)), Expect::NoServerError, false));
            }
        }
        // Inert marker in the first string property.
        if let Some((k, _)) = props.iter().find(|(_, p)| schema_type(&flatten(p)) == "string" && p.get("enum").is_none() && p.get("format").is_none()) {
            let mut b = bb.clone();
            b.insert(k.clone(), json!(MARKER));
            cases.push(mk(format!("marker.body.{k}"), Technique::Negative, format!("inert marker in '{k}'"), q.clone(), Some(Value::Object(b)), Expect::NoServerError, true));
        }
    }
    let _ = bschema;
    // Required query params: missing / wrong type / marker.
    let qparams: Vec<&Param> = op.params.iter().filter(|p| p.loc == "query").collect();
    for p in qparams.iter().filter(|p| p.required).take(2) {
        let qq: Vec<_> = q.iter().filter(|x| x.0 != p.name).cloned().collect();
        cases.push(mk(format!("negative.missing.{}", p.name), Technique::Negative, format!("missing required query '{}'", p.name), qq, base_body.clone(), Expect::Reject, false));
    }
    if let Some(p) = qparams.iter().find(|p| matches!(schema_type(&flatten(&p.schema)), "integer" | "number")) {
        let mut qq: Vec<_> = q.iter().filter(|x| x.0 != p.name).cloned().collect();
        qq.push((p.name.clone(), "not-a-number".into()));
        cases.push(mk(format!("negative.wrongtype.{}", p.name), Technique::Negative, format!("query '{}' not a number", p.name), qq, base_body.clone(), Expect::Reject, false));
    }
    if let Some(p) = qparams.iter().find(|p| schema_type(&flatten(&p.schema)) == "string" && p.schema.get("enum").is_none() && p.schema.get("format").is_none()) {
        let mut qq: Vec<_> = q.iter().filter(|x| x.0 != p.name).cloned().collect();
        qq.push((p.name.clone(), MARKER.into()));
        cases.push(mk(format!("marker.query.{}", p.name), Technique::Negative, format!("inert marker in query '{}'", p.name), qq, base_body.clone(), Expect::NoServerError, true));
    }
    cases
}

/// Pagination edge probes: (param name, bad value).
pub fn pagination_probes(op: &Op) -> Vec<(String, String)> {
    let mut v = vec![];
    for p in op.params.iter().filter(|p| p.loc == "query") {
        if matches!(p.name.to_ascii_lowercase().as_str(), "page" | "limit" | "offset" | "per_page" | "size") {
            for val in ["0", "-1", "1000000"] {
                v.push((p.name.clone(), val.to_string()));
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synth_respects_constraints() {
        let s = json!({"type":"object","required":["email","qty","id","name"],"properties":{
            "email":{"type":"string","format":"email"},
            "qty":{"type":"integer","minimum":5,"maximum":9},
            "id":{"type":"string","format":"uuid"},
            "name":{"type":"string","minLength":12,"maxLength":14},
            "opt":{"type":"string"}}});
        let v = synth(&s, "x", "readyhai-r-", 0);
        assert!(v["email"].as_str().unwrap().contains('@'));
        assert_eq!(v["qty"], 5);
        assert_eq!(v["id"].as_str().unwrap().len(), 36);
        let n = v["name"].as_str().unwrap();
        assert!((12..=14).contains(&n.len()), "{n}");
        assert!(v.get("opt").is_none());
        assert_eq!(synth(&json!({"enum":["a","b"]}), "x", "", 0), "a");
        assert_eq!(synth(&json!({"type":"string","format":"date-time"}), "x", "", 0), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn cases_cover_boundary_negative_marker() {
        let op = Op {
            method: "POST".into(),
            path: "/orders".into(),
            params: vec![],
            body: Some(json!({"type":"object","required":["item","qty"],"properties":{
                "item":{"type":"string"},"qty":{"type":"integer","minimum":1,"maximum":100},
                "note":{"type":"string","maxLength":100}}})),
            body_required: true,
            responses: Default::default(),
            secured: true,
        };
        let c = generate(&op, "readyhai-t-", false, &HashMap::new());
        let kinds: Vec<&str> = c.iter().map(|c| c.kind.as_str()).collect();
        assert!(kinds.contains(&"boundary.maxlen.note"), "{kinds:?}");
        assert!(kinds.contains(&"boundary.max.qty"));
        assert!(kinds.contains(&"boundary.min.qty"));
        assert!(kinds.contains(&"negative.missing.item"));
        assert!(kinds.iter().any(|k| k.starts_with("marker.body")));
        assert!(!kinds.iter().any(|k| k.contains("1mb")));
        let c = generate(&op, "t", true, &HashMap::new());
        assert!(c.iter().any(|c| c.kind.contains("1mb")));
        let m = c.iter().find(|c| c.kind == "boundary.maxlen.note").unwrap();
        assert_eq!(m.body.as_ref().unwrap()["note"].as_str().unwrap().len(), 101);
    }

    #[test]
    fn url_building() {
        let mut v = HashMap::new();
        v.insert("id".to_string(), "a b".to_string());
        let u = build_url("http://h/", "/o/{id}", &v, &[("q".into(), "x'y".into())]);
        assert_eq!(u, "http://h/o/a%20b?q=x%27y");
    }
}
