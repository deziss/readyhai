//! Response contract checks: schema-subset validator, documented status, error leakage, breaking changes.
use super::synth::{flatten, schema_type};
use super::spec::{Op, Spec};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::OnceLock;

fn type_ok(t: &str, v: &Value) -> bool {
    match t {
        "string" => v.is_string(),
        "integer" => v.is_i64() || v.is_u64() || v.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false) && v.is_number(),
        "number" => v.is_number(),
        "boolean" => v.is_boolean(),
        "array" => v.is_array(),
        "object" => v.is_object(),
        "null" => v.is_null(),
        _ => true,
    }
}

fn format_ok(f: &str, s: &str) -> bool {
    match f {
        "email" => s.contains('@') && s.split('@').nth(1).map(|d| d.contains('.')).unwrap_or(false),
        "uuid" => {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap()).is_match(s)
        }
        "date-time" => {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}").unwrap()).is_match(s)
        }
        "date" => {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap()).is_match(s)
        }
        "uri" | "url" => s.contains("://") || s.starts_with('/'),
        _ => true,
    }
}

/// Validate `v` against the schema subset. Returns the first mismatch as "$.path: message".
pub fn validate(schema: &Value, v: &Value, path: &str) -> Option<String> {
    let s = flatten(schema);
    if let Some(alts) = s.get("oneOf").or_else(|| s.get("anyOf")).and_then(|a| a.as_array()) {
        if alts.is_empty() || alts.iter().any(|a| validate(a, v, path).is_none()) {
            return None;
        }
        return Some(format!("{path}: matches none of the oneOf/anyOf alternatives"));
    }
    if v.is_null() {
        let nullable = s.get("nullable").and_then(|n| n.as_bool()).unwrap_or(false)
            || s.get("type").and_then(|t| t.as_array()).map(|a| a.iter().any(|x| x == "null")).unwrap_or(false)
            || s.get("type").is_none();
        return if nullable { None } else { Some(format!("{path}: null not allowed")) };
    }
    if s.get("type").is_some() || s.get("properties").is_some() {
        let t = schema_type(&s);
        if !type_ok(t, v) {
            return Some(format!("{path}: expected {t}, got {}", kind(v)));
        }
    }
    if let Some(e) = s.get("enum").and_then(|e| e.as_array()) {
        if !e.contains(v) {
            return Some(format!("{path}: value not in enum"));
        }
    }
    if let (Some(f), Some(st)) = (s.get("format").and_then(|f| f.as_str()), v.as_str()) {
        if !format_ok(f, st) {
            return Some(format!("{path}: not a valid {f}"));
        }
    }
    if let Some(o) = v.as_object() {
        if let Some(req) = s.get("required").and_then(|r| r.as_array()) {
            for r in req.iter().filter_map(|r| r.as_str()) {
                if !o.contains_key(r) {
                    return Some(format!("{path}.{r}: required property missing"));
                }
            }
        }
        if let Some(props) = s.get("properties").and_then(|p| p.as_object()) {
            for (k, ps) in props {
                if let Some(x) = o.get(k) {
                    if let Some(m) = validate(ps, x, &format!("{path}.{k}")) {
                        return Some(m);
                    }
                }
            }
        }
    }
    if let (Some(a), Some(items)) = (v.as_array(), s.get("items")) {
        for (i, x) in a.iter().enumerate().take(20) {
            if let Some(m) = validate(items, x, &format!("{path}[{i}]")) {
                return Some(m);
            }
        }
    }
    None
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Stable form of a mismatch ("$.items[3].total: ..." -> "$.items[].total") for fp keys.
pub fn normalize_mismatch(m: &str) -> String {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| Regex::new(r"\[\d+\]").unwrap());
    r.replace_all(m.split(':').next().unwrap_or(m), "[]").into_owned()
}

/// Schema for a status code: exact, then "2XX", then "default".
pub fn schema_for<'a>(op: &'a Op, status: u16) -> Option<Option<&'a Value>> {
    let exact = status.to_string();
    let class = format!("{}XX", status / 100);
    for k in [exact.as_str(), class.as_str(), "DEFAULT"] {
        if let Some(s) = op.responses.get(k) {
            return Some(s.as_ref());
        }
    }
    None
}

pub fn status_documented(op: &Op, status: u16) -> bool {
    op.responses.is_empty() || schema_for(op, status).is_some()
}

/// Returns the leak label if the body shows an internal error disclosure.
pub fn leak_kind(body: &str) -> Option<&'static str> {
    static R: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let rs = R.get_or_init(|| {
        [
            ("python_traceback", r"Traceback \(most recent call last\)"),
            ("python_file", r#"File "[^"]+\.py""#),
            ("stack_frame", r"\bat [a-z][\w$]*\.[A-Za-z_$][\w$.]*\("),
            ("sqlstate", r"SQLSTATE"),
            ("oracle", r"ORA-\d+"),
            ("java_thread", r"Exception in thread"),
            ("stack_trace", r"(?i)stack ?trace"),
            ("server_path", r"/home/|/usr/src/"),
        ]
        .iter()
        .map(|(k, p)| (*k, Regex::new(p).unwrap()))
        .collect()
    });
    rs.iter().find(|(_, r)| r.is_match(body)).map(|x| x.0)
}

fn response_fields(op: &Op, out: &mut BTreeSet<String>) {
    for (st, sch) in &op.responses {
        if st.starts_with('2') {
            if let Some(s) = sch {
                collect(s, "$", &format!("{st}"), out, 0);
            }
        }
    }
}

fn collect(s: &Value, path: &str, st: &str, out: &mut BTreeSet<String>, d: usize) {
    if d > 6 {
        return;
    }
    let s = flatten(s);
    if let Some(p) = s.get("properties").and_then(|p| p.as_object()) {
        for (k, v) in p {
            let np = format!("{path}.{k}");
            out.insert(format!("{st} {np}"));
            collect(v, &np, st, out, d + 1);
        }
    }
    if let Some(i) = s.get("items") {
        collect(i, &format!("{path}[]"), st, out, d + 1);
    }
}

fn required_request_fields(op: &Op) -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    for p in op.params.iter().filter(|p| p.required) {
        s.insert(format!("{}:{}", p.loc, p.name));
    }
    if let Some(b) = &op.body {
        if let Some(r) = flatten(b).get("required").and_then(|r| r.as_array()) {
            for x in r.iter().filter_map(|x| x.as_str()) {
                s.insert(format!("body:{x}"));
            }
        }
    }
    s
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breaking {
    /// "METHOD path" (component)
    pub op: String,
    pub what: String,
    /// stable fp key
    pub key: String,
}

/// Diff current vs baseline spec.
pub fn breaking_changes(old: &Spec, new: &Spec) -> Vec<Breaking> {
    let mut out = vec![];
    for o in &old.ops {
        match new.ops.iter().find(|n| n.method == o.method && n.path == o.path) {
            None => out.push(Breaking { op: o.key(), what: "operation removed".into(), key: format!("{}|removed_op", o.key()) }),
            Some(n) => {
                let (mut of, mut nf) = (BTreeSet::new(), BTreeSet::new());
                response_fields(o, &mut of);
                response_fields(n, &mut nf);
                for f in of.difference(&nf) {
                    out.push(Breaking { op: o.key(), what: format!("response field removed: {f}"), key: format!("{}|removed_field|{f}", o.key()) });
                }
                let (or, nr) = (required_request_fields(o), required_request_fields(n));
                for f in nr.difference(&or) {
                    out.push(Breaking { op: o.key(), what: format!("new required request field: {f}"), key: format!("{}|new_required|{f}", o.key()) });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validator_reports_first_mismatch() {
        let s = json!({"type":"object","required":["id","total"],"properties":{
            "id":{"type":"integer"},"total":{"type":"number"},"status":{"type":"string","enum":["new","paid"]},
            "email":{"type":"string","format":"email"},"tags":{"type":"array","items":{"type":"string"}},
            "opt":{"type":"string","nullable":true}}});
        assert!(validate(&s, &json!({"id":1,"total":2.5,"status":"new","email":"a@b.co","tags":["x"],"opt":null}), "$").is_none());
        assert_eq!(validate(&s, &json!({"id":1}), "$").unwrap(), "$.total: required property missing");
        assert!(validate(&s, &json!({"id":"x","total":1}), "$").unwrap().starts_with("$.id: expected integer"));
        assert!(validate(&s, &json!({"id":1,"total":1,"status":"zzz"}), "$").unwrap().contains("enum"));
        assert!(validate(&s, &json!({"id":1,"total":1,"email":"nope"}), "$").unwrap().contains("email"));
        assert!(validate(&s, &json!({"id":1,"total":1,"tags":[1]}), "$").unwrap().starts_with("$.tags[0]"));
        assert_eq!(normalize_mismatch("$.items[3].total: required property missing"), "$.items[].total");
    }

    #[test]
    fn leak_detection() {
        assert_eq!(leak_kind("Traceback (most recent call last):\n File \"/x/app.py\", line 3"), Some("python_traceback"));
        assert_eq!(leak_kind("ORA-00942: table"), Some("oracle"));
        assert_eq!(leak_kind("{\"error\":\"bad request\"}"), None);
    }

    #[test]
    fn breaking_diff() {
        let mk = |extra: Value, req: Value| {
            super::super::spec::parse(json!({"openapi":"3.0.0","paths":{
              "/a":{"get":{"responses":{"200":{"description":"","content":{"application/json":{"schema":{"type":"object","properties":extra}}}}}}},
              "/b":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":req,"properties":{"x":{"type":"string"}}}}}},"responses":{}}}}})).unwrap()
        };
        let old = mk(json!({"id":{"type":"integer"},"gone":{"type":"string"}}), json!([]));
        let new = mk(json!({"id":{"type":"integer"}}), json!(["x"]));
        let d = breaking_changes(&old, &new);
        assert!(d.iter().any(|b| b.what.contains("response field removed: 200 $.gone")));
        assert!(d.iter().any(|b| b.what.contains("new required request field: body:x")));
    }
}
