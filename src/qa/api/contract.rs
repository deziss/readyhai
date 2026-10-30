//! Response contract checks: schema-subset validator, documented status, error leakage, breaking changes.
use super::spec::{Op, Spec};
use super::synth::{flatten, schema_type};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::OnceLock;

fn type_ok(t: &str, v: &Value) -> bool {
    match t {
        "string" => v.is_string(),
        "integer" => {
            v.is_i64()
                || v.is_u64()
                || v.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false) && v.is_number()
        }
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
        "email" => {
            s.contains('@')
                && s.split('@')
                    .nth(1)
                    .map(|d| d.contains('.'))
                    .unwrap_or(false)
        }
        "uuid" => {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap()).is_match(s)
        }
        "date-time" => {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}").unwrap())
                .is_match(s)
        }
        "date" => {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap())
                .is_match(s)
        }
        "uri" | "url" => s.contains("://") || s.starts_with('/'),
        _ => true,
    }
}

/// Validate `v` against the schema subset. Returns the first mismatch as "$.path: message".
pub fn validate(schema: &Value, v: &Value, path: &str) -> Option<String> {
    let s = flatten(schema);
    if let Some(alts) = s
        .get("oneOf")
        .or_else(|| s.get("anyOf"))
        .and_then(|a| a.as_array())
    {
        if alts.is_empty() || alts.iter().any(|a| validate(a, v, path).is_none()) {
            return None;
        }
        return Some(format!(
            "{path}: matches none of the oneOf/anyOf alternatives"
        ));
    }
    if v.is_null() {
        let nullable = s.get("nullable").and_then(|n| n.as_bool()).unwrap_or(false)
            || s.get("type")
                .and_then(|t| t.as_array())
                .map(|a| a.iter().any(|x| x == "null"))
                .unwrap_or(false)
            || s.get("type").is_none();
        return if nullable {
            None
        } else {
            Some(format!("{path}: null not allowed"))
        };
    }
    if s.get("type").is_some() || s.get("properties").is_some() {
        let t = schema_type(&s);
        if !type_ok(t, v) {
            return Some(format!("{path}: expected {t}, got {}", kind(v)));
        }
    }
    if let Some(e) = s.get("enum").and_then(|e| e.as_array())
        && !e.contains(v)
    {
        return Some(format!("{path}: value not in enum"));
    }
    if let (Some(f), Some(st)) = (s.get("format").and_then(|f| f.as_str()), v.as_str())
        && !format_ok(f, st)
    {
        return Some(format!("{path}: not a valid {f}"));
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
                if let Some(x) = o.get(k)
                    && let Some(m) = validate(ps, x, &format!("{path}.{k}"))
                {
                    return Some(m);
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
    r.replace_all(m.split(':').next().unwrap_or(m), "[]")
        .into_owned()
}

/// Schema for a status code: exact, then "2XX", then "default".
pub fn schema_for(op: &Op, status: u16) -> Option<Option<&Value>> {
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

/// HTML attribute values (`href="/home/x"`) are navigation, never an error disclosure.
fn strip_attrs(body: &str) -> std::borrow::Cow<'_, str> {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:href|src|action|data-[\w-]+)\s*=\s*(?:"[^"]*"|'[^']*')"#).unwrap()
    })
    .replace_all(body, "")
}

/// Returns the leak label if the body shows an internal error disclosure. Callers only run it on
/// error responses (status >= 400); the patterns still avoid prose and navigation links.
pub fn leak_kind(body: &str) -> Option<&'static str> {
    static R: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let rs = R.get_or_init(|| {
        [
            ("python_traceback", r"Traceback \(most recent call last\)"),
            ("python_file", r#"File "[^"]+\.py", line \d+"#),
            // Java/Kotlin/Scala: at pkg.Class.method(File.java:12) | (Native Method) | (Unknown Source)
            ("java_frame", r"\bat\s+[\w$.<>]+\((?:[\w$]+\.(?:java|kt|scala|groovy)(?::\d+)?|Native Method|Unknown Source)\)"),
            // Node: at fn (/abs/path/file.js:10:5) | at async fn (file:///x.js:1:2)
            ("node_frame", r"\bat\s+(?:async\s+)?[\w$.<>\[\] ]+\s\((?:/|file:|[A-Za-z]:\\)[^)\s]+:\d+:\d+\)"),
            // .NET: at Ns.Class.Method(args) in C:\x\File.cs:line 12
            ("dotnet_frame", r"\bat\s+[\w.<>]+\([^)]*\)\s+in\s+\S+:line\s+\d+"),
            ("sqlstate", r"SQLSTATE"),
            ("oracle", r"ORA-\d{5}"),
            ("java_thread", r#"Exception in thread ""#),
            // a `stackTrace` / `stack_trace` JSON key, or a "Stack trace:" heading; not the words in prose
            ("stack_trace", r#"(?i)"stack_?trace"\s*:|(?m)^\s*stack ?trace\s*:"#),
            // absolute source paths of the server (not "/home/" nav links)
            ("server_path", r#"(?:^|[\s"'(=:])(?:/home/[\w.-]+|/usr/src|/usr/local/lib|/var/www|/opt|/srv|/app|/workspace|/root)/[\w./@+-]*\.(?:py|rb|php|js|ts|java|go|rs|cs|kt|scala|jar)\b"#),
            ("server_path", r"[A-Za-z]:\\(?:[\w .-]+\\)+[\w.-]+\.(?:py|cs|java|js|ts|rb|php)\b"),
        ]
        .iter()
        .map(|(k, p)| (*k, Regex::new(p).unwrap()))
        .collect()
    });
    let body = strip_attrs(body);
    rs.iter().find(|(_, r)| r.is_match(&body)).map(|x| x.0)
}

/// Short, volatile-free fingerprint of an error body for root-cause grouping: the first
/// meaningful line (JSON `message`/`error`/`detail` when present), numbers/uuids normalised by
/// the caller's signature function, at most 120 chars. Empty when the body says nothing.
pub fn body_fingerprint(body: &str) -> String {
    let t = body.trim();
    if t.is_empty() {
        return String::new();
    }
    let mut text = t.to_string();
    if let Ok(v) = serde_json::from_str::<Value>(t) {
        for k in [
            "message",
            "error",
            "detail",
            "title",
            "exception",
            "msg",
            "error_description",
        ] {
            if let Some(m) = v.get(k).and_then(|x| {
                x.as_str()
                    .map(String::from)
                    .or_else(|| x.get("message").and_then(|y| y.as_str()).map(String::from))
            }) {
                text = m;
                break;
            }
        }
    }
    let stripped = strip_attrs(&text).into_owned();
    let line = stripped
        .lines()
        .map(|l| l.trim())
        .find(|l| {
            !l.is_empty() && !l.starts_with('<') && !l.starts_with('{') && !l.starts_with('[')
        })
        .map(str::to_string)
        .unwrap_or_else(|| stripped.split_whitespace().collect::<Vec<_>>().join(" "));
    let mut out: String = line.chars().take(120).collect();
    if let Some(l) = leak_kind(body) {
        out = format!("[{l}] {out}");
    }
    out
}

fn response_fields(op: &Op, out: &mut BTreeSet<String>) {
    for (st, sch) in &op.responses {
        if st.starts_with('2')
            && let Some(s) = sch
        {
            collect(s, "$", &st.to_string(), out, 0);
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
    if let Some(b) = &op.body
        && let Some(r) = flatten(b).get("required").and_then(|r| r.as_array())
    {
        for x in r.iter().filter_map(|x| x.as_str()) {
            s.insert(format!("body:{x}"));
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
        match new
            .ops
            .iter()
            .find(|n| n.method == o.method && n.path == o.path)
        {
            None => out.push(Breaking {
                op: o.key(),
                what: "operation removed".into(),
                key: format!("{}|removed_op", o.key()),
            }),
            Some(n) => {
                let (mut of, mut nf) = (BTreeSet::new(), BTreeSet::new());
                response_fields(o, &mut of);
                response_fields(n, &mut nf);
                for f in of.difference(&nf) {
                    out.push(Breaking {
                        op: o.key(),
                        what: format!("response field removed: {f}"),
                        key: format!("{}|removed_field|{f}", o.key()),
                    });
                }
                let (or, nr) = (required_request_fields(o), required_request_fields(n));
                for f in nr.difference(&or) {
                    out.push(Breaking {
                        op: o.key(),
                        what: format!("new required request field: {f}"),
                        key: format!("{}|new_required|{f}", o.key()),
                    });
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
        assert_eq!(
            validate(&s, &json!({"id":1}), "$").unwrap(),
            "$.total: required property missing"
        );
        assert!(
            validate(&s, &json!({"id":"x","total":1}), "$")
                .unwrap()
                .starts_with("$.id: expected integer")
        );
        assert!(
            validate(&s, &json!({"id":1,"total":1,"status":"zzz"}), "$")
                .unwrap()
                .contains("enum")
        );
        assert!(
            validate(&s, &json!({"id":1,"total":1,"email":"nope"}), "$")
                .unwrap()
                .contains("email")
        );
        assert!(
            validate(&s, &json!({"id":1,"total":1,"tags":[1]}), "$")
                .unwrap()
                .starts_with("$.tags[0]")
        );
        assert_eq!(
            normalize_mismatch("$.items[3].total: required property missing"),
            "$.items[].total"
        );
    }

    #[test]
    fn leak_detection() {
        assert_eq!(
            leak_kind("Traceback (most recent call last):\n File \"/x/app.py\", line 3"),
            Some("python_traceback")
        );
        assert_eq!(leak_kind("ORA-00942: table"), Some("oracle"));
        assert_eq!(leak_kind("{\"error\":\"bad request\"}"), None);
        assert_eq!(
            leak_kind("\tat com.acme.shop.OrderService.load(OrderService.java:42)"),
            Some("java_frame")
        );
        assert_eq!(
            leak_kind("    at handler (/srv/app/server.js:10:5)"),
            Some("node_frame")
        );
        assert_eq!(
            leak_kind("error in /home/deploy/app/main.py near x"),
            Some("server_path")
        );
        assert_eq!(leak_kind("{\"stackTrace\": \"x\"}"), Some("stack_trace"));
        assert_eq!(leak_kind("{\"stack_trace\": \"x\"}"), Some("stack_trace"));
    }

    #[test]
    fn leak_ignores_navigation_and_prose() {
        // a normal 404 page with nav links and the words "stack trace" in prose
        let html = r#"<nav><a href="/home/index.js">Home</a> <a href="/usr/src/docs.py">Docs</a> <a href="/home/">h</a></nav>
            <p>Look at example.com(now) for help; we never show a stack trace to users.</p>"#;
        assert_eq!(leak_kind(html), None);
        assert_eq!(leak_kind("Visit /home/ or /usr/src/ for more"), None);
        assert_eq!(leak_kind("arrived at home.page(1)"), None);
    }

    #[test]
    fn body_fingerprint_is_stable_and_specific() {
        let a = body_fingerprint(
            "{\"message\":\"relation \\\"orders\\\" does not exist\",\"code\":500}",
        );
        let b = body_fingerprint("{\"message\":\"division by zero\"}");
        assert_ne!(a, b);
        assert!(a.contains("relation"));
        assert_eq!(body_fingerprint(""), "");
        assert!(
            body_fingerprint(
                "Traceback (most recent call last):\n  File \"/a/b.py\", line 3\nValueError: x"
            )
            .starts_with("[python_traceback]")
        );
    }

    #[test]
    fn breaking_diff() {
        let mk = |extra: Value, req: Value| {
            super::super::spec::parse(json!({"openapi":"3.0.0","paths":{
              "/a":{"get":{"responses":{"200":{"description":"","content":{"application/json":{"schema":{"type":"object","properties":extra}}}}}}},
              "/b":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":req,"properties":{"x":{"type":"string"}}}}}},"responses":{}}}}})).unwrap()
        };
        let old = mk(
            json!({"id":{"type":"integer"},"gone":{"type":"string"}}),
            json!([]),
        );
        let new = mk(json!({"id":{"type":"integer"}}), json!(["x"]));
        let d = breaking_changes(&old, &new);
        assert!(
            d.iter()
                .any(|b| b.what.contains("response field removed: 200 $.gone"))
        );
        assert!(
            d.iter()
                .any(|b| b.what.contains("new required request field: body:x"))
        );
    }
}
