use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

use super::models::DEFAULT_ID_KEYS;
use crate::agent::oracle::primary_object;
use crate::llm::{is_sensitive_key, redact_for_llm};

fn placeholder_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\{\{\s*([^{}\s]*)\s*\}\}").unwrap())
}

/// Names of every `{{name}}` / `{{ name }}` in `s`.
pub fn placeholder_names(s: &str) -> Vec<String> {
    placeholder_re()
        .captures_iter(s)
        .map(|c| c[1].to_string())
        .collect()
}

/// Substitute context variables `{{var}}` and `{{ var }}` in a string. Unknown placeholders are
/// left in place (the caller must reject them: see [`placeholder_names`]).
pub fn substitute_vars(template: &str, context: &HashMap<String, String>) -> String {
    placeholder_re()
        .replace_all(template, |c: &regex::Captures| match context.get(&c[1]) {
            Some(v) => v.clone(),
            None => c[0].to_string(),
        })
        .into_owned()
}

/// Key names whose values must never be stored: token, key, secret, password, session, auth.
pub fn is_secret_key(k: &str) -> bool {
    if is_sensitive_key(k) {
        return true;
    }
    let low = k.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "session",
        "credential",
        "cookie",
        "jwt",
        "bearer",
        "signature",
        "private",
    ]
    .iter()
    .any(|s| low.contains(s))
        || (low.contains("auth") && !low.contains("author"))
        || low.ends_with("key")
        || low.starts_with("key_")
        || low.starts_with("key-")
}

/// A value as it may be stored: redacted when its key looks secret, otherwise scrubbed.
pub fn storable_value(key: &str, value: &str) -> String {
    if is_secret_key(key) {
        "[REDACTED]".to_string()
    } else {
        redact_for_llm(value)
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None, // objects and arrays are not identifiers
    }
}

/// Extract ids (and any `wanted` names) from the response's top-level or primary object only:
/// never from nested sub-resources (`owner.id`) and never from list items. A top-level object
/// with no identifier of its own is looked through once, into its envelope (`data`, `result`...).
pub fn extract_json_values(
    val: &Value,
    wanted: Option<&[String]>,
    out: &mut HashMap<String, String>,
) {
    let is_wanted = |k: &str| {
        wanted.is_some_and(|w| w.iter().any(|t| t.eq_ignore_ascii_case(k)))
            || DEFAULT_ID_KEYS.contains(&k.to_ascii_lowercase().as_str())
    };
    let Some(top) = val.as_object() else { return };
    let obj = if top
        .keys()
        .any(|k| is_wanted(k) || k.eq_ignore_ascii_case("_id"))
    {
        top
    } else {
        match primary_object(val) {
            Some(o) => o,
            None => return,
        }
    };
    for (k, v) in obj {
        if is_wanted(k)
            && let Some(s) = scalar(v)
        {
            out.insert(k.clone(), s);
        }
    }
    // a step that asks for `item_id` gets the primary `id` when the response has no such key
    if let Some(w) = wanted
        && let Some(id) = out.get("id").cloned()
    {
        for name in w {
            if !out.contains_key(name) && (name == "id" || name.ends_with("_id")) {
                out.insert(name.clone(), id.clone());
            }
        }
    }
}
