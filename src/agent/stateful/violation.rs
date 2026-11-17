use serde_json::Value;

use crate::agent::exec::{Auth, Credentials, resolve_auth};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Actor {
    Anon,
    Forged,
    Role(String),
}

pub(crate) fn actor_of(s: &str) -> Actor {
    let a = s.trim().to_ascii_lowercase();
    match a.as_str() {
        "anon" | "anonymous" | "none" | "" => Actor::Anon,
        "forged" => Actor::Forged,
        _ => Actor::Role(a),
    }
}

impl Actor {
    pub(crate) fn auth(&self) -> Auth {
        match self {
            Actor::Anon => Auth::None,
            Actor::Forged => Auth::Forged,
            Actor::Role(r) => Auth::Role(r.clone()),
        }
    }
    pub(crate) fn is_anon(&self) -> bool {
        *self == Actor::Anon
    }
}

/// Resolve bearer header for an actor (kept for callers that only need the header value).
pub fn actor_bearer(actor: &str, creds: &Credentials) -> Option<String> {
    resolve_auth(&actor_of(actor).auth(), creds)
        .bearer
        .map(|b| b.header)
}

/// Evaluate whether a violation condition is met.
pub fn evaluate_violation(condition: &str, status: u16, _body: &str) -> bool {
    let cond = condition.trim().to_ascii_lowercase();
    if cond == "bola" || cond == "idor" {
        // BOLA violation: an unauthorized cross-tenant actor obtained 2xx
        return (200..=299).contains(&status);
    }
    // Handle OR expressions: "status == 200 || status == 204"
    if cond.contains("||") {
        return cond
            .split("||")
            .any(|part| evaluate_violation(part, status, _body));
    }
    // Handle AND expressions: "status != 403 && status != 404"
    if cond.contains("&&") {
        return cond
            .split("&&")
            .all(|part| evaluate_violation(part, status, _body));
    }

    let part = cond.trim();
    if let Some(rest) = part.strip_prefix("status ==")
        && let Ok(expected) = rest.trim().parse::<u16>()
    {
        return status == expected;
    }
    if let Some(rest) = part.strip_prefix("status !=")
        && let Ok(expected) = rest.trim().parse::<u16>()
    {
        return status != expected;
    }
    if let Some(rest) = part.strip_prefix("status <")
        && let Ok(threshold) = rest.trim().parse::<u16>()
    {
        return status < threshold;
    }
    if let Some(rest) = part.strip_prefix("status >=")
        && let Ok(threshold) = rest.trim().parse::<u16>()
    {
        return status >= threshold;
    }
    if part == "status in 200..=299" || part == "2xx" {
        return (200..=299).contains(&status);
    }
    if let Some(sub) = part.strip_prefix("body_contains:") {
        let needle = sub.trim();
        return !needle.is_empty() && _body.to_ascii_lowercase().contains(needle);
    }
    if let Some(sub) = part.strip_prefix("unescaped:") {
        let needle = sub.trim();
        let trimmed = _body.trim_start();
        let is_json = trimmed.starts_with('{') || trimmed.starts_with('[');
        return (200..=299).contains(&status)
            && !is_json
            && !needle.is_empty()
            && _body.to_ascii_lowercase().contains(needle);
    }
    if let Some(kv) = part.strip_prefix("json_eq:")
        && let Some((k, v)) = kv.split_once('=')
        && let Ok(parsed) = serde_json::from_str::<Value>(_body)
    {
        return json_has_key_eq(&parsed, k.trim(), v.trim());
    }
    if let Some(kv) = part.strip_prefix("json_lt:")
        && let Some((k, v)) = kv.split_once('=')
        && let Ok(limit) = v.trim().parse::<f64>()
        && let Ok(parsed) = serde_json::from_str::<Value>(_body)
    {
        return json_has_key_lt(&parsed, k.trim(), limit);
    }
    false
}

fn json_has_key_eq(v: &Value, key: &str, want: &str) -> bool {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if k.eq_ignore_ascii_case(key) {
                    let matched = match child {
                        Value::String(s) => s.eq_ignore_ascii_case(want),
                        Value::Bool(b) => {
                            want.eq_ignore_ascii_case(if *b { "true" } else { "false" })
                        }
                        Value::Number(n) => n.to_string() == want,
                        _ => false,
                    };
                    if matched {
                        return true;
                    }
                }
                if json_has_key_eq(child, key, want) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => arr.iter().any(|x| json_has_key_eq(x, key, want)),
        _ => false,
    }
}

fn json_has_key_lt(v: &Value, key: &str, limit: f64) -> bool {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if k.eq_ignore_ascii_case(key)
                    && let Some(n) = child.as_f64()
                    && n < limit
                {
                    return true;
                }
                if json_has_key_lt(child, key, limit) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => arr.iter().any(|x| json_has_key_lt(x, key, limit)),
        _ => false,
    }
}

pub(crate) fn extract_violation_tag(raw: &str) -> (&str, &str) {
    let t = raw.trim();
    if let Some(rest) = t.strip_prefix("mass_assignment:") {
        ("mass_assignment", rest.trim())
    } else if let Some(rest) = t.strip_prefix("business_logic:") {
        ("business_logic", rest.trim())
    } else if let Some(rest) = t.strip_prefix("stored_xss:") {
        ("stored_xss", rest.trim())
    } else {
        ("business_logic", t)
    }
}
