//! Secret, token, and sensitive key redaction for payloads leaving the process.

use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Key names whose values are credentials. Matches by suffix/substring so `DB_PASSWORD`,
/// `stripe_secret`, `x-api-key`, `accessKey`, `Authorization` and `Set-Cookie` all count.
pub fn is_sensitive_key(name: &str) -> bool {
    let low = name
        .trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace())
        .to_ascii_lowercase();
    if low.is_empty() {
        return false;
    }
    let compact: String = low.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    const CONTAINS: [&str; 14] = [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "accesskey",
        "privatekey",
        "credential",
        "authorization",
        "cookie",
        "sessionid",
        "signature",
        "bearer",
    ];
    if CONTAINS.iter().any(|k| compact.contains(k)) {
        return true;
    }
    if low == "key"
        || low == "pwd"
        || low == "pass"
        || low == "auth"
        || low == "session"
        || low == "sid"
    {
        return true;
    }
    if low.ends_with("_key")
        || low.ends_with("-key")
        || low.ends_with("_pwd")
        || low.ends_with("_pass")
        || low.ends_with("_auth")
    {
        return true;
    }
    // camelCase ...Key (e.g. stripeKey) from the original spelling
    let orig = name.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
    orig.len() > 3
        && orig.ends_with("Key")
        && orig.chars().next().is_some_and(|c| c.is_ascii_lowercase())
}

struct Redactors {
    plain: Vec<(Regex, &'static str)>,
    kv: Regex,
}

fn redactors() -> &'static Redactors {
    static R: OnceLock<Redactors> = OnceLock::new();
    R.get_or_init(|| Redactors {
        plain: [
            (r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "[REDACTED]"),
            (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)", "[REDACTED]"),
            (r"\b(?:sk|pk|rk|ghp|gho|ghs|xox[a-z]|AKIA|AIza)[A-Za-z0-9_\-]{12,}", "[REDACTED]"),
            (r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{6,}", "Bearer [REDACTED]"),
            (r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/:@]+:[^\s/@]+@", "${1}[REDACTED]@"),
            (r"\b[0-9a-fA-F]{32,}\b", "[REDACTED]"),
        ]
        .into_iter()
        .map(|(p, r)| (Regex::new(p).unwrap(), r))
        .collect(),
        // key (optionally quoted) <sep> value, where the key's NAME decides (see is_sensitive_key)
        kv: Regex::new(r#"(["']?)([A-Za-z_][A-Za-z0-9_.\-]{0,63})(["']?\s*[:=]\s*)("(?:[^"\\\n]|\\.){0,512}"|'[^'\n]{0,512}'|[^\s,;&"'<>}\]]{1,512})"#).unwrap(),
    })
}

/// Strip things that look like credentials before any text leaves the box.
pub fn redact_for_llm(text: &str) -> String {
    let r = redactors();
    let mut s = text.to_string();
    for (re, rep) in &r.plain {
        s = re.replace_all(&s, *rep).into_owned();
    }
    r.kv.replace_all(&s, |c: &regex::Captures| {
        if is_sensitive_key(&c[2]) {
            format!("{}{}{}\"[REDACTED]\"", &c[1], &c[2], &c[3])
        } else {
            c[0].to_string()
        }
    })
    .into_owned()
}

/// Redact a JSON value structurally: values under credential-looking key names are replaced
/// wholesale (whatever their type), every other string leaf goes through [`redact_for_llm`].
pub fn redact_value(v: &Value) -> Value {
    redact_value_capped(v, usize::MAX)
}

/// As [`redact_value`], then each string leaf is truncated to `max_leaf` chars (redaction first).
pub fn redact_value_capped(v: &Value, max_leaf: usize) -> Value {
    match v {
        Value::String(s) => {
            let r = redact_for_llm(s);
            if r.chars().count() > max_leaf {
                Value::String(r.chars().take(max_leaf).collect())
            } else {
                Value::String(r)
            }
        }
        Value::Array(a) => {
            Value::Array(a.iter().map(|x| redact_value_capped(x, max_leaf)).collect())
        }
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, val)| {
                    if is_sensitive_key(k) && !val.is_null() {
                        (k.clone(), Value::String("[REDACTED]".into()))
                    } else {
                        (k.clone(), redact_value_capped(val, max_leaf))
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}
