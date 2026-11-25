use super::super::AuthKind;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];

pub const PRIVILEGED: [&str; 7] = [
    "admin",
    "root",
    "superuser",
    "super",
    "internal",
    "staff",
    "sudo",
];

/// One operation as far as authorization goes.
#[derive(Debug, Clone)]
pub struct OpAuth {
    pub path: String,
    /// No authentication needed (`security: []`, an empty alternative, or no security at all).
    pub public: bool,
    /// Alternatives of the effective `security`: scheme name -> scopes.
    pub alts: Vec<BTreeMap<String, Vec<String>>>,
    /// `x-roles` / `x-required-roles` of the operation (lower-cased).
    pub x_roles: Vec<String>,
}

impl OpAuth {
    pub fn schemes(&self) -> BTreeSet<&str> {
        self.alts
            .iter()
            .flat_map(|a| a.keys().map(String::as_str))
            .collect()
    }

    /// Reachable only with a privileged scope (every way in needs one), or the path itself says
    /// admin when the spec gives the operation no scope at all.
    pub fn admin_only(&self) -> bool {
        if self.public {
            return false;
        }
        let scoped: Vec<Vec<&String>> = self
            .alts
            .iter()
            .map(|a| a.values().flatten().collect::<Vec<_>>())
            .filter(|s| !s.is_empty())
            .collect();
        if scoped.is_empty() {
            return path_looks_admin(&self.path);
        }
        scoped.len() == self.alts.len() && scoped.iter().all(|s| s.iter().any(|n| is_privileged(n)))
    }
}

/// How one security scheme authenticates a request.
#[derive(Debug, Clone)]
pub struct Scheme {
    pub name: String,
    pub kind: AuthKind,
    /// apiKey header name.
    pub header: Option<String>,
    /// Human description for the comment next to the role.
    pub what: String,
    /// roles.toml cannot express it (apiKey in a query string, mutualTLS).
    pub unsupported: Option<String>,
}

pub fn is_privileged(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("admin")
        || l.split(|c: char| !c.is_ascii_alphanumeric())
            .any(|t| PRIVILEGED.contains(&t))
}

pub fn path_looks_admin(path: &str) -> bool {
    path.split('/').any(|seg| {
        seg.to_ascii_lowercase().contains("admin") || seg.eq_ignore_ascii_case("internal")
    })
}

/// `[A-Za-z0-9_-]`, lower case, never empty: a usable role name (and env var stem).
pub fn role_name(raw: &str) -> String {
    let mut s: String = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    let s = s.trim_matches(|c| c == '_' || c == '-').to_string();
    if s.is_empty() { "role".into() } else { s }
}

pub fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| match x {
                Value::String(s) => Some(s.clone()),
                Value::Object(o) => o.get("name").and_then(|n| n.as_str()).map(String::from),
                _ => None,
            })
            .collect(),
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        _ => vec![],
    }
}

pub fn x_roles_of(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = ["x-roles", "x-required-roles"]
        .iter()
        .flat_map(|k| str_list(v.get(*k)))
        .map(|r| role_name(&r))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Follow a path-item `$ref` (`#/...`) up to a few hops.
pub fn path_item<'a>(doc: &'a Value, item: &'a Value) -> &'a Value {
    let mut cur = item;
    for _ in 0..4 {
        match cur
            .get("$ref")
            .and_then(|r| r.as_str())
            .and_then(|r| r.strip_prefix('#'))
            .and_then(|p| doc.pointer(p))
        {
            Some(t) => cur = t,
            None => break,
        }
    }
    cur
}

pub fn alternatives(sec: &Value) -> Option<Vec<BTreeMap<String, Vec<String>>>> {
    let arr = sec.as_array()?;
    Some(
        arr.iter()
            .filter_map(|r| r.as_object())
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), str_list(Some(v))))
                    .collect()
            })
            .collect(),
    )
}

pub fn operations(doc: &Value) -> Vec<OpAuth> {
    let global = doc.get("security").and_then(alternatives);
    let mut out = vec![];
    let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) else {
        return out;
    };
    for (path, raw) in paths {
        let item = path_item(doc, raw);
        for m in METHODS {
            let Some(op) = item.get(m).filter(|o| o.is_object()) else {
                continue;
            };
            let alts = match op.get("security").and_then(alternatives) {
                Some(a) => a,
                None if op.get("security").is_some() => vec![], // `security: null` / malformed
                None => global.clone().unwrap_or_default(),
            };
            let public = alts.is_empty() || alts.iter().any(|a| a.is_empty());
            out.push(OpAuth {
                path: path.clone(),
                public,
                alts: alts.into_iter().filter(|a| !a.is_empty()).collect(),
                x_roles: x_roles_of(op),
            });
        }
    }
    out
}

pub fn schemes_of(doc: &Value) -> BTreeMap<String, Scheme> {
    let mut out = BTreeMap::new();
    let Some(m) = doc
        .pointer("/components/securitySchemes")
        .and_then(|s| s.as_object())
    else {
        return out;
    };
    for (name, s) in m {
        let ty = s.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let (kind, header, what, unsupported) = match ty {
            "http" => match s
                .get("scheme")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str()
            {
                "basic" => (AuthKind::Basic, None, "http basic".to_string(), None),
                "bearer" => (AuthKind::Bearer, None, "http bearer".to_string(), None),
                other => (
                    AuthKind::Bearer,
                    None,
                    format!("http {other}"),
                    Some(format!(
                        "http scheme '{other}' is not bearer or basic: sent as a bearer token"
                    )),
                ),
            },
            "apiKey" => {
                let loc = s.get("in").and_then(|t| t.as_str()).unwrap_or("header");
                let key = s
                    .get("name")
                    .and_then(|t| t.as_str())
                    .unwrap_or("X-API-Key")
                    .to_string();
                match loc {
                    "header" => (
                        AuthKind::Header,
                        Some(key.clone()),
                        format!("apiKey header {key}"),
                        None,
                    ),
                    "cookie" => (AuthKind::Cookie, None, format!("apiKey cookie {key}"), None),
                    other => (
                        AuthKind::None,
                        None,
                        format!("apiKey in {other}"),
                        Some(format!(
                            "apiKey in the {other} ('{key}') cannot be expressed in roles.toml (bearer, basic, header, cookie): no role was derived for scheme '{name}'"
                        )),
                    ),
                }
            }
            "oauth2" => (
                AuthKind::Bearer,
                None,
                "oauth2 access token".to_string(),
                None,
            ),
            "openIdConnect" => (
                AuthKind::Bearer,
                None,
                "openIdConnect token".to_string(),
                None,
            ),
            other => (
                AuthKind::None,
                None,
                other.to_string(),
                Some(format!(
                    "security scheme '{name}' (type '{other}') cannot be expressed in roles.toml: no role was derived for it"
                )),
            ),
        };
        out.insert(
            name.clone(),
            Scheme {
                name: name.clone(),
                kind,
                header,
                what,
                unsupported,
            },
        );
    }
    out
}

/// Roles the document declares: top-level `x-roles`, or on a security scheme.
pub fn declared_roles(doc: &Value) -> Vec<String> {
    let mut out = x_roles_of(doc);
    if let Some(m) = doc
        .pointer("/components/securitySchemes")
        .and_then(|s| s.as_object())
    {
        for s in m.values() {
            out.extend(x_roles_of(s));
        }
    }
    out.sort();
    out.dedup();
    out
}
