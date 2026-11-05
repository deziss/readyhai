//! `readyhai roles init`: derive a roles.toml skeleton from an OpenAPI 3.x spec.
//!
//! What the spec says is turned into test accounts and an expected-access matrix:
//! * `components.securitySchemes` (http bearer / basic, apiKey, oauth2, openIdConnect) decide
//!   how a role authenticates (`auth`, header name);
//! * per-operation `security` (falling back to the global one) and `x-roles` /
//!   `x-required-roles` decide which operations a role may reach;
//! * OAuth2 scope names and role names that look privileged (`admin`, `root`, `internal`, ...)
//!   split the accounts into an admin and ordinary users; paths only they can reach become
//!   `deny` globs of the ordinary roles.
//!
//! The file holds env var NAMES only (`RH_<ROLE>_TOKEN`), never a secret value. The result is a
//! starting point to review: the globs are derived, not known.
use super::{AuthKind, Roles, env_var};
use crate::qa::api::spec::{MAX_SPEC_BYTES, base_path_of, parse_text};
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];
/// Words that mark a scope, role or path segment as privileged.
const PRIVILEGED: [&str; 7] = [
    "admin",
    "root",
    "superuser",
    "super",
    "internal",
    "staff",
    "sudo",
];
/// Glob patterns per role past which a note says the list is long.
const LONG_GLOB_LIST: usize = 200;

// ------------------------------------------------------------------ input model

/// One operation as far as authorization goes.
#[derive(Debug, Clone)]
struct OpAuth {
    path: String,
    /// No authentication needed (`security: []`, an empty alternative, or no security at all).
    public: bool,
    /// Alternatives of the effective `security`: scheme name -> scopes.
    alts: Vec<BTreeMap<String, Vec<String>>>,
    /// `x-roles` / `x-required-roles` of the operation (lower-cased).
    x_roles: Vec<String>,
}

impl OpAuth {
    fn schemes(&self) -> BTreeSet<&str> {
        self.alts
            .iter()
            .flat_map(|a| a.keys().map(String::as_str))
            .collect()
    }

    /// Reachable only with a privileged scope (every way in needs one), or the path itself says
    /// admin when the spec gives the operation no scope at all.
    fn admin_only(&self) -> bool {
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
struct Scheme {
    name: String,
    kind: AuthKind,
    /// apiKey header name.
    header: Option<String>,
    /// Human description for the comment next to the role.
    what: String,
    /// roles.toml cannot express it (apiKey in a query string, mutualTLS).
    unsupported: Option<String>,
}

fn is_privileged(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("admin")
        || l.split(|c: char| !c.is_ascii_alphanumeric())
            .any(|t| PRIVILEGED.contains(&t))
}

fn path_looks_admin(path: &str) -> bool {
    path.split('/').any(|seg| {
        seg.to_ascii_lowercase().contains("admin") || seg.eq_ignore_ascii_case("internal")
    })
}

/// `[A-Za-z0-9_-]`, lower case, never empty: a usable role name (and env var stem).
fn role_name(raw: &str) -> String {
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

fn str_list(v: Option<&Value>) -> Vec<String> {
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

fn x_roles_of(v: &Value) -> Vec<String> {
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
fn path_item<'a>(doc: &'a Value, item: &'a Value) -> &'a Value {
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

fn alternatives(sec: &Value) -> Option<Vec<BTreeMap<String, Vec<String>>>> {
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

fn operations(doc: &Value) -> Vec<OpAuth> {
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

fn schemes_of(doc: &Value) -> BTreeMap<String, Scheme> {
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

// ------------------------------------------------------------------ derivation

/// Who a role stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Level {
    /// Holds every scope: reaches everything the scheme allows.
    Admin,
    /// Holds the non-privileged scopes: denied what only an admin reaches.
    User,
    /// A role named by the spec (`x-roles`).
    Named(String),
    /// A second way to authenticate (another security scheme).
    Scheme,
}

#[derive(Debug, Clone)]
pub struct DerivedRole {
    pub name: String,
    pub auth: AuthKind,
    pub header_name: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    /// One-line comment: scheme and scopes the credential needs.
    pub note: String,
    scheme: Option<String>,
    level: Level,
}

#[derive(Debug, Clone, Default)]
pub struct Derived {
    pub roles: Vec<DerivedRole>,
    /// Things to check by hand (unsupported schemes, globs that cannot express a case, ...).
    pub warnings: Vec<String>,
    pub base_path: String,
    pub operations: usize,
}

fn auth_str(k: AuthKind) -> &'static str {
    match k {
        AuthKind::Bearer => "bearer",
        AuthKind::Basic => "basic",
        AuthKind::Header => "header",
        AuthKind::Cookie => "cookie",
        AuthKind::None => "none",
    }
}

fn unique(taken: &mut BTreeSet<String>, want: String) -> String {
    let mut n = want.clone();
    let mut i = 2;
    while !taken.insert(n.clone()) {
        n = format!("{want}{i}");
        i += 1;
    }
    n
}

/// Derive roles and their expected-access globs from a parsed OpenAPI document.
pub fn derive(doc: &Value) -> Result<Derived> {
    if doc
        .get("openapi")
        .and_then(|v| v.as_str())
        .map(|s| s.starts_with('3'))
        != Some(true)
    {
        bail!("not an OpenAPI 3.x document");
    }
    let ops = operations(doc);
    let schemes = schemes_of(doc);
    let mut d = Derived {
        base_path: base_path_of(doc),
        operations: ops.len(),
        ..Default::default()
    };
    if ops.is_empty() {
        bail!("the spec has no operations (paths is empty)");
    }

    // schemes the operations actually use, most used first (ties: by name)
    let mut uses: BTreeMap<&str, usize> = BTreeMap::new();
    for o in &ops {
        for s in o.schemes() {
            *uses.entry(s).or_default() += 1;
        }
    }
    let mut used: Vec<(&str, usize)> = uses.into_iter().collect();
    used.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (name, _) in &used {
        match schemes.get(*name) {
            None => d.warnings.push(format!(
                "operations reference security scheme '{name}' that components.securitySchemes does not define"
            )),
            Some(s) => d.warnings.extend(s.unsupported.clone()),
        }
    }
    // the most used scheme roles.toml can express, else any declared one it can
    let usable = |n: &str| schemes.get(n).is_some_and(|s| s.kind != AuthKind::None);
    let primary: Option<&Scheme> = used
        .iter()
        .map(|u| u.0)
        .find(|n| usable(n))
        .or_else(|| {
            schemes
                .iter()
                .find(|(_, s)| s.kind != AuthKind::None)
                .map(|(n, _)| n.as_str())
        })
        .and_then(|n| schemes.get(n));
    if primary.is_none() {
        d.warnings.push(if schemes.is_empty() {
            "the spec declares no securitySchemes: roles default to bearer tokens".into()
        } else {
            "no declared security scheme can be expressed in roles.toml: roles default to bearer tokens".into()
        });
    }
    let (p_kind, p_header, p_scheme, p_what) = match primary {
        Some(s) => (
            s.kind,
            s.header.clone(),
            Some(s.name.clone()),
            s.what.clone(),
        ),
        None => (
            AuthKind::Bearer,
            None,
            None,
            "assumed bearer token".to_string(),
        ),
    };

    // ---- which roles
    let declared = declared_roles(doc);
    let named: BTreeSet<String> = declared
        .iter()
        .cloned()
        .chain(ops.iter().flat_map(|o| o.x_roles.iter().cloned()))
        .collect();
    let mut taken: BTreeSet<String> = BTreeSet::new();
    let mut roles: Vec<DerivedRole> = vec![];
    let mut push = |name: String,
                    level: Level,
                    scheme: Option<String>,
                    kind: AuthKind,
                    header: Option<String>,
                    note: String| {
        roles.push(DerivedRole {
            name,
            auth: kind,
            header_name: header,
            allow: vec![],
            deny: vec![],
            note,
            scheme,
            level,
        });
    };
    let scopes_all: BTreeSet<&str> = ops
        .iter()
        .flat_map(|o| {
            o.alts
                .iter()
                .flat_map(|a| a.values().flatten().map(String::as_str))
        })
        .collect();
    let scopes_user: Vec<&str> = scopes_all
        .iter()
        .copied()
        .filter(|s| !is_privileged(s))
        .collect();
    if !named.is_empty() {
        if !ops.iter().any(|o| !o.x_roles.is_empty()) {
            d.warnings.push(
                "x-roles are declared but no operation lists one: every role is allowed everywhere"
                    .into(),
            );
        }
        for n in &named {
            let name = unique(&mut taken, n.clone());
            push(
                name,
                Level::Named(n.clone()),
                p_scheme.clone(),
                p_kind,
                p_header.clone(),
                format!("{p_what}; operations that list x-roles '{n}'"),
            );
        }
    } else {
        let has_admin = ops.iter().any(OpAuth::admin_only);
        let user_note = if scopes_user.is_empty() {
            format!("{p_what}; an ordinary account")
        } else {
            format!("{p_what}; scopes: {}", scopes_user.join(" "))
        };
        push(
            unique(&mut taken, "user".into()),
            Level::User,
            p_scheme.clone(),
            p_kind,
            p_header.clone(),
            user_note.clone(),
        );
        push(
            unique(&mut taken, "user2".into()),
            Level::User,
            p_scheme.clone(),
            p_kind,
            p_header.clone(),
            format!(
                "{user_note}; a second account of the same level (needed for BOLA / ownership tests)"
            ),
        );
        if has_admin {
            push(
                unique(&mut taken, "admin".into()),
                Level::Admin,
                p_scheme.clone(),
                p_kind,
                p_header.clone(),
                if scopes_all.is_empty() {
                    format!("{p_what}; an administrator")
                } else {
                    format!(
                        "{p_what}; scopes: {}",
                        scopes_all.iter().copied().collect::<Vec<_>>().join(" ")
                    )
                },
            );
        }
    }
    // other ways in: one role per remaining scheme that operations use
    for (name, _) in &used {
        let Some(s) = schemes.get(*name) else {
            continue;
        };
        if Some(&s.name) == p_scheme.as_ref() || s.kind == AuthKind::None {
            continue;
        }
        push(
            unique(&mut taken, role_name(&s.name)),
            Level::Scheme,
            Some(s.name.clone()),
            s.kind,
            s.header.clone(),
            format!("{} (scheme {})", s.what, s.name),
        );
    }

    if roles.len() < 2 {
        d.warnings.push(
            "fewer than 2 roles: the authorization matrix and BOLA tests need at least two test accounts (add one by hand)".into(),
        );
    }

    // ---- expected access per role
    let base = d.base_path.clone();
    let mut notes: Vec<String> = vec![];
    for role in &mut roles {
        let mut trie = Node::default();
        for o in &ops {
            trie.insert(&segments(&o.path), verdict(role, o));
        }
        trie.finish();
        let (mut allow, mut deny) = (vec![], vec![]);
        trie.emit(&base, &mut allow, &mut deny, &mut |p| {
            notes.push(format!(
                "role '{}': {p} allows some methods and denies others, so no glob was written for it",
                role.name
            ))
        });
        if allow.len() + deny.len() > LONG_GLOB_LIST {
            notes.push(format!(
                "role '{}' got {} globs: review them, or trim to the paths you care about",
                role.name,
                allow.len() + deny.len()
            ));
        }
        role.allow = allow;
        role.deny = deny;
    }
    d.roles = roles;
    d.warnings.extend(notes);
    let rendered = render(&d, "");
    d.warnings.extend(verify(&rendered, &ops, &d)?);
    Ok(d)
}

/// Roles the document declares: top-level `x-roles`, or on a security scheme.
fn declared_roles(doc: &Value) -> Vec<String> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V {
    Allow,
    Deny,
    /// Methods of one path disagree: globs match paths, so none is written.
    Mixed,
}

/// Whether `role` should reach `op`.
fn verdict(role: &DerivedRole, op: &OpAuth) -> V {
    if op.public {
        return V::Allow;
    }
    if let Some(s) = &role.scheme
        && !op.alts.is_empty()
        && !op.schemes().contains(s.as_str())
    {
        return V::Deny; // only other schemes get in
    }
    let allowed = match &role.level {
        Level::Admin | Level::Scheme => true,
        Level::User => !op.admin_only(),
        Level::Named(n) => op.x_roles.is_empty() || op.x_roles.contains(n),
    };
    if allowed { V::Allow } else { V::Deny }
}

// ------------------------------------------------------------------ globs

/// Path as glob segments: `{id}` and any other glob metacharacter become wildcards.
fn segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            let mut out = String::new();
            let mut depth = 0;
            for c in seg.chars() {
                match c {
                    '{' => {
                        if depth == 0 {
                            out.push('*');
                        }
                        depth += 1;
                    }
                    '}' if depth > 0 => depth -= 1,
                    _ if depth > 0 => {}
                    '*' | '?' | '[' | ']' | '}' | '\\' => out.push('?'),
                    c => out.push(c),
                }
            }
            out
        })
        .collect()
}

#[derive(Default)]
struct Node {
    kids: BTreeMap<String, Node>,
    /// Verdict of the operations that end exactly here.
    here: Option<V>,
    /// Verdict of everything at or below this node (None = no operation).
    agg: Option<V>,
}

fn join(a: Option<V>, b: V) -> V {
    match a {
        None => b,
        Some(x) if x == b => b,
        _ => V::Mixed,
    }
}

impl Node {
    fn insert(&mut self, segs: &[String], v: V) {
        match segs.split_first() {
            None => self.here = Some(join(self.here, v)),
            Some((s, rest)) => self.kids.entry(s.clone()).or_default().insert(rest, v),
        }
    }

    fn finish(&mut self) {
        let mut agg = self.here;
        for k in self.kids.values_mut() {
            k.finish();
            if let Some(v) = k.agg {
                agg = Some(join(agg, v));
            }
        }
        self.agg = agg;
    }

    /// Smallest glob lists that say the same: a subtree whose operations all agree becomes
    /// `<prefix>/**`; a subtree that disagrees is split further.
    fn emit(
        &self,
        prefix: &str,
        allow: &mut Vec<String>,
        deny: &mut Vec<String>,
        mixed: &mut dyn FnMut(&str),
    ) {
        let exact = if prefix.is_empty() { "/" } else { prefix };
        let mut put = |v: V, pat: String| match v {
            V::Allow => allow.push(pat),
            V::Deny => deny.push(pat),
            V::Mixed => {}
        };
        match self.agg {
            None => {}
            Some(v @ (V::Allow | V::Deny)) => {
                if self.kids.is_empty() {
                    put(v, exact.to_string());
                } else {
                    if self.here.is_some() {
                        put(v, exact.to_string());
                    }
                    put(v, format!("{prefix}/**"));
                }
            }
            Some(V::Mixed) => {
                match self.here {
                    Some(V::Mixed) => mixed(exact),
                    Some(v) => put(v, exact.to_string()),
                    None => {}
                }
                for (seg, k) in &self.kids {
                    k.emit(&format!("{prefix}/{seg}"), allow, deny, mixed);
                }
            }
        }
    }
}

/// Parse what was rendered and ask each role about every path: the globs must say what the
/// derivation meant. Returns notes for the paths they cannot express (wildcards overlap).
fn verify(text: &str, ops: &[OpAuth], d: &Derived) -> Result<Vec<String>> {
    let parsed: Roles = toml::from_str(text).context("derived roles.toml does not parse (bug)")?;
    let mut out = vec![];
    for (role, dr) in parsed.roles.iter().zip(&d.roles) {
        let mut by_path: BTreeMap<&str, V> = BTreeMap::new();
        for o in ops {
            let v = verdict(dr, o);
            by_path
                .entry(o.path.as_str())
                .and_modify(|x| *x = join(Some(*x), v))
                .or_insert(v);
        }
        let bad: Vec<&str> = by_path
            .into_iter()
            .filter_map(|(path, v)| {
                let want = match v {
                    V::Allow => Some(true),
                    V::Deny => Some(false),
                    V::Mixed => return None,
                };
                let concrete = format!("{}{}", d.base_path, concrete_path(path));
                (role.expects(&concrete) != want).then_some(path)
            })
            .collect();
        if !bad.is_empty() {
            out.push(format!(
                "role '{}': the globs do not express {} path(s) exactly (wildcards of neighbouring paths overlap), e.g. {}: edit allow/deny by hand",
                dr.name,
                bad.len(),
                bad.iter().take(5).copied().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    Ok(out)
}

fn concrete_path(path: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in path.chars() {
        match c {
            '{' => {
                if depth == 0 {
                    out.push('1');
                }
                depth += 1;
            }
            '}' if depth > 0 => depth -= 1,
            _ if depth > 0 => {}
            c => out.push(c),
        }
    }
    out
}

// ------------------------------------------------------------------ rendering

fn q(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn list(key: &str, v: &[String]) -> String {
    match v {
        [] => format!("{key} = []\n"),
        [one] => format!("{key} = [{}]\n", q(one)),
        many => {
            let mut s = format!("{key} = [\n");
            for x in many {
                s.push_str(&format!("  {},\n", q(x)));
            }
            s.push_str("]\n");
            s
        }
    }
}

/// roles.toml text. `source` names the spec in the header comment (empty = omitted).
pub fn render(d: &Derived, source: &str) -> String {
    let mut s = String::new();
    s.push_str("# roles.toml skeleton derived by `readyhai roles init`");
    if !source.is_empty() {
        s.push_str(&format!(" from {source}"));
    }
    s.push_str(&format!(" ({} operation(s)).\n", d.operations));
    s.push_str(
        "# Values below are env var NAMES. Never write a token, password or key into this file;\n",
    );
    s.push_str("# export the variables before `readyhai qa`, with credentials of dedicated TEST accounts:\n");
    let mut vars: Vec<String> = vec![];
    for r in &d.roles {
        match r.auth {
            AuthKind::Basic => {
                vars.push(format!("{}=...", env_var(&r.name, "USER")));
                vars.push(format!("{}=...", env_var(&r.name, "PASS")));
            }
            AuthKind::Bearer | AuthKind::Header => {
                vars.push(format!("{}=...", env_var(&r.name, "TOKEN")))
            }
            AuthKind::Cookie | AuthKind::None => {}
        }
    }
    if !vars.is_empty() {
        s.push_str(&format!("#   export {}\n", vars.join(" ")));
    }
    s.push_str(
        "# allow / deny are derived from the spec's security and scope names: review them.\n",
    );
    s.push_str("# Keep this file outside the target repo, mode 0600.\n");
    for w in &d.warnings {
        s.push_str(&format!("# NOTE: {}\n", w.replace('\n', " ")));
    }
    for r in &d.roles {
        s.push('\n');
        s.push_str("[[role]]\n");
        s.push_str(&format!("name = {}\n", q(&r.name)));
        s.push_str(&format!(
            "auth = {}    # {}\n",
            q(auth_str(r.auth)),
            r.note.replace('\n', " ")
        ));
        match r.auth {
            AuthKind::Bearer => s.push_str(&format!("token_env = {}\n", q(&env_var(&r.name, "TOKEN")))),
            AuthKind::Header => {
                s.push_str(&format!(
                    "header_name = {}\n",
                    q(r.header_name.as_deref().unwrap_or("X-API-Key"))
                ));
                s.push_str(&format!("token_env = {}\n", q(&env_var(&r.name, "TOKEN"))));
            }
            AuthKind::Basic => {
                s.push_str(&format!("username_env = {}\n", q(&env_var(&r.name, "USER"))));
                s.push_str(&format!("password_env = {}\n", q(&env_var(&r.name, "PASS"))));
            }
            AuthKind::Cookie => s.push_str(&format!(
                "storage_state = {}    # Playwright storageState of a logged-in test account, relative to this file\n",
                q(&format!("{}.state.json", r.name))
            )),
            AuthKind::None => {}
        }
        s.push_str(&list("allow", &r.allow));
        s.push_str(&list("deny", &r.deny));
    }
    s
}

// ------------------------------------------------------------------ command

/// Where the file goes without `--out`: `<config>/readyhai/secrets/roles.toml`
/// (`$XDG_CONFIG_HOME`, else `~/.config`): outside any repo, next to the other test secrets.
pub fn default_out() -> Result<PathBuf> {
    default_out_in(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

fn default_out_in(
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    let base = match xdg.filter(|v| !v.is_empty()) {
        Some(x) => PathBuf::from(x),
        None => PathBuf::from(
            home.filter(|v| !v.is_empty())
                .context("HOME is not set: pass --out")?,
        )
        .join(".config"),
    };
    Ok(base.join("readyhai").join("secrets").join("roles.toml"))
}

/// Write `text` to `out`, mode 0600 (a new directory 0700). An existing file is refused unless
/// `force`; a symlink at `out` is always refused.
pub fn write_secret_file(out: &Path, text: &str, force: bool) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty())
        && !dir.exists()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    if std::fs::symlink_metadata(out).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!(
            "{} is a symlink: refusing to write through it",
            out.display()
        );
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if force {
        o.create(true);
    } else {
        o.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(out).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!("{} exists: pass --force to overwrite it", out.display())
        } else {
            anyhow::Error::new(e).context(format!("write {}", out.display()))
        }
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.set_len(0)?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

/// `readyhai roles init --spec FILE [--out FILE|-] [--force]`. Returns the path written (None
/// for stdout).
pub fn run(spec: &str, out: Option<&Path>, force: bool) -> Result<Option<PathBuf>> {
    if spec.starts_with("http://") || spec.starts_with("https://") {
        bail!(
            "--spec must be a local file (download it first): roles init makes no network requests"
        );
    }
    if std::fs::metadata(spec).is_ok_and(|m| m.len() > MAX_SPEC_BYTES) {
        bail!("spec {spec} is larger than {} MiB", MAX_SPEC_BYTES >> 20);
    }
    let text = std::fs::read_to_string(spec).with_context(|| format!("read spec {spec}"))?;
    let doc = parse_text(&text)?;
    drop(text);
    let derived = derive(&doc)?;
    let file = Path::new(spec)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let body = render(&derived, &file);
    if out == Some(Path::new("-")) {
        print!("{body}");
        return Ok(None);
    }
    let path = match out {
        Some(p) => p.to_path_buf(),
        None => default_out()?,
    };
    write_secret_file(&path, &body, force)?;
    eprintln!(
        "roles init: {} role(s) for {} operation(s) -> {} (mode 0600)",
        derived.roles.len(),
        derived.operations,
        path.display()
    );
    for r in &derived.roles {
        eprintln!(
            "  {:<12} {:<7} allow {} / deny {} glob(s)",
            r.name,
            auth_str(r.auth),
            r.allow.len(),
            r.deny.len()
        );
    }
    for w in &derived.warnings {
        eprintln!("  note: {w}");
    }
    eprintln!("Review allow/deny, export the RH_* variables (test accounts only), then:");
    eprintln!(
        "  readyhai qa <url> --spec {spec} --roles {}",
        path.display()
    );
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn role<'a>(d: &'a Derived, name: &str) -> &'a DerivedRole {
        d.roles.iter().find(|r| r.name == name).unwrap_or_else(|| {
            panic!(
                "no role {name}: {:?}",
                d.roles.iter().map(|r| &r.name).collect::<Vec<_>>()
            )
        })
    }

    fn parsed(d: &Derived) -> Roles {
        toml::from_str(&render(d, "spec.json")).expect("derived file must parse as roles.toml")
    }

    fn get(sec: Value) -> Value {
        json!({"security": sec, "responses": {"200": {"description": "ok"}}})
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rh-rolesinit-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn bearer_spec_with_admin_paths_denies_them_to_ordinary_users() {
        let doc = json!({"openapi": "3.0.3", "servers": [{"url": "https://x.test/api/v1"}],
        "security": [{"bearerAuth": []}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/health": {"get": get(json!([]))},
            "/orders": {"get": {}, "post": {}},
            "/orders/{id}": {"get": {}, "delete": {}},
            "/admin/users": {"get": {}},
            "/admin/users/{id}": {"delete": {}}
        }});
        let d = derive(&doc).unwrap();
        assert_eq!(
            d.roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["user", "user2", "admin"]
        );
        assert_eq!(d.base_path, "/api/v1");
        let user = role(&d, "user");
        assert_eq!(user.auth, AuthKind::Bearer);
        // the server's base path is part of every glob: that is the path the runner matches
        assert_eq!(user.deny, ["/api/v1/admin/**"]);
        assert_eq!(
            user.allow,
            ["/api/v1/health", "/api/v1/orders", "/api/v1/orders/**"]
        );
        assert_eq!(role(&d, "admin").allow, ["/api/v1/**"]);
        assert!(role(&d, "admin").deny.is_empty());
        // the file loads through the real roles.toml code and the globs behave
        let r = parsed(&d);
        let u = &r.roles[0];
        assert_eq!(u.expects("/api/v1/admin/users/7"), Some(false));
        assert_eq!(u.expects("/api/v1/admin/users"), Some(false));
        assert_eq!(u.expects("/api/v1/orders/7"), Some(true));
        assert_eq!(u.expects("/api/v1/health"), Some(true));
        assert_eq!(r.roles[2].expects("/api/v1/admin/users"), Some(true));
        assert!(d.warnings.is_empty(), "{:?}", d.warnings);
    }

    #[test]
    fn oauth2_scopes_split_admin_from_user_and_the_note_names_the_scopes() {
        let doc = json!({"openapi": "3.0.3",
        "components": {"securitySchemes": {"oauth": {"type": "oauth2", "flows": {"clientCredentials": {
            "tokenUrl": "https://x/t", "scopes": {"read:orders": "r", "write:orders": "w", "admin:users": "a"}}}}}},
        "paths": {
            "/orders": {"get": {"security": [{"oauth": ["read:orders"]}]},
                        "post": {"security": [{"oauth": ["write:orders"]}]}},
            "/users": {"get": {"security": [{"oauth": ["admin:users"]}]}},
            "/users/{id}": {"delete": {"security": [{"oauth": ["write:orders", "admin:users"]}]}}
        }});
        let d = derive(&doc).unwrap();
        let user = role(&d, "user");
        // `/users` and everything under it (one glob each: `/users/**` does not match `/users`)
        assert_eq!(user.deny, ["/users", "/users/**"]);
        assert_eq!(user.allow, ["/orders"]);
        assert!(
            user.note.contains("read:orders write:orders") && !user.note.contains("admin:users"),
            "{}",
            user.note
        );
        let admin = role(&d, "admin");
        assert!(admin.note.contains("admin:users") && admin.note.contains("read:orders"));
        assert_eq!(admin.allow, ["/**"]);
        // an operation that ALSO accepts an ordinary scope is not admin-only
        let doc2 = json!({"openapi": "3.0.0", "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
            "paths": {"/a": {"get": {"security": [{"o": ["admin"]}, {"o": ["read"]}]}},
                      "/b": {"get": {"security": [{"o": ["admin"]}]}}}});
        let d2 = derive(&doc2).unwrap();
        assert_eq!(role(&d2, "user").deny, ["/b"]);
        assert_eq!(role(&d2, "user").allow, ["/a"]);
    }

    #[test]
    fn x_roles_make_one_role_each_with_allow_and_deny_from_the_operations() {
        let doc = json!({"openapi": "3.0.0", "x-roles": ["Customer", "Support Agent", "admin"],
        "security": [{"b": []}],
        "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/orders": {"get": {"x-roles": ["customer", "support agent", "admin"]}},
            "/tickets": {"get": {"x-required-roles": ["support agent", "admin"]}},
            "/billing/**x": {"get": {"x-roles": "admin"}},
            "/me": {"get": {}}
        }});
        let d = derive(&doc).unwrap();
        assert_eq!(
            d.roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["admin", "customer", "support_agent"]
        );
        assert_eq!(role(&d, "customer").deny, ["/billing/**", "/tickets"]);
        assert_eq!(role(&d, "customer").allow, ["/me", "/orders"]);
        assert!(role(&d, "admin").deny.is_empty());
        assert_eq!(role(&d, "support_agent").deny, ["/billing/**"]);
        assert_eq!(role(&d, "support_agent").env(), "RH_SUPPORT_AGENT_TOKEN");
        parsed(&d);
    }

    impl DerivedRole {
        fn env(&self) -> String {
            env_var(&self.name, "TOKEN")
        }
    }

    #[test]
    fn schemes_map_to_auth_kinds_and_other_schemes_become_their_own_role() {
        let doc = json!({"openapi": "3.0.0",
        "components": {"securitySchemes": {
            "jwt": {"type": "http", "scheme": "Bearer"},
            "svcKey": {"type": "apiKey", "in": "header", "name": "X-Service-Key"},
            "legacy": {"type": "http", "scheme": "basic"},
            "q": {"type": "apiKey", "in": "query", "name": "k"},
            "mtls": {"type": "mutualTLS"}}},
        "paths": {
            "/a": {"get": {"security": [{"jwt": []}]}},
            "/b": {"get": {"security": [{"jwt": []}]}},
            "/jobs": {"post": {"security": [{"svcKey": []}]}},
            "/old": {"get": {"security": [{"legacy": []}, {"jwt": []}]}},
            "/k": {"get": {"security": [{"q": []}]}},
            "/m": {"get": {"security": [{"mtls": []}]}}
        }});
        let d = derive(&doc).unwrap();
        let names: Vec<&str> = d.roles.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["user", "user2", "legacy", "svckey"], "{names:?}");
        assert_eq!(role(&d, "user").auth, AuthKind::Bearer);
        let svc = role(&d, "svckey");
        assert_eq!(
            (svc.auth, svc.header_name.as_deref()),
            (AuthKind::Header, Some("X-Service-Key"))
        );
        assert_eq!(role(&d, "legacy").auth, AuthKind::Basic);
        // the other scheme's role reaches what accepts that scheme, and is denied the rest
        assert_eq!(svc.allow, ["/jobs"]);
        assert!(svc.deny.contains(&"/a".to_string()) && svc.deny.contains(&"/b".to_string()));
        assert_eq!(role(&d, "legacy").allow, ["/old"]);
        // unsupported schemes are said, not guessed
        let w = d.warnings.join("\n");
        assert!(
            w.contains("apiKey in the query") && w.contains("mutualTLS"),
            "{w}"
        );
        let text = render(&d, "spec.yaml");
        assert!(
            text.contains("username_env = \"RH_LEGACY_USER\"")
                && text.contains("password_env = \"RH_LEGACY_PASS\"")
        );
        assert!(
            text.contains("header_name = \"X-Service-Key\"")
                && text.contains("token_env = \"RH_SVCKEY_TOKEN\"")
        );
        let r = parsed(&d);
        assert_eq!(r.roles.len(), 4);
    }

    #[test]
    fn only_env_var_names_are_ever_written() {
        let doc = json!({"openapi": "3.0.0", "security": [{"b": []}, {"k": []}],
            "components": {"securitySchemes": {"b": {"type": "http", "scheme": "basic"},
                "k": {"type": "apiKey", "in": "cookie", "name": "sid"}}},
            "paths": {"/admin/x": {"get": {}}, "/y": {"get": {}}}});
        let text = render(&derive(&doc).unwrap(), "s.json");
        for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
            if let Some((k, v)) = line.split_once(" = ")
                && k.ends_with("_env")
            {
                let v = v.split('#').next().unwrap().trim().trim_matches('"');
                assert!(
                    v.starts_with("RH_")
                        && v.chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                    "{line}"
                );
            }
        }
        assert!(
            text.contains("export RH_USER_USER=... RH_USER_PASS=..."),
            "{text}"
        );
        assert!(text.contains("Never write a token, password or key into this file"));
        assert!(
            text.contains("storage_state") || !text.contains("cookie"),
            "{text}"
        );
        parsed(&derive(&doc).unwrap());
    }

    #[test]
    fn a_spec_with_no_security_still_gets_two_bearer_roles_and_says_so() {
        let doc = json!({"openapi": "3.1.0", "paths": {"/a": {"get": {}}}});
        let d = derive(&doc).unwrap();
        assert_eq!(d.roles.len(), 2);
        assert!(d.roles.iter().all(|r| r.auth == AuthKind::Bearer));
        assert!(d.warnings.iter().any(|w| w.contains("no securitySchemes")));
        // nothing is secured, so nothing is denied: one allow-all glob each
        assert!(
            d.roles
                .iter()
                .all(|r| r.allow == ["/**"] && r.deny.is_empty())
        );
    }

    #[test]
    fn paths_whose_methods_disagree_get_no_glob_and_a_note() {
        let doc = json!({"openapi": "3.0.0", "security": [{"o": ["read"]}],
            "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
            "paths": {"/things": {"get": {"security": []}, "delete": {"security": [{"o": ["admin"]}]}},
                      "/admin/z": {"get": {"security": [{"o": ["admin"]}]}}}});
        let d = derive(&doc).unwrap();
        let user = role(&d, "user");
        assert!(
            !user
                .allow
                .iter()
                .chain(&user.deny)
                .any(|p| p.contains("things")),
            "{user:?}"
        );
        assert_eq!(user.deny, ["/admin/**"]);
        assert!(
            d.warnings
                .iter()
                .any(|w| w.contains("/things")
                    && w.contains("allows some methods and denies others")),
            "{:?}",
            d.warnings
        );
    }

    #[test]
    fn globs_that_cannot_express_a_case_are_flagged_by_the_self_check() {
        // `/users/{id}` is admin-only, `/users/export` is open: `deny /users/*` would also catch
        // `/users/export`, and deny wins, so no glob list can say it
        let doc = json!({"openapi": "3.0.0",
            "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
            "paths": {"/users/{id}": {"get": {"security": [{"o": ["admin"]}]}},
                      "/users/export": {"get": {"security": [{"o": ["read"]}]}}}});
        let d = derive(&doc).unwrap();
        assert!(
            d.warnings.iter().any(|w| w.contains("role 'user'")
                && w.contains("do not express")
                && w.contains("/users/export")),
            "{:?}",
            d.warnings
        );
        // and the note lands in the file header so a reviewer sees it
        assert!(render(&d, "x").contains("# NOTE: role 'user'"));
    }

    #[test]
    fn rejects_non_openapi3_and_empty_specs() {
        assert!(derive(&json!({"swagger": "2.0", "paths": {}})).is_err());
        let e = derive(&json!({"openapi": "3.0.0", "paths": {}})).unwrap_err();
        assert!(format!("{e}").contains("no operations"));
    }

    #[test]
    fn a_path_item_ref_is_followed() {
        let doc = json!({"openapi": "3.0.0",
            "components": {"pathItems": {"Adm": {"get": {"security": [{"o": ["admin"]}]}}},
                           "securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
            "paths": {"/admin/a": {"$ref": "#/components/pathItems/Adm"}, "/p": {"get": {"security": [{"o": ["x"]}]}}}});
        let d = derive(&doc).unwrap();
        assert_eq!(d.operations, 2);
        assert_eq!(role(&d, "user").deny, ["/admin/**"]);
    }

    #[test]
    fn a_big_spec_stays_fast_and_compact() {
        let mut paths = serde_json::Map::new();
        for i in 0..1000 {
            paths.insert(
                format!("/svc{}/res{i}", i % 20),
                json!({"get": {}, "post": {}}),
            );
            paths.insert(
                format!("/svc{}/res{i}/{{id}}", i % 20),
                json!({"get": {}, "put": {}, "delete": {}}),
            );
            paths.insert(
                format!("/admin/area{i}"),
                json!({"get": {"security": [{"o": ["admin:all"]}]}}),
            );
        }
        let doc = json!({"openapi": "3.0.0", "security": [{"o": ["user"]}],
            "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}}, "paths": paths});
        let t = std::time::Instant::now();
        let d = derive(&doc).unwrap();
        assert_eq!(d.operations, 6000);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            t.elapsed()
        );
        // the 1000 admin areas collapse into one glob, the 20 service prefixes into 20
        let user = role(&d, "user");
        assert_eq!(user.deny, ["/admin/**"]);
        assert_eq!(user.allow.len(), 20, "{:?}", &user.allow[..3]);
        assert!(d.warnings.is_empty(), "{:?}", d.warnings);
    }

    #[test]
    fn default_output_is_the_config_secrets_dir() {
        let o = |s: &str| Some(std::ffi::OsString::from(s));
        assert_eq!(
            default_out_in(o("/xdg"), o("/home/u")).unwrap(),
            PathBuf::from("/xdg/readyhai/secrets/roles.toml")
        );
        assert_eq!(
            default_out_in(None, o("/home/u")).unwrap(),
            PathBuf::from("/home/u/.config/readyhai/secrets/roles.toml")
        );
        assert_eq!(
            default_out_in(o(""), o("/home/u")).unwrap(),
            PathBuf::from("/home/u/.config/readyhai/secrets/roles.toml")
        );
        assert!(default_out_in(None, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_0600_in_a_0700_dir_and_never_overwritten_without_force() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("write");
        let out = dir.join("new").join("secrets").join("roles.toml");
        write_secret_file(&out, "a = 1\n", false).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&out), 0o600);
        assert_eq!(mode(out.parent().unwrap()), 0o700);
        // second write: refused, file untouched
        let e = write_secret_file(&out, "b = 2\n", false).unwrap_err();
        assert!(format!("{e}").contains("--force"), "{e}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "a = 1\n");
        // --force replaces it (shorter content: no stale tail) and tightens a loose mode
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_file(&out, "b\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "b\n");
        assert_eq!(mode(&out), 0o600);
        // a symlink is never written through, even with --force
        let target = dir.join("victim");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            write_secret_file(&link, "x", true)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        assert!(write_secret_file(&link, "x", false).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_reads_yaml_writes_a_loadable_file_and_refuses_urls_and_overwrites() {
        let dir = tmpdir("run");
        let spec = dir.join("api.yaml");
        std::fs::write(
            &spec,
            "openapi: 3.0.0\nsecurity:\n  - bearerAuth: []\ncomponents:\n  securitySchemes:\n    bearerAuth: {type: http, scheme: bearer}\npaths:\n  /admin/x: {get: {}}\n  /p: {get: {}}\n",
        )
        .unwrap();
        let out = dir.join("roles.toml");
        let wrote = run(spec.to_str().unwrap(), Some(&out), false).unwrap();
        assert_eq!(wrote.as_deref(), Some(out.as_path()));
        // the real loader accepts it, with no loose-mode warning, and the role set is usable
        let r = Roles::load(&out).unwrap();
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!(r.names(), ["user", "user2", "admin"]);
        assert_eq!(r.roles[0].expects("/admin/x"), Some(false));
        assert_eq!(
            r.roles[0].credential(),
            None,
            "no env var is set: nothing resolves"
        );
        assert!(std::fs::read_to_string(&out).unwrap().contains("api.yaml"));
        // second run without --force: refused; with: fine
        assert!(run(spec.to_str().unwrap(), Some(&out), false).is_err());
        run(spec.to_str().unwrap(), Some(&out), true).unwrap();
        // no network
        let e = run("https://example.test/openapi.json", Some(&out), true).unwrap_err();
        assert!(format!("{e}").contains("local file"));
        assert!(run(dir.join("missing.json").to_str().unwrap(), Some(&out), true).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_fixture_spec_derives_roles_that_match_the_hand_written_ones() {
        let doc: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/qa-api/openapi.json"))
                .unwrap();
        let d = derive(&doc).unwrap();
        // the fixture has an /admin area: ordinary roles are denied it, an admin reaches all
        let user = role(&d, "user");
        assert!(
            user.deny.iter().any(|p| p.starts_with("/admin")),
            "{user:?}"
        );
        assert_eq!(role(&d, "admin").allow, ["/**"]);
        let hand: Roles =
            toml::from_str(include_str!("../../../tests/fixtures/qa-api/roles.toml")).unwrap();
        let derived = parsed(&d);
        for path in ["/admin/stats", "/orders", "/orders/3", "/health", "/search"] {
            assert_eq!(
                derived.roles[0].expects(path),
                hand.roles[0].expects(path),
                "user vs alice on {path}"
            );
        }
    }
}
