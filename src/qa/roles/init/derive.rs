use std::collections::{BTreeMap, BTreeSet};
use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::super::{AuthKind, Roles};
use super::openapi::{
    OpAuth, Scheme, declared_roles, is_privileged, operations, role_name, schemes_of,
};
use super::render::render;
use super::trie::{Node, V, concrete_path, join, segments};
use crate::qa::api::spec::base_path_of;

/// Glob patterns per role past which a note says the list is long.
pub const LONG_GLOB_LIST: usize = 200;

/// Who a role stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Level {
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
    pub scheme: Option<String>,
    pub level: Level,
}

#[derive(Debug, Clone, Default)]
pub struct Derived {
    pub roles: Vec<DerivedRole>,
    /// Things to check by hand (unsupported schemes, globs that cannot express a case, ...).
    pub warnings: Vec<String>,
    pub base_path: String,
    pub operations: usize,
}

pub fn unique(taken: &mut BTreeSet<String>, want: String) -> String {
    let mut n = want.clone();
    let mut i = 2;
    while !taken.insert(n.clone()) {
        n = format!("{want}{i}");
        i += 1;
    }
    n
}

/// Whether `role` should reach `op`.
pub fn verdict(role: &DerivedRole, op: &OpAuth) -> V {
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

/// Parse what was rendered and ask each role about every path: the globs must say what the
/// derivation meant. Returns notes for the paths they cannot express (wildcards overlap).
pub fn verify(text: &str, ops: &[OpAuth], d: &Derived) -> Result<Vec<String>> {
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
