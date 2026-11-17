use std::collections::BTreeSet;
use tree_sitter::Node;

use super::types::DiscoveredEndpoint;

pub fn node_text<'a>(n: Node<'_>, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
}

pub fn walk_nodes<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>) -> bool) {
    if !visit(node) {
        return;
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        walk_nodes(ch, visit);
    }
}

pub fn unquote(raw: &str) -> String {
    let mut s = raw.trim();
    for pref in ["f", "r", "b", "u", "fr", "rf"] {
        if let Some(rest) = s.strip_prefix(pref)
            && (rest.starts_with('"') || rest.starts_with('\''))
        {
            s = rest;
            break;
        }
    }
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\''))
            || (s.starts_with('`') && s.ends_with('`')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

pub fn looks_like_guard_name(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [
        "auth",
        "login_required",
        "jwt",
        "protect",
        "admin",
        "require_",
        "requires_",
        "permission",
        "role",
        "guard",
        "verify",
        "session",
        "depends",
        "security",
        "current_user",
        "middleware",
    ]
    .iter()
    .any(|kw| l.contains(kw))
}

pub fn is_static_string_node(n: Node<'_>, _src: &[u8]) -> bool {
    match n.kind() {
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal" => {
            let mut has_interp = false;
            let mut cur = n.walk();
            for ch in n.children(&mut cur) {
                if matches!(
                    ch.kind(),
                    "interpolation" | "template_substitution" | "variable_name"
                ) {
                    has_interp = true;
                }
            }
            !has_interp
        }
        "template_string" => {
            let mut cur = n.walk();
            !n.children(&mut cur)
                .any(|c| c.kind() == "template_substitution")
        }
        "encapsed_string" => {
            let mut cur = n.walk();
            !n.children(&mut cur)
                .any(|c| matches!(c.kind(), "variable_name" | "member_access_expression"))
        }
        "parenthesized_expression" => n
            .named_child(0)
            .is_some_and(|c| is_static_string_node(c, _src)),
        _ => false,
    }
}

pub fn is_dynamic_expr(n: Node<'_>, src: &[u8], dynamic_vars: &BTreeSet<String>) -> bool {
    if is_static_string_node(n, src) {
        return false;
    }
    match n.kind() {
        "identifier" | "name" => {
            let txt = node_text(n, src).trim();
            dynamic_vars.contains(txt)
        }
        "variable_name" => true,
        "binary_operator"
        | "binary_expression"
        | "string"
        | "template_string"
        | "encapsed_string"
        | "subscript"
        | "subscript_expression"
        | "attribute"
        | "member_expression"
        | "selector_expression" => true,
        "call" | "call_expression" | "function_call_expression" | "member_call_expression" => true,
        _ => !matches!(
            n.kind(),
            "integer" | "float" | "number" | "true" | "false" | "none" | "null" | "nil"
        ),
    }
}

pub fn file_stem_key(rel: &str) -> String {
    let no_ext = rel.rsplit_once('.').map(|(a, _)| a).unwrap_or(rel);
    no_ext
        .strip_suffix("/__init__")
        .or_else(|| no_ext.strip_suffix("/index"))
        .unwrap_or(no_ext)
        .to_string()
}

pub fn is_public_utility_route(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/health",
        "/healthz",
        "/ready",
        "/live",
        "/ping",
        "/login",
        "/signin",
        "/logout",
        "/signup",
        "/register",
        "/auth/",
        "/oauth",
        "/token",
        "/openapi",
        "/swagger",
        "/docs",
        "/metrics",
        "/favicon",
        "/static",
        "/assets",
    ]
    .iter()
    .any(|kw| p == *kw || p.starts_with(kw) || p.contains(kw))
}

pub fn is_sensitive_or_mutating_endpoint(ep: &DiscoveredEndpoint) -> bool {
    if matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return true;
    }
    let p = ep.path.to_ascii_lowercase();
    [
        "admin", "internal", "user", "order", "account", "billing", "wallet", "export", "config",
        "secret", "debug", "invoice", "payment",
    ]
    .iter()
    .any(|kw| p.contains(kw))
}
