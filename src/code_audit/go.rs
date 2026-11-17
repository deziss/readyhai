use std::collections::BTreeSet;
use tree_sitter::Node;

use super::ast::{is_dynamic_expr, looks_like_guard_name, node_text, unquote, walk_nodes};
use super::classify::classify_sink;
use super::types::{FunctionInfo, RawEndpoint, SinkHit};

pub fn analyze_go(
    root: Node<'_>,
    src: &[u8],
    rel: &str,
    imports: &mut Vec<String>,
    pkgs: &mut Vec<String>,
    fns: &mut Vec<FunctionInfo>,
    eps: &mut Vec<RawEndpoint>,
) {
    walk_nodes(root, &mut |n| {
        if n.kind() == "import_spec"
            && let Some(pnode) = n.child_by_field_name("path")
        {
            let spec = unquote(node_text(pnode, src));
            if !spec.is_empty() {
                imports.push(spec.clone());
                pkgs.push(spec);
            }
        }
        true
    });

    let mut cur = root.walk();
    for ch in root.children(&mut cur) {
        if matches!(ch.kind(), "function_declaration" | "method_declaration")
            && let Some(fi) = inspect_go_fn(ch, src, rel, eps)
        {
            fns.push(fi);
        }
    }
}

pub fn inspect_go_fn(
    node: Node<'_>,
    src: &[u8],
    rel: &str,
    eps: &mut Vec<RawEndpoint>,
) -> Option<FunctionInfo> {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, src).trim().to_string())?;
    let mut params = Vec::new();
    let mut dynamic_vars = BTreeSet::new();
    if let Some(pnode) = node.child_by_field_name("parameters") {
        let mut pc = pnode.walk();
        for ch in pnode.named_children(&mut pc) {
            if ch.kind() == "parameter_declaration"
                && let Some(pname) = ch.child_by_field_name("name")
            {
                let id = node_text(pname, src).trim().to_string();
                dynamic_vars.insert(id.clone());
                params.push(id);
            }
        }
    }
    let Some(body) = node.child_by_field_name("body") else {
        return Some(FunctionInfo {
            file: rel.to_string(),
            name,
            line: node.start_position().row as u32 + 1,
            params,
            calls: vec![],
            sinks: vec![],
        });
    };

    let mut calls = Vec::new();
    let mut sinks = Vec::new();
    walk_nodes(body, &mut |n| {
        if matches!(n.kind(), "short_var_declaration" | "assignment_statement")
            && let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            )
        {
            let var = node_text(left, src).trim().to_string();
            let rhs = right.named_child(0).unwrap_or(right);
            if !var.contains(',') && is_dynamic_expr(rhs, src, &dynamic_vars) {
                dynamic_vars.insert(var);
            }
        }
        if n.kind() == "call_expression"
            && let Some(func) = n.child_by_field_name("function")
        {
            let callee = node_text(func, src).trim().to_string();
            calls.push(callee.clone());
            let mut args = Vec::new();
            if let Some(an) = n.child_by_field_name("arguments") {
                let mut ac = an.walk();
                for c in an.named_children(&mut ac) {
                    if c.kind() != "comment" {
                        args.push(c);
                    }
                }
            }
            if let Some(kind) = classify_sink(&callee, &args, src, &dynamic_vars) {
                sinks.push(SinkHit {
                    kind,
                    file: rel.to_string(),
                    line: n.start_position().row as u32 + 1,
                    callee: callee.clone(),
                    via_fn: name.clone(),
                });
            }
            // Capture Go HTTP route registrations (`HandleFunc`, `.GET`, `.POST`, etc.)
            let short = callee.rsplit('.').next().unwrap_or("");
            if (short == "HandleFunc"
                || matches!(short, "GET" | "POST" | "PUT" | "DELETE" | "PATCH"))
                && args.len() >= 2
                && args[0].kind() == "interpreted_string_literal"
            {
                let rpath = unquote(node_text(args[0], src));
                if rpath.starts_with('/') {
                    let mut guards = Vec::new();
                    let last = node_text(args[args.len() - 1], src).trim().to_string();
                    if looks_like_guard_name(&last) {
                        guards.push(last.clone());
                    }
                    let method = if short == "HandleFunc" { "GET" } else { short };
                    eps.push(RawEndpoint {
                        method: method.into(),
                        path: rpath,
                        handler: last,
                        file: rel.to_string(),
                        line: n.start_position().row as u32 + 1,
                        guards,
                        params: vec![],
                        inline_calls: vec![],
                        inline_sinks: vec![],
                    });
                }
            }
        }
        true
    });

    Some(FunctionInfo {
        file: rel.to_string(),
        name,
        line: node.start_position().row as u32 + 1,
        params,
        calls,
        sinks,
    })
}
