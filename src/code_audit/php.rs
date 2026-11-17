use std::collections::BTreeSet;
use tree_sitter::Node;

use super::ast::{is_dynamic_expr, node_text, unquote, walk_nodes};
use super::classify::classify_sink;
use super::types::{FunctionInfo, RawEndpoint, SinkHit};

pub fn analyze_php(
    root: Node<'_>,
    src: &[u8],
    rel: &str,
    imports: &mut Vec<String>,
    pkgs: &mut Vec<String>,
    fns: &mut Vec<FunctionInfo>,
    eps: &mut Vec<RawEndpoint>,
) {
    let mut dynamic_vars = BTreeSet::new();
    let mut file_calls = Vec::new();
    let mut file_sinks = Vec::new();

    walk_nodes(root, &mut |n| {
        if n.kind() == "namespace_use_declaration" {
            let txt = node_text(n, src).trim().trim_end_matches(';');
            if let Some(rest) = txt.strip_prefix("use ") {
                let pkg = rest.trim().to_string();
                imports.push(pkg.clone());
                if let Some(root_ns) = pkg.split('\\').next() {
                    pkgs.push(root_ns.to_ascii_lowercase());
                }
            }
        }
        if n.kind() == "assignment_expression"
            && let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            )
        {
            let var = node_text(left, src).trim().to_string();
            if is_dynamic_expr(right, src, &dynamic_vars) {
                dynamic_vars.insert(var);
            }
        }
        if matches!(
            n.kind(),
            "function_call_expression" | "member_call_expression" | "scoped_call_expression"
        ) && let Some(func) = n
            .child_by_field_name("function")
            .or_else(|| n.child_by_field_name("name"))
        {
            let callee = node_text(func, src).trim().to_string();
            file_calls.push(callee.clone());
            let mut args = Vec::new();
            if let Some(an) = n.child_by_field_name("arguments") {
                let mut ac = an.walk();
                for a in an.named_children(&mut ac) {
                    if let Some(val) = a.named_child(0) {
                        args.push(val);
                    } else {
                        args.push(a);
                    }
                }
            }
            if let Some(kind) = classify_sink(&callee, &args, src, &dynamic_vars) {
                file_sinks.push(SinkHit {
                    kind,
                    file: rel.to_string(),
                    line: n.start_position().row as u32 + 1,
                    callee: callee.clone(),
                    via_fn: "<top>".into(),
                });
            }
            let full_txt = node_text(n, src);
            if full_txt.starts_with("Route::")
                && let Some(first) = args.first()
            {
                let rpath = unquote(node_text(*first, src));
                if rpath.starts_with('/') {
                    let guards = if full_txt.to_ascii_lowercase().contains("middleware") {
                        vec!["middleware".into()]
                    } else {
                        vec![]
                    };
                    eps.push(RawEndpoint {
                        method: callee.to_ascii_uppercase(),
                        path: rpath,
                        handler: "<route>".into(),
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

    if !file_sinks.is_empty() || !file_calls.is_empty() {
        fns.push(FunctionInfo {
            file: rel.to_string(),
            name: "<top>".into(),
            line: 1,
            params: vec![],
            calls: file_calls,
            sinks: file_sinks,
        });
    }
}
