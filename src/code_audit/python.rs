use std::collections::BTreeSet;
use tree_sitter::Node;

use super::ast::{is_dynamic_expr, looks_like_guard_name, node_text, unquote, walk_nodes};
use super::classify::classify_sink;
use super::types::{FunctionInfo, RawEndpoint, SinkHit};

pub fn python_root_pkg(name: &str) -> String {
    name.trim()
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

pub fn analyze_python(
    root: Node<'_>,
    src: &[u8],
    rel: &str,
    imports: &mut Vec<String>,
    pkgs: &mut Vec<String>,
    fns: &mut Vec<FunctionInfo>,
    eps: &mut Vec<RawEndpoint>,
) {
    let mut cur = root.walk();
    for ch in root.children(&mut cur) {
        match ch.kind() {
            "import_statement" => {
                let mut ic = ch.walk();
                for n in ch.children(&mut ic) {
                    if n.kind() == "dotted_name" || n.kind() == "aliased_import" {
                        let txt = node_text(n, src);
                        let target = txt.split_whitespace().next().unwrap_or("");
                        if !target.is_empty() {
                            imports.push(target.to_string());
                            let root_pkg = python_root_pkg(target);
                            if !root_pkg.is_empty() {
                                pkgs.push(root_pkg);
                            }
                        }
                    }
                }
            }
            "import_from_statement" => {
                if let Some(mn) = ch.child_by_field_name("module_name") {
                    let mod_name = node_text(mn, src).trim().to_string();
                    if !mod_name.is_empty() {
                        imports.push(mod_name.clone());
                        let root_pkg = python_root_pkg(&mod_name);
                        if !root_pkg.is_empty() {
                            pkgs.push(root_pkg);
                        }
                    }
                }
            }
            "decorated_definition" => {
                inspect_python_decorated(ch, src, rel, fns, eps);
            }
            "function_definition" => {
                if let Some(fi) = inspect_python_fn(ch, src, rel) {
                    fns.push(fi);
                }
            }
            _ => {}
        }
    }
}

pub fn parse_py_route_decorator(txt: &str) -> Option<(Vec<String>, String)> {
    let lower = txt.to_ascii_lowercase();
    let verbs = ["route", "get", "post", "put", "delete", "patch"];
    let open = txt.find('(')?;
    let callee = txt[..open].trim();
    let last = callee.rsplit('.').next()?.to_ascii_lowercase();
    if !verbs.contains(&last.as_str()) {
        return None;
    }
    let inside = txt[open + 1..txt.rfind(')').unwrap_or(txt.len())].trim();
    let first_arg = inside.split(',').next()?.trim();
    if !(first_arg.starts_with('"') || first_arg.starts_with('\'')) {
        return None;
    }
    let path = unquote(first_arg);
    if !path.starts_with('/') {
        return None;
    }
    let methods = if last == "route" {
        let mut ms = Vec::new();
        for m in ["GET", "POST", "PUT", "DELETE", "PATCH"] {
            if lower.contains(&m.to_ascii_lowercase()) && lower.contains("methods") {
                ms.push(m.to_string());
            }
        }
        if ms.is_empty() {
            vec!["GET".into()]
        } else {
            ms
        }
    } else {
        vec![last.to_ascii_uppercase()]
    };
    Some((methods, path))
}

pub fn inspect_python_decorated(
    node: Node<'_>,
    src: &[u8],
    rel: &str,
    fns: &mut Vec<FunctionInfo>,
    eps: &mut Vec<RawEndpoint>,
) {
    let mut guards = Vec::new();
    let mut routes: Vec<(Vec<String>, String, u32)> = Vec::new();
    let mut fn_node = None;
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if ch.kind() == "decorator" {
            let txt = node_text(ch, src).trim().trim_start_matches('@');
            if let Some((ms, path)) = parse_py_route_decorator(txt) {
                routes.push((ms, path, ch.start_position().row as u32 + 1));
            } else if looks_like_guard_name(txt) {
                guards.push(txt.split('(').next().unwrap_or(txt).to_string());
            }
        } else if ch.kind() == "function_definition" {
            fn_node = Some(ch);
        }
    }
    let Some(fnode) = fn_node else {
        return;
    };
    let Some(fi) = inspect_python_fn(fnode, src, rel) else {
        return;
    };
    // Check parameter list for FastAPI `Depends(...)` / `Security(...)` guards
    if let Some(params_node) = fnode.child_by_field_name("parameters") {
        let ptxt = node_text(params_node, src);
        if looks_like_guard_name(ptxt) && guards.is_empty() {
            guards.push("Depends(auth)".into());
        }
    }
    let mut ep_params = Vec::new();
    walk_nodes(fnode, &mut |n| {
        if n.kind() == "call"
            && let Some(fn_part) = n.child_by_field_name("function")
        {
            let fn_txt = node_text(fn_part, src);
            if (fn_txt.contains("request.args.get")
                || fn_txt.contains("request.form.get")
                || fn_txt.contains("request.json.get"))
                && let Some(args_n) = n.child_by_field_name("arguments")
            {
                let mut ac = args_n.walk();
                for a in args_n.named_children(&mut ac) {
                    if a.kind() == "string" {
                        let k = unquote(node_text(a, src));
                        if !k.is_empty() && !ep_params.contains(&k) {
                            ep_params.push(k);
                        }
                        break;
                    }
                }
            }
        }
        true
    });

    let handler_name = fi.name.clone();
    let inline_calls = fi.calls.clone();
    let inline_sinks = fi.sinks.clone();
    fns.push(fi);

    for (methods, path, line) in routes {
        for method in methods {
            eps.push(RawEndpoint {
                method,
                path: path.clone(),
                handler: handler_name.clone(),
                file: rel.to_string(),
                line,
                guards: guards.clone(),
                params: ep_params.clone(),
                inline_calls: inline_calls.clone(),
                inline_sinks: inline_sinks.clone(),
            });
        }
    }
}

pub fn inspect_python_fn(node: Node<'_>, src: &[u8], rel: &str) -> Option<FunctionInfo> {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, src).trim().to_string())?;
    let mut params = Vec::new();
    let mut dynamic_vars = BTreeSet::new();
    if let Some(pnode) = node.child_by_field_name("parameters") {
        let mut pc = pnode.walk();
        for ch in pnode.named_children(&mut pc) {
            if let Some(id) = match ch.kind() {
                "identifier" => Some(node_text(ch, src).trim().to_string()),
                "typed_parameter" | "default_parameter" | "typed_default_parameter" => ch
                    .named_child(0)
                    .filter(|c| c.kind() == "identifier")
                    .map(|c| node_text(c, src).trim().to_string()),
                _ => None,
            } && !id.is_empty()
            {
                if !matches!(id.as_str(), "self" | "cls") {
                    dynamic_vars.insert(id.clone());
                }
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
            calls: Vec::new(),
            sinks: Vec::new(),
        });
    };

    let mut calls = Vec::new();
    let mut sinks = Vec::new();

    walk_nodes(body, &mut |n| {
        if n.kind() == "assignment"
            && let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            )
            && left.kind() == "identifier"
        {
            let var = node_text(left, src).trim().to_string();
            if is_dynamic_expr(right, src, &dynamic_vars) {
                dynamic_vars.insert(var);
            } else {
                dynamic_vars.remove(&var);
            }
        }
        if n.kind() == "call"
            && let Some(func) = n.child_by_field_name("function")
        {
            let callee = node_text(func, src).trim().to_string();
            calls.push(callee.clone());
            let mut arg_nodes = Vec::new();
            if let Some(an) = n.child_by_field_name("arguments") {
                let mut ac = an.walk();
                for c in an.named_children(&mut ac) {
                    if c.kind() != "comment" {
                        arg_nodes.push(c);
                    }
                }
            }
            if let Some(kind) = classify_sink(&callee, &arg_nodes, src, &dynamic_vars) {
                sinks.push(SinkHit {
                    kind,
                    file: rel.to_string(),
                    line: n.start_position().row as u32 + 1,
                    callee,
                    via_fn: name.clone(),
                });
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
