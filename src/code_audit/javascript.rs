use std::collections::BTreeSet;
use tree_sitter::Node;

use super::ast::{
    is_dynamic_expr, looks_like_guard_name, node_text, unquote, walk_nodes,
};
use super::classify::classify_sink;
use super::types::{FunctionInfo, RawEndpoint, SinkHit};

pub fn js_pkg_name(raw_spec: &str) -> Option<String> {
    let s = unquote(raw_spec);
    if s.is_empty() || s.starts_with('.') || s.starts_with('/') {
        return None;
    }
    if let Some(rest) = s.strip_prefix('@') {
        let mut parts = rest.split('/');
        let scope = parts.next()?;
        let pkg = parts.next()?;
        Some(format!("@{scope}/{pkg}"))
    } else {
        Some(s.split('/').next()?.to_string())
    }
}

pub fn next_app_route_path(rel: &str) -> String {
    let trimmed = rel.strip_prefix("src/").unwrap_or(rel);
    let trimmed = trimmed.strip_prefix("app/").unwrap_or(trimmed);
    let dir = trimmed.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    let segs: Vec<String> = dir
        .split('/')
        .filter(|s| !s.is_empty() && !(s.starts_with('(') && s.ends_with(')')))
        .map(|s| {
            if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
                format!("{{{}}}", inner.trim_start_matches('.'))
            } else {
                s.to_string()
            }
        })
        .collect();
    if segs.is_empty() {
        "/".into()
    } else {
        format!("/{}", segs.join("/"))
    }
}

pub fn analyze_js_ts(
    root: Node<'_>,
    src: &[u8],
    rel: &str,
    imports: &mut Vec<String>,
    pkgs: &mut Vec<String>,
    fns: &mut Vec<FunctionInfo>,
    eps: &mut Vec<RawEndpoint>,
) {
    let mut file_guards: Vec<String> = Vec::new();
    let mut cur = root.walk();
    for ch in root.children(&mut cur) {
        if ch.kind() == "import_statement"
            && let Some(snode) = ch.child_by_field_name("source")
        {
            let spec = unquote(node_text(snode, src));
            if !spec.is_empty() {
                imports.push(spec.clone());
                if let Some(pkg) = js_pkg_name(&spec) {
                    pkgs.push(pkg);
                }
            }
        } else if ch.kind() == "function_declaration"
            && let Some(fi) = inspect_js_fn(ch, src, rel, None)
        {
            // Support Next.js App Router `export async function GET/POST/...`
            if (rel.contains("/route.") || rel.starts_with("route."))
                && matches!(
                    fi.name.as_str(),
                    "GET" | "POST" | "PUT" | "DELETE" | "PATCH"
                )
            {
                let route_path = next_app_route_path(rel);
                eps.push(RawEndpoint {
                    method: fi.name.clone(),
                    path: route_path,
                    handler: fi.name.clone(),
                    file: rel.to_string(),
                    line: fi.line,
                    guards: vec![],
                    params: vec![],
                    inline_calls: fi.calls.clone(),
                    inline_sinks: fi.sinks.clone(),
                });
            }
            fns.push(fi);
        } else if ch.kind() == "export_statement"
            && let Some(decl) = ch.child_by_field_name("declaration")
            && decl.kind() == "function_declaration"
            && let Some(fi) = inspect_js_fn(decl, src, rel, None)
        {
            if (rel.contains("/route.") || rel.starts_with("route."))
                && matches!(
                    fi.name.as_str(),
                    "GET" | "POST" | "PUT" | "DELETE" | "PATCH"
                )
            {
                eps.push(RawEndpoint {
                    method: fi.name.clone(),
                    path: next_app_route_path(rel),
                    handler: fi.name.clone(),
                    file: rel.to_string(),
                    line: fi.line,
                    guards: vec![],
                    params: vec![],
                    inline_calls: fi.calls.clone(),
                    inline_sinks: fi.sinks.clone(),
                });
            }
            fns.push(fi);
        }
    }

    // Collect `require(...)`, arrow-function declarations, file-level `.use(guard)`, and routes.
    walk_nodes(root, &mut |n| {
        if n.kind() == "variable_declarator"
            && let (Some(name_n), Some(val_n)) = (
                n.child_by_field_name("name"),
                n.child_by_field_name("value"),
            )
            && name_n.kind() == "identifier"
            && matches!(
                val_n.kind(),
                "arrow_function" | "function_expression" | "function"
            )
        {
            let fname = node_text(name_n, src).trim().to_string();
            if let Some(fi) = inspect_js_fn(val_n, src, rel, Some(fname)) {
                fns.push(fi);
            }
        }
        if n.kind() == "call_expression"
            && let Some(fn_node) = n.child_by_field_name("function")
        {
            let callee = node_text(fn_node, src).trim();
            if callee == "require"
                && let Some(args) = n.child_by_field_name("arguments")
                && let Some(first) = args.named_child(0)
            {
                let spec = unquote(node_text(first, src));
                if !spec.is_empty() {
                    imports.push(spec.clone());
                    if let Some(pkg) = js_pkg_name(&spec) {
                        pkgs.push(pkg);
                    }
                }
            } else if let Some(method_raw) = callee.rsplit('.').next() {
                let m = method_raw.to_ascii_lowercase();
                if m == "use"
                    && let Some(args) = n.child_by_field_name("arguments")
                {
                    let mut ac = args.walk();
                    for a in args.named_children(&mut ac) {
                        let txt = node_text(a, src).trim();
                        if looks_like_guard_name(txt) && !txt.starts_with(['"', '\'', '`']) {
                            file_guards.push(txt.split('(').next().unwrap_or(txt).to_string());
                        }
                    }
                } else if matches!(
                    m.as_str(),
                    "get" | "post" | "put" | "delete" | "patch" | "all"
                ) && !callee.contains("axios")
                    && !callee.contains("http")
                    && !callee.contains("searchparams")
                    && let Some(args_n) = n.child_by_field_name("arguments")
                {
                    let mut arg_list = Vec::new();
                    let mut ac = args_n.walk();
                    for c in args_n.named_children(&mut ac) {
                        if c.kind() != "comment" {
                            arg_list.push(c);
                        }
                    }
                    if let Some(first) = arg_list.first()
                        && matches!(first.kind(), "string" | "template_string")
                    {
                        let rpath = unquote(node_text(*first, src));
                        if rpath.starts_with('/') && arg_list.len() >= 2 {
                            let mut guards = file_guards.clone();
                            for mid in &arg_list[1..arg_list.len() - 1] {
                                let txt = node_text(*mid, src).trim();
                                if looks_like_guard_name(txt) {
                                    guards.push(txt.split('(').next().unwrap_or(txt).to_string());
                                }
                            }
                            let last = arg_list[arg_list.len() - 1];
                            let (handler, inline_calls, inline_sinks, inline_params) = if matches!(
                                last.kind(),
                                "arrow_function" | "function_expression" | "function"
                            ) {
                                let fi = inspect_js_fn(last, src, rel, Some("<anon>".into()));
                                match fi {
                                    Some(f) => (
                                        f.name,
                                        f.calls,
                                        f.sinks,
                                        f.params
                                            .into_iter()
                                            .filter(|p| {
                                                !matches!(
                                                    p.as_str(),
                                                    "req" | "res" | "request" | "next"
                                                )
                                            })
                                            .collect(),
                                    ),
                                    None => ("<anon>".into(), vec![], vec![], vec![]),
                                }
                            } else {
                                let hname = node_text(last, src).trim().to_string();
                                (hname, vec![], vec![], vec![])
                            };
                            eps.push(RawEndpoint {
                                method: if m == "all" {
                                    "GET".into()
                                } else {
                                    m.to_ascii_uppercase()
                                },
                                path: rpath,
                                handler,
                                file: rel.to_string(),
                                line: n.start_position().row as u32 + 1,
                                guards,
                                params: inline_params,
                                inline_calls,
                                inline_sinks,
                            });
                        }
                    }
                }
            }
        }
        true
    });
}

pub fn inspect_js_fn(
    node: Node<'_>,
    src: &[u8],
    rel: &str,
    override_name: Option<String>,
) -> Option<FunctionInfo> {
    let name = override_name.or_else(|| {
        node.child_by_field_name("name")
            .map(|n| node_text(n, src).trim().to_string())
    })?;
    let mut params = Vec::new();
    let mut dynamic_vars = BTreeSet::new();
    if let Some(pnode) = node.child_by_field_name("parameters") {
        let mut pc = pnode.walk();
        for ch in pnode.named_children(&mut pc) {
            if let Some(id) = match ch.kind() {
                "identifier" => Some(node_text(ch, src).trim().to_string()),
                "required_parameter" | "optional_parameter" => ch
                    .named_child(0)
                    .filter(|c| c.kind() == "identifier")
                    .map(|c| node_text(c, src).trim().to_string()),
                _ => None,
            } {
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
        if n.kind() == "member_expression" {
            let txt = node_text(n, src).trim();
            for prefix in [
                "req.query.",
                "req.body.",
                "req.params.",
                "request.query.",
                "request.body.",
                "request.params.",
            ] {
                if let Some(rest) = txt.strip_prefix(prefix)
                    && !rest.is_empty()
                    && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    let key = rest.to_string();
                    dynamic_vars.insert(key.clone());
                    if !params.contains(&key) {
                        params.push(key);
                    }
                }
            }
        }
        if n.kind() == "variable_declarator"
            && let (Some(left), Some(right)) = (
                n.child_by_field_name("name"),
                n.child_by_field_name("value"),
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
