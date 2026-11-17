use std::collections::BTreeSet;
use tree_sitter::Node;

use crate::model::{Category, Finding, Severity};

use super::ast::{
    is_dynamic_expr, is_public_utility_route, is_sensitive_or_mutating_endpoint, node_text,
    unquote,
};
use super::types::{DiscoveredEndpoint, SinkKind};

pub fn classify_sink(
    callee: &str,
    args: &[Node<'_>],
    src: &[u8],
    dynamic_vars: &BTreeSet<String>,
) -> Option<SinkKind> {
    let cl = callee.to_ascii_lowercase();
    let short = cl.rsplit(['.', ':', '>']).next().unwrap_or(cl.as_str());

    // 1. SQL execution
    if matches!(
        short,
        "execute"
            | "executemany"
            | "executescript"
            | "queryrow"
            | "mysqli_query"
            | "pg_query"
            | "$queryrawunsafe"
            | "$executerawunsafe"
    ) || ((short == "query" || short == "raw" || short == "exec")
        && (cl.contains("db")
            || cl.contains("conn")
            || cl.contains("cur")
            || cl.contains("cursor")
            || cl.contains("pool")
            || cl.contains("sql")
            || cl.contains("pdo")
            || cl.contains("sequelize")
            || cl.contains("knex")))
    {
        if let Some(first_arg) = args.first()
            && is_dynamic_expr(*first_arg, src, dynamic_vars)
        {
            return Some(SinkKind::SqlInjection);
        }
        return None;
    }

    // 2. OS Command Execution
    if cl.ends_with("os.system")
        || cl.ends_with("os.popen")
        || cl == "exec.command"
        || cl == "exec.commandcontext"
        || matches!(short, "shell_exec" | "passthru" | "proc_open" | "execsync")
        || (short == "system" || (short == "exec" && !cl.contains("db") && !cl.contains("sql")))
        || (cl.contains("child_process") && matches!(short, "exec" | "execsync"))
        || (cl.contains("subprocess.")
            && matches!(short, "run" | "popen" | "call" | "check_output"))
    {
        if cl == "exec.command" || cl == "exec.commandcontext" {
            let offset = usize::from(cl == "exec.commandcontext");
            // Go `exec.Command("sh", "-c", dynamic_cmd)` or `exec.Command(dynamic_bin, ...)`
            let first_dyn = args
                .get(offset)
                .is_some_and(|a| is_dynamic_expr(*a, src, dynamic_vars));
            let shell_c = args.len() >= offset + 3
                && args.get(offset).is_some_and(|a| {
                    let s = unquote(node_text(*a, src));
                    matches!(s.as_str(), "sh" | "bash" | "/bin/sh" | "/bin/bash" | "cmd")
                })
                && is_dynamic_expr(args[offset + 2], src, dynamic_vars);
            if first_dyn || shell_c {
                return Some(SinkKind::CommandExec);
            }
            return None;
        }
        if cl.contains("subprocess.") {
            let first_dyn = args
                .first()
                .is_some_and(|a| is_dynamic_expr(*a, src, dynamic_vars));
            let has_shell_true = args
                .iter()
                .any(|a| node_text(*a, src).replace(' ', "").contains("shell=True"));
            if first_dyn && (has_shell_true || args.first().is_some_and(|a| a.kind() != "list")) {
                return Some(SinkKind::CommandExec);
            }
            return None;
        }
        if args
            .first()
            .is_some_and(|a| is_dynamic_expr(*a, src, dynamic_vars))
        {
            return Some(SinkKind::CommandExec);
        }
        return None;
    }

    // 3. SSRF
    if cl.starts_with("requests.")
        || cl.starts_with("httpx.")
        || cl.contains("urlopen")
        || cl == "fetch"
        || cl.starts_with("axios.")
        || cl == "axios"
        || cl == "http.get"
        || cl == "http.post"
        || cl == "http.newrequest"
    {
        let url_arg = if cl == "http.newrequest" {
            args.get(1)
        } else {
            args.first()
        };
        if url_arg.is_some_and(|a| is_dynamic_expr(*a, src, dynamic_vars)) {
            return Some(SinkKind::Ssrf);
        }
        return None;
    }

    // 4. SSTI
    if matches!(
        short,
        "render_template_string" | "renderstring" | "from_string"
    ) || (short == "render" && cl.starts_with("ejs."))
    {
        if args
            .first()
            .is_some_and(|a| is_dynamic_expr(*a, src, dynamic_vars))
        {
            return Some(SinkKind::ServerSideTemplate);
        }
        return None;
    }

    // 5. Path traversal
    if matches!(
        short,
        "send_file" | "sendfile" | "servefile" | "readfile" | "readfilesync" | "file_get_contents"
    ) || cl == "os.open"
        || cl == "os.readfile"
    {
        let target_arg = if short == "servefile" {
            args.get(2)
        } else {
            args.first()
        };
        if target_arg.is_some_and(|a| is_dynamic_expr(*a, src, dynamic_vars)) {
            return Some(SinkKind::PathTraversal);
        }
    }
    None
}

pub fn detect_missing_guards(endpoints: &[DiscoveredEndpoint], findings: &mut Vec<Finding>) {
    let protected: Vec<&DiscoveredEndpoint> = endpoints
        .iter()
        .filter(|e| !e.guards.is_empty() && !is_public_utility_route(&e.path))
        .collect();
    if protected.len() < 2 {
        return;
    }
    let sample_guards: Vec<String> = protected
        .iter()
        .take(3)
        .map(|e| format!("{} {} ({})", e.method, e.path, e.guards.join(",")))
        .collect();

    let mut seen = BTreeSet::new();
    for ep in endpoints {
        if !ep.guards.is_empty()
            || is_public_utility_route(&ep.path)
            || !is_sensitive_or_mutating_endpoint(ep)
        {
            continue;
        }
        if !seen.insert((ep.method.clone(), ep.path.clone())) {
            continue;
        }
        let mut f = Finding::new(
            "security.code_audit",
            "security.auth.missing_guard",
            Category::Security,
            Severity::High,
            format!(
                "Endpoint {} {} lacks authentication guard present on sibling routes",
                ep.method, ep.path
            ),
            format!("{}:{}", ep.file, ep.line),
        )
        .detail(format!(
            "Sibling endpoints enforce auth middleware ({}) while handler `{}` at {}:{} has none.",
            sample_guards.join("; "),
            ep.handler,
            ep.file,
            ep.line
        ))
        .remediation("Attach the service's authentication/authorization middleware or decorator before exposing this handler.")
        .fp_key(format!("missing_guard|{}|{}", ep.method, ep.path));
        f.finalize();
        findings.push(f);
    }
}
