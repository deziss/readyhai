//! Native Tree-sitter AST & cross-file security code auditor (Python, JS/TS, Go, PHP).
//!
//! Capabilities:
//! 1. True AST function, import, endpoint, guard-middleware, and local variable taint parsing via
//!    `tree-sitter` grammars (Python, JavaScript/JSX, TypeScript/TSX, Go, PHP).
//! 2. Cross-file import & call-graph traversal (up to 3 hops) linking route handlers to dangerous
//!    sinks (`SqlInjection`, `CommandExec`, `Ssrf`, `PathTraversal`, `ServerSideTemplate`) while
//!    ignoring parameterized/literal queries.
//! 3. Authentication middleware consistency checking (`security.auth.missing_guard`) across sibling
//!    endpoints in a protected service/prefix.
//! 4. Package import collection (`called_packages`) for supply-chain reachability enrichment.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;

use tree_sitter::{Node, Parser};
use walkdir::WalkDir;

use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};

const MAX_FILES: usize = 2500;
const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Go,
    Php,
}

impl Lang {
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "py" => Some(Self::Python),
            "js" | "mjs" | "cjs" | "jsx" => Some(Self::JavaScript),
            "ts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "go" => Some(Self::Go),
            "php" => Some(Self::Php),
            _ => None,
        }
    }

    fn parser(self) -> Option<Parser> {
        let mut p = Parser::new();
        let lang = match self {
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        };
        p.set_language(&lang).ok()?;
        Some(p)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SinkKind {
    SqlInjection,
    CommandExec,
    Ssrf,
    PathTraversal,
    ServerSideTemplate,
}

impl SinkKind {
    pub fn rule_id(self) -> &'static str {
        match self {
            SinkKind::SqlInjection => "security.taint.sql_injection",
            SinkKind::CommandExec => "security.taint.command_exec",
            SinkKind::Ssrf => "security.taint.ssrf",
            SinkKind::PathTraversal => "security.taint.path_traversal",
            SinkKind::ServerSideTemplate => "security.taint.ssti",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            SinkKind::CommandExec => Severity::Critical,
            SinkKind::SqlInjection
            | SinkKind::Ssrf
            | SinkKind::PathTraversal
            | SinkKind::ServerSideTemplate => Severity::High,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SinkKind::SqlInjection => "dynamic SQL execution",
            SinkKind::CommandExec => "dynamic OS command execution",
            SinkKind::Ssrf => "server-side HTTP request to dynamic URL",
            SinkKind::PathTraversal => "filesystem access with dynamic path",
            SinkKind::ServerSideTemplate => "template rendering with dynamic input",
        }
    }

    pub fn technique_hint(self) -> &'static str {
        match self {
            SinkKind::SqlInjection => "sqli",
            SinkKind::CommandExec => "cmdi",
            SinkKind::Ssrf => "ssrf",
            SinkKind::PathTraversal => "traversal",
            SinkKind::ServerSideTemplate => "ssti",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SinkHit {
    pub kind: SinkKind,
    pub file: String,
    pub line: u32,
    pub callee: String,
    pub via_fn: String,
}

#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    pub line: u32,
    pub guards: Vec<String>,
    pub params: Vec<String>,
    pub sinks: Vec<SinkHit>,
}

#[derive(Debug, Default, Clone)]
pub struct CodeInventory {
    pub endpoints: Vec<DiscoveredEndpoint>,
    pub imports_by_file: BTreeMap<String, Vec<String>>,
    pub imported_packages: BTreeSet<String>,
    pub findings: Vec<Finding>,
    pub unreadable: Vec<String>,
}

#[derive(Debug, Clone)]
struct FunctionInfo {
    file: String,
    name: String,
    #[allow(dead_code)]
    line: u32,
    params: Vec<String>,
    calls: Vec<String>,
    sinks: Vec<SinkHit>,
}

#[derive(Debug, Clone)]
struct RawEndpoint {
    method: String,
    path: String,
    handler: String,
    file: String,
    line: u32,
    guards: Vec<String>,
    params: Vec<String>,
    inline_calls: Vec<String>,
    inline_sinks: Vec<SinkHit>,
}

pub fn checks() -> Vec<Check> {
    vec![Check::new(
        "security.code_audit",
        "AST & cross-file security code audit (Python, JS/TS, Go, PHP)",
        &[TargetKind::Repo],
        Profile::Quick,
        code_audit_check,
    )]
}

fn code_audit_check(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no repository snapshot".into(),
        )));
    };
    let denied: BTreeSet<&str> = snap.denied.iter().map(|d| d.path.as_str()).collect();
    let inv = audit_tree_filtered(&snap.root, &denied);
    let mut findings = inv.findings;
    for f in &mut findings {
        f.finalize();
    }
    if inv.unreadable.is_empty() {
        Ok(CheckOutput::findings(findings))
    } else {
        Ok(CheckOutput {
            status: Some(CheckStatus::Partial(format!(
                "code audit skipped {} oversized/unreadable file(s): {}",
                inv.unreadable.len(),
                inv.unreadable
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
            findings,
        })
    }
}

/// Audit a repository directory cleanly with Tree-sitter ASTs.
pub fn audit_tree(root: &Path) -> CodeInventory {
    audit_tree_filtered(root, &BTreeSet::new())
}

/// Return true if a package identifier from a lockfile matches any AST-imported module.
pub fn package_is_imported(imported: &BTreeSet<String>, pkg: &str) -> bool {
    let norm = |s: &str| s.trim().to_ascii_lowercase().replace('-', "_");
    let target = norm(pkg);
    if target.is_empty() {
        return false;
    }
    imported.iter().any(|imp| {
        let ni = norm(imp);
        ni == target
            || ni.starts_with(&format!("{target}/"))
            || ni.ends_with(&format!("/{target}"))
            || target.ends_with(&format!("/{ni}"))
    })
}

/// Collect top-level package names imported across analyzed Python, JS/TS, Go, and PHP files.
pub fn called_packages(root: &Path) -> BTreeSet<String> {
    audit_tree(root).imported_packages
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | ".venv"
            | "venv"
            | "__pycache__"
            | "vendor"
            | ".next"
    )
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn audit_tree_filtered(root: &Path, denied: &BTreeSet<&str>) -> CodeInventory {
    let mut inv = CodeInventory::default();
    let mut functions: BTreeMap<(String, String), FunctionInfo> = BTreeMap::new();
    let mut fns_by_name: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut raw_endpoints: Vec<RawEndpoint> = Vec::new();
    // file -> imported target stems / module prefixes
    let mut module_edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut files_seen = 0usize;

    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            if e.file_type().is_dir() {
                return e.file_name().to_str().is_some_and(|n| !should_skip_dir(n));
            }
            true
        });

    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Some(lang) = Lang::from_path(path) else {
            continue;
        };
        let rel = rel_path(root, path);
        if denied.contains(rel.as_str()) {
            continue;
        }
        files_seen += 1;
        if files_seen > MAX_FILES {
            break;
        }
        let Ok(meta) = fs::metadata(path) else {
            inv.unreadable.push(rel);
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            inv.unreadable.push(rel);
            continue;
        }
        let Ok(src) = fs::read_to_string(path) else {
            inv.unreadable.push(rel);
            continue;
        };
        let Some(mut parser) = lang.parser() else {
            continue;
        };
        let Some(tree) = parser.parse(&src, None) else {
            continue;
        };

        let mut file_imports = Vec::new();
        let mut file_pkgs = Vec::new();
        let mut file_fns = Vec::new();
        let mut file_eps = Vec::new();

        match lang {
            Lang::Python => analyze_python(
                tree.root_node(),
                src.as_bytes(),
                &rel,
                &mut file_imports,
                &mut file_pkgs,
                &mut file_fns,
                &mut file_eps,
            ),
            Lang::JavaScript | Lang::TypeScript | Lang::Tsx => analyze_js_ts(
                tree.root_node(),
                src.as_bytes(),
                &rel,
                &mut file_imports,
                &mut file_pkgs,
                &mut file_fns,
                &mut file_eps,
            ),
            Lang::Go => analyze_go(
                tree.root_node(),
                src.as_bytes(),
                &rel,
                &mut file_imports,
                &mut file_pkgs,
                &mut file_fns,
                &mut file_eps,
            ),
            Lang::Php => analyze_php(
                tree.root_node(),
                src.as_bytes(),
                &rel,
                &mut file_imports,
                &mut file_pkgs,
                &mut file_fns,
                &mut file_eps,
            ),
        }

        if !file_imports.is_empty() {
            inv.imports_by_file
                .insert(rel.clone(), file_imports.clone());
            module_edges.insert(rel.clone(), file_imports);
        }
        for p in file_pkgs {
            inv.imported_packages.insert(p);
        }
        for f in file_fns {
            fns_by_name
                .entry(f.name.clone())
                .or_default()
                .push((f.file.clone(), f.name.clone()));
            functions.insert((f.file.clone(), f.name.clone()), f);
        }
        raw_endpoints.extend(file_eps);
    }

    // Build stem lookup for cross-file module import resolution.
    let mut stem_to_files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (file, _) in functions.keys() {
        let stem = file_stem_key(file);
        let dotted = stem.replace('/', ".");
        stem_to_files.entry(dotted).or_default().push(file.clone());
        if let Some(last) = stem.rsplit('/').next() {
            stem_to_files
                .entry(last.to_string())
                .or_default()
                .push(file.clone());
        }
        stem_to_files.entry(stem).or_default().push(file.clone());
    }

    // Resolve reachable sinks per function (intra-file + up to 3 cross-file hops).
    let resolve_callees = |caller_file: &str, callee: &str| -> Vec<(String, String)> {
        let short = callee.rsplit('.').next().unwrap_or(callee).to_string();
        let mut matches = Vec::new();
        // 1. Same file first
        if functions.contains_key(&(caller_file.to_string(), short.clone())) {
            matches.push((caller_file.to_string(), short.clone()));
        }
        // 2. Files matching imports declared in caller_file
        if let Some(imps) = module_edges.get(caller_file) {
            for imp in imps {
                let norm_imp = imp.trim_start_matches("./").trim_start_matches("../");
                let candidates = [
                    norm_imp.to_string(),
                    norm_imp.replace('.', "/"),
                    norm_imp
                        .rsplit(['.', '/'])
                        .next()
                        .unwrap_or(norm_imp)
                        .to_string(),
                ];
                for cand in candidates {
                    if let Some(files) = stem_to_files.get(&cand) {
                        for tf in files {
                            let key = (tf.clone(), short.clone());
                            if functions.contains_key(&key) && !matches.contains(&key) {
                                matches.push(key);
                            }
                        }
                    }
                }
            }
        }
        // 3. Unique repo function match fallback
        if matches.is_empty()
            && let Some(keys) = fns_by_name.get(&short)
            && keys.len() == 1
        {
            matches.push(keys[0].clone());
        }
        matches
    };

    let collect_reachable_sinks = |start_file: &str,
                                   initial_calls: &[String],
                                   initial_sinks: &[SinkHit]|
     -> Vec<(Vec<String>, SinkHit)> {
        let mut results = Vec::new();
        let mut seen_sinks: BTreeSet<(String, u32, String)> = BTreeSet::new();
        for s in initial_sinks {
            if seen_sinks.insert((s.file.clone(), s.line, s.callee.clone())) {
                results.push((vec![], s.clone()));
            }
        }
        let mut queue: VecDeque<((String, String), Vec<String>, usize)> = VecDeque::new();
        let mut visited: BTreeSet<(String, String)> = BTreeSet::new();
        for c in initial_calls {
            for key in resolve_callees(start_file, c) {
                if visited.insert(key.clone()) {
                    queue.push_back((key, vec![], 1));
                }
            }
        }
        while let Some((key, mut chain, depth)) = queue.pop_front() {
            let Some(finfo) = functions.get(&key) else {
                continue;
            };
            chain.push(format!("{}:{}", finfo.file, finfo.name));
            for s in &finfo.sinks {
                if seen_sinks.insert((s.file.clone(), s.line, s.callee.clone())) {
                    results.push((chain.clone(), s.clone()));
                }
            }
            if depth < 3 {
                for next_c in &finfo.calls {
                    for next_key in resolve_callees(&finfo.file, next_c) {
                        if visited.insert(next_key.clone()) {
                            queue.push_back((next_key, chain.clone(), depth + 1));
                        }
                    }
                }
            }
        }
        results
    };

    let mut emitted_sinks: BTreeSet<(String, u32, &'static str)> = BTreeSet::new();

    for ep in raw_endpoints {
        let mut calls = ep.inline_calls.clone();
        if !ep.handler.is_empty()
            && !ep.handler.starts_with("<anon")
            && !calls.contains(&ep.handler)
        {
            calls.push(ep.handler.clone());
        }
        let reachable = collect_reachable_sinks(&ep.file, &calls, &ep.inline_sinks);
        let mut ep_sinks = Vec::new();
        for (chain, sink) in reachable {
            ep_sinks.push(sink.clone());
            if emitted_sinks.insert((sink.file.clone(), sink.line, sink.kind.rule_id())) {
                let path_desc = if chain.is_empty() {
                    format!("{} ({}:{})", ep.handler, ep.file, ep.line)
                } else {
                    format!(
                        "{}:{} -> {} -> {}:{}",
                        ep.file,
                        ep.handler,
                        chain.join(" -> "),
                        sink.file,
                        sink.line
                    )
                };
                let mut f = Finding::new(
                    "security.code_audit",
                    sink.kind.rule_id(),
                    Category::Security,
                    sink.kind.severity(),
                    format!(
                        "Reachable {} via {} {} ({})",
                        sink.kind.label(),
                        ep.method,
                        ep.path,
                        sink.callee
                    ),
                    format!("{}:{}", sink.file, sink.line),
                )
                .detail(format!("Taint path: {path_desc}"))
                .remediation(remediation_for(sink.kind))
                .fp_key(format!(
                    "{}|{}|{}",
                    sink.file,
                    sink.kind.rule_id(),
                    sink.callee
                ));
                f.finalize();
                inv.findings.push(f);
            }
        }

        let mut params = ep.params.clone();
        // Add path params `{id}` / `<id>`
        for seg in ep.path.split('/') {
            let p = seg
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .or_else(|| seg.strip_prefix('<').and_then(|s| s.strip_suffix('>')))
                .or_else(|| seg.strip_prefix(':'));
            if let Some(name) = p {
                let clean = name.rsplit(':').next().unwrap_or(name).to_string();
                if !clean.is_empty() && !params.contains(&clean) {
                    params.push(clean);
                }
            }
        }
        if let Some(finfo) = functions.get(&(ep.file.clone(), ep.handler.clone())) {
            for p in &finfo.params {
                if !matches!(
                    p.as_str(),
                    "self" | "cls" | "req" | "res" | "next" | "request" | "conn" | "w" | "r"
                ) && !params.contains(p)
                {
                    params.push(p.clone());
                }
            }
        }

        inv.endpoints.push(DiscoveredEndpoint {
            method: ep.method,
            path: ep.path,
            handler: ep.handler,
            file: ep.file,
            line: ep.line,
            guards: ep.guards,
            params,
            sinks: ep_sinks,
        });
    }

    // Any direct dangerous sink inside a non-route function that was not yet reported via a route
    for finfo in functions.values() {
        for sink in &finfo.sinks {
            if emitted_sinks.insert((sink.file.clone(), sink.line, sink.kind.rule_id())) {
                let mut f = Finding::new(
                    "security.code_audit",
                    sink.kind.rule_id(),
                    Category::Security,
                    sink.kind.severity(),
                    format!(
                        "Potential {} in `{}` ({})",
                        sink.kind.label(),
                        finfo.name,
                        sink.callee
                    ),
                    format!("{}:{}", sink.file, sink.line),
                )
                .detail(format!(
                    "Sink call `{}` inside `{}` in `{}`.",
                    sink.callee, finfo.name, finfo.file
                ))
                .remediation(remediation_for(sink.kind))
                .fp_key(format!(
                    "{}|{}|{}",
                    sink.file,
                    sink.kind.rule_id(),
                    sink.callee
                ));
                f.finalize();
                inv.findings.push(f);
            }
        }
    }

    // Detect auth middleware inconsistencies (`security.auth.missing_guard`) across endpoints.
    detect_missing_guards(&inv.endpoints, &mut inv.findings);
    inv
}

fn remediation_for(k: SinkKind) -> &'static str {
    match k {
        SinkKind::SqlInjection => {
            "Use parameterized queries / prepared statements instead of formatting or concatenating SQL."
        }
        SinkKind::CommandExec => {
            "Avoid shell invocation; pass static command arrays directly without shell=True or sh -c."
        }
        SinkKind::Ssrf => {
            "Validate outbound URLs against an explicit host/scheme allowlist and block loopback/metadata IPs."
        }
        SinkKind::PathTraversal => {
            "Canonicalize and constrain resolved file paths under an allowed base directory."
        }
        SinkKind::ServerSideTemplate => {
            "Render static template files with auto-escaping instead of compiling user strings as templates."
        }
    }
}

fn file_stem_key(rel: &str) -> String {
    let no_ext = rel.rsplit_once('.').map(|(a, _)| a).unwrap_or(rel);
    no_ext
        .strip_suffix("/__init__")
        .or_else(|| no_ext.strip_suffix("/index"))
        .unwrap_or(no_ext)
        .to_string()
}

fn is_public_utility_route(path: &str) -> bool {
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

fn is_sensitive_or_mutating_endpoint(ep: &DiscoveredEndpoint) -> bool {
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

fn detect_missing_guards(endpoints: &[DiscoveredEndpoint], findings: &mut Vec<Finding>) {
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

fn node_text<'a>(n: Node<'_>, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
}

fn walk_nodes<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>) -> bool) {
    if !visit(node) {
        return;
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        walk_nodes(ch, visit);
    }
}

fn unquote(raw: &str) -> String {
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

fn looks_like_guard_name(s: &str) -> bool {
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

fn is_static_string_node(n: Node<'_>, _src: &[u8]) -> bool {
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

fn is_dynamic_expr(n: Node<'_>, src: &[u8], dynamic_vars: &BTreeSet<String>) -> bool {
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

fn classify_sink(
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

// ========================================================================= Python

fn python_root_pkg(name: &str) -> String {
    name.trim()
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn analyze_python(
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

fn parse_py_route_decorator(txt: &str) -> Option<(Vec<String>, String)> {
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

fn inspect_python_decorated(
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

fn inspect_python_fn(node: Node<'_>, src: &[u8], rel: &str) -> Option<FunctionInfo> {
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

// ========================================================================= JS / TS

fn js_pkg_name(raw_spec: &str) -> Option<String> {
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

fn analyze_js_ts(
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

fn next_app_route_path(rel: &str) -> String {
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

fn inspect_js_fn(
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

// ========================================================================= Go

fn analyze_go(
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

fn inspect_go_fn(
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

// ========================================================================= PHP

fn analyze_php(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cross_file_python_sqli_missing_auth_guard_and_clean_parameterized_no_fp() {
        let dir = std::env::temp_dir().join(format!(
            "rh-codeaudit-py-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("app")).unwrap();

        std::fs::write(
            dir.join("app/db.py"),
            r#"import sqlite3

def find_user_unsafe(conn, user_q):
    query = f"SELECT * FROM users WHERE name = '{user_q}'"
    return conn.execute(query).fetchall()

def find_user_safe(conn, user_q):
    return conn.execute("SELECT * FROM users WHERE name = ?", (user_q,)).fetchall()
"#,
        )
        .unwrap();

        std::fs::write(
            dir.join("app/routes.py"),
            r#"from flask import request
import requests
from app.db import find_user_unsafe, find_user_safe

@app.get("/api/orders")
@login_required
def list_orders(conn):
    return find_user_safe(conn, request.args.get("q"))

@app.post("/api/orders")
@login_required
def create_order(conn):
    return find_user_safe(conn, request.json.get("item"))

@app.get("/api/users/search")
def search_users(conn):
    return find_user_unsafe(conn, request.args.get("username"))

@app.delete("/api/admin/purge")
def purge_all(conn):
    return {"ok": True}
"#,
        )
        .unwrap();

        let inv = audit_tree(&dir);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            inv.findings
                .iter()
                .any(|f| f.rule == "security.taint.sql_injection" && f.location.starts_with("app/")),
            "expected cross-file SQLi finding: {:?}",
            inv.findings
        );
        assert!(
            inv.findings.iter().any(
                |f| f.rule == "security.auth.missing_guard" && f.location.contains("routes.py")
            ),
            "expected missing auth guard finding on /api/admin/purge: {:?}",
            inv.findings
        );
        // Parameterized helper should not trigger SQLi on find_user_safe
        assert!(
            !inv.findings
                .iter()
                .any(|f| f.rule == "security.taint.sql_injection"
                    && f.detail.contains("find_user_safe")),
            "parameterized query must not false-positive: {:?}",
            inv.findings
        );
        assert!(
            inv.imported_packages.contains("requests"),
            "{:?}",
            inv.imported_packages
        );
        assert!(
            inv.imported_packages.contains("flask"),
            "{:?}",
            inv.imported_packages
        );
        assert!(
            inv.endpoints
                .iter()
                .any(|e| e.path == "/api/admin/purge" && e.guards.is_empty()),
            "{:?}",
            inv.endpoints
        );
    }

    #[test]
    fn detects_js_express_missing_guard_and_go_cmd_injection() {
        let dir = std::env::temp_dir().join(format!(
            "rh-codeaudit-jsgo-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("src")).unwrap();

        std::fs::write(
            dir.join("src/server.ts"),
            r#"import express from "express";
const app = express();
app.get("/api/items", requireAuth, listItems);
app.post("/api/items", requireAuth, createItem);
app.delete("/api/admin/reset", (req, res) => res.json({ ok: true }));
"#,
        )
        .unwrap();

        std::fs::write(
            dir.join("src/ping.go"),
            r#"package main
import (
    "net/http"
    "os/exec"
)
func pingHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    exec.Command("sh", "-c", "ping -c 1 " + host).Run()
}
"#,
        )
        .unwrap();

        let inv = audit_tree(&dir);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            inv.findings
                .iter()
                .any(|f| f.rule == "security.auth.missing_guard"),
            "expected missing guard on /api/admin/reset: {:?}",
            inv.findings
        );
        assert!(
            inv.findings
                .iter()
                .any(|f| f.rule == "security.taint.command_exec"),
            "expected Go command injection finding: {:?}",
            inv.findings
        );
        assert!(
            inv.imported_packages.contains("express"),
            "{:?}",
            inv.imported_packages
        );
    }
}
