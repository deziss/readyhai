use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding};

use super::ast::file_stem_key;
use super::classify::detect_missing_guards;
use super::go::analyze_go;
use super::javascript::analyze_js_ts;
use super::php::analyze_php;
use super::python::analyze_python;
use super::types::{
    CodeInventory, DiscoveredEndpoint, FunctionInfo, Lang, MAX_FILE_BYTES, MAX_FILES, RawEndpoint,
    SinkHit, remediation_for,
};

pub fn should_skip_dir(name: &str) -> bool {
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

pub fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn code_audit_check(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
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
    let mut notes = Vec::new();
    if !inv.unreadable.is_empty() {
        notes.push(format!(
            "skipped {} oversized/unreadable file(s): {}",
            inv.unreadable.len(),
            inv.unreadable
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !inv.grammar_skipped.is_empty() {
        let mut langs: Vec<&str> = inv
            .grammar_skipped
            .iter()
            .filter_map(|s| s.split(':').next())
            .collect();
        langs.sort_unstable();
        langs.dedup();
        notes.push(format!(
            "skipped {} file(s): no grammar compiled in for {} (rebuild with the matching \
             `grammar-*` feature)",
            inv.grammar_skipped.len(),
            langs.join(", ")
        ));
    }
    if notes.is_empty() {
        Ok(CheckOutput::findings(findings))
    } else {
        Ok(CheckOutput {
            status: Some(CheckStatus::Partial(format!(
                "code audit {}",
                notes.join("; ")
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
        };
        let Ok(src) = fs::read_to_string(path) else {
            inv.unreadable.push(rel);
            continue;
        };
        if !lang.grammar_available() {
            inv.grammar_skipped.push(format!("{}:{rel}", lang.as_str()));
            continue;
        }
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
