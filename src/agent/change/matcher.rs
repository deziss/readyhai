use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use regex::Regex;

use super::git::read_repo_file;
use super::models::{MAX_FILES_PER_OP, MAX_SCANNED};
use crate::agent::discover::SpecDoc;
use crate::agent::types::ChangedOperation;
use crate::llm::untrusted::clean;
use crate::qa::suite::{extract_routes, is_test_path, route_segments};

const SOURCE_EXT: [&str; 14] = [
    "py", "js", "mjs", "cjs", "jsx", "ts", "tsx", "java", "kt", "go", "rb", "php", "rs", "cs",
];

pub(crate) fn is_source(file: &str) -> bool {
    let ext = file.rsplit('.').next().unwrap_or("");
    SOURCE_EXT.contains(&ext)
        && ![
            "node_modules/",
            ".venv/",
            "venv/",
            "vendor/",
            "dist/",
            "/build/",
            "site-packages/",
        ]
        .iter()
        .any(|d| file.contains(d) || file.starts_with(d.trim_start_matches('/')))
}

/// Words that name no resource: a file called this says nothing about which operation it serves.
const GENERIC_STEMS: &[&str] = &[
    "index",
    "main",
    "app",
    "application",
    "utils",
    "util",
    "common",
    "base",
    "config",
    "settings",
    "models",
    "model",
    "db",
    "database",
    "server",
    "init",
    "__init__",
    "helpers",
    "helper",
    "middleware",
    "types",
    "constants",
    "lib",
    "core",
    "schema",
    "schemas",
    // folders that group many resources
    "api",
    "src",
    "services",
    "service",
    "controllers",
    "internal",
    "pkg",
    "cmd",
    "v1",
    "v2",
    "v3",
];

/// Suffixes that say what kind of file it is, not what it is about (longest variants first).
const STEM_NOISE: [&str; 20] = [
    "_controller",
    "controller",
    "_routes",
    "routes",
    "_router",
    "router",
    "_handlers",
    "handlers",
    "_handler",
    "handler",
    "_views",
    "views",
    "_view",
    "_api",
    "_service",
    "_resources",
    "_resource",
    "_endpoints",
    "endpoints",
    "_endpoint",
];

fn singular(s: &str) -> String {
    s.strip_suffix('s')
        .filter(|r| r.len() > 2)
        .unwrap_or(s)
        .to_string()
}

/// The resource a file or folder name is about, or None when it names none (`utils`, `routes`).
fn resource_of(raw: &str) -> Option<String> {
    let mut c = raw.to_lowercase();
    for noise in STEM_NOISE {
        if let Some(rest) = c.strip_suffix(noise)
            && !rest.is_empty()
        {
            c = rest.to_string();
            break;
        }
    }
    let kind_only = STEM_NOISE.iter().any(|n| n.trim_start_matches('_') == c);
    (!c.is_empty() && !kind_only && !GENERIC_STEMS.contains(&c.as_str())).then(|| singular(&c))
}

/// Resource a changed file is about: its own name (`orders.py`, `OrdersController.java`,
/// `routes/orders_router.ts` are all `order`), else its folder's for index/main style names
/// (`orders/index.js`).
pub(crate) fn resource_names(file: &str) -> Vec<String> {
    let mut segs = file.rsplit('/');
    let name = segs.next().unwrap_or("");
    if let Some(r) = resource_of(name.split('.').next().unwrap_or("")) {
        return vec![r];
    }
    segs.next().and_then(resource_of).into_iter().collect()
}

pub(crate) struct OpInfo {
    pub(crate) label: String,
    pub(crate) method: String,
    pub(crate) norm: Vec<String>,
    /// `norm` behind the spec's server path (`/api/v1`).
    pub(crate) full: Vec<String>,
    pub(crate) operation_id: Option<String>,
    pub(crate) resources: BTreeSet<String>,
}

pub(crate) fn op_infos(spec: &SpecDoc) -> Vec<OpInfo> {
    let base = route_segments(&spec.base_path);
    spec.ops
        .iter()
        .map(|o| {
            let norm = route_segments(&o.path);
            let mut full = base.clone();
            full.extend(norm.iter().cloned());
            OpInfo {
                label: o.component(),
                method: o.method.to_ascii_uppercase(),
                resources: norm
                    .iter()
                    .filter(|s| *s != "{}")
                    .map(|s| singular(s))
                    .collect(),
                norm,
                full,
                operation_id: o.operation_id.clone().filter(|id| id.len() >= 4),
            }
        })
        .collect()
}

fn has_literal(v: &[String]) -> bool {
    v.iter().any(|s| s != "{}")
}

/// Does a route's path (already split) denote the operation's path? Equal templates do. A route
/// declared on a router mounted under a prefix (`@router.get("/{id}")` under `/orders`) is the
/// tail of the spec path, and a route that carries a prefix the spec leaves out is longer than
/// it: either is accepted when the shorter side names something literal.
fn path_matches(rs: &[String], op: &OpInfo) -> bool {
    if rs == op.norm.as_slice() || rs == op.full.as_slice() {
        return true;
    }
    [&op.norm, &op.full].into_iter().any(|t| {
        (!rs.is_empty() && has_literal(rs) && t.len() > rs.len() && t.ends_with(rs))
            || (!t.is_empty() && has_literal(t) && rs.len() > t.len() && rs.ends_with(t))
    })
}

/// `prefix="/orders"` / `url_prefix="/orders"` of a Python router or blueprint.
fn python_prefix(text: &str) -> Option<Vec<String>> {
    static RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?:url_prefix|prefix)\s*=\s*["']([^"']+)["']"#).expect("static regex")
    });
    RE.captures(text).map(|c| route_segments(&c[1]))
}

#[derive(Default)]
struct Hits {
    by_op: BTreeMap<usize, ChangedOperation>,
}

impl Hits {
    fn add(&mut self, idx: usize, label: &str, via: &str, file: &str, detail: String) {
        let e = self.by_op.entry(idx).or_insert_with(|| ChangedOperation {
            operation: label.to_string(),
            via: via.to_string(),
            files: vec![],
            detail: detail.clone(),
        });
        if via == "route" && e.via != "route" {
            e.via = "route".into();
            e.detail = detail;
        }
        if e.files.len() < MAX_FILES_PER_OP && !e.files.iter().any(|f| f == file) {
            e.files.push(file.to_string());
        }
    }
}

/// Map the changed files onto the spec's operations. Returns the operations (in spec order) and
/// the files that led to none.
pub(crate) fn map_files(
    root: &Path,
    files: &[String],
    ops: &[OpInfo],
    notes: &mut Vec<String>,
) -> (Vec<ChangedOperation>, Vec<String>) {
    let mut hits = Hits::default();
    let mut unmapped = vec![];
    let mut scanned = 0usize;
    let mut skipped_scan = 0usize;
    for file in files {
        if !is_source(file) || is_test_path(file) {
            unmapped.push(file.clone());
            continue;
        }
        if scanned >= MAX_SCANNED {
            skipped_scan += 1;
            unmapped.push(file.clone());
            continue;
        }
        scanned += 1;
        let text = read_repo_file(root, file);
        let mut touched = false;
        if let Some(t) = &text {
            let prefix = python_prefix(t).filter(|_| file.ends_with(".py"));
            for r in extract_routes(file, t) {
                let plain = route_segments(&r.path);
                let mut mounted = plain.clone();
                if let Some(p) = &prefix
                    && !plain.starts_with(p)
                {
                    mounted = p.iter().chain(plain.iter()).cloned().collect();
                }
                for (i, op) in ops.iter().enumerate() {
                    let method_ok = r.method == "ANY" || r.method == op.method;
                    if method_ok && (path_matches(&plain, op) || path_matches(&mounted, op)) {
                        touched = true;
                        hits.add(
                            i,
                            &op.label,
                            "route",
                            file,
                            format!(
                                "route {} {} in {}:{}",
                                clean(&r.method, 12),
                                clean(&r.path, 120),
                                clean(file, 160),
                                r.line
                            ),
                        );
                    }
                }
            }
        }
        if !touched {
            // the routes could not be read or match no operation: the file still changed
            let names = resource_names(file);
            for (i, op) in ops.iter().enumerate() {
                let by_id = match (&op.operation_id, &text) {
                    (Some(id), Some(t)) => Regex::new(&format!(r"\b{}\b", regex::escape(id)))
                        .map(|re| re.is_match(t))
                        .unwrap_or(false),
                    _ => false,
                };
                let by_name = names.iter().any(|n| op.resources.contains(n));
                if by_id || by_name {
                    touched = true;
                    hits.add(
                        i,
                        &op.label,
                        "file",
                        file,
                        format!(
                            "file changed, routes unknown: {} ({})",
                            clean(file, 160),
                            if by_id {
                                format!(
                                    "operationId {} appears in it",
                                    clean(op.operation_id.as_deref().unwrap_or(""), 60)
                                )
                            } else {
                                "its name is the resource of the operation".to_string()
                            }
                        ),
                    );
                }
            }
        }
        if !touched {
            unmapped.push(file.clone());
        }
    }
    if skipped_scan > 0 {
        notes.push(format!(
            "{skipped_scan} changed source file(s) beyond the first {MAX_SCANNED} were not read for routes"
        ));
    }
    (hits.by_op.into_values().collect(), unmapped)
}
