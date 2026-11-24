//! Snapshot fact detection and parsing utilities.

use crate::facts::Facts;
use crate::model::{CheckOutput, CheckStatus, Finding};
use crate::snapshot::Snapshot;
use regex::Regex;
use serde_norway::Value;
use std::collections::{BTreeSet, HashSet};
use std::fs;

pub(crate) const MAX_READ: u64 = 2 * 1024 * 1024;

pub(crate) fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}
pub(crate) fn dir(p: &str) -> &str {
    p.rsplit_once('/').map_or("", |x| x.0)
}
pub(crate) fn normalize(p: &str) -> String {
    let mut o: Vec<&str> = vec![];
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                o.pop();
            }
            c => o.push(c),
        }
    }
    o.join("/")
}

/// Reads a snapshot file; denied (placeholder) and oversized files are never read. The Err says
/// why, so a check can report the file it could not analyse instead of silently passing it.
pub(crate) fn read_checked(snap: &Snapshot, rel: &str) -> Result<String, String> {
    if snap.denied.iter().any(|d| d.path == rel) {
        return Err("secret-bearing file, deliberately not read".into());
    }
    let p = snap.root.join(rel);
    let len = fs::metadata(&p)
        .map_err(|e| format!("cannot stat: {e}"))?
        .len();
    if len > MAX_READ {
        return Err(format!(
            "{len} bytes exceeds the {MAX_READ}-byte read limit"
        ));
    }
    let bytes = fs::read(&p).map_err(|e| format!("cannot read: {e}"))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(crate) fn read(snap: &Snapshot, rel: &str) -> Option<String> {
    read_checked(snap, rel).ok()
}

/// Files a check could not read or parse: "<file>: <why>". A check with any of these ends
/// Partial (naming them), never Passed, because the unread file may hold the finding.
#[derive(Default)]
pub(crate) struct Skips(pub(crate) Vec<String>);

impl Skips {
    pub(crate) fn add(&mut self, file: &str, why: impl std::fmt::Display) {
        self.0.push(format!("{file}: {why}"));
    }

    pub(crate) fn finish(self, findings: Vec<Finding>) -> CheckOutput {
        if self.0.is_empty() {
            return CheckOutput::findings(findings);
        }
        let n = self.0.len();
        let shown = self
            .0
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
        let more = if n > 5 {
            format!("; ... {} more", n - 5)
        } else {
            String::new()
        };
        CheckOutput {
            status: Some(CheckStatus::Partial(format!(
                "{n} file(s) could not be fully analysed: {shown}{more}"
            ))),
            findings,
        }
    }
}

// ---------- dependency parsing ----------

pub(crate) struct Dep {
    pub(crate) name: String,
    pub(crate) pinned: bool,
    pub(crate) git: bool,
    pub(crate) line: usize,
}

pub(crate) fn req_deps(text: &str) -> Vec<Dep> {
    let mut v = vec![];
    for (i, l) in text.lines().enumerate() {
        let l = l.split(" #").next().unwrap_or("").trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with('-') {
            continue;
        }
        if l.contains("git+") {
            let url = l.split("git+").nth(1).unwrap_or("");
            let seg = url.rsplit('/').next().unwrap_or("");
            let name = l
                .split(" @ ")
                .next()
                .filter(|_| l.contains(" @ "))
                .unwrap_or(seg)
                .trim()
                .to_string();
            v.push(Dep {
                name,
                pinned: seg.contains('@'),
                git: true,
                line: i + 1,
            });
            continue;
        }
        let name: String = l
            .chars()
            .take_while(|c| c.is_alphanumeric() || "_.-".contains(*c))
            .collect();
        v.push(Dep {
            name,
            pinned: l.contains("=="),
            git: false,
            line: i + 1,
        });
    }
    v
}

pub(crate) fn pkg_deps(text: &str) -> Result<Vec<Dep>, String> {
    let j = serde_json::from_str::<serde_json::Value>(text)
        .map_err(|e| format!("invalid JSON: {e}"))?;
    let exact = Regex::new(r"^=?v?\d+\.\d+\.\d+([-+][\w.+-]*)?$").unwrap();
    let mut v = vec![];
    for sect in ["dependencies", "devDependencies", "optionalDependencies"] {
        for (k, s) in j
            .get(sect)
            .and_then(|d| d.as_object())
            .into_iter()
            .flatten()
        {
            let s = s.as_str().unwrap_or("");
            let git = s.starts_with("git") || s.starts_with("github:") || s.contains("github.com");
            let pinned = if git {
                s.contains('#')
            } else {
                exact.is_match(s)
                    || ["workspace:", "file:", "link:"]
                        .iter()
                        .any(|p| s.starts_with(p))
            };
            v.push(Dep {
                name: k.clone(),
                pinned,
                git,
                line: 0,
            });
        }
    }
    Ok(v)
}

pub(crate) fn manifest_deps(snap: &Snapshot, rel: &str) -> Result<Vec<Dep>, String> {
    let t = read_checked(snap, rel)?;
    if base(rel) == "package.json" {
        pkg_deps(&t)
    } else {
        Ok(req_deps(&t))
    }
}

// ---------- facts ----------

pub(crate) const LOCKFILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "cargo.lock",
    "go.sum",
    "composer.lock",
    "gemfile.lock",
];
pub(crate) const TEST_DIRS: &[&str] = &["tests", "test", "__tests__", "spec"];
pub(crate) const SRC_EXT: &[&str] = &["py", "js", "ts", "mjs", "cjs", "go", "java"];

pub(crate) fn has_yaml_content(chunk: &str) -> bool {
    chunk
        .lines()
        .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
}

/// YAML documents of `text` split on `---` / `...` markers, each with its 1-based start line.
/// Blank and comment-only chunks are not documents.
pub(crate) fn split_yaml_docs(text: &str) -> Vec<(usize, String)> {
    let mut docs: Vec<(usize, String)> = vec![];
    let (mut cur, mut start) = (String::new(), 1usize);
    for (i, l) in text.lines().enumerate() {
        let marker = |m: &str| {
            l == m
                || l.strip_prefix(m)
                    .is_some_and(|r| r.starts_with([' ', '\t']))
        };
        if marker("---") || marker("...") {
            if has_yaml_content(&cur) {
                docs.push((start, std::mem::take(&mut cur)));
            }
            cur.clear();
            start = i + 2;
            // `--- key: v` keeps its content as the first line of the next document
            let rest = l[3..].trim();
            if marker("---") && !rest.is_empty() && !rest.starts_with('#') {
                cur.push_str(rest);
                cur.push('\n');
                start = i + 1;
            }
            continue;
        }
        cur.push_str(l);
        cur.push('\n');
    }
    if has_yaml_content(&cur) {
        docs.push((start, cur));
    }
    docs
}

/// Every parseable document of a multi-document YAML file, plus one error line per document that
/// does not parse ("document N (line L): why"). A bad document never hides the ones after it.
pub(crate) fn k8s_docs_checked(text: &str) -> (Vec<Value>, Vec<String>) {
    let (mut out, mut errs) = (vec![], vec![]);
    for (n, (line, chunk)) in split_yaml_docs(text).into_iter().enumerate() {
        match serde_norway::from_str::<Value>(&chunk) {
            Ok(mut v) => {
                v.apply_merge().ok();
                out.push(v)
            }
            Err(e) => errs.push(format!("document {} (line {line}): {e}", n + 1)),
        }
    }
    (out, errs)
}

pub(crate) fn k8s_docs(text: &str) -> Vec<Value> {
    k8s_docs_checked(text).0
}

pub fn detect_facts(snap: &Snapshot) -> Facts {
    let denied: HashSet<&str> = snap.denied.iter().map(|d| d.path.as_str()).collect();
    let compose_re = Regex::new(r"^(docker-compose|compose)[^/]*\.ya?ml$").unwrap();
    let mut f = Facts::default();
    let (mut yamls, mut sources) = (vec![], vec![]);
    let mut wg_candidates: Vec<String> = vec![];
    for rel in snap
        .files
        .iter()
        .map(|s| s.as_str())
        .filter(|r| !denied.contains(r))
    {
        let b = base(rel).to_lowercase();
        let own = rel.to_string();
        let is_yaml = b.ends_with(".yaml") || b.ends_with(".yml");
        if b.starts_with("dockerfile") || b.ends_with(".dockerfile") {
            f.dockerfiles.push(own.clone());
        }
        if b.ends_with(".conf") || b.ends_with(".wgconfig") {
            wg_candidates.push(own.clone());
        }
        if b.starts_with("jenkinsfile")
            || (rel.contains(".github/workflows/") && is_yaml)
            || b == ".gitlab-ci.yml"
        {
            f.ci_files.push(own.clone());
        } else if compose_re.is_match(&b) {
            f.compose_files.push(own.clone());
        } else if is_yaml {
            yamls.push(own.clone());
        }
        if b.starts_with("requirements") && b.ends_with(".txt") {
            f.requirement_files.push(own.clone());
        }
        if b == "pyproject.toml" {
            f.pyprojects.push(own.clone());
        }
        if b == "package.json" {
            f.package_jsons.push(own.clone());
        }
        if LOCKFILES.contains(&b.as_str()) {
            f.lockfiles.push(own.clone());
        }
        if !rel.contains('/') && b.starts_with("readme") {
            f.has_readme = true;
        }
        let in_test_dir = rel.split('/').rev().skip(1).any(|c| TEST_DIRS.contains(&c));
        if in_test_dir
            || (b.starts_with("test_") && b.ends_with(".py"))
            || b.ends_with("_test.py")
            || b.ends_with("_test.go")
            || b.contains(".spec.")
            || b.contains(".test.")
        {
            f.has_tests = true;
        }
        if b.rsplit_once('.')
            .is_some_and(|(_, e)| SRC_EXT.contains(&e))
        {
            sources.push(own);
        }
    }
    for y in yamls {
        let Some(t) = read(snap, &y) else { continue };
        if k8s_docs(&t).iter().any(|d| {
            d.get("apiVersion").is_some() && d.get("kind").and_then(Value::as_str).is_some()
        }) {
            f.k8s_files.push(y);
        }
    }
    for c in wg_candidates {
        let Some(t) = read(snap, &c) else { continue };
        if super::wireguard::is_wireguard(&t) {
            f.wg_files.push(c);
        }
    }
    for l in [
        &mut f.dockerfiles,
        &mut f.compose_files,
        &mut f.k8s_files,
        &mut f.ci_files,
        &mut f.wg_files,
    ] {
        l.sort();
    }

    // dependencies, framework
    let mut names: BTreeSet<String> = BTreeSet::new();
    let tok = Regex::new(r"[a-z0-9_@/.\-]+").unwrap();
    for rel in f.requirement_files.iter().chain(&f.package_jsons) {
        let deps = manifest_deps(snap, rel).unwrap_or_default(); // deps_check reports the failure
        f.total_deps += deps.len();
        f.unpinned_deps += deps.iter().filter(|d| !d.pinned).count();
        names.extend(deps.into_iter().map(|d| d.name.to_lowercase()));
    }
    for rel in f.pyprojects.iter().chain(&f.package_jsons) {
        if let Some(t) = read(snap, rel) {
            names.extend(
                tok.find_iter(&t.to_lowercase())
                    .map(|m| m.as_str().to_string()),
            );
        }
    }
    f.web_framework = [
        ("fastapi", "fastapi"),
        ("flask", "flask"),
        ("django", "django"),
        ("express", "express"),
        ("@nestjs/core", "nestjs"),
        ("@nestjs/common", "nestjs"),
    ]
    .iter()
    .find(|(k, _)| names.contains(*k))
    .map(|(_, n)| n.to_string());
    f.has_otel = names.iter().any(|n| n.contains("opentelemetry"));

    let health = Regex::new(r"(?i)/(healthz?|ready)\b").unwrap();
    for rel in &sources {
        if f.has_health_route && f.has_otel {
            break;
        }
        let Some(t) = read(snap, rel) else { continue };
        f.has_health_route |= health.is_match(&t);
        f.has_otel |= t.to_lowercase().contains("opentelemetry");
    }
    f
}
