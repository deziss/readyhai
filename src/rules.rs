//! Native readiness rules (owned by the rules agent).
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::facts::Facts;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};
use crate::snapshot::Snapshot;
use regex::Regex;
use serde_norway::Value;
use std::collections::{BTreeSet, HashSet};
use std::fs;

const MAX_READ: u64 = 2 * 1024 * 1024;

fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}
fn dir(p: &str) -> &str {
    p.rsplit_once('/').map_or("", |x| x.0)
}
fn normalize(p: &str) -> String {
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
fn read_checked(snap: &Snapshot, rel: &str) -> Result<String, String> {
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

fn read(snap: &Snapshot, rel: &str) -> Option<String> {
    read_checked(snap, rel).ok()
}

/// Files a check could not read or parse: "<file>: <why>". A check with any of these ends
/// Partial (naming them), never Passed, because the unread file may hold the finding.
#[derive(Default)]
struct Skips(Vec<String>);

impl Skips {
    fn add(&mut self, file: &str, why: impl std::fmt::Display) {
        self.0.push(format!("{file}: {why}"));
    }

    fn finish(self, findings: Vec<Finding>) -> CheckOutput {
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

struct Dep {
    name: String,
    pinned: bool,
    git: bool,
    line: usize,
}

fn req_deps(text: &str) -> Vec<Dep> {
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

fn pkg_deps(text: &str) -> Result<Vec<Dep>, String> {
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

fn manifest_deps(snap: &Snapshot, rel: &str) -> Result<Vec<Dep>, String> {
    let t = read_checked(snap, rel)?;
    if base(rel) == "package.json" {
        pkg_deps(&t)
    } else {
        Ok(req_deps(&t))
    }
}

// ---------- facts ----------

const LOCKFILES: &[&str] = &[
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
const TEST_DIRS: &[&str] = &["tests", "test", "__tests__", "spec"];
const SRC_EXT: &[&str] = &["py", "js", "ts", "mjs", "cjs", "go", "java"];

fn has_yaml_content(chunk: &str) -> bool {
    chunk
        .lines()
        .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
}

/// YAML documents of `text` split on `---` / `...` markers, each with its 1-based start line.
/// Blank and comment-only chunks are not documents.
fn split_yaml_docs(text: &str) -> Vec<(usize, String)> {
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
fn k8s_docs_checked(text: &str) -> (Vec<Value>, Vec<String>) {
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

fn k8s_docs(text: &str) -> Vec<Value> {
    k8s_docs_checked(text).0
}

pub fn detect_facts(snap: &Snapshot) -> Facts {
    let denied: HashSet<&str> = snap.denied.iter().map(|d| d.path.as_str()).collect();
    let compose_re = Regex::new(r"^(docker-compose|compose)[^/]*\.ya?ml$").unwrap();
    let mut f = Facts::default();
    let (mut yamls, mut sources) = (vec![], vec![]);
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
    for l in [
        &mut f.dockerfiles,
        &mut f.compose_files,
        &mut f.k8s_files,
        &mut f.ci_files,
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

// ---------- Dockerfile parsing ----------

struct Stage {
    line: usize,
    image: String,
    alias: Option<String>,
    instrs: Vec<(usize, String, String)>,
}

fn parse_stages(text: &str) -> Vec<Stage> {
    let mut logical: Vec<(usize, String)> = vec![];
    let (mut cur, mut start) = (String::new(), 0);
    for (i, l) in text.lines().enumerate() {
        let t = l.trim();
        if cur.is_empty() && (t.is_empty() || t.starts_with('#'))
            || !cur.is_empty() && t.starts_with('#')
        {
            continue;
        }
        if cur.is_empty() {
            start = i + 1;
        }
        if let Some(s) = t.strip_suffix('\\') {
            cur.push_str(s);
            cur.push(' ');
        } else {
            cur.push_str(t);
            logical.push((start, std::mem::take(&mut cur)));
        }
    }
    let mut stages: Vec<Stage> = vec![];
    for (line, ins) in logical {
        let (kw, args) = ins.split_once(char::is_whitespace).unwrap_or((&ins, ""));
        let kw = kw.to_uppercase();
        if kw == "FROM" {
            let toks: Vec<&str> = args
                .split_whitespace()
                .filter(|t| !t.starts_with("--"))
                .collect();
            let alias = toks
                .iter()
                .position(|t| t.eq_ignore_ascii_case("as"))
                .and_then(|i| toks.get(i + 1))
                .map(|s| s.to_lowercase());
            stages.push(Stage {
                line,
                image: toks.first().unwrap_or(&"").to_string(),
                alias,
                instrs: vec![],
            });
        } else if let Some(s) = stages.last_mut() {
            s.instrs.push((line, kw, args.trim().to_string()));
        }
    }
    stages
}

fn image_untagged(img: &str) -> bool {
    if img.contains('@') {
        return false;
    }
    match img.rsplit('/').next().unwrap_or(img).split_once(':') {
        None => true,
        Some((_, t)) => t == "latest",
    }
}

// ---------- YAML helpers ----------

fn path<'a>(v: &'a Value, p: &[&str]) -> Option<&'a Value> {
    p.iter().try_fold(v, |v, k| v.get(*k))
}
fn truthy(v: Option<&Value>) -> bool {
    v.is_some_and(|v| {
        v.as_bool()
            .unwrap_or_else(|| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true")))
    })
}
fn non_empty_map(v: Option<&Value>) -> bool {
    v.and_then(Value::as_mapping).is_some_and(|m| !m.is_empty())
}
fn str_of(v: Option<&Value>) -> &str {
    v.and_then(Value::as_str).unwrap_or("?")
}

// ---------- check plumbing ----------

type CheckFn = fn(&Ctx, &Snapshot) -> CheckOutput;

fn repo_check(id: &str, title: &str, f: CheckFn) -> Check {
    Check::new(id, title, &[TargetKind::Repo], Profile::Quick, move |ctx| {
        Ok(match &ctx.snapshot {
            Some(s) => f(ctx, s),
            None => CheckOutput::status(CheckStatus::NotApplicable("no snapshot".into())),
        })
    })
}

fn na(why: &str) -> CheckOutput {
    CheckOutput::status(CheckStatus::NotApplicable(why.into()))
}

pub fn checks() -> Vec<Check> {
    vec![
        repo_check(
            "readiness.dockerfile",
            "Dockerfile hardening",
            dockerfile_check,
        ),
        repo_check(
            "readiness.deps",
            "Dependency pinning and lockfiles",
            deps_check,
        ),
        repo_check(
            "readiness.compose",
            "Docker Compose hardening",
            compose_check,
        ),
        repo_check("readiness.k8s", "Kubernetes manifest hardening", k8s_check),
        repo_check("readiness.ci", "CI pipeline security stages", ci_check),
        repo_check("readiness.repo", "Repository hygiene", repo_check_fn),
    ]
}

// ---------- readiness.dockerfile ----------

fn has_healthcheck(stage: &Stage) -> bool {
    stage
        .instrs
        .iter()
        .any(|i| i.1 == "HEALTHCHECK" && !i.2.to_uppercase().starts_with("NONE"))
}

/// Heuristic for one-shot tool/runner images that need no HEALTHCHECK: the Dockerfile lives under a
/// `runners/`, `tools/` or `scripts/` directory, or no stage EXPOSEs a port and the final
/// ENTRYPOINT/CMD runs a script file (.sh/.py/.js/.ts/.rb/.pl) that is expected to exit.
fn is_oneshot_image(df: &str, stages: &[Stage]) -> bool {
    if dir(df)
        .split('/')
        .any(|c| matches!(c, "runners" | "tools" | "scripts"))
    {
        return true;
    }
    let Some(last) = stages.last() else {
        return false;
    };
    if stages
        .iter()
        .any(|s| s.instrs.iter().any(|i| i.1 == "EXPOSE"))
    {
        return false;
    }
    last.instrs
        .iter()
        .rev()
        .find(|i| i.1 == "ENTRYPOINT" || i.1 == "CMD")
        .is_some_and(|i| {
            [".sh", ".py", ".js", ".ts", ".rb", ".pl"].iter().any(|e| {
                i.2.contains(&format!("{e}\""))
                    || i.2.contains(&format!("{e} "))
                    || i.2.ends_with(e)
            })
        })
}

fn dockerfile_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.dockerfile";
    if ctx.facts.dockerfiles.is_empty() {
        return na("no Dockerfile");
    }
    let mk = |r: &str, cat, sev, title: &str, loc: String| {
        Finding::new(C, &format!("{C}.{r}"), cat, sev, title, loc)
    };
    let mut out = vec![];
    let mut skips = Skips::default();
    for df in &ctx.facts.dockerfiles {
        let text = match read_checked(snap, df) {
            Ok(t) => t,
            Err(why) => {
                skips.add(df, why);
                continue;
            }
        };
        let stages = parse_stages(&text);
        let Some(last) = stages.last() else {
            skips.add(df, "no FROM instruction found, nothing to analyse");
            continue;
        };
        let user = last
            .instrs
            .iter()
            .rev()
            .find(|i| i.1 == "USER")
            .map(|i| i.2.split(':').next().unwrap_or("").trim().to_string());
        if user.as_deref().is_none_or(|u| u == "root" || u == "0") {
            out.push(
                mk(
                    "no_user",
                    Category::Security,
                    Severity::High,
                    "Container runs as root (no non-root USER in final stage)",
                    format!("{df}:{}", last.line),
                )
                .detail("The final stage has no USER instruction, or switches to root.")
                .remediation(
                    "Create an unprivileged user and add `USER app` before CMD/ENTRYPOINT.",
                ),
            );
        }
        if !has_healthcheck(last) && !is_oneshot_image(df, &stages) {
            out.push(
                mk("no_healthcheck", Category::Reliability, Severity::Medium, "No HEALTHCHECK in final stage", format!("{df}:{}", last.line))
                    .remediation("Add a HEALTHCHECK that uses a binary present in the image, or rely on orchestrator probes."),
            );
        }
        let mut seen: Vec<String> = vec![];
        for s in &stages {
            let img = s.image.to_lowercase();
            if !img.is_empty()
                && img != "scratch"
                && !img.contains('$')
                && !seen.contains(&img)
                && image_untagged(&s.image)
            {
                out.push(
                    mk(
                        "latest_base",
                        Category::SupplyChain,
                        Severity::Low,
                        &format!("Base image `{}` is untagged or :latest", s.image),
                        format!("{df}:{}", s.line),
                    )
                    .remediation("Pin the base image to a version tag, ideally a digest."),
                );
            }
            if let Some(a) = &s.alias {
                seen.push(a.clone());
            }
            for (line, kw, args) in &s.instrs {
                if kw == "ADD"
                    && args
                        .split_whitespace()
                        .find(|t| !t.starts_with("--"))
                        .is_some_and(|t| t.starts_with("http://") || t.starts_with("https://"))
                {
                    out.push(
                        mk("add_remote", Category::SupplyChain, Severity::Low, "ADD fetches a remote URL", format!("{df}:{line}"))
                            .remediation("Use curl/wget with a checksum verification step, or COPY a vendored file."),
                    );
                }
            }
        }
        let d = dir(df);
        let ignore = if d.is_empty() {
            ".dockerignore".to_string()
        } else {
            format!("{d}/.dockerignore")
        };
        if !snap.files.contains(&ignore) {
            out.push(
                mk("no_dockerignore", Category::Operability, Severity::Low, "No .dockerignore next to Dockerfile", df.clone())
                    .remediation("Add a .dockerignore (.git, .env*, node_modules, tests) to shrink context and avoid leaking secrets into layers."),
            );
        }
    }
    skips.finish(out)
}

// ---------- readiness.deps ----------

fn deps_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.deps";
    let fc = &ctx.facts;
    if fc.requirement_files.is_empty() && fc.pyprojects.is_empty() && fc.package_jsons.is_empty() {
        return na("no dependency manifests");
    }
    let mk = |r: &str, sev, title: String, loc: String| {
        Finding::new(
            C,
            &format!("{C}.{r}"),
            Category::SupplyChain,
            sev,
            title,
            loc,
        )
    };
    // Which requirements file each Dockerfile installs.
    let pip = Regex::new(r"pip3?\s+install\b.*?-r\s+(\S+)").unwrap();
    let mut installed: Vec<(String, String)> = vec![];
    for df in &fc.dockerfiles {
        for st in read(snap, df).map(|t| parse_stages(&t)).unwrap_or_default() {
            for (_, kw, args) in st.instrs.iter().filter(|i| i.1 == "RUN") {
                let _ = kw;
                for c in pip.captures_iter(args) {
                    installed.push((base(&c[1]).to_string(), df.clone()));
                }
            }
        }
    }
    let mut out = vec![];
    let mut skips = Skips::default();
    for rel in fc.requirement_files.iter().chain(&fc.package_jsons) {
        let deps = match manifest_deps(snap, rel) {
            Ok(d) => d,
            Err(why) => {
                skips.add(rel, why);
                continue;
            }
        };
        if deps.is_empty() {
            continue;
        }
        let total = deps.len();
        let unpinned: Vec<&Dep> = deps.iter().filter(|d| !d.pinned).collect();
        if !unpinned.is_empty() {
            let pinned = total - unpinned.len();
            let mut sev = if pinned * 100 < 80 * total {
                Severity::Medium
            } else {
                Severity::Low
            };
            let mut detail = format!("{pinned} of {total} pinned.");
            if base(rel) == "package.json" {
                let lock = [
                    "package-lock.json",
                    "yarn.lock",
                    "pnpm-lock.yaml",
                    "bun.lockb",
                ]
                .into_iter()
                .find(|n| {
                    fc.lockfiles
                        .iter()
                        .any(|l| dir(l) == dir(rel) && base(l) == *n)
                });
                if let Some(n) = lock {
                    sev = Severity::Low;
                    detail += &format!(" Note: ranges are locked by {n}.");
                }
            }
            if let Some((_, df)) = installed.iter().find(|(b, _)| b == base(rel)) {
                detail += &format!(" Installed by {df} (pip install -r {}).", base(rel));
            }
            let names: Vec<&str> = unpinned.iter().take(10).map(|d| d.name.as_str()).collect();
            detail += &format!(
                " Unpinned: {}{}.",
                names.join(", "),
                if unpinned.len() > 10 { ", ..." } else { "" }
            );
            out.push(
                mk(
                    "unpinned",
                    sev,
                    format!(
                        "{} of {total} dependencies unpinned in {}",
                        unpinned.len(),
                        base(rel)
                    ),
                    rel.clone(),
                )
                .detail(detail)
                .remediation(
                    "Pin exact versions (== / exact semver) and commit a lockfile or hashes.",
                ),
            );
        }
        for d in deps.iter().filter(|d| d.git && !d.pinned) {
            let loc = if d.line > 0 {
                format!("{rel}:{}", d.line)
            } else {
                rel.clone()
            };
            out.push(
                mk(
                    "git_unpinned",
                    Severity::Medium,
                    format!("Git dependency `{}` has no @ref", d.name),
                    loc,
                )
                .fp_key(format!("{rel}:{}", d.name))
                .remediation("Pin to a tag or commit SHA (git+https://...@<sha>)."),
            );
        }
    }
    let mut dirs: Vec<(&str, &String)> = vec![];
    for m in fc
        .requirement_files
        .iter()
        .chain(&fc.pyprojects)
        .chain(&fc.package_jsons)
    {
        if !dirs.iter().any(|(d, _)| *d == dir(m)) {
            dirs.push((dir(m), m));
        }
    }
    for (d, m) in dirs {
        if !fc.lockfiles.iter().any(|l| dir(l) == d) {
            out.push(
                mk(
                    "no_lockfile",
                    Severity::Medium,
                    format!(
                        "No lockfile for project `{}`",
                        if d.is_empty() { "." } else { d }
                    ),
                    m.clone(),
                )
                .remediation(
                    "Generate and commit a lockfile (uv/poetry/pip-compile, npm/pnpm/yarn lock).",
                ),
            );
        }
    }
    skips.finish(out)
}

// ---------- readiness.compose ----------

fn test_string(v: &Value) -> String {
    match v.as_sequence() {
        Some(s) => s
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        None => v.as_str().unwrap_or("").to_string(),
    }
}

/// True when the service's `build:` Dockerfile (context + dockerfile) or, for `image:` services, a
/// repo Dockerfile in a directory named like the image, defines a HEALTHCHECK.
fn image_dockerfile_has_healthcheck(ctx: &Ctx, snap: &Snapshot, svc: &Value, file: &str) -> bool {
    let hc = |p: &str| {
        read(snap, p).is_some_and(|t| parse_stages(&t).last().is_some_and(has_healthcheck))
    };
    if let Some(build) = svc.get("build") {
        let ctxdir = build
            .as_str()
            .or_else(|| build.get("context").and_then(Value::as_str))
            .unwrap_or(".");
        let dfname = build
            .get("dockerfile")
            .and_then(Value::as_str)
            .unwrap_or("Dockerfile");
        let ctx_path = normalize(&format!("{}/{ctxdir}", dir(file)));
        return hc(&normalize(&format!("{ctx_path}/{dfname}")));
    }
    let Some(img) = svc.get("image").and_then(Value::as_str) else {
        return false;
    };
    let name = img
        .rsplit('/')
        .next()
        .unwrap_or(img)
        .split([':', '@'])
        .next()
        .unwrap_or("");
    !name.is_empty()
        && ctx
            .facts
            .dockerfiles
            .iter()
            .any(|d| base(dir(d)) == name && hc(d))
}

fn compose_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.compose";
    if ctx.facts.compose_files.is_empty() {
        return na("no compose file");
    }
    let url_re = Regex::new(r#"https?://[^/\s'"]+(/[^\s'"]*)?"#).unwrap();
    let mut out = vec![];
    let mut skips = Skips::default();
    for file in &ctx.facts.compose_files {
        let text = match read_checked(snap, file) {
            Ok(t) => t,
            Err(why) => {
                skips.add(file, why);
                continue;
            }
        };
        let mut root = match serde_norway::from_str::<Value>(&text) {
            Ok(r) => r,
            Err(e) => {
                skips.add(file, format!("YAML parse error: {e}"));
                continue;
            }
        };
        root.apply_merge().ok();
        let Some(services) = root.get("services").and_then(Value::as_mapping) else {
            continue;
        };
        for (k, svc) in services {
            let name = k.as_str().unwrap_or("?");
            if name.starts_with("x-") || !svc.is_mapping() {
                continue;
            }
            let mk = |r: &str, cat, sev, what: &str| {
                Finding::new(
                    C,
                    &format!("{C}.{r}"),
                    cat,
                    sev,
                    format!("Service `{name}`: {what}"),
                    file.clone(),
                )
                .fp_key(format!("{file}:{name}"))
            };
            if truthy(svc.get("privileged")) {
                out.push(
                    mk(
                        "privileged",
                        Category::Security,
                        Severity::High,
                        "privileged: true",
                    )
                    .remediation("Drop `privileged`; grant only the specific capabilities needed."),
                );
            }
            let sock = svc
                .get("volumes")
                .and_then(Value::as_sequence)
                .is_some_and(|v| {
                    v.iter().any(|e| {
                        e.as_str().is_some_and(|s| s.contains("docker.sock"))
                            || e.get("source")
                                .and_then(Value::as_str)
                                .is_some_and(|s| s.contains("docker.sock"))
                    })
                });
            if sock {
                out.push(
                    mk(
                        "docker_sock",
                        Category::Security,
                        Severity::High,
                        "mounts the Docker socket",
                    )
                    .remediation(
                        "Avoid mounting /var/run/docker.sock; it grants root on the host.",
                    ),
                );
            }
            if svc.get("network_mode").and_then(Value::as_str) == Some("host") {
                out.push(mk(
                    "host_network",
                    Category::Security,
                    Severity::Medium,
                    "network_mode: host",
                ));
            }
            let hc = svc.get("healthcheck");
            let test = match hc {
                None => None,
                Some(h) if truthy(h.get("disable")) => None,
                Some(h) => Some(h.get("test").map(test_string).unwrap_or_default()),
            }
            .filter(|t| !t.trim_start().starts_with("NONE"));
            let image_hc = test.is_none() && image_dockerfile_has_healthcheck(ctx, snap, svc, file);
            match test {
                None if image_hc => {}
                None => out.push(
                    mk(
                        "no_healthcheck",
                        Category::Reliability,
                        Severity::Medium,
                        "no healthcheck",
                    )
                    .remediation("Add a healthcheck pointing at a real readiness endpoint."),
                ),
                Some(t) if !t.is_empty() => {
                    let paths: Vec<String> = url_re
                        .captures_iter(&t)
                        .map(|c| {
                            c.get(1)
                                .map_or("/", |m| m.as_str())
                                .split('?')
                                .next()
                                .unwrap_or("/")
                                .to_string()
                        })
                        .collect();
                    if !paths.is_empty() && paths.iter().all(|p| p == "/") {
                        out.push(
                            mk(
                                "healthcheck_root_path",
                                Category::Reliability,
                                Severity::Low,
                                "healthcheck only probes `/`",
                            )
                            .remediation(
                                "Probe a dedicated /health endpoint that checks dependencies.",
                            ),
                        );
                    }
                    let tl = t.to_lowercase();
                    let used: Vec<&str> = ["curl", "wget"]
                        .into_iter()
                        .filter(|b| tl.contains(b))
                        .collect();
                    if !used.is_empty() {
                        let build = svc.get("build");
                        let ctxdir = build
                            .and_then(|b| {
                                b.as_str()
                                    .or_else(|| b.get("context").and_then(Value::as_str))
                            })
                            .unwrap_or(".");
                        let dfname = build
                            .and_then(|b| b.get("dockerfile"))
                            .and_then(Value::as_str)
                            .unwrap_or("Dockerfile");
                        let dpath = normalize(&format!("{}/{ctxdir}/{dfname}", dir(file)));
                        if build.is_some()
                            && let Some(dt) = read(snap, &dpath)
                        {
                            let stages = parse_stages(&dt);
                            let img = stages
                                .last()
                                .map(|s| s.image.to_lowercase())
                                .unwrap_or_default();
                            let slim = img.contains("slim")
                                || img.contains("alpine")
                                || img.contains("distroless");
                            let dl = dt.to_lowercase();
                            let missing: Vec<&str> = used
                                .iter()
                                .copied()
                                .filter(|b| {
                                    !dl.contains(b) && !(*b == "wget" && img.contains("alpine"))
                                })
                                .collect();
                            if slim && !missing.is_empty() {
                                out.push(
                                        mk("healthcheck_missing_binary", Category::Reliability, Severity::Medium, &format!("healthcheck uses {} but base image `{img}` does not ship it", missing.join("/")))
                                            .detail(format!("Dockerfile {dpath} never installs it, so the container will report unhealthy."))
                                            .remediation("Install the binary in the image or use a language-native healthcheck (python -c / node -e)."),
                                    );
                            }
                        }
                    }
                }
                _ => {}
            }
            let limits = non_empty_map(path(svc, &["deploy", "resources", "limits"]))
                || svc.get("mem_limit").is_some()
                || svc.get("cpus").is_some();
            if !limits {
                out.push(
                    mk(
                        "no_limits",
                        Category::Reliability,
                        Severity::Low,
                        "no CPU/memory limits",
                    )
                    .remediation("Set deploy.resources.limits or mem_limit/cpus."),
                );
            }
            if svc.get("restart").is_none() && path(svc, &["deploy", "restart_policy"]).is_none() {
                out.push(
                    mk(
                        "no_restart",
                        Category::Reliability,
                        Severity::Low,
                        "no restart policy",
                    )
                    .remediation("Set `restart: unless-stopped` (or on-failure)."),
                );
            }
        }
    }
    skips.finish(out)
}

// ---------- readiness.k8s ----------

fn pod_spec<'a>(kind: &str, v: &'a Value) -> Option<&'a Value> {
    match kind {
        "Deployment" | "StatefulSet" | "DaemonSet" | "Job" => {
            path(v, &["spec", "template", "spec"])
        }
        "CronJob" => path(v, &["spec", "jobTemplate", "spec", "template", "spec"]),
        _ => None,
    }
}

fn non_root(sc: Option<&Value>) -> bool {
    sc.is_some_and(|s| {
        truthy(s.get("runAsNonRoot"))
            || s.get("runAsUser")
                .and_then(Value::as_u64)
                .is_some_and(|u| u != 0)
    })
}

fn k8s_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.k8s";
    if ctx.facts.k8s_files.is_empty() {
        return na("no Kubernetes manifests");
    }
    let mut out = vec![];
    let mut skips = Skips::default();
    for file in &ctx.facts.k8s_files {
        let text = match read_checked(snap, file) {
            Ok(t) => t,
            Err(why) => {
                skips.add(file, why);
                continue;
            }
        };
        // Low-severity, highly repetitive rules: one finding per file listing the objects.
        let mut grouped: std::collections::BTreeMap<&'static str, Vec<String>> = Default::default();
        // a document that does not parse is named, and the documents after it are still checked
        let (docs, doc_errors) = k8s_docs_checked(&text);
        for e in doc_errors {
            skips.add(file, e);
        }
        for doc in docs {
            let kind = str_of(doc.get("kind"));
            let name = str_of(path(&doc, &["metadata", "name"]));
            if kind == "Secret"
                && (non_empty_map(doc.get("data")) || non_empty_map(doc.get("stringData")))
            {
                out.push(
                    Finding::new(
                        C,
                        &format!("{C}.plaintext_secret"),
                        Category::Security,
                        Severity::High,
                        format!("Plaintext Secret manifest committed: {name}"),
                        file.clone(),
                    )
                    .fp_key(format!("{file}:{name}"))
                    .remediation(
                        "Use sealed-secrets / external-secrets / SOPS; rotate the exposed values.",
                    ),
                );
                continue;
            }
            let Some(pod) = pod_spec(kind, &doc) else {
                continue;
            };
            let obj = format!("{kind}/{name}");
            let mk = |r: &str, cat, sev, what: &str, id: &str| {
                Finding::new(
                    C,
                    &format!("{C}.{r}"),
                    cat,
                    sev,
                    format!("{id}: {what}"),
                    file.clone(),
                )
                .fp_key(format!("{file}:{id}"))
            };
            if truthy(pod.get("hostNetwork")) {
                out.push(mk(
                    "host_network",
                    Category::Security,
                    Severity::Medium,
                    "hostNetwork: true",
                    &obj,
                ));
            }
            let probes_expected = matches!(kind, "Deployment" | "StatefulSet");
            for c in pod
                .get("containers")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
            {
                let id = format!("{obj}/{}", str_of(c.get("name")));
                if truthy(path(c, &["securityContext", "privileged"])) {
                    out.push(
                        mk(
                            "privileged",
                            Category::Security,
                            Severity::High,
                            "privileged container",
                            &id,
                        )
                        .remediation("Remove privileged: true; add only required capabilities."),
                    );
                }
                if probes_expected {
                    let miss: Vec<&str> = ["readinessProbe", "livenessProbe"]
                        .into_iter()
                        .filter(|p| c.get(*p).is_none())
                        .collect();
                    if !miss.is_empty() {
                        out.push(
                            mk(
                                "no_probes",
                                Category::Reliability,
                                Severity::Medium,
                                &format!("missing {}", miss.join(" and ")),
                                &id,
                            )
                            .remediation(
                                "Add readiness and liveness probes against a health endpoint.",
                            ),
                        );
                    }
                }
                for p in ["readinessProbe", "livenessProbe"] {
                    if path(c, &[p, "httpGet", "path"]).and_then(Value::as_str) == Some("/") {
                        grouped
                            .entry("probe_root_path")
                            .or_default()
                            .push(format!("{id} ({p})"));
                    }
                }
                if !non_empty_map(path(c, &["resources", "limits"])) {
                    out.push(
                        mk(
                            "no_limits",
                            Category::Reliability,
                            Severity::Medium,
                            "no resource limits",
                            &id,
                        )
                        .remediation("Set resources.limits (cpu, memory)."),
                    );
                }
                if !non_root(pod.get("securityContext")) && !non_root(c.get("securityContext")) {
                    grouped.entry("run_as_root").or_default().push(id.clone());
                }
                if let Some(img) = c.get("image").and_then(Value::as_str)
                    && !img.contains('$')
                    && !img.contains('{')
                    && image_untagged(img)
                {
                    grouped
                        .entry("latest_image")
                        .or_default()
                        .push(format!("{id} ({img})"));
                }
            }
        }
        for (rule, ids) in grouped {
            let (cat, what, fix) = match rule {
                "probe_root_path" => (
                    Category::Reliability,
                    "probes only `/`",
                    "Point probes at a real health endpoint (/health, /ready).",
                ),
                "run_as_root" => (
                    Category::Security,
                    "may run as root (no runAsNonRoot / runAsUser)",
                    "Set securityContext.runAsNonRoot: true.",
                ),
                _ => (
                    Category::SupplyChain,
                    "image untagged or :latest",
                    "Pin images by version tag or digest.",
                ),
            };
            out.push(
                Finding::new(
                    C,
                    &format!("{C}.{rule}"),
                    cat,
                    Severity::Low,
                    format!("{} container(s) {what}", ids.len()),
                    file.clone(),
                )
                .detail(ids.join("\n"))
                .remediation(fix)
                .fp_key(file.clone()),
            );
        }
    }
    skips.finish(out)
}

// ---------- readiness.ci ----------

/// Scanner names. `readyhai` counts only as an actual `readyhai scan` invocation: the bare word
/// (a comment-free `name: readyhai`, `pip install readyhai`, a repo name) proves no scan runs.
const SCANNERS: &str = r"trivy|grype|snyk|semgrep|gitleaks|trufflehog|bandit|sonar|osv-scanner|dependency-check|pip-audit|npm audit|detect-secrets|ggshield|checkmarx|codeql|opengrep|readyhai(?:\.exe)?\s+scan";

/// The real readyhai scan step: `readyhai scan ...` on one line, without `--no-tools` (which
/// turns the SAST / secret / dependency scanners off).
fn runs_readyhai_scan(all_lower: &str) -> bool {
    let rs = Regex::new(r"\breadyhai(?:\.exe)?\s+scan\b").unwrap();
    all_lower
        .lines()
        .any(|l| rs.is_match(l) && !l.contains("--no-tools"))
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

fn blank_or_comment(l: &str) -> bool {
    let t = l.trim();
    t.is_empty() || t.starts_with('#') || t.starts_with("//")
}

fn is_item_start(l: &str) -> bool {
    let t = l.trim_start();
    t == "-" || t.starts_with("- ")
}

/// Lines `[start, end)` of the YAML list item (`- ...`, a GitHub Actions step) holding line `i`.
fn enclosing_item(lines: &[&str], i: usize) -> Option<(usize, usize)> {
    let at = indent(lines[i]);
    let s = (0..=i).rev().find(|&j| {
        !blank_or_comment(lines[j]) && is_item_start(lines[j]) && (j == i || indent(lines[j]) < at)
    })?;
    let si = indent(lines[s]);
    let e = (s + 1..lines.len())
        .find(|&k| !blank_or_comment(lines[k]) && indent(lines[k]) <= si)
        .unwrap_or(lines.len());
    // the nearest dash must really enclose the line (nothing at its own indent in between)
    (i < e).then_some((s, e))
}

/// A parent key of line `i` (a line with a smaller indent than `below`), nearest first.
fn parent_key(lines: &[&str], i: usize, below: usize) -> Option<usize> {
    (0..i)
        .rev()
        .find(|&j| !blank_or_comment(lines[j]) && indent(lines[j]) < below)
}

/// Does a DIRECT child of the key at line `p` (a job: `continue-on-error: true`, `allow_failure:
/// true`) say the job can never fail the pipeline?
fn child_never(lines: &[&str], p: usize, never_key: &Regex) -> bool {
    let pi = indent(lines[p]);
    let Some(first) = (p + 1..lines.len()).find(|&k| !blank_or_comment(lines[k])) else {
        return false;
    };
    let ci = indent(lines[first]);
    if ci <= pi {
        return false;
    }
    for line in lines.iter().skip(p + 1) {
        if blank_or_comment(line) {
            continue;
        }
        let ik = indent(line);
        if ik <= pi {
            break;
        }
        if ik == ci && never_key.is_match(line.trim()) {
            return true;
        }
    }
    false
}

/// Why the scanner on line `i` can never fail the pipeline, beyond its own line: a
/// `continue-on-error: true` / `allow_failure: true` in the same step (list item), or on one of
/// the jobs / keys that enclose it. GitHub Actions and GitLab CI both put these on separate lines.
fn never_fails_nearby(
    lines: &[&str],
    i: usize,
    never_key: &Regex,
) -> Option<(usize, &'static str)> {
    let item = enclosing_item(lines, i);
    if let Some((s, e)) = item
        && (s..e).any(|k| {
            !blank_or_comment(lines[k])
                && never_key.is_match(lines[k].trim().trim_start_matches("- "))
        })
    {
        return Some((s, "in the same step"));
    }
    let mut below = item
        .map(|(s, _)| indent(lines[s]))
        .unwrap_or(indent(lines[i]));
    let mut at = item.map(|(s, _)| s).unwrap_or(i);
    for _ in 0..6 {
        let p = parent_key(lines, at, below)?;
        if child_never(lines, p, never_key) {
            return Some((p, "on the enclosing job"));
        }
        below = indent(lines[p]);
        at = p;
        if below == 0 {
            break;
        }
    }
    None
}

fn ci_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.ci";
    let mk = |r: &str, cat, sev, title: &str, loc: String| {
        Finding::new(C, &format!("{C}.{r}"), cat, sev, title, loc)
    };
    let ci = &ctx.facts.ci_files;
    if ci.is_empty() {
        return CheckOutput::findings(vec![
            mk(
                "no_ci",
                Category::Operability,
                Severity::Medium,
                "No CI pipeline found",
                ".".into(),
            )
            .remediation("Add a pipeline that builds, tests and scans on every change."),
        ]);
    }
    let scan = Regex::new(&format!("(?i)({SCANNERS})")).unwrap();
    // scanner and failure-swallowing on ONE line
    let never = Regex::new(
        r"(?i)(--exit-code[= ]0\b|\|\|\s*true|--soft-fail|continue-on-error:\s*true|allow_failure:\s*true)",
    )
    .unwrap();
    // ... or on its own line elsewhere in the step / job (GitHub Actions, GitLab CI)
    let never_key = Regex::new(
        r#"(?i)^(continue-on-error|allow_failure)\s*:\s*['"]?(true|yes|on)['"]?\s*(#.*)?$"#,
    )
    .unwrap();
    let guard = Regex::new(&format!(
        r"(?i)(command\s+-v|which|type\s+-p|hash)\s+({SCANNERS}|readyhai)"
    ))
    .unwrap();
    let mut all = String::new();
    let mut out = vec![];
    let mut skips = Skips::default();
    for f in ci {
        let t = match read_checked(snap, f) {
            Ok(t) => t,
            Err(why) => {
                skips.add(f, why);
                continue;
            }
        };
        let lines: Vec<&str> = t.lines().collect();
        // (step/item start) already reported for a multi-line "never fails"
        let mut reported: HashSet<usize> = HashSet::new();
        for (i, l) in lines.iter().enumerate() {
            let tr = l.trim();
            if tr.starts_with('#') || tr.starts_with("//") {
                continue;
            }
            all.push_str(&l.to_lowercase());
            all.push('\n');
            if scan.is_match(l) {
                let loc = format!("{f}:{}", i + 1);
                let mut never_found = never.is_match(l);
                let mut why = "on the same line";
                if !never_found
                    && let Some((anchor, w)) = never_fails_nearby(&lines, i, &never_key)
                    && reported.insert(anchor)
                {
                    never_found = true;
                    why = w;
                }
                if never_found {
                    out.push(
                        mk(
                            "scanner_never_fails",
                            Category::Security,
                            Severity::Medium,
                            "Security scanner can never fail the pipeline",
                            loc.clone(),
                        )
                        .detail(format!("The scanner step is set to ignore its own failure ({why})."))
                        .remediation(
                            "Remove `|| true` / `--exit-code 0` / `continue-on-error: true` / `allow_failure: true` so findings gate the build.",
                        ),
                    );
                }
                if guard.is_match(l) {
                    out.push(
                        mk(
                            "scanner_optional",
                            Category::Security,
                            Severity::Medium,
                            "Security scanner is skipped when not installed",
                            loc,
                        )
                        .remediation(
                            "Fail the pipeline when the scanner is missing instead of skipping it.",
                        ),
                    );
                }
            }
        }
    }
    let files = ci.join(", ");
    let readyhai_scan = runs_readyhai_scan(&all);
    for (rule, title, words) in [
        (
            "no_sast",
            "No SAST stage in CI",
            &[
                "semgrep",
                "sonar",
                "bandit",
                "codeql",
                "snyk code",
                "checkmarx",
                "opengrep",
            ][..],
        ),
        (
            "no_secret_scan",
            "No secret-scanning stage in CI",
            &["gitleaks", "trufflehog", "detect-secrets", "ggshield"][..],
        ),
        (
            "no_dep_scan",
            "No dependency/vulnerability scan in CI",
            &[
                "trivy",
                "grype",
                "snyk",
                "osv-scanner",
                "dependency-check",
                "pip-audit",
                "npm audit",
            ][..],
        ),
    ] {
        if !readyhai_scan && !words.iter().any(|w| all.contains(w)) {
            out.push(
                mk(
                    rule,
                    Category::Security,
                    Severity::Medium,
                    title,
                    ci[0].clone(),
                )
                .detail(format!("Checked: {files}"))
                .fp_key(rule.to_string())
                .remediation(format!(
                    "Add one of: {}, or a `readyhai scan` step (without --no-tools).",
                    words.join(", ")
                )),
            );
        }
    }
    skips.finish(out)
}

// ---------- readiness.repo ----------

fn repo_check_fn(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.repo";
    let fc = &ctx.facts;
    let mk = |r: &str, cat, sev, title: &str, loc: String| {
        Finding::new(C, &format!("{C}.{r}"), cat, sev, title, loc)
    };
    let mut out = vec![];
    for d in snap.denied.iter().filter(|d| d.tracked) {
        out.push(
            mk("tracked_secret_file", Category::Security, Severity::High, "Secret-bearing file tracked in git", d.path.clone())
                .detail("Path only; the file was not read.")
                .remediation("Rotate the credentials it contains first, then remove it from the index and purge history; add it to .gitignore."),
        );
    }
    if !fc.has_readme {
        out.push(
            mk(
                "no_readme",
                Category::Operability,
                Severity::Low,
                "No README",
                ".".into(),
            )
            .remediation("Add a README with setup, run and ops notes."),
        );
    }
    if !fc.has_tests {
        out.push(
            mk(
                "no_tests",
                Category::Quality,
                Severity::Medium,
                "No tests found",
                ".".into(),
            )
            .remediation("Add automated tests and run them in CI."),
        );
    }
    if fc.web_framework.is_some() {
        if !fc.has_health_route {
            out.push(
                mk(
                    "no_health_route",
                    Category::Reliability,
                    Severity::Low,
                    "No /health route detected",
                    ".".into(),
                )
                .remediation("Expose /health (liveness) and /ready (readiness)."),
            );
        }
        if !fc.has_otel {
            out.push(
                mk(
                    "no_otel",
                    Category::Observability,
                    Severity::Low,
                    "OpenTelemetry not wired",
                    ".".into(),
                )
                .remediation("Add OpenTelemetry tracing/metrics instrumentation."),
            );
        }
    }
    CheckOutput::findings(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Target, TargetKind};
    use std::path::{Path, PathBuf};

    fn ctx_for(src: &Path, tag: &str, mark_tracked: bool) -> Ctx {
        let tmp = std::env::temp_dir().join(format!("readyhai-rules-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let mut snap = crate::snapshot::take(src, &tmp.join("src"), &[], &[]).unwrap();
        if mark_tracked {
            snap.denied.iter_mut().for_each(|d| d.tracked = true);
        }
        Ctx {
            run_id: "t".into(),
            target: Target {
                kind: TargetKind::Repo,
                raw: src.display().to_string(),
                path: Some(src.to_path_buf()),
                image: None,
                url: None,
                openapi: None,
                host: None,
                apk: None,
                device: None,
            },
            profile: Profile::Quick,
            run_dir: tmp.clone(),
            facts: detect_facts(&snap),
            snapshot: Some(snap),
            docker: crate::tools::Docker::detect(&tmp),
            cfg: Default::default(),
            error_lines: Default::default(),
            nonprod: false,
            qa: None,
        }
    }

    fn run_all(ctx: &Ctx) -> Vec<Finding> {
        checks()
            .iter()
            .flat_map(|c| (c.run)(ctx).unwrap().findings)
            .collect()
    }

    #[test]
    fn fixture_findings() {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vuln-app");
        let ctx = ctx_for(&src, "fx", true);
        let fc = &ctx.facts;
        assert_eq!(fc.web_framework.as_deref(), Some("fastapi"));
        assert!(fc.has_health_route && fc.has_tests && fc.has_readme && !fc.has_otel);
        assert_eq!((fc.total_deps, fc.unpinned_deps), (4, 1));
        assert_eq!(fc.k8s_files, vec!["k8s/deployment.yaml"]);
        let f = run_all(&ctx);
        let rules: HashSet<&str> = f.iter().map(|x| x.rule.as_str()).collect();
        for r in [
            "readiness.dockerfile.no_user",
            "readiness.dockerfile.no_healthcheck",
            "readiness.dockerfile.no_dockerignore",
            "readiness.deps.unpinned",
            "readiness.deps.no_lockfile",
            "readiness.compose.privileged",
            "readiness.compose.healthcheck_root_path",
            "readiness.compose.healthcheck_missing_binary",
            "readiness.compose.no_limits",
            "readiness.k8s.no_probes",
            "readiness.k8s.no_limits",
            "readiness.ci.no_sast",
            "readiness.ci.no_secret_scan",
            "readiness.ci.scanner_never_fails",
            "readiness.ci.scanner_optional",
            "readiness.repo.tracked_secret_file",
            "readiness.repo.no_otel",
        ] {
            assert!(rules.contains(r), "missing {r}; got {rules:?}");
        }
        assert!(
            !rules.contains("readiness.k8s.privileged"),
            "comment must not trigger privileged"
        );
        assert!(!rules.contains("readiness.ci.no_dep_scan"));
        assert!(
            f.iter().all(|x| !x.detail.contains("rh_fixture_secret")
                && !x.title.contains("rh_fixture_secret"))
        );
    }

    fn dump(path: &str, tag: &str) {
        let src = PathBuf::from(path);
        let ctx = ctx_for(&src, tag, false);
        let mut ctx = ctx;
        // honor real tracked flags from the snapshot
        if let Some(s) = ctx.snapshot.as_mut() {
            s.denied
                .iter_mut()
                .for_each(|d| d.tracked = s.tracked.contains(&d.path));
        }
        println!("== {path} facts: {:?}", ctx.facts);
        for f in run_all(&ctx) {
            println!("{} | {} | {}", f.rule, f.location, f.title);
        }
    }

    #[test]
    #[ignore]
    fn nuhire_user_service() {
        dump(
            "/home/anshukushwaha/95095/Backup/Desktop/learn/nuhire/services/user-service",
            "nuhire",
        );
        dump(
            "/home/anshukushwaha/95095/Backup/Desktop/learn/nuhire/argocd",
            "argocd",
        );
    }

    fn tmp_repo(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("readyhai-rules-src-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for (p, c) in files {
            let f = d.join(p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, c).unwrap();
        }
        d
    }

    #[test]
    fn compose_healthcheck_from_dockerfile() {
        let src = tmp_repo(
            "chc",
            &[
                (
                    "docker-compose.yml",
                    "services:\n  web:\n    build: ./web\n  bare:\n    build: ./bare\n",
                ),
                ("web/Dockerfile", "FROM alpine:3.19\nHEALTHCHECK CMD true\n"),
                ("bare/Dockerfile", "FROM alpine:3.19\n"),
            ],
        );
        let f = run_all(&ctx_for(&src, "chc", false));
        let hits: Vec<_> = f
            .iter()
            .filter(|x| x.rule == "readiness.compose.no_healthcheck")
            .map(|x| x.title.clone())
            .collect();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("bare"));
    }

    #[test]
    fn dockerfile_oneshot_skips_healthcheck() {
        let src = tmp_repo(
            "dhc",
            &[
                (
                    "runners/Dockerfile",
                    "FROM alpine:3.19\nUSER app\nCMD [\"server\"]\n",
                ),
                (
                    "job/Dockerfile",
                    "FROM alpine:3.19\nUSER app\nENTRYPOINT [\"/run.sh\"]\n",
                ),
                (
                    "api/Dockerfile",
                    "FROM alpine:3.19\nUSER app\nEXPOSE 80\nCMD [\"/app.sh\"]\n",
                ),
            ],
        );
        let f = run_all(&ctx_for(&src, "dhc", false));
        let locs: Vec<_> = f
            .iter()
            .filter(|x| x.rule == "readiness.dockerfile.no_healthcheck")
            .map(|x| x.location.clone())
            .collect();
        assert_eq!(locs.len(), 1, "{locs:?}");
        assert!(locs[0].starts_with("api/"));
    }

    #[test]
    fn package_json_lockfile_downgrades() {
        let pkg = r#"{"dependencies":{"a":"^1.0.0","b":"~2.0.0"}}"#;
        let src = tmp_repo("pkg", &[("package.json", pkg), ("package-lock.json", "{}")]);
        let f = run_all(&ctx_for(&src, "pkg", false));
        let u = f
            .iter()
            .find(|x| x.rule == "readiness.deps.unpinned")
            .expect("unpinned");
        assert_eq!(u.severity, Severity::Low);
        assert!(u.detail.contains("ranges are locked by package-lock.json"));
        let src = tmp_repo("pkg2", &[("package.json", pkg)]);
        let f = run_all(&ctx_for(&src, "pkg2", false));
        let u = f
            .iter()
            .find(|x| x.rule == "readiness.deps.unpinned")
            .expect("unpinned");
        assert_eq!(u.severity, Severity::Medium);
    }

    fn out_of(ctx: &Ctx, id: &str) -> CheckOutput {
        let c = checks().into_iter().find(|c| c.id == id).unwrap();
        (c.run)(ctx).unwrap()
    }

    fn ci_findings(tag: &str, files: &[(&str, &str)]) -> Vec<Finding> {
        let src = tmp_repo(tag, files);
        out_of(&ctx_for(&src, tag, false), "readiness.ci").findings
    }

    fn never_fails_at(f: &[Finding]) -> Vec<String> {
        f.iter()
            .filter(|x| x.rule == "readiness.ci.scanner_never_fails")
            .map(|x| x.location.clone())
            .collect()
    }

    const GH: &str = ".github/workflows/ci.yml";

    #[test]
    fn unreadable_or_unparseable_files_make_the_check_partial_and_name_the_file() {
        let big = format!(
            "FROM alpine:3.19\nUSER app\n# {}\n",
            "x".repeat(2 * 1024 * 1024 + 10)
        );
        let src = tmp_repo(
            "partial",
            &[
                ("Dockerfile", &big),
                ("package.json", "{ not json"),
                ("docker-compose.yml", "services: [unclosed\n  web: {"),
            ],
        );
        let ctx = ctx_for(&src, "partial", false);
        for (id, file, why) in [
            ("readiness.dockerfile", "Dockerfile", "read limit"),
            ("readiness.deps", "package.json", "invalid JSON"),
            (
                "readiness.compose",
                "docker-compose.yml",
                "YAML parse error",
            ),
        ] {
            match out_of(&ctx, id).status {
                Some(CheckStatus::Partial(r)) => {
                    assert!(r.contains(file) && r.contains(why), "{id}: {r}")
                }
                other => panic!("{id}: expected Partial, got {other:?}"),
            }
        }
        // a clean repo: no status override (Passed / Failed by findings)
        let ok = tmp_repo(
            "clean",
            &[(
                "Dockerfile",
                "FROM alpine:3.19\nUSER app\nHEALTHCHECK CMD true\n",
            )],
        );
        assert!(
            out_of(&ctx_for(&ok, "clean", false), "readiness.dockerfile")
                .status
                .is_none()
        );
    }

    #[test]
    fn k8s_parsing_continues_past_a_bad_document() {
        let manifest = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
spec:
  template:
    spec:
      containers:
        - name: c
          image: nginx:1.25
          securityContext:
            privileged: true
---
apiVersion: v1
kind: ConfigMap
data: [unclosed
  - : :
---
apiVersion: v1
kind: Secret
metadata:
  name: leaked
stringData:
  k: v
";
        let src = tmp_repo("k8sbad", &[("k8s/all.yaml", manifest)]);
        let ctx = ctx_for(&src, "k8sbad", false);
        assert_eq!(ctx.facts.k8s_files, vec!["k8s/all.yaml"]);
        let o = out_of(&ctx, "readiness.k8s");
        let rules: Vec<&str> = o.findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.contains(&"readiness.k8s.privileged"), "{rules:?}");
        assert!(
            rules.contains(&"readiness.k8s.plaintext_secret"),
            "the document AFTER the bad one must still be checked: {rules:?}"
        );
        match o.status {
            Some(CheckStatus::Partial(r)) => assert!(
                r.contains("k8s/all.yaml") && r.contains("document 2"),
                "{r}"
            ),
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn yaml_documents_split_on_markers() {
        let d = split_yaml_docs("# c\n---\na: 1\n---\n\n---\nb: 2\n...\n");
        assert_eq!(
            d.iter().map(|x| x.1.trim().to_string()).collect::<Vec<_>>(),
            ["a: 1", "b: 2"]
        );
        assert_eq!(d[0].0, 3);
        let (docs, errs) = k8s_docs_checked("a: 1\n---\nb: [\n---\nc: 3\n");
        assert_eq!((docs.len(), errs.len()), (2, 1), "{errs:?}");
        assert!(errs[0].starts_with("document 2 (line 3)"), "{errs:?}");
    }

    #[test]
    fn multi_line_continue_on_error_is_a_scanner_that_never_fails() {
        let wf = "\
name: ci
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trivy scan
        uses: aquasecurity/trivy-action@0.20.0
        continue-on-error: true
      - name: Lint
        run: make lint
        continue-on-error: true
";
        let f = ci_findings("ci-step", &[(GH, wf)]);
        assert_eq!(
            never_fails_at(&f),
            [format!("{GH}:7")],
            "one finding for the Trivy step; the Lint step is not a scanner"
        );
        // the step that is a scanner but does NOT carry the key is fine, even when the next step does
        let wf = "\
jobs:
  scan:
    steps:
      - run: trivy fs .
      - run: echo done
        continue-on-error: true
";
        assert!(never_fails_at(&ci_findings("ci-next", &[(GH, wf)])).is_empty());
        // the key as the first line of the step
        let wf = "\
jobs:
  scan:
    steps:
      - continue-on-error: true
        run: |
          gitleaks detect
";
        assert_eq!(
            never_fails_at(&ci_findings("ci-first", &[(GH, wf)])).len(),
            1
        );
    }

    #[test]
    fn job_level_continue_on_error_and_gitlab_allow_failure_are_detected() {
        let wf = "\
jobs:
  scan:
    continue-on-error: true
    steps:
      - run: gitleaks detect
  build:
    steps:
      - run: trivy fs .
";
        let f = ci_findings("ci-job", &[(GH, wf)]);
        assert_eq!(
            never_fails_at(&f),
            [format!("{GH}:5")],
            "only the job that swallows failure"
        );
        let gl = "\
trivy:
  stage: test
  script:
    - trivy fs .
  allow_failure: true
semgrep:
  script:
    - semgrep ci
";
        let f = ci_findings("ci-gl", &[(".gitlab-ci.yml", gl)]);
        assert_eq!(never_fails_at(&f), [".gitlab-ci.yml:4".to_string()]);
        // the single-line forms keep working
        let f = ci_findings(
            "ci-same",
            &[(
                GH,
                "jobs:\n  s:\n    steps:\n      - run: trivy fs . || true\n",
            )],
        );
        assert_eq!(never_fails_at(&f).len(), 1);
    }

    #[test]
    fn the_word_readyhai_alone_does_not_satisfy_the_scan_rules() {
        let has = |f: &[Finding], r: &str| f.iter().any(|x| x.rule == format!("readiness.ci.{r}"));
        let all3 = |f: &[Finding]| {
            ["no_sast", "no_secret_scan", "no_dep_scan"]
                .iter()
                .all(|r| has(f, r))
        };
        // mentions of the name, an install, a tools update: no scan runs
        let wf = "\
name: readyhai
jobs:
  x:
    steps:
      - run: pip install readyhai
      - run: readyhai tools update
";
        let f = ci_findings("rh-word", &[(GH, wf)]);
        assert!(
            all3(&f),
            "{:?}",
            f.iter().map(|x| &x.rule).collect::<Vec<_>>()
        );
        // the actual scan step satisfies all three (it runs SAST, secrets and dependency scanners)
        let wf = "jobs:\n  x:\n    steps:\n      - run: readyhai scan . --profile quick\n";
        let f = ci_findings("rh-scan", &[(GH, wf)]);
        assert!(!has(&f, "no_sast") && !has(&f, "no_secret_scan") && !has(&f, "no_dep_scan"));
        // --no-tools turns the scanners off: it is not a scan stage
        let wf = "jobs:\n  x:\n    steps:\n      - run: readyhai scan . --no-tools\n";
        assert!(all3(&ci_findings("rh-notools", &[(GH, wf)])));
        // a Jenkins stage that only updates tools
        assert!(all3(&ci_findings(
            "rh-jenkins",
            &[(
                "Jenkinsfile",
                "pipeline { stages { stage('t') { steps { sh 'readyhai tools update' } } } }\n"
            )]
        )));
        // a real scanner still satisfies exactly its own rule
        let f = ci_findings(
            "rh-trivy",
            &[(GH, "jobs:\n  x:\n    steps:\n      - run: trivy fs .\n")],
        );
        assert!(has(&f, "no_sast") && has(&f, "no_secret_scan") && !has(&f, "no_dep_scan"));
    }
}
