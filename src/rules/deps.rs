//! Dependency pinning and lockfile verification rules.

use super::dockerfile::parse_stages;
use super::facts::{Dep, Skips, base, dir, manifest_deps, read};
use super::na;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Finding, Severity};
use crate::snapshot::Snapshot;
use regex::Regex;

pub(crate) fn deps_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
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
