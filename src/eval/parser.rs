//! Specification file parsing and validation for evaluation test suites.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use super::types::{EvalOpts, SuiteKind, SuiteSpec};

pub(crate) fn resolve_root(opts: &EvalOpts) -> Result<PathBuf> {
    if let Some(r) = &opts.root {
        return Ok(r.clone());
    }
    let candidates = [
        std::env::current_dir().ok(),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
    ];
    for c in candidates.into_iter().flatten() {
        if c.join(&opts.dir).is_dir() {
            return Ok(c);
        }
    }
    bail!(
        "suite directory {} not found (run from the repo root or pass --dir)",
        opts.dir.display()
    )
}

/// Parse one suite file and check it is usable.
pub fn parse_suite(text: &str, origin: &str) -> Result<SuiteSpec> {
    let spec: SuiteSpec = toml::from_str(text).with_context(|| format!("parse {origin}"))?;
    validate_suite(&spec).with_context(|| format!("suite {origin}"))?;
    Ok(spec)
}

fn validate_suite(s: &SuiteSpec) -> Result<()> {
    if s.name.trim().is_empty()
        || !s
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("name must be non-empty [A-Za-z0-9_-]");
    }
    match s.kind {
        SuiteKind::Qa | SuiteKind::Agent => {
            if s.target.server.is_none() {
                bail!("kind {:?} needs target.server", s.kind);
            }
        }
        SuiteKind::Repo => {
            if s.target.path.is_none() {
                bail!("kind repo needs target.path");
            }
        }
    }
    if s.kind == SuiteKind::Qa && s.target.roles.is_none() {
        bail!("kind qa needs target.roles");
    }
    if s.target.repo.is_some() || s.change.is_some() {
        if s.kind != SuiteKind::Agent {
            bail!("target.repo and [change] are for kind agent");
        }
        let needs_diff = s.change.is_some()
            || s.target
                .repo
                .as_ref()
                .is_some_and(|r| r.diff_base == Some(true));
        if needs_diff {
            match &s.target.repo {
                Some(r) if r.commits.len() >= 2 => {}
                _ => bail!(
                    "[change] needs target.repo with at least two commits (base, then the change)"
                ),
            }
        } else {
            match &s.target.repo {
                Some(r) if !r.commits.is_empty() => {}
                _ => bail!("target.repo needs at least one commit directory"),
            }
        }
        if let Some(c) = &s.change {
            if c.operations.is_empty() {
                bail!("[change] needs at least one operation");
            }
            if !(0.0..=1.0).contains(&c.min_sent) {
                bail!("[change] min_sent must be within 0..=1");
            }
        }
    }
    if let Some(m) = &s.memory {
        if s.kind != SuiteKind::Agent {
            bail!("[memory] is for kind agent");
        }
        if !(2..=5).contains(&m.runs) {
            bail!("[memory] runs must be within 2..=5");
        }
        if s.target.repo.is_some() {
            bail!("[memory] and target.repo cannot be combined");
        }
    }
    if s.expect.is_empty()
        && s.expect_verdict.is_none()
        && s.forbid_verdict.is_empty()
        && s.expect_blocker.is_none()
    {
        bail!(
            "needs at least one [[expect]] (or, for a target without seeded defects, expect_verdict / forbid_verdict / expect_blocker)"
        );
    }
    if let Some(b) = &s.expect_blocker {
        if s.kind != SuiteKind::Agent {
            bail!("expect_blocker is for kind agent");
        }
        if serde_json::from_value::<crate::agent::BlockReason>(serde_json::Value::String(
            b.to_ascii_lowercase(),
        ))
        .is_err()
        {
            bail!(
                "expect_blocker '{b}' is not a blocker reason (auth_wall, out_of_scope, no_surface, transport)"
            );
        }
    }
    if let Some(want) = &s.expect_verdict
        && s.forbid_verdict
            .iter()
            .any(|f| f.eq_ignore_ascii_case(want))
    {
        bail!("expect_verdict '{want}' is also in forbid_verdict");
    }
    let mut seen = std::collections::BTreeSet::new();
    for e in &s.expect {
        if e.id.trim().is_empty() || e.rule.trim().is_empty() {
            bail!("every [[expect]] needs id and rule");
        }
        if e.optional && e.known_gap {
            bail!(
                "expect '{}': optional and known_gap are mutually exclusive",
                e.id
            );
        }
        if !seen.insert(e.id.as_str()) {
            bail!("duplicate expect id '{}'", e.id);
        }
    }
    if s.allow.iter().any(|a| a.rule.trim().is_empty()) {
        bail!("every [[allow]] needs a rule");
    }
    let t = &s.thresholds;
    if !(0.0..=1.0).contains(&t.min_recall) {
        bail!("min_recall must be within 0..=1");
    }
    if let Some(r) = t.max_inconclusive_rate {
        if s.kind != SuiteKind::Agent {
            bail!("max_inconclusive_rate is for kind agent (only agent runs have cases)");
        }
        if !(0.0..=1.0).contains(&r) {
            bail!("max_inconclusive_rate must be within 0..=1");
        }
    }
    if !s.target.server_args.is_empty() && s.target.server.is_none() {
        bail!("target.server_args needs target.server");
    }
    Ok(())
}

/// Load the suites named in `opts.suites` (all of them for `all`), sorted by name.
pub fn load_suites(root: &Path, opts: &EvalOpts) -> Result<Vec<SuiteSpec>> {
    let dir = root.join(&opts.dir);
    let mut all = vec![];
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    for f in files {
        let text = std::fs::read_to_string(&f).with_context(|| format!("read {}", f.display()))?;
        let spec = parse_suite(&text, &f.display().to_string())?;
        let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if stem != spec.name {
            bail!(
                "{}: name '{}' must match the file name",
                f.display(),
                spec.name
            );
        }
        all.push(spec);
    }
    let want: Vec<&str> = opts
        .suites
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if want.is_empty() || want.contains(&"all") {
        if all.is_empty() {
            bail!("no suites in {}", dir.display());
        }
        return Ok(all);
    }
    let mut out = vec![];
    for w in want {
        match all.iter().find(|s| s.name == w) {
            Some(s) => out.push(s.clone()),
            None => bail!(
                "unknown suite '{w}' (have: {})",
                all.iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
    Ok(out)
}
