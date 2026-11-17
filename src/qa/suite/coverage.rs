use std::fs;
use regex::Regex;

use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::*;
use crate::snapshot::Snapshot;

use super::common::{Def, MAX_READ, no_snapshot, out, re, read, record, untested};

pub(crate) const LOW_COVERAGE: f64 = 0.60;

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Cov {
    /// 0.0..=1.0
    pub(crate) overall: f64,
    pub(crate) files: Vec<(String, f64)>,
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let r = Regex::new(&format!(
        r#"(?:^|\s){}\s*=\s*"([^"]*)""#,
        regex::escape(name)
    ))
    .ok()?;
    r.captures(tag).map(|c| c[1].to_string())
}

pub(crate) fn parse_cobertura(t: &str) -> Option<Cov> {
    let root = re(r"<coverage\b[^>]*>").find(t)?.as_str().to_string();
    let mut files: Vec<(String, f64)> = vec![];
    for m in re(r"<class\b[^>]*>").find_iter(t) {
        let tag = m.as_str();
        if let (Some(f), Some(r)) = (attr(tag, "filename"), attr(tag, "line-rate"))
            && let Ok(r) = r.parse::<f64>()
            && !files.iter().any(|(n, _)| *n == f)
        {
            files.push((f, r));
        }
    }
    // `lines-valid="0"`: nothing was instrumented, so a line-rate of 1 / 0 means no data
    if attr(&root, "lines-valid").and_then(|v| v.parse::<u64>().ok()) == Some(0) {
        return None;
    }
    let overall = attr(&root, "line-rate")?.parse::<f64>().ok()?;
    Some(Cov { overall, files })
}

pub(crate) fn parse_lcov(t: &str) -> Option<Cov> {
    let (mut files, mut cur, mut lf, mut lh) = (vec![], String::new(), 0u64, 0u64);
    let (mut tf, mut th) = (0u64, 0u64);
    for l in t.lines() {
        if let Some(f) = l.strip_prefix("SF:") {
            cur = f.trim().to_string();
            lf = 0;
            lh = 0;
        } else if let Some(v) = l.strip_prefix("LF:") {
            lf = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = l.strip_prefix("LH:") {
            lh = v.trim().parse().unwrap_or(0);
        } else if l.starts_with("end_of_record") && !cur.is_empty() {
            // LF:0 = no instrumented lines: that file says nothing (it is NOT 100% covered)
            if lf > 0 {
                tf += lf;
                th += lh;
                files.push((cur.clone(), lh as f64 / lf as f64));
            }
            cur.clear();
        }
    }
    if files.is_empty() || tf == 0 {
        return None; // no line data at all: "no data", never 100%
    }
    Some(Cov {
        overall: th as f64 / tf as f64,
        files,
    })
}

pub(crate) fn parse_jacoco(t: &str) -> Option<Cov> {
    let pkg = re(r#"<package\b[^>]*>"#);
    let sf = re(r#"<sourcefile\b[^>]*>"#);
    let ctr = re(r#"<counter\b[^>]*type="LINE"[^>]*>"#);
    // Walk in document order: remember current package, then per-sourcefile LINE counter
    // (the first LINE counter after a <sourcefile> before the next </sourcefile>).
    let mut files = vec![];
    let (mut tm, mut tc) = (0u64, 0u64);
    let mut cur_pkg = String::new();
    let mut pos = 0;
    while pos < t.len() {
        let rest = &t[pos..];
        let p = pkg.find(rest).map(|m| (m.start(), m.end(), true));
        let s = sf.find(rest).map(|m| (m.start(), m.end(), false));
        let next = match (p, s) {
            (Some(a), Some(b)) => {
                if a.0 <= b.0 {
                    a
                } else {
                    b
                }
            }
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        let tag = &rest[next.0..next.1];
        if next.2 {
            cur_pkg = attr(tag, "name").unwrap_or_default();
            pos += next.1;
        } else {
            let end = rest[next.1..]
                .find("</sourcefile>")
                .map(|e| next.1 + e)
                .unwrap_or(rest.len());
            if let Some(c) = ctr.find(&rest[next.1..end]) {
                let ct = c.as_str();
                let m: u64 = attr(ct, "missed").and_then(|v| v.parse().ok()).unwrap_or(0);
                let cv: u64 = attr(ct, "covered")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let name = attr(tag, "name").unwrap_or_default();
                let path = if cur_pkg.is_empty() {
                    name
                } else {
                    format!("{cur_pkg}/{name}")
                };
                // a source file without instrumented lines carries no coverage information
                if m + cv > 0 {
                    tm += m;
                    tc += cv;
                    files.push((path, cv as f64 / (m + cv) as f64));
                }
            }
            pos += end.max(next.1);
        }
    }
    if files.is_empty() {
        return None;
    }
    let total = tm + tc;
    if total == 0 {
        return None;
    }
    Some(Cov {
        overall: tc as f64 / total as f64,
        files,
    })
}

fn parse_coverage(name: &str, text: &str) -> Option<Cov> {
    let n = name.rsplit('/').next().unwrap_or(name).to_lowercase();
    if n.contains("lcov") {
        parse_lcov(text)
    } else if n.contains("jacoco") {
        parse_jacoco(text)
    } else {
        parse_cobertura(text)
    }
}

fn is_cov_name(n: &str) -> bool {
    matches!(
        n,
        "coverage.xml" | "lcov.info" | "jacoco.xml" | "cobertura.xml"
    )
}

/// Coverage reports in the snapshot plus `<out>/` (one level deep).
fn find_coverage(ctx: &Ctx, snap: &Snapshot) -> Option<(String, Cov)> {
    for f in &snap.files {
        let name = f.rsplit('/').next().unwrap_or(f);
        if is_cov_name(name)
            && !f.contains("node_modules/")
            && let Some(c) = read(snap, f).and_then(|t| parse_coverage(name, &t))
        {
            return Some((f.clone(), c));
        }
    }
    let out = ctx.out_dir();
    let mut stack = vec![(out, 0)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if p.is_dir() && depth < 2 {
                stack.push((p, depth + 1));
            } else if is_cov_name(&name)
                && fs::metadata(&p)
                    .map(|m| m.len() <= MAX_READ)
                    .unwrap_or(false)
                && let Some(c) = fs::read_to_string(&p)
                    .ok()
                    .and_then(|t| parse_coverage(&name, &t))
            {
                return Some((format!("out/{name}"), c));
            }
        }
    }
    None
}

/// A coverage report in the snapshot that parses to nothing (no instrumented lines).
fn unusable_coverage(snap: &Snapshot) -> Option<String> {
    snap.files
        .iter()
        .filter(|f| !f.contains("node_modules/"))
        .find(|f| is_cov_name(f.rsplit('/').next().unwrap_or(f)))
        .cloned()
}

pub(crate) fn is_critical_path(p: &str) -> bool {
    let l = p.to_lowercase();
    ["auth", "payment", "order", "security", "admin"]
        .iter()
        .any(|k| l.contains(k))
}

/// 10-point band of a coverage percentage (55.0 -> 50): part of the low-coverage fingerprint.
pub(crate) fn cov_band(pct: f64) -> u32 {
    ((pct / 10.0).floor().max(0.0) as u32) * 10
}

pub(crate) fn coverage(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let case = "suite.coverage";
    let Some((src, cov)) = find_coverage(ctx, snap) else {
        // a report that exists but holds no line data (LF:0 / lines-valid=0) is "no data", not 100%
        let (why, actual) = match unusable_coverage(snap) {
            Some(f) => (
                format!(
                    "coverage report {f} contains no line data (nothing instrumented): coverage unknown"
                ),
                format!("{f} has no line data"),
            ),
            None => (
                "no coverage report (add --cov / lcov to [test] command)".to_string(),
                "no coverage report found".to_string(),
            ),
        };
        untested(ctx, &why);
        record(
            ctx,
            "qa.suite.coverage",
            Area::Suite,
            case,
            "Coverage report present",
            ".",
            ResultStatus::Blocked,
            &actual,
            vec![],
        );
        return Ok(CheckOutput::status(CheckStatus::Skipped(why)));
    };
    let mut defs = vec![];
    let pct = cov.overall * 100.0;
    if cov.overall < LOW_COVERAGE {
        // The report is the item; the 10-point band is part of the key, so coverage falling into a
        // lower band is a NEW finding instead of hiding behind the old accepted one.
        let band = cov_band(pct);
        defs.push(Def {
            rule: "qa.suite.low_coverage",
            cat: Category::Quality,
            sev: Severity::Medium,
            area: Area::Suite,
            title: format!(
                "Line coverage is {pct:.0}% (below {:.0}%)",
                LOW_COVERAGE * 100.0
            ),
            component: src.clone(),
            expected: format!("line coverage >= {:.0}%", LOW_COVERAGE * 100.0),
            actual: format!("{pct:.1}% over {} file(s) in {src}", cov.files.len()),
            remediation: "Add tests for the uncovered modules, starting with the riskiest ones."
                .into(),
            fp_key: format!("overall:{src}:{band}"),
            steps: vec![format!(
                "Open {src} and compare line-rate against the 60% bar"
            )],
        });
    }
    let crit: Vec<&(String, f64)> = cov
        .files
        .iter()
        .filter(|(f, r)| *r <= 0.0 && is_critical_path(f))
        .collect();
    for (f, _) in crit {
        defs.push(Def {
            rule: "qa.suite.critical_uncovered",
            cat: Category::Quality,
            sev: Severity::Medium,
            area: Area::Suite,
            title: format!("Security/business-critical file has 0% coverage: {f}"),
            component: f.clone(),
            expected:
                "critical paths (auth, payment, order, security, admin) are exercised by tests"
                    .into(),
            actual: format!("{f}: 0% line coverage"),
            remediation: "Write tests that execute this module before release.".into(),
            fp_key: f.clone(),
            steps: vec![format!("Open {src} and find {f}")],
        });
    }
    let st = if defs.is_empty() {
        ResultStatus::Pass
    } else {
        ResultStatus::Fail
    };
    Ok(out(record(
        ctx,
        "qa.suite.coverage",
        Area::Suite,
        case,
        "Coverage meets the bar",
        &src,
        st,
        &format!("{pct:.1}% from {src}"),
        defs,
    )))
}
