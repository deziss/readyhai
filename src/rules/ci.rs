//! CI/CD pipeline security stage validation.

use super::facts::{Skips, read_checked};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Finding, Severity};
use crate::snapshot::Snapshot;
use regex::Regex;
use std::collections::HashSet;

/// Scanner names. `readyhai` counts only as an actual `readyhai scan` invocation: the bare word
/// (a comment-free `name: readyhai`, `pip install readyhai`, a repo name) proves no scan runs.
pub(crate) const SCANNERS: &str = r"trivy|grype|snyk|semgrep|gitleaks|trufflehog|bandit|sonar|osv-scanner|dependency-check|pip-audit|npm audit|detect-secrets|ggshield|checkmarx|codeql|opengrep|readyhai(?:\.exe)?\s+scan";

// Compiled once for the process. The two `{SCANNERS}` patterns are assembled at run time (the
// name list is a const, not a literal pattern), so they go through the shared cache; the others
// are literal and use `regex_cached!`. Checks run per scan and matched per CI line.
regex_cached!(READYHAI_SCAN_STEP, r"\breadyhai(?:\.exe)?\s+scan\b");
regex_cached!(
    NEVER_INLINE,
    r"(?i)(--exit-code[= ]0\b|\|\|\s*true|--soft-fail|continue-on-error:\s*true|allow_failure:\s*true)"
);
regex_cached!(
    NEVER_KEY_LINE,
    r#"(?i)^(continue-on-error|allow_failure)\s*:\s*['"]?(true|yes|on)['"]?\s*(#.*)?$"#
);

/// The real readyhai scan step: `readyhai scan ...` on one line, without `--no-tools` (which
/// turns the SAST / secret / dependency scanners off).
pub(crate) fn runs_readyhai_scan(all_lower: &str) -> bool {
    let rs = &*READYHAI_SCAN_STEP;
    all_lower
        .lines()
        .any(|l| rs.is_match(l) && !l.contains("--no-tools"))
}

pub(crate) fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

pub(crate) fn blank_or_comment(l: &str) -> bool {
    let t = l.trim();
    t.is_empty() || t.starts_with('#') || t.starts_with("//")
}

pub(crate) fn is_item_start(l: &str) -> bool {
    let t = l.trim_start();
    t == "-" || t.starts_with("- ")
}

/// Lines `[start, end)` of the YAML list item (`- ...`, a GitHub Actions step) holding line `i`.
pub(crate) fn enclosing_item(lines: &[&str], i: usize) -> Option<(usize, usize)> {
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
pub(crate) fn parent_key(lines: &[&str], i: usize, below: usize) -> Option<usize> {
    (0..i)
        .rev()
        .find(|&j| !blank_or_comment(lines[j]) && indent(lines[j]) < below)
}

/// Does a DIRECT child of the key at line `p` (a job: `continue-on-error: true`, `allow_failure:
/// true`) say the job can never fail the pipeline?
pub(crate) fn child_never(lines: &[&str], p: usize, never_key: &Regex) -> bool {
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
pub(crate) fn never_fails_nearby(
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

pub(crate) fn ci_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
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
    let scan = crate::regex_cache::compiled(&format!("(?i)({SCANNERS})"));
    // scanner and failure-swallowing on ONE line
    let never = &*NEVER_INLINE;
    // ... or on its own line elsewhere in the step / job (GitHub Actions, GitLab CI)
    let never_key = &*NEVER_KEY_LINE;
    let guard = crate::regex_cache::compiled(&format!(
        r"(?i)(command\s+-v|which|type\s+-p|hash)\s+({SCANNERS}|readyhai)"
    ));
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
                    && let Some((anchor, w)) = never_fails_nearby(&lines, i, never_key)
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
