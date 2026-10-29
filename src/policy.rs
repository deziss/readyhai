//! Gate: suppressions + verdict.
use crate::config::Suppression;
use crate::model::{Category, CategorySummary, CheckResult, CheckStatus, Finding, FindingStatus, Severity, Verdict};
use anyhow::Result;
use globset::Glob;
use serde::Deserialize;
use std::path::Path;

const DEFAULT: &str = include_str!("../policies/default.toml");

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub fail_severity: Severity,
    pub warn_severity: Severity,
    pub only_new: bool,
    pub kev_fails: bool,
    pub hard_fail: Vec<String>,
}

impl Policy {
    pub fn load(path: Option<&Path>) -> Result<Policy> {
        let text = match path {
            Some(p) => std::fs::read_to_string(p)?,
            None => DEFAULT.to_string(),
        };
        Ok(toml::from_str(&text)?)
    }
}

/// Mark findings matched by a live suppression. Returns notes about expired ones.
pub fn apply_suppressions(findings: &mut [Finding], sups: &[Suppression], today: &str) -> Vec<String> {
    let mut notes = vec![];
    for s in sups {
        if s.expires.as_str() < today {
            notes.push(format!("suppression for '{}' expired on {} — ignored", s.rule, s.expires));
            continue;
        }
        let (Ok(rule), path) = (Glob::new(&s.rule), s.path.as_deref().map(Glob::new)) else {
            notes.push(format!("invalid suppression rule glob '{}'", s.rule));
            continue;
        };
        let rule = rule.compile_matcher();
        let path = match path {
            Some(Ok(g)) => Some(g.compile_matcher()),
            Some(Err(_)) => {
                notes.push(format!("invalid suppression path glob for '{}'", s.rule));
                continue;
            }
            None => None,
        };
        for f in findings.iter_mut() {
            let rule_hit = rule.is_match(&f.rule) || f.rule.starts_with(&s.rule);
            if rule_hit && path.as_ref().is_none_or(|p| p.is_match(f.path())) {
                f.status = FindingStatus::Suppressed;
                f.suppressed_reason = Some(format!("{} (until {})", s.reason, s.expires));
            }
        }
    }
    notes
}

pub fn summarize(findings: &[Finding]) -> Vec<CategorySummary> {
    Category::ALL
        .iter()
        .map(|c| {
            let mut s = CategorySummary { category: c.as_str().into(), ..Default::default() };
            for f in findings.iter().filter(|f| f.category == *c) {
                match f.status {
                    FindingStatus::Suppressed => {
                        s.suppressed += 1;
                        continue;
                    }
                    FindingStatus::New => s.new += 1,
                    FindingStatus::Existing => s.existing += 1,
                }
                match f.severity {
                    Severity::Critical => s.critical += 1,
                    Severity::High => s.high += 1,
                    Severity::Medium => s.medium += 1,
                    Severity::Low => s.low += 1,
                    Severity::Info => s.info += 1,
                }
            }
            s
        })
        .collect()
}

pub fn verdict(policy: &Policy, findings: &[Finding], checks: &[CheckResult]) -> (Verdict, Vec<String>) {
    let considered: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.status != FindingStatus::Suppressed)
        .filter(|f| !policy.only_new || f.status == FindingStatus::New)
        .collect();
    let scope = if policy.only_new { "new " } else { "" };
    let mut fail = vec![];
    let mut warn = vec![];

    let at_least = |sev: Severity| considered.iter().filter(|f| f.severity >= sev).count();
    let n = at_least(policy.fail_severity);
    if n > 0 {
        fail.push(format!("{n} {scope}finding(s) at or above {}", policy.fail_severity.as_str()));
    }
    let hard: Vec<&&Finding> = considered
        .iter()
        .filter(|f| policy.hard_fail.iter().any(|p| f.rule.starts_with(p.as_str())))
        .collect();
    if !hard.is_empty() {
        let mut rules: Vec<&str> = hard.iter().map(|f| f.rule.as_str()).collect();
        rules.sort();
        rules.dedup();
        fail.push(format!("{} {scope}hard-fail finding(s): {}", hard.len(), rules.join(", ")));
    }
    let kev = considered.iter().filter(|f| f.kev).count();
    if policy.kev_fails && kev > 0 {
        fail.push(format!("{kev} {scope}known-exploited (CISA KEV) vulnerabilit(ies)"));
    }
    let w = at_least(policy.warn_severity);
    if w > 0 {
        warn.push(format!("{w} {scope}finding(s) at or above {}", policy.warn_severity.as_str()));
    }
    let no_docker = checks
        .iter()
        .filter(|c| matches!(&c.status, CheckStatus::Skipped(r) if r.contains("docker not available")))
        .count();
    if no_docker > 0 {
        warn.push(format!("{no_docker} scanner check(s) did not run: docker not available"));
    }
    for c in checks {
        match &c.status {
            CheckStatus::Errored(r) => warn.push(format!("check {} errored: {r}", c.id)),
            CheckStatus::Partial(r) => warn.push(format!("check {} partial: {r}", c.id)),
            _ => {}
        }
    }
    if !fail.is_empty() {
        fail.extend(warn);
        (Verdict::Fail, fail)
    } else if !warn.is_empty() {
        (Verdict::Warn, warn)
    } else {
        (Verdict::Pass, vec!["no gating findings".into()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Category;

    fn f(rule: &str, sev: Severity, status: FindingStatus) -> Finding {
        let mut f = Finding::new("t", rule, Category::Security, sev, "t", "a/b.yml:3");
        f.status = status;
        f
    }

    #[test]
    fn gate() {
        let p = Policy::load(None).unwrap();
        let (v, _) = verdict(&p, &[f("x", Severity::Low, FindingStatus::New)], &[]);
        assert_eq!(v, Verdict::Pass);
        let (v, _) = verdict(&p, &[f("x", Severity::Medium, FindingStatus::New)], &[]);
        assert_eq!(v, Verdict::Warn);
        let (v, _) = verdict(&p, &[f("secrets.github-pat", Severity::High, FindingStatus::New)], &[]);
        assert_eq!(v, Verdict::Fail);
        // only_new: existing critical does not block
        let (v, _) = verdict(&p, &[f("x", Severity::Critical, FindingStatus::Existing)], &[]);
        assert_eq!(v, Verdict::Pass);
    }

    #[test]
    fn suppress() {
        let mut fs = vec![f("readiness.compose.privileged", Severity::High, FindingStatus::New)];
        let s = Suppression {
            rule: "readiness.compose.privileged".into(),
            path: Some("a/**".into()),
            reason: "judge0 isolate".into(),
            expires: "2099-01-01".into(),
        };
        assert!(apply_suppressions(&mut fs, &[s.clone()], "2026-10-25").is_empty());
        assert_eq!(fs[0].status, FindingStatus::Suppressed);
        let mut fs = vec![f("readiness.compose.privileged", Severity::High, FindingStatus::New)];
        let expired = Suppression { expires: "2020-01-01".into(), ..s };
        assert_eq!(apply_suppressions(&mut fs, &[expired], "2026-10-25").len(), 1);
        assert_eq!(fs[0].status, FindingStatus::New);
    }
}
