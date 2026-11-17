use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Severity};
use crate::qa::model::*;
use crate::snapshot::Snapshot;
use regex::Regex;
use std::fs;

pub(crate) const MAX_READ: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_ITEM_DEFECTS: usize = 100;

pub(crate) fn read(snap: &Snapshot, rel: &str) -> Option<String> {
    if snap.denied.iter().any(|d| d.path == rel) {
        return None;
    }
    let p = snap.root.join(rel);
    if fs::metadata(&p).ok()?.len() > MAX_READ {
        return None;
    }
    Some(String::from_utf8_lossy(&fs::read(p).ok()?).into_owned())
}

pub(crate) fn re(p: &str) -> Regex {
    Regex::new(p).expect("static regex")
}

pub(crate) fn is_test_path(p: &str) -> bool {
    let l = p.to_lowercase();
    let name = l.rsplit('/').next().unwrap_or("");
    l.starts_with("tests/")
        || l.starts_with("test/")
        || l.contains("/tests/")
        || l.contains("/test/")
        || l.contains("/__tests__/")
        || name.starts_with("test_")
        || name.ends_with("_test.go")
        || name.ends_with("_test.py")
        || name.contains(".spec.")
        || name.contains(".test.")
        || name.ends_with("test.java")
        || name.ends_with("tests.java")
}

pub(crate) fn sev_prio(s: Severity) -> Priority {
    if s >= Severity::High {
        Priority::P2
    } else if s == Severity::Medium {
        Priority::P3
    } else {
        Priority::P4
    }
}

pub(crate) struct Def {
    pub(crate) rule: &'static str,
    pub(crate) cat: Category,
    pub(crate) sev: Severity,
    pub(crate) area: Area,
    pub(crate) title: String,
    pub(crate) component: String,
    pub(crate) expected: String,
    pub(crate) actual: String,
    pub(crate) remediation: String,
    pub(crate) fp_key: String,
    pub(crate) steps: Vec<String>,
}

impl Def {
    pub(crate) fn into_defect(self, case_id: &str) -> Defect {
        Defect {
            id: format!("S-{}-{}", self.rule, self.fp_key),
            rule: self.rule.into(),
            category: self.cat,
            severity: self.sev,
            priority: sev_prio(self.sev),
            area: self.area,
            title: self.title,
            component: self.component,
            environment: "repo snapshot".into(),
            steps_to_reproduce: self.steps,
            expected: self.expected,
            actual: self.actual,
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![case_id.into()],
            remediation: self.remediation,
            fp_key: self.fp_key,
            fingerprint: String::new(),
            status: Default::default(),
            regression: false,
            ai_note: None,
        }
    }
}

/// Register the case and its result, push defects to the collector (when this is a QA run),
/// and return the Finding twins.
pub(crate) fn record(
    ctx: &Ctx,
    check: &str,
    area: Area,
    case_id: &str,
    title: &str,
    component: &str,
    status: ResultStatus,
    actual: &str,
    defs: Vec<Def>,
) -> Vec<Finding> {
    let defects: Vec<Defect> = defs.into_iter().map(|d| d.into_defect(case_id)).collect();
    let findings: Vec<Finding> = defects.iter().map(|d| d.to_finding(check)).collect();
    if let Some(qa) = &ctx.qa {
        qa.with(|c| {
            c.cases.push(TestCase {
                id: case_id.into(),
                area,
                technique: Technique::Static,
                title: title.into(),
                priority: Priority::P3,
                component: component.into(),
                role: None,
                steps: vec![],
                expected: String::new(),
                source: CaseSource::Deterministic,
            });
            c.results.push(TestResult {
                case_id: case_id.into(),
                status,
                actual: actual.into(),
                duration_ms: 0,
                attempts: 1,
                evidence: vec![],
                defect_id: defects.first().map(|d| d.id.clone()),
            });
            c.defects.extend(defects.iter().cloned());
        });
    }
    findings
}

pub(crate) fn untested(ctx: &Ctx, msg: &str) {
    if let Some(qa) = &ctx.qa {
        qa.with(|c| c.untested.push(msg.to_string()));
    }
}

pub(crate) fn out(findings: Vec<Finding>) -> CheckOutput {
    CheckOutput::findings(findings)
}

pub(crate) fn no_snapshot() -> anyhow::Result<CheckOutput> {
    Ok(CheckOutput::status(CheckStatus::NotApplicable(
        "no repo snapshot".into(),
    )))
}
