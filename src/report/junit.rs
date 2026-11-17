//! JUnit XML test report serialization.

use crate::model::*;

use super::common::esc;

/// A finding that fails the JUnit test of its check: new (not baselined, not suppressed) and either
/// Medium+ or a QA defect (every QA defect is a failed test, whatever its severity).
pub fn junit_failure(f: &Finding) -> bool {
    f.status == FindingStatus::New && (f.severity >= Severity::Medium || f.rule.starts_with("qa."))
}

pub fn junit_failure_case(classname: &str, f: &Finding) -> String {
    format!(
        "<testcase classname=\"{}\" name=\"{}\"><failure message=\"{}\" type=\"{}\">{}</failure></testcase>\n",
        esc(classname),
        esc(&format!("{} {}", f.rule, f.location)),
        esc(&f.title),
        f.severity.as_str(),
        esc(&f.detail)
    )
}

pub fn junit(run: &Run) -> String {
    let mut x = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"readyhai\">\n",
    );
    // Findings belong to the check that produced them (`f.check` is the check id; the engine fills
    // it in when a check leaves it empty).
    for c in &run.checks {
        let bad: Vec<&Finding> = run
            .findings
            .iter()
            .filter(|f| f.check == c.id && junit_failure(f))
            .collect();
        let (mut tests, failures, mut errors, mut skipped) = (1usize, bad.len(), 0usize, 0usize);
        let mut cases = String::new();
        match &c.status {
            CheckStatus::Errored(r) => {
                errors = 1;
                cases.push_str(&format!(
                    "<testcase classname=\"{0}\" name=\"{0}\"><error message=\"{1}\"/></testcase>\n",
                    esc(&c.id),
                    esc(r)
                ));
            }
            CheckStatus::Skipped(r) | CheckStatus::NotApplicable(r) => {
                skipped = 1;
                cases.push_str(&format!(
                    "<testcase classname=\"{0}\" name=\"{0}\"><skipped message=\"{1}\"/></testcase>\n",
                    esc(&c.id),
                    esc(r)
                ));
            }
            _ => cases.push_str(&format!(
                "<testcase classname=\"{0}\" name=\"{0}\"/>\n",
                esc(&c.id)
            )),
        }
        for f in &bad {
            tests += 1;
            cases.push_str(&junit_failure_case(&c.id, f));
        }
        x.push_str(&format!(
            "<testsuite name=\"{}\" tests=\"{tests}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\">\n{cases}</testsuite>\n",
            esc(&c.id)
        ));
    }
    // Failing findings whose `check` names no registered check (e.g. a QA defect that carried its
    // rule id as the check) must not vanish from the report.
    let orphans: Vec<&Finding> = run
        .findings
        .iter()
        .filter(|f| junit_failure(f) && !run.checks.iter().any(|c| c.id == f.check))
        .collect();
    if !orphans.is_empty() {
        let cases: String = orphans
            .iter()
            .map(|f| {
                junit_failure_case(
                    if f.check.is_empty() {
                        "unattributed"
                    } else {
                        &f.check
                    },
                    f,
                )
            })
            .collect();
        x.push_str(&format!(
            "<testsuite name=\"unattributed\" tests=\"{n}\" failures=\"{n}\" errors=\"0\" skipped=\"0\">\n{cases}</testsuite>\n",
            n = orphans.len()
        ));
    }
    x.push_str("</testsuites>\n");
    x
}
