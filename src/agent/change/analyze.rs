use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use super::git::{git_changed_files, git_timeout};
use super::matcher::{is_source, map_files, op_infos};
use super::models::{
    APPLIED, Analysis, ChangeSet, FAILED, MAX_FILES, MAX_LISTED_FILES, NO_CHANGES, SKIPPED,
    UNMAPPED,
};
use crate::agent::discover::SpecDoc;
use crate::agent::types::{CaseExecutionResult, ChangeImpact, ChangedOpCoverage, PlannedCase};
use crate::qa::suite::is_test_path;

/// Analyse the diff between `base` and HEAD of `repo` against the spec's operations. Never fails
/// the run: a diff that cannot be read ends as `status = failed` with the reason in `notes`, and
/// the plan stays what the profile alone would give.
pub fn analyze(repo: &Path, base: &str, spec: Option<&SpecDoc>) -> Analysis {
    analyze_with(repo, base, spec, git_timeout())
}

pub(crate) fn analyze_with(
    repo: &Path,
    base: &str,
    spec: Option<&SpecDoc>,
    timeout: Duration,
) -> Analysis {
    let mut imp = ChangeImpact {
        status: FAILED.into(),
        repo: repo.display().to_string(),
        diff_base: base.to_string(),
        ..Default::default()
    };
    let root = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let (mut files, truncated) = match git_changed_files(&root, base, timeout) {
        Ok(v) => v,
        Err(e) => {
            imp.notes.push(format!(
                "change detection failed, the plan is not change-aware: {e}"
            ));
            return Analysis {
                impact: imp,
                set: ChangeSet::default(),
            };
        }
    };
    if truncated || files.len() > MAX_FILES {
        files.truncate(MAX_FILES);
        imp.notes.push(format!(
            "the diff is larger than {MAX_FILES} files: only the first {MAX_FILES} were considered"
        ));
    }
    imp.changed_files_total = files.len();
    imp.changed_files = files.iter().take(MAX_LISTED_FILES).cloned().collect();
    if files.is_empty() {
        imp.status = NO_CHANGES.into();
        imp.notes.push(format!(
            "git diff {base}...HEAD reports no changed file: the plan is what the profile gives"
        ));
        return Analysis {
            impact: imp,
            set: ChangeSet::default(),
        };
    }
    let Some(spec) = spec.filter(|s| !s.ops.is_empty()) else {
        imp.status = SKIPPED.into();
        imp.unmapped_total = files.len();
        imp.unmapped_files = files.into_iter().take(MAX_LISTED_FILES).collect();
        imp.notes.push(
            "no OpenAPI spec was loaded (pass --spec): changed files cannot be mapped to operations, the plan is what the profile gives".into(),
        );
        return Analysis {
            impact: imp,
            set: ChangeSet::default(),
        };
    };
    let ops = op_infos(spec);
    let (operations, unmapped) = map_files(&root, &files, &ops, &mut imp.notes);
    let source_unmapped = unmapped
        .iter()
        .filter(|f| is_source(f) && !is_test_path(f))
        .count();
    imp.unmapped_total = unmapped.len();
    imp.unmapped_files = unmapped.into_iter().take(MAX_LISTED_FILES).collect();
    imp.operations = operations;
    if imp.operations.is_empty() {
        imp.status = UNMAPPED.into();
        imp.notes.push(
            "no changed file maps to an operation of the spec: the plan is what the profile gives"
                .into(),
        );
    } else {
        imp.status = APPLIED.into();
        let unchanged = spec.ops.len().saturating_sub(imp.operations.len());
        imp.notes.push(format!(
            "{} changed operation(s) get the full case set, planned first; the {unchanged} unchanged one(s) keep the profile's baseline coverage",
            imp.operations.len(),
        ));
    }
    if source_unmapped > 0 {
        imp.notes.push(format!(
            "{source_unmapped} changed source file(s) map to no operation: shared code can affect any operation, so unchanged operations are not exempt from the baseline"
        ));
    }
    let set = ChangeSet::from_labels(imp.operations.iter().map(|o| o.operation.clone()));
    Analysis { impact: imp, set }
}

/// How the run covered each changed operation. `planned` is every planned case that tests it
/// (kept and dropped); `executed` is what was sent.
pub fn coverage(
    labels: &[String],
    planned: &[PlannedCase],
    results: &[CaseExecutionResult],
) -> Vec<ChangedOpCoverage> {
    labels
        .iter()
        .map(|label| {
            let mut c = ChangedOpCoverage {
                operation: label.clone(),
                ..Default::default()
            };
            let mut techniques = BTreeSet::new();
            for case in planned.iter().filter(|p| p.changed_ops.contains(label)) {
                c.planned += 1;
                c.case_ids.push(case.id.clone());
                let Some(r) = results.iter().find(|r| r.case_id == case.id) else {
                    continue;
                };
                if r.status == "SKIPPED" {
                    continue;
                }
                c.executed += 1;
                techniques.insert(case.technique.clone());
                match r.status.as_str() {
                    "PASS" => c.pass += 1,
                    "FAIL" => c.fail += 1,
                    _ => c.inconclusive += 1,
                }
            }
            c.techniques = techniques.into_iter().collect();
            c
        })
        .collect()
}

/// Cases of changed operations that were planned / sent, over all changed operations.
pub fn coverage_totals(cov: &[ChangedOpCoverage]) -> (usize, usize) {
    (
        cov.iter().map(|c| c.executed).sum(),
        cov.iter().map(|c| c.planned).sum(),
    )
}
