//! Git change analysis and impact mapping for code changes.

use super::super::change;
use super::super::discover::SpecDoc;
use super::super::types::{AgentRunReport, AgentRunRequest};
use super::options::log;

/// The change analysis of a run that has a `repo` and a `diff_base`: the changed files, the spec
/// operations they map to, and (when there is an index) advisory context. It never fails the
/// run: whatever goes wrong is a note and the plan stays what the profile gives. The result is
/// also stored on the report (`change_impact`), coverage filled in after the run.
pub(crate) fn analyze_change(
    req: &AgentRunRequest,
    spec: Option<&SpecDoc>,
    rep: &mut AgentRunReport,
) -> Option<change::Analysis> {
    let (repo, base) = match (req.repo.as_deref(), req.diff_base.as_deref()) {
        (None, None) => return None,
        (Some(_), None) | (None, Some(_)) => {
            rep.notes.push(
                "change-aware planning needs both repo and diff_base; the plan is what the profile gives"
                    .into(),
            );
            return None;
        }
        (Some(r), Some(b)) => (r, b),
    };
    let (root, base) = match change::validate_request(repo, Some(base), None) {
        Ok((root, Some(base))) => (root, base),
        Ok((_, None)) => return None,
        Err(e) => {
            rep.notes.push(format!(
                "change-aware planning skipped: {e}; the plan is what the profile gives"
            ));
            return None;
        }
    };
    let mut a = change::analyze(&root, &base, spec);
    if a.impact.status == change::APPLIED {
        match change::retriever_from_env(&root)
            .and_then(|r| change::retrieve_context(&r, &a.impact.operations))
        {
            Ok(notes) => a.impact.context_notes = notes,
            Err(why) => a
                .impact
                .notes
                .push(format!("context retriever skipped: {why}")),
        }
    }
    let i = &a.impact;
    log(
        &mut rep.steps,
        "Discovery",
        "Change Analysis",
        &format!(
            "git diff {}...HEAD: {} changed file(s), {} mapped to {} operation(s) ({}), {} unmapped{}",
            i.diff_base,
            i.changed_files_total,
            i.changed_files_total.saturating_sub(i.unmapped_total),
            i.operations.len(),
            i.status,
            i.unmapped_total,
            if i.status == change::FAILED {
                format!("; {}", i.notes.first().map(String::as_str).unwrap_or(""))
            } else {
                String::new()
            }
        ),
        if i.status == change::FAILED {
            "warning"
        } else {
            "completed"
        },
        Some("deterministic"),
    );
    rep.change_impact = Some(a.impact.clone());
    Some(a)
}
