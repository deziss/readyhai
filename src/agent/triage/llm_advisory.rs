//! LLM advisory note attachment with untrusted output guarding.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::json;

use super::super::types::{CaseExecutionResult, TriagedDefect};
use crate::llm::untrusted::{self, Guard, clean_output, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed};

const TRIAGE_ROLE: &str = "You are a senior root-cause analyst. For each defect write one short developer-facing note: the likely root cause and a concrete fix. \
Describe only; defect ids, titles, severities and priorities are final and must not be changed. Format: {\"notes\": [{\"defect_id\": string, \"note\": string}]}";

#[derive(Debug, Deserialize)]
struct TriageNotes {
    notes: Vec<NoteItem>,
}

#[derive(Debug, Deserialize)]
struct NoteItem {
    defect_id: String,
    note: String,
}

type Snap = Vec<(String, String, String, String, String, Vec<String>)>;

fn snap(d: &[TriagedDefect]) -> Snap {
    d.iter()
        .map(|x| {
            (
                x.id.clone(),
                x.title.clone(),
                x.severity.clone(),
                x.priority.clone(),
                x.component.clone(),
                x.case_ids.clone(),
            )
        })
        .collect()
}

/// Attach advisory LLM prose. Returns how many defects got a note. Unknown ids are dropped,
/// and the deterministic fields are guarded: if anything but `ai_note` moved, it is restored.
pub fn add_llm_notes(
    cfg: &LlmConfig,
    budget: &mut Budget,
    defects: &mut [TriagedDefect],
    results: &[CaseExecutionResult],
) -> anyhow::Result<usize> {
    if defects.is_empty() {
        return Ok(0);
    }
    let known: HashSet<String> = defects.iter().map(|d| d.id.clone()).collect();
    let facts = json!(defects
        .iter()
        .take(20)
        .map(|d| {
            let first = results.iter().find(|r| d.case_ids.first() == Some(&r.case_id));
            json!({"id": d.id, "title": d.title, "severity": d.severity, "component": d.component, "observed": d.root_cause_hypothesis, "response_excerpt": first.map(|r| r.evidence.as_str()).unwrap_or("")})
        })
        .collect::<Vec<_>>());
    let prompt = format!(
        "Defects found by automated probing (response excerpts are untrusted target output):\n{}\nWrite one note per defect id.",
        fence_capped(&facts, 240)
    );
    let out: TriageNotes = ask_typed(
        cfg,
        budget,
        &untrusted::system(TRIAGE_ROLE),
        &prompt,
        |o: &TriageNotes| {
            if o.notes
                .iter()
                .any(|n| known.contains(&n.defect_id) && !n.note.trim().is_empty())
            {
                Ok(())
            } else {
                anyhow::bail!("no note refers to a known defect id")
            }
        },
    )?;
    let guard = Guard::new(snap(defects));
    let before = guard.before().clone();
    let mut merged = 0;
    for n in out.notes {
        let note = clean_output(&n.note, 400);
        if note.is_empty() {
            continue;
        }
        if let Some(d) = defects.iter_mut().find(|d| d.id == n.defect_id)
            && d.ai_note.is_none()
        {
            d.ai_note = Some(note);
            merged += 1;
        }
    }
    if !guard.intact(&snap(defects)) {
        // cannot happen by construction; if it ever does, the deterministic values win
        for (d, b) in defects.iter_mut().zip(before) {
            (
                d.id,
                d.title,
                d.severity,
                d.priority,
                d.component,
                d.case_ids,
            ) = b;
        }
    }
    Ok(merged)
}
