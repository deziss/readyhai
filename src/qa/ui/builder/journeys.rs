use super::super::model::UiReport;
use super::{B, ev};
use crate::model::{Category, Severity};
use crate::qa::model::*;

pub fn process_forms(
    b: &mut B,
    rep: &UiReport,
    m: &mut CoverageMatrix,
    unmap: &dyn Fn(&str) -> String,
) {
    for f in &rep.forms {
        let page = unmap(&f.page);
        let path = page
            .split_once("://")
            .and_then(|x| x.1.find('/').map(|i| x.1[i..].to_string()))
            .unwrap_or_else(|| page.clone());
        let id = format!("ui.{path}.{}.{}.{}", f.form, f.field, f.value_kind);
        b.case(
            id.clone(),
            Technique::Boundary,
            Priority::P2,
            format!("Field `{}` rejects {}", f.field, f.value_kind),
            page.clone(),
            None,
            vec![
                format!("Open {page}"),
                format!("Enter {} ({}) in `{}`", f.value_kind, f.value, f.field),
                "Submit the form".into(),
            ],
            "Client or server validation rejects the value with a visible error",
        );
        m.set(
            &path,
            "forms",
            if f.gap {
                Cell::Fail
            } else if m.cells.iter().any(|c| {
                m.rows.get(c.0) == Some(&path)
                    && m.columns.get(c.1).map(String::as_str) == Some("forms")
                    && c.2 == Cell::Fail
            }) {
                Cell::Fail
            } else {
                Cell::Pass
            },
        );
        if f.gap {
            let i = b.defect(
                "qa.ui.validation_gap",
                Category::Quality,
                Severity::Medium,
                format!("No validation on `{}` ({})", f.field, f.value_kind),
                page.clone(),
                format!(
                    "qa.ui.validation_gap|{path}|{}|{}|{}",
                    f.form, f.field, f.value_kind
                ),
            );
            let d = &mut b.out.defects[i];
            d.expected = "Invalid/boundary input is blocked client-side or rejected server-side with a visible error".into();
            d.actual = format!(
                "accepted: not blocked by the browser, server answered {}, no error shown",
                f.server_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into())
            );
            d.steps_to_reproduce = vec![
                format!("Open {page}"),
                format!(
                    "In {} enter `{}` into `{}` (other fields valid)",
                    f.form, f.value, f.field
                ),
                "Submit".into(),
            ];
            d.remediation = "Add input type/min/max/maxlength/required attributes and server-side validation with user-visible errors.".into();
            d.cases.push(id.clone());
            let dd = d.clone();
            b.result(&id, Some(&dd), dd.actual.clone(), vec![]);
        } else {
            let how = if f.client_blocked {
                "blocked by browser validation"
            } else if f.error_shown {
                "error shown"
            } else {
                "not accepted"
            };
            b.result(&id, None, how.into(), vec![]);
        }
    }
}

pub fn process_journeys(b: &mut B, rep: &UiReport, m: &mut CoverageMatrix) {
    for j in &rep.journeys {
        let id = format!("ui.journey.{}.{}", j.name, j.role);
        b.case(
            id.clone(),
            Technique::Regression,
            Priority::P1,
            format!("Journey `{}` as {}", j.name, j.role),
            j.name.clone(),
            Some(j.role.clone()),
            vec![format!("Run journey `{}` with role `{}`", j.name, j.role)],
            "All steps pass",
        );
        match j.status.as_str() {
            "pass" => {
                let note = if j.healed_locators.is_empty() {
                    "all steps passed".to_string()
                } else {
                    format!(
                        "all steps passed ({} locator(s) self-healed)",
                        j.healed_locators.len()
                    )
                };
                b.result(&id, None, note, vec![]);
                m.set(&j.name, &j.role, Cell::Pass);
                if !j.healed_locators.is_empty() {
                    let details: Vec<String> = j
                        .healed_locators
                        .iter()
                        .take(3)
                        .map(|h| format!("'{}' via {}", h.original, h.healed_by))
                        .collect();
                    b.out.notes.push(format!(
                        "journey `{}` ({}): self-healed {} selector(s) using resilient locator tree ({})",
                        j.name,
                        j.role,
                        j.healed_locators.len(),
                        details.join(", ")
                    ));
                }
            }
            "fail" => {
                let mut evid = vec![];
                if let Some(t) = &j.trace {
                    evid.push(ev(
                        EvidenceKind::Trace,
                        t,
                        "Playwright trace (npx playwright show-trace)",
                    ));
                }
                if let Some(s) = &j.screenshot {
                    evid.push(ev(EvidenceKind::Screenshot, s, "state at failure"));
                }
                let step = j.failed_step.unwrap_or(0);
                let i = b.defect(
                    "qa.ui.journey_failed",
                    Category::Quality,
                    Severity::High,
                    format!(
                        "Journey `{}` failed at step {} ({})",
                        j.name,
                        step + 1,
                        j.role
                    ),
                    j.name.clone(),
                    format!("qa.ui.journey_failed|{}|{}", j.name, j.role),
                );
                let d = &mut b.out.defects[i];
                d.expected = "Journey completes".into();
                d.actual = format!("step {} failed: {}", step + 1, j.message);
                d.steps_to_reproduce = vec![
                    format!("Run journey `{}` as role `{}`", j.name, j.role),
                    format!("Step {} fails", step + 1),
                ];
                d.evidence = evid.clone();
                d.remediation = "Open the trace to inspect DOM/network at the failing step.".into();
                d.cases.push(id.clone());
                let dd = d.clone();
                b.result(&id, Some(&dd), dd.actual.clone(), evid);
                m.set(&j.name, &j.role, Cell::Fail);
            }
            other => {
                b.out.results.push(TestResult {
                    case_id: id,
                    status: if other == "blocked" {
                        ResultStatus::Blocked
                    } else {
                        ResultStatus::Skipped
                    },
                    actual: j.message.clone(),
                    duration_ms: 0,
                    attempts: 1,
                    evidence: vec![],
                    defect_id: None,
                });
                m.set(&j.name, &j.role, Cell::Untested);
            }
        }
    }
}

pub fn process_state_graph(b: &mut B, rep: &UiReport) {
    if let Some(sg) = &rep.state_graph {
        let sg_id = "ui.state_graph".to_string();
        b.case(
            sg_id.clone(),
            Technique::StateTransition,
            Priority::P2,
            format!(
                "Markov State Graph: {} states, {} transitions",
                sg.states.len(),
                sg.transitions.len()
            ),
            "UI Navigation Graph".into(),
            None,
            vec!["Explore SPA views, dialogs, and interactive element transitions".into()],
            "Continuous navigable state graph with no dead-end traps",
        );
        if !sg.dead_ends.is_empty() {
            let i = b.defect(
                "qa.ui.dead_end",
                Category::Quality,
                Severity::Medium,
                format!(
                    "Dead-end UI views discovered ({} view(s) trap user)",
                    sg.dead_ends.len()
                ),
                "UI Navigation".into(),
                format!("qa.ui.dead_end|{}", sg.dead_ends.join("|")),
            );
            let d = &mut b.out.defects[i];
            d.expected = "Every UI view provides navigation paths forward or back".into();
            d.actual = format!(
                "Trapped views with no links, buttons, or actions: {}",
                sg.dead_ends.join(", ")
            );
            d.steps_to_reproduce = sg
                .dead_ends
                .iter()
                .map(|de| format!("Navigate to {de}"))
                .collect();
            d.remediation =
                "Provide clear back/home navigation links or dismissal controls on all error/terminal pages.".into();
            d.cases.push(sg_id.clone());
            let dd = d.clone();
            b.result(&sg_id, Some(&dd), dd.actual.clone(), vec![]);
        } else {
            b.result(
                &sg_id,
                None,
                format!(
                    "Navigable state graph: {} states, {} transitions, 0 dead-ends",
                    sg.states.len(),
                    sg.transitions.len()
                ),
                vec![],
            );
        }
        b.out.notes.push(format!(
            "ui state graph: mapped {} distinct UI states with {} transition edges ({} dead ends)",
            sg.states.len(),
            sg.transitions.len(),
            sg.dead_ends.len()
        ));
    }
}
