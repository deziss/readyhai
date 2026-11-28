//! Batch test case evaluator and aggregate reporting.

use super::rag::evaluate_rag_triad;
use super::safety::evaluate_safety;
use super::trajectory::evaluate_trajectory;
use super::types::{AiEvalReport, AiTestCase, AiTestResult};

/// Evaluate a collection of AI test cases and compute aggregate statistics.
///
/// Scores that could not be measured stay `None` all the way through: a case with no measurement
/// gets no score, cannot pass, and is skipped by the averages.
pub fn evaluate_cases(cases: &[AiTestCase], threshold: f64, red_team: bool) -> AiEvalReport {
    let mut results = Vec::new();
    let mut rag_total = 0.0;
    let mut rag_count = 0usize;
    let mut faith_total = 0.0;
    let mut faith_count = 0usize;
    let mut passed_count = 0;

    for case in cases {
        let mut feedback = Vec::new();
        let rag_score = evaluate_rag_triad(
            &case.query,
            case.context.as_deref(),
            &case.response,
            case.expected.as_deref(),
        );

        if let Some(v) = rag_score.composite_score {
            rag_total += v;
            rag_count += 1;
        }
        if let Some(v) = rag_score.faithfulness {
            faith_total += v;
            faith_count += 1;
        }
        if rag_score.not_evaluated("faithfulness") {
            feedback.push(
                "Faithfulness not evaluated: no retrieved context or no checkable claim".into(),
            );
        }

        let traj_eval = case.trajectory.as_ref().map(|t| evaluate_trajectory(t));
        let red_team_eval = if red_team {
            Some(evaluate_safety(
                &case.query,
                case.context.as_deref(),
                &case.response,
            ))
        } else {
            None
        };

        let mut case_score = rag_score.composite_score;
        if let Some(ref t) = traj_eval {
            case_score = Some(match case_score {
                Some(v) => (v * 0.70 + t.efficiency_score * 0.30).clamp(0.0, 1.0),
                None => t.efficiency_score,
            });
            if t.loop_detected {
                feedback.push("Agent loop detected in tool trajectory".into());
            }
        }

        if let Some(ref r) = red_team_eval {
            case_score = Some(match case_score {
                Some(v) => (v * 0.80 + r.safety_score * 0.20).clamp(0.0, 1.0),
                None => r.safety_score,
            });
            if !r.findings.is_empty() {
                feedback.extend(r.findings.clone());
            }
        }

        if rag_score.hallucination_count > 0 {
            feedback.push(format!(
                "{} ungrounded hallucination(s) detected",
                rag_score.hallucination_count
            ));
        }

        // A case with no measurement demonstrated nothing, so it cannot pass on an absent score.
        let passed =
            case_score.is_some_and(|v| v >= threshold) && rag_score.hallucination_count == 0;
        if passed {
            passed_count += 1;
        }

        results.push(AiTestResult {
            case_id: case.id.clone(),
            passed,
            rag_triad: Some(rag_score),
            trajectory_eval: traj_eval,
            red_team: red_team_eval,
            overall_score: case_score,
            feedback,
        });
    }

    let total = results.len();
    let pass_rate = if total > 0 {
        passed_count as f64 / total as f64
    } else {
        0.0
    };

    AiEvalReport {
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "2026-11-14T00:00:00Z".into()),
        total_cases: total,
        passed_cases: passed_count,
        failed_cases: total - passed_count,
        pass_rate,
        avg_rag_score: checked_average(rag_total, rag_count),
        avg_faithfulness: checked_average(faith_total, faith_count),
        results,
    }
}

/// Mean of the measured values only; `None` when nothing was measured.
fn checked_average(total: f64, count: usize) -> Option<f64> {
    if count > 0 {
        Some(total / count as f64)
    } else {
        None
    }
}
