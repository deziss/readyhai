//! Tool calling trajectory and cyclic loop evaluation.

use std::collections::HashSet;

use super::types::TrajectoryEval;

/// Evaluates Agent tool-calling execution traces:
/// - Detects cyclic redundant loops (same tool + same arguments >= 2 times).
/// - Validates tool call schema (tool name present, arguments valid JSON).
/// - Calculates trajectory efficiency score.
pub fn evaluate_trajectory(steps: &[serde_json::Value]) -> TrajectoryEval {
    let mut total_steps = steps.len();
    let mut redundant_steps = 0;
    let mut schema_violations = 0;
    let mut loop_detected = false;
    let mut issues = Vec::new();

    let mut last_signature: Option<String> = None;
    let mut seen_signatures = HashSet::new();

    for (idx, step) in steps.iter().enumerate() {
        let tool_name = step
            .get("tool")
            .or_else(|| step.get("name"))
            .and_then(|v| v.as_str());
        let arguments = step
            .get("arguments")
            .or_else(|| step.get("args"))
            .or_else(|| step.get("input"));

        if tool_name.is_none() {
            schema_violations += 1;
            issues.push(format!("Step {}: missing tool name in trajectory", idx + 1));
            continue;
        }

        let name = tool_name.unwrap();
        let args_str = arguments
            .map(|a| a.to_string())
            .unwrap_or_else(|| "{}".into());

        let sig = format!("{name}:{args_str}");

        if let Some(ref last) = last_signature
            && last == &sig
        {
            redundant_steps += 1;
            loop_detected = true;
            issues.push(format!(
                "Step {}: immediate cyclic repeat of tool '{}' with identical arguments",
                idx + 1,
                name
            ));
        }

        if seen_signatures.contains(&sig) {
            redundant_steps += 1;
            issues.push(format!(
                "Step {}: repeated invocation of tool '{}' with previously used arguments",
                idx + 1,
                name
            ));
        }

        seen_signatures.insert(sig.clone());
        last_signature = Some(sig);
    }

    if total_steps == 0 {
        total_steps = 1;
    }

    let penalty =
        (redundant_steps as f64 * 0.35 + schema_violations as f64 * 0.50) / total_steps as f64;
    let efficiency_score = (1.0 - penalty).clamp(0.0, 1.0);

    TrajectoryEval {
        total_steps,
        redundant_steps,
        schema_violations,
        loop_detected,
        efficiency_score,
        issues,
    }
}
