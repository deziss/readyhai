//! Dataset loading from files (JSON, JSONL) or CLI arguments.

use std::fs;

use anyhow::{Context, Result, bail};

use super::types::{AiTestCase, EvalAiOpts};

/// Load test cases from single CLI flags or a dataset file (JSON / JSONL).
pub fn load_cases(opts: &EvalAiOpts) -> Result<Vec<AiTestCase>> {
    if let Some(ref path) = opts.dataset {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read dataset file {}", path.display()))?;
        if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
            let mut cases = Vec::new();
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_str(trimmed).with_context(|| {
                    format!("Malformed JSON on line {} of {}", idx + 1, path.display())
                })?;
                let id = v
                    .get("id")
                    .and_then(|x| x.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| format!("case-{}", idx + 1));
                let query = v
                    .get("query")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let context = v.get("context").and_then(|x| x.as_str()).map(String::from);
                let response = v
                    .get("response")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let expected = v.get("expected").and_then(|x| x.as_str()).map(String::from);
                let trajectory = v.get("trajectory").and_then(|x| x.as_array()).cloned();
                cases.push(AiTestCase {
                    id,
                    query,
                    context,
                    response,
                    expected,
                    trajectory,
                });
            }
            return Ok(cases);
        } else {
            // Assume JSON array or object
            let v: serde_json::Value = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse JSON dataset {}", path.display()))?;
            if let Some(arr) = v.as_array() {
                let cases: Vec<AiTestCase> =
                    serde_json::from_value(serde_json::Value::Array(arr.clone()))
                        .context("Invalid AiTestCase array schema in dataset")?;
                return Ok(cases);
            } else if let Ok(single) = serde_json::from_value::<AiTestCase>(v) {
                return Ok(vec![single]);
            } else {
                bail!("Dataset JSON must be an array of test cases or a single case object");
            }
        }
    }

    // From CLI flags
    let query = opts.query.clone().unwrap_or_default();
    let response = opts.response.clone().unwrap_or_default();
    if query.is_empty() && response.is_empty() {
        bail!("Please provide either --dataset <path> or --query and --response");
    }

    let trajectory = if let Some(ref tpath) = opts.trajectory {
        let ttext = fs::read_to_string(tpath)
            .with_context(|| format!("Failed to read trajectory {}", tpath.display()))?;
        serde_json::from_str::<Vec<serde_json::Value>>(&ttext).ok()
    } else {
        None
    };

    Ok(vec![AiTestCase {
        id: "cli-case".into(),
        query,
        context: opts.context.clone(),
        response,
        expected: opts.expected.clone(),
        trajectory,
    }])
}
