//! Defect collection from historical run reports or live code audit trees.

use std::fs;
use std::path::{Path, PathBuf};

use crate::model::Severity;

use super::types::TargetDefect;

/// Load defects to remediate from a stored run or live AST scan.
///
/// When `run_id` is given the run **must** resolve: the collected findings are exactly what that
/// run recorded. A missing or unreadable run is an error, never a silent fallback to a live audit
/// of the current tree (which would report different findings than the run the user named).
pub fn collect_target_defects(
    repo: &Path,
    run_id: Option<&str>,
    filter: Option<&str>,
) -> anyhow::Result<Vec<TargetDefect>> {
    let mut targets = Vec::new();

    if let Some(rid) = run_id {
        let run_path = resolve_run_path(rid)?;
        let data = fs::read_to_string(&run_path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", run_path.display()))?;
        let run_val: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| anyhow::anyhow!("{} is not valid JSON: {e}", run_path.display()))?;
        if let Some(findings) = run_val.get("findings").and_then(|f| f.as_array()) {
            for (i, f) in findings.iter().enumerate() {
                let rule = f
                    .get("rule")
                    .and_then(|r| r.as_str())
                    .unwrap_or("")
                    .to_string();
                let target = f
                    .get("location")
                    .or_else(|| f.get("target"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                let title = f
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                let sev_str = f.get("severity").and_then(|s| s.as_str()).unwrap_or("high");
                let severity = match sev_str {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };

                let parts: Vec<&str> = target.split(':').collect();
                let file = parts.first().unwrap_or(&"").to_string();
                let line = parts
                    .get(1)
                    .and_then(|l| l.parse::<usize>().ok())
                    .unwrap_or(1);

                targets.push(TargetDefect {
                    id: format!("D-{:03}", i + 1),
                    rule,
                    severity,
                    file,
                    line,
                    title,
                    component: target.to_string(),
                    reproduction: None,
                });
            }
        }
    } else {
        // Run live AST code inventory
        let inv = crate::code_audit::audit_tree(repo);
        for (i, f) in inv.findings.iter().enumerate() {
            let parts: Vec<&str> = f.location.split(':').collect();
            let file = parts.first().unwrap_or(&"").to_string();
            let line = parts
                .get(1)
                .and_then(|l| l.parse::<usize>().ok())
                .unwrap_or(1);

            targets.push(TargetDefect {
                id: format!("D-{:03}", i + 1),
                rule: f.rule.clone(),
                severity: f.severity,
                file,
                line,
                title: f.title.clone(),
                component: f.location.clone(),
                reproduction: None,
            });
        }
    }

    if let Some(filt) = filter {
        let f_low = filt.to_ascii_lowercase();
        targets.retain(|t| {
            t.id.to_ascii_lowercase().contains(&f_low)
                || t.rule.to_ascii_lowercase().contains(&f_low)
                || t.title.to_ascii_lowercase().contains(&f_low)
                || t.file.to_ascii_lowercase().contains(&f_low)
        });
    }

    Ok(targets)
}

/// Locate a stored run by ID.
///
/// `readyhai scan` writes runs under the data directory (`engine::run_dir`), so that is where a
/// `--run` ID normally lives. A repo-local or CWD-relative `runs/<id>/run.json` is also accepted
/// for runs written there by older versions or by hand.
fn resolve_run_path(run_id: &str) -> anyhow::Result<PathBuf> {
    let candidates = [
        crate::engine::run_dir(run_id).join("run.json"),
        PathBuf::from("runs").join(run_id).join("run.json"),
    ];
    for path in &candidates {
        if path.is_file() {
            return Ok(path.clone());
        }
    }
    anyhow::bail!(
        "run '{run_id}' was not found. Looked in {} and {}. List stored runs with `readyhai dashboard`, \
         or omit --run to audit the working tree live.",
        candidates[0].display(),
        candidates[1].display()
    )
}
