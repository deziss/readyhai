//! HTML report generator with strict CSP and zero external JavaScript.

use anyhow::Result;
use minijinja::value::Serde;
use minijinja::{AutoEscape, Environment};
use serde_json::{json, Value};

use crate::model::*;

use super::common::{sev_order, status_str};

pub fn html(run: &Run) -> Result<String> {
    let mut env = Environment::new();
    env.set_auto_escape_callback(|_| AutoEscape::Html);
    env.add_template(
        "report.html.j2",
        include_str!("../../templates/report.html.j2"),
    )?;
    let mut sorted: Vec<&Finding> = run.findings.iter().collect();
    sorted.sort_by_key(|f| {
        (
            sev_order(f.severity),
            match f.status {
                FindingStatus::New => 0,
                FindingStatus::Existing => 1,
                FindingStatus::Suppressed => 2,
            },
        )
    });
    let mut groups: Vec<Value> = vec![];
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let items: Vec<Value> = sorted
            .iter()
            .filter(|f| f.severity == sev)
            .map(|f| {
                json!({
                    "severity": f.severity.as_str(), "title": f.title, "rule": f.rule, "check": f.check,
                    "category": f.category.as_str(), "location": f.location, "ids": f.ids,
                    "package": f.package, "version": f.version, "fix_version": f.fix_version,
                    "epss": f.epss.map(|e| format!("{:.1}%", e * 100.0)), "kev": f.kev,
                    "detail": f.detail, "remediation": f.remediation,
                    "status": status_str(f.status), "suppressed_reason": f.suppressed_reason,
                })
            })
            .collect();
        if !items.is_empty() {
            groups.push(json!({"severity": sev.as_str(), "items": items}));
        }
    }
    let checks: Vec<Value> = run
        .checks
        .iter()
        .map(|c| {
            json!({"id": c.id, "title": c.title, "tool": c.tool, "status": c.status.label(),
                   "reason": c.status.reason().unwrap_or(""), "findings": c.findings, "duration_ms": c.duration_ms})
        })
        .collect();
    let (verdict, class) = match run.verdict {
        Verdict::Pass => ("PASS", "pass"),
        Verdict::Warn => ("WARN", "warn"),
        Verdict::Fail => ("FAIL", "fail"),
    };
    let ctx = json!({
        "verdict": verdict, "verdict_class": class, "reasons": run.reasons,
        "target": run.target.raw, "kind": format!("{:?}", run.target.kind).to_lowercase(),
        "profile": format!("{:?}", run.profile).to_lowercase(), "run_id": run.id,
        "started": run.started, "finished": run.finished, "version": run.version,
        "fixed": run.fixed, "categories": run.categories, "checks": checks,
        "groups": groups, "finding_count": run.findings.len(), "notes": run.notes,
        "errors": run.errors.iter().map(|e| json!({"count": e.count, "source": e.source, "signature": e.signature, "example": e.example, "first_seen": e.first_seen})).collect::<Vec<_>>(),
    });
    Ok(env.get_template("report.html.j2")?.render(Serde(&ctx))?)
}
