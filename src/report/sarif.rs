//! OASIS SARIF 2.1.0 report serialization.

use serde_json::{Value, json};

use crate::model::*;

use super::common::{is_component, status_str, uri_escape};

pub fn sarif(run: &Run) -> Value {
    let mut rule_ids: Vec<&str> = vec![];
    let mut rules = vec![];
    for f in &run.findings {
        if !rule_ids.contains(&f.rule.as_str()) {
            rule_ids.push(&f.rule);
            rules.push(json!({"id": f.rule, "shortDescription": {"text": f.title}}));
        }
    }
    let results: Vec<Value> = run
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                _ => "note",
            };
            let is_url = f.location.contains("://");
            // `location` is also a QA component ("GET /x", "GET /a, GET /b") or a journey name:
            // never a valid artifact URI. Those go to logicalLocations (and the message), file
            // paths and URLs to physicalLocation with every illegal URI character escaped.
            let component = !is_url && is_component(&f.location);
            let location = if component {
                json!({"logicalLocations": [{"name": f.location, "kind": "member"}]})
            } else if is_url {
                json!({"physicalLocation": {"artifactLocation": {"uri": uri_escape(&f.location)}}})
            } else {
                let mut phys = json!({"artifactLocation": {"uri": uri_escape(f.path())}});
                if let Some((_, l)) = f.location.rsplit_once(':')
                    && let Ok(n) = l.parse::<u64>()
                {
                    phys["region"] = json!({"startLine": n});
                }
                json!({"physicalLocation": phys})
            };
            let mut text = f.title.clone();
            if !f.detail.is_empty() {
                text = format!("{}: {}", f.title, f.detail);
            }
            if component {
                text = format!("{text} [{}]", f.location);
            }
            let mut r = json!({
                "ruleId": f.rule, "level": level, "message": {"text": text},
                "locations": [location],
                "partialFingerprints": {"readyhai/v1": f.fingerprint},
                "properties": {"severity": f.severity.as_str(), "category": f.category.as_str(),
                    "status": status_str(f.status), "kev": f.kev, "epss": f.epss},
            });
            if f.status == FindingStatus::Suppressed {
                r["suppressions"] = json!([{"kind": "external",
                    "justification": f.suppressed_reason.clone().unwrap_or_default()}]);
            }
            r
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "readyhai", "version": run.version,
                "informationUri": "https://github.com/deziss/readyhai", "rules": rules}},
            "results": results,
        }]
    })
}
