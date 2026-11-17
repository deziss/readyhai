use serde_json::json;

use crate::agent::types::AgentRunReport;
use super::helpers::verdict_of;

pub fn sarif_level(sev: &str) -> &'static str {
    match sev.to_ascii_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

pub fn generate_agent_sarif_report(rep: &AgentRunReport) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = vec![];
    let mut results = vec![];
    for d in &rep.triaged_defects {
        let slug: String = d
            .owasp_category
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '-'
                }
            })
            .collect();
        let rule_id = format!("READYHAI-{}", slug.trim_matches('-'));
        let idx = match rules.iter().position(|r| r["id"] == rule_id) {
            Some(i) => i,
            None => {
                rules.push(json!({
                    "id": rule_id, "name": d.owasp_category, "shortDescription": {"text": d.owasp_category}, "fullDescription": {"text": d.recommended_fix},
                    "defaultConfiguration": {"level": sarif_level(&d.severity)}
                }));
                rules.len() - 1
            }
        };
        let mut result = json!({
            "ruleId": rule_id, "ruleIndex": idx, "level": sarif_level(&d.severity),
            "message": {"text": format!("{}: {}", d.title, d.recommended_fix)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": d.component}}}],
            "properties": {"defectId": d.id, "severity": d.severity, "priority": d.priority, "caseIds": d.case_ids, "evidenceFiles": d.evidence_files, "verified": d.verified, "reproduced": d.reproduced, "verification": d.verification, "flaky": d.flaky}
        });
        if !d.fingerprint.is_empty() {
            result["partialFingerprints"] = json!({"readyhai/v1": d.fingerprint});
        }
        if let Some(sc) = &d.source_context {
            result["properties"]["sourceContext"] = json!(sc);
        }
        if let Some(a) = &d.accepted {
            // an operator accepted it until `expires`: SARIF's own way to say "listed, not blocking"
            result["suppressions"] = json!([{
                "kind": "external", "status": "accepted",
                "justification": format!("accepted by {} until {}: {}", a.by, a.expires, a.reason)
            }]);
        }
        results.push(result);
    }
    let mut props = serde_json::Map::new();
    if let Some(ip) = rep.requester_ip.as_deref().filter(|s| !s.is_empty()) {
        props.insert("requesterIp".into(), ip.into());
    }
    if let Some(g) = rep.allowlist_guidance.as_deref().filter(|s| !s.is_empty()) {
        props.insert("allowlistGuidance".into(), g.into());
    }
    props.insert("gateVerdict".into(), verdict_of(rep).0.into());
    if let Some(v) = rep
        .evidence_ledger
        .as_ref()
        .and_then(|l| l.verification.as_ref())
    {
        props.insert(
            "verification".into(),
            json!({"k": v.k, "confirmed": v.confirmed, "flaky": v.flaky, "notReproduced": v.not_reproduced, "unverified": v.unverified, "passK": v.pass_k}),
        );
    }
    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ReadyHai Agent QA Gate", "version": env!("CARGO_PKG_VERSION"), "informationUri": "https://github.com/deziss/readyhai", "rules": rules}},
            "properties": props,
            "results": results
        }]
    })
}
