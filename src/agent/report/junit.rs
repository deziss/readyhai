use std::collections::BTreeMap;

use crate::agent::types::{AgentRunReport, CaseExecutionResult};
use super::helpers::{verdict_of, xml_escape};

pub fn generate_agent_junit_report(rep: &AgentRunReport) -> String {
    let rs = &rep.executed_results;
    // failing cases of a defect an operator accepted (unexpired) are reported as skipped, with why
    let accepted: BTreeMap<&str, &crate::agent::memory::Acceptance> = rep
        .triaged_defects
        .iter()
        .filter_map(|d| d.accepted.as_ref().map(|a| (d, a)))
        .flat_map(|(d, a)| d.case_ids.iter().map(move |c| (c.as_str(), a)))
        .collect();
    let is_accepted =
        |c: &CaseExecutionResult| c.status == "FAIL" && accepted.contains_key(c.case_id.as_str());
    let failures = rs
        .iter()
        .filter(|c| c.status == "FAIL" && !is_accepted(c))
        .count();
    let errors = rs.iter().filter(|c| c.status == "BLOCKED").count();
    let skipped = rs
        .iter()
        .filter(|c| c.status == "SKIPPED" || c.status == "INCONCLUSIVE" || is_accepted(c))
        .count();
    let time: f64 = rs.iter().map(|c| c.latency_ms as f64 / 1000.0).sum();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"ReadyHai QA Agent\" tests=\"{}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\" time=\"{time:.3}\">\n",
        rs.len()
    );
    let mut sysout = vec![format!("gate verdict: {}", verdict_of(rep).0)];
    if let Some(ip) = rep.requester_ip.as_deref().filter(|s| !s.is_empty()) {
        sysout.push(format!("requester egress IP: {ip}"));
    }
    if let Some(g) = rep.allowlist_guidance.as_deref().filter(|s| !s.is_empty()) {
        sysout.push(format!("allowlist guidance: {g}"));
    }
    xml.push_str(&format!(
        "  <system-out>{}</system-out>\n",
        xml_escape(&sysout.join("\n"))
    ));
    for c in rs {
        let name = xml_escape(&format!("{}: {}", c.case_id, c.title));
        let class = xml_escape(&c.technique);
        let time = c.latency_ms as f64 / 1000.0;
        let reason = c.failure_reason.as_deref().unwrap_or("");
        let body = match c.status.as_str() {
            "FAIL" if is_accepted(c) => {
                let a = accepted[c.case_id.as_str()];
                format!(
                    "<skipped message=\"{}\"/>",
                    xml_escape(&format!(
                        "accepted defect, does not block: by {} until {}: {}",
                        a.by, a.expires, a.reason
                    ))
                )
            }
            "FAIL" => format!(
                "<failure message=\"{}\" type=\"{}\">{}</failure>",
                xml_escape(if reason.is_empty() {
                    "assertion failed"
                } else {
                    reason
                }),
                xml_escape(
                    c.oracle
                        .as_ref()
                        .and_then(|o| o.first_fail())
                        .map(|k| k.code.as_str())
                        .unwrap_or("assertion")
                ),
                xml_escape(&c.reproduction_curl)
            ),
            "BLOCKED" => format!(
                "<error message=\"{}\" type=\"transport\">{}</error>",
                xml_escape(reason),
                xml_escape(&c.reproduction_curl)
            ),
            "SKIPPED" => format!("<skipped message=\"{}\"/>", xml_escape(reason)),
            "INCONCLUSIVE" => format!(
                "<skipped message=\"{}\"/>",
                xml_escape(&format!("inconclusive: {reason}"))
            ),
            _ if !reason.is_empty() => format!("<system-out>{}</system-out>", xml_escape(reason)),
            _ => String::new(),
        };
        if body.is_empty() {
            xml.push_str(&format!(
                "  <testcase classname=\"{class}\" name=\"{name}\" time=\"{time:.3}\"/>\n"
            ));
        } else {
            xml.push_str(&format!("  <testcase classname=\"{class}\" name=\"{name}\" time=\"{time:.3}\">\n    {body}\n  </testcase>\n"));
        }
    }
    xml.push_str("</testsuite>\n");
    xml
}
