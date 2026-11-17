use super::parsers::rel;
use super::types::JunitCase;
use crate::model::{Category, Finding, Severity, sha256_hex};
use anyhow::Result;
use serde_json::Value;

fn unescape(t: &str) -> String {
    t.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn attr(attrs: &str, name: &str) -> String {
    let re = regex::Regex::new(&format!(
        r#"(?:^|\s){}\s*=\s*(?:"([^"]*)"|'([^']*)')"#,
        regex::escape(name)
    ))
    .unwrap();
    re.captures(attrs)
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| unescape(m.as_str()))
        .unwrap_or_default()
}

pub fn parse_junit(xml: &str) -> Vec<JunitCase> {
    let case_re = regex::Regex::new(r"(?s)<testcase\b([^>]*?)(?:/>|>(.*?)</testcase>)").unwrap();
    let child_re = regex::Regex::new(r"(?s)<(failure|error|skipped)\b([^>]*?)(?:/>|>)").unwrap();
    let mut out = vec![];
    for c in case_re.captures_iter(xml) {
        let attrs = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = c.get(2).map(|m| m.as_str()).unwrap_or("");
        let mut case = JunitCase {
            suite: attr(attrs, "classname"),
            name: attr(attrs, "name"),
            failed: false,
            errored: false,
            skipped: false,
            message: String::new(),
        };
        for ch in child_re.captures_iter(body) {
            match &ch[1] {
                "failure" => case.failed = true,
                "error" => case.errored = true,
                _ => case.skipped = true,
            }
            if case.message.is_empty() {
                case.message = attr(&ch[2], "message");
            }
        }
        out.push(case);
    }
    out
}

pub fn parse_sarif(json: &str, check: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(json)?;
    let mut out = vec![];
    for run in v
        .get("runs")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        for r in run
            .get("results")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let rule = r.get("ruleId").and_then(|x| x.as_str()).unwrap_or("");
            let sev = match r.get("level").and_then(|x| x.as_str()).unwrap_or("") {
                "error" => Severity::High,
                "warning" => Severity::Medium,
                "note" => Severity::Low,
                "none" => Severity::Info,
                _ => Severity::Medium,
            };
            let msg = r
                .get("message")
                .and_then(|m| m.get("text"))
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let loc = r
                .get("locations")
                .and_then(|l| l.as_array())
                .and_then(|l| l.first())
                .and_then(|l| l.get("physicalLocation"));
            let (uri, line) = match loc {
                Some(p) => (
                    rel(p
                        .get("artifactLocation")
                        .and_then(|a| a.get("uri"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("")),
                    p.get("region")
                        .and_then(|g| g.get("startLine"))
                        .and_then(|x| x.as_u64()),
                ),
                None => (String::new(), None),
            };
            let location = match (uri.is_empty(), line) {
                (true, _) => "unknown".to_string(),
                (false, Some(l)) => format!("{uri}:{l}"),
                (false, None) => uri.clone(),
            };
            out.push(
                Finding::new(
                    check,
                    rule,
                    Category::Security,
                    sev,
                    super::parsers::first_line(msg, 200),
                    location,
                )
                .fp_key(format!("{uri}|{rule}|{}", &sha256_hex(msg.as_bytes())[..8])),
            );
        }
    }
    Ok(out)
}
