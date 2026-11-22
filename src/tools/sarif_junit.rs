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

/// Why one SARIF `run` (index `i`) cannot be treated as a complete scan.
///
/// SARIF 2.1.0 §3.13.4 lets a tool say `executionSuccessful: false` and §3.14 lets it attach
/// error notifications, all in a document that parses fine whose `results` array is legitimately
/// empty. Missing `invocations` is *unknown* status, not a failure, so it stays silent: only an
/// explicit negative is reported, which keeps honest minimal SARIF from being flagged.
fn run_incompleteness(run: &Value, i: usize) -> Vec<String> {
    let notifications = run
        .get("invocations")
        .and_then(|x| x.as_array())
        .map(|invs| {
            invs.iter()
                .flat_map(|inv| {
                    inv.get("toolExecutionNotifications")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let fatal_note = notifications.iter().find_map(|n| {
        let failed = matches!(n.get("level").and_then(|x| x.as_str()), Some("error"));
        let threw = n.get("exception").is_some();
        if !(failed || threw) {
            return None;
        }
        let msg = n
            .get("message")
            .and_then(|m| m.get("text"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim();
        Some(if msg.is_empty() {
            "no message".to_string()
        } else {
            super::parsers::first_line(msg, 200)
        })
    });
    let mut notes = vec![];
    let failed_run = run
        .get("invocations")
        .and_then(|x| x.as_array())
        .is_some_and(|invs| {
            invs.iter().any(|inv| {
                inv.get("executionSuccessful").and_then(|x| x.as_bool()) == Some(false)
            })
        });
    if failed_run {
        notes.push(match &fatal_note {
            Some(m) => format!("run {i}: tool reported executionSuccessful=false ({m})"),
            None => format!("run {i}: tool reported executionSuccessful=false"),
        });
    } else if let Some(m) = &fatal_note {
        notes.push(format!("run {i}: tool reported an error notification ({m})"));
    }
    notes
}

/// Findings plus **incomplete-run notes** from one SARIF document.
///
/// A note means coverage is unknown, so the caller must report `CheckStatus::Partial`: a scan
/// whose tool errored can warn or fail the gate, but can never green-light it.
pub fn parse_sarif_report(json: &str, check: &str) -> Result<(Vec<Finding>, Vec<String>)> {
    let v: Value = serde_json::from_str(json)?;
    let mut out = vec![];
    let mut notes = vec![];
    let runs: Vec<Value> = v
        .get("runs")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    if runs.is_empty() {
        notes.push("SARIF document has no runs: no tool output to trust".to_string());
    }
    for (i, run) in runs.iter().enumerate() {
        notes.extend(run_incompleteness(run, i));
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
    Ok((out, notes))
}

