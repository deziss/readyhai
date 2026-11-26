//! Planning helper primitives: case constructors, keys, and template matching.

use super::super::exec::{Credentials, normalize_method};
use super::super::types::PlannedCase;

#[allow(clippy::too_many_arguments)]
pub(crate) fn mk(
    technique: &str,
    title: String,
    method: &str,
    component: String,
    hint: &str,
    payload: Option<String>,
    behavior: &str,
    status: Option<u16>,
    risk: &str,
    role: &str,
    source: &str,
) -> PlannedCase {
    PlannedCase {
        id: String::new(),
        title,
        component,
        // upper-cased at plan time: every later method check (dry-run included) sees one spelling
        method: normalize_method(method)
            .map(str::to_string)
            .unwrap_or_else(|| method.trim().to_ascii_uppercase()),
        technique: technique.to_string(),
        input_hint: hint.to_string(),
        payload,
        headers: vec![],
        content_type: None,
        probe_oracle: None,
        expected_behavior: behavior.to_string(),
        expected_status: status,
        risk_level: risk.to_string(),
        role: Some(role.to_string()),
        secured: None,
        route_status: None,
        expect_fields: vec![],
        expected_content_type: None,
        source: Some(source.to_string()),
        stateful_steps: None,
        concurrency_burst: None,
        contract: None,
        changed_ops: vec![],
        area: String::new(),
        regression_of: vec![],
        history_priority: false,
        intel_note: String::new(),
    }
}

/// The role ordinary authenticated cases run as: the acting credential (`Credentials::actor`), or
/// `anon` when there is none.
pub(crate) fn user_or_anon(creds: &Credentials) -> String {
    creds.actor().unwrap_or_else(|| "anon".to_string())
}

pub(crate) fn key_of(c: &PlannedCase) -> String {
    let mut hdrs: Vec<(String, &str)> = c
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
        .collect();
    hdrs.sort();
    let hdr_key = hdrs
        .into_iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(";");
    let probe_key = c
        .probe_oracle
        .as_ref()
        .map(|p| format!("{p:?}"))
        .unwrap_or_default();
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        c.method,
        c.component,
        c.technique,
        c.payload.as_deref().unwrap_or(""),
        c.role.as_deref().unwrap_or(""),
        c.content_type.as_deref().unwrap_or(""),
        hdr_key,
        probe_key
    )
}

pub(crate) fn template_regex(tpl: &str) -> Option<regex::Regex> {
    let mut re = String::from("^");
    let mut rest = tpl;
    while let Some(i) = rest.find('{') {
        re.push_str(&regex::escape(&rest[..i]));
        let j = rest[i..].find('}')? + i;
        re.push_str("[^/]+");
        rest = &rest[j + 1..];
    }
    re.push_str(&regex::escape(rest));
    re.push('$');
    regex::Regex::new(&re).ok()
}
