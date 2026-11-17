use serde::{Deserialize, Serialize};

use super::super::types::{CaseExecutionResult, PlannedCase};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserSecOutcome {
    pub added_cases: Vec<PlannedCase>,
    pub added_results: Vec<CaseExecutionResult>,
    pub source: &'static str,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserSecReport {
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub xss_hits: Vec<BrowserXssHit>,
    #[serde(default)]
    pub dom_sinks: Vec<BrowserDomSink>,
    #[serde(default)]
    pub storage_leaks: Vec<BrowserStorageLeak>,
    #[serde(default)]
    pub cookie_issues: Vec<BrowserCookieIssue>,
    #[serde(default)]
    pub sourcemaps: Vec<BrowserSourcemap>,
    #[serde(default)]
    pub clickjacking: Vec<BrowserClickjacking>,
    #[serde(default)]
    pub postmessage_issues: Vec<BrowserPostMessageIssue>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserXssHit {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub probe_url: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserDomSink {
    #[serde(default)]
    pub sink: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub sample: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserStorageLeak {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub store: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub preview: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserCookieIssue {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserSourcemap {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserClickjacking {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserPostMessageIssue {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub snippet: String,
}

pub(crate) fn path_of_url(raw: &str) -> String {
    if let Ok(u) = reqwest::Url::parse(raw) {
        let p = u.path();
        if p.is_empty() {
            "/".into()
        } else {
            p.into()
        }
    } else {
        let p = raw.split(['?', '#']).next().unwrap_or("/");
        if p.starts_with('/') {
            p.into()
        } else {
            format!("/{p}")
        }
    }
}

pub(crate) fn target_host_key(u: &reqwest::Url) -> String {
    let host = u.host_str().unwrap_or("localhost");
    match u.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

pub(crate) fn target_url_for_component(target: &str, component: &str) -> String {
    let base = target.trim_end_matches('/');
    if component.starts_with('/') {
        format!("{base}{component}")
    } else {
        format!("{base}/{component}")
    }
}
