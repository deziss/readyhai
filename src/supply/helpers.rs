use crate::model::{Severity, TargetKind};
use serde_json::Value;

pub(crate) fn repo() -> Vec<TargetKind> {
    vec![TargetKind::Repo]
}

pub(crate) fn sv<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

pub(crate) fn src_rel(p: &str) -> String {
    let p = p.trim_start_matches("file://");
    let p = p.strip_prefix("/src/").unwrap_or(p);
    p.trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

pub(crate) fn lower(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}
