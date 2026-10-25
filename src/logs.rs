//! Error/log clustering: normalize lines into signatures, group, redact examples.
use crate::model::ErrorCluster;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

const MAX_CLUSTERS: usize = 50;
const MAX_EXAMPLE: usize = 300;

struct Pats {
    ts: Regex,
    uuid: Regex,
    ipv4: Regex,
    ipv6: Regex,
    hex: Regex,
    quoted: Regex,
    num: Regex,
    ws: Regex,
    collapse: Regex,
    jwt: Regex,
    akia: Regex,
    bearer: Regex,
    kv: Regex,
    email: Regex,
    blob: Regex,
}

fn p() -> &'static Pats {
    static P: OnceLock<Pats> = OnceLock::new();
    P.get_or_init(|| {
        let r = |s: &str| Regex::new(s).expect("static regex");
        Pats {
            ts: r(r"\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
            uuid: r(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
            ipv4: r(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
            ipv6: r(r"(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b"),
            hex: r(r"(?i)\b(?:0x)?[0-9a-f]{8,}\b"),
            quoted: r(r#""[^"]*"|'[^']*'"#),
            num: r(r"\d+"),
            ws: r(r"\s+"),
            collapse: r(r"(?:<\*>[^\w<]{0,1}){2,}"),
            jwt: r(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
            akia: r(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            bearer: r(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
            kv: r(r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)(["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&]+)"#),
            email: r(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            blob: r(r"\b[A-Za-z0-9+_-]{33,}={0,2}"),
        }
    })
}

/// Mask secrets and PII in a log line.
pub fn redact(line: &str) -> String {
    let p = p();
    let s = p.jwt.replace_all(line, "[REDACTED]");
    let s = p.akia.replace_all(&s, "[REDACTED]");
    let s = p.bearer.replace_all(&s, "$1 [REDACTED]");
    let s = p.kv.replace_all(&s, "$1$2[REDACTED]");
    let s = p.email.replace_all(&s, "[EMAIL]");
    let s = p.blob.replace_all(&s, "[REDACTED]");
    s.into_owned()
}

fn timestamp(line: &str) -> Option<String> {
    p().ts.find(line).map(|m| m.as_str().to_string())
}

/// Normalized signature: variable parts replaced with `<*>`.
pub fn signature(line: &str) -> String {
    let p = p();
    let s = p.ts.replace_all(line, " ");
    let s = p.uuid.replace_all(&s, "<*>");
    let s = p.quoted.replace_all(&s, "<*>");
    let s = p.ipv4.replace_all(&s, "<*>");
    let s = p.ipv6.replace_all(&s, "<*>");
    let s = p.hex.replace_all(&s, "<*>");
    let s = p.num.replace_all(&s, "<*>");
    let s = p.collapse.replace_all(&s, "<*> ");
    let s = p.ws.replace_all(s.trim(), " ");
    s.to_lowercase()
}

/// (source, line) pairs → clusters sorted by count desc (max 50).
pub fn cluster(lines: &[(String, String)]) -> Vec<ErrorCluster> {
    let mut map: HashMap<(String, String), usize> = HashMap::new();
    let mut out: Vec<ErrorCluster> = vec![];
    for (i, (source, raw)) in lines.iter().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let sig = signature(raw);
        if sig.is_empty() {
            continue;
        }
        match map.get(&(source.clone(), sig.clone())) {
            Some(&idx) => out[idx].count += 1,
            None => {
                let ex: String = redact(raw).chars().take(MAX_EXAMPLE).collect();
                map.insert((source.clone(), sig.clone()), out.len());
                out.push(ErrorCluster {
                    signature: sig.chars().take(MAX_EXAMPLE).collect(),
                    example: ex,
                    count: 1,
                    source: source.clone(),
                    first_seen: timestamp(raw).unwrap_or_else(|| format!("#{}", i + 1)),
                });
            }
        }
    }
    // stable sort keeps first-seen order among ties
    out.sort_by(|a, b| b.count.cmp(&a.count));
    out.truncate(MAX_CLUSTERS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load() -> Vec<(String, String)> {
        include_str!("../tests/fixtures/logs/sample.log")
            .lines()
            .map(|l| ("host.log".to_string(), l.to_string()))
            .collect()
    }

    #[test]
    fn groups_connection_refused() {
        let c = cluster(&load());
        let top = &c[0];
        assert_eq!(top.count, 5, "{:?}", top);
        assert!(top.signature.contains("connection refused to <*>"));
        assert!(top.first_seen.starts_with("2026-10-20T10:00:01"));
    }

    #[test]
    fn groups_other_families() {
        let c = cluster(&load());
        let find = |s: &str| c.iter().find(|x| x.signature.contains(s)).unwrap_or_else(|| panic!("{s}: {c:#?}"));
        assert_eq!(find("invalid literal for int()").count, 2);
        assert_eq!(find("open()").count, 2);
        assert_eq!(find("failed to start worker-").count, 2);
    }

    #[test]
    fn redacts_secrets() {
        let c = cluster(&load());
        let a = c.iter().find(|x| x.example.contains("Auth failed")).unwrap();
        for bad in ["bob@example.com", "hunter2", "AKIAABCDEFGHIJKLMNOP", "abc.def.ghi"] {
            assert!(!a.example.contains(bad), "{bad} leaked: {}", a.example);
        }
        assert!(a.example.contains("[EMAIL]"));
        assert!(a.example.contains("[REDACTED]"));
        let jwt = "tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk x";
        assert!(!redact(jwt).contains("eyJhbGci"));
        assert!(!redact("blob 0123456789abcdef0123456789abcdef0123456789").contains("0123456789abcdef"));
    }

    #[test]
    fn caps_and_truncates() {
        let lines: Vec<(String, String)> =
            (0..80).map(|i| ("s".to_string(), format!("unique error kind{}x {}", "z".repeat(i), "y".repeat(500)))).collect();
        let c = cluster(&lines);
        assert!(c.len() <= 50);
        assert!(c.iter().all(|x| x.example.chars().count() <= 300));
    }
}
