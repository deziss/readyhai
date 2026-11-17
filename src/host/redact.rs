//! Secret and credential redaction for host command logs and error streams.
use regex::Regex;
use std::sync::OnceLock;

fn re(cell: &'static OnceLock<Regex>, p: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(p).expect("static regex"))
}

/// Mask obvious secrets in a log line (password=..., token=..., bearer ..., AWS key ids,
/// URL credentials, long hex/base64 blobs).
pub fn redact_line(line: &str) -> String {
    static KV: OnceLock<Regex> = OnceLock::new();
    static BEARER: OnceLock<Regex> = OnceLock::new();
    static AKIA: OnceLock<Regex> = OnceLock::new();
    static URLC: OnceLock<Regex> = OnceLock::new();
    static LONG: OnceLock<Regex> = OnceLock::new();
    let s = re(
        &KV,
        r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(["']?\s*[=:]\s*["']?)[^\s"',;&]+"#,
    )
    .replace_all(line, "${1}${2}[REDACTED]");
    let s = re(&BEARER, r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}")
        .replace_all(&s, "${1} [REDACTED]");
    let s = re(&AKIA, r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").replace_all(&s, "[REDACTED]");
    let s = re(&URLC, r"://[^/\s:@]+:[^@\s]+@").replace_all(&s, "://[REDACTED]@");
    let s = re(&LONG, r"[A-Za-z0-9+/_=-]{33,}").replace_all(&s, |c: &regex::Captures| {
        let t = &c[0];
        let pathlike = t.matches('/').count() > 2;
        let has_digit = t.chars().any(|c| c.is_ascii_digit());
        let has_alpha = t.chars().any(|c| c.is_ascii_alphabetic());
        if !pathlike && has_digit && has_alpha {
            "[REDACTED]".to_string()
        } else {
            t.to_string()
        }
    });
    s.into_owned()
}
