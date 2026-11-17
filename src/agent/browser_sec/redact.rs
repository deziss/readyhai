use std::sync::OnceLock;
use regex::Regex;
use crate::llm::untrusted::redact_then_truncate;

fn jwt_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?").unwrap()
    })
}

/// Strictly mask any JWT/secret preview before storing in cases, results, or evidence files.
pub(crate) fn redact_secret_preview(raw: &str, kind: &str) -> String {
    let scrubbed = jwt_re().replace_all(raw, "[REDACTED_JWT]");
    let cleaned = redact_then_truncate(scrubbed.as_ref(), 80);
    if kind.eq_ignore_ascii_case("jwt")
        || cleaned.contains("[REDACTED_JWT]")
        || (!cleaned.contains("redacted") && !cleaned.contains("REDACTED") && raw.len() >= 12)
    {
        format!("[REDACTED kind={kind} len={}]", raw.len())
    } else {
        cleaned
    }
}
