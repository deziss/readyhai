//! Shared formatting, ordering, and escaping utilities for report generation.

use crate::model::{FindingStatus, Severity};

pub fn sev_order(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

pub fn status_str(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::New => "new",
        FindingStatus::Existing => "existing",
        FindingStatus::Suppressed => "suppressed",
    }
}

/// `GET /x`, `POST /orders/{id}`, `GET /a, GET /b`: an HTTP operation, not a file.
pub fn is_component(loc: &str) -> bool {
    const M: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    loc.split_once(' ')
        .is_some_and(|(m, rest)| M.contains(&m) && rest.trim_start().starts_with(['/', '{', '*']))
}

/// Percent-escape what a URI reference may not contain (spaces, quotes, `<>`, `{}`, controls,
/// non-ASCII, a stray `%`); everything else (including `?#&=:/@[]`) is kept as is.
pub fn uri_escape(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = String::with_capacity(s.len());
    for (i, &c) in b.iter().enumerate() {
        let keep = c.is_ascii_alphanumeric()
            || b"-._~:/?#[]@!$&'()*+,;=".contains(&c)
            || (c == b'%'
                && i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit());
        if keep {
            o.push(c as char);
        } else {
            o.push_str(&format!("%{c:02X}"));
        }
    }
    o
}

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c if (c as u32) < 0x20 && !matches!(c, '\n' | '\r' | '\t') => {}
            c => o.push(c),
        }
    }
    o
}
