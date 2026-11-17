//! Sanitizing functions and date utilities for memory data.

use sha2::{Digest, Sha256};
use std::path::Path;

use super::types::{MAX_ENDPOINT, MAX_IDENT};
use crate::agent::triage::{endpoint_template, path_of};

pub(crate) fn ident_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '/' | '_'
                | '-'
                | '.'
                | '{'
                | '}'
                | '~'
                | ':'
                | '@'
                | '+'
                | ','
                | ';'
                | '='
                | '*'
                | '%'
                | '('
                | ')'
                | '['
                | ']'
                | ' '
        )
}

/// A target-derived identifier (an endpoint, a check code) reduced to a conservative ASCII set,
/// whitespace collapsed, at most `max` characters. `|` (the key separator), quotes, angle brackets,
/// backslashes, control and non-ASCII characters all become `_`.
pub fn clean_ident(s: &str, max: usize) -> String {
    clean_chars(s, max, false)
}

/// [`clean_ident`] that keeps `|`: for a case class key (`technique|METHOD|endpoint|role`).
pub fn clean_class(s: &str) -> String {
    clean_chars(s, MAX_ENDPOINT + 64, true)
}

pub(crate) fn clean_chars(s: &str, max: usize, keep_pipe: bool) -> String {
    let mut out = String::new();
    let mut last_space = false;
    for c in s.trim().chars() {
        let c = if ident_char_ok(c) || (keep_pipe && c == '|') {
            c
        } else {
            '_'
        };
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        out.push(c);
        if out.len() >= max {
            break;
        }
    }
    out
}

/// Operator text (who accepted, why): control characters dropped, whitespace collapsed, capped.
pub fn clean_text(s: &str, max: usize) -> String {
    let t: String = s
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control())
        .collect();
    t.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

pub(crate) fn clean_method(m: &str) -> String {
    let u = m.trim().to_ascii_uppercase();
    if matches!(
        u.as_str(),
        "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE" | "TRACE" | "CONNECT"
    ) {
        u
    } else {
        "OTHER".into()
    }
}

pub(crate) fn clean_severity(s: &str) -> String {
    let l = s.trim().to_ascii_lowercase();
    if matches!(l.as_str(), "critical" | "high" | "medium" | "low" | "info") {
        l
    } else {
        "medium".into()
    }
}

pub(crate) fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// The endpoint a component belongs to: query dropped, record ids collapsed to `{id}`, sanitized.
pub fn clean_endpoint(component: &str) -> String {
    clean_ident(&endpoint_template(path_of(component)), MAX_ENDPOINT)
}

/// Identity of a defect: `sha256(rule NUL endpoint)`, 24 hex characters (the same shape as a scan
/// finding's fingerprint).
pub fn fingerprint(rule: &str, endpoint: &str) -> String {
    let mut h = Sha256::new();
    h.update(clean_ident(rule, MAX_IDENT).as_bytes());
    h.update([0u8]);
    h.update(clean_ident(endpoint, MAX_ENDPOINT).as_bytes());
    hex::encode(h.finalize())[..24].to_string()
}

pub(crate) fn valid_fingerprint(s: &str) -> bool {
    s.len() == 24 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------- dates

/// Days since 1970-01-01 of a valid `YYYY-MM-DD` (a real calendar date, year 1970..=9999).
pub fn parse_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.chars()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || d < 1 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match m {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if d > dim {
        return None;
    }
    // days from civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Whole days from `from` to `to` (negative when `to` is earlier); None for an invalid date.
pub fn days_between(from: &str, to: &str) -> Option<i64> {
    Some(parse_date(to)? - parse_date(from)?)
}

/// `YYYY-MM-DD` of a file's modification time.
pub(crate) fn file_date(p: &Path) -> Option<String> {
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    let dt = time::OffsetDateTime::from(t);
    dt.format(&time::macros::format_description!("[year]-[month]-[day]"))
        .ok()
}
