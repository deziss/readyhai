use crate::qa::model::{Defect, Priority, QaReport, Recommendation};

pub(crate) fn lc<T: std::fmt::Debug>(v: &T) -> String {
    format!("{v:?}").to_lowercase()
}

pub(crate) fn rec_text(r: Recommendation) -> (&'static str, &'static str) {
    match r {
        Recommendation::Go => ("GO", "go"),
        Recommendation::ConditionalGo => ("CONDITIONAL GO", "cgo"),
        Recommendation::NoGo => ("NO-GO", "nogo"),
        // shares the red badge: no evidence is never a pass
        Recommendation::Inconclusive => ("INCONCLUSIVE", "nogo"),
    }
}

pub(crate) fn prio_str(p: Priority) -> &'static str {
    match p {
        Priority::P1 => "P1",
        Priority::P2 => "P2",
        Priority::P3 => "P3",
        Priority::P4 => "P4",
    }
}

pub fn jira_priority(p: Priority) -> &'static str {
    match p {
        Priority::P1 => "Highest",
        Priority::P2 => "High",
        Priority::P3 => "Medium",
        Priority::P4 => "Low",
    }
}

pub(crate) fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::with_capacity(data.len() * 4 / 3 + 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        o.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    o
}

/// Spreadsheet formula injection: a cell that starts with = + - @ (or TAB / CR) is evaluated by
/// Excel / LibreOffice / Sheets. Defect text comes from specs and pages we do not control, so
/// such a cell is prefixed with an apostrophe (the OWASP-recommended neutralisation).
pub fn csv_neutralize(s: &str) -> std::borrow::Cow<'_, str> {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        std::borrow::Cow::Owned(format!("'{s}"))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// RFC 4180 field quoting (after formula neutralisation).
pub fn csv_field(s: &str) -> String {
    let s = csv_neutralize(s);
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.into_owned()
    }
}

/// Escape text for INLINE Markdown (GitHub/GitLab flavour): one line, no emphasis / links /
/// images / raw HTML / tables / headings / list markers, and no @mention pings. Defect text comes
/// from spec and page sources, so nothing in it may become markup.
pub fn md_inline(s: &str) -> String {
    let one: String = s
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let chars: Vec<char> = one.trim().chars().collect();
    let mut o = String::with_capacity(chars.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        let alnum = |j: Option<usize>| {
            j.and_then(|j| chars.get(j))
                .map(|x| x.is_alphanumeric())
                .unwrap_or(false)
        };
        match c {
            '\\' | '`' | '*' | '[' | ']' | '<' | '>' | '|' | '~' => {
                o.push('\\');
                o.push(c);
            }
            // intraword underscores (snake_case, $RH_USER_TOKEN) are plain text in CommonMark
            '_' if !(alnum(i.checked_sub(1)) && alnum(Some(i + 1))) => {
                o.push('\\');
                o.push(c);
            }
            '#' | '-' | '+' if i == 0 => {
                o.push('\\');
                o.push(c);
            }
            '@' => o.push_str("@\u{200B}"),
            _ => o.push(c),
        }
    }
    // "1. text" at the start would become an ordered list
    if let Some(d) = o.find(|c: char| !c.is_ascii_digit())
        && d > 0
        && o[d..].starts_with(['.', ')'])
    {
        o.insert(d, '\\');
    }
    o
}

/// Multi-line text as Markdown paragraphs: each line escaped, hard line breaks kept.
pub fn md_lines(s: &str) -> String {
    s.lines().map(md_inline).collect::<Vec<_>>().join("  \n")
}

/// A fenced code block whose fence is longer than any backtick run in `body`, so the content can
/// never close it early (a spec value containing ``` stays inside the block).
pub fn md_fence(body: &str, lang: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in body.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let f = "`".repeat((longest + 1).max(3));
    format!("{f}{lang}\n{}\n{f}\n", body.trim_end_matches('\n'))
}

/// Escape text for Jira wiki markup (inline).
pub fn jira_text(s: &str) -> String {
    let one: String = s
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let t = one.trim();
    let chars: Vec<char> = t.chars().collect();
    let mut o = String::with_capacity(t.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        let prev_ws = i == 0 || chars[i - 1].is_whitespace();
        let next_nonws = chars
            .get(i + 1)
            .map(|n| !n.is_whitespace())
            .unwrap_or(false);
        match c {
            '\\' | '{' | '}' | '[' | ']' | '|' | '*' | '_' | '^' | '~' => {
                o.push('\\');
                o.push(c);
            }
            // -strike- / +underline+ / !image! / ??cite?? / list markers only start at a word boundary
            '-' | '+' | '#' | '!' | '?' if prev_ws && (next_nonws || i == 0) => {
                o.push('\\');
                o.push(c);
            }
            _ => o.push(c),
        }
    }
    // headings / block quotes must start a line
    let lower = o.to_ascii_lowercase();
    let heading = lower.len() > 2
        && lower.starts_with('h')
        && lower.as_bytes()[1].is_ascii_digit()
        && lower[2..].starts_with('.');
    if heading || lower.starts_with("bq.") {
        o.insert(0, ' ');
    }
    o
}

/// Body of a Jira `{code}` block: only the closing macro matters, neutralise every `{code`.
pub fn jira_code(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.to_ascii_lowercase().find("{code") {
        out.push_str(&rest[..i]);
        out.push_str("{ code");
        rest = &rest[i + 5..];
    }
    out.push_str(rest);
    out
}

pub(crate) fn csv_row(fields: &[String]) -> String {
    let mut l = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    l.push_str("\r\n");
    l
}

pub(crate) fn defects_sorted(q: &QaReport) -> Vec<&Defect> {
    let mut d: Vec<&Defect> = q.defects.iter().collect();
    d.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(b.severity.cmp(&a.severity))
            .then(a.id.cmp(&b.id))
    });
    d
}

pub(crate) fn looks_like_code(s: &str) -> bool {
    let t = s.trim_start();
    t.starts_with("curl")
        || t.starts_with("npx")
        || t.starts_with("await ")
        || t.contains('\n')
        || t.starts_with("$ ")
}

pub(crate) fn status_label(s: crate::model::FindingStatus) -> &'static str {
    match s {
        crate::model::FindingStatus::New => "new",
        crate::model::FindingStatus::Existing => "existing",
        crate::model::FindingStatus::Suppressed => "suppressed",
    }
}
