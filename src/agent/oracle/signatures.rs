//! Security signatures, regex caches, auth wall detection, and leak patterns.

use regex::Regex;
use std::sync::OnceLock;

use super::super::types::RedirectHop;
use crate::qa::api::contract;

pub(crate) fn re(cell: &'static OnceLock<Regex>, p: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(p).unwrap())
}

/// A stack trace / SQL error / internal path in a response body: the QA engine's catalog
/// (`qa::api::contract::leak_kind`), worded for a report.
pub fn disclosure_signature(body: &str) -> Option<&'static str> {
    contract::leak_kind(body).map(contract::leak_description)
}

pub fn is_sensitive_path(component: &str) -> bool {
    let path = component
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if path.starts_with("/.well-known") {
        return false;
    }
    path.contains("/.")
        || [
            "phpinfo",
            "info.php",
            "secrets.json",
            "secrets.yml",
            "/actuator",
            "server-status",
            "wp-config",
            "id_rsa",
            ".bak",
            ".sql",
            ".old",
            "/debug",
        ]
        .iter()
        .any(|k| path.contains(k))
}

pub(crate) fn looks_like_secret_or_config(body: &str) -> bool {
    let head = body.trim_start();
    let lower = head
        .get(..head.len().min(64))
        .unwrap_or("")
        .to_ascii_lowercase();
    if lower.starts_with("<!") || lower.starts_with("<html") {
        return false;
    }
    let body_low = body.to_ascii_lowercase();
    static KV: OnceLock<Regex> = OnceLock::new();
    re(
        &KV,
        r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*\S",
    )
    .is_match(body)
        || body.contains("[core]")
        || body.contains("repositoryformatversion")
        || body.contains("ref: refs/")
        || body.contains("PHP Version")
        || body.contains("<?php")
        || body.contains("\"propertySources\"")
        || body.contains("\"cmdline\"")
        || body.contains("\"memstats\"")
        || body_low.contains("-- mysql dump")
        || body_low.contains("postgresql database dump")
        || body_low.contains("create table ")
        || body_low.contains("apache server status")
        || body_low.contains("aws_access_key_id")
        || crate::llm::redact_for_llm(body) != body
}

/// `/dashboard?next=/login` is not a login page and `/authors` is not an auth page). The one
/// matcher behind the authz oracle, the executor's auth-wall detection and the planner.
pub fn is_login_location(loc: &str) -> bool {
    let l = loc.trim().to_ascii_lowercase();
    let base = l.split(['?', '#']).next().unwrap_or("");
    let words: Vec<&str> = base
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let word = |w: &str| {
        w.contains("login")
            || w.contains("signin")
            || w.contains("oauth")
            || w.contains("openid")
            || matches!(w, "logon" | "sso" | "saml" | "auth" | "authn" | "adfs")
            || w.starts_with("authenticat")
            || w.starts_with("authoriz")
            // auth0, auth2 ... but not author, authors, authority
            || (w.starts_with("auth") && w[4..].chars().all(|c| c.is_ascii_digit()))
    };
    words.iter().any(|w| word(w)) || words.windows(2).any(|p| p[0] == "sign" && p[1] == "in")
}

/// Does an HTML body hold a password input: the page asks for credentials.
pub fn has_password_field(body: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r#"(?i)<input\b[^>]*\btype\s*=\s*["']?password"#).is_match(body)
}

/// Why a response says "you need to log in" and whether the page the case targeted was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WallSignal {
    /// What was seen, for the report ("HTTP 307 redirect to a login page (/login)").
    pub what: String,
    /// A redirect to a login page: the request never reached the page it targeted, whatever the
    /// final answer says.
    pub redirected: bool,
}

/// The auth-wall evidence in a response (the final one, after any same-origin redirects followed:
/// `chain`): a 401, a redirect to a login page, or a redirect that ended on a password form. None
/// when the response is not a wall. Whether it applies to a case (no credential was sent, the case
/// does not expect a denial) is the caller's call.
pub fn auth_wall_signal(
    status: u16,
    content_type: &str,
    headers: &[(String, String)],
    body: &str,
    chain: &[RedirectHop],
) -> Option<WallSignal> {
    let show = |loc: &str| crate::llm::untrusted::redact_then_truncate(loc, 120);
    if let Some(h) = chain.iter().find(|h| is_login_location(&h.location)) {
        return Some(WallSignal {
            what: format!(
                "HTTP {} redirect to a login page ({})",
                h.status,
                show(&h.location)
            ),
            redirected: true,
        });
    }
    if (300..=399).contains(&status)
        && let Some((_, loc)) = headers.iter().find(|(k, _)| k == "location")
        && is_login_location(loc)
    {
        return Some(WallSignal {
            what: format!("HTTP {status} redirect to a login page ({})", show(loc)),
            redirected: true,
        });
    }
    if status == 401 {
        return Some(WallSignal {
            what: "HTTP 401: the route requires credentials".into(),
            redirected: false,
        });
    }
    if (200..=299).contains(&status)
        && !chain.is_empty()
        && content_type.to_ascii_lowercase().contains("html")
        && has_password_field(body)
    {
        return Some(WallSignal {
            what: "the redirect ended on a page with a password form".into(),
            redirected: true,
        });
    }
    None
}

/// Server file content that only a traversal can have produced.
pub fn traversal_signature(body: &str) -> Option<&'static str> {
    static SIGS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let sigs =
        SIGS.get_or_init(|| {
            [
            (r"(?m)^root:[^:\r\n]*:0:0:", "the contents of /etc/passwd"),
            (r"(?m)^(?:daemon|bin|sys|nobody):[^:\r\n]*:\d+:\d+:", "the contents of /etc/passwd"),
            (
                r"(?i)\[(?:boot loader|fonts|extensions|mci extensions)\]|for 16-bit app support",
                "the contents of win.ini / boot.ini",
            ),
        ]
        .into_iter()
        .map(|(p, n)| (Regex::new(p).unwrap(), n))
        .collect()
        });
    sigs.iter().find(|(r, _)| r.is_match(body)).map(|(_, n)| *n)
}

pub(crate) fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn has_dom_xss_sink_flow(html: &str) -> Option<String> {
    static SCRIPT_RE: OnceLock<Regex> = OnceLock::new();
    static DIRECT_FLOW_RE: OnceLock<Regex> = OnceLock::new();
    static SRC_VAR_RE: OnceLock<Regex> = OnceLock::new();
    static SINK_ARG_RE: OnceLock<Regex> = OnceLock::new();

    let script_re = SCRIPT_RE.get_or_init(|| {
        Regex::new(r#"(?is)<script\b([^>]*)>(.*?)</script>"#).expect("valid script regex")
    });
    let direct_re = DIRECT_FLOW_RE.get_or_init(|| {
        Regex::new(r#"(?is)(?:\.(?:innerHTML|outerHTML)\s*(?:\+=|=)|document\.write(?:ln)?\s*\(|insertAdjacentHTML\s*\([^,]+,|eval\s*\()\s*[^;\n]{0,160}\b(?:location\.(?:hash|search|href)|window\.location(?:\.(?:hash|search|href))?|document\.(?:URL|documentURI|location)|URLSearchParams|window\.name)\b"#).expect("valid direct dom xss regex")
    });
    let src_var_re = SRC_VAR_RE.get_or_init(|| {
        Regex::new(r#"(?is)\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;\n]{0,140}\b(?:location\.(?:hash|search|href)|window\.location(?:\.(?:hash|search|href))?|document\.(?:URL|documentURI|location)|URLSearchParams|window\.name)\b"#).expect("valid src var regex")
    });
    let sink_arg_re = SINK_ARG_RE.get_or_init(|| {
        Regex::new(r#"(?is)(?:\.(?:innerHTML|outerHTML)\s*(?:\+=|=)|document\.write(?:ln)?\s*\(|insertAdjacentHTML\s*\([^,]+,|eval\s*\()\s*([^;\n]{1,120})"#).expect("valid sink arg regex")
    });

    for cap in script_re.captures_iter(html) {
        let attrs = cap
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if attrs.contains("application/json") || attrs.contains("application/ld+json") {
            continue;
        }
        let code = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        if code.trim().is_empty()
            || code.contains("DOMPurify.sanitize")
            || code.contains("sanitizeHtml")
        {
            continue;
        }
        if let Some(m) = direct_re.find(code) {
            return Some(m.as_str().trim().chars().take(120).collect());
        }
        let tainted_vars: Vec<&str> = src_var_re
            .captures_iter(code)
            .filter_map(|c| c.get(1).map(|v| v.as_str()))
            .collect();
        if !tainted_vars.is_empty() {
            for sc in sink_arg_re.captures_iter(code) {
                let rhs = sc.get(1).map(|m| m.as_str()).unwrap_or("");
                if tainted_vars.iter().any(|var| {
                    rhs.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
                        .any(|tok| tok == *var)
                }) {
                    return Some(
                        sc.get(0)
                            .map(|m| m.as_str())
                            .unwrap_or("")
                            .trim()
                            .chars()
                            .take(120)
                            .collect(),
                    );
                }
            }
        }
    }
    None
}
