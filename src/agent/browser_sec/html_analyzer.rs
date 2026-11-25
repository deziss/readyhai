use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use super::models::{path_of_url, target_host_key};
use crate::agent::budget::RunBudget;
use crate::agent::discover::Discovery;
use crate::agent::exec::{Auth, Clients, ExecOptions, OutReq, resolve_auth};
use crate::agent::oracle::is_login_location;
use crate::agent::types::CaseExecutionResult;

const MAX_HTML_PEEKS: usize = 6;

pub(crate) fn is_danger_route(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    [
        "/delete",
        "/remove",
        "/destroy",
        "/drop",
        "/reset",
        "/purge",
        "/truncate",
        "/logout",
        "/signout",
    ]
    .iter()
    .any(|kw| low.contains(kw))
}

pub(crate) fn looks_like_api_or_static(path: &str) -> bool {
    let low = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if low.starts_with("/api/")
        || low == "/api"
        || low.starts_with("/graphql")
        || low.starts_with("/_")
    {
        return true;
    }
    [
        ".json", ".xml", ".yaml", ".yml", ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".map", ".txt",
    ]
    .iter()
    .any(|ext| low.ends_with(ext))
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedHtmlForm {
    pub(crate) action_path: String,
    pub(crate) field_names: Vec<String>,
    pub(crate) hidden_fields: Vec<(String, String)>,
}

fn attr_value(tag: &str, name: &str) -> Option<String> {
    static PATS: std::sync::Mutex<Option<BTreeMap<String, Regex>>> = std::sync::Mutex::new(None);
    let mut guard = PATS.lock().ok()?;
    let map = guard.get_or_insert_with(BTreeMap::new);
    let key = name.to_ascii_lowercase();
    let re = map.entry(key.clone()).or_insert_with(|| {
        Regex::new(&format!(
            r#"(?is)\b{key}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+))"#
        ))
        .unwrap()
    });
    let caps = re.captures(tag)?;
    caps.get(1)
        .or_else(|| caps.get(2))
        .or_else(|| caps.get(3))
        .map(|m| m.as_str().trim().to_string())
}

fn resolve_same_origin_action(target: &str, page_path: &str, action: &str) -> Option<String> {
    let base = reqwest::Url::parse(target).ok()?;
    let page_url = base.join(page_path).ok()?;
    let trimmed = action.trim();
    let dest = if trimmed.is_empty() {
        page_url
    } else {
        page_url.join(trimmed).ok()?
    };
    if dest.origin() != base.origin() {
        return None;
    }
    let p = dest.path().to_string();
    Some(if p.is_empty() { "/".into() } else { p })
}

/// Extract non-password, non-destructive HTML `<form method="post">` definitions for Stored XSS checks.
pub(crate) fn extract_post_html_forms(
    target: &str,
    page_path: &str,
    html: &str,
) -> Vec<ParsedHtmlForm> {
    static FORM_RE: OnceLock<Regex> = OnceLock::new();
    static CTRL_RE: OnceLock<Regex> = OnceLock::new();
    let form_re = FORM_RE.get_or_init(|| Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form>").unwrap());
    let ctrl_re = CTRL_RE.get_or_init(|| Regex::new(r"(?is)<(input|textarea)\b([^>]*)>").unwrap());

    let mut out = Vec::new();
    for cap in form_re.captures_iter(html) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let inner = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let method = attr_value(attrs, "method")
            .unwrap_or_else(|| "get".into())
            .to_ascii_lowercase();
        if method != "post" {
            continue;
        }
        let action_raw = attr_value(attrs, "action").unwrap_or_default();
        let Some(action_path) = resolve_same_origin_action(target, page_path, &action_raw) else {
            continue;
        };
        if is_login_location(&action_path) || is_danger_route(&action_path) {
            continue;
        }

        let mut has_password = false;
        let mut field_names = Vec::new();
        let mut hidden_fields = Vec::new();

        for ctrl in ctrl_re.captures_iter(inner) {
            let tag = ctrl
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let cattrs = ctrl.get(2).map(|m| m.as_str()).unwrap_or("");
            let input_type = attr_value(cattrs, "type")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if input_type == "password" {
                has_password = true;
                break;
            }
            let Some(name) = attr_value(cattrs, "name").filter(|n| !n.is_empty()) else {
                continue;
            };
            if tag == "textarea" {
                field_names.push(name);
            } else if input_type == "hidden" {
                let val = attr_value(cattrs, "value").unwrap_or_default();
                hidden_fields.push((name, val));
            } else if matches!(
                input_type.as_str(),
                "" | "text" | "search" | "email" | "url" | "tel"
            ) {
                field_names.push(name);
            }
        }
        if has_password || field_names.is_empty() {
            continue;
        }
        out.push(ParsedHtmlForm {
            action_path,
            field_names,
            hidden_fields,
        });
    }
    out
}

pub(crate) fn form_urlencoded_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub(crate) fn collect_html_snapshots(
    target: &str,
    disc: &Discovery,
    exec_opts: &ExecOptions,
    budget: &mut RunBudget,
    existing_results: &[CaseExecutionResult],
) -> BTreeMap<String, String> {
    let mut html_by_path: BTreeMap<String, String> = BTreeMap::new();

    // Reuse HTML already observed during discovery/Wave 1-2 first.
    for r in existing_results {
        let p = path_of_url(&r.component);
        if is_login_location(&p) || is_danger_route(&p) || r.blocked_reason.is_some() {
            continue;
        }
        let ct_html = r
            .content_type
            .as_deref()
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("html"));
        let status_ok = r.status_code.is_some_and(|s| (200..300).contains(&s));
        if !ct_html || !status_ok || r.is_spa_shell {
            continue;
        }
        if let Some(excerpt) = r
            .evidence_detail
            .as_ref()
            .and_then(|d| d.get("response"))
            .and_then(|resp| resp.get("body_excerpt"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            html_by_path.entry(p).or_insert_with(|| excerpt.to_string());
        }
    }

    // Collect non-API, non-login, non-catchall GET HTML route candidates.
    let mut peek_paths: Vec<String> = Vec::new();
    let mut seen_peek: HashSet<String> = HashSet::new();
    for r in &disc.routes {
        if r.catch_all || !r.method.eq_ignore_ascii_case("GET") {
            continue;
        }
        let p = path_of_url(&r.path);
        if p.contains('{')
            || is_login_location(&p)
            || is_danger_route(&p)
            || looks_like_api_or_static(&p)
        {
            continue;
        }
        // Only peek routes that either are already known HTML routes or appear browser-facing.
        let known_html = html_by_path.contains_key(&p)
            || r.content_type.to_ascii_lowercase().contains("html")
            || (r.content_type.is_empty() && (200..300).contains(&r.status_code));
        // Skip routes where earlier runs saw an auth wall / non-HTML answer.
        let blocked_or_json = existing_results.iter().any(|res| {
            path_of_url(&res.component) == p
                && (res.blocked_reason.is_some()
                    || res.is_spa_shell
                    || res
                        .content_type
                        .as_deref()
                        .is_some_and(|ct| ct.to_ascii_lowercase().contains("json")))
        });
        if known_html && !blocked_or_json && seen_peek.insert(p.clone()) {
            peek_paths.push(p);
        }
    }
    peek_paths.truncate(MAX_HTML_PEEKS);

    if peek_paths.is_empty() {
        return html_by_path;
    }

    let Ok(base_url) = reqwest::Url::parse(target) else {
        return html_by_path;
    };
    let Ok(clients) = Clients::new(exec_opts.timeout, &base_url) else {
        return html_by_path;
    };
    let host_key = target_host_key(&base_url);
    let auth = match exec_opts.credentials.actor() {
        Some(role) => resolve_auth(&Auth::Role(role), &exec_opts.credentials),
        None => resolve_auth(&Auth::None, &exec_opts.credentials),
    };

    for p in peek_paths {
        // Need full HTML body because evidence excerpts cut at ~400 bytes, while `<form>` / `<script>` can follow later.
        if budget.requests_left() <= 16 || budget.is_cancelled() {
            break;
        }
        if budget.take_request(&host_key).is_err() {
            break;
        }
        let Ok(u) = base_url.join(&p) else {
            continue;
        };
        let req = OutReq {
            method: "GET",
            url: u.as_str(),
            body: None,
            headers: &[],
            bearer: auth.bearer.as_ref(),
        };
        if let Ok(followed) =
            clients.send_following(&req, 2, &mut || budget.take_request(&host_key))
        {
            let seen = followed.seen;
            if (200..300).contains(&seen.status)
                && seen.content_type.to_ascii_lowercase().contains("html")
                && !crate::agent::oracle::has_password_field(&seen.body)
            {
                html_by_path.insert(p, seen.body);
            }
        }
    }

    html_by_path
}
