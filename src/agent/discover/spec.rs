//! OpenAPI specification discovery, loading, and resolution.
use regex::Regex;
use serde_json::Value;
use std::io::Read;
use std::sync::OnceLock;

use super::spa;
use super::surface::{fetch, same_host};
use super::tech::SpecDoc;
use crate::agent::budget::RunBudget;

pub const SPEC_CAP: usize = 4 * 1024 * 1024;
pub const LOCAL_SPEC_CAP: usize = 5 * 1024 * 1024;
pub const MAX_SPEC_ROUTES: usize = 200;

/// Where a spec is looked for when none was given: the usual FastAPI/Swagger/Springdoc/Nest
/// paths, and an API docs page (`/docs`) whose HTML names the spec.
pub const SPEC_LOCATIONS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/docs/openapi.json",
    "/v3/api-docs",
    "/api-docs",
    "/openapi.yaml",
    "/swagger/v1/swagger.json",
    "/api/v1/openapi.json",
    "/.well-known/openapi",
    "/docs",
];

/// A path (`/x?y=1`) on the target's own host for a URL as written in a page, sitemap or
/// chunk: relative paths as they are, absolute URLs only when they point at the target host
/// (or its `www.` twin). None: another host, or not a path.
pub fn local_path(raw: &str, target_host: &str) -> Option<String> {
    let raw = raw.trim();
    let alt = match target_host.strip_prefix("www.") {
        Some(h) => h.to_string(),
        None => format!("www.{target_host}"),
    };
    let p = if raw.starts_with("http://") || raw.starts_with("https://") {
        let u = reqwest::Url::parse(raw).ok()?;
        let h = u.host_str()?.to_ascii_lowercase();
        if h != target_host && h != alt {
            return None;
        }
        let mut p = u.path().to_string();
        if let Some(q) = u.query() {
            p.push('?');
            p.push_str(q);
        }
        p
    } else if raw.starts_with('/') && !raw.starts_with("//") {
        raw.split('#').next().unwrap_or("").to_string()
    } else {
        return None;
    };
    (!p.is_empty() && !p.chars().any(|c| c.is_whitespace() || c.is_control())).then_some(p)
}

/// Optional discovery work stops once the run's request budget is half spent: the planned cases
/// need the rest.
pub fn extras_ok(budget: &RunBudget) -> bool {
    budget.stopped().is_none()
        && !budget.is_cancelled()
        && budget.requests_used() * 2 < budget.max_requests()
}

/// Looks like an action rather than a page or a read: never requested speculatively.
pub fn looks_destructive(path: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)logout|log-out|signout|sign-out|delete|remove|destroy|revoke|reset|cron|seed|purge|clear|unsubscribe|checkout|purchase|\bpay\b|webhook",
        )
        .unwrap()
    })
    .is_match(path)
}

pub fn servers_base_path(doc: &Value, target_host: &str) -> String {
    let Some(u) = doc["servers"][0]["url"].as_str() else {
        return String::new();
    };
    if u.contains('{') {
        return String::new();
    }
    let path = if u.starts_with('/') {
        u.to_string()
    } else if let Ok(p) = reqwest::Url::parse(u) {
        if p.host_str().map(|h| h.eq_ignore_ascii_case(target_host)) != Some(true) {
            return String::new();
        }
        p.path().to_string()
    } else {
        return String::new();
    };
    let t = path.trim_end_matches('/');
    t.to_string()
}

/// A `spec_url` that names a local file rather than an http(s) URL: a plain path (`./openapi.yaml`,
/// `/srv/api/openapi.json`) or a `file://` URL. `None` for http(s) and for anything that is not
/// an existing regular file.
pub fn local_spec_path(spec: &str) -> Option<std::path::PathBuf> {
    let s = spec.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        return None;
    }
    let path = match reqwest::Url::parse(s) {
        Ok(u) if u.scheme() == "file" => u.to_file_path().ok()?,
        _ => std::path::PathBuf::from(s),
    };
    path.is_file().then_some(path)
}

/// Read a spec from disk: at most [`LOCAL_SPEC_CAP`] bytes, JSON or YAML (parsed by the caller).
pub fn read_local_spec(path: &std::path::Path) -> Result<String, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.take(LOCAL_SPEC_CAP as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() > LOCAL_SPEC_CAP {
        return Err(format!(
            "larger than the {} MB limit",
            LOCAL_SPEC_CAP / (1024 * 1024)
        ));
    }
    String::from_utf8(buf).map_err(|_| "not valid UTF-8 text".into())
}

/// A parsed document is an OpenAPI spec when it has a `paths` object.
pub fn spec_from_text(
    text: &str,
    source: String,
    target_host: &str,
    notes: &mut Vec<String>,
    explicit: bool,
) -> Option<SpecDoc> {
    let Ok(doc) = crate::qa::plan::parse_doc(text) else {
        if explicit {
            notes.push("OpenAPI spec is neither valid JSON nor YAML".into());
        }
        return None;
    };
    if doc.get("paths").and_then(|p| p.as_object()).is_none() {
        if explicit {
            notes.push("document has no `paths`; not an OpenAPI spec".into());
        }
        return None;
    }
    let ops = crate::qa::plan::ops_from_doc(&doc);
    let base_path = servers_base_path(&doc, target_host);
    Some(SpecDoc {
        doc,
        ops,
        base_path,
        source,
    })
}

pub fn load_spec(
    cl: &reqwest::blocking::Client,
    base: &str,
    host: &str,
    target_host: &str,
    spec_url: Option<&str>,
    budget: &mut RunBudget,
    notes: &mut Vec<String>,
) -> Option<SpecDoc> {
    let origin = {
        let u = reqwest::Url::parse(base).ok()?;
        format!("{}://{}", u.scheme(), u.host_str()?)
            + &u.port().map(|p| format!(":{p}")).unwrap_or_default()
    };
    let candidates: Vec<String> = match spec_url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(u) if u.starts_with("http://") || u.starts_with("https://") => vec![u.to_string()],
        Some(other) => {
            let shown = other.chars().take(80).collect::<String>();
            let Some(path) = local_spec_path(other) else {
                notes.push(format!(
                    "spec_url '{shown}' ignored: neither an http(s) URL nor an existing file"
                ));
                return None;
            };
            let text = match read_local_spec(&path) {
                Ok(t) => t,
                Err(e) => {
                    notes.push(format!("OpenAPI spec file '{shown}' not read: {e}"));
                    return None;
                }
            };
            return spec_from_text(&text, path.display().to_string(), target_host, notes, true);
        }
        None => SPEC_LOCATIONS
            .iter()
            .map(|p| format!("{origin}{p}"))
            .collect(),
    };
    let explicit = spec_url.is_some();
    let mut followed_link = false;
    for url in candidates {
        let spec_host = reqwest::Url::parse(&url)
            .ok()
            .map(|u| {
                format!(
                    "{}:{}",
                    u.host_str().unwrap_or(""),
                    u.port_or_known_default().unwrap_or(0)
                )
            })
            .unwrap_or_else(|| host.to_string());
        let f = match fetch(cl, &url, &spec_host, budget, SPEC_CAP) {
            Ok(f) => f,
            Err(e) => {
                if explicit {
                    notes.push(format!("OpenAPI spec fetch failed: {e}"));
                }
                if budget.stopped().is_some() {
                    break;
                }
                continue;
            }
        };
        if !(200..300).contains(&f.final_status) {
            if explicit {
                notes.push(format!(
                    "OpenAPI spec fetch returned HTTP {}",
                    f.final_status
                ));
            }
            continue;
        }
        if let Some(spec) = spec_from_text(&f.body, url.clone(), target_host, notes, explicit) {
            return Some(spec);
        }
        // an API docs page (Swagger UI, ReDoc) names its spec: follow the link once, same host only
        if !followed_link
            && f.content_type.contains("html")
            && let Some(link) = spa::spec_link_in_html(&f.body)
            && let Ok(base_url) = reqwest::Url::parse(&url)
            && let Ok(next) = base_url.join(&link)
            && matches!(next.scheme(), "http" | "https")
            && same_host(&base_url, &next)
        {
            followed_link = true;
            if let Ok(g) = fetch(cl, next.as_str(), &spec_host, budget, SPEC_CAP)
                && (200..300).contains(&g.final_status)
                && let Some(spec) =
                    spec_from_text(&g.body, next.to_string(), target_host, notes, false)
            {
                return Some(spec);
            }
        }
    }
    None
}
