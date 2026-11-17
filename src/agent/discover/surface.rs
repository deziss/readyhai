//! Attack surface extraction: link parsing, redirects, login walls, and route derivation.
use regex::Regex;
use std::collections::{HashSet, VecDeque};
use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use super::soft404;
use crate::agent::budget::RunBudget;
use crate::agent::types::{
    DiscoveredRoute, InputSurface, RedirectHop, Soft404Fingerprint, TargetTechProfile,
};

/// Redirects followed (same host only) before the answer is taken as it is.
pub const MAX_REDIRECTS: usize = 5;

pub fn is_static_asset(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let exts = [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".js", ".woff", ".woff2",
        ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
    ];
    exts.iter()
        .any(|ext| lower.ends_with(ext) || lower.contains(&format!("{ext}?")))
}

/// `<title>` text, at most 80 chars. ASCII-lowercasing keeps byte offsets identical to the
/// original string, so slicing can never land inside a multi-byte character.
pub fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")? + "<title>".len();
    let end = start + lower[start..].find("</title>")?;
    let t = html.get(start..end)?;
    Some(
        t.trim()
            .replace(['\n', '\r'], " ")
            .chars()
            .take(80)
            .collect(),
    )
}

fn link_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?:href|action)\s*=\s*["']([^"']+)["']"#).unwrap())
}

pub fn parse_internal_links_from_html(
    html: &str,
    target_host: &str,
    seen: &mut HashSet<String>,
    queue: &mut VecDeque<String>,
    max_queue: usize,
) {
    let target_host_lower = target_host.to_lowercase();
    let alt_host = match target_host_lower.strip_prefix("www.") {
        Some(h) => h.to_string(),
        None => format!("www.{target_host_lower}"),
    };
    for cap in link_re().captures_iter(html) {
        if queue.len() >= max_queue {
            break;
        }
        let raw = cap[1].trim();
        if raw.starts_with('#')
            || raw.starts_with("javascript:")
            || raw.starts_with("mailto:")
            || raw.starts_with("tel:")
            || raw.starts_with("//")
        {
            continue;
        }
        let clean_path = if raw.starts_with("http://") || raw.starts_with("https://") {
            let Ok(u) = reqwest::Url::parse(raw) else {
                continue;
            };
            let h = u.host_str().unwrap_or("").to_lowercase();
            if h != target_host_lower && h != alt_host {
                continue;
            }
            let mut p = u.path().to_string();
            if let Some(q) = u.query() {
                p.push('?');
                p.push_str(q);
            }
            p
        } else if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("/{raw}")
        };
        let no_anchor = clean_path.split('#').next().unwrap_or("").to_string();
        if no_anchor.is_empty()
            || is_static_asset(&no_anchor)
            || no_anchor
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            continue;
        }
        if seen.insert(no_anchor.clone()) {
            queue.push_back(no_anchor);
        }
    }
}

/// One answer, after the same-host redirects it led through.
pub struct Fetched {
    /// The status the server answered the request with: the FIRST hop of a redirect chain.
    pub status: u16,
    /// Status of the last response (== `status` when nothing redirected).
    pub final_status: u16,
    /// Headers, content type and body of the last response.
    pub headers: reqwest::header::HeaderMap,
    pub content_type: String,
    pub body: String,
    /// Where the answer finally came from (None: no redirect was followed).
    pub final_url: Option<String>,
    /// Every redirect met, first to last. A redirect that was not followed (another host, or more
    /// than [`MAX_REDIRECTS`]) is the last hop and `final_url` stays None.
    pub chain: Vec<RedirectHop>,
}

/// The HTTP client of discovery. It never follows redirects itself: [`fetch`] does, one hop at a
/// time, so each hop is recorded and counted against the budget.
pub fn crawl_client() -> Option<reqwest::blocking::Client> {
    crawl_client_timeout(5000)
}

pub fn crawl_client_timeout(ms: u64) -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(ms))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 ReadyHai/1.0")
        .build()
        .ok()
}

pub fn same_host(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.host_str().map(str::to_ascii_lowercase) == b.host_str().map(str::to_ascii_lowercase)
}

/// GET `url`, following up to [`MAX_REDIRECTS`] redirects that stay on the same host (a redirect
/// to another host is recorded and not followed). Each request counts against the budget.
pub fn fetch(
    cl: &reqwest::blocking::Client,
    url: &str,
    host: &str,
    budget: &mut RunBudget,
    cap: usize,
) -> Result<Fetched, String> {
    let mut cur = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    let mut chain: Vec<RedirectHop> = vec![];
    let mut first_status: Option<u16> = None;
    let mut followed = false;
    loop {
        budget.take_request(host)?;
        let resp = cl.get(cur.clone()).send().map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let first = *first_status.get_or_insert(status);
        let headers = resp.headers().clone();
        let location = headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        if matches!(status, 301 | 302 | 303 | 307 | 308)
            && let Some(loc) = location
        {
            chain.push(RedirectHop {
                status,
                location: loc.clone(),
            });
            if let Ok(next) = cur.join(&loc)
                && matches!(next.scheme(), "http" | "https")
                && same_host(&cur, &next)
                && chain.len() <= MAX_REDIRECTS
            {
                cur = next;
                followed = true;
                continue;
            }
        }
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut buf = Vec::new();
        let _ = resp.take(cap as u64).read_to_end(&mut buf);
        let final_url = followed.then(|| cur.to_string());
        return Ok(Fetched {
            status: first,
            final_status: status,
            headers,
            content_type,
            body: String::from_utf8_lossy(&buf).into_owned(),
            final_url,
            chain,
        });
    }
}

// ---------------------------------------------------------------- login walls

/// Does this redirect target (`Location` header value, absolute or relative) lead to a login /
/// sign-in / SSO page? Matches whole path segments (`/login`, `/sign-in`, `/auth/...`,
/// `/account/login`, `/users/sign_in`, `/login.php`, `/oauth2/authorize`), not substrings, so
/// `/authors` and `/blogin` do not match. A host that is an identity provider (`login.`, `auth.`,
/// `sso.`, `accounts.`, Auth0, Okta, Entra, Cognito, Keycloak) matches whatever the path.
pub fn is_login_location(loc: &str) -> bool {
    const SEGMENTS: &[&str] = &[
        "login",
        "log-in",
        "log_in",
        "logon",
        "signin",
        "sign-in",
        "sign_in",
        "sso",
        "oauth",
        "oauth2",
        "auth",
        "authenticate",
        "authorize",
        "saml",
        "saml2",
        "cas",
        "openid",
    ];
    const HOST_LABELS: &[&str] = &[
        "login", "auth", "sso", "signin", "accounts", "idp", "identity", "oauth", "cas",
    ];
    const HOST_PARTS: &[&str] = &[
        "auth0.com",
        "okta.com",
        "oktapreview.com",
        "microsoftonline.com",
        "amazoncognito.com",
        "keycloak",
    ];
    let loc = loc.trim();
    if loc.is_empty() {
        return false;
    }
    let parsed = if loc.starts_with("//") {
        reqwest::Url::parse(&format!("http:{loc}")).ok()
    } else {
        reqwest::Url::parse(loc).ok()
    };
    let (host, path) = match &parsed {
        Some(u) if u.has_host() => (
            u.host_str().unwrap_or("").to_ascii_lowercase(),
            u.path().to_string(),
        ),
        _ => (
            String::new(),
            loc.split(['?', '#']).next().unwrap_or("").to_string(),
        ),
    };
    if !host.is_empty() {
        let label = host.split('.').next().unwrap_or("");
        if HOST_LABELS.contains(&label) || HOST_PARTS.iter().any(|p| host.contains(p)) {
            return true;
        }
    }
    path.to_ascii_lowercase()
        .split('/')
        .filter(|seg| !seg.is_empty())
        .any(|seg| {
            let stem = seg.split('.').next().unwrap_or(seg);
            SEGMENTS.contains(&stem)
        })
}

/// A password input in the HTML: the page asks for credentials.
pub fn has_password_input(html: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)<input\b[^>]*\btype\s*=\s*["']?password"#).unwrap())
        .is_match(html)
}

/// The answer asks for credentials: 401, a redirect to a login page, or a password form.
pub fn auth_wall_of(f: &Fetched) -> bool {
    f.status == 401
        || f.chain.iter().any(|h| is_login_location(&h.location))
        || f.final_url.as_deref().is_some_and(is_login_location)
        || (f.content_type.contains("html") && has_password_input(&f.body))
}

// ---------------------------------------------------------------- routes

/// A route from one fetched answer. `path` is what was requested; the status is the first hop's
/// (what the server answers when nothing follows redirects), content type, title and form flag
/// come from the final page.
pub fn route_from(
    path: &str,
    f: &Fetched,
    tech: &TargetTechProfile,
    sf: Option<&Soft404Fingerprint>,
    source: &str,
    is_root: bool,
) -> DiscoveredRoute {
    let auth_wall = auth_wall_of(f);
    let catch_all = !is_root
        && (source == "probe" || !auth_wall)
        && sf.is_some_and(|c| {
            !matches!(c.status, 404 | 410) && soft404::matches(c, &soft404::of_fetched(f, path))
        });
    let is_html = f.content_type.contains("text/html");
    let is_api = if is_root {
        !tech.is_spa && f.final_status != 404 && f.content_type.contains("application/json")
    } else {
        f.content_type.contains("application/json") || f.status == 401 || f.status == 403
    };
    DiscoveredRoute {
        final_url: f.final_url.clone(),
        redirect_chain: f.chain.clone(),
        auth_wall,
        catch_all,
        input_surface: InputSurface::None,
        path: path.to_string(),
        method: "GET".into(),
        status_code: f.status,
        content_type: f.content_type.clone(),
        is_spa_shell: if is_root {
            tech.is_spa
        } else {
            tech.is_spa && is_html
        },
        is_api,
        title: extract_title(&f.body),
        has_form: f.body.contains("<form") || f.body.contains("type=\"submit\""),
        secured: None,
        has_body: false,
        source: source.into(),
    }
}

/// Where a route takes input. Priority: an OpenAPI operation with parameters or a body (`Spec`),
/// then a JSON/API endpoint (`Json`), a query string (`Query`), a form (`Form`); anything else, a
/// catch-all and an operation without input take none.
pub fn derive_input_surface(r: &DiscoveredRoute, spec_inputs: &HashSet<String>) -> InputSurface {
    if r.catch_all {
        return InputSurface::None;
    }
    if r.source == "openapi" {
        return if r.has_body || spec_inputs.contains(&format!("{} {}", r.method, r.path)) {
            InputSurface::Spec
        } else {
            InputSurface::None
        };
    }
    let json_like = r.is_api
        || r.content_type.to_ascii_lowercase().contains("json")
        || r.source == "js"
        || (r.source == "xhr" && r.has_body);
    if json_like {
        InputSurface::Json
    } else if r.path.contains('?') {
        InputSurface::Query
    } else if r.has_form {
        InputSurface::Form
    } else {
        InputSurface::None
    }
}

/// `scope.toml` lists this host explicitly (a bare `*` does not count: it would put every
/// third-party host a bundle mentions in scope).
pub fn host_in_scope(scope: Option<&crate::scope::Scope>, host: &str) -> bool {
    scope
        .and_then(|s| s.find(host))
        .is_some_and(|h| h.host.trim() != "*")
}
