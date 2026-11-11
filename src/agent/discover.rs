//! Discovery: technology fingerprint, soft-404 calibration, bounded same-host crawl, SPA route and
//! API extraction (Next.js manifests, JS chunks, sitemap.xml, robots.txt), OpenAPI operations and
//! headless XHR capture. Every request goes through the run budget.
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use super::budget::RunBudget;
use super::exec::{Auth, Clients, Credentials, OutReq, resolve_auth};
use super::types::{
    DiscoveredRoute, InputSurface, RedirectHop, Soft404Fingerprint, TargetTechProfile,
};

mod soft404;
mod spa;
mod xhr;

pub use xhr::run_xhr_discovery;

const CRAWL_BODY_CAP: usize = 256 * 1024;
const SPEC_CAP: usize = 4 * 1024 * 1024;
/// Largest JS chunk read when looking for API calls, and the most chunks and bytes read per run.
const CHUNK_CAP: usize = 2 * 1024 * 1024;
const MAX_CHUNKS: usize = 30;
const CHUNKS_TOTAL_CAP: usize = 24 * 1024 * 1024;
/// Largest sitemap / robots.txt read, and the most URLs taken from them.
const SITEMAP_CAP: usize = 2 * 1024 * 1024;
const MAX_SITEMAP_URLS: usize = 200;
/// Most page routes taken from a build manifest and most API paths taken from chunks.
const MAX_MANIFEST_ROUTES: usize = 60;
const MAX_JS_API_PATHS: usize = 40;
/// Most GET verifications of API paths found in chunks.
const API_VERIFY_CAP: usize = 15;
/// Redirects followed (same host only) before the answer is taken as it is.
const MAX_REDIRECTS: usize = 5;
/// Most in-scope API hosts probed for an OpenAPI document.
const MAX_FOREIGN_SPEC_HOSTS: usize = 3;
/// Largest spec read from a local file (the CLI's `--spec ./openapi.yaml`).
const LOCAL_SPEC_CAP: usize = 5 * 1024 * 1024;
const MAX_SPEC_ROUTES: usize = 200;
/// Where a spec is looked for when none was given: the usual FastAPI/Swagger/Springdoc/Nest
/// paths, and an API docs page (`/docs`) whose HTML names the spec.
const SPEC_LOCATIONS: &[&str] = &[
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

/// An OpenAPI document found for the target.
#[derive(Debug, Clone)]
pub struct SpecDoc {
    pub doc: Value,
    pub ops: Vec<crate::qa::plan::Op>,
    /// Path prefix from `servers[0].url` (e.g. "/api/v1"), "" when none.
    pub base_path: String,
    pub source: String,
}

impl SpecDoc {
    /// The operations in the QA engine's model (parameters, body and response schemas): the form
    /// its shared generators and validators take. Empty when the document is not OpenAPI 3.x.
    pub fn api_ops(&self) -> Vec<crate::qa::api::spec::Op> {
        crate::qa::api::spec::parse(self.doc.clone())
            .map(|s| s.ops)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub routes: Vec<DiscoveredRoute>,
    pub tech: TargetTechProfile,
    pub spec: Option<SpecDoc>,
    pub notes: Vec<String>,
    /// Ids of records that exist, by spec collection path (`/orders` -> ["1", "2"]), read from the
    /// collection endpoints by [`harvest_ids`]. Empty until then.
    pub ids: BTreeMap<String, Vec<String>>,
    /// How the target answers paths that cannot exist (None: not calibrated).
    pub soft404: Option<crate::agent::types::Soft404Fingerprint>,
    /// API hosts referenced by the app (JS chunks, XHR) that are outside scope: reported, never called.
    pub api_hosts_seen: Vec<String>,
    /// API hosts referenced by the app that scope.toml lists explicitly. Requests of the agent go
    /// to the target origin only, so these are reported (and probed for a spec), not tested.
    pub api_hosts_in_scope: Vec<String>,
}

pub fn detect_target_tech(
    headers: &reqwest::header::HeaderMap,
    body: &str,
    status_code: u16,
    content_type: &str,
) -> TargetTechProfile {
    let body_lower = body.to_lowercase();
    let set_cookie = headers
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let x_powered_by = headers
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let expires = headers
        .get("expires")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut signals = Vec::new();

    // 1. PHP signatures
    let has_phpsessid = set_cookie.contains("PHPSESSID");
    let has_php_expires = expires.contains("Thu, 19 Nov 1981");
    let has_php_powered = x_powered_by.to_lowercase().contains("php");
    let has_php_links = body_lower.contains(".php");
    let has_wordpress = body_lower.contains("/wp-content/themes/")
        || body_lower.contains("/wp-content/plugins/")
        || body_lower.contains("/wp-includes/")
        || set_cookie.contains("wordpress_");
    let has_laravel = set_cookie.contains("laravel_session")
        || set_cookie.contains("XSRF-TOKEN")
        || body_lower.contains("laravel");

    let is_php = has_phpsessid
        || has_php_expires
        || has_php_powered
        || has_php_links
        || has_wordpress
        || has_laravel;
    if has_phpsessid {
        signals.push("PHPSESSID session cookie active".to_string());
    }
    if has_php_expires {
        signals.push("Standard PHP session_start cache limiter headers detected".to_string());
    }
    if has_php_powered {
        signals.push(format!("X-Powered-By: {}", x_powered_by));
    }
    if has_wordpress {
        signals.push("WordPress theme & plugin assets identified".to_string());
    }
    if has_laravel {
        signals.push("Laravel session / CSRF token cookies detected".to_string());
    }
    let mk =
        |is_spa: bool, arch: &str, fw: &str, signals: Vec<String>, is_php: bool, api_only: bool| {
            TargetTechProfile {
                is_spa,
                app_architecture: arch.to_string(),
                primary_framework: fw.to_string(),
                detected_signals: signals,
                is_php,
                is_api_only: api_only,
            }
        };
    if is_php {
        let (arch, fw) = if has_wordpress {
            ("WordPress (PHP/HTML MPA)", "WordPress")
        } else if has_laravel {
            ("Laravel (PHP/HTML MPA)", "Laravel")
        } else {
            ("PHP & HTML (Server-Side MPA)", "PHP")
        };
        return mk(false, arch, fw, signals, true, false);
    }

    // 2. Python / Django / Flask
    if set_cookie.contains("csrftoken")
        || set_cookie.contains("sessionid")
        || server.to_lowercase().contains("gunicorn")
    {
        signals.push("Django / Python session cookie and WSGI headers detected".to_string());
        return mk(
            false,
            "Python (Django/HTML MPA)",
            "Django",
            signals,
            false,
            false,
        );
    }
    // 3. Java / Spring
    if set_cookie.contains("JSESSIONID") {
        signals.push("Java / Spring JSESSIONID cookie detected".to_string());
        return mk(
            false,
            "Java / Spring (HTML MPA)",
            "Spring",
            signals,
            false,
            false,
        );
    }
    // 4. SPA signatures
    let has_next = body.contains("__NEXT_DATA__") || body.contains("/_next/static/");
    let has_nuxt =
        body.contains("__NUXT__") || body.contains("/_nuxt/") || body.contains("data-v-");
    let has_angular = body.contains("ng-version") || body.contains("<app-root");
    let has_react = body.contains("data-reactroot") || body.contains("react-dom");
    let has_svelte = body.contains("__sveltekit") || body.contains("svelte-");
    let has_vite = body.contains("/@vite/client") || body.contains("/src/main.tsx");
    if has_next {
        signals.push(
            "Next.js hydration payload (__NEXT_DATA__) and static chunks detected".to_string(),
        );
        return mk(
            true,
            "SPA (Next.js/React)",
            "Next.js",
            signals,
            false,
            false,
        );
    }
    if has_nuxt {
        signals.push("Nuxt / Vue client hydration bundle detected".to_string());
        return mk(true, "SPA (Nuxt/Vue)", "Nuxt/Vue", signals, false, false);
    }
    if has_angular {
        signals.push("Angular ng-version runtime and <app-root> tag detected".to_string());
        return mk(true, "SPA (Angular)", "Angular", signals, false, false);
    }
    if has_react || has_vite {
        signals.push("Client-side React virtual DOM / Vite client bundle detected".to_string());
        return mk(true, "SPA (React)", "React", signals, false, false);
    }
    if has_svelte {
        signals.push("SvelteKit client hydration detected".to_string());
        return mk(true, "SPA (SvelteKit)", "SvelteKit", signals, false, false);
    }
    // 5. REST API
    let is_json = content_type.contains("application/json")
        || content_type.contains("application/problem+json");
    if is_json || (status_code == 401 && !content_type.contains("text/html")) {
        signals.push("JSON Content-Type response without HTML rendering detected".to_string());
        return mk(false, "REST API (JSON)", "REST API", signals, false, true);
    }
    // 6. server-rendered HTML
    signals.push(
        "Server-side rendered HTML5 markup; zero client-side SPA hydration scripts".to_string(),
    );
    mk(
        false,
        "Traditional Web App (HTML5/SSR)",
        "HTML5",
        signals,
        false,
        false,
    )
}

fn is_static_asset(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let exts = [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".js", ".woff", ".woff2",
        ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
    ];
    exts.iter()
        .any(|ext| lower.ends_with(ext) || lower.contains(&format!("{ext}?")))
}

/// `<title>` text, at most 80 chars. ASCII-lowercasing keeps byte offsets identical to the
/// original string, so slicing can never land inside a multi-byte character (the previous
/// `to_lowercase()` could shift offsets for e.g. 'İ' and panic).
pub(crate) fn extract_title(html: &str) -> Option<String> {
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

pub(crate) fn parse_internal_links_from_html(
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
pub(crate) struct Fetched {
    /// The status the server answered the request with: the FIRST hop of a redirect chain.
    status: u16,
    /// Status of the last response (== `status` when nothing redirected).
    final_status: u16,
    /// Headers, content type and body of the last response.
    headers: reqwest::header::HeaderMap,
    content_type: String,
    body: String,
    /// Where the answer finally came from (None: no redirect was followed).
    final_url: Option<String>,
    /// Every redirect met, first to last. A redirect that was not followed (another host, or more
    /// than [`MAX_REDIRECTS`]) is the last hop and `final_url` stays None.
    chain: Vec<RedirectHop>,
}

/// The HTTP client of discovery. It never follows redirects itself: [`fetch`] does, one hop at a
/// time, so each hop is recorded and counted against the budget.
fn crawl_client() -> Option<reqwest::blocking::Client> {
    crawl_client_timeout(5000)
}

fn crawl_client_timeout(ms: u64) -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(ms))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 ReadyHai/1.0")
        .build()
        .ok()
}

fn same_host(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.host_str().map(str::to_ascii_lowercase) == b.host_str().map(str::to_ascii_lowercase)
}

/// GET `url`, following up to [`MAX_REDIRECTS`] redirects that stay on the same host (a redirect
/// to another host is recorded and not followed). Each request counts against the budget.
fn fetch(
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
fn has_password_input(html: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)<input\b[^>]*\btype\s*=\s*["']?password"#).unwrap())
        .is_match(html)
}

/// The answer asks for credentials: 401, a redirect to a login page, or a password form.
fn auth_wall_of(f: &Fetched) -> bool {
    f.status == 401
        || f.chain.iter().any(|h| is_login_location(&h.location))
        || f.final_url.as_deref().is_some_and(is_login_location)
        || (f.content_type.contains("html") && has_password_input(&f.body))
}

// ---------------------------------------------------------------- routes

/// A route from one fetched answer. `path` is what was requested; the status is the first hop's
/// (what the server answers when nothing follows redirects), content type, title and form flag
/// come from the final page. `sf` flags a catch-all: an answer identical to the calibrated
/// not-found answer is not a route, unless a login wall explains it (the server redirects
/// everything to its login, so the paths cannot be told apart) or it is the root.
fn route_from(
    path: &str,
    f: &Fetched,
    tech: &TargetTechProfile,
    sf: Option<&Soft404Fingerprint>,
    source: &str,
    is_root: bool,
) -> DiscoveredRoute {
    let auth_wall = auth_wall_of(f);
    // only a SOFT 404 (an unknown path answered with a page that says "fine") makes a catch-all:
    // a server that answers unknown paths with a real 404 has none
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
/// catch-all and an operation without input take none. `spec_inputs` is the set of
/// "METHOD path" keys of spec operations that have parameters or a body.
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
fn host_in_scope(scope: Option<&crate::scope::Scope>, host: &str) -> bool {
    scope
        .and_then(|s| s.find(host))
        .is_some_and(|h| h.host.trim() != "*")
}

/// A path (`/x?y=1`) on the target's own host for a URL as written in a page, sitemap or
/// chunk: relative paths as they are, absolute URLs only when they point at the target host
/// (or its `www.` twin). None: another host, or not a path.
fn local_path(raw: &str, target_host: &str) -> Option<String> {
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
fn extras_ok(budget: &RunBudget) -> bool {
    budget.stopped().is_none()
        && !budget.is_cancelled()
        && budget.requests_used() * 2 < budget.max_requests()
}

/// Looks like an action rather than a page or a read: never requested speculatively.
fn looks_destructive(path: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)logout|log-out|signout|sign-out|delete|remove|destroy|revoke|reset|cron|seed|purge|clear|unsubscribe|checkout|purchase|\bpay\b|webhook",
        )
        .unwrap()
    })
    .is_match(path)
}

fn servers_base_path(doc: &Value, target_host: &str) -> String {
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
/// an existing regular file. The server and MCP callers guard `spec_url` as a web URL before it
/// gets here, so only the CLI can reach this with a path.
fn local_spec_path(spec: &str) -> Option<std::path::PathBuf> {
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
fn read_local_spec(path: &std::path::Path) -> Result<String, String> {
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
fn spec_from_text(
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

fn load_spec(
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

/// Collections read for ids: a few GETs, never a crawl of the API.
const MAX_ID_COLLECTIONS: usize = 6;

/// Read the ids of existing records, so the planner reads and checks real ones (the contract of
/// `GET /orders/2`, not of an id that may not exist). For every `GET /x/{id}` of the spec whose
/// collection `GET /x` exists, ONE read-only GET of the collection (as the acting role, or without
/// credentials when it is public) and the ids found in its answer (`qa::api::ids_in_list`). It is
/// a GET, so it is also sent in a dry run, and it is charged to the run budget. Returns the ids by
/// collection path and the notes to report.
pub fn harvest_ids(
    spec: &SpecDoc,
    target: &str,
    creds: &Credentials,
    timeout: Duration,
    budget: &mut RunBudget,
) -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    use crate::qa::api::{collection_of, ids_in_list, synth};
    let mut ids: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut notes = vec![];
    let api = spec.api_ops();
    let Some(parsed) = reqwest::Url::parse(target)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
    else {
        return (ids, notes);
    };
    let Ok(clients) = Clients::new(timeout, &parsed) else {
        return (ids, notes);
    };
    let host = format!(
        "{}:{}",
        parsed.host_str().unwrap_or(""),
        parsed.port_or_known_default().unwrap_or(0)
    );
    let actor = creds.actor();
    let mut tried: Vec<String> = vec![];
    for item in api.iter().filter(|o| o.method == "GET") {
        let Some((list_path, param)) = collection_of(item) else {
            continue;
        };
        if tried.contains(&list_path) || tried.len() >= MAX_ID_COLLECTIONS {
            continue;
        }
        let Some(list) = api
            .iter()
            .find(|o| o.method == "GET" && o.path == list_path && o.path_params().count() == 0)
        else {
            continue;
        };
        let auth = match (&actor, list.secured) {
            (_, false) => Auth::None,
            (Some(a), true) => Auth::Role(a.clone()),
            (None, true) => continue, // nobody to read it as: not worth a 401
        };
        tried.push(list_path.clone());
        // the operation's own valid request (its required query parameters)
        let probe = synth::generate(list, "readyhai-", false, &HashMap::new());
        let Some(valid) = probe.first() else { continue };
        let url = synth::build_url(
            &format!("{}{}", target.trim_end_matches('/'), spec.base_path),
            &list.path,
            &valid.path_vals,
            &valid.query,
        );
        if budget.take_request(&host).is_err() {
            break;
        }
        let resolved = resolve_auth(&auth, creds);
        let sent = clients.send_resolved(
            &OutReq {
                method: "GET",
                url: &url,
                body: None,
                headers: &[],
                bearer: resolved.bearer.as_ref(),
            },
            &resolved,
        );
        let mut found: Vec<String> = vec![];
        if let Ok(seen) = sent
            && (200..300).contains(&seen.status)
            && let Ok(j) = serde_json::from_str::<Value>(seen.body.trim())
        {
            ids_in_list(&j, &param, &mut found);
        }
        if !found.is_empty() {
            ids.insert(list_path, found);
        }
    }
    if !ids.is_empty() {
        notes.push(format!(
            "read the ids of existing records from {} collection(s) (GET, read-only): {}",
            ids.len(),
            ids.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    (ids, notes)
}

/// `host:port`, the key the budget paces requests by.
fn host_key_of(u: &reqwest::Url) -> String {
    format!(
        "{}:{}",
        u.host_str().unwrap_or("").to_ascii_lowercase(),
        u.port_or_known_default().unwrap_or(0)
    )
}

/// What the extraction steps share.
struct Cx<'a> {
    cl: &'a reqwest::blocking::Client,
    /// Longer timeout for JS bundles.
    asset_cl: &'a reqwest::blocking::Client,
    base: &'a str,
    host_key: &'a str,
    target_host: &'a str,
    scope: Option<&'a crate::scope::Scope>,
    max_urls: usize,
}

impl Cx<'_> {
    /// An asset URL as written in a page, resolved against the target; None unless it is on the
    /// target host (or its `www.` twin) or a host scope.toml lists.
    fn asset_url(&self, raw: &str) -> Option<reqwest::Url> {
        let u = reqwest::Url::parse(&format!("{}/", self.base))
            .ok()?
            .join(raw.trim())
            .ok()?;
        if !matches!(u.scheme(), "http" | "https") {
            return None;
        }
        let h = u.host_str()?.to_ascii_lowercase();
        let alt = match self.target_host.strip_prefix("www.") {
            Some(x) => x.to_string(),
            None => format!("www.{}", self.target_host),
        };
        (h == self.target_host || h == alt || host_in_scope(self.scope, &h)).then_some(u)
    }
}

/// Chunk files worth reading for API calls: page-specific ones first, the framework runtime,
/// polyfills and bundler bootstrap never.
fn chunk_rank(url: &str) -> Option<u8> {
    let path = url.split('?').next().unwrap_or("");
    let name = path.rsplit('/').next().unwrap_or("");
    if !path.ends_with(".js") {
        return None;
    }
    const SKIP: &[&str] = &[
        "framework",
        "polyfills",
        "webpack",
        "main-app",
        "main-",
        "react-refresh",
        "_buildManifest",
        "_ssgManifest",
        "_middlewareManifest",
        "turbopack",
    ];
    if SKIP.iter().any(|p| name.starts_with(p)) {
        return None;
    }
    Some(
        if path.contains("/chunks/pages/") || path.contains("/chunks/app/") {
            0
        } else {
            1
        },
    )
}

/// SPA extraction after the crawl: the Next.js build manifest and chunk names, API calls in the
/// app's JS chunks, `robots.txt` and `sitemap.xml`. Candidate pages and API paths are verified
/// with a GET (bounded), and routes are added to `d`. Returns the origins of API hosts that scope.toml
/// lists (their spec is looked for).
fn spa_extras(
    c: &Cx,
    d: &mut Discovery,
    acc: spa::PageAssets,
    budget: &mut RunBudget,
) -> Vec<String> {
    let sf = d.soft404.clone();
    let mut origins: Vec<String> = vec![];

    // ---- a. pages-router manifest
    let mut manifest_urls = acc.manifest_urls.clone();
    if manifest_urls.is_empty()
        && let Some(id) = &acc.build_id
    {
        manifest_urls.push(format!("/_next/static/{id}/_buildManifest.js"));
    }
    let mut page_cands: Vec<(String, &'static str)> = vec![];
    let mut dynamic: Vec<String> = acc.dynamic.iter().cloned().collect();
    let mut chunk_urls: Vec<reqwest::Url> = vec![];
    let mut manifest_routes = 0usize;
    for m in manifest_urls.iter().take(2) {
        if !extras_ok(budget) {
            break;
        }
        let Some(url) = c.asset_url(m) else { continue };
        let Ok(f) = fetch(c.asset_cl, url.as_str(), c.host_key, budget, CHUNK_CAP) else {
            continue;
        };
        if !(200..300).contains(&f.final_status) || f.content_type.contains("html") {
            continue;
        }
        let mf = spa::parse_build_manifest(&f.body);
        manifest_routes += mf.routes.len();
        for r in mf.routes {
            page_cands.push((r, "manifest"));
        }
        for r in mf.dynamic {
            if !dynamic.contains(&r) {
                dynamic.push(r);
            }
        }
        for ch in mf.chunks {
            if let Some(u) = c.asset_url(&format!("/_next/{ch}")) {
                chunk_urls.push(u);
            }
        }
    }
    let hinted: Vec<String> = acc.routes.iter().cloned().collect();
    let hinted_n = hinted.len();
    for r in hinted {
        page_cands.push((r, "manifest"));
    }
    if manifest_routes > 0 {
        d.notes.push(format!(
            "manifest: {manifest_routes} route(s) from _buildManifest.js"
        ));
    }
    if hinted_n > 0 {
        d.notes.push(format!(
            "next.js: {hinted_n} route(s) from chunk names, hydration data and link payloads"
        ));
    }
    if !dynamic.is_empty() {
        d.notes.push(format!(
            "{} dynamic route(s) not requested without a real id (e.g. {})",
            dynamic.len(),
            dynamic
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // ---- b. API calls in the app's JS chunks
    for s in &acc.script_srcs {
        if let Some(u) = c.asset_url(s) {
            chunk_urls.push(u);
        }
    }
    let mut ranked: Vec<(u8, reqwest::Url)> = vec![];
    for u in chunk_urls {
        if ranked.iter().any(|(_, x)| x == &u) {
            continue;
        }
        if let Some(r) = chunk_rank(u.as_str()) {
            ranked.push((r, u));
        }
    }
    ranked.sort_by_key(|(r, _)| *r);
    // a server-rendered site's scripts are rarely where its API calls live: read a few, not 30
    let chunk_limit = if d.tech.is_spa || !acc.routes.is_empty() || !acc.manifest_urls.is_empty() {
        MAX_CHUNKS
    } else {
        8
    };
    let mut api_paths: Vec<String> = vec![];
    let (mut chunks_read, mut bytes) = (0usize, 0usize);
    let mut seen_hosts: Vec<String> = vec![];
    for (_, u) in ranked.into_iter().take(chunk_limit) {
        if !extras_ok(budget) || bytes >= CHUNKS_TOTAL_CAP {
            break;
        }
        let Ok(f) = fetch(c.asset_cl, u.as_str(), &host_key_of(&u), budget, CHUNK_CAP) else {
            continue;
        };
        if !(200..300).contains(&f.final_status) || f.content_type.contains("html") {
            continue; // a missing chunk answered with the app shell is not JS
        }
        chunks_read += 1;
        bytes += f.body.len();
        for p in spa::api_paths_in_js(&f.body) {
            if !api_paths.contains(&p) && api_paths.len() < MAX_JS_API_PATHS {
                api_paths.push(p);
            }
        }
        for abs in spa::absolute_urls_in_js(&f.body) {
            let host = abs.host_str().unwrap_or("").to_ascii_lowercase();
            let alt = match c.target_host.strip_prefix("www.") {
                Some(x) => x.to_string(),
                None => format!("www.{}", c.target_host),
            };
            if host == c.target_host || host == alt {
                // the app calls its own origin by absolute URL
                for p in spa::api_paths_in_js(&format!("\"{}\"", abs.path())) {
                    if !api_paths.contains(&p) && api_paths.len() < MAX_JS_API_PATHS {
                        api_paths.push(p);
                    }
                }
                continue;
            }
            if !spa::is_api_url(&abs) || seen_hosts.contains(&host) || seen_hosts.len() >= 10 {
                continue;
            }
            seen_hosts.push(host.clone());
            if host_in_scope(c.scope, &host) {
                if !d.api_hosts_in_scope.contains(&host) {
                    d.api_hosts_in_scope.push(host.clone());
                }
                let origin = format!(
                    "{}://{}{}",
                    abs.scheme(),
                    host,
                    abs.port().map(|p| format!(":{p}")).unwrap_or_default()
                );
                if !origins.contains(&origin) {
                    origins.push(origin);
                }
            } else {
                if !d.api_hosts_seen.contains(&host) {
                    d.api_hosts_seen.push(host.clone());
                }
                d.notes.push(format!(
                    "API host {host} referenced by the app; add to scope.toml to test it"
                ));
            }
        }
    }
    if chunks_read > 0 {
        d.notes.push(format!(
            "js chunks: {} API path(s) in {chunks_read} chunk(s)",
            api_paths.len()
        ));
    }

    // ---- c. robots.txt and sitemap.xml (same origin only)
    let mut robots_paths: Vec<String> = vec![];
    let mut sitemap_paths: Vec<String> = vec![];
    let mut sitemap_queue: VecDeque<String> = VecDeque::from(["/sitemap.xml".to_string()]);
    if extras_ok(budget)
        && let Ok(f) = fetch(
            c.cl,
            &format!("{}/robots.txt", c.base),
            c.host_key,
            budget,
            SITEMAP_CAP,
        )
        && (200..300).contains(&f.final_status)
        && !f.content_type.contains("html")
    {
        let r = spa::parse_robots(&f.body, MAX_SITEMAP_URLS);
        robots_paths = r.paths;
        for sm in r.sitemaps {
            if let Some(p) = local_path(&sm, c.target_host)
                && !sitemap_queue.contains(&p)
            {
                sitemap_queue.push_back(p);
            }
        }
    }
    let mut sitemaps_read = 0usize;
    while let Some(sm) = sitemap_queue.pop_front() {
        if sitemaps_read >= 4 || !extras_ok(budget) {
            break;
        }
        sitemaps_read += 1;
        let Ok(f) = fetch(
            c.cl,
            &format!("{}{sm}", c.base),
            c.host_key,
            budget,
            SITEMAP_CAP,
        ) else {
            continue;
        };
        if !(200..300).contains(&f.final_status) {
            continue;
        }
        let (locs, index) = spa::parse_sitemap(&f.body, MAX_SITEMAP_URLS);
        for loc in locs {
            let Some(p) = local_path(&loc, c.target_host) else {
                continue;
            };
            if index {
                if !sitemap_queue.contains(&p) {
                    sitemap_queue.push_back(p);
                }
            } else if sitemap_paths.len() < MAX_SITEMAP_URLS && !sitemap_paths.contains(&p) {
                sitemap_paths.push(p);
            }
        }
    }
    if !sitemap_paths.is_empty() || !robots_paths.is_empty() {
        d.notes.push(format!(
            "sitemap/robots: {} sitemap URL(s), {} robots path(s) (same origin)",
            sitemap_paths.len(),
            robots_paths.len()
        ));
    }
    for p in sitemap_paths {
        page_cands.push((p, "sitemap"));
    }
    for p in robots_paths {
        page_cands.push((p, "robots"));
    }

    // ---- d. verify the candidates with a GET (bounded) and add the real ones
    let page_cap = c.max_urls.clamp(10, 40);
    let mut known: HashSet<String> = d
        .routes
        .iter()
        .filter(|r| r.method == "GET")
        .map(|r| r.path.clone())
        .collect();
    let (mut verified, mut kept, mut unverified_dropped, mut manifest_added) = (0, 0, 0, 0);
    for (path, origin) in page_cands {
        if !known.insert(path.clone()) {
            continue;
        }
        let source: &str = if origin == "manifest" {
            "manifest"
        } else {
            "sitemap"
        };
        if origin == "manifest" && manifest_added >= MAX_MANIFEST_ROUTES {
            continue;
        }
        let can_verify = verified < page_cap && extras_ok(budget) && !looks_destructive(&path);
        if !can_verify {
            if origin == "manifest" {
                // the app names the route: keep it, status unknown
                manifest_added += 1;
                d.routes.push(DiscoveredRoute {
                    final_url: None,
                    redirect_chain: vec![],
                    auth_wall: false,
                    catch_all: false,
                    input_surface: InputSurface::None,
                    path,
                    method: "GET".into(),
                    status_code: 0,
                    content_type: String::new(),
                    is_spa_shell: d.tech.is_spa,
                    is_api: false,
                    title: None,
                    has_form: false,
                    secured: None,
                    has_body: false,
                    source: "manifest".into(),
                });
            } else {
                unverified_dropped += 1;
            }
            continue;
        }
        verified += 1;
        let Ok(f) = fetch(
            c.cl,
            &format!("{}{path}", c.base),
            c.host_key,
            budget,
            CRAWL_BODY_CAP,
        ) else {
            continue;
        };
        if matches!(f.final_status, 0 | 404 | 410) {
            continue;
        }
        let mut r = route_from(&path, &f, &d.tech, sf.as_ref(), source, false);
        if r.catch_all {
            // the answer is the catch-all page. A route the app itself names stands; so does a
            // sitemap entry of a SPA (every SPA path answers with the shell); the rest is not real
            if origin == "manifest" || (origin == "sitemap" && d.tech.is_spa) {
                r.catch_all = false;
            } else {
                continue;
            }
        }
        if origin == "manifest" {
            manifest_added += 1;
        }
        kept += 1;
        d.routes.push(r);
    }
    if verified > 0 || unverified_dropped > 0 {
        d.notes.push(format!(
            "candidate pages: {verified} verified with GET, {kept} kept{}",
            if unverified_dropped > 0 {
                format!(", {unverified_dropped} sitemap/robots path(s) not verified (limit)")
            } else {
                String::new()
            }
        ));
    }

    // API paths found in chunks: GET-verified (read-only), the real ones kept
    let (mut api_checked, mut api_kept) = (0usize, 0usize);
    for path in api_paths {
        if !known.insert(path.clone()) {
            continue;
        }
        if api_checked >= API_VERIFY_CAP || !extras_ok(budget) || looks_destructive(&path) {
            continue;
        }
        api_checked += 1;
        let Ok(f) = fetch(
            c.cl,
            &format!("{}{path}", c.base),
            c.host_key,
            budget,
            CRAWL_BODY_CAP,
        ) else {
            continue;
        };
        if matches!(f.final_status, 0 | 404 | 410) {
            continue;
        }
        let mut r = route_from(&path, &f, &d.tech, sf.as_ref(), "js", false);
        r.is_api = true;
        r.is_spa_shell = false;
        r.title = Some("API path referenced by the app's JS".into());
        api_kept += 1;
        d.routes.push(r);
    }
    if api_checked > 0 {
        d.notes.push(format!(
            "js chunks: {api_kept} of {api_checked} API path(s) answer (GET)"
        ));
    }
    origins.truncate(MAX_FOREIGN_SPEC_HOSTS);
    origins
}

/// Full discovery with an explicit budget. Scope comes from the active scope file.
pub fn discover(
    target: &str,
    spec_url: Option<&str>,
    max_urls: usize,
    budget: &mut RunBudget,
) -> Discovery {
    let scope = crate::scope::active().ok().flatten();
    discover_scoped(target, spec_url, max_urls, budget, scope.as_ref())
}

/// [`discover`] with the scope given (tests pass their own). `scope` decides which other hosts
/// the app's API calls point at may be looked at: only hosts it lists explicitly.
pub(crate) fn discover_scoped(
    target: &str,
    spec_url: Option<&str>,
    max_urls: usize,
    budget: &mut RunBudget,
    scope: Option<&crate::scope::Scope>,
) -> Discovery {
    let mut d = Discovery::default();
    let Ok(parsed) = reqwest::Url::parse(target) else {
        d.notes.push("target is not a valid URL".into());
        return d;
    };
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        d.notes
            .push("target is not an http(s) URL; nothing to discover".into());
        return d;
    }
    let target_host = parsed.host_str().unwrap_or("").to_lowercase();
    let host_key = format!(
        "{}:{}",
        target_host,
        parsed.port_or_known_default().unwrap_or(0)
    );
    let base = target.trim_end_matches('/').to_string();
    let (Some(cl), Some(asset_cl)) = (crawl_client(), crawl_client_timeout(10_000)) else {
        d.notes.push("could not build the HTTP client".into());
        return d;
    };

    // 0. how does the target answer a path that cannot exist? (3 random paths)
    // (not on a tiny budget: three requests would be a large share of it)
    let (fp, cal_notes) = if budget.requests_left() >= 20 {
        soft404::calibrate(&cl, &base, &host_key, budget)
    } else {
        (
            None,
            vec!["soft-404 calibration skipped: the request budget is too small".to_string()],
        )
    };
    d.soft404 = fp;
    d.notes.extend(cal_notes);
    let sf = d.soft404.clone();

    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut assets = spa::PageAssets::default();
    seen.insert("/".into());

    // 1. root
    match fetch(&cl, &format!("{base}/"), &host_key, budget, CRAWL_BODY_CAP) {
        Ok(f) => {
            d.tech = detect_target_tech(&f.headers, &f.body, f.final_status, &f.content_type);
            d.routes
                .push(route_from("/", &f, &d.tech, sf.as_ref(), "crawl", true));
            if f.content_type.contains("text/html") {
                parse_internal_links_from_html(
                    &f.body,
                    &target_host,
                    &mut seen,
                    &mut queue,
                    max_urls * 5,
                );
                assets.merge(spa::analyse_html(&f.body));
            }
        }
        Err(e) => d.notes.push(format!("root request failed: {e}")),
    }

    // 2. BFS over same-host links. A catch-all answer is not a route and is not read for links.
    let mut crawled = 0usize;
    while let Some(path) = queue.pop_front() {
        if d.routes.iter().filter(|r| !r.catch_all).count() >= max_urls || crawled >= max_urls * 3 {
            break;
        }
        crawled += 1;
        let url = if path.starts_with('/') {
            format!("{base}{path}")
        } else {
            format!("{base}/{path}")
        };
        let Ok(f) = fetch(&cl, &url, &host_key, budget, CRAWL_BODY_CAP) else {
            if budget.stopped().is_some() {
                d.notes
                    .push(format!("crawl stopped: {}", budget.stopped().unwrap_or("")));
                break;
            }
            continue;
        };
        if f.final_status != 404 && f.final_status != 0 {
            let r = route_from(&path, &f, &d.tech, sf.as_ref(), "crawl", false);
            let catch_all = r.catch_all;
            d.routes.push(r);
            if catch_all {
                continue;
            }
        }
        if f.content_type.contains("text/html") && queue.len() < max_urls * 3 {
            parse_internal_links_from_html(
                &f.body,
                &target_host,
                &mut seen,
                &mut queue,
                max_urls * 5,
            );
            assets.merge(spa::analyse_html(&f.body));
        }
    }

    // 3. SPA: build manifest, chunk names, API calls in JS, robots.txt, sitemap.xml
    let cx = Cx {
        cl: &cl,
        asset_cl: &asset_cl,
        base: &base,
        host_key: &host_key,
        target_host: &target_host,
        scope,
        max_urls,
    };
    let api_origins = if extras_ok(budget) {
        spa_extras(&cx, &mut d, assets, budget)
    } else {
        vec![]
    };

    // 4. sensitive-file probes: status only, GET, safe in dry-run. An answer that is the
    // catch-all page is flagged, so it is not mistaken for an exposed file.
    // Core probes always run; extended secret/backup/debug probes run when budget is plentiful
    // so diff-aware runs with tight budgets keep room for targeted verification.
    let mut sensitive_probes: Vec<&str> = vec!["/.env", "/.git/config"];
    if budget.max_requests() >= 80 && extras_ok(budget) {
        sensitive_probes.extend([
            "/.git/HEAD",
            "/.svn/entries",
            "/.hg/hgrc",
            "/.htaccess",
            "/.htpasswd",
            "/.DS_Store",
            "/.dockerenv",
            "/.npmrc",
            "/.pypirc",
            "/.aws/credentials",
            "/backup.sql",
            "/dump.sql",
            "/db.sql",
            "/secrets.json",
            "/secrets.yml",
            "/phpinfo.php",
            "/info.php",
            "/actuator/env",
            "/actuator/heapdump",
            "/actuator/mappings",
            "/debug/vars",
            "/debug/pprof",
            "/server-status",
        ]);
    }
    for (idx, probe) in sensitive_probes.into_iter().enumerate() {
        if idx >= 2 && !extras_ok(budget) {
            break;
        }
        if d.routes.iter().any(|r| r.path == probe) {
            continue;
        }
        if let Ok(f) = fetch(
            &cl,
            &format!("{base}{probe}"),
            &host_key,
            budget,
            soft404::CALIBRATION_BODY_CAP,
        ) {
            let mut r = route_from(probe, &f, &d.tech, sf.as_ref(), "probe", false);
            r.is_spa_shell = false;
            r.is_api = false;
            r.has_form = false;
            r.title = Some("Sensitive file probe".into());
            d.routes.push(r);
        }
    }

    // 5. OpenAPI
    if let Some(spec) = load_spec(
        &cl,
        &base,
        &host_key,
        &target_host,
        spec_url,
        budget,
        &mut d.notes,
    ) {
        for op in spec.ops.iter().take(MAX_SPEC_ROUTES) {
            let path = format!("{}{}", spec.base_path, op.path);
            if d.routes
                .iter()
                .any(|r| r.path == path && r.method == op.method)
            {
                continue;
            }
            d.routes.push(DiscoveredRoute {
                final_url: None,
                redirect_chain: vec![],
                auth_wall: false,
                catch_all: false,
                input_surface: InputSurface::None,
                path,
                method: op.method.clone(),
                status_code: 0,
                content_type: "application/json".into(),
                is_spa_shell: false,
                is_api: true,
                title: Some(
                    op.operation_id
                        .clone()
                        .unwrap_or_else(|| format!("OpenAPI: {}", op.path)),
                ),
                has_form: false,
                secured: Some(op.secured),
                has_body: op.has_body,
                source: "openapi".into(),
            });
        }
        d.notes.push(format!(
            "OpenAPI spec loaded from {} ({} operations)",
            spec.source,
            spec.ops.len()
        ));
        d.spec = Some(spec);
    }

    // 6. a spec on an API host that scope.toml lists. The agent tests the target origin only, so
    // the operations are reported, not planned.
    if d.spec.is_none() {
        for origin in api_origins {
            if !extras_ok(budget) {
                break;
            }
            let Ok(u) = reqwest::Url::parse(&origin) else {
                continue;
            };
            let mut scratch = vec![];
            if let Some(spec) = load_spec(
                &cl,
                &origin,
                &host_key_of(&u),
                u.host_str().unwrap_or(""),
                None,
                budget,
                &mut scratch,
            ) {
                d.notes.push(format!(
                    "OpenAPI spec found on API host {} ({}, {} operations); the agent tests the target origin only: run it with that host as the target to test them",
                    u.host_str().unwrap_or(""),
                    spec.source,
                    spec.ops.len()
                ));
            }
        }
    }

    // 7. where does each route take input?
    let spec_inputs: HashSet<String> = d
        .spec
        .as_ref()
        .map(|s| {
            s.api_ops()
                .iter()
                .filter(|o| !o.params.is_empty() || o.body.is_some())
                .map(|o| {
                    format!(
                        "{} {}{}",
                        o.method.to_ascii_uppercase(),
                        s.base_path,
                        o.path
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    for r in d.routes.iter_mut() {
        r.input_surface = derive_input_surface(r, &spec_inputs);
    }
    d
}

pub fn discover_routes(
    target: &str,
    spec_url: Option<&str>,
    max_urls: usize,
) -> (Vec<DiscoveredRoute>, TargetTechProfile) {
    crawl_and_discover_routes(target, spec_url, max_urls)
}

pub fn crawl_and_discover_routes(
    target: &str,
    spec_url: Option<&str>,
    max_urls: usize,
) -> (Vec<DiscoveredRoute>, TargetTechProfile) {
    let max_urls = max_urls.clamp(1, 500);
    // the crawl, the calibration, the SPA extraction and the spec probes (each bounded) share it
    let mut budget = RunBudget::from_env().with_max_requests(max_urls * 3 + 20 + 200);
    let d = discover(target, spec_url, max_urls, &mut budget);
    (d.routes, d.tech)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_title_survives_multibyte_and_case_expansion() {
        // 'İ' (U+0130) lowercases to two chars: the old to_lowercase()-based offsets shifted and sliced mid-char
        assert_eq!(
            extract_title("<html><head><TITLE>İstanbul — Ünï</TITLE></head>").as_deref(),
            Some("İstanbul — Ünï")
        );
        assert_eq!(extract_title("İİİİİ<title>x</title>").as_deref(), Some("x"));
        assert_eq!(extract_title("<title>never closed"), None);
        assert_eq!(extract_title("no title"), None);
        let long = format!("<title>{}</title>", "é".repeat(200));
        assert_eq!(extract_title(&long).unwrap().chars().count(), 80);
    }

    #[test]
    fn link_parser_keeps_same_host_and_drops_assets() {
        let html = r##"<a href="/events.php">E</a><a href="history.php">H</a><form action="/enquiry.php"></form>
            <a href="https://myvapi.com/x?y=1#z">abs</a><a href="https://evil.test/x">ext</a><a href="/logo.png">img</a><a href="#top">t</a><a href="mailto:a@b">m</a>"##;
        let mut seen = HashSet::new();
        let mut q = VecDeque::new();
        seen.insert("/".to_string());
        parse_internal_links_from_html(html, "myvapi.com", &mut seen, &mut q, 50);
        let got: Vec<&str> = q.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            got,
            ["/events.php", "/history.php", "/enquiry.php", "/x?y=1"]
        );
    }

    #[test]
    fn spec_base_path() {
        let d: Value = serde_json::json!({"servers": [{"url": "/api/v1/"}]});
        assert_eq!(servers_base_path(&d, "h"), "/api/v1");
        let d: Value = serde_json::json!({"servers": [{"url": "https://other.test/x"}]});
        assert_eq!(servers_base_path(&d, "h"), "");
        let d: Value = serde_json::json!({"servers": [{"url": "/"}]});
        assert_eq!(servers_base_path(&d, "h"), "");
        let d: Value = serde_json::json!({"servers": [{"url": "https://{host}/v1"}]});
        assert_eq!(servers_base_path(&d, "h"), "");
    }

    #[test]
    fn non_http_target_discovers_nothing() {
        let mut b = RunBudget::default();
        let d = discover("ftp://x", None, 10, &mut b);
        assert!(d.routes.is_empty() && !d.notes.is_empty());
        assert!(discover("/etc/passwd", None, 10, &mut b).routes.is_empty());
    }

    // ---- spec_url as a local file

    /// A closed port: the crawl finds nothing and fails fast, so only the spec can supply routes.
    const DEAD_TARGET: &str = "http://127.0.0.1:1";

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rh-spec-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn discover_with(spec: &str) -> Discovery {
        let mut b = RunBudget::default();
        discover(DEAD_TARGET, Some(spec), 5, &mut b)
    }

    #[test]
    fn a_local_json_spec_path_is_read_like_a_spec_url() {
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/qa-api/openapi.json"
        );
        let d = discover_with(fixture);
        let spec = d
            .spec
            .as_ref()
            .unwrap_or_else(|| panic!("no spec: {:?}", d.notes));
        assert_eq!(spec.source, fixture);
        assert!(
            spec.ops
                .iter()
                .any(|o| o.method == "POST" && o.path == "/orders")
        );
        assert!(
            d.routes
                .iter()
                .any(|r| r.source == "openapi" && r.path == "/orders" && r.method == "POST")
        );
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains("OpenAPI spec loaded from")),
            "{:?}",
            d.notes
        );
    }

    #[test]
    fn a_local_yaml_spec_and_a_file_url_are_read_too() {
        let dir = temp_dir("yaml");
        let f = dir.join("api.yaml");
        std::fs::write(
            &f,
            "openapi: 3.0.0\nservers:\n  - url: /api/v1\npaths:\n  /things:\n    get:\n      responses:\n        '200': {description: ok}\n",
        )
        .unwrap();
        for spec in [f.display().to_string(), format!("file://{}", f.display())] {
            let d = discover_with(&spec);
            let s = d
                .spec
                .as_ref()
                .unwrap_or_else(|| panic!("{spec}: {:?}", d.notes));
            assert_eq!(
                (s.base_path.as_str(), s.ops.len()),
                ("/api/v1", 1),
                "{spec}"
            );
            assert!(
                d.routes.iter().any(|r| r.path == "/api/v1/things"),
                "{spec}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_local_spec_that_cannot_be_used_is_reported_never_guessed() {
        let dir = temp_dir("bad");
        let big = dir.join("big.json");
        std::fs::write(&big, vec![b' '; LOCAL_SPEC_CAP + 1]).unwrap();
        let junk = dir.join("junk.json");
        std::fs::write(&junk, "{\"no\": \"paths\"}").unwrap();
        let text = dir.join("text.yaml");
        std::fs::write(&text, ": : :\n\t- [").unwrap();
        // at the cap exactly is accepted by the size check (the content just is not a spec)
        let at_cap = dir.join("cap.json");
        std::fs::write(&at_cap, vec![b' '; LOCAL_SPEC_CAP]).unwrap();
        for (spec, want) in [
            (big.display().to_string(), "5 MB limit"),
            (junk.display().to_string(), "no `paths`"),
            (text.display().to_string(), "neither valid JSON nor YAML"),
            (
                dir.display().to_string(),
                "neither an http(s) URL nor an existing file",
            ),
            (
                dir.join("missing.json").display().to_string(),
                "neither an http(s) URL nor an existing file",
            ),
            (
                "ftp://example.test/openapi.json".into(),
                "neither an http(s) URL nor an existing file",
            ),
        ] {
            let d = discover_with(&spec);
            assert!(d.spec.is_none(), "{spec}");
            assert!(
                d.notes.iter().any(|n| n.contains(want)),
                "{spec}: {:?}",
                d.notes
            );
        }
        assert!(read_local_spec(&at_cap).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn http_urls_are_never_treated_as_paths() {
        assert!(local_spec_path("http://x/openapi.json").is_none());
        assert!(local_spec_path("https://x/openapi.json").is_none());
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/qa-api/openapi.json"
        );
        assert!(local_spec_path(fixture).is_some());
        assert!(
            local_spec_path(&format!("  {fixture}  ")).is_some(),
            "surrounding blanks are trimmed"
        );
    }
    // ---- harvest_ids

    /// A server answering every request with `answer(method, path, authorization)`; returns its
    /// base URL and the log of "METHOD path" lines.
    fn stub(
        answer: impl Fn(&str, &str, Option<&str>) -> (u16, String) + Send + Sync + 'static,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let (lg, answer) = (log.clone(), std::sync::Arc::new(answer));
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let mut first = head.lines().next().unwrap_or("").split_whitespace();
                let (m, t) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
                let auth = head.lines().find_map(|l| {
                    l.to_ascii_lowercase()
                        .starts_with("authorization:")
                        .then(|| l["authorization:".len()..].trim().to_string())
                });
                lg.lock().unwrap().push(format!("{m} {t}"));
                let (code, body) = answer(m, t, auth.as_deref());
                let _ = write!(
                    s,
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (base, log)
    }

    fn fixture_spec_doc() -> SpecDoc {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/qa-api/openapi.json"
        ))
        .unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        let ops = crate::qa::plan::ops_from_doc(&doc);
        SpecDoc {
            doc,
            ops,
            base_path: String::new(),
            source: "t".into(),
        }
    }

    #[test]
    fn the_ids_of_existing_records_are_read_from_the_collection_as_the_acting_role() {
        let (base, log) = stub(|m, t, auth| match (m, t, auth) {
            ("GET", "/orders", Some("Bearer alice-token")) => (
                200,
                r#"[{"id":1,"item":"a"},{"id":2,"item":"b"},{"id":3},{"id":4},{"id":5}]"#.into(),
            ),
            _ => (401, r#"{"error":"unauthorized"}"#.into()),
        });
        let creds = Credentials::none()
            .with("alice", "alice-token")
            .with("admin", "admin-token");
        let mut b = RunBudget::default().with_rate(0.0);
        let (ids, notes) = harvest_ids(
            &fixture_spec_doc(),
            &base,
            &creds,
            Duration::from_secs(5),
            &mut b,
        );
        assert_eq!(
            ids.get("/orders").map(Vec::as_slice),
            Some(&["1".to_string(), "2".to_string(), "3".to_string()][..]),
            "a few ids, never the whole collection"
        );
        assert!(notes.iter().any(|n| n.contains("/orders")), "{notes:?}");
        // exactly one read-only request, the collection (the item path is not guessed)
        assert_eq!(*log.lock().unwrap(), ["GET /orders"]);
        assert_eq!(b.requests_used(), 1, "charged to the run budget");
    }

    #[test]
    fn nothing_is_harvested_without_a_credential_for_a_secured_collection_or_when_it_answers_badly()
    {
        let (base, log) = stub(|_, _, _| (500, "boom".into()));
        let mut b = RunBudget::default().with_rate(0.0);
        // no credential: not worth a 401, so no request at all
        let (ids, _) = harvest_ids(
            &fixture_spec_doc(),
            &base,
            &Credentials::none(),
            Duration::from_secs(5),
            &mut b,
        );
        assert!(ids.is_empty() && log.lock().unwrap().is_empty());
        // an administrator token is not an acting role either
        let admin = Credentials::none().with("admin", "t");
        let (ids, _) = harvest_ids(
            &fixture_spec_doc(),
            &base,
            &admin,
            Duration::from_secs(5),
            &mut b,
        );
        assert!(ids.is_empty() && log.lock().unwrap().is_empty());
        // a failing collection yields no ids and no note
        let alice = Credentials::none().with("alice", "t");
        let (ids, notes) = harvest_ids(
            &fixture_spec_doc(),
            &base,
            &alice,
            Duration::from_secs(5),
            &mut b,
        );
        assert!(ids.is_empty() && notes.is_empty());
        assert_eq!(log.lock().unwrap().len(), 1);
        // an exhausted request budget stops it
        let mut spent = RunBudget::default().with_max_requests(0);
        let (ids, _) = harvest_ids(
            &fixture_spec_doc(),
            &base,
            &alice,
            Duration::from_secs(5),
            &mut spent,
        );
        assert!(ids.is_empty());
        assert_eq!(log.lock().unwrap().len(), 1, "no request over the budget");
    }
}

/// Discovery against local sites: redirect chains, login walls, soft-404 calibration, SPA
/// extraction, scope, spec locations. No network beyond 127.0.0.1.
#[cfg(test)]
mod site_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    struct Reply {
        code: u16,
        ctype: &'static str,
        headers: Vec<(String, String)>,
        body: String,
    }

    fn page(code: u16, ctype: &'static str, body: &str) -> Reply {
        Reply {
            code,
            ctype,
            headers: vec![],
            body: body.into(),
        }
    }

    fn html(body: &str) -> Reply {
        page(200, "text/html; charset=utf-8", body)
    }

    fn redirect(code: u16, to: &str) -> Reply {
        Reply {
            code,
            ctype: "text/plain",
            headers: vec![("Location".into(), to.into())],
            body: String::new(),
        }
    }

    type Log = Arc<Mutex<Vec<(String, String)>>>;

    /// A site on all loopback addresses answering `answer(host_header, path_and_query)`. Returns
    /// the port and the log of (Host header, path) it was asked.
    fn site(answer: impl Fn(&str, &str) -> Reply + Send + Sync + 'static) -> (u16, Log) {
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let log: Log = Default::default();
        let (lg, answer) = (log.clone(), Arc::new(answer));
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let (lg, answer) = (lg.clone(), answer.clone());
                std::thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let path = head
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    let host = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .starts_with("host:")
                                .then(|| l["host:".len()..].trim().to_string())
                        })
                        .unwrap_or_default();
                    lg.lock().unwrap().push((host.clone(), path.clone()));
                    let r = answer(&host, &path);
                    let mut out = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        r.code,
                        r.ctype,
                        r.body.len()
                    );
                    for (k, v) in &r.headers {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    out.push_str("\r\n");
                    out.push_str(&r.body);
                    let _ = s.write_all(out.as_bytes());
                });
            }
        });
        (port, log)
    }

    fn budget() -> RunBudget {
        RunBudget::default().with_rate(0.0)
    }

    fn paths(log: &Log) -> Vec<String> {
        log.lock().unwrap().iter().map(|(_, p)| p.clone()).collect()
    }

    fn route<'a>(d: &'a Discovery, path: &str) -> &'a DiscoveredRoute {
        d.routes.iter().find(|r| r.path == path).unwrap_or_else(|| {
            panic!(
                "no route {path}: {:?}",
                d.routes.iter().map(|r| &r.path).collect::<Vec<_>>()
            )
        })
    }

    // ---- redirects and login walls

    #[test]
    fn fetch_records_the_first_status_the_chain_and_the_final_url() {
        let (port, log) = site(|_, p| match p {
            "/a" => redirect(302, "/b"),
            "/b" => redirect(301, "/c?x=1"),
            "/c?x=1" => html("<html><title>C</title><body>end</body></html>"),
            "/out" => redirect(302, "http://other.invalid/steal"),
            "/loop" => redirect(302, "/loop"),
            _ => page(404, "text/plain", "nf"),
        });
        let (cl, mut b) = (crawl_client().unwrap(), budget());
        let base = format!("http://127.0.0.1:{port}");
        let f = fetch(&cl, &format!("{base}/a"), "h", &mut b, 4096).unwrap();
        assert_eq!((f.status, f.final_status), (302, 200), "first hop vs final");
        assert_eq!(
            f.chain,
            [
                RedirectHop {
                    status: 302,
                    location: "/b".into()
                },
                RedirectHop {
                    status: 301,
                    location: "/c?x=1".into()
                }
            ]
        );
        assert_eq!(
            f.final_url.as_deref(),
            Some(format!("{base}/c?x=1").as_str())
        );
        assert!(f.body.contains("end") && f.content_type.contains("html"));
        assert_eq!(b.requests_used(), 3, "every hop is a budgeted request");

        // another host: recorded, not followed (the 3xx is the answer)
        let f = fetch(&cl, &format!("{base}/out"), "h", &mut b, 4096).unwrap();
        assert_eq!((f.status, f.final_status, f.final_url), (302, 302, None));
        assert_eq!(f.chain.len(), 1);
        assert_eq!(f.chain[0].location, "http://other.invalid/steal");

        // a loop stops after MAX_REDIRECTS followed hops
        let before = paths(&log).len();
        let f = fetch(&cl, &format!("{base}/loop"), "h", &mut b, 4096).unwrap();
        assert_eq!(f.final_status, 302);
        assert_eq!(paths(&log).len() - before, MAX_REDIRECTS + 1);

        // no redirect: nothing recorded
        let f = fetch(&cl, &format!("{base}/b"), "h", &mut b, 4096).unwrap();
        assert_eq!(f.chain.len(), 1);
        let (port2, _) = site(|_, _| html("<html>x</html>"));
        let f = fetch(
            &cl,
            &format!("http://127.0.0.1:{port2}/"),
            "h",
            &mut b,
            4096,
        )
        .unwrap();
        assert!(f.chain.is_empty() && f.final_url.is_none() && f.status == f.final_status);
    }

    #[test]
    fn the_login_matcher_reads_segments_and_identity_hosts_not_substrings() {
        for yes in [
            "/login",
            "/login?next=/dashboard",
            "/Sign-In",
            "/signin",
            "/sign_in",
            "/users/sign_in",
            "/account/login",
            "/auth/login",
            "/api/auth/signin?callbackUrl=%2F",
            "/sso/start",
            "/oauth2/authorize?client_id=1",
            "/login.php",
            "https://app.test/login",
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "https://acme.okta.com/app/x",
            "https://accounts.example.com/",
            "//sso.corp.test/start",
        ] {
            assert!(is_login_location(yes), "{yes}");
        }
        for no in [
            "",
            "/",
            "/dashboard",
            "/authors",
            "/blogin",
            "/about/login-page-design",
            "https://app.test/home?returnTo=/login",
            "/catalog",
            "https://shop.test/cart",
        ] {
            assert!(!is_login_location(no), "{no}");
        }
    }

    #[test]
    fn a_password_field_is_a_wall_and_so_is_a_401() {
        assert!(has_password_input(
            r#"<form><input type="password" name="p"></form>"#
        ));
        assert!(has_password_input("<INPUT class=x TYPE='password'>"));
        assert!(!has_password_input(
            r#"<input type="text" name="password_hint">"#
        ));
        assert!(!has_password_input("<p>type your password</p>"));
    }

    // ---- a Next.js app behind a login wall (the NuHire shape)

    const LOGIN_PAGE: &str = r#"<html><head><title>Sign in</title>
        <script src="/_next/static/build123/_buildManifest.js" defer></script>
        <script src="/_next/static/chunks/app/login/page-0123456789abcdef.js" defer></script>
        <script src="/_next/static/chunks/pages/dashboard-aaaaaaaaaaaaaaaa.js" defer></script>
        <script src="/_next/static/chunks/main-app-1234567890123456.js" defer></script>
        <script src="/_next/static/chunks/framework-abcdefabcdefabcd.js"></script>
        </head><body><form action="/login"><input type="password" name="p"><input name="e"></form><a href="/signup">New</a></body></html>"#;

    const MANIFEST: &str = r#"self.__BUILD_MANIFEST=function(s,a){return{__rewrites:{beforeFiles:[],afterFiles:[{source:"/old",destination:"/legacy"}],fallback:[]},"/":[s,"static/chunks/pages/index-1111111111111111.js"],"/_error":["static/chunks/pages/_error-2222222222222222.js"],"/dashboard":[a,"static/chunks/pages/dashboard-aaaaaaaaaaaaaaaa.js"],"/jobs/[id]":["static/chunks/pages/jobs/[id]-3333333333333333.js"],sortedPages:["/","/_app","/_error","/dashboard","/jobs/[id]","/reports"]}}("a","b");"#;

    const DASHBOARD_CHUNK: &str = r#""use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[100],{1:function(e,t,n){fetch("/api/jobs").then(r=>r.json());fetch("/api/users/"+id);fetch(`/api/companies/${cid}/members`);const u="https://api.thirdparty.example/v1/x";n.p="/_next/"}}]);"#;

    fn walled_next_site() -> (u16, Log) {
        site(|host, p| {
            let path = p.split('?').next().unwrap();
            match path {
                "/login" => html(LOGIN_PAGE),
                "/_next/static/build123/_buildManifest.js" => {
                    page(200, "application/javascript", MANIFEST)
                }
                "/_next/static/chunks/pages/dashboard-aaaaaaaaaaaaaaaa.js" => {
                    page(200, "application/javascript", DASHBOARD_CHUNK)
                }
                "/api/jobs" => page(401, "application/json", r#"{"error":"unauthorized"}"#),
                "/api/users" => page(200, "application/json", r#"[{"id":1,"name":"a"}]"#),
                "/api/companies" => page(404, "application/json", r#"{"error":"not found"}"#),
                "/robots.txt" => page(
                    200,
                    "text/plain",
                    &format!(
                        "User-agent: *\nDisallow: /admin\nSitemap: http://{host}/sitemap.xml\n"
                    ),
                ),
                "/sitemap.xml" => page(
                    200,
                    "application/xml",
                    &format!(
                        "<urlset><url><loc>http://{host}/pricing</loc></url><url><loc>https://evil.test/x</loc></url></urlset>"
                    ),
                ),
                "/pricing" => html(
                    "<html><head><title>Pricing</title></head><body>Plans and prices</body></html>",
                ),
                // everything else (including paths that cannot exist) is sent to the login page
                _ if path.starts_with("/_next/") => page(404, "text/plain", "nf"),
                _ => redirect(307, "/login"),
            }
        })
    }

    #[test]
    fn a_walled_next_app_gets_its_routes_apis_and_wall_recorded() {
        let (port, log) = walled_next_site();
        let target = format!("http://127.0.0.1:{port}");
        let mut b = budget();
        let d = discover_scoped(&target, None, 20, &mut b, None);

        // the root: 307 to /login, the wall is recorded, and it is still a real route
        let root = route(&d, "/");
        assert_eq!(root.status_code, 307, "the first hop, not the followed 200");
        assert!(root.auth_wall && !root.catch_all);
        assert_eq!(
            root.final_url.as_deref(),
            Some(format!("{target}/login").as_str())
        );
        assert_eq!(
            root.redirect_chain,
            [RedirectHop {
                status: 307,
                location: "/login".into()
            }]
        );
        assert!(
            d.tech.is_spa && d.tech.primary_framework == "Next.js",
            "{:?}",
            d.tech
        );

        // unknown paths are redirected to the login too: calibrated by their first hop
        let fp = d.soft404.as_ref().expect("calibrated");
        assert_eq!(fp.status, 307);

        // pages from the build manifest: real statuses, the wall visible, dynamic and internal routes out
        for p in ["/dashboard", "/reports"] {
            let r = route(&d, p);
            assert_eq!(
                (r.source.as_str(), r.status_code, r.auth_wall),
                ("manifest", 307, true),
                "{p}"
            );
            assert!(
                r.is_spa_shell && !r.catch_all,
                "{p}: a walled route is not a catch-all"
            );
        }
        let all: Vec<&str> = d.routes.iter().map(|r| r.path.as_str()).collect();
        for gone in ["/jobs/[id]", "/_app", "/_error", "/legacy", "/old"] {
            assert!(!all.contains(&gone), "{gone} in {all:?}");
        }
        assert!(route(&d, "/login").auth_wall, "a password form is a wall");

        // API paths from the chunk: only ones that answer, as JSON endpoints
        let jobs = route(&d, "/api/jobs");
        assert_eq!(
            (jobs.source.as_str(), jobs.status_code, jobs.is_api),
            ("js", 401, true)
        );
        assert!(jobs.auth_wall && jobs.input_surface == InputSurface::Json);
        assert_eq!(route(&d, "/api/users").status_code, 200);
        assert!(
            !all.contains(&"/api/companies"),
            "answered 404: not an endpoint"
        );

        // sitemap (same origin only) and robots paths
        let pricing = route(&d, "/pricing");
        assert_eq!(
            (pricing.source.as_str(), pricing.status_code),
            ("sitemap", 200)
        );
        assert!(!all.contains(&"/x"), "evil.test is another host");
        assert!(
            route(&d, "/admin").auth_wall,
            "a robots path behind the wall is kept as walled"
        );

        // the other host is reported, never requested
        assert_eq!(d.api_hosts_seen, ["api.thirdparty.example"]);
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains("API host api.thirdparty.example")
                    && n.contains("add to scope.toml")),
            "{:?}",
            d.notes
        );
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .all(|(h, _)| h == &format!("127.0.0.1:{port}"))
        );
        assert!(paths(&log).contains(&"/robots.txt".to_string()));
        // the notes say what was found
        let notes = d.notes.join("\n");
        assert!(notes.contains("manifest: 3 route(s)"), "{notes}");
        assert!(notes.contains("js chunks: 3 API path(s)"), "{notes}");
        assert!(
            notes.contains("1 dynamic route(s) not requested"),
            "{notes}"
        );
        assert!(notes.contains("soft-404 calibration"), "{notes}");
        // one request budget: everything above stayed bounded
        assert!(b.requests_used() < 120, "{}", b.requests_used());
    }

    #[test]
    fn extras_stop_when_the_request_budget_is_half_spent() {
        let (port, log) = walled_next_site();
        let target = format!("http://127.0.0.1:{port}");
        let mut b = RunBudget::default().with_rate(0.0).with_max_requests(12);
        let d = discover_scoped(&target, None, 20, &mut b, None);
        assert!(d.routes.iter().any(|r| r.path == "/"));
        assert!(b.requests_used() <= 12);
        assert!(
            log.lock().unwrap().len() <= 12,
            "no request beyond the budget"
        );
        assert!(
            !paths(&log).contains(&"/robots.txt".to_string()),
            "extras skipped: {:?}",
            paths(&log)
        );
    }

    // ---- a SPA that answers 200 with its shell for everything

    const SHELL: &str = r#"<html><head><title>App</title></head><body><div id="__next"></div>
        <script src="/_next/static/chunks/main-app-aaaaaaaaaaaaaaaa.js"></script><a href="/about">a</a><a href="/other">o</a></body></html>"#;

    fn shell_site() -> (u16, Log) {
        site(|host, p| match p.split('?').next().unwrap() {
            "/robots.txt" => page(200, "text/plain", "User-agent: *\nDisallow: /secret\n"),
            "/sitemap.xml" => page(
                200,
                "application/xml",
                &format!("<urlset><url><loc>http://{host}/pricing</loc></url></urlset>"),
            ),
            _ => html(SHELL),
        })
    }

    #[test]
    fn a_catch_all_shell_is_calibrated_flagged_and_not_counted() {
        let (port, _) = shell_site();
        let mut b = budget();
        let d = discover_scoped(&format!("http://127.0.0.1:{port}"), None, 20, &mut b, None);
        let fp = d.soft404.as_ref().expect("calibrated");
        assert_eq!(fp.status, 200);
        assert!(
            d.notes.iter().any(|n| n.contains("catch-all")),
            "{:?}",
            d.notes
        );

        // the root stays; linked pages that are the shell are flagged
        assert!(!route(&d, "/").catch_all);
        assert!(route(&d, "/about").catch_all && route(&d, "/other").catch_all);
        assert!(
            d.routes
                .iter()
                .filter(|r| r.catch_all)
                .all(|r| r.input_surface == InputSurface::None)
        );
        // sensitive-file probes that are the shell are flagged: not exposed
        for probe in ["/.env", "/.git/config"] {
            let r = route(&d, probe);
            assert_eq!(
                (r.status_code, r.source.as_str(), r.catch_all),
                (200, "probe", true),
                "{probe}"
            );
        }
        // the sitemap of a SPA stands (every path answers with the shell); a robots path is dropped
        assert!(!route(&d, "/pricing").catch_all);
        assert!(d.routes.iter().all(|r| r.path != "/secret"));
        // none of the shell's answers were taken for an OpenAPI document
        assert!(d.spec.is_none());
    }

    #[test]
    fn a_real_404_is_calibrated_too_and_nothing_is_flagged() {
        let (port, _) = site(|_, p| match p {
            "/" => html(r#"<html><body><a href="/real">r</a></body></html>"#),
            "/real" => html("<html><body>real page</body></html>"),
            _ => page(404, "text/html", "<html><body>Not found</body></html>"),
        });
        let mut b = budget();
        let d = discover_scoped(&format!("http://127.0.0.1:{port}"), None, 20, &mut b, None);
        assert_eq!(d.soft404.as_ref().map(|f| f.status), Some(404));
        assert!(d.routes.iter().all(|r| !r.catch_all), "{:?}", d.routes);
        assert_eq!(route(&d, "/real").input_surface, InputSurface::None);
        // a 404 probe is recorded as it is; a real 404 page is not a "catch-all"
        let env = route(&d, "/.env");
        assert_eq!((env.status_code, env.catch_all), (404, false));
    }

    // ---- scope: other hosts

    #[test]
    fn hosts_are_looked_at_only_when_scope_lists_them() {
        // the API server: listed as `localhost`; the out-of-scope one is the same server as 127.0.0.2
        let (api_port, api_log) = site(|_, p| match p {
            "/openapi.json" => page(
                200,
                "application/json",
                r#"{"openapi":"3.0.0","paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#,
            ),
            _ => page(404, "application/json", r#"{"detail":"Not Found"}"#),
        });
        let chunk = format!(
            r#"a=fetch("http://localhost:{api_port}/v1/items");b=fetch("http://127.0.0.2:{api_port}/v1/secret");"#
        );
        let (port, log) = site(move |_, p| match p.split('?').next().unwrap() {
            "/" => html(
                r#"<html><body><script src="/assets/index-abc123.js"></script><div id="root"></div></body></html>"#,
            ),
            "/assets/index-abc123.js" => page(200, "application/javascript", &chunk),
            _ => page(404, "text/plain", "nf"),
        });
        let scope: crate::scope::Scope =
            toml::from_str("[[hosts]]\nhost = \"localhost\"\nenv = \"nonprod\"\n").unwrap();
        let d = discover_scoped(
            &format!("http://127.0.0.1:{port}"),
            None,
            20,
            &mut budget(),
            Some(&scope),
        );
        assert_eq!(d.api_hosts_in_scope, ["localhost"]);
        assert_eq!(d.api_hosts_seen, ["127.0.0.2"]);
        let notes = d.notes.join("\n");
        assert!(
            notes
                .contains("API host 127.0.0.2 referenced by the app; add to scope.toml to test it"),
            "{notes}"
        );
        assert!(
            notes.contains("OpenAPI spec found on API host localhost"),
            "{notes}"
        );
        // the spec of the listed host is reported, not planned (the agent tests the target origin)
        assert!(d.spec.is_none() && d.routes.iter().all(|r| r.source != "openapi"));
        let seen = api_log.lock().unwrap().clone();
        assert!(
            seen.iter()
                .any(|(h, p)| h.starts_with("localhost:") && p == "/openapi.json"),
            "{seen:?}"
        );
        assert!(
            seen.iter().all(|(h, _)| !h.starts_with("127.0.0.2")),
            "never requested: {seen:?}"
        );
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .all(|(h, _)| h.starts_with("127.0.0.1:"))
        );

        // without a scope entry nothing is probed: both are only reported
        let before = api_log.lock().unwrap().len();
        let d = discover_scoped(
            &format!("http://127.0.0.1:{port}"),
            None,
            20,
            &mut budget(),
            None,
        );
        assert!(d.api_hosts_in_scope.is_empty());
        assert_eq!(d.api_hosts_seen.len(), 2);
        assert_eq!(
            api_log.lock().unwrap().len(),
            before,
            "no request to either API host"
        );
        // a bare `*` entry does not make every host a bundle mentions a test target
        let wild: crate::scope::Scope =
            toml::from_str("[[hosts]]\nhost = \"*\"\nenv = \"nonprod\"\n").unwrap();
        assert!(!host_in_scope(Some(&wild), "api.example.org"));
        assert!(host_in_scope(Some(&scope), "LOCALHOST"));
    }

    // ---- spec locations

    #[test]
    fn more_spec_locations_are_tried_and_a_docs_page_is_followed() {
        const SPEC: &str = r#"{"openapi":"3.0.0","paths":{"/things":{"get":{"parameters":[{"name":"q","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},"/ping":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#;
        // 1. a spec at /api-docs
        let (p1, _) = site(|_, p| match p {
            "/api-docs" => page(200, "application/json", SPEC),
            _ => page(404, "text/plain", "nf"),
        });
        let d = discover_scoped(
            &format!("http://127.0.0.1:{p1}"),
            None,
            5,
            &mut budget(),
            None,
        );
        assert!(
            d.spec
                .as_ref()
                .is_some_and(|s| s.source.ends_with("/api-docs")),
            "{:?}",
            d.notes
        );
        // an operation with parameters has a spec input surface, one without does not
        assert_eq!(route(&d, "/things").input_surface, InputSurface::Spec);
        assert_eq!(route(&d, "/ping").input_surface, InputSurface::None);

        // 2. /docs (Swagger UI) names the spec at a path nobody would guess
        let (p2, log2) = site(|_, p| match p {
            "/docs" => html(
                r#"<html><script>SwaggerUIBundle({ url: "/internal/spec-v7.json" })</script></html>"#,
            ),
            "/internal/spec-v7.json" => page(200, "application/json", SPEC),
            _ => page(404, "text/plain", "nf"),
        });
        let d = discover_scoped(
            &format!("http://127.0.0.1:{p2}"),
            None,
            5,
            &mut budget(),
            None,
        );
        assert!(
            d.spec
                .as_ref()
                .is_some_and(|s| s.source.ends_with("/internal/spec-v7.json")),
            "{:?}",
            d.notes
        );
        assert!(paths(&log2).contains(&"/docs".to_string()));

        // 3. the YAML and the well-known locations are asked for
        let (p3, log3) = site(|_, _| page(404, "text/plain", "nf"));
        let d = discover_scoped(
            &format!("http://127.0.0.1:{p3}"),
            None,
            5,
            &mut budget(),
            None,
        );
        assert!(d.spec.is_none());
        let asked = paths(&log3);
        for want in [
            "/openapi.yaml",
            "/swagger/v1/swagger.json",
            "/api/v1/openapi.json",
            "/.well-known/openapi",
            "/api-docs",
            "/docs",
        ] {
            assert!(asked.contains(&want.to_string()), "{want} in {asked:?}");
        }
    }

    // ---- input surface

    fn r(source: &str) -> DiscoveredRoute {
        DiscoveredRoute {
            path: "/x".into(),
            method: "GET".into(),
            source: source.into(),
            content_type: "text/html".into(),
            ..Default::default()
        }
    }

    #[test]
    fn input_surface_is_derived_from_what_the_route_takes() {
        let none = HashSet::new();
        let d = |x: &DiscoveredRoute| derive_input_surface(x, &none);
        assert_eq!(d(&r("crawl")), InputSurface::None, "plain page");
        let mut q = r("crawl");
        q.path = "/search?q=a".into();
        assert_eq!(d(&q), InputSurface::Query);
        let mut f = r("crawl");
        f.has_form = true;
        assert_eq!(d(&f), InputSurface::Form);
        let mut j = r("crawl");
        j.content_type = "application/json; charset=utf-8".into();
        assert_eq!(d(&j), InputSurface::Json);
        let mut a = r("crawl");
        a.is_api = true;
        a.has_form = true;
        assert_eq!(d(&a), InputSurface::Json, "an API wins over a form");
        assert_eq!(d(&r("js")), InputSurface::Json);
        let mut x = r("xhr");
        assert_eq!(d(&x), InputSurface::None);
        x.has_body = true;
        assert_eq!(d(&x), InputSurface::Json);
        // spec operations: only those with parameters or a body take input
        let mut op = r("openapi");
        op.is_api = true;
        assert_eq!(d(&op), InputSurface::None);
        let with: HashSet<String> = ["GET /x".to_string()].into();
        assert_eq!(derive_input_surface(&op, &with), InputSurface::Spec);
        op.has_body = true;
        assert_eq!(d(&op), InputSurface::Spec);
        // a catch-all takes nothing
        let mut c = r("crawl");
        c.has_form = true;
        c.catch_all = true;
        assert_eq!(d(&c), InputSurface::None);
    }

    #[test]
    fn local_paths_keep_only_the_targets_own_host() {
        assert_eq!(local_path("/a?b=1#h", "x.test").as_deref(), Some("/a?b=1"));
        assert_eq!(
            local_path("https://x.test/p?q=2", "x.test").as_deref(),
            Some("/p?q=2")
        );
        assert_eq!(
            local_path("https://www.x.test/p", "x.test").as_deref(),
            Some("/p")
        );
        assert_eq!(local_path("https://evil.test/p", "x.test"), None);
        assert_eq!(local_path("//evil.test/p", "x.test"), None);
        assert_eq!(local_path("rel/path", "x.test"), None);
    }

    #[test]
    fn sensitive_probes_cover_expanded_wordlist_respecting_budget_and_soft404() {
        let (port, _) = site(|_, p| match p {
            "/" => html("<html><body>hi</body></html>"),
            "/.git/HEAD" => page(200, "text/plain", "ref: refs/heads/main\n"),
            "/actuator/env" => page(200, "application/json", r#"{"propertySources":[]}"#),
            "/backup.sql" => page(200, "text/plain", "-- MySQL dump\nCREATE TABLE u(id INT);"),
            _ => page(404, "text/html", "<html>not found</html>"),
        });
        let mut b = budget();
        let d = discover_scoped(&format!("http://127.0.0.1:{port}"), None, 20, &mut b, None);
        assert!(
            d.routes
                .iter()
                .any(|r| r.path == "/.git/HEAD" && r.status_code == 200)
        );
        assert!(
            d.routes
                .iter()
                .any(|r| r.path == "/actuator/env" && r.status_code == 200)
        );
        assert!(
            d.routes
                .iter()
                .any(|r| r.path == "/backup.sql" && r.status_code == 200)
        );
        assert!(d.routes.iter().any(|r| r.path == "/.aws/credentials"));

        // Tight budget (like diff-aware mode max_requests = 40): skips extended wordlist
        let mut tight = crate::agent::budget::RunBudget::new(20, 40, Duration::from_secs(30), 0.0);
        let d_tight = discover_scoped(
            &format!("http://127.0.0.1:{port}"),
            None,
            20,
            &mut tight,
            None,
        );
        assert!(d_tight.routes.iter().any(|r| r.path == "/.env"));
        assert!(!d_tight.routes.iter().any(|r| r.path == "/.aws/credentials"));
    }
}
