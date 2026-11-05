//! Discovery: technology fingerprint, bounded same-host crawl, OpenAPI operations.
//! Every request goes through the run budget.
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use super::budget::RunBudget;
use super::exec::{Auth, Clients, Credentials, OutReq, resolve_auth};
use super::types::{DiscoveredRoute, TargetTechProfile};

const CRAWL_BODY_CAP: usize = 256 * 1024;
const SPEC_CAP: usize = 4 * 1024 * 1024;
/// Largest spec read from a local file (the CLI's `--spec ./openapi.yaml`).
const LOCAL_SPEC_CAP: usize = 5 * 1024 * 1024;
const MAX_SPEC_ROUTES: usize = 200;

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

struct Fetched {
    status: u16,
    headers: reqwest::header::HeaderMap,
    content_type: String,
    body: String,
}

fn crawl_client() -> Option<reqwest::blocking::Client> {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects");
        }
        let same = attempt
            .previous()
            .last()
            .map(|p| p.host_str() == attempt.url().host_str())
            .unwrap_or(true);
        if same {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(5000))
        .danger_accept_invalid_certs(true)
        .redirect(policy)
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 ReadyHai/1.0")
        .build()
        .ok()
}

fn fetch(
    cl: &reqwest::blocking::Client,
    url: &str,
    host: &str,
    budget: &mut RunBudget,
    cap: usize,
) -> Result<Fetched, String> {
    budget.take_request(host)?;
    let resp = cl.get(url).send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut buf = Vec::new();
    let _ = resp.take(cap as u64).read_to_end(&mut buf);
    Ok(Fetched {
        status,
        headers,
        content_type,
        body: String::from_utf8_lossy(&buf).into_owned(),
    })
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
        None => [
            "/openapi.json",
            "/swagger.json",
            "/api/openapi.json",
            "/docs/openapi.json",
            "/v3/api-docs",
        ]
        .iter()
        .map(|p| format!("{origin}{p}"))
        .collect(),
    };
    let explicit = spec_url.is_some();
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
                continue;
            }
        };
        if !(200..300).contains(&f.status) {
            if explicit {
                notes.push(format!("OpenAPI spec fetch returned HTTP {}", f.status));
            }
            continue;
        }
        if let Some(spec) = spec_from_text(&f.body, url, target_host, notes, explicit) {
            return Some(spec);
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
        let sent = clients.send(&OutReq {
            method: "GET",
            url: &url,
            body: None,
            headers: &[],
            bearer: resolved.bearer.as_ref(),
        });
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

/// Full discovery with an explicit budget.
pub fn discover(
    target: &str,
    spec_url: Option<&str>,
    max_urls: usize,
    budget: &mut RunBudget,
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
    let Some(cl) = crawl_client() else {
        d.notes.push("could not build the HTTP client".into());
        return d;
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    seen.insert("/".into());

    // 1. root
    match fetch(&cl, &format!("{base}/"), &host_key, budget, CRAWL_BODY_CAP) {
        Ok(f) => {
            d.tech = detect_target_tech(&f.headers, &f.body, f.status, &f.content_type);
            let is_api =
                !d.tech.is_spa && f.status != 404 && f.content_type.contains("application/json");
            d.routes.push(DiscoveredRoute {
                path: "/".into(),
                method: "GET".into(),
                status_code: f.status,
                content_type: f.content_type.clone(),
                is_spa_shell: d.tech.is_spa,
                is_api,
                title: extract_title(&f.body),
                has_form: f.body.contains("<form") || f.body.contains("type=\"submit\""),
                secured: None,
                has_body: false,
                source: "crawl".into(),
            });
            if f.content_type.contains("text/html") {
                parse_internal_links_from_html(
                    &f.body,
                    &target_host,
                    &mut seen,
                    &mut queue,
                    max_urls * 5,
                );
            }
        }
        Err(e) => d.notes.push(format!("root request failed: {e}")),
    }

    // 2. BFS over same-host links
    while let Some(path) = queue.pop_front() {
        if d.routes.len() >= max_urls {
            break;
        }
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
        if f.status != 404 && f.status != 0 {
            d.routes.push(DiscoveredRoute {
                path: path.clone(),
                method: "GET".into(),
                status_code: f.status,
                content_type: f.content_type.clone(),
                is_spa_shell: d.tech.is_spa && f.content_type.contains("text/html"),
                is_api: f.content_type.contains("application/json")
                    || f.status == 401
                    || f.status == 403,
                title: extract_title(&f.body),
                has_form: f.body.contains("<form") || f.body.contains("type=\"submit\""),
                secured: None,
                has_body: false,
                source: "crawl".into(),
            });
        }
        if f.content_type.contains("text/html") && queue.len() < max_urls * 3 {
            parse_internal_links_from_html(
                &f.body,
                &target_host,
                &mut seen,
                &mut queue,
                max_urls * 5,
            );
        }
    }

    // 3. sensitive-file probes: status only, GET, safe in dry-run
    for probe in ["/.env", "/.git/config"] {
        if d.routes.iter().any(|r| r.path == probe) {
            continue;
        }
        if let Ok(f) = fetch(&cl, &format!("{base}{probe}"), &host_key, budget, 4096) {
            d.routes.push(DiscoveredRoute {
                path: probe.into(),
                method: "GET".into(),
                status_code: f.status,
                content_type: f.content_type,
                is_spa_shell: false,
                is_api: false,
                title: Some("Sensitive file probe".into()),
                has_form: false,
                secured: None,
                has_body: false,
                source: "probe".into(),
            });
        }
    }

    // 4. OpenAPI
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
    let mut budget = RunBudget::from_env().with_max_requests(max_urls * 3 + 20);
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
