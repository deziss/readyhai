//! SPA and crawler extraction: build manifests, JS chunks, sitemap, and robots.txt.
use std::collections::{HashSet, VecDeque};

use super::harvest::host_key_of;
use super::spa;
use super::spec::{extras_ok, local_path, looks_destructive};
use super::surface::{fetch, host_in_scope, route_from};
use super::tech::Discovery;
use crate::agent::budget::RunBudget;
use crate::agent::types::{DiscoveredRoute, InputSurface};

pub const CRAWL_BODY_CAP: usize = 256 * 1024;
/// Largest JS chunk read when looking for API calls, and the most chunks and bytes read per run.
pub const CHUNK_CAP: usize = 2 * 1024 * 1024;
pub const MAX_CHUNKS: usize = 30;
pub const CHUNKS_TOTAL_CAP: usize = 24 * 1024 * 1024;
/// Largest sitemap / robots.txt read, and the most URLs taken from them.
pub const SITEMAP_CAP: usize = 2 * 1024 * 1024;
pub const MAX_SITEMAP_URLS: usize = 200;
/// Most page routes taken from a build manifest and most API paths taken from chunks.
pub const MAX_MANIFEST_ROUTES: usize = 60;
pub const MAX_JS_API_PATHS: usize = 40;
/// Most GET verifications of API paths found in chunks.
pub const API_VERIFY_CAP: usize = 15;
/// Most in-scope API hosts probed for an OpenAPI document.
pub const MAX_FOREIGN_SPEC_HOSTS: usize = 3;

/// What the extraction steps share.
pub struct Cx<'a> {
    pub cl: &'a reqwest::blocking::Client,
    /// Longer timeout for JS bundles.
    pub asset_cl: &'a reqwest::blocking::Client,
    pub base: &'a str,
    pub host_key: &'a str,
    pub target_host: &'a str,
    pub scope: Option<&'a crate::scope::Scope>,
    pub max_urls: usize,
}

impl Cx<'_> {
    /// An asset URL as written in a page, resolved against the target; None unless it is on the
    /// target host (or its `www.` twin) or a host scope.toml lists.
    pub fn asset_url(&self, raw: &str) -> Option<reqwest::Url> {
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
pub fn chunk_rank(url: &str) -> Option<u8> {
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
pub fn spa_extras(
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
