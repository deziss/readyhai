//! Text parsers for single-page apps: Next.js manifests and app-router chunk names, API strings in
//! JS chunks, `sitemap.xml` and `robots.txt`. Pure functions, no I/O: discovery fetches, these read.
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).unwrap())
}

/// Percent-decode the ASCII escapes a chunk path can carry (`%5Bid%5D` -> `[id]`).
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            && v.is_ascii()
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

/// A page route after normalisation: a plain path, or a dynamic template (`/jobs/[id]`) that cannot
/// be requested as it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    Static(String),
    Dynamic(String),
}

/// Classify a route string taken from a manifest, a chunk name or a payload. None: not a page
/// (internal `_app`/`_error`/`_next`, error pages, wildcards, garbage).
pub fn page_route(raw: &str) -> Option<Page> {
    let r = raw.trim();
    let r = r.split(['?', '#']).next().unwrap_or("");
    if !r.starts_with('/') || r.starts_with("//") || r.len() > 200 {
        return None;
    }
    if r.chars().any(|c| c.is_whitespace() || c.is_control()) || !r.is_ascii() {
        return None;
    }
    let r = if r.len() > 1 {
        r.trim_end_matches('/')
    } else {
        r
    };
    let first = r.trim_start_matches('/').split('/').next().unwrap_or("");
    if first.starts_with('_') || matches!(r, "/404" | "/500" | "/favicon.ico" | "/robots.txt") {
        return None;
    }
    if r.contains('*') || r.contains(':') || r.contains('\\') {
        return None;
    }
    if super::is_static_asset(r) {
        return None;
    }
    if r.contains('[') || r.contains('{') {
        return Some(Page::Dynamic(r.to_string()));
    }
    Some(Page::Static(r.to_string()))
}

// ---------------------------------------------------------------- HTML: scripts, Next.js hints

/// What one HTML document says about the app behind it.
#[derive(Debug, Default, Clone)]
pub struct PageAssets {
    /// `<script src>` and `<link href=*.js>` values, as written.
    pub script_srcs: Vec<String>,
    /// `_buildManifest.js` URLs (as written), pages router.
    pub manifest_urls: Vec<String>,
    /// Page routes named by chunk file names, `__NEXT_DATA__` and RSC link payloads.
    pub routes: BTreeSet<String>,
    /// Dynamic routes seen (`/jobs/[id]`): reported, not requested.
    pub dynamic: BTreeSet<String>,
    pub build_id: Option<String>,
}

impl PageAssets {
    pub fn merge(&mut self, o: PageAssets) {
        for s in o.script_srcs {
            if !self.script_srcs.contains(&s) {
                self.script_srcs.push(s);
            }
        }
        for m in o.manifest_urls {
            if !self.manifest_urls.contains(&m) {
                self.manifest_urls.push(m);
            }
        }
        self.routes.extend(o.routes);
        self.dynamic.extend(o.dynamic);
        if self.build_id.is_none() {
            self.build_id = o.build_id;
        }
    }

    fn add(&mut self, p: Option<Page>) {
        match p {
            Some(Page::Static(s)) => {
                self.routes.insert(s);
            }
            Some(Page::Dynamic(s)) => {
                self.dynamic.insert(s);
            }
            None => {}
        }
    }
}

/// Scripts, build manifest and route hints of one HTML document (any framework; the Next.js parts
/// simply find nothing elsewhere).
pub fn analyse_html(html: &str) -> PageAssets {
    static SCRIPT: OnceLock<Regex> = OnceLock::new();
    static LINK: OnceLock<Regex> = OnceLock::new();
    static NEXT_PAGE: OnceLock<Regex> = OnceLock::new();
    static BUILD_ID: OnceLock<Regex> = OnceLock::new();
    static RSC_HREF: OnceLock<Regex> = OnceLock::new();
    let mut a = PageAssets::default();
    for c in re(
        &SCRIPT,
        r#"(?is)<script\b[^>]*?\ssrc\s*=\s*["']([^"']+)["']"#,
    )
    .captures_iter(html)
    {
        a.script_srcs.push(c[1].to_string());
    }
    for c in re(
        &LINK,
        r#"(?is)<link\b[^>]*?\shref\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']"#,
    )
    .captures_iter(html)
    {
        let s = c[1].to_string();
        if !a.script_srcs.contains(&s) {
            a.script_srcs.push(s);
        }
    }
    for s in a.script_srcs.clone() {
        if s.split('?')
            .next()
            .unwrap_or("")
            .ends_with("/_buildManifest.js")
        {
            a.manifest_urls.push(s);
        }
    }
    a.build_id = re(&BUILD_ID, r#""buildId"\s*:\s*"([A-Za-z0-9_.-]+)""#)
        .captures(html)
        .map(|c| c[1].to_string());
    // the page the server rendered (`__NEXT_DATA__`)
    for c in re(&NEXT_PAGE, r#""page"\s*:\s*"(/[^"]*)""#).captures_iter(html) {
        a.add(page_route(&c[1]));
    }
    // the app router's own links, as they appear in the RSC payload (`self.__next_f.push`)
    for c in re(&RSC_HREF, r#"href\\*"\s*:\s*\\*"(/[^"\\\s]*)"#).captures_iter(html) {
        a.add(page_route(&c[1]));
    }
    let srcs = a.script_srcs.clone();
    for r in app_router_routes(html)
        .into_iter()
        .chain(pages_router_routes(html))
    {
        a.add(Some(r));
    }
    // chunk names also appear in the script list alone when the HTML is truncated
    for s in &srcs {
        for r in app_router_routes(s)
            .into_iter()
            .chain(pages_router_routes(s))
        {
            a.add(Some(r));
        }
    }
    a
}

/// Routes named by app-router page chunks: `.../chunks/app/<segments>/page-<hash>.js`. Route groups
/// `(x)` vanish from the URL, `@slot` and intercepting routes are skipped, `[param]` segments make
/// the route dynamic.
pub fn app_router_routes(text: &str) -> Vec<Page> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(
        &R,
        r#"chunks/app/((?:[^/"'\s?\\]+/)*)page(?:-[A-Za-z0-9_-]+)?\.js"#,
    );
    let mut out = vec![];
    for c in r.captures_iter(text) {
        let dir = pct_decode(&c[1]);
        let mut segs: Vec<&str> = vec![];
        let mut skip = false;
        for seg in dir.split('/').filter(|s| !s.is_empty()) {
            if seg.starts_with('@') || (seg.starts_with('(') && !seg.ends_with(')')) {
                skip = true; // parallel slot / intercepting route: not a URL of its own
                break;
            }
            if seg.starts_with('(') {
                continue; // route group
            }
            segs.push(seg);
        }
        if skip {
            continue;
        }
        let path = format!("/{}", segs.join("/"));
        if let Some(p) = page_route(&path) {
            out.push(p);
        }
    }
    out
}

/// Routes named by pages-router chunks: `.../chunks/pages/<name>-<hash>.js` (`index` is the folder).
pub fn pages_router_routes(text: &str) -> Vec<Page> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r#"chunks/pages/([^"'\s?\\]+?)(?:-[0-9a-f]{8,})?\.js"#);
    let mut out = vec![];
    for c in r.captures_iter(text) {
        let name = pct_decode(&c[1]);
        let name = match name.strip_suffix("/index") {
            Some(n) => n.to_string(),
            None if name == "index" => String::new(),
            None => name,
        };
        if let Some(p) = page_route(&format!("/{name}")) {
            out.push(p);
        }
    }
    out
}

// ---------------------------------------------------------------- pages router: _buildManifest.js

/// What a `_buildManifest.js` lists.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildManifest {
    pub routes: Vec<String>,
    pub dynamic: Vec<String>,
    /// Chunk files named by the manifest (`static/chunks/pages/x-abc.js`), relative to `/_next/`.
    pub chunks: Vec<String>,
}

/// Route keys of a build manifest, in the plain and the minified form alike: every `"/path":[`
/// key plus the strings of `sortedPages`. Only keys starting with `/` are routes (the chunk
/// lists may hold identifiers in the minified form), and `__rewrites` destinations are values,
/// never keys, so they are not read as routes.
pub fn parse_build_manifest(js: &str) -> BuildManifest {
    static KEY: OnceLock<Regex> = OnceLock::new();
    static SORTED: OnceLock<Regex> = OnceLock::new();
    static STR: OnceLock<Regex> = OnceLock::new();
    static CHUNK: OnceLock<Regex> = OnceLock::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut m = BuildManifest::default();
    let mut take = |raw: &str, m: &mut BuildManifest| {
        let raw = raw.to_string();
        if !seen.insert(raw.clone()) {
            return;
        }
        match page_route(&raw) {
            Some(Page::Static(s)) => m.routes.push(s),
            Some(Page::Dynamic(s)) => m.dynamic.push(s),
            None => {}
        }
    };
    for c in re(&KEY, r#""(/[^"\s]*)"\s*:\s*\["#).captures_iter(js) {
        take(&c[1], &mut m);
    }
    for c in re(&SORTED, r#"sortedPages"?\s*:\s*\[((?:\s*"[^"]*"\s*,?)*)\]"#).captures_iter(js) {
        for s in re(&STR, r#""(/[^"\s]*)""#).captures_iter(&c[1]) {
            take(&s[1], &mut m);
        }
    }
    for c in re(&CHUNK, r#""(static/[^"\s]+\.js)""#).captures_iter(js) {
        let s = c[1].to_string();
        if !m.chunks.contains(&s) {
            m.chunks.push(s);
        }
    }
    m
}

// ---------------------------------------------------------------- JS chunks: API strings

/// A request path out of a string literal: cut at the first dynamic part (`${id}`, `:id`, `{id}`,
/// `[id]`), at `?`/`#`, trailing slash dropped (so `"/api/users/"+id` names the collection
/// `/api/users`). None when nothing static is left.
pub fn clean_api_path(raw: &str) -> Option<String> {
    let cut = raw.split(['?', '#']).next().unwrap_or("");
    let mut segs: Vec<&str> = vec![];
    for seg in cut.split('/').skip(1) {
        if seg.is_empty()
            || seg.starts_with(':')
            || seg.contains(['{', '}', '$', '[', ']', '(', ')', '*', ',', ';', '='])
        {
            break;
        }
        segs.push(seg);
    }
    if segs.is_empty() {
        return None;
    }
    let p = format!("/{}", segs.join("/"));
    if p.len() > 200 || !p.is_ascii() || super::is_static_asset(&p) {
        return None;
    }
    Some(p)
}

/// API-looking path strings in a JS source: `"/api/..."`, `/graphql`, `/trpc/...`, `/rest/...`,
/// `/v1/...`. A bare `/api`, `/rest` or `/trpc` (a base constant) names no endpoint and is dropped.
pub fn api_paths_in_js(js: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(
        &R,
        r#"["'`](/(?:api|graphql|trpc|rest|v[0-9]{1,2})(?:/[^"'`\s\\<>)]*)?)["'`]"#,
    );
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    for c in r.captures_iter(js) {
        let Some(p) = clean_api_path(&c[1]) else {
            continue;
        };
        if matches!(p.as_str(), "/api" | "/rest" | "/trpc") {
            continue;
        }
        if seen.insert(p.clone()) {
            out.push(p);
        }
    }
    out
}

/// `scheme://host[:port]` origins and the paths after them, for absolute http(s) URLs in string
/// literals of a JS source.
pub fn absolute_urls_in_js(js: &str) -> Vec<reqwest::Url> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(
        &R,
        r#"["'`](https?://[A-Za-z0-9._~-]+(?::[0-9]{2,5})?(?:/[^"'`\s\\<>)]*)?)["'`]"#,
    );
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    for c in r.captures_iter(js) {
        if let Ok(u) = reqwest::Url::parse(&c[1])
            && seen.insert(u.as_str().to_string())
        {
            out.push(u);
        }
    }
    out
}

/// Hosts that are never the app's own API: documentation, standards, CDNs, analytics, social.
fn is_noise_host(host: &str) -> bool {
    const NOISE: &[&str] = &[
        "w3.org",
        "schema.org",
        "reactjs.org",
        "react.dev",
        "nextjs.org",
        "vercel.com",
        "github.com",
        "githubusercontent.com",
        "googleapis.com",
        "gstatic.com",
        "google.com",
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "facebook.com",
        "facebook.net",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "youtube.com",
        "youtu.be",
        "mozilla.org",
        "npmjs.com",
        "unpkg.com",
        "jsdelivr.net",
        "cloudflare.com",
        "fontawesome.com",
        "stripe.com",
        "sentry.io",
        "hotjar.com",
        "segment.com",
        "mixpanel.com",
        "amplitude.com",
        "intercom.io",
        "w3schools.com",
        "example.com",
        "example.org",
        "creativecommons.org",
        "wikipedia.org",
    ];
    let h = host.to_ascii_lowercase();
    NOISE
        .iter()
        .any(|n| h == *n || h.ends_with(&format!(".{n}")))
}

/// Is an absolute URL the app's API (as opposed to a link to a docs page or a CDN asset)?
pub fn is_api_url(u: &reqwest::Url) -> bool {
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    if host.is_empty() || is_noise_host(&host) {
        return false;
    }
    let path = u.path().to_ascii_lowercase();
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    let path_api = matches!(first, "api" | "graphql" | "trpc" | "rest")
        || (first.starts_with('v')
            && first.len() <= 3
            && first[1..].chars().all(|c| c.is_ascii_digit())
            && first.len() > 1);
    let label = host.split('.').next().unwrap_or("");
    let host_api = label.starts_with("api")
        || label.ends_with("-api")
        || label.contains("-api-")
        || matches!(label, "gateway" | "backend" | "graphql" | "rest" | "bff");
    path_api || host_api
}

// ---------------------------------------------------------------- sitemap.xml and robots.txt

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// `<loc>` URLs of a sitemap and whether the document is a sitemap index (its `<loc>`s are other
/// sitemaps). At most `cap` URLs.
pub fn parse_sitemap(xml: &str, cap: usize) -> (Vec<String>, bool) {
    static LOC: OnceLock<Regex> = OnceLock::new();
    let lower_head: String = xml
        .chars()
        .take(2048)
        .collect::<String>()
        .to_ascii_lowercase();
    if !lower_head.contains("<urlset")
        && !lower_head.contains("<sitemapindex")
        && !xml.contains("<loc>")
    {
        return (vec![], false);
    }
    let index = lower_head.contains("<sitemapindex");
    let mut out = vec![];
    for c in re(
        &LOC,
        r"(?is)<loc>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</loc>",
    )
    .captures_iter(xml)
    {
        let u = xml_unescape(c[1].trim());
        if !u.is_empty() {
            out.push(u);
        }
        if out.len() >= cap {
            break;
        }
    }
    (out, index)
}

/// What a `robots.txt` names: `Sitemap:` URLs and the paths of `Allow`/`Disallow` rules (wildcard
/// rules are cut at the wildcard; `/` and empty rules say nothing).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Robots {
    pub sitemaps: Vec<String>,
    pub paths: Vec<String>,
}

pub fn parse_robots(text: &str, cap: usize) -> Robots {
    let mut r = Robots::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "sitemap" => {
                if !v.is_empty() && !r.sitemaps.contains(&v.to_string()) && r.sitemaps.len() < 5 {
                    r.sitemaps.push(v.to_string());
                }
            }
            "allow" | "disallow" => {
                let v = v.trim_end_matches('$');
                let v = v.split('*').next().unwrap_or("");
                if !v.starts_with('/') || v == "/" || v.len() > 200 {
                    continue;
                }
                if r.paths.len() < cap && !r.paths.contains(&v.to_string()) {
                    r.paths.push(v.to_string());
                }
            }
            _ => {}
        }
    }
    r
}

// ---------------------------------------------------------------- spec links in HTML

/// A spec URL named by an API docs page (Swagger UI `url: "..."`, ReDoc `spec-url="..."`, a link
/// to `openapi.json`/`swagger.json`/`.yaml`), as written.
pub fn spec_link_in_html(html: &str) -> Option<String> {
    static A: OnceLock<Regex> = OnceLock::new();
    static B: OnceLock<Regex> = OnceLock::new();
    if let Some(c) = re(
        &A,
        r#"(?i)(?:\burl|spec-url|specurl)["']?\s*[:=]\s*["']([^"']+)["']"#,
    )
    .captures(html)
    {
        let u = c[1].trim();
        if !u.is_empty() && !u.starts_with("data:") && !u.starts_with('#') {
            return Some(u.to_string());
        }
    }
    re(
        &B,
        r#"(?i)["']([^"'\s]*(?:openapi|swagger)[^"'\s]*\.(?:json|ya?ml))["']"#,
    )
    .captures(html)
    .map(|c| c[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Next 12 style: minified, chunk lists hold variables, rewrites carry destinations.
    const MINIFIED: &str = r#"self.__BUILD_MANIFEST=function(s,a,e){return{__rewrites:{beforeFiles:[],afterFiles:[{source:"/old",destination:"/legacy"}],fallback:[{source:"/:path*",destination:"/proxy/:path*"}]},"/":[s,a,"static/chunks/pages/index-1111111111111111.js"],"/_error":["static/chunks/pages/_error-2222222222222222.js"],"/dashboard":[e,"static/chunks/pages/dashboard-aaaaaaaaaaaaaaaa.js"],"/jobs/[id]":["static/chunks/pages/jobs/[id]-3333333333333333.js"],"/settings/profile":[s],sortedPages:["/","/_app","/_error","/dashboard","/jobs/[id]","/reports","/settings/profile"]}}("a","b","c");self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()"#;

    /// Next 13 style: plain JSON.
    const PLAIN: &str = r#"self.__BUILD_MANIFEST = {"__rewrites":{"afterFiles":[],"beforeFiles":[],"fallback":[]},"sortedPages":["/_app","/_error","/blog","/blog/[slug]","/about"],"/":["static/chunks/pages/index-abc.js"],"/about":["static/chunks/pages/about-def.js"],"/blog":["static/chunks/pages/blog-1.js"]};self.__BUILD_MANIFEST_CB && self.__BUILD_MANIFEST_CB()"#;

    #[test]
    fn a_minified_build_manifest_yields_routes_and_ignores_rewrites_and_internals() {
        let m = parse_build_manifest(MINIFIED);
        assert_eq!(
            m.routes,
            ["/", "/dashboard", "/settings/profile", "/reports"],
            "keys first, then sortedPages-only entries; no /_app, /_error, /legacy, /old, /proxy"
        );
        assert_eq!(m.dynamic, ["/jobs/[id]"]);
        assert!(
            m.chunks
                .contains(&"static/chunks/pages/dashboard-aaaaaaaaaaaaaaaa.js".to_string())
        );
    }

    #[test]
    fn a_plain_build_manifest_works_too() {
        let m = parse_build_manifest(PLAIN);
        assert_eq!(m.routes, ["/", "/about", "/blog"]);
        assert_eq!(m.dynamic, ["/blog/[slug]"]);
        assert_eq!(
            parse_build_manifest("not a manifest"),
            BuildManifest::default()
        );
    }

    #[test]
    fn app_router_page_chunks_name_routes() {
        let html = r#"<script src="/_next/static/chunks/app/layout-1a2b3c4d5e6f7a8b.js" async></script>
            <script src="/_next/static/chunks/app/page-1a2b3c4d5e6f7a8b.js" async></script>
            <script src="/_next/static/chunks/app/dashboard/settings/page-0123456789abcdef.js" async></script>
            <script src="/_next/static/chunks/app/(marketing)/pricing/page-0123456789abcdef.js"></script>
            <script src="/_next/static/chunks/app/%28auth%29/login/page-0123456789abcdef.js"></script>
            <script src="/_next/static/chunks/app/jobs/%5Bid%5D/page-0123456789abcdef.js"></script>
            <script src="/_next/static/chunks/app/@modal/photo/page-0123456789abcdef.js"></script>
            <script src="/_next/static/chunks/app/_not-found/page-0123456789abcdef.js"></script>"#;
        let a = analyse_html(html);
        assert_eq!(
            a.routes.iter().map(String::as_str).collect::<Vec<_>>(),
            ["/", "/dashboard/settings", "/login", "/pricing"],
            "groups vanish, slots and _not-found are skipped, layouts are not pages"
        );
        assert_eq!(a.dynamic.iter().collect::<Vec<_>>(), ["/jobs/[id]"]);
        assert_eq!(a.script_srcs.len(), 8);
    }

    #[test]
    fn pages_router_chunks_the_next_data_page_and_rsc_links_name_routes() {
        let html = r#"<script src="/_next/static/chunks/pages/index-1111111111111111.js"></script>
            <script src="/_next/static/chunks/pages/blog/index-2222222222222222.js"></script>
            <script src="/_next/static/chunks/pages/blog/[slug]-3333333333333333.js"></script>
            <script src="/_next/static/chunks/pages/_app-4444444444444444.js"></script>
            <script src="/_next/static/build-xyz/_buildManifest.js?dpl=abc" defer></script>
            <script id="__NEXT_DATA__" type="application/json">{"props":{},"page":"/account","query":{},"buildId":"build-xyz"}</script>
            <script>self.__next_f.push([1,"3:[\"$\",\"a\",null,{\"href\":\"/team\",\"children\":\"Team\"}],[\"$\",\"a\",null,{\"href\":\"/api/x\"}]"])</script>"#;
        let a = analyse_html(html);
        assert_eq!(
            a.routes.iter().map(String::as_str).collect::<Vec<_>>(),
            ["/", "/account", "/api/x", "/blog", "/team"]
        );
        assert_eq!(a.dynamic.iter().collect::<Vec<_>>(), ["/blog/[slug]"]);
        assert_eq!(
            a.manifest_urls,
            ["/_next/static/build-xyz/_buildManifest.js?dpl=abc"]
        );
        assert_eq!(a.build_id.as_deref(), Some("build-xyz"));
    }

    #[test]
    fn api_paths_are_read_from_string_literals_and_cut_at_the_dynamic_part() {
        let js = r#"e.get("/api/jobs").then(t);fetch("/api/users/"+id);fetch(`/api/companies/${cid}/members`);
            axios.post('/api/auth/login',d);const g="/graphql";x("/v2/items/:id/children");y("/apiary/x");z("/api");
            w("/api/files/report.pdf");q("/api/search?q=1&page=2");const u="https://api.example.org/v1/jobs";"#;
        assert_eq!(
            api_paths_in_js(js),
            [
                "/api/jobs",
                "/api/users",
                "/api/companies",
                "/api/auth/login",
                "/graphql",
                "/v2/items",
                "/api/search"
            ],
            "no /apiary, bare /api or asset"
        );
    }

    #[test]
    fn absolute_urls_split_api_hosts_from_documentation_and_cdn_noise() {
        let js = r#"a("https://api.nuhire.in/v1/jobs");b("https://react.dev/errors/1");c("https://www.w3.org/2000/svg");
            d("https://backend.corp.test:8443/health");e("https://cdn.example-assets.net/img/x.png");f("https://api.stripe.com/v1/charges");"#;
        let all = absolute_urls_in_js(js);
        assert_eq!(all.len(), 6);
        let api: Vec<&str> = all
            .iter()
            .filter(|u| is_api_url(u))
            .map(|u| u.host_str().unwrap())
            .collect();
        assert_eq!(api, ["api.nuhire.in", "backend.corp.test"]);
    }

    #[test]
    fn sitemaps_and_indexes_are_read_with_a_cap() {
        let xml = r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://x.test/</loc></url><url><loc> https://x.test/a?b=1&amp;c=2 </loc></url>
            <url><loc><![CDATA[https://x.test/cdata]]></loc></url></urlset>"#;
        let (locs, index) = parse_sitemap(xml, 10);
        assert!(!index);
        assert_eq!(
            locs,
            [
                "https://x.test/",
                "https://x.test/a?b=1&c=2",
                "https://x.test/cdata"
            ]
        );
        assert_eq!(parse_sitemap(xml, 2).0.len(), 2);
        let idx =
            "<sitemapindex><sitemap><loc>https://x.test/s1.xml</loc></sitemap></sitemapindex>";
        assert_eq!(
            parse_sitemap(idx, 10),
            (vec!["https://x.test/s1.xml".to_string()], true)
        );
        // an HTML app shell served for /sitemap.xml is not a sitemap
        assert_eq!(
            parse_sitemap("<html><body>app</body></html>", 10),
            (vec![], false)
        );
    }

    #[test]
    fn robots_rules_become_paths_and_sitemap_lines() {
        let txt = "User-agent: *\nDisallow: /admin\nDisallow: /private/*.json$ # comment\nAllow: /public/\nDisallow:\nDisallow: /\nDisallow: /*.pdf$\nSitemap: https://x.test/sitemap.xml\nsitemap: https://x.test/s2.xml\nCrawl-delay: 5\n";
        let r = parse_robots(txt, 50);
        assert_eq!(r.paths, ["/admin", "/private/", "/public/"]);
        assert_eq!(
            r.sitemaps,
            ["https://x.test/sitemap.xml", "https://x.test/s2.xml"]
        );
        assert_eq!(parse_robots("<html>nope</html>", 50), Robots::default());
        assert_eq!(parse_robots(txt, 1).paths.len(), 1);
    }

    #[test]
    fn a_docs_page_names_its_spec() {
        assert_eq!(
            spec_link_in_html(r##"<script>const ui = SwaggerUIBundle({ url: "/api/v1/openapi.json", dom_id: "#swagger-ui" })</script>"##).as_deref(),
            Some("/api/v1/openapi.json")
        );
        assert_eq!(
            spec_link_in_html(r#"<redoc spec-url="/spec/api.yaml"></redoc>"#).as_deref(),
            Some("/spec/api.yaml")
        );
        assert_eq!(
            spec_link_in_html(r#"<a href="/files/swagger.json">spec</a>"#).as_deref(),
            Some("/files/swagger.json")
        );
        assert_eq!(spec_link_in_html("<html>no spec here</html>"), None);
    }

    #[test]
    fn page_route_rejects_what_is_not_a_page() {
        for bad in [
            "/_app",
            "/_next/x",
            "/404",
            "/a*b",
            "/x:y",
            "//evil.test",
            "rel",
            "/a b",
            "/logo.png",
        ] {
            assert_eq!(page_route(bad), None, "{bad}");
        }
        assert_eq!(page_route("/a/b/"), Some(Page::Static("/a/b".into())));
        assert_eq!(page_route("/a?x=1#h"), Some(Page::Static("/a".into())));
        assert_eq!(
            page_route("/[...slug]"),
            Some(Page::Dynamic("/[...slug]".into()))
        );
    }
}
