//! Headless XHR discovery: load the start page and a few same-origin links in the Playwright
//! runner (`runners/playwright/qa.mjs`, mode `discover`) and record the fetch/XHR requests the app
//! makes (method, URL template, status, content type, JSON key shapes; values and credentials are
//! never recorded). Navigation only: no clicks, no form submits, and on a target that is not
//! nonprod (or in a dry run) the page's own non-GET requests are blocked.
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

use super::{Discovery, host_in_scope};
use crate::agent::budget::RunBudget;
use crate::agent::plan::Depth;
use crate::agent::types::{DiscoveredRoute, InputSurface};

/// Most XHR routes taken from one run.
const MAX_XHR_ROUTES: usize = 100;
/// Wall clock of the headless session (the runner's own deadline) and of the container.
const RUNNER_DEADLINE_MS: u64 = 60_000;
const CONTAINER_TIMEOUT_SECS: u64 = 90;
/// Request budget that must be left for the headless step to run (it is charged a share of it).
const MIN_REQUESTS_LEFT: usize = 100;

/// `/out/xhr.json` as the runner writes it.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct XhrReport {
    #[serde(default)]
    pub pages: Vec<XhrPage>,
    #[serde(default)]
    pub requests: Vec<XhrEntry>,
    /// Hosts the page called that the runner did not let through (outside the allowed set).
    #[serde(default)]
    pub other_hosts: Vec<XhrHost>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct XhrPage {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub status: u16,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct XhrHost {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub count: u32,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct XhrEntry {
    #[serde(default)]
    pub method: String,
    /// URL path with numeric / uuid / hash segments templated (`/api/jobs/{id}`).
    #[serde(default)]
    pub path: String,
    /// The first concrete path observed for the template (requestable as it stands).
    #[serde(default)]
    pub sample_path: String,
    /// Query parameter NAMES (never values).
    #[serde(default)]
    pub query_keys: Vec<String>,
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub content_type: String,
    /// Top-level JSON keys of the request / response body (never values).
    #[serde(default)]
    pub req_keys: Vec<String>,
    #[serde(default)]
    pub res_keys: Vec<String>,
    /// The request carried an Authorization header (the value is never recorded).
    #[serde(default)]
    pub has_auth: bool,
    /// The runner aborted the request (a non-GET on a target that may not be written to).
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub count: u32,
}

/// Does this run use the headless step: standard or deep profile, and an app that renders in
/// the browser.
pub fn xhr_wanted(profile: &str, tech: &crate::agent::types::TargetTechProfile) -> bool {
    Depth::from_profile(profile) != Depth::Quick && tech.is_spa
}

/// Merge a runner report into the discovery: same-origin requests become routes (source `xhr`),
/// hosts the page called become `api_hosts_in_scope` / `api_hosts_seen`. Returns the number of
/// routes added.
pub fn merge_xhr(
    d: &mut Discovery,
    rep: &XhrReport,
    scope: Option<&crate::scope::Scope>,
    target_host: &str,
) -> usize {
    let mut known: HashSet<(String, String)> = d
        .routes
        .iter()
        .map(|r| (r.method.to_ascii_uppercase(), r.path.clone()))
        .collect();
    let mut added = 0usize;
    for e in &rep.requests {
        if added >= MAX_XHR_ROUTES {
            break;
        }
        let method = e.method.to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
        ) {
            continue;
        }
        let path = if e.sample_path.is_empty() {
            e.path.clone()
        } else {
            e.sample_path.clone()
        };
        if !path.starts_with('/') || path.starts_with("//") || path.contains(char::is_whitespace) {
            continue;
        }
        if !known.insert((method.clone(), path.clone())) {
            continue;
        }
        let json_ct = e.content_type.to_ascii_lowercase().contains("json");
        let has_body = !e.req_keys.is_empty() || (method != "GET" && method != "HEAD");
        let is_api = json_ct || has_body || !e.res_keys.is_empty();
        let template = if e.path.is_empty() {
            path.clone()
        } else {
            e.path.clone()
        };
        let surface = if is_api {
            InputSurface::Json
        } else if !e.query_keys.is_empty() {
            InputSurface::Query
        } else {
            InputSurface::None
        };
        d.routes.push(DiscoveredRoute {
            final_url: None,
            redirect_chain: vec![],
            auth_wall: e.status == 401,
            catch_all: false,
            input_surface: surface,
            path,
            method,
            status_code: e.status,
            content_type: e.content_type.clone(),
            is_spa_shell: false,
            is_api,
            title: Some(format!(
                "XHR: {} {}",
                e.method.to_ascii_uppercase(),
                template
            )),
            has_form: false,
            secured: e.has_auth.then_some(true),
            has_body,
            source: "xhr".into(),
        });
        added += 1;
    }
    for h in &rep.other_hosts {
        let host = h.host.trim().to_ascii_lowercase();
        if host.is_empty() || host == target_host {
            continue;
        }
        if host_in_scope(scope, &host) {
            if !d.api_hosts_in_scope.contains(&host) {
                d.api_hosts_in_scope.push(host);
            }
        } else if !d.api_hosts_seen.contains(&host) {
            d.notes.push(format!(
                "API host {host} referenced by the app; add to scope.toml to test it"
            ));
            d.api_hosts_seen.push(host);
        }
    }
    added
}

/// Run the headless discovery and merge what it saw into `d`. Standard and deep profiles only, on
/// an app that renders in the browser, and only when Docker and the runner image are present
/// (otherwise a note says so and nothing else changes). `allow_writes` is the target being nonprod
/// AND the run not being a dry run: without it the page's own non-GET requests are blocked.
/// `work_dir` is a directory of the run (it holds the runner's input and output).
pub fn run_xhr_discovery(
    d: &mut Discovery,
    target: &str,
    profile: &str,
    work_dir: &Path,
    run_id: &str,
    budget: &mut RunBudget,
    allow_writes: bool,
) {
    if !xhr_wanted(profile, &d.tech) {
        return;
    }
    if std::env::var("READYHAI_AGENT_XHR")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "off" | "0" | "false"
            )
        })
        .unwrap_or(false)
    {
        d.notes
            .push("headless XHR discovery is off (READYHAI_AGENT_XHR)".into());
        return;
    }
    if budget.requests_left() < MIN_REQUESTS_LEFT || budget.is_cancelled() {
        d.notes
            .push("headless XHR discovery skipped: the request budget is nearly spent".into());
        return;
    }
    let docker = crate::tools::Docker::detect(&crate::engine::data_dir());
    if !docker.available {
        d.notes
            .push("headless XHR discovery skipped: docker not available".into());
        return;
    }
    let image = crate::qa::ui::playwright_image();
    if crate::tools::local_image_id(&image).is_none() {
        d.notes.push(format!(
            "headless XHR discovery skipped: runner image {image} is not present locally ({})",
            crate::qa::ui::HINT
        ));
        return;
    }
    let scope = crate::scope::active().ok().flatten();
    match run_runner(&docker, &image, d, target, work_dir, run_id, allow_writes) {
        Ok(rep) => {
            let host = reqwest::Url::parse(target)
                .ok()
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                .unwrap_or_default();
            let n = merge_xhr(d, &rep, scope.as_ref(), &host);
            // the browser's requests count against the run's allowance (a share of them: pages
            // and their requests, not every asset)
            let charge = (rep.pages.len()
                + rep.requests.iter().map(|r| r.count as usize).sum::<usize>())
            .min(40);
            for _ in 0..charge {
                if budget.take_request(&format!("{host}:xhr")).is_err() {
                    break;
                }
            }
            d.notes.push(format!(
                "headless XHR discovery: {} page(s), {} distinct request(s), {n} new route(s){}",
                rep.pages.len(),
                rep.requests.len(),
                if allow_writes {
                    ""
                } else {
                    " (non-GET requests of the page were blocked)"
                }
            ));
            d.notes.extend(rep.notes.iter().take(5).cloned());
        }
        Err(why) => d
            .notes
            .push(format!("headless XHR discovery skipped: {why}")),
    }
}

fn run_runner(
    docker: &crate::tools::Docker,
    image: &str,
    d: &Discovery,
    target: &str,
    work_dir: &Path,
    run_id: &str,
    allow_writes: bool,
) -> Result<XhrReport, String> {
    use crate::tools::ToolSpec;
    let out = work_dir.join("xhr-out");
    let src = work_dir.join("xhr-src");
    for p in [&out, &src] {
        std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        crate::snapshot::set_mode(p, 0o777);
    }
    let (cbase, gw) = crate::qa::ui::container_base(target);
    let input = serde_json::json!({
        "base_url": cbase,
        "modes": ["discover"],
        "max_pages": 8,
        "max_requests": 200,
        "deadline_ms": RUNNER_DEADLINE_MS,
        "writes": allow_writes,
        "allowed_hosts": d.api_hosts_in_scope,
    });
    let _ = std::fs::remove_file(out.join("xhr.json"));
    std::fs::write(
        out.join("xhr-input.json"),
        serde_json::to_vec_pretty(&input).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut ts = ToolSpec::new(
        "playwright",
        &["node", "/runner/qa.mjs", "/out/xhr-input.json"],
    );
    ts.image = Some(image.to_string());
    ts.network = true;
    ts.host_gateway = gw;
    ts.memory = "2g".into();
    ts.timeout_secs = CONTAINER_TIMEOUT_SECS;
    ts.tmpfs = vec!["/home/pwuser:rw,size=256m,mode=1777".into()];
    ts.env = vec![("PLAYWRIGHT_BROWSERS_PATH".into(), "/ms-playwright".into())];
    let run = docker
        .run_dirs(run_id, &src, &out, &ts)
        .map_err(|e| format!("{e:#}"))?;
    let text = std::fs::read_to_string(out.join("xhr.json")).map_err(|_| {
        format!(
            "the runner produced no report (exit {}): {}. An image built before the `discover` mode existed does this: {}",
            run.exit_code,
            run.stderr_tail.chars().take(200).collect::<String>(),
            crate::qa::ui::HINT
        )
    })?;
    serde_json::from_str(&text).map_err(|e| format!("xhr.json: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::types::TargetTechProfile;

    /// What the runner wrote for a walled Next.js app (values never appear, only names).
    const REPORT: &str = r#"{
      "base_url": "http://app.test/", "mode": "discover",
      "pages": [{"url": "http://app.test/", "path": "/", "status": 200}, {"url": "http://app.test/login", "path": "/login", "status": 200}],
      "requests": [
        {"method": "GET", "path": "/api/auth/session", "sample_path": "/api/auth/session", "query_keys": [], "status": 200, "content_type": "application/json", "req_keys": [], "res_keys": ["user", "expires"], "has_auth": false, "blocked": false, "count": 2},
        {"method": "GET", "path": "/api/jobs/{id}/applications", "sample_path": "/api/jobs/123/applications", "query_keys": ["limit", "offset"], "status": 401, "content_type": "application/json", "req_keys": [], "res_keys": ["error"], "has_auth": true, "blocked": false, "count": 1},
        {"method": "POST", "path": "/api/track", "sample_path": "/api/track", "query_keys": [], "status": 0, "content_type": "", "req_keys": ["event"], "res_keys": [], "has_auth": false, "blocked": true, "count": 1},
        {"method": "GET", "path": "/_next/image", "sample_path": "/_next/image", "query_keys": ["url", "w"], "status": 200, "content_type": "image/webp", "req_keys": [], "res_keys": [], "has_auth": false, "blocked": false, "count": 4},
        {"method": "GET", "path": "/plain", "sample_path": "/plain", "query_keys": [], "status": 200, "content_type": "text/plain", "req_keys": [], "res_keys": [], "has_auth": false, "blocked": false, "count": 1},
        {"method": "TRACE", "path": "/api/x", "sample_path": "/api/x", "status": 200},
        {"method": "GET", "path": "//evil.test/x", "sample_path": "//evil.test/x", "status": 200}
      ],
      "other_hosts": [{"host": "api.thirdparty.example", "count": 3}, {"host": "localhost", "count": 1}, {"host": "app.test", "count": 9}],
      "notes": []
    }"#;

    fn spa() -> TargetTechProfile {
        TargetTechProfile {
            is_spa: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_runner_report_becomes_xhr_routes_with_their_input_surface() {
        let rep: XhrReport = serde_json::from_str(REPORT).unwrap();
        assert_eq!((rep.pages.len(), rep.requests.len()), (2, 7));
        let mut d = Discovery::default();
        // an existing crawl route is not duplicated
        d.routes.push(DiscoveredRoute {
            path: "/api/auth/session".into(),
            method: "GET".into(),
            source: "crawl".into(),
            ..Default::default()
        });
        let scope: crate::scope::Scope =
            toml::from_str("[[hosts]]\nhost = \"localhost\"\nenv = \"nonprod\"\n").unwrap();
        let n = merge_xhr(&mut d, &rep, Some(&scope), "app.test");
        assert_eq!(
            n,
            4,
            "{:?}",
            d.routes
                .iter()
                .map(|r| (&r.method, &r.path))
                .collect::<Vec<_>>()
        );

        let jobs = d
            .routes
            .iter()
            .find(|r| r.path == "/api/jobs/123/applications")
            .unwrap();
        assert_eq!(jobs.source, "xhr");
        assert_eq!((jobs.method.as_str(), jobs.status_code), ("GET", 401));
        assert!(jobs.auth_wall && jobs.is_api && jobs.secured == Some(true));
        assert_eq!(jobs.input_surface, InputSurface::Json);
        assert_eq!(
            jobs.title.as_deref(),
            Some("XHR: GET /api/jobs/{id}/applications")
        );

        // a POST the runner blocked is still a route (status unknown), with a body
        let track = d.routes.iter().find(|r| r.path == "/api/track").unwrap();
        assert_eq!(
            (track.method.as_str(), track.status_code, track.has_body),
            ("POST", 0, true)
        );
        assert_eq!(track.input_surface, InputSurface::Json);

        // a GET with only query parameters and a non-JSON answer takes a query; a bare one takes nothing
        let img = d.routes.iter().find(|r| r.path == "/_next/image").unwrap();
        assert_eq!(
            (img.is_api, img.input_surface),
            (false, InputSurface::Query)
        );
        let plain = d.routes.iter().find(|r| r.path == "/plain").unwrap();
        assert_eq!(plain.input_surface, InputSurface::None);

        // no TRACE, no protocol-relative path; the crawl route stays the only one of its path
        assert!(
            d.routes
                .iter()
                .all(|r| r.path != "/api/x" && !r.path.starts_with("//"))
        );
        assert_eq!(
            d.routes
                .iter()
                .filter(|r| r.path == "/api/auth/session")
                .count(),
            1
        );

        // hosts: listed -> in scope; unlisted -> reported; the target itself -> ignored
        assert_eq!(d.api_hosts_in_scope, ["localhost"]);
        assert_eq!(d.api_hosts_seen, ["api.thirdparty.example"]);
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains("api.thirdparty.example") && n.contains("add to scope.toml"))
        );
    }

    #[test]
    fn merging_the_same_report_twice_adds_nothing_and_the_count_is_capped() {
        let rep: XhrReport = serde_json::from_str(REPORT).unwrap();
        let mut d = Discovery::default();
        assert_eq!(merge_xhr(&mut d, &rep, None, "app.test"), 5);
        assert_eq!(merge_xhr(&mut d, &rep, None, "app.test"), 0);
        let many = XhrReport {
            requests: (0..300)
                .map(|i| XhrEntry {
                    method: "GET".into(),
                    path: format!("/api/r{i}"),
                    sample_path: format!("/api/r{i}"),
                    content_type: "application/json".into(),
                    status: 200,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let mut d = Discovery::default();
        assert_eq!(merge_xhr(&mut d, &many, None, "app.test"), MAX_XHR_ROUTES);
        // an empty or garbled report adds nothing
        let empty: XhrReport = serde_json::from_str("{}").unwrap();
        assert_eq!(merge_xhr(&mut Discovery::default(), &empty, None, "x"), 0);
    }

    #[test]
    fn the_headless_step_runs_for_standard_and_deep_spas_only() {
        assert!(xhr_wanted("standard", &spa()));
        assert!(xhr_wanted("deep", &spa()));
        assert!(xhr_wanted(" Standard ", &spa()));
        assert!(!xhr_wanted("quick", &spa()));
        assert!(
            !xhr_wanted("standard", &TargetTechProfile::default()),
            "not a SPA"
        );
        // a quick run or a server-rendered app returns before anything is probed or noted
        let mut d = Discovery::default();
        let mut b = RunBudget::default();
        run_xhr_discovery(
            &mut d,
            "http://127.0.0.1:1",
            "quick",
            Path::new("."),
            "run-x",
            &mut b,
            false,
        );
        d.tech = spa();
        run_xhr_discovery(
            &mut d,
            "http://127.0.0.1:1",
            "quick",
            Path::new("."),
            "run-x",
            &mut b,
            false,
        );
        assert!(d.notes.is_empty() && d.routes.is_empty());
        // a nearly spent request budget skips it with a note (before Docker is even asked)
        let mut spent = RunBudget::default().with_max_requests(10);
        run_xhr_discovery(
            &mut d,
            "http://127.0.0.1:1",
            "standard",
            Path::new("."),
            "run-x",
            &mut spent,
            false,
        );
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains("skipped") && n.contains("budget")),
            "{:?}",
            d.notes
        );
    }

    /// Needs Docker and the runner image (`docker build -t readyhai/playwright-runner:local
    /// runners/playwright`): `cargo test live_headless -- --ignored`.
    #[test]
    #[ignore = "needs docker and the Playwright runner image"]
    fn live_headless_capture_against_a_local_site() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let posts = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let p2 = posts.clone();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (method, path) = {
                    let mut f = head.lines().next().unwrap_or("").split_whitespace();
                    (
                        f.next().unwrap_or("").to_string(),
                        f.next().unwrap_or("/").to_string(),
                    )
                };
                if method == "POST" {
                    *p2.lock().unwrap() += 1;
                }
                let (ct, body) = match path.as_str() {
                    "/" => ("text/html", r#"<html><body><script>fetch("/api/jobs/42/items?limit=5",{headers:{Authorization:"Bearer S"}});fetch("/api/track",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({event:"x"})})</script></body></html>"#.to_string()),
                    p if p.starts_with("/api/jobs") => ("application/json", r#"{"items":[],"total":0}"#.to_string()),
                    _ => ("text/plain", "ok".to_string()),
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let work = std::env::temp_dir().join(format!("rh-xhr-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let mut d = Discovery {
            tech: spa(),
            ..Default::default()
        };
        let mut b = RunBudget::default().with_rate(0.0);
        run_xhr_discovery(
            &mut d,
            &format!("http://127.0.0.1:{port}"),
            "standard",
            &work,
            "run-live-xhr",
            &mut b,
            false,
        );
        let _ = std::fs::remove_dir_all(&work);
        let route = |m: &str, p: &str| d.routes.iter().find(|r| r.method == m && r.path == p);
        let jobs = route("GET", "/api/jobs/42/items").unwrap_or_else(|| panic!("{:?}", d.notes));
        assert_eq!((jobs.status_code, jobs.source.as_str()), (200, "xhr"));
        assert!(jobs.secured == Some(true) && jobs.input_surface == InputSurface::Json);
        assert!(
            route("POST", "/api/track").is_some(),
            "seen, blocked, recorded"
        );
        assert_eq!(
            *posts.lock().unwrap(),
            0,
            "no write was sent without allow_writes"
        );
    }
}
