//! Discovery: technology fingerprint, soft-404 calibration, bounded same-host crawl, SPA route and
//! API extraction (Next.js manifests, JS chunks, sitemap.xml, robots.txt), OpenAPI operations and
//! headless XHR capture. Every request goes through the run budget.

use std::collections::{HashSet, VecDeque};

use crate::agent::budget::RunBudget;
use crate::agent::types::{DiscoveredRoute, InputSurface, TargetTechProfile};

mod crawler;
mod harvest;
mod soft404;
mod spa;
mod spec;
mod surface;
mod tech;
mod xhr;
pub mod semantic;

#[cfg(test)]
mod tests;

pub use crawler::*;
pub use harvest::*;
pub use semantic::*;
pub use spec::*;
pub use surface::*;
pub use tech::*;
pub use xhr::run_xhr_discovery;

// Internal re-exports needed by submodules (soft404.rs and xhr.rs)
pub(crate) use surface::host_in_scope;
pub(crate) use surface::{Fetched, fetch};
pub(crate) use tech::Discovery;

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
