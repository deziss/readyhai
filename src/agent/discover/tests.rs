use super::*;
use crate::agent::Credentials;
use crate::agent::types::RedirectHop;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::time::Duration;

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
fn nothing_is_harvested_without_a_credential_for_a_secured_collection_or_when_it_answers_badly() {
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

/// Discovery against local sites: redirect chains, login walls, soft-404 calibration, SPA
/// extraction, scope, spec locations. No network beyond 127.0.0.1.
#[cfg(test)]
mod site_tests {
    use super::*;
    use crate::agent::types::RedirectHop;
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

    #[test]
    fn test_parse_semantic_discovered_routes() {
        let raw = r#"[
            {"path": "/api/v1/internal/health", "method": "GET", "reasoning": "Standard Spring/Actuator monitor path"},
            {"path": "/api/v1/users/{id}/permissions", "method": "GET", "reasoning": "Inferred RBAC boundary from auth endpoints"}
        ]"#;
        let routes = super::semantic::parse_semantic_routes(raw).expect("parse semantic routes");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path, "/api/v1/internal/health");
        assert_eq!(routes[0].method, "GET");
        assert_eq!(routes[1].path, "/api/v1/users/{id}/permissions");
    }

    #[test]
    fn test_discover_semantic_routes_deterministic() {
        let tech = TargetTechProfile {
            app_architecture: "Microservices API".to_string(),
            primary_framework: "Spring Boot".to_string(),
            detected_signals: vec!["Spring Actuator".to_string()],
            ..Default::default()
        };
        let known = vec![];
        let directives = crate::agent::recon::SynthesizedDirectives {
            focus_areas: vec!["BOLA/IDOR on tenant endpoints".to_string()],
            boundary_rules: vec!["Stay in scope".to_string()],
            rules_of_engagement: "Security test".to_string(),
            canary_token: "CANARY_TEST".to_string(),
        };
        let routes = super::semantic::discover_semantic_routes(
            None,
            "https://example.com",
            &tech,
            &known,
            Some(&directives),
        );
        assert!(!routes.is_empty());
        assert!(routes.iter().any(|r| r.path == "/actuator/health"));
        assert!(routes.iter().any(|r| r.path == "/api/v1/tenant/settings"));
        assert!(routes.iter().all(|r| r.source == "semantic"));
    }
}
