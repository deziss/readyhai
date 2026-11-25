use super::*;
use crate::agent::budget::RunBudget;
use crate::agent::oracle::*;
use crate::agent::types::*;
use std::time::Duration;

fn case(method: &str, component: &str, payload: Option<&str>) -> PlannedCase {
    PlannedCase {
        id: "TC-001".into(),
        title: "t".into(),
        component: component.into(),
        method: method.into(),
        technique: "boundary".into(),
        input_hint: String::new(),
        payload: payload.map(String::from),
        headers: vec![],
        content_type: None,
        probe_oracle: None,
        expected_behavior: String::new(),
        expected_status: None,
        risk_level: "low".into(),
        role: None,
        secured: None,
        route_status: None,
        expect_fields: vec![],
        expected_content_type: None,
        source: None,
        stateful_steps: None,
        concurrency_burst: None,
        contract: None,
        changed_ops: vec![],
        area: String::new(),
        regression_of: vec![],
        history_priority: false,
    }
}

#[test]
fn only_the_seven_http_methods_are_allowed() {
    for m in ["GET", "head", "Options", "POST", "put", "PATCH", "delete"] {
        assert!(
            build_request(&case(m, "/x", None), "http://h").is_ok(),
            "{m}"
        );
    }
    for m in [
        "TRACE",
        "CONNECT",
        "PROPFIND",
        "",
        "GET /x HTTP/1.1\r\nX:",
        "G ET",
    ] {
        assert!(
            build_request(&case(m, "/x", None), "http://h").is_err(),
            "{m:?} must be rejected"
        );
    }
}

#[test]
fn components_cannot_leave_the_target_or_inject() {
    for bad in [
        "http://evil.test/x",
        "//evil.test/x",
        "/a b",
        "/a\r\nHost: evil",
        "",
        "/orders/{id}",
    ] {
        assert!(
            build_request(&case("GET", bad, None), "http://h").is_err(),
            "{bad:?}"
        );
    }
    let ok = build_request(&case("GET", "orders", None), "http://h:8080/").unwrap();
    assert_eq!(ok.url, "http://h:8080/orders");
}

#[test]
fn get_payload_goes_to_the_query_string_not_the_body() {
    let s = build_request(
        &case("GET", "/search", Some("q=\"><script>alert(1)</script>")),
        "http://h",
    )
    .unwrap();
    assert!(s.body.is_none());
    assert!(s.url.starts_with("http://h/search?q="), "{}", s.url);
    assert!(
        s.sent_values
            .iter()
            .any(|v| v == "\"><script>alert(1)</script>")
    );
    let j = build_request(
        &case("HEAD", "/search", Some("{\"a\": 1, \"b\": \"x y\"}")),
        "http://h",
    )
    .unwrap();
    assert!(
        j.body.is_none()
            && j.url.contains("a=1")
            && (j.url.contains("b=x+y") || j.url.contains("b=x%20y")),
        "{}",
        j.url
    );
    let free = build_request(&case("GET", "/s?z=1", Some("' OR '1'='1")), "http://h").unwrap();
    assert!(
        free.url.contains("z=1") && free.url.contains("q="),
        "{}",
        free.url
    );
    let post = build_request(
        &case("POST", "/orders", Some("{\"item\": \"a\"}")),
        "http://h",
    )
    .unwrap();
    assert_eq!(post.body.as_ref().unwrap().0, "application/json");
    let bad_json = build_request(&case("POST", "/orders", Some("{\"")), "http://h").unwrap();
    assert_eq!(
        bad_json.body.unwrap().0,
        "application/json",
        "malformed JSON is still sent as JSON: that is the test"
    );
    let form = build_request(&case("POST", "/f", Some("data=AAA&x=1")), "http://h").unwrap();
    assert_eq!(form.body.unwrap().0, "application/x-www-form-urlencoded");
}

#[test]
fn curl_uses_the_same_method_url_body_and_single_quotes() {
    let mut c = case("PATCH", "/o/1", Some("{\"note\": \"it's\"}"));
    c.role = Some("user".into());
    let s = build_request(&c, "http://h").unwrap();
    let curl = curl_for(&s);
    assert!(curl.contains("-X PATCH"), "{curl}");
    assert!(curl.contains("'http://h/o/1'"), "{curl}");
    assert!(
        curl.contains("--data-raw '{\"note\": \"it'\\''s\"}'"),
        "{curl}"
    );
    assert!(
        curl.contains("Authorization: Bearer ${RH_USER_TOKEN}"),
        "{curl}"
    );
    // a hostile path cannot break out of the quotes
    let h = build_request(&case("GET", "/x'$(id)'", None), "http://h").unwrap();
    let hc = curl_for(&h);
    assert!(hc.ends_with("'http://h/x'\\''$(id)'\\'''"), "{hc}");
    assert!(
        !hc.contains("\"http"),
        "URL must not be double-quoted: {hc}"
    );
    let head = curl_for(&build_request(&case("HEAD", "/x", None), "http://h").unwrap());
    assert!(head.contains("-I -X HEAD"), "{head}");
    let g = curl_for(&build_request(&case("GET", "/s", Some("q=1")), "http://h").unwrap());
    assert!(g.contains("-X GET") && !g.contains("--data"), "{g}");
}

#[test]
fn auth_roles_and_env_names() {
    let mut c = case("GET", "/x", None);
    assert_eq!(auth_for(&c), Auth::Role("user".into()));
    c.technique = "authz".into();
    assert_eq!(auth_for(&c), Auth::None);
    c.title = "Forged JWT".into();
    assert_eq!(auth_for(&c), Auth::Forged);
    c.role = Some("Admin".into());
    assert_eq!(auth_for(&c), Auth::Role("Admin".into()));
    assert_eq!(Credentials::env_var("shop-admin"), "RH_SHOP_ADMIN_TOKEN");
    let creds = Credentials::none().with("admin", "tok");
    assert_eq!(creds.token("ADMIN"), Some("tok"));
    assert!(
        !format!("{creds:?}").contains("tok\""),
        "Debug must not print tokens"
    );
}

#[test]
fn the_acting_role_is_user_then_alice_then_any_unprivileged_role_never_an_admin() {
    let with = |roles: &[&str]| {
        roles
            .iter()
            .fold(Credentials::none(), |c, r| c.with(r, "tok"))
    };
    assert_eq!(Credentials::none().actor(), None);
    assert_eq!(
        with(&["alice", "bob", "admin"]).actor().as_deref(),
        Some("alice")
    );
    assert_eq!(with(&["alice", "user"]).actor().as_deref(), Some("user"));
    assert_eq!(
        with(&["viewer", "admin"]).actor().as_deref(),
        Some("viewer")
    );
    assert_eq!(
        with(&["shop-admin"]).actor(),
        None,
        "an administrator is never the actor"
    );
    assert_eq!(with(&["Root", "admin"]).actor(), None);
    // the role name round-trips through the token lookup
    let c = with(&["read-only"]);
    let a = c.actor().unwrap();
    assert!(c.has_role(&a), "{a}");
}

// ---- confirm_deleted

fn clients_for(base: &str) -> Clients {
    Clients::new(Duration::from_secs(5), &reqwest::Url::parse(base).unwrap()).unwrap()
}

fn bearer(token: &str) -> Bearer {
    Bearer {
        header: format!("Bearer {token}"),
        real: true,
    }
}

fn delete(api: &fixture::Api, path: &str, token: &str) -> u16 {
    let c = clients_for(&api.base);
    let b = bearer(token);
    c.send(&OutReq {
        method: "DELETE",
        url: &format!("{}{path}", api.base),
        body: None,
        headers: &[],
        bearer: Some(&b),
    })
    .unwrap()
    .status
}

#[test]
fn a_deleted_resource_reads_back_as_gone() {
    let api = fixture::start(false);
    let c = clients_for(&api.base);
    let admin = bearer("admin-token");
    assert_eq!(
        confirm_deleted_as(&c, &api.base, "/orders/3", Some(&admin)),
        DeleteCheck::StillPresent(200),
        "before the DELETE the order is there"
    );
    assert_eq!(delete(&api, "/orders/3", "admin-token"), 204);
    assert_eq!(
        confirm_deleted_as(&c, &api.base, "/orders/3", Some(&admin)),
        DeleteCheck::Gone
    );
    assert_eq!(api.order_ids(), vec![1, 2]);
}

#[test]
fn a_delete_that_kept_the_resource_reads_back_as_still_present() {
    let api = fixture::start(true); // the fixture's seeded "DELETE answers 204 but deletes nothing"
    let c = clients_for(&api.base);
    let alice = bearer("alice-token");
    assert_eq!(delete(&api, "/orders/1", "alice-token"), 204);
    assert_eq!(
        confirm_deleted_as(&c, &api.base, "/orders/1", Some(&alice)),
        DeleteCheck::StillPresent(200)
    );
    assert_eq!(api.order_ids(), vec![1, 2, 3]);
}

#[test]
fn a_read_back_that_proves_nothing_is_unknown() {
    let api = fixture::start(false);
    let c = clients_for(&api.base);
    let alice = bearer("alice-token");
    // no credential on an authenticated API: 401 is not "gone" and not "present"
    assert_eq!(
        confirm_deleted(&c, &api.base, "/orders/1"),
        DeleteCheck::Unknown
    );
    // server error, redirect (never followed), transport error
    assert_eq!(
        confirm_deleted_as(&c, &api.base, "/boom", Some(&alice)),
        DeleteCheck::Unknown
    );
    assert_eq!(
        confirm_deleted_as(&c, &api.base, "/redir", Some(&alice)),
        DeleteCheck::Unknown
    );
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    assert_eq!(
        confirm_deleted(&clients_for(&dead), &dead, "/orders/1"),
        DeleteCheck::Unknown
    );
    // not a path on the target: nothing is sent
    let before = api.requests().len();
    for bad in [
        "",
        "//evil.test/x",
        "http://evil.test/x",
        "/a b",
        "/a\r\nHost: evil",
        "/orders/{id}",
    ] {
        assert_eq!(
            confirm_deleted_as(&c, &api.base, bad, Some(&alice)),
            DeleteCheck::Unknown,
            "{bad:?}"
        );
    }
    assert_eq!(
        confirm_deleted(&c, "not a url", "/orders/1"),
        DeleteCheck::Unknown
    );
    assert_eq!(
        confirm_deleted(&c, "ftp://127.0.0.1/", "/orders/1"),
        DeleteCheck::Unknown
    );
    assert_eq!(
        api.requests().len(),
        before,
        "refused read-backs sent nothing"
    );
}

#[test]
fn the_read_back_never_leaves_the_runs_target_and_never_carries_a_credential_elsewhere() {
    let target = fixture::start(false);
    let other = fixture::start(false);
    let c = clients_for(&target.base);
    let alice = bearer("alice-token");
    // a credential is withheld from any other host, and nothing is sent to it at all
    assert_eq!(
        confirm_deleted_as(&c, &other.base, "/orders/1", Some(&alice)),
        DeleteCheck::Unknown
    );
    assert_eq!(
        confirm_deleted(&c, &other.base, "/orders/1"),
        DeleteCheck::Unknown
    );
    assert!(other.requests().is_empty(), "{:?}", other.requests());
    // on the target the credential is attached: the same GET that was 401 is now a 200
    assert_eq!(
        confirm_deleted(&c, &target.base, "/orders/1"),
        DeleteCheck::Unknown
    );
    assert_eq!(
        confirm_deleted_as(&c, &target.base, "/orders/1", Some(&alice)),
        DeleteCheck::StillPresent(200)
    );
    // a base with a path or query is reduced to its origin, as teardown does
    assert_eq!(
        confirm_deleted_as(
            &c,
            &format!("{}/app/?x=1", target.base),
            "/orders/1",
            Some(&alice)
        ),
        DeleteCheck::StillPresent(200)
    );
}
#[cfg(test)]
mod custom_header_tests {
    use super::*;

    fn base_case(method: &str, component: &str) -> PlannedCase {
        crate::agent::types::fixtures::planned("TC-H1", "injection", method, component)
    }

    #[test]
    fn custom_headers_and_content_type_propagate_to_request_and_curl() {
        let mut c = base_case("POST", "/xml");
        c.payload = Some("<root>hi</root>".into());
        c.content_type = Some("application/xml".into());
        c.headers = vec![
            ("X-Forwarded-For".into(), "127.0.0.1".into()),
            ("X-Original-URL".into(), "/admin".into()),
        ];
        c.role = Some("user".into());
        let spec = build_request(&c, "http://127.0.0.1:8080").unwrap();
        assert_eq!(spec.body.as_ref().unwrap().0, "application/xml");
        assert!(
            spec.extra_headers
                .iter()
                .any(|(k, v)| k == "X-Forwarded-For" && v == "127.0.0.1")
        );
        assert!(
            spec.extra_headers
                .iter()
                .any(|(k, v)| k == "X-Original-URL" && v == "/admin")
        );
        let curl = curl_for(&spec);
        assert!(curl.contains("Content-Type: application/xml"), "{curl}");
        assert!(curl.contains("X-Forwarded-For: 127.0.0.1"), "{curl}");
        assert!(curl.contains("X-Original-URL: /admin"), "{curl}");
    }

    #[test]
    fn custom_headers_reject_crlf_and_credential_overrides() {
        let mut crlf = base_case("GET", "/admin");
        crlf.headers = vec![("X-Test".into(), "1\r\nEvil: true".into())];
        assert!(build_request(&crlf, "http://127.0.0.1:8080").is_err());

        let mut auth_override = base_case("GET", "/admin");
        auth_override.role = Some("user".into());
        auth_override.headers = vec![("Authorization".into(), "Bearer hijack".into())];
        assert!(build_request(&auth_override, "http://127.0.0.1:8080").is_err());

        let mut cookie_override = base_case("GET", "/admin");
        cookie_override.role = Some("user".into());
        cookie_override.headers = vec![("Cookie".into(), "sid=evil".into())];
        assert!(build_request(&cookie_override, "http://127.0.0.1:8080").is_err());

        let mut bad_ct = base_case("POST", "/xml");
        bad_ct.payload = Some("x".into());
        bad_ct.content_type = Some("text/plain\r\nX-Injected: 1".into());
        assert!(build_request(&bad_ct, "http://127.0.0.1:8080").is_err());
    }
}

#[cfg(test)]
mod multimodal_auth_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn credentials_support_cookie_header_and_env_parsing_without_leaking_secrets() {
        let creds = Credentials::from_env_pairs([
            (
                "RH_USER_COOKIE".to_string(),
                "session=sec-cookie; csrf=xyz".to_string(),
            ),
            (
                "RH_SVC_HEADER".to_string(),
                "X-API-Key: sec-apikey".to_string(),
            ),
            ("RH_CAROL_HEADER".to_string(), "carol-raw".to_string()),
            (
                "RH_CAROL_HEADER_NAME".to_string(),
                "X-Carol-Auth".to_string(),
            ),
            (
                "RH_ADMIN_COOKIE".to_string(),
                "session=root-cookie".to_string(),
            ),
        ]);

        assert!(creds.has_role("user"));
        assert!(creds.has_role("svc"));
        assert!(creds.has_role("carol"));
        assert!(creds.has_role("admin"));
        assert_eq!(creds.actor().as_deref(), Some("user"));

        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("sec-cookie"), "{dbg}");
        assert!(!dbg.contains("sec-apikey"), "{dbg}");
        assert!(!dbg.contains("carol-raw"), "{dbg}");

        let auth_u = resolve_auth(&Auth::Role("user".into()), &creds);
        assert!(auth_u.authenticated);
        assert!(auth_u.real);
        assert!(
            auth_u
                .extra_headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("Cookie")
                    && v == "session=sec-cookie; csrf=xyz")
        );

        let auth_s = resolve_auth(&Auth::Role("svc".into()), &creds);
        assert!(auth_s.authenticated);
        assert!(auth_s.real);
        assert!(
            auth_s
                .extra_headers
                .iter()
                .any(|(k, v)| k == "X-API-Key" && v == "sec-apikey")
        );

        let auth_c = resolve_auth(&Auth::Role("carol".into()), &creds);
        assert!(auth_c.authenticated);
        assert!(
            auth_c
                .extra_headers
                .iter()
                .any(|(k, v)| k == "X-Carol-Auth" && v == "carol-raw")
        );

        let mut case = crate::agent::types::fixtures::planned("TC-MA1", "authz", "GET", "/me");
        case.role = Some("user".into());
        let spec = build_request(&case, "http://127.0.0.1:8080").unwrap();
        let curl = curl_for_auth(&spec, &creds);
        assert!(curl.contains("${RH_USER_COOKIE}"), "{curl}");
        assert!(!curl.contains("sec-cookie"), "{curl}");

        let mut svc_case = crate::agent::types::fixtures::planned("TC-MA2", "authz", "GET", "/svc");
        svc_case.role = Some("svc".into());
        let svc_spec = build_request(&svc_case, "http://127.0.0.1:8080").unwrap();
        let svc_curl = curl_for_auth(&svc_spec, &creds);
        assert!(svc_curl.contains("${RH_SVC_HEADER}"), "{svc_curl}");
        assert!(!svc_curl.contains("sec-apikey"), "{svc_curl}");
    }

    #[test]
    fn cookie_and_header_credentials_are_withheld_off_origin() {
        let target = fixture::start(false);
        let other = fixture::start(false);
        let target_u = reqwest::Url::parse(&target.base).unwrap();
        let clients = Clients::new(Duration::from_secs(2), &target_u).unwrap();
        let creds = Credentials::none().with_cookie("user", "sid=secret");
        let auth = resolve_auth(&Auth::Role("user".into()), &creds);

        let err = clients
            .send_resolved(
                &OutReq {
                    method: "GET",
                    url: &format!("{}/orders", other.base),
                    body: None,
                    headers: &[],
                    bearer: auth.bearer.as_ref(),
                },
                &auth,
            )
            .err()
            .expect("must refuse sending cookies to off-origin host");
        assert!(err.contains("credentials withheld"), "{err}");
    }

    #[test]
    fn login_bootstrap_handles_csrf_cookies_and_json_token() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let base = format!("http://127.0.0.1:{}", addr.port());
        let h = std::thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = l.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = req.lines().next().unwrap_or("");
                let resp = if first.starts_with("GET /login ") {
                    "HTTP/1.1 200 OK\r\nSet-Cookie: pre=p1; Path=/\r\nContent-Type: text/html\r\nContent-Length: 55\r\nConnection: close\r\n\r\n<form><input type=\"hidden\" name=\"_csrf\" value=\"tok99\"/></form>"
                } else if first.starts_with("POST /login ") {
                    let has_pre = req.to_ascii_lowercase().contains("cookie: pre=p1");
                    let has_csrf = req.contains("_csrf=tok99");
                    if has_pre
                        && has_csrf
                        && req.contains("username=alice")
                        && req.contains("password=pw")
                    {
                        "HTTP/1.1 200 OK\r\nSet-Cookie: sid=sess42; HttpOnly\r\nContent-Type: application/json\r\nContent-Length: 24\r\nConnection: close\r\n\r\n{\"access_token\":\"jwt42\"}"
                    } else {
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad"
                    }
                } else if first.starts_with("GET /me ") {
                    if req.to_ascii_lowercase().contains("sid=sess42")
                        && req
                            .to_ascii_lowercase()
                            .contains("authorization: bearer jwt42")
                    {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    } else {
                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno"
                    }
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let base_u = reqwest::Url::parse(&base).unwrap();
        let clients = Clients::new(Duration::from_secs(2), &base_u).unwrap();
        let mut creds = Credentials::none();
        creds
            .bootstrap_login(
                &clients,
                "user",
                &LoginBootstrap {
                    login_url: format!("{base}/login"),
                    csrf_page_url: Some(format!("{base}/login")),
                    mode: LoginMode::Form,
                    username: "alice".into(),
                    password: "pw".into(),
                    ..LoginBootstrap::default()
                },
            )
            .unwrap();
        assert_eq!(creds.token("user"), Some("jwt42"));
        assert!(creds.cookie("user").unwrap().contains("sid=sess42"));

        let auth = resolve_auth(&Auth::Role("user".into()), &creds);
        let seen = clients
            .send_resolved(
                &OutReq {
                    method: "GET",
                    url: &format!("{base}/me"),
                    body: None,
                    headers: &[],
                    bearer: auth.bearer.as_ref(),
                },
                &auth,
            )
            .unwrap();
        assert_eq!(seen.status, 200);
        let _ = h.join();
    }

    #[test]
    fn roles_toml_cookie_and_header_integration() {
        let dir = std::env::temp_dir().join(format!(
            "readyhai_roles_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let storage_path = dir.join("user_state.json");
        std::fs::write(
            &storage_path,
            r#"{"cookies":[{"name":"sid","value":"cookie-from-state"},{"name":"pref","value":"1"}]}"#,
        )
        .unwrap();
        let roles_path = dir.join("roles.toml");
        std::fs::write(
            &roles_path,
            r#"
[[role]]
name = "viewer"
auth = "cookie"
storage_state = "user_state.json"

[[role]]
name = "svc_ext"
auth = "header"
header_name = "X-Service-Key"
token_env = "PATH"
"#,
        )
        .unwrap();
        let roles = crate::qa::roles::Roles::load(&roles_path).unwrap();
        let creds = Credentials::none().with_roles(&roles);
        assert!(creds.has_role("viewer"));
        assert_eq!(
            creds.cookie("viewer"),
            Some("sid=cookie-from-state; pref=1")
        );
        assert!(creds.has_role("svc_ext"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
