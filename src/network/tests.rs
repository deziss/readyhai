//! Unit and integration test suite for the network module.

#![allow(unused_imports)]

use super::ip::IpCache;
use super::*;
use serde_json::json;
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tiny HTTP stub on an ephemeral port. `handler` gets the raw request head and returns the
/// full response, or None to hang (the connection is held open for 4 s without an answer).
fn stub(handler: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = std::sync::Arc::new(handler);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { continue };
            let handler = handler.clone();
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match std::io::Read::read(&mut c, &mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                match handler(&String::from_utf8_lossy(&head)) {
                    Some(resp) => {
                        let _ = c.write_all(resp.as_bytes());
                    }
                    None => std::thread::sleep(Duration::from_secs(4)),
                }
            });
        }
    });
    format!("http://{addr}/")
}

fn reply(status: &str, body: &str) -> Option<String> {
    Some(format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ))
}

fn reply_html(status: &str, body: &str) -> Option<String> {
    Some(format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ))
}

fn base_regress(target: &str) -> RegressRequest {
    serde_json::from_value(
        json!({"target": target, "iterations": 3, "delay_between_ms": 0, "timeout_ms": 2000}),
    )
    .unwrap()
}

fn iteration(status: u16, err: Option<&str>) -> IterationResult {
    IterationResult {
        iteration: 1,
        session_id: "sess-1".into(),
        timestamp: "2026-10-28T00:00:00Z".into(),
        duration_ms: 50,
        dns_lookup_ms: 5,
        tcp_connect_ms: 10,
        ttfb_ms: 40,
        status_code: status,
        success: (200..300).contains(&status),
        error_message: err.map(String::from),
        curl_command: "curl http://localhost".into(),
        response_headers: HashMap::new(),
        response_body_snippet: Some("OK".into()),
        resolved_ip: None,
        http_version: None,
    }
}

// ------------------------------------------------------------ target / clamp validation

// ---------------------------------------------------------------- public IP detection

fn dummy_info(ip: &str) -> RequesterIpInfo {
    RequesterIpInfo {
        egress_public_ip: ip.into(),
        ip_type: "t".into(),
        is_private: false,
        allowlist_guidance: String::new(),
        detected_via: "test".into(),
        detected_at: String::new(),
    }
}

#[test]
fn private_ip_uses_the_one_internal_definition() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1", // CGNAT
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:10.0.0.1",
        "[fd00::1]",
        "fe80::1%eth0",
        " 10.1.1.1 ",
    ] {
        assert!(is_private_ip(ip), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "172.32.0.1", // just outside 172.16/12 (the old string-prefix check called it private)
        "172.200.1.1",
        "100.128.0.1",
        "2606:4700:4700::1111",
        "not an ip",
        "",
    ] {
        assert!(!is_private_ip(ip), "{ip}");
    }
}

#[test]
fn ip_providers_must_return_a_bare_ip() {
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    let good = stub(move |_| {
        h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        reply("200 OK", "203.0.113.5\n")
    });
    let html = stub(|_| reply_html("200 OK", "<html>blocked</html>"));
    let down = stub(|_| reply("503 Service Unavailable", "no"));
    // a provider that answers with HTML or an error is skipped; the next one is used
    let r = query_ip_providers(&[
        ("html", html.as_str()),
        ("down", down.as_str()),
        ("good", good.as_str()),
    ]);
    assert_eq!(r, Some(("203.0.113.5".to_string(), "good".to_string())));
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    // nobody usable: None, and quickly (a closed port, then a hanging one: bounded by the timeouts)
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/", l.local_addr().unwrap())
    };
    let hang = stub(|_| None);
    let t0 = Instant::now();
    assert_eq!(
        query_ip_providers(&[("closed", closed.as_str()), ("hang", hang.as_str())]),
        None
    );
    assert!(t0.elapsed() < Duration::from_secs(4), "{:?}", t0.elapsed());
}

#[test]
fn offline_mode_never_contacts_an_ip_service() {
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    let url = stub(move |_| {
        h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        reply("200 OK", "203.0.113.5")
    });
    let (info, detected) = resolve_with(true, &[("stub", url.as_str())]);
    assert!(!detected);
    assert!(
        info.detected_via.contains("offline"),
        "{}",
        info.detected_via
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    // online, the same stub is used
    let (info, detected) = resolve_with(false, &[("stub", url.as_str())]);
    assert!(detected);
    assert_eq!(info.egress_public_ip, "203.0.113.5");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    // and READYHAI_OFFLINE is what resolve_public_ip consults
    let _g = crate::bundle::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("READYHAI_OFFLINE", "1") };
    let (info, detected) = resolve_public_ip();
    unsafe { std::env::remove_var("READYHAI_OFFLINE") };
    assert!(!detected && info.detected_via.contains("offline"));
}

#[test]
fn a_failed_detection_is_not_cached_forever() {
    let cache: IpCache = Mutex::new(None);
    let calls = std::cell::Cell::new(0);
    let mk = |ip: &'static str, ok: bool| {
        let calls = &calls;
        move || {
            calls.set(calls.get() + 1);
            (dummy_info(ip), ok)
        }
    };
    let hour = Duration::from_secs(3600);
    // a failure whose TTL has run out is looked up again, and the new answer replaces it
    assert_eq!(
        cached_or(&cache, hour, Duration::ZERO, mk("10.0.0.1", false)).egress_public_ip,
        "10.0.0.1"
    );
    assert_eq!(
        cached_or(&cache, hour, Duration::ZERO, mk("203.0.113.9", true)).egress_public_ip,
        "203.0.113.9"
    );
    assert_eq!(calls.get(), 2);
    // a success is reused while fresh
    assert_eq!(
        cached_or(&cache, hour, Duration::ZERO, mk("198.51.100.1", true)).egress_public_ip,
        "203.0.113.9"
    );
    assert_eq!(calls.get(), 2);
    // a failure is reused only for the short TTL
    let cache: IpCache = Mutex::new(None);
    let calls2 = std::cell::Cell::new(0);
    for _ in 0..3 {
        cached_or(&cache, hour, hour, || {
            calls2.set(calls2.get() + 1);
            (dummy_info("10.0.0.2"), false)
        });
    }
    assert_eq!(
        calls2.get(),
        1,
        "within the fail TTL the failure is served from cache"
    );
}

#[test]
fn targets_must_be_http_or_https() {
    for bad in [
        "ftp://x/",
        "file:///etc/passwd",
        "gopher://x/",
        "javascript:alert(1)",
        "x",
        "",
        "-oProxyCommand=x",
        "http://user:pw@x/",
    ] {
        assert!(parse_target(bad).is_err(), "{bad}");
    }
    assert_eq!(
        parse_target("HTTP://Example.com").unwrap().as_str(),
        "http://example.com/"
    );
    // the backslash form is normalised before anything (curl included) sees it
    assert_eq!(
        parse_target("http://app.example\\@evil.example/x")
            .unwrap()
            .as_str(),
        "http://app.example/@evil.example/x"
    );
    let mut c = CurlTestRequest {
        target: "file:///etc/passwd".into(),
        method: "GET".into(),
        headers: HashMap::new(),
        payload: None,
        timeout_ms: 1000,
    };
    assert!(c.sanitize().is_err());
    assert!(execute_curl_test(&c).is_err());
}

#[test]
fn regress_request_is_clamped() {
    let mut r: RegressRequest = serde_json::from_value(json!({
        "target": "http://x.example", "iterations": 10_000_000u64, "timeout_ms": u64::MAX,
        "simulated_latency_ms": u64::MAX, "delay_between_ms": u64::MAX, "method": "post"
    }))
    .unwrap();
    assert!(r.is_intrusive());
    r.sanitize().unwrap();
    assert_eq!(r.iterations, MAX_ITERATIONS);
    assert_eq!(r.timeout_ms, MAX_TIMEOUT_MS);
    assert_eq!(r.simulated_latency_ms, MAX_LATENCY_MS);
    assert_eq!(r.delay_between_ms, MAX_DELAY_MS);
    assert_eq!(r.method, "POST");
    assert_eq!(r.target, "http://x.example/");
    let mut r: RegressRequest = serde_json::from_value(
        json!({"target": "http://x.example", "iterations": 0, "timeout_ms": 0}),
    )
    .unwrap();
    r.sanitize().unwrap();
    assert_eq!((r.iterations, r.timeout_ms), (1, MIN_TIMEOUT_MS));
}

#[test]
fn other_requests_are_clamped() {
    let mut c = CurlTestRequest {
        target: "http://x.example".into(),
        method: "GET".into(),
        headers: HashMap::new(),
        payload: None,
        timeout_ms: u64::MAX,
    };
    c.sanitize().unwrap();
    assert_eq!(c.timeout_ms, MAX_TIMEOUT_MS);
    let mut d = DeepAuditRequest {
        target: "http://x.example".into(),
        timeout_ms: u64::MAX,
    };
    d.sanitize().unwrap();
    assert_eq!(d.timeout_ms, MAX_TIMEOUT_MS);
    d.timeout_ms = 0;
    d.sanitize().unwrap();
    assert_eq!(d.timeout_ms, MIN_TIMEOUT_MS);
    let mut m = MultiRegionRequest {
        target: "http://x.example".into(),
        timeout_ms: Some(u64::MAX),
    };
    m.sanitize().unwrap();
    assert_eq!(m.timeout_ms, Some(MAX_TIMEOUT_MS));
    let mut m = MultiRegionRequest {
        target: "http://x.example".into(),
        timeout_ms: None,
    };
    m.sanitize().unwrap();
    assert_eq!(m.timeout_ms, Some(4000));
}

#[test]
fn methods_headers_and_payload_are_validated() {
    let ok = |m: &str| {
        RegressRequest {
            method: m.into(),
            ..base_regress("http://x.example")
        }
        .sanitize()
        .is_ok()
    };
    assert!(ok("get") && ok("PATCH") && ok("options"));
    assert!(!ok("TRACE") && !ok("CONNECT") && !ok("GET --upload-file /etc/passwd") && !ok(""));
    let mut r = base_regress("http://x.example");
    r.headers.insert("X-Ok".into(), "v".into());
    assert!(r.clone().sanitize().is_ok());
    for (k, v) in [
        ("X\nBad", "v"),
        ("X-A", "a\r\nInjected: 1"),
        ("@/etc/passwd", "x"),
        ("", "v"),
        ("X-A", "nul\0"),
    ] {
        let mut r = base_regress("http://x.example");
        r.headers.insert(k.into(), v.into());
        assert!(r.sanitize().is_err(), "{k:?}");
    }
    let mut r = base_regress("http://x.example");
    r.payload = Some("A".repeat(MAX_PAYLOAD_BYTES + 1));
    assert!(r.sanitize().is_err());
    let mut r = base_regress("http://x.example");
    for i in 0..=MAX_HEADERS {
        r.headers.insert(format!("X-{i}"), "v".into());
    }
    assert!(r.sanitize().is_err());
}

#[test]
fn intrusive_classification() {
    let mut r = base_regress("http://x.example");
    assert!(!r.is_intrusive());
    r.iterations = READONLY_MAX_ITERATIONS + 1;
    assert!(r.is_intrusive());
    r.iterations = 3;
    r.payload = Some("{}".into());
    assert!(r.is_intrusive());
    assert!(is_safe_method("head") && !is_safe_method("DELETE"));
}

// ------------------------------------------------------------ curl hardening

#[test]
fn curl_gets_proto_limit_and_double_dash_before_the_url() {
    let mut req = CurlTestRequest {
        target: "http://x.example/a?b=c".into(),
        method: "post".into(),
        headers: HashMap::new(),
        payload: Some("@/etc/passwd".into()),
        timeout_ms: 2000,
    };
    let url = req.sanitize().unwrap();
    let cmd = curl_command(&req, &url, 2);
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let pos = |s: &str| {
        args.iter()
            .position(|a| a == s)
            .unwrap_or_else(|| panic!("{s} missing in {args:?}"))
    };
    assert_eq!(args[0], "-q", "ignore ~/.curlrc");
    assert_eq!(args[pos("--proto") + 1], "=http,https");
    assert_eq!(args[args.len() - 2], "--");
    assert_eq!(args[args.len() - 1], "http://x.example/a?b=c");
    assert!(pos("--proto") < pos("--"));
    // '@file' payloads are sent literally, never read from disk
    assert_eq!(args[pos("--data-raw") + 1], "@/etc/passwd");
    assert!(!args.iter().any(|a| a == "-d"));
    // the protocol probes carry the same protection
    assert!(
        // formatting-independent: every curl invocation pins the protocol list
        concat!(include_str!("curl.rs"), include_str!("audit.rs"))
            .matches("\"=http,https\"")
            .count()
            >= 2
    );
}

#[test]
fn repro_command_is_shell_safe() {
    let mut h = HashMap::new();
    h.insert("X-A".to_string(), "v'; rm -rf / #".to_string());
    let c = generate_curl("get", "http://x/?a=1&b=$(id)", &h, Some("it's \"x\""));
    assert!(c.contains("-H 'X-A: v'\\''; rm -rf / #'"), "{c}");
    assert!(c.contains("-- 'http://x/?a=1&b=$(id)'"), "{c}");
    assert!(c.contains("--data-raw 'it'\\''s \"x\"'"), "{c}");
    assert!(c.contains("-X 'GET'"));
}

#[test]
fn curl_output_is_capped_but_timings_survive() {
    // 3 MiB of body, cap 1 MiB: the -w trailer must still be parsed from the retained tail
    let body = "x".repeat(3 * 1024 * 1024);
    let url = stub(move |_| reply("200 OK", &body));
    let r = execute_curl_test(&CurlTestRequest {
        target: url,
        method: "GET".into(),
        headers: HashMap::new(),
        payload: None,
        timeout_ms: 5000,
    })
    .unwrap();
    if Command::new("curl").arg("--version").output().is_err() {
        return; // no curl: the fallback path is covered by fallback_reports_unmeasured_fields
    }
    assert!(
        r.not_measured.is_empty(),
        "curl was available but the fallback ran: {}",
        r.stderr
    );
    assert_eq!(r.exit_code, 0, "{}", r.stderr);
    assert!(r.truncated, "{}", r.stdout.len());
    assert!(
        r.stdout.len() < MAX_CAPTURE_BYTES + 200,
        "{}",
        r.stdout.len()
    );
    assert!(r.stdout.contains("[output truncated"));
    assert_eq!(
        r.status_code, 200,
        "timings trailer must survive truncation"
    );
    assert!(r.total_s > 0.0);
}

#[test]
fn curl_refuses_non_http_schemes_even_if_it_reached_curl() {
    // belt and braces: --proto limits curl itself, independent of our URL parsing
    let out = Command::new("curl")
        .args([
            "-q",
            "-sS",
            "--proto",
            "=http,https",
            "--",
            "file:///etc/hostname",
        ])
        .output();
    if let Ok(o) = out {
        assert!(!o.status.success());
    }
}

#[test]
fn tls_is_measured_from_a_real_handshake() {
    if Command::new("openssl").arg("version").output().is_err() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("rh-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (key, crt) = (dir.join("k.pem"), dir.join("c.pem"));
    let keygen = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&crt)
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut server = Command::new("openssl")
        .args(["s_server", "-accept"])
        .arg(port.to_string())
        .arg("-cert")
        .arg(&crt)
        .arg("-key")
        .arg(&key)
        .arg("-www")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let url = parse_target(&format!("https://127.0.0.1:{port}/")).unwrap();
    let t = audit_tls_chain(&url, "127.0.0.1", port, 5000);
    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(t.measured && t.is_https, "{t:?}");
    assert!(t.tls_version.starts_with("TLSv1."), "{}", t.tls_version);
    assert!(!t.cipher.is_empty() && t.cipher != "not measured");
    assert!(t.cert_subject.contains("localhost"), "{}", t.cert_subject);
    assert!(t.cert_issuer.contains("localhost"), "{}", t.cert_issuer);
    assert_eq!(t.cert_sans, vec!["localhost"]);
    assert!(t.is_self_signed, "{t:?}");
    assert!(!t.is_intermediate_missing);
    assert!(
        matches!(t.days_remaining, Some(29 | 30)),
        "{:?}",
        t.days_remaining
    );
    assert!(t.not_after.as_deref().is_some_and(|d| d.ends_with("GMT")));
    assert_eq!(
        t.ocsp_stapled,
        Some(false),
        "a plain s_server staples nothing"
    );
    assert_eq!(t.chain_length, Some(1));
}

#[test]
fn tls_against_a_closed_port_is_not_measured() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let url = parse_target(&format!("https://127.0.0.1:{port}/")).unwrap();
    let t = audit_tls_chain(&url, "127.0.0.1", port, 2000);
    assert!(
        !t.measured && t.ocsp_stapled.is_none() && t.days_remaining.is_none(),
        "{t:?}"
    );
    assert_eq!(t.cert_issuer, "not measured");
}

#[test]
fn fallback_reports_unmeasured_fields() {
    // the native-client fallback must not invent DNS/connect timings
    let url = stub(|_| reply("200 OK", "hi"));
    let u = parse_target(&url).unwrap();
    let req = CurlTestRequest {
        target: url,
        method: "GET".into(),
        headers: HashMap::new(),
        payload: None,
        timeout_ms: 2000,
    };
    let r = native_curl_fallback(&req, &u, "curl ...".into(), "no curl").unwrap();
    assert_eq!((r.status_code, r.stdout.as_str()), (200, "hi"));
    assert_eq!(
        (r.dns_lookup_s, r.connect_s, r.appconnect_s),
        (0.0, 0.0, 0.0)
    );
    assert_eq!(
        r.not_measured,
        vec!["dns_lookup_s", "connect_s", "appconnect_s"]
    );
    assert!(r.starttransfer_s > 0.0 && r.total_s >= r.starttransfer_s);
    // and a dead target lists everything as unmeasured
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://127.0.0.1:{}/", l.local_addr().unwrap().port());
    drop(l);
    let req = CurlTestRequest {
        target: dead.clone(),
        method: "GET".into(),
        headers: HashMap::new(),
        payload: None,
        timeout_ms: 1000,
    };
    let r = native_curl_fallback(
        &req,
        &parse_target(&dead).unwrap(),
        "curl ...".into(),
        "no curl",
    )
    .unwrap();
    assert_eq!(r.exit_code, 1);
    assert_eq!(r.not_measured.len(), 4);
}

// ------------------------------------------------------------ regress

#[test]
fn non_2xx_counts_as_failure() {
    for (status, line) in [
        (200, "200 OK"),
        (404, "404 Not Found"),
        (500, "500 Internal Server Error"),
        (401, "401 Unauthorized"),
    ] {
        let url = stub(move |_| reply(line, "body"));
        let rep = run_regress_test(&base_regress(&url)).unwrap();
        assert_eq!(rep.total_iterations, 3);
        if status == 200 {
            assert_eq!((rep.successful_iterations, rep.failed_iterations), (3, 0));
            assert_eq!(rep.availability_percentage, 100.0);
            assert_eq!(rep.diagnosis.root_cause_type, "STABLE");
        } else {
            assert_eq!(
                (rep.successful_iterations, rep.failed_iterations),
                (0, 3),
                "{status}"
            );
            assert_eq!(rep.availability_percentage, 0.0);
            assert_ne!(
                rep.diagnosis.root_cause_type, "STABLE",
                "{status} must not be reported as stable"
            );
            assert!(rep.diagnosis.flakiness_detected);
        }
        assert!(
            rep.iterations
                .iter()
                .all(|i| i.resolved_ip.as_deref() == Some("127.0.0.1"))
        );
        assert!(
            rep.iterations
                .iter()
                .all(|i| i.session_id.starts_with("sess-"))
        );
    }
}

#[test]
fn redirects_are_failures_and_never_leave_the_host() {
    let url = stub(|_| {
        Some("HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into())
    });
    let rep = run_regress_test(&base_regress(&url)).unwrap();
    assert_eq!(rep.failed_iterations, 3);
    assert_eq!(
        rep.iterations[0].status_code, 302,
        "the redirect must not be followed to another host"
    );
}

#[test]
fn multibyte_body_does_not_panic_the_snippet_cut() {
    // 300 three-byte characters: byte 256 is inside a character
    let body = "日".repeat(300);
    let url = stub(move |_| reply("200 OK", &body));
    let rep = run_regress_test(&base_regress(&url)).unwrap();
    let snip = rep.iterations[0].response_body_snippet.clone().unwrap();
    assert_eq!(snip.chars().count(), BODY_SNIPPET_CHARS + 3);
    assert!(snip.ends_with("..."));
    assert_eq!(truncate_chars("é".repeat(10).as_str(), 4), "éééé...");
    assert_eq!(truncate_chars("abc", 4), "abc");
    assert_eq!(truncate_chars("", 0), "");
}

#[test]
fn diagnose_non_2xx_is_not_stable() {
    let rs = vec![
        iteration(404, Some("HTTP Status 404")),
        iteration(404, Some("HTTP Status 404")),
    ];
    let d = diagnose(&rs, 0.0, 50, 55, 5, 5000);
    assert_eq!(d.root_cause_type, "HTTP_ERRORS");
    assert!(d.flakiness_detected);
    let rs = vec![iteration(301, Some("HTTP Status 301"))];
    assert_eq!(
        diagnose(&rs, 0.0, 50, 55, 5, 5000).root_cause_type,
        "HTTP_ERRORS"
    );
}

#[test]
fn jitter_needs_an_absolute_spread_not_just_a_ratio() {
    assert_eq!(
        diagnose(&[iteration(200, None)], 100.0, 1, 4, 3, 5000).root_cause_type,
        "STABLE"
    );
    assert_eq!(
        diagnose(&[iteration(200, None)], 100.0, 30, 120, 90, 5000).root_cause_type,
        "HIGH_JITTER"
    );
    assert_eq!(
        diagnose(&[iteration(200, None)], 100.0, 500, 900, 400, 5000).root_cause_type,
        "HIGH_JITTER"
    );
}

#[test]
fn test_diagnose_stable() {
    let d = diagnose(&[iteration(200, None)], 100.0, 50, 55, 10, 5000);
    assert_eq!(d.root_cause_type, "STABLE");
}

#[test]
fn test_diagnose_timeout() {
    let mut r = iteration(0, Some("Operation timed out"));
    r.duration_ms = 5000;
    let d = diagnose(&[r], 0.0, 5000, 5000, 0, 5000);
    assert_eq!(d.root_cause_type, "TIMEOUT");
}

// ------------------------------------------------------------ MTU

fn mtu_item(size: usize, delivered: bool, transport_failure: bool, status: u16) -> MtuSweepItem {
    MtuSweepItem {
        payload_bytes: size,
        label: String::new(),
        status_code: status,
        duration_ms: 1,
        success: (200..300).contains(&status),
        delivered,
        transport_failure,
        header_limit_hit: is_header_limit_status(status),
        error: None,
    }
}

#[test]
fn mtu_rule_distinguishes_header_limits_from_black_holes() {
    // 431 / 400 / 413 / 414 on large probes: packets arrived, server said no
    for st in [400, 413, 414, 431] {
        let r = vec![
            mtu_item(512, true, false, 200),
            mtu_item(1400, true, false, st),
            mtu_item(4096, true, false, st),
            mtu_item(8192, true, false, st),
        ];
        assert!(!mtu_black_hole(&r), "HTTP {st} is not a black hole");
    }
    // timeout on large after a good baseline: black hole
    let r = vec![
        mtu_item(512, true, false, 200),
        mtu_item(1400, false, true, 0),
    ];
    assert!(mtu_black_hole(&r));
    // dead target (baseline fails too) or a refused connection is not a black hole
    assert!(!mtu_black_hole(&[
        mtu_item(512, false, true, 0),
        mtu_item(1400, false, true, 0)
    ]));
    assert!(!mtu_black_hole(&[
        mtu_item(512, true, false, 200),
        mtu_item(1400, false, false, 0)
    ]));
}

#[test]
fn mtu_sweep_with_a_431_server_reports_no_black_hole() {
    let url = stub(|req| {
        if req.len() > 1000 {
            reply("431 Request Header Fields Too Large", "")
        } else {
            reply("200 OK", "ok")
        }
    });
    let a = audit_mtu_sweep(&url, 2000);
    assert!(!a.black_hole_detected, "{}", a.diagnosis);
    assert_eq!(a.maximum_safe_bytes, 512);
    assert_eq!(a.maximum_delivered_bytes, 8192);
    assert!(
        a.sweep_results
            .iter()
            .skip(1)
            .all(|r| r.header_limit_hit && r.delivered && !r.success)
    );
    assert!(a.diagnosis.contains("header-size limit"), "{}", a.diagnosis);
}

#[test]
fn mtu_sweep_flags_a_real_black_hole() {
    // large requests are swallowed (no response at all), small ones answered
    let url = stub(|req| {
        if req.len() > 1000 {
            None
        } else {
            reply("200 OK", "ok")
        }
    });
    let a = audit_mtu_sweep(&url, 800);
    assert!(a.black_hole_detected, "{}", a.diagnosis);
    assert_eq!(a.maximum_safe_bytes, 512);
}

// ------------------------------------------------------------ deep audit

#[test]
fn deep_audit_against_a_local_stub() {
    let url = stub(|req| {
        if req.starts_with("OPTIONS") {
            Some("HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: https://qa-probe.readyhai.internal\r\nConnection: close\r\n\r\n".into())
        } else {
            // every path, /app.js included, answers with the HTML shell (a broken SPA fallback)
            reply_html(
                "200 OK",
                "<html><script src=\"/app.js\"></script><script src=\"http://169.254.169.254/x.js\"></script></html>",
            )
        }
    });
    let rep = run_deep_audit(&DeepAuditRequest {
        target: url,
        timeout_ms: 2000,
    })
    .unwrap();
    assert!(rep.health_score > 0);
    assert!(!rep.overall_verdict.is_empty());
    // plain http: no TLS fabrication
    assert!(!rep.tls_chain.is_https);
    assert!(
        rep.tls_chain.ocsp_stapled.is_none()
            && rep.tls_chain.days_remaining.is_none()
            && rep.tls_chain.not_after.is_none()
    );
    // the cross-host asset was not fetched, only recorded as skipped
    assert_eq!(rep.subresources.skipped_cross_host, 1);
    assert!(
        rep.subresources
            .items
            .iter()
            .all(|i| i.url.contains("127.0.0.1"))
    );
    assert_eq!(
        rep.subresources.spa_fallback_mismatches, 1,
        "{:?}",
        rep.subresources
    );
    assert!(
        rep.identified_risks
            .iter()
            .any(|r| r.contains("SPA Routing Flaw"))
    );
    assert!(
        rep.protocol_matrix
            .protocols
            .iter()
            .any(|p| p.protocol.starts_with("HTTP/3") && p.status_code == 0)
    );
}

#[test]
fn deep_audit_non_2xx_assets_are_broken() {
    let url = stub(|req| {
        if req.starts_with("GET / ") {
            reply(
                "200 OK",
                "<html><script src=\"/missing.js\"></script></html>",
            )
        } else {
            reply("404 Not Found", "nope")
        }
    });
    let u = parse_target(&url).unwrap();
    let a = audit_subresources(&u, 2000);
    assert_eq!(a.broken_count, 1, "{a:?}");
    assert_eq!(a.items[0].status_code, 404);
}

#[test]
fn deep_audit_rejects_non_http_targets() {
    assert!(
        run_deep_audit(&DeepAuditRequest {
            target: "file:///etc/passwd".into(),
            timeout_ms: 1000
        })
        .is_err()
    );
}

// ------------------------------------------------------------ TLS parsing (no hard-coded values)

const S_CLIENT: &str = "\
CONNECTED(00000003)
Certificate chain
 0 s:CN = example.com
   i:C = US, O = Let's Encrypt, CN = R3
-----BEGIN CERTIFICATE-----
MIIAAA==
-----END CERTIFICATE-----
 1 s:C = US, O = Let's Encrypt, CN = R3
   i:O = Digital Signature Trust Co., CN = DST Root CA X3
-----BEGIN CERTIFICATE-----
MIIBBB==
-----END CERTIFICATE-----
OCSP response: no response sent
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Verify return code: 0 (ok)
";

#[test]
fn s_client_output_is_parsed_not_assumed() {
    let s = parse_s_client(S_CLIENT);
    assert_eq!(s.version.as_deref(), Some("TLSv1.3"));
    assert_eq!(s.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
    assert_eq!(s.verify_code, Some(0));
    assert_eq!(
        s.ocsp_stapled,
        Some(false),
        "'no response sent' means NOT stapled (it used to be hard-coded true)"
    );
    assert_eq!(s.chain_len, 2);
    let pem = s.leaf_pem.unwrap();
    assert!(pem.contains("MIIAAA==") && !pem.contains("MIIBBB=="));
    assert_eq!(
        parse_s_client("OCSP Response Status: successful (0x0)").ocsp_stapled,
        Some(true)
    );
    assert_eq!(parse_s_client("nothing relevant").ocsp_stapled, None);
    let failed = parse_s_client("New, (NONE), Cipher is (NONE)");
    assert!(failed.version.is_none() && failed.cipher.is_none());
    assert_eq!(
        parse_s_client("Verify return code: 21 (unable to verify the first certificate)")
            .verify_code,
        Some(21)
    );
}

#[test]
fn x509_and_dates_are_parsed() {
    let leaf = parse_x509(
        "subject=CN = example.com\nissuer=C = US, O = Let's Encrypt, CN = R3\nnotAfter=Jan  1 00:00:00 2027 GMT\nX509v3 Subject Alternative Name: \n    DNS:example.com, DNS:www.example.com\n",
    );
    assert_eq!(leaf.subject.as_deref(), Some("CN = example.com"));
    assert_eq!(
        leaf.issuer.as_deref(),
        Some("C = US, O = Let's Encrypt, CN = R3")
    );
    assert_eq!(leaf.sans, vec!["example.com", "www.example.com"]);
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(days_from_civil(2000, 1, 1), 10_957);
    assert_eq!(
        parse_openssl_date("Jan  1 00:00:00 2027 GMT"),
        Some(1_798_761_600)
    );
    assert_eq!(
        parse_openssl_date("Feb 29 12:30:15 2028 GMT"),
        Some(days_from_civil(2028, 2, 29) * 86_400 + 12 * 3600 + 30 * 60 + 15)
    );
    assert_eq!(
        days_from_civil(2028, 3, 1) - days_from_civil(2028, 2, 29),
        1
    );
    assert_eq!(parse_openssl_date("garbage"), None);
    assert_eq!(parse_openssl_date("Foo  1 00:00:00 2027 GMT"), None);
}

#[test]
fn unmeasured_tls_says_so() {
    let t = unmeasured_tls(true, "openssl is not available");
    assert!(
        !t.measured
            && t.ocsp_stapled.is_none()
            && t.days_remaining.is_none()
            && t.not_after.is_none()
    );
    assert_eq!(t.cert_issuer, "not measured");
    assert_eq!(t.tls_version, "not measured");
    assert!(t.cert_sans.is_empty());
    assert_eq!(t.not_measured, vec!["openssl is not available"]);
}

// ------------------------------------------------------------ multi-region

#[test]
fn multi_region_reports_only_the_local_measurement() {
    let url = stub(|_| reply("200 OK", "ok"));
    let rep = run_multi_region_audit(&MultiRegionRequest {
        target: url,
        timeout_ms: Some(2000),
    })
    .unwrap();
    assert_eq!(rep.regions.len(), 1);
    let r = &rep.regions[0];
    assert!(r.measured && r.region_id == "local");
    assert_eq!(r.http_status, 200);
    assert_eq!(r.resolved_ip, "127.0.0.1");
    assert_eq!(r.packet_loss_pct, 0.0);
    assert_eq!(rep.not_measured_regions.len(), 4);
    assert!(
        rep.geo_dns_consistent.is_none(),
        "geo-DNS consistency cannot be known from one vantage point"
    );
    assert!(rep.measurement_note.contains("no remote probe nodes"));
    assert_eq!(rep.fastest_region, "not measured");
}

#[test]
fn multi_region_unreachable_target_is_offline() {
    // nothing listens here
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let rep = run_multi_region_audit(&MultiRegionRequest {
        target: format!("http://127.0.0.1:{port}/"),
        timeout_ms: Some(800),
    })
    .unwrap();
    assert_eq!(rep.regions[0].status, "OFFLINE");
    assert_eq!(rep.regions[0].packet_loss_pct, 100.0);
    assert!(rep.agent_verdict.starts_with("CRITICAL"));
}

// ------------------------------------------------------------ HAR

#[test]
fn test_generate_har() {
    let mut it = iteration(200, None);
    it.resolved_ip = Some("10.1.2.3".into());
    it.http_version = Some("HTTP/2.0".into());
    let rep = RegressReport {
        target: "http://localhost".into(),
        method: "POST".into(),
        total_iterations: 1,
        iterations_requested: 1,
        stopped_early: false,
        successful_iterations: 1,
        failed_iterations: 0,
        availability_percentage: 100.0,
        avg_latency_ms: 50,
        p50_latency_ms: 50,
        p90_latency_ms: 50,
        p99_latency_ms: 50,
        min_latency_ms: 50,
        max_latency_ms: 50,
        jitter_ms: 0,
        status_distribution: HashMap::new(),
        iterations: vec![it, iteration(0, Some("boom"))],
        diagnosis: diagnose(&[iteration(200, None)], 100.0, 50, 50, 0, 5000),
        requester_ip: Some("127.0.0.1".into()),
        allowlist_recommendation: Some("Add 127.0.0.1/32 to allowlist".into()),
    };
    let har = generate_har_from_regress(&rep);
    assert_eq!(har["log"]["version"], "1.2");
    let entries = har["log"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0]["request"]["method"], "POST",
        "method comes from the report, not a constant"
    );
    assert_eq!(entries[0]["serverIPAddress"], "10.1.2.3");
    assert_eq!(entries[0]["response"]["httpVersion"], "HTTP/2.0");
    assert!(
        entries[1].get("serverIPAddress").is_none(),
        "no invented 127.0.0.1"
    );
    assert_eq!(entries[1]["response"]["httpVersion"], "");
    assert_eq!(entries[0]["timings"]["ssl"], -1);
}

#[test]
fn old_reports_still_deserialize() {
    // a RegressReport saved before the additive fields existed
    let v = json!({"target":"http://a/","total_iterations":1,"successful_iterations":1,"failed_iterations":0,
            "availability_percentage":100.0,"avg_latency_ms":1,"p50_latency_ms":1,"p90_latency_ms":1,"p99_latency_ms":1,
            "min_latency_ms":1,"max_latency_ms":1,"jitter_ms":0,"status_distribution":{},
            "diagnosis":{"flakiness_detected":false,"root_cause_type":"STABLE","severity":"STABLE","title":"t","summary":"s",
              "how_agent_found_it":[],"technical_breakdown":[],"reproduction_curl":"c","remediation_checklist":[]},
            "iterations":[{"iteration":1,"session_id":"s","timestamp":"t","duration_ms":1,"dns_lookup_ms":1,"tcp_connect_ms":1,
              "ttfb_ms":1,"status_code":200,"success":true,"error_message":null,"curl_command":"c","response_headers":{},"response_body_snippet":null}]});
    let r: RegressReport = serde_json::from_value(v).unwrap();
    assert_eq!(r.method, "GET");
    assert!(r.iterations[0].resolved_ip.is_none());
}
