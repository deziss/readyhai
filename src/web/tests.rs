use super::client::{container_url, host_of};
use super::nuclei::parse_nuclei;
use super::playwright::{is_missing_image, parse_playwright};
use super::schemathesis::junit_failure_text;
use super::smoke::{csp_findings, tls_findings};
use super::zap::{parse_zap, parse_zap_report, zap_active};
use super::checks;
use crate::ctx::Ctx;
use crate::model::*;

#[test]
fn hosts() {
    assert_eq!(host_of("http://user@localhost:8080/x"), "localhost");
    // Backslash in the authority: the client connects to evil.example, so must we.
    assert_eq!(
        host_of("https://evil.example\\@app.nonprod.example/"),
        "evil.example"
    );
    assert_eq!(
        container_url("http://127.0.0.1:3000/a").0,
        "http://host.docker.internal:3000/a"
    );
    assert!(!container_url("https://example.com").1);
}

#[test]
fn playwright_parse() {
    let j = r#"{"pages":[{"url":"http://a/","status":200,"console_errors":["x 1","y"],"page_errors":["TypeError: z"],
      "failed_requests":[{"url":"http://a/api","status":503,"failure":""},{"url":"http://a/api","status":503,"failure":""},{"url":"http://a/n","status":404,"failure":""},{"url":"http://a/f","status":0,"failure":"net::ERR"}],
      "broken_links":["http://a/dead (404)"],
      "storage_leaks":[{"store":"localStorage","key":"auth_token","kind":"jwt"}],
      "cookie_issues":[{"name":"session_id","httpOnly":false,"secure":true}],
      "sourcemaps":["http://a/app.js.map"],
      "postmessage_issues":["e => eval(e.data)"],
      "screenshot":"page-0.png"}]}"#;
    let (f, lines) = parse_playwright(j).unwrap();
    let rules: Vec<&str> = f.iter().map(|x| x.rule.as_str()).collect();
    assert_eq!(rules.iter().filter(|r| **r == "web.5xx").count(), 1);
    assert!(
        rules.contains(&"web.page_error")
            && rules.contains(&"web.console_error")
            && rules.contains(&"web.broken_link")
            && rules.contains(&"web.4xx")
            && rules.contains(&"web.storage_secret")
            && rules.contains(&"web.cookie_httponly")
            && rules.contains(&"web.sourcemap_exposed")
            && rules.contains(&"web.postmessage_no_origin")
    );
    assert_eq!(
        f.iter()
            .find(|x| x.rule == "web.page_error")
            .unwrap()
            .severity,
        Severity::High
    );
    assert_eq!(lines.len(), 3);
    assert!(is_missing_image("Unable to find image 'x' locally"));
}

#[test]
fn junit_failure_text_skips_selfclosing() {
    let x = r#"<testsuite><testcase name="A" time="1"/><testcase name="B" time="2"><failure message="ST101">- ST101 Server error &lt;x&gt;

Reproduce with: curl</failure></testcase></testsuite>"#;
    let m = junit_failure_text(x);
    assert!(!m.contains_key("A"));
    assert_eq!(m["B"], "- ST101 Server error <x>");
}

#[test]
fn zap_parse() {
    let j = r#"{"site":[{"alerts":[{"pluginid":"10038","alert":"CSP","riskcode":"2","desc":"<p>x</p>","instances":[{"uri":"http://a/"},{"uri":"http://a/b"}]}]}]}"#;
    let f = parse_zap(j).unwrap();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].rule, "zap.10038");
    assert_eq!(f[0].severity, Severity::Medium);
}

#[test]
fn nuclei_parse_and_lock_pin() {
    let (img, pinned) = crate::tools::image_for("nuclei");
    assert!(img.starts_with("projectdiscovery/nuclei@sha256:"), "{img}");
    assert!(pinned);
    assert!(
        checks()
            .iter()
            .any(|c| c.id == "tool.nuclei" && !c.intrusive)
    );

    let jsonl = concat!(
        r#"{"template-id":"CVE-2023-22515","info":{"name":"Atlassian Confluence Broken Access Control","severity":"critical","description":"Privilege escalation.","remediation":"Upgrade Confluence.","classification":{"cve-id":["CVE-2023-22515"],"cwe-id":["CWE-284"]}},"matched-at":"https://app.example/setup/setupadministrator.action"}"#,
        "\n",
        r#"{"template-id":"git-config-exposure","info":{"name":"Git Config Exposed","severity":"medium"},"matched-at":"https://app.example/.git/config"}"#,
        "\n"
    );
    let findings = parse_nuclei(jsonl).unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].check, "tool.nuclei");
    assert_eq!(findings[0].rule, "nuclei.CVE-2023-22515");
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(
        findings[0].location,
        "https://app.example/setup/setupadministrator.action"
    );
    assert!(findings[0].ids.contains(&"CVE-2023-22515".to_string()));
    assert_eq!(findings[1].severity, Severity::Medium);
}

#[test]
fn zap_active_parses_xml_and_json_and_requires_deep_nonprod() {
    let act = checks()
        .into_iter()
        .find(|c| c.id == "tool.zap_active")
        .expect("tool.zap_active check registered");
    assert!(act.intrusive);
    assert_eq!(act.min_profile, Profile::Deep);

    let xml = r#"<?xml version="1.0"?>
<OWASPZAPReport version="2.15.0">
  <site name="https://app.example">
    <alerts>
      <alertitem>
        <pluginid>40018</pluginid>
        <alert>SQL Injection</alert>
        <riskcode>3</riskcode>
        <desc>&lt;p&gt;SQLi possible.&lt;/p&gt;</desc>
        <solution>&lt;p&gt;Use prepared statements.&lt;/p&gt;</solution>
        <instances>
          <instance><uri>https://app.example/search?q=1</uri></instance>
        </instances>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"#;
    let xml_f = parse_zap_report(xml, "tool.zap_active").unwrap();
    assert_eq!(xml_f.len(), 1);
    assert_eq!(xml_f[0].check, "tool.zap_active");
    assert_eq!(xml_f[0].rule, "zap.40018");
    assert_eq!(xml_f[0].severity, Severity::High);
    assert_eq!(xml_f[0].location, "https://app.example/search?q=1");

    let mk_ctx = |profile: Profile, nonprod: bool| Ctx {
        run_id: "r1".into(),
        target: Target {
            kind: TargetKind::Web,
            raw: "https://app.example".into(),
            path: None,
            image: None,
            url: Some("https://app.example".into()),
            openapi: None,
            host: None,
            apk: None,
            device: None,
        },
        profile,
        run_dir: std::env::temp_dir(),
        snapshot: None,
        facts: crate::facts::Facts::default(),
        docker: crate::tools::Docker {
            available: true,
            mode: crate::tools::MountMode::Bind,
            cache_dir: std::env::temp_dir(),
        },
        cfg: crate::config::TargetConfig::default(),
        error_lines: std::sync::Mutex::new(vec![]),
        nonprod,
        qa: None,
    };
    let out_std = zap_active(&mk_ctx(Profile::Standard, true)).unwrap();
    assert!(matches!(out_std.status, Some(CheckStatus::Skipped(_))));
    let out_prod = zap_active(&mk_ctx(Profile::Deep, false)).unwrap();
    assert!(matches!(out_prod.status, Some(CheckStatus::Skipped(_))));
}

#[test]
fn weak_csp_and_tls_findings_are_emitted() {
    let mut out = vec![];
    csp_findings(
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' http://cdn.example",
        "https://example.com/",
        &mut out,
    );
    assert!(out.iter().any(|f| f.rule == "web.weak_csp"));
    let d = &out
        .iter()
        .find(|f| f.rule == "web.weak_csp")
        .unwrap()
        .detail;
    assert!(d.contains("unsafe-inline") && d.contains("unsafe-eval") && d.contains("http:"));

    let mut clean = vec![];
    csp_findings(
        "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'",
        "https://example.com/",
        &mut clean,
    );
    assert!(clean.is_empty(), "{clean:?}");

    let expiring = crate::network::TlsChainAudit {
        is_https: true,
        measured: true,
        tls_version: "TLSv1.1".into(),
        cipher: "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
        cert_issuer: "Let's Encrypt".into(),
        cert_subject: "example.com".into(),
        cert_sans: vec![],
        not_after: Some("Jan 01 00:00:00 2026 GMT".into()),
        days_remaining: Some(5),
        is_self_signed: false,
        is_intermediate_missing: true,
        ocsp_stapled: Some(false),
        chain_length: Some(1),
        verify_result: Some("21 (unable to verify)".into()),
        not_measured: vec![],
        diagnosis: String::new(),
    };
    let mut tls_out = vec![];
    tls_findings(&expiring, "https://example.com/", false, &mut tls_out);
    let rules: Vec<&str> = tls_out.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"web.tls_weak_protocol"), "{rules:?}");
    assert!(rules.contains(&"web.tls_expiring"), "{rules:?}");
    assert!(rules.contains(&"web.tls_untrusted"), "{rules:?}");
}
