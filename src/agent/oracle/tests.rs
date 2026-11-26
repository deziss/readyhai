//! Unit tests for the typed assertion oracle.

#![allow(unused_imports)]

use super::super::types::PlannedCase;
use super::burst::*;
use super::contract::*;
use super::expectations::*;
use super::judge::*;
use super::probes::*;
use super::signatures::*;
use super::stateful::*;
use super::types::*;
use super::*;
use crate::agent::{RedirectHop, ResponseContract};
use crate::qa::api::contract as qa_contract;
use crate::qa::api::latency;

fn case(tech: &str, method: &str, component: &str) -> PlannedCase {
    PlannedCase {
        id: "TC-001".into(),
        title: "t".into(),
        component: component.into(),
        method: method.into(),
        technique: tech.into(),
        input_hint: String::new(),
        payload: None,
        headers: vec![],
        content_type: None,
        probe_oracle: None,
        expected_behavior: String::new(),
        expected_status: None,
        risk_level: "medium".into(),
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
        intel_note: String::new(),
    }
}

fn obs<'a>(status: u16, ct: &'a str, body: &'a str) -> Observation<'a> {
    Observation {
        status,
        content_type: ct,
        headers: &[],
        body,
        sent_values: &[],
        is_spa_shell: false,
        authenticated: false,
        https: false,
        request_body: None,
        origin: None,
        latency_ms: 5,
        probe: None,
    }
}

fn v(c: &PlannedCase, o: &Observation) -> (Verdict, Option<Severity>) {
    let r = judge(c, o);
    (r.verdict, r.max_fail_severity())
}

#[test]
fn authz_golden_table() {
    let mut c = case("authz", "GET", "/admin/stats");
    c.secured = Some(true);
    c.expected_status = Some(401);
    assert_eq!(
        v(&c, &obs(401, "application/json", "{}")),
        (Verdict::Pass, None)
    );
    assert_eq!(
        v(&c, &obs(403, "application/json", "{}")),
        (Verdict::Pass, None)
    );
    // arbitrary keys: the verdict must not depend on "id"/"user"/"token"/"session"
    assert_eq!(
        v(&c, &obs(200, "application/json", r#"{"orders": 3}"#)),
        (Verdict::Fail, Some(Severity::Critical))
    );
    assert_eq!(
        v(&c, &obs(200, "application/json", r#"{"zzz": [1,2,3]}"#)),
        (Verdict::Fail, Some(Severity::Critical))
    );
    assert_eq!(
        v(&c, &obs(404, "application/json", "{}")).0,
        Verdict::Inconclusive
    );
    let mut spa = obs(200, "text/html", "<!doctype html><div id=root>");
    spa.is_spa_shell = true;
    assert_eq!(v(&c, &spa).0, Verdict::Inconclusive);
    // unknown protection + 2xx is not a failure, it is unknown
    let mut open = case("authz", "GET", "/pricing");
    open.expected_status = Some(401);
    assert_eq!(
        v(&open, &obs(200, "text/html", "<p>hi</p>")).0,
        Verdict::Inconclusive
    );
    // protected by discovery (401 without creds) but a forged token gets 200
    let mut forged = case("authz", "GET", "/me");
    forged.role = Some("forged".into());
    forged.route_status = Some(401);
    let r = judge(&forged, &obs(200, "application/json", r#"{"a":1}"#));
    assert_eq!(r.verdict, Verdict::Fail);
    assert!(r.reason().unwrap().contains("forged token accepted"));
}

#[test]
fn sensitive_files() {
    let mut c = case("authz", "GET", "/.env");
    c.expected_status = Some(403);
    assert_eq!(v(&c, &obs(404, "text/html", "nf")), (Verdict::Pass, None));
    assert_eq!(v(&c, &obs(403, "text/html", "no")), (Verdict::Pass, None));
    assert_eq!(
        v(&c, &obs(200, "text/plain", "DB_HOST=db\nAPP_KEY=abc")),
        (Verdict::Fail, Some(Severity::Critical))
    );
    assert_eq!(
        v(
            &c,
            &obs(200, "text/html", "<!doctype html><title>x</title>")
        ),
        (Verdict::Pass, None)
    );
    let g = case("authz", "GET", "/.git/config");
    assert_eq!(
        v(
            &g,
            &obs(200, "text/plain", "[core]\n\trepositoryformatversion = 0")
        ),
        (Verdict::Fail, Some(Severity::Critical))
    );
    assert!(
        is_sensitive_path("/.env")
            && is_sensitive_path("/a/phpinfo.php?x=1")
            && !is_sensitive_path("/.well-known/security.txt")
            && !is_sensitive_path("/orders")
    );
}

#[test]
fn five_xx_after_negative_or_injection_input_fails() {
    let b = case("boundary", "POST", "/orders");
    assert_eq!(
        v(&b, &obs(500, "application/json", "{}")),
        (Verdict::Fail, Some(Severity::Medium))
    );
    let n = case("negative", "POST", "/orders");
    assert_eq!(
        v(&n, &obs(502, "text/html", "bad gateway")),
        (Verdict::Fail, Some(Severity::Medium))
    );
    let i = case("injection", "GET", "/search");
    assert_eq!(
        v(&i, &obs(500, "text/plain", "oops")),
        (Verdict::Fail, Some(Severity::High))
    );
    // robustness cases pass on a clean 4xx even without an explicit expectation
    assert_eq!(
        v(&b, &obs(422, "application/json", "{}")),
        (Verdict::Pass, None)
    );
}

#[test]
fn expected_status_and_behavior_are_compared() {
    let mut c = case("state_transition", "GET", "/health");
    c.expected_status = Some(200);
    assert_eq!(v(&c, &obs(200, "application/json", "{}")).0, Verdict::Pass);
    assert_eq!(v(&c, &obs(204, "", "")).0, Verdict::Pass, "same 2xx class");
    assert_eq!(
        v(&c, &obs(404, "text/html", "x")),
        (Verdict::Fail, Some(Severity::Medium))
    );
    assert_eq!(
        v(&c, &obs(401, "application/json", "{}")).0,
        Verdict::Inconclusive,
        "no credential: not a defect"
    );
    let mut e = case("state_transition", "GET", "/x");
    e.expected_status = Some(201);
    assert_eq!(
        v(&e, &obs(200, "application/json", "{}")),
        (Verdict::Fail, Some(Severity::Medium))
    );
    // behaviour text
    let mut b = case("negative", "POST", "/orders");
    b.expected_behavior = "Malformed JSON must be rejected with a 4xx client error".into();
    assert_eq!(v(&b, &obs(400, "application/json", "{}")).0, Verdict::Pass);
    assert_eq!(
        v(&b, &obs(201, "application/json", "{}")),
        (Verdict::Fail, Some(Severity::Medium))
    );
    assert_eq!(
        v(&b, &obs(401, "application/json", "{}")).0,
        Verdict::Inconclusive,
        "refused at auth: validation not exercised"
    );
    let mut s = case("state_transition", "GET", "/p");
    s.expected_behavior = "HTTP 200 OK with a valid response".into();
    assert_eq!(v(&s, &obs(302, "", "")).0, Verdict::Inconclusive);
    assert_eq!(v(&s, &obs(200, "text/html", "ok")).0, Verdict::Pass);
    // ambiguous text yields no expectation, and a liveness case with none is INCONCLUSIVE
    let mut amb = case("state_transition", "GET", "/p");
    amb.expected_behavior = "Payload is HTML encoded or blocked with 403".into();
    assert_eq!(
        v(&amb, &obs(200, "text/html", "ok")).0,
        Verdict::Inconclusive
    );
}

#[test]
fn error_disclosure_and_reflection() {
    let c = case("negative", "GET", "/x");
    let tb = "Traceback (most recent call last):\n  File \"/home/app/server.py\", line 88";
    let r = judge(&c, &obs(400, "text/plain", tb));
    assert_eq!(
        (r.verdict, r.max_fail_severity()),
        (Verdict::Fail, Some(Severity::High))
    );
    assert_eq!(
        disclosure_signature("You have an error in your SQL syntax near"),
        Some("a SQL error")
    );
    assert_eq!(
        disclosure_signature("Fatal error: Uncaught x in /var/www/a.php on line 4"),
        Some("a PHP error")
    );
    assert_eq!(disclosure_signature("all good"), None);

    let i = case("injection", "GET", "/search");
    let sent = vec![r#""><script>alert(1)</script>"#.to_string()];
    let mut o = obs(200, "text/html", r#"<p>"><script>alert(1)</script></p>"#);
    o.sent_values = &sent;
    assert_eq!(judge(&i, &o).verdict, Verdict::Fail);
    let mut o2 = obs(
        200,
        "text/html",
        "<p>&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;</p>",
    );
    o2.sent_values = &sent;
    assert_eq!(judge(&i, &o2).verdict, Verdict::Pass);
    // reflected inside JSON is not executable markup
    let mut o3 = obs(
        200,
        "application/json",
        r#"{"q":"\"><script>alert(1)</script>"}"#,
    );
    o3.sent_values = &sent;
    assert_eq!(judge(&i, &o3).verdict, Verdict::Pass);
    // canary
    let canary = vec!["CANARY_PROMPT_LEAK_7".to_string()];
    let mut o4 = obs(
        200,
        "application/json",
        "{\"echo\": \"CANARY_PROMPT_LEAK_7\"}",
    );
    o4.sent_values = &canary;
    assert_eq!(judge(&i, &o4).verdict, Verdict::Fail);
}

#[test]
fn contract_fields_come_from_the_spec() {
    let mut c = case("state_transition", "GET", "/orders/2");
    c.expected_status = Some(200);
    c.expect_fields = vec!["id".into(), "total".into()];
    assert_eq!(
        v(&c, &obs(200, "application/json", r#"{"id":2,"item":"m"}"#)),
        (Verdict::Fail, Some(Severity::Medium))
    );
    assert_eq!(
        v(&c, &obs(200, "application/json", r#"{"id":2,"total":10}"#)).0,
        Verdict::Pass
    );
    assert_eq!(
        v(
            &c,
            &obs(200, "application/json", r#"[{"id":2,"total":10}]"#)
        )
        .0,
        Verdict::Pass
    );
    assert_eq!(
        v(&c, &obs(200, "text/html", "<p>")).0,
        Verdict::Inconclusive
    );
}

fn order_contract(latency: bool) -> ResponseContract {
    let order = serde_json::json!({"type":"object","required":["id","total"],"properties":{
            "id":{"type":"integer"},"total":{"type":"integer"}}});
    let mut responses = qa_contract::Responses::new();
    responses.insert("200".into(), Some(order));
    responses.insert("404".into(), None);
    responses.insert("401".into(), None);
    ResponseContract { responses, latency }
}

#[test]
fn the_documented_schema_judges_a_2xx_body_with_the_qa_validator() {
    let mut c = case("state_transition", "GET", "/orders/2");
    c.expected_status = Some(200);
    c.contract = Some(order_contract(false));
    // the QA engine's bug 5: a required field is missing
    let r = judge(&c, &obs(200, "application/json", r#"{"id":2,"item":"m"}"#));
    assert_eq!(
        (r.verdict, r.max_fail_severity()),
        (Verdict::Fail, Some(Severity::Medium))
    );
    let f = r.first_fail().unwrap();
    assert_eq!(f.code, "contract_fields");
    assert!(
        f.detail.contains("$.total: required property missing"),
        "{}",
        f.detail
    );
    // a type the schema forbids is caught too, which the field-name check never saw
    let r = judge(
        &c,
        &obs(200, "application/json", r#"{"id":"2","total":10}"#),
    );
    assert!(
        r.first_fail()
            .unwrap()
            .detail
            .contains("$.id: expected integer")
    );
    assert_eq!(
        v(&c, &obs(200, "application/json", r#"{"id":2,"total":10}"#)).0,
        Verdict::Pass
    );
    // the schema supersedes the bare field check (one contract verdict, not two)
    c.expect_fields = vec!["id".into(), "total".into()];
    let r = judge(&c, &obs(200, "application/json", r#"{"id":2,"item":"m"}"#));
    assert_eq!(
        r.checks
            .iter()
            .filter(|k| k.code == "contract_fields")
            .count(),
        1
    );
    // an unparseable body does not turn a good status into INCONCLUSIVE: it is a warning (the
    // bare field check, when the case has one, keeps judging it as before)
    c.expect_fields.clear();
    let r = judge(&c, &obs(200, "text/html", "<p>shell</p>"));
    assert_eq!(r.verdict, Verdict::Pass, "{r:?}");
    assert!(r.warnings.iter().any(|w| w.contains("not (complete) JSON")));
    // without a contract the legacy field-name check still runs
    c.contract = None;
    c.expect_fields = vec!["id".into(), "total".into()];
    assert_eq!(
        v(&c, &obs(200, "application/json", r#"{"id":2,"item":"m"}"#)).0,
        Verdict::Fail
    );
}

#[test]
fn an_undocumented_status_is_a_low_finding_but_auth_rate_limit_and_5xx_are_not() {
    let mut c = case("boundary", "POST", "/orders");
    c.expected_behavior = "Invalid input is rejected with a 4xx client error".into();
    c.contract = Some(order_contract(false));
    // 409 is a rejection (the input was refused) but the spec does not list it
    let r = judge(&c, &obs(409, "application/json", "{}"));
    assert_eq!(r.verdict, Verdict::Fail);
    assert_eq!(r.first_fail().unwrap().code, "undocumented_status");
    assert_eq!(r.max_fail_severity(), Some(Severity::Low));
    // documented 404 is fine; 401/403/429 are the auth layer and the limiter, not the contract
    for st in [404, 401, 403, 429] {
        let r = judge(&c, &obs(st, "application/json", "{}"));
        assert!(
            r.checks.iter().all(|k| k.code != "undocumented_status"),
            "{st}: {r:?}"
        );
    }
    // a 500 stays a server_error alone
    let r = judge(&c, &obs(500, "application/json", "{}"));
    assert!(r.checks.iter().all(|k| k.code != "undocumented_status"));
    assert_eq!(r.first_fail().unwrap().code, "server_error");
    // a spec that documents no response judges no status
    c.contract = Some(ResponseContract::default());
    assert!(
        judge(&c, &obs(409, "application/json", "{}"))
            .checks
            .iter()
            .all(|k| k.code != "undocumented_status")
    );
}

#[test]
fn a_read_over_the_qa_latency_limit_fails_as_slow_response() {
    let mut c = case("state_transition", "GET", "/reports/slow");
    c.expected_status = Some(200);
    c.contract = Some(ResponseContract {
        responses: Default::default(),
        latency: true,
    });
    let mut o = obs(200, "application/json", "{}");
    o.latency_ms = latency::SLOW_P95_MS as u64 + 1;
    let r = judge(&c, &o);
    assert_eq!(
        (r.verdict, r.max_fail_severity()),
        (Verdict::Fail, Some(Severity::Low))
    );
    assert_eq!(r.first_fail().unwrap().code, "slow_response");
    assert!(r.reason().unwrap().contains("1001 ms"), "{:?}", r.reason());
    // exactly at the limit is not slow, and a case without `latency` is never judged on it
    o.latency_ms = latency::SLOW_P95_MS as u64;
    let r = judge(&c, &o);
    assert_eq!(r.verdict, Verdict::Pass);
    assert!(
        r.checks
            .iter()
            .any(|k| k.code == "latency" && k.verdict == Verdict::Pass)
    );
    o.latency_ms = 60_000;
    c.contract.as_mut().unwrap().latency = false;
    assert_eq!(judge(&c, &o).verdict, Verdict::Pass);
    // a slow error answer is not the operation's latency
    c.contract.as_mut().unwrap().latency = true;
    assert!(
        judge(&c, &obs_at(404, 60_000))
            .checks
            .iter()
            .all(|k| k.code != "slow_response")
    );
}

fn obs_at(status: u16, ms: u64) -> Observation<'static> {
    let mut o = obs(status, "application/json", "{}");
    o.latency_ms = ms;
    o
}

#[test]
fn the_severities_of_the_contract_checks_come_from_the_triage_table() {
    use super::super::triage::severity_for;
    assert_eq!(
        severity_for("contract_fields", Technique::Other),
        Severity::Medium
    );
    assert_eq!(
        severity_for("slow_response", Technique::Other),
        Severity::Low
    );
    assert_eq!(
        severity_for("undocumented_status", Technique::Other),
        Severity::Low
    );
}

#[test]
fn cookie_flags_warn_but_do_not_fail() {
    let mut c = case("state_transition", "GET", "/");
    c.expected_status = Some(200);
    let hdrs = vec![(
        "set-cookie".to_string(),
        "PHPSESSID=abc; path=/".to_string(),
    )];
    let mut o = obs(200, "text/html", "<p>");
    o.headers = &hdrs;
    let r = judge(&c, &o);
    assert_eq!(r.verdict, Verdict::Pass);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("HttpOnly"));
    assert!(
        !r.warnings[0].contains("abc"),
        "cookie value must not be copied"
    );
}

#[test]
fn liveness_without_any_expectation_is_inconclusive_not_pass() {
    let c = case("state_transition", "GET", "/x");
    let r = judge(&c, &obs(200, "text/html", "ok"));
    assert_eq!(r.verdict, Verdict::Inconclusive);
    assert!(r.checks.iter().any(|c| c.code == "no_assertion"));
}

// ------------------------------------------------------------ class-specific evidence

#[test]
fn robustness_cases_pass_only_on_class_specific_evidence() {
    let b = case("boundary", "POST", "/orders");
    // "no 5xx" alone proves nothing
    for code in [200u16, 201, 204] {
        let r = judge(&b, &obs(code, "application/json", "{}"));
        assert_eq!(r.verdict, Verdict::Inconclusive, "boundary {code}");
        assert!(r.checks.iter().any(|c| c.code == "no_class_evidence"));
    }
    // an explicit validation response is evidence
    for code in [400u16, 413, 422] {
        let r = judge(&b, &obs(code, "application/json", "{}"));
        assert_eq!(r.verdict, Verdict::Pass, "boundary {code}");
        assert!(r.checks.iter().any(|c| c.code == "validation_rejection"));
    }
    // 404 / 405 / 429 / auth-layer refusals are not "rejected"
    for code in [401u16, 403, 404, 405, 410, 429] {
        assert_eq!(
            judge(&b, &obs(code, "application/json", "{}")).verdict,
            Verdict::Inconclusive,
            "boundary {code}"
        );
    }
    // the same holds for an explicit "must be rejected" expectation
    let mut n = case("negative", "POST", "/orders");
    n.expected_behavior = "Malformed input must be rejected with a 4xx client error".into();
    for code in [404u16, 405, 429] {
        assert_eq!(
            judge(&n, &obs(code, "application/json", "{}")).verdict,
            Verdict::Inconclusive,
            "{code} is not a validation rejection"
        );
    }
    assert_eq!(
        judge(&n, &obs(422, "application/json", "{}")).verdict,
        Verdict::Pass
    );
    // a SQL-style probe answered 200 with no error is inconclusive, not a pass
    let mut sqli = case("injection", "GET", "/search");
    sqli.payload = Some("q=' OR '1'='1' --".into());
    let sent = vec!["' OR '1'='1' --".to_string()];
    let mut o = obs(200, "application/json", r#"{"results": []}"#);
    o.sent_values = &sent;
    assert_eq!(judge(&sqli, &o).verdict, Verdict::Inconclusive);
    let mut rej = obs(400, "application/json", "{}");
    rej.sent_values = &sent;
    assert_eq!(judge(&sqli, &rej).verdict, Verdict::Pass);
    // verb probes: a clean 2xx or 405 is how a server handles HEAD/OPTIONS
    let head = case("negative", "HEAD", "/about");
    assert_eq!(
        judge(&head, &obs(200, "text/html", "")).verdict,
        Verdict::Pass
    );
    assert_eq!(
        judge(&head, &obs(405, "text/html", "")).verdict,
        Verdict::Pass
    );
    assert_eq!(
        judge(&head, &obs(404, "text/html", "")).verdict,
        Verdict::Inconclusive
    );
}

#[test]
fn path_traversal_content_signature() {
    let mut c = case("injection", "GET", "/files");
    c.payload = Some("file=..%2f..%2f..%2fetc%2fpasswd".into());
    let sent = vec!["..%2f..%2f..%2fetc%2fpasswd".to_string()];
    let mut o = obs(
        200,
        "text/plain",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin",
    );
    o.sent_values = &sent;
    let r = judge(&c, &o);
    assert_eq!(
        (r.verdict, r.max_fail_severity()),
        (Verdict::Fail, Some(Severity::Critical))
    );
    assert!(r.checks.iter().any(|c| c.code == "path_traversal"));
    assert_eq!(
        traversal_signature("[boot loader]\ntimeout=30"),
        Some("the contents of win.ini / boot.ini")
    );
    // the same text on a request that carried no traversal sequence is a document, not a finding
    let plain = case("injection", "GET", "/docs");
    let r = judge(
        &plain,
        &obs(200, "text/plain", "root:x:0:0:root:/root:/bin/bash"),
    );
    assert!(r.checks.iter().all(|c| c.code != "path_traversal"));
    // a traversal answered with an ordinary page is not evidence of anything
    let mut o2 = obs(200, "text/html", "<p>welcome</p>");
    o2.sent_values = &sent;
    assert_eq!(judge(&c, &o2).verdict, Verdict::Inconclusive);
}

#[test]
fn mass_assignment_reflection_check() {
    let mut c = case("boundary", "POST", "/users");
    c.payload = Some(r#"{"name":"x","role":"admin","is_admin":true}"#.into());
    let body = r#"{"name":"x","role":"admin","is_admin":true}"#;
    let mut o = obs(
        201,
        "application/json",
        r#"{"id":7,"name":"x","role":"admin"}"#,
    );
    o.request_body = Some(body);
    let r = judge(&c, &o);
    assert_eq!(
        (r.verdict, r.max_fail_severity()),
        (Verdict::Fail, Some(Severity::High))
    );
    assert!(r.checks.iter().any(|c| c.code == "mass_assignment"));
    // envelope responses are looked through; nested sub-resources are not
    let mut env = obs(
        200,
        "application/json",
        r#"{"data":{"id":7,"is_admin":true}}"#,
    );
    env.request_body = Some(body);
    assert_eq!(judge(&c, &env).verdict, Verdict::Fail);
    let mut nested = obs(
        200,
        "application/json",
        r#"{"id":7,"owner":{"role":"admin"}}"#,
    );
    nested.request_body = Some(body);
    assert_eq!(
        judge(&c, &nested).verdict,
        Verdict::Inconclusive,
        "not echoed on the primary object"
    );
    // role was ignored: no reflection, and 2xx alone is still not evidence
    let mut ign = obs(
        201,
        "application/json",
        r#"{"id":7,"name":"x","role":"user"}"#,
    );
    ign.request_body = Some(body);
    assert_eq!(judge(&c, &ign).verdict, Verdict::Inconclusive);
    // rejected: explicit evidence
    let mut rej = obs(422, "application/json", r#"{"error":"unknown field role"}"#);
    rej.request_body = Some(body);
    assert_eq!(judge(&c, &rej).verdict, Verdict::Pass);
    // form-encoded bodies work too
    let mut form = obs(200, "application/json", r#"{"id":1,"role":"admin"}"#);
    form.request_body = Some("name=x&role=admin");
    assert_eq!(judge(&c, &form).verdict, Verdict::Fail);
}

#[test]
fn cors_probe_is_judged_on_the_allow_origin_header() {
    let mut c = case("authz", "OPTIONS", "/");
    c.title = "CORS preflight validation (/)".into();
    c.expected_status = Some(200); // must be ignored: the status class is not the question
    assert!(is_cors_case(&c));
    let h = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let run = |status: u16, hdrs: &[(&str, &str)]| {
        let hv = h(hdrs);
        let mut o = obs(status, "", "");
        o.headers = &hv;
        o.origin = Some(CORS_PROBE_ORIGIN);
        judge(&c, &o)
    };
    // reflects the foreign origin
    let r = run(204, &[("access-control-allow-origin", CORS_PROBE_ORIGIN)]);
    assert_eq!(
        (r.verdict, r.max_fail_severity()),
        (Verdict::Fail, Some(Severity::Medium))
    );
    // ... with credentials: worse
    let r = run(
        204,
        &[
            ("access-control-allow-origin", CORS_PROBE_ORIGIN),
            ("access-control-allow-credentials", "true"),
        ],
    );
    assert_eq!(
        (r.verdict, r.max_fail_severity()),
        (Verdict::Fail, Some(Severity::High))
    );
    // wildcard + credentials fails; a bare wildcard is an advisory warning
    assert_eq!(
        run(
            200,
            &[
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "true")
            ]
        )
        .verdict,
        Verdict::Fail
    );
    let w = run(200, &[("access-control-allow-origin", "*")]);
    assert_eq!(w.verdict, Verdict::Pass);
    assert_eq!(w.warnings.len(), 1);
    // not granted: absent, or a different fixed origin
    assert_eq!(run(204, &[]).verdict, Verdict::Pass);
    assert_eq!(
        run(
            200,
            &[("access-control-allow-origin", "https://app.example")]
        )
        .verdict,
        Verdict::Pass
    );
    // route not served: nothing was learned
    assert_eq!(run(404, &[]).verdict, Verdict::Inconclusive);
    assert_eq!(run(405, &[]).verdict, Verdict::Inconclusive);
    // a 200 does NOT pass a CORS case by itself when the origin is reflected
    assert_eq!(
        run(200, &[("access-control-allow-origin", CORS_PROBE_ORIGIN)]).verdict,
        Verdict::Fail
    );
    // no Origin was sent: the policy was not exercised
    let r = judge(&c, &obs(200, "", ""));
    assert_eq!(r.verdict, Verdict::Inconclusive);
}

#[test]
fn llm_proposed_cases_cannot_fail_on_their_own_expectation() {
    let mut c = case("state_transition", "GET", "/health");
    c.source = Some("llm".into());
    c.expected_status = Some(200);
    let r = judge(&c, &obs(404, "text/html", "x"));
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:?}");
    assert!(r.exploratory && r.max_fail_severity().is_none());
    assert!(r.reason().unwrap().contains("exploratory"));
    // the same case from the deterministic planner fails
    c.source = Some("deterministic".into());
    assert_eq!(
        judge(&c, &obs(404, "text/html", "x")).verdict,
        Verdict::Fail
    );
    // a deterministic invariant still fails an LLM case
    let mut l = case("injection", "GET", "/search");
    l.source = Some("llm".into());
    let r = judge(&l, &obs(500, "text/plain", "oops"));
    assert_eq!(r.verdict, Verdict::Fail);
    assert!(r.exploratory);
    let r = judge(
        &l,
        &obs(200, "text/plain", "Traceback (most recent call last):\n x"),
    );
    assert_eq!(
        r.verdict,
        Verdict::Fail,
        "stack trace disclosure is deterministic"
    );
}

#[test]
fn stateful_oracle_table() {
    use StatefulFacts::*;
    let cross = |second: u16,
                 anon: Option<u16>,
                 again: Option<bool>,
                 owner: Option<u16>,
                 anon_actor: bool| {
        judge_stateful(&CrossActor {
            second_actor_anon: anon_actor,
            safe_method: true,
            owner_control: owner,
            second_status: second,
            anon_status: anon,
            reproduced: again,
        })
    };
    // confirmed breach
    let r = cross(200, Some(401), Some(true), Some(200), false);
    assert_eq!(
        (r.verdict, r.max_fail_severity()),
        (Verdict::Fail, Some(Severity::Critical))
    );
    // not reproduced / public resource / unconfirmed
    assert_eq!(
        cross(200, Some(401), Some(false), Some(200), false).verdict,
        Verdict::Inconclusive
    );
    assert_eq!(
        cross(200, Some(200), None, Some(200), false).verdict,
        Verdict::Inconclusive
    );
    assert_eq!(
        cross(200, Some(401), None, Some(200), false).verdict,
        Verdict::Inconclusive
    );
    // 401/403/429/3xx from the second actor are never a PASS
    for s in [401u16, 403, 429, 301, 302, 400, 405, 500] {
        assert_eq!(
            cross(s, None, None, Some(200), false).verdict,
            Verdict::Inconclusive,
            "{s}"
        );
    }
    // hidden resource while the owner reads it: the one positive isolation signal
    assert_eq!(
        cross(404, None, None, Some(200), false).verdict,
        Verdict::Pass
    );
    // an anonymous second actor has no credential that could be "wrong"
    assert_eq!(
        cross(401, None, None, Some(200), true).verdict,
        Verdict::Pass
    );
    // the owner control failing makes any answer meaningless
    assert_eq!(
        cross(404, None, None, Some(404), false).verdict,
        Verdict::Inconclusive
    );
    assert_eq!(
        cross(200, Some(401), Some(true), Some(403), false).verdict,
        Verdict::Inconclusive
    );
    assert_eq!(
        cross(404, None, None, None, false).verdict,
        Verdict::Inconclusive
    );
    // a state-changing access step cannot be re-run safely
    let w = judge_stateful(&CrossActor {
        second_actor_anon: false,
        safe_method: false,
        owner_control: Some(200),
        second_status: 200,
        anon_status: None,
        reproduced: None,
    });
    assert_eq!(w.verdict, Verdict::Inconclusive);
    // workflow + setup
    assert_eq!(
        judge_stateful(&Workflow { failed_step: None }).verdict,
        Verdict::Pass
    );
    assert_eq!(
        judge_stateful(&Workflow {
            failed_step: Some((2, Some(200), 404))
        })
        .verdict,
        Verdict::Inconclusive
    );
    assert_eq!(
        judge_stateful(&Workflow {
            failed_step: Some((2, Some(200), 409))
        })
        .verdict,
        Verdict::Fail
    );
    assert_eq!(
        judge_stateful(&Setup {
            step: 1,
            status: Some(401),
            reason: "x".into()
        })
        .verdict,
        Verdict::Inconclusive
    );
}

#[test]
fn burst_oracle_fails_only_on_a_violated_invariant() {
    let r = |status: u16, body: &str| BurstResponse {
        status,
        body: body.into(),
    };
    let judge = |method: &str, rs: &[BurstResponse], pre: Option<&str>, post: Option<&str>| {
        judge_burst(&BurstFacts {
            method,
            requested: rs.len(),
            responses: rs,
            pre_read: pre,
            post_read: post,
        })
    };
    // every request 2xx and nothing to compare: INCONCLUSIVE, never FAIL
    let all_ok: Vec<_> = (0..5).map(|_| r(200, "{\"ok\":true}")).collect();
    let o = judge("POST", &all_ok, None, None);
    assert_eq!(o.verdict, Verdict::Inconclusive);
    assert!(o.max_fail_severity().is_none());
    // duplicate created ids
    let dup: Vec<_> = (0..4).map(|_| r(201, "{\"id\": 4}")).collect();
    let o = judge("POST", &dup, None, None);
    assert_eq!(
        (o.verdict, o.max_fail_severity()),
        (Verdict::Fail, Some(Severity::High))
    );
    // distinct ids: the invariant held
    let ok: Vec<_> = (1..=4)
        .map(|i| r(201, &format!("{{\"id\": {i}}}")))
        .collect();
    assert_eq!(judge("POST", &ok, None, None).verdict, Verdict::Pass);
    // PUT answering the same id is idempotence, not a duplicate creation
    let put: Vec<_> = (0..3).map(|_| r(200, "{\"id\": 9}")).collect();
    assert_eq!(
        judge("PUT", &put, None, None).verdict,
        Verdict::Inconclusive
    );
    // lost update: five acknowledged increments, same value in the responses, +1 on re-read
    let lost: Vec<_> = (0..5).map(|_| r(200, "{\"count\": 1}")).collect();
    let o = judge(
        "POST",
        &lost,
        Some("{\"count\": 0}"),
        Some("{\"count\": 1}"),
    );
    assert_eq!(o.verdict, Verdict::Fail, "{o:?}");
    // atomic counter: distinct values, final == acknowledged
    let good: Vec<_> = (1..=5)
        .map(|i| r(200, &format!("{{\"count\": {i}}}")))
        .collect();
    assert_eq!(
        judge(
            "POST",
            &good,
            Some("{\"count\": 0}"),
            Some("{\"count\": 5}")
        )
        .verdict,
        Verdict::Pass
    );
    // an unrelated field that did not move is not a counter of ours
    let still: Vec<_> = (0..3).map(|_| r(200, "{\"total\": 3}")).collect();
    assert_eq!(
        judge(
            "POST",
            &still,
            Some("{\"total\": 3}"),
            Some("{\"total\": 3}")
        )
        .verdict,
        Verdict::Inconclusive
    );
    // 5xx under load is recorded as a warning, not an invariant failure
    let mixed = vec![r(200, "{}"), r(500, "oops"), r(500, "oops")];
    let o = judge("POST", &mixed, None, None);
    assert_eq!(o.verdict, Verdict::Inconclusive);
    assert_eq!(o.warnings.len(), 1);
    // too few answers
    assert_eq!(
        judge("POST", &[r(200, "{}")], None, None).verdict,
        Verdict::Inconclusive
    );
}
// ------------------------------------------------------------ login matcher, auth wall

#[test]
fn the_login_matcher_knows_login_pages_and_not_lookalikes() {
    for yes in [
        "/login",
        "/Login?next=/dashboard",
        "/users/sign-in",
        "/signin",
        "/sso/start",
        "https://idp.example.com/oauth2/authorize?client_id=1",
        "https://tenant.auth0.com/authorize",
        "/auth/callback",
        "/account/authentication",
        "https://accounts.example.com/saml/redirect",
    ] {
        assert!(is_login_location(yes), "{yes} is a login page");
    }
    for no in [
        "/",
        "/authors",
        "/authors/42",
        "/blog/author-bio",
        "/associates",
        "/dashboard?next=/login",
        "/products?utm=sso",
        "/pricing#login",
        "",
    ] {
        assert!(!is_login_location(no), "{no} is not a login page");
    }
}

#[test]
fn a_password_input_is_found_and_text_about_passwords_is_not() {
    assert!(has_password_field(
        r#"<form><input type="password" name="p"></form>"#
    ));
    assert!(has_password_field(
        "<INPUT name=p class='x' TYPE = 'Password'>"
    ));
    assert!(!has_password_field(
        r#"<input type="text" name="password_hint"> Reset your password here"#
    ));
    assert!(!has_password_field("{\"type\": \"password\"}"));
}

fn hop(status: u16, to: &str) -> RedirectHop {
    RedirectHop {
        status,
        location: to.into(),
    }
}

#[test]
fn auth_wall_signals_are_a_401_a_login_redirect_or_a_password_form_after_a_redirect() {
    let loc = |v: &str| vec![("location".to_string(), v.to_string())];
    // a 401
    let w = auth_wall_signal(401, "application/json", &[], "{}", &[]).unwrap();
    assert!(w.what.contains("401") && !w.redirected);
    // a redirect to a login page that was not followed
    let w = auth_wall_signal(307, "text/plain", &loc("/login"), "", &[]).unwrap();
    assert!(w.what.contains("307") && w.what.contains("/login") && w.redirected);
    // ... or one that was followed
    let w = auth_wall_signal(
        200,
        "text/html",
        &[],
        "<h1>Sign in</h1>",
        &[hop(302, "/accounts/login?next=/")],
    )
    .unwrap();
    assert!(w.redirected && w.what.contains("login"));
    // a redirect that ended on a password form
    let w = auth_wall_signal(
        200,
        "text/html",
        &[],
        r#"<input type="password">"#,
        &[hop(302, "/welcome")],
    )
    .unwrap();
    assert!(w.redirected && w.what.contains("password"));
    // not walls: a page with a password field that nothing redirected to, a plain 200, a
    // redirect to somewhere else, a 403
    assert_eq!(
        auth_wall_signal(200, "text/html", &[], r#"<input type="password">"#, &[]),
        None
    );
    assert_eq!(
        auth_wall_signal(200, "application/json", &[], "{}", &[]),
        None
    );
    assert_eq!(auth_wall_signal(302, "", &loc("/home"), "", &[]), None);
    assert_eq!(
        auth_wall_signal(200, "text/html", &[], "<p>ok</p>", &[hop(301, "/new-home")]),
        None
    );
    assert_eq!(auth_wall_signal(403, "text/html", &[], "no", &[]), None);
}

#[test]
fn the_authz_oracle_uses_the_same_login_matcher() {
    let mut c = case("authz", "GET", "/account");
    c.expected_status = Some(401);
    let mut o = obs(302, "text/plain", "");
    let to_login = [("location".to_string(), "/users/sign-in".to_string())];
    o.headers = &to_login;
    assert_eq!(judge(&c, &o).verdict, Verdict::Pass);
    let lookalike = [("location".to_string(), "/authors".to_string())];
    o.headers = &lookalike;
    assert_eq!(
        judge(&c, &o).verdict,
        Verdict::Inconclusive,
        "/authors is not an authentication page"
    );
}

#[test]
fn the_case_says_what_it_expects_for_redirects_and_denials() {
    let mut c = case("state_transition", "GET", "/");
    assert!(!expects_redirect(&c) && !expects_denial(&c));
    c.expected_status = Some(307);
    assert!(expects_redirect(&c));
    c.expected_status = Some(401);
    assert!(expects_denial(&c));
    c.expected_status = Some(200);
    assert!(!expects_redirect(&c) && !expects_denial(&c));
    let mut t = case("state_transition", "GET", "/");
    t.expected_behavior = "redirects as it did during discovery".into();
    assert!(expects_redirect(&t));
}

#[test]
fn the_class_evidence_message_reads_right_for_every_technique() {
    for (tech, article) in [
        ("injection", "an injection case"),
        ("boundary", "a boundary case"),
        ("negative", "a negative case"),
    ] {
        let r = judge(
            &case(tech, "GET", "/x"),
            &obs(200, "application/json", "{}"),
        );
        let msg = r.reason().unwrap();
        assert!(msg.contains(article), "{msg}");
        assert!(!msg.contains("a injection"), "{msg}");
    }
}

#[test]
fn blind_boolean_diff_flags_when_true_diverges_from_false_and_passes_on_identical() {
    let mut c = case("injection", "GET", "/items");
    c.payload = Some("q=' OR '1'='1".into());
    c.probe_oracle = Some(crate::agent::types::ProbeOracle::BooleanDiff {
        baseline_payload: "q=widget".into(),
        false_payload: "q=' AND '1'='2".into(),
    });
    // Vulnerable: baseline & true return rich item list; false returns empty
    let vuln_ev = ProbeEvidence {
        baseline: Some(ProbeSnapshot {
            status: 200,
            body: "{\"items\":[{\"id\":1,\"name\":\"widget\"},{\"id\":2,\"name\":\"gadget\"}]}"
                .into(),
            latency_ms: 4,
        }),
        control: Some(ProbeSnapshot {
            status: 200,
            body: "{\"items\":[]}".into(),
            latency_ms: 4,
        }),
        ..ProbeEvidence::default()
    };
    let mut o = obs(
        200,
        "application/json",
        "{\"items\":[{\"id\":1,\"name\":\"widget\"},{\"id\":2,\"name\":\"gadget\"}]}",
    );
    o.probe = Some(&vuln_ev);
    let out = judge(&c, &o);
    assert_eq!(out.verdict, Verdict::Fail);
    assert!(
        out.checks
            .iter()
            .any(|k| k.code == "blind_boolean_injection" && k.verdict == Verdict::Fail),
        "{:?}",
        out.checks
    );

    // Safe: baseline returns normal list while true and false both return empty (treated as literal search term)
    let safe_ev = ProbeEvidence {
        baseline: Some(ProbeSnapshot {
            status: 200,
            body: "{\"items\":[{\"id\":1,\"name\":\"widget\"}]}".into(),
            latency_ms: 4,
        }),
        control: Some(ProbeSnapshot {
            status: 200,
            body: "{\"items\":[]}".into(),
            latency_ms: 4,
        }),
        ..ProbeEvidence::default()
    };
    let mut o2 = obs(200, "application/json", "{\"items\":[]}");
    o2.probe = Some(&safe_ev);
    assert_eq!(judge(&c, &o2).verdict, Verdict::Pass);
}

#[test]
fn blind_time_delay_flags_only_when_delayed_above_baseline() {
    let mut c = case("injection", "GET", "/search");
    c.payload = Some("q=' OR SLEEP(1)--".into());
    c.probe_oracle = Some(crate::agent::types::ProbeOracle::TimeDelay {
        baseline_payload: "q=test".into(),
        min_delay_ms: 150,
    });
    let slow_ev = ProbeEvidence {
        baseline: Some(ProbeSnapshot {
            status: 200,
            body: "{}".into(),
            latency_ms: 8,
        }),
        ..ProbeEvidence::default()
    };
    let mut o = obs(200, "application/json", "{}");
    o.latency_ms = 210;
    o.probe = Some(&slow_ev);
    let out = judge(&c, &o);
    assert_eq!(out.verdict, Verdict::Fail);
    assert!(
        out.checks
            .iter()
            .any(|k| k.code == "blind_time_injection" && k.verdict == Verdict::Fail)
    );

    // Fast probe: PASS
    o.latency_ms = 12;
    assert_eq!(judge(&c, &o).verdict, Verdict::Pass);
}

#[test]
fn ssti_flags_evaluated_arithmetic_and_ignores_literal_echo() {
    let mut c = case("injection", "GET", "/greet");
    c.payload = Some("name={{1337*79}}".into());
    c.probe_oracle = Some(crate::agent::types::ProbeOracle::Ssti {
        expected_eval: "105623".into(),
    });
    let out_eval = judge(&c, &obs(200, "text/html", "Hello 105623!"));
    assert_eq!(out_eval.verdict, Verdict::Fail);
    assert!(out_eval.checks.iter().any(|k| k.code == "ssti"));

    let out_echo = judge(
        &c,
        &obs(
            200,
            "text/html",
            "Hello &lbrace;&lbrace;1337*79&rbrace;&rbrace;",
        ),
    );
    assert_eq!(out_echo.verdict, Verdict::Pass);
}

#[test]
fn open_redirect_flags_external_canary_location_and_allows_safe_redirect() {
    let mut c = case(
        "negative",
        "GET",
        "/login?next=https://readyhai-redirect.invalid/",
    );
    c.probe_oracle = Some(crate::agent::types::ProbeOracle::OpenRedirect {
        canary_host: "readyhai-redirect.invalid".into(),
    });
    let mut o = obs(302, "text/plain", "");
    let evil = [(
        "location".to_string(),
        "https://readyhai-redirect.invalid/steal".to_string(),
    )];
    o.headers = &evil;
    let out = judge(&c, &o);
    assert_eq!(out.verdict, Verdict::Fail);
    assert!(
        out.checks
            .iter()
            .any(|k| k.code == "open_redirect" && k.verdict == Verdict::Fail)
    );

    let safe = [("location".to_string(), "/dashboard".to_string())];
    o.headers = &safe;
    assert_eq!(judge(&c, &o).verdict, Verdict::Pass);
}

#[test]
fn oast_callback_flags_confirmed_hit_and_inconclusive_when_unavailable() {
    let mut c = case("injection", "POST", "/webhook");
    c.probe_oracle = Some(crate::agent::types::ProbeOracle::OastCallback {
        placeholder: "__OAST_URL__".into(),
        wait_ms: 200,
    });
    let hit_ev = ProbeEvidence {
        oast_hit: true,
        oast_detail: Some("GET /oast/abc from 127.0.0.1".into()),
        ..ProbeEvidence::default()
    };
    let mut o = obs(200, "application/json", "{\"queued\":true}");
    o.probe = Some(&hit_ev);
    let out = judge(&c, &o);
    assert_eq!(out.verdict, Verdict::Fail);
    assert!(
        out.checks
            .iter()
            .any(|k| k.code == "oast_callback" && k.verdict == Verdict::Fail)
    );

    let unavail = ProbeEvidence {
        oast_unavailable: true,
        ..ProbeEvidence::default()
    };
    o.probe = Some(&unavail);
    assert_eq!(judge(&c, &o).verdict, Verdict::Inconclusive);
}

#[test]
fn excessive_data_exposure_flags_unmasked_secret_fields() {
    let mut c = case("state_transition", "GET", "/api/users/1");
    c.probe_oracle = Some(crate::agent::types::ProbeOracle::ExcessiveDataExposure);
    let o = obs(
        200,
        "application/json",
        r#"{"id":1,"email":"a@b.com","password_hash":"$2b$12$abcdef"}"#,
    );
    let out = judge(&c, &o);
    assert_eq!(out.verdict, Verdict::Fail);
    let chk = out
        .checks
        .iter()
        .find(|k| k.code == "excessive_data_exposure")
        .unwrap();
    assert!(
        !chk.detail.contains("$2b$12$abcdef"),
        "must not leak raw secret value"
    );

    let clean = obs(200, "application/json", r#"{"id":1,"email":"a@b.com"}"#);
    let mut c2 = case("state_transition", "GET", "/api/users/1");
    c2.expected_status = Some(200);
    c2.probe_oracle = Some(crate::agent::types::ProbeOracle::ExcessiveDataExposure);
    assert_eq!(judge(&c2, &clean).verdict, Verdict::Pass);
}

#[test]
fn sensitive_path_and_config_body_recognizes_git_head_actuator_sql_and_vars() {
    for p in [
        "/.git/HEAD",
        "/actuator/env",
        "/backup.sql",
        "/debug/vars",
        "/secrets.json",
    ] {
        assert!(is_sensitive_path(p), "{p}");
        let mut c = case("authz", "GET", p);
        c.expected_status = Some(404);
        let body = match p {
            "/.git/HEAD" => "ref: refs/heads/main\n",
            "/actuator/env" => r#"{"activeProfiles":["prod"],"propertySources":[{"name":"env"}]}"#,
            "/backup.sql" => "-- MySQL dump 10.13\nCREATE TABLE users (id int);",
            "/debug/vars" => r#"{"cmdline":["/usr/local/bin/app"],"memstats":{}}"#,
            _ => "STRIPE_SECRET=sk_live_test_51234567890abcdef",
        };
        assert_eq!(
            judge(&c, &obs(200, "text/plain", body)).verdict,
            Verdict::Fail,
            "{p}"
        );
    }
}
