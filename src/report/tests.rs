//! Comprehensive unit tests for report generation formats.

use crate::model::*;

use super::common::{is_component, uri_escape};
use super::html::html;
use super::junit::junit;
use super::pr::{pr_comment, PR_COMMENT_MARKER};
use super::sarif::sarif;

fn sample() -> Run {
    let mut f1 = Finding::new(
        "web.smoke",
        "web.xss",
        Category::Security,
        Severity::High,
        "<script>alert(1)</script>",
        "http://a/x",
    );
    f1.detail = "<img src=x onerror=alert(1)>".into();
    f1.finalize();
    let mut f2 = Finding::new(
        "rules.a",
        "r.two",
        Category::Quality,
        Severity::Low,
        "low",
        "src/a.rs:12",
    );
    f2.status = FindingStatus::Suppressed;
    f2.suppressed_reason = Some("ok".into());
    f2.finalize();
    let mk = |id: &str, s: CheckStatus, n| CheckResult {
        id: id.into(),
        title: id.into(),
        tool: None,
        status: s,
        findings: n,
        duration_ms: 5,
    };
    Run {
        id: "r1".into(),
        version: "0.1.0".into(),
        target: Target {
            kind: TargetKind::Web,
            raw: "http://a".into(),
            path: None,
            image: None,
            url: Some("http://a".into()),
            openapi: None,
            host: None,
            apk: None,
            device: None,
        },
        profile: Profile::Quick,
        started: "s".into(),
        finished: "f".into(),
        verdict: Verdict::Fail,
        reasons: vec!["FAIL: 1 high".into()],
        categories: vec![CategorySummary {
            category: "security".into(),
            high: 1,
            new: 1,
            ..Default::default()
        }],
        checks: vec![
            mk("web.smoke", CheckStatus::Failed, 1),
            mk("c2", CheckStatus::Passed, 0),
            mk("c3", CheckStatus::Partial("p".into()), 0),
            mk("c4", CheckStatus::Skipped("s".into()), 0),
            mk("c5", CheckStatus::NotApplicable("n".into()), 0),
            mk("c6", CheckStatus::Errored("e".into()), 0),
        ],
        findings: vec![f1, f2],
        fixed: 3,
        notes: vec!["<b>note</b>".into()],
        errors: vec![],
        qa: None,
    }
}

#[test]
fn pr_comment_summarises_and_escapes() {
    let c = pr_comment(&sample());
    assert!(c.starts_with(PR_COMMENT_MARKER));
    assert!(c.contains("ReadyHai: FAIL"));
    assert!(c.contains("readyhai `0.1.0`"));
    assert!(c.contains("| security | 0 | 1 | 0 | 0 |"));
    // Suppressed finding is not listed; the open one is, escaped.
    assert!(!c.contains("r.two"));
    assert!(c.contains("web.xss"));
    assert!(!c.contains("<script>"));
    assert!(c.contains("**1** open findings (1 new)"));
}

#[test]
fn html_escapes() {
    let h = html(&sample()).unwrap();
    assert!(h.contains("&lt;script&gt;alert(1)"));
    assert!(!h.contains("<script>"));
    assert!(!h.contains("<b>note</b>"));
    assert!(h.contains("Content-Security-Policy"));
    assert!(h.contains("FAIL"));
}

#[test]
fn errors_render_escaped() {
    let mut r = sample();
    r.errors = vec![ErrorCluster {
        signature: "<img src=x onerror=alert(2)> <*>".into(),
        example: "<script>alert(3)</script> failed".into(),
        count: 7,
        source: "web.console".into(),
        first_seen: "#1".into(),
    }];
    let h = html(&r).unwrap();
    assert!(h.contains("Top errors"));
    assert!(h.contains("&lt;script&gt;alert(3)"));
    assert!(h.contains("&lt;img src=x"));
    assert!(!h.contains("<script>alert(3)"));
    assert!(!html(&sample()).unwrap().contains("Top errors"));
    let j = serde_json::to_string(&r).unwrap();
    assert!(j.contains("\"errors\"") && j.contains("web.console"));
}

#[test]
fn sarif_counts() {
    let s = sarif(&sample());
    let r = s["runs"][0]["results"].as_array().unwrap();
    assert_eq!(r.len(), 2);
    assert!(
        r[0]["partialFingerprints"]["readyhai/v1"]
            .as_str()
            .unwrap()
            .len()
            > 4
    );
    assert_eq!(
        r[1]["locations"][0]["physicalLocation"]["region"]["startLine"],
        12
    );
    assert_eq!(r[1]["suppressions"][0]["kind"], "external");
}

#[test]
fn junit_includes_qa_defects_by_check_and_orphans() {
    let mk = |check: &str, rule: &str, sev: Severity, status: FindingStatus| {
        let mut f = Finding::new(
            check,
            rule,
            Category::Quality,
            sev,
            format!("{rule} title"),
            "GET /x",
        );
        f.status = status;
        f.finalize();
        f
    };
    let mut r = sample();
    r.checks = ["qa.api.authz", "qa.ui", "web.smoke"]
        .iter()
        .map(|id| CheckResult {
            id: (*id).into(),
            title: (*id).into(),
            tool: None,
            status: CheckStatus::Failed,
            findings: 1,
            duration_ms: 1,
        })
        .collect();
    r.findings = vec![
        mk(
            "qa.api.authz",
            "qa.api.bola",
            Severity::Critical,
            FindingStatus::New,
        ),
        // a LOW QA defect is still a failed test
        mk("qa.ui", "qa.ui.a11y", Severity::Low, FindingStatus::New),
        // baselined (existing) QA defect: not a failure
        mk(
            "qa.ui",
            "qa.ui.visual_change",
            Severity::Low,
            FindingStatus::Existing,
        ),
        // non-QA low finding: not a failure
        mk("web.smoke", "web.low", Severity::Low, FindingStatus::New),
        // QA defect whose check is its rule (matches no check): reported, not dropped
        mk(
            "qa.api.validation_missing",
            "qa.api.validation_missing",
            Severity::Medium,
            FindingStatus::New,
        ),
    ];
    let x = junit(&r);
    let suite = |name: &str| {
        let a = x
            .find(&format!("<testsuite name=\"{name}\""))
            .unwrap_or_else(|| panic!("no suite {name}: {x}"));
        let b = x[a..].find("</testsuite>").unwrap();
        x[a..a + b].to_string()
    };
    assert!(
        suite("qa.api.authz").contains("failures=\"1\"")
            && suite("qa.api.authz").contains("qa.api.bola")
    );
    let ui = suite("qa.ui");
    assert!(
        ui.contains("failures=\"1\"")
            && ui.contains("qa.ui.a11y")
            && !ui.contains("visual_change")
    );
    assert!(suite("web.smoke").contains("failures=\"0\""));
    let o = suite("unattributed");
    assert!(o.contains("qa.api.validation_missing") && o.contains("failures=\"1\""));
    assert_eq!(x.matches("<failure").count(), 3);
    assert_eq!(
        x.matches("<testsuite ").count(),
        x.matches("</testsuite>").count()
    );
}

#[test]
fn junit_wellformed() {
    let x = junit(&sample());
    assert_eq!(x.matches("<testsuite ").count(), 6);
    assert_eq!(x.matches("</testsuite>").count(), 6);
    assert_eq!(x.matches("<failure").count(), 1);
    assert_eq!(x.matches("<error ").count(), 1);
    assert_eq!(x.matches("<skipped").count(), 2);
    assert!(!x.contains("<script>"));
}

#[test]
fn sarif_artifact_uris_are_valid_for_qa_components_and_odd_paths() {
    let mk = |loc: &str| {
        let mut f = Finding::new(
            "qa.api.functional",
            "qa.api.bola",
            Category::Security,
            Severity::High,
            "BOLA on the order",
            loc,
        );
        f.finalize();
        f
    };
    let mut run = sample();
    run.findings = vec![
        mk("GET /orders/{id}"),
        mk("GET /a, GET /b, GET /c"),
        mk("docs/my report.md:7"),
        mk("src/a.rs:12"),
        mk("http://h/x y?q=<1>"),
        mk("login"),
    ];
    let s = sarif(&run);
    let r = s["runs"][0]["results"].as_array().unwrap();
    // an operation is a logical location + named in the message, never an artifact URI
    for i in [0, 1] {
        let loc = &r[i]["locations"][0];
        assert!(loc.get("physicalLocation").is_none(), "{loc}");
        assert_eq!(
            loc["logicalLocations"][0]["name"],
            run.findings[i].location.as_str()
        );
        assert!(
            r[i]["message"]["text"]
                .as_str()
                .unwrap()
                .contains(&run.findings[i].location)
        );
    }
    // every artifact URI that IS emitted is a legal URI reference
    let legal = |u: &str| {
        u.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&c))
            && !u.contains(' ')
    };
    for x in r {
        if let Some(u) =
            x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str()
        {
            assert!(legal(u), "invalid artifact uri {u:?}");
        }
    }
    let uri = |i: usize| {
        r[i]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(uri(2), "docs/my%20report.md");
    assert_eq!(
        r[2]["locations"][0]["physicalLocation"]["region"]["startLine"],
        7
    );
    assert_eq!(uri(3), "src/a.rs");
    assert_eq!(uri(4), "http://h/x%20y?q=%3C1%3E");
    assert_eq!(uri(5), "login");
    // a path that was already percent-encoded is not double-encoded
    assert_eq!(uri_escape("a%20b"), "a%20b");
    assert_eq!(uri_escape("100%"), "100%25");
    assert!(
        is_component("POST /x") && !is_component("src/GET /x") && !is_component("GETTING /x")
    );
}
