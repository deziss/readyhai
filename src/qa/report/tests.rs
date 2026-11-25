use super::dispatch::{owner_user, write_formats};
use super::exporters::{gitlab_json, jira_csv, jira_description, testrail_csv, xray_csv};
use super::helpers::{b64, csv_field, jira_code, jira_priority, jira_text, md_fence, md_inline};
use super::html::qa_html;
use super::markdown::markdown;
use crate::model::{Category, FindingStatus, Profile, Run, Severity, Target, TargetKind, Verdict};
use crate::qa::model::{
    Area, CaseSource, Cell, CoverageMatrix, Defect, Evidence, EvidenceKind, ExitCriterion,
    Priority, QaReport, Recommendation, ResultCounts, Risk, Technique, TestCase,
};

#[test]
fn pdf_runs_as_dir_owner() {
    let d = std::env::temp_dir();
    let u = owner_user(&d);
    assert!(u.contains(':') && u.split(':').all(|p| p.parse::<u32>().is_ok()));
}

pub(crate) fn sample_qa(rec: Recommendation) -> QaReport {
    let d = Defect {
        id: "D-001".into(),
        rule: "qa.api.bola".into(),
        category: Category::Security,
        severity: Severity::High,
        priority: Priority::P1,
        area: Area::Api,
        title: "<script>alert(1)</script>, \"quoted\"\nline".into(),
        component: "GET /orders/{id}".into(),
        environment: "staging".into(),
        steps_to_reproduce: vec![
            "Login as user".into(),
            "curl -H \"Authorization: Bearer $RH_USER_TOKEN\" https://x/orders/2".into(),
        ],
        expected: "403".into(),
        actual: "200 with other user's order".into(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Screenshot,
            path: "shots/a.png".into(),
            note: String::new(),
        }],
        reproduced: (3, 3),
        cases: vec![],
        remediation: "Check ownership".into(),
        fp_key: "k".into(),
        fingerprint: String::new(),
        status: FindingStatus::New,
        regression: true,
        ai_note: Some("<b>ai</b>".into()),
    };
    let mut cov = CoverageMatrix::default();
    cov.set("GET /orders", "authz", Cell::Fail);
    cov.set("GET /orders", "positive", Cell::Pass);
    QaReport {
        recommendation: rec,
        conditions: vec!["Fix D-001".into()],
        executive_summary: "All good, mostly.".into(),
        ai_summary: Some("AI says <i>hi</i>".into()),
        mode: "deterministic".into(),
        environment: "staging".into(),
        scope: vec!["API".into()],
        out_of_scope: vec!["Load".into()],
        roles: vec!["user".into()],
        plan: vec![],
        counts: ResultCounts {
            planned: 5,
            executed: 4,
            passed: 3,
            failed: 1,
            ..Default::default()
        },
        cases: vec![TestCase {
            id: "c1".into(),
            area: Area::Api,
            technique: Technique::AuthMatrix,
            title: "Orders, authz".into(),
            priority: Priority::P1,
            component: "GET /orders/{id}".into(),
            role: Some("user".into()),
            steps: vec!["Login".into(), "GET order 2".into()],
            expected: "403".into(),
            source: CaseSource::Deterministic,
        }],
        results: vec![],
        defects: vec![d],
        coverage: cov,
        risks: vec![Risk {
            title: "r".into(),
            level: "high".into(),
            mitigation: "m".into(),
        }],
        exit_criteria: vec![ExitCriterion {
            name: "No P1".into(),
            met: false,
            blocking: true,
            detail: "1 open".into(),
        }],
        notes: vec!["perf p95=120ms".into()],
    }
}

pub(crate) fn sample_run(rec: Recommendation) -> Run {
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
        started: "2026-10-25T10:00:00Z".into(),
        finished: "f".into(),
        verdict: Verdict::Fail,
        reasons: vec![],
        categories: vec![],
        checks: vec![],
        findings: vec![],
        fixed: 0,
        notes: vec![],
        errors: vec![],
        qa: Some(sample_qa(rec)),
    }
}

#[test]
fn html_escaped_and_badges() {
    let h = qa_html(&sample_run(Recommendation::NoGo), None).unwrap();
    assert!(h.contains("&lt;script&gt;alert(1)"));
    assert!(!h.contains("<script>"));
    assert!(!h.contains("<b>ai</b>"));
    assert!(h.contains("Content-Security-Policy"));
    assert!(h.contains("NO-GO"));
    assert!(h.contains("AI-written summary"));
    assert!(
        qa_html(&sample_run(Recommendation::Go), None)
            .unwrap()
            .contains(">GO<")
    );
    assert!(
        qa_html(&sample_run(Recommendation::ConditionalGo), None)
            .unwrap()
            .contains("CONDITIONAL GO")
    );
}

#[test]
fn csv_quoting_and_jira() {
    assert_eq!(csv_field("a,b"), "\"a,b\"");
    assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    assert_eq!(csv_field("a\nb"), "\"a\nb\"");
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(jira_priority(Priority::P1), "Highest");
    assert_eq!(jira_priority(Priority::P2), "High");
    assert_eq!(jira_priority(Priority::P3), "Medium");
    assert_eq!(jira_priority(Priority::P4), "Low");
    let q = sample_qa(Recommendation::NoGo);
    let j = jira_csv(&q);
    assert!(j.starts_with("Summary,Issue Type,Priority,Labels,Component,Description\r\n"));
    assert!(
        j.contains("Highest")
            && j.contains("readyhai qa-api")
            && j.contains("{code}")
            && j.contains("h3. Steps")
    );
    assert!(j.contains("\"\"quoted\"\""));
}

#[test]
fn exports_have_no_secrets() {
    let q = sample_qa(Recommendation::NoGo);
    let all = format!(
        "{}{}{}{}{}",
        jira_csv(&q),
        gitlab_json(&q),
        testrail_csv(&q),
        xray_csv(&q),
        markdown(&sample_run(Recommendation::NoGo)).unwrap()
    );
    assert!(all.contains("$RH_USER_TOKEN"));
    let re = regex::Regex::new(r"Bearer\s+[A-Za-z0-9._-]{16,}").unwrap();
    assert!(!re.is_match(&all));
    assert!(xray_csv(&q).lines().count() >= 3);
    assert_eq!(gitlab_json(&q)[0]["labels"][0], "readyhai");
}

#[test]
fn markdown_sanity_and_write() {
    let m = markdown(&sample_run(Recommendation::ConditionalGo)).unwrap();
    assert!(
        m.contains("## Recommendation: CONDITIONAL GO")
            && m.contains("### D-001")
            && m.contains("```sh")
            && m.contains("## Exit criteria")
    );
    let dir = std::env::temp_dir().join(format!("rh-qa-{}", std::process::id()));
    let files = write_formats(
        &sample_run(Recommendation::Go),
        &dir,
        &[
            "qa".into(),
            "md".into(),
            "jira".into(),
            "gitlab".into(),
            "testrail".into(),
            "xray".into(),
        ],
    )
    .unwrap();
    assert_eq!(files.len(), 6);
    // non-QA run: skipped
    let mut r = sample_run(Recommendation::Go);
    r.qa = None;
    assert!(write_formats(&r, &dir, &["md".into()]).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

fn hostile_defect() -> Defect {
    let mut q = sample_qa(Recommendation::NoGo);
    let mut d = q.defects.remove(0);
    d.title = "=HYPERLINK(\"http://evil/\",\"x\") [click](javascript:alert(1)) <img src=x onerror=alert(1)> @admin".into();
    d.component = "+cmd|' /C calc'!A0 GET /a`b".into();
    d.expected = "- @SUM(1+1)\n# not a heading\n1. not a list".into();
    d.actual = "{code}\n{panel}h1. pwned{panel}".into();
    d.remediation = "*bold* _it_ ~~x~~ {noformat}".into();
    d.steps_to_reproduce = vec![
        "Open {code}http://x/{code} and [[link]]".into(),
        "curl -sS 'http://x/```\nrm -rf /```' # code fence breakout".into(),
    ];
    d
}

#[test]
fn markdown_helpers_escape_markup() {
    assert_eq!(md_inline("a_b_c"), "a_b_c", "intraword underscores stay");
    assert_eq!(md_inline("_x_ *y* `z`"), "\\_x\\_ \\*y\\* \\`z\\`");
    assert_eq!(md_inline("1. first"), "1\\. first");
    assert_eq!(md_inline("# h"), "\\# h");
    assert_eq!(md_inline("- item"), "\\- item");
    assert_eq!(md_inline("[a](b) <i>|"), "\\[a\\](b) \\<i\\>\\|");
    assert!(md_inline("@admin ping").starts_with("@\u{200B}admin"));
    assert_eq!(md_inline("a\nb\r\nc"), "a b  c");
    // a fence is always longer than the longest backtick run inside the body
    assert_eq!(md_fence("x```y", "sh"), "````sh\nx```y\n````\n");
    assert_eq!(md_fence("plain", ""), "```\nplain\n```\n");
    assert_eq!(
        md_fence("a``````b", "sh").lines().next().unwrap(),
        "```````sh"
    );
}

#[test]
fn markdown_report_cannot_be_hijacked_by_spec_text() {
    let mut r = sample_run(Recommendation::NoGo);
    r.qa.as_mut().unwrap().defects = vec![hostile_defect()];
    let m = markdown(&r).unwrap();
    // no live link / image / raw html / mention from the defect text
    assert_eq!(
        m.matches("<img").count(),
        m.matches("\\<img").count(),
        "every < is escaped: {m}"
    );
    assert!(m.contains("\\[click\\](javascript:alert(1))"));
    assert!(!m.contains("@admin"), "mentions are neutralised");
    // the heading, the table row and the headings-in-text stay inert
    assert!(m.contains("### D-001 \\=HYPERLINK") || m.contains("### D-001 =HYPERLINK"));
    assert!(
        !m.lines()
            .any(|l| l.trim_start().starts_with("# not a heading"))
    );
    assert!(m.contains("\\# not a heading") && m.contains("1\\. not a list"));
    // the code step with ``` is inside a LONGER fence
    assert!(
        m.contains("````sh\ncurl -sS 'http://x/```\nrm -rf /```' # code fence breakout\n````\n"),
        "{m}"
    );
    // fence balance: every line made only of backticks opens/closes with matching lengths
    let fences: Vec<&str> = m.lines().filter(|l| l.starts_with("```")).collect();
    assert_eq!(fences.len() % 2, 0, "{fences:?}");
}

#[test]
fn gitlab_description_is_escaped_too() {
    let mut q = sample_qa(Recommendation::NoGo);
    q.defects = vec![hostile_defect()];
    let g = gitlab_json(&q);
    let desc = g[0]["description"].as_str().unwrap();
    assert_eq!(desc.matches("<img").count(), desc.matches("\\<img").count());
    assert!(!desc.contains("@admin"));
    assert!(desc.contains("````sh\ncurl -sS 'http://x/```"));
    // the title is a plain field, untouched
    assert!(g[0]["title"].as_str().unwrap().starts_with("=HYPERLINK"));
}

#[test]
fn jira_text_cannot_open_macros_or_close_the_code_block() {
    assert_eq!(jira_text("{code}x{code}"), "\\{code\\}x\\{code\\}");
    assert_eq!(
        jira_text("*b* _i_ [l] |t|"),
        "\\*b\\* \\_i\\_ \\[l\\] \\|t\\|"
    );
    assert_eq!(
        jira_text("snake-case and a - b"),
        "snake-case and a - b",
        "mid-word dashes are not strike-through"
    );
    assert_eq!(jira_text("-struck-"), "\\-struck-");
    assert!(
        jira_text("h1. title").starts_with(' '),
        "headings must start a line"
    );
    assert!(jira_text("bq. quote").starts_with(' '));
    assert_eq!(jira_code("a{code}b{CODE:java}c"), "a{ code}b{ code:java}c");
    let d = hostile_defect();
    let desc = jira_description(&d);
    // exactly one {code} pair (the curl step); nothing from the spec can add another
    assert_eq!(desc.matches("{code}").count(), 2, "{desc}");
    assert!(!desc.contains("{panel}") && !desc.contains("{noformat}"));
    assert!(desc.contains("\\{panel\\}"));
}

#[test]
fn csv_formula_injection_is_neutralised_in_every_export() {
    for bad in ["=1+1", "+1", "-1+2", "@SUM(A1)", "\t=1", "\r=1"] {
        let f = csv_field(bad);
        assert!(
            f.trim_start_matches('"').starts_with('\''),
            "{bad:?} -> {f:?}"
        );
    }
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(csv_field("a=b"), "a=b", "only a LEADING sign is dangerous");
    assert_eq!(
        csv_field("=a,b"),
        "\"'=a,b\"",
        "quoting still applies after neutralising"
    );
    let mut q = sample_qa(Recommendation::NoGo);
    q.defects = vec![hostile_defect()];
    q.cases[0].title = "=cmd|' /C calc'!A0".into();
    q.cases[0].steps = vec!["+SUM(1)".into(), "@x".into()];
    q.cases[0].expected = "-2".into();
    // parse every cell back: none may start with a formula trigger
    let all = [jira_csv(&q), testrail_csv(&q), xray_csv(&q)];
    for csv in &all {
        for rec in split_csv(csv).iter().skip(1) {
            for cell in rec {
                assert!(
                    !cell.starts_with(['=', '+', '-', '@', '\t', '\r']),
                    "formula cell {cell:?} in {csv}"
                );
            }
        }
    }
    assert!(
        all[0].contains("\"'=HYPERLINK"),
        "the defect title cell is prefixed"
    );
}

/// Minimal RFC 4180 reader for the assertions above.
fn split_csv(s: &str) -> Vec<Vec<String>> {
    let (mut rows, mut row, mut cell, mut q) = (vec![], vec![], String::new(), false);
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match (c, q) {
            ('"', true) if it.peek() == Some(&'"') => {
                cell.push('"');
                it.next();
            }
            ('"', _) => q = !q,
            (',', false) => row.push(std::mem::take(&mut cell)),
            ('\r', false) => {}
            ('\n', false) => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (c, _) => cell.push(c),
        }
    }
    rows
}

#[test]
fn b64_ok() {
    assert_eq!(b64(b"Man"), "TWFu");
    assert_eq!(b64(b"Ma"), "TWE=");
    assert_eq!(b64(b"M"), "TQ==");
}
