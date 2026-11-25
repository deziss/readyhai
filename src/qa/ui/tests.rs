use super::baseline::{accept_visual_baseline_in, visual_baseline_dir};
use super::builder::build;
use super::exec::SecretsGuard;
use super::image::{LOCAL_IMAGE, PUBLISHED_IMAGE, container_base, origin, pick_image};
use super::model::UiReport;
use crate::model::Severity;
use crate::qa::model::*;

#[test]
fn host_docker_internal_gets_gateway() {
    let (u, gw) = container_base("http://host.docker.internal:8099/x");
    assert!(gw);
    assert_eq!(u, "http://host.docker.internal:8099/x");
}

#[test]
fn image_resolution_order() {
    assert_eq!(pick_image(Some("x/y:1".into()), true), "x/y:1");
    assert_eq!(pick_image(Some(" ".into()), true), LOCAL_IMAGE);
    assert_eq!(pick_image(None, true), LOCAL_IMAGE);
    assert_eq!(pick_image(None, false), PUBLISHED_IMAGE);
}

#[test]
fn sample_report() {
    let text = include_str!("../../../tests/fixtures/qa-ui/sample-qa-ui.json");
    let rep: UiReport = serde_json::from_str(text).unwrap();
    let b = build(&rep, "nonprod", &|s| {
        s.replace("host.docker.internal:8099", "127.0.0.1:8099")
    });
    let rules: Vec<&str> = b.defects.iter().map(|d| d.rule.as_str()).collect();
    let count = |r: &str| rules.iter().filter(|x| **x == r).count();
    assert_eq!(count("qa.ui.validation_gap"), 1);
    assert_eq!(count("qa.ui.responsive_overflow"), 1);
    assert_eq!(count("qa.ui.a11y"), 3);
    assert_eq!(count("qa.ui.journey_failed"), 1);
    assert_eq!(count("qa.ui.visual_change"), 1);
    assert_eq!(count("qa.ui.slow_page"), 2); // LCP on /, CLS on /wide.html
    let a11y: Vec<_> = b
        .defects
        .iter()
        .filter(|d| d.rule == "qa.ui.a11y")
        .collect();
    assert!(
        a11y.iter()
            .any(|d| d.title.contains("image-alt") && d.severity == Severity::Medium)
    );
    assert!(
        a11y.iter()
            .any(|d| d.title.contains("region") && d.severity == Severity::Low)
    );
    let j = b
        .defects
        .iter()
        .find(|d| d.rule == "qa.ui.journey_failed")
        .unwrap();
    assert_eq!(j.severity, Severity::High);
    assert_eq!(j.evidence.len(), 2);
    assert!(j.evidence[0].path.starts_with("ui/traces/"));
    assert!(
        b.defects
            .iter()
            .all(|d| !d.to_finding("qa.ui").rule.is_empty())
    );
    assert!(b.cases.iter().any(|c| c.id == "ui./wide.html.responsive"));
    assert!(b.cases.iter().any(|c| c.technique == Technique::Boundary));
    let m = &b.coverage;
    let cell = |r: &str, c: &str| {
        let (ri, ci) = (
            m.rows.iter().position(|x| x == r).unwrap(),
            m.columns.iter().position(|x| x == c).unwrap(),
        );
        m.cells.iter().find(|x| x.0 == ri && x.1 == ci).unwrap().2
    };
    assert_eq!(cell("/wide.html", "responsive"), Cell::Fail);
    assert_eq!(cell("login", "user"), Cell::Fail);
    assert_eq!(cell("login", "admin"), Cell::Pass);
    assert_eq!(cell("/signup.html", "forms"), Cell::Fail);
    assert!(j.component == "login");
}

#[test]
fn a11y_and_visual_are_per_item() {
    let page = |u: &str, p: &str, axe: &str, shots: &str| {
        format!(r#"{{"url":"http://x{u}","path":"{p}","axe":[{axe}],"shots":[{shots}]}}"#)
    };
    let violation = |id: &str| {
        format!(r##"{{"id":"{id}","impact":"serious","help":"h","nodes":2,"target":"#t"}}"##)
    };
    let shot = |vp: u32, ratio: f64| {
        format!(r#"{{"viewport":{vp},"file":"shots/{vp}.png","diff_ratio":{ratio}}}"#)
    };
    let json = format!(
        r#"{{"pages":[{},{}]}}"#,
        page(
            "/a",
            "/a",
            &format!("{},{}", violation("image-alt"), violation("label")),
            &format!("{},{},{}", shot(375, 0.2), shot(768, 0.3), shot(1366, 0.0))
        ),
        page("/b", "/b", &violation("image-alt"), "")
    );
    let rep: UiReport = serde_json::from_str(&json).unwrap();
    let b = build(&rep, "nonprod", &|s| s.to_string());
    let a11y: Vec<&Defect> = b
        .defects
        .iter()
        .filter(|d| d.rule == "qa.ui.a11y")
        .collect();
    // same rule on two pages + a second rule on one page: three distinct fingerprints
    assert_eq!(a11y.len(), 3);
    let fps: std::collections::BTreeSet<&str> = a11y.iter().map(|d| d.fp_key.as_str()).collect();
    assert_eq!(fps.len(), 3);
    assert!(
        fps.contains("qa.ui.a11y|image-alt|/a")
            && fps.contains("qa.ui.a11y|image-alt|/b")
            && fps.contains("qa.ui.a11y|label|/a")
    );
    // two changed viewports of one page: two fingerprints
    let vis: Vec<&str> = b
        .defects
        .iter()
        .filter(|d| d.rule == "qa.ui.visual_change")
        .map(|d| d.fp_key.as_str())
        .collect();
    assert_eq!(
        vis,
        vec!["qa.ui.visual_change|/a|375", "qa.ui.visual_change|/a|768"]
    );
}

#[test]
fn first_visual_run_compares_nothing_so_is_not_a_pass() {
    let rep: UiReport = serde_json::from_str(r#"{"pages":[{"url":"http://x/","path":"/","shots":[{"viewport":375,"file":"shots/375.png"}]}]}"#).unwrap();
    let b = build(&rep, "nonprod", &|s| s.to_string());
    let r = b
        .results
        .iter()
        .find(|r| r.case_id == "ui./.visual")
        .unwrap();
    assert_eq!(r.status, ResultStatus::Skipped);
    let m = &b.coverage;
    let (ri, ci) = (
        m.rows.iter().position(|x| x == "/").unwrap(),
        m.columns.iter().position(|x| x == "visual").unwrap(),
    );
    assert_eq!(
        m.cells.iter().find(|x| x.0 == ri && x.1 == ci).unwrap().2,
        Cell::Untested
    );
}

#[test]
fn accept_visual_promotes_run_shots() {
    let d = std::env::temp_dir().join(format!("rh-vis-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let run = d.join("runs/r1");
    let shots = run.join("artifacts/ui/shots");
    std::fs::create_dir_all(&shots).unwrap();
    std::fs::write(shots.join("a.png"), b"png").unwrap();
    std::fs::write(shots.join("a.diff.png"), b"diff").unwrap();
    let old = visual_baseline_dir(&d, "k");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("stale.png"), b"old").unwrap();
    assert_eq!(accept_visual_baseline_in(&d, "k", &run).unwrap(), 1);
    assert!(
        old.join("a.png").is_file()
            && !old.join("a.diff.png").exists()
            && !old.join("stale.png").exists()
    );
    assert!(accept_visual_baseline_in(&d, "k", &d.join("runs/none")).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn secrets_guard_deletes() {
    let d = std::env::temp_dir().join(format!("rh-ui-secrets-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("user.json"), "{}").unwrap();
    {
        let _g = SecretsGuard(d.clone());
    }
    assert!(!d.exists());
}

#[test]
fn container_rewrite() {
    assert_eq!(
        container_base("http://127.0.0.1:8099/").0,
        "http://host.docker.internal:8099/"
    );
    assert_eq!(
        container_base("https://example.com").0,
        "https://example.com"
    );
    assert_eq!(origin("http://a:1/x?y"), "http://a:1");
}

#[test]
fn vitals_of_zero_on_an_error_or_blank_page_are_not_a_pass() {
    let page = |status: &str, lcp: f64, cls: f64, path: &str| {
        format!(
            r#"{{"url":"http://x{path}","path":"{path}"{status},"vitals":{{"lcp_ms":{lcp},"cls":{cls}}}}}"#
        )
    };
    let json = format!(
        r#"{{"pages":[{},{},{},{},{}]}}"#,
        page(r#","status":200"#, 0.0, 0.0, "/blank"), // nothing painted
        page(r#","status":500"#, 120.0, 0.0, "/err"), // an error page
        page(r#","status":0"#, 0.0, 0.0, "/down"),    // no response
        page(r#","status":200"#, 900.0, 0.02, "/good"), // a real, fast page
        page("", 900.0, 0.02, "/legacy")              // runner did not report a status
    );
    let rep: UiReport = serde_json::from_str(&json).unwrap();
    let b = build(&rep, "nonprod", &|s| s.to_string());
    let st = |p: &str| {
        b.results
            .iter()
            .find(|r| r.case_id == format!("ui.{p}.vitals"))
            .unwrap()
            .clone()
    };
    for p in ["/blank", "/err", "/down"] {
        let r = st(p);
        assert_eq!(r.status, ResultStatus::Blocked, "{p}: {r:?}");
        assert!(r.actual.contains("not measurable"), "{r:?}");
        assert!(r.defect_id.is_none());
    }
    assert!(st("/err").actual.contains("HTTP 500"));
    assert_eq!(st("/good").status, ResultStatus::Pass);
    assert_eq!(
        st("/legacy").status,
        ResultStatus::Pass,
        "no status reported: judged on the vitals"
    );
    let cell = |r: &str| {
        let m = &b.coverage;
        let (ri, ci) = (
            m.rows.iter().position(|x| x == r).unwrap(),
            m.columns.iter().position(|x| x == "vitals").unwrap(),
        );
        m.cells.iter().find(|x| x.0 == ri && x.1 == ci).unwrap().2
    };
    assert_eq!(cell("/blank"), Cell::Untested);
    assert_eq!(cell("/err"), Cell::Untested);
    assert_eq!(cell("/good"), Cell::Pass);
    assert!(b.defects.is_empty());
}

#[test]
fn test_journey_self_healing_locators() {
    let json = r##"{
        "pages": [],
        "forms": [],
        "journeys": [
            {
                "name": "checkout-resilient",
                "role": "alice",
                "status": "pass",
                "steps": 4,
                "healed_locators": [
                    {
                        "original": "#submit-btn-legacy",
                        "healed_by": "role button",
                        "healed_selector": "getByRole('button', { name: /submit/i })"
                    }
                ]
            }
        ],
        "notes": []
    }"##;
    let rep: UiReport = serde_json::from_str(json).expect("valid UiReport JSON");
    let b = build(&rep, "nonprod", &|s| s.to_string());
    let res = b
        .results
        .iter()
        .find(|r| r.case_id == "ui.journey.checkout-resilient.alice")
        .expect("journey result exists");
    assert_eq!(res.status, ResultStatus::Pass);
    assert!(res.actual.contains("1 locator(s) self-healed"));
    assert!(
        b.notes
            .iter()
            .any(|n| n.contains("self-healed 1 selector(s)") && n.contains("role button"))
    );
}

#[test]
fn test_state_graph_and_dead_ends() {
    let json = r##"{
        "pages": [],
        "forms": [],
        "journeys": [],
        "state_graph": {
            "states": [
                { "id": "s1", "route": "/", "title": "Home", "dom_fingerprint": "a1b2", "interactive_elements": 5, "dead_end": false },
                { "id": "s2", "route": "/broken-modal", "title": "Error Trap", "dom_fingerprint": "c3d4", "interactive_elements": 0, "dead_end": true }
            ],
            "transitions": [
                { "from": "s1", "to": "s2", "action": "navigate", "target": "/broken-modal" }
            ],
            "dead_ends": ["/broken-modal"]
        },
        "notes": []
    }"##;
    let rep: UiReport = serde_json::from_str(json).expect("valid UiReport JSON");
    let b = build(&rep, "nonprod", &|s| s.to_string());
    let res = b
        .results
        .iter()
        .find(|r| r.case_id == "ui.state_graph")
        .expect("ui.state_graph case exists");
    assert_eq!(res.status, ResultStatus::Fail);
    assert!(res.actual.contains("Trapped views"));
    assert!(res.actual.contains("/broken-modal"));

    let defect = b
        .defects
        .iter()
        .find(|d| d.rule == "qa.ui.dead_end")
        .expect("dead_end defect created");
    assert_eq!(defect.severity, Severity::Medium);
    assert_eq!(defect.priority, Priority::P2);
    assert!(defect.title.contains("1 view(s) trap user"));

    assert!(
        b.notes
            .iter()
            .any(|n| n.contains("mapped 2 distinct UI states with 1 transition edges"))
    );
}

#[test]
fn test_multi_persona_journey_reporting() {
    let json = r##"{
        "pages": [],
        "forms": [],
        "journeys": [
            {
                "name": "rbac-permission-revocation",
                "role": "admin+member",
                "status": "pass",
                "steps": 5,
                "healed_locators": []
            }
        ],
        "notes": []
    }"##;
    let rep: UiReport = serde_json::from_str(json).expect("valid UiReport JSON");
    let b = build(&rep, "nonprod", &|s| s.to_string());
    let res = b
        .results
        .iter()
        .find(|r| r.case_id == "ui.journey.rbac-permission-revocation.admin+member")
        .expect("multi-persona journey result exists");
    assert_eq!(res.status, ResultStatus::Pass);
    assert_eq!(res.actual, "all steps passed");
}
