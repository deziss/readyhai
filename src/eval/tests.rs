//! Unit tests for evaluation harness.

#![allow(unused_imports)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::*;
use super::types::*;
use super::parser::*;
use super::scoring::*;
use super::checks::*;
use super::fixture::*;
use super::runner::*;
use super::report::*;

    fn spec(extra: &str) -> SuiteSpec {
        parse_suite(
            &format!(
                r#"
name = "t"
kind = "qa"
[target]
server = "s.py"
roles = "r.toml"
[[expect]]
id = "a"
rule = "qa.api.bola"
[[expect]]
id = "b"
rule = "qa.api.server_error"
component = "POST /orders"
note = "the 500 on note"
[[expect]]
id = "c"
rule = "qa.api.slow_*"
[[expect]]
id = "d"
rule = "qa.api.optional"
optional = true
[[allow]]
rule = "qa.api.privilege_escalation"
{extra}
"#
            ),
            "test",
        )
        .unwrap()
    }

    fn obs(rule: &str, comp: &str) -> Observed {
        Observed {
            rules: vec![rule.into()],
            component: comp.into(),
            title: format!("{rule} on {comp}"),
        }
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match("qa.api.bola", "qa.api.bola"));
        assert!(!glob_match("qa.api.bola", "qa.api.bola2"));
        assert!(glob_match("qa.api.*", "qa.api.bola"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*c*e", "abcde"));
        assert!(!glob_match("a*c*e", "abcd"));
        assert!(glob_match("*.bola", "qa.api.bola"));
        assert!(!glob_match("*.bola", "qa.api.bolas"));
        assert!(glob_match("GET /orders/{id}", "GET /orders/{id}"));
        assert!(!glob_match("a*bc", "ab"));
        assert!(
            !glob_match("ab*ba", "aba"),
            "prefix and suffix may not overlap"
        );
    }

    #[test]
    fn recall_counts_required_only_and_component_must_match() {
        let s = spec("");
        let seen = [
            obs("qa.api.bola", "GET /orders/{id}"),
            obs("qa.api.server_error", "GET /search"), // wrong component for "b"
            obs("qa.api.slow_response", "GET /reports/slow"),
            obs("qa.api.optional", "x"),
        ];
        let r = score_run(&s, 1, "NoGo", &seen, 10, 1.0);
        assert_eq!(r.found, ["a", "c"]);
        assert_eq!(r.missed, ["b"]);
        assert_eq!(r.optional_found, ["d"]);
        assert!((r.recall - 0.667).abs() < 1e-9);
        // the mismatched server_error is unexpected: it matches neither an expect nor an allow
        assert_eq!(r.false_positives, ["qa.api.server_error @ GET /search"]);
    }

    #[test]
    fn allowed_extras_are_not_false_positives() {
        let s = spec("reason = \"role matrix view\"");
        let seen = [
            obs("qa.api.privilege_escalation", "GET /admin/stats"),
            obs("qa.api.surprise", "GET /x"),
        ];
        let r = score_run(&s, 1, "NoGo", &seen, 0, 0.0);
        assert_eq!(r.false_positives, ["qa.api.surprise @ GET /x"]);
        assert_eq!(
            r.allowed_seen,
            ["qa.api.privilege_escalation @ GET /admin/stats: role matrix view"]
        );
        assert_eq!(r.recall, 0.0);
    }

    #[test]
    fn observe_prefix_ignores_other_findings() {
        let mut s = spec("");
        s.observe_prefix = Some("qa.".into());
        let seen = [
            obs("readiness.dockerfile.no_user", "Dockerfile"),
            obs("qa.api.bola", "x"),
        ];
        let r = score_run(&s, 1, "Warn", &seen, 0, 0.0);
        assert!(r.false_positives.is_empty());
        assert_eq!(r.observed.len(), 1);
    }

    fn gap_spec() -> SuiteSpec {
        parse_suite(
            r#"
name = "g"
kind = "agent"
[target]
server = "s.py"
[[expect]]
id = "found"
rule = "authz"
[[expect]]
id = "gap"
rule = "slow"
known_gap = true
"#,
            "test",
        )
        .unwrap()
    }

    #[test]
    fn known_gaps_are_reported_but_never_counted_in_recall() {
        let s = gap_spec();
        let open = score_run(&s, 1, "NO_GO", &[obs("authz", "/admin")], 0, 0.0);
        assert_eq!(open.recall, 1.0, "the gap does not lower recall");
        assert_eq!(open.gap_missed, ["gap"]);
        assert!(open.missed.is_empty());
        let r = summarize_suite(&s, 1, vec![open], None);
        assert!(r.passed);
        assert_eq!(r.known_gaps_open, ["gap"]);
        assert!(r.known_gaps_closed.is_empty());

        // once the tool finds it the report says to promote it, in every run
        let closed = |n| {
            score_run(
                &s,
                n,
                "NO_GO",
                &[obs("authz", "/a"), obs("slow", "/b")],
                0,
                0.0,
            )
        };
        let r = summarize_suite(&s, 2, vec![closed(1), closed(2)], None);
        assert_eq!(r.known_gaps_closed, ["gap"]);
        assert!(r.known_gaps_open.is_empty());
        // a gap found in only one of two runs is still open
        let r = summarize_suite(
            &s,
            2,
            vec![
                closed(1),
                score_run(&s, 2, "NO_GO", &[obs("authz", "/a")], 0, 0.0),
            ],
            None,
        );
        assert_eq!(r.known_gaps_open, ["gap"]);
        assert!(r.known_gaps_closed.is_empty());
        // and the markdown names them
        let md = render_markdown(&EvalSummary {
            version: "0".into(),
            started: "now".into(),
            k: 2,
            passed: r.passed,
            suites: vec![r],
            report_json: PathBuf::new(),
            report_md: PathBuf::new(),
        });
        assert!(md.contains("known gaps still open (not counted in recall): gap"));
    }

    #[test]
    fn multi_rule_agent_defect_matches_any_of_its_rules() {
        let s = spec("");
        let o = Observed {
            rules: vec!["status_5xx".into(), "qa.api.bola".into()],
            component: "GET /orders/{id}".into(),
            title: "x".into(),
        };
        let r = score_run(&s, 1, "NO_GO", &[o], 0, 0.0);
        assert_eq!(r.found, ["a"]);
        assert!(r.false_positives.is_empty());
    }

    fn run(recall: f64, fp: usize, verdict: &str, requests: usize, seconds: f64) -> RunScore {
        RunScore {
            run: 1,
            verdict: verdict.into(),
            recall,
            found: vec![],
            missed: vec![],
            optional_found: vec![],
            optional_missed: vec![],
            gap_found: vec![],
            gap_missed: vec![],
            false_positives: (0..fp).map(|i| format!("fp{i}")).collect(),
            true_positives: 0,
            precision: 1.0,
            allowed_seen: vec![],
            observed: vec![],
            requests,
            seconds,
            cases: BTreeMap::new(),
            inconclusive_rate: None,
            confidence: None,
            blockers: vec![],
            checks: vec![],
        }
    }

    fn check<'a>(r: &'a SuiteResult, name: &str) -> &'a Check {
        r.checks.iter().find(|c| c.name == name).unwrap()
    }

    #[test]
    fn thresholds_pass_when_every_run_is_good() {
        let s = spec("");
        let r = summarize_suite(
            &s,
            2,
            vec![run(1.0, 1, "NoGo", 100, 5.0), run(0.9, 2, "NoGo", 120, 6.0)],
            None,
        );
        assert!(r.passed, "{:?}", r.checks);
        assert!(r.pass_k && r.verdict_stable);
        assert_eq!(r.false_positives, 2);
        assert_eq!(r.requests, 120);
        assert!((r.recall - 0.95).abs() < 1e-9);
    }

    #[test]
    fn pass_k_fails_when_one_run_is_below_threshold_even_if_the_mean_passes() {
        let s = spec("");
        let r = summarize_suite(
            &s,
            2,
            vec![run(1.0, 0, "NoGo", 1, 1.0), run(0.8, 0, "NoGo", 1, 1.0)],
            None,
        );
        assert!(check(&r, "recall").ok, "mean 0.9 is fine");
        assert!(!check(&r, "pass^k").ok);
        assert!(!r.passed);
    }

    #[test]
    fn false_positives_verdict_and_budgets_each_fail_the_suite() {
        let mut s = spec("");
        s.thresholds.max_requests = Some(100);
        s.thresholds.max_seconds = Some(10.0);
        s.expect_verdict = Some("NoGo".into());

        let fp = summarize_suite(&s, 1, vec![run(1.0, 3, "NoGo", 1, 1.0)], None);
        assert!(!check(&fp, "false positives").ok);

        let unstable = summarize_suite(
            &s,
            2,
            vec![run(1.0, 0, "NoGo", 1, 1.0), run(1.0, 0, "Go", 1, 1.0)],
            None,
        );
        assert!(!check(&unstable, "verdict stable").ok);
        assert!(!check(&unstable, "expected verdict").ok);

        let req = summarize_suite(&s, 1, vec![run(1.0, 0, "NoGo", 101, 1.0)], None);
        assert!(!check(&req, "request budget").ok);

        let slow = summarize_suite(&s, 1, vec![run(1.0, 0, "NoGo", 1, 10.5)], None);
        assert!(!check(&slow, "time budget").ok);

        let ok = summarize_suite(&s, 1, vec![run(1.0, 0, "nogo", 100, 10.0)], None);
        assert!(ok.passed, "{:?}", ok.checks);
    }

    #[test]
    fn an_errored_or_short_suite_never_passes() {
        let s = spec("");
        let r = summarize_suite(
            &s,
            2,
            vec![run(1.0, 0, "NoGo", 1, 1.0)],
            Some("run 2: boom".into()),
        );
        assert!(!r.passed);
        assert!(!r.pass_k);
        assert!(check(&r, "runs completed").detail.contains("boom"));
        let none = summarize_suite(&s, 2, vec![], Some("run 1: boom".into()));
        assert!(!none.passed);
        assert_eq!(none.recall, 0.0);
    }

    #[test]
    fn exit_code_follows_the_overall_result() {
        let s = spec("");
        let ok = summarize_suite(&s, 1, vec![run(1.0, 0, "NoGo", 1, 1.0)], None);
        let bad = summarize_suite(&s, 1, vec![run(0.1, 0, "NoGo", 1, 1.0)], None);
        let mk = |suites: Vec<SuiteResult>| EvalSummary {
            version: "t".into(),
            started: "now".into(),
            k: 1,
            passed: suites.iter().all(|s| s.passed),
            suites,
            report_json: PathBuf::new(),
            report_md: PathBuf::new(),
        };
        assert_eq!(mk(vec![ok.clone()]).exit_code(), 0);
        assert_eq!(mk(vec![ok, bad]).exit_code(), 1);
    }

    #[test]
    fn markdown_lists_suites_and_the_misses() {
        let s = spec("");
        let mut bad = run(0.5, 1, "NoGo", 9, 2.0);
        bad.missed = vec!["b".into()];
        let r = summarize_suite(&s, 1, vec![bad], None);
        let md = render_markdown(&EvalSummary {
            version: "0.0.0".into(),
            started: "now".into(),
            k: 1,
            passed: false,
            suites: vec![r],
            report_json: PathBuf::new(),
            report_md: PathBuf::new(),
        });
        assert!(md.contains("# ReadyHai eval: FAIL"));
        assert!(md.contains("| t | Qa |"));
        assert!(md.contains("run 1 missed: b (the 500 on note)"));
        assert!(md.contains("run 1 false positive: fp0"));
    }

    #[test]
    fn suite_validation_rejects_broken_files() {
        let bad = |t: &str| parse_suite(t, "x").is_err();
        assert!(bad("name = \"t\"\nkind = \"qa\"\n[target]\n")); // no server, no expect
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        )); // no path
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\npath=\"p\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        )); // duplicate id
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\nbogus = 1\n[target]\npath=\"p\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        )); // unknown key
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\npath=\"p\"\n[thresholds]\nmin_recall = 1.5\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        ));
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\npath=\"p\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\noptional=true\nknown_gap=true\n"
        )); // exclusive flags
        assert!(!bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\npath=\"p\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        ));
    }

    fn counts(v: &[(&str, usize)]) -> BTreeMap<String, usize> {
        v.iter().map(|(k, n)| (k.to_string(), *n)).collect()
    }

    #[test]
    fn precision_is_true_positives_over_reported_and_allowed_extras_are_out() {
        let s = spec("reason = \"role matrix view\"");
        // 2 expected, 1 unexpected, 1 allowed extra: precision 2 / 3
        let seen = [
            obs("qa.api.bola", "GET /orders/{id}"),
            obs("qa.api.slow_response", "GET /reports/slow"),
            obs("qa.api.surprise", "GET /x"),
            obs("qa.api.privilege_escalation", "GET /admin/stats"),
        ];
        let r = score_run(&s, 1, "NoGo", &seen, 0, 0.0);
        assert_eq!(r.true_positives, 2);
        assert_eq!(r.false_positives.len(), 1);
        assert!((r.precision - 0.667).abs() < 1e-9, "{}", r.precision);
        // all unexpected: precision 0; nothing reported: nothing was wrong, 1.0
        let none = score_run(&s, 1, "NoGo", &[obs("qa.api.surprise", "x")], 0, 0.0);
        assert_eq!(none.precision, 0.0);
        let empty = score_run(&s, 1, "Go", &[], 0, 0.0);
        assert_eq!(empty.precision, 1.0);
        // only allowed extras: no true and no false positive, so still 1.0
        let allowed = score_run(
            &s,
            1,
            "NoGo",
            &[obs("qa.api.privilege_escalation", "x")],
            0,
            0.0,
        );
        assert_eq!((allowed.true_positives, allowed.precision), (0, 1.0));
        // the suite reports the mean and the worst run
        let mut bad = run(1.0, 1, "NoGo", 1, 1.0);
        bad.precision = 0.5;
        let r = summarize_suite(&s, 2, vec![run(1.0, 0, "NoGo", 1, 1.0), bad], None);
        assert!((r.precision - 0.75).abs() < 1e-9);
        assert!((r.precision_min - 0.5).abs() < 1e-9);
    }

    #[test]
    fn inconclusive_rate_counts_executed_applicable_cases_only() {
        // 3 inconclusive of 3 + 2 + 1 + 3 = 9 executed; NOT_APPLICABLE, SKIPPED, BLOCKED are out
        let c = counts(&[
            ("PASS", 3),
            ("WARN", 2),
            ("FAIL", 1),
            ("INCONCLUSIVE", 3),
            ("NOT_APPLICABLE", 7),
            ("SKIPPED", 4),
            ("BLOCKED", 5),
        ]);
        assert!((inconclusive_rate(&c).unwrap() - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(inconclusive_rate(&counts(&[("PASS", 4)])), Some(0.0));
        assert_eq!(
            inconclusive_rate(&counts(&[("INCONCLUSIVE", 2)])),
            Some(1.0)
        );
        // nothing executed (all blocked / not applicable): no rate, not 0 and not 1
        assert_eq!(
            inconclusive_rate(&counts(&[("BLOCKED", 5), ("NOT_APPLICABLE", 2)])),
            None
        );
        assert_eq!(inconclusive_rate(&BTreeMap::new()), None);
        // statuses are normalised
        let st = RunStats::from_statuses(["pass", "PASS", " Inconclusive "], Some(66), vec![]);
        assert_eq!(st.cases, counts(&[("INCONCLUSIVE", 1), ("PASS", 2)]));
        let sc = run(1.0, 0, "GO", 1, 1.0).with_stats(st);
        assert_eq!(sc.inconclusive_rate, Some(0.333));
        assert_eq!(sc.confidence, Some(66));
    }

    fn agent_spec(extra: &str) -> SuiteSpec {
        parse_suite(
            &format!(
                r#"
name = "a"
kind = "agent"
{extra}
[target]
server = "s.py"
"#
            ),
            "test",
        )
        .unwrap()
    }

    fn with_rate(rate: Option<f64>, cases: &[(&str, usize)], verdict: &str) -> RunScore {
        let mut r = run(1.0, 0, verdict, 1, 1.0);
        r.inconclusive_rate = rate;
        r.cases = counts(cases);
        r
    }

    #[test]
    fn max_inconclusive_rate_gates_the_worst_run_and_is_off_by_default() {
        let mut s = agent_spec("forbid_verdict = [\"NO_GO\"]");
        // unset: no check at all, whatever the runs did
        let off = summarize_suite(
            &s,
            1,
            vec![with_rate(Some(0.9), &[("INCONCLUSIVE", 9)], "GO")],
            None,
        );
        assert!(off.checks.iter().all(|c| c.name != "inconclusive rate"));
        assert!(off.passed, "{:?}", off.checks);
        assert_eq!(off.inconclusive_rate, Some(0.9), "still reported");

        s.thresholds.max_inconclusive_rate = Some(0.25);
        let ok = summarize_suite(
            &s,
            2,
            vec![
                with_rate(Some(0.1), &[("PASS", 9), ("INCONCLUSIVE", 1)], "GO"),
                with_rate(Some(0.25), &[("PASS", 3), ("INCONCLUSIVE", 1)], "GO"),
            ],
            None,
        );
        assert!(check(&ok, "inconclusive rate").ok, "{:?}", ok.checks);
        assert_eq!(ok.inconclusive_rate, Some(0.25));
        // one bad run fails the suite even though the mean would pass
        let bad = summarize_suite(
            &s,
            2,
            vec![
                with_rate(Some(0.0), &[("PASS", 9)], "GO"),
                with_rate(Some(0.4), &[("PASS", 3), ("INCONCLUSIVE", 2)], "GO"),
            ],
            None,
        );
        let c = check(&bad, "inconclusive rate");
        assert!(!c.ok && c.detail.contains("40%") && c.detail.contains("25%"));
        // no executed case in a run: nothing to rate, so it cannot pass the gate
        let none = summarize_suite(
            &s,
            1,
            vec![with_rate(None, &[("BLOCKED", 4)], "NOT_EVALUATED")],
            None,
        );
        let c = check(&none, "inconclusive rate");
        assert!(
            !c.ok && c.detail.contains("no applicable case"),
            "{}",
            c.detail
        );
    }

    #[test]
    fn forbid_verdict_fails_any_run_that_ends_with_it() {
        let s = agent_spec("forbid_verdict = [\"NO_GO\", \"error\"]");
        let ok = summarize_suite(
            &s,
            2,
            vec![
                run(1.0, 0, "GO", 1, 1.0),
                run(1.0, 0, "NOT_EVALUATED", 1, 1.0),
            ],
            None,
        );
        assert!(check(&ok, "forbidden verdict").ok);
        // case-insensitive, and one run is enough
        let bad = summarize_suite(
            &s,
            2,
            vec![run(1.0, 0, "GO", 1, 1.0), run(1.0, 0, "no_go", 1, 1.0)],
            None,
        );
        let c = check(&bad, "forbidden verdict");
        assert!(!c.ok && c.detail.contains("NO_GO or error"), "{}", c.detail);
        assert!(!bad.passed);
        // no runs: it never passes
        let none = summarize_suite(&s, 1, vec![], Some("run 1: boom".into()));
        assert!(!check(&none, "forbidden verdict").ok);
    }

    #[test]
    fn expect_verdict_match_is_reported_and_exact() {
        let s = agent_spec("expect_verdict = \"NOT_EVALUATED\"");
        let ok = summarize_suite(&s, 1, vec![run(1.0, 0, "not_evaluated", 1, 1.0)], None);
        assert_eq!(ok.verdict_match, Some(true));
        let near = summarize_suite(&s, 1, vec![run(1.0, 0, "NOT_EVALUATED (x)", 1, 1.0)], None);
        assert_eq!(near.verdict_match, Some(false), "exact, not a prefix");
        assert!(!near.passed);
        let none = summarize_suite(&agent_spec("forbid_verdict = [\"X\"]"), 1, vec![], None);
        assert_eq!(
            none.verdict_match, None,
            "no expect_verdict: no match to report"
        );
    }

    #[test]
    fn expect_blocker_must_be_in_the_ledger_of_every_run() {
        let s = agent_spec("expect_blocker = \"auth_wall\"");
        let with = |b: &[&str]| {
            let mut r = run(1.0, 0, "NOT_EVALUATED", 1, 1.0);
            r.blockers = b.iter().map(|x| x.to_string()).collect();
            r
        };
        let ok = summarize_suite(
            &s,
            2,
            vec![with(&["auth_wall"]), with(&["no_surface", "auth_wall"])],
            None,
        );
        assert!(check(&ok, "expected blocker").ok, "{:?}", ok.checks);
        assert_eq!(ok.blockers, ["auth_wall", "no_surface"]);
        let bad = summarize_suite(
            &s,
            2,
            vec![with(&["auth_wall"]), with(&["no_surface"])],
            None,
        );
        let c = check(&bad, "expected blocker");
        assert!(
            !c.ok && c.detail.contains("missing in run 1"),
            "{}",
            c.detail
        );
        // no blockers at all
        let none = summarize_suite(&s, 1, vec![with(&[])], None);
        assert!(!check(&none, "expected blocker").ok);
    }

    #[test]
    fn agent_stats_reads_statuses_confidence_and_blocker_reasons_from_the_report() {
        use crate::agent::fixtures::{report, result};
        use crate::agent::{BlockReason, Blocker, EvidenceLedger};
        let mut rep = report("r");
        rep.executed_results = vec![
            result("TC-1", "authz", "PASS"),
            result("TC-2", "injection", "INCONCLUSIVE"),
            result("TC-3", "injection", "NOT_APPLICABLE"),
            result("TC-4", "state_transition", "BLOCKED"),
        ];
        let blocker = |reason| Blocker {
            reason,
            detail: String::new(),
            next_step: String::new(),
            case_ids: vec![],
        };
        rep.evidence_ledger = Some(EvidenceLedger {
            confidence: Some(40),
            blockers: vec![
                blocker(BlockReason::AuthWall),
                blocker(BlockReason::NoSurface),
                blocker(BlockReason::OutOfScope),
            ],
            ..Default::default()
        });
        let st = agent_stats(&rep);
        assert_eq!(
            st.cases,
            counts(&[
                ("PASS", 1),
                ("INCONCLUSIVE", 1),
                ("NOT_APPLICABLE", 1),
                ("BLOCKED", 1)
            ])
        );
        assert_eq!(st.confidence, Some(40));
        assert_eq!(st.blockers, ["auth_wall", "no_surface", "out_of_scope"]);
        // an old report without a ledger: statuses only
        rep.evidence_ledger = None;
        let st = agent_stats(&rep);
        assert_eq!((st.confidence, st.blockers.is_empty()), (None, true));
    }

    #[test]
    fn suites_without_seeded_defects_need_a_verdict_or_blocker_expectation() {
        let bad = |t: &str| parse_suite(t, "x").is_err();
        let head = "name = \"t\"\nkind = \"agent\"\n";
        let tail = "\n[target]\nserver = \"s.py\"\n";
        assert!(bad(&format!("{head}{tail}")), "nothing to check");
        assert!(!bad(&format!("{head}forbid_verdict = [\"NO_GO\"]{tail}")));
        assert!(!bad(&format!(
            "{head}expect_verdict = \"NOT_EVALUATED\"{tail}"
        )));
        assert!(!bad(&format!("{head}expect_blocker = \"auth_wall\"{tail}")));
        // expect_blocker must name a real reason and belongs to the agent kind
        assert!(bad(&format!("{head}expect_blocker = \"login\"{tail}")));
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\nexpect_blocker = \"auth_wall\"\n[target]\npath = \"p\"\n"
        ));
        // a verdict cannot be both expected and forbidden
        assert!(bad(&format!(
            "{head}expect_verdict = \"GO\"\nforbid_verdict = [\"go\"]{tail}"
        )));
        // max_inconclusive_rate: agent kind, 0..=1
        assert!(!bad(&format!(
            "{head}forbid_verdict = [\"X\"]{tail}[thresholds]\nmax_inconclusive_rate = 0.25\n"
        )));
        assert!(bad(&format!(
            "{head}forbid_verdict = [\"X\"]{tail}[thresholds]\nmax_inconclusive_rate = 1.5\n"
        )));
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\nforbid_verdict = [\"X\"]\n[target]\npath = \"p\"\n[thresholds]\nmax_inconclusive_rate = 0.2\n"
        ));
        // server_args need a server
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\nforbid_verdict = [\"X\"]\n[target]\npath = \"p\"\nserver_args = [\"--clean\"]\n"
        ));
    }

    #[test]
    fn markdown_shows_the_new_metrics_and_the_blockers() {
        let mut s = agent_spec("expect_blocker = \"auth_wall\"");
        s.thresholds.max_inconclusive_rate = Some(0.5);
        let mut r = run(1.0, 0, "NOT_EVALUATED", 5, 1.0);
        r.precision = 1.0;
        r.blockers = vec!["auth_wall".into()];
        let r = r.with_stats(RunStats::from_statuses(
            ["PASS", "INCONCLUSIVE", "BLOCKED"],
            Some(50),
            vec!["auth_wall".into()],
        ));
        let res = summarize_suite(&s, 1, vec![r], None);
        assert_eq!(res.confidence, Some(50));
        let md = render_markdown(&EvalSummary {
            version: "0".into(),
            started: "now".into(),
            k: 1,
            passed: res.passed,
            suites: vec![res],
            report_json: PathBuf::new(),
            report_md: PathBuf::new(),
        });
        assert!(
            md.contains("| precision | FP | inconclusive | confidence |"),
            "{md}"
        );
        assert!(md.contains("| 1.00 | 0 | 50% | 50% |"), "{md}");
        assert!(md.contains("- blockers reported: auth_wall"), "{md}");
        assert!(
            md.contains("- run 1 cases: BLOCKED 1, INCONCLUSIVE 1, PASS 1"),
            "{md}"
        );
        assert!(md.contains("PASS expected blocker"), "{md}");
        assert!(
            md.contains("PASS inconclusive rate: worst run 50% vs <= 50%"),
            "{md}"
        );
    }

    #[test]
    fn the_spa_suites_are_wired_to_the_fixture() {
        let load = |name: &str| {
            let text =
                std::fs::read_to_string(crate_root().join(format!("tests/eval/{name}.toml")))
                    .unwrap();
            parse_suite(&text, name).unwrap()
        };
        let spa = load("agent-spa");
        assert!(
            spa.target.spec.is_none(),
            "the agent has to find the API itself"
        );
        assert_eq!(spa.expect_verdict.as_deref(), Some("NO_GO"));
        assert_eq!(spa.thresholds.max_inconclusive_rate, Some(0.25));
        assert!(spa.thresholds.min_recall >= 0.85);
        assert_eq!(spa.expect.len(), 3, "one expectation per seeded bug");
        assert!(spa.target.server_args.is_empty());
        let clean = load("agent-spa-clean");
        assert_eq!(clean.target.server_args, ["--clean"]);
        assert_eq!(clean.forbid_verdict, ["NO_GO"]);
        assert!(clean.expect.is_empty() && clean.thresholds.max_false_positives <= 1);
        assert_eq!(clean.thresholds.max_inconclusive_rate, Some(0.25));
        assert_eq!(
            clean.target.tokens, spa.target.tokens,
            "same accounts, no bugs"
        );
        let noauth = load("agent-spa-noauth");
        assert!(
            noauth.target.tokens.is_empty(),
            "no credentials is the point"
        );
        assert_eq!(noauth.expect_verdict.as_deref(), Some("NOT_EVALUATED"));
        assert_eq!(noauth.expect_blocker.as_deref(), Some("auth_wall"));
        for s in [&spa, &clean, &noauth] {
            assert_eq!(
                s.target.server.as_deref(),
                Some("tests/fixtures/spa-next/server.py")
            );
        }
    }

    fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn shipped_suites_parse_and_point_at_real_files() {
        let opts = EvalOpts::default();
        let suites = load_suites(&crate_root(), &opts).unwrap();
        let names: Vec<&str> = suites.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "agent-api",
                "agent-diff",
                "agent-memory",
                "agent-spa-clean",
                "agent-spa-noauth",
                "agent-spa",
                "qa-api",
                "qa-repo",
                "security-deep",
                "whitebox-exploit"
            ]
        );
        for s in &suites {
            for p in [
                &s.target.server,
                &s.target.spec,
                &s.target.roles,
                &s.target.path,
            ]
            .into_iter()
            .flatten()
            .chain(s.target.repo.iter().flat_map(|r| &r.commits))
            {
                assert!(rel(&crate_root(), p).exists(), "{}: {p} is missing", s.name);
            }
            assert!(
                s.thresholds.min_recall >= 0.85,
                "{}: threshold must not be loosened silently",
                s.name
            );
        }
        let qa = suites.iter().find(|s| s.name == "qa-api").unwrap();
        assert_eq!(
            qa.expect
                .iter()
                .filter(|e| !e.optional && !e.known_gap)
                .count(),
            7,
            "one required expectation per seeded bug"
        );
        let agent = suites.iter().find(|s| s.name == "agent-api").unwrap();
        assert_eq!(
            agent.expect.len(),
            7,
            "the agent suite lists every seeded bug (known gaps flagged)"
        );
    }

    #[test]
    fn suite_selection_by_name() {
        let root = crate_root();
        let one = load_suites(
            &root,
            &EvalOpts {
                suites: vec!["qa-repo".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(one.len(), 1);
        let two = load_suites(
            &root,
            &EvalOpts {
                suites: vec!["qa-repo,qa-api".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(two.len(), 2);
        let err = load_suites(
            &root,
            &EvalOpts {
                suites: vec!["nope".into()],
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown suite 'nope'"));
    }

    #[test]
    fn env_guard_restores_previous_values() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let k = "READYHAI_EVAL_TEST_ONLY_VAR";
        let n = "READYHAI_EVAL_TEST_ONLY_UNSET";
        // SAFETY: names are private to this test and ENV_LOCK is held.
        unsafe { std::env::set_var(k, "before") };
        {
            let mut g = EnvGuard::new();
            g.set(k, "during");
            g.set(n, "during");
            assert_eq!(std::env::var(k).unwrap(), "during");
            g.unset(k);
            assert!(std::env::var(k).is_err());
        }
        assert_eq!(std::env::var(k).unwrap(), "before");
        assert!(std::env::var(n).is_err());
        unsafe { std::env::remove_var(k) };
        assert_eq!(role_env("ali ce"), "RH_ALI_CE_TOKEN");
    }

    #[test]
    fn fixture_starts_serves_and_counts_requests() {
        let script = crate_root().join("tests/fixtures/qa-api/server.py");
        let dir = std::env::temp_dir().join(format!("rh-eval-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fx = match Fixture::start(&script, &dir.join("req.log"), &[]) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skipping: no usable python3 ({e:#})");
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
        };
        assert_eq!(fx.requests(), 0, "the readiness probe is not counted");
        let c = reqwest::blocking::Client::new();
        for _ in 0..3 {
            let r = c.get(format!("{}/health", fx.url())).send().unwrap();
            assert!(r.status().is_success());
        }
        assert_eq!(fx.requests(), 3);
        let port = fx.port;
        drop(fx);
        assert!(
            TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                Duration::from_millis(300)
            )
            .is_err(),
            "the server is killed on drop"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_spa_fixture_has_a_login_wall_a_catch_all_and_three_switchable_bugs() {
        use reqwest::blocking::Client;
        let script = crate_root().join("tests/fixtures/spa-next/server.py");
        let dir = std::env::temp_dir().join(format!("rh-eval-spa-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for clean in [false, true] {
            let args: Vec<String> = clean.then(|| "--clean".to_string()).into_iter().collect();
            let fx = match Fixture::start(&script, &dir.join(format!("req-{clean}.log")), &args) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("skipping: no usable python3 ({e:#})");
                    break;
                }
            };
            let u = |p: &str| format!("{}{p}", fx.url());
            let alice = |p: &str| c.get(u(p)).bearer_auth("alice-token");
            // the login wall: 307 to /login, a password field there, and a session gets through
            let r = c.get(u("/")).send().unwrap();
            assert_eq!(r.status().as_u16(), 307);
            assert!(
                r.headers()["location"]
                    .to_str()
                    .unwrap()
                    .starts_with("/login")
            );
            let login = c.get(u("/login")).send().unwrap().text().unwrap();
            assert!(login.contains("type=\"password\"") && login.contains("/_next/static/"));
            assert_eq!(alice("/").send().unwrap().status().as_u16(), 200);
            // the catch-all: unknown paths are one and the same 200 shell
            let a = c.get(u("/rh0123456789ab")).send().unwrap();
            assert_eq!(a.status().as_u16(), 200);
            let (a, b) = (
                a.text().unwrap(),
                c.get(u("/pricing")).send().unwrap().text().unwrap(),
            );
            assert_eq!(a, b);
            assert!(a.contains("_buildManifest.js") && a.contains("page-abc123.js"));
            // what a spec-less agent can learn from
            let manifest = c
                .get(u("/_next/static/rhBuild01/_buildManifest.js"))
                .send()
                .unwrap()
                .text()
                .unwrap();
            assert!(manifest.contains("\"/orders/[id]\"") && manifest.contains("__rewrites"));
            let chunk = c
                .get(u("/_next/static/chunks/app/(main)/settings/page-abc123.js"))
                .send()
                .unwrap()
                .text()
                .unwrap();
            assert!(chunk.contains("\"/api/profile\"") && chunk.contains("api.example.invalid"));
            assert!(
                c.get(u("/sitemap.xml"))
                    .send()
                    .unwrap()
                    .text()
                    .unwrap()
                    .contains("/pricing")
            );
            assert_eq!(
                c.get(u("/_next/static/nope.js"))
                    .send()
                    .unwrap()
                    .status()
                    .as_u16(),
                404
            );
            // the API needs a Bearer token
            assert_eq!(
                c.get(u("/api/orders")).send().unwrap().status().as_u16(),
                401
            );
            assert_eq!(alice("/api/orders").send().unwrap().status().as_u16(), 200);
            // bug 1: bob's order 3 for alice
            let idor = alice("/api/orders/3").send().unwrap().status().as_u16();
            // bug 2: a quote in q leaks a SQL error and a stack trace
            let leak = alice("/api/orders?q=%27").send().unwrap();
            let (leak_status, leak_body) = (leak.status().as_u16(), leak.text().unwrap());
            // bug 3: bad paging
            let paging = alice("/api/orders?limit=-1")
                .send()
                .unwrap()
                .status()
                .as_u16();
            if clean {
                assert_eq!((idor, leak_status, paging), (404, 200, 400));
            } else {
                assert_eq!((idor, leak_status, paging), (200, 500, 500));
                assert!(leak_body.contains("SQLITE_ERROR") && leak_body.contains(".js:"));
            }
            // an order of your own is readable in both
            assert_eq!(
                alice("/api/orders/1").send().unwrap().status().as_u16(),
                200
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn change_spec(extra: &str) -> SuiteSpec {
        parse_suite(
            &format!(
                r#"
name = "d"
kind = "agent"
[target]
server = "s.py"
spec = "o.json"
[target.repo]
commits = ["a", "b"]
[change]
operations = ["GET /search"]
{extra}
[[expect]]
id = "a"
rule = "server_error"
"#
            ),
            "t",
        )
        .unwrap()
    }

    #[test]
    fn the_agent_diff_suite_file_is_a_valid_change_suite_over_real_fixture_directories() {
        let root = crate_root();
        let text = std::fs::read_to_string(root.join("tests/eval/agent-diff.toml")).unwrap();
        let s = parse_suite(&text, "agent-diff").unwrap();
        let c = s.change.as_ref().expect("a [change] table");
        assert_eq!(c.operations, ["GET /search"]);
        assert!(c.planned_first && (c.min_sent - 1.0).abs() < 1e-9);
        let commits = &s.target.repo.as_ref().unwrap().commits;
        assert_eq!(commits.len(), 2);
        assert!(commits.iter().all(|d| root.join(d).is_dir()), "{commits:?}");
    }

    #[test]
    fn memory_blocks_are_validated_and_the_shipped_suite_has_one() {
        let suite = |kind: &str, extra: &str, memory: &str| {
            let t = format!(
                "name = \"m\"\nkind = \"{kind}\"\n[target]\nserver = \"s.py\"\nroles = \"r\"\n{extra}\n{memory}\n[[expect]]\nid = \"a\"\nrule = \"x\"\n"
            );
            parse_suite(&t, "t")
                .map(|s| s.memory.map(|m| m.runs))
                .map_err(|e| format!("{e:#}"))
        };
        assert_eq!(
            suite("agent", "", "[memory]"),
            Ok(Some(2)),
            "two runs by default"
        );
        assert_eq!(suite("agent", "", "[memory]\nruns = 3"), Ok(Some(3)));
        assert_eq!(suite("agent", "", ""), Ok(None));
        assert!(
            suite("qa", "", "[memory]")
                .unwrap_err()
                .contains("kind agent")
        );
        for runs in ["runs = 1", "runs = 6"] {
            assert!(
                suite("agent", "", &format!("[memory]\n{runs}"))
                    .unwrap_err()
                    .contains("2..=5"),
                "{runs}"
            );
        }
        assert!(
            suite(
                "agent",
                "[target.repo]\ncommits = [\"a\", \"b\"]",
                "[memory]"
            )
            .unwrap_err()
            .contains("cannot be combined")
        );
        assert!(suite("agent", "", "[memory]\nbogus = 1").is_err());
        let text =
            std::fs::read_to_string(crate_root().join("tests/eval/agent-memory.toml")).unwrap();
        let s = parse_suite(&text, "agent-memory").unwrap();
        assert_eq!(s.memory.as_ref().map(|m| m.runs), Some(2));
        assert_eq!(s.expect.len(), 7, "the same seven seeded bugs as agent-api");
    }

    /// A two-run series: run 1 found one authz defect, run 2 found it again.
    fn memory_series(
        still_open: bool,
        probe_first: bool,
        drop_case: bool,
    ) -> (SuiteSpec, Vec<crate::agent::AgentRunReport>) {
        use crate::agent::fixtures::{planned, report, result};
        use crate::agent::memory::{DefectLine, SinceLastRun};
        use crate::agent::{OracleCheck, OracleOutcome, Severity, TriagedDefect, Verdict};
        let fp = crate::agent::memory::fingerprint("authz", "/admin");
        let defect = || TriagedDefect {
            id: "DEF-001".into(),
            severity: "critical".into(),
            component: "/admin".into(),
            rule: "authz".into(),
            fingerprint: fp.clone(),
            case_ids: vec!["TC-001".into()],
            ..Default::default()
        };
        let line = DefectLine {
            fingerprint: fp.clone(),
            rule: "authz".into(),
            endpoint: "/admin".into(),
            ..Default::default()
        };
        let mk = |id: &str, since: SinceLastRun, order: &[(&str, bool)]| {
            let mut r = report(id);
            r.triaged_defects = vec![defect()];
            let mut res = result("TC-001", "authz", "FAIL");
            res.oracle = Some(OracleOutcome {
                verdict: Verdict::Fail,
                checks: vec![OracleCheck {
                    code: "authz".into(),
                    verdict: Verdict::Fail,
                    severity: Some(Severity::Critical),
                    detail: "d".into(),
                }],
                warnings: vec![],
                exploratory: false,
            });
            r.executed_results = vec![res];
            r.planned_cases = order
                .iter()
                .map(|(comp, probe)| {
                    let mut c = planned(&format!("TC-{:03}", comp.len()), "authz", "GET", comp);
                    if *probe {
                        c.regression_of = vec![fp.clone()];
                    }
                    c
                })
                .collect();
            r.since_last_run = Some(since);
            r
        };
        let first = mk(
            "run-1",
            SinceLastRun {
                first_run: true,
                committed: true,
                new: vec![line.clone()],
                ..Default::default()
            },
            &[("/", false), ("/admin", false), ("/about", false)],
        );
        let mut order = if probe_first {
            vec![("/admin", true), ("/", false), ("/about", false)]
        } else {
            vec![("/", false), ("/admin", true), ("/about", false)]
        };
        if drop_case {
            order.pop();
        }
        let last = mk(
            "run-2",
            SinceLastRun {
                committed: true,
                still_open: if still_open {
                    vec![line.clone()]
                } else {
                    vec![]
                },
                new: if still_open { vec![] } else { vec![line] },
                ..Default::default()
            },
            &order,
        );
        let spec = parse_suite(
            "name = \"m\"\nkind = \"agent\"\n[target]\nserver = \"s.py\"\n[memory]\n[[expect]]\nid = \"a\"\nrule = \"authz\"\ncomponent = \"/admin\"\n",
            "t",
        )
        .unwrap();
        (spec, vec![first, last])
    }

    #[test]
    fn memory_checks_name_what_a_series_got_wrong() {
        let names = |cs: &[Check]| {
            cs.iter()
                .filter(|c| !c.ok)
                .map(|c| c.name.clone())
                .collect::<Vec<_>>()
        };
        let (spec, reps) = memory_series(true, true, false);
        let cs = memory_checks(&spec, &reps);
        assert_eq!(cs.len(), 4);
        assert!(names(&cs).is_empty(), "{cs:?}");
        // the defect is reported new again instead of still open
        let (spec, reps) = memory_series(false, true, false);
        assert_eq!(
            names(&memory_checks(&spec, &reps)),
            ["memory: seeded defects still open"]
        );
        // the probe is not first
        let (spec, reps) = memory_series(true, false, false);
        assert_eq!(
            names(&memory_checks(&spec, &reps)),
            ["memory: regression probes lead the plan"]
        );
        // memory dropped a case
        let (spec, reps) = memory_series(true, true, true);
        assert_eq!(
            names(&memory_checks(&spec, &reps)),
            ["memory: no case dropped"]
        );
        // a run with no memory section at all
        let (spec, mut reps) = memory_series(true, true, false);
        reps[0].since_last_run = None;
        reps[1].since_last_run = None;
        assert!(
            names(&memory_checks(&spec, &reps))
                .contains(&"memory: first run remembered".to_string())
        );
    }

    #[test]
    fn change_blocks_are_validated() {
        let suite = |kind: &str, repo: &str, change: &str| {
            let t = format!(
                "name = \"d\"\nkind = \"{kind}\"\n[target]\nserver = \"s.py\"\nroles = \"r\"\n{repo}\n{change}\n[[expect]]\nid = \"a\"\nrule = \"x\"\n"
            );
            parse_suite(&t, "t")
                .map(|_| ())
                .map_err(|e| format!("{e:#}"))
        };
        let two = "[target.repo]\ncommits = [\"a\", \"b\"]";
        let one = "[target.repo]\ncommits = [\"a\"]";
        let ch = "[change]\noperations = [\"GET /x\"]";
        assert!(suite("agent", two, ch).is_ok());
        assert!(suite("agent", one, ch).unwrap_err().contains("two commits"));
        assert!(suite("agent", "", ch).unwrap_err().contains("two commits"));
        assert!(suite("qa", two, ch).unwrap_err().contains("kind agent"));
        assert!(
            suite("agent", two, "[change]\noperations = []")
                .unwrap_err()
                .contains("at least one operation")
        );
        for bad in ["min_sent = 2.0", "bogus = 1"] {
            assert!(
                suite("agent", two, &format!("{ch}\n{bad}")).is_err(),
                "{bad}"
            );
        }
    }

    fn change_report(
        ops: &[&str],
        cases: &[(&str, &[&str])],
        sent: usize,
    ) -> crate::agent::AgentRunReport {
        use crate::agent::fixtures::{planned, report};
        let mut rep = report("run-x");
        rep.planned_cases = cases
            .iter()
            .enumerate()
            .map(|(i, (comp, tagged))| {
                let mut c = planned(&format!("TC-{:03}", i + 1), "boundary", "GET", comp);
                c.changed_ops = tagged.iter().map(|s| s.to_string()).collect();
                c
            })
            .collect();
        let mut ci = crate::agent::ChangeImpact {
            status: "applied".into(),
            changed_files_total: 2,
            ..Default::default()
        };
        ci.operations = ops
            .iter()
            .map(|o| crate::agent::ChangedOperation {
                operation: o.to_string(),
                via: "route".into(),
                files: vec![],
                detail: String::new(),
            })
            .collect();
        ci.coverage = ops
            .iter()
            .map(|o| crate::agent::ChangedOpCoverage {
                operation: o.to_string(),
                planned: rep
                    .planned_cases
                    .iter()
                    .filter(|c| c.changed_ops.iter().any(|x| x == o))
                    .count(),
                executed: sent,
                ..Default::default()
            })
            .collect();
        rep.change_impact = Some(ci);
        rep
    }

    #[test]
    fn change_checks_require_the_right_operations_planned_first_and_sent() {
        let c = change_spec("").change.unwrap();
        let ok = |v: &[Check]| v.iter().all(|c| c.ok);
        let good = change_report(
            &["GET /search"],
            &[
                ("/search", &["GET /search"]),
                ("/search", &["GET /search"]),
                ("/", &[]),
                ("/.env", &[]),
            ],
            2,
        );
        let v = change_checks(&c, &good);
        assert_eq!(v.len(), 3);
        assert!(ok(&v), "{v:?}");
        // another operation was reported
        let other = change_report(&["GET /orders"], &[("/orders", &["GET /orders"])], 1);
        assert!(!change_checks(&c, &other)[0].ok);
        // an unchanged case ahead of a changed one (the root probe is allowed to lead)
        let late = change_report(
            &["GET /search"],
            &[
                ("/", &[]),
                ("/search", &["GET /search"]),
                ("/admin", &[]),
                ("/search", &["GET /search"]),
            ],
            2,
        );
        let v = change_checks(&c, &late);
        assert!(v[0].ok && !v[1].ok, "{v:?}");
        // planned but not sent (dropped by a cut)
        let cut = change_report(
            &["GET /search"],
            &[("/search", &["GET /search"]), ("/search", &["GET /search"])],
            1,
        );
        let v = change_checks(&c, &cut);
        assert!(!v[2].ok, "{v:?}");
        // a run without change impact says so instead of passing
        let mut none = good.clone();
        none.change_impact = None;
        assert!(!ok(&change_checks(&c, &none)));
        // the suite holds only when every run held
        let mut s = change_spec("");
        s.thresholds.max_false_positives = 0;
        let mut r1 = run(1.0, 0, "NO_GO", 1, 1.0);
        let mut r2 = run(1.0, 0, "NO_GO", 1, 1.0);
        r1.checks = change_checks(&c, &good);
        r2.checks = change_checks(&c, &cut);
        let res = summarize_suite(&s, 2, vec![r1.clone(), r2], None);
        assert!(!res.passed);
        assert!(check(&res, "changed operations").ok);
        assert!(!check(&res, "changed operations covered").ok);
        let res = summarize_suite(&s, 2, vec![r1.clone(), r1], None);
        assert!(
            check(&res, "changed operations planned first").ok && res.passed,
            "{:?}",
            res.checks
        );
    }

    #[test]
    fn the_fixture_repo_has_the_base_commit_tagged_and_the_change_on_top() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipping: no git");
            return;
        }
        let root = crate_root();
        let dest = std::env::temp_dir().join(format!("rh-eval-repo-{}", std::process::id()));
        let commits = vec![
            "tests/fixtures/qa-api-src/base".to_string(),
            "tests/fixtures/qa-api-src/change".to_string(),
        ];
        build_fixture_repo(&root, &commits, &dest).unwrap();
        let (files, _) = {
            let mut cmd = Command::new("git");
            cmd.current_dir(&dest)
                .args(["diff", "--name-only", "base...HEAD"]);
            let out =
                crate::tools::run_capped(&mut cmd, Duration::from_secs(20), 4096, None).unwrap();
            (out.stdout_lossy(), out.success())
        };
        assert_eq!(
            files.lines().collect::<Vec<_>>(),
            ["app/search.py", "docs/CHANGELOG.md"]
        );
        assert!(dest.join("app/orders.py").is_file());
        // rebuilding starts from nothing
        build_fixture_repo(&root, &commits, &dest).unwrap();
        assert!(build_fixture_repo(&root, &["nope".to_string()], &dest).is_err());
        let _ = std::fs::remove_dir_all(&dest);
    }

    /// Dev entry point: runs the real fixtures end to end in its own process.
    /// `EVAL_SUITES=qa-repo EVAL_K=1 cargo test -j 2 eval::tests::live -- --ignored --nocapture`
    #[test]
    #[ignore = "runs the fixtures end to end (needs python3; minutes)"]
    fn live_eval() {
        let suites = std::env::var("EVAL_SUITES").unwrap_or_else(|_| "all".into());
        let k = std::env::var("EVAL_K")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        let out = std::env::var("EVAL_OUT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("readyhai-eval-live"));
        let s = run_eval(EvalOpts {
            suites: vec![suites],
            k,
            root: Some(crate_root()),
            out,
            ..Default::default()
        })
        .unwrap();
        eprintln!("exit code would be {}", s.exit_code());
    }
