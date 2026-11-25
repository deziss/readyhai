//! Comprehensive unit tests for recommendation gates, evidence thresholds, and exit criteria.

#[cfg(test)]
mod tests {
    use super::super::builder::build;
    use super::super::fingerprint::fingerprint;
    use crate::model::{
        Category, Finding, FindingStatus, Profile, Run, Severity, Target, TargetKind, Verdict,
    };
    use crate::qa::QaCtx;
    use crate::qa::model::{
        Area, CaseSource, Defect, ExitCriterion, Priority, QaCollector, QaReport, Recommendation,
        ResultStatus, Technique, TestCase, TestResult,
    };
    use crate::qa::roles::Roles;

    fn run(v: Verdict, findings: Vec<Finding>) -> Run {
        Run {
            id: "r".into(),
            version: "t".into(),
            target: Target {
                kind: TargetKind::Web,
                raw: "https://x.test".into(),
                path: None,
                image: None,
                url: Some("https://x.test".into()),
                openapi: None,
                host: None,
                apk: None,
                device: None,
            },
            profile: Profile::Quick,
            started: String::new(),
            finished: String::new(),
            verdict: v,
            reasons: vec![],
            categories: vec![],
            checks: vec![],
            findings,
            fixed: 0,
            notes: vec![],
            errors: vec![],
            qa: None,
        }
    }

    fn case(id: &str, tech: Technique, role: Option<&str>) -> TestCase {
        TestCase {
            id: id.into(),
            area: Area::Api,
            technique: tech,
            title: "t".into(),
            priority: Priority::P2,
            component: "GET /a".into(),
            role: role.map(String::from),
            steps: vec![],
            expected: String::new(),
            source: CaseSource::Deterministic,
        }
    }

    fn result(id: &str, status: ResultStatus, defect: Option<&str>) -> TestResult {
        TestResult {
            case_id: id.into(),
            status,
            actual: String::new(),
            duration_ms: 1,
            attempts: 1,
            evidence: vec![],
            defect_id: defect.map(String::from),
        }
    }

    /// Two roles ("a", "b") each executed an auth-matrix case, plus an anonymous one: all pass.
    fn good_col() -> QaCollector {
        let mut c = QaCollector::default();
        for (id, role) in [("anon", None), ("ca", Some("a")), ("cb", Some("b"))] {
            c.cases.push(case(id, Technique::AuthMatrix, role));
            c.results.push(result(id, ResultStatus::Pass, None));
        }
        c
    }

    fn qa2() -> QaCtx {
        let r: Roles =
            toml::from_str("[[role]]\nname='a'\nauth='none'\n[[role]]\nname='b'\nauth='none'\n")
                .unwrap();
        QaCtx::new(r, None, None, true)
    }

    fn crit<'a>(r: &'a QaReport, name: &str) -> &'a ExitCriterion {
        r.exit_criteria
            .iter()
            .find(|c| c.name.starts_with(name))
            .unwrap_or_else(|| panic!("no criterion {name}"))
    }

    fn defect(id: &str, sev: Severity, status: FindingStatus) -> Defect {
        Defect {
            id: id.into(),
            rule: "qa.api.contract_violation".into(),
            category: Category::Quality,
            severity: sev,
            priority: Priority::P4,
            area: Area::Api,
            title: "t".into(),
            component: format!("GET /{id}"),
            environment: String::new(),
            steps_to_reproduce: vec![],
            expected: String::new(),
            actual: String::new(),
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![],
            remediation: String::new(),
            fp_key: id.into(),
            fingerprint: String::new(),
            status,
            regression: false,
            ai_note: None,
        }
    }

    #[test]
    fn matrix() {
        let q = qa2();
        assert_eq!(
            build(good_col(), &run(Verdict::Fail, vec![]), &q, "d").recommendation,
            Recommendation::NoGo
        );
        assert_eq!(
            build(good_col(), &run(Verdict::Warn, vec![]), &q, "d").recommendation,
            Recommendation::ConditionalGo
        );
        assert_eq!(
            build(good_col(), &run(Verdict::Pass, vec![]), &q, "d").recommendation,
            Recommendation::Go
        );
        // PASS + unmet non-blocking (flaky)
        let mut c = good_col();
        c.results[0].status = ResultStatus::Flaky;
        let r = build(c, &run(Verdict::Pass, vec![]), &q, "d");
        assert_eq!(r.recommendation, Recommendation::ConditionalGo);
        assert!(!r.conditions.is_empty());
        // PASS + no roles -> conditional
        let q0 = QaCtx::new(Roles::default(), None, None, false);
        assert_eq!(
            build(good_col(), &run(Verdict::Pass, vec![]), &q0, "d").recommendation,
            Recommendation::ConditionalGo
        );
    }

    #[test]
    fn authorization_criterion_counts_distinct_roles_that_ran_role_specific_cases() {
        let q = qa2();
        let go = |c: QaCollector| build(c, &run(Verdict::Pass, vec![]), &q, "d");
        // two roles ran -> met, and the detail names them
        let r = go(good_col());
        assert!(crit(&r, "Authorization").met);
        assert!(
            crit(&r, "Authorization")
                .detail
                .starts_with("2 distinct role(s)")
        );
        // anonymous + invalid-token cases only (no role on any case): unmet, even with roles configured
        let mut c = QaCollector::default();
        for id in ["anon", "invalid"] {
            c.cases.push(case(id, Technique::AuthMatrix, None));
            c.results.push(result(id, ResultStatus::Pass, None));
        }
        assert!(!crit(&go(c), "Authorization").met);
        // the SAME role twice is one role
        let mut c = QaCollector::default();
        for id in ["x1", "x2", "x3"] {
            c.cases.push(case(id, Technique::AuthMatrix, Some("a")));
            c.results.push(result(id, ResultStatus::Pass, None));
        }
        let r = go(c);
        assert!(
            !crit(&r, "Authorization").met
                && crit(&r, "Authorization")
                    .detail
                    .starts_with("1 distinct role(s)")
        );
        // a configured-but-unset role never got a case; a case that was blocked/skipped did not run
        let mut c = good_col();
        c.results[2].status = ResultStatus::Blocked;
        assert!(
            !crit(&go(c), "Authorization").met,
            "blocked case does not count"
        );
        let mut c = good_col();
        c.results[1].status = ResultStatus::Skipped;
        assert!(!crit(&go(c), "Authorization").met);
        // a role that is not in roles.toml is not counted
        let mut c = good_col();
        c.cases[2].role = Some("stranger".into());
        assert!(!crit(&go(c), "Authorization").met);
        // other techniques do not count; BOLA (cross-role) cases do
        let mut c = good_col();
        c.cases[2].technique = Technique::Positive;
        assert!(!crit(&go(c), "Authorization").met);
        let mut c = good_col();
        c.cases[2] = case(
            "api.GET./o/{id}.state.bola.b",
            Technique::StateTransition,
            Some("b"),
        );
        c.results[2].case_id = "api.GET./o/{id}.state.bola.b".into();
        assert!(crit(&go(c), "Authorization").met);
        // failed-but-executed cases did run
        let mut c = good_col();
        c.results[1].status = ResultStatus::Fail;
        c.results[1].defect_id = Some("D-1".into());
        c.defects
            .push(defect("D-1", Severity::Low, FindingStatus::New));
        assert!(crit(&go(c), "Authorization").met);
    }

    #[test]
    fn failed_cases_must_be_explained_by_a_defect() {
        let q = qa2();
        let go = |c: QaCollector| build(c, &run(Verdict::Pass, vec![]), &q, "d");
        // a failed case with NO defect: blocking, whatever the gate says
        let mut c = good_col();
        c.results[1].status = ResultStatus::Fail;
        let r = go(c);
        assert_eq!(r.counts.failed, 1);
        assert!(!crit(&r, "Every failed case").met && crit(&r, "Every failed case").blocking);
        assert_eq!(r.recommendation, Recommendation::NoGo);
        assert!(r.conditions.iter().any(|c| c.contains("Every failed case")));
        // a failed case whose defect id points nowhere is just as unexplained
        let mut c = good_col();
        c.results[1].status = ResultStatus::Fail;
        c.results[1].defect_id = Some("D-404".into());
        assert_eq!(go(c).recommendation, Recommendation::NoGo);
        // failed WITH a (low) defect: not blocking, but the non-blocking "no failed cases" is unmet
        let mut c = good_col();
        c.results[1].status = ResultStatus::Fail;
        c.results[1].defect_id = Some("D-1".into());
        c.defects
            .push(defect("D-1", Severity::Low, FindingStatus::New));
        let r = go(c);
        assert!(crit(&r, "Every failed case").met);
        assert!(
            !crit(&r, "No failed test cases").met && !crit(&r, "No failed test cases").blocking
        );
        assert_eq!(r.recommendation, Recommendation::ConditionalGo);
        // the failure behind a SUPPRESSED defect is an accepted one
        let mut c = good_col();
        c.results[1].status = ResultStatus::Fail;
        c.results[1].defect_id = Some("D-1".into());
        c.defects
            .push(defect("D-1", Severity::Low, FindingStatus::Suppressed));
        let r = go(c);
        assert!(crit(&r, "No failed test cases").met);
        assert_eq!(r.counts.failed, 1, "the raw count still shows it");
        // nothing failed: both criteria met -> Go
        assert!(crit(&go(good_col()), "No failed test cases").met);
        assert_eq!(go(good_col()).recommendation, Recommendation::Go);
    }

    #[test]
    fn p1_defect_blocks_and_fingerprint_matches() {
        let q = qa2();
        let mut c = good_col();
        let mut d = Defect {
            id: "x".into(),
            rule: "qa.api.authz_missing".into(),
            category: Category::Security,
            severity: Severity::High,
            priority: Priority::P4,
            area: Area::Api,
            title: "Missing auth".into(),
            component: "DELETE /users/{id}".into(),
            environment: String::new(),
            steps_to_reproduce: vec![],
            expected: "401".into(),
            actual: "200".into(),
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![],
            remediation: String::new(),
            fp_key: "DELETE /users/{id}|noauth".into(),
            fingerprint: String::new(),
            status: FindingStatus::New,
            regression: false,
            ai_note: None,
        };
        let mut f = d.to_finding("qa.api");
        f.finalize();
        assert_eq!(f.fingerprint, fingerprint(&d.rule, &d.fp_key));
        f.status = FindingStatus::Existing;
        d.id = "y".into();
        c.defects.push(d);
        let r = build(c, &run(Verdict::Pass, vec![f]), &q, "d");
        assert_eq!(r.recommendation, Recommendation::NoGo);
        assert_eq!(r.defects[0].status, FindingStatus::Existing);
        assert!(!r.defects[0].regression);
        assert!(r.executive_summary.contains("NO-GO"));
    }

    // ------------------------------------------------------------ insufficient evidence

    fn check(id: &str, st: crate::model::CheckStatus) -> crate::model::CheckResult {
        crate::model::CheckResult {
            id: id.into(),
            title: id.into(),
            tool: None,
            status: st,
            findings: 0,
            duration_ms: 1,
        }
    }

    /// `n` planned api cases of which the first `executed` passed (role a / b auth-matrix cases first).
    fn col_with(n: usize, executed: usize) -> QaCollector {
        let mut c = QaCollector::default();
        for i in 0..n {
            let role = ["a", "b"].get(i).copied();
            c.cases
                .push(case(&format!("c{i}"), Technique::AuthMatrix, role));
            c.results.push(result(
                &format!("c{i}"),
                if i < executed {
                    ResultStatus::Pass
                } else {
                    ResultStatus::Blocked
                },
                None,
            ));
        }
        c
    }

    #[test]
    fn nothing_executed_is_inconclusive_never_a_go() {
        let q = qa2();
        // nothing planned at all
        let r = build(QaCollector::default(), &run(Verdict::Pass, vec![]), &q, "d");
        assert_eq!(r.recommendation, Recommendation::Inconclusive);
        assert!(
            r.conditions[0].starts_with("Insufficient evidence"),
            "{:?}",
            r.conditions
        );
        assert!(
            crit(&r, "Sufficient test evidence").blocking
                && !crit(&r, "Sufficient test evidence").met
        );
        assert!(
            r.executive_summary.contains("INCONCLUSIVE")
                && r.executive_summary.contains("insufficient")
        );
        // planned but everything blocked
        let r = build(col_with(4, 0), &run(Verdict::Pass, vec![]), &q, "d");
        assert_eq!(r.recommendation, Recommendation::Inconclusive);
        assert_eq!(r.counts.executed, 0);
    }

    #[test]
    fn below_half_executed_is_inconclusive_half_is_not() {
        let q = qa2();
        let go = |c: QaCollector| build(c, &run(Verdict::Pass, vec![]), &q, "d");
        let r = go(col_with(4, 1));
        assert_eq!(r.recommendation, Recommendation::Inconclusive);
        assert!(
            r.conditions[0].contains("only 1 of 4 planned cases executed (25%"),
            "{:?}",
            r.conditions
        );
        // exactly 50% is enough evidence to judge (the 90% criterion is then just unmet)
        let r = go(col_with(4, 2));
        assert_eq!(r.recommendation, Recommendation::ConditionalGo);
        assert!(crit(&r, "Sufficient test evidence").met);
        // all executed: unchanged Go
        assert_eq!(go(col_with(4, 4)).recommendation, Recommendation::Go);
    }

    #[test]
    fn a_requested_api_area_that_never_ran_is_inconclusive() {
        // the user gave a spec (API requested); only UI cases executed
        let r: Roles =
            toml::from_str("[[role]]\nname='a'\nauth='none'\n[[role]]\nname='b'\nauth='none'\n")
                .unwrap();
        let q = QaCtx::new(r, Some("spec.json".into()), None, true);
        let mut c = QaCollector::default();
        for i in 0..3 {
            let mut t = case(&format!("ui{i}"), Technique::Exploratory, None);
            t.area = Area::Ui;
            c.cases.push(t);
            c.results
                .push(result(&format!("ui{i}"), ResultStatus::Pass, None));
        }
        let rep = build(c, &run(Verdict::Pass, vec![]), &q, "d");
        assert_eq!(rep.recommendation, Recommendation::Inconclusive);
        assert!(
            rep.conditions[0].contains("API area was requested but no API case executed"),
            "{:?}",
            rep.conditions
        );
        // the same run without a spec / api checks never asked for the API: UI evidence is enough
        let q2 = qa2();
        let mut c = QaCollector::default();
        let mut t = case("ui0", Technique::Exploratory, None);
        t.area = Area::Ui;
        c.cases.push(t);
        c.results.push(result("ui0", ResultStatus::Pass, None));
        assert_ne!(
            build(c, &run(Verdict::Pass, vec![]), &q2, "d").recommendation,
            Recommendation::Inconclusive
        );
        // an api check that ran in this run (even without --spec: it was discovered) is "requested"
        let mut c = QaCollector::default();
        let mut t = case("ui0", Technique::Exploratory, None);
        t.area = Area::Ui;
        c.cases.push(t);
        c.results.push(result("ui0", ResultStatus::Pass, None));
        let mut rn = run(Verdict::Pass, vec![]);
        rn.checks = vec![check(
            "qa.api.authz",
            crate::model::CheckStatus::Errored("down".into()),
        )];
        assert_eq!(
            build(c, &rn, &q2, "d").recommendation,
            Recommendation::Inconclusive
        );
    }

    #[test]
    fn a_known_failure_beats_missing_evidence() {
        let q = qa2();
        // no evidence, but the gate failed: No-Go (something IS known to be wrong)
        let r = build(col_with(4, 0), &run(Verdict::Fail, vec![]), &q, "d");
        assert_eq!(r.recommendation, Recommendation::NoGo);
        // no evidence and an open P1 defect: No-Go
        let mut c = col_with(4, 1);
        let mut d = defect("D-1", Severity::Critical, FindingStatus::New);
        d.priority = Priority::P1;
        c.defects.push(d);
        assert_eq!(
            build(c, &run(Verdict::Pass, vec![]), &q, "d").recommendation,
            Recommendation::NoGo
        );
    }

    #[test]
    fn skipped_ui_perf_suite_areas_are_conditions_not_just_out_of_scope() {
        use crate::model::CheckStatus::{Passed, Skipped};
        let q = qa2();
        let mut rn = run(Verdict::Pass, vec![]);
        rn.checks = vec![
            check("qa.api.authz", Passed),
            check("qa.ui", Skipped("playwright image not available".into())),
            check("qa.perf", Skipped("k6 image not available".into())),
            check("qa.suite.coverage", Skipped("no coverage report".into())),
        ];
        let r = build(good_col(), &rn, &q, "d");
        // good evidence + a clean gate, but three requested areas never ran: not a plain Go
        assert_eq!(r.recommendation, Recommendation::ConditionalGo);
        for (label, why) in [
            ("UI exploratory testing", "playwright image not available"),
            ("Performance testing", "k6 image not available"),
            ("Test-suite quality", "no coverage report"),
        ] {
            assert!(
                r.conditions
                    .iter()
                    .any(|c| c.contains(label) && c.contains("did not run") && c.contains(why)),
                "{label}: {:?}",
                r.conditions
            );
        }
        // still listed as out of scope too
        assert!(
            r.out_of_scope
                .iter()
                .any(|o| o.contains("UI exploratory testing"))
        );
        // areas that simply are not part of the run (no check at all) do not degrade a Go...
        assert_eq!(
            build(good_col(), &run(Verdict::Pass, vec![]), &q, "d").recommendation,
            Recommendation::Go
        );
        // ...but are named when the recommendation is not a Go anyway
        let r = build(good_col(), &run(Verdict::Warn, vec![]), &q, "d");
        assert!(
            r.conditions
                .iter()
                .any(|c| c.contains("Performance testing did not run (not part of this run")),
            "{:?}",
            r.conditions
        );
    }

    #[test]
    fn exit_codes_per_recommendation() {
        assert_eq!(Recommendation::Go.exit_code(), 0);
        assert_eq!(Recommendation::ConditionalGo.exit_code(), 1);
        assert_eq!(Recommendation::NoGo.exit_code(), 2);
        assert_eq!(Recommendation::Inconclusive.exit_code(), 2);
    }

    // ------------------------------------------------------------ merged defects keep every member

    fn finding_for(d: &Defect, st: FindingStatus) -> Finding {
        let mut f = d.to_finding("qa.api.functional");
        f.finalize();
        f.status = st;
        f
    }

    #[test]
    fn a_merged_defect_is_new_when_any_member_is_new_and_suppressed_only_when_all_are() {
        let q = qa2();
        let mk = |p: &str| {
            let mut d = crate::qa::triage::tests::defect(
                "qa.api.server_error",
                &format!("GET {p}"),
                Severity::High,
                "HTTP 500 (alice); body: [python_traceback] KeyError: 'x'",
            );
            d.fp_key = format!("GET {p}|state");
            d
        };
        let build_with = |sts: [FindingStatus; 3]| {
            let mut c = good_col();
            let ds: Vec<Defect> = ["/a", "/b", "/c"].iter().map(|p| mk(p)).collect();
            let fs: Vec<Finding> = ds
                .iter()
                .zip(sts)
                .map(|(d, st)| finding_for(d, st))
                .collect();
            c.defects = ds;
            build(c, &run(Verdict::Pass, fs), &q, "d")
        };
        use FindingStatus::*;
        // first member accepted (suppressed), another one NEW: the merged defect is new + open
        let r = build_with([Suppressed, New, Suppressed]);
        assert_eq!(r.defects.len(), 1, "three members share one root cause");
        assert!(r.defects[0].title.starts_with("Same server error on 3"));
        assert_eq!(r.defects[0].status, New);
        assert!(r.defects[0].regression);
        // all accepted: suppressed
        assert_eq!(
            build_with([Suppressed, Suppressed, Suppressed]).defects[0].status,
            Suppressed
        );
        // a mix of baselined and suppressed: existing
        let r = build_with([Suppressed, Existing, Suppressed]);
        assert_eq!(r.defects[0].status, Existing);
        assert!(!r.defects[0].regression);
    }
}
