//! Exit criteria + Go / Conditional Go / No-Go. Computed, never chosen by an LLM.
use super::QaCtx;
use super::model::*;
use crate::model::{Category, CheckStatus, FindingStatus, Run, Severity, Verdict, sha256_hex};
use std::collections::BTreeSet;

/// Below this share of planned cases executed the run proves nothing either way.
pub const MIN_EXECUTED_PCT: f64 = 50.0;
/// Name of the exit criterion that decides "insufficient evidence" (blocking, but it yields
/// Inconclusive, not No-Go: nothing was shown to be broken, nothing was shown to work).
pub const EVIDENCE_CRITERION: &str =
    "Sufficient test evidence (≥50% of planned cases executed, requested core area ran)";

/// Same formula as Finding::finalize: sha256(rule \0 fp_key)[..12 bytes] hex.
pub fn fingerprint(rule: &str, fp_key: &str) -> String {
    let mut b = rule.as_bytes().to_vec();
    b.push(0);
    b.extend_from_slice(fp_key.as_bytes());
    sha256_hex(&b)[..24].to_string()
}

fn area_label(a: Area) -> &'static str {
    match a {
        Area::Api => "API functional testing",
        Area::Ui => "UI exploratory testing",
        Area::Perf => "Performance testing",
        Area::Resilience => "Resilience testing",
        Area::Suite => "Test-suite quality",
        Area::Release => "Release quality",
    }
}

/// Status of a defect made of `keys` (rule, fp_key) members, judged on their Finding twins.
/// None when no member has a twin in the run.
fn merged_status(keys: &[(String, String)], run: &Run) -> Option<FindingStatus> {
    let sts: Vec<FindingStatus> = keys
        .iter()
        .filter_map(|(r, k)| {
            let fp = fingerprint(r, k);
            run.findings
                .iter()
                .find(|f| f.fingerprint == fp)
                .map(|f| f.status)
        })
        .collect();
    if sts.is_empty() {
        None
    } else if sts.contains(&FindingStatus::New) {
        Some(FindingStatus::New)
    } else if sts.contains(&FindingStatus::Existing) {
        Some(FindingStatus::Existing)
    } else {
        Some(FindingStatus::Suppressed)
    }
}

/// Check-id prefixes whose checks produce the cases of `a`.
fn area_checks(a: Area) -> &'static [&'static str] {
    match a {
        Area::Api => &["qa.api."],
        Area::Ui => &["qa.ui"],
        Area::Perf => &["qa.perf"],
        Area::Resilience => &["qa.resilience"],
        Area::Suite | Area::Release => &["qa.suite", "qa.release"],
    }
}

/// An area that executed no case: why (from the check status, when a check of the area is in
/// the run) and whether it was requested (a check ran but ended Skipped/Errored/Partial).
struct NotRun {
    area: Area,
    reason: String,
    requested: bool,
}

fn not_run(area: Area, executed_in_area: usize, run: &Run) -> Option<NotRun> {
    if executed_in_area > 0 {
        return None;
    }
    let mut reason = String::new();
    let mut requested = false;
    let mut present = false;
    for c in run
        .checks
        .iter()
        .filter(|c| area_checks(area).iter().any(|p| c.id.starts_with(p)))
    {
        present = true;
        match &c.status {
            CheckStatus::Skipped(r) | CheckStatus::Errored(r) | CheckStatus::Partial(r) => {
                requested = true;
                if reason.is_empty() {
                    reason = r.clone();
                }
            }
            CheckStatus::NotApplicable(r) if reason.is_empty() => reason = r.clone(),
            _ => {}
        }
    }
    if reason.is_empty() {
        reason = if present {
            "no case executed".into()
        } else {
            "not part of this run (profile or target)".into()
        };
    }
    Some(NotRun {
        area,
        reason,
        requested,
    })
}

pub fn build(mut col: QaCollector, run: &Run, qa: &QaCtx, mode: &str) -> QaReport {
    super::triage::triage(&mut col);

    for d in col.defects.iter_mut() {
        d.fingerprint = fingerprint(&d.rule, &d.fp_key);
        // A merged defect stands for several raw defects, each with its own Finding twin and
        // baseline status: it is New when ANY member is new, Suppressed only when ALL are.
        let own = [(d.rule.clone(), d.fp_key.clone())];
        let keys = col.merged.get(&d.id).map(|m| m.as_slice()).unwrap_or(&own);
        if let Some(st) = merged_status(keys, run) {
            d.status = st;
            d.regression = st == FindingStatus::New;
        }
    }

    let mut counts = ResultCounts {
        planned: col.cases.len(),
        ..Default::default()
    };
    for r in &col.results {
        match r.status {
            ResultStatus::Pass => counts.passed += 1,
            ResultStatus::Fail => counts.failed += 1,
            ResultStatus::Blocked => counts.blocked += 1,
            ResultStatus::Skipped => counts.skipped += 1,
            ResultStatus::Flaky => counts.flaky += 1,
        }
    }
    counts.executed = counts.passed + counts.failed + counts.flaky;

    let open = |d: &&Defect| d.status != FindingStatus::Suppressed;
    let open_p1 = col
        .defects
        .iter()
        .filter(open)
        .filter(|d| d.priority == Priority::P1)
        .count();
    let new_sec = run
        .findings
        .iter()
        .filter(|f| {
            f.status == FindingStatus::New
                && f.severity >= Severity::High
                && f.category == Category::Security
        })
        .count();
    let contract = col
        .defects
        .iter()
        .filter(open)
        .filter(|d| d.rule == "qa.api.contract_violation")
        .count();
    let roles = qa.roles.names();
    // Distinct CONFIGURED roles that executed role-specific authorization cases. Anonymous /
    // invalid-token cases carry no role, a role whose credential is unset never gets a case, and
    // a case that was blocked/skipped did not run.
    let ran: BTreeSet<&str> = col
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                ResultStatus::Pass | ResultStatus::Fail | ResultStatus::Flaky
            )
        })
        .map(|r| r.case_id.as_str())
        .collect();
    let authz_roles: BTreeSet<String> = col
        .cases
        .iter()
        .filter(|c| ran.contains(c.id.as_str()))
        .filter(|c| c.technique == Technique::AuthMatrix || c.id.contains(".state.bola."))
        .filter_map(|c| c.role.clone())
        .filter(|r| roles.contains(r))
        .collect();
    // Failed cases: how many are not explained by any defect, and how many are still open
    // (a failure behind a suppressed defect is an accepted one).
    let defect_of = |r: &TestResult| {
        r.defect_id
            .as_deref()
            .and_then(|id| col.defects.iter().find(|d| d.id == id))
    };
    let failed_unexplained = col
        .results
        .iter()
        .filter(|r| r.status == ResultStatus::Fail && defect_of(r).is_none())
        .count();
    let failed_open = col
        .results
        .iter()
        .filter(|r| r.status == ResultStatus::Fail)
        .filter(|r| {
            defect_of(r)
                .map(|d| d.status != FindingStatus::Suppressed)
                .unwrap_or(true)
        })
        .count();
    let pct = if counts.planned == 0 {
        0.0
    } else {
        counts.executed as f64 * 100.0 / counts.planned as f64
    };
    // Evidence: executed cases per area (an area "ran" when at least one of its cases executed).
    let executed_in = |a: Area| {
        col.cases
            .iter()
            .filter(|c| c.area == a && ran.contains(c.id.as_str()))
            .count()
    };
    let api_requested = qa.spec.is_some()
        || run.target.openapi.is_some()
        || run.checks.iter().any(|c| {
            c.id.starts_with("qa.api.") && !matches!(c.status, CheckStatus::NotApplicable(_))
        });
    let mut evidence_gaps: Vec<String> = vec![];
    if counts.planned == 0 {
        evidence_gaps.push("no test case was planned".into());
    } else if pct < MIN_EXECUTED_PCT {
        evidence_gaps.push(format!(
            "only {} of {} planned cases executed ({pct:.0}%, minimum {MIN_EXECUTED_PCT:.0}%)",
            counts.executed, counts.planned
        ));
    }
    if api_requested && executed_in(Area::Api) == 0 {
        evidence_gaps.push("the API area was requested but no API case executed".into());
    }
    let evidence_ok = evidence_gaps.is_empty();

    let crit = |name: &str, met: bool, blocking: bool, detail: String| ExitCriterion {
        name: name.into(),
        met,
        blocking,
        detail,
    };
    let exit_criteria = vec![
        crit(
            "No open P1 defects",
            open_p1 == 0,
            true,
            format!("{open_p1} open P1 defect(s)"),
        ),
        crit(
            "No new critical/high security findings",
            new_sec == 0,
            true,
            format!("{new_sec} new critical/high security finding(s)"),
        ),
        crit(
            "Gate verdict not FAIL",
            run.verdict != Verdict::Fail,
            true,
            format!("verdict {:?}", run.verdict),
        ),
        crit(
            "≥90% of planned cases executed",
            counts.planned > 0 && pct >= 90.0,
            false,
            format!(
                "{}/{} executed ({pct:.0}%)",
                counts.executed, counts.planned
            ),
        ),
        crit(
            EVIDENCE_CRITERION,
            evidence_ok,
            true,
            if evidence_ok {
                format!(
                    "{}/{} executed ({pct:.0}%)",
                    counts.executed, counts.planned
                )
            } else {
                evidence_gaps.join("; ")
            },
        ),
        crit(
            "Every failed case is traced to a defect",
            failed_unexplained == 0,
            true,
            format!("{failed_unexplained} failed case(s) without a recorded defect"),
        ),
        crit(
            "No failed test cases",
            failed_open == 0,
            false,
            format!(
                "{failed_open} open failed case(s) of {} failed",
                counts.failed
            ),
        ),
        crit(
            "No flaky tests",
            counts.flaky == 0,
            false,
            format!("{} flaky", counts.flaky),
        ),
        crit(
            "Authorization tested with ≥2 roles",
            authz_roles.len() >= 2,
            false,
            format!(
                "{} distinct role(s) executed role-specific authorization cases ({}); {} configured",
                authz_roles.len(),
                authz_roles.iter().cloned().collect::<Vec<_>>().join(", "),
                roles.len()
            ),
        ),
        crit(
            "API contract violations = 0",
            contract == 0,
            false,
            format!("{contract} violation(s)"),
        ),
    ];

    // Areas that executed nothing. UI / performance / test-suite quality are conditions of a
    // release; resilience only when its check was actually requested (it needs deep + a scope).
    let skipped_areas: Vec<NotRun> = [Area::Ui, Area::Perf, Area::Suite, Area::Resilience]
        .into_iter()
        .filter_map(|a| {
            not_run(
                a,
                executed_in(a)
                    + if a == Area::Suite {
                        executed_in(Area::Release)
                    } else {
                        0
                    },
                run,
            )
        })
        .filter(|n| n.area != Area::Resilience || n.requested)
        .collect();
    let degraded = skipped_areas.iter().any(|n| n.requested);

    // Known-bad (a blocking criterion other than evidence, a failed gate) beats unknown:
    // No-Go. Without evidence there is no recommendation to give: Inconclusive.
    let other_blocking_unmet = exit_criteria
        .iter()
        .any(|c| c.blocking && !c.met && c.name != EVIDENCE_CRITERION);
    let any_unmet = exit_criteria.iter().any(|c| !c.met);
    let recommendation = if run.verdict == Verdict::Fail || other_blocking_unmet {
        Recommendation::NoGo
    } else if !evidence_ok {
        Recommendation::Inconclusive
    } else if run.verdict == Verdict::Warn || any_unmet || degraded {
        Recommendation::ConditionalGo
    } else {
        Recommendation::Go
    };

    let mut conditions: Vec<String> = vec![];
    if recommendation != Recommendation::Go {
        if !evidence_ok {
            conditions.push(format!(
                "Insufficient evidence: {}. Fix what blocked the run (credentials, reachability, budget) and re-run so that most planned cases execute",
                evidence_gaps.join("; ")
            ));
        }
        for c in exit_criteria
            .iter()
            .filter(|c| !c.met && c.name != EVIDENCE_CRITERION)
        {
            conditions.push(format!("{} ({})", c.name, c.detail));
        }
        for n in skipped_areas
            .iter()
            .filter(|n| n.area != Area::Resilience || n.requested)
        {
            conditions.push(format!(
                "{} did not run ({}): run it, or accept that it is untested",
                area_label(n.area),
                n.reason
            ));
        }
        for d in col
            .defects
            .iter()
            .filter(open)
            .filter(|d| d.priority == Priority::P2)
        {
            conditions.push(format!("Resolve {}: {}", d.id, d.title));
        }
        if run.verdict == Verdict::Warn {
            conditions.push("Review the gate WARN reasons".into());
        }
        conditions.truncate(12);
    }

    let environment = format!(
        "{} ({})",
        run.target
            .url
            .clone()
            .unwrap_or_else(|| run.target.raw.clone()),
        if qa.nonprod {
            "nonprod"
        } else {
            "prod/unknown (read-only)"
        }
    );

    let present: BTreeSet<Area> = col.cases.iter().map(|c| c.area).collect();
    let scope: Vec<String> = present
        .iter()
        .map(|a| {
            format!(
                "{} ({} cases)",
                area_label(*a),
                col.cases.iter().filter(|c| c.area == *a).count()
            )
        })
        .collect();
    let mut out_of_scope: Vec<String> = [Area::Ui, Area::Perf, Area::Resilience, Area::Suite]
        .iter()
        .filter(|a| !present.contains(a))
        .map(|a| format!("{} not run", area_label(*a)))
        .collect();
    out_of_scope.extend(col.untested.iter().cloned());

    let rec_s = match recommendation {
        Recommendation::Go => "GO",
        Recommendation::ConditionalGo => "CONDITIONAL GO",
        Recommendation::NoGo => "NO-GO",
        Recommendation::Inconclusive => "INCONCLUSIVE (insufficient evidence)",
    };
    let mut s = format!(
        "Recommendation: {rec_s} for {environment}. {} of {} planned cases were executed: {} passed, {} failed, {} flaky, {} blocked. ",
        counts.executed, counts.planned, counts.passed, counts.failed, counts.flaky, counts.blocked
    );
    if !evidence_ok {
        s.push_str(&format!(
            "The evidence is insufficient: {}. ",
            evidence_gaps.join("; ")
        ));
    }
    let open_defects: Vec<&Defect> = col.defects.iter().filter(open).collect();
    s.push_str(&format!(
        "{} defect(s) are open, {open_p1} of them P1. ",
        open_defects.len()
    ));
    if open_defects.is_empty() {
        s.push_str("No defects were recorded. ");
    } else {
        let top: Vec<String> = open_defects
            .iter()
            .take(3)
            .map(|d| format!("{} [{:?}] {}", d.id, d.priority, d.title))
            .collect();
        s.push_str(&format!("Top defects: {}. ", top.join("; ")));
    }
    s.push_str(&format!("Gate verdict is {:?}. ", run.verdict));
    if let Some(r) = col.risks.iter().min_by_key(|r| match r.level.as_str() {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }) {
        s.push_str(&format!("Biggest risk: {}.", r.title));
    } else {
        s.push_str("No outstanding risks were identified.");
    }

    QaReport {
        recommendation,
        conditions,
        executive_summary: s,
        ai_summary: None,
        mode: mode.into(),
        environment,
        scope,
        out_of_scope,
        roles,
        plan: col.plan,
        counts,
        cases: col.cases,
        results: col.results,
        defects: col.defects,
        coverage: col.coverage,
        risks: col.risks,
        exit_criteria,
        notes: col.notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Profile, Target, TargetKind};
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
