//! Exit criteria + Go / Conditional Go / No-Go. Computed, never chosen by an LLM.
use super::QaCtx;
use super::model::*;
use crate::model::{Category, FindingStatus, Run, Severity, Verdict, sha256_hex};
use std::collections::BTreeSet;

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

pub fn build(mut col: QaCollector, run: &Run, qa: &QaCtx, mode: &str) -> QaReport {
    super::triage::triage(&mut col);

    for d in col.defects.iter_mut() {
        d.fingerprint = fingerprint(&d.rule, &d.fp_key);
        if let Some(f) = run.findings.iter().find(|f| f.fingerprint == d.fingerprint) {
            d.status = f.status;
            d.regression = f.status == FindingStatus::New;
        }
    }

    let mut counts = ResultCounts { planned: col.cases.len(), ..Default::default() };
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
    let open_p1 = col.defects.iter().filter(open).filter(|d| d.priority == Priority::P1).count();
    let new_sec = run
        .findings
        .iter()
        .filter(|f| f.status == FindingStatus::New && f.severity >= Severity::High && f.category == Category::Security)
        .count();
    let contract = col.defects.iter().filter(open).filter(|d| d.rule == "qa.api.contract_violation").count();
    let roles = qa.roles.names();
    let authz_run = col
        .results
        .iter()
        .filter(|r| r.status != ResultStatus::Blocked && r.status != ResultStatus::Skipped)
        .filter(|r| col.cases.iter().any(|c| c.id == r.case_id && c.technique == Technique::AuthMatrix))
        .count();
    let pct = if counts.planned == 0 { 0.0 } else { counts.executed as f64 * 100.0 / counts.planned as f64 };

    let crit = |name: &str, met: bool, blocking: bool, detail: String| ExitCriterion {
        name: name.into(),
        met,
        blocking,
        detail,
    };
    let exit_criteria = vec![
        crit("No open P1 defects", open_p1 == 0, true, format!("{open_p1} open P1 defect(s)")),
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
            format!("{}/{} executed ({pct:.0}%)", counts.executed, counts.planned),
        ),
        crit("No flaky tests", counts.flaky == 0, false, format!("{} flaky", counts.flaky)),
        crit(
            "Authorization tested with ≥2 roles",
            roles.len() >= 2 && authz_run > 0,
            false,
            format!("{} role(s) configured, {authz_run} auth-matrix case(s) executed", roles.len()),
        ),
        crit("API contract violations = 0", contract == 0, false, format!("{contract} violation(s)")),
    ];

    let blocking_unmet = exit_criteria.iter().any(|c| c.blocking && !c.met);
    let any_unmet = exit_criteria.iter().any(|c| !c.met);
    let recommendation = if run.verdict == Verdict::Fail || blocking_unmet {
        Recommendation::NoGo
    } else if run.verdict == Verdict::Warn || any_unmet {
        Recommendation::ConditionalGo
    } else {
        Recommendation::Go
    };

    let mut conditions: Vec<String> = vec![];
    if recommendation != Recommendation::Go {
        for c in exit_criteria.iter().filter(|c| !c.met) {
            conditions.push(format!("{} ({})", c.name, c.detail));
        }
        for d in col.defects.iter().filter(open).filter(|d| d.priority == Priority::P2) {
            conditions.push(format!("Resolve {}: {}", d.id, d.title));
        }
        if run.verdict == Verdict::Warn {
            conditions.push("Review the gate WARN reasons".into());
        }
        conditions.truncate(10);
    }

    let environment = format!(
        "{} ({})",
        run.target.url.clone().unwrap_or_else(|| run.target.raw.clone()),
        if qa.nonprod { "nonprod" } else { "prod/unknown (read-only)" }
    );

    let present: BTreeSet<Area> = col.cases.iter().map(|c| c.area).collect();
    let scope: Vec<String> = present
        .iter()
        .map(|a| format!("{} ({} cases)", area_label(*a), col.cases.iter().filter(|c| c.area == *a).count()))
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
    };
    let mut s = format!(
        "Recommendation: {rec_s} for {environment}. {} of {} planned cases were executed: {} passed, {} failed, {} flaky, {} blocked. ",
        counts.executed, counts.planned, counts.passed, counts.failed, counts.flaky, counts.blocked
    );
    let open_defects: Vec<&Defect> = col.defects.iter().filter(open).collect();
    s.push_str(&format!("{} defect(s) are open, {open_p1} of them P1. ", open_defects.len()));
    if open_defects.is_empty() {
        s.push_str("No defects were recorded. ");
    } else {
        let top: Vec<String> =
            open_defects.iter().take(3).map(|d| format!("{} [{:?}] {}", d.id, d.priority, d.title)).collect();
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

    fn good_col() -> QaCollector {
        let mut c = QaCollector::default();
        c.cases.push(TestCase {
            id: "c1".into(),
            area: Area::Api,
            technique: Technique::AuthMatrix,
            title: "t".into(),
            priority: Priority::P2,
            component: "GET /a".into(),
            role: None,
            steps: vec![],
            expected: String::new(),
            source: CaseSource::Deterministic,
        });
        c.results.push(TestResult {
            case_id: "c1".into(),
            status: ResultStatus::Pass,
            actual: String::new(),
            duration_ms: 1,
            attempts: 1,
            evidence: vec![],
            defect_id: None,
        });
        c
    }

    fn qa2() -> QaCtx {
        let r: Roles = toml::from_str(
            "[[role]]\nname='a'\nauth='none'\n[[role]]\nname='b'\nauth='none'\n",
        )
        .unwrap();
        QaCtx::new(r, None, None, true)
    }

    #[test]
    fn matrix() {
        let q = qa2();
        assert_eq!(build(good_col(), &run(Verdict::Fail, vec![]), &q, "d").recommendation, Recommendation::NoGo);
        assert_eq!(build(good_col(), &run(Verdict::Warn, vec![]), &q, "d").recommendation, Recommendation::ConditionalGo);
        assert_eq!(build(good_col(), &run(Verdict::Pass, vec![]), &q, "d").recommendation, Recommendation::Go);
        // PASS + unmet non-blocking (flaky)
        let mut c = good_col();
        c.results[0].status = ResultStatus::Flaky;
        let r = build(c, &run(Verdict::Pass, vec![]), &q, "d");
        assert_eq!(r.recommendation, Recommendation::ConditionalGo);
        assert!(!r.conditions.is_empty());
        // PASS + no roles -> conditional
        let q0 = QaCtx::new(Roles::default(), None, None, false);
        assert_eq!(build(good_col(), &run(Verdict::Pass, vec![]), &q0, "d").recommendation, Recommendation::ConditionalGo);
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
}
