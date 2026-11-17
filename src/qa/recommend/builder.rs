//! QA report builder, recommendation determination, and executive summary synthesis.

use std::collections::BTreeSet;

use super::criteria::build_exit_criteria;
use super::evidence::{area_label, not_run, EVIDENCE_CRITERION, MIN_EXECUTED_PCT, NotRun};
use super::fingerprint::{fingerprint, merged_status};
use super::super::model::*;
use super::super::QaCtx;
use crate::model::{Category, CheckStatus, FindingStatus, Run, Severity, Verdict};

pub fn build(mut col: QaCollector, run: &Run, qa: &QaCtx, mode: &str) -> QaReport {
    super::super::triage::triage(&mut col);

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

    let exit_criteria = build_exit_criteria(
        open_p1,
        new_sec,
        run.verdict,
        &counts,
        pct,
        evidence_ok,
        &evidence_gaps,
        failed_unexplained,
        failed_open,
        &authz_roles,
        &roles,
        contract,
    );

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
