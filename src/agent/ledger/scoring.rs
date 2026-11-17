use std::collections::{BTreeMap, BTreeSet};

use super::super::oracle::Severity;
use super::super::types::{
    BlockReason, CaseExecutionResult, CoverageCell, EvidenceLedger, ExitCheckItem, LedgerClaim,
    PillarResult, TriagedDefect, evidence_share,
};
use super::blockers::{blocker_label, blockers_of, is_blocking, is_unconfirmed_exploratory};
use super::constants::{
    EVIDENCE_WEIGHT, FULL_CONFIDENCE, MIN_OVERALL_CONFIDENCE, MIN_PILLAR_CONFIDENCE, PILLARS,
    TECHNIQUES,
};
use super::types::{
    LedgerInput, add, applicable, bucket, conclusive, confidence_pct, describe, merge, points,
    status_of,
};

pub fn compute_scored(inp: &LedgerInput) -> EvidenceLedger {
    let exploratory: Vec<&CaseExecutionResult> = inp
        .results
        .iter()
        .filter(|r| is_unconfirmed_exploratory(r))
        .collect();
    let scored: Vec<CaseExecutionResult> = inp
        .results
        .iter()
        .filter(|r| !is_unconfirmed_exploratory(r))
        .cloned()
        .collect();
    let results = &scored[..];
    // 1. technique coverage matrix
    let mut cells: BTreeMap<String, CoverageCell> = BTreeMap::new();
    for t in TECHNIQUES {
        cells.insert(
            t.to_string(),
            CoverageCell {
                technique: t.to_string(),
                ..Default::default()
            },
        );
    }
    for r in results {
        let t = if TECHNIQUES.contains(&r.technique.as_str()) {
            r.technique.clone()
        } else {
            "other".to_string()
        };
        add(
            cells.entry(t.clone()).or_insert_with(|| CoverageCell {
                technique: t,
                ..Default::default()
            }),
            r,
        );
    }
    let coverage: Vec<CoverageCell> = cells.into_values().filter(|c| c.planned > 0).collect();
    let cell = |t: &str| coverage.iter().find(|c| c.technique == t);

    // 2. severities of failures decide caps; only blocking defects count (see `is_blocking`)
    let sev = |s: Severity| {
        inp.defects
            .iter()
            .filter(|d| is_blocking(d) && d.severity == s.as_str())
            .count()
    };
    let (critical, high) = (sev(Severity::Critical), sev(Severity::High));
    let sev_of_fail = |techs: &[&str]| -> Option<Severity> {
        results
            .iter()
            .filter(|r| r.status == "FAIL" && techs.contains(&r.technique.as_str()))
            .filter_map(|r| {
                r.oracle
                    .as_ref()
                    .and_then(|o| o.max_fail_severity())
                    .or(Some(Severity::High))
            })
            .max()
    };

    // 3. pillars: the score is over the conclusive cases only (an inconclusive case is missing
    // evidence, not a failure), and is shown with its confidence, the conclusive share of the
    // applicable cases. A pillar whose confidence is under the minimum is not scored at all.
    let mut pillars: Vec<PillarResult> = vec![];
    for (id, name, techs, _) in PILLARS {
        let m = merge(
            &techs.join("/"),
            &techs.iter().filter_map(|t| cell(t)).collect::<Vec<_>>(),
        );
        let (concl, appl) = (conclusive(&m), applicable(&m));
        let conf = confidence_pct(concl, appl);
        let (score, status, claim) = if concl == 0 {
            (
                None,
                "not_evaluated",
                format!(
                    "not evaluated: no conclusive result for {} ({} inconclusive, {} blocked, {} not executed{} of {} planned)",
                    techs.join("/"),
                    m.inconclusive,
                    m.blocked,
                    m.skipped,
                    if m.not_applicable > 0 {
                        format!(", {} not applicable", m.not_applicable)
                    } else {
                        String::new()
                    },
                    m.planned
                ),
            )
        } else if conf.is_some_and(|c| c < MIN_PILLAR_CONFIDENCE) {
            (
                None,
                "not_evaluated",
                format!(
                    "not evaluated: only {concl} of {appl} applicable case(s) gave a conclusive result ({}% confidence, at least {MIN_PILLAR_CONFIDENCE}% is needed); {}",
                    conf.unwrap_or(0),
                    describe(&m)
                ),
            )
        } else {
            let mut s = (100.0 * points(&m) / concl as f64).round() as u32;
            match sev_of_fail(techs) {
                Some(Severity::Critical) => s = s.min(40),
                Some(Severity::High) => s = s.min(65),
                _ => {}
            }
            (Some(s), status_of(&m), describe(&m))
        };
        pillars.push(PillarResult {
            confidence: conf,
            id: id.into(),
            name: name.into(),
            score,
            status: status.into(),
            claim,
            techniques: techs.iter().map(|t| t.to_string()).collect(),
            case_ids: m.case_ids,
            evidence_files: m.evidence_files,
        });
    }
    // evidence pillar: the share of executed cases that have a stored request/response pair (the
    // target answered and the evidence file exists). A reproduction command is generated for every
    // case, so it proves nothing; a transport error or a missing file is not evidence. A case that
    // was never sent (SKIPPED, NOT_APPLICABLE, a ledger-only row) is not executed.
    let executed: Vec<&CaseExecutionResult> = results.iter().filter(|r| r.was_sent()).collect();
    let (repro_ok, _) = evidence_share(results);
    pillars.push(if executed.is_empty() {
        PillarResult {
            confidence: None,
            id: "evidence".into(),
            name: "Reproducible evidence".into(),
            score: None,
            status: "not_evaluated".into(),
            claim: "not evaluated: no case was executed".into(),
            techniques: vec![],
            case_ids: vec![],
            evidence_files: vec![],
        }
    } else {
        let s = (100.0 * repro_ok as f64 / executed.len() as f64).round() as u32;
        PillarResult {
            confidence: None,
            id: "evidence".into(),
            name: "Reproducible evidence".into(),
            score: Some(s),
            status: if repro_ok == executed.len() {
                "pass"
            } else {
                "partial"
            }
            .into(),
            claim: format!(
                "{repro_ok} of {} executed cases have a stored request/response evidence file",
                executed.len()
            ),
            techniques: vec![],
            case_ids: executed.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: executed
                .iter()
                .filter(|r| r.has_stored_evidence())
                .filter_map(|r| r.evidence_file.clone())
                .collect(),
        }
    });

    // 4. overall: weighted over the scored pillars; at least one functional pillar must be scored
    let weights: BTreeMap<&str, u32> = PILLARS
        .iter()
        .map(|(id, _, _, w)| (*id, *w))
        .chain([("evidence", EVIDENCE_WEIGHT)])
        .collect();
    let (mut num, mut den) = (0u32, 0u32);
    for p in &pillars {
        if let Some(s) = p.score {
            let w = weights[p.id.as_str()];
            num += s * w;
            den += w;
        }
    }
    let functional_scored = pillars
        .iter()
        .filter(|p| p.id != "evidence")
        .any(|p| p.score.is_some())
        && den > 0;
    let overall_raw = if functional_scored {
        ((num as f64) / (den as f64)).round() as u32
    } else {
        0
    };

    // 5. counts, confidence and verdict
    let n = |b: &str| results.iter().filter(|r| bucket(r) == b).count();
    let (pass, warn, fail, inconclusive, blocked, skipped, not_applicable) = (
        n("pass"),
        n("warn"),
        n("fail"),
        n("inconclusive"),
        n("blocked"),
        n("skipped"),
        n("not_applicable"),
    );
    let total = results.len();
    let flaky = results.iter().filter(|r| r.flaky).count();
    let conclusive_n = pass + warn + fail;
    let applicable_n = total.saturating_sub(skipped + not_applicable);
    // the share of the applicable cases that gave an answer: how much of the verdict is evidence
    let confidence = confidence_pct(conclusive_n, applicable_n);
    let low_confidence = confidence.is_none_or(|c| c < MIN_OVERALL_CONFIDENCE);
    let conf_text = confidence.map_or("n/a".to_string(), |c| format!("{c}%"));
    let unevaluated: Vec<&str> = pillars
        .iter()
        .filter(|p| p.score.is_none())
        .map(|p| p.id.as_str())
        .collect();
    let blockers = blockers_of(results, &coverage);

    // A login wall stopped cases and neither pillar that exercises the application (value: its
    // behaviour and input handling; safety: injection) could be scored. What did conclude is
    // hygiene that holds whatever the app does (sensitive files that are not there, a forged
    // token refused at the door, an anonymous page load): that is not a verdict on the app.
    let pillar_scored = |id: &str| pillars.iter().any(|p| p.id == id && p.score.is_some());
    let app_unreached = blockers.iter().any(|b| b.reason == BlockReason::AuthWall)
        && !pillar_scored("value")
        && !pillar_scored("safety");
    let mut reasons: Vec<String> = vec![];
    let computed = if critical > 0 {
        // a proven critical defect is a finding whatever the coverage: never hidden behind NOT_EVALUATED
        reasons.push(format!("{critical} critical defect(s)"));
        if functional_scored && overall_raw < 70 {
            reasons.push(format!("overall readiness {overall_raw} < 70"));
        }
        if low_confidence {
            reasons.push(format!(
                "only {conf_text} of the applicable cases were conclusive: the failure is proven, the rest of the target is not evaluated"
            ));
        }
        "NO_GO"
    } else if !functional_scored || low_confidence || app_unreached {
        if !functional_scored {
            reasons.push("no pillar could be evaluated from conclusive results".into());
        }
        if app_unreached {
            reasons.push("insufficient evidence: the application sits behind a login wall and no credential was given, so neither its behaviour (value) nor its injection resistance (safety) could be evaluated; what concluded is hygiene that holds whatever the app does".into());
        }
        if low_confidence {
            reasons.push(format!(
                "insufficient evidence: only {conf_text} of the applicable cases reached a conclusive result (at least {MIN_OVERALL_CONFIDENCE}% is needed)"
            ));
        }
        "NOT_EVALUATED"
    } else if overall_raw < 70 {
        reasons.push(format!("overall readiness {overall_raw} < 70"));
        "NO_GO"
    } else {
        if high > 0 {
            reasons.push(format!("{high} high-severity defect(s)"));
        }
        if fail > 0 {
            reasons.push(format!("{fail} failed case(s)"));
        }
        if flaky > 0 {
            reasons.push(format!("{flaky} flaky case(s)"));
        }
        if blocked > 0 {
            reasons.push(format!("{blocked} blocked case(s)"));
        }
        if !unevaluated.is_empty() {
            reasons.push(format!(
                "pillar(s) not evaluated: {}",
                unevaluated.join(", ")
            ));
        }
        if confidence.is_some_and(|c| c < FULL_CONFIDENCE) {
            reasons.push(format!(
                "only {conf_text} of the applicable cases reached a conclusive result (need {FULL_CONFIDENCE}%)"
            ));
        }
        if overall_raw < 85 {
            reasons.push(format!("overall readiness {overall_raw} < 85"));
        }
        if inp.dry_run && skipped > 0 {
            reasons.push("dry-run: state-changing cases were not executed".into());
        }
        if reasons.is_empty() {
            "GO"
        } else {
            "CONDITIONAL_GO"
        }
    };
    // not evaluated: no readiness number (the pillars keep their own scores and confidence)
    let evaluated = computed != "NOT_EVALUATED";
    let overall = if evaluated { overall_raw } else { 0 };

    // 6. claims, each citing case ids and evidence files
    let mut claims: Vec<LedgerClaim> = vec![];
    for c in &coverage {
        claims.push(LedgerClaim {
            claim: if status_of(c) == "not_evaluated" {
                format!("{}: not evaluated (no conclusive result)", describe(c))
            } else {
                describe(c)
            },
            status: status_of(c).into(),
            case_ids: c.case_ids.clone(),
            evidence_files: c.evidence_files.clone(),
        });
    }
    for d in inp.defects {
        claims.push(LedgerClaim {
            claim: format!("{} [{}] {}", d.id, d.severity, d.title),
            status: "fail".into(),
            case_ids: d.case_ids.clone(),
            evidence_files: d.evidence_files.clone(),
        });
    }
    let flaky_ids: Vec<&CaseExecutionResult> = results.iter().filter(|r| r.flaky).collect();
    if !flaky_ids.is_empty() {
        claims.push(LedgerClaim {
            claim: format!(
                "{} case(s) failed once but did not reproduce on re-run (flaky)",
                flaky_ids.len()
            ),
            status: "partial".into(),
            case_ids: flaky_ids.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: flaky_ids
                .iter()
                .filter_map(|r| r.evidence_file.clone())
                .collect(),
        });
    }
    let skipped_cases: Vec<&CaseExecutionResult> =
        results.iter().filter(|r| r.status == "SKIPPED").collect();
    if !skipped_cases.is_empty() {
        let why: BTreeMap<String, usize> =
            skipped_cases.iter().fold(BTreeMap::new(), |mut m, r| {
                let reason = r.failure_reason.as_deref().unwrap_or("not executed");
                let key = if reason.starts_with("dry_run") {
                    "dry-run"
                } else if reason.contains("budget") {
                    "budget"
                } else if reason.starts_with("invalid") {
                    "invalid case"
                } else if reason.contains("missing credential") {
                    "missing credentials"
                } else if reason.starts_with("stateful check skipped") {
                    "stateful check not applicable"
                } else {
                    "other"
                };
                *m.entry(key.to_string()).or_default() += 1;
                m
            });
        claims.push(LedgerClaim {
            claim: format!(
                "{} case(s) were not executed ({})",
                skipped_cases.len(),
                why.iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            status: "not_evaluated".into(),
            case_ids: skipped_cases.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: vec![],
        });
    }
    let na_cases: Vec<&CaseExecutionResult> = results
        .iter()
        .filter(|r| r.status == "NOT_APPLICABLE")
        .collect();
    if !na_cases.is_empty() {
        claims.push(LedgerClaim {
            claim: format!(
                "{} case(s) are not applicable: no input surface was found for them. They count toward no score, confidence or pass rate",
                na_cases.len()
            ),
            status: "not_evaluated".into(),
            case_ids: na_cases.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: vec![],
        });
    }
    let walled: Vec<&CaseExecutionResult> = results
        .iter()
        .filter(|r| r.blocked_reason == Some(BlockReason::AuthWall))
        .collect();
    if !walled.is_empty() {
        claims.push(LedgerClaim {
            claim: format!(
                "{} case(s) are behind a login wall: no credential was available",
                walled.len()
            ),
            status: "not_evaluated".into(),
            case_ids: walled.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: walled
                .iter()
                .filter_map(|r| r.evidence_file.clone())
                .collect(),
        });
    }
    let blocked_cases: Vec<&CaseExecutionResult> = results
        .iter()
        .filter(|r| r.status == "BLOCKED" && r.blocked_reason != Some(BlockReason::AuthWall))
        .collect();
    if !blocked_cases.is_empty() {
        claims.push(LedgerClaim {
            claim: format!("{} case(s) could not reach the target", blocked_cases.len()),
            status: "not_evaluated".into(),
            case_ids: blocked_cases.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: blocked_cases
                .iter()
                .filter_map(|r| r.evidence_file.clone())
                .collect(),
        });
    }

    if !exploratory.is_empty() {
        claims.push(LedgerClaim {
            claim: format!(
                "{} exploratory case(s) proposed by the LLM were run but are not scored: an LLM-written expectation is not evidence, and none of them was failed by a deterministic oracle",
                exploratory.len()
            ),
            status: "not_evaluated".into(),
            case_ids: exploratory.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: exploratory
                .iter()
                .filter_map(|r| r.evidence_file.clone())
                .collect(),
        });
    }

    // 7. exit criteria (all computed)
    let ids = |f: &dyn Fn(&CaseExecutionResult) -> bool| -> (Vec<String>, Vec<String>) {
        let rs: Vec<&CaseExecutionResult> = results.iter().filter(|r| f(r)).collect();
        (
            rs.iter().map(|r| r.case_id.clone()).collect(),
            rs.iter().filter_map(|r| r.evidence_file.clone()).collect(),
        )
    };
    let item =
        |criterion: &str,
         met: bool,
         status: &str,
         details: String,
         (case_ids, evidence_files): (Vec<String>, Vec<String>)| ExitCheckItem {
            criterion: criterion.into(),
            met,
            status: Some(status.into()),
            details,
            case_ids,
            evidence_files,
        };
    let pillar = |id: &str| pillars.iter().find(|p| p.id == id);
    // over the conclusive cases: an inconclusive, blocked or not applicable case is no pass and no fail
    let pass_rate = if conclusive_n == 0 {
        0.0
    } else {
        100.0 * pass as f64 / conclusive_n as f64
    };
    let authz_fails = cell("authz").map_or(0, |c| c.fail);
    let authz_met = pillar("authority").is_some_and(|p| p.score.is_some()) && authz_fails == 0;
    let authz_status = if authz_met {
        "met"
    } else if authz_fails > 0 {
        "unmet"
    } else {
        "warning"
    };

    let inj_fails = cell("injection").map_or(0, |c| c.fail);
    let inj_met = pillar("safety").is_some_and(|p| p.score.is_some()) && inj_fails == 0;
    let inj_status = if inj_met {
        "met"
    } else if inj_fails > 0 {
        "unmet"
    } else {
        "warning"
    };

    let checklist = vec![
        item(
            "Zero critical defects",
            evaluated && critical == 0,
            if evaluated && critical == 0 {
                "met"
            } else if critical > 0 {
                "unmet"
            } else {
                "warning"
            },
            if evaluated {
                format!("{critical} critical defect(s)")
            } else {
                "not evaluated".into()
            },
            ids(&|r| {
                r.status == "FAIL"
                    && r.oracle.as_ref().and_then(|o| o.max_fail_severity())
                        == Some(Severity::Critical)
            }),
        ),
        item(
            "No high-severity defects",
            evaluated && high == 0,
            if evaluated && high == 0 {
                "met"
            } else if high > 0 {
                "unmet"
            } else {
                "warning"
            },
            if evaluated {
                format!("{high} high-severity defect(s)")
            } else {
                "not evaluated".into()
            },
            ids(&|r| {
                r.status == "FAIL"
                    && r.oracle.as_ref().and_then(|o| o.max_fail_severity()) == Some(Severity::High)
            }),
        ),
        item(
            "Pass rate >= 85% of conclusive applicable cases",
            conclusive_n > 0 && pass_rate >= 85.0,
            if conclusive_n > 0 && pass_rate >= 85.0 {
                "met"
            } else if conclusive_n > 0 {
                "unmet"
            } else {
                "warning"
            },
            format!("{pass} of {conclusive_n} conclusive case(s) passed ({pass_rate:.0}%)"),
            ids(&|r| r.status == "PASS"),
        ),
        item(
            "Conclusive coverage >= 80% of applicable cases",
            confidence.is_some_and(|c| c >= FULL_CONFIDENCE),
            if confidence.is_some_and(|c| c >= FULL_CONFIDENCE) {
                "met"
            } else {
                "warning"
            },
            format!(
                "{conclusive_n} of {applicable_n} applicable case(s) were conclusive ({conf_text})"
            ),
            ids(&|r| matches!(r.status.as_str(), "PASS" | "WARN" | "FAIL")),
        ),
        item(
            "Authorization boundary exercised and held",
            authz_met,
            authz_status,
            pillar("authority")
                .map(|p| p.claim.clone())
                .unwrap_or_default(),
            ids(&|r| r.technique == "authz"),
        ),
        item(
            "Injection resistance exercised and held",
            inj_met,
            inj_status,
            pillar("safety")
                .map(|p| p.claim.clone())
                .unwrap_or_default(),
            ids(&|r| r.technique == "injection"),
        ),
        item(
            "No blocked or flaky cases",
            blocked == 0 && flaky == 0,
            if blocked == 0 && flaky == 0 {
                "met"
            } else {
                "warning"
            },
            format!("{blocked} blocked, {flaky} flaky"),
            ids(&|r| r.status == "BLOCKED" || r.flaky),
        ),
        item(
            "Every executed case has stored request/response evidence",
            !executed.is_empty() && repro_ok == executed.len(),
            if !executed.is_empty() && repro_ok == executed.len() {
                "met"
            } else {
                "warning"
            },
            format!("{repro_ok} of {} executed", executed.len()),
            ids(&|r| r.was_sent()),
        ),
    ];

    // 8. summary, from facts only
    let mut summary = format!(
        "Evaluated {conclusive_n} of {applicable_n} applicable cases ({total} planned, {not_applicable} not applicable, {skipped} not executed): {pass} passed, {fail} failed, {warn} warning(s), {inconclusive} inconclusive, {blocked} blocked. Confidence {conf_text}. Deterministic verdict: {computed}"
    );
    if !reasons.is_empty() {
        summary.push_str(&format!(" ({})", reasons.join("; ")));
    }
    summary.push('.');
    if !blockers.is_empty() {
        summary.push_str(" What kept evidence from being gathered: ");
        summary.push_str(
            &blockers
                .iter()
                .map(|b| {
                    format!(
                        "{}: {}. Next step: {}.",
                        blocker_label(b.reason),
                        b.detail,
                        b.next_step
                    )
                })
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if let Some(s) = inp.budget_stop {
        summary.push_str(&format!(" Run stopped early: {s}."));
    }
    let score = |id: &str| pillar(id).and_then(|p| p.score);
    EvidenceLedger {
        confidence,
        blockers,
        value_score: score("value"),
        authority_score: score("authority"),
        safety_score: score("safety"),
        evidence_score: score("evidence"),
        overall_readiness: overall,
        gate_verdict: computed.into(),
        executive_summary: summary,
        exit_criteria_checklist: checklist,
        composite_score: if evaluated { Some(overall) } else { None },
        verdict: Some(computed.into()),
        evaluated,
        computed_verdict: computed.into(),
        verdict_basis: format!(
            "computed: {}",
            if reasons.is_empty() {
                "all criteria met".to_string()
            } else {
                reasons.join("; ")
            }
        ),
        pillars,
        coverage,
        claims,
        llm_advisory: None,
        ai_summary: None,
        verification: None,
    }
}
