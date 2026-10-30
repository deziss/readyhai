//! Readiness ledger. Everything here is computed from results: a technique-coverage matrix feeds
//! four pillars, the pillars feed the verdict, and every claim cites case ids and evidence files.
//! A pillar nobody exercised is "not evaluated" (None) -- there are no default scores. The LLM may
//! add prose and an advisory opinion; the final verdict is the WORST of computed and LLM, never better.
use std::collections::BTreeMap;

use super::oracle::Severity;
use super::types::{
    CaseExecutionResult, CoverageCell, EvidenceLedger, ExitCheckItem, LedgerClaim, LlmAdvisory,
    PillarResult, TriagedDefect,
};

const TECHNIQUES: [&str; 5] = [
    "authz",
    "boundary",
    "negative",
    "injection",
    "state_transition",
];

/// (id, name, techniques, weight)
const PILLARS: [(&str, &str, &[&str], u32); 3] = [
    (
        "value",
        "Functional correctness and input handling",
        &["boundary", "negative", "state_transition"],
        30,
    ),
    (
        "authority",
        "Authorization and least privilege",
        &["authz"],
        30,
    ),
    (
        "safety",
        "Injection resistance and data safety",
        &["injection"],
        25,
    ),
];
const EVIDENCE_WEIGHT: u32 = 15;

pub struct LedgerInput<'a> {
    pub results: &'a [CaseExecutionResult],
    pub defects: &'a [TriagedDefect],
    pub dry_run: bool,
    /// Set when a budget limit cut the run short.
    pub budget_stop: Option<&'a str>,
}

fn bucket(r: &CaseExecutionResult) -> &'static str {
    match r.status.as_str() {
        "PASS" => "pass",
        "WARN" => "warn",
        "FAIL" => "fail",
        "INCONCLUSIVE" => "inconclusive",
        "BLOCKED" => "blocked",
        _ => "skipped",
    }
}

fn add(cell: &mut CoverageCell, r: &CaseExecutionResult) {
    cell.planned += 1;
    match bucket(r) {
        "pass" => cell.pass += 1,
        "warn" => cell.warn += 1,
        "fail" => cell.fail += 1,
        "inconclusive" => cell.inconclusive += 1,
        "blocked" => cell.blocked += 1,
        _ => cell.skipped += 1,
    }
    if r.flaky {
        cell.flaky += 1;
    }
    cell.case_ids.push(r.case_id.clone());
    if let Some(f) = &r.evidence_file {
        cell.evidence_files.push(f.clone());
    }
}

fn status_of(c: &CoverageCell) -> &'static str {
    let conclusive = c.pass + c.warn + c.fail;
    if conclusive == 0 {
        "not_evaluated"
    } else if c.fail > 0 {
        "fail"
    } else if c.warn + c.inconclusive + c.blocked + c.skipped > 0 {
        "partial"
    } else {
        "pass"
    }
}

fn describe(c: &CoverageCell) -> String {
    format!(
        "{}: {} passed, {} failed, {} warning(s), {} inconclusive, {} blocked, {} not executed of {} planned",
        c.technique, c.pass, c.fail, c.warn, c.inconclusive, c.blocked, c.skipped, c.planned
    )
}

fn points(c: &CoverageCell) -> f64 {
    c.pass as f64 + 0.5 * c.warn as f64
}

fn merge(cells: &[&CoverageCell]) -> CoverageCell {
    let mut m = CoverageCell::default();
    for c in cells {
        m.planned += c.planned;
        m.pass += c.pass;
        m.warn += c.warn;
        m.fail += c.fail;
        m.inconclusive += c.inconclusive;
        m.blocked += c.blocked;
        m.skipped += c.skipped;
        m.flaky += c.flaky;
        m.case_ids.extend(c.case_ids.iter().cloned());
        m.evidence_files.extend(c.evidence_files.iter().cloned());
    }
    m
}

fn rank(v: &str) -> Option<u8> {
    match v {
        "GO" => Some(0),
        "CONDITIONAL_GO" => Some(1),
        "NO_GO" => Some(2),
        _ => None,
    }
}

/// Ledger for a run that executed nothing (discovery only, rejected target...). Never carries scores.
pub fn not_evaluated(
    verdict: &str,
    summary: impl Into<String>,
    checklist: Vec<ExitCheckItem>,
) -> EvidenceLedger {
    EvidenceLedger {
        value_score: None,
        authority_score: None,
        safety_score: None,
        evidence_score: None,
        overall_readiness: 0,
        gate_verdict: verdict.to_string(),
        executive_summary: summary.into(),
        exit_criteria_checklist: checklist,
        composite_score: None,
        verdict: Some(verdict.to_string()),
        evaluated: false,
        computed_verdict: verdict.to_string(),
        verdict_basis: "no test case was executed".into(),
        pillars: vec![],
        coverage: vec![],
        claims: vec![],
        llm_advisory: None,
        ai_summary: None,
    }
}

pub fn compute(inp: &LedgerInput) -> EvidenceLedger {
    let results = inp.results;
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

    // 2. severities of failures decide caps
    let sev = |s: Severity| {
        inp.defects
            .iter()
            .filter(|d| d.severity == s.as_str())
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

    // 3. pillars
    let mut pillars: Vec<PillarResult> = vec![];
    for (id, name, techs, _) in PILLARS {
        let m = merge(&techs.iter().filter_map(|t| cell(t)).collect::<Vec<_>>());
        let conclusive = m.pass + m.warn + m.fail;
        let (score, status, claim) = if conclusive == 0 {
            (
                None,
                "not_evaluated",
                format!(
                    "not evaluated: no conclusive result for {} ({} inconclusive, {} blocked, {} not executed of {} planned)",
                    techs.join("/"),
                    m.inconclusive,
                    m.blocked,
                    m.skipped,
                    m.planned
                ),
            )
        } else {
            let mut s = (100.0 * points(&m) / m.planned as f64).round() as u32;
            match sev_of_fail(techs) {
                Some(Severity::Critical) => s = s.min(40),
                Some(Severity::High) => s = s.min(65),
                _ => {}
            }
            (Some(s), status_of(&m), describe(&m))
        };
        pillars.push(PillarResult {
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
    // evidence pillar: did every executed case leave a reproduction command and an evidence file?
    let executed: Vec<&CaseExecutionResult> =
        results.iter().filter(|r| r.status != "SKIPPED").collect();
    let repro_ok = executed
        .iter()
        .filter(|r| !r.reproduction_curl.is_empty() && r.evidence_file.is_some())
        .count();
    pillars.push(if executed.is_empty() {
        PillarResult {
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
                "{repro_ok} of {} executed cases have a reproduction command and an evidence file",
                executed.len()
            ),
            techniques: vec![],
            case_ids: executed.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: executed
                .iter()
                .filter_map(|r| r.evidence_file.clone())
                .collect(),
        }
    });

    // 4. overall: weighted over evaluated pillars; at least one functional pillar must be evaluated
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
    let functional_evaluated = pillars
        .iter()
        .filter(|p| p.id != "evidence")
        .any(|p| p.score.is_some());
    let evaluated = functional_evaluated && den > 0;
    let overall = if evaluated {
        ((num as f64) / (den as f64)).round() as u32
    } else {
        0
    };

    // 5. counts and verdict
    let n = |b: &str| results.iter().filter(|r| bucket(r) == b).count();
    let (pass, warn, fail, inconclusive, blocked, skipped) = (
        n("pass"),
        n("warn"),
        n("fail"),
        n("inconclusive"),
        n("blocked"),
        n("skipped"),
    );
    let total = results.len();
    let flaky = results.iter().filter(|r| r.flaky).count();
    let conclusive = pass + warn + fail;
    let coverage_ratio = if total == 0 {
        0.0
    } else {
        conclusive as f64 / total as f64
    };
    let unevaluated: Vec<&str> = pillars
        .iter()
        .filter(|p| p.score.is_none())
        .map(|p| p.id.as_str())
        .collect();

    let mut reasons: Vec<String> = vec![];
    let computed = if !evaluated {
        reasons.push("no pillar could be evaluated from conclusive results".into());
        "NOT_EVALUATED"
    } else if critical > 0 || overall < 70 {
        if critical > 0 {
            reasons.push(format!("{critical} critical defect(s)"));
        }
        if overall < 70 {
            reasons.push(format!("overall readiness {overall} < 70"));
        }
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
        if coverage_ratio < 0.8 {
            reasons.push(format!(
                "only {:.0}% of planned cases reached a conclusive result (need 80%)",
                coverage_ratio * 100.0
            ));
        }
        if overall < 85 {
            reasons.push(format!("overall readiness {overall} < 85"));
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
    let blocked_cases: Vec<&CaseExecutionResult> =
        results.iter().filter(|r| r.status == "BLOCKED").collect();
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
         details: String,
         (case_ids, evidence_files): (Vec<String>, Vec<String>)| ExitCheckItem {
            criterion: criterion.into(),
            met,
            details,
            case_ids,
            evidence_files,
        };
    let pillar = |id: &str| pillars.iter().find(|p| p.id == id);
    let pass_rate = if total == 0 {
        0.0
    } else {
        100.0 * pass as f64 / total as f64
    };
    let checklist = vec![
        item(
            "Zero critical defects",
            evaluated && critical == 0,
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
            "Pass rate >= 85% of planned cases",
            total > 0 && pass_rate >= 85.0,
            format!("{pass} of {total} passed ({pass_rate:.0}%)"),
            ids(&|r| r.status == "PASS"),
        ),
        item(
            "Authorization boundary exercised and held",
            pillar("authority").is_some_and(|p| p.score.is_some())
                && cell("authz").is_some_and(|c| c.fail == 0),
            pillar("authority")
                .map(|p| p.claim.clone())
                .unwrap_or_default(),
            ids(&|r| r.technique == "authz"),
        ),
        item(
            "Injection resistance exercised and held",
            pillar("safety").is_some_and(|p| p.score.is_some())
                && cell("injection").is_some_and(|c| c.fail == 0),
            pillar("safety")
                .map(|p| p.claim.clone())
                .unwrap_or_default(),
            ids(&|r| r.technique == "injection"),
        ),
        item(
            "No blocked or flaky cases",
            blocked == 0 && flaky == 0,
            format!("{blocked} blocked, {flaky} flaky"),
            ids(&|r| r.status == "BLOCKED" || r.flaky),
        ),
        item(
            "Every executed case has a reproduction command and evidence file",
            !executed.is_empty() && repro_ok == executed.len(),
            format!("{repro_ok} of {} executed", executed.len()),
            ids(&|r| r.status != "SKIPPED"),
        ),
    ];

    // 8. summary, from facts only
    let mut summary = format!(
        "Evaluated {conclusive} of {total} planned cases: {pass} passed, {fail} failed, {warn} warning(s), {inconclusive} inconclusive, {blocked} blocked, {skipped} not executed. Deterministic verdict: {computed}"
    );
    if !reasons.is_empty() {
        summary.push_str(&format!(" ({})", reasons.join("; ")));
    }
    summary.push('.');
    if let Some(s) = inp.budget_stop {
        summary.push_str(&format!(" Run stopped early: {s}."));
    }
    let score = |id: &str| pillar(id).and_then(|p| p.score);
    EvidenceLedger {
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
    }
}

fn clamp(v: i64) -> u32 {
    v.clamp(0, 100) as u32
}

/// Fold the LLM's opinion in. Scores are stored clamped to 0..=100 as advisory only; the verdict
/// becomes the worse of computed and LLM. A computed NOT_EVALUATED can never be upgraded.
pub fn apply_llm(
    l: &mut EvidenceLedger,
    verdict: Option<&str>,
    scores: [Option<i64>; 5],
    summary: Option<String>,
) {
    let adv = LlmAdvisory {
        verdict: verdict.map(|v| v.to_string()),
        overall_readiness: scores[0].map(clamp),
        value_score: scores[1].map(clamp),
        authority_score: scores[2].map(clamp),
        safety_score: scores[3].map(clamp),
        evidence_score: scores[4].map(clamp),
    };
    l.ai_summary = summary;
    let computed = l.computed_verdict.clone();
    let final_v = match (rank(&computed), verdict.and_then(rank)) {
        (Some(c), Some(a)) if a > c => {
            l.verdict_basis = format!(
                "worst-of(computed={computed}, llm={}): the LLM was stricter",
                verdict.unwrap_or("")
            );
            verdict.unwrap_or("").to_string()
        }
        (Some(_), Some(_)) => {
            l.verdict_basis = format!(
                "worst-of(computed={computed}, llm={}): computed verdict stands",
                verdict.unwrap_or("")
            );
            computed
        }
        _ => computed,
    };
    l.gate_verdict = final_v.clone();
    l.verdict = Some(final_v);
    l.llm_advisory = Some(adv);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::oracle::{OracleCheck, OracleOutcome, Verdict};

    fn res(id: &str, tech: &str, status: &str) -> CaseExecutionResult {
        let executed = status != "SKIPPED";
        CaseExecutionResult {
            case_id: id.into(),
            title: id.into(),
            component: "/x".into(),
            method: "GET".into(),
            technique: tech.into(),
            status: status.into(),
            status_code: Some(200),
            latency_ms: 1,
            reproduction_curl: "curl 'http://h/x'".into(),
            request_payload: None,
            evidence: String::new(),
            content_type: None,
            is_spa_shell: false,
            failure_reason: None,
            expected_status: None,
            oracle: if status == "FAIL" {
                Some(OracleOutcome {
                    verdict: Verdict::Fail,
                    checks: vec![OracleCheck {
                        code: "server_error".into(),
                        verdict: Verdict::Fail,
                        severity: Some(Severity::Medium),
                        detail: "d".into(),
                    }],
                    warnings: vec![],
                })
            } else {
                None
            },
            flaky: false,
            attempts: vec![],
            evidence_file: executed.then(|| format!("evidence/{id}.json")),
            evidence_detail: None,
        }
    }

    fn all_pass() -> Vec<CaseExecutionResult> {
        vec![
            res("TC-001", "state_transition", "PASS"),
            res("TC-002", "authz", "PASS"),
            res("TC-003", "injection", "PASS"),
            res("TC-004", "boundary", "PASS"),
            res("TC-005", "negative", "PASS"),
        ]
    }

    fn ledger(r: &[CaseExecutionResult], d: &[TriagedDefect], dry: bool) -> EvidenceLedger {
        compute(&LedgerInput {
            results: r,
            defects: d,
            dry_run: dry,
            budget_stop: None,
        })
    }

    #[test]
    fn nothing_evaluated_means_not_evaluated_not_a_default_score() {
        let l = ledger(&[], &[], false);
        assert_eq!(
            (l.gate_verdict.as_str(), l.overall_readiness, l.evaluated),
            ("NOT_EVALUATED", 0, false)
        );
        assert!(
            l.value_score.is_none()
                && l.authority_score.is_none()
                && l.safety_score.is_none()
                && l.evidence_score.is_none()
                && l.composite_score.is_none()
        );
        let blocked: Vec<_> = all_pass()
            .into_iter()
            .map(|mut r| {
                r.status = "BLOCKED".into();
                r
            })
            .collect();
        let l = ledger(&blocked, &[], false);
        assert_eq!(
            l.gate_verdict, "NOT_EVALUATED",
            "a dead target is not a pass"
        );
        assert!(
            l.pillars
                .iter()
                .filter(|p| p.id != "evidence")
                .all(|p| p.score.is_none() && p.status == "not_evaluated")
        );
    }

    #[test]
    fn all_pass_is_go_with_scores_from_coverage() {
        let l = ledger(&all_pass(), &[], false);
        assert_eq!((l.gate_verdict.as_str(), l.overall_readiness), ("GO", 100));
        assert_eq!(
            (
                l.value_score,
                l.authority_score,
                l.safety_score,
                l.evidence_score
            ),
            (Some(100), Some(100), Some(100), Some(100))
        );
    }

    #[test]
    fn blocked_warn_skipped_and_inconclusive_all_move_the_score() {
        let base = ledger(&all_pass(), &[], false).overall_readiness;
        for st in ["WARN", "BLOCKED", "SKIPPED", "INCONCLUSIVE"] {
            let mut r = all_pass();
            r.push(res("TC-006", "authz", st));
            let l = ledger(&r, &[], false);
            assert!(
                l.overall_readiness < base,
                "{st} must lower the score: {} !< {base}",
                l.overall_readiness
            );
            assert_ne!(l.gate_verdict, "NOT_EVALUATED");
        }
        // WARN counts for half
        let mut r = all_pass();
        r.push(res("TC-006", "authz", "WARN"));
        assert_eq!(ledger(&r, &[], false).authority_score, Some(75));
    }

    #[test]
    fn verdict_rules() {
        let mut r = all_pass();
        r.push(res("TC-006", "boundary", "FAIL"));
        let defect = |sev: &str| TriagedDefect {
            id: "DEF-001".into(),
            title: "t".into(),
            severity: sev.into(),
            priority: "P1".into(),
            component: "/x".into(),
            root_cause_hypothesis: String::new(),
            blast_radius: String::new(),
            owasp_category: String::new(),
            recommended_fix: String::new(),
            reproduction: String::new(),
            case_ids: vec!["TC-006".into()],
            evidence_files: vec![],
            ai_note: None,
        };
        assert_eq!(
            ledger(&r, &[defect("medium")], false).gate_verdict,
            "CONDITIONAL_GO"
        );
        // critical failure => NO_GO and the pillar is capped
        let mut c = all_pass();
        let mut f = res("TC-006", "authz", "FAIL");
        f.oracle.as_mut().unwrap().checks[0].severity = Some(Severity::Critical);
        c.push(f);
        let l = ledger(&c, &[defect("critical")], false);
        assert_eq!(l.gate_verdict, "NO_GO");
        assert!(l.authority_score.unwrap() <= 40);
        // dry-run with skipped mutating cases cannot be GO
        let mut d = all_pass();
        d.push(res("TC-006", "boundary", "SKIPPED"));
        assert_eq!(ledger(&d, &[], true).gate_verdict, "CONDITIONAL_GO");
        // a missing pillar caps at CONDITIONAL_GO
        let partial: Vec<_> = all_pass()
            .into_iter()
            .filter(|r| r.technique != "injection")
            .collect();
        let l = ledger(&partial, &[], false);
        assert_eq!(l.gate_verdict, "CONDITIONAL_GO");
        assert_eq!(l.safety_score, None);
        assert!(l.verdict_basis.contains("not evaluated: safety"));
        // flaky blocks GO
        let mut fl = all_pass();
        fl[0].flaky = true;
        fl[0].status = "WARN".into();
        assert_eq!(ledger(&fl, &[], false).gate_verdict, "CONDITIONAL_GO");
    }

    #[test]
    fn every_claim_cites_existing_cases_and_evidence() {
        let mut r = all_pass();
        r.push(res("TC-006", "authz", "SKIPPED"));
        r.push(res("TC-007", "injection", "BLOCKED"));
        r.push(res("TC-008", "boundary", "FAIL"));
        let l = ledger(&r, &[], false);
        let ids: Vec<&str> = r.iter().map(|x| x.case_id.as_str()).collect();
        let files: Vec<&str> = r
            .iter()
            .filter_map(|x| x.evidence_file.as_deref())
            .collect();
        assert!(!l.claims.is_empty());
        for c in &l.claims {
            assert!(
                !c.case_ids.is_empty(),
                "claim without case ids: {}",
                c.claim
            );
            assert!(
                c.case_ids.iter().all(|i| ids.contains(&i.as_str())),
                "{c:?}"
            );
            assert!(
                c.evidence_files.iter().all(|f| files.contains(&f.as_str())),
                "{c:?}"
            );
            if c.status != "not_evaluated" {
                assert!(
                    !c.evidence_files.is_empty(),
                    "evaluated claim without evidence: {}",
                    c.claim
                );
            }
        }
        for p in l.pillars.iter().filter(|p| p.score.is_some()) {
            assert!(!p.case_ids.is_empty() && !p.evidence_files.is_empty());
        }
        assert!(
            l.exit_criteria_checklist
                .iter()
                .all(|c| c.case_ids.iter().all(|i| ids.contains(&i.as_str())))
        );
        assert!(!l.executive_summary.contains("Zero cross-tenant"));
    }

    #[test]
    fn llm_is_advisory_worst_of_and_clamped() {
        let mut l = ledger(&all_pass(), &[], false);
        assert_eq!(l.gate_verdict, "GO");
        // LLM tries to inflate: nothing changes
        apply_llm(
            &mut l,
            Some("GO"),
            [Some(100), Some(999), Some(-5), Some(100), Some(100)],
            Some("fine".into()),
        );
        assert_eq!((l.gate_verdict.as_str(), l.overall_readiness), ("GO", 100));
        let a = l.llm_advisory.clone().unwrap();
        assert_eq!(
            (a.value_score, a.authority_score),
            (Some(100), Some(0)),
            "advisory scores are clamped to 0..=100"
        );
        // LLM stricter: the worse verdict wins, scores still untouched
        let mut l = ledger(&all_pass(), &[], false);
        apply_llm(
            &mut l,
            Some("NO_GO"),
            [Some(10), None, None, None, None],
            None,
        );
        assert_eq!(
            (
                l.gate_verdict.as_str(),
                l.overall_readiness,
                l.computed_verdict.as_str()
            ),
            ("NO_GO", 100, "GO")
        );
        assert!(l.verdict_basis.contains("worst-of"));
        // computed worse than LLM: computed stands
        let mut r = all_pass();
        r.push(res("TC-006", "boundary", "FAIL"));
        let mut l = ledger(&r, &[], false);
        let comp = l.computed_verdict.clone();
        apply_llm(&mut l, Some("GO"), [Some(100); 5], None);
        assert_eq!(l.gate_verdict, comp);
        // NOT_EVALUATED is final
        let mut l = ledger(&[], &[], false);
        apply_llm(&mut l, Some("GO"), [Some(100); 5], None);
        assert_eq!(l.gate_verdict, "NOT_EVALUATED");
        // unknown verdict strings are ignored
        let mut l = ledger(&all_pass(), &[], false);
        apply_llm(&mut l, Some("YOLO"), [None; 5], None);
        assert_eq!(l.gate_verdict, "GO");
    }
}
