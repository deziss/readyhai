//! Readiness ledger. Everything here is computed from results: a technique-coverage matrix feeds
//! four pillars, the pillars feed the verdict, and every claim cites case ids and evidence files.
//! A pillar nobody exercised is "not evaluated" (None) -- there are no default scores. The LLM may
//! add prose and an advisory opinion, which is stored next to the verdict and never changes it: the
//! gate is the deterministic one. LLM-proposed (exploratory) cases are listed but not scored unless a
//! deterministic oracle failed them.
use std::collections::BTreeMap;

use super::exec::NEXT_STEP_AUTH_WALL;
use super::oracle::Severity;
use super::types::{
    BlockReason, Blocker, CaseExecutionResult, CoverageCell, EvidenceLedger, ExitCheckItem,
    LedgerClaim, LlmAdvisory, PillarResult, TriagedDefect, VerificationSummary, evidence_share,
};

const TECHNIQUES: [&str; 5] = [
    "authz",
    "boundary",
    "negative",
    "injection",
    "state_transition",
];

/// The techniques that need an input surface to exercise (see `plan::baseline`).
const INPUT_TECHNIQUES: [&str; 3] = ["boundary", "negative", "injection"];

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
/// A pillar is scored only when at least this share (percent) of its applicable cases was conclusive.
const MIN_PILLAR_CONFIDENCE: u32 = 50;
/// Below this overall confidence (percent) the run did not gather enough evidence to say GO or NO_GO.
const MIN_OVERALL_CONFIDENCE: u32 = 50;
/// The conclusive share (percent) a GO needs.
const FULL_CONFIDENCE: u32 = 80;

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
        "NOT_APPLICABLE" => "not_applicable",
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
        "not_applicable" => cell.not_applicable += 1,
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

/// Cases that gave an answer the oracle could judge: pass + warn + fail.
fn conclusive(c: &CoverageCell) -> usize {
    c.pass + c.warn + c.fail
}

/// Cases that could have gained evidence: planned, minus not applicable, minus not executed.
fn applicable(c: &CoverageCell) -> usize {
    c.planned.saturating_sub(c.not_applicable + c.skipped)
}

/// Conclusive share of the applicable cases, in whole percent (rounded down: 49.6% is not 50%).
/// None when nothing was applicable.
fn confidence_pct(conclusive: usize, applicable: usize) -> Option<u32> {
    (applicable > 0).then(|| (conclusive * 100 / applicable) as u32)
}

fn status_of(c: &CoverageCell) -> &'static str {
    if conclusive(c) == 0 {
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
    let na = if c.not_applicable > 0 {
        format!(", {} not applicable", c.not_applicable)
    } else {
        String::new()
    };
    format!(
        "{}: {} passed, {} failed, {} warning(s), {} inconclusive, {} blocked, {} not executed{na} of {} planned",
        c.technique, c.pass, c.fail, c.warn, c.inconclusive, c.blocked, c.skipped, c.planned
    )
}

fn points(c: &CoverageCell) -> f64 {
    c.pass as f64 + 0.5 * c.warn as f64
}

/// The cells of several techniques as one. `technique` labels it (`describe` starts with it).
fn merge(technique: &str, cells: &[&CoverageCell]) -> CoverageCell {
    let mut m = CoverageCell {
        technique: technique.to_string(),
        ..Default::default()
    };
    for c in cells {
        m.planned += c.planned;
        m.pass += c.pass;
        m.warn += c.warn;
        m.fail += c.fail;
        m.inconclusive += c.inconclusive;
        m.blocked += c.blocked;
        m.skipped += c.skipped;
        m.flaky += c.flaky;
        m.not_applicable += c.not_applicable;
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
        confidence: None,
        blockers: vec![],
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
        verification: None,
    }
}

/// An LLM-proposed case that no deterministic oracle failed: its outcome is not evidence either
/// way (a PASS against an LLM-written expectation proves nothing), so it is not scored.
fn is_unconfirmed_exploratory(r: &CaseExecutionResult) -> bool {
    r.status != "FAIL" && r.oracle.as_ref().is_some_and(|o| o.exploratory)
}

/// Whether a defect counts toward the gate. The verifier decides which failures are real:
/// * no verification data (an older run, verification off): counts, as before the verifier existed;
/// * confirmed (every replay reproduced it): counts;
/// * flaky: counts when high/critical (a flaky Medium/Low is a WARN and never reaches the gate as a
///   defect);
/// * unverified (not replayable: a write on a real record, a burst, a stopped budget): counts when
///   high/critical. A failure the verifier could not examine is not evidence that it is gone, so it
///   is never allowed to soften the gate; it is listed as unverified for a person to confirm.
///
/// A failure that did not reproduce is INCONCLUSIVE and is not a defect at all.
pub fn is_blocking(d: &TriagedDefect) -> bool {
    if d.accepted.is_some() {
        return false; // an unexpired acceptance (memory): listed, not blocking
    }
    let severe = matches!(d.severity.as_str(), "critical" | "high");
    match d.verification.as_deref() {
        Some("flaky") | Some("unverified") => severe,
        _ => true,
    }
}

/// The ledger of a run. A defect that carries an unexpired acceptance (`TriagedDefect::accepted`,
/// set from the agent's memory by an explicit operator decision) does not block: its failing cases
/// are run and listed but not scored, like unconfirmed exploratory cases, and the verdict basis says
/// what the computed verdict would be without the acceptance. Nothing else in a run is waived.
pub fn compute(inp: &LedgerInput) -> EvidenceLedger {
    let waived: Vec<&TriagedDefect> = inp
        .defects
        .iter()
        .filter(|d| d.accepted.is_some())
        .collect();
    if waived.is_empty() {
        return compute_scored(inp);
    }
    let waived_cases: std::collections::BTreeSet<&str> = waived
        .iter()
        .flat_map(|d| d.case_ids.iter().map(String::as_str))
        .collect();
    let kept: Vec<CaseExecutionResult> = inp
        .results
        .iter()
        .filter(|r| !(r.status == "FAIL" && waived_cases.contains(r.case_id.as_str())))
        .cloned()
        .collect();
    let live: Vec<TriagedDefect> = inp
        .defects
        .iter()
        .filter(|d| d.accepted.is_none())
        .cloned()
        .collect();
    let mut l = compute_scored(&LedgerInput {
        results: &kept,
        defects: &live,
        dry_run: inp.dry_run,
        budget_stop: inp.budget_stop,
    });
    let unwaived: Vec<TriagedDefect> = inp
        .defects
        .iter()
        .map(|d| TriagedDefect {
            accepted: None,
            ..d.clone()
        })
        .collect();
    let without = compute_scored(&LedgerInput {
        results: inp.results,
        defects: &unwaived,
        dry_run: inp.dry_run,
        budget_stop: inp.budget_stop,
    })
    .computed_verdict;
    for d in &waived {
        let a = d.accepted.as_ref();
        l.claims.push(LedgerClaim {
            claim: format!(
                "{} [{}] {} is accepted by {} until {} ({}): it does not block the gate and its failing case(s) are not scored",
                d.id,
                d.severity,
                d.title,
                a.map(|a| a.by.as_str()).unwrap_or("?"),
                a.map(|a| a.expires.as_str()).unwrap_or("?"),
                a.map(|a| a.reason.as_str()).unwrap_or("")
            ),
            status: "partial".into(),
            case_ids: d.case_ids.clone(),
            evidence_files: d.evidence_files.clone(),
        });
    }
    let note = format!(
        "{} defect(s) covered by an unexpired acceptance do not block; without the acceptance the computed verdict would be {without}",
        waived.len()
    );
    l.verdict_basis = format!("{}; {note}", l.verdict_basis);
    l.executive_summary.push_str(&format!(" {note}."));
    l
}

/// What kept evidence from being gathered, and what to do about it: from the results themselves.
fn blockers_of(results: &[CaseExecutionResult], coverage: &[CoverageCell]) -> Vec<Blocker> {
    let ids = |f: &dyn Fn(&CaseExecutionResult) -> bool| -> Vec<String> {
        results
            .iter()
            .filter(|r| f(r))
            .map(|r| r.case_id.clone())
            .collect()
    };
    let mut out = vec![];
    let wall = ids(&|r| r.blocked_reason == Some(BlockReason::AuthWall));
    if !wall.is_empty() {
        out.push(Blocker {
            reason: BlockReason::AuthWall,
            detail: format!(
                "{} case(s) ran into a login wall (HTTP 401, a redirect to a login page or a password form) with no credential, so what sits behind the login was not tested",
                wall.len()
            ),
            next_step: NEXT_STEP_AUTH_WALL.to_string(),
            case_ids: wall,
        });
    }
    let input: Vec<&CoverageCell> = coverage
        .iter()
        .filter(|c| INPUT_TECHNIQUES.contains(&c.technique.as_str()))
        .collect();
    let (input_planned, input_na): (usize, usize) = input
        .iter()
        .fold((0, 0), |(p, n), c| (p + c.planned, n + c.not_applicable));
    if input_na > 0 && input_na * 2 >= input_planned {
        out.push(Blocker {
            reason: BlockReason::NoSurface,
            detail: format!(
                "no input surface (query parameters, forms or API endpoints) was found for the injection, boundary and negative tests: {input_na} of {input_planned} such case(s) are not applicable, so those techniques were not exercised"
            ),
            next_step: "provide the OpenAPI spec (the spec URL of the run, e.g. /openapi.json) or use the deep profile so that API endpoints and forms are discovered, then re-run".into(),
            case_ids: ids(&|r| {
                r.status == "NOT_APPLICABLE" && r.blocked_reason == Some(BlockReason::NoSurface)
            }),
        });
    }
    let transport = ids(&|r| {
        r.status == "BLOCKED"
            && (r.blocked_reason == Some(BlockReason::Transport)
                || (r.blocked_reason.is_none()
                    && r.failure_reason
                        .as_deref()
                        .is_some_and(|f| f.starts_with("Connection error"))))
    });
    if !transport.is_empty() {
        out.push(Blocker {
            reason: BlockReason::Transport,
            detail: format!(
                "{} case(s) got no HTTP answer from the target (connection error or timeout)",
                transport.len()
            ),
            next_step: "check that the target is reachable from where ReadyHai runs (DNS, network, TLS certificate, firewall), then re-run".into(),
            case_ids: transport,
        });
    }
    let scope = ids(&|r| r.blocked_reason == Some(BlockReason::OutOfScope));
    if !scope.is_empty() {
        out.push(Blocker {
            reason: BlockReason::OutOfScope,
            detail: format!(
                "{} case(s) would have left the allowed scope and were not sent",
                scope.len()
            ),
            next_step: "add the host to scope.toml if it is yours to test, then re-run".into(),
            case_ids: scope,
        });
    }
    out
}

fn blocker_label(r: BlockReason) -> &'static str {
    match r {
        BlockReason::AuthWall => "auth wall",
        BlockReason::OutOfScope => "out of scope",
        BlockReason::NoSurface => "no input surface",
        BlockReason::Transport => "target not reachable",
    }
}

fn compute_scored(inp: &LedgerInput) -> EvidenceLedger {
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
         details: String,
         (case_ids, evidence_files): (Vec<String>, Vec<String>)| ExitCheckItem {
            criterion: criterion.into(),
            met,
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
            "Pass rate >= 85% of conclusive applicable cases",
            conclusive_n > 0 && pass_rate >= 85.0,
            format!("{pass} of {conclusive_n} conclusive case(s) passed ({pass_rate:.0}%)"),
            ids(&|r| r.status == "PASS"),
        ),
        item(
            "Conclusive coverage >= 80% of applicable cases",
            confidence.is_some_and(|c| c >= FULL_CONFIDENCE),
            format!(
                "{conclusive_n} of {applicable_n} applicable case(s) were conclusive ({conf_text})"
            ),
            ids(&|r| matches!(r.status.as_str(), "PASS" | "WARN" | "FAIL")),
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
            "Every executed case has stored request/response evidence",
            !executed.is_empty() && repro_ok == executed.len(),
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

/// Record what the independent verifier did: the summary (with pass^k) on the ledger, one claim that
/// cites every verified case and its evidence file, and a sentence in the executive summary. The gate
/// itself was computed from the defects' verification status (`is_blocking`) and is not changed here.
pub fn attach_verification(
    l: &mut EvidenceLedger,
    v: VerificationSummary,
    defects: &[TriagedDefect],
) {
    let text = if v.k == 0 {
        "Verification: off (READYHAI_VERIFY_K=0); failures were not replayed".to_string()
    } else if v.candidates == 0 {
        format!("Verification (k={}): no failed case needed replaying", v.k)
    } else {
        let mut t = format!(
            "Verification (k={}): {} of {} failed case(s) fully replayed: {} confirmed, {} flaky, {} not reproduced (INCONCLUSIVE, not defects); {} unverified; pass^{} {}",
            v.k,
            v.replayed,
            v.candidates,
            v.confirmed,
            v.flaky,
            v.not_reproduced,
            v.unverified,
            v.k,
            v.pass_k_text()
        );
        if let Some(s) = &v.stopped {
            t.push_str(&format!("; stopped: {s}"));
        }
        t
    };
    let unverified_severe = defects
        .iter()
        .filter(|d| d.verification.as_deref() == Some("unverified") && is_blocking(d))
        .count();
    if v.k > 0 && v.candidates > 0 {
        l.claims.push(LedgerClaim {
            claim: text.clone(),
            status: if v.unverified == 0 && v.flaky == 0 && v.not_reproduced == 0 {
                "pass"
            } else {
                "partial"
            }
            .into(),
            case_ids: v.records.iter().map(|r| r.case_id.clone()).collect(),
            evidence_files: v
                .records
                .iter()
                .filter_map(|r| r.evidence_file.clone())
                .collect(),
        });
    }
    l.executive_summary.push_str(&format!(" {text}."));
    if unverified_severe > 0 {
        l.verdict_basis.push_str(&format!(
            "; {unverified_severe} unverified high/critical defect(s) kept as blocking (not replayable, a person must confirm them)"
        ));
    }
    l.verification = Some(v);
}

fn clamp(v: i64) -> u32 {
    v.clamp(0, 100) as u32
}

/// Record the LLM's opinion. It is advisory and stored in `llm_advisory` (scores clamped to
/// 0..=100); it never changes `gate_verdict`, `verdict` or any computed score: the gate is the
/// deterministic verdict, whatever the model says, stricter or softer.
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
    // the gate is, by construction, the computed verdict
    l.gate_verdict = computed.clone();
    l.verdict = Some(computed.clone());
    if let (Some(v), Some(a), Some(c)) = (verdict, verdict.and_then(rank), rank(&computed)) {
        let rel = match a.cmp(&c) {
            std::cmp::Ordering::Greater => "stricter than",
            std::cmp::Ordering::Equal => "the same as",
            std::cmp::Ordering::Less => "softer than",
        };
        l.verdict_basis = format!(
            "{}; LLM advisory verdict {v} ({rel} the computed {computed}) is recorded separately and does not change the gate",
            l.verdict_basis
        );
    }
    l.llm_advisory = Some(adv);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::oracle::{OracleCheck, OracleOutcome, Verdict};
    use crate::agent::types::BlockReason;

    fn res(id: &str, tech: &str, status: &str) -> CaseExecutionResult {
        let executed = status != "SKIPPED";
        CaseExecutionResult {
            blocked_reason: None,
            redirect_chain: vec![],
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
                    exploratory: false,
                })
            } else {
                None
            },
            flaky: false,
            attempts: vec![],
            evidence_file: executed.then(|| format!("evidence/{id}.json")),
            evidence_detail: None,
            stateful_chain: None,
            concurrency_burst_results: None,
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
    fn evidence_pillar_is_the_share_of_cases_with_stored_evidence() {
        // 5 executed cases, 2 of them without a stored request/response pair: the pillar is 60,
        // not 100, even though every case has a reproduction command.
        let mut r = all_pass();
        r[1].evidence_file = None; // evidence file never written
        r[3].status_code = None; // target never answered (transport error)
        assert!(r.iter().all(|x| !x.reproduction_curl.is_empty()));
        let l = ledger(&r, &[], false);
        let p = l.pillars.iter().find(|p| p.id == "evidence").unwrap();
        assert_eq!((p.score, p.status.as_str()), (Some(60), "partial"));
        assert!(p.claim.starts_with("3 of 5 executed cases"), "{}", p.claim);
        assert_eq!(p.evidence_files.len(), 3, "only stored evidence is cited");
        assert_eq!(l.evidence_score, Some(60));
        assert!(l.evidence_score.unwrap() < 100);
        // the exit check agrees
        assert!(
            l.exit_criteria_checklist
                .iter()
                .any(|c| c.criterion.contains("stored request/response evidence") && !c.met),
            "{:?}",
            l.exit_criteria_checklist
        );
        // skipped cases are not executed and do not count against the share
        let mut r = all_pass();
        r.push(res("TC-006", "authz", "SKIPPED"));
        assert_eq!(ledger(&r, &[], false).evidence_score, Some(100));
    }

    #[test]
    fn a_warning_lowers_the_score_and_missing_evidence_lowers_the_confidence() {
        let base = ledger(&all_pass(), &[], false);
        assert_eq!((base.confidence, base.overall_readiness), (Some(100), 100));
        // WARN counts for half
        let mut r = all_pass();
        r.push(res("TC-006", "authz", "WARN"));
        let l = ledger(&r, &[], false);
        assert_eq!(l.authority_score, Some(75));
        assert!(l.overall_readiness < base.overall_readiness);
        // an inconclusive, blocked or not executed case is no failure: the score is over the
        // conclusive cases. The confidence says how much of the picture is missing.
        for (st, conf) in [("INCONCLUSIVE", 83), ("BLOCKED", 83), ("SKIPPED", 100)] {
            let mut r = all_pass();
            r.push(res("TC-006", "authz", st));
            let l = ledger(&r, &[], false);
            assert_eq!(l.authority_score, Some(100), "{st}");
            assert_eq!(l.confidence, Some(conf), "{st}");
            assert_ne!(l.gate_verdict, "NOT_EVALUATED", "{st}");
        }
        // ... and the pillar shows its own confidence
        let mut r = all_pass();
        r.push(res("TC-006", "authz", "INCONCLUSIVE"));
        let l = ledger(&r, &[], false);
        let a = l.pillars.iter().find(|p| p.id == "authority").unwrap();
        assert_eq!((a.score, a.confidence), (Some(100), Some(50)));
        // a blocked case keeps the gate from GO
        let mut r = all_pass();
        r.push(res("TC-006", "authz", "BLOCKED"));
        assert_eq!(ledger(&r, &[], false).gate_verdict, "CONDITIONAL_GO");
    }

    fn blocked_by(id: &str, tech: &str, why: BlockReason) -> CaseExecutionResult {
        let mut r = res(id, tech, "BLOCKED");
        r.blocked_reason = Some(why);
        if why != BlockReason::Transport {
            r.status_code = None;
            r.evidence_file = None; // a ledger-only row: nothing was sent
        }
        r
    }

    fn not_applicable(id: &str, tech: &str) -> CaseExecutionResult {
        let mut r = res(id, tech, "NOT_APPLICABLE");
        r.status_code = None;
        r.evidence_file = None;
        r.blocked_reason = Some(BlockReason::NoSurface);
        r
    }

    #[test]
    fn a_pillar_is_scored_on_conclusive_cases_and_only_when_it_is_confident_enough() {
        // 3 conclusive of 6 applicable: 50% confidence, scored over the 3 that answered
        let mut r: Vec<CaseExecutionResult> = (1..=3)
            .map(|i| res(&format!("TC-{i:03}"), "injection", "PASS"))
            .collect();
        r.extend((4..=6).map(|i| res(&format!("TC-{i:03}"), "injection", "INCONCLUSIVE")));
        let l = ledger(&r, &[], false);
        let p = l.pillars.iter().find(|p| p.id == "safety").unwrap();
        assert_eq!(
            (p.score, p.confidence),
            (Some(100), Some(50)),
            "{}",
            p.claim
        );
        // 2 of 6: 33%, below the minimum: not scored, and the claim says why
        let mut r: Vec<CaseExecutionResult> = (1..=2)
            .map(|i| res(&format!("TC-{i:03}"), "injection", "PASS"))
            .collect();
        r.extend((3..=6).map(|i| res(&format!("TC-{i:03}"), "injection", "INCONCLUSIVE")));
        let l = ledger(&r, &[], false);
        let p = l.pillars.iter().find(|p| p.id == "safety").unwrap();
        assert_eq!(
            (p.score, p.confidence, p.status.as_str()),
            (None, Some(33), "not_evaluated")
        );
        assert!(
            p.claim.contains("only 2 of 6 applicable") && p.claim.contains("33%"),
            "{}",
            p.claim
        );
        assert_eq!(l.safety_score, None);
        // pass and warn over the conclusive ones: (pass + 0.5 warn) / conclusive
        let r = vec![
            res("TC-001", "authz", "PASS"),
            res("TC-002", "authz", "PASS"),
            res("TC-003", "authz", "WARN"),
            res("TC-004", "authz", "INCONCLUSIVE"),
        ];
        let l = ledger(&r, &[], false);
        assert_eq!(l.authority_score, Some(83), "(2 + 0.5) / 3");
    }

    #[test]
    fn not_applicable_cases_are_in_no_denominator() {
        let mut r = all_pass();
        r.extend([
            not_applicable("TC-006", "injection"),
            not_applicable("TC-007", "boundary"),
            not_applicable("TC-008", "negative"),
        ]);
        let l = ledger(&r, &[], false);
        // same scores, same confidence, same verdict as without the rows
        let base = ledger(&all_pass(), &[], false);
        assert_eq!(
            (
                l.value_score,
                l.authority_score,
                l.safety_score,
                l.evidence_score,
                l.confidence,
                l.overall_readiness,
                l.gate_verdict.as_str()
            ),
            (
                base.value_score,
                base.authority_score,
                base.safety_score,
                base.evidence_score,
                base.confidence,
                base.overall_readiness,
                base.gate_verdict.as_str()
            )
        );
        // the matrix shows them, in the cell of their technique
        let inj = l
            .coverage
            .iter()
            .find(|c| c.technique == "injection")
            .unwrap();
        assert_eq!((inj.planned, inj.not_applicable, inj.pass), (2, 1, 1));
        // the evidence pillar counts what was sent only
        let ev = l.pillars.iter().find(|p| p.id == "evidence").unwrap();
        assert_eq!(ev.score, Some(100), "{}", ev.claim);
        assert!(
            l.exit_criteria_checklist
                .iter()
                .find(|c| c.criterion.starts_with("Every executed case"))
                .unwrap()
                .met
        );
        // a pillar with nothing but not applicable cases is not evaluated: absence of a found
        // surface is not a pass, and the verdict cannot be GO
        let only_na = vec![
            res("TC-001", "state_transition", "PASS"),
            res("TC-002", "authz", "PASS"),
            not_applicable("TC-003", "injection"),
        ];
        let l = ledger(&only_na, &[], false);
        assert_eq!(l.safety_score, None);
        assert_eq!(l.gate_verdict, "CONDITIONAL_GO");
        assert!(l.verdict_basis.contains("not evaluated: safety"));
        // the claim cites the not applicable rows
        assert!(
            l.claims
                .iter()
                .any(|c| c.claim.contains("not applicable") && c.case_ids == ["TC-003"])
        );
    }

    /// The NuHire run: 18 cases, 3 gave a result, 15 were inconclusive. Not one of them was a
    /// defect of the app.
    #[test]
    fn mostly_inconclusive_is_not_evaluated_never_no_go() {
        let mut r: Vec<CaseExecutionResult> = vec![
            res("TC-001", "authz", "PASS"),
            res("TC-002", "authz", "PASS"),
            res("TC-003", "state_transition", "PASS"),
        ];
        let techs = [
            "injection",
            "boundary",
            "negative",
            "authz",
            "state_transition",
        ];
        for i in 4..=18 {
            r.push(res(&format!("TC-{i:03}"), techs[i % 5], "INCONCLUSIVE"));
        }
        let l = ledger(&r, &[], false);
        assert_eq!(l.gate_verdict, "NOT_EVALUATED", "{}", l.verdict_basis);
        assert_eq!(l.confidence, Some(16), "3 of 18");
        assert!(!l.evaluated);
        assert_eq!((l.composite_score, l.overall_readiness), (None, 0));
        assert!(
            l.verdict_basis.contains("insufficient evidence"),
            "{}",
            l.verdict_basis
        );
        assert!(
            l.executive_summary.contains("Confidence 16%"),
            "{}",
            l.executive_summary
        );
        // the same run with the cases that did answer failing for real is a different story
        let mut r2 = r.clone();
        r2[0].status = "FAIL".into();
        r2[0].oracle = res("x", "authz", "FAIL").oracle;
        r2[0].oracle.as_mut().unwrap().checks[0].severity = Some(Severity::Critical);
        let l = ledger(&r2, &[defect_with("critical", None)], false);
        assert_eq!(
            l.gate_verdict, "NO_GO",
            "a proven critical defect is never hidden behind low coverage"
        );
        assert!(l.verdict_basis.contains("critical"), "{}", l.verdict_basis);
    }

    #[test]
    fn a_proven_failure_with_enough_evidence_is_no_go_and_a_low_score_on_confident_pillars_too() {
        // real critical failure
        let mut c = all_pass();
        let mut f = res("TC-006", "authz", "FAIL");
        f.oracle.as_mut().unwrap().checks[0].severity = Some(Severity::Critical);
        c.push(f);
        let l = ledger(&c, &[defect_with("critical", None)], false);
        assert_eq!(l.gate_verdict, "NO_GO");
        assert!(l.evaluated && l.authority_score.unwrap() <= 40);
        assert_eq!(l.confidence, Some(100));
        // many medium failures: conclusive, confident, and below 70
        let mut r: Vec<CaseExecutionResult> = vec![];
        for i in 1..=10 {
            r.push(res(
                &format!("TC-{i:03}"),
                "boundary",
                if i <= 6 { "FAIL" } else { "PASS" },
            ));
        }
        let l = ledger(&r, &[], false);
        assert_eq!(l.gate_verdict, "NO_GO", "{}", l.verdict_basis);
        assert!(l.verdict_basis.contains("< 70"), "{}", l.verdict_basis);
    }

    #[test]
    fn the_blockers_say_what_stopped_the_evidence_and_what_to_provide() {
        let mut r = all_pass();
        r.push(blocked_by("TC-006", "injection", BlockReason::AuthWall));
        r.push(blocked_by("TC-007", "boundary", BlockReason::AuthWall));
        let l = ledger(&r, &[], false);
        let b = l
            .blockers
            .iter()
            .find(|b| b.reason == BlockReason::AuthWall)
            .expect("auth wall blocker");
        assert_eq!(b.case_ids, ["TC-006", "TC-007"]);
        assert!(b.detail.contains("2 case(s)") && b.detail.contains("login"));
        assert!(
            b.next_step.contains("roles init") && b.next_step.contains("RH_<ROLE>_TOKEN"),
            "{}",
            b.next_step
        );
        assert!(
            l.executive_summary.contains("auth wall") && l.executive_summary.contains("Next step"),
            "{}",
            l.executive_summary
        );
        // no input surface: most of the input techniques are not applicable
        let mut r = vec![
            res("TC-001", "state_transition", "PASS"),
            res("TC-002", "authz", "PASS"),
        ];
        r.extend(
            ["injection", "boundary", "negative"]
                .iter()
                .enumerate()
                .map(|(i, t)| not_applicable(&format!("TC-{:03}", 3 + i), t)),
        );
        let l = ledger(&r, &[], false);
        let b = l
            .blockers
            .iter()
            .find(|b| b.reason == BlockReason::NoSurface)
            .expect("no surface blocker");
        assert_eq!(b.case_ids.len(), 3);
        assert!(b.next_step.contains("spec"), "{}", b.next_step);
        assert!(l.blockers.iter().all(|b| b.reason != BlockReason::AuthWall));
        // transport
        let mut r = all_pass();
        r.push(blocked_by("TC-006", "authz", BlockReason::Transport));
        let l = ledger(&r, &[], false);
        assert!(
            l.blockers
                .iter()
                .any(|b| b.reason == BlockReason::Transport && b.next_step.contains("reachable"))
        );
        // a clean run has none
        assert!(ledger(&all_pass(), &[], false).blockers.is_empty());
    }

    #[test]
    fn an_app_behind_a_login_is_not_evaluated_with_an_auth_wall_blocker() {
        // the entry redirects to a login, nothing else is reachable: the sensitive-file probes
        // answer and the rest is blocked by the wall
        let r = vec![
            blocked_by("TC-001", "state_transition", BlockReason::AuthWall),
            res("TC-002", "authz", "PASS"),
            res("TC-003", "authz", "PASS"),
            blocked_by("TC-004", "injection", BlockReason::AuthWall),
            blocked_by("TC-005", "boundary", BlockReason::AuthWall),
            blocked_by("TC-006", "negative", BlockReason::AuthWall),
        ];
        let l = ledger(&r, &[], false);
        assert_eq!(l.gate_verdict, "NOT_EVALUATED", "{}", l.verdict_basis);
        assert_eq!(l.confidence, Some(33));
        assert!(
            l.blockers
                .iter()
                .any(|b| b.reason == BlockReason::AuthWall && b.case_ids.len() == 4)
        );
    }

    /// spa-next without test accounts: the hygiene probes conclude (that is 55% of the cases) but
    /// nothing says anything about the app behind the login.
    #[test]
    fn hygiene_that_holds_whatever_the_app_does_is_not_a_verdict_behind_a_login_wall() {
        let r = vec![
            blocked_by("TC-001", "state_transition", BlockReason::AuthWall),
            res("TC-002", "authz", "PASS"), // /.env is the shell
            res("TC-003", "authz", "PASS"), // /.git/config is the shell
            res("TC-004", "authz", "PASS"), // forged token on /api/orders: 401
            res("TC-005", "authz", "PASS"), // forged token on /api/profile: 401
            blocked_by("TC-006", "injection", BlockReason::AuthWall),
            blocked_by("TC-007", "boundary", BlockReason::AuthWall),
            blocked_by("TC-008", "negative", BlockReason::AuthWall),
            res("TC-009", "state_transition", "PASS"), // a catch-all page loads
        ];
        let l = ledger(&r, &[], false);
        assert_eq!(l.confidence, Some(55), "5 of 9");
        assert_eq!(
            l.authority_score,
            Some(100),
            "the pillar is scored, and shown"
        );
        assert_eq!((l.value_score, l.safety_score), (None, None));
        assert_eq!(l.gate_verdict, "NOT_EVALUATED", "{}", l.verdict_basis);
        assert!(
            l.verdict_basis.contains("behind a login wall"),
            "{}",
            l.verdict_basis
        );
        assert!(l.blockers.iter().any(|b| b.reason == BlockReason::AuthWall));
        // the same run once the wall was passed for some of the app: scored, a gate verdict
        let mut r2 = r.clone();
        for (i, t) in [(0, "state_transition"), (6, "boundary"), (7, "negative")] {
            r2[i] = res(&format!("TC-{:03}", i + 1), t, "PASS");
        }
        let l = ledger(&r2, &[], false);
        assert_ne!(l.gate_verdict, "NOT_EVALUATED", "{}", l.verdict_basis);
    }

    #[test]
    fn the_pass_rate_is_over_conclusive_cases_and_coverage_is_a_criterion_of_its_own() {
        let crit = |l: &EvidenceLedger, name: &str| {
            l.exit_criteria_checklist
                .iter()
                .find(|c| c.criterion.starts_with(name))
                .unwrap_or_else(|| panic!("no criterion {name}"))
                .clone()
        };
        // 9 pass, 1 inconclusive, 2 not applicable: pass rate 100% of the 9 conclusive, coverage 90%
        let mut r: Vec<CaseExecutionResult> = (1..=9)
            .map(|i| res(&format!("TC-{i:03}"), "boundary", "PASS"))
            .collect();
        r.push(res("TC-010", "boundary", "INCONCLUSIVE"));
        r.push(not_applicable("TC-011", "injection"));
        r.push(not_applicable("TC-012", "negative"));
        let l = ledger(&r, &[], false);
        let pass = crit(&l, "Pass rate");
        assert!(pass.met, "{}", pass.details);
        assert!(pass.criterion.contains("conclusive applicable"));
        assert!(pass.details.contains("9 of 9"), "{}", pass.details);
        let cov = crit(&l, "Conclusive coverage >= 80%");
        assert!(cov.met, "{}", cov.details);
        assert!(cov.details.contains("9 of 10"), "{}", cov.details);
        // 6 conclusive of 10 applicable: 60% < 80%, and the verdict says so
        let mut r: Vec<CaseExecutionResult> = (1..=6)
            .map(|i| res(&format!("TC-{i:03}"), "boundary", "PASS"))
            .collect();
        r.extend((7..=10).map(|i| res(&format!("TC-{i:03}"), "boundary", "INCONCLUSIVE")));
        let l = ledger(&r, &[], false);
        assert!(!crit(&l, "Conclusive coverage >= 80%").met);
        assert!(crit(&l, "Pass rate").met, "100% of what was conclusive");
        assert_eq!(l.gate_verdict, "CONDITIONAL_GO");
        assert!(l.verdict_basis.contains("need 80%"), "{}", l.verdict_basis);
    }

    #[test]
    fn a_pillar_claim_names_its_techniques() {
        // the merged cell carried no technique, so the claim began with ": 2 passed"
        let l = ledger(&all_pass(), &[], false);
        for p in l.pillars.iter().filter(|p| p.id != "evidence") {
            assert!(
                !p.claim.starts_with(':') && p.claim.starts_with(&p.techniques.join("/")),
                "{}: {}",
                p.id,
                p.claim
            );
        }
        let v = l.pillars.iter().find(|p| p.id == "value").unwrap();
        assert!(
            v.claim
                .starts_with("boundary/negative/state_transition: 3 passed"),
            "{}",
            v.claim
        );
        let m = merge("a/b", &[]);
        assert_eq!(m.technique, "a/b");
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
            remediation_patch: None,
            remediation_explanation: None,
            reproduction_script: None,
            ..Default::default()
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
    fn llm_opinion_is_recorded_separately_and_never_moves_the_gate() {
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
        // LLM stricter: the opinion is stored, the gate stays the deterministic one
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
                l.verdict.as_deref(),
                l.overall_readiness,
                l.computed_verdict.as_str()
            ),
            ("GO", Some("GO"), 100, "GO")
        );
        assert_eq!(
            l.llm_advisory.as_ref().unwrap().verdict.as_deref(),
            Some("NO_GO"),
            "the opinion is kept next to the verdict"
        );
        assert!(
            l.verdict_basis.contains("recorded separately")
                && l.verdict_basis.contains("stricter than")
        );
        // computed worse than LLM: computed stands
        let mut r = all_pass();
        r.push(res("TC-006", "boundary", "FAIL"));
        let mut l = ledger(&r, &[], false);
        let comp = l.computed_verdict.clone();
        apply_llm(&mut l, Some("GO"), [Some(100); 5], None);
        assert_eq!(l.gate_verdict, comp);
        assert!(l.verdict_basis.contains("softer than"));
        // NOT_EVALUATED is final
        let mut l = ledger(&[], &[], false);
        apply_llm(&mut l, Some("GO"), [Some(100); 5], None);
        assert_eq!(l.gate_verdict, "NOT_EVALUATED");
        // unknown verdict strings are ignored
        let mut l = ledger(&all_pass(), &[], false);
        apply_llm(&mut l, Some("YOLO"), [None; 5], None);
        assert_eq!(l.gate_verdict, "GO");
    }

    #[test]
    fn exploratory_cases_are_not_scored_unless_a_deterministic_oracle_failed_them() {
        let exploratory = |id: &str, status: &str| {
            let mut r = res(id, "authz", status);
            let mut o = r.oracle.take().unwrap_or(OracleOutcome {
                verdict: Verdict::Pass,
                checks: vec![],
                warnings: vec![],
                exploratory: false,
            });
            o.exploratory = true;
            r.oracle = Some(o);
            r
        };
        let base = ledger(&all_pass(), &[], false);
        // exploratory PASS/INCONCLUSIVE neither raise nor lower anything
        let mut r = all_pass();
        r.push(exploratory("TC-006", "PASS"));
        r.push(exploratory("TC-007", "INCONCLUSIVE"));
        let l = ledger(&r, &[], false);
        assert_eq!(
            (l.overall_readiness, l.gate_verdict.as_str()),
            (base.overall_readiness, "GO")
        );
        assert!(
            l.claims
                .iter()
                .any(|c| c.claim.contains("exploratory") && c.case_ids == ["TC-006", "TC-007"])
        );
        // an exploratory FAIL that a deterministic oracle produced counts like any other
        let mut r = all_pass();
        r.push(exploratory("TC-006", "FAIL"));
        let l = ledger(&r, &[], false);
        assert_ne!(l.gate_verdict, "GO");
    }
    fn defect_with(sev: &str, verification: Option<&str>) -> TriagedDefect {
        TriagedDefect {
            id: "DEF-001".into(),
            title: "t".into(),
            severity: sev.into(),
            case_ids: vec!["TC-006".into()],
            verification: verification.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn only_confirmed_and_flaky_or_unverified_high_defects_block_the_gate() {
        // verified / no verifier data: blocks
        assert!(is_blocking(&defect_with("critical", None)));
        assert!(is_blocking(&defect_with("critical", Some("confirmed"))));
        assert!(is_blocking(&defect_with("medium", Some("confirmed"))));
        // flaky and unverified: only when high or critical (never softened for what could not be examined)
        assert!(is_blocking(&defect_with("high", Some("flaky"))));
        assert!(!is_blocking(&defect_with("medium", Some("flaky"))));
        assert!(is_blocking(&defect_with("critical", Some("unverified"))));
        assert!(!is_blocking(&defect_with("low", Some("unverified"))));
        // and the gate follows it
        let mut r = all_pass();
        r.push(res("TC-006", "boundary", "FAIL"));
        let blocked = |sev: &str, v: Option<&str>| ledger(&r, &[defect_with(sev, v)], false);
        assert_eq!(blocked("critical", Some("confirmed")).gate_verdict, "NO_GO");
        assert_eq!(blocked("critical", Some("flaky")).gate_verdict, "NO_GO");
        assert_eq!(
            blocked("critical", Some("unverified")).gate_verdict,
            "NO_GO"
        );
        let m = blocked("medium", Some("unverified"));
        assert_eq!(
            m.gate_verdict, "CONDITIONAL_GO",
            "a failed case still keeps the gate from GO"
        );
    }

    #[test]
    fn the_verification_summary_pass_k_and_claim_reach_the_ledger() {
        use crate::agent::types::{VerificationRecord, VerifyVerdict};
        let rec = |id: &str, v: VerifyVerdict, rep: u32| VerificationRecord {
            case_id: id.into(),
            method: "GET".into(),
            component: "/x".into(),
            verdict: v,
            severity: "high".into(),
            k: 2,
            completed: 2,
            reproduced: rep,
            replays: vec![],
            note: None,
            original_status: "FAIL".into(),
            final_status: "FAIL".into(),
            evidence_file: Some(format!("evidence/{id}.json")),
        };
        let mut v = VerificationSummary {
            k: 2,
            records: vec![
                rec("TC-001", VerifyVerdict::Confirmed, 2),
                rec("TC-002", VerifyVerdict::Confirmed, 2),
                rec("TC-003", VerifyVerdict::Flaky, 1),
                rec("TC-004", VerifyVerdict::NotReproduced, 0),
            ],
            ..Default::default()
        };
        v.tally();
        assert_eq!((v.replayed, v.pass_k), (4, Some(0.5)));
        let mut l = ledger(&all_pass(), &[], false);
        let verdict_before = l.gate_verdict.clone();
        attach_verification(&mut l, v, &[]);
        assert_eq!(
            l.gate_verdict, verdict_before,
            "attaching changes no verdict"
        );
        let s = l.verification.as_ref().unwrap();
        assert_eq!(s.pass_k_text(), "50%");
        assert!(
            l.executive_summary.contains("pass^2 50%"),
            "{}",
            l.executive_summary
        );
        assert!(
            l.executive_summary
                .contains("2 confirmed, 1 flaky, 1 not reproduced"),
            "{}",
            l.executive_summary
        );
        let claim = l
            .claims
            .iter()
            .find(|c| c.claim.starts_with("Verification"))
            .unwrap();
        assert_eq!(claim.status, "partial");
        assert_eq!(claim.case_ids.len(), 4);
        assert_eq!(claim.evidence_files.len(), 4);
        // verification off
        let mut off = ledger(&all_pass(), &[], false);
        attach_verification(&mut off, VerificationSummary::default(), &[]);
        assert!(off.executive_summary.contains("Verification: off"));
        assert!(
            off.claims
                .iter()
                .all(|c| !c.claim.starts_with("Verification"))
        );
        // unverified high defects are called out in the basis
        let mut u = ledger(
            &all_pass(),
            &[defect_with("critical", Some("unverified"))],
            false,
        );
        attach_verification(
            &mut u,
            VerificationSummary {
                k: 2,
                ..Default::default()
            },
            &[defect_with("critical", Some("unverified"))],
        );
        assert!(
            u.verdict_basis
                .contains("1 unverified high/critical defect(s) kept as blocking"),
            "{}",
            u.verdict_basis
        );
    }
}
