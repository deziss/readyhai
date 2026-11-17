use super::*;
use crate::agent::ledger::types::merge;
use crate::agent::oracle::{OracleCheck, OracleOutcome, Severity, Verdict};
use crate::agent::types::{
    BlockReason, CaseExecutionResult, EvidenceLedger, TriagedDefect, VerificationSummary,
};

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
    let inj_crit = l
        .exit_criteria_checklist
        .iter()
        .find(|c| c.criterion.contains("Injection resistance"))
        .unwrap();
    assert!(!inj_crit.met);
    assert_eq!(inj_crit.status.as_deref(), Some("warning"));
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
