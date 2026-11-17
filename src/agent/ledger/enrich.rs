use super::super::types::{
    CaseExecutionResult, EvidenceLedger, LedgerClaim, LlmAdvisory, TriagedDefect,
    VerificationSummary,
};
use super::blockers::is_blocking;
use super::types::rank;

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

pub fn clamp(v: i64) -> u32 {
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
