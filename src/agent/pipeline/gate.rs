//! Advisory LLM readiness gate prose, summary, and Software Factory Attestation.

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::super::ledger;
pub use super::super::types::{
    AsvsCategoryScore, EvidenceLedger, OwaspAsvsBreakdown, SoftwareFactoryAttestation,
    TriagedDefect,
};
use crate::llm::untrusted::{self, clean_output, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed};

const GATE_ROLE: &str = "You are a production-readiness reviewer. You receive facts that deterministic code computed from real HTTP test results. \
Write a short summary for a release manager and give an advisory opinion. Your opinion is advisory: it is recorded separately and never changes the verdict. \
Format: {\"executive_summary\": string, \"gate_verdict\": \"GO\"|\"CONDITIONAL_GO\"|\"NO_GO\", \"overall_readiness\": int, \"value_score\": int, \"authority_score\": int, \"safety_score\": int, \"evidence_score\": int}";

const ATTESTATION_ROLE: &str = "You are the Software Factory Attestation Recorder. You receive facts that deterministic code \
computed from executed, evidence-linked test cases: observed findings and what was not evaluated. \
Write a short formal attestation summary and advisory directives that state only what was measured; never claim \
compliance, certification or coverage the facts do not state, and report NOT_EVALUATED for anything not measured. \
Format: {\"advisory_summary\": string, \"directives\": [string]}";

#[derive(Debug, Deserialize)]
pub(crate) struct GateOut {
    #[serde(default)]
    pub executive_summary: Option<String>,
    #[serde(default)]
    pub gate_verdict: Option<String>,
    #[serde(default)]
    pub overall_readiness: Option<i64>,
    #[serde(default)]
    pub value_score: Option<i64>,
    #[serde(default)]
    pub authority_score: Option<i64>,
    #[serde(default)]
    pub safety_score: Option<i64>,
    #[serde(default)]
    pub evidence_score: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AttestationLlmOut {
    #[serde(default)]
    advisory_summary: Option<String>,
    #[serde(default)]
    directives: Vec<String>,
}

pub(crate) fn llm_gate(
    cfg: &LlmConfig,
    budget: &mut Budget,
    target: &str,
    l: &mut EvidenceLedger,
    defects: &[TriagedDefect],
) -> Result<()> {
    let facts = json!({
        "target": target, "computed_verdict": l.computed_verdict, "overall_readiness": l.overall_readiness, "verdict_basis": l.verdict_basis,
        "pillars": l.pillars.iter().map(|p| json!({"id": p.id, "score": p.score, "status": p.status, "claim": p.claim})).collect::<Vec<_>>(),
        "defects": defects.iter().take(20).map(|d| json!({"id": d.id, "severity": d.severity, "title": d.title, "component": d.component})).collect::<Vec<_>>(),
    });
    let prompt = format!(
        "Computed readiness facts:\n{}\nWrite the summary and your advisory opinion.",
        fence_capped(&facts, 240)
    );
    // a summary of facts already computed: 2048 tokens and no reasoning, whatever tier the planner runs at
    let out: GateOut = ask_typed(
        &cfg.without_thinking(),
        budget,
        &untrusted::system(GATE_ROLE),
        &prompt,
        |o: &GateOut| {
            if let Some(v) = o.gate_verdict.as_deref()
                && !matches!(v, "GO" | "CONDITIONAL_GO" | "NO_GO")
            {
                bail!(
                    "gate_verdict '{}' is not one of GO, CONDITIONAL_GO, NO_GO",
                    v.chars().take(20).collect::<String>()
                );
            }
            if o.gate_verdict.is_none()
                && o.executive_summary
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
            {
                bail!("neither a verdict nor a summary");
            }
            Ok(())
        },
    )?;
    let summary = out
        .executive_summary
        .as_deref()
        .map(|s| clean_output(s, 900))
        .filter(|s| !s.is_empty());
    ledger::apply_llm(
        l,
        out.gate_verdict.as_deref(),
        [
            out.overall_readiness,
            out.value_score,
            out.authority_score,
            out.safety_score,
            out.evidence_score,
        ],
        summary,
    );
    Ok(())
}

/// One observed-severity tally over the defects an attestation is built from.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Observed {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Counts defects by severity. Defects only ever come from cases that actually failed, so this is
/// a statement about what was observed, never about what was not tested.
pub(crate) fn observe(defects: &[TriagedDefect]) -> Observed {
    let n = |sev: &str| {
        defects
            .iter()
            .filter(|d| d.severity.eq_ignore_ascii_case(sev))
            .count()
    };
    Observed {
        critical: n("critical"),
        high: n("high"),
        medium: n("medium"),
        low: n("low"),
    }
}

/// One ASVS-shaped area: how its defects are allocated, and what in the ledger actually tests it.
struct AreaSpec {
    code: &'static str,
    name: &'static str,
    /// Keyword for the best-effort allocation of *observed* defects.
    key: &'static str,
    /// Ledger techniques whose cases test this area.
    techniques: &'static [&'static str],
    /// Claim-text keywords for areas no technique maps to directly.
    claim_keys: &'static [&'static str],
}

/// The six areas the report has always shown. `techniques`/`claim_keys` say what would count as
/// evidence that the area was tested at all; the default is nothing, which reports `not_evaluated`.
const AREAS: &[AreaSpec] = &[
    AreaSpec {
        code: "V2",
        name: "Authentication",
        key: "auth",
        techniques: &["authz"],
        claim_keys: &["authentication", "credential", "login wall"],
    },
    AreaSpec {
        code: "V4",
        name: "Access Control",
        key: "authz",
        techniques: &["authz"],
        claim_keys: &["authorization", "idor"],
    },
    AreaSpec {
        code: "V5",
        name: "Validation & Sanitization",
        key: "injection",
        techniques: &["injection", "boundary", "negative"],
        claim_keys: &["injection", "validation"],
    },
    AreaSpec {
        code: "V8",
        name: "Data Protection",
        key: "sensitive",
        techniques: &[],
        claim_keys: &["sensitive", "exposure", "leak", "data protection"],
    },
    AreaSpec {
        code: "V13",
        name: "API & Web Service",
        key: "contract",
        techniques: &["state_transition"],
        claim_keys: &["content-type", "contract", "api"],
    },
    AreaSpec {
        code: "V14",
        name: "Configuration",
        key: "config",
        techniques: &[],
        claim_keys: &["config", "security headers", "server error"],
    },
];

/// Best-effort keyword allocation of the *observed* defects to one area. It groups findings that
/// were seen; it says nothing about whether the area was tested, and it is not ASVS-verified
/// coverage.
fn allocated_findings(spec: &AreaSpec, defects: &[TriagedDefect]) -> usize {
    let key = spec.key;
    defects
        .iter()
        .filter(|d| {
            let low_title = d.title.to_ascii_lowercase();
            let low_cat = d.owasp_category.to_ascii_lowercase();
            let low_rule = d.rule.to_ascii_lowercase();
            low_title.contains(key)
                || low_cat.contains(key)
                || low_rule.contains(key)
                || match key {
                    "auth" => low_title.contains("token") || low_cat.contains("api2"),
                    "authz" => {
                        low_title.contains("bola")
                            || low_title.contains("bfla")
                            || low_title.contains("role")
                            || low_title.contains("forged")
                    }
                    "injection" => {
                        low_title.contains("sql")
                            || low_title.contains("xss")
                            || low_title.contains("error")
                    }
                    "sensitive" => low_title.contains("exposure") || low_title.contains("leak"),
                    "contract" => low_title.contains("content_type"),
                    _ => false,
                }
        })
        .count()
}

/// Aggregates the statuses of the evidence rows that cover one area.
fn aggregate_status(statuses: &[&str]) -> &'static str {
    if statuses.is_empty() {
        "not_evaluated"
    } else if statuses.iter().all(|s| *s == "pass") {
        "pass"
    } else if statuses.contains(&"fail") {
        "fail"
    } else {
        "partial"
    }
}

fn norm_status(s: &str) -> &'static str {
    match s {
        "pass" => "pass",
        "fail" => "fail",
        "partial" => "partial",
        "not_evaluated" => "not_evaluated",
        _ => "partial",
    }
}

/// Builds the six areas: `findings` from the keyword allocation of observed defects, `status` and
/// `evidence_case_ids` only from ledger content that actually tested the area.
fn area_scores(
    defects: &[TriagedDefect],
    ledger: Option<&EvidenceLedger>,
) -> Vec<AsvsCategoryScore> {
    AREAS
        .iter()
        .map(|spec| {
            let findings = allocated_findings(spec, defects);
            let mut statuses: Vec<&str> = Vec::new();
            let mut case_ids: Vec<String> = Vec::new();

            if let Some(led) = ledger {
                // Prefer the coverage matrix: it is per technique and counts applicable cases.
                let cells: Vec<&super::super::types::CoverageCell> = led
                    .coverage
                    .iter()
                    .filter(|c| spec.techniques.contains(&c.technique.as_str()))
                    .collect();
                for cell in &cells {
                    if ledger::types::applicable(cell) > 0 {
                        statuses.push(ledger::types::status_of(cell));
                        case_ids.extend(cell.case_ids.iter().cloned());
                    }
                }
                if statuses.is_empty() {
                    // No technique maps to this area: fall back to ledger claims that name it.
                    for claim in &led.claims {
                        let low = claim.claim.to_ascii_lowercase();
                        if !claim.case_ids.is_empty()
                            && spec.claim_keys.iter().any(|k| low.contains(*k))
                        {
                            statuses.push(norm_status(&claim.status));
                            case_ids.extend(claim.case_ids.iter().cloned());
                        }
                    }
                }
            }

            let status = aggregate_status(&statuses);
            case_ids.sort();
            case_ids.dedup();
            let evaluated = status != "not_evaluated";
            AsvsCategoryScore {
                code: spec.code.to_string(),
                name: spec.name.to_string(),
                score: evaluated.then(|| 100u32.saturating_sub((findings * 30) as u32)),
                passed: evaluated && findings == 0 && status == "pass",
                findings,
                status: status.to_string(),
                evidence_case_ids: if evaluated { case_ids } else { vec![] },
            }
        })
        .collect()
}

/// Conclusive share of the applicable cases over the whole run, from the ledger's coverage cells.
/// None when the run recorded no applicable coverage data at all.
pub(crate) fn cases_conclusively_evaluated_pct(ledger: Option<&EvidenceLedger>) -> Option<u32> {
    let led = ledger?;
    let mut conclusive = 0usize;
    let mut applicable = 0usize;
    for cell in &led.coverage {
        conclusive += ledger::types::conclusive(cell);
        applicable += ledger::types::applicable(cell);
    }
    ledger::types::confidence_pct(conclusive, applicable)
}

/// What the booleans and per-area numbers are, and are not.
pub(crate) const ASVS_BASIS: &str = "These booleans and per-area numbers are derived only from defects observed by evidence-backed cases in this run; they are not an OWASP ASVS certification and do not certify compliance with any ASVS requirement.";

/// The observed-findings breakdown shaped like an ASVS report. `evaluated` gates the booleans: a
/// run that evaluated nothing knows nothing, so it may not claim that no defect was observed.
pub(crate) fn build_breakdown(
    defects: &[TriagedDefect],
    ledger: Option<&EvidenceLedger>,
    evaluated: bool,
) -> OwaspAsvsBreakdown {
    let obs = observe(defects);
    let no_critical_or_high_findings = evaluated && obs.critical == 0 && obs.high == 0;
    let no_high_or_medium_above_threshold =
        evaluated && obs.high == 0 && obs.medium <= 2 && obs.critical == 0;
    let no_observed_findings = evaluated && defects.is_empty();
    OwaspAsvsBreakdown {
        no_critical_or_high_findings,
        no_high_or_medium_above_threshold,
        no_observed_findings,
        cases_conclusively_evaluated_pct: cases_conclusively_evaluated_pct(ledger),
        basis: ASVS_BASIS.to_string(),
        categories: area_scores(defects, ledger),
    }
}

/// True when the ledger reflects at least one case whose result an oracle could judge.
pub(crate) fn ledger_evaluated(ledger: &EvidenceLedger) -> bool {
    ledger.evaluated
        && !matches!(
            ledger.computed_verdict.as_str(),
            "NOT_EVALUATED" | "SCANNED"
        )
        && !matches!(ledger.gate_verdict.as_str(), "NOT_EVALUATED" | "SCANNED")
}

/// A short human-readable statement of what kept evidence from being gathered.
fn blocker_line(ledger: Option<&EvidenceLedger>) -> String {
    match ledger {
        Some(led) if !led.blockers.is_empty() => led
            .blockers
            .iter()
            .take(3)
            .map(|b| {
                format!(
                    "{}: {}",
                    ledger::blockers::blocker_label(b.reason),
                    b.detail.trim_end_matches('.')
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
        Some(led) if !led.verdict_basis.trim().is_empty() => {
            led.verdict_basis.trim_end_matches('.').to_string()
        }
        _ => "the run gathered no conclusive evidence".to_string(),
    }
}

/// The directive a run that evaluated nothing must carry: it names the blocker instead of granting
/// anything.
pub(crate) fn not_evaluated_directive(ledger: Option<&EvidenceLedger>) -> String {
    format!(
        "NOT_EVALUATED: no evidence-backed case was evaluated ({}); nothing was evaluated, so no release readiness can be attested.",
        blocker_line(ledger)
    )
}

/// Fallback advisory prose for a run that evaluated nothing.
pub(crate) fn not_evaluated_summary(ledger: Option<&EvidenceLedger>) -> String {
    format!(
        "Software factory attestation: nothing was evaluated ({}). Release readiness is not evaluated: no score, no compliance or certification claim, and no release approval.",
        blocker_line(ledger)
    )
}

/// Assembles the attestation, stamping the timestamp and the canonical digest over its substance.
/// `digest_ledger` supplies the evidence file identity; pass the ledger the verdict came from.
pub(crate) fn assemble(
    gate_verdict: &str,
    release_readiness_score: Option<u32>,
    asvs_breakdown: OwaspAsvsBreakdown,
    release_directives: Vec<String>,
    advisory_summary: Option<String>,
    defects: &[TriagedDefect],
    digest_ledger: Option<&EvidenceLedger>,
) -> SoftwareFactoryAttestation {
    let mut att = SoftwareFactoryAttestation {
        release_readiness_score,
        gate_verdict: gate_verdict.to_string(),
        asvs_breakdown,
        release_directives,
        attestation_digest: String::new(),
        timestamp: crate::agent::store::now_iso(),
        advisory_summary,
    };
    att.attestation_digest = attestation_digest(&att, defects, digest_ledger);
    att
}

/// Canonical, unkeyed integrity digest over the attestation's substance: verdict, score, every
/// area with its status and case ids, every directive, the identity of every defect
/// (rule/component/severity/verification) and the ledger's evidence file paths. Lines are sorted,
/// so the digest does not depend on input ordering, and the timestamp is deliberately excluded so
/// re-serializing the same attestation reproduces it. Key-based signing (minisign, Sigstore) is not
/// implemented: anyone with the same content can recompute this digest.
pub fn attestation_digest(
    att: &SoftwareFactoryAttestation,
    defects: &[TriagedDefect],
    ledger: Option<&EvidenceLedger>,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "verdict={}|score={}|coverage={}",
        att.gate_verdict,
        att.release_readiness_score
            .map(|s| s.to_string())
            .unwrap_or_else(|| "None".into()),
        att.asvs_breakdown
            .cases_conclusively_evaluated_pct
            .map(|s| s.to_string())
            .unwrap_or_else(|| "None".into()),
    ));
    for cat in &att.asvs_breakdown.categories {
        let mut cases = cat.evidence_case_ids.clone();
        cases.sort();
        lines.push(format!(
            "area={}|{}|status={}|score={}|cases={}",
            cat.code,
            cat.name,
            cat.status,
            cat.score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "None".into()),
            cases.join(",")
        ));
    }
    for d in &att.release_directives {
        lines.push(format!("directive={d}"));
    }
    if let Some(led) = ledger {
        let mut paths: Vec<&String> = Vec::new();
        for cell in &led.coverage {
            paths.extend(cell.evidence_files.iter());
        }
        for claim in &led.claims {
            paths.extend(claim.evidence_files.iter());
        }
        for p in &led.pillars {
            paths.extend(p.evidence_files.iter());
        }
        paths.sort();
        paths.dedup();
        for p in paths {
            lines.push(format!("evidence={p}"));
        }
    }
    let mut finding_lines: Vec<String> = defects
        .iter()
        .map(|d| {
            let mut ids = d.case_ids.clone();
            ids.sort();
            format!(
                "finding={}|{}|severity={}|verification={}|cases={}",
                d.rule,
                d.component,
                d.severity,
                d.verification.clone().unwrap_or_else(|| "none".into()),
                ids.join(",")
            )
        })
        .collect();
    finding_lines.sort();
    lines.extend(finding_lines);
    lines.sort();
    let mut hasher = Sha256::new();
    hasher.update(lines.join("\n").as_bytes());
    hex::encode(hasher.finalize())
}

/// Caps a raw readiness score by what was observed: an observed critical or high defect keeps it
/// in the blocked / conditional band no matter how good the pillar evidence looked.
pub(crate) fn cap_score(raw: u32, obs: Observed) -> u32 {
    let s = raw.min(100);
    if obs.critical > 0 {
        s.min(25)
    } else if obs.high > 0 {
        s.min(65)
    } else {
        s
    }
}

/// The substance a release attestation is made of, computed by the one honest constructor shared
/// by the ledger-driven path (`software_factory_attestation`) and the pillar-score path
/// (`gates::validate_release_gate`).
pub(crate) struct ReleaseSubstance {
    pub gate_verdict: String,
    pub score: Option<u32>,
    pub breakdown: OwaspAsvsBreakdown,
    pub directives: Vec<String>,
    /// Deterministic prose used when the advisory LLM did not answer.
    pub fallback_summary: String,
}

/// The single honest release attestation constructor. `score` is `None` when readiness was not
/// measured; `evaluated` says whether the run actually gathered conclusive evidence. An
/// unevaluated run gets `NOT_EVALUATED`, no score, and only the blocker-naming directive: a run
/// that measured nothing cannot approve a release.
pub(crate) fn release_substance(
    score: Option<u32>,
    obs: Observed,
    defects: &[TriagedDefect],
    ledger: Option<&EvidenceLedger>,
    evaluated: bool,
) -> ReleaseSubstance {
    let breakdown = build_breakdown(defects, ledger, evaluated);
    let mut directives: Vec<String> = Vec::new();
    if !evaluated {
        directives.push(not_evaluated_directive(ledger));
        return ReleaseSubstance {
            gate_verdict: "NOT_EVALUATED".to_string(),
            score: None,
            breakdown,
            directives,
            fallback_summary: not_evaluated_summary(ledger),
        };
    }

    debug_assert!(
        score.is_some(),
        "an evaluated attestation needs a measured score"
    );
    let s = score.unwrap_or(0);
    if obs.critical > 0 {
        directives.push(format!(
            "BLOCK_DEPLOYMENT: {} critical vulnerability detected. Production release halted.",
            obs.critical
        ));
    }
    if obs.high > 0 {
        directives.push(format!(
            "CONDITIONAL_SIGN_OFF: {} high-severity defect(s) require security engineering sign-off.",
            obs.high
        ));
    }
    if defects
        .iter()
        .any(|d| d.flaky || d.verification.as_deref() == Some("unverified"))
    {
        directives.push(
            "STAGING_REVERIFY: Flaky or unverified defect replays require staging environment re-test."
                .into(),
        );
    }
    for cat in &breakdown.categories {
        if cat.status == "not_evaluated" {
            directives.push(format!(
                "COVERAGE_GAP_{}: No executed case tested {} this run, so it was not verified.",
                cat.code, cat.name
            ));
        } else if cat.findings > 0 {
            directives.push(format!(
                "REMEDIATE_{}: {} observed defect(s) allocated to {} ({}); remediate before release.",
                cat.code, cat.findings, cat.code, cat.name
            ));
        }
    }

    let gate_verdict = if obs.critical > 0 || s < 50 {
        "NO_GO"
    } else if obs.high > 0 || s < 80 {
        "CONDITIONAL_GO"
    } else {
        "GO"
    };
    let gate_verdict = gate_verdict.to_string();
    if gate_verdict == "GO" {
        directives.push(
            "EVIDENCE_BACKED_GO: Readiness is computed from conclusive, evidence-linked cases and no critical or high defect was observed."
                .into(),
        );
    }

    let fallback_summary = format!(
        "Software factory attestation: release readiness score {}/100, verdict {}. Observed findings: {} critical, {} high, {} medium ({} total). {} {}",
        s,
        gate_verdict,
        obs.critical,
        obs.high,
        obs.medium,
        defects.len(),
        if breakdown.no_critical_or_high_findings {
            "No critical or high defect was observed."
        } else {
            "A critical or high defect was observed."
        },
        ASVS_BASIS
    );

    ReleaseSubstance {
        gate_verdict,
        score: Some(s),
        breakdown,
        directives,
        fallback_summary,
    }
}

/// Builds the substance from the ledger (the honest run-shaped path) and assembles the attestation.
pub(crate) fn attestation_from_ledger(
    ledger: &EvidenceLedger,
    defects: &[TriagedDefect],
) -> ReleaseSubstance {
    let obs = observe(defects);
    let evaluated = ledger_evaluated(ledger);
    let score = evaluated.then(|| cap_score(ledger.overall_readiness, obs));
    release_substance(score, obs, defects, Some(ledger), evaluated)
}

/// Synthesize the Software Factory Attestation: what a run actually evaluated, the observed-findings
/// breakdown, and release directives. A ledger that evaluated nothing yields `NOT_EVALUATED` with no
/// score and no permissive directive, because an unmeasured run cannot certify a release.
pub fn software_factory_attestation(
    mut llm: Option<(&LlmConfig, &mut Budget)>,
    ledger: &EvidenceLedger,
    defects: &[TriagedDefect],
) -> SoftwareFactoryAttestation {
    let obs = observe(defects);
    let evaluated = ledger_evaluated(ledger);
    let substance = attestation_from_ledger(ledger, defects);
    let ReleaseSubstance {
        gate_verdict,
        score,
        breakdown,
        mut directives,
        fallback_summary,
    } = substance;

    let mut advisory_summary = None;
    if let Some((cfg, budget)) = llm.as_mut() {
        let facts = json!({
            "evaluated": evaluated,
            "release_readiness_score": score.map(|s| s as i64),
            "gate_verdict": gate_verdict,
            "no_critical_or_high_findings": breakdown.no_critical_or_high_findings,
            "no_high_or_medium_above_threshold": breakdown.no_high_or_medium_above_threshold,
            "no_observed_findings": breakdown.no_observed_findings,
            "basis": breakdown.basis.clone(),
            "defects_count": defects.len(),
            "critical": obs.critical,
            "high": obs.high,
        });
        let prompt = format!(
            "Software Factory release attestation facts. These are observed findings, not compliance certifications; report NOT_EVALUATED for anything the facts do not measure.\n{}\nWrite your advisory attestation summary and directives.",
            fence_capped(&facts, 200)
        );
        if let Ok(out) = ask_typed::<AttestationLlmOut>(
            &cfg.without_thinking(),
            budget,
            &untrusted::system(ATTESTATION_ROLE),
            &prompt,
            |_: &AttestationLlmOut| Ok(()),
        ) {
            if let Some(sum) = out.advisory_summary {
                advisory_summary = Some(clean_output(&sum, 400));
            }
            for d in &out.directives {
                let cleaned = clean_output(d, 160);
                if !cleaned.is_empty() && !directives.contains(&cleaned) {
                    directives.push(cleaned);
                }
            }
        }
    }

    assemble(
        &gate_verdict,
        score,
        breakdown,
        directives,
        Some(advisory_summary.unwrap_or(fallback_summary)),
        defects,
        Some(ledger),
    )
}
