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

const ATTESTATION_ROLE: &str = "You are the Software Factory Attestation Officer. Given the release readiness score, \
OWASP ASVS compliance breakdown, and security defects, write a concise formal release attestation summary \
and advisory deployment directives. \
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

/// Synthesize a formal Software Factory Attestation certifying release readiness,
/// OWASP ASVS compliance breakdown, and signed release directives.
pub fn software_factory_attestation(
    mut llm: Option<(&LlmConfig, &mut Budget)>,
    ledger: &EvidenceLedger,
    defects: &[TriagedDefect],
) -> SoftwareFactoryAttestation {
    let crit_count = defects
        .iter()
        .filter(|d| d.severity.eq_ignore_ascii_case("critical"))
        .count();
    let high_count = defects
        .iter()
        .filter(|d| d.severity.eq_ignore_ascii_case("high"))
        .count();
    let med_count = defects
        .iter()
        .filter(|d| d.severity.eq_ignore_ascii_case("medium"))
        .count();
    let low_count = defects
        .iter()
        .filter(|d| d.severity.eq_ignore_ascii_case("low"))
        .count();

    let mut score: u32 = if ledger.overall_readiness > 0 {
        ledger.overall_readiness.min(100)
    } else {
        let penalty = (crit_count * 40 + high_count * 20 + med_count * 5 + low_count * 2) as u32;
        100u32.saturating_sub(penalty)
    };

    if crit_count > 0 {
        score = score.min(25);
    } else if high_count > 0 {
        score = score.min(65);
    }

    let gate_verdict = if crit_count > 0 || score < 50 {
        "NO_GO".to_string()
    } else if high_count > 0 || score < 80 {
        "CONDITIONAL_GO".to_string()
    } else {
        "GO".to_string()
    };

    let categories_def = [
        ("V2", "Authentication", "auth"),
        ("V4", "Access Control", "authz"),
        ("V5", "Validation & Sanitization", "injection"),
        ("V8", "Data Protection", "sensitive"),
        ("V13", "API & Web Service", "contract"),
        ("V14", "Configuration", "config"),
    ];

    let mut categories = Vec::with_capacity(categories_def.len());
    for (code, name, key) in categories_def {
        let findings = defects
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
            .count();

        let cat_score = 100u32.saturating_sub((findings * 30) as u32);
        let passed = findings == 0;
        categories.push(AsvsCategoryScore {
            code: code.to_string(),
            name: name.to_string(),
            score: cat_score,
            passed,
            findings,
        });
    }

    let level_1_compliant = crit_count == 0 && high_count == 0;
    let level_2_compliant = level_1_compliant && score >= 80 && med_count <= 2;
    let level_3_compliant = level_2_compliant && defects.is_empty();
    let passed_cats = categories.iter().filter(|c| c.passed).count();
    let overall_coverage_pct = (passed_cats * 100 / categories.len()) as u32;

    let asvs_breakdown = OwaspAsvsBreakdown {
        level_1_compliant,
        level_2_compliant,
        level_3_compliant,
        overall_coverage_pct,
        categories: categories.clone(),
    };

    let mut release_directives = vec![];
    if crit_count > 0 {
        release_directives.push(format!(
            "BLOCK_DEPLOYMENT: {crit_count} critical vulnerability detected. Production release halted."
        ));
    }
    if high_count > 0 {
        release_directives.push(format!(
            "CONDITIONAL_SIGN_OFF: {high_count} high-severity defect(s) require security engineering sign-off."
        ));
    }
    if defects
        .iter()
        .any(|d| d.flaky || d.verification.as_deref() == Some("unverified"))
    {
        release_directives.push(
            "STAGING_REVERIFY: Flaky or unverified defect replays require staging environment re-test."
                .into(),
        );
    }
    for cat in &categories {
        if !cat.passed {
            release_directives.push(format!(
                "REMEDIATE_{}: Enforce OWASP ASVS {} ({}) controls before release.",
                cat.code, cat.code, cat.name
            ));
        }
    }
    if gate_verdict == "GO" {
        release_directives.push(
            "ALLOW_DEPLOYMENT: Software factory attestation verified release readiness.".into(),
        );
    }

    let mut advisory_summary = None;
    if let Some((cfg, budget)) = llm.as_mut() {
        let facts = json!({
            "release_readiness_score": score,
            "gate_verdict": gate_verdict,
            "asvs_l1": level_1_compliant,
            "asvs_l2": level_2_compliant,
            "asvs_l3": level_3_compliant,
            "defects_count": defects.len(),
            "critical": crit_count,
            "high": high_count,
        });
        let prompt = format!(
            "Software Factory release attestation facts:\n{}\nWrite your advisory attestation summary and directives.",
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
                if !cleaned.is_empty() && !release_directives.contains(&cleaned) {
                    release_directives.push(cleaned);
                }
            }
        }
    }

    if advisory_summary.is_none() {
        advisory_summary = Some(format!(
            "Software factory attestation: release readiness score {}/100, verdict {}, OWASP ASVS L1: {}, L2: {}.",
            score, gate_verdict, level_1_compliant, level_2_compliant
        ));
    }

    let timestamp = crate::agent::store::now_iso();
    let digest_input = format!("{}:{}:{}:{}", score, gate_verdict, timestamp, defects.len());
    let mut hasher = Sha256::new();
    hasher.update(digest_input.as_bytes());
    let attestation_digest = hex::encode(hasher.finalize());

    SoftwareFactoryAttestation {
        release_readiness_score: score,
        gate_verdict,
        asvs_breakdown,
        release_directives,
        attestation_digest,
        timestamp,
        advisory_summary,
    }
}
