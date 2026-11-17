//! Advisory LLM readiness gate prose and summary.

use anyhow::{bail, Result};
use serde::Deserialize;
use serde_json::json;

use super::super::ledger;
use super::super::types::{EvidenceLedger, TriagedDefect};
use crate::llm::untrusted::{self, clean_output, fence_capped};
use crate::llm::{ask_typed, Budget, LlmConfig};

const GATE_ROLE: &str = "You are a production-readiness reviewer. You receive facts that deterministic code computed from real HTTP test results. \
Write a short summary for a release manager and give an advisory opinion. Your opinion is advisory: it is recorded separately and never changes the verdict. \
Format: {\"executive_summary\": string, \"gate_verdict\": \"GO\"|\"CONDITIONAL_GO\"|\"NO_GO\", \"overall_readiness\": int, \"value_score\": int, \"authority_score\": int, \"safety_score\": int, \"evidence_score\": int}";

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
