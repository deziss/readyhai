//! Software Factory Quality Gates between pipeline stations.
//!
//! Enforces typed station entrance and exit contracts across the 6 formal software factory stations:
//! 1. `ReconGate`: Validates target reachable, security posture fingerprinted, directives synthesized.
//! 2. `DiscoveryGate`: Validates route discovery inventory (>0 routes or verified empty fallback), semantic route predictions validated.
//! 3. `PlanGate`: Validates Attack DAG is acyclic, baseline cases generated, directives covered.
//! 4. `ExecutionGate`: Validates area worker wave completion, budget compliance, zero worker thread panics.
//! 5. `VerifyGate`: Validates k-pass replay records, Juror Source->Sink taint evaluation, zero unverified false-positive defects.
//! 6. `ReleaseGate`: Validates Evidence Ledger four-pillar thresholds (Value, Authority, Safety, Evidence) and observed findings, and generates the Software Factory Attestation, stamped with an unkeyed SHA-256 integrity digest (key-based signing is not implemented).

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::gate;
use super::graph::PipelineState;
pub use crate::agent::types::{
    AsvsCategoryScore, EvidenceLedger, OwaspAsvsBreakdown, SoftwareFactoryAttestation,
    TriagedDefect,
};

/// Type of quality gate: Entrance precondition or Exit postcondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateType {
    Entrance,
    Exit,
}

/// Individual quality check record within a gate verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Detailed evaluation verdict emitted by a software factory quality gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateVerdict {
    pub station: PipelineState,
    pub gate_type: GateType,
    pub passed: bool,
    pub summary: String,
    pub checks: Vec<GateCheck>,
}

impl GateVerdict {
    pub fn new(
        station: PipelineState,
        gate_type: GateType,
        passed: bool,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            station,
            gate_type,
            passed,
            summary: summary.into(),
            checks: vec![],
        }
    }

    pub fn with_check(
        mut self,
        name: impl Into<String>,
        passed: bool,
        detail: impl Into<String>,
    ) -> Self {
        self.checks.push(GateCheck {
            name: name.into(),
            passed,
            detail: detail.into(),
        });
        self
    }
}

/// Generic trait for software factory station quality gates.
pub trait QualityGate {
    type Input;
    type Output;

    fn gate_name(&self) -> &'static str;
    fn station(&self) -> PipelineState;
    fn evaluate(&self, input: &Self::Input) -> Result<Self::Output>;
}

// ============================================================================
// Station 1: ReconGate
// ============================================================================

/// Typed input for Recon quality gate validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconGateInput {
    pub target_reachable: bool,
    pub directives_present: bool,
    pub focus_areas_count: usize,
}

/// Quality gate for Station 1 (Recon).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconGate {
    pub target_reachable: bool,
    pub security_posture_fingerprinted: bool,
    pub directives_synthesized: bool,
    pub focus_areas_count: usize,
    pub canary_token_present: bool,
}

impl ReconGate {
    pub fn check_entrance(target_url: &str, max_budget_requests: usize) -> Result<GateVerdict> {
        let mut verdict = GateVerdict::new(
            PipelineState::Recon,
            GateType::Entrance,
            true,
            "Recon station entrance gate passed",
        );
        let url_parsed = reqwest::Url::parse(target_url);
        match url_parsed {
            Ok(u) if u.scheme() == "http" || u.scheme() == "https" => {
                verdict = verdict.with_check(
                    "target_url_scheme",
                    true,
                    format!("Valid {} scheme", u.scheme()),
                );
            }
            Ok(u) => {
                bail!(
                    "ReconGate entrance failure: unsupported URL scheme '{}'",
                    u.scheme()
                );
            }
            Err(e) => {
                bail!("ReconGate entrance failure: malformed target URL: {e}");
            }
        }
        if max_budget_requests == 0 {
            bail!("ReconGate entrance failure: zero request budget available");
        }
        verdict = verdict.with_check(
            "budget_available",
            true,
            format!("{max_budget_requests} requests allowed"),
        );
        Ok(verdict)
    }

    pub fn check_exit(input: &ReconGateInput) -> Result<GateVerdict> {
        validate_recon_gate(input)
    }
}

impl QualityGate for ReconGate {
    type Input = ReconGateInput;
    type Output = GateVerdict;

    fn gate_name(&self) -> &'static str {
        "ReconGate"
    }

    fn station(&self) -> PipelineState {
        PipelineState::Recon
    }

    fn evaluate(&self, input: &Self::Input) -> Result<Self::Output> {
        validate_recon_gate(input)
    }
}

pub fn validate_recon_gate(input: &ReconGateInput) -> Result<GateVerdict> {
    if !input.target_reachable {
        bail!("ReconGate exit failure: target is not reachable");
    }
    if !input.directives_present {
        bail!("ReconGate exit failure: autonomous directives not synthesized");
    }
    if input.focus_areas_count == 0 {
        bail!("ReconGate exit failure: zero focus areas synthesized in directives");
    }
    let verdict = GateVerdict::new(
        PipelineState::Recon,
        GateType::Exit,
        true,
        format!(
            "ReconGate passed with {} focus areas",
            input.focus_areas_count
        ),
    )
    .with_check("target_reachable", true, "Target responded successfully")
    .with_check(
        "directives_present",
        true,
        "Autonomous rules of engagement generated",
    )
    .with_check(
        "focus_areas_count",
        true,
        format!("{} focus areas active", input.focus_areas_count),
    );
    Ok(verdict)
}

// ============================================================================
// Station 2: DiscoveryGate
// ============================================================================

/// Typed input for Discovery quality gate validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryGateInput {
    pub routes_count: usize,
    pub verified_empty_fallback: bool,
    pub semantic_predictions_validated: bool,
}

/// Quality gate for Station 2 (Discovery).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryGate {
    pub routes_count: usize,
    pub verified_empty_fallback: bool,
    pub semantic_predictions_validated: bool,
    pub app_architecture: Option<String>,
    pub primary_framework: Option<String>,
}

impl DiscoveryGate {
    pub fn check_entrance(target_reachable: bool) -> Result<GateVerdict> {
        if !target_reachable {
            bail!("DiscoveryGate entrance failure: target must be verified reachable by Recon");
        }
        Ok(GateVerdict::new(
            PipelineState::Discovery,
            GateType::Entrance,
            true,
            "Discovery station entrance gate passed",
        )
        .with_check("target_reachable", true, "Target verified reachable"))
    }

    pub fn check_exit(input: &DiscoveryGateInput) -> Result<GateVerdict> {
        validate_discovery_gate(input)
    }
}

impl QualityGate for DiscoveryGate {
    type Input = DiscoveryGateInput;
    type Output = GateVerdict;

    fn gate_name(&self) -> &'static str {
        "DiscoveryGate"
    }

    fn station(&self) -> PipelineState {
        PipelineState::Discovery
    }

    fn evaluate(&self, input: &Self::Input) -> Result<Self::Output> {
        validate_discovery_gate(input)
    }
}

pub fn validate_discovery_gate(input: &DiscoveryGateInput) -> Result<GateVerdict> {
    if input.routes_count == 0 && !input.verified_empty_fallback {
        bail!(
            "DiscoveryGate exit failure: route discovery inventory is empty and verified empty fallback was not confirmed"
        );
    }
    if !input.semantic_predictions_validated {
        bail!("DiscoveryGate exit failure: semantic route predictions could not be validated");
    }
    let verdict = GateVerdict::new(
        PipelineState::Discovery,
        GateType::Exit,
        true,
        format!(
            "DiscoveryGate passed: {} routes discovered (fallback: {})",
            input.routes_count, input.verified_empty_fallback
        ),
    )
    .with_check(
        "route_inventory",
        true,
        if input.routes_count > 0 {
            format!("{} route(s) discovered", input.routes_count)
        } else {
            "Verified empty route fallback confirmed".to_string()
        },
    )
    .with_check(
        "semantic_predictions",
        true,
        "Semantic route predictions validated",
    );
    Ok(verdict)
}

// ============================================================================
// Station 3: PlanGate
// ============================================================================

/// Typed input for Plan quality gate validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlanGateInput {
    pub is_dag_acyclic: bool,
    pub baseline_cases_count: usize,
    pub directives_covered: bool,
}

/// Quality gate for Station 3 (Plan).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlanGate {
    pub is_dag_acyclic: bool,
    pub baseline_cases_count: usize,
    pub directives_covered: bool,
}

impl PlanGate {
    pub fn check_entrance(
        routes_count: usize,
        verified_empty_fallback: bool,
    ) -> Result<GateVerdict> {
        if routes_count == 0 && !verified_empty_fallback {
            bail!(
                "PlanGate entrance failure: requires routes or verified empty fallback from Discovery"
            );
        }
        Ok(GateVerdict::new(
            PipelineState::Plan,
            GateType::Entrance,
            true,
            "Plan station entrance gate passed",
        )
        .with_check(
            "inventory_ready",
            true,
            format!("{routes_count} route(s) ready for planning"),
        ))
    }

    pub fn check_exit(input: &PlanGateInput) -> Result<GateVerdict> {
        validate_plan_gate(input)
    }
}

impl QualityGate for PlanGate {
    type Input = PlanGateInput;
    type Output = GateVerdict;

    fn gate_name(&self) -> &'static str {
        "PlanGate"
    }

    fn station(&self) -> PipelineState {
        PipelineState::Plan
    }

    fn evaluate(&self, input: &Self::Input) -> Result<Self::Output> {
        validate_plan_gate(input)
    }
}

pub fn validate_plan_gate(input: &PlanGateInput) -> Result<GateVerdict> {
    if !input.is_dag_acyclic {
        bail!("PlanGate exit failure: Attack DAG contains cycles or self-loops");
    }
    if input.baseline_cases_count == 0 {
        bail!("PlanGate exit failure: zero baseline test cases generated");
    }
    if !input.directives_covered {
        bail!(
            "PlanGate exit failure: synthesized directives and focus areas are not covered in plan"
        );
    }
    let verdict = GateVerdict::new(
        PipelineState::Plan,
        GateType::Exit,
        true,
        format!(
            "PlanGate passed: {} baseline cases, acyclic Attack DAG, directives covered",
            input.baseline_cases_count
        ),
    )
    .with_check(
        "attack_dag_acyclic",
        true,
        "Attack DAG topologically verified acyclic",
    )
    .with_check(
        "baseline_cases_generated",
        true,
        format!("{} baseline cases generated", input.baseline_cases_count),
    )
    .with_check(
        "directives_covered",
        true,
        "Autonomous focus areas covered in plan",
    );
    Ok(verdict)
}

// ============================================================================
// Station 4: ExecutionGate
// ============================================================================

/// Typed input for Execution quality gate validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionGateInput {
    pub waves_completed: usize,
    pub budget_compliant: bool,
    pub worker_panics: usize,
}

/// Quality gate for Station 4 (Execution).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionGate {
    pub waves_completed: usize,
    pub budget_compliant: bool,
    pub worker_panics: usize,
}

impl ExecutionGate {
    pub fn check_entrance(
        planned_cases_count: usize,
        budget_remaining: usize,
    ) -> Result<GateVerdict> {
        if planned_cases_count == 0 {
            bail!("ExecutionGate entrance failure: zero planned cases to execute");
        }
        if budget_remaining == 0 {
            bail!("ExecutionGate entrance failure: zero execution budget remaining");
        }
        Ok(GateVerdict::new(
            PipelineState::Execute,
            GateType::Entrance,
            true,
            "Execution station entrance gate passed",
        )
        .with_check(
            "planned_cases_present",
            true,
            format!("{planned_cases_count} cases planned"),
        )
        .with_check(
            "budget_available",
            true,
            format!("{budget_remaining} budget remaining"),
        ))
    }

    pub fn check_exit(input: &ExecutionGateInput) -> Result<GateVerdict> {
        validate_execution_gate(input)
    }
}

impl QualityGate for ExecutionGate {
    type Input = ExecutionGateInput;
    type Output = GateVerdict;

    fn gate_name(&self) -> &'static str {
        "ExecutionGate"
    }

    fn station(&self) -> PipelineState {
        PipelineState::Execute
    }

    fn evaluate(&self, input: &Self::Input) -> Result<Self::Output> {
        validate_execution_gate(input)
    }
}

pub fn validate_execution_gate(input: &ExecutionGateInput) -> Result<GateVerdict> {
    if input.worker_panics > 0 {
        bail!(
            "ExecutionGate exit failure: detected {} worker thread panic(s)",
            input.worker_panics
        );
    }
    if !input.budget_compliant {
        bail!("ExecutionGate exit failure: budget non-compliance detected");
    }
    if input.waves_completed == 0 {
        bail!("ExecutionGate exit failure: zero area worker waves were completed");
    }
    let verdict = GateVerdict::new(
        PipelineState::Execute,
        GateType::Exit,
        true,
        format!(
            "ExecutionGate passed: {} waves completed, zero worker panics, budget compliant",
            input.waves_completed
        ),
    )
    .with_check("worker_panics", true, "Zero worker thread panics confirmed")
    .with_check(
        "budget_compliance",
        true,
        "Execution remained within allocated budget",
    )
    .with_check(
        "waves_completed",
        true,
        format!("{} area worker waves completed", input.waves_completed),
    );
    Ok(verdict)
}

// ============================================================================
// Station 5: VerifyGate
// ============================================================================

/// Typed input for Verify quality gate validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyGateInput {
    pub k_replay_executed: bool,
    pub juror_taint_evaluated: bool,
    /// Reproduced defects the taint juror judged likely false positives. They are kept (a
    /// measurement outranks an opinion), and this count is what makes the disagreement visible.
    #[serde(default)]
    pub juror_disagreements: usize,
    pub unverified_false_positives: usize,
}

/// Quality gate for Station 5 (Verify).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyGate {
    pub k_replay_executed: bool,
    pub juror_taint_evaluated: bool,
    pub juror_disagreements: usize,
    pub unverified_false_positives: usize,
}

impl VerifyGate {
    pub fn check_entrance(executed_results_count: usize) -> Result<GateVerdict> {
        if executed_results_count == 0 {
            bail!("VerifyGate entrance failure: zero executed results available for verification");
        }
        Ok(GateVerdict::new(
            PipelineState::Verify,
            GateType::Entrance,
            true,
            "Verify station entrance gate passed",
        )
        .with_check(
            "execution_results_present",
            true,
            format!("{executed_results_count} results executed"),
        ))
    }

    pub fn check_exit(input: &VerifyGateInput) -> Result<GateVerdict> {
        validate_verify_gate(input)
    }
}

impl QualityGate for VerifyGate {
    type Input = VerifyGateInput;
    type Output = GateVerdict;

    fn gate_name(&self) -> &'static str {
        "VerifyGate"
    }

    fn station(&self) -> PipelineState {
        PipelineState::Verify
    }

    fn evaluate(&self, input: &Self::Input) -> Result<Self::Output> {
        validate_verify_gate(input)
    }
}

pub fn validate_verify_gate(input: &VerifyGateInput) -> Result<GateVerdict> {
    if !input.k_replay_executed {
        bail!(
            "VerifyGate exit failure: k-pass replay records missing or verification was not executed"
        );
    }
    if !input.juror_taint_evaluated {
        bail!("VerifyGate exit failure: Juror Source->Sink taint evaluation was not performed");
    }
    if input.unverified_false_positives > 0 {
        bail!(
            "VerifyGate exit failure: detected {} unverified false-positive defect(s)",
            input.unverified_false_positives
        );
    }
    let verdict = GateVerdict::new(
        PipelineState::Verify,
        GateType::Exit,
        true,
        if input.juror_disagreements == 0 {
            "VerifyGate passed: k-pass replays verified, every defect adjudicated, no unresolved juror disagreement".to_string()
        } else {
            format!(
                "VerifyGate passed with {} reproduced defect(s) the juror doubts; they are retained \
                 and flagged in `juror_opinion`",
                input.juror_disagreements
            )
        },
    )
    .with_check(
        "k_replay_records",
        true,
        "k-pass replay verification confirmed",
    )
    .with_check(
        "juror_taint_evaluation",
        true,
        "every defect reached a juror verdict (or there were none to trace)",
    )
    .with_check(
        "juror_disagreements_recorded",
        true,
        format!(
            "{} reproduced defect(s) carry a recorded juror disagreement",
            input.juror_disagreements
        ),
    )
    .with_check(
        "zero_unverified_false_positives",
        true,
        "Zero unverified false-positive defects confirmed",
    );
    Ok(verdict)
}

// ============================================================================
// Station 6: ReleaseGate
// ============================================================================

/// Typed input for Release quality gate validation.
///
/// The pillar scores are caller-supplied: `pillar_scores_measured` must say whether they were
/// actually computed from evidence. Without it a caller could green-light a release by passing
/// plausible numbers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseGateInput {
    /// `None` = not evaluated.
    #[serde(default)]
    pub value_score: Option<u32>,
    #[serde(default)]
    pub authority_score: Option<u32>,
    #[serde(default)]
    pub safety_score: Option<u32>,
    #[serde(default)]
    pub evidence_score: Option<u32>,
    pub min_threshold: u32,
    /// An observed-findings statement: no critical or high defect was seen. Never a compliance claim.
    pub no_critical_or_high_findings: bool,
    pub critical_defects: usize,
    /// False = the pillar scores above were not actually measured; the attestation then reports
    /// `NOT_EVALUATED` instead of a score.
    #[serde(default)]
    pub pillar_scores_measured: bool,
}

impl Default for ReleaseGateInput {
    /// Reports not-evaluated everywhere: an all-default run measured nothing, and the gate says so.
    fn default() -> Self {
        Self {
            value_score: None,
            authority_score: None,
            safety_score: None,
            evidence_score: None,
            min_threshold: 70,
            no_critical_or_high_findings: true,
            critical_defects: 0,
            pillar_scores_measured: false,
        }
    }
}

/// Quality gate for Station 6 (Release / Gate).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReleaseGate {
    pub value_score: Option<u32>,
    pub authority_score: Option<u32>,
    pub safety_score: Option<u32>,
    pub evidence_score: Option<u32>,
    pub min_threshold: u32,
    pub no_critical_or_high_findings: bool,
    pub critical_defects: usize,
    pub pillar_scores_measured: bool,
}

impl ReleaseGate {
    pub fn check_entrance(
        ledger_computed: bool,
        verification_attached: bool,
    ) -> Result<GateVerdict> {
        if !ledger_computed {
            bail!("ReleaseGate entrance failure: evidence ledger not computed");
        }
        if !verification_attached {
            bail!("ReleaseGate entrance failure: verifier summary not attached to evidence ledger");
        }
        Ok(GateVerdict::new(
            PipelineState::Gate,
            GateType::Entrance,
            true,
            "Release station entrance gate passed",
        )
        .with_check("ledger_computed", true, "Evidence ledger computed")
        .with_check("verification_attached", true, "Verification attached"))
    }

    pub fn check_exit(input: &ReleaseGateInput) -> Result<SoftwareFactoryAttestation> {
        validate_release_gate(input)
    }

    pub fn evaluate_ledger(
        ledger: &EvidenceLedger,
        defects: &[TriagedDefect],
        min_threshold: u32,
    ) -> Result<SoftwareFactoryAttestation> {
        let obs = gate::observe(defects);
        let measured = gate::ledger_evaluated(ledger)
            && ledger.value_score.is_some()
            && ledger.authority_score.is_some()
            && ledger.safety_score.is_some()
            && ledger.evidence_score.is_some();

        let input = ReleaseGateInput {
            value_score: ledger.value_score,
            authority_score: ledger.authority_score,
            safety_score: ledger.safety_score,
            evidence_score: ledger.evidence_score,
            min_threshold,
            no_critical_or_high_findings: obs.critical == 0 && obs.high == 0,
            critical_defects: obs.critical,
            pillar_scores_measured: measured,
        };
        validate_release_gate_with_ledger(&input, defects, Some(ledger))
    }
}

impl QualityGate for ReleaseGate {
    type Input = ReleaseGateInput;
    type Output = SoftwareFactoryAttestation;

    fn gate_name(&self) -> &'static str {
        "ReleaseGate"
    }

    fn station(&self) -> PipelineState {
        PipelineState::Gate
    }

    fn evaluate(&self, input: &Self::Input) -> Result<Self::Output> {
        validate_release_gate(input)
    }
}

/// Build the Software Factory Attestation from declared pillar scores and observed findings.
///
/// Declared scores are only honoured when `pillar_scores_measured` is set: when they were not
/// actually computed the attestation reports `NOT_EVALUATED` with no score, exactly as
/// [`gate::software_factory_attestation`] does for an unevaluated ledger. No ASVS category,
/// coverage number or compliance claim is invented here — the substance comes from the same shared
/// constructor in [`gate`].
pub fn validate_release_gate(input: &ReleaseGateInput) -> Result<SoftwareFactoryAttestation> {
    validate_release_gate_with_ledger(input, &[], None)
}

/// [`validate_release_gate`] with the evidence the caller actually has: the triaged defects and,
/// when available, the evidence ledger. Passing them lets the per-area statuses, the coverage
/// percentage and the integrity digest be drawn from real evidence instead of being left blank.
pub fn validate_release_gate_with_ledger(
    input: &ReleaseGateInput,
    defects: &[TriagedDefect],
    ledger: Option<&EvidenceLedger>,
) -> Result<SoftwareFactoryAttestation> {
    if input.critical_defects > 0 {
        bail!(
            "ReleaseGate exit failure: {} critical defect(s) detected; deployment blocked",
            input.critical_defects
        );
    }
    if !input.no_critical_or_high_findings {
        bail!(
            "ReleaseGate exit failure: a high finding was observed and is still open; release not cleared"
        );
    }
    if input.pillar_scores_measured {
        for (name, score) in [
            ("Value", input.value_score),
            ("Authority", input.authority_score),
            ("Safety", input.safety_score),
            ("Evidence", input.evidence_score),
        ] {
            if let Some(val) = score
                && val < input.min_threshold
            {
                bail!(
                    "ReleaseGate exit failure: {} pillar score {} is below required threshold {}",
                    name,
                    val,
                    input.min_threshold
                );
            }
        }
    }

    // Four-pillar weighted readiness score: Value 30%, Authority 30%, Safety 25%, Evidence 15%.
    // Not computed at all when the pillars were never measured.
    let declared = if input.pillar_scores_measured {
        Some(
            (input.value_score.unwrap_or(0) * 30
                + input.authority_score.unwrap_or(0) * 30
                + input.safety_score.unwrap_or(0) * 25
                + input.evidence_score.unwrap_or(0) * 15)
                / 100,
        )
    } else {
        None
    };

    let obs = if defects.is_empty() {
        // No defect list was supplied: the caller's two flags are all that is known.
        gate::Observed {
            critical: input.critical_defects,
            high: usize::from(!input.no_critical_or_high_findings),
            medium: 0,
            low: 0,
        }
    } else {
        gate::observe(defects)
    };

    let sub = gate::release_substance(declared, obs, defects, ledger, input.pillar_scores_measured);
    let mut attestation = gate::assemble(
        &sub.gate_verdict,
        sub.score,
        sub.breakdown,
        sub.directives,
        sub.fallback_summary.into(),
        defects,
        ledger,
    );
    if let (Some(summary), Some(v), Some(a), Some(sf), Some(e)) = (
        attestation.advisory_summary.as_mut(),
        input.value_score,
        input.authority_score,
        input.safety_score,
        input.evidence_score,
    ) {
        let measured = if input.pillar_scores_measured {
            "measured"
        } else {
            "declared without measurement"
        };
        summary.push_str(&format!(
            " Pillar scores ({measured}, min {}): Value {v}, Authority {a}, Safety {sf}, Evidence {e}.",
            input.min_threshold
        ));
    }
    Ok(attestation)
}

fn score_text(score: Option<u32>, min_threshold: u32) -> String {
    match score {
        Some(val) => format!("Score: {val} (min: {min_threshold})"),
        None => "Not evaluated".to_string(),
    }
}

pub fn validate_release_gate_verdict(input: &ReleaseGateInput) -> Result<GateVerdict> {
    let attestation = validate_release_gate(input)?;
    Ok(release_gate_verdict_for(input, &attestation, &[]))
}

/// The Release exit gate verdict **for an attestation the caller already built from real evidence**
/// (executed defects and the evidence ledger), plus the run-level reasons it is not cleared.
///
/// A run that has already built its attestation must use this instead of
/// [`validate_release_gate_verdict`], which rebuilds an attestation from pillar scores alone (no
/// defects, no ledger). Going through the plain version logs a score and an integrity digest that
/// are not the ones the run records, so two attestations of the same release disagree.
///
/// `blockers` name why a release is not cleared (a failed station, a cancelled run, an incomplete
/// sweep). A non-empty list yields a **failed** verdict that lists them, so a blocked release can
/// never be logged as a passed gate — the check detail carries the reason either way.
pub fn release_gate_verdict_for(
    input: &ReleaseGateInput,
    attestation: &SoftwareFactoryAttestation,
    blockers: &[String],
) -> GateVerdict {
    let readiness_text = match attestation.release_readiness_score {
        Some(score) => format!("{score}/100"),
        None => "not evaluated".to_string(),
    };
    let digest: String = attestation.attestation_digest.chars().take(16).collect();
    // An attestation that measured nothing cannot clear a release, whatever the caller says.
    let mut reasons: Vec<&str> = blockers.iter().map(String::as_str).collect();
    let not_evaluated = attestation.gate_verdict == "NOT_EVALUATED";
    if not_evaluated {
        reasons.push("the run evaluated no conclusive evidence, so readiness was never measured");
    }
    let passed = reasons.is_empty();
    let head = if passed {
        "ReleaseGate cleared".to_string()
    } else {
        format!(
            "ReleaseGate NOT cleared: {} blocking condition(s)",
            reasons.len()
        )
    };
    let mut verdict = GateVerdict::new(
        PipelineState::Gate,
        GateType::Exit,
        passed,
        format!(
            "{head}: attestation verdict {}, score {readiness_text}, digest {digest}",
            attestation.gate_verdict
        ),
    );
    for reason in reasons {
        verdict = verdict.with_check("blocker", false, reason.to_string());
    }
    verdict
        .with_check(
            "attestation_verdict",
            !not_evaluated,
            attestation.gate_verdict.clone(),
        )
        .with_check(
            "release_readiness_score",
            attestation.release_readiness_score.is_some(),
            match attestation.release_readiness_score {
                Some(score) => format!("Score: {score}/100 computed from executed cases"),
                None => "Not evaluated: this run gathered no conclusive evidence".to_string(),
            },
        )
        .with_check(
            "value_pillar",
            true,
            score_text(input.value_score, input.min_threshold),
        )
        .with_check(
            "authority_pillar",
            true,
            score_text(input.authority_score, input.min_threshold),
        )
        .with_check(
            "safety_pillar",
            true,
            score_text(input.safety_score, input.min_threshold),
        )
        .with_check(
            "evidence_pillar",
            true,
            score_text(input.evidence_score, input.min_threshold),
        )
        .with_check(
            "no_critical_or_high_findings",
            input.no_critical_or_high_findings,
            if input.no_critical_or_high_findings {
                "No critical or high finding was observed".to_string()
            } else {
                "A critical or high finding is still open".to_string()
            },
        )
        .with_check(
            "attestation_digest_recorded",
            true,
            format!(
                "Unkeyed SHA-256 integrity digest: {}",
                attestation.attestation_digest
            ),
        )
}
