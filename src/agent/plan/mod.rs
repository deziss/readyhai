//! Grounded, deterministic test planning engine with OpenAPI expansion and LLM augmentation.

use std::collections::HashSet;

use super::change::ChangeSet;
use super::discover::Discovery;
use super::exec::{Credentials, normalize_method};
use super::memory::PlanHints;
use super::types::{
    INTEL_OPEN, INTEL_REPRODUCED, PlannedCase, any_prioritised, intel_rank, plan_order,
};
use crate::llm::{Budget, LlmConfig};

pub mod baseline;
pub mod dag;
pub mod directives;
pub mod helpers;
pub mod llm;
pub mod openapi;
pub mod surface;
pub mod types;

#[cfg(test)]
mod tests;

pub use dag::{AttackDag, AttackDagNode, SKIPPED_PREREQUISITE_FAILED, is_prerequisite_skipped};
pub(crate) use helpers::{key_of, mk, user_or_anon};
pub use llm::synthesize_attack_dag;
pub(crate) use llm::{Known, PlannerOutput, RawCase, validate_raw};
pub use types::{Depth, MAX_CASES, PlanOutcome, plans_from_spec, seed_from_run_id};

use baseline::baseline;
use directives::plan_directives;
use llm::llm_extras;
use openapi::spec_cases;

/// Build the plan with a seed derived from the target and profile (no run id available). Prefer
/// [`plan_cases_seeded`] with `seed_from_run_id(run_id)` so every run has its own reproducible seed.
pub fn plan_cases(
    llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    profile: &str,
    d: &Discovery,
    instructions: Option<&str>,
    creds: &Credentials,
) -> PlanOutcome {
    let seed = seed_from_run_id(&format!("{target}|{profile}"));
    plan_cases_seeded(llm, target, profile, d, instructions, creds, seed)
}

/// Build the plan. `llm` is None when the LLM is not configured/reachable: then the plan is purely
/// deterministic. `seed` (see [`seed_from_run_id`]) is the only source of variation: it is used by
/// the LLM exploration prompt and recorded in `PlanOutcome.seed` and in the plan notes.
pub fn plan_cases_seeded(
    llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    profile: &str,
    d: &Discovery,
    instructions: Option<&str>,
    creds: &Credentials,
    seed: u64,
) -> PlanOutcome {
    plan_cases_changed(llm, target, profile, d, instructions, creds, seed, None)
}

/// [`plan_cases_seeded`] for a run that knows what the code diff changed. `change` names the spec
/// operations the diff touched: each gets the full case set (contract, boundary, negative,
/// injection, authz, stateful) even at the quick profile, its cases come first in the plan and are
/// the last to be cut, and every case carries the operation in `changed_ops`. The other
/// operations are planned exactly as the profile alone would plan them. With `None` (or an empty
/// set) the plan is the same as before change-awareness existed.
#[allow(clippy::too_many_arguments)]
pub fn plan_cases_changed(
    llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    profile: &str,
    d: &Discovery,
    instructions: Option<&str>,
    creds: &Credentials,
    seed: u64,
    change: Option<&ChangeSet>,
) -> PlanOutcome {
    plan_cases_remembered(
        llm,
        target,
        profile,
        d,
        instructions,
        creds,
        seed,
        change,
        None,
    )
}

/// [`plan_cases_changed`] for a target the agent remembers. `memory` (see `agent::memory`) only
/// REORDERS what the profile plans anyway: the cases that re-test a known defect (open, regressed
/// or recently fixed) come first, tagged with the defect's fingerprint (`regression_of`), then the
/// changed operations, then operations that failed or were flaky last time (`history_priority`),
/// then the rest, each tier in the planner's order. No case is added, dropped or rewritten, so a
/// passed operation keeps its baseline coverage. With `None`, or memory that holds nothing, the plan
/// is exactly what [`plan_cases_changed`] gives.
#[allow(clippy::too_many_arguments)]
pub fn plan_cases_remembered(
    llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    profile: &str,
    d: &Discovery,
    instructions: Option<&str>,
    creds: &Credentials,
    seed: u64,
    change: Option<&ChangeSet>,
    memory: Option<&PlanHints>,
) -> PlanOutcome {
    plan_cases_remembered_with_whitebox(
        llm,
        target,
        profile,
        d,
        instructions,
        creds,
        seed,
        change,
        memory,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn plan_cases_remembered_with_whitebox(
    llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    profile: &str,
    d: &Discovery,
    instructions: Option<&str>,
    creds: &Credentials,
    seed: u64,
    change: Option<&ChangeSet>,
    memory: Option<&PlanHints>,
    whitebox: Option<&super::whitebox::WhiteboxAnalysis>,
) -> PlanOutcome {
    let focus = change.filter(|c| !c.is_empty());
    let depth = Depth::from_profile(profile);
    let mut notes = vec![format!("plan synthesis seed: {seed:016x}")];
    if depth == Depth::Quick {
        notes.push(if focus.is_some() {
            "quick profile: baseline plan only, plus the changed operations in full (the other OpenAPI-derived cases, concurrency bursts and LLM extras are planned at standard/deep)".into()
        } else {
            "quick profile: baseline plan only (OpenAPI-derived cases, concurrency bursts and LLM extras are planned at standard/deep)".into()
        });
    }
    let mut cases = baseline(d, creds, &mut notes);
    let mut spec_n = 0;
    // the profile's baseline of operations; at quick (None) only the changed ones come from the spec
    let baseline_ops = match (depth.spec_ops(), focus) {
        (Some(n), _) => Some(Some(n)),
        (None, Some(_)) => Some(None),
        (None, None) => None,
    };
    if let (Some(max_ops), Some(spec)) =
        (baseline_ops, d.spec.as_ref().filter(|s| !s.ops.is_empty()))
    {
        let sc = spec_cases(spec, &d.ids, creds, depth, max_ops, focus, &mut notes);
        spec_n = sc.len();
        cases.extend(sc);
        if spec.ops.iter().any(|o| o.secured) && creds.actor().is_none() {
            notes.push(format!("no {} credential: authenticated positive/contract checks were not planned; secured operations are probed without credentials only", Credentials::env_var("user")));
        }
    }
    if focus.is_none() || depth != Depth::Quick {
        cases.extend(super::attacks::auth::plan_auth_attacks(d, creds, depth));
        cases.extend(super::attacks::injection::plan_injection_attacks(
            d, creds, depth,
        ));
        cases.extend(super::attacks::bopla::plan_bopla_attacks(d, creds, depth));
        cases.extend(super::attacks::logic::plan_logic_attacks(d, creds, depth));
        if let Some(wb) = whitebox {
            cases.extend(super::whitebox::plan_whitebox_cases(wb, creds, depth));
        }
    }
    if let Some(instr) = instructions {
        let dc = plan_directives(instr, d, creds);
        if !dc.is_empty() {
            notes.push(format!(
                "operator directives: {} test case(s) synthesized directly from instructions",
                dc.len()
            ));
            cases.extend(dc);
        }
    }
    // dedupe, cap
    let mut seen = HashSet::new();
    cases.retain(|c| seen.insert(key_of(c)));
    // what the agent remembers about the target: tag and reorder (the cases themselves stay)
    if let Some(h) = memory.filter(|h| !h.is_empty()) {
        let probes = h.apply(&mut cases);
        let past = cases.iter().filter(|c| c.history_priority).count();
        if probes + past > 0 {
            notes.push(format!(
                "agent memory: {probes} case(s) re-test known defects and run first, {past} more belong to operations that failed or were flaky before; nothing was added or dropped"
            ));
        }
        // traceability for the intel tiers: the why rides on each case's `intel_note`
        let live = cases
            .iter()
            .filter(|c| c.intel_note.starts_with(INTEL_REPRODUCED))
            .count();
        let open = cases
            .iter()
            .filter(|c| c.intel_note.starts_with(INTEL_OPEN))
            .count();
        if live + open > 0 {
            notes.push(format!(
                "project intelligence: {live} case(s) re-test findings safe exploitation re-confirmed live and run first, {open} more relate to findings still open in the vulnerability database; nothing was added or dropped"
            ));
        }
    }
    let changed = any_prioritised(&cases);
    if let Some(f) = focus {
        // changed operations first, after the intel cases and the known-defect probes (stable:
        // each side keeps the planner's order)
        cases.sort_by_key(|c| {
            (
                intel_rank(c) != 0,
                intel_rank(c) != 1,
                c.regression_of.is_empty(),
                intel_rank(c) != 2,
                c.changed_ops.is_empty(),
                !c.history_priority,
            )
        });
        notes.push(format!(
            "change-aware plan: {} changed operation(s) ({}) planned in full and first; the other operations keep the {} profile's baseline",
            f.len(),
            f.labels().take(6).cloned().collect::<Vec<_>>().join(", "),
            profile.trim().to_ascii_lowercase()
        ));
    }
    if cases.len() > depth.max_cases() {
        // what matters most survives the cap (the pipeline trims by the same order): changed
        // operations, then access control and the rest by priority
        let key = plan_order(changed);
        cases.sort_by_key(|c| key(c));
        cases.truncate(depth.max_cases());
    }

    let mut llm_cases = 0;
    if let Some((cfg, budget)) = llm.filter(|_| depth.llm_cases() > 0) {
        let room = depth
            .max_cases()
            .saturating_sub(cases.len())
            .min(depth.llm_cases());
        if room > 0 {
            for c in llm_extras(
                cfg,
                budget,
                target,
                profile,
                d,
                instructions,
                creds,
                seed,
                depth.llm_cases(),
                &mut notes,
            ) {
                if llm_cases < room && seen.insert(key_of(&c)) {
                    cases.push(c);
                    llm_cases += 1;
                }
            }
        }
    }
    if llm_cases > 0 {
        // the LLM's extras are tagged and ordered like every other case
        if let Some(h) = memory.filter(|h| !h.is_empty()) {
            h.apply(&mut cases);
        }
    }
    // Evict placeholder ledger rows if real executable cases exist for that technique
    let techniques_with_real_cases: HashSet<String> = cases
        .iter()
        .filter(|c| !c.is_ledger_row())
        .map(|c| c.technique.clone())
        .collect();
    cases.retain(|c| !c.is_ledger_row() || !techniques_with_real_cases.contains(&c.technique));
    for (i, c) in cases.iter_mut().enumerate() {
        c.id = format!("TC-{:03}", i + 1);
        // the lead's area worker for this case
        c.area = super::lead::Area::classify(c).as_str().to_string();
        // one spelling of every verb, whatever the source (spec, LLM, hand-edited plan)
        if let Some(m) = normalize_method(&c.method) {
            c.method = m.to_string();
        }
        for st in c.stateful_steps.iter_mut().flatten() {
            if let Some(m) = normalize_method(&st.method) {
                st.method = m.to_string();
            }
        }
    }
    let base = if spec_n > 0 {
        "openapi"
    } else {
        "deterministic"
    };
    PlanOutcome {
        source: if llm_cases > 0 {
            format!("{base}+llm")
        } else {
            base.to_string()
        },
        cases,
        notes,
        llm_cases,
        seed,
    }
}
