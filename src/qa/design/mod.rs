//! Test-design generation: builds boundary-value, equivalence-partition, pairwise
//! combination and decision-table cases from the API spec, plus an op x technique coverage
//! matrix that reports what remains untested.
//!
//! Generated cases are marked *Skipped (not auto-executed)* — they document design coverage
//! gaps for a human to run; only safe read-only operations are ever executed by this module.

mod common;
mod pairwise;

pub fn checks() -> Vec<crate::checks::Check> {
    use crate::checks::Check;
    use crate::model::{Profile, TargetKind};
    vec![
        Check::new(
            "qa.design.boundary",
            "Boundary-value cases from spec bounds",
            &[TargetKind::Web],
            Profile::Standard,
            common::boundary,
        )
        .qa(),
        Check::new(
            "qa.design.equivalence",
            "Equivalence-partition cases from spec types",
            &[TargetKind::Web],
            Profile::Standard,
            common::equivalence,
        )
        .qa(),
        Check::new(
            "qa.design.pairwise",
            "Pairwise parameter-combination cases",
            &[TargetKind::Web],
            Profile::Deep,
            pairwise::pairwise,
        )
        .qa(),
        Check::new(
            "qa.design.decision-table",
            "Decision-table cases from boolean flag combinations",
            &[TargetKind::Web],
            Profile::Deep,
            pairwise::decision_table,
        )
        .qa(),
        Check::new(
            "qa.design.matrix",
            "Coverage matrix: spec operations x test techniques",
            &[TargetKind::Web],
            Profile::Standard,
            pairwise::matrix,
        )
        .qa(),
    ]
}
