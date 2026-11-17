//! OpenAPI-driven functional API testing: generated positive/boundary/negative cases,
//! contract checks, auth matrix, stateful CRUD/BOLA, robustness probes.

pub mod authz;
pub mod baseline;
pub mod contract;
pub mod defect_types;
pub mod exec;
pub mod functional;
pub mod helpers;
pub mod latency;
pub mod planning;
pub mod runner;
pub mod spec;
pub mod stateful;
pub mod synth;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod testsrv;

use crate::checks::Check;
use crate::model::{Profile, TargetKind};

#[allow(unused_imports)]
pub use baseline::{accept_spec_baseline, accept_spec_baseline_in, stage_dir};

#[allow(unused_imports)]
pub use defect_types::{DefectRef, NewDefect, Req, Reruns};

#[allow(unused_imports)]
pub use functional::{functional, functional_in};

#[allow(unused_imports)]
pub use helpers::{
    MAX_IDS, UNLIKELY_ID, blocked_reason, collection_of, created_id, field, ids_in_list,
    latency_note, list_items, not_applicable, unlikely_ids,
};

#[allow(unused_imports)]
pub use planning::{Planned, plan_order};

#[allow(unused_imports)]
pub use runner::{MAX_RERUN, Runner, scratch_id};

pub fn checks() -> Vec<Check> {
    let w = &[TargetKind::Web];
    // Order matters: the request budget is shared, so the highest-priority cases (auth matrix,
    // P1) run first, then functional cases by plan risk, then the stateful lifecycle (BOLA).
    vec![
        Check::new(
            "qa.api.authz",
            "API auth matrix: anonymous, invalid token, roles",
            w,
            Profile::Quick,
            authz::run,
        )
        .qa(),
        Check::new(
            "qa.api.functional",
            "API functional: positive/boundary/negative, contract, robustness",
            w,
            Profile::Quick,
            functional,
        )
        .qa(),
        Check::new(
            "qa.api.stateful",
            "API stateful CRUD lifecycle, BOLA, delete semantics",
            w,
            Profile::Standard,
            stateful::run,
        )
        .qa(),
    ]
}
