//! The agent's memory of one target across runs: what it found, what was flaky, what is covered.

pub mod observe;
pub mod reconcile;
pub mod render;
pub mod sanitize;
pub mod store;
pub mod types;
pub mod update;

#[cfg(test)]
mod tests;

// 100% backward-compatible re-exports
pub use observe::{
    ClassObs, Observation, ObservedDefect, OpObs, RunFacts, class_key, class_of, observe,
    op_of_case, op_of_class,
};
pub use reconcile::{PlanHints, Reconciled, reconcile};
pub use render::render_text;
pub use sanitize::{
    clean_class, clean_endpoint, clean_ident, clean_text, days_between, fingerprint, parse_date,
};
pub(crate) use store::write_memory;
pub use store::{
    accept, canonical_target, default_dir, dir, forget, inspect, load, memory_path,
    observe_baselines, peek, read_strict, target_key,
};
pub use types::{
    Acceptance, Accepted, BaselineState, BaselinesInEffect, DefectLine, DefectStatus, FLAKY_WINDOW,
    FlakyHistory, FlakyLine, KnownDefect, Loaded, MAX_CLASSES, MAX_DEFECTS, MAX_ENDPOINT,
    MAX_FILE_BYTES, MAX_IDENT, MAX_OPERATIONS, MAX_REPRO, MAX_RUNS, MAX_TEXT, Memory,
    OperationMemory, ProbeLine, RECENT_FIX_DAYS, RETENTION_DAYS, RunAggregate, SCHEMA,
    SinceLastRun,
};
pub use update::Update;
