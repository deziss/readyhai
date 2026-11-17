//! Stateful scenario chains and the TOCTOU concurrency burst.
//!
//! A chain is "actor A creates a resource, actor B tries to read it" (BOLA/IDOR). The executor
//! collects facts; `oracle::judge_stateful` decides.

pub mod burst;
pub mod exchange;
pub mod models;
pub mod preflight;
pub mod scenario;
pub mod vars;
pub mod violation;

#[cfg(test)]
mod tests;

pub use burst::{run_concurrency_burst, run_concurrency_burst_auth};
pub use models::{BurstRun, DEFAULT_ID_KEYS, StatefulScenarioResult};
pub use preflight::preflight;
pub use scenario::execute_stateful_scenario;
pub use vars::{
    extract_json_values, is_secret_key, placeholder_names, storable_value, substitute_vars,
};
pub use violation::{actor_bearer, evaluate_violation};
