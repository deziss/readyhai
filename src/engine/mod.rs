//! Orchestration: target → snapshot → facts → checks → gate.

pub mod deadline;
pub mod git;
pub mod orchestrator;
pub mod storage;
pub mod target_parser;
#[cfg(test)]
mod tests;
pub mod types;

#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub use deadline::*;
pub use git::*;
pub use orchestrator::*;
pub use storage::*;
pub use target_parser::*;
pub use types::*;
