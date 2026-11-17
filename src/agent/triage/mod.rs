//! Triager. Defects are derived deterministically from FAIL results: one defect per
//! (failure class, endpoint), severity from the failed assertions, every FAIL case id mapped.
//! The LLM may only attach advisory prose (`ai_note`) to a defect id that already exists.

pub mod derivation;
pub mod grouping;
pub mod llm_advisory;
pub mod rules;
#[cfg(test)]
mod tests;

pub use derivation::*;
pub use grouping::*;
pub use llm_advisory::*;
pub use rules::*;
