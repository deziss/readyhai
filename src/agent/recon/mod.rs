//! Target reconnaissance and dynamic agent directives engine.

pub mod directives;

#[cfg(test)]
mod tests;

pub use directives::{
    SynthesizedDirectives, TargetRecon, generate_canary_token, parse_directives_response,
    probe_target_recon, synthesize_directives,
};
