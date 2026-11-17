//! UI exploratory QA: runs runners/playwright/qa.mjs in the Playwright runner image and
//! turns /out/qa-ui.json into test cases, results, defects and coverage.

pub mod baseline;
pub mod builder;
pub mod exec;
pub mod image;
pub mod model;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use baseline::{accept_visual_baseline, accept_visual_baseline_in, visual_baseline_dir};
#[allow(unused_imports)]
pub use builder::{Built, build};
#[allow(unused_imports)]
pub use exec::{SecretsGuard, checks, load_journeys, run};
#[allow(unused_imports)]
pub use image::{HINT, container_base, playwright_image};
#[allow(unused_imports)]
pub use model::*;
