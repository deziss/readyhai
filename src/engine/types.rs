//! Scan configuration options and version constants.

use std::path::PathBuf;
use std::time::Instant;

use crate::model::{Os, Profile};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanOpts {
    pub target: String,
    #[serde(default)]
    pub profile: Option<Profile>,
    #[serde(default)]
    pub openapi: Option<String>,
    #[serde(skip)]
    pub policy: Option<PathBuf>,
    #[serde(skip)]
    pub scope: Option<PathBuf>,
    #[serde(skip)]
    pub config: Option<PathBuf>,
    #[serde(skip)]
    pub baseline: Option<PathBuf>,
    #[serde(default)]
    pub no_tools: bool,
    #[serde(default)]
    pub os: Option<Os>,
    #[serde(skip)]
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub device: Option<String>,
    /// `readyhai qa`: also snapshot this repo alongside a web target (composite run).
    #[serde(skip)]
    pub repo: Option<PathBuf>,
    #[serde(skip)]
    pub roles: Option<PathBuf>,
    #[serde(skip)]
    pub journeys: Option<PathBuf>,
    /// Run senior-QA checks.
    #[serde(skip)]
    pub qa: bool,
    #[serde(skip)]
    pub plugins: Option<PathBuf>,
    /// Server mode: repo paths must sit under allowed roots; web targets need scope.
    #[serde(skip)]
    pub server: bool,
    #[serde(skip)]
    pub allowed_roots: Vec<PathBuf>,
    /// Wall-clock deadline for the whole run (server worker). Checks that would start after it
    /// are skipped, running tools are capped to it, and the run then fails instead of producing
    /// a verdict from partial results.
    #[serde(skip)]
    pub deadline: Option<Instant>,
}
