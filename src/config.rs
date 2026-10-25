//! Per-target `readyhai.toml` (read from the snapshot root or --config).
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct TargetConfig {
    pub suppress: Vec<Suppression>,
    pub snapshot: SnapshotCfg,
    pub test: Option<TestCfg>,
    pub license: LicenseCfg,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct LicenseCfg {
    /// SPDX ids or globs to deny, e.g. ["AGPL-3.0*", "GPL-3.0*"].
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Suppression {
    /// Rule id or prefix glob, e.g. "readiness.compose.privileged" or "CVE-2024-*".
    pub rule: String,
    /// Optional location glob, e.g. "services/coding-platform/**".
    #[serde(default)]
    pub path: Option<String>,
    pub reason: String,
    /// YYYY-MM-DD; expired suppressions are ignored.
    pub expires: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SnapshotCfg {
    /// Extra denylist globs (matched against relative path).
    pub deny: Vec<String>,
    /// Extra directories to skip entirely.
    pub skip_dirs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestCfg {
    /// Image to run the project's tests in (e.g. the built app image).
    pub image: String,
    /// Shell command; must write JUnit XML to /out/junit.xml.
    pub command: String,
    #[serde(default)]
    pub network: bool,
    #[serde(default = "default_test_timeout")]
    pub timeout_secs: u64,
}

fn default_test_timeout() -> u64 {
    900
}

impl TargetConfig {
    pub fn load(path: &Path) -> anyhow::Result<Option<TargetConfig>> {
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(path)?;
        Ok(Some(toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?))
    }
}
