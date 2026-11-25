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
        Ok(Some(
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?,
        ))
    }
}

/// Automatically loads environment variables from `.env` and checks default configuration paths
/// for standalone binary usage on Linux, macOS, and Windows.
pub fn auto_load_env() {
    let mut candidates = Vec::new();
    if let Ok(custom) = std::env::var("READYHAI_ENV_FILE") {
        candidates.push(std::path::PathBuf::from(custom));
    }
    candidates.push(std::path::PathBuf::from(".env"));

    #[cfg(windows)]
    if let Ok(app_data) = std::env::var("APPDATA") {
        candidates.push(
            std::path::PathBuf::from(app_data)
                .join("readyhai")
                .join(".env"),
        );
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok();
    if let Some(h) = &home {
        candidates.push(std::path::PathBuf::from(h).join(".config/readyhai/.env"));
        candidates.push(std::path::PathBuf::from(h).join(".readyhai/.env"));
    }

    for path in candidates {
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let line = trimmed.strip_prefix("export ").unwrap_or(trimmed);
                    if let Some((k, v)) = line.split_once('=') {
                        let key = k.trim();
                        let mut val = v.trim();
                        if (val.starts_with('"') && val.ends_with('"'))
                            || (val.starts_with('\'') && val.ends_with('\''))
                        {
                            val = &val[1..val.len() - 1];
                        }
                        if !key.is_empty() && std::env::var(key).is_err() {
                            unsafe {
                                std::env::set_var(key, val);
                            }
                        }
                    }
                }
            }
            break;
        }
    }

    // Default scope file auto-discovery for standalone binary execution
    if std::env::var("READYHAI_SCOPE").is_err() {
        let mut scope_candidates = vec![std::path::PathBuf::from("scope.toml")];
        #[cfg(windows)]
        if let Ok(app_data) = std::env::var("APPDATA") {
            scope_candidates.push(
                std::path::PathBuf::from(app_data)
                    .join("readyhai")
                    .join("scope.toml"),
            );
        }
        if let Some(h) = &home {
            scope_candidates.push(std::path::PathBuf::from(h).join(".config/readyhai/scope.toml"));
            scope_candidates.push(std::path::PathBuf::from(h).join(".readyhai/scope.toml"));
        }
        for s in scope_candidates {
            if s.is_file() {
                unsafe {
                    std::env::set_var("READYHAI_SCOPE", s);
                }
                break;
            }
        }
    }
}
