//! Scope file parsing, per-host configuration, and global active scope tracking.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use super::url::norm_host;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub hosts: Vec<ScopeHost>,
    /// `[git]`: hosts allowed for remote repository clones.
    #[serde(default)]
    pub git: GitCfg,
}

/// `[git] hosts = [...]`: extra git hosts allowed for clone targets, on top of
/// the built-in public defaults. Entries match exactly or as `*.suffix`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GitCfg {
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeHost {
    /// Exact host or "*.suffix".
    pub host: String,
    /// "prod" | "nonprod". Intrusive checks only run on nonprod.
    pub env: String,
    /// Optional load-test limits for this host (`[hosts.perf]`).
    #[serde(default)]
    pub perf: Option<PerfLimits>,
    /// Optional fault-injection allow-list for this host (`[hosts.resilience]`).
    #[serde(default)]
    pub resilience: Option<ResilienceCfg>,
}

/// `[hosts.perf]` overrides. Still hard-capped (10 VUs / 120 s) unless `allow_heavy = true`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PerfLimits {
    pub vus: Option<u32>,
    pub duration_secs: Option<u32>,
    /// Abort threshold for http_req_failed (fraction, default 0.05).
    pub max_error_rate: Option<f64>,
    #[serde(default)]
    pub allow_heavy: bool,
}

/// `[hosts.resilience]`: only containers of this compose project AND listed services are touched.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResilienceCfg {
    pub compose_project: String,
    #[serde(default)]
    pub services: Vec<String>,
}

impl Scope {
    /// Read and parse a scope file. Fails with a message that says what is wrong with the path:
    /// missing, a directory (what `docker compose up` creates when the bind-mount source was
    /// missing), unreadable, or invalid TOML. There is no "treat it as no scope" outcome.
    pub fn load(path: &Path) -> Result<Scope> {
        let meta = std::fs::metadata(path).map_err(|e| {
            anyhow!(
                "scope file {} cannot be read: {e}. Create it with `cp scope.example.toml scope.toml` (or point READYHAI_SCOPE / --scope at an existing file)",
                path.display()
            )
        })?;
        if meta.is_dir() {
            bail!(
                "scope file {} is a directory, not a file. This is what Docker creates when the file did not exist at `docker compose up`: remove the empty directory, run `cp scope.example.toml scope.toml`, then recreate the container",
                path.display()
            );
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("scope file {} cannot be read", path.display()))?;
        toml::from_str(&text)
            .map_err(|e| anyhow!("scope file {} is not valid: {e}", path.display()))
    }

    /// Default scope: [`active`]. `Ok(None)` only when no scope file is configured at all; a
    /// configured but unloadable one is an error (fail closed).
    pub fn load_default() -> Result<Option<Scope>> {
        active()
    }

    /// Scope entry that governs `host`.
    ///
    /// When several entries match: an exact entry beats a wildcard, and `prod` beats `nonprod`
    /// (fail safe: an ambiguous host is never treated as a free-for-all test target). Anything
    /// whose `env` is not literally "nonprod" counts as prod. Among equal wildcards the longest
    /// suffix wins so the result does not depend on file order.
    pub fn find(&self, host: &str) -> Option<&ScopeHost> {
        let host = norm_host(host);
        self.hosts
            .iter()
            .filter_map(|h| {
                let p = norm_host(&h.host);
                let (wildcard, suffix_len) = match p.strip_prefix("*.") {
                    Some(sfx) if !sfx.is_empty() => {
                        let dotted = host.len() > sfx.len() + 1
                            && host.ends_with(sfx)
                            && host.as_bytes()[host.len() - sfx.len() - 1] == b'.';
                        if !dotted {
                            return None;
                        }
                        (true, sfx.len())
                    }
                    Some(_) => return None,
                    None if p == "*" => (true, 0),
                    None if p == host => (false, 0),
                    None => return None,
                };
                let nonprod = h.env.eq_ignore_ascii_case("nonprod");
                Some(((wildcard, nonprod, std::cmp::Reverse(suffix_len)), h))
            })
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, h)| h)
    }
}

static ACTIVE: OnceLock<PathBuf> = OnceLock::new();

/// Engine hook: record the scope.toml path of this run so checks can read per-host config.
#[allow(dead_code)]
pub fn set_active(p: &Path) {
    let _ = ACTIVE.set(p.to_path_buf());
}

/// The scope file named by `READYHAI_SCOPE`. A blank value counts as not set; anything else must
/// load (see [`Scope::load`]).
pub fn from_env() -> Result<Option<Scope>> {
    load_configured(std::env::var("READYHAI_SCOPE").ok().as_deref())
}

/// `raw` is the configured scope path, if any. Not configured is `Ok(None)`; configured but
/// unusable is an error that says so, never `Ok(None)`.
pub(crate) fn load_configured(raw: Option<&str>) -> Result<Option<Scope>> {
    match raw.map(str::trim).filter(|p| !p.is_empty()) {
        None => Ok(None),
        Some(p) => Scope::load(Path::new(p)).map(Some).context(
            "READYHAI_SCOPE is set but the scope file cannot be used; refusing to run without it",
        ),
    }
}

/// Scope of the current run: the `set_active` path, else `READYHAI_SCOPE`. `Ok(None)` means no
/// scope file is configured. A configured file that is missing, a directory or invalid is an
/// `Err`: callers must refuse the operation, not carry on as if there were no scope.
pub fn active() -> Result<Option<Scope>> {
    match ACTIVE.get() {
        Some(p) => Scope::load(p).map(Some),
        None => from_env(),
    }
}
