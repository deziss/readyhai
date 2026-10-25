//! Rules of engagement for network targets (scope.toml).
use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub hosts: Vec<ScopeHost>,
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
    pub fn load(path: &Path) -> Result<Scope> {
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }
    pub fn find(&self, host: &str) -> Option<&ScopeHost> {
        let host = host.to_ascii_lowercase();
        self.hosts.iter().find(|h| {
            let p = h.host.to_ascii_lowercase();
            match p.strip_prefix("*.") {
                Some(sfx) => host.ends_with(&format!(".{sfx}")),
                None => p == host,
            }
        })
    }
}

static ACTIVE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Engine hook: record the scope.toml path of this run so checks can read per-host config.
#[allow(dead_code)]
pub fn set_active(p: &Path) {
    let _ = ACTIVE.set(p.to_path_buf());
}

/// Scope of the current run: `set_active` path, else READYHAI_SCOPE.
pub fn active() -> Option<Scope> {
    let p = ACTIVE.get().cloned().or_else(|| std::env::var("READYHAI_SCOPE").ok().map(Into::into))?;
    Scope::load(&p).ok()
}

pub fn url_host(url: &str) -> Result<String> {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        bail!("no host in URL '{url}'");
    }
    Ok(host.to_ascii_lowercase())
}

/// Is the web target allowed, and is it nonprod (for intrusive checks)?
pub fn check(url: &str, scope: Option<&Scope>, required: bool) -> Result<bool> {
    let host = url_host(url)?;
    match scope {
        None if required => bail!("server mode: web targets must be listed in scope.toml (READYHAI_SCOPE)"),
        None => Ok(false),
        Some(s) => match s.find(&host) {
            Some(h) => Ok(h.env.eq_ignore_ascii_case("nonprod")),
            None => bail!("host '{host}' is not in scope.toml"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(url_host("https://user:pw@App.Example.com:8443/x?y").unwrap(), "app.example.com");
        let s: Scope = toml::from_str(
            "[[hosts]]\nhost='*.nonprod.example'\nenv='nonprod'\n[[hosts]]\nhost='app.example'\nenv='prod'",
        )
        .unwrap();
        assert!(check("https://a.nonprod.example/", Some(&s), true).unwrap());
        assert!(!check("https://app.example/", Some(&s), true).unwrap());
        assert!(check("https://evil.example/", Some(&s), true).is_err());
        assert!(check("https://x/", None, true).is_err());
    }

    #[test]
    fn perf_resilience_fields() {
        let s: Scope = toml::from_str(
            "[[hosts]]\nhost='app.test'\nenv='nonprod'\n[hosts.perf]\nvus=50\nallow_heavy=true\n[hosts.resilience]\ncompose_project='shop'\nservices=['postgres','redis']",
        )
        .unwrap();
        let h = s.find("app.test").unwrap();
        assert_eq!(h.perf.as_ref().unwrap().vus, Some(50));
        assert!(h.perf.as_ref().unwrap().allow_heavy);
        assert_eq!(h.resilience.as_ref().unwrap().services, vec!["postgres", "redis"]);
        let s: Scope = toml::from_str("[[hosts]]\nhost='a'\nenv='prod'").unwrap();
        assert!(s.hosts[0].perf.is_none() && s.hosts[0].resilience.is_none());
    }
}
