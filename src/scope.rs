//! Rules of engagement for network targets (scope.toml).
use anyhow::{Result, anyhow, bail};
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

/// Lowercase, no IPv6 brackets, no trailing dot: the form hosts are compared in.
fn norm_host(h: &str) -> String {
    let h = h.trim().to_ascii_lowercase();
    let h = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(&h);
    h.trim_end_matches('.').to_string()
}

/// Parse an http(s) URL with the WHATWG parser (the one reqwest uses). Everything that decides
/// "which host will this request hit" must go through here: a hand-rolled authority splitter
/// disagrees with the real client on inputs like `http://evil.example\@allowed.example/`.
pub fn parse_web_url(url: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(url.trim()).map_err(|e| anyhow!("invalid URL: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        bail!("only http:// and https:// targets are accepted (got '{}')", u.scheme());
    }
    if u.host_str().is_none_or(str::is_empty) {
        bail!("no host in URL");
    }
    Ok(u)
}

/// Host of an http(s) URL, as the HTTP client will resolve it.
pub fn url_host(url: &str) -> Result<String> {
    let u = parse_web_url(url)?;
    Ok(norm_host(u.host_str().unwrap_or_default()))
}

/// Is the web target allowed, and is it nonprod (for intrusive checks)?
pub fn check(url: &str, scope: Option<&Scope>, required: bool) -> Result<bool> {
    check_host(&url_host(url)?, scope, required)
}

/// Same decision for a bare host (ssh and git remotes, where the caller already extracted it).
pub fn check_host(host: &str, scope: Option<&Scope>, required: bool) -> Result<bool> {
    let host = norm_host(host);
    if host.is_empty() {
        bail!("empty host");
    }
    match scope {
        None if required => bail!("server mode: web targets must be listed in scope.toml (READYHAI_SCOPE)"),
        None => Ok(false),
        Some(s) => match s.find(&host) {
            Some(h) => Ok(h.env.eq_ignore_ascii_case("nonprod")),
            None => bail!("host '{host}' is not in scope.toml"),
        },
    }
}

/// Outcome of [`egress_guard`]: the URL to actually request (normalised, so the client and the
/// guard agree on the host) and what the scope says about it.
#[derive(Debug, Clone)]
pub struct Egress {
    pub url: String,
    #[allow(dead_code)] // part of the decision record; callers that only need the URL ignore it
    pub host: String,
    #[allow(dead_code)]
    pub nonprod: bool,
}

/// The one gate every outbound HTTP action of the server goes through (agent run/retest/discover/
/// crawl, network lab, scans): the host must be in scope, and `intrusive` actions (writes,
/// attack payloads, load, fault injection) are additionally refused on anything not tagged
/// `nonprod`. A missing scope file refuses everything: the server never guesses.
pub fn egress_guard(url: &str, scope: Option<&Scope>, intrusive: bool) -> Result<Egress> {
    let u = parse_web_url(url)?;
    let host = norm_host(u.host_str().unwrap_or_default());
    let nonprod = check_host(&host, scope, true)?;
    if intrusive && !nonprod {
        bail!("host '{host}' is not tagged env = \"nonprod\" in scope.toml; intrusive actions are refused on prod hosts");
    }
    Ok(Egress { url: u.to_string(), host, nonprod })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(toml_text: &str) -> Scope {
        toml::from_str(toml_text).unwrap()
    }

    #[test]
    fn hosts() {
        assert_eq!(url_host("https://user:pw@App.Example.com:8443/x?y").unwrap(), "app.example.com");
        let s = scope("[[hosts]]\nhost='*.nonprod.example'\nenv='nonprod'\n[[hosts]]\nhost='app.example'\nenv='prod'");
        assert!(check("https://a.nonprod.example/", Some(&s), true).unwrap());
        assert!(!check("https://app.example/", Some(&s), true).unwrap());
        assert!(check("https://evil.example/", Some(&s), true).is_err());
        assert!(check("https://x/", None, true).is_err());
        // a wildcard never matches the bare suffix or a look-alike
        assert!(check("https://nonprod.example/", Some(&s), true).is_err());
        assert!(check("https://anonprod.example/", Some(&s), true).is_err());
    }

    #[test]
    fn host_normalisation() {
        assert_eq!(url_host("http://[::1]:8080/x").unwrap(), "::1");
        assert_eq!(url_host("http://App.Example./").unwrap(), "app.example");
        let s = scope("[[hosts]]\nhost='APP.example.'\nenv='nonprod'\n[[hosts]]\nhost='[::1]'\nenv='nonprod'");
        assert!(check("http://app.example/", Some(&s), true).unwrap());
        assert!(check("http://[::1]:9/", Some(&s), true).unwrap());
    }

    #[test]
    fn only_http_and_https() {
        for u in ["ftp://app.example/", "file:///etc/passwd", "ssh://app.example", "javascript:alert(1)", "app.example", ""] {
            assert!(url_host(u).is_err(), "{u}");
        }
        assert!(url_host("HTTPS://app.example").is_ok());
    }

    #[test]
    fn backslash_in_authority_uses_the_real_host() {
        // The WHATWG parser (reqwest) treats `\` like `/` in special URLs, so the request goes
        // to the part BEFORE the backslash. A hand-rolled splitter that looked after the last
        // '@' would call the first URL "allowed" while the client connects to evil.example.
        let s = scope("[[hosts]]\nhost='app.example'\nenv='nonprod'");
        assert_eq!(url_host("http://evil.example\\@app.example/").unwrap(), "evil.example");
        assert!(check("http://evil.example\\@app.example/", Some(&s), true).is_err());
        assert!(egress_guard("http://evil.example\\@app.example/", Some(&s), false).is_err());
        // and the reverse: what looks foreign to a naive parser is really the scoped host
        assert_eq!(url_host("http://app.example\\@evil.example/").unwrap(), "app.example");
        let e = egress_guard("http://app.example\\@evil.example/x", Some(&s), false).unwrap();
        assert_eq!(e.host, "app.example");
        // the normalised URL no longer contains the ambiguous backslash
        assert!(!e.url.contains('\\'), "{}", e.url);
        assert_eq!(url_host(&e.url).unwrap(), "app.example");
        // other authority tricks
        for u in ["http://evil.example#@app.example/", "http://evil.example?@app.example/", "http://app.example@evil.example/", "http://app.example:80@evil.example/"] {
            assert_eq!(url_host(u).unwrap(), "evil.example", "{u}");
            assert!(check(u, Some(&s), true).is_err(), "{u}");
        }
    }

    #[test]
    fn overlapping_entries_exact_beats_wildcard() {
        // exact nonprod entry under a prod wildcard: the exact entry wins
        for order in [
            "[[hosts]]\nhost='*.example'\nenv='prod'\n[[hosts]]\nhost='qa.example'\nenv='nonprod'",
            "[[hosts]]\nhost='qa.example'\nenv='nonprod'\n[[hosts]]\nhost='*.example'\nenv='prod'",
        ] {
            let s = scope(order);
            assert!(check("https://qa.example/", Some(&s), true).unwrap(), "{order}");
            assert!(!check("https://other.example/", Some(&s), true).unwrap(), "{order}");
        }
        // and the other way round
        let s = scope("[[hosts]]\nhost='*.example'\nenv='nonprod'\n[[hosts]]\nhost='www.example'\nenv='prod'");
        assert!(!check("https://www.example/", Some(&s), true).unwrap());
        assert!(check("https://dev.example/", Some(&s), true).unwrap());
    }

    #[test]
    fn overlapping_entries_prod_beats_nonprod() {
        for order in [
            "[[hosts]]\nhost='a.example'\nenv='nonprod'\n[[hosts]]\nhost='a.example'\nenv='prod'",
            "[[hosts]]\nhost='a.example'\nenv='prod'\n[[hosts]]\nhost='a.example'\nenv='nonprod'",
        ] {
            assert!(!check("https://a.example/", Some(&scope(order)), true).unwrap(), "{order}");
        }
        for order in [
            "[[hosts]]\nhost='*.example'\nenv='prod'\n[[hosts]]\nhost='*.stage.example'\nenv='nonprod'",
            "[[hosts]]\nhost='*.stage.example'\nenv='nonprod'\n[[hosts]]\nhost='*.example'\nenv='prod'",
        ] {
            assert!(!check("https://x.stage.example/", Some(&scope(order)), true).unwrap(), "{order}");
        }
        // an env value that is not exactly "nonprod" is prod
        let s = scope("[[hosts]]\nhost='a.example'\nenv='non-prod'");
        assert!(!check("https://a.example/", Some(&s), true).unwrap());
    }

    #[test]
    fn overlapping_equal_wildcards_are_order_independent() {
        let a = scope("[[hosts]]\nhost='*.example'\nenv='nonprod'\n[[hosts]]\nhost='*.b.example'\nenv='nonprod'");
        let b = scope("[[hosts]]\nhost='*.b.example'\nenv='nonprod'\n[[hosts]]\nhost='*.example'\nenv='nonprod'");
        assert_eq!(a.find("x.b.example").unwrap().host, "*.b.example");
        assert_eq!(b.find("x.b.example").unwrap().host, "*.b.example");
    }

    #[test]
    fn egress_guard_gates_intrusive_actions() {
        let s = scope("[[hosts]]\nhost='qa.example'\nenv='nonprod'\n[[hosts]]\nhost='www.example'\nenv='prod'");
        assert!(egress_guard("https://www.example/", Some(&s), false).is_ok());
        assert!(!egress_guard("https://www.example/", Some(&s), false).unwrap().nonprod);
        let e = egress_guard("https://www.example/", Some(&s), true).unwrap_err().to_string();
        assert!(e.contains("nonprod"), "{e}");
        assert!(egress_guard("https://qa.example/x", Some(&s), true).unwrap().nonprod);
        assert!(egress_guard("https://other.example/", Some(&s), false).is_err());
        // no scope file: everything is refused
        assert!(egress_guard("https://qa.example/", None, false).is_err());
        assert!(egress_guard("ftp://qa.example/", Some(&s), false).is_err());
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
