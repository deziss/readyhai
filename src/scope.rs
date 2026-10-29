//! Rules of engagement for network targets (scope.toml).
//!
//! Policy (relaxed 2026-10): scope.toml no longer has to list every target.
//! - A **public** host is allowed without an entry and defaults to `nonprod`
//!   (full testing), because the user typed a public address they can reach.
//! - An **internal** host (loopback, RFC1918, link-local/metadata, CGNAT,
//!   unique-local v6) is refused *unless* it is listed in scope.toml. Listing it
//!   is the user vouching "this private host is mine to test". This keeps the
//!   SSRF protection (no accidental hit on 169.254.169.254 or an internal box)
//!   while removing the per-host friction for public targets.
//! - A listed host always uses its own `env`; `prod` stays read-only.
//! - Remote git clones use the `[git]` host allowlist (seeded with the public
//!   code hosts, so github/gitlab work out of the box).
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;

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

/// Public code hosts allowed for `git clone` with no scope.toml entry.
const DEFAULT_GIT_HOSTS: &[&str] =
    &["github.com", "*.github.com", "gitlab.com", "*.gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht"];

/// An IP that must not be reached unless the user explicitly listed its host in
/// scope.toml: loopback, private, link-local (incl. the 169.254.169.254 cloud
/// metadata endpoint), CGNAT, and the v6 equivalents.
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || matches!(v4.octets(), [100, b, ..] if (64..=127).contains(&b)) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => {
            if let Some(m) = v6.to_ipv4_mapped() {
                return is_internal_ip(IpAddr::V4(m));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local (incl. fd00:ec2::254 metadata)
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Does `host` name an internal address? A literal IP is checked directly; a
/// name is resolved and counts as internal if *any* of its addresses is (a
/// public name pointing at an internal IP is treated as internal). A name that
/// does not resolve is treated as public — nothing connects to it, and the real
/// operation fails later with a plain connection error.
pub fn host_is_internal(host: &str) -> bool {
    let h = norm_host(host);
    if let Ok(ip) = h.parse::<IpAddr>() {
        return is_internal_ip(ip);
    }
    match (h.as_str(), 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|a| a.ip()).any(is_internal_ip),
        Err(_) => false,
    }
}

/// Host-name matches an allowlist entry (exact, or `*.suffix`).
fn host_matches(host: &str, pattern: &str) -> bool {
    let (host, pat) = (norm_host(host), norm_host(pattern));
    match pat.strip_prefix("*.") {
        Some(sfx) if !sfx.is_empty() => {
            host.len() > sfx.len() + 1 && host.ends_with(sfx) && host.as_bytes()[host.len() - sfx.len() - 1] == b'.'
        }
        _ => host == pat,
    }
}

/// A remote git clone host is allowed when it is a known public code host or is
/// listed under `[git] hosts`. (A listed host may be internal: that is the user
/// vouching for their own git server.) Public but unlisted hosts are allowed so
/// `github.com/...` just works; an unknown *internal* host is refused.
pub fn check_git_host(host: &str, scope: Option<&Scope>) -> Result<()> {
    let host = norm_host(host);
    if host.is_empty() {
        bail!("empty git host");
    }
    let listed = DEFAULT_GIT_HOSTS.iter().any(|p| host_matches(&host, p))
        || scope.is_some_and(|s| s.git.hosts.iter().any(|p| host_matches(&host, p)));
    if listed {
        return Ok(());
    }
    if host_is_internal(&host) {
        bail!("git host '{host}' is internal and not listed — add it under [git] hosts in scope.toml to clone from it");
    }
    Ok(())
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
/// `_required` is kept for call-site compatibility; the policy no longer depends
/// on it (public hosts are allowed without a scope file).
pub fn check(url: &str, scope: Option<&Scope>, _required: bool) -> Result<bool> {
    check_host(&url_host(url)?, scope, _required)
}

/// Decide a bare host (web, ssh, resolved from a URL). Returns whether it is
/// `nonprod` (intrusive actions allowed). Refuses an **internal** host that is
/// not listed in scope.toml; a public host needs no entry and defaults to
/// nonprod. A listed host always uses its own `env`.
pub fn check_host(host: &str, scope: Option<&Scope>, _required: bool) -> Result<bool> {
    let host = norm_host(host);
    if host.is_empty() {
        bail!("empty host");
    }
    if let Some(h) = scope.and_then(|s| s.find(&host)) {
        return Ok(h.env.eq_ignore_ascii_case("nonprod"));
    }
    if host_is_internal(&host) {
        bail!(
            "host '{host}' is internal and not listed in scope.toml — add it (env = \"nonprod\" for full testing, \"prod\" for read-only) to test it"
        );
    }
    // Public, unlisted: allowed, treated as a nonprod test target.
    Ok(true)
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
/// crawl, network lab, scans). A **public** host is allowed with no scope entry; an **internal**
/// host must be listed in scope.toml. `intrusive` actions (writes, attack payloads, load, fault
/// injection) are refused on any host whose scope entry is not `nonprod`.
pub fn egress_guard(url: &str, scope: Option<&Scope>, intrusive: bool) -> Result<Egress> {
    let u = parse_web_url(url)?;
    let host = norm_host(u.host_str().unwrap_or_default());
    let nonprod = check_host(&host, scope, true)?;
    if intrusive && !nonprod {
        bail!("host '{host}' is tagged env = \"prod\" in scope.toml; intrusive actions (writes, attacks, load) are refused on prod hosts");
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
        // listed entries use their env
        assert!(check("https://a.nonprod.example/", Some(&s), true).unwrap());
        assert!(!check("https://app.example/", Some(&s), true).unwrap());
        // a public host that is not listed is allowed and treated as nonprod (relaxed policy)
        assert!(check("https://evil.example/", Some(&s), true).unwrap());
        assert!(check("https://x.unlisted.example/", None, true).unwrap());
        // a wildcard still does not match the bare suffix or a look-alike (but those are public → nonprod)
        assert!(check("https://nonprod.example/", Some(&s), true).unwrap());
        assert!(check("https://anonprod.example/", Some(&s), true).unwrap());
    }

    #[test]
    fn internal_hosts_need_an_entry() {
        assert!(is_internal_ip("127.0.0.1".parse().unwrap()));
        assert!(is_internal_ip("10.1.2.3".parse().unwrap()));
        assert!(is_internal_ip("192.168.0.9".parse().unwrap()));
        assert!(is_internal_ip("169.254.169.254".parse().unwrap())); // cloud metadata
        assert!(is_internal_ip("100.100.0.1".parse().unwrap())); // CGNAT
        assert!(is_internal_ip("::1".parse().unwrap()));
        assert!(is_internal_ip("fd00:ec2::254".parse().unwrap())); // unique-local metadata
        assert!(!is_internal_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_internal_ip("1.1.1.1".parse().unwrap()));
        // an unlisted internal IP target is refused
        assert!(check("http://169.254.169.254/latest/meta-data/", None, true).is_err());
        assert!(check("http://10.0.0.5:8080/", None, true).is_err());
        // but a listed internal host is allowed with its env
        let s = scope("[[hosts]]\nhost='10.0.0.5'\nenv='nonprod'\n[[hosts]]\nhost='127.0.0.1'\nenv='prod'");
        assert!(check("http://10.0.0.5:8080/", Some(&s), true).unwrap());
        assert!(!check("http://127.0.0.1/", Some(&s), true).unwrap()); // listed prod → read-only
    }

    #[test]
    fn git_host_allowlist() {
        assert!(check_git_host("github.com", None).is_ok());
        assert!(check_git_host("gist.github.com", None).is_ok());
        assert!(check_git_host("gitlab.com", None).is_ok());
        // an unknown public host is allowed to clone (public code can live anywhere)
        assert!(check_git_host("git.example.com", None).is_ok());
        // an internal git host is refused unless listed under [git] hosts
        assert!(check_git_host("10.0.0.9", None).is_err());
        let s = scope("[git]\nhosts=['git.internal', '10.0.0.9']");
        assert!(check_git_host("10.0.0.9", Some(&s)).is_ok());
        assert!(check_git_host("git.internal", Some(&s)).is_ok());
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
        // Prove the guard keys off the REAL host (before the backslash), not the decoy after it,
        // using an internal host that is blocked unless listed: if the parser were fooled into
        // reading `allowed.internal` the request would be allowed; it must read `10.9.9.9` and refuse.
        let s = scope("[[hosts]]\nhost='allowed.internal'\nenv='nonprod'");
        assert_eq!(url_host("http://10.9.9.9\\@allowed.internal/").unwrap(), "10.9.9.9");
        assert!(check("http://10.9.9.9\\@allowed.internal/", Some(&s), true).is_err());
        assert!(egress_guard("http://10.9.9.9\\@allowed.internal/", Some(&s), false).is_err());
        // and the reverse: what looks foreign to a naive parser is really the listed host
        let s = scope("[[hosts]]\nhost='app.example'\nenv='nonprod'");
        assert_eq!(url_host("http://app.example\\@evil.example/").unwrap(), "app.example");
        let e = egress_guard("http://app.example\\@evil.example/x", Some(&s), false).unwrap();
        assert_eq!(e.host, "app.example");
        // the normalised URL no longer contains the ambiguous backslash
        assert!(!e.url.contains('\\'), "{}", e.url);
        assert_eq!(url_host(&e.url).unwrap(), "app.example");
        // authority tricks all resolve to the real host
        for u in ["http://evil.example#@app.example/", "http://evil.example?@app.example/", "http://app.example@evil.example/", "http://app.example:80@evil.example/"] {
            assert_eq!(url_host(u).unwrap(), "evil.example", "{u}");
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
        assert!(e.contains("prod") && e.contains("refused"), "{e}");
        assert!(egress_guard("https://qa.example/x", Some(&s), true).unwrap().nonprod);
        // an unlisted PUBLIC host is allowed (relaxed policy), even for intrusive actions
        assert!(egress_guard("https://other.example/", Some(&s), false).is_ok());
        assert!(egress_guard("https://other.example/", Some(&s), true).unwrap().nonprod);
        // no scope file: public hosts allowed, internal still refused
        assert!(egress_guard("https://qa.example/", None, false).is_ok());
        assert!(egress_guard("http://127.0.0.1:8080/", None, true).is_err());
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
