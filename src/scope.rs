//! Rules of engagement for network targets (scope.toml).
//!
//! Policy:
//! - A **public** host is allowed without an entry and defaults to **full testing** (`nonprod = true`):
//!   both non-intrusive actions and intrusive actions (writes, attack payloads, load, agent swarm)
//!   are allowed for any URL unless it is explicitly marked `env = "prod"` in scope.toml.
//! - A **wildcard** `*` is supported in scope.toml to match any host (internal ones too). An exact
//!   entry beats a wildcard and `prod` beats `nonprod`, so `*` + a `prod` entry keeps that one host
//!   read-only.
//! - An **internal** host (loopback, RFC1918, link-local/metadata, CGNAT, unique-local v6, and the
//!   names `localhost`, `*.localhost`, `host.docker.internal`) is refused unless it is listed or
//!   matched by a scope entry (e.g. `host = "*"`).
//! - A listed host always uses its own `env`; `prod` stays read-only.
//! - Intrusive actions on an *unlisted* name that does not resolve are refused: it cannot be told
//!   apart from an internal host, so the guard fails closed.
//! - A scope file that is configured (`READYHAI_SCOPE` / `--scope`) but missing, a directory or
//!   invalid is an **error**, never "no scope".
//! - Remote git clones use the `[git]` host allowlist (seeded with the public
//!   code hosts, so github/gitlab work out of the box; `*` matches all).
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::net::IpAddr;
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
const DEFAULT_GIT_HOSTS: &[&str] = &[
    "github.com",
    "*.github.com",
    "gitlab.com",
    "*.gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
];

/// An IP that must not be reached unless the user explicitly listed its host in
/// scope.toml: loopback, private, link-local (incl. the 169.254.169.254 cloud
/// metadata endpoint), CGNAT, unspecified/reserved/multicast, and the v6
/// equivalents (including v4-mapped and NAT64 forms that embed a v4 address).
/// The single definition of "internal" for the whole crate.
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0 // 0.0.0.0/8 "this network"
                || o[0] >= 240 // 240.0.0.0/4 reserved
                || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 CGNAT
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking
        }
        IpAddr::V6(v6) => {
            if let Some(m) = v6.to_ipv4_mapped() {
                return is_internal_ip(IpAddr::V4(m));
            }
            let seg = v6.segments();
            // 64:ff9b::/96 (NAT64) embeds a v4 address in the last 32 bits.
            if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|s| *s == 0) {
                let [a, b] = seg[6].to_be_bytes();
                let [c, d] = seg[7].to_be_bytes();
                return is_internal_ip(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local (incl. fd00:ec2::254 metadata)
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (seg[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
        }
    }
}

/// Names that always mean "this machine / its container host", whatever DNS says (a resolver
/// that does not know them, or an attacker-controlled one, must not turn them into "public").
fn is_internal_name(h: &str) -> bool {
    h == "localhost"
        || h.ends_with(".localhost")
        || h == "host.docker.internal"
        || h == "gateway.docker.internal"
        || h == "metadata.google.internal"
}

/// How a host classifies for the SSRF guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostClass {
    /// A literal internal IP, an always-internal name, or a name with at least one internal address.
    Internal,
    /// Every resolved address is public.
    Public,
    /// A name that does not resolve: nothing connects to it now, but it cannot be classified.
    Unresolvable,
}

/// Classify `host`. A literal IP is checked directly; the names in [`is_internal_name`] are
/// internal without a lookup; any other name is resolved and counts as internal if *any* of its
/// addresses is (a public name pointing at an internal IP is treated as internal). **Blocking**
/// (getaddrinfo): async callers must run it on the blocking pool.
pub fn classify_host(host: &str) -> HostClass {
    let h = norm_host(host);
    if let Ok(ip) = h.parse::<IpAddr>() {
        return if is_internal_ip(ip) {
            HostClass::Internal
        } else {
            HostClass::Public
        };
    }
    if is_internal_name(&h) {
        return HostClass::Internal;
    }
    match resolve_name(&h) {
        Ok(addrs) => {
            let mut any = false;
            for ip in addrs {
                any = true;
                if is_internal_ip(ip) {
                    return HostClass::Internal;
                }
            }
            if any {
                HostClass::Public
            } else {
                HostClass::Unresolvable
            }
        }
        Err(_) => HostClass::Unresolvable,
    }
}

/// Resolve a name to its addresses with the system resolver (blocking getaddrinfo). Unit tests
/// swap in a local table ([`test_dns`]) so none of them depends on, or waits for, real DNS.
fn resolve_name(host: &str) -> std::io::Result<Vec<IpAddr>> {
    #[cfg(test)]
    {
        test_dns::resolve(host)
    }
    #[cfg(not(test))]
    {
        use std::net::ToSocketAddrs;
        (host, 0u16)
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect())
    }
}

/// Local stand-in for DNS in unit tests. Every name resolves to a public documentation address
/// (203.0.113.7) unless it is under `.invalid` (does not resolve) or was given addresses with
/// [`test_dns::set`]. Names starting `slow-` take 300 ms to answer.
#[cfg(test)]
pub(crate) mod test_dns {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::{Mutex, OnceLock};

    static TABLE: OnceLock<Mutex<HashMap<String, Vec<IpAddr>>>> = OnceLock::new();

    fn table() -> &'static Mutex<HashMap<String, Vec<IpAddr>>> {
        TABLE.get_or_init(Default::default)
    }

    /// Make `name` resolve to `ips` (use a name no other test uses).
    pub fn set(name: &str, ips: &[&str]) {
        table().lock().unwrap_or_else(|e| e.into_inner()).insert(
            name.to_ascii_lowercase(),
            ips.iter().map(|i| i.parse().unwrap()).collect(),
        );
    }

    pub fn resolve(host: &str) -> std::io::Result<Vec<IpAddr>> {
        if let Some(v) = table()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&host.to_ascii_lowercase())
        {
            return Ok(v.clone());
        }
        if host.starts_with("slow-") {
            // a resolver that takes a while (used to prove callers do not block async threads)
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        if host == "invalid" || host.ends_with(".invalid") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such host (test resolver)",
            ));
        }
        Ok(vec!["203.0.113.7".parse().unwrap()])
    }
}

/// Does `host` name an internal address? See [`classify_host`]. A name that does not resolve is
/// *not* internal here (nothing connects to it; the real operation fails later with a plain
/// connection error); intrusive actions on such a name are refused by [`egress_guard`].
pub fn host_is_internal(host: &str) -> bool {
    classify_host(host) == HostClass::Internal
}

/// Host-name matches an allowlist entry (exact, `*.suffix`, or `*`).
fn host_matches(host: &str, pattern: &str) -> bool {
    let (host, pat) = (norm_host(host), norm_host(pattern));
    if pat == "*" {
        return true;
    }
    match pat.strip_prefix("*.") {
        Some(sfx) if !sfx.is_empty() => {
            host.len() > sfx.len() + 1
                && host.ends_with(sfx)
                && host.as_bytes()[host.len() - sfx.len() - 1] == b'.'
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
        bail!(
            "git host '{host}' is internal and not listed — add it under [git] hosts in scope.toml to clone from it"
        );
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

static ACTIVE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

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
fn load_configured(raw: Option<&str>) -> Result<Option<Scope>> {
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

/// Lowercase, no IPv6 brackets, no trailing dot: the form hosts are compared in.
fn norm_host(h: &str) -> String {
    let h = h.trim().to_ascii_lowercase();
    let h = h
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(&h);
    h.trim_end_matches('.').to_string()
}

/// Parse an http(s) URL with the WHATWG parser (the one reqwest uses). Everything that decides
/// "which host will this request hit" must go through here: a hand-rolled authority splitter
/// disagrees with the real client on inputs like `http://evil.example\@allowed.example/`.
pub fn parse_web_url(url: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(url.trim()).map_err(|e| anyhow!("invalid URL: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        bail!(
            "only http:// and https:// targets are accepted (got '{}')",
            u.scheme()
        );
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
pub fn check(url: &str, scope: Option<&Scope>) -> Result<bool> {
    check_host(&url_host(url)?, scope)
}

/// What the scope says about one host.
struct Decision {
    nonprod: bool,
    /// A scope entry governs the host (so its `env` decided, and no DNS lookup was needed).
    listed: bool,
    /// DNS/IP classification; only computed for an unlisted host.
    class: Option<HostClass>,
}

fn decide(host: &str, scope: Option<&Scope>) -> Result<Decision> {
    let host = norm_host(host);
    if host.is_empty() {
        bail!("empty host");
    }
    if let Some(h) = scope.and_then(|s| s.find(&host)) {
        return Ok(Decision {
            nonprod: h.env.eq_ignore_ascii_case("nonprod"),
            listed: true,
            class: None,
        });
    }
    let class = classify_host(&host);
    if class == HostClass::Internal {
        bail!(
            "host '{host}' is internal and not listed in scope.toml — add `[[hosts]] host = \"{host}\"` (env = \"nonprod\" for full testing, \"prod\" for read-only) to test it"
        );
    }
    // Public (or not resolvable), unlisted: allowed, defaults to nonprod (full testing).
    Ok(Decision {
        nonprod: true,
        listed: false,
        class: Some(class),
    })
}

/// Decide a bare host (web, ssh, resolved from a URL). Returns whether it is
/// `nonprod` (intrusive actions allowed). Refuses an **internal** host that is
/// not listed in scope.toml; a public host needs no entry and defaults to
/// nonprod. A listed host always uses its own `env`. **Blocking** for an unlisted name (DNS).
pub fn check_host(host: &str, scope: Option<&Scope>) -> Result<bool> {
    Ok(decide(host, scope)?.nonprod)
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
/// crawl, network lab, scans). A **public** host is allowed with no scope entry (and counts as
/// nonprod); an **internal** host must be listed in scope.toml. `intrusive` actions (writes, attack
/// payloads, load, fault injection) are refused on a host whose scope entry is `prod`, and on an
/// unlisted name that does not resolve (it cannot be classified, so it fails closed). **Blocking**
/// for an unlisted name (DNS): async callers run it on the blocking pool.
pub fn egress_guard(url: &str, scope: Option<&Scope>, intrusive: bool) -> Result<Egress> {
    let u = parse_web_url(url)?;
    let host = norm_host(u.host_str().unwrap_or_default());
    let d = decide(&host, scope)?;
    if intrusive {
        if !d.nonprod {
            // Only a listed host can be non-nonprod: unlisted public hosts default to nonprod.
            bail!(
                "host '{host}' is tagged env = \"prod\" in scope.toml; intrusive actions (writes, attacks, load) are refused on prod hosts"
            );
        }
        if !d.listed && d.class == Some(HostClass::Unresolvable) {
            bail!(
                "host '{host}' does not resolve, so it cannot be classified as public or internal; intrusive actions (writes, attacks, load, fault injection) are refused until it resolves or is listed in scope.toml"
            );
        }
    }
    Ok(Egress {
        url: u.to_string(),
        host,
        nonprod: d.nonprod,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(toml_text: &str) -> Scope {
        toml::from_str(toml_text).unwrap()
    }

    #[test]
    fn hosts() {
        assert_eq!(
            url_host("https://user:pw@App.Example.com:8443/x?y").unwrap(),
            "app.example.com"
        );
        let s = scope(
            "[[hosts]]\nhost='*.nonprod.example'\nenv='nonprod'\n[[hosts]]\nhost='app.example'\nenv='prod'",
        );
        // listed entries use their env
        assert!(check("https://a.nonprod.example/", Some(&s)).unwrap());
        assert!(!check("https://app.example/", Some(&s)).unwrap());
        // an unlisted public host is allowed for full testing by default (nonprod = true)
        assert!(check("https://evil.example/", Some(&s)).unwrap());
        assert!(check("https://x.unlisted.example/", None).unwrap());
        assert!(check("https://nonprod.example/", Some(&s)).unwrap());
        assert!(check("https://anonprod.example/", Some(&s)).unwrap());
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
        assert!(check("http://169.254.169.254/latest/meta-data/", None).is_err());
        assert!(check("http://10.0.0.5:8080/", None).is_err());
        // but a listed internal host is allowed with its env
        let s = scope(
            "[[hosts]]\nhost='10.0.0.5'\nenv='nonprod'\n[[hosts]]\nhost='127.0.0.1'\nenv='prod'",
        );
        assert!(check("http://10.0.0.5:8080/", Some(&s)).unwrap());
        assert!(!check("http://127.0.0.1/", Some(&s)).unwrap()); // listed prod → read-only
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
        let s = scope(
            "[[hosts]]\nhost='APP.example.'\nenv='nonprod'\n[[hosts]]\nhost='[::1]'\nenv='nonprod'",
        );
        assert!(check("http://app.example/", Some(&s)).unwrap());
        assert!(check("http://[::1]:9/", Some(&s)).unwrap());
    }

    #[test]
    fn only_http_and_https() {
        for u in [
            "ftp://app.example/",
            "file:///etc/passwd",
            "ssh://app.example",
            "javascript:alert(1)",
            "app.example",
            "",
        ] {
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
        assert_eq!(
            url_host("http://10.9.9.9\\@allowed.internal/").unwrap(),
            "10.9.9.9"
        );
        assert!(check("http://10.9.9.9\\@allowed.internal/", Some(&s)).is_err());
        assert!(egress_guard("http://10.9.9.9\\@allowed.internal/", Some(&s), false).is_err());
        // and the reverse: what looks foreign to a naive parser is really the listed host
        let s = scope("[[hosts]]\nhost='app.example'\nenv='nonprod'");
        assert_eq!(
            url_host("http://app.example\\@evil.example/").unwrap(),
            "app.example"
        );
        let e = egress_guard("http://app.example\\@evil.example/x", Some(&s), false).unwrap();
        assert_eq!(e.host, "app.example");
        // the normalised URL no longer contains the ambiguous backslash
        assert!(!e.url.contains('\\'), "{}", e.url);
        assert_eq!(url_host(&e.url).unwrap(), "app.example");
        // authority tricks all resolve to the real host
        for u in [
            "http://evil.example#@app.example/",
            "http://evil.example?@app.example/",
            "http://app.example@evil.example/",
            "http://app.example:80@evil.example/",
        ] {
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
            assert!(check("https://qa.example/", Some(&s)).unwrap(), "{order}");
            assert!(
                !check("https://other.example/", Some(&s)).unwrap(),
                "{order}"
            );
        }
        // and the other way round
        let s = scope(
            "[[hosts]]\nhost='*.example'\nenv='nonprod'\n[[hosts]]\nhost='www.example'\nenv='prod'",
        );
        assert!(!check("https://www.example/", Some(&s)).unwrap());
        assert!(check("https://dev.example/", Some(&s)).unwrap());
    }

    #[test]
    fn overlapping_entries_prod_beats_nonprod() {
        for order in [
            "[[hosts]]\nhost='a.example'\nenv='nonprod'\n[[hosts]]\nhost='a.example'\nenv='prod'",
            "[[hosts]]\nhost='a.example'\nenv='prod'\n[[hosts]]\nhost='a.example'\nenv='nonprod'",
        ] {
            assert!(
                !check("https://a.example/", Some(&scope(order))).unwrap(),
                "{order}"
            );
        }
        for order in [
            "[[hosts]]\nhost='*.example'\nenv='prod'\n[[hosts]]\nhost='*.stage.example'\nenv='nonprod'",
            "[[hosts]]\nhost='*.stage.example'\nenv='nonprod'\n[[hosts]]\nhost='*.example'\nenv='prod'",
        ] {
            assert!(
                !check("https://x.stage.example/", Some(&scope(order))).unwrap(),
                "{order}"
            );
        }
        // an env value that is not exactly "nonprod" is prod
        let s = scope("[[hosts]]\nhost='a.example'\nenv='non-prod'");
        assert!(!check("https://a.example/", Some(&s)).unwrap());
    }

    #[test]
    fn overlapping_equal_wildcards_are_order_independent() {
        let a = scope(
            "[[hosts]]\nhost='*.example'\nenv='nonprod'\n[[hosts]]\nhost='*.b.example'\nenv='nonprod'",
        );
        let b = scope(
            "[[hosts]]\nhost='*.b.example'\nenv='nonprod'\n[[hosts]]\nhost='*.example'\nenv='nonprod'",
        );
        assert_eq!(a.find("x.b.example").unwrap().host, "*.b.example");
        assert_eq!(b.find("x.b.example").unwrap().host, "*.b.example");
    }

    #[test]
    fn egress_guard_gates_intrusive_actions() {
        let s = scope(
            "[[hosts]]\nhost='qa.example'\nenv='nonprod'\n[[hosts]]\nhost='www.example'\nenv='prod'",
        );
        assert!(egress_guard("https://www.example/", Some(&s), false).is_ok());
        assert!(
            !egress_guard("https://www.example/", Some(&s), false)
                .unwrap()
                .nonprod
        );
        let e = egress_guard("https://www.example/", Some(&s), true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("prod") && e.contains("refused"), "{e}");
        assert!(
            egress_guard("https://qa.example/x", Some(&s), true)
                .unwrap()
                .nonprod
        );
        // an unlisted PUBLIC host is allowed for full testing (defaults to nonprod)
        assert!(egress_guard("https://other.example/", Some(&s), false).is_ok());
        assert!(egress_guard("https://other.example/", Some(&s), true).is_ok());
        assert!(egress_guard("https://other.example/", None, true).is_ok());
        // no scope file: public hosts allowed, internal still refused
        assert!(egress_guard("https://qa.example/", None, false).is_ok());
        assert!(egress_guard("http://127.0.0.1:8080/", None, true).is_err());
        assert!(egress_guard("ftp://qa.example/", Some(&s), false).is_err());
        // wildcard * in scope allows any host (both public and internal)
        let any_scope = scope("[[hosts]]\nhost='*'\nenv='nonprod'");
        assert!(egress_guard("https://deziss.com/", Some(&any_scope), true).is_ok());
        assert!(egress_guard("http://127.0.0.1:8080/", Some(&any_scope), true).is_ok());
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
        assert_eq!(
            h.resilience.as_ref().unwrap().services,
            vec!["postgres", "redis"]
        );
        let s: Scope = toml::from_str("[[hosts]]\nhost='a'\nenv='prod'").unwrap();
        assert!(s.hosts[0].perf.is_none() && s.hosts[0].resilience.is_none());
    }

    // ---------------------------------------------------------------- fail-closed loading

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("readyhai-scope-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_unloadable_scope_is_refused_never_treated_as_no_scope() {
        let d = tmp_dir("unloadable");
        // missing file
        let missing = d.join("scope.toml");
        let e = format!("{:#}", Scope::load(&missing).unwrap_err());
        assert!(
            e.contains("cannot be read") && e.contains("scope.example.toml"),
            "{e}"
        );
        // a directory (what `docker compose up` makes when the bind-mount source is missing)
        let dir = d.join("adir");
        std::fs::create_dir_all(&dir).unwrap();
        let e = format!("{:#}", Scope::load(&dir).unwrap_err());
        assert!(
            e.contains("is a directory") && e.contains("cp scope.example.toml scope.toml"),
            "{e}"
        );
        // invalid TOML, and a wrong shape
        let bad = d.join("bad.toml");
        std::fs::write(&bad, "[[hosts]\nhost = ").unwrap();
        let e = format!("{:#}", Scope::load(&bad).unwrap_err());
        assert!(e.contains("not valid"), "{e}");
        std::fs::write(&bad, "[[hosts]]\nhost = 'a'\n").unwrap(); // env missing
        assert!(Scope::load(&bad).is_err());

        // configured-but-broken is an Err through every entry point: no "no scope" outcome
        for p in [&missing, &dir, &bad] {
            let r = load_configured(Some(p.to_str().unwrap()));
            assert!(r.is_err(), "{}", p.display());
            assert!(
                format!("{:#}", r.unwrap_err()).contains("refusing"),
                "{}",
                p.display()
            );
        }
        // only "not configured" (or blank) means no scope
        assert!(load_configured(None).unwrap().is_none());
        assert!(load_configured(Some("")).unwrap().is_none());
        assert!(load_configured(Some("   ")).unwrap().is_none());
        // a good file loads
        let ok = d.join("ok.toml");
        std::fs::write(&ok, "[[hosts]]\nhost='a.example'\nenv='prod'\n").unwrap();
        let s = load_configured(Some(ok.to_str().unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(s.hosts.len(), 1);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn shipped_scope_files_parse() {
        let root = env!("CARGO_MANIFEST_DIR");
        // the example is part of the repo and must always load
        let ex = Scope::load(&std::path::Path::new(root).join("scope.example.toml"))
            .expect("scope.example.toml must parse");
        assert!(!ex.hosts.is_empty());
        // scope.toml is the operator's local copy (absent on a fresh clone): when it exists it must parse
        let own = std::path::Path::new(root).join("scope.toml");
        let mut files = vec![("scope.example.toml", ex)];
        if own.is_file() {
            files.push((
                "scope.toml",
                Scope::load(&own).expect("scope.toml must parse"),
            ));
        }
        for (name, s) in files {
            for h in &s.hosts {
                assert!(!h.host.trim().is_empty(), "{name}: empty host");
                assert!(
                    h.env == "prod" || h.env == "nonprod",
                    "{name}: {} has env {:?} (expected prod|nonprod)",
                    h.host,
                    h.env
                );
            }
        }
    }

    // ---------------------------------------------------------------- policy: prod beats *

    #[test]
    fn a_prod_listed_host_stays_read_only_next_to_the_wildcard() {
        let s = scope(
            "[[hosts]]\nhost='app.shop.example'\nenv='prod'\n[[hosts]]\nhost='*.shop.example'\nenv='prod'\n[[hosts]]\nhost='*'\nenv='nonprod'\n[git]\nhosts=['*']\n",
        );
        // reads are fine, intrusive actions are refused, with the prod reason
        for url in ["https://app.shop.example/", "https://www.shop.example/x"] {
            assert!(
                !egress_guard(url, Some(&s), false).unwrap().nonprod,
                "{url}"
            );
            let e = egress_guard(url, Some(&s), true).unwrap_err().to_string();
            assert!(e.contains("prod") && e.contains("refused"), "{url}: {e}");
        }
        // everything else the wildcard covers is fully testable, public or internal
        assert!(
            egress_guard("https://other.example/", Some(&s), true)
                .unwrap()
                .nonprod
        );
        assert!(
            egress_guard("http://127.0.0.1:8080/", Some(&s), true)
                .unwrap()
                .nonprod
        );
        // same result whichever order the file lists them in
        let s = scope(
            "[[hosts]]\nhost='*'\nenv='nonprod'\n[[hosts]]\nhost='app.shop.example'\nenv='prod'\n",
        );
        assert!(egress_guard("https://app.shop.example/", Some(&s), true).is_err());
        assert!(egress_guard("https://app.shop.example/", Some(&s), false).is_ok());
        // the shipped example, with a prod entry added, behaves the same way
        let ex = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scope.example.toml"),
        )
        .unwrap();
        let s = scope(&format!(
            "{ex}\n[[hosts]]\nhost='app.example.com'\nenv='prod'\n"
        ));
        assert!(egress_guard("https://app.example.com/", Some(&s), true).is_err());
        assert!(egress_guard("https://app.example.com/", Some(&s), false).is_ok());
    }

    // ---------------------------------------------------------------- internal names, DNS

    #[test]
    fn internal_names_are_internal_whatever_dns_says() {
        // even a resolver that maps them to a public address cannot make them public
        test_dns::set("localhost", &["8.8.8.8"]);
        test_dns::set("host.docker.internal", &["8.8.8.8"]);
        test_dns::set("api.localhost", &["8.8.8.8"]);
        for h in [
            "localhost",
            "LOCALHOST.",
            "api.localhost",
            "a.b.localhost",
            "host.docker.internal",
            "metadata.google.internal",
        ] {
            assert_eq!(classify_host(h), HostClass::Internal, "{h}");
            assert!(check_host(h, None).is_err(), "{h} must need an entry");
            assert!(
                egress_guard(&format!("http://{h}/"), None, false).is_err(),
                "{h}"
            );
        }
        // not fooled by lookalikes
        assert_eq!(classify_host("notlocalhost.example"), HostClass::Public);
        assert_eq!(classify_host("localhost.example"), HostClass::Public);
        // listed, they are testable
        let s = scope(
            "[[hosts]]\nhost='*.localhost'\nenv='nonprod'\n[[hosts]]\nhost='localhost'\nenv='nonprod'",
        );
        assert!(egress_guard("http://api.localhost:3000/", Some(&s), true).is_ok());
        assert!(egress_guard("http://localhost:3000/", Some(&s), true).is_ok());
    }

    #[test]
    fn a_public_name_with_an_internal_address_is_internal() {
        test_dns::set("rebind.example", &["10.1.2.3"]);
        test_dns::set("mixed.example", &["93.184.216.34", "192.168.1.5"]);
        test_dns::set("v6.example", &["fd00::1"]);
        test_dns::set("fine.example", &["93.184.216.34", "2606:2800:220:1::1"]);
        for h in ["rebind.example", "mixed.example", "v6.example"] {
            assert_eq!(classify_host(h), HostClass::Internal, "{h}");
            assert!(
                egress_guard(&format!("https://{h}/"), None, false).is_err(),
                "{h}"
            );
        }
        assert_eq!(classify_host("fine.example"), HostClass::Public);
        assert!(egress_guard("https://fine.example/", None, true).is_ok());
    }

    #[test]
    fn unresolvable_names_are_refused_for_intrusive_actions_only() {
        // an unlisted name that does not resolve cannot be told apart from an internal host
        assert_eq!(classify_host("nx.invalid"), HostClass::Unresolvable);
        assert!(egress_guard("https://nx.invalid/", None, false).is_ok());
        let e = egress_guard("https://nx.invalid/", None, true)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("does not resolve") && e.contains("intrusive"),
            "{e}"
        );
        // a scope entry decides for a listed name, with no lookup needed
        let s = scope("[[hosts]]\nhost='nx.invalid'\nenv='nonprod'");
        assert!(egress_guard("https://nx.invalid/", Some(&s), true).is_ok());
        let s = scope("[[hosts]]\nhost='*'\nenv='nonprod'");
        assert!(egress_guard("https://other.invalid/", Some(&s), true).is_ok());
        // a resolvable public name is unaffected
        assert!(egress_guard("https://app.example/", None, true).is_ok());
    }

    #[test]
    fn more_internal_ranges() {
        for ip in [
            "0.1.2.3",
            "224.0.0.1",
            "240.0.0.1",
            "198.18.0.1",
            "ff02::1",
            "fec0::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1", // NAT64 of 10.0.0.1
            "64:ff9b::7f00:1",
        ] {
            assert!(is_internal_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "64:ff9b::808:808", // NAT64 of 8.8.8.8
            "100.63.255.255",
            "100.128.0.1",
        ] {
            assert!(!is_internal_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}
