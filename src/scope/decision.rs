//! Egress decision engine and intrusive action gating.

use anyhow::{bail, Result};

use super::config::Scope;
use super::ip::{classify_host, HostClass};
use super::url::{norm_host, parse_web_url, url_host};

/// Is the web target allowed, and is it nonprod (for intrusive checks)?
pub fn check(url: &str, scope: Option<&Scope>) -> Result<bool> {
    check_host(&url_host(url)?, scope)
}

/// What the scope says about one host.
pub(crate) struct Decision {
    pub nonprod: bool,
    /// A scope entry governs the host (so its `env` decided, and no DNS lookup was needed).
    pub listed: bool,
    /// DNS/IP classification; only computed for an unlisted host.
    pub class: Option<HostClass>,
}

pub(crate) fn decide(host: &str, scope: Option<&Scope>) -> Result<Decision> {
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
