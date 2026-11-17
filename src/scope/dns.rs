//! Host resolution and pattern matching.

use std::net::IpAddr;

use super::ip::{classify_host, HostClass};
use super::url::norm_host;

/// Resolve a name to its addresses with the system resolver (blocking getaddrinfo). Unit tests
/// swap in a local table ([`test_dns`]) so none of them depends on, or waits for, real DNS.
pub fn resolve_name(host: &str) -> std::io::Result<Vec<IpAddr>> {
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
pub mod test_dns {
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
pub fn host_matches(host: &str, pattern: &str) -> bool {
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
