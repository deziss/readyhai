//! Egress public IP discovery, DNS resolution, and IP cache management.

use super::types::{
    IP_CACHE_FAIL_TTL, IP_CACHE_OK_TTL, IP_LOOKUP_BUDGET, IP_PROVIDER_CONNECT, IP_PROVIDER_TIMEOUT,
    RequesterIpInfo,
};
use super::utils::read_capped;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static REQUESTER_IP_CACHE: Mutex<Option<(Instant, Duration, RequesterIpInfo)>> = Mutex::new(None);

pub fn detect_requester_public_ip() -> RequesterIpInfo {
    // An operator override is read on every call: cheap, and a change takes effect at once.
    if let Some(info) = env_override_ip() {
        return info;
    }
    cached_or(
        &REQUESTER_IP_CACHE,
        IP_CACHE_OK_TTL,
        IP_CACHE_FAIL_TTL,
        resolve_public_ip,
    )
}

pub(crate) type IpCache = Mutex<Option<(Instant, Duration, RequesterIpInfo)>>;

/// The cached value while it is fresh, else whatever `resolve` returns (and cache that for
/// `ok_ttl` if it was a real detection, `fail_ttl` if it was only the local fallback).
pub(crate) fn cached_or(
    cache: &IpCache,
    ok_ttl: Duration,
    fail_ttl: Duration,
    resolve: impl FnOnce() -> (RequesterIpInfo, bool),
) -> RequesterIpInfo {
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, ttl, info)) = guard.as_ref()
        && at.elapsed() < *ttl
    {
        return info.clone();
    }
    let (info, detected) = resolve();
    let ttl = if detected { ok_ttl } else { fail_ttl };
    *guard = Some((Instant::now(), ttl, info.clone()));
    info
}

pub(crate) fn env_override_ip() -> Option<RequesterIpInfo> {
    let env_ip = std::env::var("READYHAI_PUBLIC_IP")
        .or_else(|_| std::env::var("READYHAI_EGRESS_IP"))
        .ok()?;
    let trimmed = env_ip.trim();
    if trimmed.is_empty() {
        return None;
    }
    let is_priv = is_private_ip(trimmed);
    Some(RequesterIpInfo {
        egress_public_ip: trimmed.to_string(),
        ip_type: if is_priv {
            "Private Intranet (Manual)"
        } else {
            "Public Egress (Manual)"
        }
        .to_string(),
        is_private: is_priv,
        allowlist_guidance: format!(
            "Add `{trimmed}/32` to target firewall allowlist, AWS Security Group, Cloudflare WAF, or iptables."
        ),
        detected_via: "Environment Variable (READYHAI_PUBLIC_IP)".to_string(),
        detected_at: crate::engine::now(),
    })
}

/// The IP-echo providers, tried in order.
const IP_PROVIDERS: [(&str, &str); 4] = [
    ("api.ipify.org", "https://api.ipify.org"),
    ("checkip.amazonaws.com", "https://checkip.amazonaws.com"),
    ("icanhazip.com", "https://icanhazip.com"),
    ("ifconfig.me", "https://ifconfig.me/ip"),
];

/// Ask the providers for our address. Short timeouts and one overall budget: a blackholed
/// network costs seconds, not minutes. The answer must be a bare IP address.
pub(crate) fn query_ip_providers(providers: &[(&str, &str)]) -> Option<(String, String)> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(IP_PROVIDER_CONNECT)
        .timeout(IP_PROVIDER_TIMEOUT)
        .build()
        .ok()?;
    let t0 = Instant::now();
    for (name, url) in providers {
        if t0.elapsed() >= IP_LOOKUP_BUDGET {
            break;
        }
        let Ok(resp) = client.get(*url).send() else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let (body, _) = read_capped(resp, 128);
        let text = String::from_utf8_lossy(&body);
        if let Ok(ip) = text.trim().parse::<std::net::IpAddr>() {
            return Some((ip.to_string(), (*name).to_string()));
        }
    }
    None
}

/// Returns the info and whether it came from a real detection (vs the local-interface fallback).
pub(crate) fn resolve_public_ip() -> (RequesterIpInfo, bool) {
    resolve_with(crate::bundle::offline(), &IP_PROVIDERS)
}

pub(crate) fn resolve_with(offline: bool, providers: &[(&str, &str)]) -> (RequesterIpInfo, bool) {
    let now = crate::engine::now();

    // Query external IP check providers, unless offline (no internet by definition).
    if !offline && let Some((ip, name)) = query_ip_providers(providers) {
        let is_priv = is_private_ip(&ip);
        return (
            RequesterIpInfo {
                egress_public_ip: ip.clone(),
                ip_type: if is_priv {
                    "Private Network (RFC1918)"
                } else {
                    "Public Egress (Direct)"
                }
                .to_string(),
                is_private: is_priv,
                allowlist_guidance: format!(
                    "Add `{ip}/32` to your target's firewall, AWS Security Group, Cloudflare WAF, or iptables to allow ReadyHai automated QA probes."
                ),
                detected_via: name,
                detected_at: now,
            },
            true,
        );
    }

    // Fallback: local outbound socket address (connecting a UDP socket sends no packet).
    let local_ip = std::net::UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| {
            s.connect("8.8.8.8:80").ok()?;
            s.local_addr().ok().map(|a| a.ip().to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let is_priv = is_private_ip(&local_ip);
    (
        RequesterIpInfo {
            egress_public_ip: local_ip.clone(),
            ip_type: if is_priv {
                "Private Intranet (RFC1918)"
            } else {
                "Local Egress"
            }
            .to_string(),
            is_private: is_priv,
            allowlist_guidance: format!(
                "Add `{local_ip}/32` to your local firewall or internal gateway allowlist."
            ),
            detected_via: if offline {
                "Local Network Interface Socket (offline mode: no external lookup)".to_string()
            } else {
                "Local Network Interface Socket (external lookup failed)".to_string()
            },
            detected_at: now,
        },
        false,
    )
}

/// Is this address internal (loopback, RFC1918, link-local, CGNAT, unique-local v6, ...)? One
/// definition for the crate: [`crate::scope::is_internal_ip`]. Text that is not an IP is not private.
pub fn is_private_ip(ip: &str) -> bool {
    let t = ip.trim().trim_start_matches('[').trim_end_matches(']');
    let t = t.split('%').next().unwrap_or(t); // drop an IPv6 zone id
    t.parse::<std::net::IpAddr>()
        .map(crate::scope::is_internal_ip)
        .unwrap_or(false)
}
