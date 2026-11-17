//! Internal IP and network classification for SSRF mitigation.

use std::net::IpAddr;

use super::dns::resolve_name;
use super::url::norm_host;

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
pub fn is_internal_name(h: &str) -> bool {
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
