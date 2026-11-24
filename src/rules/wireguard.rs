//! WireGuard (wg-quick style) configuration auditing.
//!
//! Scans `*.conf` / `*.wgconfig` files that parse as WireGuard config
//! (an `[Interface]` or `[Peer]` section plus at least one WireGuard-specific
//! directive) and reports committed key material, key reuse, default-route
//! overreach, weak keys, duplicate ListenPorts, missing keepalives and
//! `[Interface]` sections without `Address=`. Line-based parsing only: no
//! external deps, and key values are never echoed into finding messages.

use super::facts::{Skips, read_checked};
use super::na;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Finding, Severity};
use crate::snapshot::Snapshot;
use std::collections::BTreeMap;

// ---------- parsing ----------

#[derive(Debug)]
struct Opt {
    /// Lower-cased directive key (wg-quick keys are case-insensitive).
    key: String,
    value: String,
    line: usize,
}

#[derive(Debug)]
struct Section {
    /// Lower-cased section name ("interface" | "peer" | ...).
    name: String,
    line: usize,
    opts: Vec<Opt>,
}

#[derive(Debug)]
struct WgConfig {
    file: String,
    sections: Vec<Section>,
}

/// Parses wg-quick INI-ish content: `[Section]` headers and `Key = Value` lines.
/// Comments (`#`, `;`) and blanks are skipped; within a section the first
/// occurrence of a key wins, matching wg-quick's behaviour of honouring the
/// first definition.
fn parse(file: &str, text: &str) -> WgConfig {
    let mut sections: Vec<Section> = vec![];
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            sections.push(Section {
                name: line[1..line.len() - 1].trim().to_lowercase(),
                line: i + 1,
                opts: vec![],
            });
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if let Some(sec) = sections.last_mut() {
            let key = k.trim().to_lowercase();
            if !sec.opts.iter().any(|o| o.key == key) {
                sec.opts.push(Opt {
                    key,
                    value: v.trim().to_string(),
                    line: i + 1,
                });
            }
        }
    }
    WgConfig {
        file: file.to_string(),
        sections,
    }
}

/// Directives that only exist in WireGuard configs; their presence (together
/// with an `[Interface]`/`[Peer]` section) distinguishes a wg config from
/// look-alike `.conf` files such as nginx.conf.
const WG_DIRECTIVES: [&str; 9] = [
    "privatekey",
    "privatekeyfile",
    "publickey",
    "presharedkey",
    "presharedkeyfile",
    "allowedips",
    "listenport",
    "persistentkeepalive",
    "endpoint",
];

/// True when the content looks like a WireGuard configuration.
pub(crate) fn is_wireguard(text: &str) -> bool {
    let cfg = parse("", text);
    cfg.sections
        .iter()
        .any(|s| s.name == "interface" || s.name == "peer")
        && cfg.sections.iter().any(|s| {
            s.opts
                .iter()
                .any(|o| WG_DIRECTIVES.contains(&o.key.as_str()))
        })
}

// ---------- key checks ----------

/// Minimal base64 decoder (std alphabet, `=` padding). None for invalid input
/// or any length that is not 32 bytes, which is what WG keys must be.
fn b64_to_32(src: &str) -> Option<()> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out: Vec<u8> = vec![];
    let mut seen_pad = false;
    for &c in src.as_bytes() {
        if c == b'=' {
            seen_pad = true;
            continue;
        }
        if seen_pad {
            return None; // data after padding is malformed
        }
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // A 4k+1 character body cannot be valid base64 (8 leftover bits).
    if bits > 4 || src.len() % 4 == 1 {
        return None;
    }
    if out.len() == 32 { Some(()) } else { None }
}

/// Why a key value is weak, if it is: not decodable base64, wrong length, or
/// all-zero (which covers the `AAAA…=` example-placeholder key).
fn weak_reason(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("empty key value");
    }
    if b64_to_32(value).is_none() {
        return Some("not base64 that decodes to a 32-byte key");
    }
    // All-zero key: every base64 char of the body is 'A' ('/' of padding).
    if value.trim_end_matches('=').chars().all(|c| c == 'A') {
        return Some("all-zero (placeholder) key");
    }
    None
}

/// Splits an `AllowedIPs=` value into CIDR entries.
fn split_ips(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// True for full-tunnel default routes (0.0.0.0/0 or ::/0).
fn is_default_route(cidr: &str) -> bool {
    cidr == "0.0.0.0/0" || cidr == "::/0"
}

// ---------- the check ----------

pub(crate) fn wireguard_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "wireguard";
    if ctx.facts.wg_files.is_empty() {
        return na("no WireGuard configuration files");
    }
    let mut out: Vec<Finding> = vec![];
    let mut skips = Skips::default();

    // Map for key reuse: key kind -> value -> occurrences "file:line".
    let mut occurrences: BTreeMap<(&str, String), Vec<String>> = BTreeMap::new();
    // ListenPort -> every "[Interface]" occurrence "file:line".
    let mut ports: BTreeMap<u32, Vec<String>> = BTreeMap::new();

    for file in &ctx.facts.wg_files {
        let text = match read_checked(snap, file) {
            Ok(t) => t,
            Err(why) => {
                skips.add(file, why);
                continue;
            }
        };
        let cfg = parse(file, &text);

        for sec in &cfg.sections {
            let mk = |rule: &str,
                      cat: Category,
                      sev: Severity,
                      title: String,
                      line: usize,
                      detail: &str,
                      fp_extra: &str| {
                let loc = format!("{}:{}", cfg.file, line);
                Finding::new(C, &format!("{C}.{rule}"), cat, sev, title, loc)
                    .detail(detail.to_string())
                    .fp_key(format!("{C}.{rule}:{file}:{line}{fp_extra}"))
            };

            if sec.name == "interface" {
                // 1. committed private key
                if let Some(o) = sec.opts.iter().find(|o| o.key == "privatekey") {
                    if !o.value.is_empty() {
                        out.push(mk(
                            "private-key-committed",
                            Category::Security,
                            Severity::High,
                            format!(
                                "Interface private key committed to the tree ({} chars, redacted)",
                                o.value.chars().count()
                            ),
                            o.line,
                            "`PrivateKey=` in a [Interface] section is live key material; \
                             anyone with repo access can impersonate this peer.",
                            "",
                        ));
                        occurrences
                            .entry(("privkey", o.value.clone()))
                            .or_default()
                            .push(format!("{}:{}", cfg.file, o.line));
                    }
                    // 4. weak key material on the interface key too
                    if let Some(why) = weak_reason(&o.value) {
                        out.push(mk(
                            "weak-key-material",
                            Category::Security,
                            Severity::Medium,
                            format!("Interface PrivateKey is weak: {why}"),
                            o.line,
                            "WireGuard keys must be 32 random bytes base64-encoded; \
                             placeholder or malformed keys weaken or break the tunnel.",
                            "",
                        ));
                    }
                }
                // 7. interface without Address=
                if !sec
                    .opts
                    .iter()
                    .any(|o| o.key == "address" && !o.value.is_empty())
                {
                    out.push(mk(
                        "missing-address",
                        Category::Reliability,
                        Severity::Medium,
                        "[Interface] section has no Address= entry".to_string(),
                        sec.line,
                        "Without an Address= entry the interface comes up with no tunnel IP \
                         and cannot route any traffic.",
                        "",
                    ));
                }
                // 5. collect ListenPort occurrences for conflict detection
                if let Some(o) = sec.opts.iter().find(|o| o.key == "listenport")
                    && let Ok(p) = o.value.trim().parse::<u32>()
                {
                    ports
                        .entry(p)
                        .or_default()
                        .push(format!("{}:{}", cfg.file, o.line));
                }
            }

            if sec.name == "peer" {
                // 1. committed preshared key
                if let Some(o) = sec.opts.iter().find(|o| o.key == "presharedkey")
                    && !o.value.is_empty()
                {
                    out.push(mk(
                        "private-key-committed",
                        Category::Security,
                        Severity::High,
                        format!(
                            "Peer PresharedKey committed to the tree ({} chars, redacted)",
                            o.value.chars().count()
                        ),
                        o.line,
                        "`PresharedKey=` in a [Peer] section is live key material; \
                         it defeats the extra layer PSKs are meant to add.",
                        "",
                    ));
                }
                // 4. weak key material on peer keys
                for o in sec
                    .opts
                    .iter()
                    .filter(|o| o.key == "publickey" || o.key == "presharedkey")
                {
                    if let Some(why) = weak_reason(&o.value) {
                        out.push(mk(
                            "weak-key-material",
                            Category::Security,
                            Severity::Medium,
                            format!("Peer {} is weak: {why}", o.key),
                            o.line,
                            "WireGuard keys must be 32 random bytes base64-encoded; \
                             placeholder or malformed keys weaken or break the tunnel.",
                            "",
                        ));
                    }
                }
                if let Some(o) = sec.opts.iter().find(|o| o.key == "presharedkey")
                    && !o.value.is_empty()
                {
                    occurrences
                        .entry(("psk", o.value.clone()))
                        .or_default()
                        .push(format!("{}:{}", cfg.file, o.line));
                }
                // 3. AllowedIPs grabbing the whole internet
                if let Some(o) = sec.opts.iter().find(|o| o.key == "allowedips") {
                    let grab: Vec<&str> = split_ips(&o.value)
                        .into_iter()
                        .filter(|c| is_default_route(c))
                        .collect();
                    if !grab.is_empty() {
                        out.push(mk(
                            "allowed-ips-overreach",
                            Category::Security,
                            Severity::Medium,
                            format!(
                                "AllowedIPs includes {} (tunnel captures all traffic)",
                                grab.join(", ")
                            ),
                            o.line,
                            "Full-tunnel configs leak traffic if the gateway or kill-switch \
                             fails; scope AllowedIPs to the networks that actually need it.",
                            "",
                        ));
                    }
                }
                // 6. endpoint behind NAT without keepalive
                if let Some(ep) = sec.opts.iter().find(|o| o.key == "endpoint")
                    && !ep.value.is_empty()
                    && !sec
                        .opts
                        .iter()
                        .any(|o| o.key == "persistentkeepalive" && !o.value.is_empty())
                {
                        out.push(mk(
                            "no-keepalive",
                            Category::Reliability,
                            Severity::Low,
                            "Peer has an Endpoint but no PersistentKeepalive".to_string(),
                            ep.line,
                            "NAT state can time out and silently drop the pinhole; \
                             PersistentKeepalive = 25 keeps the mapping alive.",
                            "",
                        ));
                }
            }
        }
    }

    // 5. same ListenPort claimed by several [Interface] sections
    for (port, locs) in &ports {
        if locs.len() >= 2 {
            let first = locs.first().cloned().unwrap_or_default();
            out.push(
                Finding::new(
                    C,
                    &format!("{C}.listen-port-conflict"),
                    Category::Reliability,
                    Severity::Medium,
                    format!("ListenPort {port} used by {} interfaces", locs.len()),
                    first.clone(),
                )
                .detail(format!(
                    "Sections claiming the port: {} — only one interface can bind it.",
                    locs.join(", ")
                ))
                .fp_key(format!("{C}.listen-port-conflict:{port}")),
            );
        }
    }

    // 2. same key value reused across peers/files
    for ((kind, value), locs) in &occurrences {
        if locs.len() >= 2 {
            let first = locs.first().cloned().unwrap_or_default();
            let label = if *kind == "psk" {
                "PresharedKey"
            } else {
                "PrivateKey"
            };
            out.push(
                Finding::new(
                    C,
                    &format!("{C}.key-reuse"),
                    Category::Security,
                    Severity::Medium,
                    format!(
                        "Same {label} value reused in {} places (value redacted)",
                        locs.len()
                    ),
                    first,
                )
                .detail(format!(
                    "Occurrences: {} — reuse lets one compromised key decrypt other channels.",
                    locs.join(", ")
                ))
                .fp_key(format!("{C}.key-reuse:{kind}:{}", value.len())),
            );
        }
    }

    // Keep findings in a stable order regardless of map iteration.
    out.sort_by(|a, b| (&a.location, &a.rule).cmp(&(&b.location, &b.rule)));
    skips.finish(out)
}
