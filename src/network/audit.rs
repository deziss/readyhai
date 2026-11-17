//! 6-Pillar Deep Network & Protocol Diagnostics Suite (IPv4/v6, CORS, MTU, Subresources, Protocol Matrix).

use super::ip::detect_requester_public_ip;
use super::tls::audit_tls_chain;
use super::types::{
    CorsAudit, DeepAuditReport, DeepAuditRequest, DualStackAudit, MtuSweepAudit, MtuSweepItem,
    ProtocolItem, ProtocolMatrixAudit, SubresourceAudit, SubresourceItem, HTML_BYTES_CAP,
    MAX_SUBRESOURCES, SUBRESOURCE_BYTES_CAP,
};
use super::utils::{count_capped, host_of, hostport, http_client, port_of, read_capped, truncate_chars};
use crate::tools::run_capped;
use anyhow::Result;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

pub fn run_deep_audit(req: &DeepAuditRequest) -> Result<DeepAuditReport> {
    let mut req = req.clone();
    let url = req.sanitize()?;
    let timestamp = crate::engine::now();
    let host = host_of(&url);
    let port = port_of(&url);
    let target = url.as_str();

    // 1. Dual-Stack IPv4 vs IPv6 Happy Eyeballs Audit
    let dual_stack = audit_dual_stack(&host, port, req.timeout_ms);

    // 2. Sub-Resource Cascade Audit (SPA & Assets)
    let subresources = audit_subresources(&url, req.timeout_ms);

    // 3. Protocol Matrix Audit
    let protocol_matrix = audit_protocol_matrix(target, req.timeout_ms);

    // 4. TLS & Certificate Chain Audit
    let tls_chain = audit_tls_chain(&url, &host, port, req.timeout_ms);

    // 5. CORS Preflight Audit
    let cors_preflight = audit_cors_preflight(target, req.timeout_ms);

    // 6. MTU & Packet Size Sweep Audit
    let mtu_sweep = audit_mtu_sweep(target, req.timeout_ms);

    // Calculate Health Score & Verdict
    let mut score: i32 = 100;
    let mut risks: Vec<String> = Vec::new();
    let mut remedies: Vec<String> = Vec::new();
    let mut not_measured: Vec<String> = Vec::new();

    if dual_stack.happy_eyeballs_risk {
        score -= 25;
        risks.push("Happy Eyeballs Risk: IPv6 record exists in DNS, but socket connection fails/hangs, causing first-load 3s delay.".to_string());
        remedies.push("Fix or remove broken AAAA DNS record for your domain, or ensure upstream gateway listens on IPv6.".to_string());
    }

    if subresources.broken_count > 0 {
        score -= (subresources.broken_count as i32 * 10).min(30);
        risks.push(format!(
            "{} sub-resource asset(s) did not return a 2xx response.",
            subresources.broken_count
        ));
        remedies.push("Verify asset paths and ensure build assets / bundles are properly uploaded to your web server / CDN.".to_string());
    }

    if subresources.spa_fallback_mismatches > 0 {
        score -= 30;
        risks.push(format!("SPA Routing Flaw: {} JavaScript chunk(s) returned HTML index shell instead of JS code! This causes fatal SyntaxErrors and blank screens on first load.", subresources.spa_fallback_mismatches));
        remedies.push("Update Nginx/reverse proxy `try_files` rule so missing static files (`.js`, `.css`) return 404 instead of falling back to `/index.html`.".to_string());
    }

    if !tls_chain.measured && tls_chain.is_https {
        not_measured.push(format!(
            "tls_chain ({})",
            tls_chain
                .not_measured
                .first()
                .map(String::as_str)
                .unwrap_or("openssl unavailable")
        ));
    }
    if tls_chain.is_intermediate_missing {
        score -= 25;
        risks.push("Incomplete TLS Certificate Chain: Intermediate CA is missing from server bundle. Fails on clean browsers and mobile devices.".to_string());
        remedies.push("Replace your server certificate with the full chain bundle (e.g. `fullchain.pem` instead of `cert.pem`).".to_string());
    }
    if let Some(days) = tls_chain.days_remaining {
        if days < 0 {
            score -= 30;
            risks.push(format!("TLS certificate expired {} day(s) ago.", -days));
            remedies.push(
                "Renew the certificate immediately and automate renewal (ACME / cert-manager)."
                    .to_string(),
            );
        } else if days <= 14 {
            score -= 15;
            risks.push(format!("TLS certificate expires in {days} day(s)."));
            remedies.push(
                "Renew the certificate and verify that automated renewal is working.".to_string(),
            );
        }
    }

    if !cors_preflight.preflight_passed {
        score -= 20;
        risks.push(format!("CORS Preflight (OPTIONS) failed with HTTP status {}. Cross-origin API calls will be blocked by browsers.", cors_preflight.preflight_status_code));
        remedies.push("Ensure your reverse proxy or API gateway handles HTTP OPTIONS requests with 200/204 and Access-Control-Allow-Origin headers.".to_string());
    }

    if mtu_sweep.black_hole_detected {
        score -= 30;
        risks.push("MTU Black Hole Detected: requests with larger headers time out or are reset while the small baseline request succeeds.".to_string());
        remedies.push("Enable Path MTU Discovery or configure TCP MSS clamping (`iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`).".to_string());
    }

    let final_score = score.clamp(0, 100) as u8;
    let overall_verdict = if final_score >= 90 {
        "PASS"
    } else if final_score >= 70 {
        "WARN"
    } else {
        "FAIL"
    };

    let summary = if risks.is_empty() && not_measured.is_empty() {
        "All 6 deep network and protocol pillars were measured and look healthy.".to_string()
    } else if risks.is_empty() {
        format!(
            "No problems found in the measured pillars; not measured: {}.",
            not_measured.join(", ")
        )
    } else {
        format!(
            "Detected {} network vulnerability/flakiness vector(s). Overall Network Health Score: {}/100.",
            risks.len(),
            final_score
        )
    };

    let ip_info = detect_requester_public_ip();
    Ok(DeepAuditReport {
        target: req.target.clone(),
        timestamp,
        overall_verdict: overall_verdict.to_string(),
        health_score: final_score,
        executive_summary: summary,
        identified_risks: risks,
        dual_stack,
        subresources,
        protocol_matrix,
        tls_chain,
        cors_preflight,
        mtu_sweep,
        remediation_checklist: remedies,
        not_measured,
        requester_ip: Some(ip_info.egress_public_ip.clone()),
        allowlist_recommendation: Some(ip_info.allowlist_guidance.clone()),
    })
}

pub(crate) fn audit_dual_stack(host: &str, port: u16, timeout_ms: u64) -> DualStackAudit {
    let connect_timeout = Duration::from_millis(timeout_ms.min(2500));
    let lookup_result = hostport(host, port).to_socket_addrs();

    match lookup_result {
        Ok(addrs) => {
            let mut v4_addrs = Vec::new();
            let mut v6_addrs = Vec::new();

            for addr in addrs {
                match addr {
                    SocketAddr::V4(v4) => v4_addrs.push(v4.ip().to_string()),
                    SocketAddr::V6(v6) => v6_addrs.push(v6.ip().to_string()),
                }
            }

            let has_ipv4 = !v4_addrs.is_empty();
            let has_ipv6 = !v6_addrs.is_empty();

            // Test IPv4 connection
            let mut v4_latency = None;
            if let Some(first_v4) = v4_addrs.first()
                && let Ok(sock) = format!("{}:{}", first_v4, port).parse::<SocketAddr>()
            {
                let t0 = Instant::now();
                if TcpStream::connect_timeout(&sock, connect_timeout).is_ok() {
                    v4_latency = Some(t0.elapsed().as_millis());
                }
            }

            // Test IPv6 connection
            let mut v6_latency = None;
            let mut ipv6_status = "NOT_CONFIGURED".to_string();
            let mut happy_eyeballs_risk = false;

            if has_ipv6
                && let Some(first_v6) = v6_addrs.first()
                && let Ok(sock) = format!("[{}]:{}", first_v6, port).parse::<SocketAddr>()
            {
                let t0 = Instant::now();
                match TcpStream::connect_timeout(&sock, connect_timeout) {
                    Ok(_) => {
                        v6_latency = Some(t0.elapsed().as_millis());
                        ipv6_status = "HEALTHY".to_string();
                    }
                    Err(_) => {
                        ipv6_status = "BROKEN_OR_BLACKHOLE".to_string();
                        happy_eyeballs_risk = true;
                    }
                }
            }

            let diagnosis = if happy_eyeballs_risk {
                "CRITICAL: AAAA record is published in DNS, but IPv6 socket connection timed out or was dropped. Browsers will stall for 250-3000ms on first load before falling back to IPv4!".to_string()
            } else if has_ipv4 && has_ipv6 {
                "EXCELLENT: Dual-stack IPv4/IPv6 is fully operational with fast TCP handshakes on both protocols.".to_string()
            } else if has_ipv4 {
                "STANDARD: Host is IPv4-only. No IPv6 AAAA record published (zero Happy Eyeballs fallback delay risk).".to_string()
            } else {
                "No valid IP addresses could be reached.".to_string()
            };

            DualStackAudit {
                has_ipv4,
                has_ipv6,
                ipv4_addresses: v4_addrs,
                ipv6_addresses: v6_addrs,
                ipv4_latency_ms: v4_latency,
                ipv6_latency_ms: v6_latency,
                ipv6_status,
                happy_eyeballs_risk,
                diagnosis,
            }
        }
        Err(e) => DualStackAudit {
            has_ipv4: false,
            has_ipv6: false,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            ipv4_latency_ms: None,
            ipv6_latency_ms: None,
            ipv6_status: "DNS_LOOKUP_FAILED".to_string(),
            happy_eyeballs_risk: false,
            diagnosis: format!("DNS resolution error: {}", e),
        },
    }
}

pub(crate) fn audit_subresources(base_url: &reqwest::Url, timeout_ms: u64) -> SubresourceAudit {
    let client = http_client(timeout_ms, false);

    let mut items = Vec::new();
    let mut total_size_bytes = 0;
    let mut broken_count = 0;
    let mut spa_fallback_count = 0;
    let mut skipped_cross_host = 0;
    let mut max_ttfb = 0;
    let base_host = base_url.host_str().map(str::to_ascii_lowercase);

    let res = client.get(base_url.as_str()).send();
    if let Ok(resp) = res {
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let (bytes, _) = read_capped(resp, HTML_BYTES_CAP);
        let body = String::from_utf8_lossy(&bytes).into_owned();

        if content_type.contains("text/html")
            || body.contains("<html")
            || body.contains("<!doctype")
        {
            // Extract sub-resources
            let mut discovered_urls = Vec::new();

            // Scripts: <script ... src="..."
            let re_script = regex::Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap();
            for cap in re_script.captures_iter(&body) {
                if let Some(m) = cap.get(1) {
                    discovered_urls.push((m.as_str().to_string(), "script"));
                }
            }

            // Styles: <link ... rel="stylesheet" ... href="..." or vice versa
            let re_style =
                regex::Regex::new(r#"(?i)<link[^>]+href=["']([^"']+\.css[^"']*)["']"#).unwrap();
            for cap in re_style.captures_iter(&body) {
                if let Some(m) = cap.get(1) {
                    discovered_urls.push((m.as_str().to_string(), "stylesheet"));
                }
            }

            // Preload: <link rel="preload" href="..."
            let re_preload =
                regex::Regex::new(r#"(?i)<link[^>]+rel=["']preload["'][^>]+href=["']([^"']+)["']"#)
                    .unwrap();
            for cap in re_preload.captures_iter(&body) {
                if let Some(m) = cap.get(1) {
                    discovered_urls.push((m.as_str().to_string(), "preload"));
                }
            }

            // Limit to first 12 discovered subresources for performance
            discovered_urls.truncate(MAX_SUBRESOURCES);

            for (raw_url, tag_type) in discovered_urls {
                // The page is untrusted input: only probe assets on the audited host, never a
                // URL the page points at (internal addresses, other hosts, non-http schemes).
                let resolved = match base_url.join(&raw_url) {
                    Ok(u)
                        if matches!(u.scheme(), "http" | "https")
                            && u.host_str().map(str::to_ascii_lowercase) == base_host =>
                    {
                        u
                    }
                    _ => {
                        skipped_cross_host += 1;
                        continue;
                    }
                };
                let resolved_url = resolved.to_string();

                let t0 = Instant::now();
                let asset_res = client.get(resolved.as_str()).send();
                let ttfb = t0.elapsed().as_millis();
                max_ttfb = max_ttfb.max(ttfb);

                match asset_res {
                    Ok(a_resp) => {
                        let status = a_resp.status().as_u16();
                        let a_ct = a_resp
                            .headers()
                            .get("content-type")
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or("")
                            .to_lowercase();
                        let a_bytes = count_capped(a_resp, SUBRESOURCE_BYTES_CAP);
                        total_size_bytes += a_bytes;

                        let is_broken = !(200..300).contains(&status);
                        if is_broken {
                            broken_count += 1;
                        }

                        // Check SPA Fallback Mismatch
                        // If file is named .js or .mjs, but server sent text/html!
                        let path = resolved.path();
                        let is_spa_fallback_error = (path.ends_with(".js")
                            || path.ends_with(".mjs"))
                            && a_ct.contains("text/html");
                        if is_spa_fallback_error {
                            spa_fallback_count += 1;
                        }

                        items.push(SubresourceItem {
                            url: resolved_url,
                            tag_type: tag_type.to_string(),
                            status_code: status,
                            ttfb_ms: ttfb,
                            content_type: a_ct,
                            size_bytes: a_bytes,
                            is_spa_fallback_error,
                            is_broken,
                            error: if is_broken {
                                Some(format!("HTTP {status}"))
                            } else {
                                None
                            },
                        });
                    }
                    Err(err) => {
                        broken_count += 1;
                        items.push(SubresourceItem {
                            url: resolved_url,
                            tag_type: tag_type.to_string(),
                            status_code: 0,
                            ttfb_ms: ttfb,
                            content_type: "error".to_string(),
                            size_bytes: 0,
                            is_spa_fallback_error: false,
                            is_broken: true,
                            error: Some(err.to_string()),
                        });
                    }
                }
            }
        }
    }

    let diagnosis = if spa_fallback_count > 0 {
        format!(
            "CRITICAL: Detected {spa_fallback_count} JavaScript chunk(s) returning HTML index shells! This causes fatal syntax errors and blank screens on first load."
        )
    } else if broken_count > 0 {
        format!("WARNING: {broken_count} sub-resource asset(s) did not return a 2xx response.")
    } else if items.is_empty() {
        "Target is an API endpoint or non-HTML resource, or has no same-host sub-resources; nothing to probe.".to_string()
    } else {
        format!(
            "All {} discovered sub-resources loaded successfully with correct MIME types.",
            items.len()
        )
    };
    let diagnosis = if skipped_cross_host > 0 {
        format!(
            "{diagnosis} ({skipped_cross_host} cross-host or non-http asset(s) were not probed: only the audited host is contacted.)"
        )
    } else {
        diagnosis
    };

    SubresourceAudit {
        total_discovered: items.len(),
        successful_count: items.iter().filter(|i| !i.is_broken).count(),
        broken_count,
        spa_fallback_mismatches: spa_fallback_count,
        skipped_cross_host,
        total_size_kb: (total_size_bytes as f64) / 1024.0,
        max_asset_ttfb_ms: max_ttfb,
        items,
        diagnosis,
    }
}

/// One curl protocol probe. Returns (negotiated HTTP version, status code), or None when curl
/// could not be run or reached nothing.
pub(crate) fn curl_protocol_probe(flag: &str, target: &str, timeout_s: u64) -> Option<(String, u16)> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-q",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_version}:%{http_code}",
        "--proto",
        "=http,https",
        flag,
    ]);
    cmd.arg("--connect-timeout").arg(timeout_s.to_string());
    cmd.arg("--max-time").arg(timeout_s.to_string());
    cmd.arg("--").arg(target);
    let out = run_capped(&mut cmd, Duration::from_secs(timeout_s + 3), 4096, None).ok()?;
    let s = out.stdout_lossy();
    let (ver, code) = s.trim().split_once(':')?;
    Some((ver.to_string(), code.parse().ok().filter(|c| *c > 0)?))
}

pub(crate) fn audit_protocol_matrix(target: &str, timeout_ms: u64) -> ProtocolMatrixAudit {
    let timeout_s = (timeout_ms / 1000).clamp(1, 2);
    let mut protocols = Vec::new();

    // 1. Probe HTTP/1.1
    let t0 = Instant::now();
    let p11 = curl_protocol_probe("--http1.1", target, timeout_s);
    let dur_11 = t0.elapsed().as_millis();
    let (sup_11, code_11, ver_11) = match &p11 {
        Some((v, c)) => (true, *c, v.clone()),
        None => (false, 0, "1.1".to_string()),
    };

    protocols.push(ProtocolItem {
        protocol: "HTTP/1.1".to_string(),
        supported: sup_11,
        negotiation_time_ms: dur_11,
        status_code: code_11,
        notes: "Baseline universal transport protocol.".to_string(),
    });

    // 2. Probe HTTP/2
    let t0 = Instant::now();
    let p2 = curl_protocol_probe("--http2", target, timeout_s);
    let dur_2 = t0.elapsed().as_millis();
    let (sup_2, code_2) = match &p2 {
        Some((v, c)) => (v == "2", *c),
        None => (false, 0),
    };

    protocols.push(ProtocolItem {
        protocol: "HTTP/2 (Multiplexed)".to_string(),
        supported: sup_2,
        negotiation_time_ms: dur_2,
        status_code: code_2,
        notes: if sup_2 {
            "Active. Supports binary framing and single-connection multiplexing.".to_string()
        } else {
            "Not supported or fell back to HTTP/1.1.".to_string()
        },
    });

    // 3. HTTP/3 is only detected through the Alt-Svc header; no QUIC connection is attempted.
    let client = http_client(timeout_ms, false);
    let mut alt_svc = None;
    if let Ok(res) = client.get(target).send()
        && let Some(h) = res.headers().get("alt-svc")
    {
        alt_svc = h.to_str().ok().map(|s| truncate_chars(s, 512));
    }

    let http3_advertised = alt_svc.as_ref().map(|s| s.contains("h3")).unwrap_or(false);
    protocols.push(ProtocolItem {
        protocol: "HTTP/3 (QUIC / UDP)".to_string(),
        supported: http3_advertised,
        negotiation_time_ms: 0,
        status_code: 0,
        notes: if http3_advertised {
            "Advertised via Alt-Svc header. A QUIC connection was not attempted (no negotiation time or status measured).".to_string()
        } else {
            "Alt-Svc header not detected. Server does not announce HTTP/3 QUIC.".to_string()
        },
    });

    let active_protocol = if sup_2 {
        "HTTP/2".to_string()
    } else if sup_11 {
        format!("HTTP/{ver_11}")
    } else {
        "unreachable".to_string()
    };

    let diagnosis = if sup_2 {
        "EXCELLENT: HTTP/2 multiplexing is operational, reducing connection overhead for multiple assets.".to_string()
    } else if sup_11 {
        "STANDARD: Server operates on HTTP/1.1 without multiplexing. Multiple concurrent assets require separate TCP sockets.".to_string()
    } else {
        "No protocol probe got an HTTP response (target unreachable, or curl is not installed)."
            .to_string()
    };

    ProtocolMatrixAudit {
        active_protocol,
        http2_supported: sup_2,
        http3_advertised,
        alt_svc_header: alt_svc,
        protocols,
        diagnosis,
    }
}


pub(crate) fn audit_cors_preflight(target: &str, timeout_ms: u64) -> CorsAudit {
    let client = http_client(timeout_ms, false);

    let res = client
        .request(reqwest::Method::OPTIONS, target)
        .header("Origin", "https://qa-probe.readyhai.internal")
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "authorization, content-type, x-readyhai-probe",
        )
        .send();

    match res {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp.headers();

            let allow_orig = headers
                .get("access-control-allow-origin")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            let allow_meth = headers
                .get("access-control-allow-methods")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            let allow_head = headers
                .get("access-control-allow-headers")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            let allow_cred = headers
                .get("access-control-allow-credentials")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let has_wildcard_with_creds =
                allow_orig.as_deref() == Some("*") && allow_cred.as_deref() == Some("true");
            let preflight_passed = (status == 200 || status == 204)
                && allow_orig.is_some()
                && !has_wildcard_with_creds;

            let diagnosis = if has_wildcard_with_creds {
                "FAIL: Wildcard Access-Control-Allow-Origin '*' with Access-Control-Allow-Credentials 'true' is rejected by browser CORS specifications.".to_string()
            } else if !preflight_passed {
                format!(
                    "FAIL: CORS Preflight returned HTTP status {status} without a usable Access-Control-Allow-Origin. Browsers will reject cross-origin requests before sending data."
                )
            } else {
                "PASS: Preflight OPTIONS is accepted with valid Access-Control headers.".to_string()
            };

            CorsAudit {
                preflight_status_code: status,
                preflight_passed,
                allow_origin: allow_orig,
                allow_methods: allow_meth,
                allow_headers: allow_head,
                allow_credentials: allow_cred,
                has_wildcard_with_creds,
                diagnosis,
            }
        }
        Err(err) => CorsAudit {
            preflight_status_code: 0,
            preflight_passed: false,
            allow_origin: None,
            allow_methods: None,
            allow_headers: None,
            allow_credentials: None,
            has_wildcard_with_creds: false,
            diagnosis: format!("Preflight request failed: {err}"),
        },
    }
}

/// HTTP statuses a server uses to say "your headers are too big" (a server limit, not a network fault).
pub(crate) fn is_header_limit_status(status: u16) -> bool {
    matches!(status, 400 | 413 | 414 | 431)
}

/// Transport-level failure that large packets dying in the network look like: a timeout, a reset
/// or a connection closed mid-request. A refused connection or DNS failure is not one.
pub(crate) fn is_black_hole_error(e: &reqwest::Error) -> bool {
    if e.is_timeout() {
        return true;
    }
    let s = format!("{e:?}").to_lowercase();
    [
        "reset",
        "broken pipe",
        "closed before",
        "incomplete",
        "unexpected eof",
        "connection closed",
    ]
    .iter()
    .any(|p| s.contains(p))
}

/// A payload size counts as black-holed only when a request that got NO HTTP response at all
/// (timeout/reset) follows a smaller one that did. Any HTTP status, including 400/431, proves the
/// packets arrived.
pub(crate) fn mtu_black_hole(results: &[MtuSweepItem]) -> bool {
    let baseline_delivered = results.first().is_some_and(|r| r.delivered);
    baseline_delivered
        && results
            .iter()
            .any(|r| r.payload_bytes >= 1400 && !r.delivered && r.transport_failure)
}

pub(crate) fn audit_mtu_sweep(target: &str, timeout_ms: u64) -> MtuSweepAudit {
    let sweep_timeout = timeout_ms.clamp(800, 2000);
    let client = http_client(sweep_timeout, true);

    let probes = [
        (512, "512B Baseline"),
        (1400, "1.4KB Standard MTU"),
        (4096, "4KB Large Headers"),
        (8192, "8KB High Payload"),
    ];

    let mut results = Vec::new();
    let mut max_safe = 0;
    let mut max_delivered = 0;
    let mut header_limit_seen = false;

    for (size, label) in probes {
        let padding = "A".repeat(size);
        let attempt = || {
            let t0 = Instant::now();
            let res = client
                .get(target)
                .header("X-MTU-Sweep-Padding", padding.clone())
                .send();
            (res, t0.elapsed().as_millis())
        };
        let (mut res, mut dur) = attempt();
        // one retry on a timeout: a single lost SYN is not a black hole
        if size >= 1400 && res.as_ref().is_err_and(|e| e.is_timeout()) {
            (res, dur) = attempt();
        }

        match res {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let success = (200..300).contains(&status);
                let header_limit_hit = is_header_limit_status(status);
                header_limit_seen |= header_limit_hit;
                max_delivered = max_delivered.max(size);
                if !header_limit_hit {
                    max_safe = max_safe.max(size);
                }
                results.push(MtuSweepItem {
                    payload_bytes: size,
                    label: label.to_string(),
                    status_code: status,
                    duration_ms: dur,
                    success,
                    delivered: true,
                    transport_failure: false,
                    header_limit_hit,
                    error: if success { None } else if header_limit_hit {
                        Some(format!("HTTP {status}: the server rejected the header size (a server limit, not a network drop)"))
                    } else {
                        Some(format!("HTTP {status}"))
                    },
                });
            }
            Err(e) => {
                results.push(MtuSweepItem {
                    payload_bytes: size,
                    label: label.to_string(),
                    status_code: 0,
                    duration_ms: dur,
                    success: false,
                    delivered: false,
                    transport_failure: is_black_hole_error(&e),
                    header_limit_hit: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    let black_hole_detected = mtu_black_hole(&results);
    let baseline_failed = results.first().is_some_and(|r| !r.delivered);
    let diagnosis = if black_hole_detected {
        "CRITICAL: Path MTU Black Hole suspected! The small baseline request was answered, but a larger request timed out or was reset without any HTTP response. Network firewalls may be blocking ICMP Fragmentation Needed packets.".to_string()
    } else if baseline_failed {
        "Baseline request got no HTTP response; the target is unreachable, so the MTU sweep is inconclusive.".to_string()
    } else if header_limit_seen {
        format!(
            "No black hole: every probe got an HTTP response. The server rejects large headers (HTTP 400/413/414/431) above {max_safe} bytes; that is a header-size limit, not a network fault."
        )
    } else {
        format!(
            "All MTU packet size sweeps got HTTP responses up to {max_delivered} bytes without drops."
        )
    };

    MtuSweepAudit {
        black_hole_detected,
        maximum_safe_bytes: max_safe,
        maximum_delivered_bytes: max_delivered,
        sweep_results: results,
        diagnosis,
    }
}

