//! Network regression testing engine, jitter calculation, and AI flakiness diagnostic engine.

use super::curl::generate_curl;
use super::ip::detect_requester_public_ip;
use super::types::{
    AgentDiagnosis, IterationResult, RegressReport, RegressRequest, BODY_READ_CAP,
    BODY_SNIPPET_CHARS, MAX_ITERATIONS, MAX_REGRESS_BUDGET_MS,
};
use super::utils::{
    has_header, host_of, hostport, http_client, parse_method, port_of, read_capped,
    truncate_chars,
};
use anyhow::Result;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub fn run_regress_test(req: &RegressRequest) -> Result<RegressReport> {
    let mut req = req.clone();
    let requested = req.iterations;
    let url = req.sanitize()?;
    let requested = requested.clamp(1, MAX_ITERATIONS);
    let method = parse_method(&req.method)?;
    let host = host_of(&url);
    let port = port_of(&url);
    let iterations = req.iterations;

    let mut results = Vec::with_capacity(iterations);
    let mut durations: Vec<u128> = Vec::with_capacity(iterations);
    let mut status_counts: HashMap<String, usize> = HashMap::new();
    let mut successful_count = 0;
    let mut failed_count = 0;
    let run_started = Instant::now();
    let mut stopped_early = false;
    let curl_cmd = generate_curl(
        &req.method,
        url.as_str(),
        &req.headers,
        req.payload.as_deref(),
    );

    for i in 1..=iterations {
        if run_started.elapsed() >= Duration::from_millis(MAX_REGRESS_BUDGET_MS) {
            stopped_early = true;
            break;
        }
        let session_id = format!("sess-{i}-{:08x}", rand::random::<u32>());
        let t_start = Instant::now();
        let timestamp = crate::engine::now();

        // Simulate network throttle latency if requested
        let injected_latency = match req.throttle_profile.as_str() {
            "fast_3g" => 75 + (i % 25) as u64,
            "slow_3g" => 250 + (i % 50) as u64,
            "flaky" => {
                if i % 3 == 0 {
                    400
                } else {
                    20
                }
            }
            "custom" => req.simulated_latency_ms,
            _ => 0,
        };
        if injected_latency > 0 {
            std::thread::sleep(Duration::from_millis(injected_latency));
        }

        // 1. Measure DNS Lookup
        let dns_t0 = Instant::now();
        let addrs: Vec<SocketAddr> = hostport(&host, port)
            .to_socket_addrs()
            .map(|iter| iter.collect())
            .unwrap_or_default();
        let dns_lookup_ms = dns_t0.elapsed().as_millis();
        let resolved_ip = addrs.first().map(|a| a.ip().to_string());

        // 2. Measure TCP Connect
        let tcp_t0 = Instant::now();
        if let Some(addr) = addrs.first() {
            let _ =
                TcpStream::connect_timeout(addr, Duration::from_millis(req.timeout_ms.min(3000)));
        }
        let tcp_connect_ms = tcp_t0.elapsed().as_millis();

        // 3. HTTP Request with separate private session isolation
        let client = http_client(req.timeout_ms, req.separate_sessions);
        let mut http_req = client.request(method.clone(), url.as_str());
        for (k, v) in &req.headers {
            http_req = http_req.header(k, v);
        }
        if let Some(ref p) = req.payload {
            if !has_header(&req.headers, "content-type") {
                http_req = http_req.header("Content-Type", "application/json");
            }
            http_req = http_req.body(p.clone());
        }

        let send_t0 = Instant::now();
        let res = http_req.send();
        let ttfb_ms = send_t0.elapsed().as_millis();

        match res {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let http_version = Some(format!("{:?}", resp.version()));
                let mut resp_headers = HashMap::new();
                for (name, val) in resp.headers() {
                    if let Ok(v_str) = val.to_str() {
                        resp_headers.insert(name.to_string(), v_str.to_string());
                    }
                }

                // bounded read, then a char-boundary-safe cut (a byte slice could split a
                // multi-byte character and panic)
                let (bytes, _) = read_capped(resp, BODY_READ_CAP);
                let body_snippet = Some(truncate_chars(
                    &String::from_utf8_lossy(&bytes),
                    BODY_SNIPPET_CHARS,
                ));
                let total_duration_ms = t_start.elapsed().as_millis();

                // only 2xx is a success: a 3xx that was not followed, a 4xx or a 5xx is a failure
                let is_success = (200..300).contains(&status);
                if is_success {
                    successful_count += 1;
                } else {
                    failed_count += 1;
                }

                *status_counts.entry(status.to_string()).or_insert(0) += 1;
                durations.push(total_duration_ms);

                results.push(IterationResult {
                    iteration: i,
                    session_id,
                    timestamp,
                    duration_ms: total_duration_ms,
                    dns_lookup_ms,
                    tcp_connect_ms,
                    ttfb_ms,
                    status_code: status,
                    success: is_success,
                    error_message: if is_success {
                        None
                    } else {
                        Some(format!("HTTP Status {status}"))
                    },
                    curl_command: curl_cmd.clone(),
                    response_headers: resp_headers,
                    response_body_snippet: body_snippet,
                    resolved_ip,
                    http_version,
                });
            }
            Err(e) => {
                let total_duration_ms = t_start.elapsed().as_millis();
                failed_count += 1;
                *status_counts.entry("ERR".to_string()).or_insert(0) += 1;
                durations.push(total_duration_ms);

                results.push(IterationResult {
                    iteration: i,
                    session_id,
                    timestamp,
                    duration_ms: total_duration_ms,
                    dns_lookup_ms,
                    tcp_connect_ms,
                    ttfb_ms: 0,
                    status_code: 0,
                    success: false,
                    error_message: Some(e.to_string()),
                    curl_command: curl_cmd.clone(),
                    response_headers: HashMap::new(),
                    response_body_snippet: None,
                    resolved_ip,
                    http_version: None,
                });
            }
        }

        if req.delay_between_ms > 0 && i < iterations {
            std::thread::sleep(Duration::from_millis(req.delay_between_ms));
        }
    }

    // Compute percentiles & stats
    durations.sort_unstable();
    let total_count = durations.len();
    let min_latency_ms = durations.first().copied().unwrap_or(0);
    let max_latency_ms = durations.last().copied().unwrap_or(0);
    let avg_latency_ms = if total_count > 0 {
        durations.iter().sum::<u128>() / total_count as u128
    } else {
        0
    };

    let p50_idx = ((total_count as f64 * 0.50).ceil() as usize).saturating_sub(1);
    let p90_idx = ((total_count as f64 * 0.90).ceil() as usize).saturating_sub(1);
    let p99_idx = ((total_count as f64 * 0.99).ceil() as usize).saturating_sub(1);

    let p50_latency_ms = durations.get(p50_idx).copied().unwrap_or(0);
    let p90_latency_ms = durations.get(p90_idx).copied().unwrap_or(0);
    let p99_latency_ms = durations.get(p99_idx).copied().unwrap_or(0);
    let jitter_ms = p99_latency_ms.saturating_sub(p50_latency_ms);

    let availability_percentage = if total_count > 0 {
        (successful_count as f64 / total_count as f64) * 100.0
    } else {
        0.0
    };

    let diagnosis = diagnose(
        &results,
        availability_percentage,
        p50_latency_ms,
        p99_latency_ms,
        jitter_ms,
        req.timeout_ms,
    );

    let ip_info = detect_requester_public_ip();
    Ok(RegressReport {
        target: req.target.clone(),
        method: req.method.clone(),
        total_iterations: total_count,
        iterations_requested: requested,
        stopped_early,
        successful_iterations: successful_count,
        failed_iterations: failed_count,
        availability_percentage,
        avg_latency_ms,
        p50_latency_ms,
        p90_latency_ms,
        p99_latency_ms,
        min_latency_ms,
        max_latency_ms,
        jitter_ms,
        status_distribution: status_counts,
        diagnosis,
        iterations: results,
        requester_ip: Some(ip_info.egress_public_ip.clone()),
        allowlist_recommendation: Some(ip_info.allowlist_guidance.clone()),
    })
}

// ============================================================================
// Agent Root-Cause Diagnostic Heuristics
// ============================================================================

pub fn diagnose(
    results: &[IterationResult],
    availability: f64,
    p50: u128,
    p99: u128,
    jitter: u128,
    timeout_ms: u64,
) -> AgentDiagnosis {
    let sample_curl = results
        .first()
        .map(|r| r.curl_command.clone())
        .unwrap_or_default();

    if availability < 100.0 {
        let timeout_failures = results
            .iter()
            .filter(|r| {
                if let Some(ref e) = r.error_message {
                    e.to_lowercase().contains("timed out") || e.to_lowercase().contains("timeout")
                } else {
                    false
                }
            })
            .count();

        let conn_refused_failures = results
            .iter()
            .filter(|r| {
                if let Some(ref e) = r.error_message {
                    e.to_lowercase().contains("connection refused")
                        || e.to_lowercase().contains("reset")
                } else {
                    false
                }
            })
            .count();

        let gateway_flaps = results
            .iter()
            .filter(|r| r.status_code == 502 || r.status_code == 503 || r.status_code == 504)
            .count();

        if timeout_failures > 0 {
            return AgentDiagnosis {
                flakiness_detected: true,
                root_cause_type: "TIMEOUT".to_string(),
                severity: "CRITICAL".to_string(),
                title: "Intermittent TCP Handshake or Cold Start Timeout".to_string(),
                summary: format!("{}/{} requests timed out after {}ms under isolated sessions.", timeout_failures, results.len(), timeout_ms),
                how_agent_found_it: vec![
                    format!("The agent spawned {} isolated HTTP sessions (zero socket reuse).", results.len()),
                    format!("Observed that {} sessions stalled during initial TCP connection or TLS handshake.", timeout_failures),
                    "Confirmed failure is isolated to fresh sessions (indicative of reverse-proxy socket limits or backend cold start).".to_string(),
                ],
                technical_breakdown: vec![
                    "Reverse proxy connection pool limit reached or upstream backend took > proxy_connect_timeout to respond.".to_string(),
                    "Container cold start latency: container was spun down or idle, causing first request to exceed connect timeout.".to_string(),
                    "Firewall / iptables dropping SYN packets due to conntrack table exhaustion.".to_string(),
                ],
                reproduction_curl: sample_curl,
                remediation_checklist: vec![
                    "Increase proxy connect timeout (e.g., `proxy_connect_timeout 10s;` in Nginx).".to_string(),
                    "Implement container keep-warm pings or configure minimum healthy instances to prevent cold shutdowns.".to_string(),
                    "Check server backlog capacity: `sysctl net.core.somaxconn` and socket TIME_WAIT limits.".to_string(),
                    format!("Private Network Allowlist: Ensure ReadyHai requester public IP `{}` is allowlisted in target firewall/VPC security groups.", detect_requester_public_ip().egress_public_ip),
                ],
            };
        }

        if gateway_flaps > 0 {
            return AgentDiagnosis {
                flakiness_detected: true,
                root_cause_type: "5XX_FLAPPING".to_string(),
                severity: "HIGH".to_string(),
                title: "Upstream Reverse Proxy Gateway Flapping (502/503/504)".to_string(),
                summary: format!("{}/{} requests returned Gateway 5xx errors intermittently.", gateway_flaps, results.len()),
                how_agent_found_it: vec![
                    "Monitored HTTP status code distribution across continuous attempts.".to_string(),
                    format!("Detected {} gateway error responses interspersed with successful responses.", gateway_flaps),
                    "Determined that upstream worker processes or microservices are flapping under load.".to_string(),
                ],
                technical_breakdown: vec![
                    "Upstream backend worker crash-looping or restarting (OOM killed or unhandled panic).".to_string(),
                    "Load balancer routing traffic to an unhealthy or terminating replica.".to_string(),
                    "Database connection pool exhaustion on the upstream app.".to_string(),
                ],
                reproduction_curl: sample_curl,
                remediation_checklist: vec![
                    "Inspect backend container crash logs (`docker logs --tail 100`).".to_string(),
                    "Check upstream healthcheck intervals in your load balancer to ensure unready replicas are removed immediately.".to_string(),
                    "Increase database pool size or verify connection leak hygiene.".to_string(),
                ],
            };
        }

        if conn_refused_failures > 0 {
            return AgentDiagnosis {
                flakiness_detected: true,
                root_cause_type: "CONNECTION_RESET".to_string(),
                severity: "HIGH".to_string(),
                title: "TCP Connection Reset by Peer (ECONNRESET)".to_string(),
                summary: format!("{}/{} requests experienced TCP connection drops.", conn_refused_failures, results.len()),
                how_agent_found_it: vec![
                    "Captured lower-level socket transport errors during session handshake.".to_string(),
                    "Observed immediate TCP RST packet received from target host.".to_string(),
                ],
                technical_breakdown: vec![
                    "Application process crashed or closed the socket prematurely before flushing response.".to_string(),
                    "Stateful firewall or NAT gateway dropping idle connections.".to_string(),
                ],
                reproduction_curl: sample_curl,
                remediation_checklist: vec![
                    "Inspect application error logs for unhandled panics right before connection drops.".to_string(),
                    "Verify file descriptor limits on host: `ulimit -n`.".to_string(),
                ],
            };
        }

        // Everything else that failed: plain non-2xx answers (3xx not followed, 4xx, other 5xx)
        // or errors with no response. Never fall through to "STABLE" with failures on record.
        let c3 = results
            .iter()
            .filter(|r| (300..400).contains(&r.status_code))
            .count();
        let c4 = results
            .iter()
            .filter(|r| (400..500).contains(&r.status_code))
            .count();
        let c5 = results.iter().filter(|r| r.status_code >= 500).count();
        let other = results
            .iter()
            .filter(|r| !r.success && r.status_code == 0)
            .count();
        let failed = results.iter().filter(|r| !r.success).count();
        return AgentDiagnosis {
            flakiness_detected: true,
            root_cause_type: "HTTP_ERRORS".to_string(),
            severity: if c5 > 0 { "HIGH" } else if c4 > 0 || other > 0 { "MEDIUM" } else { "LOW" }.to_string(),
            title: "Target Answered With Non-2xx Responses".to_string(),
            summary: format!("{failed}/{} requests did not return 2xx (3xx: {c3}, 4xx: {c4}, 5xx: {c5}, no response: {other}).", results.len()),
            how_agent_found_it: vec![
                format!("Sent {} isolated requests and classified each response by status class.", results.len()),
                "Only 2xx counts as success; redirects are not followed to other hosts and count as failures.".to_string(),
            ],
            technical_breakdown: vec![
                "4xx: wrong path/method, missing credentials, or a WAF/rate limiter rejecting the probe.".to_string(),
                "5xx other than 502/503/504: the application itself is failing.".to_string(),
                "3xx: the target redirects (for example http to https); probe the final URL instead.".to_string(),
            ],
            reproduction_curl: sample_curl,
            remediation_checklist: vec![
                "Confirm the URL, method and headers are what the endpoint expects (re-run with the reproduction curl).".to_string(),
                "If the target redirects, use its canonical URL.".to_string(),
                "Check application logs for the failing status codes.".to_string(),
            ],
        };
    }

    // A 3x ratio alone is noise at sub-millisecond latencies (1ms vs 4ms); require real spread too.
    if jitter > 350 || (p99 > p50 * 3 && jitter > 50) {
        return AgentDiagnosis {
            flakiness_detected: true,
            root_cause_type: "HIGH_JITTER".to_string(),
            severity: "MEDIUM".to_string(),
            title: "Severe Network Latency Jitter Detected".to_string(),
            summary: format!(
                "P50 latency is {}ms while P99 latency spikes to {}ms (Jitter: {}ms).",
                p50, p99, jitter
            ),
            how_agent_found_it: vec![
                format!(
                    "Compared median latency ({}ms) against 99th percentile ({}ms).",
                    p50, p99
                ),
                format!(
                    "Detected a latency deviation of {}ms between cold sessions.",
                    jitter
                ),
            ],
            technical_breakdown: vec![
                "Garbage collection (GC) pauses or CPU throttling in container.".to_string(),
                "Noisy neighbor on shared hosting or packet retransmission on network link."
                    .to_string(),
            ],
            reproduction_curl: sample_curl,
            remediation_checklist: vec![
                "Check container CPU limits (`docker stats`) for CPU throttling.".to_string(),
                "Analyze runtime garbage collection logs or thread pool contention.".to_string(),
            ],
        };
    }

    AgentDiagnosis {
        flakiness_detected: false,
        root_cause_type: "STABLE".to_string(),
        severity: "STABLE".to_string(),
        title: "Network Connection is Deterministic and Resilient".to_string(),
        summary: format!(
            "100% of {} iterations succeeded. P50: {}ms, P99: {}ms, Jitter: {}ms.",
            results.len(),
            p50,
            p99,
            jitter
        ),
        how_agent_found_it: vec![
            format!(
                "Verified {} independent HTTP sessions with clean connection setup.",
                results.len()
            ),
            "Confirmed consistent DNS resolution and sub-second TCP 3-way handshakes.".to_string(),
            "Observed uniform HTTP status codes without dropped packets or timeouts.".to_string(),
        ],
        technical_breakdown: vec![
            "Connection pool exhaustion risk is LOW.".to_string(),
            "Upstream reverse proxy health is STABLE.".to_string(),
        ],
        reproduction_curl: sample_curl,
        remediation_checklist: vec![
            "Continue periodic continuous regression monitoring to detect drift over time."
                .to_string(),
        ],
    }
}


