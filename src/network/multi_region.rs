//! Multi-region latency benchmarking and geographical anomaly detection.

use super::types::{
    MultiRegionReport, MultiRegionRequest, RegionProbeResult, NOT_MEASURED, NOT_MEASURED_REGIONS,
    SUBRESOURCE_BYTES_CAP,
};
use super::utils::{count_capped, host_of, hostport, http_client, port_of, truncate_chars};
use anyhow::Result;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const LOCAL_SAMPLES: usize = 3;

pub(crate) struct Sample {
    dns_ms: u64,
    connect_ms: u64,
    ttfb_ms: u64,
    total_ms: u64,
    status: u16,
    resolved_ip: Option<String>,
    headers: HashMap<String, String>,
}

pub(crate) fn local_sample(url: &reqwest::Url, host: &str, port: u16, timeout_ms: u64) -> Option<Sample> {
    let dns_t0 = Instant::now();
    let addrs: Vec<SocketAddr> = hostport(host, port)
        .to_socket_addrs()
        .map(|i| i.collect())
        .unwrap_or_default();
    let dns_ms = dns_t0.elapsed().as_millis() as u64;
    let addr = *addrs.first()?;

    let tcp_t0 = Instant::now();
    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).ok()?;
    let connect_ms = tcp_t0.elapsed().as_millis() as u64;

    let client = http_client(timeout_ms, true);
    let t0 = Instant::now();
    let resp = client.get(url.as_str()).send().ok()?;
    let ttfb_ms = t0.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), truncate_chars(v, 200)))
        })
        .collect();
    let _ = count_capped(resp, SUBRESOURCE_BYTES_CAP);
    let total_ms = t0.elapsed().as_millis() as u64;
    Some(Sample {
        dns_ms,
        connect_ms,
        ttfb_ms,
        total_ms,
        status,
        resolved_ip: Some(addr.ip().to_string()),
        headers,
    })
}

pub fn run_multi_region_audit(req: &MultiRegionRequest) -> Result<MultiRegionReport> {
    let mut req = req.clone();
    let url = req.sanitize()?;
    let timestamp = crate::engine::now();
    let timeout_ms = req.timeout_ms.unwrap_or(4000);
    let host = host_of(&url);
    let port = port_of(&url);

    let mut samples = Vec::new();
    let mut failures = 0usize;
    for _ in 0..LOCAL_SAMPLES {
        match local_sample(&url, &host, port, timeout_ms) {
            Some(s) => samples.push(s),
            None => {
                failures += 1;
                // two failures in a row: the target is down, do not burn the full timeout again
                if failures >= 2 && samples.is_empty() {
                    break;
                }
            }
        }
    }
    let attempted = samples.len() + failures;
    let loss = if attempted > 0 {
        failures as f32 / attempted as f32 * 100.0
    } else {
        100.0
    };

    let median = |f: fn(&Sample) -> u64| -> u64 {
        let mut v: Vec<u64> = samples.iter().map(f).collect();
        v.sort_unstable();
        v.get(v.len() / 2).copied().unwrap_or(0)
    };
    let totals: Vec<u64> = samples.iter().map(|s| s.total_ms).collect();
    let jitter = totals
        .iter()
        .max()
        .copied()
        .unwrap_or(0)
        .saturating_sub(totals.iter().min().copied().unwrap_or(0));
    let last = samples.last();
    let (cf_ray, pop_hdr, server_hdr) = match last {
        Some(s) => (
            s.headers.get("cf-ray").cloned(),
            s.headers
                .get("x-amz-cf-pop")
                .or_else(|| s.headers.get("x-served-by"))
                .cloned(),
            s.headers.get("server").cloned(),
        ),
        None => (None, None, None),
    };
    let cdn_edge_active = cf_ray.is_some()
        || pop_hdr.is_some()
        || server_hdr
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains("cloudflare");
    let total_ms = median(|s| s.total_ms);

    let (label, notes) = if samples.is_empty() {
        ("OFFLINE", "No request from this host got an HTTP response (DNS failure, connection refused or timeout).".to_string())
    } else if total_ms < 150 {
        ("OPTIMAL", "Low latency from this host.".to_string())
    } else if total_ms < 300 {
        (
            "ELEVATED",
            "Moderate latency from this host; verify asset compression and HTTP/2 multiplexing."
                .to_string(),
        )
    } else {
        (
            "DEGRADED",
            "High round-trip time from this host.".to_string(),
        )
    };

    let region = RegionProbeResult {
        region_id: "local".to_string(),
        region_name: "This host (measured)".to_string(),
        flag: String::new(),
        location: "Machine running ReadyHai".to_string(),
        resolved_ip: last
            .and_then(|s| s.resolved_ip.clone())
            .unwrap_or_else(|| NOT_MEASURED.to_string()),
        dns_time_ms: median(|s| s.dns_ms),
        tcp_connect_ms: median(|s| s.connect_ms),
        ttfb_ms: median(|s| s.ttfb_ms),
        total_time_ms: total_ms,
        http_status: last.map(|s| s.status).unwrap_or(0),
        edge_pop: pop_hdr
            .clone()
            .or(cf_ray.clone())
            .unwrap_or_else(|| "not detected".to_string()),
        status: label.to_string(),
        jitter_ms: jitter,
        packet_loss_pct: loss,
        notes,
        measured: true,
    };

    let note = "ReadyHai has no remote probe nodes: only this host was measured. Regional latency, geo-DNS behaviour and per-region edge selection were not measured.".to_string();
    let verdict = if samples.is_empty() {
        "CRITICAL: Target is unreachable from this host: no request got an HTTP response."
            .to_string()
    } else if cdn_edge_active {
        format!(
            "REACHABLE from this host in {total_ms}ms (median of {} sample(s)); CDN/edge response headers are present. {note}",
            samples.len()
        )
    } else {
        format!(
            "REACHABLE from this host in {total_ms}ms (median of {} sample(s)); no CDN/edge response headers seen. {note}",
            samples.len()
        )
    };

    Ok(MultiRegionReport {
        target: req.target.clone(),
        timestamp,
        regions: vec![region],
        fastest_region: NOT_MEASURED.to_string(),
        slowest_region: NOT_MEASURED.to_string(),
        geo_dns_consistent: None,
        cdn_edge_active,
        regional_disparity_ms: 0,
        agent_verdict: verdict,
        recommendations: vec![
            "To compare regions, run ReadyHai from a machine in each region you care about and compare the reports.".to_string(),
        ],
        not_measured_regions: NOT_MEASURED_REGIONS.iter().map(|s| s.to_string()).collect(),
        measurement_note: note,
    })
}

