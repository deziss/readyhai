//! Curl command generation, containerized runner orchestration, and output parser.

use super::types::{CurlTestRequest, CurlTestResponse, MAX_CAPTURE_BYTES, MAX_TIMEOUT_MS};
use super::utils::{has_header, http_client, parse_method, read_capped, sh_quote, truncate_chars};
use crate::tools::run_capped;
use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

const CURL_MARKER: &str = "---READYHAI_TIMINGS---";

pub(crate) fn curl_command(req: &CurlTestRequest, url: &reqwest::Url, timeout_s: u64) -> Command {
    let mut cmd = Command::new("curl");
    cmd.arg("-q").arg("-sS").arg("-v");
    cmd.arg("--proto").arg("=http,https");
    cmd.arg("-X").arg(req.method.to_uppercase());
    cmd.arg("--connect-timeout").arg(timeout_s.to_string());
    cmd.arg("--max-time").arg((timeout_s * 2).to_string());
    cmd.arg("-w").arg(format!("\n{CURL_MARKER}\nnamelookup:%{{time_namelookup}}\nconnect:%{{time_connect}}\nappconnect:%{{time_appconnect}}\npretransfer:%{{time_pretransfer}}\nstarttransfer:%{{time_starttransfer}}\ntotal:%{{time_total}}\nhttp_code:%{{http_code}}\nspeed_download:%{{speed_download}}\n"));
    for (k, v) in &req.headers {
        cmd.arg("-H").arg(format!("{k}: {v}"));
    }
    if let Some(ref p) = req.payload {
        if !has_header(&req.headers, "content-type") {
            cmd.arg("-H").arg("Content-Type: application/json");
        }
        cmd.arg("--data-raw").arg(p);
    }
    cmd.arg("--").arg(url.as_str());
    cmd
}

pub fn execute_curl_test(req: &CurlTestRequest) -> Result<CurlTestResponse> {
    let mut req = req.clone();
    let url = req.sanitize()?;
    let timeout_s = req
        .timeout_ms
        .div_ceil(1000)
        .clamp(1, MAX_TIMEOUT_MS / 1000);
    let full_curl_cmd = generate_curl(
        &req.method,
        url.as_str(),
        &req.headers,
        req.payload.as_deref(),
    );
    let mut cmd = curl_command(&req, &url, timeout_s);

    // hard wall-clock limit slightly above curl's own --max-time, bounded output
    match run_capped(
        &mut cmd,
        Duration::from_secs(timeout_s * 2 + 5),
        MAX_CAPTURE_BYTES,
        None,
    ) {
        Ok(out) => {
            let mut stderr_str = out.stderr_lossy();
            if out.timed_out {
                stderr_str.push_str("\n(curl was killed after the hard time limit)");
            }
            let (mut clean_stdout, timings) = if out.truncated && !out.stdout_tail.is_empty() {
                // the -w trailer is at the very end: read the timings from the retained tail
                let (_, t) = parse_curl_output(&String::from_utf8_lossy(&out.stdout_tail));
                let mut body = out.stdout_lossy();
                if let Some(pos) = body.find(CURL_MARKER) {
                    body.truncate(pos);
                }
                (body.trim().to_string(), t)
            } else {
                parse_curl_output(&out.stdout_lossy())
            };
            if out.truncated {
                clean_stdout.push_str(&format!(
                    "\n[output truncated at {MAX_CAPTURE_BYTES} bytes]"
                ));
            }
            let secs = |k: &str| timings.get(k).and_then(|v| v.parse().ok()).unwrap_or(0.0);

            Ok(CurlTestResponse {
                command: full_curl_cmd,
                exit_code: out.status.and_then(|s| s.code()).unwrap_or(-1),
                stdout: clean_stdout,
                stderr: truncate_chars(&stderr_str, 64 * 1024),
                status_code: timings
                    .get("http_code")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                dns_lookup_s: secs("namelookup"),
                connect_s: secs("connect"),
                appconnect_s: secs("appconnect"),
                starttransfer_s: secs("starttransfer"),
                total_s: secs("total"),
                not_measured: vec![],
                truncated: out.truncated,
            })
        }
        Err(e) => native_curl_fallback(&req, &url, full_curl_cmd, &e.to_string()),
    }
}

/// curl could not be run: measure what the native client can measure, and say what it cannot.
/// Nothing is invented: DNS/connect/TLS handshake timings are not observable here, so they are
/// zero and listed in `not_measured`.
pub(crate) fn native_curl_fallback(
    req: &CurlTestRequest,
    url: &reqwest::Url,
    command: String,
    why: &str,
) -> Result<CurlTestResponse> {
    let t0 = Instant::now();
    let client = http_client(req.timeout_ms, true);
    let method = parse_method(&req.method)?;
    let mut rb = client.request(method, url.as_str());
    for (k, v) in &req.headers {
        rb = rb.header(k, v);
    }
    if let Some(ref p) = req.payload {
        if !has_header(&req.headers, "content-type") {
            rb = rb.header("Content-Type", "application/json");
        }
        rb = rb.body(p.clone());
    }
    let res = rb.send();
    let headers_s = t0.elapsed().as_secs_f64();
    match res {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let (bytes, truncated) = read_capped(resp, MAX_CAPTURE_BYTES);
            let total_s = t0.elapsed().as_secs_f64();
            Ok(CurlTestResponse {
                command,
                exit_code: 0,
                stdout: String::from_utf8_lossy(&bytes).into_owned(),
                stderr: format!(
                    "(Fallback execution via native HTTP client; curl could not be run: {why})"
                ),
                status_code: code,
                dns_lookup_s: 0.0,
                connect_s: 0.0,
                appconnect_s: 0.0,
                starttransfer_s: headers_s,
                total_s,
                not_measured: ["dns_lookup_s", "connect_s", "appconnect_s"]
                    .map(String::from)
                    .to_vec(),
                truncated,
            })
        }
        Err(err) => Ok(CurlTestResponse {
            command,
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("Execution failed: {err}"),
            status_code: 0,
            dns_lookup_s: 0.0,
            connect_s: 0.0,
            appconnect_s: 0.0,
            starttransfer_s: 0.0,
            total_s: t0.elapsed().as_secs_f64(),
            not_measured: [
                "dns_lookup_s",
                "connect_s",
                "appconnect_s",
                "starttransfer_s",
            ]
            .map(String::from)
            .to_vec(),
            truncated: false,
        }),
    }
}

/// Reproduction command for the report: every value single-quoted so a header or payload cannot
/// break out of the command when someone pastes it into a shell.
pub fn generate_curl(
    method: &str,
    target: &str,
    headers: &HashMap<String, String>,
    payload: Option<&str>,
) -> String {
    let mut parts = vec![format!(
        "curl -s -o /dev/null -w {} -X {}",
        sh_quote(
            "DNS: %{time_namelookup}s | Connect: %{time_connect}s | TTFB: %{time_starttransfer}s | Total: %{time_total}s | Status: %{http_code}\\n"
        ),
        sh_quote(&method.to_uppercase())
    )];
    for (k, v) in headers {
        parts.push(format!("-H {}", sh_quote(&format!("{k}: {v}"))));
    }
    if let Some(p) = payload {
        if !has_header(headers, "content-type") {
            parts.push("-H 'Content-Type: application/json'".to_string());
        }
        parts.push(format!("--data-raw {}", sh_quote(p)));
    }
    parts.push(format!("-- {}", sh_quote(target)));
    parts.join(" ")
}

pub(crate) fn parse_curl_output(stdout: &str) -> (String, HashMap<String, String>) {
    let mut timings = HashMap::new();
    let clean_body;

    if let Some(pos) = stdout.find(CURL_MARKER) {
        clean_body = stdout[..pos].trim().to_string();
        let timing_section = &stdout[pos + CURL_MARKER.len()..];
        for line in timing_section.lines() {
            if let Some((k, v)) = line.split_once(':') {
                timings.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    } else {
        clean_body = stdout.to_string();
    }

    (clean_body, timings)
}

// ============================================================================
// 6-Pillar Deep Diagnostic Suite Implementations
// ============================================================================

