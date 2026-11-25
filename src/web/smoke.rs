use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::client::{client, host_of, is_local, origin_of};
use crate::ctx::Ctx;
use crate::model::*;

pub fn gate(ctx: &Ctx) -> Option<CheckOutput> {
    if !ctx.docker.available {
        return Some(CheckOutput::status(CheckStatus::Skipped(
            "docker not available".into(),
        )));
    }
    None
}

pub use super::security_headers::{cookie_findings, csp_findings, hdr, tls_findings};

pub fn smoke(ctx: &Ctx) -> Result<CheckOutput> {
    let url = ctx.target.url.clone().context("no target url")?;
    let c = client(true)?;
    let mut out: Vec<Finding> = vec![];
    let mut add = |mut f: Finding| {
        f.finalize();
        out.push(f);
    };
    let t = Instant::now();
    let resp = match c.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let mut f = Finding::new(
                "web.smoke",
                "web.5xx",
                Category::Reliability,
                Severity::High,
                "Target unreachable",
                &url,
            )
            .detail(format!("GET failed: {e}"))
            .remediation("Verify the service is running and reachable from the scanner.");
            f.finalize();
            return Ok(CheckOutput::findings(vec![f]));
        }
    };
    let latency = t.elapsed();
    let status = resp.status().as_u16();
    let path_of = |u: &str| {
        let rest = u.split_once("://").map(|x| x.1).unwrap_or(u);
        let p = rest.find(['/', '?']).map(|i| &rest[i..]).unwrap_or("/");
        p.split('?').next().unwrap_or("/").to_string()
    };
    if status >= 400 {
        ctx.error_line("web.http", &format!("GET {} -> {status}", path_of(&url)));
    }
    let headers = resp.headers().clone();
    if status >= 500 {
        add(Finding::new(
            "web.smoke",
            "web.5xx",
            Category::Reliability,
            Severity::High,
            format!("Server error {status}"),
            &url,
        )
        .detail(format!("GET returned HTTP {status}."))
        .remediation("Fix the server error; check application logs."));
    } else if status >= 400 {
        add(Finding::new(
            "web.smoke",
            "web.4xx",
            Category::Reliability,
            Severity::Medium,
            format!("Client error {status} on target URL"),
            &url,
        )
        .detail(format!("GET returned HTTP {status}."))
        .remediation("Confirm the URL is correct and publicly reachable."));
    }
    if latency > Duration::from_secs(2) {
        add(Finding::new(
            "web.smoke",
            "web.slow",
            Category::Performance,
            Severity::Low,
            "Slow response",
            &url,
        )
        .detail(format!(
            "Response took {} ms (threshold 2000 ms).",
            latency.as_millis()
        ))
        .remediation("Profile the endpoint; add caching or reduce backend latency."));
    }
    let https = url.starts_with("https://");
    let host = host_of(&url);
    if !https && !is_local(&host) {
        add(Finding::new(
            "web.smoke",
            "web.no_tls",
            Category::Security,
            Severity::Medium,
            "Target served over plain HTTP",
            &url,
        )
        .remediation("Serve over HTTPS and redirect HTTP to HTTPS."));
    }
    let mut missing = vec![];
    if https && hdr(&headers, "strict-transport-security").is_none() {
        missing.push("Strict-Transport-Security");
    }
    let mut sec_extra = vec![];
    let csp = hdr(&headers, "content-security-policy");
    if let Some(ref policy) = csp {
        csp_findings(policy, &url, &mut sec_extra);
    } else {
        missing.push("Content-Security-Policy");
    }
    if https && let Ok(parsed_u) = reqwest::Url::parse(&url) {
        let port = parsed_u.port_or_known_default().unwrap_or(443);
        let audit = crate::network::audit_tls_chain(&parsed_u, &host, port, 5000);
        tls_findings(&audit, &url, is_local(&host), &mut sec_extra);
    }
    for f in sec_extra {
        add(f);
    }
    if hdr(&headers, "x-content-type-options").is_none() {
        missing.push("X-Content-Type-Options");
    }
    let fa = csp
        .as_deref()
        .map(|c| c.to_ascii_lowercase().contains("frame-ancestors"))
        .unwrap_or(false);
    if hdr(&headers, "x-frame-options").is_none() && !fa {
        missing.push("X-Frame-Options");
    }
    if hdr(&headers, "referrer-policy").is_none() {
        missing.push("Referrer-Policy");
    }
    if !missing.is_empty() {
        add(Finding::new(
            "web.smoke",
            "web.missing_headers",
            Category::Security,
            Severity::Medium,
            format!("Missing security headers: {}", missing.join(", ")),
            &url,
        )
        .detail(format!("Response lacks: {}.", missing.join(", ")))
        .remediation("Add the listed headers at the reverse proxy or application."));
    }
    for name in ["server", "x-powered-by"] {
        if let Some(v) = hdr(&headers, name)
            && v.chars().any(|c| c.is_ascii_digit())
        {
            add(Finding::new(
                "web.smoke",
                "web.version_disclosure",
                Category::Security,
                Severity::Low,
                format!("Version disclosed in {name} header"),
                &url,
            )
            .detail(format!("{name}: {v}"))
            .remediation("Strip version details from Server / X-Powered-By.")
            .fp_key(format!("{url}#{name}")));
        }
    }
    let mut cf = vec![];
    cookie_findings(&headers, &url, &mut cf);
    for f in cf {
        add(f);
    }

    // CORS probe
    let probe = "https://readyhai-probe.invalid";
    if let Ok(r) = c.get(&url).header("Origin", probe).send() {
        let acao = hdr(r.headers(), "access-control-allow-origin");
        let acac = hdr(r.headers(), "access-control-allow-credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let bad = match acao.as_deref() {
            Some("*") if acac => Some("wildcard origin with credentials"),
            Some(o) if o == probe => Some("arbitrary Origin is reflected"),
            _ => None,
        };
        if r.status().as_u16() >= 400 {
            ctx.error_line(
                "web.http",
                &format!(
                    "GET {} -> {} (CORS probe)",
                    path_of(&url),
                    r.status().as_u16()
                ),
            );
        }
        if let Some(why) = bad {
            add(Finding::new(
                "web.smoke",
                "web.cors_permissive",
                Category::Security,
                Severity::Medium,
                "Permissive CORS policy",
                &url,
            )
            .detail(format!("CORS: {why} (credentials allowed: {acac})."))
            .remediation(
                "Allow-list trusted origins; never reflect Origin or combine * with credentials.",
            ));
        }
    }
    // Health endpoints
    let origin = origin_of(&url);
    let healthy = ["/health", "/healthz", "/api/health", "/ready"]
        .iter()
        .any(|p| {
            c.get(format!("{origin}{p}"))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false)
        });
    if !healthy {
        add(Finding::new(
            "web.smoke",
            "web.no_health",
            Category::Reliability,
            Severity::Low,
            "No health endpoint found",
            &origin,
        )
        .detail("None of /health, /healthz, /api/health, /ready returned 2xx.")
        .remediation("Expose a health endpoint for orchestrators and monitors."));
    }
    Ok(CheckOutput::findings(out))
}
