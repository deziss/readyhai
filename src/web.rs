//! Web/API checks: native smoke check, Schemathesis, ZAP baseline (passive).
//! TLS certificate expiry is intentionally not checked here (needs a TLS
//! handshake library beyond reqwest); it is a documented gap.
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::*;
use crate::tools::{parse_junit, ToolSpec};
use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, SET_COOKIE};
use std::time::{Duration, Instant};

pub fn checks() -> Vec<Check> {
    let w = &[TargetKind::Web];
    vec![
        Check::new("web.smoke", "Web smoke: status, headers, cookies, CORS, health", w, Profile::Quick, smoke),
        Check::new("tool.schemathesis", "Schemathesis API fuzzing (OpenAPI)", w, Profile::Standard, schemathesis)
            .tool("schemathesis"),
        Check::new("tool.zap_baseline", "ZAP baseline (passive)", w, Profile::Standard, zap).tool("zap"),
        Check::new("tool.playwright", "Browser crawl: JS errors, failed requests, broken links (Playwright)", w, Profile::Standard, playwright)
            .tool("playwright"),
    ]
}

/// Follow at most 5 redirects, and never to another host (scope/SSRF guard).
fn same_host_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|a| {
        let first = a.previous().first().and_then(|u| u.host_str().map(str::to_owned));
        if a.previous().len() >= 5 {
            a.stop()
        } else if first.as_deref() != a.url().host_str() {
            a.stop()
        } else {
            a.follow()
        }
    })
}

fn client(redirects: bool) -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(if redirects { same_host_redirects() } else { reqwest::redirect::Policy::none() })
        .user_agent("readyhai")
        .build()?)
}

/// Host part of an http(s) URL (no userinfo, no port).
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or(auth);
    if let Some(r) = auth.strip_prefix('[') {
        return r.split(']').next().unwrap_or(r);
    }
    auth.split(':').next().unwrap_or(auth)
}

fn is_local(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0") || host.ends_with(".localhost")
}

fn origin_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    format!("{scheme}://{auth}")
}

/// Rewrite loopback hosts so a container can reach the host machine.
fn container_url(url: &str) -> (String, bool) {
    let h = host_of(url);
    if is_local(h) {
        let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
        let (auth, tail) = match rest.find(['/', '?', '#']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let port = if h == "::1" { auth.rsplit_once("]:").map(|x| x.1) } else { auth.rsplit_once(':').map(|x| x.1) };
        let port = port.filter(|p| p.chars().all(|c| c.is_ascii_digit()));
        let a = match port {
            Some(p) => format!("host.docker.internal:{p}"),
            None => "host.docker.internal".to_string(),
        };
        (format!("{scheme}://{a}{tail}"), true)
    } else {
        (url.to_string(), false)
    }
}

pub fn discover_openapi(base: &str) -> Option<String> {
    let c = client(true).ok()?;
    let origin = origin_of(base);
    for p in ["/openapi.json", "/docs/openapi.json", "/api/openapi.json", "/swagger.json"] {
        let u = format!("{origin}{p}");
        if let Ok(r) = c.get(&u).send() {
            if r.status().is_success() {
                let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
                if ct.contains("json") || ct.contains("yaml") {
                    return Some(u);
                }
            }
        }
    }
    None
}

fn hdr(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

fn cookie_findings(h: &HeaderMap, url: &str, out: &mut Vec<Finding>) {
    for v in h.get_all(SET_COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        let mut parts = s.split(';');
        let name = parts.next().unwrap_or("").split('=').next().unwrap_or("").trim().to_string();
        let attrs: Vec<String> = parts.map(|a| a.trim().to_ascii_lowercase()).collect();
        let mut missing = vec![];
        if !attrs.iter().any(|a| a == "secure") {
            missing.push("Secure");
        }
        if !attrs.iter().any(|a| a == "httponly") {
            missing.push("HttpOnly");
        }
        if !attrs.iter().any(|a| a.starts_with("samesite")) {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            let mut f = Finding::new("web.smoke", "web.insecure_cookie", Category::Security, Severity::Medium,
                format!("Cookie '{name}' lacks {}", missing.join(", ")), url)
                .detail(format!("Cookie '{name}' is missing attributes: {}.", missing.join(", ")))
                .remediation("Set Secure, HttpOnly and SameSite on session cookies.")
                .fp_key(format!("{url}#{name}"));
            f.finalize();
            out.push(f);
        }
    }
}

fn smoke(ctx: &Ctx) -> Result<CheckOutput> {
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
            let mut f = Finding::new("web.smoke", "web.5xx", Category::Reliability, Severity::High,
                "Target unreachable", &url)
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
        add(Finding::new("web.smoke", "web.5xx", Category::Reliability, Severity::High,
            format!("Server error {status}"), &url)
            .detail(format!("GET returned HTTP {status}."))
            .remediation("Fix the server error; check application logs."));
    } else if status >= 400 {
        add(Finding::new("web.smoke", "web.4xx", Category::Reliability, Severity::Medium,
            format!("Client error {status} on target URL"), &url)
            .detail(format!("GET returned HTTP {status}."))
            .remediation("Confirm the URL is correct and publicly reachable."));
    }
    if latency > Duration::from_secs(2) {
        add(Finding::new("web.smoke", "web.slow", Category::Performance, Severity::Low,
            "Slow response", &url)
            .detail(format!("Response took {} ms (threshold 2000 ms).", latency.as_millis()))
            .remediation("Profile the endpoint; add caching or reduce backend latency."));
    }
    let https = url.starts_with("https://");
    let host = host_of(&url).to_string();
    if !https && !is_local(&host) {
        add(Finding::new("web.smoke", "web.no_tls", Category::Security, Severity::Medium,
            "Target served over plain HTTP", &url)
            .remediation("Serve over HTTPS and redirect HTTP to HTTPS."));
    }
    let mut missing = vec![];
    if https && hdr(&headers, "strict-transport-security").is_none() {
        missing.push("Strict-Transport-Security");
    }
    let csp = hdr(&headers, "content-security-policy");
    if csp.is_none() {
        missing.push("Content-Security-Policy");
    }
    if hdr(&headers, "x-content-type-options").is_none() {
        missing.push("X-Content-Type-Options");
    }
    let fa = csp.as_deref().map(|c| c.to_ascii_lowercase().contains("frame-ancestors")).unwrap_or(false);
    if hdr(&headers, "x-frame-options").is_none() && !fa {
        missing.push("X-Frame-Options");
    }
    if hdr(&headers, "referrer-policy").is_none() {
        missing.push("Referrer-Policy");
    }
    if !missing.is_empty() {
        add(Finding::new("web.smoke", "web.missing_headers", Category::Security, Severity::Medium,
            format!("Missing security headers: {}", missing.join(", ")), &url)
            .detail(format!("Response lacks: {}.", missing.join(", ")))
            .remediation("Add the listed headers at the reverse proxy or application."));
    }
    for name in ["server", "x-powered-by"] {
        if let Some(v) = hdr(&headers, name) {
            if v.chars().any(|c| c.is_ascii_digit()) {
                add(Finding::new("web.smoke", "web.version_disclosure", Category::Security, Severity::Low,
                    format!("Version disclosed in {name} header"), &url)
                    .detail(format!("{name}: {v}"))
                    .remediation("Strip version details from Server / X-Powered-By.")
                    .fp_key(format!("{url}#{name}")));
            }
        }
    }
    let mut cf = vec![];
    cookie_findings(&headers, &url, &mut cf);
    for f in cf { add(f); }

    // CORS probe
    let probe = "https://readyhai-probe.invalid";
    if let Ok(r) = c.get(&url).header("Origin", probe).send() {
        let acao = hdr(r.headers(), "access-control-allow-origin");
        let acac = hdr(r.headers(), "access-control-allow-credentials").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
        let bad = match acao.as_deref() {
            Some("*") if acac => Some("wildcard origin with credentials"),
            Some(o) if o == probe => Some("arbitrary Origin is reflected"),
            _ => None,
        };
        if r.status().as_u16() >= 400 {
            ctx.error_line("web.http", &format!("GET {} -> {} (CORS probe)", path_of(&url), r.status().as_u16()));
        }
        if let Some(why) = bad {
            add(Finding::new("web.smoke", "web.cors_permissive", Category::Security, Severity::Medium,
                "Permissive CORS policy", &url)
                .detail(format!("CORS: {why} (credentials allowed: {acac})."))
                .remediation("Allow-list trusted origins; never reflect Origin or combine * with credentials."));
        }
    }
    // Health endpoints
    let origin = origin_of(&url);
    let healthy = ["/health", "/healthz", "/api/health", "/ready"]
        .iter()
        .any(|p| c.get(format!("{origin}{p}")).send().map(|r| r.status().is_success()).unwrap_or(false));
    if !healthy {
        add(Finding::new("web.smoke", "web.no_health", Category::Reliability, Severity::Low,
            "No health endpoint found", &origin)
            .detail("None of /health, /healthz, /api/health, /ready returned 2xx.")
            .remediation("Expose a health endpoint for orchestrators and monitors."));
    }
    Ok(CheckOutput::findings(out))
}

fn gate(ctx: &Ctx) -> Option<CheckOutput> {
    if !ctx.docker.available {
        return Some(CheckOutput::status(CheckStatus::Skipped("docker not available".into())));
    }
    None
}

fn schemathesis(ctx: &Ctx) -> Result<CheckOutput> {
    let url = ctx.target.url.clone().context("no target url")?;
    let spec = match ctx.target.openapi.clone().or_else(|| discover_openapi(&url)) {
        Some(s) => s,
        None => return Ok(CheckOutput::status(CheckStatus::NotApplicable("no OpenAPI spec given or discovered".into()))),
    };
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    let (base, gw) = container_url(&origin_of(&url));
    let (schema, gw2) = if spec.starts_with("http") {
        container_url(&spec)
    } else {
        // local spec file: stage it into the mounted /out dir so the container can read it
        let out = ctx.out_dir();
        std::fs::create_dir_all(&out)?;
        std::fs::copy(&spec, out.join("openapi-spec.json")).with_context(|| format!("cannot read spec {spec}"))?;
        ("/out/openapi-spec.json".to_string(), false)
    };
    let mut ts = ToolSpec::new("schemathesis", &[
        "run", &schema, "--url", &base, "--checks", "all", "--max-examples", "20",
        "--report", "junit", "--report-dir", "/out",
    ]);
    ts.network = true;
    ts.host_gateway = gw || gw2;
    ts.timeout_secs = 600;
    let run = ctx.docker.run(ctx, &ts)?;
    let mut findings = vec![];
    let mut parsed_any = false;
    if let Ok(rd) = std::fs::read_dir(ctx.out_dir()) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("xml") {
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.to_lowercase().contains("schemathesis") && !name.starts_with("junit") {
                continue;
            }
            let Ok(xml) = std::fs::read_to_string(&p) else { continue };
            parsed_any = true;
            for case in parse_junit(&xml) {
                if !(case.failed || case.errored) {
                    continue;
                }
                let m = case.message.to_lowercase();
                let server = m.contains("500") || m.contains("5xx") || m.contains("server error") || m.contains("server_error");
                let (rule, cat, sev) = if server {
                    ("api.server_error".to_string(), Category::Reliability, Severity::High)
                } else {
                    let kind = if m.contains("schema") || m.contains("conformance") { "schema" }
                        else if m.contains("content") { "content_type" }
                        else if m.contains("status") { "status_code" } else { "check" };
                    (format!("api.{kind}"), Category::Quality, Severity::Medium)
                };
                let msg: String = case.message.chars().take(400).collect();
                let mut f = Finding::new("tool.schemathesis", &rule, cat, sev,
                    format!("API check failed: {}", case.name), case.name.clone())
                    .detail(msg)
                    .remediation("Reproduce with Schemathesis against the failing operation and fix the handler or the schema.");
                f.finalize();
                findings.push(f);
            }
        }
    }
    if !parsed_any && run.exit_code != 0 {
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "schemathesis exited {} with no report: {}", run.exit_code, run.stderr_tail.chars().take(300).collect::<String>()))));
    }
    Ok(CheckOutput::findings(findings))
}

fn playwright(ctx: &Ctx) -> Result<CheckOutput> {
    let url = ctx.target.url.clone().context("no target url")?;
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    let (u, gw) = container_url(&url);
    let mut ts = ToolSpec::new("playwright", &["node", "/runner/crawl.mjs", &u, "--max-pages", "20", "--out", "/out"]);
    ts.network = true;
    ts.host_gateway = gw;
    ts.memory = "2g".into();
    ts.timeout_secs = 600;
    ts.tmpfs = vec!["/home/pwuser:rw,size=256m,mode=1777".into()];
    ts.env = vec![("PLAYWRIGHT_BROWSERS_PATH".into(), "/ms-playwright".into())];
    let hint = "build the runner: docker build -t readyhai/playwright-runner:local runners/playwright";
    let run = match ctx.docker.run(ctx, &ts) {
        Ok(r) => r,
        Err(e) if is_missing_image(&e.to_string()) => return Ok(CheckOutput::status(CheckStatus::Skipped(hint.into()))),
        Err(e) => return Err(e),
    };
    let path = ctx.out_dir().join("playwright.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        if is_missing_image(&run.stderr_tail) {
            return Ok(CheckOutput::status(CheckStatus::Skipped(hint.into())));
        }
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "playwright produced no report (exit {}): {}", run.exit_code, run.stderr_tail.chars().take(300).collect::<String>()))));
    };
    let (findings, lines) = parse_playwright(&text)?;
    for l in lines {
        ctx.error_line("web.console", &l);
    }
    Ok(CheckOutput::findings(findings))
}

fn is_missing_image(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("unable to find image") || l.contains("pull access denied") || l.contains("no such image")
}

/// Parse /out/playwright.json into findings plus raw console/page error lines for clustering.
pub fn parse_playwright(text: &str) -> Result<(Vec<Finding>, Vec<String>)> {
    let v: serde_json::Value = serde_json::from_str(text)?;
    let mut out: Vec<Finding> = vec![];
    let mut lines: Vec<String> = vec![];
    let mut seen_failed = std::collections::HashSet::new();
    let strs = |x: &serde_json::Value| -> Vec<String> {
        x.as_array().into_iter().flatten().map(|e| {
            e.as_str().map(|s| s.to_string()).or_else(|| e["url"].as_str().map(|u| {
                format!("{u} ({})", e["status"].as_i64().map(|n| n.to_string()).unwrap_or_else(|| "?".into()))
            })).unwrap_or_default()
        }).filter(|s| !s.is_empty()).collect()
    };
    for pg in v["pages"].as_array().into_iter().flatten() {
        let url = pg["url"].as_str().unwrap_or("").to_string();
        let shot = pg["screenshot"].as_str().filter(|s| !s.is_empty());
        let tail = shot.map(|s| format!(" Screenshot: out/{s}")).unwrap_or_default();
        let perrs = strs(&pg["page_errors"]);
        for e in &perrs {
            lines.push(format!("pageerror: {e}"));
            let mut f = Finding::new("tool.playwright", "web.page_error", Category::Quality, Severity::High,
                "Uncaught JavaScript exception", &url)
                .detail(format!("{}{tail}", e.chars().take(300).collect::<String>()))
                .remediation("Fix the exception; it breaks page behaviour for real users.")
                .fp_key(format!("{url}#{}", crate::logs::signature(e)));
            f.finalize();
            out.push(f);
        }
        let cerrs = strs(&pg["console_errors"]);
        for e in &cerrs {
            lines.push(format!("console.error: {e}"));
        }
        if !cerrs.is_empty() {
            let sample = cerrs.iter().take(3).map(|e| e.chars().take(200).collect::<String>()).collect::<Vec<_>>().join(" | ");
            let mut f = Finding::new("tool.playwright", "web.console_error", Category::Quality, Severity::Medium,
                format!("{} console error(s) on page", cerrs.len()), &url)
                .detail(sample)
                .remediation("Open DevTools on this page and resolve the logged errors.")
                .fp_key(format!("{url}#console"));
            f.finalize();
            out.push(f);
        }
        let broken = strs(&pg["broken_links"]);
        if !broken.is_empty() {
            let sample = broken.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
            let mut f = Finding::new("tool.playwright", "web.broken_link", Category::Quality, Severity::Medium,
                format!("{} broken link(s) on page", broken.len()), &url)
                .detail(sample)
                .remediation("Fix or remove the dead links.")
                .fp_key(format!("{url}#links"));
            f.finalize();
            out.push(f);
        }
        for fr in pg["failed_requests"].as_array().into_iter().flatten() {
            let ru = fr["url"].as_str().unwrap_or("");
            let st = fr["status"].as_i64().unwrap_or(0);
            let (rule, cat, sev) = if st >= 500 {
                ("web.5xx", Category::Reliability, Severity::High)
            } else if st >= 400 {
                ("web.4xx", Category::Reliability, Severity::Low)
            } else {
                continue;
            };
            if !seen_failed.insert((ru.to_string(), st)) {
                continue;
            }
            let mut f = Finding::new("tool.playwright", rule, cat, sev,
                format!("Request failed with HTTP {st}"), ru)
                .detail(format!("Observed while loading {url}."))
                .remediation("Fix the failing endpoint or the reference to it.")
                .fp_key(format!("{ru}#{st}"));
            f.finalize();
            out.push(f);
        }
    }
    Ok((out, lines))
}

fn zap(ctx: &Ctx) -> Result<CheckOutput> {
    let url = ctx.target.url.clone().context("no target url")?;
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    if url.chars().any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '`' | ';' | '$' | '\\' | '&' | '|' | '<' | '>' | '(' | ')')) {
        return Ok(CheckOutput::status(CheckStatus::Skipped("target URL contains characters unsafe for the ZAP command line".into())));
    }
    let (u, gw) = container_url(&url);
    let cmd = format!("zap-baseline.py -t '{u}' -J zap.json -I; cp /zap/wrk/zap.json /out/zap.json");
    let mut ts = ToolSpec::new("zap", &["-c", &cmd]);
    ts.entrypoint = Some("sh".into());
    ts.workdir = Some("/zap/wrk".into());
    ts.tmpfs = vec!["/zap/wrk:rw,exec,mode=1777".into(), "/home/zap:rw,exec,mode=1777".into()];
    ts.env = vec![("JAVA_TOOL_OPTIONS".into(), "-Duser.home=/home/zap".into())];
    ts.network = true;
    ts.host_gateway = gw;
    ts.timeout_secs = 900;
    let run = ctx.docker.run(ctx, &ts)?;
    let path = ctx.out_dir().join("zap.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "ZAP produced no report (exit {}): {}", run.exit_code, run.stderr_tail.chars().take(300).collect::<String>()))));
    };
    Ok(CheckOutput::findings(parse_zap(&text)?))
}

pub fn parse_zap(text: &str) -> Result<Vec<Finding>> {
    let v: serde_json::Value = serde_json::from_str(text)?;
    let mut out = vec![];
    for site in v["site"].as_array().into_iter().flatten() {
        for a in site["alerts"].as_array().into_iter().flatten() {
            let risk = a["riskcode"].as_str().map(|s| s.to_string()).or_else(|| a["riskcode"].as_i64().map(|n| n.to_string())).unwrap_or_default();
            let sev = match risk.as_str() {
                "3" => Severity::High,
                "2" => Severity::Medium,
                "1" => Severity::Low,
                _ => Severity::Info,
            };
            let pid = a["pluginid"].as_str().map(|s| s.to_string()).or_else(|| a["pluginid"].as_i64().map(|n| n.to_string())).unwrap_or_else(|| "0".into());
            let name = a["alert"].as_str().or(a["name"].as_str()).unwrap_or("ZAP alert");
            let inst = a["instances"].as_array();
            let loc = inst.and_then(|i| i.first()).and_then(|i| i["uri"].as_str()).unwrap_or("").to_string();
            let n = inst.map(|i| i.len()).unwrap_or(0);
            let strip = |s: &str| {
                let mut o = String::new();
                let mut in_tag = false;
                for ch in s.chars() {
                    match ch { '<' => in_tag = true, '>' => in_tag = false, c if !in_tag => o.push(c), _ => {} }
                }
                o.trim().to_string()
            };
            let mut f = Finding::new("tool.zap_baseline", &format!("zap.{pid}"), Category::Security, sev,
                name.to_string(), loc)
                .detail(format!("{} ({} instance(s))", strip(a["desc"].as_str().unwrap_or("")), n))
                .remediation(strip(a["solution"].as_str().unwrap_or("")));
            f.finalize();
            out.push(f);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hosts() {
        assert_eq!(host_of("http://user@localhost:8080/x"), "localhost");
        assert_eq!(container_url("http://127.0.0.1:3000/a").0, "http://host.docker.internal:3000/a");
        assert!(!container_url("https://example.com").1);
    }
    #[test]
    fn playwright_parse() {
        let j = r#"{"pages":[{"url":"http://a/","status":200,"console_errors":["x 1","y"],"page_errors":["TypeError: z"],
          "failed_requests":[{"url":"http://a/api","status":503,"failure":""},{"url":"http://a/api","status":503,"failure":""},{"url":"http://a/n","status":404,"failure":""},{"url":"http://a/f","status":0,"failure":"net::ERR"}],
          "broken_links":["http://a/dead (404)"],"screenshot":"page-0.png"}]}"#;
        let (f, lines) = parse_playwright(j).unwrap();
        let rules: Vec<&str> = f.iter().map(|x| x.rule.as_str()).collect();
        assert_eq!(rules.iter().filter(|r| **r == "web.5xx").count(), 1);
        assert!(rules.contains(&"web.page_error") && rules.contains(&"web.console_error") && rules.contains(&"web.broken_link") && rules.contains(&"web.4xx"));
        assert_eq!(f.iter().find(|x| x.rule == "web.page_error").unwrap().severity, Severity::High);
        assert_eq!(lines.len(), 3);
        assert!(is_missing_image("Unable to find image 'x' locally"));
    }
    #[test]
    fn zap_parse() {
        let j = r#"{"site":[{"alerts":[{"pluginid":"10038","alert":"CSP","riskcode":"2","desc":"<p>x</p>","instances":[{"uri":"http://a/"},{"uri":"http://a/b"}]}]}]}"#;
        let f = parse_zap(j).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "zap.10038");
        assert_eq!(f[0].severity, Severity::Medium);
    }
}
