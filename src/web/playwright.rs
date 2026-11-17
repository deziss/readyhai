use std::collections::HashSet;

use anyhow::{Context, Result};

use crate::ctx::Ctx;
use crate::model::*;
use crate::tools::ToolSpec;
use super::client::container_url;
use super::smoke::gate;

pub fn is_missing_image(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("unable to find image")
        || l.contains("pull access denied")
        || l.contains("no such image")
}

pub fn playwright(ctx: &Ctx) -> Result<CheckOutput> {
    let url = ctx.target.url.clone().context("no target url")?;
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    let (u, gw) = container_url(&url);
    let mut ts = ToolSpec::new(
        "playwright",
        &[
            "node",
            "/runner/crawl.mjs",
            &u,
            "--max-pages",
            "20",
            "--out",
            "/out",
        ],
    );
    ts.network = true;
    ts.host_gateway = gw;
    ts.memory = "2g".into();
    ts.timeout_secs = 600;
    ts.tmpfs = vec!["/home/pwuser:rw,size=256m,mode=1777".into()];
    ts.env = vec![("PLAYWRIGHT_BROWSERS_PATH".into(), "/ms-playwright".into())];
    // Same resolution as the UI QA checks: env override, local build, then the published image.
    ts.image = Some(crate::qa::ui::playwright_image());
    let hint = crate::qa::ui::HINT;
    let run = match ctx.docker.run(ctx, &ts) {
        Ok(r) => r,
        Err(e) if is_missing_image(&e.to_string()) => {
            return Ok(CheckOutput::status(CheckStatus::Skipped(hint.into())));
        }
        Err(e) => return Err(e),
    };
    let path = ctx.out_dir().join("playwright.json");
    let text = match crate::tools::read_text_capped(&path, crate::tools::MAX_OUT_BYTES) {
        Ok(t) => Some(t),
        Err(e) if crate::tools::is_oversize(&e) => return Err(e),
        Err(_) => None,
    };
    let Some(text) = text else {
        if is_missing_image(&run.stderr_tail) {
            return Ok(CheckOutput::status(CheckStatus::Skipped(hint.into())));
        }
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "playwright produced no report (exit {}): {}",
            run.exit_code,
            run.stderr_tail.chars().take(300).collect::<String>()
        ))));
    };
    let (findings, lines) = parse_playwright(&text)?;
    for l in lines {
        ctx.error_line("web.console", &l);
    }
    Ok(CheckOutput::findings(findings))
}

/// Parse /out/playwright.json into findings plus raw console/page error lines for clustering.
pub fn parse_playwright(text: &str) -> Result<(Vec<Finding>, Vec<String>)> {
    let v: serde_json::Value = serde_json::from_str(text)?;
    let mut out: Vec<Finding> = vec![];
    let mut lines: Vec<String> = vec![];
    let mut seen_failed = HashSet::new();
    let strs = |x: &serde_json::Value| -> Vec<String> {
        x.as_array()
            .into_iter()
            .flatten()
            .map(|e| {
                e.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| {
                        e["url"].as_str().map(|u| {
                            format!(
                                "{u} ({})",
                                e["status"]
                                    .as_i64()
                                    .map(|n| n.to_string())
                                    .unwrap_or_else(|| "?".into())
                            )
                        })
                    })
                    .unwrap_or_default()
            })
            .filter(|s| !s.is_empty())
            .collect()
    };
    for pg in v["pages"].as_array().into_iter().flatten() {
        let url = pg["url"].as_str().unwrap_or("").to_string();
        let shot = pg["screenshot"].as_str().filter(|s| !s.is_empty());
        let tail = shot
            .map(|s| format!(" Screenshot: out/{s}"))
            .unwrap_or_default();
        let perrs = strs(&pg["page_errors"]);
        for e in &perrs {
            lines.push(format!("pageerror: {e}"));
            let mut f = Finding::new(
                "tool.playwright",
                "web.page_error",
                Category::Quality,
                Severity::High,
                "Uncaught JavaScript exception",
                &url,
            )
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
            let sample = cerrs
                .iter()
                .take(3)
                .map(|e| e.chars().take(200).collect::<String>())
                .collect::<Vec<_>>()
                .join(" | ");
            let mut f = Finding::new(
                "tool.playwright",
                "web.console_error",
                Category::Quality,
                Severity::Medium,
                format!("{} console error(s) on page", cerrs.len()),
                &url,
            )
            .detail(sample)
            .remediation("Open DevTools on this page and resolve the logged errors.")
            .fp_key(format!("{url}#console"));
            f.finalize();
            out.push(f);
        }
        let broken = strs(&pg["broken_links"]);
        if !broken.is_empty() {
            let sample = broken
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let mut f = Finding::new(
                "tool.playwright",
                "web.broken_link",
                Category::Quality,
                Severity::Medium,
                format!("{} broken link(s) on page", broken.len()),
                &url,
            )
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
            let mut f = Finding::new(
                "tool.playwright",
                rule,
                cat,
                sev,
                format!("Request failed with HTTP {st}"),
                ru,
            )
            .detail(format!("Observed while loading {url}."))
            .remediation("Fix the failing endpoint or the reference to it.")
            .fp_key(format!("{ru}#{st}"));
            f.finalize();
            out.push(f);
        }
        for lk in pg["storage_leaks"].as_array().into_iter().flatten() {
            let store = lk["store"].as_str().unwrap_or("storage");
            let key = lk["key"].as_str().unwrap_or("");
            if key.is_empty() {
                continue;
            }
            let kind = lk["kind"].as_str().unwrap_or("sensitive_key");
            let mut f = Finding::new(
                "tool.playwright",
                "web.storage_secret",
                Category::Security,
                Severity::High,
                format!("Sensitive credential ({kind}) stored in {store}"),
                &url,
            )
            .detail(format!(
                "Key '{key}' in {store} exposes sensitive material to client-side JS / XSS."
            ))
            .remediation("Move tokens and secrets to HttpOnly, Secure, SameSite session cookies.")
            .fp_key(format!("{url}#storage#{store}#{key}"));
            f.finalize();
            out.push(f);
        }
        for ck in pg["cookie_issues"].as_array().into_iter().flatten() {
            let name = ck["name"].as_str().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let mut f = Finding::new(
                "tool.playwright",
                "web.cookie_httponly",
                Category::Security,
                Severity::Medium,
                format!("Sensitive cookie '{name}' missing HttpOnly/Secure flags"),
                &url,
            )
            .detail(format!(
                "httpOnly={}, secure={}",
                ck["httpOnly"].as_bool().unwrap_or(false),
                ck["secure"].as_bool().unwrap_or(false)
            ))
            .remediation("Mark authentication/session cookies with HttpOnly, Secure, and SameSite attributes.")
            .fp_key(format!("{url}#cookie#{name}"));
            f.finalize();
            out.push(f);
        }
        for map_url in strs(&pg["sourcemaps"]) {
            let mut f = Finding::new(
                "tool.playwright",
                "web.sourcemap_exposed",
                Category::Security,
                Severity::Medium,
                "Production JavaScript source map exposed",
                &map_url,
            )
            .detail(format!("Source map publicly fetched while crawling {url}."))
            .remediation("Disable public serving of .js.map files in production.")
            .fp_key(format!("{map_url}#sourcemap"));
            f.finalize();
            out.push(f);
        }
        let pm = strs(&pg["postmessage_issues"]);
        if !pm.is_empty() {
            let mut f = Finding::new(
                "tool.playwright",
                "web.postmessage_no_origin",
                Category::Security,
                Severity::Medium,
                format!("{} postMessage handler(s) without origin validation", pm.len()),
                &url,
            )
            .detail(pm[0].chars().take(180).collect::<String>())
            .remediation("Verify event.origin against an explicit allow-list inside window 'message' listeners.")
            .fp_key(format!("{url}#postmessage"));
            f.finalize();
            out.push(f);
        }
    }
    Ok((out, lines))
}
