use std::collections::HashMap;

use anyhow::{Context, Result};
use regex::Regex;

use super::client::{container_url, discover_openapi, origin_of};
use super::smoke::gate;
use crate::ctx::Ctx;
use crate::model::*;
use crate::tools::{ToolSpec, parse_junit};

/// testcase name -> text of its first failure/error element (Schemathesis puts the prose there).
pub fn junit_failure_text(xml: &str) -> HashMap<String, String> {
    let case_re =
        Regex::new(r#"(?s)<testcase\b[^>]*?\bname="([^"]*)"[^>/]*>(.*?)</testcase>"#).unwrap();
    let body_re = Regex::new(r"(?s)<(?:failure|error)\b[^>]*>(.*?)</(?:failure|error)>").unwrap();
    let un = |t: &str| {
        t.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#x27;", "'")
            .replace("&amp;", "&")
    };
    let mut m = HashMap::new();
    for c in case_re.captures_iter(xml) {
        if let Some(b) = body_re.captures(&c[2]) {
            // drop the HTML/body dump after the check list: keep text up to "Reproduce with"
            let t = un(&b[1]);
            let t = t
                .split("Reproduce with")
                .next()
                .unwrap_or(&t)
                .trim()
                .to_string();
            m.insert(un(&c[1]), t);
        }
    }
    m
}

pub fn schemathesis(ctx: &Ctx) -> Result<CheckOutput> {
    let url = ctx.target.url.clone().context("no target url")?;
    let spec = match ctx
        .target
        .openapi
        .clone()
        .or_else(|| discover_openapi(&url))
    {
        Some(s) => s,
        None => {
            return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                "no OpenAPI spec given or discovered".into(),
            )));
        }
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
        std::fs::copy(&spec, out.join("openapi-spec.json"))
            .with_context(|| format!("cannot read spec {spec}"))?;
        ("/out/openapi-spec.json".to_string(), false)
    };
    let mut ts = ToolSpec::new(
        "schemathesis",
        &[
            "run",
            &schema,
            "--url",
            &base,
            "--checks",
            "all",
            "--max-examples",
            "20",
            "--report",
            "junit",
            "--report-dir",
            "/out",
        ],
    );
    ts.network = true;
    ts.host_gateway = gw || gw2;
    ts.timeout_secs = 600;
    let run = ctx.docker.run(ctx, &ts)?;
    let mut findings = vec![];
    let mut parsed_any = false;
    // Reports over the read cap: skipped, and the check says so (Partial) instead of passing.
    let mut oversize_notes: Vec<String> = vec![];
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
            let xml = match crate::tools::read_text_capped(&p, crate::tools::MAX_OUT_BYTES) {
                Ok(x) => x,
                Err(e) if crate::tools::is_oversize(&e) => {
                    oversize_notes.push(format!("{e:#}"));
                    continue;
                }
                Err(_) => continue,
            };
            parsed_any = true;
            let details = junit_failure_text(&xml);
            for case in parse_junit(&xml) {
                if !(case.failed || case.errored) {
                    continue;
                }
                let m = case.message.to_lowercase();
                let detail_txt = details.get(&case.name).cloned().unwrap_or_default();
                let dl = detail_txt.to_lowercase();
                let codes: Vec<&str> = case
                    .message
                    .split([',', ' '])
                    .filter(|c| c.starts_with("ST"))
                    .collect();
                let has = |c: &str| codes.contains(&c);
                // Schemathesis v4 reports check codes (ST101 ...) in `message`; the prose is in the body.
                let undeclared_501 = has("ST204") && dl.contains("returned 501");
                let (rule, cat, sev) = if has("ST401") || has("ST203") {
                    (
                        "api.auth_not_enforced".to_string(),
                        Category::Security,
                        Severity::High,
                    )
                } else if (has("ST101") && !undeclared_501)
                    || m.contains("500")
                    || m.contains("5xx")
                    || m.contains("server error")
                {
                    (
                        "api.server_error".to_string(),
                        Category::Reliability,
                        Severity::High,
                    )
                } else if has("ST204") {
                    (
                        "api.undeclared_method".to_string(),
                        Category::Quality,
                        Severity::Low,
                    )
                } else {
                    let kind = if has("ST201") || has("ST202") {
                        "invalid_input_accepted"
                    } else if m.contains("schema") || m.contains("conformance") || has("ST301") {
                        "schema"
                    } else if m.contains("content") || has("ST302") {
                        "content_type"
                    } else if m.contains("status") || has("ST303") {
                        "status_code"
                    } else {
                        "check"
                    };
                    (format!("api.{kind}"), Category::Quality, Severity::Medium)
                };
                let msg: String = if detail_txt.is_empty() {
                    case.message.clone()
                } else {
                    detail_txt
                }
                .chars()
                .take(600)
                .collect();
                let mut f = Finding::new(
                    "tool.schemathesis",
                    &rule,
                    cat,
                    sev,
                    format!("API check failed: {} ({})", case.name, case.message),
                    case.name.clone(),
                )
                .detail(msg)
                .remediation(
                    "Reproduce with Schemathesis against the failing operation and fix the handler or the schema.",
                );
                f.finalize();
                findings.push(f);
            }
        }
    }
    if !parsed_any && oversize_notes.is_empty() && run.exit_code != 0 {
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "schemathesis exited {} with no report: {}",
            run.exit_code,
            run.stderr_tail.chars().take(300).collect::<String>()
        ))));
    }
    Ok(crate::tools::partial(oversize_notes, findings))
}
