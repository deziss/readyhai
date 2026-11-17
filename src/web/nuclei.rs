use std::path::Path;
use anyhow::{Context, Result};

use crate::ctx::Ctx;
use crate::model::*;
use crate::tools::ToolSpec;
use super::client::{container_url, has_shell_unsafe_chars};
use super::smoke::gate;

fn dir_has_entries(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .ok()
        .and_then(|mut it| it.next())
        .is_some()
}

pub fn nuclei(ctx: &Ctx) -> Result<CheckOutput> {
    let url = ctx.target.url.clone().context("no target url")?;
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    if has_shell_unsafe_chars(&url) {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "target URL contains characters unsafe for container invocation".into(),
        )));
    }
    let templates_dir = ctx.docker.cache_dir.join("nuclei");
    let has_cached_templates = dir_has_entries(&templates_dir);
    if crate::bundle::offline() && !has_cached_templates {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "offline mode: run `readyhai tools update` to cache nuclei templates".into(),
        )));
    }

    let (u, gw) = container_url(&url);
    let mut args = vec![
        "-u".to_string(),
        u,
        "-tags".to_string(),
        "cve,misconfig,exposure,takeover".to_string(),
        "-etags".to_string(),
        "dos,fuzz".to_string(),
        "-rl".to_string(),
        "20".to_string(),
        "-silent".to_string(),
        "-duc".to_string(),
        "-jsonl".to_string(),
        "-o".to_string(),
        "/out/nuclei.jsonl".to_string(),
    ];
    if has_cached_templates {
        args.push("-t".into());
        args.push("/cache/nuclei".into());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut ts = ToolSpec::new("nuclei", &arg_refs);
    ts.tmpfs = vec![
        "/tmp:rw,mode=1777".into(),
        "/home/nuclei:rw,mode=1777".into(),
    ];
    ts.env = vec![("HOME".into(), "/home/nuclei".into())];
    ts.network = true;
    ts.host_gateway = gw;
    ts.timeout_secs = 900;
    let run = ctx.docker.run(ctx, &ts)?;
    let path = ctx.out_dir().join("nuclei.jsonl");
    let text = match crate::tools::read_text_capped(&path, crate::tools::MAX_OUT_BYTES) {
        Ok(t) => Some(t),
        Err(e) if crate::tools::is_oversize(&e) => return Err(e),
        Err(_) => None,
    };
    if let Some(text) = text {
        return Ok(CheckOutput::findings(parse_nuclei(&text)?));
    }
    if run.exit_code != 0 {
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "nuclei produced no report (exit {}): {}",
            run.exit_code,
            run.stderr_tail.chars().take(300).collect::<String>()
        ))));
    }
    Ok(CheckOutput::findings(vec![]))
}

/// Parse Nuclei JSONL output into `Finding` entries under `tool.nuclei`.
pub fn parse_nuclei(text: &str) -> Result<Vec<Finding>> {
    let mut out = vec![];
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(trimmed).with_context(|| "invalid nuclei JSONL line")?;
        let tid = v["template-id"]
            .as_str()
            .or_else(|| v["template"].as_str())
            .unwrap_or("unknown");
        let info = &v["info"];
        let sev = match info["severity"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let title = info["name"].as_str().unwrap_or(tid);
        let loc = v["matched-at"]
            .as_str()
            .or_else(|| v["host"].as_str())
            .unwrap_or("");
        let mut detail = info["description"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();
        if let Some(matcher) = v["matcher-name"].as_str() {
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str(&format!("[matcher: {matcher}]"));
        }
        let mut ids = Vec::new();
        for key in ["cve-id", "cwe-id"] {
            if let Some(arr) = info["classification"][key].as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        ids.push(s.to_string());
                    }
                }
            } else if let Some(s) = info["classification"][key].as_str() {
                ids.push(s.to_string());
            }
        }
        let mut f = Finding::new(
            "tool.nuclei",
            &format!("nuclei.{tid}"),
            Category::Security,
            sev,
            title.to_string(),
            loc.to_string(),
        )
        .detail(detail)
        .remediation(info["remediation"].as_str().unwrap_or("").trim())
        .fp_key(format!("{tid}#{loc}"));
        if !ids.is_empty() {
            f = f.ids(ids);
        }
        f.finalize();
        out.push(f);
    }
    Ok(out)
}
