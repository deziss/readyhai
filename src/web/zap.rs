use anyhow::{Context, Result};

use crate::ctx::Ctx;
use crate::model::*;
use crate::tools::ToolSpec;
use super::client::{container_url, has_shell_unsafe_chars};
use super::smoke::gate;

pub fn run_zap_scan(
    ctx: &Ctx,
    check_id: &str,
    script: &str,
    out_file: &str,
    timeout_secs: u64,
) -> Result<CheckOutput> {
    let url = ctx.target.url.clone().context("no target url")?;
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    if has_shell_unsafe_chars(&url) {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "target URL contains characters unsafe for the ZAP command line".into(),
        )));
    }
    let (u, gw) = container_url(&url);
    let cmd = format!("{script} -t '{u}' -J {out_file} -I; cp /zap/wrk/{out_file} /out/{out_file}");
    let mut ts = ToolSpec::new("zap", &["-c", &cmd]);
    ts.entrypoint = Some("sh".into());
    ts.workdir = Some("/zap/wrk".into());
    ts.tmpfs = vec![
        "/zap/wrk:rw,exec,mode=1777".into(),
        "/home/zap:rw,exec,mode=1777".into(),
    ];
    ts.env = vec![("JAVA_TOOL_OPTIONS".into(), "-Duser.home=/home/zap".into())];
    ts.network = true;
    ts.host_gateway = gw;
    ts.timeout_secs = timeout_secs;
    let run = ctx.docker.run(ctx, &ts)?;
    let path = ctx.out_dir().join(out_file);
    let text = match crate::tools::read_text_capped(&path, crate::tools::MAX_OUT_BYTES) {
        Ok(t) => Some(t),
        Err(e) if crate::tools::is_oversize(&e) => return Err(e),
        Err(_) => None,
    };
    let Some(text) = text else {
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "ZAP produced no report (exit {}): {}",
            run.exit_code,
            run.stderr_tail.chars().take(300).collect::<String>()
        ))));
    };
    Ok(CheckOutput::findings(parse_zap_report(&text, check_id)?))
}

pub fn zap(ctx: &Ctx) -> Result<CheckOutput> {
    run_zap_scan(ctx, "tool.zap_baseline", "zap-baseline.py", "zap.json", 900)
}

pub fn zap_active(ctx: &Ctx) -> Result<CheckOutput> {
    if !ctx.nonprod || !matches!(ctx.profile, Profile::Deep) {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "intrusive: tool.zap_active requires --profile deep on a nonprod target".into(),
        )));
    }
    run_zap_scan(
        ctx,
        "tool.zap_active",
        "zap-full-scan.py",
        "zap-active.json",
        1800,
    )
}

pub fn strip_zap_html(s: &str) -> String {
    let mut dec = String::with_capacity(s.len());
    let rest = s
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"");
    let mut in_tag = false;
    for ch in rest.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => dec.push(c),
            _ => {}
        }
    }
    dec.trim().to_string()
}

pub fn zap_severity(risk: &str) -> Severity {
    match risk.trim() {
        "3" => Severity::High,
        "2" => Severity::Medium,
        "1" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse ZAP baseline (`tool.zap_baseline`) JSON report.
#[cfg(test)]
pub fn parse_zap(text: &str) -> Result<Vec<Finding>> {
    parse_zap_report(text, "tool.zap_baseline")
}

/// Parse ZAP JSON or XML report under the specified `check_id`.
pub fn parse_zap_report(text: &str, check_id: &str) -> Result<Vec<Finding>> {
    if text.trim_start().starts_with('<') {
        return parse_zap_xml(text, check_id);
    }
    let v: serde_json::Value = serde_json::from_str(text)?;
    let mut out = vec![];
    for site in v["site"].as_array().into_iter().flatten() {
        for a in site["alerts"].as_array().into_iter().flatten() {
            let risk = a["riskcode"]
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| a["riskcode"].as_i64().map(|n| n.to_string()))
                .unwrap_or_default();
            let pid = a["pluginid"]
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| a["pluginid"].as_i64().map(|n| n.to_string()))
                .unwrap_or_else(|| "0".into());
            let name = a["alert"]
                .as_str()
                .or(a["name"].as_str())
                .unwrap_or("ZAP alert");
            let inst = a["instances"].as_array();
            let loc = inst
                .and_then(|i| i.first())
                .and_then(|i| i["uri"].as_str())
                .unwrap_or("")
                .to_string();
            let n = inst.map(|i| i.len()).unwrap_or(0);
            let mut f = Finding::new(
                check_id,
                &format!("zap.{pid}"),
                Category::Security,
                zap_severity(&risk),
                name.to_string(),
                loc,
            )
            .detail(format!(
                "{} ({} instance(s))",
                strip_zap_html(a["desc"].as_str().unwrap_or("")),
                n
            ))
            .remediation(strip_zap_html(a["solution"].as_str().unwrap_or("")));
            f.finalize();
            out.push(f);
        }
    }
    Ok(out)
}

fn xml_tag_text<'a>(block: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let Some(start) = block.find(&open) else {
        return "";
    };
    let after = &block[start + open.len()..];
    let Some(end) = after.find(&close) else {
        return "";
    };
    after[..end].trim()
}

pub fn parse_zap_xml(text: &str, check_id: &str) -> Result<Vec<Finding>> {
    let mut out = vec![];
    let mut rest = text;
    while let Some(start) = rest.find("<alertitem>") {
        let after = &rest[start + "<alertitem>".len()..];
        let Some(end) = after.find("</alertitem>") else {
            break;
        };
        let block = &after[..end];
        rest = &after[end + "</alertitem>".len()..];
        let pid = {
            let p = xml_tag_text(block, "pluginid");
            if p.is_empty() { "0" } else { p }
        };
        let name = {
            let a = xml_tag_text(block, "alert");
            if a.is_empty() {
                xml_tag_text(block, "name")
            } else {
                a
            }
        };
        let risk = xml_tag_text(block, "riskcode");
        let loc = xml_tag_text(block, "uri").to_string();
        let inst_count = block
            .matches("<instance>")
            .count()
            .max(usize::from(!loc.is_empty()));
        let mut f = Finding::new(
            check_id,
            &format!("zap.{pid}"),
            Category::Security,
            zap_severity(risk),
            if name.is_empty() { "ZAP alert" } else { name }.to_string(),
            loc,
        )
        .detail(format!(
            "{} ({} instance(s))",
            strip_zap_html(xml_tag_text(block, "desc")),
            inst_count
        ))
        .remediation(strip_zap_html(xml_tag_text(block, "solution")));
        f.finalize();
        out.push(f);
    }
    Ok(out)
}
