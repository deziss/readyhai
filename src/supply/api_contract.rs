use anyhow::Result;
use regex::Regex;
use serde_json::Value;

use super::helpers::{src_rel, sv};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Severity};
use crate::tools::{
    ToolSpec, gate, is_oversize, missing_image, partial, read_out, tool_failed,
};

pub(crate) const MAX_SPECS: usize = 20;
pub(crate) const MAX_READ: u64 = 4 * 1024 * 1024;

pub(crate) fn read_snap(ctx: &Ctx, rel: &str, max: u64) -> Option<String> {
    let snap = ctx.snapshot.as_ref()?;
    if snap.denied.iter().any(|d| d.path == rel) {
        return None;
    }
    let p = snap.root.join(rel);
    if std::fs::metadata(&p).ok()?.len() > max {
        return None;
    }
    Some(String::from_utf8_lossy(&std::fs::read(p).ok()?).into_owned())
}

fn is_baseline_name(rel: &str) -> bool {
    let n = rel.rsplit('/').next().unwrap_or(rel);
    n.contains(".baseline.")
}

/// OpenAPI 3 / Swagger 2 documents in the snapshot (baseline copies excluded).
fn find_specs(ctx: &Ctx) -> Vec<String> {
    let Some(snap) = &ctx.snapshot else {
        return vec![];
    };
    let head = Regex::new(r#"(?m)^\s*["']?(?:openapi|swagger)["']?\s*:\s*["']?[23]\."#).unwrap();
    let mut v = vec![];
    for f in &snap.files {
        let l = f.to_ascii_lowercase();
        if !(l.ends_with(".yaml") || l.ends_with(".yml") || l.ends_with(".json"))
            || is_baseline_name(f)
        {
            continue;
        }
        // Cheap path filter first: spec files are named after what they are, or live in api dirs.
        let stem = l.rsplit('/').next().unwrap_or(&l);
        if !(stem.contains("openapi")
            || stem.contains("swagger")
            || stem.contains("api")
            || l.contains("/api/")
            || l.contains("/spec"))
        {
            continue;
        }
        let Some(t) = read_snap(ctx, f, MAX_READ) else {
            continue;
        };
        let t: String = t.chars().take(4096).collect();
        if head.is_match(&t) {
            v.push(f.clone());
            if v.len() >= MAX_SPECS {
                break;
            }
        }
    }
    v
}

fn baseline_for(ctx: &Ctx, spec: &str) -> Option<String> {
    let snap = ctx.snapshot.as_ref()?;
    let (stem, ext) = spec.rsplit_once('.')?;
    let ext_l = ext.to_ascii_lowercase();
    let mut cands = vec![format!("{stem}.baseline.{ext}")];
    for e in ["yaml", "yml", "json"] {
        if e != ext_l {
            cands.push(format!("{stem}.baseline.{e}"));
        }
    }
    cands.into_iter().find(|c| snap.files.contains(c))
}

/// Spectral JSON report: severity 0 error, 1 warn, 2 info, 3 hint.
pub fn parse_spectral(json: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(if json.trim().is_empty() { "[]" } else { json })?;
    let mut out = vec![];
    for r in v.as_array().cloned().unwrap_or_default() {
        let code = sv(&r, "code");
        let file = src_rel(sv(&r, "source"));
        let line = r
            .pointer("/range/start/line")
            .and_then(|x| x.as_u64())
            .unwrap_or(0)
            + 1;
        let jpath = r
            .get("path")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .map(|p| {
                        p.as_str()
                            .map(String::from)
                            .unwrap_or_else(|| p.to_string())
                    })
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .unwrap_or_default();
        let sev = match r.get("severity").and_then(|x| x.as_i64()).unwrap_or(1) {
            0 => Severity::Medium,
            1 => Severity::Low,
            _ => Severity::Info,
        };
        out.push(
            Finding::new(
                "tool.spectral",
                &format!("spectral.{code}"),
                Category::Quality,
                sev,
                sv(&r, "message").to_string(),
                format!("{file}:{line}"),
            )
            .fp_key(format!("{file}|{code}|{jpath}"))
            .detail(if jpath.is_empty() {
                String::new()
            } else {
                format!("OpenAPI path: /{jpath}")
            })
            .remediation("Fix the OpenAPI document or tune the ruleset."),
        );
    }
    Ok(out)
}

pub(crate) fn spectral(ctx: &Ctx) -> Result<CheckOutput> {
    if ctx.snapshot.is_none() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no repo snapshot".into(),
        )));
    }
    let specs = find_specs(ctx);
    if specs.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no OpenAPI spec in the repo".into(),
        )));
    }
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    if let Some(o) = missing_image("spectral") {
        return Ok(o);
    }
    std::fs::create_dir_all(ctx.out_dir())?;
    std::fs::write(
        ctx.out_dir().join("spectral-ruleset.yaml"),
        "extends: [\"spectral:oas\"]\n",
    )?;
    let mut args: Vec<String> = [
        "lint",
        "-r",
        "/out/spectral-ruleset.yaml",
        "-f",
        "json",
        "-o",
        "/out/spectral.json",
        "--ignore-unknown-format",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(specs.iter().map(|s| format!("/src/{s}")));
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let mut spec = ToolSpec::new("spectral", &refs);
    spec.timeout_secs = 300;
    spec.env = vec![
        ("SCARF_ANALYTICS".into(), "false".into()),
        ("DO_NOT_TRACK".into(), "1".into()),
    ];
    let r = ctx.docker.run(ctx, &spec)?;
    // Exit 1 = rule errors found (the findings); anything higher is a tool failure.
    if r.exit_code > 1 {
        return Err(tool_failed("spectral", &r));
    }
    let txt = match read_out(ctx, "spectral.json") {
        Ok(t) => t,
        Err(e) if is_oversize(&e) => return Err(e),
        Err(_) if r.exit_code != 0 => return Err(tool_failed("spectral", &r)),
        Err(_) => "[]".into(),
    };
    Ok(CheckOutput::findings(parse_spectral(&txt)?))
}

/// oasdiff `breaking -f json`: level 1 info, 2 warn, 3 error.
pub fn parse_oasdiff(json: &str, spec: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(if json.trim().is_empty() { "[]" } else { json })?;
    let mut out = vec![];
    for c in v.as_array().cloned().unwrap_or_default() {
        let id = sv(&c, "id");
        let op = sv(&c, "operation");
        let path = sv(&c, "path");
        let sev = match c.get("level").and_then(|x| x.as_i64()).unwrap_or(1) {
            3 => Severity::High,
            2 => Severity::Medium,
            _ => Severity::Low,
        };
        let loc = if op.is_empty() && path.is_empty() {
            spec.to_string()
        } else {
            format!("{spec} {op} {path}").trim().to_string()
        };
        out.push(
            Finding::new(
                "tool.oasdiff",
                &format!("oasdiff.{id}"),
                Category::Reliability,
                sev,
                sv(&c, "text").to_string(),
                loc.clone(),
            )
            .fp_key(format!("{spec}|{id}|{op} {path}|{}", sv(&c, "text")))
            .detail(format!(
                "Breaking change against the accepted baseline of {spec}."
            ))
            .remediation(
                "Restore compatibility, version the API, or accept the new spec as the baseline.",
            ),
        );
    }
    Ok(out)
}

pub(crate) fn oasdiff(ctx: &Ctx) -> Result<CheckOutput> {
    if ctx.snapshot.is_none() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no repo snapshot".into(),
        )));
    }
    let specs = find_specs(ctx);
    if specs.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no OpenAPI spec in the repo".into(),
        )));
    }
    let pairs: Vec<(String, String)> = specs
        .into_iter()
        .filter_map(|s| baseline_for(ctx, &s).map(|b| (s, b)))
        .collect();
    if pairs.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no accepted OpenAPI baseline (commit it as <spec>.baseline.yaml next to the spec)"
                .into(),
        )));
    }
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    if let Some(o) = missing_image("oasdiff") {
        return Ok(o);
    }
    let mut findings = vec![];
    let mut notes = vec![];
    for (spec_path, base) in pairs {
        let (b, c) = (format!("/src/{base}"), format!("/src/{spec_path}"));
        let mut spec = ToolSpec::new("oasdiff", &["breaking", &b, &c, "-f", "json"]);
        spec.timeout_secs = 120;
        let r = ctx.docker.run(ctx, &spec)?;
        if r.exit_code != 0 {
            notes.push(format!(
                "{spec_path}: {}",
                r.stderr_tail.trim().lines().next().unwrap_or("failed")
            ));
            continue;
        }
        findings.extend(parse_oasdiff(&r.stdout, &spec_path)?);
    }
    Ok(partial(notes, findings))
}
