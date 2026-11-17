use anyhow::Result;
use serde_json::Value;

use super::helpers::{lower, src_rel, sv};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Severity};
use crate::tools::{ToolSpec, gate, is_oversize, missing_image, read_out, tool_failed};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Reachable,
    Unreachable,
    Unknown,
}

impl Reach {
    fn label(self) -> &'static str {
        match self {
            Reach::Reachable => "reachable",
            Reach::Unreachable => "unreachable",
            Reach::Unknown => "unknown",
        }
    }
}

fn cvss_severity(score: &str) -> Option<Severity> {
    let n: f64 = score.trim().parse().ok()?;
    Some(if n >= 9.0 {
        Severity::Critical
    } else if n >= 7.0 {
        Severity::High
    } else if n >= 4.0 {
        Severity::Medium
    } else if n > 0.0 {
        Severity::Low
    } else {
        Severity::Info
    })
}

fn fixed_version(vulns: &[Value], ids: &[String], pkg: &str) -> Option<String> {
    for v in vulns
        .iter()
        .filter(|v| ids.iter().any(|i| i == sv(v, "id")))
    {
        for a in v.get("affected")?.as_array()? {
            if a.pointer("/package/name").and_then(|x| x.as_str()) != Some(pkg) {
                continue;
            }
            for r in a.get("ranges").and_then(|x| x.as_array())? {
                for e in r.get("events").and_then(|x| x.as_array())? {
                    if let Some(f) = e.get("fixed").and_then(|x| x.as_str()) {
                        return Some(f.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Parse `osv-scanner scan source --format json`. Reachability comes from the group's
/// `experimental_analysis` (call analysis): any analysed id called -> reachable, analysed and none
/// called -> unreachable (severity lowered one level), otherwise unknown (never lowered).
pub fn parse_osv(json: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(if json.trim().is_empty() { "{}" } else { json })?;
    let mut out = vec![];
    for res in v
        .get("results")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let path = src_rel(
            res.pointer("/source/path")
                .and_then(|x| x.as_str())
                .unwrap_or(""),
        );
        for p in res
            .get("packages")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let name = p
                .pointer("/package/name")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let version = p
                .pointer("/package/version")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let vulns = p
                .get("vulnerabilities")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            for g in p
                .get("groups")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let strs = |k: &str| -> Vec<String> {
                    g.get(k)
                        .and_then(|x| x.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let gids = strs("ids");
                let aliases = strs("aliases");
                let Some(first) = gids.first().cloned() else {
                    continue;
                };
                let canon = aliases
                    .iter()
                    .chain(gids.iter())
                    .find(|i| i.starts_with("CVE-"))
                    .cloned()
                    .unwrap_or(first);
                // Reachability.
                let analysis = g.get("experimental_analysis").and_then(|x| x.as_object());
                // A group lists several ids (GO-/GHSA-/CVE-) but call analysis only covers some.
                let called: Vec<bool> = gids
                    .iter()
                    .filter_map(|i| {
                        analysis
                            .and_then(|a| a.get(i))
                            .and_then(|e| e.get("called"))
                            .and_then(|c| c.as_bool())
                    })
                    .collect();
                let reach = if called.contains(&true) {
                    Reach::Reachable
                } else if !called.is_empty() {
                    Reach::Unreachable
                } else {
                    Reach::Unknown
                };
                // Severity: CVSS from the group, else the advisory's own rating, else Medium.
                let base = cvss_severity(sv(&g, "max_severity"))
                    .or_else(|| {
                        vulns
                            .iter()
                            .filter(|x| gids.iter().any(|i| i == sv(x, "id")))
                            .find_map(|x| {
                                let s = sv(x.get("database_specific")?, "severity");
                                (!s.is_empty()).then(|| Severity::parse(s))
                            })
                    })
                    .unwrap_or(Severity::Medium);
                let sev = if reach == Reach::Unreachable {
                    lower(base)
                } else {
                    base
                };
                let note = match reach {
                    Reach::Reachable => {
                        "Call analysis found a call path to the vulnerable code.".to_string()
                    }
                    Reach::Unreachable => format!(
                        "Call analysis found no call path to the vulnerable code; severity lowered {} -> {}.",
                        base.as_str(),
                        sev.as_str()
                    ),
                    Reach::Unknown => "No call analysis result (unsupported ecosystem, or the Go/Rust toolchain and modules were unavailable in the sandbox); severity not lowered.".to_string(),
                };
                let mut all_ids = gids.clone();
                for a in &aliases {
                    if !all_ids.contains(a) {
                        all_ids.push(a.clone());
                    }
                }
                let mut f = Finding::new(
                    "tool.osv_reachability",
                    &canon,
                    Category::SupplyChain,
                    sev,
                    format!("{canon} in {name} {version} ({})", reach.label()),
                    path.clone(),
                )
                .fp_key(format!("{path}|{name}|{canon}"))
                .package(name, version)
                .ids(all_ids)
                .detail(format!("Reachability: {}. {note}", reach.label()))
                .remediation(
                    "Upgrade to a fixed version; prioritise reachable findings.".to_string(),
                );
                f.fix_version = fixed_version(&vulns, &gids, name);
                out.push(f);
            }
        }
    }
    Ok(out)
}

pub(crate) fn osv_reachability(ctx: &Ctx) -> Result<CheckOutput> {
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    if let Some(o) = missing_image("osv-scanner") {
        return Ok(o);
    }
    if !ctx.docker.cache_dir.join("osv-scanner").is_dir() {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "osv vuln DB missing: run `readyhai tools update`".into(),
        )));
    }
    let mut spec = ToolSpec::new(
        "osv-scanner",
        &[
            "scan",
            "source",
            "--offline-vulnerabilities",
            "--call-analysis=go",
            "--format",
            "json",
            "--output-file",
            "/out/osv.json",
            "-r",
            "/src",
        ],
    );
    spec.timeout_secs = 600;
    spec.env = vec![
        (
            "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY".into(),
            "/cache/osv-scanner".into(),
        ),
        // govulncheck needs writable Go dirs; the rootfs is read-only and the network is off, so
        // only vendored/prefetched modules can be analysed (the rest stay `unknown`).
        ("GOPATH".into(), "/tmp/go".into()),
        ("GOCACHE".into(), "/tmp/gocache".into()),
        ("GOPROXY".into(), "off".into()),
    ];
    let r = ctx.docker.run(ctx, &spec)?;
    // 0 = clean, 1 = vulnerabilities found, 128 = nothing to scan.
    if r.exit_code == 128 {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no lockfiles or manifests found".into(),
        )));
    }
    if r.exit_code > 1 {
        return Err(tool_failed("osv-scanner", &r));
    }
    let txt = match read_out(ctx, "osv.json") {
        Ok(t) => t,
        // Output too big to read is Partial (via the engine), never "no findings".
        Err(e) if is_oversize(&e) => return Err(e),
        Err(_) if r.exit_code != 0 => return Err(tool_failed("osv-scanner", &r)),
        Err(_) => "{}".into(),
    };
    let mut findings = parse_osv(&txt)?;
    if let Some(snap) = &ctx.snapshot {
        enrich_osv_with_ast(&mut findings, &snap.root);
    }
    Ok(CheckOutput::findings(findings))
}

/// Annotate OSV findings whose call-graph reachability is `unknown` using Tree-sitter AST
/// import analysis across Python/JS/TS/Go/PHP source files. Severity is preserved (never lowered).
pub fn enrich_osv_with_ast(findings: &mut [Finding], root: &std::path::Path) {
    let has_unknown = findings
        .iter()
        .any(|f| f.package.is_some() && f.detail.starts_with("Reachability: unknown"));
    if !has_unknown {
        return;
    }
    let imported = crate::code_audit::called_packages(root);
    if imported.is_empty() {
        return;
    }
    for f in findings.iter_mut() {
        if !f.detail.starts_with("Reachability: unknown") {
            continue;
        }
        if let Some(pkg) = f.package.as_deref()
            && crate::code_audit::package_is_imported(&imported, pkg)
        {
            if !f.detail.ends_with('.') {
                f.detail.push('.');
            }
            f.detail
                .push_str(" AST import check: package is imported in source code.");
        }
    }
}
