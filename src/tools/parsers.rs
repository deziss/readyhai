use super::docker::{scrub_keys, walk_mut};
use crate::model::{Category, Finding, Severity, sha256_hex};
use anyhow::{Result, anyhow};
use serde_json::Value;

#[allow(unused_imports)]
pub use super::sarif_junit::{parse_junit, parse_sarif};

pub(crate) fn rel(p: &str) -> String {
    let p = p.trim_start_matches("file://");
    let p = p.strip_prefix("/src/").unwrap_or(p);
    p.trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

pub(crate) fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

pub(crate) fn first_line(t: &str, max: usize) -> String {
    t.lines().next().unwrap_or("").chars().take(max).collect()
}

pub fn scrub_gitleaks(json: &str) -> Option<String> {
    scrub_keys(json, &["Match", "Secret", "Line", "Fragment"])
}

pub fn scrub_semgrep(json: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(json).ok()?;
    walk_mut(&mut v, &mut |m| {
        if let Some(Value::Object(extra)) = m.get_mut("extra") {
            for k in ["lines", "fix", "fix_regex"] {
                if extra.contains_key(k) {
                    extra.insert(k.into(), Value::String(String::new()));
                }
            }
            if extra.contains_key("dataflow_trace") {
                extra.insert("dataflow_trace".into(), Value::Null);
            }
        }
    });
    serde_json::to_string(&v).ok()
}

pub fn scrub_checkov(json: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(json).ok()?;
    walk_mut(&mut v, &mut |m| {
        if m.contains_key("code_block") {
            m.insert("code_block".into(), Value::Array(vec![]));
        }
        m.remove("check_result");
        m.remove("entity_tags");
    });
    serde_json::to_string(&v).ok()
}

// ---------------------------------------------------------------- parsers

pub fn parse_gitleaks(json: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(if json.trim().is_empty() { "[]" } else { json })?;
    let mut out = vec![];
    for r in v.as_array().cloned().unwrap_or_default() {
        let rule = s(&r, "RuleID");
        let file = rel(s(&r, "File"));
        let line = r.get("StartLine").and_then(|x| x.as_u64()).unwrap_or(0);
        let desc = s(&r, "Description");
        let mut f = Finding::new(
            "tool.gitleaks",
            &format!("secrets.{rule}"),
            Category::Security,
            Severity::High,
            if desc.is_empty() {
                format!("Possible secret ({rule})")
            } else {
                desc.to_string()
            },
            format!("{file}:{line}"),
        )
        .fp_key(format!("{file}|{rule}"))
        .remediation("Rotate the credential, remove it from the repository and its history, and load it from a secret store at runtime.");
        f.detail = "Secret value intentionally not recorded.".into();
        out.push(f);
    }
    Ok(out)
}

fn canonical_id(id: &str, related: &[String]) -> String {
    if id.starts_with("CVE-") {
        return id.to_string();
    }
    related
        .iter()
        .find(|r| r.starts_with("CVE-"))
        .cloned()
        .unwrap_or_else(|| id.to_string())
}

pub fn parse_grype(json: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(json)?;
    let mut out = vec![];
    for m in v
        .get("matches")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let vuln = m.get("vulnerability").cloned().unwrap_or(Value::Null);
        let art = m.get("artifact").cloned().unwrap_or(Value::Null);
        let id = s(&vuln, "id").to_string();
        let related: Vec<String> = m
            .get("relatedVulnerabilities")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .map(|r| s(r, "id").to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let mut ids = vec![id.clone()];
        for r in &related {
            if !ids.contains(r) {
                ids.push(r.clone());
            }
        }
        let name = s(&art, "name");
        let version = s(&art, "version");
        let path = art
            .get("locations")
            .and_then(|l| l.as_array())
            .and_then(|l| l.first())
            .map(|l| rel(s(l, "path")))
            .unwrap_or_default();
        let kev = vuln
            .get("knownExploited")
            .and_then(|x| x.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        let epss = vuln
            .get("epss")
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
            .and_then(|e| e.get("epss"))
            .and_then(|x| x.as_f64());
        let fixes: Vec<String> = vuln
            .get("fix")
            .and_then(|f| f.get("versions"))
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let sev = Severity::parse(match s(&vuln, "severity") {
            "Negligible" | "Unknown" | "" => "info",
            x => x,
        });
        let loc = if path.is_empty() {
            name.to_string()
        } else {
            path.clone()
        };
        let mut f = Finding::new(
            "tool.sbom_cve",
            &id,
            if kev {
                Category::Security
            } else {
                Category::SupplyChain
            },
            sev,
            format!("{id} in {name} {version}"),
            loc,
        )
        .ids(ids)
        .package(name, version)
        .fp_key(format!("{}|{}|{}", canonical_id(&id, &related), name, path));
        if !fixes.is_empty() {
            f.fix_version = Some(fixes.join(", "));
            f.remediation = format!("Upgrade {name} to {}.", fixes.join(" or "));
        }
        f.epss = epss;
        f.kev = kev;
        out.push(f);
    }
    Ok(out)
}

fn trace_loc_label(loc: &Value) -> Option<String> {
    let p = rel(loc.get("path")?.as_str()?);
    let line = loc.get("start")?.get("line")?.as_u64()?;
    Some(format!("{p}:{line}"))
}

fn format_dataflow_trace(extra: &Value) -> Option<String> {
    let trace = extra.get("dataflow_trace")?;
    if !trace.is_object() {
        return None;
    }
    let mut hops: Vec<String> = Vec::new();
    if let Some(arr) = trace.get("taint_source").and_then(|x| x.as_array())
        && let Some(loc_info) = arr
            .get(1)
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
        && let Some(lbl) = trace_loc_label(loc_info)
    {
        hops.push(lbl);
    }
    for v in trace
        .get("intermediate_vars")
        .and_then(|x| x.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(lbl) = v.get("location").and_then(trace_loc_label)
            && hops.last() != Some(&lbl)
        {
            hops.push(lbl);
        }
    }
    if let Some(arr) = trace.get("taint_sink").and_then(|x| x.as_array())
        && let Some(loc_info) = arr
            .get(1)
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
        && let Some(lbl) = trace_loc_label(loc_info)
        && hops.last() != Some(&lbl)
    {
        hops.push(lbl);
    }
    (!hops.is_empty()).then(|| format!("taint flow: {}", hops.join(" -> ")))
}

pub(crate) fn parse_grep_findings(json: &str, check_id: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(json)?;
    let mut out = vec![];
    for r in v
        .get("results")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let extra = r.get("extra").cloned().unwrap_or(Value::Null);
        let path = rel(s(&r, "path"));
        let line = r
            .get("start")
            .and_then(|x| x.get("line"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let sev = match s(&extra, "severity") {
            "ERROR" => Severity::High,
            "WARNING" => Severity::Medium,
            _ => Severity::Low,
        };
        let h = sha256_hex(s(&extra, "lines").trim().as_bytes());
        // scanners prefix rule ids with the rules-file path (`cache.semgrep.<id>`, `cache.opengrep.<id>`)
        let raw_rule = s(&r, "check_id");
        let rule = raw_rule
            .strip_prefix("cache.opengrep.")
            .or_else(|| raw_rule.strip_prefix("cache.semgrep."))
            .unwrap_or(raw_rule);
        let mut f = Finding::new(
            check_id,
            rule,
            Category::Security,
            sev,
            first_line(s(&extra, "message"), 200),
            format!("{path}:{line}"),
        )
        .fp_key(format!("{path}|{}", &h[..16]));
        if let Some(flow) = format_dataflow_trace(&extra) {
            f = f.detail(flow);
        }
        out.push(f);
    }
    Ok(out)
}

#[cfg(test)]
pub fn parse_semgrep(json: &str) -> Result<Vec<Finding>> {
    parse_grep_findings(json, "tool.semgrep")
}

/// Parse Opengrep JSON output (including optional intra-file taint traces) into `tool.opengrep`.
#[cfg(test)]
pub fn parse_opengrep(json: &str) -> Result<Vec<Finding>> {
    parse_grep_findings(json, "tool.opengrep")
}

pub fn parse_hadolint(json: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(if json.trim().is_empty() { "[]" } else { json })?;
    let mut out = vec![];
    for r in v.as_array().cloned().unwrap_or_default() {
        let code = s(&r, "code");
        let file = rel(s(&r, "file"));
        let line = r.get("line").and_then(|x| x.as_u64()).unwrap_or(0);
        let msg = s(&r, "message");
        let sev = match s(&r, "level") {
            "error" => Severity::High,
            "warning" => Severity::Medium,
            _ => Severity::Low,
        };
        let cat = if matches!(code, "DL3002" | "DL3004" | "DL3020") {
            Category::Security
        } else {
            Category::Quality
        };
        out.push(
            Finding::new(
                "tool.hadolint",
                code,
                cat,
                sev,
                msg,
                format!("{file}:{line}"),
            )
            .fp_key(format!(
                "{file}|{code}|{}",
                &sha256_hex(msg.as_bytes())[..8]
            )),
        );
    }
    Ok(out)
}

pub fn parse_checkov(json: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(json)?;
    let reports: Vec<Value> = match v {
        Value::Array(a) => a,
        o => vec![o],
    };
    let mut out = vec![];
    for rep in reports {
        let failed = rep
            .get("results")
            .and_then(|r| r.get("failed_checks"))
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        for c in failed {
            let id = s(&c, "check_id");
            let file = rel(s(&c, "file_path"));
            let line = c
                .get("file_line_range")
                .and_then(|x| x.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            let sev = match c.get("severity").and_then(|x| x.as_str()) {
                Some(x) => Severity::parse(x),
                None => Severity::Medium,
            };
            let res = s(&c, "resource");
            let mut f = Finding::new(
                "tool.checkov",
                id,
                Category::Security,
                sev,
                s(&c, "check_name"),
                format!("{file}:{line}"),
            )
            .fp_key(format!("{file}|{res}|{id}"));
            f.remediation = s(&c, "guideline").to_string();
            out.push(f);
        }
    }
    Ok(out)
}

pub fn parse_dockle(json: &str, image: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(json)?;
    let mut out = vec![];
    for d in v
        .get("details")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let sev = match s(&d, "level") {
            "FATAL" => Severity::High,
            "WARN" => Severity::Medium,
            "INFO" => Severity::Low,
            _ => continue,
        };
        let code = s(&d, "code");
        let alerts: Vec<&str> = d
            .get("alerts")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        out.push(
            Finding::new(
                "tool.dockle",
                code,
                Category::Security,
                sev,
                s(&d, "title"),
                image,
            )
            .detail(alerts.join("; "))
            .fp_key(code),
        );
    }
    Ok(out)
}

pub fn parse_image_inspect(json: &str, image: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(json)?;
    let i = v
        .get(0)
        .cloned()
        .ok_or_else(|| anyhow!("empty docker image inspect"))?;
    let cfg = i.get("Config").cloned().unwrap_or(Value::Null);
    let mut out = vec![];
    let user = s(&cfg, "User").trim();
    let uname = user.split(':').next().unwrap_or("");
    if uname.is_empty() || uname == "root" || uname == "0" {
        out.push(
            Finding::new(
                "image.inspect",
                "image.root_user",
                Category::Security,
                Severity::High,
                "Image runs as root",
                image,
            )
            .remediation("Add a non-root USER to the Dockerfile."),
        );
    }
    let hc = cfg.get("Healthcheck");
    let has_hc = hc
        .and_then(|h| h.get("Test"))
        .and_then(|t| t.as_array())
        .map(|t| !t.is_empty() && t.first().and_then(|x| x.as_str()) != Some("NONE"))
        .unwrap_or(false);
    if !has_hc {
        out.push(
            Finding::new(
                "image.inspect",
                "image.no_healthcheck",
                Category::Reliability,
                Severity::Medium,
                "Image defines no HEALTHCHECK",
                image,
            )
            .remediation("Add a HEALTHCHECK instruction or rely on orchestrator probes."),
        );
    }
    if i.get("Size").and_then(|x| x.as_u64()).unwrap_or(0) > 1_000_000_000 {
        out.push(Finding::new(
            "image.inspect",
            "image.large",
            Category::Performance,
            Severity::Low,
            "Image is larger than 1 GB",
            image,
        ));
    }
    let last = image.rsplit('/').next().unwrap_or(image);
    let untagged_or_latest =
        !image.contains("@sha256:") && (!last.contains(':') || last.ends_with(":latest"));
    if untagged_or_latest {
        out.push(
            Finding::new(
                "image.inspect",
                "image.latest_tag",
                Category::SupplyChain,
                Severity::Low,
                "Image uses the mutable :latest tag",
                image,
            )
            .remediation("Reference an immutable version tag or digest."),
        );
    }
    Ok(out)
}
