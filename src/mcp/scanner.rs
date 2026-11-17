use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::engine::{self, ScanOpts};
use crate::model::{Finding, FindingStatus, Profile, Run, Severity};

use super::protocol::UNTRUSTED;

pub fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(n).collect::<String>())
    }
}

pub fn under_roots(p: &Path, roots: &[PathBuf]) -> bool {
    let p = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    roots
        .iter()
        .any(|r| r.canonicalize().map(|r| p.starts_with(r)).unwrap_or(false))
}

pub fn mcp_allowed_roots() -> Result<Vec<PathBuf>> {
    Ok(match std::env::var("READYHAI_ALLOWED_ROOTS") {
        Ok(v) if !v.trim().is_empty() => v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
        _ => vec![std::env::current_dir()?],
    })
}

/// Server-like restrictions shared by MCP and the REST API (`/runs` and `/api/scans`): path/apk
/// and spec files under allowed roots, every network destination (web URL, spec URL, ssh host,
/// git remote in any URL form) in the scope file. Cheap, no side effects.
pub fn precheck(opts: &ScanOpts) -> Result<()> {
    let t = engine::parse_target(&opts.target, opts.openapi.clone())?;
    for p in [t.path.as_ref(), t.apk.as_ref()].into_iter().flatten() {
        if !under_roots(p, &opts.allowed_roots) {
            bail!("path is outside READYHAI_ALLOWED_ROOTS");
        }
    }
    // `openapi` is a URL or a local file; a local file is copied into the run, so it is a read
    // primitive unless it is confined like every other path.
    let spec_is_url = t
        .openapi
        .as_deref()
        .is_some_and(|o| o.starts_with("http://") || o.starts_with("https://"));
    if let Some(o) = t.openapi.as_deref().filter(|_| !spec_is_url) {
        let p = std::path::Path::new(o);
        if p.canonicalize().is_err() || !under_roots(p, &opts.allowed_roots) {
            bail!("openapi spec must be an http(s) URL or a file under READYHAI_ALLOWED_ROOTS");
        }
    }
    let scope = match &opts.scope {
        Some(p) => Some(crate::scope::Scope::load(p)?),
        None => None,
    };
    // Every network destination the scan will touch must be in scope (SSRF guard).
    let mut web: Vec<&str> = vec![];
    if let Some(url) = &t.url {
        web.push(url);
    }
    if spec_is_url && let Some(o) = &t.openapi {
        web.push(o);
    }
    for u in web {
        crate::scope::egress_guard(u, scope.as_ref(), false)?;
    }
    if let Some(h) = &t.host {
        crate::scope::check_host(&h.host, scope.as_ref())?;
    }
    // Any remote repository, whatever its spelling: https://, git:<url>, ssh://, bare git@host:path.
    // Public code hosts (github/gitlab/...) are allowed by default; an internal git host must be
    // listed under [git] hosts in scope.toml.
    if t.kind == crate::model::TargetKind::Repo && t.path.is_none() {
        let host = engine::remote_repo_host(&t.raw)?;
        crate::scope::check_git_host(&host, scope.as_ref())?;
    }
    Ok(())
}

pub fn mcp_opts(args: &Value) -> Result<ScanOpts> {
    let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
    if target.is_empty() {
        bail!("target is required");
    }
    let profile: Profile = match args.get("profile").and_then(|v| v.as_str()) {
        None => Profile::Quick,
        Some(p) => serde_json::from_value(json!(p))
            .map_err(|_| anyhow::anyhow!("profile must be quick|standard|deep"))?,
    };
    if profile == Profile::Deep && std::env::var("READYHAI_MCP_ALLOW_DEEP").as_deref() != Ok("1") {
        bail!(
            "deep profile is refused over MCP (set READYHAI_MCP_ALLOW_DEEP=1 on the server to allow)"
        );
    }
    let allowed_roots = mcp_allowed_roots()?;
    let os = match args.get("os").and_then(|v| v.as_str()) {
        Some(o) => Some(
            serde_json::from_value(json!(o))
                .map_err(|_| anyhow::anyhow!("os must be linux|macos|windows"))?,
        ),
        None => None,
    };
    Ok(ScanOpts {
        target: target.to_string(),
        profile: Some(profile),
        openapi: args
            .get("openapi")
            .and_then(|v| v.as_str())
            .map(String::from),
        os,
        device: args
            .get("device")
            .and_then(|v| v.as_str())
            .map(String::from),
        no_tools: args
            .get("no_tools")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        scope: std::env::var("READYHAI_SCOPE").ok().map(PathBuf::from),
        plugins: std::env::var("READYHAI_PLUGINS").ok().map(PathBuf::from),
        server: true,
        allowed_roots,
        ..Default::default()
    })
}

pub fn tool_scan(args: &Value) -> Result<String> {
    let opts = mcp_opts(args)?;
    precheck(&opts)?;
    let id = engine::new_run_id();
    eprintln!("readyhai mcp: scanning {} (run {id})", opts.target);
    let run = engine::scan(&opts, &id)?;
    let rep = engine::run_dir(&id).join("report");
    crate::report::write(&run, &rep, &["html".into(), "json".into()])?;
    Ok(format!("{}\nreport: {}", summarize(&run), rep.display()))
}

pub fn summarize(run: &Run) -> String {
    let mut s = format!(
        "{UNTRUSTED}\n\nVerdict: {}\n",
        serde_json::to_value(run.verdict)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    );
    for r in &run.reasons {
        s += &format!("- {}\n", trunc(r, 300));
    }
    let count = |sev: Severity| {
        run.findings
            .iter()
            .filter(|f| f.severity == sev && f.status != FindingStatus::Suppressed)
            .count()
    };
    s += &format!(
        "Findings: critical {}, high {}, medium {}, low {}, info {}\n",
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        count(Severity::Info)
    );
    let bad: Vec<_> = run
        .checks
        .iter()
        .filter(|c| c.status.label() != "passed")
        .collect();
    if !bad.is_empty() {
        s += "Checks not passed:\n";
        for c in bad {
            s += &format!(
                "- {}: {}{}\n",
                c.id,
                c.status.label(),
                c.status
                    .reason()
                    .map(|r| format!(" ({})", trunc(r, 200)))
                    .unwrap_or_default()
            );
        }
    }
    let mut fs: Vec<&Finding> = run.findings.iter().collect();
    fs.sort_by(|a, b| b.severity.cmp(&a.severity));
    s += &format!(
        "Top findings (showing {} of {}):\n",
        fs.len().min(25),
        fs.len()
    );
    for f in fs.iter().take(25) {
        s += &format!(
            "- [{}] {} | {} | {} | {} | {}\n",
            f.severity.as_str(),
            f.rule,
            trunc(&f.title, 200),
            trunc(&f.location, 200),
            serde_json::to_value(f.status)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            f.fingerprint
        );
    }
    s += &format!("Run id: {}\n", run.id);
    s
}

pub fn tool_findings(args: &Value) -> Result<String> {
    let id = args.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let run = engine::load_run(id)?;
    let min = args
        .get("severity_min")
        .and_then(|v| v.as_str())
        .map(Severity::parse);
    let status: Option<FindingStatus> = match args.get("status").and_then(|v| v.as_str()) {
        Some(s) => Some(
            serde_json::from_value(json!(s))
                .map_err(|_| anyhow::anyhow!("status must be new|existing|suppressed"))?,
        ),
        None => None,
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .min(500) as usize;
    let out: Vec<Value> = run
        .findings
        .iter()
        .filter(|f| min.is_none_or(|m| f.severity >= m) && status.is_none_or(|s| f.status == s))
        .take(limit)
        .map(|f| {
            let mut v = serde_json::to_value(f).unwrap_or(Value::Null);
            if let Some(d) = v.get("detail").and_then(|d| d.as_str()) {
                v["detail"] = json!(trunc(d, 500));
            }
            v
        })
        .collect();
    Ok(format!(
        "{UNTRUSTED}\n{}",
        serde_json::to_string_pretty(&out)?
    ))
}
