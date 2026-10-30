//! Supply-chain and API-contract checks: OSV reachability, OpenSSF Scorecard, Spectral, oasdiff,
//! and mutation-score reading (no mutation run: reports and configs only).
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};
use crate::tools::{ToolSpec, gate, missing_image, partial, read_out, tool_failed};
use anyhow::Result;
use regex::Regex;
use serde_json::Value;

const MAX_SPECS: usize = 20;
const MAX_READ: u64 = 4 * 1024 * 1024;
/// Mutation score below this (percent) is a finding.
const MIN_MUTATION_SCORE: f64 = 60.0;

fn repo() -> Vec<TargetKind> {
    vec![TargetKind::Repo]
}

pub fn checks() -> Vec<Check> {
    vec![
        Check::new(
            "tool.osv_reachability",
            "Known vulnerabilities with reachability (OSV-Scanner call analysis)",
            &repo(),
            Profile::Standard,
            osv_reachability,
        )
        .tool("osv-scanner"),
        Check::new(
            "tool.scorecard",
            "OpenSSF Scorecard (GitHub remote)",
            &repo(),
            Profile::Standard,
            scorecard,
        )
        .tool("scorecard"),
        Check::new(
            "tool.spectral",
            "OpenAPI lint (Spectral, oas ruleset)",
            &repo(),
            Profile::Quick,
            spectral,
        )
        .tool("spectral"),
        Check::new(
            "tool.oasdiff",
            "OpenAPI breaking changes vs accepted baseline (oasdiff)",
            &repo(),
            Profile::Quick,
            oasdiff,
        )
        .tool("oasdiff"),
        Check::new(
            "qa.suite.mutation",
            "Mutation score from existing reports",
            &repo(),
            Profile::Quick,
            mutation,
        )
        .qa(),
    ]
}

fn sv<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

fn src_rel(p: &str) -> String {
    let p = p.trim_start_matches("file://");
    let p = p.strip_prefix("/src/").unwrap_or(p);
    p.trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn lower(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

// ================================================================= 1. OSV reachability

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

fn osv_reachability(ctx: &Ctx) -> Result<CheckOutput> {
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
        Err(_) if r.exit_code != 0 => return Err(tool_failed("osv-scanner", &r)),
        Err(_) => "{}".into(),
    };
    Ok(CheckOutput::findings(parse_osv(&txt)?))
}

// ================================================================= 2. OpenSSF Scorecard

/// `github.com/owner/repo` from a git remote URL (credentials dropped), only for github.com.
pub fn github_slug(url: &str) -> Option<String> {
    let u = url.trim();
    let rest = if let Some(r) = u.strip_prefix("git@github.com:") {
        r.to_string()
    } else {
        let r = u
            .strip_prefix("https://")
            .or_else(|| u.strip_prefix("http://"))
            .or_else(|| u.strip_prefix("ssh://"))
            .or_else(|| u.strip_prefix("git://"))?;
        let r = r.rsplit_once('@').map(|(_, h)| h).unwrap_or(r);
        r.strip_prefix("github.com/")
            .or_else(|| r.strip_prefix("github.com:"))?
            .to_string()
    };
    let rest = rest.trim_end_matches('/').trim_end_matches(".git");
    let mut it = rest.split('/');
    let (o, n) = (it.next()?, it.next()?);
    if it.next().is_some() || o.is_empty() || n.is_empty() {
        return None;
    }
    let ok = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    (ok(o) && ok(n)).then(|| format!("github.com/{o}/{n}"))
}

/// Origin (or first) remote URL from the text of a `.git/config`.
pub fn remote_url(config: &str) -> Option<String> {
    let mut cur = String::new();
    let mut first: Option<String> = None;
    for l in config.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            cur = l.to_string();
        } else if cur.starts_with("[remote ")
            && let Some(u) = l.strip_prefix("url")
            && let Some(u) = u.trim_start().strip_prefix('=')
        {
            let u = u.trim().to_string();
            if cur == "[remote \"origin\"]" {
                return Some(u);
            }
            first.get_or_insert(u);
        }
    }
    first
}

fn scorecard_risk(check: &str) -> Severity {
    // Scorecard's own risk levels, one notch down: a posture gap is not an exploitable bug.
    match check {
        "Dangerous-Workflow" | "Webhooks" => Severity::High,
        "Binary-Artifacts"
        | "Branch-Protection"
        | "Code-Review"
        | "Dependency-Update-Tool"
        | "Maintained"
        | "Signed-Releases"
        | "Token-Permissions"
        | "Vulnerabilities" => Severity::Medium,
        "Fuzzing" | "Pinned-Dependencies" | "Packaging" | "SAST" | "Security-Policy" | "SBOM" => {
            Severity::Low
        }
        _ => Severity::Info,
    }
}

/// Scorecard JSON: one finding per check scoring 0..4 (-1 = inconclusive, ignored).
pub fn parse_scorecard(json: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(json)?;
    let repo = v
        .pointer("/repo/name")
        .and_then(|x| x.as_str())
        .unwrap_or("repo")
        .to_string();
    let mut out = vec![];
    for c in v
        .get("checks")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let name = sv(&c, "name");
        let score = c.get("score").and_then(|x| x.as_i64()).unwrap_or(-1);
        if !(0..5).contains(&score) {
            continue;
        }
        let mut detail = format!("Score {score}/10: {}", sv(&c, "reason"));
        for d in c
            .get("details")
            .and_then(|x| x.as_array())
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
            .take(10)
        {
            detail.push_str("\n- ");
            detail.push_str(d);
        }
        let url = c
            .pointer("/documentation/url")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        out.push(
            Finding::new(
                "tool.scorecard",
                &format!("scorecard.{}", name.to_ascii_lowercase().replace('-', "_")),
                Category::SupplyChain,
                scorecard_risk(name),
                format!("OpenSSF Scorecard: {name} scored {score}/10"),
                repo.clone(),
            )
            .fp_key(format!("{repo}|{name}"))
            .detail(detail)
            .remediation(format!("See {url}")),
        );
    }
    Ok(out)
}

fn scorecard(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(dir) = ctx.target.path.as_ref() else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no repo path".into(),
        )));
    };
    let slug = std::fs::read_to_string(dir.join(".git").join("config"))
        .ok()
        .as_deref()
        .and_then(remote_url)
        .as_deref()
        .and_then(github_slug);
    let Some(slug) = slug else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no github.com git remote".into(),
        )));
    };
    let token = std::env::var("READYHAI_GITHUB_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty());
    let Some(token) = token else {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "READYHAI_GITHUB_TOKEN not set (Scorecard needs the GitHub API)".into(),
        )));
    };
    if crate::bundle::offline() {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "network required (READYHAI_OFFLINE)".into(),
        )));
    }
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    if let Some(o) = missing_image("scorecard") {
        return Ok(o);
    }
    let repo_arg = format!("--repo={slug}");
    let mut spec = ToolSpec::new(
        "scorecard",
        &[
            repo_arg.as_str(),
            "--format=json",
            "--show-details",
            "--output=/out/scorecard.json",
        ],
    );
    spec.network = true;
    spec.timeout_secs = 600;
    spec.env = vec![("GITHUB_AUTH_TOKEN".into(), token)];
    let r = ctx.docker.run(ctx, &spec)?;
    // Scorecard exits non-zero when any single check errors but still writes the rest.
    let txt = match read_out(ctx, "scorecard.json") {
        Ok(t) => t,
        Err(_) => return Err(tool_failed("scorecard", &r)),
    };
    Ok(CheckOutput::findings(parse_scorecard(&txt)?))
}

// ================================================================= 3. OpenAPI specs

fn read_snap(ctx: &Ctx, rel: &str, max: u64) -> Option<String> {
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

fn spectral(ctx: &Ctx) -> Result<CheckOutput> {
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

fn oasdiff(ctx: &Ctx) -> Result<CheckOutput> {
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

// ================================================================= 4. mutation score

#[derive(Debug, Clone, PartialEq)]
pub struct MutationScore {
    pub tool: &'static str,
    pub detected: u64,
    /// Detected + survived (compile/unviable/ignored mutants excluded).
    pub total: u64,
}

impl MutationScore {
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.detected as f64 * 100.0 / self.total as f64
        }
    }
}

/// cargo-mutants `mutants.out/outcomes.json`.
pub fn parse_cargo_mutants(json: &str) -> Option<MutationScore> {
    let v: Value = serde_json::from_str(json).ok()?;
    let (mut caught, mut missed, mut timeout) = (0u64, 0u64, 0u64);
    if let Some(a) = v.get("outcomes").and_then(|x| x.as_array()) {
        for o in a {
            if o.get("scenario").and_then(|s| s.as_str()) == Some("Baseline") {
                continue;
            }
            match sv(o, "summary") {
                "CaughtMutant" => caught += 1,
                "MissedMutant" => missed += 1,
                "Timeout" => timeout += 1,
                _ => {}
            }
        }
    } else {
        let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        caught = n("caught");
        missed = n("missed");
        timeout = n("timeout");
    }
    Some(MutationScore {
        tool: "cargo-mutants",
        detected: caught + timeout,
        total: caught + timeout + missed,
    })
}

/// Stryker `reports/mutation/mutation.json` (mutation-testing-elements schema).
pub fn parse_stryker(json: &str) -> Option<MutationScore> {
    let v: Value = serde_json::from_str(json).ok()?;
    let files = v.get("files")?.as_object()?;
    let (mut det, mut surv) = (0u64, 0u64);
    for f in files.values() {
        for m in f.get("mutants")?.as_array()? {
            match sv(m, "status") {
                "Killed" | "Timeout" => det += 1,
                "Survived" | "NoCoverage" => surv += 1,
                _ => {}
            }
        }
    }
    Some(MutationScore {
        tool: "stryker",
        detected: det,
        total: det + surv,
    })
}

/// mutmut 3 `mutants/**/*.meta`: `exit_code_by_key` (0 = survived, null = not checked).
pub fn parse_mutmut_meta(json: &str) -> Option<MutationScore> {
    let v: Value = serde_json::from_str(json).ok()?;
    let m = v.get("exit_code_by_key")?.as_object()?;
    let (mut det, mut surv) = (0u64, 0u64);
    for c in m.values() {
        match c.as_i64() {
            Some(0) => surv += 1,
            Some(1 | 3 | 36 | -24) => det += 1,
            _ => {}
        }
    }
    Some(MutationScore {
        tool: "mutmut",
        detected: det,
        total: det + surv,
    })
}

fn mutation(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no repo snapshot".into(),
        )));
    };
    let ends = |f: &str, s: &str| f == s || f.ends_with(&format!("/{s}"));
    let mut reports: Vec<(String, MutationScore)> = vec![];
    let mut mutmut_meta: Option<(String, u64, u64)> = None;
    let mut v2_cache = false;
    let mut configured: Vec<&str> = vec![];
    for f in &snap.files {
        let leaf = f.rsplit('/').next().unwrap_or(f);
        let parsed = if ends(f, "mutants.out/outcomes.json") {
            read_snap(ctx, f, 64 * 1024 * 1024).and_then(|t| parse_cargo_mutants(&t))
        } else if ends(f, "reports/mutation/mutation.json") {
            read_snap(ctx, f, 64 * 1024 * 1024).and_then(|t| parse_stryker(&t))
        } else {
            None
        };
        if let Some(p) = parsed {
            reports.push((f.clone(), p));
        } else if leaf.ends_with(".meta") && f.split('/').any(|p| p == "mutants") {
            if let Some(p) = read_snap(ctx, f, MAX_READ).and_then(|t| parse_mutmut_meta(&t)) {
                let e = mutmut_meta.get_or_insert((f.clone(), 0, 0));
                e.1 += p.detected;
                e.2 += p.total;
            }
        } else if leaf == ".mutmut-cache" {
            v2_cache = true;
        } else if (ends(f, ".cargo/mutants.toml") || leaf == "mutants.toml")
            && !configured.contains(&"cargo-mutants")
        {
            configured.push("cargo-mutants");
        } else if leaf.starts_with("stryker.conf") || leaf.starts_with(".stryker.conf") {
            configured.push("Stryker");
        }
    }
    if let Some((f, det, total)) = mutmut_meta {
        reports.push((
            f.rsplit_once('/')
                .map(|x| x.0)
                .unwrap_or("mutants")
                .to_string(),
            MutationScore {
                tool: "mutmut",
                detected: det,
                total,
            },
        ));
    }
    if reports.is_empty() {
        let hint = if v2_cache {
            "mutmut v2 cache (.mutmut-cache) is SQLite; upgrade to mutmut 3 or run it in CI and keep mutants/"
        } else if !configured.is_empty() {
            "mutation config found but no report; run it in CI and keep the report (cargo mutants -> mutants.out/outcomes.json, stryker -> reports/mutation/mutation.json)"
        } else {
            "no mutation testing set up; try `cargo mutants`, Stryker or mutmut and keep the report"
        };
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(hint.into())));
    }
    let mut findings = vec![];
    let mut scored = 0;
    for (path, s) in &reports {
        if s.total == 0 {
            continue;
        }
        scored += 1;
        let pct = s.percent();
        if pct < MIN_MUTATION_SCORE {
            findings.push(
                Finding::new(
                    "qa.suite.mutation",
                    "qa.suite.low_mutation_score",
                    Category::Quality,
                    Severity::Medium,
                    format!(
                        "Mutation score is {pct:.0}% (below {MIN_MUTATION_SCORE:.0}%) [{}]",
                        s.tool
                    ),
                    path.clone(),
                )
                .fp_key(format!("{}|{path}", s.tool))
                .detail(format!(
                    "{} of {} viable mutants were detected by the tests ({}).",
                    s.detected, s.total, s.tool
                ))
                .remediation("Add assertions for the surviving mutants; review the report's survivors first."),
            );
        }
    }
    if scored == 0 {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "mutation report holds no scored mutants".into(),
        )));
    }
    Ok(CheckOutput::findings(findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real outputs captured 2026-10-30: osv-scanner v2.7.0 (Go module, golang.org/x/text 0.3.7),
    // scorecard v5.6.0 (--local), spectral 6.17.0, oasdiff (breaking, json).
    const OSV: &str = include_str!("../tests/fixtures/tool-outputs/osv-scanner.json");
    const OSV_NOCALL: &str = include_str!("../tests/fixtures/tool-outputs/osv-scanner-nocall.json");
    const SCORECARD: &str = include_str!("../tests/fixtures/tool-outputs/scorecard.json");
    const SPECTRAL: &str = include_str!("../tests/fixtures/tool-outputs/spectral.json");
    const OASDIFF: &str = include_str!("../tests/fixtures/tool-outputs/oasdiff.json");
    // Format-faithful, hand-built (the real tools were not runnable here).
    const CARGO_MUTANTS: &str =
        include_str!("../tests/fixtures/tool-outputs/mutation-cargo-mutants.json");
    const STRYKER: &str = include_str!("../tests/fixtures/tool-outputs/mutation-stryker.json");

    fn fin(mut v: Vec<Finding>) -> Vec<Finding> {
        v.iter_mut().for_each(|f| f.finalize());
        v
    }

    #[test]
    fn osv_unreachable_lowers_one_level() {
        let f = fin(parse_osv(OSV).unwrap());
        assert_eq!(f.len(), 3);
        let a = f.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
        // CVSS 7.5 = High, lowered to Medium because call analysis found it uncalled.
        assert_eq!(a.severity, Severity::Medium);
        assert!(a.title.contains("(unreachable)"), "{}", a.title);
        assert!(a.detail.contains("lowered high -> medium"), "{}", a.detail);
        assert_eq!(a.package.as_deref(), Some("golang.org/x/text"));
        assert_eq!(a.fix_version.as_deref(), Some("0.3.8"));
        assert_eq!(a.location, "go.mod");
        assert!(a.ids.contains(&"GO-2022-1059".to_string()));
        assert_eq!(a.category, Category::SupplyChain);
        let g = fin(parse_osv(&OSV.replace("0.3.7", "0.3.6")).unwrap());
        let b = g.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn osv_unknown_never_lowers_and_reachable_keeps() {
        let u = fin(parse_osv(OSV_NOCALL).unwrap());
        let a = u.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
        assert_eq!(a.severity, Severity::High);
        assert!(a.title.contains("(unknown)"));
        // Ungraded groups (empty max_severity) fall back to Medium or the advisory rating.
        assert!(u.iter().all(|x| x.detail.contains("Reachability: unknown")));
        // Flip the first group to called=true: reachable, full severity.
        let r = OSV.replacen("\"called\": false", "\"called\": true", 1);
        let f = fin(parse_osv(&r).unwrap());
        let a = f.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
        assert_eq!(a.severity, Severity::High);
        assert!(a.title.contains("(reachable)"));
    }

    #[test]
    fn osv_any_called_is_reachable_and_empty_is_unknown() {
        let mut v: Value = serde_json::from_str(OSV).unwrap();
        v["results"][0]["packages"][0]["groups"][0]["experimental_analysis"] = serde_json::json!({
            "GO-2022-1059": {"called": false},
            "GHSA-69ch-w2m2-3vjp": {"called": true}
        });
        let f = parse_osv(&v.to_string()).unwrap();
        let a = f.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
        assert!(a.title.contains("(reachable)"));
        assert_eq!(a.severity, Severity::High);
        v["results"][0]["packages"][0]["groups"][0]["experimental_analysis"] =
            serde_json::json!({});
        let f = parse_osv(&v.to_string()).unwrap();
        let a = f.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
        assert!(a.title.contains("(unknown)"));
        assert!(parse_osv("").unwrap().is_empty());
    }

    #[test]
    fn scorecard_golden() {
        let f = fin(parse_scorecard(SCORECARD).unwrap());
        let rules: Vec<_> = f.iter().map(|x| x.rule.as_str()).collect();
        assert!(rules.contains(&"scorecard.token_permissions"), "{rules:?}");
        assert!(rules.contains(&"scorecard.pinned_dependencies"));
        // scores >= 5 and -1 (inconclusive) never produce findings
        assert!(!rules.contains(&"scorecard.binary_artifacts"));
        assert!(!rules.contains(&"scorecard.fuzzing"));
        let t = f
            .iter()
            .find(|x| x.rule == "scorecard.token_permissions")
            .unwrap();
        assert_eq!(t.severity, Severity::Medium);
        assert_eq!(t.category, Category::SupplyChain);
        assert!(t.title.contains("0/10"));
    }

    #[test]
    fn github_remote_parsing() {
        let ok = Some("github.com/o/r".to_string());
        assert_eq!(github_slug("https://github.com/o/r.git"), ok);
        assert_eq!(github_slug("git@github.com:o/r.git"), ok);
        assert_eq!(github_slug("https://tok:x@github.com/o/r"), ok);
        assert_eq!(github_slug("ssh://git@github.com/o/r.git"), ok);
        assert_eq!(github_slug("https://gitlab.com/o/r.git"), None);
        assert_eq!(github_slug("https://github.com/o/r/extra"), None);
        assert_eq!(github_slug("https://github.com.evil.io/o/r"), None);
        let cfg = "[core]\n\tbare = false\n[remote \"fork\"]\n\turl = https://github.com/a/b\n[remote \"origin\"]\n\turl = git@github.com:o/r.git\n";
        assert_eq!(remote_url(cfg).as_deref(), Some("git@github.com:o/r.git"));
        assert_eq!(remote_url("[core]\n"), None);
    }

    #[test]
    fn spectral_golden() {
        let f = fin(parse_spectral(SPECTRAL).unwrap());
        assert_eq!(f.len(), 8);
        let e = f.iter().find(|x| x.rule == "spectral.path-params").unwrap();
        assert_eq!(e.severity, Severity::Medium);
        assert_eq!(e.location, "openapi.yaml:13");
        assert!(e.detail.contains("/paths//pets/{id}/get"));
        let w = f
            .iter()
            .find(|x| x.rule == "spectral.info-contact")
            .unwrap();
        assert_eq!(w.severity, Severity::Low);
        assert_eq!(w.category, Category::Quality);
        assert!(parse_spectral("").unwrap().is_empty());
    }

    #[test]
    fn oasdiff_golden() {
        let f = fin(parse_oasdiff(OASDIFF, "api/openapi.yaml").unwrap());
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].rule, "oasdiff.request-parameter-became-required");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].location, "api/openapi.yaml GET /pets");
        assert_eq!(f[1].rule, "oasdiff.api-path-removed-without-deprecation");
        assert_eq!(f[0].category, Category::Reliability);
        assert!(parse_oasdiff("[]", "x").unwrap().is_empty());
    }

    #[test]
    fn mutation_scores() {
        let c = parse_cargo_mutants(CARGO_MUTANTS).unwrap();
        // 3 caught + 1 timeout vs 4 missed; unviable and Baseline excluded.
        assert_eq!((c.detected, c.total), (4, 8));
        assert!((c.percent() - 50.0).abs() < 0.1);
        let s = parse_stryker(STRYKER).unwrap();
        // Killed 2 + Timeout 1 vs Survived 1 + NoCoverage 1; CompileError excluded.
        assert_eq!((s.detected, s.total), (3, 5));
        assert!(parse_stryker("{").is_none());
        let m = parse_mutmut_meta(r#"{"exit_code_by_key":{"a":1,"b":0,"c":null,"d":36}}"#).unwrap();
        assert_eq!((m.detected, m.total), (2, 3));
        let top =
            parse_cargo_mutants(r#"{"caught":8,"missed":2,"timeout":0,"unviable":5}"#).unwrap();
        assert_eq!((top.detected, top.total), (8, 10));
    }

    #[test]
    fn registered() {
        let ids: Vec<String> = checks().into_iter().map(|c| c.id).collect();
        for i in [
            "tool.osv_reachability",
            "tool.scorecard",
            "tool.spectral",
            "tool.oasdiff",
            "qa.suite.mutation",
        ] {
            assert!(ids.iter().any(|x| x == i), "{i}");
        }
        let e = crate::tools::lock_entries();
        for t in ["osv-scanner", "scorecard", "spectral", "oasdiff"] {
            assert!(e[t].digest.starts_with("sha256:"), "{t}");
        }
    }
}
