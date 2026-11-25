use anyhow::Result;
use serde_json::Value;

use super::helpers::sv;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Severity};
use crate::tools::{
    ToolSpec, gate, missing_image, out_err, read_out, read_text_capped, tool_failed,
};

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

/// The GitHub slug a remote clone target was given as: `https://github.com/o/r(.git)`,
/// `git:<url>`, `git@github.com:o/r.git`. A local path (or any non-GitHub URL) gives `None`.
pub fn slug_from_target_raw(raw: &str) -> Option<String> {
    let r = raw.trim();
    github_slug(r.strip_prefix("git:").unwrap_or(r).trim())
}

/// Where Scorecard should look: the repo's own `origin` remote when the target is a local checkout,
/// else the URL a remote target was cloned from. (A remote clone is deleted after the snapshot is
/// taken, so its `.git/config` is gone by the time checks run: the slug must come from `target.raw`.)
fn scorecard_slug(ctx: &Ctx) -> Option<String> {
    ctx.target
        .path
        .as_ref()
        .and_then(|d| read_text_capped(&d.join(".git").join("config"), 1 << 20).ok())
        .as_deref()
        .and_then(remote_url)
        .as_deref()
        .and_then(github_slug)
        .or_else(|| slug_from_target_raw(&ctx.target.raw))
}

pub(crate) fn scorecard(ctx: &Ctx) -> Result<CheckOutput> {
    if ctx.target.path.is_none() && slug_from_target_raw(&ctx.target.raw).is_none() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no repo path".into(),
        )));
    }
    let slug = scorecard_slug(ctx);
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
    let txt =
        read_out(ctx, "scorecard.json").map_err(|e| out_err(e, || tool_failed("scorecard", &r)))?;
    Ok(CheckOutput::findings(parse_scorecard(&txt)?))
}
