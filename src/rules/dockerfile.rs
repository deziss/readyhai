//! Dockerfile hardening and stage inspection rules.

use super::facts::{dir, read_checked, Skips};
use super::na;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Finding, Severity};
use crate::snapshot::Snapshot;

pub(crate) struct Stage {
    pub(crate) line: usize,
    pub(crate) image: String,
    pub(crate) alias: Option<String>,
    pub(crate) instrs: Vec<(usize, String, String)>,
}

pub(crate) fn parse_stages(text: &str) -> Vec<Stage> {
    let mut logical: Vec<(usize, String)> = vec![];
    let (mut cur, mut start) = (String::new(), 0);
    for (i, l) in text.lines().enumerate() {
        let t = l.trim();
        if cur.is_empty() && (t.is_empty() || t.starts_with('#'))
            || !cur.is_empty() && t.starts_with('#')
        {
            continue;
        }
        if cur.is_empty() {
            start = i + 1;
        }
        if let Some(s) = t.strip_suffix('\\') {
            cur.push_str(s);
            cur.push(' ');
        } else {
            cur.push_str(t);
            logical.push((start, std::mem::take(&mut cur)));
        }
    }
    let mut stages: Vec<Stage> = vec![];
    for (line, ins) in logical {
        let (kw, args) = ins.split_once(char::is_whitespace).unwrap_or((&ins, ""));
        let kw = kw.to_uppercase();
        if kw == "FROM" {
            let toks: Vec<&str> = args
                .split_whitespace()
                .filter(|t| !t.starts_with("--"))
                .collect();
            let alias = toks
                .iter()
                .position(|t| t.eq_ignore_ascii_case("as"))
                .and_then(|i| toks.get(i + 1))
                .map(|s| s.to_lowercase());
            stages.push(Stage {
                line,
                image: toks.first().unwrap_or(&"").to_string(),
                alias,
                instrs: vec![],
            });
        } else if let Some(s) = stages.last_mut() {
            s.instrs.push((line, kw, args.trim().to_string()));
        }
    }
    stages
}

pub(crate) fn image_untagged(img: &str) -> bool {
    if img.contains('@') {
        return false;
    }
    match img.rsplit('/').next().unwrap_or(img).split_once(':') {
        None => true,
        Some((_, t)) => t == "latest",
    }
}

// ---------- readiness.dockerfile ----------

pub(crate) fn has_healthcheck(stage: &Stage) -> bool {
    stage
        .instrs
        .iter()
        .any(|i| i.1 == "HEALTHCHECK" && !i.2.to_uppercase().starts_with("NONE"))
}

/// Heuristic for one-shot tool/runner images that need no HEALTHCHECK: the Dockerfile lives under a
/// `runners/`, `tools/` or `scripts/` directory, or no stage EXPOSEs a port and the final
/// ENTRYPOINT/CMD runs a script file (.sh/.py/.js/.ts/.rb/.pl) that is expected to exit.
pub(crate) fn is_oneshot_image(df: &str, stages: &[Stage]) -> bool {
    if dir(df)
        .split('/')
        .any(|c| matches!(c, "runners" | "tools" | "scripts"))
    {
        return true;
    }
    let Some(last) = stages.last() else {
        return false;
    };
    if stages
        .iter()
        .any(|s| s.instrs.iter().any(|i| i.1 == "EXPOSE"))
    {
        return false;
    }
    last.instrs
        .iter()
        .rev()
        .find(|i| i.1 == "ENTRYPOINT" || i.1 == "CMD")
        .is_some_and(|i| {
            [".sh", ".py", ".js", ".ts", ".rb", ".pl"].iter().any(|e| {
                i.2.contains(&format!("{e}\""))
                    || i.2.contains(&format!("{e} "))
                    || i.2.ends_with(e)
            })
        })
}

pub(crate) fn dockerfile_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.dockerfile";
    if ctx.facts.dockerfiles.is_empty() {
        return na("no Dockerfile");
    }
    let mk = |r: &str, cat, sev, title: &str, loc: String| {
        Finding::new(C, &format!("{C}.{r}"), cat, sev, title, loc)
    };
    let mut out = vec![];
    let mut skips = Skips::default();
    for df in &ctx.facts.dockerfiles {
        let text = match read_checked(snap, df) {
            Ok(t) => t,
            Err(why) => {
                skips.add(df, why);
                continue;
            }
        };
        let stages = parse_stages(&text);
        let Some(last) = stages.last() else {
            skips.add(df, "no FROM instruction found, nothing to analyse");
            continue;
        };
        let user = last
            .instrs
            .iter()
            .rev()
            .find(|i| i.1 == "USER")
            .map(|i| i.2.split(':').next().unwrap_or("").trim().to_string());
        if user.as_deref().is_none_or(|u| u == "root" || u == "0") {
            out.push(
                mk(
                    "no_user",
                    Category::Security,
                    Severity::High,
                    "Container runs as root (no non-root USER in final stage)",
                    format!("{df}:{}", last.line),
                )
                .detail("The final stage has no USER instruction, or switches to root.")
                .remediation(
                    "Create an unprivileged user and add `USER app` before CMD/ENTRYPOINT.",
                ),
            );
        }
        if !has_healthcheck(last) && !is_oneshot_image(df, &stages) {
            out.push(
                mk("no_healthcheck", Category::Reliability, Severity::Medium, "No HEALTHCHECK in final stage", format!("{df}:{}", last.line))
                    .remediation("Add a HEALTHCHECK that uses a binary present in the image, or rely on orchestrator probes."),
            );
        }
        let mut seen: Vec<String> = vec![];
        for s in &stages {
            let img = s.image.to_lowercase();
            if !img.is_empty()
                && img != "scratch"
                && !img.contains('$')
                && !seen.contains(&img)
                && image_untagged(&s.image)
            {
                out.push(
                    mk(
                        "latest_base",
                        Category::SupplyChain,
                        Severity::Low,
                        &format!("Base image `{}` is untagged or :latest", s.image),
                        format!("{df}:{}", s.line),
                    )
                    .remediation("Pin the base image to a version tag, ideally a digest."),
                );
            }
            if let Some(a) = &s.alias {
                seen.push(a.clone());
            }
            for (line, kw, args) in &s.instrs {
                if kw == "ADD"
                    && args
                        .split_whitespace()
                        .find(|t| !t.starts_with("--"))
                        .is_some_and(|t| t.starts_with("http://") || t.starts_with("https://"))
                {
                    out.push(
                        mk("add_remote", Category::SupplyChain, Severity::Low, "ADD fetches a remote URL", format!("{df}:{line}"))
                            .remediation("Use curl/wget with a checksum verification step, or COPY a vendored file."),
                    );
                }
            }
        }
        let d = dir(df);
        let ignore = if d.is_empty() {
            ".dockerignore".to_string()
        } else {
            format!("{d}/.dockerignore")
        };
        if !snap.files.contains(&ignore) {
            out.push(
                mk("no_dockerignore", Category::Operability, Severity::Low, "No .dockerignore next to Dockerfile", df.clone())
                    .remediation("Add a .dockerignore (.git, .env*, node_modules, tests) to shrink context and avoid leaking secrets into layers."),
            );
        }
    }
    skips.finish(out)
}
