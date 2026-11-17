use super::checks::junit_output;
use super::docker::read_out;
use super::pinning::warn_unpinned;
use super::sarif_junit::parse_sarif;
use super::types::{ToolSpec, gate, out_err, partial, tool_failed};
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{CheckOutput, Finding, Profile, TargetKind};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Plugin {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) kinds: Vec<String>,
    #[serde(default)]
    pub(crate) profile: String,
    pub(crate) image: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default)]
    pub(crate) network: bool,
    #[serde(default)]
    pub(crate) entrypoint: Option<String>,
    pub(crate) output: String,
    pub(crate) format: String,
}

pub(crate) fn run_plugin(ctx: &Ctx, p: &Plugin) -> Result<CheckOutput> {
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    let check = format!("plugin.{}", p.id);
    let url = ctx.target.url.clone().unwrap_or_default();
    let args: Vec<String> = p
        .args
        .iter()
        .map(|a| {
            a.replace("{src}", "/src")
                .replace("{out}", "/out")
                .replace("{url}", &url)
                .replace("{image_tar}", "/src/image.tar")
        })
        .collect();
    let mut spec = ToolSpec::new(&format!("plugin-{}", p.id), &[]);
    spec.args = args;
    spec.image = Some(p.image.clone());
    spec.network = p.network;
    spec.entrypoint = p.entrypoint.clone();
    if !p.image.contains("@sha256:") {
        warn_unpinned(&format!("plugin:{}", p.id), &p.image);
    }
    let r = ctx.docker.run(ctx, &spec)?;
    let name = p.output.strip_prefix("/out/").unwrap_or(&p.output);
    let txt = read_out(ctx, name).map_err(|e| out_err(e, || tool_failed(&p.id, &r)))?;
    let mut findings = match p.format.as_str() {
        "sarif" => parse_sarif(&txt, &check)?,
        "junit" => match junit_output(&txt, r.exit_code) {
            CheckOutput {
                status: Some(st), ..
            } => return Ok(CheckOutput::status(st)),
            o => o.findings,
        },
        "readyhai-json" => serde_json::from_str::<Vec<Finding>>(&txt)?,
        f => bail!("plugin {}: unknown format {f}", p.id),
    };
    for f in &mut findings {
        f.check = check.clone();
    }
    let notes = if p.image.contains("@sha256:") {
        vec![]
    } else {
        vec!["plugin image unpinned".to_string()]
    };
    Ok(partial(notes, findings))
}

pub fn plugin_checks(dir: &Path) -> Vec<Check> {
    let mut v = vec![];
    let Ok(rd) = std::fs::read_dir(dir) else {
        return v;
    };
    let mut dirs: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for d in dirs {
        let Ok(text) = std::fs::read_to_string(d.join("plugin.toml")) else {
            continue;
        };
        let Ok(p) = toml::from_str::<Plugin>(&text) else {
            continue;
        };
        let kinds: Vec<TargetKind> = p
            .kinds
            .iter()
            .filter_map(|k| match k.as_str() {
                "repo" => Some(TargetKind::Repo),
                "image" => Some(TargetKind::Image),
                "web" => Some(TargetKind::Web),
                _ => None,
            })
            .collect();
        if kinds.is_empty() {
            continue;
        }
        let profile = match p.profile.as_str() {
            "quick" => Profile::Quick,
            "deep" => Profile::Deep,
            _ => Profile::Standard,
        };
        let title = if p.title.is_empty() {
            p.id.clone()
        } else {
            p.title.clone()
        };
        let id = format!("plugin.{}", p.id);
        let tool = p.id.clone();
        v.push(
            Check::new(&id, &title, &kinds, profile, move |ctx| run_plugin(ctx, &p)).tool(&tool),
        );
    }
    v
}
