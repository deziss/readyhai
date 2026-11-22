use super::checks::junit_output;
use super::docker::read_out;
use super::pinning::warn_unpinned;
use super::sarif_junit::parse_sarif_report;
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
    #[serde(default)]
    pub(crate) output: String,
    pub(crate) format: String,
    /// Capture the container's stdout instead of reading a file under /out
    /// (stdout-only CLIs: `npm audit`, `clairctl`). When true, `output` is unused.
    #[serde(default)]
    pub(crate) stdout: bool,
    /// Writable `/cache` mount for tools with persistent DBs/feed caches
    /// (trivy-db, NVD feed, nuclei templates). Default false = read-only.
    #[serde(default)]
    pub(crate) cache_rw: bool,
    /// Names     of ReadyHai-process environment variables to pass into the container
    /// (vendor tokens: WPScanAPIToken, SNYK_TOKEN, ...). Values are passed via the
    /// docker client env (`-e NAME`), never through args, so secrets do not appear
    /// in the host process list.
    #[serde(default)]
    pub(crate) env: Vec<String>,
    /// Map host.docker.internal to the host gateway (targets bound to localhost).
    #[serde(default)]
    pub(crate) host_gateway: bool,
    /// Run as this uid:gid instead of the default nobody (65534:65534), e.g. an
    /// image whose tool needs its own home. Must be numeric; validated here.
    #[serde(default)]
    pub(crate) user: Option<String>,
    /// Intrusive: like core checks, only runs under `--profile deep` and a nonprod target.
    #[serde(default)]
    pub(crate) intrusive: bool,
    /// `lines` format: rule id for the generated inventory findings.
    #[serde(default)]
    pub(crate) rule: String,
    /// `lines` format: category (security/supply_chain/...) default security.
    #[serde(default)]
    pub(crate) category: String,
    /// `lines` format: severity of generated findings, default info.
    #[serde(default)]
    pub(crate) severity: String,
    /// `lines` format: title prefix, e.g. "Subdomain" -> "Subdomain: a.example.com".
    #[serde(default)]
    pub(crate) title_prefix: String,
}

/// First non-empty string under any of the recon-tool keys, searched one level
/// into `request`/`data` (katana nests under request.url; ferox uses url_full).
fn pick_url_key(v: &serde_json::Value) -> Option<&str> {
    const KEYS: [&str; 8] = ["host", "url", "url_full", "input", "endpoint", "name", "value", "path"];
    for k in KEYS {
        if let Some(s) = v.get(k).and_then(|x| x.as_str())
            && !s.is_empty()
        {
            return Some(s);
        }
    }
    ["request", "data"].iter().find_map(|o| v.get(*o).and_then(pick_url_key))
}

/// Turn one text line into an inventory finding. Accepts bare hosts/URLs and
/// JSON object lines ({"host": "..."} / {"url": "..."} / {"input": "..."});
/// anything else contributes the raw line. Recon tools (subfinder/httpx/katana)
/// emit exactly these shapes, so no jq wrapper is needed in their images.
fn line_finding(check: &str, p: &Plugin, line: &str) -> Option<Finding> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let value = if line.starts_with('{') {
        serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| pick_url_key(&v).map(str::to_string))
            .unwrap_or_else(|| line.to_string())
    } else {
        line.to_string()
    };
    if value.is_empty() {
        return None;
    }
    let sev = match p.severity.as_str() {
        "critical" => crate::model::Severity::Critical,
        "high" => crate::model::Severity::High,
        "medium" => crate::model::Severity::Medium,
        "low" => crate::model::Severity::Low,
        _ => crate::model::Severity::Info,
    };
    let cat = match p.category.as_str() {
        "supply_chain" => crate::model::Category::SupplyChain,
        "reliability" => crate::model::Category::Reliability,
        "observability" => crate::model::Category::Observability,
        "quality" => crate::model::Category::Quality,
        "operability" => crate::model::Category::Operability,
        "performance" => crate::model::Category::Performance,
        _ => crate::model::Category::Security,
    };
    let rule = if p.rule.is_empty() {
        format!("recon.{}.line", p.id)
    } else {
        p.rule.clone()
    };
    let title = if p.title_prefix.is_empty() {
        value.clone()
    } else {
        format!("{}: {}", p.title_prefix, value)
    };
    Some(
        Finding::new(check, &rule, cat, sev, title, value)
            .detail("inventory from plugin output (lines format)"),
    )
}

fn parse_lines(check: &str, p: &Plugin, text: &str) -> Vec<Finding> {
    let mut seen = std::collections::BTreeSet::new();
    text.lines()
        .filter_map(|l| line_finding(check, p, l))
        .filter(|f| seen.insert(f.location.clone()))
        .collect()
}

fn valid_user(u: &str) -> bool {
    let (uid, gid) = match u.split_once(':') {
        Some((a, b)) => (a, Some(b)),
        None => (u, None),
    };
    let num = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    num(uid) && gid.is_none_or(num)
}

/// Bare hostname from a URL/target string (no scheme/port/path).
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    host.rsplit_once('@').map_or(host, |(_, h)| h).split(':').next().unwrap_or("").to_string()
}

/// Non-zero exit with parseable output = a truncated run, not a clean one: the tool stopped
/// midway, so whatever it enumerated is partial coverage. The note becomes `CheckStatus::Partial`,
/// which the gate can warn or fail on but can never turn into PASS. The `lines` inventory format
/// is exempt — those capture stdout, and several recon tools exit non-zero on partial input while
/// their inventory is still valid.
pub(crate) fn exit_incompleteness(
    format: &str,
    exit_code: i32,
    stderr_tail: &str,
) -> Option<String> {
    if exit_code == 0 || format == "lines" {
        return None;
    }
    Some(format!(
        "tool exited {exit_code}: findings may be incomplete ({})",
        super::parsers::first_line(stderr_tail.trim(), 160)
    ))
}

pub(crate) fn run_plugin(ctx: &Ctx, p: &Plugin) -> Result<CheckOutput> {
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    let check = format!("plugin.{}", p.id);
    // Rewrite loopback targets to host.docker.internal so containers can reach a
    // localhost dev server (same rule the core web checks use), and remember to
    // request the host-gateway mapping either way.
    let (c_url, needs_gw) = ctx
        .target
        .url
        .as_deref()
        .map(crate::web::client::container_url)
        .unwrap_or_default();
    let url = c_url.as_str();
    let args: Vec<String> = p
        .args
        .iter()
        .map(|a| {
            a.replace("{src}", "/src")
                .replace("{out}", "/out")
                .replace("{url}", url)
                .replace("{domain}", &host_of(url))
                .replace("{image_tar}", "/src/image.tar")
        })
        .collect();
    let mut spec = ToolSpec::new(&format!("plugin-{}", p.id), &[]);
    spec.args = args;
    spec.image = Some(p.image.clone());
    spec.network = p.network;
    spec.cache_rw = p.cache_rw;
    spec.host_gateway = p.host_gateway || needs_gw;
    spec.entrypoint = p.entrypoint.clone();
    // Pass env by NAME; the docker client resolves values from our own environment
    // (same pattern as ToolSpec.env), so secrets never land in the host cmdline.
    spec.env = p
        .env
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.clone(), v)))
        .collect();
    let missing_env: Vec<&String> = p
        .env
        .iter()
        .filter(|k| std::env::var(k).is_err())
        .collect();
    if let Some(u) = &p.user {
        if !valid_user(u) {
            bail!("plugin {}: invalid user {u:?} (must be numeric uid[:gid])", p.id);
        }
        spec.user = Some(u.clone());
    }
    if !p.image.contains("@sha256:") {
        warn_unpinned(&format!("plugin:{}", p.id), &p.image);
    }
    let r = ctx.docker.run(ctx, &spec)?;
    let skipped_env = if missing_env.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "env not set, plugin may under-check: {}",
            missing_env
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )]
    };
    let txt = if p.stdout {
        if r.stdout_truncated {
            bail!(
                "plugin {}: stdout exceeded the capture cap; write findings to a file under /out instead",
                p.id
            );
        }
        r.stdout.clone()
    } else {
        let name = p.output.strip_prefix("/out/").unwrap_or(&p.output);
        read_out(ctx, name).map_err(|e| out_err(e, || tool_failed(&p.id, &r)))?
    };
    // An empty file for sarif/junit/readyhai-json is broken output, but for the
    // line-oriented `lines` format empty simply means "the tool found nothing"
    // (e.g. subfinder on an IP literal has no passive results) — as long as the
    // tool itself exited successfully.
    if txt.trim().is_empty() && !(p.format == "lines" && p.stdout && r.exit_code == 0) {
        return Err(tool_failed(&p.id, &r));
    }
    let mut sarif_notes = Vec::new();
    let mut findings = match p.format.as_str() {
        "sarif" => {
            let (f, notes) = parse_sarif_report(&txt, &check)?;
            sarif_notes = notes;
            f
        }
        "junit" => match junit_output(&txt, if p.stdout { r.exit_code } else { 0 }) {
            CheckOutput {
                status: Some(st), ..
            } => return Ok(CheckOutput::status(st)),
            o => o.findings,
        },
        "readyhai-json" => serde_json::from_str::<Vec<Finding>>(&txt)?,
        "lines" => parse_lines(&check, p, &txt),
        f => bail!("plugin {}: unknown format {f}", p.id),
    };
    for f in &mut findings {
        f.check = check.clone();
    }
    let mut notes = skipped_env;
    notes.extend(sarif_notes);
    notes.extend(exit_incompleteness(&p.format, r.exit_code, &r.stderr_tail));
    if !p.image.contains("@sha256:") {
        notes.push("plugin image unpinned".to_string());
    }
    Ok(partial(notes, findings))
}

/// Whether one candidate plugin directory loaded under the loader rules.
#[derive(Debug, Clone)]
pub enum PluginLoad {
    Loaded,
    Skipped,
}

/// One candidate plugin (a directory holding a readable `plugin.toml`) and why it
/// loaded or was skipped. Produced by [`plugin_diags`]; same rules as [`plugin_checks`].
#[derive(Debug, Clone)]
pub struct PluginDiag {
    /// The pack directory the manifest was read from (`<dir>/<pack>`).
    pub dir: String,
    /// Declared plugin id; the directory name when the manifest could not be parsed.
    pub id: String,
    pub status: PluginLoad,
    /// Rejection reason; `None` when loaded.
    pub reason: Option<String>,
    /// Image the manifest declares (empty when the manifest could not be parsed).
    pub image: String,
}

/// The single source of truth for rejecting malformed plugins — at load, not at
/// scan time (the loader is best-effort). `None` means the manifest is valid.
fn reject_reason(p: &Plugin) -> Option<String> {
    if !p.stdout && p.output.is_empty() {
        return Some("file format with no output path (empty `output` and `stdout=false`)".into());
    }
    if let Some(u) = p.user.as_deref().filter(|u| !valid_user(u)) {
        return Some(format!("invalid user {u:?} (must be numeric uid[:gid])"));
    }
    if let Some(k) = p
        .env
        .iter()
        .find(|k| k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        return Some(format!("invalid env name {k:?}"));
    }
    if p.kinds
        .iter()
        .all(|k| !matches!(k.as_str(), "repo" | "image" | "web"))
    {
        return Some("no valid kinds (repo/image/web)".into());
    }
    None
}

/// Pack subdirectories of `dir`, sorted: the loader reads one level, `<dir>/<pack>/plugin.toml`.
fn pack_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    v
}

fn skip_diag(dir: &str, id: String, reason: String, image: String) -> PluginDiag {
    PluginDiag {
        dir: dir.to_string(),
        id,
        status: PluginLoad::Skipped,
        reason: Some(reason),
        image,
    }
}

/// Reads and validates one pack directory: `Ok(Some)` loads; `Err(diag)` is a
/// candidate that was rejected; `Ok(None)` has no readable `plugin.toml`, so the
/// directory is inert (a pack root like `official/`), not a candidate.
fn load_plugin(dir: &Path) -> Result<Option<Plugin>, PluginDiag> {
    let dir_s = dir.display().to_string();
    let name = || {
        dir.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string()
    };
    let Ok(text) = std::fs::read_to_string(dir.join("plugin.toml")) else {
        return Ok(None);
    };
    let p = match toml::from_str::<Plugin>(&text) {
        Ok(p) => p,
        Err(e) => {
            return Err(skip_diag(
                &dir_s,
                name(),
                format!("plugin.toml parse failed: {e}"),
                String::new(),
            ));
        }
    };
    match reject_reason(&p) {
        Some(reason) => {
            let id = if p.id.is_empty() {
                name()
            } else {
                p.id.clone()
            };
            Err(skip_diag(&dir_s, id, reason, p.image.clone()))
        }
        None => Ok(Some(p)),
    }
}

/// Every candidate plugin under `dir` sorted by directory, with load status and
/// skip reason — exactly what [`plugin_checks`] accepts or drops. Pure filesystem:
/// no docker, no network.
pub fn plugin_diags(dir: &Path) -> Vec<PluginDiag> {
    pack_dirs(dir)
        .into_iter()
        .filter_map(|d| match load_plugin(&d) {
            Ok(Some(p)) => Some(PluginDiag {
                dir: d.display().to_string(),
                id: p.id.clone(),
                status: PluginLoad::Loaded,
                reason: None,
                image: p.image.clone(),
            }),
            Ok(None) => None,
            Err(diag) => Some(diag),
        })
        .collect()
}

/// `(id, image)` for every plugin that loads successfully (validation shared with
/// [`plugin_checks`]), in directory order. Duplicates across plugins are kept;
/// callers dedup.
pub fn plugin_image_refs(dir: &Path) -> Vec<(String, String)> {
    pack_dirs(dir)
        .into_iter()
        .filter_map(|d| load_plugin(&d).ok().flatten().map(|p| (p.id, p.image)))
        .collect()
}

/// Plugin dir for commands without a `--plugins` flag: `READYHAI_PLUGINS` when set,
/// else `<data>/plugins`. A scan with neither loads no plugins; `doctor` and
/// `tools pull` also probe the data-dir location so an installed layout is visible.
pub fn plugins_dir() -> PathBuf {
    match std::env::var_os("READYHAI_PLUGINS") {
        Some(d) => PathBuf::from(d),
        None => crate::engine::data_dir().join("plugins"),
    }
}

pub fn plugin_checks(dir: &Path) -> Vec<Check> {
    let mut v = vec![];
    for d in pack_dirs(dir) {
        // load_plugin applies reject_reason, so every plugin below is valid.
        let Ok(Some(p)) = load_plugin(&d) else {
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
        let intrusive = p.intrusive;
        let mut c =
            Check::new(&id, &title, &kinds, profile, move |ctx| run_plugin(ctx, &p)).tool(&tool);
        if intrusive {
            c = c.intrusive();
        }
        v.push(c);
    }
    v
}
