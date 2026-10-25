//! Orchestration: target → snapshot → facts → checks → gate.
use crate::baseline::{self, Baseline};
use crate::checks;
use crate::config::TargetConfig;
use crate::ctx::Ctx;
use crate::facts::Facts;
use crate::model::*;
use crate::policy::{self, Policy};
use crate::scope::{self, Scope};
use crate::snapshot;
use crate::tools::Docker;
use anyhow::{Context, Result, bail};
use rand::Rng;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ScanOpts {
    pub target: String,
    #[serde(default)]
    pub profile: Option<Profile>,
    #[serde(default)]
    pub openapi: Option<String>,
    #[serde(skip)]
    pub policy: Option<PathBuf>,
    #[serde(skip)]
    pub scope: Option<PathBuf>,
    #[serde(skip)]
    pub config: Option<PathBuf>,
    #[serde(skip)]
    pub baseline: Option<PathBuf>,
    #[serde(default)]
    pub no_tools: bool,
    #[serde(default)]
    pub os: Option<Os>,
    #[serde(skip)]
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub device: Option<String>,
    /// `readyhai qa`: also snapshot this repo alongside a web target (composite run).
    #[serde(skip)]
    pub repo: Option<PathBuf>,
    #[serde(skip)]
    pub roles: Option<PathBuf>,
    #[serde(skip)]
    pub journeys: Option<PathBuf>,
    /// Run senior-QA checks.
    #[serde(skip)]
    pub qa: bool,
    #[serde(skip)]
    pub plugins: Option<PathBuf>,
    /// Server mode: repo paths must sit under allowed roots; web targets need scope.
    #[serde(skip)]
    pub server: bool,
    #[serde(skip)]
    pub allowed_roots: Vec<PathBuf>,
}

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("READYHAI_DATA") {
        return PathBuf::from(d);
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share"));
    base.join("readyhai")
}

pub fn now() -> String {
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default()
}

pub fn today() -> String {
    now().get(..10).unwrap_or("").to_string()
}

pub fn new_run_id() -> String {
    let t = OffsetDateTime::now_utc();
    let r: u16 = rand::rng().random();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}-{r:04x}",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

pub fn valid_run_id(id: &str) -> bool {
    !id.is_empty() && id.len() < 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

pub fn run_dir(id: &str) -> PathBuf {
    data_dir().join("runs").join(id)
}

pub fn load_run(id: &str) -> Result<Run> {
    if !valid_run_id(id) {
        bail!("invalid run id");
    }
    let p = run_dir(id).join("run.json");
    Ok(serde_json::from_str(&std::fs::read_to_string(&p).with_context(|| format!("run {id} not found"))?)?)
}

/// Stable per-target key for the default baseline location.
pub fn target_key(t: &Target) -> String {
    let raw = match &t.path {
        Some(p) => p.to_string_lossy().to_string(),
        None => t.raw.clone(),
    };
    sha256_hex(raw.as_bytes())[..16].to_string()
}

pub fn default_baseline_path(t: &Target) -> PathBuf {
    data_dir().join("baselines").join(format!("{}.json", target_key(t)))
}

pub fn parse_target(raw: &str, openapi: Option<String>) -> Result<Target> {
    let mut t = Target {
        kind: TargetKind::Repo,
        raw: raw.to_string(),
        path: None,
        image: None,
        url: None,
        openapi,
        host: None,
        apk: None,
        device: None,
    };
    if let Some(img) = raw.strip_prefix("image:") {
        if img.is_empty() || img.starts_with('-') || img.contains(char::is_whitespace) {
            bail!("invalid image reference");
        }
        t.kind = TargetKind::Image;
        t.image = Some(img.to_string());
    } else if raw.starts_with("http://") || raw.starts_with("https://") {
        t.kind = TargetKind::Web;
        t.url = Some(raw.to_string());
    } else if let Some(rest) = raw.strip_prefix("ssh://") {
        t.kind = TargetKind::Host;
        t.host = Some(parse_ssh(rest)?);
    } else if let Some(p) = raw.strip_prefix("android:") {
        let p = Path::new(p);
        let ok = p.is_file()
            && matches!(p.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref(), Some("apk" | "aab"));
        if !ok {
            bail!("android target must be android:<path to .apk/.aab>");
        }
        t.kind = TargetKind::Android;
        t.apk = Some(p.canonicalize()?);
    } else if raw.starts_with("git:") {
        t.kind = TargetKind::Repo;
    } else {
        let p = Path::new(raw);
        if !p.is_dir() {
            bail!("target '{raw}' is not a directory, image:<ref>, http(s):// URL or git:<url>");
        }
        t.path = Some(p.canonicalize()?);
    }
    Ok(t)
}

/// user@host[:port] — strict charset so nothing reaches ssh as an option.
fn parse_ssh(rest: &str) -> Result<HostSpec> {
    let rest = rest.trim_end_matches('/');
    let (user, hostport) = rest.split_once('@').ok_or_else(|| anyhow::anyhow!("ssh target must be ssh://user@host[:port]"))?;
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse::<u16>().map_err(|_| anyhow::anyhow!("bad ssh port"))?),
        _ => (hostport, 22),
    };
    let ok = |s: &str| !s.is_empty() && !s.starts_with('-') && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !ok(user) || !ok(host) {
        bail!("invalid ssh user or host");
    }
    Ok(HostSpec { user: user.into(), host: host.into(), port, os: Os::Linux, key: None })
}

/// Shallow clone with hooks/submodules/file-protocol disabled.
fn git_clone(url: &str, dest: &Path) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("ssh://") || url.starts_with("git@")) {
        bail!("git targets must be https://, ssh:// or git@ URLs");
    }
    let st = Command::new("git")
        .args([
            "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "core.symlinks=false",
            "clone", "--depth", "1", "--no-recurse-submodules", "--", url,
        ])
        .arg(dest)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()?;
    if !st.success() {
        bail!("git clone failed");
    }
    Ok(())
}

pub fn scan(opts: &ScanOpts, run_id: &str) -> Result<Run> {
    let started = now();
    if opts.server {
        crate::mcp::precheck(opts)?;
    }
    let profile = opts.profile.unwrap_or(Profile::Quick);
    let mut target = parse_target(&opts.target, opts.openapi.clone())?;
    if let Some(h) = target.host.as_mut() {
        h.os = opts.os.unwrap_or(Os::Linux);
        h.key = opts.key.clone();
        if opts.server && h.key.is_none() && std::env::var("SSH_AUTH_SOCK").is_err() {
            bail!("server mode: host targets need ssh-agent (SSH_AUTH_SOCK)");
        }
    }
    if target.kind == TargetKind::Android {
        if opts.server && !opts.allowed_roots.iter().any(|r| r.canonicalize().map(|r| target.apk.as_ref().is_some_and(|a| a.starts_with(r))).unwrap_or(false)) {
            bail!("apk is outside READYHAI_ALLOWED_ROOTS");
        }
        target.device = opts.device.clone();
    }
    let dir = run_dir(run_id);
    let src = dir.join("src");
    std::fs::create_dir_all(dir.join("out"))?;
    std::fs::create_dir_all(dir.join("artifacts"))?;
    let docker = Docker::detect(&data_dir());
    let mut notes = vec![];

    if opts.server
        && let Some(p) = &target.path
        && !opts.allowed_roots.iter().any(|r| r.canonicalize().map(|r| p.starts_with(r)).unwrap_or(false))
    {
        bail!("path is outside READYHAI_ALLOWED_ROOTS");
    }

    // Web scope
    let scope = match &opts.scope {
        Some(p) => {
            crate::scope::set_active(p);
            Some(Scope::load(p)?)
        }
        None => None,
    };
    let mut nonprod = false;
    if let Some(url) = &target.url {
        nonprod = scope::check(url, scope.as_ref(), opts.server)?;
    }

    let mut cfg = match &opts.config {
        Some(p) => TargetConfig::load(p)?.unwrap_or_default(),
        None => TargetConfig::default(),
    };
    let mut snap = None;
    // Composite QA run: web target + optional repo.
    if let Some(r) = &opts.repo {
        if target.kind != TargetKind::Web {
            bail!("--repo is only valid with a web target (readyhai qa <url> --repo DIR)");
        }
        let r = r.canonicalize().with_context(|| format!("repo {}", r.display()))?;
        if opts.server && !opts.allowed_roots.iter().any(|a| a.canonicalize().map(|a| r.starts_with(a)).unwrap_or(false)) {
            bail!("repo is outside READYHAI_ALLOWED_ROOTS");
        }
        target.path = Some(r);
    }
    let snapshot_repo = target.kind == TargetKind::Repo || target.path.is_some() && target.kind == TargetKind::Web;
    match target.kind {
        _ if snapshot_repo => {
            let source = match &target.path {
                Some(p) => p.clone(),
                None => {
                    let url = target.raw.trim_start_matches("git:").to_string();
                    let clone = dir.join("clone");
                    git_clone(&url, &clone)?;
                    target.path = Some(clone.clone());
                    clone
                }
            };
            if opts.config.is_none()
                && let Some(c) = TargetConfig::load(&source.join("readyhai.toml"))?
            {
                cfg = c;
                notes.push("using readyhai.toml from target".into());
                if !cfg.suppress.is_empty() {
                    notes.push(format!("{} suppression(s) come from the target's own readyhai.toml — review them", cfg.suppress.len()));
                }
                // An untrusted repo must not grant its own tests network access in server/MCP mode.
                if opts.server
                    && let Some(t) = cfg.test.as_mut()
                    && t.network
                {
                    t.network = false;
                    notes.push("server mode: ignored network=true from the target's readyhai.toml [test]".into());
                }
            }
            let s = snapshot::take(&source, &src, &cfg.snapshot.deny, &cfg.snapshot.skip_dirs)?;
            if !s.denied.is_empty() {
                notes.push(format!("{} secret-bearing file(s) withheld from all tools (never read)", s.denied.len()));
            }
            if !s.dropped_symlinks.is_empty() {
                notes.push(format!("{} symlink(s) dropped from snapshot", s.dropped_symlinks.len()));
            }
            if target.raw.starts_with("git:") {
                let _ = std::fs::remove_dir_all(dir.join("clone"));
            }
            snap = Some(s);
        }
        TargetKind::Image => {
            std::fs::create_dir_all(&src)?;
            snapshot::set_mode(&src, 0o755);
            if docker.available && !opts.no_tools {
                docker.export_image(target.image.as_deref().unwrap_or_default(), &src.join("image.tar"))?;
                snapshot::set_mode(&src.join("image.tar"), 0o644);
            }
        }
        _ => {}
    }
    for w in crate::tools::pin_warnings() {
        notes.push(w);
    }

    let facts = snap.as_ref().map(crate::rules::detect_facts).unwrap_or_else(Facts::default);
    let has_repo = snap.is_some();
    let qa = if opts.qa {
        let roles = match &opts.roles {
            Some(p) => crate::qa::roles::Roles::load(p)?,
            None => Default::default(),
        };
        notes.extend(roles.warnings.iter().cloned());
        if !nonprod {
            notes.push("QA: host is not tagged env=nonprod in scope.toml — read-only testing (no writes, forms, load or fault injection)".into());
        }
        Some(crate::qa::QaCtx::new(roles, opts.openapi.clone(), opts.journeys.clone(), nonprod))
    } else {
        None
    };
    let ctx = Ctx {
        run_id: run_id.into(),
        target: target.clone(),
        profile,
        run_dir: dir.clone(),
        snapshot: snap,
        facts,
        docker,
        cfg,
        error_lines: Default::default(),
        nonprod,
        qa,
    };

    let mut results = vec![];
    let mut findings: Vec<Finding> = vec![];
    for c in checks::all(opts.plugins.as_deref()) {
        let kind_ok = c.kinds.contains(&target.kind) || has_repo && c.kinds.contains(&TargetKind::Repo);
        if !kind_ok || profile < c.min_profile || c.qa && ctx.qa.is_none() {
            continue;
        }
        let t0 = Instant::now();
        let status_findings: (CheckStatus, Vec<Finding>) = if c.tool.is_some() && opts.no_tools {
            (CheckStatus::Skipped("--no-tools".into()), vec![])
        } else if c.tool.is_some() && !ctx.docker.available {
            (CheckStatus::Skipped("docker not available".into()), vec![])
        } else if c.intrusive && (profile != Profile::Deep || !nonprod) {
            (CheckStatus::Skipped("intrusive: needs --profile deep and a nonprod host in scope.toml".into()), vec![])
        } else {
            eprintln!("  · {} …", c.id);
            match catch_unwind(AssertUnwindSafe(|| (c.run)(&ctx))) {
                Ok(Ok(out)) => {
                    let st = out.status.unwrap_or(if out.findings.is_empty() { CheckStatus::Passed } else { CheckStatus::Failed });
                    (st, out.findings)
                }
                Ok(Err(e)) => (CheckStatus::Errored(format!("{e:#}")), vec![]),
                Err(_) => (CheckStatus::Errored("check panicked".into()), vec![]),
            }
        };
        let (status, mut fs) = status_findings;
        for f in &mut fs {
            if f.check.is_empty() {
                f.check = c.id.clone();
            }
            f.finalize();
        }
        results.push(CheckResult {
            id: c.id.clone(),
            title: c.title.clone(),
            tool: c.tool.clone(),
            status,
            findings: fs.len(),
            duration_ms: t0.elapsed().as_millis(),
        });
        findings.extend(fs);
    }
    ctx.docker.reap(run_id);
    let errors = crate::logs::cluster(&ctx.error_lines.lock().map(|v| v.clone()).unwrap_or_default());

    // Dedup by fingerprint, then gate.
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.fingerprint.clone()));
    notes.extend(policy::apply_suppressions(&mut findings, &ctx.cfg.suppress, &today()));
    let bpath = opts.baseline.clone().unwrap_or_else(|| default_baseline_path(&target));
    let base = Baseline::load(&bpath)?;
    if base.is_none() {
        notes.push("no baseline yet: every finding counts as new (accept one with `readyhai baseline accept <run>`)".into());
    }
    let fixed = baseline::apply(&mut findings, base.as_ref());
    findings.sort_by(|a, b| {
        (a.status as u8).cmp(&(b.status as u8)).then(b.severity.cmp(&a.severity)).then(a.rule.cmp(&b.rule))
    });
    let pol = Policy::load(opts.policy.as_deref())?;
    let (verdict, reasons) = policy::verdict(&pol, &findings, &results);

    let run = Run {
        id: run_id.into(),
        version: VERSION.into(),
        target,
        profile,
        started,
        finished: now(),
        verdict,
        reasons,
        categories: policy::summarize(&findings),
        checks: results,
        findings,
        fixed,
        notes,
        errors,
        qa: None,
    };
    let mut run = run;
    if let Some(q) = &ctx.qa {
        let configured = crate::llm::LlmConfig::from_env().ok();
        // Offline = no internet/registries. A LAN LLM is still allowed; cloud providers are
        // already refused unless READYHAI_LLM_ALLOW_CLOUD is set.
        let cfg = configured.clone().filter(crate::llm::probe);
        let mode = match (crate::bundle::offline(), cfg.is_some()) {
            (true, true) => "offline+lan-llm",
            (true, false) => "offline",
            (false, true) => "lan-llm",
            (false, false) => "deterministic",
        };
        let mut report = crate::qa::build_report(q, &run, mode);
        if configured.is_some() && cfg.is_none() {
            report.notes.push("LLM configured but unreachable (2s probe): report is deterministic-only".into());
        }
        if let Some(c) = &cfg {
            crate::qa::ai::enrich(&mut report, &run, c);
        }
        run.qa = Some(report);
    }
    std::fs::write(dir.join("run.json"), serde_json::to_string_pretty(&run)?)?;
    crate::dashboard::append_index(&run);
    Ok(run)
}
