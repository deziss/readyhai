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
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
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
    /// Wall-clock deadline for the whole run (server worker). Checks that would start after it
    /// are skipped, running tools are capped to it, and the run then fails instead of producing
    /// a verdict from partial results.
    #[serde(skip)]
    pub deadline: Option<Instant>,
}

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("READYHAI_DATA") {
        return PathBuf::from(d);
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share")
        });
    base.join("readyhai")
}

pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub fn today() -> String {
    now().get(..10).unwrap_or("").to_string()
}

/// `YYYYMMDD-HHMMSS-<64 random bits as hex>`. The timestamp keeps listings sortable; the random
/// part keeps ids unguessable (REST run ids are capability-like: 16 bits was enumerable).
pub fn new_run_id() -> String {
    let t = OffsetDateTime::now_utc();
    let r: u64 = rand::rng().random();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}-{r:016x}",
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

/// Write `bytes` to `path` atomically: a temp file in the same directory, then rename. Readers
/// (status polling, report download) never see a half-written file, and a crash leaves either the
/// old or the new content. Fails (instead of creating directories) when the parent is gone, so a
/// run that was deleted underneath a worker is not resurrected.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent directory"))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{:08x}.tmp", rand::rng().random::<u32>()));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

static DEADLINES: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(Default::default);

/// Wall-clock deadline registered for a running scan (see `ScanOpts::deadline`).
pub fn run_deadline(run_id: &str) -> Option<Instant> {
    DEADLINES.lock().ok()?.get(run_id).copied()
}

fn deadline_passed(run_id: &str) -> bool {
    run_deadline(run_id).is_some_and(|d| Instant::now() >= d)
}

/// Registers the deadline for the lifetime of a scan, whatever way it exits.
struct DeadlineGuard(String);
impl DeadlineGuard {
    fn new(run_id: &str, at: Option<Instant>) -> Self {
        if let (Some(at), Ok(mut m)) = (at, DEADLINES.lock()) {
            m.insert(run_id.to_string(), at);
        }
        DeadlineGuard(run_id.to_string())
    }
}
impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = DEADLINES.lock() {
            m.remove(&self.0);
        }
    }
}

pub fn load_run(id: &str) -> Result<Run> {
    if !valid_run_id(id) {
        bail!("invalid run id");
    }
    let p = run_dir(id).join("run.json");
    Ok(serde_json::from_str(
        &std::fs::read_to_string(&p).with_context(|| format!("run {id} not found"))?,
    )?)
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
    data_dir()
        .join("baselines")
        .join(format!("{}.json", target_key(t)))
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
    } else if let Some(rest) = raw.strip_prefix("ssh://") {
        t.kind = TargetKind::Host;
        t.host = Some(parse_ssh(rest)?);
    } else if let Some(p) = raw.strip_prefix("android:") {
        let p = Path::new(p);
        let ok = p.is_file()
            && matches!(
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("apk" | "aab")
            );
        if !ok {
            bail!("android target must be android:<path to .apk/.aab>");
        }
        t.kind = TargetKind::Android;
        t.apk = Some(p.canonicalize()?);
    } else if raw.starts_with("git:")
        || raw.ends_with(".git")
        || raw.starts_with("https://github.com/")
        || raw.starts_with("http://github.com/")
        || raw.starts_with("https://gitlab.com/")
        || raw.starts_with("http://gitlab.com/")
    {
        t.kind = TargetKind::Repo;
    } else if raw.starts_with("http://") || raw.starts_with("https://") {
        t.kind = TargetKind::Web;
        // Use the WHATWG-normalised form everywhere downstream: it is the one the scope check
        // saw, so no tool can parse the authority differently (backslash/userinfo tricks).
        t.url = Some(scope::parse_web_url(raw)?.to_string());
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
    let (user, hostport) = rest
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("ssh target must be ssh://user@host[:port]"))?;
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (
            h,
            p.parse::<u16>()
                .map_err(|_| anyhow::anyhow!("bad ssh port"))?,
        ),
        _ => (hostport, 22),
    };
    let ok = |s: &str| {
        !s.is_empty()
            && !s.starts_with('-')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    };
    if !ok(user) || !ok(host) {
        bail!("invalid ssh user or host");
    }
    Ok(HostSpec {
        user: user.into(),
        host: host.into(),
        port,
        os: Os::Linux,
        key: None,
    })
}

/// Host a `git clone` of this target contacts (`raw` may carry the `git:` prefix). Understands
/// `https://`, `http://`, `ssh://` and scp-like `[user@]host:path` (`git@host:org/repo.git`).
/// The charset is strict so nothing that looks like an ssh option can pass as a host.
pub fn remote_repo_host(raw: &str) -> Result<String> {
    let url = raw.strip_prefix("git:").unwrap_or(raw).trim();
    if url.contains(char::is_whitespace) || url.contains('\0') {
        bail!("not a recognised remote repository URL");
    }
    let host = if url.contains("://") {
        let u = reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid git URL: {e}"))?;
        if !matches!(u.scheme(), "https" | "http" | "ssh") {
            bail!("git targets must be https://, ssh:// or git@host:path URLs");
        }
        u.host_str().unwrap_or_default().to_ascii_lowercase()
    } else {
        let (userhost, path) = url
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("not a recognised remote repository URL"))?;
        // `ext::<command>` and `transport::address` helpers are not scp-style paths
        if path.is_empty() || path.starts_with(':') || userhost.contains('/') {
            bail!("not a recognised remote repository URL");
        }
        userhost
            .rsplit_once('@')
            .map(|x| x.1)
            .unwrap_or(userhost)
            .to_ascii_lowercase()
    };
    let host = host.trim_end_matches('.').to_string();
    if host.is_empty()
        || host.starts_with('-')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        bail!("unsupported git host '{host}'");
    }
    Ok(host)
}

/// What to hand to `git clone`: URL forms are re-serialised by the same parser that produced
/// the host the scope check approved.
fn clone_url(raw: &str) -> Result<String> {
    let url = raw.strip_prefix("git:").unwrap_or(raw).trim();
    if url.contains("://") {
        Ok(reqwest::Url::parse(url)
            .map_err(|e| anyhow::anyhow!("invalid git URL: {e}"))?
            .to_string())
    } else {
        Ok(url.to_string())
    }
}

fn git_timeout(run_id: &str) -> Duration {
    let secs = std::env::var("READYHAI_GIT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300)
        .clamp(10, 3600);
    let mut t = Duration::from_secs(secs);
    if let Some(rd) = run_deadline(run_id) {
        t = t.min(rd.saturating_duration_since(Instant::now()));
    }
    t
}

fn redact_url_credentials(s: &str) -> String {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)((?:https?|ssh)://)[^/\s@]+@").unwrap());
    RE.replace_all(s, "${1}***@").into_owned()
}

/// The clone command: hooks/submodules/file-protocol disabled, no prompts of any kind (terminal,
/// credential helper, ssh).
fn git_clone_command(url: &str, dest: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.symlinks=false",
        "-c",
        "credential.helper=",
        "clone",
        "--depth",
        "1",
        "--no-recurse-submodules",
        "--",
        url,
    ])
    .arg(dest)
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes");
    cmd
}

/// Shallow clone with a wall-clock limit and no inherited stdio (stdin null, output captured).
fn git_clone(url: &str, dest: &Path, timeout: Duration) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("ssh://") || url.starts_with("git@")) {
        bail!("git targets must be https://, ssh:// or git@ URLs");
    }
    let mut cmd = git_clone_command(url, dest);
    let out =
        crate::tools::run_capped(&mut cmd, timeout, 16 * 1024, None).context("running git")?;
    if out.timed_out {
        let _ = std::fs::remove_dir_all(dest);
        bail!("git clone timed out after {}s", timeout.as_secs());
    }
    if !out.success() {
        let err = out.stderr_lossy();
        let tail: String = err
            .trim()
            .chars()
            .rev()
            .take(400)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        bail!("git clone failed: {}", redact_url_credentials(&tail));
    }
    Ok(())
}

pub fn scan(opts: &ScanOpts, run_id: &str) -> Result<Run> {
    let started = now();
    let _deadline = DeadlineGuard::new(run_id, opts.deadline);
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
        if opts.server
            && !opts.allowed_roots.iter().any(|r| {
                r.canonicalize()
                    .map(|r| target.apk.as_ref().is_some_and(|a| a.starts_with(r)))
                    .unwrap_or(false)
            })
        {
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
        && !opts
            .allowed_roots
            .iter()
            .any(|r| r.canonicalize().map(|r| p.starts_with(r)).unwrap_or(false))
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
        let r = r
            .canonicalize()
            .with_context(|| format!("repo {}", r.display()))?;
        if opts.server
            && !opts
                .allowed_roots
                .iter()
                .any(|a| a.canonicalize().map(|a| r.starts_with(a)).unwrap_or(false))
        {
            bail!("repo is outside READYHAI_ALLOWED_ROOTS");
        }
        target.path = Some(r);
    }
    let snapshot_repo =
        target.kind == TargetKind::Repo || target.path.is_some() && target.kind == TargetKind::Web;
    match target.kind {
        _ if snapshot_repo => {
            let source = match &target.path {
                Some(p) => p.clone(),
                None => {
                    let url = clone_url(&target.raw)?;
                    let clone = dir.join("clone");
                    git_clone(&url, &clone, git_timeout(run_id))?;
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
                    notes.push(format!(
                        "{} suppression(s) come from the target's own readyhai.toml — review them",
                        cfg.suppress.len()
                    ));
                }
                // An untrusted repo must not grant its own tests network access in server/MCP mode.
                if opts.server
                    && let Some(t) = cfg.test.as_mut()
                    && t.network
                {
                    t.network = false;
                    notes.push(
                        "server mode: ignored network=true from the target's readyhai.toml [test]"
                            .into(),
                    );
                }
            }
            let s = snapshot::take(&source, &src, &cfg.snapshot.deny, &cfg.snapshot.skip_dirs)?;
            if !s.denied.is_empty() {
                notes.push(format!(
                    "{} secret-bearing file(s) withheld from all tools (never read)",
                    s.denied.len()
                ));
            }
            if !s.dropped_symlinks.is_empty() {
                notes.push(format!(
                    "{} symlink(s) dropped from snapshot",
                    s.dropped_symlinks.len()
                ));
            }
            if dir.join("clone").exists() {
                let _ = std::fs::remove_dir_all(dir.join("clone"));
            }
            snap = Some(s);
        }
        TargetKind::Image => {
            std::fs::create_dir_all(&src)?;
            snapshot::set_mode(&src, 0o755);
            if docker.available && !opts.no_tools {
                docker.export_image(
                    run_id,
                    target.image.as_deref().unwrap_or_default(),
                    &src.join("image.tar"),
                )?;
                snapshot::set_mode(&src.join("image.tar"), 0o644);
            }
        }
        _ => {}
    }
    for w in crate::tools::pin_warnings() {
        notes.push(w);
    }

    let facts = snap
        .as_ref()
        .map(crate::rules::detect_facts)
        .unwrap_or_else(Facts::default);
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
        Some(crate::qa::QaCtx::new(
            roles,
            opts.openapi.clone(),
            opts.journeys.clone(),
            nonprod,
        ))
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
        let kind_ok =
            c.kinds.contains(&target.kind) || has_repo && c.kinds.contains(&TargetKind::Repo);
        if !kind_ok || profile < c.min_profile || c.qa && ctx.qa.is_none() {
            continue;
        }
        let t0 = Instant::now();
        let status_findings: (CheckStatus, Vec<Finding>) = if c.tool.is_some() && opts.no_tools {
            (CheckStatus::Skipped("--no-tools".into()), vec![])
        } else if c.tool.is_some() && !ctx.docker.available {
            (CheckStatus::Skipped("docker not available".into()), vec![])
        } else if deadline_passed(run_id) {
            (
                CheckStatus::Skipped("run wall-clock deadline exceeded".into()),
                vec![],
            )
        } else if c.intrusive && (profile != Profile::Deep || !nonprod) {
            (
                CheckStatus::Skipped(
                    "intrusive: needs --profile deep and a nonprod host in scope.toml".into(),
                ),
                vec![],
            )
        } else {
            eprintln!("  · {} …", c.id);
            match catch_unwind(AssertUnwindSafe(|| (c.run)(&ctx))) {
                Ok(Ok(out)) => {
                    let st = out.status.unwrap_or(if out.findings.is_empty() {
                        CheckStatus::Passed
                    } else {
                        CheckStatus::Failed
                    });
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
    if deadline_passed(run_id) {
        bail!("run exceeded its wall-clock deadline; partial results discarded (no verdict)");
    }
    let errors = crate::logs::cluster(
        &ctx.error_lines
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default(),
    );

    // Dedup by fingerprint, then gate.
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.fingerprint.clone()));
    notes.extend(policy::apply_suppressions(
        &mut findings,
        &ctx.cfg.suppress,
        &today(),
    ));
    let bpath = opts
        .baseline
        .clone()
        .unwrap_or_else(|| default_baseline_path(&target));
    let base = Baseline::load(&bpath)?;
    if base.is_none() {
        notes.push("no baseline yet: every finding counts as new (accept one with `readyhai baseline accept <run>`)".into());
    }
    let fixed = baseline::apply(&mut findings, base.as_ref());
    findings.sort_by(|a, b| {
        (a.status as u8)
            .cmp(&(b.status as u8))
            .then(b.severity.cmp(&a.severity))
            .then(a.rule.cmp(&b.rule))
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
        let configured = crate::llm::LlmConfig::from_env()
            .ok()
            .filter(|c| c.base_url().is_ok()); // no base URL = not configured
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
            report.notes.push(
                "LLM configured but unreachable (2s probe): report is deterministic-only".into(),
            );
        }
        if let Some(c) = &cfg {
            crate::qa::ai::enrich(&mut report, &run, c);
        }
        run.qa = Some(report);
    }
    write_atomic(
        &dir.join("run.json"),
        serde_json::to_string_pretty(&run)?.as_bytes(),
    )?;
    let _ = crate::report::write(
        &run,
        &dir.join("report"),
        &["html".into(), "json".into(), "sarif".into(), "junit".into()],
    );
    crate::dashboard::append_index(&run);
    Ok(run)
}

/// READYHAI_DATA is process-global: every test that points it somewhere holds this lock.
#[cfg(test)]
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_carry_64_random_bits() {
        let id = new_run_id();
        let (ts, rand_part) = id.rsplit_once('-').unwrap();
        assert_eq!(rand_part.len(), 16, "{id}");
        assert!(rand_part.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(ts.len(), "20260101-000000".len());
        assert!(valid_run_id(&id));
        let ids: std::collections::HashSet<String> = (0..2000).map(|_| new_run_id()).collect();
        assert_eq!(ids.len(), 2000);
        // ids from older versions (16 random bits) stay valid for lookups
        assert!(valid_run_id("20261027-053327-57e2"));
        assert!(!valid_run_id("../etc") && !valid_run_id("") && !valid_run_id(&"a".repeat(64)));
    }

    #[test]
    fn write_atomic_replaces_whole_files_and_never_creates_dirs() {
        let d = std::env::temp_dir().join(format!("rh-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("status.json");
        write_atomic(&f, b"one").unwrap();
        write_atomic(&f, b"two-longer").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "two-longer");
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["status.json".to_string()],
            "no temp file may survive"
        );
        // parent gone (run deleted underneath a worker): fails, does not resurrect
        let gone = d.join("deleted-run");
        assert!(write_atomic(&gone.join("status.json"), b"x").is_err());
        assert!(!gone.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remote_repo_hosts_in_every_spelling() {
        let host = |s: &str| remote_repo_host(s).unwrap();
        assert_eq!(host("https://GitHub.com/org/x"), "github.com");
        assert_eq!(
            host("git:https://git.example.com:8443/org/x.git"),
            "git.example.com"
        );
        assert_eq!(host("git@git.example.com:org/x.git"), "git.example.com");
        assert_eq!(host("git:git@git.example.com:org/x.git"), "git.example.com");
        assert_eq!(host("deploy@git.example.com:org/x.git"), "git.example.com");
        assert_eq!(
            host("ssh://git@git.example.com:2222/org/x.git"),
            "git.example.com"
        );
        assert_eq!(
            host("git:ssh://git@git.example.com/org/x.git"),
            "git.example.com"
        );
        // the real host of a backslash URL is the part before the backslash
        assert_eq!(
            host("https://evil.example\\@git.example.com/x.git"),
            "evil.example"
        );
        for bad in [
            "git:ext::sh -c id",
            "file:///srv/x.git",
            "git@-oProxyCommand=x:org/x.git",
            "x.git",
            "git@host",
            "git@:path",
            "ftp://h/x.git",
            "git@ho st:x",
            "git@[::1]:x.git",
        ] {
            assert!(remote_repo_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn clone_url_is_the_normalised_form_of_what_was_checked() {
        assert_eq!(
            clone_url("git:https://evil.example\\@git.example.com/x.git").unwrap(),
            "https://evil.example/@git.example.com/x.git"
        );
        assert_eq!(
            clone_url("git@host:org/x.git").unwrap(),
            "git@host:org/x.git"
        );
    }

    #[test]
    fn web_targets_are_normalised_at_parse_time() {
        let t = parse_target("https://app.example\\@evil.example/x", None).unwrap();
        assert_eq!(
            t.url.as_deref(),
            Some("https://app.example/@evil.example/x")
        );
        assert!(parse_target("http://", None).is_err());
    }

    #[test]
    fn git_command_is_non_interactive() {
        let cmd = git_clone_command("git@h:o/r.git", Path::new("/tmp/x"));
        let env: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(
            env.get("GIT_SSH_COMMAND").map(String::as_str),
            Some("ssh -o BatchMode=yes")
        );
        assert_eq!(
            env.get("GIT_TERMINAL_PROMPT").map(String::as_str),
            Some("0")
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.windows(2).any(|w| w == ["-c", "credential.helper="]));
        assert!(args.iter().any(|a| a == "--"));
        assert_eq!(args[args.len() - 2], "git@h:o/r.git");
    }

    #[test]
    fn git_clone_times_out_and_does_not_leak_credentials() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        // a server that accepts and never answers: git hangs in the TLS handshake
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = vec![];
            for c in l.incoming().flatten() {
                held.push(c);
            }
        });
        let dest = std::env::temp_dir().join(format!("rh-clone-{}", std::process::id()));
        let t0 = Instant::now();
        let e = git_clone(
            &format!("https://127.0.0.1:{port}/x.git"),
            &dest,
            Duration::from_secs(2),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("timed out"), "{e}");
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
        assert!(!dest.exists());

        // refused connection: fails fast, credentials redacted from the message
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let e = git_clone(
            &format!("https://user:s3cr3tpass@127.0.0.1:{closed}/x.git"),
            &dest,
            Duration::from_secs(20),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("git clone failed"), "{e}");
        assert!(!e.contains("s3cr3tpass"), "{e}");
        assert!(git_clone("file:///etc", &dest, Duration::from_secs(1)).is_err());
        assert_eq!(
            redact_url_credentials("fatal: https://u:p@h/x and ssh://k@h/y"),
            "fatal: https://***@h/x and ssh://***@h/y"
        );
    }

    #[test]
    fn deadline_registry_follows_the_guard() {
        let id = "20990101-000000-00000000000000ff";
        assert!(run_deadline(id).is_none() && !deadline_passed(id));
        {
            let _g = DeadlineGuard::new(id, Some(Instant::now() - Duration::from_secs(1)));
            assert!(deadline_passed(id));
        }
        assert!(run_deadline(id).is_none(), "guard must unregister on drop");
        let _g = DeadlineGuard::new(id, Some(Instant::now() + Duration::from_secs(60)));
        assert!(!deadline_passed(id) && run_deadline(id).is_some());
    }

    #[test]
    fn a_scan_past_its_deadline_fails_instead_of_returning_a_partial_verdict() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = std::env::temp_dir().join(format!("rh-deadline-{}", std::process::id()));
        let target = d.join("repo");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("README.md"), "hi").unwrap();
        unsafe { std::env::set_var("READYHAI_DATA", d.join("data")) };
        let opts = ScanOpts {
            target: target.to_string_lossy().into_owned(),
            no_tools: true,
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            ..Default::default()
        };
        let id = new_run_id();
        let e = scan(&opts, &id).unwrap_err().to_string();
        assert!(e.contains("deadline"), "{e}");
        assert!(
            !run_dir(&id).join("run.json").exists(),
            "no run.json for a run that missed its deadline"
        );
        assert!(run_deadline(&id).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
