//! Sandboxed container tools, parsers, plugins (owned by the tools agent).
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{
    Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind, sha256_hex,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How tool containers reach the run directory.
#[derive(Debug, Clone)]
pub enum MountMode {
    /// CLI on a host: bind-mount host paths.
    Bind,
    /// Server in a container: named volume + subpath (Docker >= 26).
    /// `data_root` is where the volume is mounted inside this container.
    Volume { name: String, data_root: PathBuf },
}

#[derive(Debug, Clone)]
pub struct Docker {
    pub available: bool,
    pub mode: MountMode,
    /// Shared tool cache (grype DB, semgrep rules): <data>/cache
    pub cache_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ToolSpec {
    /// Key in tools.lock.toml, e.g. "grype".
    pub tool: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub network: bool,
    pub cache_rw: bool,
    pub timeout_secs: u64,
    pub memory: String,
    /// Override image (own-tests uses the target's image).
    pub image: Option<String>,
    pub entrypoint: Option<String>,
    /// Extra writable tmpfs mounts (rootfs is read-only), e.g. "/zap/wrk".
    pub tmpfs: Vec<String>,
    pub workdir: Option<String>,
    /// Map host.docker.internal to the host gateway (web targets on localhost).
    pub host_gateway: bool,
    /// Run as this uid:gid instead of 65534 (e.g. the owner of 0600 secret files).
    pub user: Option<String>,
}

impl ToolSpec {
    pub fn new(tool: &str, args: &[&str]) -> Self {
        ToolSpec {
            tool: tool.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: vec![],
            network: false,
            cache_rw: false,
            timeout_secs: 600,
            memory: "2g".into(),
            image: None,
            entrypoint: None,
            tmpfs: vec![],
            workdir: None,
            host_gateway: false,
            user: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolRun {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr_tail: String,
    #[allow(dead_code)]
    pub image: String,
}

// ---------------------------------------------------------------- lock file

const EMBEDDED_LOCK: &str = include_str!("../tools.lock.toml");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockEntry {
    pub image: String,
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub version: String,
    /// Local image ID (`sha256:...`), recorded for offline bundles where RepoDigests don't survive `docker load`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LockFile {
    #[serde(default)]
    tools: BTreeMap<String, LockEntry>,
}

/// Lock precedence: READYHAI_TOOLS_LOCK env file > <data>/tools.lock.toml (installed by `bundle import`) > embedded.
fn pick_lock_text(env_path: Option<&str>, data: &Path) -> String {
    if let Some(p) = env_path
        && let Ok(t) = std::fs::read_to_string(p)
    {
        return t;
    }
    if let Ok(t) = std::fs::read_to_string(data.join("tools.lock.toml")) {
        return t;
    }
    EMBEDDED_LOCK.to_string()
}

fn lock_text() -> String {
    let env = std::env::var("READYHAI_TOOLS_LOCK").ok();
    pick_lock_text(env.as_deref(), &crate::engine::data_dir())
}

fn load_lock() -> LockFile {
    toml::from_str(&lock_text()).unwrap_or_default()
}

/// Lock entries (tool -> entry) as currently resolved.
pub fn lock_entries() -> BTreeMap<String, LockEntry> {
    load_lock().tools
}

/// ID of a local image (`docker image inspect`), None when it is not present.
pub fn local_image_id(reference: &str) -> Option<String> {
    let o = run_capped(
        Command::new("docker").args(["image", "inspect", "--format", "{{.Id}}", reference]),
        DOCKER_QUICK,
        8192,
        None,
    )
    .ok()?;
    if !o.success() {
        return None;
    }
    let t = o.stdout_lossy().trim().to_string();
    if t.is_empty() { None } else { Some(t) }
}

/// Resolve a lock entry to (reference, pinned, by_id). `exists` tells whether a ref is present locally.
fn resolve_entry(e: &LockEntry, exists: &dyn Fn(&str) -> bool) -> (String, bool, bool) {
    if let Some(id) = e.id.as_deref().filter(|i| i.starts_with("sha256:"))
        && exists(id)
    {
        return (id.to_string(), true, true);
    }
    let (r, p) = ref_with_digest(&e.image, &e.digest);
    (r, p, false)
}

/// (reference, pinned, run-by-id) for a tool.
fn image_ref(tool: &str) -> (String, bool, bool) {
    let lock = load_lock();
    match lock.tools.get(tool) {
        Some(e) => resolve_entry(e, &|r| local_image_id(r).is_some()),
        None => (tool.to_string(), false, false),
    }
}

/// Image reference for a tool (the local image ID when the lock has one and it is loaded,
/// else repo@digest when pinned) and whether it is pinned.
pub fn image_for(tool: &str) -> (String, bool) {
    let r = image_ref(tool);
    (r.0, r.1)
}

/// True when the tool's image is available locally (by ID or by reference).
pub fn image_present(tool: &str) -> bool {
    let lock = load_lock();
    match lock.tools.get(tool) {
        Some(e) => {
            e.id.as_deref()
                .map(|i| local_image_id(i).is_some())
                .unwrap_or(false)
                || local_image_id(&ref_with_digest(&e.image, &e.digest).0).is_some()
                || local_image_id(&e.image).is_some()
        }
        None => local_image_id(tool).is_some(),
    }
}

/// Add a free-form warning to the set the engine surfaces next to pin warnings.
pub fn add_warning(w: String) {
    if let Ok(mut g) = PIN_WARNINGS.lock() {
        g.insert(w);
    }
}

fn ref_with_digest(image: &str, digest: &str) -> (String, bool) {
    if digest.starts_with("sha256:") {
        let slash = image.rfind('/').map(|i| i + 1).unwrap_or(0);
        let repo = match image[slash..].find(':') {
            Some(i) => &image[..slash + i],
            None => image,
        };
        (format!("{repo}@{digest}"), true)
    } else {
        (image.to_string(), image.contains("@sha256:"))
    }
}

static PIN_WARNINGS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn warn_unpinned(tool: &str, image: &str) {
    if let Ok(mut g) = PIN_WARNINGS.lock() {
        g.insert(format!(
            "tool image {tool} unpinned ({image}) — run `readyhai tools pull --lock`"
        ));
    }
}

/// Warnings about images that ran without a digest pin; the engine surfaces these.
pub fn pin_warnings() -> Vec<String> {
    PIN_WARNINGS
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------- docker runner

struct Mount {
    host: PathBuf,
    dst: &'static str,
    rw: bool,
}

const ALLOWED_DST: [&str; 3] = ["/src", "/out", "/cache"];

/// Defense in depth over the docker flag list (everything before the image).
pub fn validate_create_policy(args: &[String]) -> Result<()> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = args.get(i + 1).map(|s| s.as_str()).unwrap_or("");
        if a.contains("docker.sock") {
            bail!("create-policy: docker socket mount rejected");
        }
        match a {
            "--privileged" | "--privileged=true" => bail!("create-policy: --privileged rejected"),
            "--network" | "--net" | "--pid" | "--ipc" | "--userns" | "--uts" if next == "host" => {
                bail!("create-policy: host namespace rejected")
            }
            "--network=host" | "--net=host" | "--pid=host" | "--ipc=host" | "--userns=host" => {
                bail!("create-policy: host namespace rejected")
            }
            "--cap-add" => bail!("create-policy: --cap-add rejected"),
            "-v" | "--volume" => {
                let dst = next.split(':').nth(1).unwrap_or("");
                if !ALLOWED_DST.contains(&dst) {
                    bail!("create-policy: extra bind mount rejected: {next}");
                }
                i += 1;
            }
            "--mount" => {
                let dst = next
                    .split(',')
                    .find_map(|kv| {
                        kv.strip_prefix("dst=")
                            .or_else(|| kv.strip_prefix("target="))
                    })
                    .unwrap_or("");
                if !ALLOWED_DST.contains(&dst) {
                    bail!("create-policy: extra mount rejected: {next}");
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn abs(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

fn mount_args(docker: &Docker, m: &Mount) -> Result<Vec<String>> {
    let host = abs(&m.host);
    match &docker.mode {
        MountMode::Bind => Ok(vec![
            "-v".into(),
            format!(
                "{}:{}:{}",
                host.display(),
                m.dst,
                if m.rw { "rw" } else { "ro" }
            ),
        ]),
        MountMode::Volume { name, data_root } => {
            let root = abs(data_root);
            let rel = host.strip_prefix(&root).map_err(|_| {
                anyhow!(
                    "{} is outside the data volume {}",
                    host.display(),
                    root.display()
                )
            })?;
            let mut s = format!(
                "type=volume,src={name},dst={},volume-subpath={}",
                m.dst,
                rel.to_string_lossy()
            );
            if !m.rw {
                s.push_str(",readonly");
            }
            Ok(vec!["--mount".into(), s])
        }
    }
}

fn exec(docker: &Docker, run_id: &str, mounts: &[Mount], spec: &ToolSpec) -> Result<ToolRun> {
    if !docker.available {
        bail!("docker not available");
    }
    let (image, by_id) = match &spec.image {
        Some(i) => (i.clone(), false),
        None => {
            let r = image_ref(&spec.tool);
            if !r.1 {
                warn_unpinned(&spec.tool, &r.0);
            }
            (r.0, r.2)
        }
    };
    let no_pull = crate::bundle::offline() || by_id;
    let name = format!(
        "readyhai-{}-{}-{:04x}",
        sanitize(run_id),
        sanitize(&spec.tool),
        rand::random::<u16>()
    );
    let mut flags: Vec<String> = vec![];
    if no_pull {
        flags.extend(["--pull".to_string(), "never".to_string()]);
    }
    flags.extend(vec![
        "--rm".into(),
        "--name".into(),
        name.clone(),
        "--label".into(),
        format!("readyhai.run={run_id}"),
        "--network".into(),
        if spec.network {
            "bridge".into()
        } else {
            "none".into()
        },
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--read-only".into(),
        "--tmpfs".into(),
        "/tmp:rw,exec,size=1g,mode=1777".into(),
    ]);
    for t in &spec.tmpfs {
        flags.push("--tmpfs".into());
        flags.push(t.clone());
    }
    flags.extend(
        [
            "--pids-limit",
            "512",
            "--memory",
            spec.memory.as_str(),
            "--cpus",
            "2",
            "--log-driver",
            "none",
            "-e",
            "HOME=/tmp",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    flags.push("--user".into());
    flags.push(spec.user.clone().unwrap_or_else(|| "65534:65534".into()));
    for (k, v) in &spec.env {
        flags.push("-e".into());
        flags.push(format!("{k}={v}"));
    }
    if spec.host_gateway {
        flags.push("--add-host".into());
        flags.push("host.docker.internal:host-gateway".into());
    }
    if let Some(e) = &spec.entrypoint {
        flags.push("--entrypoint".into());
        flags.push(e.clone());
    }
    if let Some(w) = &spec.workdir {
        flags.push("-w".into());
        flags.push(w.clone());
    }
    for m in mounts {
        flags.extend(mount_args(docker, m)?);
    }
    validate_create_policy(&flags)?;
    if spec.args.iter().any(|a| a.contains("docker.sock")) {
        bail!("create-policy: docker socket reference in tool args rejected");
    }

    let mut cmd = Command::new("docker");
    cmd.arg("run").args(&flags).arg(&image).args(&spec.args);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawning docker")?;
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut tail: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(n) = err.read(&mut buf) {
            if n == 0 {
                break;
            }
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > 4096 {
                let cut = tail.len() - 2048;
                tail.drain(..cut);
            }
        }
        let cut = tail.len().saturating_sub(2048);
        tail.drain(..cut);
        tail
    });
    let mut deadline = Instant::now() + Duration::from_secs(spec.timeout_secs);
    // The run-wide wall-clock deadline (server worker) caps every tool, not just the next check.
    let mut run_limited = false;
    if let Some(rd) = crate::engine::run_deadline(run_id).filter(|rd| *rd < deadline) {
        deadline = rd;
        run_limited = true;
    }
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = run_capped(
                Command::new("docker").args(["rm", "-f", &name]),
                DOCKER_QUICK,
                4096,
                None,
            );
            let _ = child.kill();
            let _ = child.wait();
            if run_limited {
                bail!("run wall-clock deadline exceeded");
            }
            bail!("timeout after {}s", spec.timeout_secs);
        }
        std::thread::sleep(Duration::from_millis(150));
    };
    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    Ok(ToolRun {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr_tail: String::from_utf8_lossy(&stderr).into_owned(),
        image,
    })
}

// ---------------------------------------------------------------- bounded subprocesses

/// Result of [`run_capped`].
#[derive(Debug)]
pub struct Captured {
    /// None when the process was killed on timeout.
    pub status: Option<std::process::ExitStatus>,
    /// First `cap` bytes of stdout.
    pub stdout: Vec<u8>,
    /// Last few KiB of stdout (what `stdout` lost when `truncated`; curl's `-w` trailer lives here).
    pub stdout_tail: Vec<u8>,
    /// First `cap` bytes of stderr.
    pub stderr: Vec<u8>,
    /// stdout or stderr exceeded `cap` (the rest was drained and discarded).
    pub truncated: bool,
    pub timed_out: bool,
}

impl Captured {
    pub fn success(&self) -> bool {
        !self.timed_out && self.status.is_some_and(|s| s.success())
    }
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

const TAIL_KEEP: usize = 4096;

fn drain_capped<R: Read + Send + 'static>(
    mut r: R,
    cap: usize,
) -> std::sync::mpsc::Receiver<(Vec<u8>, Vec<u8>, bool)> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut head, mut tail, mut truncated) = (Vec::new(), Vec::new(), false);
        let mut buf = [0u8; 8192];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let room = cap.saturating_sub(head.len());
            head.extend_from_slice(&buf[..n.min(room)]);
            if n > room {
                truncated = true;
            }
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > TAIL_KEEP * 2 {
                let cut = tail.len() - TAIL_KEEP;
                tail.drain(..cut);
            }
        }
        let cut = tail.len().saturating_sub(TAIL_KEEP);
        tail.drain(..cut);
        let _ = tx.send((head, tail, truncated));
    });
    rx
}

/// Run a command with a hard wall-clock limit and bounded output. stdin is null (or `input`),
/// stdout and stderr are always piped: a child never inherits the parent's stdout, which matters
/// for the MCP server whose stdout carries only JSON-RPC. On timeout the child is killed.
pub fn run_capped(
    cmd: &mut Command,
    timeout: Duration,
    cap: usize,
    input: Option<&[u8]>,
) -> std::io::Result<Captured> {
    use std::io::Write;
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let rx_out = drain_capped(child.stdout.take().expect("piped"), cap);
    let rx_err = drain_capped(child.stderr.take().expect("piped"), cap);
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        if let Some(s) = child.try_wait()? {
            break (Some(s), false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break (None, true);
        }
        std::thread::sleep(Duration::from_millis(15));
    };
    // A grandchild may keep the pipe open after the child died: do not wait for it forever.
    let grace = Duration::from_secs(2);
    let (stdout, stdout_tail, t1) = rx_out.recv_timeout(grace).unwrap_or_default();
    let (stderr, _, t2) = rx_err.recv_timeout(grace).unwrap_or_default();
    Ok(Captured {
        status,
        stdout,
        stdout_tail,
        stderr,
        truncated: t1 || t2,
        timed_out,
    })
}

const DOCKER_QUICK: Duration = Duration::from_secs(30);

fn mkdir_open(p: &Path) {
    let _ = std::fs::create_dir_all(p);
    crate::snapshot::set_mode(p, 0o777);
}

impl Docker {
    pub fn detect(data_dir: &Path) -> Docker {
        // A wedged daemon must not hang the scan (or the MCP server): 10 s, then "unavailable".
        let available = run_capped(
            Command::new("docker").args(["version", "--format", "{{.Server.Version}}"]),
            Duration::from_secs(10),
            4096,
            None,
        )
        .map(|o| o.success() && !o.stdout.is_empty())
        .unwrap_or(false);
        let mode = match std::env::var("READYHAI_DATA_VOLUME") {
            Ok(name) if !name.is_empty() => MountMode::Volume {
                name,
                data_root: data_dir.to_path_buf(),
            },
            _ => MountMode::Bind,
        };
        let cache_dir = data_dir.join("cache");
        mkdir_open(&cache_dir);
        Docker {
            available,
            mode,
            cache_dir,
        }
    }

    pub fn run(&self, ctx: &Ctx, spec: &ToolSpec) -> Result<ToolRun> {
        let out = ctx.out_dir();
        mkdir_open(&out);
        mkdir_open(&self.cache_dir);
        let mounts = [
            Mount {
                host: ctx.src_dir(),
                dst: "/src",
                rw: false,
            },
            Mount {
                host: out,
                dst: "/out",
                rw: true,
            },
            Mount {
                host: self.cache_dir.clone(),
                dst: "/cache",
                rw: spec.cache_rw,
            },
        ];
        exec(self, &ctx.run_id, &mounts, spec)
    }

    /// `docker save` the image to a tar file (placed at /src/image.tar by the engine).
    pub fn export_image(&self, run_id: &str, image: &str, dest: &Path) -> Result<()> {
        if !self.available {
            bail!("docker not available");
        }
        // Large images take a while, but never forever: 15 min, or the run deadline if sooner.
        let mut limit = Duration::from_secs(900);
        if let Some(rd) = crate::engine::run_deadline(run_id) {
            limit = limit.min(rd.saturating_duration_since(Instant::now()));
        }
        let o = run_capped(
            Command::new("docker")
                .arg("save")
                .arg("-o")
                .arg(dest)
                .arg(image),
            limit,
            8192,
            None,
        )
        .context("docker save")?;
        if o.timed_out {
            let _ = std::fs::remove_file(dest);
            bail!("docker save {image}: timed out after {}s", limit.as_secs());
        }
        if !o.success() {
            bail!("docker save {image}: {}", o.stderr_lossy().trim());
        }
        Ok(())
    }

    /// Remove leftover containers labelled readyhai.run=<run_id>.
    pub fn reap(&self, run_id: &str) {
        reap_run(run_id);
    }
}

/// Remove containers labelled `readyhai.run=<run_id>` (end of run, run deadline, shutdown).
pub fn reap_run(run_id: &str) {
    reap_label(&format!("label=readyhai.run={run_id}"));
}

fn reap_label(filter: &str) {
    let Ok(o) = run_capped(
        Command::new("docker").args(["ps", "-aq", "--filter", filter]),
        DOCKER_QUICK,
        1 << 16,
        None,
    ) else {
        return;
    };
    let ids: Vec<String> = o
        .stdout_lossy()
        .split_whitespace()
        .map(String::from)
        .collect();
    if !ids.is_empty() {
        let _ = run_capped(
            Command::new("docker").arg("rm").arg("-f").args(&ids),
            DOCKER_QUICK,
            4096,
            None,
        );
    }
}

/// Server startup: containers labelled `readyhai.run=<id>` whose run is dead (`is_dead(id)`) were
/// orphaned by a crash or restart; remove them. Containers of runs this predicate does not claim
/// (for example a CLI scan started by someone else) are left alone.
pub fn reap_dead_runs(is_dead: &dyn Fn(&str) -> bool) -> usize {
    let Ok(o) = run_capped(
        Command::new("docker").args([
            "ps",
            "-a",
            "--filter",
            "label=readyhai.run",
            "--format",
            "{{.ID}} {{.Label \"readyhai.run\"}}",
        ]),
        DOCKER_QUICK,
        1 << 16,
        None,
    ) else {
        return 0;
    };
    if !o.success() {
        return 0;
    }
    let mut ids: Vec<String> = vec![];
    for line in o.stdout_lossy().lines() {
        if let Some((cid, run)) = line.split_once(' ')
            && is_dead(run.trim())
            && cid.chars().all(|c| c.is_ascii_hexdigit())
        {
            ids.push(cid.to_string());
        }
    }
    if !ids.is_empty() {
        let _ = run_capped(
            Command::new("docker").arg("rm").arg("-f").args(&ids),
            DOCKER_QUICK,
            4096,
            None,
        );
    }
    ids.len()
}

// ---------------------------------------------------------------- helpers

fn rel(p: &str) -> String {
    let p = p.trim_start_matches("file://");
    let p = p.strip_prefix("/src/").unwrap_or(p);
    p.trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

fn first_line(t: &str, max: usize) -> String {
    t.lines().next().unwrap_or("").chars().take(max).collect()
}

fn gate(ctx: &Ctx) -> Option<CheckOutput> {
    if !ctx.docker.available {
        return Some(CheckOutput::status(CheckStatus::Skipped(
            "docker not available".into(),
        )));
    }
    None
}

/// Skipped result when the tool's image is not available locally and we cannot pull (offline).
fn missing_image(tool: &str) -> Option<CheckOutput> {
    if crate::bundle::offline() && !image_present(tool) {
        return Some(CheckOutput::status(CheckStatus::Skipped(format!(
            "image not in bundle: {tool}"
        ))));
    }
    None
}

fn read_out(ctx: &Ctx, name: &str) -> Result<String> {
    std::fs::read_to_string(ctx.out_dir().join(name))
        .with_context(|| format!("tool did not write /out/{name}"))
}

fn tool_failed(name: &str, r: &ToolRun) -> anyhow::Error {
    anyhow!("{name} exited {}: {}", r.exit_code, r.stderr_tail.trim())
}

fn rewrite_scrubbed(ctx: &Ctx, name: &str, f: impl Fn(&str) -> Option<String>) {
    let p = ctx.out_dir().join(name);
    if let Ok(t) = std::fs::read_to_string(&p) {
        match f(&t) {
            Some(n) => {
                let _ = std::fs::write(&p, n);
            }
            None => {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

fn walk_mut(v: &mut Value, f: &mut dyn FnMut(&mut serde_json::Map<String, Value>)) {
    match v {
        Value::Object(m) => {
            f(m);
            for (_, c) in m.iter_mut() {
                walk_mut(c, f);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|c| walk_mut(c, f)),
        _ => {}
    }
}

fn scrub_keys(json: &str, keys: &[&str]) -> Option<String> {
    let mut v: Value = serde_json::from_str(json).ok()?;
    walk_mut(&mut v, &mut |m| {
        for k in keys {
            if m.contains_key(*k) {
                m.insert((*k).into(), Value::String(String::new()));
            }
        }
    });
    serde_json::to_string(&v).ok()
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

fn partial(notes: Vec<String>, findings: Vec<Finding>) -> CheckOutput {
    if notes.is_empty() {
        CheckOutput::findings(findings)
    } else {
        CheckOutput {
            status: Some(CheckStatus::Partial(notes.join("; "))),
            findings,
        }
    }
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
            if desc.is_empty() { format!("Possible secret ({rule})") } else { desc.to_string() },
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

pub fn parse_semgrep(json: &str) -> Result<Vec<Finding>> {
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
        // semgrep prefixes ids with the rules-file path (`cache.semgrep.<id>`)
        let rule = s(&r, "check_id");
        let rule = rule.strip_prefix("cache.semgrep.").unwrap_or(rule);
        let f = Finding::new(
            "tool.semgrep",
            rule,
            Category::Security,
            sev,
            first_line(s(&extra, "message"), 200),
            format!("{path}:{line}"),
        )
        .fp_key(format!("{path}|{}", &h[..16]));
        out.push(f);
    }
    Ok(out)
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

// ---------------------------------------------------------------- JUnit

pub struct JunitCase {
    pub suite: String,
    pub name: String,
    pub failed: bool,
    pub errored: bool,
    pub skipped: bool,
    pub message: String,
}

fn unescape(t: &str) -> String {
    t.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn attr(attrs: &str, name: &str) -> String {
    let re = regex::Regex::new(&format!(
        r#"(?:^|\s){}\s*=\s*(?:"([^"]*)"|'([^']*)')"#,
        regex::escape(name)
    ))
    .unwrap();
    re.captures(attrs)
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| unescape(m.as_str()))
        .unwrap_or_default()
}

pub fn parse_junit(xml: &str) -> Vec<JunitCase> {
    let case_re = regex::Regex::new(r"(?s)<testcase\b([^>]*?)(?:/>|>(.*?)</testcase>)").unwrap();
    let child_re = regex::Regex::new(r"(?s)<(failure|error|skipped)\b([^>]*?)(?:/>|>)").unwrap();
    let mut out = vec![];
    for c in case_re.captures_iter(xml) {
        let attrs = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = c.get(2).map(|m| m.as_str()).unwrap_or("");
        let mut case = JunitCase {
            suite: attr(attrs, "classname"),
            name: attr(attrs, "name"),
            failed: false,
            errored: false,
            skipped: false,
            message: String::new(),
        };
        for ch in child_re.captures_iter(body) {
            match &ch[1] {
                "failure" => case.failed = true,
                "error" => case.errored = true,
                _ => case.skipped = true,
            }
            if case.message.is_empty() {
                case.message = attr(&ch[2], "message");
            }
        }
        out.push(case);
    }
    out
}

// ---------------------------------------------------------------- SARIF

pub fn parse_sarif(json: &str, check: &str) -> Result<Vec<Finding>> {
    let v: Value = serde_json::from_str(json)?;
    let mut out = vec![];
    for run in v
        .get("runs")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        for r in run
            .get("results")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let rule = s(&r, "ruleId");
            let sev = match s(&r, "level") {
                "error" => Severity::High,
                "warning" => Severity::Medium,
                "note" => Severity::Low,
                "none" => Severity::Info,
                _ => Severity::Medium,
            };
            let msg = r.get("message").map(|m| s(m, "text")).unwrap_or("");
            let loc = r
                .get("locations")
                .and_then(|l| l.as_array())
                .and_then(|l| l.first())
                .and_then(|l| l.get("physicalLocation"));
            let (uri, line) = match loc {
                Some(p) => (
                    rel(p.get("artifactLocation").map(|a| s(a, "uri")).unwrap_or("")),
                    p.get("region")
                        .and_then(|g| g.get("startLine"))
                        .and_then(|x| x.as_u64()),
                ),
                None => (String::new(), None),
            };
            let location = match (uri.is_empty(), line) {
                (true, _) => "unknown".to_string(),
                (false, Some(l)) => format!("{uri}:{l}"),
                (false, None) => uri.clone(),
            };
            out.push(
                Finding::new(
                    check,
                    rule,
                    Category::Security,
                    sev,
                    first_line(msg, 200),
                    location,
                )
                .fp_key(format!("{uri}|{rule}|{}", &sha256_hex(msg.as_bytes())[..8])),
            );
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- checks

/// Age in days of the grype DB under `<cache>/grype` (mtime of `vulnerability.db` / `metadata.json`,
/// falling back to the newest file in the tree).
pub fn db_age_days(cache: &Path) -> Option<u64> {
    let files: Vec<_> = walkdir::WalkDir::new(cache.join("grype"))
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    let key = |n: &str| {
        files
            .iter()
            .filter(|e| e.file_name().to_str() == Some(n))
            .filter_map(|e| e.metadata().ok()?.modified().ok())
            .max()
    };
    let newest = key("vulnerability.db")
        .or_else(|| key("metadata.json"))
        .or_else(|| {
            files
                .iter()
                .filter_map(|e| e.metadata().ok()?.modified().ok())
                .max()
        })?;
    Some(
        std::time::SystemTime::now()
            .duration_since(newest)
            .ok()?
            .as_secs()
            / 86400,
    )
}

fn has_rules(cache: &Path) -> bool {
    std::fs::read_dir(cache.join("semgrep"))
        .map(|d| {
            d.filter_map(|e| e.ok()).any(|e| {
                let p = e.path();
                matches!(p.extension().and_then(|x| x.to_str()), Some("yml" | "yaml"))
            })
        })
        .unwrap_or(false)
}

fn repo_like() -> Vec<TargetKind> {
    vec![TargetKind::Repo]
}

pub fn checks() -> Vec<Check> {
    let mut v = vec![];

    v.push(
        Check::new(
            "tool.gitleaks",
            "Secret scan (gitleaks)",
            &repo_like(),
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("gitleaks") {
                    return Ok(o);
                }
                let mut spec = ToolSpec::new(
                    "gitleaks",
                    &[
                        "dir",
                        "/src",
                        "--redact",
                        "--no-banner",
                        "--exit-code",
                        "0",
                        "--report-format",
                        "json",
                        "--report-path",
                        "/out/gitleaks.json",
                    ],
                );
                spec.timeout_secs = 300;
                let r = ctx.docker.run(ctx, &spec)?;
                let txt = match read_out(ctx, "gitleaks.json") {
                    Ok(t) => t,
                    Err(_) if r.exit_code != 0 => return Err(tool_failed("gitleaks", &r)),
                    Err(_) => "[]".into(),
                };
                let f = parse_gitleaks(&txt);
                rewrite_scrubbed(ctx, "gitleaks.json", scrub_gitleaks);
                Ok(CheckOutput::findings(f?))
            },
        )
        .tool("gitleaks"),
    );

    v.push(
        Check::new(
            "tool.sbom_cve",
            "SBOM + known vulnerabilities (syft + grype)",
            &[TargetKind::Repo, TargetKind::Image],
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                let cache = &ctx.docker.cache_dir;
                for t in ["syft", "grype"] {
                    if let Some(o) = missing_image(t) {
                        return Ok(o);
                    }
                }
                if !cache.join("grype").is_dir() {
                    return Ok(CheckOutput::status(CheckStatus::Skipped(
                        "vuln DB missing: run `readyhai tools update`".into(),
                    )));
                }
                let source = if ctx.target.kind == TargetKind::Image {
                    "docker-archive:/src/image.tar"
                } else {
                    "dir:/src"
                };
                let mut syft = ToolSpec::new(
                    "syft",
                    &["scan", source, "-o", "cyclonedx-json=/out/sbom.cdx.json"],
                );
                syft.env
                    .push(("SYFT_CHECK_FOR_APP_UPDATE".into(), "false".into()));
                let r = ctx.docker.run(ctx, &syft)?;
                if r.exit_code != 0 {
                    return Err(tool_failed("syft", &r));
                }
                let mut grype = ToolSpec::new(
                    "grype",
                    &[
                        "sbom:/out/sbom.cdx.json",
                        "-o",
                        "json",
                        "--file",
                        "/out/grype.json",
                    ],
                );
                grype.env = vec![
                    ("GRYPE_DB_CACHE_DIR".into(), "/cache/grype".into()),
                    ("GRYPE_DB_AUTO_UPDATE".into(), "false".into()),
                    ("GRYPE_CHECK_FOR_APP_UPDATE".into(), "false".into()),
                ];
                if crate::bundle::offline() {
                    // ReadyHai does its own age check below; the offline DB is legitimately old.
                    grype
                        .env
                        .push(("GRYPE_DB_VALIDATE_AGE".into(), "false".into()));
                }
                let r = ctx.docker.run(ctx, &grype)?;
                if r.exit_code != 0 {
                    return Err(tool_failed("grype", &r));
                }
                let findings = parse_grype(&read_out(ctx, "grype.json")?)?;
                let mut notes = vec![];
                if ctx.facts.unpinned_deps > 0 {
                    notes.push(format!(
                        "{} of {} deps unpinned; CVE coverage incomplete — scan the built image",
                        ctx.facts.unpinned_deps, ctx.facts.total_deps
                    ));
                }
                if let Some(d) = db_age_days(cache) {
                    if d > 7 {
                        let how = if crate::bundle::offline() {
                            "import a fresh bundle"
                        } else {
                            "run `readyhai tools update`"
                        };
                        notes.push(format!("vuln DB is {d} days old; {how}"));
                    }
                    if d > 30 {
                        add_warning(format!("vuln DB is {d} days old — CVE coverage is stale"));
                    }
                }
                Ok(partial(notes, findings))
            },
        )
        .tool("grype"),
    );

    v.push(
        Check::new(
            "tool.semgrep",
            "Static analysis (semgrep)",
            &repo_like(),
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("semgrep") {
                    return Ok(o);
                }
                if !has_rules(&ctx.docker.cache_dir) {
                    return Ok(CheckOutput::status(CheckStatus::Skipped(
                        "rules missing: run `readyhai tools update`".into(),
                    )));
                }
                let mut spec = ToolSpec::new(
                    "semgrep",
                    &[
                        "scan",
                        "--config",
                        "/cache/semgrep",
                        "--metrics=off",
                        "--disable-version-check",
                        "--json",
                        "-o",
                        "/out/semgrep.json",
                        "/src",
                    ],
                );
                spec.entrypoint = Some("semgrep".into());
                spec.memory = "3g".into();
                spec.timeout_secs = 900;
                let r = ctx.docker.run(ctx, &spec)?;
                let txt = read_out(ctx, "semgrep.json").map_err(|_| tool_failed("semgrep", &r))?;
                let f = parse_semgrep(&txt);
                rewrite_scrubbed(ctx, "semgrep.json", scrub_semgrep);
                Ok(CheckOutput::findings(f?))
            },
        )
        .tool("semgrep"),
    );

    v.push(
        Check::new(
            "tool.hadolint",
            "Dockerfile lint (hadolint)",
            &repo_like(),
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("hadolint") {
                    return Ok(o);
                }
                if ctx.facts.dockerfiles.is_empty() {
                    return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                        "no Dockerfiles".into(),
                    )));
                }
                let mut spec = ToolSpec::new("hadolint", &["-f", "json", "--no-fail"]);
                spec.entrypoint = Some("/bin/hadolint".into());
                for d in &ctx.facts.dockerfiles {
                    spec.args.push(format!("/src/{d}"));
                }
                let r = ctx.docker.run(ctx, &spec)?;
                if r.stdout.trim().is_empty() && r.exit_code != 0 {
                    return Err(tool_failed("hadolint", &r));
                }
                Ok(CheckOutput::findings(parse_hadolint(&r.stdout)?))
            },
        )
        .tool("hadolint"),
    );

    v.push(
        Check::new(
            "tool.checkov",
            "IaC misconfiguration (checkov)",
            &repo_like(),
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("checkov") {
                    return Ok(o);
                }
                let f = &ctx.facts;
                let tf = ctx
                    .snapshot
                    .as_ref()
                    .map(|s| s.files.iter().any(|p| p.ends_with(".tf")))
                    .unwrap_or(false);
                if f.k8s_files.is_empty()
                    && f.compose_files.is_empty()
                    && f.dockerfiles.is_empty()
                    && !tf
                {
                    return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                        "no k8s/compose/Dockerfile/terraform files".into(),
                    )));
                }
                let mut spec = ToolSpec::new(
                    "checkov",
                    &[
                        "-d",
                        "/src",
                        "--skip-framework",
                        "secrets",
                        "--skip-download",
                        "--quiet",
                        "--soft-fail",
                        "-o",
                        "json",
                        "--output-file-path",
                        "/out",
                    ],
                );
                spec.entrypoint = Some("checkov".into());
                spec.env
                    .push(("CKV_IGNORE_HIDDEN_DIRECTORIES".into(), "true".into()));
                let r = ctx.docker.run(ctx, &spec)?;
                let txt =
                    read_out(ctx, "results_json.json").map_err(|_| tool_failed("checkov", &r))?;
                let found = parse_checkov(&txt);
                rewrite_scrubbed(ctx, "results_json.json", scrub_checkov);
                Ok(CheckOutput::findings(found?))
            },
        )
        .tool("checkov"),
    );

    v.push(
        Check::new(
            "tool.dockle",
            "Image best practices (dockle)",
            &[TargetKind::Image],
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("dockle") {
                    return Ok(o);
                }
                let mut spec = ToolSpec::new(
                    "dockle",
                    &[
                        "-f",
                        "json",
                        "-o",
                        "/out/dockle.json",
                        "--input",
                        "/src/image.tar",
                        "--exit-code",
                        "0",
                    ],
                );
                spec.entrypoint = Some("dockle".into());
                let r = ctx.docker.run(ctx, &spec)?;
                let txt = read_out(ctx, "dockle.json").map_err(|_| tool_failed("dockle", &r))?;
                let image = ctx
                    .target
                    .image
                    .clone()
                    .unwrap_or_else(|| ctx.target.raw.clone());
                Ok(CheckOutput::findings(parse_dockle(&txt, &image)?))
            },
        )
        .tool("dockle"),
    );

    v.push(
        Check::new(
            "image.inspect",
            "Image configuration",
            &[TargetKind::Image],
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                let Some(image) = ctx.target.image.clone() else {
                    return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                        "no image".into(),
                    )));
                };
                let o = run_capped(
                    Command::new("docker").args(["image", "inspect", &image]),
                    DOCKER_QUICK,
                    8 << 20,
                    None,
                )?;
                if !o.success() {
                    bail!(
                        "docker image inspect {image}: {}",
                        if o.timed_out {
                            "timed out".to_string()
                        } else {
                            o.stderr_lossy().trim().to_string()
                        }
                    );
                }
                Ok(CheckOutput::findings(parse_image_inspect(
                    &o.stdout_lossy(),
                    &image,
                )?))
            },
        )
        .tool("docker"),
    );

    v.push(Check::new(
        "tests.own",
        "Project's own tests",
        &repo_like(),
        Profile::Standard,
        |ctx| {
            if let Some(o) = gate(ctx) {
                return Ok(o);
            }
            let Some(t) = ctx.cfg.test.clone() else {
                return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                    "add [test] image+command to readyhai.toml".into(),
                )));
            };
            let mut spec = ToolSpec::new("tests", &["-c", &t.command]);
            spec.image = Some(t.image.clone());
            spec.entrypoint = Some("sh".into());
            spec.network = t.network;
            spec.workdir = Some("/src".into());
            spec.timeout_secs = t.timeout_secs;
            // /src is read-only: tests must write caches (pytest, .pyc, node_modules/.cache) to /tmp.
            let r = ctx.docker.run(ctx, &spec)?;
            let Ok(xml) = read_out(ctx, "junit.xml") else {
                return Ok(CheckOutput::status(CheckStatus::Errored(format!(
                    "no /out/junit.xml (exit {}; /src is read-only, write caches to /tmp): {}",
                    r.exit_code,
                    first_line(r.stderr_tail.trim(), 200)
                ))));
            };
            Ok(junit_output(&xml, r.exit_code))
        },
    ));

    v
}

pub fn junit_output(xml: &str, exit_code: i32) -> CheckOutput {
    let cases = parse_junit(xml);
    if cases.is_empty() {
        return CheckOutput::status(CheckStatus::Errored(format!(
            "junit.xml has no test cases (exit {exit_code})"
        )));
    }
    let failed: Vec<&JunitCase> = cases.iter().filter(|c| c.failed).collect();
    let errors = cases.iter().filter(|c| c.errored).count();
    if failed.is_empty() && errors > 0 {
        return CheckOutput::status(CheckStatus::Errored(format!(
            "{errors} test errors (environment?)"
        )));
    }
    let findings = failed
        .iter()
        .map(|c| {
            Finding::new(
                "tests.own",
                "tests.failed",
                Category::Quality,
                Severity::High,
                format!("Test failed: {}", c.name),
                format!("{}::{}", c.suite, c.name),
            )
            .detail(first_line(&c.message, 300))
            .fp_key(format!("{}::{}", c.suite, c.name))
        })
        .collect();
    CheckOutput::findings(findings)
}

// ---------------------------------------------------------------- plugins

#[derive(Debug, Clone, Deserialize)]
struct Plugin {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    profile: String,
    image: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    network: bool,
    #[serde(default)]
    entrypoint: Option<String>,
    output: String,
    format: String,
}

fn run_plugin(ctx: &Ctx, p: &Plugin) -> Result<CheckOutput> {
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
    let txt = read_out(ctx, name).map_err(|_| tool_failed(&p.id, &r))?;
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

// ---------------------------------------------------------------- pull / update

/// `readyhai tools pull [--lock]`
pub fn tools_pull(write_lock: Option<&Path>) -> Result<()> {
    tools_pull_filtered(write_lock, None)
}

/// Like `tools_pull`, restricted to the named tools (the rest of the lock is kept as-is).
pub fn tools_pull_filtered(
    write_lock: Option<&Path>,
    only: Option<&BTreeSet<String>>,
) -> Result<()> {
    if crate::bundle::offline() {
        bail!("offline mode: use `readyhai bundle import`");
    }
    let mut lock = load_lock();
    for (name, e) in lock.tools.iter_mut() {
        if only.is_some_and(|o| !o.contains(name)) {
            continue;
        }
        eprintln!("pulling {name}: {}", e.image);
        let st = Command::new("docker")
            .args(["pull", &e.image])
            .status()
            .context("docker pull")?;
        if !st.success() {
            eprintln!("  pull failed for {}", e.image);
            if write_lock.is_some() {
                e.id = local_image_id(&e.image);
            }
            continue;
        }
        if write_lock.is_some() {
            let o = Command::new("docker")
                .args([
                    "image",
                    "inspect",
                    "--format",
                    "{{index .RepoDigests 0}}",
                    &e.image,
                ])
                .output()?;
            let t = String::from_utf8_lossy(&o.stdout);
            if let Some((_, d)) = t.trim().split_once('@') {
                e.digest = d.to_string();
            }
            e.id = local_image_id(&e.image);
        }
    }
    if let Some(p) = write_lock {
        let body = toml::to_string_pretty(&lock)?;
        std::fs::write(
            p,
            format!(
                "# Pinned tool images (digests written by `readyhai tools pull --lock`).\n{body}"
            ),
        )?;
        eprintln!("wrote {}", p.display());
    }
    Ok(())
}

/// `readyhai tools update` — the only networked step: vuln DBs + rule packs into cache.
pub fn tools_update(docker: &Docker) -> Result<()> {
    if crate::bundle::offline() {
        bail!("offline mode: use `readyhai bundle import`");
    }
    mkdir_open(&docker.cache_dir);
    mkdir_open(&docker.cache_dir.join("grype"));
    mkdir_open(&docker.cache_dir.join("semgrep"));
    if docker.available {
        let mut spec = ToolSpec::new("grype", &["db", "update"]);
        spec.timeout_secs = 3600; // slow links: the DB is a ~100 MB+ download
        spec.network = true;
        spec.cache_rw = true;
        spec.env = vec![
            ("GRYPE_DB_CACHE_DIR".into(), "/cache/grype".into()),
            ("GRYPE_CHECK_FOR_APP_UPDATE".into(), "false".into()),
        ];
        let mounts = [Mount {
            host: docker.cache_dir.clone(),
            dst: "/cache",
            rw: true,
        }];
        let r = exec(docker, "update", &mounts, &spec)?;
        if r.exit_code != 0 {
            bail!("grype db update failed: {}", r.stderr_tail.trim());
        }
        eprintln!("grype DB updated");
    } else {
        eprintln!("docker not available: skipping grype DB update");
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(180))
        .user_agent("readyhai")
        .build()?;
    let resp = client
        .get("https://semgrep.dev/c/p/default")
        .send()?
        .error_for_status()?;
    let body = resp.text()?;
    if body.trim().is_empty() {
        bail!("empty semgrep ruleset");
    }
    std::fs::write(docker.cache_dir.join("semgrep").join("default.yml"), body)?;
    eprintln!("semgrep rules updated");
    match crate::host::fetch_lynis(&docker.cache_dir) {
        Ok(()) => eprintln!("lynis tarball cached (checksum recorded, upstream publishes none)"),
        Err(e) => eprintln!("lynis fetch failed (host.lynis will be skipped): {e:#}"),
    }
    Ok(())
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------- run_capped

    #[test]
    fn run_capped_kills_on_timeout() {
        let t0 = Instant::now();
        let o = run_capped(
            Command::new("sh").args(["-c", "sleep 30"]),
            Duration::from_millis(300),
            1024,
            None,
        )
        .unwrap();
        assert!(o.timed_out && !o.success() && o.status.is_none());
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    }

    #[test]
    fn run_capped_bounds_output_and_keeps_the_tail() {
        // ~2 MiB of output with cap 1 KiB: head capped, tail retained, child not blocked
        let o = run_capped(
            Command::new("sh").args(["-c", "yes abcdefgh | head -c 2000000; echo END-MARKER"]),
            Duration::from_secs(20),
            1024,
            None,
        )
        .unwrap();
        assert!(o.success() && o.truncated);
        assert_eq!(o.stdout.len(), 1024);
        assert!(String::from_utf8_lossy(&o.stdout_tail).contains("END-MARKER"));
    }

    #[test]
    fn run_capped_stdin_is_null_and_stdout_is_captured() {
        // `cat` would hang on an inherited terminal/pipe; with null stdin it returns at once
        let o = run_capped(&mut Command::new("cat"), Duration::from_secs(5), 1024, None).unwrap();
        assert!(o.success() && o.stdout.is_empty());
        let o = run_capped(
            &mut Command::new("cat"),
            Duration::from_secs(5),
            1024,
            Some(b"piped in"),
        )
        .unwrap();
        assert_eq!(o.stdout_lossy(), "piped in");
        let o = run_capped(
            Command::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]),
            Duration::from_secs(5),
            1024,
            None,
        )
        .unwrap();
        assert_eq!(
            (
                o.stdout_lossy().trim(),
                o.stderr_lossy().trim(),
                o.status.and_then(|s| s.code())
            ),
            ("out", "err", Some(3))
        );
        assert!(
            run_capped(
                &mut Command::new("/nonexistent/binary"),
                Duration::from_secs(1),
                10,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn run_capped_does_not_wait_for_a_grandchild_holding_the_pipe() {
        // the shell exits at once but leaves `sleep` holding stdout open
        let t0 = Instant::now();
        let o = run_capped(
            Command::new("sh").args(["-c", "sleep 20 & echo started"]),
            Duration::from_secs(10),
            1024,
            None,
        )
        .unwrap();
        assert!(o.success());
        assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
    }

    const SECRET: &str = "FAKE-SECRET-VALUE-9f8e7d6c";
    const GITLEAKS: &str = include_str!("../tests/fixtures/tool-outputs/gitleaks.json");
    const GRYPE: &str = include_str!("../tests/fixtures/tool-outputs/grype.json");
    const SEMGREP: &str = include_str!("../tests/fixtures/tool-outputs/semgrep.json");
    const HADOLINT: &str = include_str!("../tests/fixtures/tool-outputs/hadolint.json");
    const CHECKOV: &str = include_str!("../tests/fixtures/tool-outputs/checkov.json");
    const DOCKLE: &str = include_str!("../tests/fixtures/tool-outputs/dockle.json");
    const JUNIT: &str = include_str!("../tests/fixtures/tool-outputs/junit.xml");
    const SARIF: &str = include_str!("../tests/fixtures/tool-outputs/sarif.json");

    fn dump(f: &[Finding]) -> String {
        serde_json::to_string(f).unwrap()
    }
    fn fin(mut v: Vec<Finding>) -> Vec<Finding> {
        v.iter_mut().for_each(|f| f.finalize());
        v
    }

    #[test]
    fn policy_rejects_bad_args() {
        let v = |a: &[&str]| {
            validate_create_policy(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert!(v(&["--privileged"]).is_err());
        assert!(v(&["--network", "host"]).is_err());
        assert!(v(&["--network=host"]).is_err());
        assert!(v(&["-v", "/var/run/docker.sock:/var/run/docker.sock"]).is_err());
        assert!(v(&["-v", "/etc:/etc:ro"]).is_err());
        assert!(v(&["--mount", "type=bind,src=/,dst=/host"]).is_err());
        assert!(
            v(&[
                "-v",
                "/a/b:/src:ro",
                "--network",
                "none",
                "--cap-drop",
                "ALL"
            ])
            .is_ok()
        );
    }

    #[test]
    fn lock_loads_and_pins() {
        let (img, pinned) = image_for("grype");
        // tools.lock.toml pins grype by digest
        assert!(img.starts_with("anchore/grype@sha256:"), "{img}");
        assert!(pinned);
        assert_eq!(
            ref_with_digest("a/b:1.0", "sha256:abc"),
            ("a/b@sha256:abc".to_string(), true)
        );
        assert_eq!(
            ref_with_digest("localhost:5000/b:1.0", "sha256:abc").0,
            "localhost:5000/b@sha256:abc"
        );
    }

    #[test]
    fn gitleaks_golden() {
        let f = fin(parse_gitleaks(GITLEAKS).unwrap());
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].rule, "secrets.aws-access-token");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].location, "config/settings.py:12");
        assert!(!dump(&f).contains(SECRET));
        let scrubbed = scrub_gitleaks(GITLEAKS).unwrap();
        assert!(!scrubbed.contains(SECRET));
    }

    #[test]
    fn grype_golden_and_fp_stability() {
        let f = fin(parse_grype(GRYPE).unwrap());
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].rule, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].fix_version.as_deref(), Some("2.31.0"));
        assert_eq!(f[0].epss, Some(0.0123));
        assert_eq!(f[0].category, Category::SupplyChain);
        assert!(f[0].ids.contains(&"CVE-2024-35195".to_string()));
        assert_eq!(f[0].location, "requirements.txt");
        assert!(f[1].kev);
        assert_eq!(f[1].category, Category::Security);
        assert_eq!(f[1].severity, Severity::Critical);
        let g = fin(parse_grype(&GRYPE.replace("2.25.0", "2.26.0")).unwrap());
        assert_eq!(f[0].fingerprint, g[0].fingerprint);
        assert_ne!(f[0].version, g[0].version);
    }

    #[test]
    fn semgrep_golden() {
        let f = fin(parse_semgrep(SEMGREP).unwrap());
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[1].severity, Severity::Medium);
        assert_eq!(f[0].location, "app/db.py:42");
        assert!(!dump(&f).contains(SECRET));
        assert!(!scrub_semgrep(SEMGREP).unwrap().contains(SECRET));
        // line-number shift keeps the fingerprint
        let g = fin(parse_semgrep(&SEMGREP.replace("\"line\":42", "\"line\":50")).unwrap());
        assert_eq!(f[0].fingerprint, g[0].fingerprint);
    }

    #[test]
    fn hadolint_golden() {
        let f = parse_hadolint(HADOLINT).unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].location, "Dockerfile:1");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[1].category, Category::Security);
        assert_eq!(f[2].severity, Severity::High);
        assert_eq!(f[2].location, "sub/Dockerfile:3");
    }

    #[test]
    fn checkov_golden() {
        let f = parse_checkov(CHECKOV).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].rule, "CKV_K8S_23");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].location, "deploy/app.yaml:1");
        assert_eq!(f[1].severity, Severity::High);
        assert!(!dump(&f).contains(SECRET));
        assert!(!scrub_checkov(CHECKOV).unwrap().contains(SECRET));
        // list form
        let l = format!("[{CHECKOV}]");
        assert_eq!(parse_checkov(&l).unwrap().len(), 2);
    }

    #[test]
    fn dockle_golden() {
        let f = parse_dockle(DOCKLE, "app:1").unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[1].severity, Severity::High);
        assert_eq!(f[2].severity, Severity::Low);
        assert_eq!(f[0].location, "app:1");
    }

    #[test]
    fn image_inspect_rules() {
        let j = r#"[{"Size":2000000000,"Config":{"User":"","Healthcheck":null}}]"#;
        let f = parse_image_inspect(j, "myapp:latest").unwrap();
        let rules: Vec<&str> = f.iter().map(|x| x.rule.as_str()).collect();
        for r in [
            "image.root_user",
            "image.no_healthcheck",
            "image.large",
            "image.latest_tag",
        ] {
            assert!(rules.contains(&r), "{r}");
        }
        let ok = r#"[{"Size":10,"Config":{"User":"1000","Healthcheck":{"Test":["CMD","true"]}}}]"#;
        assert!(parse_image_inspect(ok, "myapp:1.2").unwrap().is_empty());
    }

    #[test]
    fn junit_golden() {
        let c = parse_junit(JUNIT);
        assert_eq!(c.len(), 4);
        assert!(c[1].failed);
        assert_eq!(c[1].message, "assert 1 < 0 && \"x\"");
        assert_eq!(c[1].suite, "tests.test_a");
        assert!(c[2].errored && !c[2].failed);
        assert!(c[3].skipped);
        let o = junit_output(JUNIT, 1);
        assert_eq!(o.findings.len(), 1);
        assert_eq!(o.findings[0].rule, "tests.failed");
        assert_eq!(o.findings[0].location, "tests.test_a::test_bad");
        let errs = r#"<testsuite><testcase classname="a" name="b"><error message="x"/></testcase></testsuite>"#;
        assert!(matches!(
            junit_output(errs, 1).status,
            Some(CheckStatus::Errored(_))
        ));
    }

    #[test]
    fn sarif_golden() {
        let f = parse_sarif(SARIF, "plugin.x").unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].rule, "XR001");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].location, "a/b.py:5");
        assert_eq!(f[1].severity, Severity::Low);
    }

    #[test]
    fn plugin_loading() {
        let dir = std::env::temp_dir().join(format!("readyhai-plug-{:08x}", rand::random::<u32>()));
        let p = dir.join("demo");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(
            p.join("plugin.toml"),
            r#"
id = "demo"
title = "Demo plugin"
kinds = ["repo", "image"]
profile = "quick"
image = "example/demo@sha256:0000"
args = ["--src", "{src}", "--out", "{out}/demo.sarif"]
network = false
output = "/out/demo.sarif"
format = "sarif"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("bad")).unwrap();
        std::fs::write(dir.join("bad").join("plugin.toml"), "not toml [").unwrap();
        let c = plugin_checks(&dir);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].id, "plugin.demo");
        assert_eq!(c[0].kinds, vec![TargetKind::Repo, TargetKind::Image]);
        assert_eq!(c[0].min_profile, Profile::Quick);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_precedence_env_data_embedded() {
        let d = std::env::temp_dir().join(format!("rh-lockprec-{:08x}", rand::random::<u32>()));
        std::fs::create_dir_all(&d).unwrap();
        // embedded
        assert!(pick_lock_text(None, &d).contains("anchore/grype"));
        // data dir lock beats embedded
        std::fs::write(
            d.join("tools.lock.toml"),
            "[tools.grype]\nimage=\"data/grype:1\"\n",
        )
        .unwrap();
        assert!(pick_lock_text(None, &d).contains("data/grype:1"));
        // env beats data dir
        let e = d.join("env.toml");
        std::fs::write(&e, "[tools.grype]\nimage=\"env/grype:1\"\n").unwrap();
        assert!(pick_lock_text(e.to_str(), &d).contains("env/grype:1"));
        // unreadable env falls through
        assert!(pick_lock_text(Some("/nonexistent/x"), &d).contains("data/grype:1"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn image_resolves_by_id_when_present() {
        let e = LockEntry {
            image: "anchore/grype:latest".into(),
            digest: "sha256:aaa".into(),
            version: "x".into(),
            id: Some("sha256:bbb".into()),
        };
        let (r, pinned, by_id) = resolve_entry(&e, &|r| r == "sha256:bbb");
        assert_eq!((r.as_str(), pinned, by_id), ("sha256:bbb", true, true));
        // id not loaded -> falls back to digest ref
        let (r, pinned, by_id) = resolve_entry(&e, &|_| false);
        assert_eq!(
            (r.as_str(), pinned, by_id),
            ("anchore/grype@sha256:aaa", true, false)
        );
        // no id -> tag, unpinned
        let e2 = LockEntry {
            image: "a/b:1".into(),
            ..Default::default()
        };
        assert_eq!(
            resolve_entry(&e2, &|_| true),
            ("a/b:1".to_string(), false, false)
        );
    }

    #[test]
    fn offline_refuses_pull_and_update() {
        let _g = crate::bundle::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("READYHAI_OFFLINE", "1") };
        let e1 = tools_pull(None).unwrap_err().to_string();
        let d = Docker {
            available: false,
            mode: MountMode::Bind,
            cache_dir: std::env::temp_dir().join("rh-off-cache"),
        };
        let e2 = tools_update(&d).unwrap_err().to_string();
        unsafe { std::env::remove_var("READYHAI_OFFLINE") };
        assert!(e1.contains("bundle import"), "{e1}");
        assert!(e2.contains("bundle import"), "{e2}");
    }

    #[test]
    fn db_age_from_metadata() {
        let d = std::env::temp_dir().join(format!("rh-dbage-{:08x}", rand::random::<u32>()));
        std::fs::create_dir_all(d.join("grype/6")).unwrap();
        assert_eq!(db_age_days(&d), None);
        std::fs::write(d.join("grype/6/vulnerability.db"), "x").unwrap();
        assert_eq!(db_age_days(&d), Some(0));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn builtin_checks_registered() {
        let ids: Vec<String> = checks().into_iter().map(|c| c.id).collect();
        for i in [
            "tool.gitleaks",
            "tool.sbom_cve",
            "tool.semgrep",
            "tool.hadolint",
            "tool.checkov",
            "tool.dockle",
            "image.inspect",
            "tests.own",
        ] {
            assert!(ids.iter().any(|x| x == i), "{i}");
        }
    }
}
