use super::policy::{Mount, mount_args, sanitize, validate_create_policy};
use super::process::{drain_capped, run_capped};
use super::types::{
    MAX_OUT_BYTES, MountMode, OutTooLarge, TOOL_STDOUT_CAP, ToolRun, ToolSpec, is_oversize,
};
use crate::ctx::Ctx;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Docker {
    pub available: bool,
    pub mode: MountMode,
    /// Shared tool cache (grype DB, semgrep rules): <data>/cache
    pub cache_dir: PathBuf,
}

pub(crate) const DOCKER_QUICK: Duration = Duration::from_secs(30);

pub(crate) fn mkdir_open(p: &Path) {
    let _ = std::fs::create_dir_all(p);
    crate::snapshot::set_mode(p, 0o777);
}

pub(crate) fn exec(
    docker: &Docker,
    run_id: &str,
    mounts: &[Mount],
    spec: &ToolSpec,
) -> Result<ToolRun> {
    exec_with("docker", TOOL_STDOUT_CAP, docker, run_id, mounts, spec)
}

/// [`exec`] with the docker binary and the stdout cap made explicit (tests drive it with a stub).
pub(crate) fn exec_with(
    bin: &str,
    stdout_cap: usize,
    docker: &Docker,
    run_id: &str,
    mounts: &[Mount],
    spec: &ToolSpec,
) -> Result<ToolRun> {
    if !docker.available {
        bail!("docker not available");
    }
    let (image, by_id) = match &spec.image {
        Some(i) => (i.clone(), false),
        None => {
            let r = super::pinning::image_ref(&spec.tool);
            if !r.1 {
                super::pinning::warn_unpinned(&spec.tool, &r.0);
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
    // Pass env by NAME only (`-e KEY`); the value is set on the docker client process below, so
    // secrets such as tokens never appear in the host's process list (`ps`, /proc/*/cmdline).
    for (k, _) in &spec.env {
        flags.push("-e".into());
        flags.push(k.clone());
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

    let mut cmd = Command::new(bin);
    cmd.arg("run").args(&flags).arg(&image).args(&spec.args);
    cmd.envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawning docker")?;
    // stdout is bounded like every other subprocess here: the head is kept up to TOOL_STDOUT_CAP,
    // the rest is drained and discarded so the child never blocks on a full pipe.
    let rx_out = drain_capped(child.stdout.take().unwrap(), stdout_cap);
    let mut err = child.stderr.take().unwrap();
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
                Command::new(bin).args(["rm", "-f", &name]),
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
    let (stdout, _, stdout_truncated) = rx_out
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    Ok(ToolRun {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stdout_truncated,
        stderr_tail: String::from_utf8_lossy(&stderr).into_owned(),
        image,
    })
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
        self.run_dirs(&ctx.run_id, &ctx.src_dir(), &ctx.out_dir(), spec)
    }

    /// [`Docker::run`] without a [`Ctx`]: `src` is mounted read-only at /src and `out` writable at
    /// /out (both must exist; in volume mode both must lie under the data volume).
    pub fn run_dirs(
        &self,
        run_id: &str,
        src: &Path,
        out: &Path,
        spec: &ToolSpec,
    ) -> Result<ToolRun> {
        mkdir_open(out);
        mkdir_open(&self.cache_dir);
        let mounts = [
            Mount {
                host: src.to_path_buf(),
                dst: "/src",
                rw: false,
            },
            Mount {
                host: out.to_path_buf(),
                dst: "/out",
                rw: true,
            },
            Mount {
                host: self.cache_dir.clone(),
                dst: "/cache",
                rw: spec.cache_rw,
            },
        ];
        exec(self, run_id, &mounts, spec)
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
    reap_label(&format!("label=readyhai.run={run_id}"), DOCKER_QUICK);
}

/// [`reap_run`] with each docker call limited to `per_call` (server shutdown has to finish inside
/// the orchestrator's stop grace period).
pub fn reap_run_within(run_id: &str, per_call: Duration) {
    reap_label(&format!("label=readyhai.run={run_id}"), per_call);
}

fn reap_label(filter: &str, per_call: Duration) {
    let Ok(o) = run_capped(
        Command::new("docker").args(["ps", "-aq", "--filter", filter]),
        per_call,
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
            per_call,
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

/// Read a tool-written text file after checking its size first. Refuses non-regular files
/// (a symlink planted in a tool's output directory must not be followed to host files), and
/// stops reading at `max + 1` bytes even if the file grows after the size check.
pub(crate) fn read_text_capped(p: &Path, max: u64) -> Result<String> {
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let meta = std::fs::symlink_metadata(p)?;
    if !meta.is_file() {
        bail!("{name} is not a regular file");
    }
    if meta.len() > max {
        return Err(OutTooLarge { name, cap: max }.into());
    }
    let mut buf = String::new();
    std::fs::File::open(p)?
        .take(max + 1)
        .read_to_string(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(OutTooLarge { name, cap: max }.into());
    }
    Ok(buf)
}

pub(crate) fn read_out(ctx: &Ctx, name: &str) -> Result<String> {
    read_text_capped(&ctx.out_dir().join(name), MAX_OUT_BYTES).map_err(|e| {
        if is_oversize(&e) {
            e
        } else {
            e.context(format!("tool did not write /out/{name}"))
        }
    })
}

/// Replace a tool output file with its scrubbed form (or delete it when it cannot be scrubbed).
/// A missing file is left alone; an oversized or unreadable one is removed rather than left behind
/// with secret-bearing text it was never possible to scrub.
pub(crate) fn rewrite_scrubbed(ctx: &Ctx, name: &str, f: impl Fn(&str) -> Option<String>) {
    let p = ctx.out_dir().join(name);
    if std::fs::symlink_metadata(&p).is_err() {
        return;
    }
    match read_text_capped(&p, MAX_OUT_BYTES) {
        Ok(t) => match f(&t) {
            Some(n) => {
                let _ = std::fs::write(&p, n);
            }
            None => {
                let _ = std::fs::remove_file(&p);
            }
        },
        Err(_) => {
            let _ = std::fs::remove_file(&p);
        }
    }
}

pub(crate) fn walk_mut(v: &mut Value, f: &mut dyn FnMut(&mut serde_json::Map<String, Value>)) {
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

pub(crate) fn scrub_keys(json: &str, keys: &[&str]) -> Option<String> {
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
