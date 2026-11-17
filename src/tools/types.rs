use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus, Finding};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

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

/// Most stdout a tool container may return before the rest is discarded (see [`ToolRun::stdout_truncated`]).
pub const TOOL_STDOUT_CAP: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ToolRun {
    pub exit_code: i32,
    pub stdout: String,
    /// stdout exceeded [`TOOL_STDOUT_CAP`]: `stdout` holds only its head and is not valid to parse.
    pub stdout_truncated: bool,
    pub stderr_tail: String,
    #[allow(dead_code)]
    pub image: String,
}

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
pub(crate) struct LockFile {
    #[serde(default)]
    pub(crate) tools: BTreeMap<String, LockEntry>,
}

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

pub struct JunitCase {
    pub suite: String,
    pub name: String,
    pub failed: bool,
    pub errored: bool,
    pub skipped: bool,
    pub message: String,
}

/// Largest tool output file read into memory. Bigger outputs are not parsed: the check reports
/// `Partial` (see [`OutTooLarge`]) instead of exhausting memory or silently passing.
pub const MAX_OUT_BYTES: u64 = 50 * 1024 * 1024;

/// A tool output file over [`MAX_OUT_BYTES`]. Travels as an `anyhow` error; the engine turns it
/// into `CheckStatus::Partial` (never `Passed`, never a hard `Errored`).
#[derive(Debug)]
pub struct OutTooLarge {
    pub name: String,
    /// The cap that was exceeded, in bytes.
    pub cap: u64,
}

impl std::fmt::Display for OutTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} exceeds the {} MB read cap: not parsed, findings from it are missing",
            self.name,
            self.cap / (1024 * 1024)
        )
    }
}

impl std::error::Error for OutTooLarge {}

pub fn is_oversize(e: &anyhow::Error) -> bool {
    e.downcast_ref::<OutTooLarge>().is_some()
}

/// Keep an [`OutTooLarge`] error (the engine reports it as Partial); anything else becomes `other()`.
pub fn out_err(e: anyhow::Error, other: impl FnOnce() -> anyhow::Error) -> anyhow::Error {
    if is_oversize(&e) { e } else { other() }
}

pub(crate) fn gate(ctx: &Ctx) -> Option<CheckOutput> {
    if !ctx.docker.available {
        return Some(CheckOutput::status(CheckStatus::Skipped(
            "docker not available".into(),
        )));
    }
    None
}

pub fn tool_failed(name: &str, r: &ToolRun) -> anyhow::Error {
    anyhow!("{name} exited {}: {}", r.exit_code, r.stderr_tail.trim())
}

pub fn partial(notes: Vec<String>, findings: Vec<Finding>) -> CheckOutput {
    if notes.is_empty() {
        CheckOutput::findings(findings)
    } else {
        CheckOutput {
            status: Some(CheckStatus::Partial(notes.join("; "))),
            findings,
        }
    }
}
