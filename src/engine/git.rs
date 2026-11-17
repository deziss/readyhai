//! Git remote repository cloning, URL normalization, and command sandboxing.

use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use super::deadline::run_deadline;

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
pub fn clone_url(raw: &str) -> Result<String> {
    let url = raw.strip_prefix("git:").unwrap_or(raw).trim();
    if url.contains("://") {
        Ok(reqwest::Url::parse(url)
            .map_err(|e| anyhow::anyhow!("invalid git URL: {e}"))?
            .to_string())
    } else {
        Ok(url.to_string())
    }
}

pub fn git_timeout(run_id: &str) -> Duration {
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

pub fn redact_url_credentials(s: &str) -> String {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)((?:https?|ssh)://)[^/\s@]+@").unwrap());
    RE.replace_all(s, "${1}***@").into_owned()
}

/// The clone command: hooks/submodules/file-protocol disabled, no prompts of any kind (terminal,
/// credential helper, ssh).
pub fn git_clone_command(url: &str, dest: &Path) -> Command {
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
pub fn git_clone(url: &str, dest: &Path, timeout: Duration) -> Result<()> {
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
