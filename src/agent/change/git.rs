use std::path::Path;
use std::process::Command;
use std::time::Duration;

use super::models::{MAX_DIFF_OUTPUT, MAX_READ};
use crate::llm::untrusted::clean;

pub(crate) fn git_timeout() -> Duration {
    let secs = std::env::var("READYHAI_GIT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
        .clamp(5, 3600);
    Duration::from_secs(secs)
}

/// Files changed between `base` and HEAD (`git diff --name-only base...HEAD`), relative to `repo`.
/// Hooks and external diff/textconv helpers are off, git never prompts, stdin is null and the
/// run is bounded in time and output (see `tools::run_capped`).
pub(crate) fn git_changed_files(
    repo: &Path,
    base: &str,
    timeout: Duration,
) -> Result<(Vec<String>, bool), String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.quotepath=off",
            "--no-pager",
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--relative",
        ])
        .arg(format!("{base}...HEAD"))
        .arg("--")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_EXTERNAL_DIFF");
    let out = crate::tools::run_capped(&mut cmd, timeout, MAX_DIFF_OUTPUT, None)
        .map_err(|e| format!("could not run git: {e}"))?;
    if out.timed_out {
        return Err(format!("git diff timed out after {}s", timeout.as_secs()));
    }
    if !out.success() {
        let err = out.stderr_lossy();
        let tail: String = err.trim().chars().take(300).collect();
        return Err(format!(
            "git diff {base}...HEAD failed: {}",
            clean(&tail, 300)
        ));
    }
    let text = out.stdout_lossy();
    let mut files: Vec<String> = text
        .split('\0')
        .filter(|f| !f.is_empty())
        .filter(|f| !f.starts_with('/') && !f.split('/').any(|seg| seg == ".." || seg == "."))
        .map(String::from)
        .collect();
    files.sort();
    files.dedup();
    Ok((files, out.truncated))
}

/// Source text of a changed file, only when it is a regular file of moderate size that really
/// lives under the repo (no symlink, no symlinked directory out of it). None for a deleted file.
pub(crate) fn read_repo_file(root: &Path, rel: &str) -> Option<String> {
    let p = root.join(rel);
    let md = std::fs::symlink_metadata(&p).ok()?;
    if !md.is_file() || md.len() > MAX_READ {
        return None;
    }
    if !p.canonicalize().ok()?.starts_with(root) {
        return None;
    }
    Some(String::from_utf8_lossy(&std::fs::read(&p).ok()?).into_owned())
}
