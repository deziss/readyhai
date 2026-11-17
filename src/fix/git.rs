//! Local git branch creation and commit authoring.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::Result;

/// Execute git branch and commit authoring locally (strict no remote push).
pub fn commit_local_branch(
    repo: &Path,
    branch_name: &str,
    commit_msg: &str,
    changed_files: &[String],
) -> Result<Option<String>> {
    // 1. Create and switch to new branch
    let mut check_git = Command::new("git");
    check_git
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(repo);
    if !crate::tools::run_capped(&mut check_git, Duration::from_secs(5), 4096, None)?.success() {
        return Ok(None);
    }

    let mut branch_cmd = Command::new("git");
    branch_cmd
        .args(["checkout", "-b", branch_name])
        .current_dir(repo);
    let _ = crate::tools::run_capped(&mut branch_cmd, Duration::from_secs(10), 4096, None);

    // 2. Add files
    let mut add_cmd = Command::new("git");
    add_cmd.arg("add").current_dir(repo);
    for f in changed_files {
        add_cmd.arg(f);
    }
    crate::tools::run_capped(&mut add_cmd, Duration::from_secs(10), 4096, None)?;

    // 3. Commit
    let mut commit_cmd = Command::new("git");
    commit_cmd
        .args(["commit", "-m", commit_msg])
        .current_dir(repo);
    let commit_res =
        crate::tools::run_capped(&mut commit_cmd, Duration::from_secs(15), 8192, None)?;

    if !commit_res.success() {
        return Ok(None);
    }

    // 4. Retrieve commit SHA
    let mut rev_cmd = Command::new("git");
    rev_cmd.args(["rev-parse", "HEAD"]).current_dir(repo);
    let rev_out = crate::tools::run_capped(&mut rev_cmd, Duration::from_secs(5), 4096, None)?;
    let sha = rev_out.stdout_lossy().trim().to_string();

    Ok(Some(sha))
}
