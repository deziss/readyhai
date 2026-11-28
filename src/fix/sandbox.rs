//! Test runner detection and sandboxed verification.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Detect the repository test runner.
pub fn detect_test_runner(repo: &Path) -> Option<(&'static str, &'static [&'static str])> {
    if repo.join("Cargo.toml").exists() {
        Some(("cargo", &["test", "--", "--quiet"]))
    } else if repo.join("package.json").exists() {
        // `--silent` must be an npm flag, not an argument forwarded to the script: `npm test --
        // --silent` passes `--silent` to the test command itself (e.g. `node --silent`), which
        // fails every suite and made every npm patch look like a regression.
        Some(("npm", &["--silent", "test"]))
    } else if repo.join("pyproject.toml").exists() || repo.join("pytest.ini").exists() {
        Some(("pytest", &["-q"]))
    } else if repo.join("go.mod").exists() {
        Some(("go", &["test", "./..."]))
    } else {
        None
    }
}

/// Verification sandbox: executes test runner in repo to verify patch safety.
pub fn verify_in_sandbox(repo: &Path, runner: (&str, &[&str])) -> Result<(bool, u128, String)> {
    let mut cmd = Command::new(runner.0);
    cmd.args(runner.1)
        .current_dir(repo)
        .env("CI", "true")
        .env("NODE_ENV", "test");

    let start = Instant::now();
    let captured = crate::tools::run_capped(&mut cmd, Duration::from_secs(60), 256 * 1024, None)
        .with_context(|| format!("failed to run test runner `{}`", runner.0))?;
    let duration_ms = start.elapsed().as_millis();

    let success = captured.success();
    let output = if success {
        captured.stdout_lossy()
    } else {
        format!("{}\n{}", captured.stdout_lossy(), captured.stderr_lossy())
    };

    Ok((success, duration_ms, output))
}
