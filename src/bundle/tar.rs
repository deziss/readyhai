//! Archive inspection, security validations, and filesystem copy helpers.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// List a tar and reject absolute paths, `..` components and link entries.
pub fn check_tar_safe(tar: &Path) -> Result<()> {
    let o = Command::new("tar")
        .arg("-tf")
        .arg(tar)
        .stdin(Stdio::null())
        .output()
        .context("running tar")?;
    if !o.status.success() {
        bail!(
            "tar -tf failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    for name in String::from_utf8_lossy(&o.stdout).lines() {
        let n = name.trim_end_matches('/');
        if name.starts_with('/') || n.split('/').any(|c| c == "..") || name.contains('\\') {
            bail!("unsafe path in bundle tar: {name}");
        }
    }
    let o = Command::new("tar")
        .arg("-tvf")
        .arg(tar)
        .stdin(Stdio::null())
        .output()
        .context("running tar")?;
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        match line.chars().next() {
            Some('-') | Some('d') => {}
            _ => bail!("unsupported entry type in bundle tar (links/devices rejected): {line}"),
        }
    }
    Ok(())
}

pub fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let o = cmd
        .stdin(Stdio::null())
        .output()
        .with_context(|| what.to_string())?;
    if !o.status.success() {
        bail!("{what}: {}", String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

pub fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    let mut s = src.as_os_str().to_os_string();
    s.push("/.");
    run(Command::new("cp").arg("-a").arg(&s).arg(dst), "cp -a")
}

/// Copy `<cache>/<sub>` to `dest` through `docker cp` (works for dirs the host user cannot read).
pub fn copy_cache_dir(image: &str, cache: &Path, sub: &str, dest: &Path) -> Result<()> {
    let o = Command::new("docker")
        .arg("create")
        .arg("-v")
        .arg(format!(
            "{}:/cache:ro",
            std::path::absolute(cache)?.display()
        ))
        .arg(image)
        .arg("x")
        .stdin(Stdio::null())
        .output()
        .context("docker create")?;
    if !o.status.success() {
        bail!(
            "docker create: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    let ctr = String::from_utf8_lossy(&o.stdout).trim().to_string();
    std::fs::create_dir_all(dest)?;
    let r = run(
        Command::new("docker")
            .arg("cp")
            .arg(format!("{ctr}:/cache/{sub}/."))
            .arg(dest),
        &format!("docker cp cache/{sub}"),
    );
    let _ = Command::new("docker").args(["rm", "-f", &ctr]).output();
    r?;
    run(
        Command::new("chmod").arg("-R").arg("u+rwX").arg(dest),
        "chmod",
    )?;
    // interrupted downloads from earlier runs are not part of the DB
    if let Ok(rd) = std::fs::read_dir(dest) {
        for e in rd.filter_map(|e| e.ok()) {
            if e.file_name()
                .to_string_lossy()
                .starts_with("grype-db-download")
            {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    Ok(())
}

pub fn human(n: u64) -> String {
    let n = n as f64;
    if n >= 1e9 {
        format!("{:.2} GB", n / 1e9)
    } else {
        format!("{:.1} MB", n / 1e6)
    }
}

pub fn tmp_name(prefix: &str) -> String {
    format!("{prefix}-{:08x}", rand::random::<u32>())
}
