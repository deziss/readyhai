//! Filtered copy of a source tree. Tools only ever see the snapshot.
//! Denylisted (secret-bearing) files are never opened: they are recreated as
//! empty placeholders so rules can still see that they exist. `.git` is not
//! copied and symlinks are dropped.
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize)]
pub struct DeniedFile {
    pub path: String,
    pub tracked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub root: PathBuf,
    /// Relative paths of everything copied (placeholders included).
    pub files: Vec<String>,
    pub denied: Vec<DeniedFile>,
    pub dropped_symlinks: Vec<String>,
    pub skipped_large: Vec<String>,
    /// Paths tracked in any git repo inside the tree (nested repos included).
    pub tracked: BTreeSet<String>,
    pub git_repos: Vec<String>,
}

const MAX_FILE: u64 = 20 * 1024 * 1024;
const SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", ".venv", "venv", "__pycache__", "target", ".tox", ".mypy_cache",
    ".pytest_cache", "dist", ".next", ".cache", ".gradle", ".idea", ".readyhai",
];

/// Basename / path globs that are secret-bearing. Matched case-insensitively.
const DENY: &[&str] = &[
    "**/.env", "**/.env.*", "**/*.env", "**/*secret*.yaml", "**/*secret*.yml", "**/*secrets*.json",
    "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.keystore", "**/*.csr",
    "**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*", "**/id_dsa*",
    "**/creds*.{md,txt,json,yaml,yml,csv,ini,conf,cfg,toml,xml}", "**/creds",
    "**/*credential*.{md,txt,json,yaml,yml,csv,ini,conf,cfg,toml,xml}",
    "**/.npmrc", "**/.pypirc", "**/.netrc", "**/.htpasswd", "**/.dockercfg", "**/.docker/config.json",
    "**/*password*.{txt,json,yaml,yml,csv,ini,conf,cfg,toml}", "**/*token*.json", "**/robot$*.json", "**/*.tfstate", "**/*.tfstate.*",
    "**/*.kdbx", "**/backups/env_backup*",
];
/// Example/template files are safe and useful (they show expected config).
const ALLOW: &[&str] = &[
    "**/*.example", "**/*.sample", "**/*.template", "**/*.dist", "**/*_example", "**/*.example.*",
    "**/.env.example*", "**/.env.sample*", "**/.env.template*",
];

fn globset(pats: &[&str], extra: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in pats.iter().map(|s| s.to_string()).chain(extra.iter().cloned()) {
        b.add(Glob::new(&p.to_lowercase())?);
    }
    Ok(b.build()?)
}

pub struct Denylist {
    deny: GlobSet,
    allow: GlobSet,
}

impl Denylist {
    pub fn new(extra: &[String]) -> Result<Self> {
        Ok(Denylist { deny: globset(DENY, extra)?, allow: globset(ALLOW, &[])? })
    }
    pub fn is_denied(&self, rel: &str) -> bool {
        let l = rel.to_lowercase();
        self.deny.is_match(&l) && !self.allow.is_match(&l)
    }
}

/// Paths tracked by git, for the repo at `repo` (prefix = its path relative to the root).
fn git_tracked(repo: &Path, prefix: &str, out: &mut BTreeSet<String>) {
    let Ok(o) = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.quotepath=off", "ls-files", "-z"])
        .output()
    else {
        return;
    };
    if !o.status.success() {
        return;
    }
    for p in o.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let p = String::from_utf8_lossy(p);
        out.insert(if prefix.is_empty() { p.to_string() } else { format!("{prefix}/{p}") });
    }
}

/// True when `dir` sits inside a git work tree of a parent directory.
fn inside_work_tree(dir: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|o| o.status.success() && o.stdout.starts_with(b"true"))
        .unwrap_or(false)
}

pub fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

/// Copy `src` into `dest` (created, must not exist or be empty).
pub fn take(src: &Path, dest: &Path, extra_deny: &[String], extra_skip: &[String]) -> Result<Snapshot> {
    let src = src.canonicalize().with_context(|| format!("target {}", src.display()))?;
    let deny = Denylist::new(extra_deny)?;
    fs::create_dir_all(dest)?;
    let mut snap = Snapshot {
        root: dest.to_path_buf(),
        files: vec![],
        denied: vec![],
        dropped_symlinks: vec![],
        skipped_large: vec![],
        tracked: BTreeSet::new(),
        git_repos: vec![],
    };
    let skip = |name: &str| SKIP_DIRS.contains(&name) || extra_skip.iter().any(|s| s == name);

    let walker = WalkDir::new(&src).follow_links(false).into_iter().filter_entry(|e| {
        e.depth() == 0 || !(e.file_type().is_dir() && skip(&e.file_name().to_string_lossy()))
    });
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // unreadable dir: skip, never fail the whole run
        };
        let path = entry.path();
        let r = rel(&src, path);
        let ft = entry.file_type();
        if ft.is_dir() {
            let parent_repo = r.is_empty() && !path.join(".git").exists() && inside_work_tree(path);
            if path.join(".git").exists() || parent_repo {
                git_tracked(path, &r, &mut snap.tracked);
                snap.git_repos.push(if r.is_empty() { ".".into() } else { r.clone() });
            }
            if !r.is_empty() {
                fs::create_dir_all(dest.join(&r))?;
            }
            continue;
        }
        if ft.is_symlink() {
            snap.dropped_symlinks.push(r);
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let target = dest.join(&r);
        if deny.is_denied(&r) {
            // Never open: placeholder only.
            fs::write(&target, b"")?;
            snap.denied.push(DeniedFile { path: r.clone(), tracked: false });
            snap.files.push(r);
            continue;
        }
        let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if len > MAX_FILE {
            snap.skipped_large.push(r);
            continue;
        }
        if fs::copy(path, &target).is_err() {
            continue; // unreadable file (permissions): skip
        }
        snap.files.push(r);
    }
    for d in &mut snap.denied {
        d.tracked = snap.tracked.contains(&d.path);
    }
    // Tools run as an unprivileged uid: make the tree world-readable.
    for e in WalkDir::new(dest).into_iter().flatten() {
        let mode = if e.file_type().is_dir() { 0o755 } else { 0o644 };
        set_mode(e.path(), mode);
    }
    Ok(snap)
}

#[cfg(unix)]
pub fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
pub fn set_mode(_p: &Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylist() {
        let d = Denylist::new(&[]).unwrap();
        for p in [".env", "a/.env.prod", "k8s/secret.yaml", "x/id_rsa", "certs/tls.key", "creds.md", "app/prod.env"] {
            assert!(d.is_denied(p), "{p} should be denied");
        }
        for p in [".env.example", "app/.env_example", "src/main.py", "README.md", "k8s/deployment.yaml",
            "templates/reset_password.html", "app/credentials_service.py", "creds_helper.py"] {
            assert!(!d.is_denied(p), "{p} should be allowed");
        }
    }
}
