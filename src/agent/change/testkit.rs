use std::path::{Path, PathBuf};
use std::process::Command;

pub fn git(dir: &Path, args: &[&str]) {
    let st = Command::new("git")
        .current_dir(dir)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("git");
    assert!(
        st.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}

pub fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rh-change-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

pub fn write(dir: &Path, rel: &str, text: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// base commit with `files`, then a second commit that rewrites `changed`.
pub fn repo_with(name: &str, files: &[(&str, &str)], changed: &[(&str, &str)]) -> PathBuf {
    let d = tmp(name);
    git(&d, &["init", "-q", "-b", "main"]);
    for (p, t) in files {
        write(&d, p, t);
    }
    git(&d, &["add", "-A"]);
    git(&d, &["commit", "-q", "-m", "base", "--no-verify"]);
    git(&d, &["tag", "base"]);
    for (p, t) in changed {
        write(&d, p, t);
    }
    git(&d, &["add", "-A"]);
    git(
        &d,
        &[
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "change",
            "--no-verify",
        ],
    );
    d
}
