//! Unit tests for bundle manifest verification, tar safety, and offline gates.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use super::env::ENV_LOCK;
use super::eol::{endoflife, EMBEDDED_EOL, EOL_PRODUCTS};
use super::export::export;
use super::manifest::{build_files, verify_manifest, Manifest};
use super::tar::{check_tar_safe, run};

fn tmpdir(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rh-{n}-{:08x}", rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn manifest_build_verify_and_tamper() {
    let d = tmpdir("manifest");
    std::fs::create_dir_all(d.join("images")).unwrap();
    std::fs::write(d.join("images/a.tar"), b"image-bytes").unwrap();
    std::fs::write(d.join("tools.lock.toml"), b"[tools]\n").unwrap();
    let m = Manifest {
        version: "t".into(),
        created: "now".into(),
        set: "core".into(),
        files: build_files(&d).unwrap(),
        images: vec![],
    };
    assert_eq!(m.files.len(), 2);
    verify_manifest(&d, &m).unwrap();
    std::fs::write(d.join("images/a.tar"), b"image-byteX").unwrap();
    let e = verify_manifest(&d, &m).unwrap_err().to_string();
    assert!(e.contains("mismatch"), "{e}");
    std::fs::write(d.join("images/a.tar"), b"image-bytes").unwrap();
    std::fs::remove_file(d.join("tools.lock.toml")).unwrap();
    assert!(verify_manifest(&d, &m).is_err());
    let mut bad = m.clone();
    bad.files[0].path = "../escape".into();
    assert!(
        verify_manifest(&d, &bad)
            .unwrap_err()
            .to_string()
            .contains("escapes")
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn tar_traversal_rejected() {
    let d = tmpdir("tar");
    let sub = d.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(d.join("evil.txt"), b"x").unwrap();
    std::fs::write(sub.join("ok.txt"), b"x").unwrap();
    let good = d.join("good.tar");
    run(
        Command::new("tar")
            .arg("-cf")
            .arg(&good)
            .arg("-C")
            .arg(&sub)
            .arg("."),
        "tar",
    )
    .unwrap();
    check_tar_safe(&good).unwrap();
    let dotdot = d.join("dotdot.tar");
    run(
        Command::new("tar")
            .arg("-cPf")
            .arg(&dotdot)
            .arg("-C")
            .arg(&sub)
            .arg("../evil.txt"),
        "tar",
    )
    .unwrap();
    assert!(
        check_tar_safe(&dotdot)
            .unwrap_err()
            .to_string()
            .contains("unsafe")
    );
    let abs = d.join("abs.tar");
    run(
        Command::new("tar")
            .arg("-cPf")
            .arg(&abs)
            .arg(d.join("evil.txt")),
        "tar",
    )
    .unwrap();
    assert!(
        check_tar_safe(&abs)
            .unwrap_err()
            .to_string()
            .contains("unsafe")
    );
    let lnk = d.join("lnk.tar");
    std::os::unix::fs::symlink("/etc/passwd", sub.join("l")).unwrap();
    run(
        Command::new("tar")
            .arg("-cf")
            .arg(&lnk)
            .arg("-C")
            .arg(&sub)
            .arg("l"),
        "tar",
    )
    .unwrap();
    assert!(check_tar_safe(&lnk).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn export_refused_offline() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("READYHAI_OFFLINE", "1") };
    let e = export(Path::new("/tmp/x.tar"), "core", None)
        .unwrap_err()
        .to_string();
    unsafe { std::env::remove_var("READYHAI_OFFLINE") };
    assert!(e.contains("offline"), "{e}");
}

#[test]
fn embedded_endoflife_parses() {
    let v: Value = serde_json::from_str(EMBEDDED_EOL).unwrap();
    for p in EOL_PRODUCTS {
        assert!(v[p].as_array().is_some_and(|a| !a.is_empty()), "{p}");
    }
    assert!(endoflife().is_object());
}
