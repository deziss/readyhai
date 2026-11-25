//! Air-gapped offline bundle import and validation workflow.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

use crate::engine;
use crate::tools::{self, Docker};

use super::manifest::{Manifest, safe_rel, verify_manifest};
use super::tar::{check_tar_safe, copy_tree, run, tmp_name};

/// `readyhai bundle import` — run on the air-gapped machine.
pub fn import(bundle: &Path) -> Result<()> {
    if !bundle.is_file() {
        bail!("bundle not found: {}", bundle.display());
    }
    check_tar_safe(bundle)?;
    let data = engine::data_dir();
    let root = data.join("bundles");
    std::fs::create_dir_all(&root)?;
    let tmp = root.join(tmp_name(".incoming"));
    std::fs::create_dir_all(&tmp)?;
    let r = import_into(bundle, &data, &root, &tmp);
    if tmp.exists() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    r
}

pub fn import_into(bundle: &Path, data: &Path, root: &Path, tmp: &Path) -> Result<()> {
    eprintln!("extracting {}", bundle.display());
    run(
        Command::new("tar")
            .arg("-xf")
            .arg(bundle)
            .arg("-C")
            .arg(tmp)
            .arg("--no-same-owner"),
        "tar -xf",
    )?;
    let man: Manifest = serde_json::from_slice(
        &std::fs::read(tmp.join("manifest.json")).context("manifest.json missing")?,
    )
    .context("manifest.json invalid")?;
    eprintln!("verifying {} files", man.files.len());
    verify_manifest(tmp, &man)?;
    for im in &man.images {
        if !safe_rel(&im.tool) || im.tool.contains('/') {
            bail!("bad tool name in manifest: {}", im.tool);
        }
    }

    let docker = Docker::detect(data);
    if !docker.available {
        bail!("docker not available: cannot load images");
    }
    let mut loaded = vec![];
    for im in &man.images {
        eprintln!("docker load {}", im.tool);
        let tar = tmp.join("images").join(format!("{}.tar", im.tool));
        run(
            Command::new("docker").arg("load").arg("-i").arg(&tar),
            &format!("docker load {}", im.tool),
        )?;
        let got = tools::local_image_id(&im.id)
            .ok_or_else(|| anyhow!("{}: image {} not present after load", im.tool, im.id))?;
        if got != im.id {
            bail!("{}: loaded image id {got} != manifest {}", im.tool, im.id);
        }
        loaded.push(im.tool.clone());
    }

    std::fs::write(
        data.join("tools.lock.toml"),
        std::fs::read(tmp.join("tools.lock.toml")).context("tools.lock.toml missing")?,
    )?;
    let cache = data.join("cache");
    std::fs::create_dir_all(&cache)?;
    if tmp.join("cache").is_dir() {
        copy_tree(&tmp.join("cache"), &cache)?;
    }
    // tool containers run as nobody and only read the cache
    let _ = Command::new("chmod")
        .arg("-R")
        .arg("a+rX")
        .arg(&cache)
        .status();

    let stamp: String = man
        .created
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let dest = root.join(&stamp);
    if dest.exists() {
        std::fs::remove_dir_all(&dest)?;
    }
    // images are loaded into docker; drop the duplicate tars to save disk
    let _ = std::fs::remove_dir_all(tmp.join("images"));
    let _ = std::fs::remove_dir_all(tmp.join("cache"));
    std::fs::rename(tmp, &dest)?;

    println!(
        "bundle imported: {} (readyhai {}, set {}, created {})",
        dest.display(),
        man.version,
        man.set,
        man.created
    );
    println!("  images loaded: {}", loaded.join(", "));
    println!(
        "  lock installed: {}",
        data.join("tools.lock.toml").display()
    );
    println!("  cache: {}", cache.display());
    if let Some(d) = tools::db_age_days(&cache) {
        println!("  vuln DB age: {d} day(s)");
    }
    if dest.join("bin").join("readyhai").is_file() {
        println!(
            "  bundled binary: {}",
            dest.join("bin").join("readyhai").display()
        );
    }
    if dest.join("model").is_dir() {
        println!("  model: {}", dest.join("model").display());
    }
    Ok(())
}
