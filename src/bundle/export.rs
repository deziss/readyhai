//! Air-gapped offline bundle export workflow.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

use crate::engine;
use crate::tools::{self, Docker};

use super::env::offline;
use super::eol::fetch_endoflife;
use super::manifest::{build_files, ImageEntry, Manifest};
use super::tar::{copy_cache_dir, human, run, tmp_name};

/// `readyhai bundle export` — run on a network-capable machine.
pub fn export(out: &Path, set: &str, model: Option<&Path>) -> Result<()> {
    if offline() {
        bail!(
            "offline mode: bundle export needs a network-capable machine (unset READYHAI_OFFLINE)"
        );
    }
    if !matches!(set, "core" | "full") {
        bail!("--set must be core or full");
    }
    let data = engine::data_dir();
    let docker = Docker::detect(&data);
    if !docker.available {
        bail!("docker not available: cannot save tool images");
    }
    let filter: Option<BTreeSet<String>> = std::env::var("READYHAI_BUNDLE_TOOLS")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());
    let current = tools::lock_entries();
    let mut wanted: BTreeSet<String> = current.keys().cloned().collect();
    if set == "core" {
        wanted.remove("zap");
        wanted.remove("mobsf");
    }
    if let Some(f) = &filter {
        wanted.retain(|t| f.contains(t));
    }
    if wanted.is_empty() {
        bail!("no tools selected");
    }

    let staging = data.join("bundles").join(tmp_name(".staging"));
    std::fs::create_dir_all(staging.join("bin"))?;
    std::fs::create_dir_all(staging.join("images"))?;
    std::fs::create_dir_all(staging.join("cache"))?;
    let res = (|| -> Result<u64> {
        eprintln!("[1/5] pulling images and recording IDs");
        let lock_tmp = staging.join("tools.lock.toml");
        tools::tools_pull_filtered(Some(&lock_tmp), Some(&wanted))?;
        eprintln!("[2/5] updating vuln DB, rules, lynis");
        tools::tools_update(&docker)?;
        eprintln!("[3/5] endoflife snapshot");
        let eol = docker.cache_dir.join("endoflife.json");
        if let Err(e) = fetch_endoflife(&eol) {
            eprintln!("  endoflife fetch failed ({e:#}); the embedded snapshot will be used");
        }

        eprintln!("[4/5] saving images");
        let text = std::fs::read_to_string(&lock_tmp)?;
        let lock: toml::Table = toml::from_str(&text)?;
        let mut images = vec![];
        for t in &wanted {
            let ent = lock.get("tools").and_then(|x| x.get(t.as_str()));
            let id = ent
                .and_then(|e| e.get("id"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let image = ent
                .and_then(|e| e.get("image"))
                .and_then(|v| v.as_str())
                .unwrap_or(t)
                .to_string();
            let Some(id) = id else {
                eprintln!(
                    "  skipping {t}: image {image} is not present locally (not pulled/built)"
                );
                continue;
            };
            eprintln!("  docker save {t} ({image})");
            let dest = staging.join("images").join(format!("{t}.tar"));
            run(
                Command::new("docker")
                    .arg("save")
                    .arg("-o")
                    .arg(&dest)
                    .arg(&id),
                &format!("docker save {t}"),
            )?;
            images.push(ImageEntry {
                tool: t.clone(),
                reference: image,
                id,
            });
        }
        if images.is_empty() {
            bail!("no images could be saved");
        }

        eprintln!("[5/5] assembling bundle");
        let me = std::env::current_exe()?;
        std::fs::copy(&me, staging.join("bin").join("readyhai"))?;
        // Tool containers run as nobody and create 0700 dirs; `docker cp` reads them regardless.
        let helper = images[0].id.clone();
        for d in ["grype", "semgrep", "lynis"] {
            let src = docker.cache_dir.join(d);
            if src.is_dir() {
                copy_cache_dir(
                    &helper,
                    &docker.cache_dir,
                    d,
                    &staging.join("cache").join(d),
                )?;
            }
        }
        if eol.is_file() {
            std::fs::copy(&eol, staging.join("cache").join("endoflife.json"))?;
        }
        if let Some(m) = model {
            std::fs::create_dir_all(staging.join("model"))?;
            let name = m.file_name().ok_or_else(|| anyhow!("bad model path"))?;
            std::fs::copy(m, staging.join("model").join(name)).context("copying model")?;
        }
        let man = Manifest {
            version: engine::VERSION.to_string(),
            created: engine::now(),
            set: set.to_string(),
            files: build_files(&staging)?,
            images,
        };
        std::fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&man)?,
        )?;
        if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        run(
            Command::new("tar")
                .arg("-cf")
                .arg(out)
                .arg("-C")
                .arg(&staging)
                .arg("."),
            "tar -cf",
        )?;
        Ok(std::fs::metadata(out)?.len())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    let size = res?;
    eprintln!("bundle written: {} ({})", out.display(), human(size));
    Ok(())
}
