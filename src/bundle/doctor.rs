//! System diagnostics and offline readiness verification (readyhai doctor).

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::Result;

use crate::engine;
use crate::tools;

use super::env::offline;
use super::tar::human;

pub fn probe_llm() -> (String, bool) {
    let cfg = match crate::llm::LlmConfig::from_env() {
        Ok(c) => c,
        Err(e) => return (format!("no provider ({e})"), false),
    };
    let base = match cfg.base_url() {
        Ok(b) => b,
        Err(e) => return (format!("{} ({e})", cfg.provider.id), false),
    };
    // Same request, key and guard as a real call; the note names the provider and models, never a key.
    match crate::llm::probe_status(&cfg) {
        Some(code) => (
            format!("{} @ {base} answered HTTP {code}", cfg.describe()),
            true,
        ),
        None => (
            format!("{} @ {base} unreachable (2s)", cfg.describe()),
            false,
        ),
    }
}

pub fn free_disk_kb(dir: &Path) -> Option<u64> {
    let mut d = dir.to_path_buf();
    while !d.exists() {
        d = d.parent()?.to_path_buf();
    }
    let o = Command::new("df").arg("-Pk").arg(&d).output().ok()?;
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()
}

pub fn mtime_date(p: &Path) -> Option<String> {
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    let d = time::OffsetDateTime::from(t).date();
    Some(d.to_string())
}

pub fn doctor() -> Result<()> {
    let data = engine::data_dir();
    let cache = data.join("cache");
    let (llm_note, llm_ok) = probe_llm();
    let mode = if llm_ok {
        "lan-llm"
    } else if offline() {
        "offline"
    } else {
        "deterministic"
    };
    println!("readyhai {} doctor", engine::VERSION);
    println!(
        "mode:        {mode}{}",
        if offline() {
            " (READYHAI_OFFLINE=1: no pulls, no DB updates)"
        } else {
            ""
        }
    );
    println!("llm:         {llm_note}");
    println!("data dir:    {}", data.display());

    let dv = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    match &dv {
        Some(v) => println!("docker:      server {v}"),
        None => println!("! docker:    not available (container tools will be skipped)"),
    }

    println!("tools:");
    for (name, e) in tools::lock_entries() {
        let by_id = e
            .id
            .as_deref()
            .filter(|i| tools::local_image_id(i).is_some());
        let present = dv.is_some() && tools::image_present(&name);
        let pinned = by_id.is_some() || e.digest.starts_with("sha256:");
        let id = e
            .id
            .as_deref()
            .map(|i| {
                i.trim_start_matches("sha256:")
                    .chars()
                    .take(12)
                    .collect::<String>()
            })
            .unwrap_or_else(|| "-".into());
        let mark = if present { " " } else { "!" };
        println!(
            "{mark} {:<12} present={:<5} pinned={:<5} id={id}  {}",
            name, present, pinned, e.image
        );
    }

    match tools::db_age_days(&cache) {
        Some(d) if d > 30 => println!("! grype DB:  {d} day(s) old (> 30: stale)"),
        Some(d) if d > 7 => println!("! grype DB:  {d} day(s) old (> 7: scans are Partial)"),
        Some(d) => println!("  grype DB:  {d} day(s) old"),
        None => println!(
            "! grype DB:  missing ({})",
            if offline() {
                "import a bundle"
            } else {
                "run `readyhai tools update`"
            }
        ),
    }
    let rules = std::fs::read_dir(cache.join("semgrep"))
        .map(|d| {
            d.filter_map(|e| e.ok()).any(|e| {
                matches!(
                    e.path().extension().and_then(|x| x.to_str()),
                    Some("yml" | "yaml")
                )
            })
        })
        .unwrap_or(false);
    println!(
        "{} semgrep rules: {}",
        if rules { " " } else { "!" },
        if rules { "present" } else { "missing" }
    );
    let lynis = cache.join("lynis").join("lynis.tar.gz").is_file();
    println!(
        "{} lynis:      {}",
        if lynis { " " } else { "!" },
        if lynis { "present" } else { "missing" }
    );
    match mtime_date(&cache.join("endoflife.json")) {
        Some(d) => println!("  endoflife: snapshot {d}"),
        None => println!("  endoflife: embedded snapshot (no cached copy)"),
    }
    match free_disk_kb(&data) {
        Some(kb) if kb < 5 * 1024 * 1024 => println!(
            "! disk free: {} (low; bundles are 3-9 GB)",
            human(kb * 1024)
        ),
        Some(kb) => println!("  disk free: {}", human(kb * 1024)),
        None => println!("! disk free: unknown"),
    }
    Ok(())
}
