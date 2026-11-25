//! Run storage paths, atomic file persistence, run ID generation, and run loading.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rand::RngExt;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::model::{Run, Target, sha256_hex};

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("READYHAI_DATA") {
        return PathBuf::from(d);
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("readyhai");
    }
    #[cfg(windows)]
    {
        if let Ok(app_data) = std::env::var("LOCALAPPDATA").or_else(|_| std::env::var("APPDATA")) {
            return PathBuf::from(app_data).join("readyhai");
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".local/share/readyhai")
}

pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub fn today() -> String {
    now().get(..10).unwrap_or("").to_string()
}

/// `YYYYMMDD-HHMMSS-<64 random bits as hex>`. The timestamp keeps listings sortable; the random
/// part keeps ids unguessable (REST run ids are capability-like: 16 bits was enumerable).
pub fn new_run_id() -> String {
    let t = OffsetDateTime::now_utc();
    let r: u64 = rand::rng().random();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}-{r:016x}",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

pub fn valid_run_id(id: &str) -> bool {
    !id.is_empty() && id.len() < 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

pub fn run_dir(id: &str) -> PathBuf {
    data_dir().join("runs").join(id)
}

/// Write `bytes` to `path` atomically: a temp file in the same directory, then rename. Readers
/// (status polling, report download) never see a half-written file, and a crash leaves either the
/// old or the new content. Fails (instead of creating directories) when the parent is gone, so a
/// run that was deleted underneath a worker is not resurrected.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent directory"))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{:08x}.tmp", rand::rng().random::<u32>()));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

pub fn load_run(id: &str) -> Result<Run> {
    if !valid_run_id(id) {
        bail!("invalid run id");
    }
    let p = run_dir(id).join("run.json");
    Ok(serde_json::from_str(
        &std::fs::read_to_string(&p).with_context(|| format!("run {id} not found"))?,
    )?)
}

/// Stable per-target key for the default baseline location.
pub fn target_key(t: &Target) -> String {
    let raw = match &t.path {
        Some(p) => p.to_string_lossy().to_string(),
        None => t.raw.clone(),
    };
    sha256_hex(raw.as_bytes())[..16].to_string()
}

pub fn default_baseline_path(t: &Target) -> PathBuf {
    data_dir()
        .join("baselines")
        .join(format!("{}.json", target_key(t)))
}
