//! Bundle manifest format, file enumeration, and SHA256 integrity validation.

use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageEntry {
    pub tool: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub created: String,
    pub set: String,
    pub files: Vec<FileEntry>,
    pub images: Vec<ImageEntry>,
}

/// Streaming sha256 (files can be many GB).
pub fn sha256_file(p: &Path) -> Result<(String, u64)> {
    let f = std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?;
    let mut r = BufReader::with_capacity(1 << 20, f);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n_total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        n_total += n as u64;
    }
    Ok((hex::encode(h.finalize()), n_total))
}

/// Hash every regular file under `dir` (except manifest.json).
pub fn build_files(dir: &Path) -> Result<Vec<FileEntry>> {
    let mut v = vec![];
    for e in walkdir::WalkDir::new(dir).sort_by_file_name() {
        let e = e?;
        if !e.file_type().is_file() {
            continue;
        }
        let rel = e
            .path()
            .strip_prefix(dir)?
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "manifest.json" {
            continue;
        }
        let (sha256, size) = sha256_file(e.path())?;
        v.push(FileEntry {
            path: rel,
            sha256,
            size,
        });
    }
    Ok(v)
}

pub fn safe_rel(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && Path::new(p).components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

/// Verify every manifest entry against `dir`; fails on any mismatch, missing file or path escape.
pub fn verify_manifest(dir: &Path, m: &Manifest) -> Result<()> {
    for f in &m.files {
        if !safe_rel(&f.path) {
            bail!("manifest path escapes the bundle: {}", f.path);
        }
        let p = dir.join(&f.path);
        let (got, size) =
            sha256_file(&p).with_context(|| format!("manifest file missing: {}", f.path))?;
        if got != f.sha256 || size != f.size {
            bail!(
                "sha256 mismatch for {} (bundle is corrupt or tampered)",
                f.path
            );
        }
    }
    Ok(())
}
