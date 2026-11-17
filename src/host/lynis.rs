//! Lynis report parsing, finding generation, and cache retrieval.
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::host::types::{LYNIS_URL, LYNIS_VERSION, LynisReport};
use crate::model::{Category, Finding, Severity, sha256_hex};

pub fn parse_lynis(report: &str) -> LynisReport {
    let mut r = LynisReport::default();
    for line in report.lines() {
        let line = line.trim();
        if let Some(u) = line.strip_prefix("#uid=") {
            r.uid = u.parse().ok();
        } else if let Some(x) = line.strip_prefix("hardening_index=") {
            r.hardening_index = x.trim().parse().ok();
        } else if let Some(x) = line.strip_prefix("warning[]=") {
            let mut p = x.split('|');
            r.warnings.push((
                p.next().unwrap_or("").to_string(),
                p.next().unwrap_or("").to_string(),
            ));
        } else if let Some(x) = line.strip_prefix("suggestion[]=") {
            let mut p = x.split('|');
            r.suggestions.push((
                p.next().unwrap_or("").to_string(),
                p.next().unwrap_or("").to_string(),
            ));
        }
    }
    r
}

pub fn lynis_findings(r: &LynisReport, who: &str) -> Vec<Finding> {
    let mut out = vec![];
    let mk = |id: &str, text: &str, sev: Severity| {
        let id = if id.is_empty() { "UNKNOWN" } else { id };
        Finding::new(
            "host.lynis",
            &format!("lynis.{id}"),
            Category::Security,
            sev,
            text.to_string(),
            who.to_string(),
        )
        .fp_key(format!("{who}|{id}"))
        .remediation("See `lynis show details <ID>` for the hardening guidance.")
    };
    for (id, t) in &r.warnings {
        out.push(mk(id, t, Severity::Medium));
    }
    for (id, t) in &r.suggestions {
        out.push(mk(id, t, Severity::Low));
    }
    if let Some(h) = r.hardening_index
        && h < 65
    {
        out.push(
            Finding::new(
                "host.lynis",
                "lynis.hardening_index",
                Category::Security,
                Severity::Low,
                format!("Lynis hardening index is {h} (< 65)"),
                who.to_string(),
            )
            .fp_key(format!("{who}|hardening_index")),
        );
    }
    out
}

pub(crate) fn lynis_tarball(cache: &Path) -> PathBuf {
    cache.join("lynis").join("lynis.tar.gz")
}

/// Download the pinned Lynis tarball into `<cache>/lynis/lynis.tar.gz` (called from `tools update`).
/// Verifies against a published .sha256 when available; otherwise records the hash in a sibling
/// `lynis.tar.gz.sha256` file marked "unverified".
pub fn fetch_lynis(cache_dir: &Path) -> Result<()> {
    let dir = cache_dir.join("lynis");
    std::fs::create_dir_all(&dir)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let resp = client
        .get(LYNIS_URL)
        .send()?
        .error_for_status()
        .context("downloading lynis")?;
    let bytes = resp.bytes()?;
    if bytes.len() < 100_000 {
        bail!("lynis download too small ({} bytes)", bytes.len());
    }
    let got = sha256_hex(&bytes);
    let published = client
        .get(format!("{LYNIS_URL}.sha256"))
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.text().ok())
        .and_then(|t| t.split_whitespace().next().map(|s| s.to_ascii_lowercase()))
        .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()));
    let note = match published {
        Some(want) if want == got => "verified against published sha256",
        Some(want) => bail!("lynis sha256 mismatch: published {want}, got {got}"),
        None => "unverified (no published sha256); pin this hash",
    };
    std::fs::write(lynis_tarball(cache_dir), &bytes)?;
    std::fs::write(
        dir.join("lynis.tar.gz.sha256"),
        format!("{got}  lynis-{LYNIS_VERSION}.tar.gz  {note}\n"),
    )?;
    Ok(())
}
