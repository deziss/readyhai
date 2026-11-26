//! Global vulnerability database: one JSONL file under the data dir that remembers every
//! warn/fail ReadyHai has produced, across every target.
//!
//! The per-target [`crate::agent::memory`] answers "what does the agent know about *this*
//! app". This answers the operator's question instead: "what has ReadyHai seen on this
//! machine, and how often did it come back?" It is deliberately tiny and dumb:
//!
//! * One row per (`target`, `kind`, `rule`, `resource`), keyed by a stable fingerprint
//!   (the agent memory's construction: SHA-256 over the null-separated identity parts,
//!   first 24 hex characters). Seeing a finding again updates `last_seen` and
//!   `occurrences` instead of adding a row.
//! * Status is an operator decision that survives re-scans: `open`, `accepted`
//!   (`readyhai vulns accept`), `forgotten` (`readyhai vulns forget`). A `forgotten` row
//!   stays forgotten and an `accepted` row stays accepted; acceptance is reset to `open`
//!   only when what came back is not what was accepted (its severity moved).
//! * JSONL, one record per line, whole file rewritten with the engine's atomic temp +
//!   rename. Rewriting everything is cheap here by construction: a row is one line of
//!   summary text per distinct finding, not a run's worth of data, and a file over
//!   [`MAX_FILE_BYTES`] is refused rather than rewritten behind the operator's back.
//!
//! Writes come from the scan finalize path ([`record_run`]) and are strictly advisory: a
//! database problem becomes a note in the report, never a failed scan. Reads are tolerant:
//! one unparseable line (a hand-edit, a torn write) is skipped with a warning and the rest
//! of the file still answers.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent::memory::store::{canonical_target, target_key};
use crate::engine::{data_dir, now, write_atomic};
use crate::model::{Finding, FindingStatus, Severity};
use crate::settings::Settings;

/// A database file larger than this is not read or rewritten (see the module docs).
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Message/title text kept in a record.
pub const MAX_TEXT: usize = 300;
/// The statuses a record can carry.
pub const STATUSES: [&str; 3] = ["open", "accepted", "forgotten"];
/// Verification verdicts a record can carry (see [`crate::exploits`]). `unverified`
/// is the absence of a verdict, not an outcome of a probe.
pub const VERIFICATIONS: [&str; 5] = [
    "unverified",
    "verified",
    "not_reproducible",
    "inconclusive",
    "skipped",
];

/// One finding as the scan hands it to the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnEntry<'a> {
    /// Check/tool id that produced it, e.g. `plugin.nmap`.
    pub kind: &'a str,
    /// Stable rule id, e.g. `CVE-2024-1234` or `readiness.dockerfile.no_user`.
    pub rule: &'a str,
    pub title: &'a str,
    /// Anything [`Severity::parse`] understands; stored as the lowercase word.
    pub severity: &'a str,
    /// URL / file / port the finding is about (may be empty).
    pub resource: &'a str,
    pub message: &'a str,
}

/// One row of the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnRecord {
    pub fingerprint: String,
    /// Canonical target as typed (scheme://host:port/path, or the raw path/git ref).
    pub target: String,
    /// First 16 hex of the SHA-256 of `target` — the same key the agent memory uses.
    pub target_key: String,
    pub kind: String,
    pub rule: String,
    pub title: String,
    /// Lowercase [`Severity`] word.
    pub severity: String,
    pub resource: String,
    /// RFC3339 UTC.
    pub first_seen: String,
    /// RFC3339 UTC.
    pub last_seen: String,
    pub occurrences: u64,
    /// `open|accepted|forgotten`.
    pub status: String,
    pub message: String,
    /// `unverified|verified|not_reproducible|inconclusive|skipped` — see
    /// [`crate::exploits`]. Absent in files written before v3.7 reads as `unverified`.
    #[serde(default)]
    pub verification: String,
    /// Exploit template id that produced the verdict, if any.
    #[serde(default)]
    pub verified_by: Option<String>,
    /// RFC3339 UTC of the verification, if any.
    #[serde(default)]
    pub verified_at: Option<String>,
}

/// What [`list`] keeps; a `None` field does not filter.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub target: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    /// `unverified|verified|not_reproducible|inconclusive|skipped`.
    pub verification: Option<String>,
}

/// What one record call did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Fingerprints that were not in the database before.
    pub added: usize,
    /// Fingerprints that were already there and were stamped again.
    pub updated: usize,
}

impl Report {
    pub fn total(&self) -> usize {
        self.added + self.updated
    }
}

/// Stable identity of a finding: SHA-256 of the null-separated parts, first 24 hex
/// characters — same shape as the agent memory's `fingerprint`. Positional on purpose: the
/// meaning of each slot is fixed, so the value is stable across builds and a different
/// `resource` (or rule, or target) is a different finding.
pub fn fingerprint(target: &str, kind: &str, rule: &str, resource: &str) -> String {
    let mut h = Sha256::new();
    h.update(target_key(target).as_bytes());
    h.update([0u8]);
    h.update(kind.as_bytes());
    h.update([0u8]);
    h.update(rule.as_bytes());
    h.update([0u8]);
    h.update(resource.as_bytes());
    hex::encode(h.finalize())[..24].to_string()
}

/// Trimmed, control characters flattened, at most [`MAX_TEXT`] characters: records are
/// operator-visible text written next to a report.
fn clean(s: &str) -> String {
    let mut out: String = s
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_TEXT)
        .collect();
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

/// `<data>/vulns/vulns.jsonl`, or the operator's `[vulndb] path` when set. Pure, so the
/// rule is testable without touching the process environment.
pub fn path_in(data: &Path, override_path: Option<&str>) -> PathBuf {
    match override_path.map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => data.join("vulns").join("vulns.jsonl"),
    }
}

/// The settings file the database location comes from: `READYHAI_SETTINGS` wins, else the
/// `<data>/settings.toml` the Settings UI writes (the same rule serve scans use).
fn settings_of() -> Settings {
    let p = crate::settings::settings_path_from_env().or_else(|| {
        let d = data_dir().join("settings.toml");
        d.is_file().then_some(d)
    });
    // A broken settings file already hard-fails the scan that loads it; `readyhai vulns`
    // still has to answer, so fall back to defaults instead of propagating.
    Settings::load(p.as_deref()).unwrap_or_default()
}

/// Where the database lives on this machine, honoring the `[vulndb] path` override.
pub fn path() -> PathBuf {
    let s = settings_of();
    path_in(&data_dir(), s.vulndb.path.as_deref())
}

/// Findings worth remembering: something the operator should act on (`Severity::Info` is a
/// note, not a finding) that is not suppressed.
fn worth_recording(f: &Finding) -> bool {
    f.severity != Severity::Info && f.status != FindingStatus::Suppressed
}

/// A finding as a database entry. `resource` is the path/URL/port part of the location
/// with a trailing `:line` dropped, so an unrelated edit that moves a line is not new.
fn entry_of(f: &Finding) -> VulnEntry<'_> {
    VulnEntry {
        kind: &f.check,
        rule: &f.rule,
        title: &f.title,
        severity: f.severity.as_str(),
        resource: f.path(),
        message: if f.detail.is_empty() {
            &f.title
        } else {
            &f.detail
        },
    }
}

/// The scan finalize hook: record this run's warn/fail findings and return one report
/// note, or `None` when the section is disabled or there was nothing to record. Never
/// fails — a database that cannot be written must not change a verdict.
pub fn record_run(settings: &Settings, target: &str, findings: &[Finding]) -> Option<String> {
    if !settings.vulndb.enabled {
        return None;
    }
    let path = path_in(&data_dir(), settings.vulndb.path.as_deref());
    let entries: Vec<VulnEntry> = findings
        .iter()
        .filter(|f| worth_recording(f))
        .map(entry_of)
        .collect();
    if entries.is_empty() {
        return None;
    }
    match record_findings_at(&path, target, &entries) {
        Ok(r) => Some(format!(
            "vulndb: {} finding(s) recorded in {} ({} new, {} seen again)",
            r.total(),
            path.display(),
            r.added,
            r.updated
        )),
        Err(e) => {
            eprintln!("  warning: vulnerability database was not updated: {e:#}");
            Some(format!("vulndb: NOT updated ({e:#})"))
        }
    }
}

/// Record `entries` for `target` in the file at [`path()`] — the entry point for callers
/// outside the scan path (the REST `/api/vulns` work uses it); the scans themselves go
/// through [`record_run`], which resolves the path from the settings already loaded.
#[allow(dead_code)]
pub fn record_findings(target: &str, entries: &[VulnEntry]) -> Result<Report> {
    record_findings_at(&path(), target, entries)
}

/// Record `entries` for `target` in `path`: unseen fingerprints are added as `open`,
/// known ones are stamped (`last_seen`, `occurrences + 1`) and keep their operator status
/// — see the module docs for when a status is reset.
pub fn record_findings_at(path: &Path, target: &str, entries: &[VulnEntry]) -> Result<Report> {
    let target = canonical_target(target);
    let key = target_key(&target);
    let (mut rows, warnings) = read_at(path)?;
    warn_all(&warnings);
    let stamp = now();
    let mut report = Report::default();
    for e in entries {
        let fp = fingerprint(&target, e.kind, e.rule, e.resource);
        let severity = clean(Severity::parse(e.severity).as_str());
        match rows.iter_mut().find(|r| r.fingerprint == fp) {
            Some(r) => {
                // What the operator accepted is not what came back: the decision was about
                // a different finding, so it is open again.
                if r.status == "accepted" && r.severity != severity {
                    r.status = "open".into();
                }
                // A forgotten row is left exactly as it was apart from its counters.
                if r.status != "forgotten" {
                    r.severity = severity;
                    r.title = clean(e.title);
                    r.message = clean(e.message);
                }
                r.last_seen = stamp.clone();
                r.occurrences = r.occurrences.saturating_add(1);
                report.updated += 1;
            }
            None => {
                rows.push(VulnRecord {
                    fingerprint: fp,
                    target: target.clone(),
                    target_key: key.clone(),
                    kind: clean(e.kind),
                    rule: clean(e.rule),
                    title: clean(e.title),
                    severity,
                    resource: clean(e.resource),
                    first_seen: stamp.clone(),
                    last_seen: stamp.clone(),
                    occurrences: 1,
                    status: "open".into(),
                    message: clean(e.message),
                    verification: "unverified".into(),
                    verified_by: None,
                    verified_at: None,
                });
                report.added += 1;
            }
        }
    }
    write_rows(path, &rows)?;
    Ok(report)
}

/// Surfaces skipped lines the way the rest of ReadyHai does: a warning, never a failure.
fn warn_all(warnings: &[String]) {
    for w in warnings {
        eprintln!("  warning: vulndb: {w}");
    }
}

/// Every row in `path`, skipping (with one warning each) blank, oversized, and
/// unparseable lines. `Ok` even when the file does not exist: it is created on first write.
pub fn read_at(path: &Path) -> Result<(Vec<VulnRecord>, Vec<String>)> {
    let mut rows = vec![];
    let mut warnings = vec![];
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((rows, warnings)),
        Err(e) => bail!("vulndb {} cannot be read: {e}", path.display()),
    };
    if meta.len() > MAX_FILE_BYTES {
        bail!(
            "vulndb {} is {} bytes, over the {} byte limit: not read, not rewritten",
            path.display(),
            meta.len(),
            MAX_FILE_BYTES
        );
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("vulndb {}", path.display()))?;
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<VulnRecord>(line) {
            Ok(r) if valid_fingerprint(&r.fingerprint) => rows.push(r),
            Ok(_) => warnings.push(format!(
                "{}:{}: line without a usable fingerprint skipped",
                path.display(),
                n + 1
            )),
            Err(e) => warnings.push(format!(
                "{}:{}: skipped unparseable line ({e})",
                path.display(),
                n + 1
            )),
        }
    }
    Ok((rows, warnings))
}

/// Whole-file write: parent directory on demand (the file is created lazily on the first
/// record), then the engine's atomic temp file + rename.
fn write_rows(path: &Path, rows: &[VulnRecord]) -> Result<()> {
    let mut body = String::new();
    for r in rows {
        body.push_str(&serde_json::to_string(r)?);
        body.push('\n');
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    write_atomic(path, body.as_bytes()).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn sev_rank(s: &str) -> u8 {
    Severity::parse(s) as u8
}

/// A stored fingerprint (24 hex characters, like the agent memory's).
fn valid_fingerprint(s: &str) -> bool {
    s.len() == 24 && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl Filter {
    /// Target matches on the canonical form, the stored raw form or the target key; the
    /// word filters match exactly (both sides are stored lowercase).
    fn keeps(&self, r: &VulnRecord) -> bool {
        if let Some(t) = self.target.as_deref().map(str::trim)
            && !t.is_empty()
            && r.target != canonical_target(t)
            && r.target != t
            && r.target_key != target_key(t)
        {
            return false;
        }
        if let Some(s) = self.status.as_deref().map(str::trim)
            && !s.is_empty()
            && r.status != s.to_ascii_lowercase()
        {
            return false;
        }
        if let Some(s) = self.severity.as_deref().map(str::trim)
            && !s.is_empty()
            && r.severity != s.to_ascii_lowercase()
        {
            return false;
        }
        if let Some(v) = self.verification.as_deref().map(str::trim)
            && !v.is_empty()
            // Rows written before v3.7 carry no field and read as "unverified".
            && effective_verification(r) != v.to_ascii_lowercase()
        {
            return false;
        }
        true
    }
}

/// The verification word for a row, normalising the empty string that pre-v3.7
/// files deserialize to.
pub fn effective_verification(r: &VulnRecord) -> String {
    if r.verification.is_empty() {
        "unverified".into()
    } else {
        r.verification.clone()
    }
}

/// The database at [`path()`], severity desc then `last_seen` desc. Unreadable lines are
/// skipped with a warning on stderr; use [`list_at`] when the warnings matter.
pub fn list(filters: &Filter) -> Vec<VulnRecord> {
    let (rows, warnings) = list_at(&path(), filters);
    warn_all(&warnings);
    rows
}

/// [`list`] with the file explicit, returning the skip warnings instead of printing them.
pub fn list_at(path: &Path, filters: &Filter) -> (Vec<VulnRecord>, Vec<String>) {
    let (rows, mut warnings) = match read_at(path) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("{e:#}");
            return (vec![], vec![msg]);
        }
    };
    for r in &rows {
        if !valid_status(&r.status) {
            warnings.push(format!(
                "vulndb: {} has unknown status {:?}",
                r.fingerprint, r.status
            ));
        }
    }
    let mut out: Vec<VulnRecord> = rows.into_iter().filter(|r| filters.keeps(r)).collect();
    out.sort_by(|a, b| {
        sev_rank(&b.severity)
            .cmp(&sev_rank(&a.severity))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    (out, warnings)
}

/// The full fingerprint behind an operator-supplied one: exact, else a unique prefix of at
/// least 6 characters (the rule `readyhai agent-memory accept` uses).
pub fn resolve(rows: &[VulnRecord], fingerprint: &str) -> Option<String> {
    let fp = fingerprint.trim().to_ascii_lowercase();
    if rows.iter().any(|r| r.fingerprint == fp) {
        return Some(fp);
    }
    if fp.len() < 6 {
        return None;
    }
    let hits: Vec<String> = rows
        .iter()
        .filter(|r| r.fingerprint.starts_with(&fp))
        .map(|r| r.fingerprint.clone())
        .collect();
    match hits.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// `true` when `status` is one of [`STATUSES`].
pub fn valid_status(status: &str) -> bool {
    STATUSES.contains(&status.trim().to_ascii_lowercase().as_str())
}

/// Set the status of one record in the file at [`path()`]. `Ok(false)` = no such
/// fingerprint (or an ambiguous prefix).
pub fn set_status(fingerprint: &str, status: &str) -> Result<bool> {
    set_status_at(&path(), fingerprint, status)
}

/// True for the five verdict words a record can carry.
pub fn valid_verification(status: &str) -> bool {
    VERIFICATIONS.contains(&status)
}

/// Stamp one record with a verification verdict (see [`crate::exploits`]). Like
/// [`set_status`] this is an operator-surface write: it records what a probe proved,
/// never what a scan re-reported, so re-scans leave it alone. The engine stamps
/// through [`set_verification_at`] in its own read-modify-write pass; this mirror
/// of [`set_status`] stays for any single-fingerprint caller (file paths included).
#[allow(dead_code)] // mirrors set_status for future single-fp callers
pub fn set_verification(
    fingerprint: &str,
    verification: &str,
    template: &str,
) -> Result<(bool, Option<VulnRecord>)> {
    set_verification_at(&path(), fingerprint, verification, template)
}

/// [`set_verification`] with the file explicit. Returns (found, the stamped record)
/// so REST/CLI callers can report the row without a second read.
pub fn set_verification_at(
    path: &Path,
    fingerprint: &str,
    verification: &str,
    template: &str,
) -> Result<(bool, Option<VulnRecord>)> {
    let verification = verification.trim().to_ascii_lowercase();
    if !valid_verification(&verification) {
        bail!("verification must be one of {}", VERIFICATIONS.join("|"));
    }
    let (mut rows, warnings) = read_at(path)?;
    warn_all(&warnings);
    let Some(full) = resolve(&rows, fingerprint) else {
        return Ok((false, None));
    };
    let Some(r) = rows.iter_mut().find(|r| r.fingerprint == full) else {
        return Ok((false, None));
    };
    r.verification = verification;
    r.verified_by = (!template.trim().is_empty()).then(|| clean(template));
    r.verified_at = Some(now());
    let stamped = r.clone();
    write_rows(path, &rows)?;
    Ok((true, Some(stamped)))
}

/// [`set_status`] with the file explicit.
pub fn set_status_at(path: &Path, fingerprint: &str, status: &str) -> Result<bool> {
    let status = status.trim().to_ascii_lowercase();
    if !valid_status(&status) {
        bail!("status must be one of {}", STATUSES.join("|"));
    }
    let (mut rows, warnings) = read_at(path)?;
    warn_all(&warnings);
    let Some(full) = resolve(&rows, fingerprint) else {
        return Ok(false);
    };
    let Some(r) = rows.iter_mut().find(|r| r.fingerprint == full) else {
        return Ok(false);
    };
    r.status = status;
    write_rows(path, &rows)?;
    Ok(true)
}

#[cfg(test)]
mod tests;
