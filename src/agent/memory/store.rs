//! File persistence, storage paths, strict reading, and quarantine for memory files.

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

use super::sanitize::{clean_ident, clean_text, days_between, file_date};
use super::types::{
    Acceptance, Accepted, BaselineState, BaselinesInEffect, DefectStatus, Loaded, MAX_FILE_BYTES,
    MAX_TEXT, Memory, SCHEMA,
};
use crate::agent::store::RunLock;
use crate::llm::write_atomic;

/// The target as the memory knows it: scheme, host, port and path of the URL; no userinfo, query
/// or fragment, no trailing slash. `http://h:8080` and `http://h:8080/` are the same target.
pub fn canonical_target(raw: &str) -> String {
    match reqwest::Url::parse(raw.trim()) {
        Ok(u) if u.host_str().is_some() => {
            let mut s = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
            if let Some(p) = u.port() {
                s.push_str(&format!(":{p}"));
            }
            let path = u.path().trim_end_matches('/');
            s.push_str(path);
            s
        }
        _ => raw.trim().to_string(),
    }
}

/// The memory key of a target: the first 16 hex characters of the SHA-256 of its canonical form
/// (the same construction as `engine::target_key` for a web target).
pub fn target_key(raw: &str) -> String {
    crate::model::sha256_hex(canonical_target(raw).as_bytes())[..16].to_string()
}

/// Every key a QA baseline of this target may be stored under: `engine::target_key` hashes the
/// target as typed, so `qa http://h:8080` and `qa http://h:8080/` differ.
fn baseline_keys(raw: &str) -> Vec<String> {
    let canon = canonical_target(raw);
    let mut v: Vec<String> = [
        raw.trim().to_string(),
        canon.clone(),
        format!("{canon}/"),
        raw.trim().trim_end_matches('/').to_string(),
    ]
    .iter()
    .map(|s| crate::model::sha256_hex(s.as_bytes())[..16].to_string())
    .collect();
    v.sort();
    v.dedup();
    v
}

/// Which baselines exist for the target under `data/baselines` (written by `qa` runs and promoted
/// by `baseline accept`), and the date each was written.
pub fn observe_baselines(data: &Path, raw_target: &str) -> BaselinesInEffect {
    let dir = data.join("baselines");
    let newest = |files: Vec<PathBuf>| -> BaselineState {
        let dates: Vec<String> = files
            .iter()
            .filter(|p| p.is_file())
            .filter_map(|p| file_date(p))
            .collect();
        BaselineState {
            exists: !dates.is_empty(),
            accepted: dates.into_iter().max(),
        }
    };
    let mut perf = vec![];
    let mut spec = vec![];
    let mut visual = vec![];
    for k in baseline_keys(raw_target) {
        perf.push(dir.join(format!("{k}.perf.json")));
        spec.push(dir.join(format!("{k}.spec-full.json")));
        spec.push(dir.join(format!("{k}.spec.json")));
        if let Ok(rd) = std::fs::read_dir(dir.join(&k).join("visual")) {
            visual.extend(
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "png")),
            );
        }
    }
    BaselinesInEffect {
        perf: newest(perf),
        spec: newest(spec),
        visual: newest(visual),
    }
}

pub fn memory_path(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("{key}.json"))
}

pub(crate) fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 64 && key.chars().all(|c| c.is_ascii_hexdigit())
}

/// Read the memory of `key`. `Ok(None)`: there is none. `Err(why)`: the file exists and cannot be
/// trusted (see the module docs); nothing is changed on disk.
pub fn read_strict(dir: &Path, key: &str) -> std::result::Result<Option<Memory>, String> {
    let path = memory_path(dir, key);
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot be read: {e}")),
    };
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("is larger than {} bytes", MAX_FILE_BYTES));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot be read: {e}"))?;
    let mut m: Memory =
        serde_json::from_slice(&bytes).map_err(|e| format!("is not valid memory JSON ({e})"))?;
    if m.schema == 0 {
        return Err("has no schema version".into());
    }
    if m.schema > SCHEMA {
        return Err(format!(
            "was written by a newer readyhai (schema {}, this build reads {SCHEMA})",
            m.schema
        ));
    }
    if m.target_key != key {
        return Err("belongs to another target".into());
    }
    if m.digest != m.digest_of() {
        return Err("fails its integrity check (edited outside readyhai?)".into());
    }
    m.normalize();
    Ok(Some(m))
}

/// A memory file that cannot be trusted is moved aside, never deleted: `<key>.json.corrupt-<tag>`.
pub(crate) fn quarantine(dir: &Path, key: &str, tag: &str) -> std::io::Result<PathBuf> {
    let from = memory_path(dir, key);
    let tag = clean_ident(tag, 40).replace(['/', ' '], "_");
    let mut to = dir.join(format!("{key}.json.corrupt-{tag}"));
    let mut n = 1;
    while to.exists() {
        n += 1;
        to = dir.join(format!("{key}.json.corrupt-{tag}-{n}"));
    }
    std::fs::rename(&from, &to)?;
    Ok(to)
}

/// Read the memory of a target for a run; never fails. A file that cannot be trusted is moved
/// aside (under the lock) and the run starts empty, with a note. `tag` names the backup.
pub fn load(dir: &Path, key: &str, target: &str, tag: &str, now: &str) -> Loaded {
    let fresh = || Memory::fresh(key, target, now);
    match read_strict(dir, key) {
        Ok(Some(memory)) => Loaded {
            memory,
            existed: true,
            notes: vec![],
        },
        Ok(None) => Loaded {
            memory: fresh(),
            existed: false,
            notes: vec![],
        },
        Err(why) => {
            let mut notes = vec![];
            // set it aside under the lock; a writer that repaired it meanwhile wins
            match RunLock::acquire(dir, key) {
                Ok(_lock) => match read_strict(dir, key) {
                    Ok(Some(memory)) => {
                        return Loaded {
                            memory,
                            existed: true,
                            notes,
                        };
                    }
                    Ok(None) => {}
                    Err(why2) => match quarantine(dir, key, tag) {
                        Ok(bak) => notes.push(format!(
                            "agent memory {} {why2}: it was moved to {} and ignored; this run starts with an empty memory",
                            memory_path(dir, key).display(),
                            bak.display()
                        )),
                        Err(e) => notes.push(format!(
                            "agent memory {} {why2} and could not be moved aside ({e}); it is ignored for this run",
                            memory_path(dir, key).display()
                        )),
                    },
                },
                Err(e) => notes.push(format!(
                    "agent memory {} {why} and could not be set aside ({e}); it is ignored for this run",
                    memory_path(dir, key).display()
                )),
            }
            Loaded {
                memory: fresh(),
                existed: false,
                notes,
            }
        }
    }
}

/// The memory of a target as it is right now, read without the lock and without touching the
/// file: an unusable file reads as empty, with a note (it is set aside by [`Update::begin`] when the
/// run ends). For work that must not hold the lock, such as the middle of a run.
pub fn peek(dir: &Path, target: &str, now: &str) -> (Memory, Vec<String>) {
    let key = target_key(target);
    match read_strict(dir, &key) {
        Ok(Some(m)) => (m, vec![]),
        Ok(None) => (Memory::fresh(&key, &canonical_target(target), now), vec![]),
        Err(why) => (
            Memory::fresh(&key, &canonical_target(target), now),
            vec![format!(
                "agent memory {} {why}: it is ignored",
                memory_path(dir, &key).display()
            )],
        ),
    }
}

/// Write `mem` atomically (temp file + rename), stamping `updated` and the digest. The caller holds
/// the per-target lock.
pub(crate) fn write_memory(dir: &Path, mem: &mut Memory, now: &str) -> Result<()> {
    if !valid_key(&mem.target_key) {
        bail!("invalid memory key");
    }
    mem.schema = SCHEMA;
    mem.updated = now.to_string();
    mem.digest = mem.digest_of();
    std::fs::create_dir_all(dir)?;
    write_atomic(
        &memory_path(dir, &mem.target_key),
        serde_json::to_string_pretty(mem)?.as_bytes(),
    )?;
    Ok(())
}

/// Read the memory of a target for display or the API: Ok(None) when there is none, Err when the
/// file cannot be trusted. Never changes anything on disk.
pub fn inspect(dir: &Path, target: &str) -> Result<Option<Memory>> {
    let key = target_key(target);
    read_strict(dir, &key)
        .map_err(|why| anyhow::anyhow!("agent memory {} {why}", memory_path(dir, &key).display()))
}

/// Accept a known open defect until `expires` (`YYYY-MM-DD`, not in the past). `fingerprint` may
/// be a unique prefix of at least 6 characters. Refuses a fixed defect (nothing to accept), an
/// empty reason, an invalid or past date and an unreadable memory file.
pub fn accept(
    dir: &Path,
    target: &str,
    fingerprint: &str,
    by: &str,
    reason: &str,
    expires: &str,
    today: &str,
    now: &str,
) -> Result<Accepted> {
    let reason = clean_text(reason, MAX_TEXT);
    if reason.is_empty() {
        bail!("an acceptance needs a reason");
    }
    let by = clean_text(by, 80);
    let by = if by.is_empty() {
        "operator".to_string()
    } else {
        by
    };
    match days_between(today, expires) {
        None => bail!("expires must be a valid date, YYYY-MM-DD"),
        Some(d) if d < 0 => bail!("expires {expires} is in the past (today is {today})"),
        Some(_) => {}
    }
    let fp = fingerprint.trim().to_ascii_lowercase();
    if fp.len() < 6 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("fingerprint must be at least 6 hex characters (see `readyhai agent-memory show`)");
    }
    let key = target_key(target);
    let _lock = RunLock::acquire(dir, &key)?;
    let mut mem = match read_strict(dir, &key) {
        Ok(Some(m)) => m,
        Ok(None) => bail!("no agent memory for {target}"),
        Err(why) => bail!(
            "agent memory {} {why}; `readyhai agent-memory forget` clears it",
            memory_path(dir, &key).display()
        ),
    };
    let hits: Vec<String> = mem
        .defects
        .keys()
        .filter(|k| k.starts_with(&fp))
        .cloned()
        .collect();
    let full = match hits.as_slice() {
        [] => bail!("no known defect with fingerprint {fp}"),
        [one] => one.clone(),
        _ => bail!(
            "fingerprint prefix {fp} matches {} defects; give more characters",
            hits.len()
        ),
    };
    let Some(d) = mem.defects.get_mut(&full) else {
        bail!("no known defect with fingerprint {fp}");
    };
    if d.status == DefectStatus::Fixed {
        bail!("defect {full} is fixed; there is nothing to accept");
    }
    let acceptance = Acceptance {
        by,
        reason,
        expires: expires.to_string(),
        accepted_at: today.to_string(),
    };
    d.accepted = Some(acceptance.clone());
    let out = Accepted {
        fingerprint: full,
        rule: d.rule.clone(),
        endpoint: d.endpoint.clone(),
        severity: d.severity.clone(),
        acceptance,
    };
    write_memory(dir, &mut mem, now)?;
    Ok(out)
}

/// Delete the memory of a target (and every backup of a corrupt file stays). Returns whether there
/// was a file.
pub fn forget(dir: &Path, target: &str) -> Result<bool> {
    let key = target_key(target);
    let _lock = RunLock::acquire(dir, &key)?;
    match std::fs::remove_file(memory_path(dir, &key)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Where the agent's memory of every target lives: `<data_dir>/memory`.
pub fn dir() -> PathBuf {
    crate::engine::data_dir().join("memory")
}

/// The directory memory lives in, unless it is switched off (`READYHAI_AGENT_MEMORY=off`).
pub fn default_dir() -> Option<PathBuf> {
    let off = std::env::var("READYHAI_AGENT_MEMORY")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "off" | "0" | "false" | "no" | "none"
            )
        })
        .unwrap_or(false);
    (!off).then(dir)
}
