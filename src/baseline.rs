//! Baseline = accepted fingerprints. Portable JSON so CI can carry it between runs.
use crate::model::{Finding, FindingStatus, Run};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub run_id: String,
    pub target: String,
    pub accepted: String,
    pub fingerprints: BTreeSet<String>,
}

impl Baseline {
    pub fn from_run(run: &Run, accepted: String) -> Baseline {
        Baseline {
            version: 1,
            run_id: run.id.clone(),
            target: run.target.raw.clone(),
            accepted,
            fingerprints: run
                .findings
                .iter()
                .filter(|f| f.status != FindingStatus::Suppressed)
                .map(|f| f.fingerprint.clone())
                .collect(),
        }
    }
    pub fn load(path: &Path) -> Result<Option<Baseline>> {
        if !path.is_file() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&std::fs::read_to_string(path)?)?))
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

/// Mark New/Existing; returns how many baseline fingerprints disappeared (fixed).
pub fn apply(findings: &mut [Finding], base: Option<&Baseline>) -> usize {
    let Some(b) = base else { return 0 };
    let mut seen = BTreeSet::new();
    for f in findings.iter_mut() {
        if b.fingerprints.contains(&f.fingerprint) {
            seen.insert(f.fingerprint.clone());
            if f.status == FindingStatus::New {
                f.status = FindingStatus::Existing;
            }
        }
    }
    b.fingerprints.len() - seen.len()
}
