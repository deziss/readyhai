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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Severity, Verdict};
    use crate::policy::{self, Policy};

    fn item(rule: &str, key: &str) -> Finding {
        let mut f = Finding::new("qa.suite.routes", rule, Category::Quality, Severity::Medium, format!("{key} is untested"), "routes").fp_key(key.to_string());
        f.finalize();
        f
    }

    fn accepted(fs: &[Finding]) -> Baseline {
        Baseline {
            version: 1,
            run_id: "r".into(),
            target: "t".into(),
            accepted: "now".into(),
            fingerprints: fs.iter().map(|f| f.fingerprint.clone()).collect(),
        }
    }

    /// QA suite defects carry one fingerprint PER ITEM (route, smell, licence, a11y rule+page,
    /// visual viewport...), so a new item in an already-accepted bucket is New and gates.
    #[test]
    fn a_new_item_in_an_accepted_bucket_gates() {
        let pol = Policy::load(None).unwrap();
        let old = vec![item("qa.suite.untested_routes", "route:GET /a"), item("qa.suite.untested_routes", "route:GET /b")];
        let base = accepted(&old);

        // same two routes: both Existing, only_new gate passes
        let mut same = old.clone();
        let fixed = apply(&mut same, Some(&base));
        assert_eq!(fixed, 0);
        assert!(same.iter().all(|f| f.status == FindingStatus::Existing));
        assert_eq!(policy::verdict(&pol, &same, &[]).0, Verdict::Pass);

        // a THIRD untested route appears: the accepted two stay Existing, the new one is New and warns
        let mut grown = old.clone();
        grown.push(item("qa.suite.untested_routes", "route:GET /c"));
        apply(&mut grown, Some(&base));
        assert_eq!(grown.iter().filter(|f| f.status == FindingStatus::New).count(), 1);
        assert_eq!(grown[2].status, FindingStatus::New);
        assert_eq!(policy::verdict(&pol, &grown, &[]).0, Verdict::Warn);

        // one route got a test: its fingerprint disappears and is counted as fixed
        let mut shrunk = vec![old[0].clone()];
        assert_eq!(apply(&mut shrunk, Some(&base)), 1);

        // the old single-bucket key would have hidden the new route
        let bucket = |k: &str| { let mut f = item("qa.suite.untested_routes", "untested_routes"); f.title = k.into(); f.finalize(); f };
        let b0 = bucket("2 routes");
        let base0 = accepted(&[b0]);
        let mut hidden = vec![bucket("3 routes")];
        apply(&mut hidden, Some(&base0));
        assert_eq!(hidden[0].status, FindingStatus::Existing, "documents why per-item keys are needed");
    }
}
