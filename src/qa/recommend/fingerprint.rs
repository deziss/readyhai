//! Defect fingerprinting and baseline finding status resolution.

use crate::model::{FindingStatus, Run, sha256_hex};

/// Same formula as Finding::finalize: sha256(rule \0 fp_key)[..12 bytes] hex.
pub fn fingerprint(rule: &str, fp_key: &str) -> String {
    let mut b = rule.as_bytes().to_vec();
    b.push(0);
    b.extend_from_slice(fp_key.as_bytes());
    sha256_hex(&b)[..24].to_string()
}

/// Status of a defect made of `keys` (rule, fp_key) members, judged on their Finding twins.
/// None when no member has a twin in the run.
pub(crate) fn merged_status(keys: &[(String, String)], run: &Run) -> Option<FindingStatus> {
    let sts: Vec<FindingStatus> = keys
        .iter()
        .filter_map(|(r, k)| {
            let fp = fingerprint(r, k);
            run.findings
                .iter()
                .find(|f| f.fingerprint == fp)
                .map(|f| f.status)
        })
        .collect();
    if sts.is_empty() {
        None
    } else if sts.contains(&FindingStatus::New) {
        Some(FindingStatus::New)
    } else if sts.contains(&FindingStatus::Existing) {
        Some(FindingStatus::Existing)
    } else {
        Some(FindingStatus::Suppressed)
    }
}
