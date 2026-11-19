//! Repo-side data-quality QA: the checks a QA engineer runs on the *data* that feeds tests —
//! fixtures (CSV/JSON), SQL seed data, and the fixtures' hygiene (PII, staleness, references).
//! Everything reads only the snapshot; no live systems are touched.

pub(crate) mod csvscan;
pub(crate) mod hygiene;
pub(crate) mod jsonscan;
pub(crate) mod sqlscan;

pub(crate) use csvscan::{duplicate_key, null_violation};
pub(crate) use hygiene::{orphan_reference, pii_exposed, stale_dates};
pub(crate) use jsonscan::invalid_format;

use crate::checks::Check;
use crate::model::{Profile, TargetKind};
use crate::snapshot::Snapshot;

/// Files that look like test/seed data. Kept intentionally narrow so a big app repo does not
/// turn into a full ETL job.
pub(crate) fn data_files(snap: &Snapshot, want: &[&str]) -> Vec<String> {
    snap.files
        .iter()
        .filter(|f| {
            let l = f.to_lowercase();
            let name = l.rsplit('/').next().unwrap_or("");
            want.iter().any(|ext| name.ends_with(ext))
                && (l.contains("fixture")
                    || l.contains("seed")
                    || l.contains("sample")
                    || l.contains("testdata")
                    || l.contains("test_data")
                    || l.contains("mock")
                    || l.contains("/data/")
                    || l.starts_with("data/"))
        })
        .cloned()
        .collect()
}

pub fn checks() -> Vec<Check> {
    let k = &[TargetKind::Repo];
    vec![
        Check::new(
            "qa.data.null-violation",
            "Null / empty values in required columns",
            k,
            Profile::Quick,
            null_violation,
        )
        .qa(),
        Check::new(
            "qa.data.duplicate-key",
            "Duplicate keys in fixtures",
            k,
            Profile::Quick,
            duplicate_key,
        )
        .qa(),
        Check::new(
            "qa.data.invalid-format",
            "Malformed JSON fixtures",
            k,
            Profile::Quick,
            invalid_format,
        )
        .qa(),
        Check::new(
            "qa.data.sql-fixture",
            "SQL fixture hygiene",
            k,
            Profile::Quick,
            sqlscan::sql_fixture,
        )
        .qa(),
        Check::new(
            "qa.data.pii-exposed",
            "PII in test fixtures",
            k,
            Profile::Quick,
            pii_exposed,
        )
        .qa(),
        Check::new(
            "qa.data.stale-dates",
            "Stale date fixtures",
            k,
            Profile::Standard,
            stale_dates,
        )
        .qa(),
        Check::new(
            "qa.data.orphan-reference",
            "Foreign-key references without parents",
            k,
            Profile::Standard,
            orphan_reference,
        )
        .qa(),
    ]
}
