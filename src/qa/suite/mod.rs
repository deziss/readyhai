//! Repo-side senior-QA checks: test-suite quality (coverage, untested routes, smells)
//! and release quality (EOL runtimes, migrations up/down/up, licences).
//! Everything here reads only the snapshot and `<run>/out`; the migration check is the only
//! one that starts containers.

pub(crate) mod common;
pub(crate) mod coverage;
pub(crate) mod eol;
pub(crate) mod licenses;
pub(crate) mod migrations;
pub(crate) mod routes;
pub(crate) mod smells;

#[cfg(test)]
mod tests;

pub(crate) use common::is_test_path;
pub(crate) use coverage::coverage;
pub(crate) use eol::eol;
pub(crate) use licenses::licenses;
pub(crate) use migrations::migrations;
pub(crate) use routes::{extract_routes, route_segments, routes};
pub(crate) use smells::smells;

use crate::checks::Check;
use crate::model::{Profile, TargetKind};

pub fn checks() -> Vec<Check> {
    let k = &[TargetKind::Repo];
    vec![
        Check::new(
            "qa.suite.coverage",
            "Test coverage report",
            k,
            Profile::Quick,
            coverage,
        )
        .qa(),
        Check::new(
            "qa.suite.routes",
            "Routes without tests",
            k,
            Profile::Quick,
            routes,
        )
        .qa(),
        Check::new("qa.suite.smells", "Test smells", k, Profile::Quick, smells).qa(),
        Check::new(
            "qa.release.eol",
            "End-of-life runtimes",
            k,
            Profile::Quick,
            eol,
        )
        .qa(),
        Check::new(
            "qa.release.migrations",
            "Database migrations up/down/up",
            k,
            Profile::Standard,
            migrations,
        )
        .qa(),
        Check::new(
            "qa.release.licenses",
            "Dependency licences",
            k,
            Profile::Quick,
            licenses,
        )
        .qa(),
    ]
}
