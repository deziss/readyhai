//! Supply-chain and API-contract checks: OSV reachability, OpenSSF Scorecard, Spectral, oasdiff,
//! and mutation-score reading (no mutation run: reports and configs only).

pub mod api_contract;
pub mod helpers;
pub mod mutation;
pub mod osv;
pub mod scorecard;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use api_contract::{parse_oasdiff, parse_spectral};
#[allow(unused_imports)]
pub use mutation::{MutationScore, parse_cargo_mutants, parse_mutmut_meta, parse_stryker};
#[allow(unused_imports)]
pub use osv::{Reach, enrich_osv_with_ast, parse_osv};
#[allow(unused_imports)]
pub use scorecard::{github_slug, parse_scorecard, remote_url, slug_from_target_raw};

use crate::checks::Check;
use crate::model::Profile;
use helpers::repo;

pub fn checks() -> Vec<Check> {
    vec![
        Check::new(
            "tool.osv_reachability",
            "Known vulnerabilities with reachability (OSV-Scanner call analysis)",
            &repo(),
            Profile::Standard,
            osv::osv_reachability,
        )
        .tool("osv-scanner"),
        Check::new(
            "tool.scorecard",
            "OpenSSF Scorecard (GitHub remote)",
            &repo(),
            Profile::Standard,
            scorecard::scorecard,
        )
        .tool("scorecard"),
        Check::new(
            "tool.spectral",
            "OpenAPI lint (Spectral, oas ruleset)",
            &repo(),
            Profile::Quick,
            api_contract::spectral,
        )
        .tool("spectral"),
        Check::new(
            "tool.oasdiff",
            "OpenAPI breaking changes vs accepted baseline (oasdiff)",
            &repo(),
            Profile::Quick,
            api_contract::oasdiff,
        )
        .tool("oasdiff"),
        Check::new(
            "qa.suite.mutation",
            "Mutation score from existing reports",
            &repo(),
            Profile::Standard,
            mutation::mutation,
        ),
    ]
}
