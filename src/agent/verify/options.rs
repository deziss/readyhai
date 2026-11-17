use std::collections::BTreeSet;
use std::time::Duration;

use crate::agent::exec::Credentials;
use crate::agent::types::{CaseExecutionResult, Leftover, VerificationSummary};

/// Replays per failed case when nothing else is configured.
pub const DEFAULT_K: u32 = 2;
/// Upper bound for `READYHAI_VERIFY_K`.
pub const MAX_K: u32 = 5;
/// Stop verifying after this many candidates in a row ended in a transport error.
pub const MAX_UNREACHABLE: u32 = 3;

/// `READYHAI_VERIFY_K` text to a replay count: unset or unparsable = 2, capped at 5, `0` = off.
pub fn parse_k(raw: Option<&str>) -> u32 {
    match raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<u32>().ok())
    {
        Some(n) => n.min(MAX_K),
        None => DEFAULT_K,
    }
}

pub fn k_from_env() -> u32 {
    parse_k(std::env::var("READYHAI_VERIFY_K").ok().as_deref())
}

pub struct VerifyOptions<'a> {
    /// Replays per failed case; 0 = verification off.
    pub k: u32,
    /// Ids of planned cases the agent's memory knows as flaky: their failures get [`MAX_K`]
    /// replays (when verification is on at all).
    pub raise_k: &'a BTreeSet<String>,
    pub dry_run: bool,
    pub is_spa_target: bool,
    pub credentials: &'a Credentials,
    pub timeout: Duration,
}

/// No case is known as flaky: every failure gets the run's k.
pub fn no_raise() -> &'static BTreeSet<String> {
    static NONE: BTreeSet<String> = BTreeSet::new();
    &NONE
}

/// Replays for one failed case: the run's k, or the maximum when memory knows the case as flaky.
pub(crate) fn k_for(r: &CaseExecutionResult, opts: &VerifyOptions) -> u32 {
    let base = r
        .case_id
        .strip_suffix("-M1")
        .or_else(|| r.case_id.strip_suffix("-B"))
        .unwrap_or(&r.case_id);
    if opts.k > 0 && opts.k < MAX_K && opts.raise_k.contains(base) {
        MAX_K
    } else {
        opts.k
    }
}

pub struct VerifyOutcome {
    pub summary: VerificationSummary,
    /// Resources a replay created whose id was not announced: they cannot be torn down by id.
    pub unidentified: Vec<Leftover>,
}
