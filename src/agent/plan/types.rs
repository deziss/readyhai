//! Planning domain models, depths, PRNG seed generation, and limits.

use super::super::types::PlannedCase;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) static NULL: Value = Value::Null;

pub const MAX_CASES: usize = 60;
pub(crate) const MAX_LLM_CASES: usize = 12;
pub(crate) const XSS: &str = "\"><script>alert(1)</script>";
pub(crate) const SQLI: &str = "' OR '1'='1' --";

/// How deep a run plans, derived from its profile (see [`Depth::from_profile`]).
///
/// * `Quick` (`quick`): the baseline only, the crawl-grounded smoke test. No OpenAPI-derived cases
///   (so no spec-declared bursts or stateful chains) and no LLM extras.
/// * `Standard` (`standard`, and any profile the planner does not know, e.g. `discovery-scan`):
///   baseline + OpenAPI-derived cases (top 15 operations) + validated LLM extras when an LLM is
///   configured (at most 12).
/// * `Deep` (`deep`): everything `Standard` plans, over more of the spec (top 30 operations), with
///   more LLM extras (at most 20) and a higher plan cap.
///
/// A concurrency burst is planned only from the spec (a POST whose request schema yields a valid
/// body), at `Standard` and `Deep`: a crawled form gives nothing to build a valid body from.
///
/// The seed never depends on the depth: the same run id plans the same way at any profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    Quick,
    Standard,
    Deep,
}

impl Depth {
    pub fn from_profile(profile: &str) -> Depth {
        match profile.trim().to_ascii_lowercase().as_str() {
            "quick" => Depth::Quick,
            "deep" => Depth::Deep,
            _ => Depth::Standard,
        }
    }

    /// OpenAPI operations planned from (None: the spec is not used at all).
    pub(crate) fn spec_ops(self) -> Option<usize> {
        match self {
            Depth::Quick => None,
            Depth::Standard => Some(15),
            Depth::Deep => Some(30),
        }
    }

    /// Most LLM-proposed cases (0: the LLM is not asked).
    pub(crate) fn llm_cases(self) -> usize {
        match self {
            Depth::Quick => 0,
            Depth::Standard => MAX_LLM_CASES,
            Depth::Deep => 20,
        }
    }

    /// Most boundary/negative probes planned for one operation from the spec's constraints.
    pub(crate) fn probes_per_op(self) -> usize {
        match self {
            Depth::Quick => 0,
            Depth::Standard => 4,
            Depth::Deep => 8,
        }
    }

    /// Most such probes in a plan, over all operations.
    pub(crate) fn probes_total(self) -> usize {
        match self {
            Depth::Quick => 0,
            Depth::Standard => 24,
            Depth::Deep => 60,
        }
    }

    /// Plan cap before the pipeline's own step/profile limits.
    pub(crate) fn max_cases(self) -> usize {
        match self {
            Depth::Deep => 100,
            _ => MAX_CASES,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PlanOutcome {
    pub cases: Vec<PlannedCase>,
    /// deterministic | openapi | <either>+llm
    pub source: String,
    pub notes: Vec<String>,
    pub llm_cases: usize,
    /// Synthesis seed (see [`seed_from_run_id`]). Everything random in planning derives from it,
    /// and it is also written into `notes`, so a stored plan can be re-synthesised exactly.
    pub seed: u64,
}

/// The profile plans from the OpenAPI spec (everything but `quick`).
pub fn plans_from_spec(profile: &str) -> bool {
    Depth::from_profile(profile).spec_ops().is_some()
}

/// The planner's synthesis seed for a run: the first 8 bytes of SHA-256(run id). Never the clock,
/// so the same run id always produces the same prompt and the same archetype selection.
pub fn seed_from_run_id(run_id: &str) -> u64 {
    let d = Sha256::digest(run_id.as_bytes());
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// splitmix64: a tiny, specified PRNG so a seed means the same thing in every build.
#[derive(Debug, Clone)]
pub(crate) struct SeededRng(pub(crate) u64);

impl SeededRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Fisher-Yates shuffle.
    pub(crate) fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }
}
