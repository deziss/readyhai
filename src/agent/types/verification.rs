//! Independent failure verification models, replay records, and pass^k verification summaries.

use serde::{Deserialize, Serialize};

/// What the verifier concluded about one failed case after replaying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyVerdict {
    /// All k replays reproduced the failure.
    Confirmed,
    /// Some, but not all, replays reproduced it.
    Flaky,
    /// None of the k replays reproduced it.
    NotReproduced,
    /// Not (fully) replayed: a state-changing request that is not safe to repeat, a burst, a budget or
    /// cancellation stop, or replays that could not be sent.
    Unverified,
}

impl VerifyVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyVerdict::Confirmed => "confirmed",
            VerifyVerdict::Flaky => "flaky",
            VerifyVerdict::NotReproduced => "not_reproduced",
            VerifyVerdict::Unverified => "unverified",
        }
    }
}

/// One replay of a failed case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayRecord {
    pub replay: u32,
    pub status_code: Option<u16>,
    pub latency_ms: u64,
    /// The oracle's verdict on the replay (PASS | FAIL | INCONCLUSIVE), or ERROR when it was not
    /// sent / did not complete.
    pub verdict: String,
    /// The replay failed the same way the original did.
    pub reproduced: bool,
    #[serde(default)]
    pub note: Option<String>,
}

/// The verifier's record for one failed case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub case_id: String,
    pub method: String,
    pub component: String,
    pub verdict: VerifyVerdict,
    /// Severity of the original failure (lowercase).
    pub severity: String,
    /// Replays asked for.
    pub k: u32,
    /// Replays that completed (got an answer that was judged).
    pub completed: u32,
    /// Completed replays that reproduced the failure.
    pub reproduced: u32,
    #[serde(default)]
    pub replays: Vec<ReplayRecord>,
    /// Why it was not replayed (`unverified-write`, burst, budget...) or how the replays ended.
    #[serde(default)]
    pub note: Option<String>,
    /// Status of the result before / after the verdict was applied.
    pub original_status: String,
    pub final_status: String,
    /// Run-relative evidence file; its `verification` section holds the replays' responses.
    #[serde(default)]
    pub evidence_file: Option<String>,
}

impl VerificationRecord {
    /// "2/2" for a confirmed failure, "1/2" for a flaky one; None when nothing was replayed.
    pub fn ratio(&self) -> Option<String> {
        (self.completed > 0).then(|| format!("{}/{}", self.reproduced, self.k))
    }
}

/// What the verifier did in one run. Stored on the evidence ledger.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VerificationSummary {
    /// Replays per failed case (0 = verification was off).
    pub k: u32,
    /// FAIL results the verifier looked at.
    pub candidates: usize,
    /// Candidates that got all k replays (confirmed + flaky + not reproduced).
    pub replayed: usize,
    pub confirmed: usize,
    pub flaky: usize,
    pub not_reproduced: usize,
    pub unverified: usize,
    /// HTTP requests the replays sent (charged to the run budget).
    pub replay_requests: usize,
    /// pass^k: the share of replayed failures that reproduced on all k replays (confirmed / replayed).
    /// None when nothing was replayed.
    #[serde(default)]
    pub pass_k: Option<f64>,
    /// Why verification stopped early or did not run (budget, cancellation, disabled).
    #[serde(default)]
    pub stopped: Option<String>,
    #[serde(default)]
    pub records: Vec<VerificationRecord>,
}

impl VerificationSummary {
    /// Recompute the counters and pass^k from `records`.
    pub fn tally(&mut self) {
        let n = |v: VerifyVerdict| self.records.iter().filter(|r| r.verdict == v).count();
        self.candidates = self.records.len();
        self.confirmed = n(VerifyVerdict::Confirmed);
        self.flaky = n(VerifyVerdict::Flaky);
        self.not_reproduced = n(VerifyVerdict::NotReproduced);
        self.unverified = n(VerifyVerdict::Unverified);
        self.replayed = self.confirmed + self.flaky + self.not_reproduced;
        self.pass_k = (self.replayed > 0).then(|| self.confirmed as f64 / self.replayed as f64);
    }

    /// "75%" / "not evaluated".
    pub fn pass_k_text(&self) -> String {
        match self.pass_k {
            Some(p) => format!("{:.0}%", p * 100.0),
            None => "not evaluated".into(),
        }
    }

    pub fn record(&self, case_id: &str) -> Option<&VerificationRecord> {
        self.records.iter().find(|r| r.case_id == case_id)
    }
}
