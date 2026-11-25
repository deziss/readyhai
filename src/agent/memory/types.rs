//! Core domain types for target memory across runs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::sanitize::{
    clean_class, clean_ident, clean_method, clean_severity, clean_text, days_between,
    valid_fingerprint,
};

pub const SCHEMA: u32 = 1;
/// Run aggregates kept.
pub const MAX_RUNS: usize = 50;
/// A defect, flaky entry or operation not seen for this long is forgotten.
pub const RETENTION_DAYS: i64 = 90;
/// A fixed defect is re-tested first for this long after it was fixed.
pub const RECENT_FIX_DAYS: i64 = 30;
/// Outcomes kept per case class.
pub const FLAKY_WINDOW: usize = 20;
pub const MAX_DEFECTS: usize = 500;
pub const MAX_OPERATIONS: usize = 1000;
pub const MAX_CLASSES: usize = 2000;
/// Reproduction case classes kept per defect.
pub const MAX_REPRO: usize = 8;
/// A memory file larger than this is not read.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_IDENT: usize = 64;
pub const MAX_ENDPOINT: usize = 200;
pub const MAX_TEXT: usize = 300;
/// Planner notes and report lists are capped.
pub(crate) const MAX_LISTED: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefectStatus {
    Open,
    Fixed,
    Regressed,
}

impl DefectStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DefectStatus::Open => "open",
            DefectStatus::Fixed => "fixed",
            DefectStatus::Regressed => "regressed",
        }
    }
}

/// An operator's decision to live with a defect for a while. Valid through `expires` (inclusive);
/// afterwards the defect blocks again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acceptance {
    pub by: String,
    pub reason: String,
    /// `YYYY-MM-DD`.
    pub expires: String,
    #[serde(default)]
    pub accepted_at: String,
}

impl Acceptance {
    /// Still in force on `today`?
    pub fn is_effective(&self, today: &str) -> bool {
        matches!(days_between(today, &self.expires), Some(d) if d >= 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownDefect {
    /// The failing check (`authz`, `server_error`, ...).
    pub rule: String,
    /// Endpoint template (record ids collapsed), or the list of endpoints of a merged server error.
    pub endpoint: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub technique: String,
    pub severity: String,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_at: Option<String>,
    pub status: DefectStatus,
    pub runs_seen: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Acceptance>,
    /// Case classes (`technique|METHOD|endpoint|role`) whose failure defines the defect: the
    /// planner re-tests them first, and the defect is fixed when they all pass.
    #[serde(default)]
    pub repro: Vec<String>,
}

/// Outcomes of one case class over the last runs that executed it: `p` passed, `f` failed, `k`
/// flaky (failed on some attempts only), oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlakyHistory {
    /// `METHOD endpoint` the class belongs to.
    pub operation: String,
    pub last_seen: String,
    pub recent: String,
    #[serde(default)]
    pub pass: u32,
    #[serde(default)]
    pub fail: u32,
    #[serde(default)]
    pub flaky: u32,
}

impl FlakyHistory {
    pub(crate) fn recount(&mut self) {
        let kept: Vec<char> = self
            .recent
            .chars()
            .filter(|c| matches!(c, 'p' | 'f' | 'k'))
            .collect();
        let start = kept.len().saturating_sub(FLAKY_WINDOW);
        self.recent = kept[start..].iter().collect();
        let n = |c: char| self.recent.chars().filter(|x| *x == c).count() as u32;
        self.pass = n('p');
        self.fail = n('f');
        self.flaky = n('k');
    }

    pub(crate) fn push(&mut self, outcome: char) {
        self.recent.push(outcome);
        self.recount();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OperationMemory {
    pub last_run: String,
    pub last_at: String,
    pub planned: u32,
    pub executed: u32,
    pub pass: u32,
    pub fail: u32,
    pub inconclusive: u32,
    #[serde(default)]
    pub techniques: Vec<String>,
    /// pass | fail | inconclusive | not_run
    pub last_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BaselineState {
    pub exists: bool,
    /// Date the baseline file was last written (when it was accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BaselinesInEffect {
    pub perf: BaselineState,
    pub spec: BaselineState,
    pub visual: BaselineState,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RunAggregate {
    pub run_id: String,
    pub at: String,
    #[serde(default)]
    pub dry_run: bool,
    pub planned: u32,
    pub executed: u32,
    pub pass: u32,
    pub fail: u32,
    pub inconclusive: u32,
    pub blocked: u32,
    pub skipped: u32,
    pub flaky: u32,
    pub defects: u32,
    pub new: u32,
    pub still_open: u32,
    pub fixed: u32,
    pub regressed: u32,
    /// Gate verdict of the run (GO | CONDITIONAL_GO | NO_GO | ...).
    #[serde(default)]
    pub verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Memory {
    pub schema: u32,
    pub target_key: String,
    /// The target as the memory knows it (canonical URL, no query).
    pub target: String,
    pub created: String,
    pub updated: String,
    /// SHA-256 of the JSON serialization of `Memory` with this field empty.
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub defects: BTreeMap<String, KnownDefect>,
    #[serde(default)]
    pub flaky: BTreeMap<String, FlakyHistory>,
    #[serde(default)]
    pub operations: BTreeMap<String, OperationMemory>,
    #[serde(default)]
    pub baselines: BaselinesInEffect,
    #[serde(default)]
    pub runs: Vec<RunAggregate>,
}

impl Memory {
    pub fn fresh(key: &str, target: &str, now: &str) -> Self {
        Memory {
            schema: SCHEMA,
            target_key: key.to_string(),
            target: clean_ident(target, MAX_ENDPOINT),
            created: now.to_string(),
            updated: now.to_string(),
            ..Default::default()
        }
    }

    pub fn digest_of(&self) -> String {
        let mut c = self.clone();
        c.digest.clear();
        hex::encode(Sha256::digest(serde_json::to_vec(&c).unwrap_or_default()))
    }

    /// Re-impose every limit and the character sets on what was read (defence in depth: the digest
    /// proves the file is as written, not that what was written is sane).
    pub(crate) fn normalize(&mut self) {
        self.target = clean_ident(&self.target, MAX_ENDPOINT);
        for r in &mut self.runs {
            r.run_id = clean_ident(&r.run_id, MAX_IDENT);
            r.verdict = clean_ident(&r.verdict, MAX_IDENT);
        }
        let n = self.runs.len();
        if n > MAX_RUNS {
            self.runs.drain(..n - MAX_RUNS);
        }
        self.defects.retain(|fp, _| valid_fingerprint(fp));
        for d in self.defects.values_mut() {
            d.rule = clean_ident(&d.rule, MAX_IDENT);
            d.endpoint = clean_ident(&d.endpoint, MAX_ENDPOINT);
            d.technique = clean_ident(&d.technique, MAX_IDENT);
            d.severity = clean_severity(&d.severity);
            d.methods = d.methods.iter().map(|m| clean_method(m)).collect();
            d.methods.sort();
            d.methods.dedup();
            d.repro = d
                .repro
                .iter()
                .map(|r| clean_class(r))
                .take(MAX_REPRO)
                .collect();
            if let Some(a) = d.accepted.as_mut() {
                a.by = clean_text(&a.by, 80);
                a.reason = clean_text(&a.reason, MAX_TEXT);
            }
        }
        self.flaky = std::mem::take(&mut self.flaky)
            .into_iter()
            .map(|(k, mut f)| {
                f.operation = clean_ident(&f.operation, MAX_ENDPOINT);
                f.recount();
                (clean_class(&k), f)
            })
            .collect();
        self.operations = std::mem::take(&mut self.operations)
            .into_iter()
            .map(|(k, v)| (clean_ident(&k, MAX_ENDPOINT), v))
            .collect();
        for o in self.operations.values_mut() {
            o.last_run = clean_ident(&o.last_run, MAX_IDENT);
            o.techniques = o
                .techniques
                .iter()
                .map(|t| clean_ident(t, MAX_IDENT))
                .take(8)
                .collect();
        }
        self.cap();
    }

    /// Drop what is too old and what exceeds the caps (oldest first, then by key: deterministic).
    pub(crate) fn prune(&mut self, today: &str) {
        let stale = |last: &str| days_between(last, today).is_some_and(|d| d > RETENTION_DAYS);
        self.defects.retain(|_, d| !stale(&d.last_seen));
        self.flaky.retain(|_, f| !stale(&f.last_seen));
        self.operations.retain(|_, o| !stale(&o.last_at));
        self.cap();
    }

    pub(crate) fn cap(&mut self) {
        fn keep_newest<V>(m: &mut BTreeMap<String, V>, max: usize, age: impl Fn(&V) -> String) {
            if m.len() <= max {
                return;
            }
            let mut ks: Vec<(String, String)> =
                m.iter().map(|(k, v)| (age(v), k.clone())).collect();
            ks.sort(); // oldest first, ties by key
            for (_, k) in ks.into_iter().take(m.len() - max) {
                m.remove(&k);
            }
        }
        keep_newest(&mut self.defects, MAX_DEFECTS, |d| d.last_seen.clone());
        keep_newest(&mut self.flaky, MAX_CLASSES, |f| f.last_seen.clone());
        keep_newest(&mut self.operations, MAX_OPERATIONS, |o| o.last_at.clone());
    }
}

/// What `load` found.
pub struct Loaded {
    pub memory: Memory,
    /// A memory file existed and was used.
    pub existed: bool,
    /// What the report must say (a file that was set aside, ...).
    pub notes: Vec<String>,
}

/// One planned case that re-tests a known defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeLine {
    pub case_id: String,
    pub class: String,
    pub defects: Vec<String>,
}

/// A line in the report / diff describing a defect.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DefectLine {
    pub fingerprint: String,
    pub rule: String,
    pub endpoint: String,
    #[serde(default)]
    pub methods: Vec<String>,
    pub severity: String,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    pub runs_seen: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defect_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Acceptance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlakyLine {
    pub class: String,
    pub operation: String,
    pub pass: u32,
    pub fail: u32,
    pub flaky: u32,
}

/// Differences between this run and the memory it loaded: what the report and the CLI summarize.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinceLastRun {
    pub first_run: bool,
    pub previous_run: Option<String>,
    pub previous_at: Option<String>,
    pub runs_remembered: usize,
    pub new: Vec<DefectLine>,
    pub still_open: Vec<DefectLine>,
    pub fixed: Vec<DefectLine>,
    pub regressed: Vec<DefectLine>,
    pub accepted: Vec<DefectLine>,
    pub expired: Vec<DefectLine>,
    pub not_retested: Vec<DefectLine>,
    pub known_flaky: Vec<FlakyLine>,
    pub regression_probes: Vec<ProbeLine>,
    pub notes: Vec<String>,
    /// Whether the update was written to disk: false in a dry run or when an uncommitted `Update`
    /// was dropped. The report notes when memory was not updated with this run.
    pub committed: bool,
}

impl SinceLastRun {
    /// One line for the CLI and the MCP status.
    pub fn summary_line(&self) -> String {
        if self.first_run {
            return format!(
                "first run remembered for this target: {} new defect(s)",
                self.new.len()
            );
        }
        format!(
            "{} new, {} still open, {} fixed, {} regressed, {} known flaky, {} accepted ({} expired), {} not re-tested; {} regression probe(s) planned first",
            self.new.len(),
            self.still_open.len(),
            self.fixed.len(),
            self.regressed.len(),
            self.known_flaky.len(),
            self.accepted.len(),
            self.expired.len(),
            self.not_retested.len(),
            self.regression_probes.len()
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accepted {
    pub fingerprint: String,
    pub rule: String,
    pub endpoint: String,
    pub severity: String,
    pub acceptance: Acceptance,
}
