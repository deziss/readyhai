//! Core types and DTOs for the evaluation harness.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ------------------------------------------------------------------ suite files

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SuiteKind {
    /// `readyhai qa` against a fixture server (engine::scan with qa options).
    Qa,
    /// The autonomous agent loop against a fixture server.
    Agent,
    /// Static scan of a repo directory (`qa.suite.*` / `qa.release.*` checks).
    Repo,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteSpec {
    pub name: String,
    pub kind: SuiteKind,
    #[serde(default)]
    pub description: String,
    pub target: TargetSpec,
    /// Only observations whose rule starts with this prefix are scored (others are ignored).
    #[serde(default)]
    pub observe_prefix: Option<String>,
    /// Verdict every run must end with (qa: `NoGo/Fail`, agent: `NO_GO`, repo: `Warn`).
    #[serde(default)]
    pub expect_verdict: Option<String>,
    /// Verdicts no run may end with (agent: `["NO_GO"]` for a clean target: a false alarm).
    #[serde(default)]
    pub forbid_verdict: Vec<String>,
    /// A blocker reason (`auth_wall`, `out_of_scope`, `no_surface`, `transport`) every run must
    /// list in `evidence_ledger.blockers` (agent).
    #[serde(default)]
    pub expect_blocker: Option<String>,
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(default)]
    pub expect: Vec<Expect>,
    #[serde(default)]
    pub allow: Vec<Allow>,
    /// What a change-aware agent run must do with the code diff of `target.repo` (agent).
    #[serde(default)]
    pub change: Option<ChangeSpec>,
    /// Run the agent several times in the same data directory against the same fixture: what it
    /// remembers about the target must carry over (agent).
    #[serde(default)]
    pub memory: Option<MemorySpec>,
}

/// `[memory]`: how many times the agent runs against the fixture in one data directory. The last
/// run is scored (recall, false positives, verdict); every run after the first must report the
/// seeded defects as still open and lead its plan with their reproduction cases.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySpec {
    #[serde(default = "d_two")]
    pub runs: usize,
}

pub(crate) fn d_two() -> usize {
    2
}

/// `[target.repo]`: a throwaway git repository the harness builds for the agent's `repo` /
/// `diff_base`. Each directory of `commits` is copied over the previous state and committed; the
/// first commit is tagged `base`, which is the run's `diff_base`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoSpec {
    pub commits: Vec<String>,
    /// Attach commit `base` as `diff_base` (defaults to `true` when multiple commits exist).
    #[serde(default)]
    pub diff_base: Option<bool>,
    /// Require at least one defect to carry `source_context` (`file:line` white-box linkage).
    #[serde(default)]
    pub require_source_context: bool,
}

/// `[change]`: what the run's change impact must show, on top of the expectations.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSpec {
    /// The operations the diff must be mapped to (exactly these).
    pub operations: Vec<String>,
    /// Every case of a changed operation comes before any case of another one (the root liveness
    /// probe aside).
    #[serde(default = "d_true")]
    pub planned_first: bool,
    /// Share of the planned changed-operation cases that must have been sent.
    #[serde(default = "d_one")]
    pub min_sent: f64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSpec {
    /// Fixture server script (python3), started on a free 127.0.0.1 port. Repo suites have none.
    #[serde(default)]
    pub server: Option<String>,
    /// OpenAPI spec file (qa, agent).
    #[serde(default)]
    pub spec: Option<String>,
    /// roles.toml (qa).
    #[serde(default)]
    pub roles: Option<String>,
    /// Directory to scan (repo).
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Exploration step cap (agent).
    #[serde(default)]
    pub max_steps: Option<usize>,
    /// role -> FAKE fixture token, exported as RH_<ROLE>_TOKEN for the run.
    #[serde(default)]
    pub tokens: BTreeMap<String, String>,
    /// Source repository of the service under test, for a change-aware agent run.
    #[serde(default)]
    pub repo: Option<RepoSpec>,
    /// Extra arguments for the fixture server, after `PORT LOGFILE` (e.g. `["--clean"]`).
    #[serde(default)]
    pub server_args: Vec<String>,
}

pub(crate) fn default_profile() -> String {
    "standard".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    #[serde(default = "d_recall")]
    pub min_recall: f64,
    #[serde(default = "d_fp")]
    pub max_false_positives: usize,
    /// Every one of the k runs must reach `min_recall`.
    #[serde(default = "d_true")]
    pub pass_k: bool,
    /// All k runs must end with the same verdict.
    #[serde(default = "d_true")]
    pub stable_verdict: bool,
    /// Most requests one run may send to the fixture (counted by the fixture's own log).
    #[serde(default)]
    pub max_requests: Option<usize>,
    /// Longest wall time one run may take.
    #[serde(default)]
    pub max_seconds: Option<f64>,
    /// Most INCONCLUSIVE results one agent run may have, as a share of the cases it executed
    /// (PASS + WARN + FAIL + INCONCLUSIVE; NOT_APPLICABLE, SKIPPED and BLOCKED are not in it).
    /// Unset = unchecked (the shipped older suites leave it off).
    #[serde(default)]
    pub max_inconclusive_rate: Option<f64>,
}

pub(crate) fn d_recall() -> f64 {
    0.85
}
pub(crate) fn d_fp() -> usize {
    2
}
pub(crate) fn d_true() -> bool {
    true
}
pub(crate) fn d_one() -> f64 {
    1.0
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            min_recall: d_recall(),
            max_false_positives: d_fp(),
            pass_k: true,
            stable_verdict: true,
            max_requests: None,
            max_seconds: None,
            max_inconclusive_rate: None,
        }
    }
}

/// One seeded defect the run must find.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub id: String,
    /// Rule id pattern (`*` is the only wildcard): `qa.api.bola`, `qa.suite.*`.
    pub rule: String,
    /// Component pattern, e.g. `GET /orders/{id}`.
    #[serde(default)]
    pub component: Option<String>,
    /// Case-insensitive substring of the defect title.
    #[serde(default)]
    pub title: Option<String>,
    /// Needs something this machine may not have (docker): reported, never counted in recall.
    #[serde(default)]
    pub optional: bool,
    /// The tool is known not to find this yet. Reported every run, never counted in recall; when
    /// a run does find it the report says so and the flag should be removed (it then gates).
    #[serde(default)]
    pub known_gap: bool,
    #[serde(default)]
    pub note: String,
}

/// An extra defect that is real (or harmless) and must not count as a false positive.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    pub rule: String,
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub reason: String,
}

// ------------------------------------------------------------------ observations and scoring

/// What a run reported, reduced to what scoring needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// Rule ids that describe it (qa: the defect rule; agent: the failing oracle checks).
    pub rules: Vec<String>,
    pub component: String,
    pub title: String,
}

impl Observed {
    pub fn label(&self) -> String {
        format!(
            "{} @ {}",
            self.rules.first().map(String::as_str).unwrap_or("-"),
            self.component
        )
    }
}

pub(crate) fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

#[derive(Debug, Clone, Serialize)]
pub struct RunScore {
    pub run: usize,
    pub verdict: String,
    /// Required expectations found / required expectations.
    pub recall: f64,
    pub found: Vec<String>,
    pub missed: Vec<String>,
    pub optional_found: Vec<String>,
    pub optional_missed: Vec<String>,
    /// `known_gap` expectations that were (not) found.
    pub gap_found: Vec<String>,
    pub gap_missed: Vec<String>,
    pub false_positives: Vec<String>,
    /// Reported defects that match an `[[expect]]` (any flavour: required, optional, known gap).
    pub true_positives: usize,
    /// true positives / (true positives + false positives). Extras that match an `[[allow]]` are in
    /// neither count. 1.0 when the run reported nothing scorable (nothing was wrong).
    pub precision: f64,
    /// Extras that matched an `[[allow]]`: `rule @ component: reason`.
    pub allowed_seen: Vec<String>,
    /// Everything scored in this run (rule @ component), for diagnosis.
    pub observed: Vec<String>,
    pub requests: usize,
    pub seconds: f64,
    /// Agent only: case status (PASS, FAIL, INCONCLUSIVE, BLOCKED, NOT_APPLICABLE, ...) -> count.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub cases: BTreeMap<String, usize>,
    /// Agent only: INCONCLUSIVE / (PASS + WARN + FAIL + INCONCLUSIVE). None: no case was executed.
    pub inconclusive_rate: Option<f64>,
    /// Agent only: the ledger's confidence (conclusive share of applicable cases, percent).
    pub confidence: Option<u32>,
    /// Agent only: the reasons in `evidence_ledger.blockers` (`auth_wall`, ...).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    /// Extra checks of this run (the `[change]` ones); each must hold in every run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<Check>,
}

/// What an agent run's cases and ledger say about the quality of its evidence, reduced to what
/// scoring needs. `Default` (no cases) for the executors that have none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunStats {
    /// Case status -> count, over every executed result.
    pub cases: BTreeMap<String, usize>,
    pub confidence: Option<u32>,
    pub blockers: Vec<String>,
}

impl RunStats {
    /// Count `statuses` (one per case result; case-insensitive, stored upper-case).
    pub fn from_statuses<'a>(
        statuses: impl IntoIterator<Item = &'a str>,
        confidence: Option<u32>,
        blockers: Vec<String>,
    ) -> RunStats {
        let mut cases = BTreeMap::new();
        for s in statuses {
            *cases.entry(s.trim().to_ascii_uppercase()).or_insert(0) += 1;
        }
        RunStats {
            cases,
            confidence,
            blockers,
        }
    }
}

/// INCONCLUSIVE / executed applicable cases. "Executed applicable" = PASS + WARN + FAIL +
/// INCONCLUSIVE: NOT_APPLICABLE (no surface) and SKIPPED (not run) are out, and so is BLOCKED (no
/// request was sent; it has its own reason and is reported as a blocker). None when none ran.
pub fn inconclusive_rate(cases: &BTreeMap<String, usize>) -> Option<f64> {
    let n = |k: &str| cases.get(k).copied().unwrap_or(0);
    let inconclusive = n("INCONCLUSIVE");
    let executed = n("PASS") + n("WARN") + n("FAIL") + inconclusive;
    (executed > 0).then(|| inconclusive as f64 / executed as f64)
}

impl RunScore {
    /// Attach the evidence-quality numbers of an agent run.
    pub fn with_stats(mut self, stats: RunStats) -> RunScore {
        self.inconclusive_rate = inconclusive_rate(&stats.cases).map(round3);
        self.cases = stats.cases;
        self.confidence = stats.confidence;
        self.blockers = stats.blockers;
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuiteResult {
    pub name: String,
    pub kind: SuiteKind,
    pub description: String,
    /// Expectation id -> note (what the seeded defect is), to read the missed ids by.
    pub notes: BTreeMap<String, String>,
    pub k: usize,
    pub runs: Vec<RunScore>,
    /// Mean recall over completed runs.
    pub recall: f64,
    pub recall_min: f64,
    /// Mean precision over completed runs (reported defects that were expected).
    pub precision: f64,
    pub precision_min: f64,
    /// Worst run.
    pub false_positives: usize,
    /// Worst (highest) inconclusive rate of the agent runs; None: no run executed a case.
    pub inconclusive_rate: Option<f64>,
    /// Worst (lowest) ledger confidence over the runs (percent); None: not an agent suite.
    pub confidence: Option<u32>,
    /// Blocker reasons any run reported, sorted.
    pub blockers: Vec<String>,
    /// Every run ended with `expect_verdict`; None when the suite sets none.
    pub verdict_match: Option<bool>,
    /// Every run reached `min_recall`.
    pub pass_k: bool,
    pub verdict_stable: bool,
    pub verdicts: Vec<String>,
    /// `known_gap` expectations still missed in at least one run.
    pub known_gaps_open: Vec<String>,
    /// `known_gap` expectations found in every run: remove the flag so they gate.
    pub known_gaps_closed: Vec<String>,
    /// Worst run.
    pub requests: usize,
    pub seconds: f64,
    pub thresholds: Thresholds,
    pub checks: Vec<Check>,
    pub passed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvalSummary {
    pub version: String,
    pub started: String,
    pub k: usize,
    pub suites: Vec<SuiteResult>,
    pub passed: bool,
    #[serde(skip)]
    pub report_json: PathBuf,
    #[serde(skip)]
    pub report_md: PathBuf,
}

impl EvalSummary {
    /// Process exit code: 0 every threshold met, 1 at least one missed. (Harness errors that stop
    /// the whole evaluation surface as `Err` from [`run_eval`]; `main` maps those to 3.)
    pub fn exit_code(&self) -> u8 {
        if self.passed { 0 } else { 1 }
    }
}

// ------------------------------------------------------------------ options and loading

#[derive(Debug, Clone)]
pub struct EvalOpts {
    /// Suite names; empty or `all` runs every suite in `dir`.
    pub suites: Vec<String>,
    /// Runs per suite.
    pub k: usize,
    /// Where the suite files live, relative to the repo root.
    pub dir: PathBuf,
    /// Repo root that fixture paths in the suite files are relative to. Default: the current
    /// directory when it holds `dir`, else this crate's source directory.
    pub root: Option<PathBuf>,
    /// Output directory for eval-report.json and eval-report.md.
    pub out: PathBuf,
}

impl Default for EvalOpts {
    fn default() -> Self {
        EvalOpts {
            suites: vec!["all".into()],
            k: 2,
            dir: PathBuf::from("tests/eval"),
            root: None,
            out: PathBuf::from("eval-report"),
        }
    }
}
