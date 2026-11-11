//! Evaluation harness: scores ReadyHai's QA engine and agent against fixtures with seeded defects.
//!
//! `readyhai eval` runs every suite in `tests/eval/<suite>.toml` `k` times and reports, per suite:
//! recall (expected defects found), precision (reported defects that were expected), false
//! positives (FAIL defects nobody expected), pass^k (every run meets the recall threshold), the
//! inconclusive rate and confidence of agent runs, verdict stability and match, blockers, requests
//! sent and wall time. The numbers are compared with the thresholds in the suite file and the
//! process exits non-zero on any miss.
//!
//! Each run is isolated: its own `READYHAI_DATA` directory (so there is no baseline and no state
//! carried between runs), a temp `scope.toml` that lists only 127.0.0.1/localhost as nonprod, a
//! fresh fixture server on a free loopback port, no LLM, `READYHAI_OFFLINE=1`, no tools and no
//! docker. Nothing leaves the machine.
//!
//! Environment is process-global, so [`run_eval`] holds a lock for its whole duration and restores
//! every variable it touched. Do not call it from tests that share a process with other tests:
//! the unit tests here exercise the pure logic and the fixture launcher only.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Serialises everything that mutates process environment.
static ENV_LOCK: Mutex<()> = Mutex::new(());

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

fn d_two() -> usize {
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

fn default_profile() -> String {
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

fn d_recall() -> f64 {
    0.85
}
fn d_fp() -> usize {
    2
}
fn d_true() -> bool {
    true
}
fn d_one() -> f64 {
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
    fn label(&self) -> String {
        format!(
            "{} @ {}",
            self.rules.first().map(String::as_str).unwrap_or("-"),
            self.component
        )
    }
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

/// `*` is the only wildcard; everything else is literal and case-sensitive.
pub fn glob_match(pat: &str, text: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == text;
    }
    let first = parts[0];
    let last = parts[parts.len() - 1];
    if !text.starts_with(first) {
        return false;
    }
    let mut pos = first.len();
    for mid in &parts[1..parts.len() - 1] {
        match text[pos..].find(mid) {
            Some(i) => pos += i + mid.len(),
            None => return false,
        }
    }
    text[pos..].ends_with(last)
}

fn matches(rule: &str, component: Option<&str>, title: Option<&str>, observed: &Observed) -> bool {
    observed.rules.iter().any(|r| glob_match(rule, r))
        && component.is_none_or(|c| glob_match(c, &observed.component))
        && title.is_none_or(|t| {
            observed
                .title
                .to_ascii_lowercase()
                .contains(&t.to_ascii_lowercase())
        })
}

fn expect_matches(e: &Expect, o: &Observed) -> bool {
    matches(&e.rule, e.component.as_deref(), e.title.as_deref(), o)
}

fn allow_matches(a: &Allow, o: &Observed) -> bool {
    matches(&a.rule, a.component.as_deref(), a.title.as_deref(), o)
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// Score one run's observations against the suite's expectations.
pub fn score_run(
    spec: &SuiteSpec,
    run: usize,
    verdict: &str,
    observed: &[Observed],
    requests: usize,
    seconds: f64,
) -> RunScore {
    let considered: Vec<&Observed> = observed
        .iter()
        .filter(|o| match &spec.observe_prefix {
            Some(p) => o.rules.iter().any(|r| r.starts_with(p.as_str())),
            None => true,
        })
        .collect();

    let (mut found, mut missed) = (vec![], vec![]);
    let (mut optional_found, mut optional_missed) = (vec![], vec![]);
    let (mut gap_found, mut gap_missed) = (vec![], vec![]);
    for e in &spec.expect {
        let hit = considered.iter().any(|o| expect_matches(e, o));
        let bucket = match (e.optional, e.known_gap, hit) {
            (true, _, true) => &mut optional_found,
            (true, _, false) => &mut optional_missed,
            (false, true, true) => &mut gap_found,
            (false, true, false) => &mut gap_missed,
            (false, false, true) => &mut found,
            (false, false, false) => &mut missed,
        };
        bucket.push(e.id.clone());
    }
    let required = found.len() + missed.len();
    let recall = if required == 0 {
        1.0
    } else {
        found.len() as f64 / required as f64
    };

    let false_positives: Vec<String> = considered
        .iter()
        .filter(|o| {
            !spec.expect.iter().any(|e| expect_matches(e, o))
                && !spec.allow.iter().any(|a| allow_matches(a, o))
        })
        .map(|o| o.label())
        .collect();
    let true_positives = considered
        .iter()
        .filter(|o| spec.expect.iter().any(|e| expect_matches(e, o)))
        .count();
    let precision = match true_positives + false_positives.len() {
        0 => 1.0,
        n => true_positives as f64 / n as f64,
    };

    let allowed_seen: Vec<String> = considered
        .iter()
        .filter(|o| !spec.expect.iter().any(|e| expect_matches(e, o)))
        .filter_map(|o| {
            let a = spec.allow.iter().find(|a| allow_matches(a, o))?;
            Some(if a.reason.is_empty() {
                o.label()
            } else {
                format!("{}: {}", o.label(), a.reason)
            })
        })
        .collect();

    RunScore {
        run,
        verdict: verdict.to_string(),
        recall: round3(recall),
        found,
        missed,
        optional_found,
        optional_missed,
        gap_found,
        gap_missed,
        false_positives,
        true_positives,
        precision: round3(precision),
        allowed_seen,
        observed: considered.iter().map(|o| o.label()).collect(),
        requests,
        seconds: round3(seconds),
        cases: BTreeMap::new(),
        inconclusive_rate: None,
        confidence: None,
        blockers: vec![],
        checks: vec![],
    }
}

/// Aggregate k runs into suite metrics and evaluate the thresholds.
pub fn summarize_suite(
    spec: &SuiteSpec,
    k: usize,
    runs: Vec<RunScore>,
    error: Option<String>,
) -> SuiteResult {
    let t = spec.thresholds.clone();
    let n = runs.len();
    let recall = if n == 0 {
        0.0
    } else {
        runs.iter().map(|r| r.recall).sum::<f64>() / n as f64
    };
    let recall_min = runs.iter().map(|r| r.recall).fold(f64::INFINITY, f64::min);
    let recall_min = if recall_min.is_finite() {
        recall_min
    } else {
        0.0
    };
    let fp = runs
        .iter()
        .map(|r| r.false_positives.len())
        .max()
        .unwrap_or(0);
    let precision = if n == 0 {
        0.0
    } else {
        runs.iter().map(|r| r.precision).sum::<f64>() / n as f64
    };
    let precision_min = runs
        .iter()
        .map(|r| r.precision)
        .fold(f64::INFINITY, f64::min);
    let precision_min = if precision_min.is_finite() {
        precision_min
    } else {
        0.0
    };
    let inconclusive_worst = runs
        .iter()
        .filter_map(|r| r.inconclusive_rate)
        .fold(None, |a: Option<f64>, x| Some(a.map_or(x, |a| a.max(x))));
    let confidence = runs.iter().filter_map(|r| r.confidence).min();
    let mut blockers: Vec<String> = runs.iter().flat_map(|r| r.blockers.clone()).collect();
    blockers.sort();
    blockers.dedup();
    let pass_k = n == k && n > 0 && runs.iter().all(|r| r.recall >= t.min_recall);
    let verdicts: Vec<String> = runs.iter().map(|r| r.verdict.clone()).collect();
    let verdict_stable = n > 0 && verdicts.windows(2).all(|w| w[0] == w[1]);
    let requests = runs.iter().map(|r| r.requests).max().unwrap_or(0);
    let known_gaps_open: Vec<String> = spec
        .expect
        .iter()
        .filter(|e| e.known_gap && !e.optional)
        .filter(|e| runs.is_empty() || runs.iter().any(|r| r.gap_missed.contains(&e.id)))
        .map(|e| e.id.clone())
        .collect();
    let known_gaps_closed: Vec<String> = spec
        .expect
        .iter()
        .filter(|e| e.known_gap && !e.optional)
        .filter(|e| !runs.is_empty() && runs.iter().all(|r| r.gap_found.contains(&e.id)))
        .map(|e| e.id.clone())
        .collect();
    let seconds = runs.iter().map(|r| r.seconds).fold(0.0, f64::max);

    let mut checks = vec![];
    let mut push = |name: &str, ok: bool, detail: String| {
        checks.push(Check {
            name: name.into(),
            ok,
            detail,
        })
    };
    push(
        "runs completed",
        error.is_none() && n == k && k > 0,
        match &error {
            Some(e) => format!("{n}/{k} completed: {e}"),
            None => format!("{n}/{k} completed"),
        },
    );
    push(
        "recall",
        n > 0 && recall >= t.min_recall,
        format!(
            "mean {:.3} (min run {:.3}) vs >= {:.2}",
            recall, recall_min, t.min_recall
        ),
    );
    push(
        "false positives",
        fp <= t.max_false_positives,
        format!("worst run {fp} vs <= {}", t.max_false_positives),
    );
    if t.pass_k {
        push(
            "pass^k",
            pass_k,
            format!(
                "{}/{k} runs at recall >= {:.2}",
                runs.iter().filter(|r| r.recall >= t.min_recall).count(),
                t.min_recall
            ),
        );
    }
    if t.stable_verdict {
        push("verdict stable", verdict_stable, verdicts.join(" | "));
    }
    let verdict_match = spec
        .expect_verdict
        .as_ref()
        .map(|want| n > 0 && verdicts.iter().all(|v| v.eq_ignore_ascii_case(want)));
    if let (Some(want), Some(ok)) = (&spec.expect_verdict, verdict_match) {
        push(
            "expected verdict",
            ok,
            format!("want {want}, got {}", verdicts.join(" | ")),
        );
    }
    if !spec.forbid_verdict.is_empty() {
        let hit: Vec<&String> = verdicts
            .iter()
            .filter(|v| {
                spec.forbid_verdict
                    .iter()
                    .any(|f| v.eq_ignore_ascii_case(f))
            })
            .collect();
        push(
            "forbidden verdict",
            n > 0 && hit.is_empty(),
            format!(
                "must not be {}, got {}",
                spec.forbid_verdict.join(" or "),
                verdicts.join(" | ")
            ),
        );
    }
    if let Some(want) = &spec.expect_blocker {
        let missing: Vec<usize> = runs
            .iter()
            .filter(|r| !r.blockers.iter().any(|b| b.eq_ignore_ascii_case(want)))
            .map(|r| r.run)
            .collect();
        push(
            "expected blocker",
            n > 0 && missing.is_empty(),
            format!(
                "want {want} in every run, got [{}]{}",
                runs.iter()
                    .map(|r| r.blockers.join(", "))
                    .collect::<Vec<_>>()
                    .join("] ["),
                if missing.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; missing in run {}",
                        missing
                            .iter()
                            .map(|r| r.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            ),
        );
    }
    if let Some(max) = t.max_inconclusive_rate {
        let none: Vec<usize> = runs
            .iter()
            .filter(|r| r.inconclusive_rate.is_none())
            .map(|r| r.run)
            .collect();
        let ok = n > 0 && none.is_empty() && inconclusive_worst.is_some_and(|w| w <= max + 1e-9);
        push(
            "inconclusive rate",
            ok,
            match (inconclusive_worst, none.is_empty()) {
                (_, false) => format!(
                    "run {} executed no applicable case (nothing to rate)",
                    none.iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                (Some(w), _) => format!("worst run {:.0}% vs <= {:.0}%", w * 100.0, max * 100.0),
                (None, _) => "no run".into(),
            },
        );
    }
    if let Some(max) = t.max_requests {
        push(
            "request budget",
            requests <= max,
            format!("worst run {requests} vs <= {max}"),
        );
    }
    if let Some(max) = t.max_seconds {
        push(
            "time budget",
            seconds <= max,
            format!("worst run {seconds:.1}s vs <= {max:.0}s"),
        );
    }
    // the run-level checks (`[change]`): the suite holds when every run held
    let mut names: Vec<&str> = vec![];
    for c in runs.iter().flat_map(|r| &r.checks) {
        if !names.contains(&c.name.as_str()) {
            names.push(&c.name);
        }
    }
    for name in names {
        let per_run: Vec<&Check> = runs
            .iter()
            .filter_map(|r| r.checks.iter().find(|c| c.name == name))
            .collect();
        let detail = per_run
            .iter()
            .find(|c| !c.ok)
            .or(per_run.first())
            .map(|c| c.detail.clone())
            .unwrap_or_default();
        checks.push(Check {
            name: name.to_string(),
            ok: n > 0 && per_run.len() == n && per_run.iter().all(|c| c.ok),
            detail,
        });
    }
    let passed = checks.iter().all(|c| c.ok);

    SuiteResult {
        name: spec.name.clone(),
        kind: spec.kind,
        description: spec.description.clone(),
        notes: spec
            .expect
            .iter()
            .filter(|e| !e.note.is_empty())
            .map(|e| (e.id.clone(), e.note.clone()))
            .collect(),
        k,
        runs,
        recall: round3(recall),
        recall_min: round3(recall_min),
        precision: round3(precision),
        precision_min: round3(precision_min),
        false_positives: fp,
        inconclusive_rate: inconclusive_worst.map(round3),
        confidence,
        blockers,
        verdict_match,
        pass_k,
        verdict_stable,
        verdicts,
        known_gaps_open,
        known_gaps_closed,
        requests,
        seconds: round3(seconds),
        thresholds: t,
        checks,
        passed,
        error,
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

fn resolve_root(opts: &EvalOpts) -> Result<PathBuf> {
    if let Some(r) = &opts.root {
        return Ok(r.clone());
    }
    let candidates = [
        std::env::current_dir().ok(),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
    ];
    for c in candidates.into_iter().flatten() {
        if c.join(&opts.dir).is_dir() {
            return Ok(c);
        }
    }
    bail!(
        "suite directory {} not found (run from the repo root or pass --dir)",
        opts.dir.display()
    )
}

/// Parse one suite file and check it is usable.
pub fn parse_suite(text: &str, origin: &str) -> Result<SuiteSpec> {
    let spec: SuiteSpec = toml::from_str(text).with_context(|| format!("parse {origin}"))?;
    validate_suite(&spec).with_context(|| format!("suite {origin}"))?;
    Ok(spec)
}

fn validate_suite(s: &SuiteSpec) -> Result<()> {
    if s.name.trim().is_empty()
        || !s
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("name must be non-empty [A-Za-z0-9_-]");
    }
    match s.kind {
        SuiteKind::Qa | SuiteKind::Agent => {
            if s.target.server.is_none() {
                bail!("kind {:?} needs target.server", s.kind);
            }
        }
        SuiteKind::Repo => {
            if s.target.path.is_none() {
                bail!("kind repo needs target.path");
            }
        }
    }
    if s.kind == SuiteKind::Qa && s.target.roles.is_none() {
        bail!("kind qa needs target.roles");
    }
    if s.target.repo.is_some() || s.change.is_some() {
        if s.kind != SuiteKind::Agent {
            bail!("target.repo and [change] are for kind agent");
        }
        let needs_diff = s.change.is_some()
            || s.target
                .repo
                .as_ref()
                .is_some_and(|r| r.diff_base == Some(true));
        if needs_diff {
            match &s.target.repo {
                Some(r) if r.commits.len() >= 2 => {}
                _ => bail!(
                    "[change] needs target.repo with at least two commits (base, then the change)"
                ),
            }
        } else {
            match &s.target.repo {
                Some(r) if !r.commits.is_empty() => {}
                _ => bail!("target.repo needs at least one commit directory"),
            }
        }
        if let Some(c) = &s.change {
            if c.operations.is_empty() {
                bail!("[change] needs at least one operation");
            }
            if !(0.0..=1.0).contains(&c.min_sent) {
                bail!("[change] min_sent must be within 0..=1");
            }
        }
    }
    if let Some(m) = &s.memory {
        if s.kind != SuiteKind::Agent {
            bail!("[memory] is for kind agent");
        }
        if !(2..=5).contains(&m.runs) {
            bail!("[memory] runs must be within 2..=5");
        }
        if s.target.repo.is_some() {
            bail!("[memory] and target.repo cannot be combined");
        }
    }
    if s.expect.is_empty()
        && s.expect_verdict.is_none()
        && s.forbid_verdict.is_empty()
        && s.expect_blocker.is_none()
    {
        bail!(
            "needs at least one [[expect]] (or, for a target without seeded defects, expect_verdict / forbid_verdict / expect_blocker)"
        );
    }
    if let Some(b) = &s.expect_blocker {
        if s.kind != SuiteKind::Agent {
            bail!("expect_blocker is for kind agent");
        }
        if serde_json::from_value::<crate::agent::BlockReason>(serde_json::Value::String(
            b.to_ascii_lowercase(),
        ))
        .is_err()
        {
            bail!(
                "expect_blocker '{b}' is not a blocker reason (auth_wall, out_of_scope, no_surface, transport)"
            );
        }
    }
    if let Some(want) = &s.expect_verdict
        && s.forbid_verdict
            .iter()
            .any(|f| f.eq_ignore_ascii_case(want))
    {
        bail!("expect_verdict '{want}' is also in forbid_verdict");
    }
    let mut seen = std::collections::BTreeSet::new();
    for e in &s.expect {
        if e.id.trim().is_empty() || e.rule.trim().is_empty() {
            bail!("every [[expect]] needs id and rule");
        }
        if e.optional && e.known_gap {
            bail!(
                "expect '{}': optional and known_gap are mutually exclusive",
                e.id
            );
        }
        if !seen.insert(e.id.as_str()) {
            bail!("duplicate expect id '{}'", e.id);
        }
    }
    if s.allow.iter().any(|a| a.rule.trim().is_empty()) {
        bail!("every [[allow]] needs a rule");
    }
    let t = &s.thresholds;
    if !(0.0..=1.0).contains(&t.min_recall) {
        bail!("min_recall must be within 0..=1");
    }
    if let Some(r) = t.max_inconclusive_rate {
        if s.kind != SuiteKind::Agent {
            bail!("max_inconclusive_rate is for kind agent (only agent runs have cases)");
        }
        if !(0.0..=1.0).contains(&r) {
            bail!("max_inconclusive_rate must be within 0..=1");
        }
    }
    if !s.target.server_args.is_empty() && s.target.server.is_none() {
        bail!("target.server_args needs target.server");
    }
    Ok(())
}

/// Load the suites named in `opts.suites` (all of them for `all`), sorted by name.
pub fn load_suites(root: &Path, opts: &EvalOpts) -> Result<Vec<SuiteSpec>> {
    let dir = root.join(&opts.dir);
    let mut all = vec![];
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    for f in files {
        let text = std::fs::read_to_string(&f).with_context(|| format!("read {}", f.display()))?;
        let spec = parse_suite(&text, &f.display().to_string())?;
        let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if stem != spec.name {
            bail!(
                "{}: name '{}' must match the file name",
                f.display(),
                spec.name
            );
        }
        all.push(spec);
    }
    let want: Vec<&str> = opts
        .suites
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if want.is_empty() || want.contains(&"all") {
        if all.is_empty() {
            bail!("no suites in {}", dir.display());
        }
        return Ok(all);
    }
    let mut out = vec![];
    for w in want {
        match all.iter().find(|s| s.name == w) {
            Some(s) => out.push(s.clone()),
            None => bail!(
                "unknown suite '{w}' (have: {})",
                all.iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------ process environment

/// Sets/unsets variables and restores the previous values on drop.
struct EnvGuard(Vec<(String, Option<OsString>)>);

impl EnvGuard {
    fn new() -> Self {
        EnvGuard(vec![])
    }
    fn set(&mut self, k: &str, v: impl AsRef<std::ffi::OsStr>) {
        self.0.push((k.to_string(), std::env::var_os(k)));
        // SAFETY: run_eval holds ENV_LOCK and starts no threads while the environment changes.
        unsafe { std::env::set_var(k, v) };
    }
    fn unset(&mut self, k: &str) {
        self.0.push((k.to_string(), std::env::var_os(k)));
        // SAFETY: see `set`.
        unsafe { std::env::remove_var(k) };
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.0.drain(..).rev() {
            // SAFETY: see `set`.
            unsafe {
                match v {
                    Some(v) => std::env::set_var(&k, v),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }
}

fn role_env(role: &str) -> String {
    let key: String = role
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("RH_{key}_TOKEN")
}

// ------------------------------------------------------------------ fixture server

/// A fixture server child process on a free loopback port. Killed on drop.
pub struct Fixture {
    child: Child,
    pub port: u16,
    log: PathBuf,
    /// Requests already in the log when the server became ready (our own readiness probe).
    baseline: usize,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn python() -> String {
    std::env::var("READYHAI_EVAL_PYTHON").unwrap_or_else(|_| "python3".into())
}

fn free_port() -> Result<u16> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("bind a free loopback port")?;
    Ok(l.local_addr()?.port())
}

fn count_lines(p: &Path) -> usize {
    std::fs::read_to_string(p)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

impl Fixture {
    /// Start the server as `script PORT LOGFILE [args...]`.
    pub fn start(script: &Path, log: &Path, args: &[String]) -> Result<Fixture> {
        if !script.is_file() {
            bail!("fixture server {} not found", script.display());
        }
        let port = free_port()?;
        std::fs::write(log, b"")?;
        let child = Command::new(python())
            .arg(script)
            .arg(port.to_string())
            .arg(log)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| {
                format!(
                    "start {} (python3 missing? set READYHAI_EVAL_PYTHON)",
                    script.display()
                )
            })?;
        let mut f = Fixture {
            child,
            port,
            log: log.to_path_buf(),
            baseline: 0,
        };
        f.wait_ready()?;
        f.baseline = count_lines(&f.log);
        Ok(f)
    }

    fn wait_ready(&mut self) -> Result<()> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(Some(st)) = self.child.try_wait() {
                bail!("fixture server exited at start ({st})");
            }
            if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                if s.write_all(b"GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                    .is_ok()
                {
                    let mut buf = String::new();
                    let _ = s.read_to_string(&mut buf);
                    if buf.starts_with("HTTP/1.") && buf.contains(" 200 ") {
                        return Ok(());
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!("fixture server did not answer /health within 15s")
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Requests the target saw since it was ready.
    pub fn requests(&self) -> usize {
        count_lines(&self.log).saturating_sub(self.baseline)
    }
}

// ------------------------------------------------------------------ executors

struct Outcome {
    verdict: String,
    observed: Vec<Observed>,
    /// Run-level checks beyond recall and false positives (`[change]`).
    checks: Vec<Check>,
    /// Evidence quality of an agent run (cases by status, confidence, blockers).
    stats: RunStats,
}

fn rel(root: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

fn parse_profile(s: &str) -> Result<crate::model::Profile> {
    use crate::model::Profile;
    Ok(match s.to_ascii_lowercase().as_str() {
        "quick" => Profile::Quick,
        "standard" => Profile::Standard,
        "deep" => Profile::Deep,
        other => bail!("unknown profile '{other}' (quick|standard|deep)"),
    })
}

fn exec_qa(spec: &SuiteSpec, root: &Path, base_url: &str) -> Result<Outcome> {
    let t = &spec.target;
    let opts = crate::engine::ScanOpts {
        target: base_url.to_string(),
        profile: Some(parse_profile(&t.profile)?),
        openapi: t.spec.as_ref().map(|s| rel(root, s).display().to_string()),
        roles: t.roles.as_ref().map(|r| rel(root, r)),
        no_tools: true,
        qa: true,
        ..Default::default()
    };
    let id = crate::engine::new_run_id();
    let run = crate::engine::scan(&opts, &id)?;
    let qa = run.qa.as_ref().context("the run produced no QA report")?;
    let observed = qa
        .defects
        .iter()
        .filter(|d| d.status != crate::model::FindingStatus::Suppressed)
        .map(|d| Observed {
            rules: vec![d.rule.clone()],
            component: d.component.clone(),
            title: d.title.clone(),
        })
        .collect();
    Ok(Outcome {
        verdict: format!("{:?}/{:?}", qa.recommendation, run.verdict),
        observed,
        checks: vec![],
        stats: RunStats::default(),
    })
}

fn exec_repo(spec: &SuiteSpec, root: &Path) -> Result<Outcome> {
    let t = &spec.target;
    let path = rel(root, t.path.as_deref().unwrap_or("."));
    let opts = crate::engine::ScanOpts {
        target: path.display().to_string(),
        profile: Some(parse_profile(&t.profile)?),
        no_tools: true,
        qa: true,
        ..Default::default()
    };
    let id = crate::engine::new_run_id();
    let run = crate::engine::scan(&opts, &id)?;
    let observed = run
        .findings
        .iter()
        .filter(|f| f.status != crate::model::FindingStatus::Suppressed)
        .map(|f| Observed {
            rules: vec![f.rule.clone()],
            component: f.location.clone(),
            title: f.title.clone(),
        })
        .collect();
    Ok(Outcome {
        verdict: format!("{:?}", run.verdict),
        observed,
        checks: vec![],
        stats: RunStats::default(),
    })
}

/// One agent run against the fixture, as the suite file describes it.
fn agent_run_once(
    spec: &SuiteSpec,
    root: &Path,
    work: &Path,
    base_url: &str,
    limits: &Thresholds,
) -> Result<crate::agent::AgentRunReport> {
    use crate::agent::{self, Credentials, LlmMode, RunBudget, RunOptions};
    let t = &spec.target;
    let max_steps = t.max_steps.unwrap_or(50);
    // the source repo of a change-aware run: built fresh for every run
    let repo = match &t.repo {
        Some(r) => {
            let dest = work.join("src-repo");
            build_fixture_repo(root, &r.commits, &dest)?;
            Some(dest.display().to_string())
        }
        None => None,
    };
    // serde defaults fill every field a newer AgentRunRequest may have.
    let req: agent::AgentRunRequest = serde_json::from_value(serde_json::json!({
        "target": base_url,
        "profile": t.profile,
        "spec_url": t.spec.as_ref().map(|s| rel(root, s).display().to_string()),
        "dry_run": false,
        "thinking": false,
        "repo": repo,
        "diff_base": repo
            .as_ref()
            .filter(|_| {
                spec.target
                    .repo
                    .as_ref()
                    .is_some_and(|r| r.diff_base.unwrap_or(r.commits.len() > 1))
            })
            .map(|_| "base"),
    }))?;
    let mut budget = RunBudget::default().with_max_steps(max_steps);
    if let Some(r) = limits.max_requests {
        budget = budget.with_max_requests(r);
    }
    if let Some(s) = limits.max_seconds {
        budget = budget.with_max_wall(Duration::from_secs_f64(s));
    }
    let mut creds = Credentials::none();
    for (role, token) in &t.tokens {
        creds = creds.with(role, token);
    }
    let mut ro = RunOptions::default();
    ro.budget = budget;
    ro.credentials = creds;
    ro.llm = LlmMode::Off;
    ro.lookup_requester_ip = false;

    let id = crate::engine::new_run_id();
    let rep = agent::run_agentic_loop_with(&req, &id, ro)?;
    if let Some(e) = &rep.error {
        bail!("agent run {}: {e}", rep.status);
    }
    Ok(rep)
}

/// What an agent run reported: each triaged defect with the failing oracle checks of its cases
/// (a defect can carry several), and its fingerprint.
fn agent_defects(rep: &crate::agent::AgentRunReport) -> Vec<(Observed, String)> {
    use crate::agent::Verdict;
    rep.triaged_defects
        .iter()
        .map(|d| {
            let mut rules: Vec<String> = vec![];
            for cid in &d.case_ids {
                if let Some(o) = rep
                    .executed_results
                    .iter()
                    .find(|r| &r.case_id == cid)
                    .and_then(|r| r.oracle.as_ref())
                {
                    for c in o.checks.iter().filter(|c| c.verdict == Verdict::Fail) {
                        if !rules.contains(&c.code) {
                            rules.push(c.code.clone());
                        }
                    }
                }
            }
            (
                Observed {
                    rules,
                    component: d.component.clone(),
                    title: d.title.clone(),
                },
                d.fingerprint.clone(),
            )
        })
        .collect()
}

fn exec_agent(
    spec: &SuiteSpec,
    root: &Path,
    work: &Path,
    base_url: &str,
    limits: &Thresholds,
) -> Result<Outcome> {
    let n = spec.memory.as_ref().map_or(1, |m| m.runs);
    let mut reports = vec![];
    for i in 1..=n {
        if n > 1 {
            eprintln!(
                "eval:   {} agent run {i}/{n} in the same data directory",
                spec.name
            );
        }
        reports.push(agent_run_once(spec, root, work, base_url, limits)?);
    }
    let rep = reports.last().expect("at least one run");
    let observed = agent_defects(rep).into_iter().map(|(o, _)| o).collect();
    let verdict = rep
        .evidence_ledger
        .as_ref()
        .map(|l| l.gate_verdict.clone())
        .unwrap_or_else(|| "UNKNOWN".into());
    let mut checks = spec
        .change
        .as_ref()
        .map(|c| change_checks(c, rep))
        .unwrap_or_default();
    if spec.memory.is_some() {
        checks.extend(memory_checks(spec, &reports));
    }
    if spec
        .target
        .repo
        .as_ref()
        .is_some_and(|r| r.require_source_context)
    {
        let linked: Vec<String> = rep
            .triaged_defects
            .iter()
            .filter_map(|d| {
                d.source_context
                    .as_deref()
                    .filter(|s| s.contains(':'))
                    .map(|s| format!("{} ({s})", d.component))
            })
            .collect();
        checks.push(Check {
            name: "whitebox source linkage".into(),
            ok: !linked.is_empty(),
            detail: if linked.is_empty() {
                "expected at least one defect with file:line source_context".into()
            } else {
                format!("linked {}", linked.join(", "))
            },
        });
    }
    Ok(Outcome {
        verdict,
        observed,
        checks,
        stats: agent_stats(rep),
    })
}

/// Cases by status, the ledger's confidence and its blocker reasons (`auth_wall`, ...).
pub fn agent_stats(rep: &crate::agent::AgentRunReport) -> RunStats {
    let ledger = rep.evidence_ledger.as_ref();
    let blockers = ledger
        .map(|l| {
            l.blockers
                .iter()
                .filter_map(|b| serde_json::to_value(b.reason).ok())
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    RunStats::from_statuses(
        rep.executed_results.iter().map(|r| r.status.as_str()),
        ledger.and_then(|l| l.confidence),
        blockers,
    )
}

/// What `[memory]` asks of a series of runs in one data directory: the first run remembers what it
/// found, every later run reports the seeded defects as still open, leads its plan with their
/// reproduction cases, and plans every case the first run planned (memory only reorders).
pub fn memory_checks(spec: &SuiteSpec, reps: &[crate::agent::AgentRunReport]) -> Vec<Check> {
    let (Some(first), Some(last)) = (reps.first(), reps.last()) else {
        return vec![];
    };
    let mut out = vec![];
    let check = |name: &str, ok: bool, detail: String| Check {
        name: name.into(),
        ok,
        detail,
    };
    // the first run: nothing was known, everything it found is new, and it was remembered
    let s1 = first.since_last_run.as_ref();
    out.push(check(
        "memory: first run remembered",
        s1.is_some_and(|s| {
            s.first_run
                && s.committed
                && s.new.len() == first.triaged_defects.len()
                && !first.triaged_defects.is_empty()
        }),
        match s1 {
            Some(s) => format!(
                "first_run {}, remembered {}, {} new of {} defect(s)",
                s.first_run,
                s.committed,
                s.new.len(),
                first.triaged_defects.len()
            ),
            None => "the report has no since_last_run (memory off?)".into(),
        },
    ));
    let Some(sl) = last.since_last_run.as_ref().filter(|_| reps.len() > 1) else {
        out.push(check(
            "memory: seeded defects still open",
            false,
            "the last run has no since_last_run".into(),
        ));
        return out;
    };
    // the seeded defects: every required expectation is matched by a defect that is "still open"
    let defects = agent_defects(last);
    let still_open: std::collections::BTreeSet<&str> = sl
        .still_open
        .iter()
        .map(|l| l.fingerprint.as_str())
        .collect();
    let required: Vec<&Expect> = spec
        .expect
        .iter()
        .filter(|e| !e.optional && !e.known_gap)
        .collect();
    let not_open: Vec<&str> = required
        .iter()
        .filter(|e| {
            !defects
                .iter()
                .any(|(o, fp)| expect_matches(e, o) && still_open.contains(fp.as_str()))
        })
        .map(|e| e.id.as_str())
        .collect();
    let first_fps: std::collections::BTreeSet<&str> = first
        .triaged_defects
        .iter()
        .map(|d| d.fingerprint.as_str())
        .collect();
    let renewed: Vec<&str> = sl
        .new
        .iter()
        .filter(|l| first_fps.contains(l.fingerprint.as_str()))
        .map(|l| l.endpoint.as_str())
        .collect();
    out.push(check(
        "memory: seeded defects still open",
        not_open.is_empty() && renewed.is_empty(),
        format!(
            "{} of {} expected defect(s) reported still open ({} defect(s) in all){}{}",
            required.len() - not_open.len(),
            required.len(),
            sl.still_open.len(),
            if not_open.is_empty() {
                String::new()
            } else {
                format!("; not still open: {}", not_open.join(", "))
            },
            if renewed.is_empty() {
                String::new()
            } else {
                format!("; reported new again: {}", renewed.join(", "))
            }
        ),
    ));
    // the plan: the reproduction cases lead it, one for every still-open defect that has a planned
    // reproduction (a defect found by the teardown has none: no planned case deletes and re-reads)
    let plan: Vec<&crate::agent::PlannedCase> = last
        .planned_cases
        .iter()
        .filter(|c| !c.id.contains("-F"))
        .collect();
    let lead = plan
        .iter()
        .take_while(|c| !c.regression_of.is_empty())
        .count();
    let tagged_after = plan[lead..].iter().any(|c| !c.regression_of.is_empty());
    let planned_repro: Vec<&crate::agent::memory::DefectLine> = sl
        .still_open
        .iter()
        .filter(|l| l.rule != "delete_not_effective")
        .collect();
    let uncovered: Vec<&str> = planned_repro
        .iter()
        .filter(|l| {
            !plan[..lead]
                .iter()
                .any(|c| c.regression_of.contains(&l.fingerprint))
        })
        .map(|l| l.endpoint.as_str())
        .collect();
    out.push(check(
        "memory: regression probes lead the plan",
        lead > 0 && !tagged_after && uncovered.is_empty(),
        format!(
            "{lead} probe(s) lead the plan of {} case(s), none after the first other case; {} of {} still-open defect(s) have one{}",
            plan.len(),
            planned_repro.len() - uncovered.len(),
            planned_repro.len(),
            if uncovered.is_empty() {
                String::new()
            } else {
                format!("; without a probe: {}", uncovered.join(", "))
            }
        ),
    ));
    // memory reorders, it never drops a case: whatever passed before is planned (and run) again.
    // The target may list records it did not list before (the fixture keeps the orders its
    // no-op DELETE leaves behind), so the later plan may hold MORE reads; it never holds fewer cases.
    let shape = |rep: &crate::agent::AgentRunReport| {
        let mut v: Vec<String> = rep
            .planned_cases
            .iter()
            .filter(|c| !c.id.contains("-F"))
            .map(|c| {
                format!(
                    "{} {} {} {:?} {:?}",
                    c.method, c.component, c.technique, c.payload, c.role
                )
            })
            .collect();
        v.sort();
        v
    };
    let (a, b) = (shape(first), shape(last));
    let mut left = b.clone();
    let dropped: Vec<&String> = a
        .iter()
        .filter(|c| match left.iter().position(|x| x == *c) {
            Some(i) => {
                left.remove(i);
                false
            }
            None => true,
        })
        .collect();
    out.push(check(
        "memory: no case dropped",
        dropped.is_empty(),
        format!(
            "run 1 planned {} case(s), the last run {} ({} more)",
            a.len(),
            b.len(),
            b.len().saturating_sub(a.len())
        ) + &if dropped.is_empty() {
            String::new()
        } else {
            format!(
                "; no longer planned: {}",
                dropped
                    .iter()
                    .take(5)
                    .map(|d| d.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    ));
    out
}

/// What `[change]` asks of the run's change impact: the right operations were found, their cases
/// lead the plan, and they were really sent.
pub fn change_checks(c: &ChangeSpec, rep: &crate::agent::AgentRunReport) -> Vec<Check> {
    let Some(ci) = &rep.change_impact else {
        return vec![Check {
            name: "change impact".into(),
            ok: false,
            detail: "the report has no change impact (repo or diff_base not applied)".into(),
        }];
    };
    let mut out = vec![];
    let mut got: Vec<String> = ci.operations.iter().map(|o| o.operation.clone()).collect();
    let mut want = c.operations.clone();
    got.sort();
    want.sort();
    out.push(Check {
        name: "changed operations".into(),
        ok: got == want,
        detail: format!(
            "{} changed file(s) -> reported [{}], expected [{}]",
            ci.changed_files_total,
            got.join(", "),
            want.join(", ")
        ),
    });
    if c.planned_first {
        let pos: Vec<usize> = rep
            .planned_cases
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.changed_ops.is_empty())
            .map(|(i, _)| i)
            .collect();
        let first_other = rep
            .planned_cases
            .iter()
            .position(|p| p.changed_ops.is_empty() && p.component != "/");
        let last = pos.last().copied();
        out.push(Check {
            name: "changed operations planned first".into(),
            ok: match (last, first_other) {
                (Some(l), Some(o)) => l < o,
                (Some(_), None) => true,
                (None, _) => false,
            },
            detail: format!(
                "{} changed case(s), the last at position {}; the first other case at {}",
                pos.len(),
                last.map(|l| (l + 1).to_string())
                    .unwrap_or_else(|| "-".into()),
                first_other
                    .map(|o| (o + 1).to_string())
                    .unwrap_or_else(|| "-".into()),
            ),
        });
    }
    let (sent, planned) = crate::agent::change::coverage_totals(&ci.coverage);
    let share = if planned == 0 {
        0.0
    } else {
        sent as f64 / planned as f64
    };
    let uncovered: Vec<&str> = ci
        .coverage
        .iter()
        .filter(|o| o.executed == 0)
        .map(|o| o.operation.as_str())
        .collect();
    out.push(Check {
        name: "changed operations covered".into(),
        ok: planned > 0 && share + 1e-9 >= c.min_sent && uncovered.is_empty(),
        detail: format!(
            "{sent} of {planned} planned case(s) sent ({:.0}%) vs >= {:.0}%{}",
            share * 100.0,
            c.min_sent * 100.0,
            if uncovered.is_empty() {
                String::new()
            } else {
                format!("; not sent at all: {}", uncovered.join(", "))
            }
        ),
    });
    out
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let e = e?;
        let ty = e.file_type()?;
        let to = dst.join(e.file_name());
        if ty.is_dir() {
            copy_tree(&e.path(), &to)?;
        } else if ty.is_file() {
            std::fs::copy(e.path(), &to)?;
        } // symlinks are not fixtures
    }
    Ok(())
}

fn fixture_git(dir: &Path, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "readyhai-eval")
        .env("GIT_AUTHOR_EMAIL", "eval@example.invalid")
        .env("GIT_COMMITTER_NAME", "readyhai-eval")
        .env("GIT_COMMITTER_EMAIL", "eval@example.invalid");
    let out = crate::tools::run_capped(&mut cmd, Duration::from_secs(60), 16 * 1024, None)
        .context("run git (the change-aware eval needs git on PATH)")?;
    if !out.success() {
        bail!("git {}: {}", args.join(" "), out.stderr_lossy().trim());
    }
    Ok(())
}

/// A repository whose history is the fixture directories in order: each one is copied over the
/// working tree and committed, and the first commit is tagged `base`.
pub fn build_fixture_repo(root: &Path, commits: &[String], dest: &Path) -> Result<()> {
    let _ = std::fs::remove_dir_all(dest);
    std::fs::create_dir_all(dest)?;
    fixture_git(dest, &["init", "-q"])?;
    for (i, c) in commits.iter().enumerate() {
        let src = rel(root, c);
        if !src.is_dir() {
            bail!("fixture commit {} is not a directory", src.display());
        }
        copy_tree(&src, dest)?;
        fixture_git(dest, &["add", "-A"])?;
        fixture_git(
            dest,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "--no-verify",
                "-m",
                &format!("fixture commit {}", i + 1),
            ],
        )?;
        if i == 0 {
            fixture_git(dest, &["tag", "base"])?;
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ driver

fn run_suite(spec: &SuiteSpec, k: usize, root: &Path, work: &Path, scope: &Path) -> SuiteResult {
    let mut runs = vec![];
    let mut error = None;
    for i in 1..=k {
        eprintln!("eval: {} run {i}/{k} ({:?})", spec.name, spec.kind);
        match run_once(spec, i, root, work, scope) {
            Ok(r) => {
                eprintln!(
                    "eval:   {} recall {:.2} · precision {:.2} · {} false positive(s) · inconclusive {} · {} request(s) · {:.1}s · {}",
                    spec.name,
                    r.recall,
                    r.precision,
                    r.false_positives.len(),
                    pct(r.inconclusive_rate),
                    r.requests,
                    r.seconds,
                    r.verdict
                );
                runs.push(r);
            }
            Err(e) => {
                eprintln!("eval:   {} run {i} failed: {e:#}", spec.name);
                error = Some(format!("run {i}: {e:#}"));
                break;
            }
        }
    }
    summarize_suite(spec, k, runs, error)
}

fn run_once(
    spec: &SuiteSpec,
    i: usize,
    root: &Path,
    work: &Path,
    scope: &Path,
) -> Result<RunScore> {
    let dir = work.join(format!("{}-{i}", spec.name));
    let data = dir.join("data");
    std::fs::create_dir_all(&data)?;

    let mut env = EnvGuard::new();
    env.set("READYHAI_DATA", &data);
    env.set("READYHAI_SCOPE", scope);
    env.set("READYHAI_OFFLINE", "1");
    for k in [
        "READYHAI_LLM_PROVIDER",
        "READYHAI_LLM_MODEL",
        "READYHAI_LLM_MODELS",
        "READYHAI_LLM_URL",
        "READYHAI_LLM_API_KEY",
        "READYHAI_LLM_ALLOW_CLOUD",
        "READYHAI_VLLM_URL",
        "READYHAI_PLUGINS",
        "READYHAI_ROLES",
        "READYHAI_ALLOWED_ROOTS",
        "READYHAI_AGENT_MAX_STEPS",
        "READYHAI_AGENT_MAX_REQUESTS",
        "READYHAI_AGENT_MAX_SECONDS",
        "READYHAI_AGENT_RATE_PER_HOST",
        "READYHAI_AGENT_MAX_LLM_CALLS",
        "READYHAI_AGENT_WORKERS",
        "READYHAI_AGENT_MEMORY",
    ] {
        env.unset(k);
    }
    for (role, token) in &spec.target.tokens {
        env.set(&role_env(role), token);
    }

    let fixture = match &spec.target.server {
        Some(s) => Some(Fixture::start(
            &rel(root, s),
            &dir.join("requests.log"),
            &spec.target.server_args,
        )?),
        None => None,
    };
    let url = fixture.as_ref().map(Fixture::url).unwrap_or_default();

    let started = Instant::now();
    let outcome = match spec.kind {
        SuiteKind::Qa => exec_qa(spec, root, &url)?,
        SuiteKind::Agent => exec_agent(spec, root, &dir, &url, &spec.thresholds)?,
        SuiteKind::Repo => exec_repo(spec, root)?,
    };
    let seconds = started.elapsed().as_secs_f64();
    let requests = fixture.as_ref().map_or(0, Fixture::requests);
    let mut score = score_run(
        spec,
        i,
        &outcome.verdict,
        &outcome.observed,
        requests,
        seconds,
    );
    score.checks = outcome.checks;
    Ok(score.with_stats(outcome.stats))
}

const SCOPE_TOML: &str = "# Written by `readyhai eval`: the fixture runs on loopback and may be attacked.\n\
[[hosts]]\nhost = \"127.0.0.1\"\nenv = \"nonprod\"\n\n\
[[hosts]]\nhost = \"localhost\"\nenv = \"nonprod\"\n";

/// Run the selected suites `k` times each and write `eval-report.json` / `eval-report.md`.
pub fn run_eval(opts: EvalOpts) -> Result<EvalSummary> {
    if opts.k == 0 {
        bail!("k must be at least 1");
    }
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = resolve_root(&opts)?;
    let suites = load_suites(&root, &opts)?;

    let work = std::env::temp_dir().join(format!(
        "readyhai-eval-{}-{}",
        std::process::id(),
        crate::engine::new_run_id()
    ));
    std::fs::create_dir_all(&work)?;
    let scope = work.join("scope.toml");
    std::fs::write(&scope, SCOPE_TOML)?;

    let started = crate::engine::now();
    let results: Vec<SuiteResult> = suites
        .iter()
        .map(|s| run_suite(s, opts.k, &root, &work, &scope))
        .collect();
    if std::env::var_os("READYHAI_EVAL_KEEP").is_some() {
        eprintln!("eval: kept run data in {}", work.display());
    } else {
        let _ = std::fs::remove_dir_all(&work);
    }

    let mut summary = EvalSummary {
        version: crate::engine::VERSION.to_string(),
        started,
        k: opts.k,
        passed: results.iter().all(|s| s.passed),
        suites: results,
        report_json: opts.out.join("eval-report.json"),
        report_md: opts.out.join("eval-report.md"),
    };
    std::fs::create_dir_all(&opts.out).with_context(|| format!("create {}", opts.out.display()))?;
    std::fs::write(&summary.report_json, serde_json::to_vec_pretty(&summary)?)?;
    let md = render_markdown(&summary);
    std::fs::write(&summary.report_md, &md)?;
    summary.report_json = summary
        .report_json
        .canonicalize()
        .unwrap_or(summary.report_json);
    summary.report_md = summary
        .report_md
        .canonicalize()
        .unwrap_or(summary.report_md);

    eprintln!("\n{md}");
    eprintln!("eval: report: {}", summary.report_json.display());
    eprintln!("eval: report: {}", summary.report_md.display());
    Ok(summary)
}

// ------------------------------------------------------------------ report

fn mark(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

/// `12%`, or `-` when there is no number (not an agent suite, or nothing was executed).
fn pct(x: Option<f64>) -> String {
    x.map_or("-".into(), |x| format!("{:.0}%", x * 100.0))
}

/// The markdown summary: one table row per suite, then the detail of every suite that missed.
pub fn render_markdown(s: &EvalSummary) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "# ReadyHai eval: {}\n\nversion {} · {} · k = {}\n\n",
        mark(s.passed),
        s.version,
        s.started,
        s.k
    ));
    o.push_str("| suite | kind | recall | min run | precision | FP | inconclusive | confidence | pass^k | verdict | requests | time | open gaps | result |\n");
    o.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for r in &s.suites {
        o.push_str(&format!(
            "| {} | {:?} | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} | {} | {} | {:.1}s | {} | {} |\n",
            r.name,
            r.kind,
            r.recall,
            r.recall_min,
            r.precision,
            r.false_positives,
            pct(r.inconclusive_rate),
            r.confidence.map_or("-".into(), |c| format!("{c}%")),
            if r.pass_k { "yes" } else { "no" },
            if r.verdict_stable {
                r.verdicts.first().cloned().unwrap_or_default()
            } else {
                format!("UNSTABLE ({})", r.verdicts.join(" / "))
            },
            r.requests,
            r.seconds,
            r.known_gaps_open.len(),
            mark(r.passed),
        ));
    }
    for r in &s.suites {
        o.push_str(&format!("\n## {} ({})\n\n", r.name, mark(r.passed)));
        if !r.description.is_empty() {
            o.push_str(&format!("{}\n\n", r.description));
        }
        for c in &r.checks {
            o.push_str(&format!("- {} {}: {}\n", mark(c.ok), c.name, c.detail));
        }
        if !r.known_gaps_open.is_empty() {
            o.push_str(&format!(
                "- known gaps still open (not counted in recall): {}\n",
                r.known_gaps_open.join(", ")
            ));
        }
        if !r.known_gaps_closed.is_empty() {
            o.push_str(&format!(
                "- known gaps now found in every run, remove `known_gap` so they gate: {}\n",
                r.known_gaps_closed.join(", ")
            ));
        }
        if !r.blockers.is_empty() {
            o.push_str(&format!("- blockers reported: {}\n", r.blockers.join(", ")));
        }
        for run in &r.runs {
            if !run.cases.is_empty() {
                o.push_str(&format!(
                    "- run {} cases: {}\n",
                    run.run,
                    run.cases
                        .iter()
                        .map(|(k, v)| format!("{k} {v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !run.missed.is_empty() {
                let with_notes: Vec<String> = run
                    .missed
                    .iter()
                    .map(|id| match r.notes.get(id) {
                        Some(n) => format!("{id} ({n})"),
                        None => id.clone(),
                    })
                    .collect();
                o.push_str(&format!(
                    "- run {} missed: {}\n",
                    run.run,
                    with_notes.join("; ")
                ));
            }
            if !run.optional_missed.is_empty() {
                o.push_str(&format!(
                    "- run {} optional not found: {}\n",
                    run.run,
                    run.optional_missed.join(", ")
                ));
            }
            for fp in &run.false_positives {
                o.push_str(&format!("- run {} false positive: {fp}\n", run.run));
            }
        }
    }
    o
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(extra: &str) -> SuiteSpec {
        parse_suite(
            &format!(
                r#"
name = "t"
kind = "qa"
[target]
server = "s.py"
roles = "r.toml"
[[expect]]
id = "a"
rule = "qa.api.bola"
[[expect]]
id = "b"
rule = "qa.api.server_error"
component = "POST /orders"
note = "the 500 on note"
[[expect]]
id = "c"
rule = "qa.api.slow_*"
[[expect]]
id = "d"
rule = "qa.api.optional"
optional = true
[[allow]]
rule = "qa.api.privilege_escalation"
{extra}
"#
            ),
            "test",
        )
        .unwrap()
    }

    fn obs(rule: &str, comp: &str) -> Observed {
        Observed {
            rules: vec![rule.into()],
            component: comp.into(),
            title: format!("{rule} on {comp}"),
        }
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match("qa.api.bola", "qa.api.bola"));
        assert!(!glob_match("qa.api.bola", "qa.api.bola2"));
        assert!(glob_match("qa.api.*", "qa.api.bola"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*c*e", "abcde"));
        assert!(!glob_match("a*c*e", "abcd"));
        assert!(glob_match("*.bola", "qa.api.bola"));
        assert!(!glob_match("*.bola", "qa.api.bolas"));
        assert!(glob_match("GET /orders/{id}", "GET /orders/{id}"));
        assert!(!glob_match("a*bc", "ab"));
        assert!(
            !glob_match("ab*ba", "aba"),
            "prefix and suffix may not overlap"
        );
    }

    #[test]
    fn recall_counts_required_only_and_component_must_match() {
        let s = spec("");
        let seen = [
            obs("qa.api.bola", "GET /orders/{id}"),
            obs("qa.api.server_error", "GET /search"), // wrong component for "b"
            obs("qa.api.slow_response", "GET /reports/slow"),
            obs("qa.api.optional", "x"),
        ];
        let r = score_run(&s, 1, "NoGo", &seen, 10, 1.0);
        assert_eq!(r.found, ["a", "c"]);
        assert_eq!(r.missed, ["b"]);
        assert_eq!(r.optional_found, ["d"]);
        assert!((r.recall - 0.667).abs() < 1e-9);
        // the mismatched server_error is unexpected: it matches neither an expect nor an allow
        assert_eq!(r.false_positives, ["qa.api.server_error @ GET /search"]);
    }

    #[test]
    fn allowed_extras_are_not_false_positives() {
        let s = spec("reason = \"role matrix view\"");
        let seen = [
            obs("qa.api.privilege_escalation", "GET /admin/stats"),
            obs("qa.api.surprise", "GET /x"),
        ];
        let r = score_run(&s, 1, "NoGo", &seen, 0, 0.0);
        assert_eq!(r.false_positives, ["qa.api.surprise @ GET /x"]);
        assert_eq!(
            r.allowed_seen,
            ["qa.api.privilege_escalation @ GET /admin/stats: role matrix view"]
        );
        assert_eq!(r.recall, 0.0);
    }

    #[test]
    fn observe_prefix_ignores_other_findings() {
        let mut s = spec("");
        s.observe_prefix = Some("qa.".into());
        let seen = [
            obs("readiness.dockerfile.no_user", "Dockerfile"),
            obs("qa.api.bola", "x"),
        ];
        let r = score_run(&s, 1, "Warn", &seen, 0, 0.0);
        assert!(r.false_positives.is_empty());
        assert_eq!(r.observed.len(), 1);
    }

    fn gap_spec() -> SuiteSpec {
        parse_suite(
            r#"
name = "g"
kind = "agent"
[target]
server = "s.py"
[[expect]]
id = "found"
rule = "authz"
[[expect]]
id = "gap"
rule = "slow"
known_gap = true
"#,
            "test",
        )
        .unwrap()
    }

    #[test]
    fn known_gaps_are_reported_but_never_counted_in_recall() {
        let s = gap_spec();
        let open = score_run(&s, 1, "NO_GO", &[obs("authz", "/admin")], 0, 0.0);
        assert_eq!(open.recall, 1.0, "the gap does not lower recall");
        assert_eq!(open.gap_missed, ["gap"]);
        assert!(open.missed.is_empty());
        let r = summarize_suite(&s, 1, vec![open], None);
        assert!(r.passed);
        assert_eq!(r.known_gaps_open, ["gap"]);
        assert!(r.known_gaps_closed.is_empty());

        // once the tool finds it the report says to promote it, in every run
        let closed = |n| {
            score_run(
                &s,
                n,
                "NO_GO",
                &[obs("authz", "/a"), obs("slow", "/b")],
                0,
                0.0,
            )
        };
        let r = summarize_suite(&s, 2, vec![closed(1), closed(2)], None);
        assert_eq!(r.known_gaps_closed, ["gap"]);
        assert!(r.known_gaps_open.is_empty());
        // a gap found in only one of two runs is still open
        let r = summarize_suite(
            &s,
            2,
            vec![
                closed(1),
                score_run(&s, 2, "NO_GO", &[obs("authz", "/a")], 0, 0.0),
            ],
            None,
        );
        assert_eq!(r.known_gaps_open, ["gap"]);
        assert!(r.known_gaps_closed.is_empty());
        // and the markdown names them
        let md = render_markdown(&EvalSummary {
            version: "0".into(),
            started: "now".into(),
            k: 2,
            passed: r.passed,
            suites: vec![r],
            report_json: PathBuf::new(),
            report_md: PathBuf::new(),
        });
        assert!(md.contains("known gaps still open (not counted in recall): gap"));
    }

    #[test]
    fn multi_rule_agent_defect_matches_any_of_its_rules() {
        let s = spec("");
        let o = Observed {
            rules: vec!["status_5xx".into(), "qa.api.bola".into()],
            component: "GET /orders/{id}".into(),
            title: "x".into(),
        };
        let r = score_run(&s, 1, "NO_GO", &[o], 0, 0.0);
        assert_eq!(r.found, ["a"]);
        assert!(r.false_positives.is_empty());
    }

    fn run(recall: f64, fp: usize, verdict: &str, requests: usize, seconds: f64) -> RunScore {
        RunScore {
            run: 1,
            verdict: verdict.into(),
            recall,
            found: vec![],
            missed: vec![],
            optional_found: vec![],
            optional_missed: vec![],
            gap_found: vec![],
            gap_missed: vec![],
            false_positives: (0..fp).map(|i| format!("fp{i}")).collect(),
            true_positives: 0,
            precision: 1.0,
            allowed_seen: vec![],
            observed: vec![],
            requests,
            seconds,
            cases: BTreeMap::new(),
            inconclusive_rate: None,
            confidence: None,
            blockers: vec![],
            checks: vec![],
        }
    }

    fn check<'a>(r: &'a SuiteResult, name: &str) -> &'a Check {
        r.checks.iter().find(|c| c.name == name).unwrap()
    }

    #[test]
    fn thresholds_pass_when_every_run_is_good() {
        let s = spec("");
        let r = summarize_suite(
            &s,
            2,
            vec![run(1.0, 1, "NoGo", 100, 5.0), run(0.9, 2, "NoGo", 120, 6.0)],
            None,
        );
        assert!(r.passed, "{:?}", r.checks);
        assert!(r.pass_k && r.verdict_stable);
        assert_eq!(r.false_positives, 2);
        assert_eq!(r.requests, 120);
        assert!((r.recall - 0.95).abs() < 1e-9);
    }

    #[test]
    fn pass_k_fails_when_one_run_is_below_threshold_even_if_the_mean_passes() {
        let s = spec("");
        let r = summarize_suite(
            &s,
            2,
            vec![run(1.0, 0, "NoGo", 1, 1.0), run(0.8, 0, "NoGo", 1, 1.0)],
            None,
        );
        assert!(check(&r, "recall").ok, "mean 0.9 is fine");
        assert!(!check(&r, "pass^k").ok);
        assert!(!r.passed);
    }

    #[test]
    fn false_positives_verdict_and_budgets_each_fail_the_suite() {
        let mut s = spec("");
        s.thresholds.max_requests = Some(100);
        s.thresholds.max_seconds = Some(10.0);
        s.expect_verdict = Some("NoGo".into());

        let fp = summarize_suite(&s, 1, vec![run(1.0, 3, "NoGo", 1, 1.0)], None);
        assert!(!check(&fp, "false positives").ok);

        let unstable = summarize_suite(
            &s,
            2,
            vec![run(1.0, 0, "NoGo", 1, 1.0), run(1.0, 0, "Go", 1, 1.0)],
            None,
        );
        assert!(!check(&unstable, "verdict stable").ok);
        assert!(!check(&unstable, "expected verdict").ok);

        let req = summarize_suite(&s, 1, vec![run(1.0, 0, "NoGo", 101, 1.0)], None);
        assert!(!check(&req, "request budget").ok);

        let slow = summarize_suite(&s, 1, vec![run(1.0, 0, "NoGo", 1, 10.5)], None);
        assert!(!check(&slow, "time budget").ok);

        let ok = summarize_suite(&s, 1, vec![run(1.0, 0, "nogo", 100, 10.0)], None);
        assert!(ok.passed, "{:?}", ok.checks);
    }

    #[test]
    fn an_errored_or_short_suite_never_passes() {
        let s = spec("");
        let r = summarize_suite(
            &s,
            2,
            vec![run(1.0, 0, "NoGo", 1, 1.0)],
            Some("run 2: boom".into()),
        );
        assert!(!r.passed);
        assert!(!r.pass_k);
        assert!(check(&r, "runs completed").detail.contains("boom"));
        let none = summarize_suite(&s, 2, vec![], Some("run 1: boom".into()));
        assert!(!none.passed);
        assert_eq!(none.recall, 0.0);
    }

    #[test]
    fn exit_code_follows_the_overall_result() {
        let s = spec("");
        let ok = summarize_suite(&s, 1, vec![run(1.0, 0, "NoGo", 1, 1.0)], None);
        let bad = summarize_suite(&s, 1, vec![run(0.1, 0, "NoGo", 1, 1.0)], None);
        let mk = |suites: Vec<SuiteResult>| EvalSummary {
            version: "t".into(),
            started: "now".into(),
            k: 1,
            passed: suites.iter().all(|s| s.passed),
            suites,
            report_json: PathBuf::new(),
            report_md: PathBuf::new(),
        };
        assert_eq!(mk(vec![ok.clone()]).exit_code(), 0);
        assert_eq!(mk(vec![ok, bad]).exit_code(), 1);
    }

    #[test]
    fn markdown_lists_suites_and_the_misses() {
        let s = spec("");
        let mut bad = run(0.5, 1, "NoGo", 9, 2.0);
        bad.missed = vec!["b".into()];
        let r = summarize_suite(&s, 1, vec![bad], None);
        let md = render_markdown(&EvalSummary {
            version: "0.0.0".into(),
            started: "now".into(),
            k: 1,
            passed: false,
            suites: vec![r],
            report_json: PathBuf::new(),
            report_md: PathBuf::new(),
        });
        assert!(md.contains("# ReadyHai eval: FAIL"));
        assert!(md.contains("| t | Qa |"));
        assert!(md.contains("run 1 missed: b (the 500 on note)"));
        assert!(md.contains("run 1 false positive: fp0"));
    }

    #[test]
    fn suite_validation_rejects_broken_files() {
        let bad = |t: &str| parse_suite(t, "x").is_err();
        assert!(bad("name = \"t\"\nkind = \"qa\"\n[target]\n")); // no server, no expect
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        )); // no path
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\npath=\"p\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        )); // duplicate id
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\nbogus = 1\n[target]\npath=\"p\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        )); // unknown key
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\npath=\"p\"\n[thresholds]\nmin_recall = 1.5\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        ));
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\npath=\"p\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\noptional=true\nknown_gap=true\n"
        )); // exclusive flags
        assert!(!bad(
            "name = \"t\"\nkind = \"repo\"\n[target]\npath=\"p\"\n[[expect]]\nid=\"a\"\nrule=\"r\"\n"
        ));
    }

    fn counts(v: &[(&str, usize)]) -> BTreeMap<String, usize> {
        v.iter().map(|(k, n)| (k.to_string(), *n)).collect()
    }

    #[test]
    fn precision_is_true_positives_over_reported_and_allowed_extras_are_out() {
        let s = spec("reason = \"role matrix view\"");
        // 2 expected, 1 unexpected, 1 allowed extra: precision 2 / 3
        let seen = [
            obs("qa.api.bola", "GET /orders/{id}"),
            obs("qa.api.slow_response", "GET /reports/slow"),
            obs("qa.api.surprise", "GET /x"),
            obs("qa.api.privilege_escalation", "GET /admin/stats"),
        ];
        let r = score_run(&s, 1, "NoGo", &seen, 0, 0.0);
        assert_eq!(r.true_positives, 2);
        assert_eq!(r.false_positives.len(), 1);
        assert!((r.precision - 0.667).abs() < 1e-9, "{}", r.precision);
        // all unexpected: precision 0; nothing reported: nothing was wrong, 1.0
        let none = score_run(&s, 1, "NoGo", &[obs("qa.api.surprise", "x")], 0, 0.0);
        assert_eq!(none.precision, 0.0);
        let empty = score_run(&s, 1, "Go", &[], 0, 0.0);
        assert_eq!(empty.precision, 1.0);
        // only allowed extras: no true and no false positive, so still 1.0
        let allowed = score_run(
            &s,
            1,
            "NoGo",
            &[obs("qa.api.privilege_escalation", "x")],
            0,
            0.0,
        );
        assert_eq!((allowed.true_positives, allowed.precision), (0, 1.0));
        // the suite reports the mean and the worst run
        let mut bad = run(1.0, 1, "NoGo", 1, 1.0);
        bad.precision = 0.5;
        let r = summarize_suite(&s, 2, vec![run(1.0, 0, "NoGo", 1, 1.0), bad], None);
        assert!((r.precision - 0.75).abs() < 1e-9);
        assert!((r.precision_min - 0.5).abs() < 1e-9);
    }

    #[test]
    fn inconclusive_rate_counts_executed_applicable_cases_only() {
        // 3 inconclusive of 3 + 2 + 1 + 3 = 9 executed; NOT_APPLICABLE, SKIPPED, BLOCKED are out
        let c = counts(&[
            ("PASS", 3),
            ("WARN", 2),
            ("FAIL", 1),
            ("INCONCLUSIVE", 3),
            ("NOT_APPLICABLE", 7),
            ("SKIPPED", 4),
            ("BLOCKED", 5),
        ]);
        assert!((inconclusive_rate(&c).unwrap() - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(inconclusive_rate(&counts(&[("PASS", 4)])), Some(0.0));
        assert_eq!(
            inconclusive_rate(&counts(&[("INCONCLUSIVE", 2)])),
            Some(1.0)
        );
        // nothing executed (all blocked / not applicable): no rate, not 0 and not 1
        assert_eq!(
            inconclusive_rate(&counts(&[("BLOCKED", 5), ("NOT_APPLICABLE", 2)])),
            None
        );
        assert_eq!(inconclusive_rate(&BTreeMap::new()), None);
        // statuses are normalised
        let st = RunStats::from_statuses(["pass", "PASS", " Inconclusive "], Some(66), vec![]);
        assert_eq!(st.cases, counts(&[("INCONCLUSIVE", 1), ("PASS", 2)]));
        let sc = run(1.0, 0, "GO", 1, 1.0).with_stats(st);
        assert_eq!(sc.inconclusive_rate, Some(0.333));
        assert_eq!(sc.confidence, Some(66));
    }

    fn agent_spec(extra: &str) -> SuiteSpec {
        parse_suite(
            &format!(
                r#"
name = "a"
kind = "agent"
{extra}
[target]
server = "s.py"
"#
            ),
            "test",
        )
        .unwrap()
    }

    fn with_rate(rate: Option<f64>, cases: &[(&str, usize)], verdict: &str) -> RunScore {
        let mut r = run(1.0, 0, verdict, 1, 1.0);
        r.inconclusive_rate = rate;
        r.cases = counts(cases);
        r
    }

    #[test]
    fn max_inconclusive_rate_gates_the_worst_run_and_is_off_by_default() {
        let mut s = agent_spec("forbid_verdict = [\"NO_GO\"]");
        // unset: no check at all, whatever the runs did
        let off = summarize_suite(
            &s,
            1,
            vec![with_rate(Some(0.9), &[("INCONCLUSIVE", 9)], "GO")],
            None,
        );
        assert!(off.checks.iter().all(|c| c.name != "inconclusive rate"));
        assert!(off.passed, "{:?}", off.checks);
        assert_eq!(off.inconclusive_rate, Some(0.9), "still reported");

        s.thresholds.max_inconclusive_rate = Some(0.25);
        let ok = summarize_suite(
            &s,
            2,
            vec![
                with_rate(Some(0.1), &[("PASS", 9), ("INCONCLUSIVE", 1)], "GO"),
                with_rate(Some(0.25), &[("PASS", 3), ("INCONCLUSIVE", 1)], "GO"),
            ],
            None,
        );
        assert!(check(&ok, "inconclusive rate").ok, "{:?}", ok.checks);
        assert_eq!(ok.inconclusive_rate, Some(0.25));
        // one bad run fails the suite even though the mean would pass
        let bad = summarize_suite(
            &s,
            2,
            vec![
                with_rate(Some(0.0), &[("PASS", 9)], "GO"),
                with_rate(Some(0.4), &[("PASS", 3), ("INCONCLUSIVE", 2)], "GO"),
            ],
            None,
        );
        let c = check(&bad, "inconclusive rate");
        assert!(!c.ok && c.detail.contains("40%") && c.detail.contains("25%"));
        // no executed case in a run: nothing to rate, so it cannot pass the gate
        let none = summarize_suite(
            &s,
            1,
            vec![with_rate(None, &[("BLOCKED", 4)], "NOT_EVALUATED")],
            None,
        );
        let c = check(&none, "inconclusive rate");
        assert!(
            !c.ok && c.detail.contains("no applicable case"),
            "{}",
            c.detail
        );
    }

    #[test]
    fn forbid_verdict_fails_any_run_that_ends_with_it() {
        let s = agent_spec("forbid_verdict = [\"NO_GO\", \"error\"]");
        let ok = summarize_suite(
            &s,
            2,
            vec![
                run(1.0, 0, "GO", 1, 1.0),
                run(1.0, 0, "NOT_EVALUATED", 1, 1.0),
            ],
            None,
        );
        assert!(check(&ok, "forbidden verdict").ok);
        // case-insensitive, and one run is enough
        let bad = summarize_suite(
            &s,
            2,
            vec![run(1.0, 0, "GO", 1, 1.0), run(1.0, 0, "no_go", 1, 1.0)],
            None,
        );
        let c = check(&bad, "forbidden verdict");
        assert!(!c.ok && c.detail.contains("NO_GO or error"), "{}", c.detail);
        assert!(!bad.passed);
        // no runs: it never passes
        let none = summarize_suite(&s, 1, vec![], Some("run 1: boom".into()));
        assert!(!check(&none, "forbidden verdict").ok);
    }

    #[test]
    fn expect_verdict_match_is_reported_and_exact() {
        let s = agent_spec("expect_verdict = \"NOT_EVALUATED\"");
        let ok = summarize_suite(&s, 1, vec![run(1.0, 0, "not_evaluated", 1, 1.0)], None);
        assert_eq!(ok.verdict_match, Some(true));
        let near = summarize_suite(&s, 1, vec![run(1.0, 0, "NOT_EVALUATED (x)", 1, 1.0)], None);
        assert_eq!(near.verdict_match, Some(false), "exact, not a prefix");
        assert!(!near.passed);
        let none = summarize_suite(&agent_spec("forbid_verdict = [\"X\"]"), 1, vec![], None);
        assert_eq!(
            none.verdict_match, None,
            "no expect_verdict: no match to report"
        );
    }

    #[test]
    fn expect_blocker_must_be_in_the_ledger_of_every_run() {
        let s = agent_spec("expect_blocker = \"auth_wall\"");
        let with = |b: &[&str]| {
            let mut r = run(1.0, 0, "NOT_EVALUATED", 1, 1.0);
            r.blockers = b.iter().map(|x| x.to_string()).collect();
            r
        };
        let ok = summarize_suite(
            &s,
            2,
            vec![with(&["auth_wall"]), with(&["no_surface", "auth_wall"])],
            None,
        );
        assert!(check(&ok, "expected blocker").ok, "{:?}", ok.checks);
        assert_eq!(ok.blockers, ["auth_wall", "no_surface"]);
        let bad = summarize_suite(
            &s,
            2,
            vec![with(&["auth_wall"]), with(&["no_surface"])],
            None,
        );
        let c = check(&bad, "expected blocker");
        assert!(
            !c.ok && c.detail.contains("missing in run 1"),
            "{}",
            c.detail
        );
        // no blockers at all
        let none = summarize_suite(&s, 1, vec![with(&[])], None);
        assert!(!check(&none, "expected blocker").ok);
    }

    #[test]
    fn agent_stats_reads_statuses_confidence_and_blocker_reasons_from_the_report() {
        use crate::agent::fixtures::{report, result};
        use crate::agent::{BlockReason, Blocker, EvidenceLedger};
        let mut rep = report("r");
        rep.executed_results = vec![
            result("TC-1", "authz", "PASS"),
            result("TC-2", "injection", "INCONCLUSIVE"),
            result("TC-3", "injection", "NOT_APPLICABLE"),
            result("TC-4", "state_transition", "BLOCKED"),
        ];
        let blocker = |reason| Blocker {
            reason,
            detail: String::new(),
            next_step: String::new(),
            case_ids: vec![],
        };
        rep.evidence_ledger = Some(EvidenceLedger {
            confidence: Some(40),
            blockers: vec![
                blocker(BlockReason::AuthWall),
                blocker(BlockReason::NoSurface),
                blocker(BlockReason::OutOfScope),
            ],
            ..Default::default()
        });
        let st = agent_stats(&rep);
        assert_eq!(
            st.cases,
            counts(&[
                ("PASS", 1),
                ("INCONCLUSIVE", 1),
                ("NOT_APPLICABLE", 1),
                ("BLOCKED", 1)
            ])
        );
        assert_eq!(st.confidence, Some(40));
        assert_eq!(st.blockers, ["auth_wall", "no_surface", "out_of_scope"]);
        // an old report without a ledger: statuses only
        rep.evidence_ledger = None;
        let st = agent_stats(&rep);
        assert_eq!((st.confidence, st.blockers.is_empty()), (None, true));
    }

    #[test]
    fn suites_without_seeded_defects_need_a_verdict_or_blocker_expectation() {
        let bad = |t: &str| parse_suite(t, "x").is_err();
        let head = "name = \"t\"\nkind = \"agent\"\n";
        let tail = "\n[target]\nserver = \"s.py\"\n";
        assert!(bad(&format!("{head}{tail}")), "nothing to check");
        assert!(!bad(&format!("{head}forbid_verdict = [\"NO_GO\"]{tail}")));
        assert!(!bad(&format!(
            "{head}expect_verdict = \"NOT_EVALUATED\"{tail}"
        )));
        assert!(!bad(&format!("{head}expect_blocker = \"auth_wall\"{tail}")));
        // expect_blocker must name a real reason and belongs to the agent kind
        assert!(bad(&format!("{head}expect_blocker = \"login\"{tail}")));
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\nexpect_blocker = \"auth_wall\"\n[target]\npath = \"p\"\n"
        ));
        // a verdict cannot be both expected and forbidden
        assert!(bad(&format!(
            "{head}expect_verdict = \"GO\"\nforbid_verdict = [\"go\"]{tail}"
        )));
        // max_inconclusive_rate: agent kind, 0..=1
        assert!(!bad(&format!(
            "{head}forbid_verdict = [\"X\"]{tail}[thresholds]\nmax_inconclusive_rate = 0.25\n"
        )));
        assert!(bad(&format!(
            "{head}forbid_verdict = [\"X\"]{tail}[thresholds]\nmax_inconclusive_rate = 1.5\n"
        )));
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\nforbid_verdict = [\"X\"]\n[target]\npath = \"p\"\n[thresholds]\nmax_inconclusive_rate = 0.2\n"
        ));
        // server_args need a server
        assert!(bad(
            "name = \"t\"\nkind = \"repo\"\nforbid_verdict = [\"X\"]\n[target]\npath = \"p\"\nserver_args = [\"--clean\"]\n"
        ));
    }

    #[test]
    fn markdown_shows_the_new_metrics_and_the_blockers() {
        let mut s = agent_spec("expect_blocker = \"auth_wall\"");
        s.thresholds.max_inconclusive_rate = Some(0.5);
        let mut r = run(1.0, 0, "NOT_EVALUATED", 5, 1.0);
        r.precision = 1.0;
        r.blockers = vec!["auth_wall".into()];
        let r = r.with_stats(RunStats::from_statuses(
            ["PASS", "INCONCLUSIVE", "BLOCKED"],
            Some(50),
            vec!["auth_wall".into()],
        ));
        let res = summarize_suite(&s, 1, vec![r], None);
        assert_eq!(res.confidence, Some(50));
        let md = render_markdown(&EvalSummary {
            version: "0".into(),
            started: "now".into(),
            k: 1,
            passed: res.passed,
            suites: vec![res],
            report_json: PathBuf::new(),
            report_md: PathBuf::new(),
        });
        assert!(
            md.contains("| precision | FP | inconclusive | confidence |"),
            "{md}"
        );
        assert!(md.contains("| 1.00 | 0 | 50% | 50% |"), "{md}");
        assert!(md.contains("- blockers reported: auth_wall"), "{md}");
        assert!(
            md.contains("- run 1 cases: BLOCKED 1, INCONCLUSIVE 1, PASS 1"),
            "{md}"
        );
        assert!(md.contains("PASS expected blocker"), "{md}");
        assert!(
            md.contains("PASS inconclusive rate: worst run 50% vs <= 50%"),
            "{md}"
        );
    }

    #[test]
    fn the_spa_suites_are_wired_to_the_fixture() {
        let load = |name: &str| {
            let text =
                std::fs::read_to_string(crate_root().join(format!("tests/eval/{name}.toml")))
                    .unwrap();
            parse_suite(&text, name).unwrap()
        };
        let spa = load("agent-spa");
        assert!(
            spa.target.spec.is_none(),
            "the agent has to find the API itself"
        );
        assert_eq!(spa.expect_verdict.as_deref(), Some("NO_GO"));
        assert_eq!(spa.thresholds.max_inconclusive_rate, Some(0.25));
        assert!(spa.thresholds.min_recall >= 0.85);
        assert_eq!(spa.expect.len(), 3, "one expectation per seeded bug");
        assert!(spa.target.server_args.is_empty());
        let clean = load("agent-spa-clean");
        assert_eq!(clean.target.server_args, ["--clean"]);
        assert_eq!(clean.forbid_verdict, ["NO_GO"]);
        assert!(clean.expect.is_empty() && clean.thresholds.max_false_positives <= 1);
        assert_eq!(clean.thresholds.max_inconclusive_rate, Some(0.25));
        assert_eq!(
            clean.target.tokens, spa.target.tokens,
            "same accounts, no bugs"
        );
        let noauth = load("agent-spa-noauth");
        assert!(
            noauth.target.tokens.is_empty(),
            "no credentials is the point"
        );
        assert_eq!(noauth.expect_verdict.as_deref(), Some("NOT_EVALUATED"));
        assert_eq!(noauth.expect_blocker.as_deref(), Some("auth_wall"));
        for s in [&spa, &clean, &noauth] {
            assert_eq!(
                s.target.server.as_deref(),
                Some("tests/fixtures/spa-next/server.py")
            );
        }
    }

    fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn shipped_suites_parse_and_point_at_real_files() {
        let opts = EvalOpts::default();
        let suites = load_suites(&crate_root(), &opts).unwrap();
        let names: Vec<&str> = suites.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "agent-api",
                "agent-diff",
                "agent-memory",
                "agent-spa-clean",
                "agent-spa-noauth",
                "agent-spa",
                "qa-api",
                "qa-repo",
                "security-deep",
                "whitebox-exploit"
            ]
        );
        for s in &suites {
            for p in [
                &s.target.server,
                &s.target.spec,
                &s.target.roles,
                &s.target.path,
            ]
            .into_iter()
            .flatten()
            .chain(s.target.repo.iter().flat_map(|r| &r.commits))
            {
                assert!(rel(&crate_root(), p).exists(), "{}: {p} is missing", s.name);
            }
            assert!(
                s.thresholds.min_recall >= 0.85,
                "{}: threshold must not be loosened silently",
                s.name
            );
        }
        let qa = suites.iter().find(|s| s.name == "qa-api").unwrap();
        assert_eq!(
            qa.expect
                .iter()
                .filter(|e| !e.optional && !e.known_gap)
                .count(),
            7,
            "one required expectation per seeded bug"
        );
        let agent = suites.iter().find(|s| s.name == "agent-api").unwrap();
        assert_eq!(
            agent.expect.len(),
            7,
            "the agent suite lists every seeded bug (known gaps flagged)"
        );
    }

    #[test]
    fn suite_selection_by_name() {
        let root = crate_root();
        let one = load_suites(
            &root,
            &EvalOpts {
                suites: vec!["qa-repo".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(one.len(), 1);
        let two = load_suites(
            &root,
            &EvalOpts {
                suites: vec!["qa-repo,qa-api".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(two.len(), 2);
        let err = load_suites(
            &root,
            &EvalOpts {
                suites: vec!["nope".into()],
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown suite 'nope'"));
    }

    #[test]
    fn env_guard_restores_previous_values() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let k = "READYHAI_EVAL_TEST_ONLY_VAR";
        let n = "READYHAI_EVAL_TEST_ONLY_UNSET";
        // SAFETY: names are private to this test and ENV_LOCK is held.
        unsafe { std::env::set_var(k, "before") };
        {
            let mut g = EnvGuard::new();
            g.set(k, "during");
            g.set(n, "during");
            assert_eq!(std::env::var(k).unwrap(), "during");
            g.unset(k);
            assert!(std::env::var(k).is_err());
        }
        assert_eq!(std::env::var(k).unwrap(), "before");
        assert!(std::env::var(n).is_err());
        unsafe { std::env::remove_var(k) };
        assert_eq!(role_env("ali ce"), "RH_ALI_CE_TOKEN");
    }

    #[test]
    fn fixture_starts_serves_and_counts_requests() {
        let script = crate_root().join("tests/fixtures/qa-api/server.py");
        let dir = std::env::temp_dir().join(format!("rh-eval-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fx = match Fixture::start(&script, &dir.join("req.log"), &[]) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skipping: no usable python3 ({e:#})");
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
        };
        assert_eq!(fx.requests(), 0, "the readiness probe is not counted");
        let c = reqwest::blocking::Client::new();
        for _ in 0..3 {
            let r = c.get(format!("{}/health", fx.url())).send().unwrap();
            assert!(r.status().is_success());
        }
        assert_eq!(fx.requests(), 3);
        let port = fx.port;
        drop(fx);
        assert!(
            TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                Duration::from_millis(300)
            )
            .is_err(),
            "the server is killed on drop"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_spa_fixture_has_a_login_wall_a_catch_all_and_three_switchable_bugs() {
        use reqwest::blocking::Client;
        let script = crate_root().join("tests/fixtures/spa-next/server.py");
        let dir = std::env::temp_dir().join(format!("rh-eval-spa-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for clean in [false, true] {
            let args: Vec<String> = clean.then(|| "--clean".to_string()).into_iter().collect();
            let fx = match Fixture::start(&script, &dir.join(format!("req-{clean}.log")), &args) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("skipping: no usable python3 ({e:#})");
                    break;
                }
            };
            let u = |p: &str| format!("{}{p}", fx.url());
            let alice = |p: &str| c.get(u(p)).bearer_auth("alice-token");
            // the login wall: 307 to /login, a password field there, and a session gets through
            let r = c.get(u("/")).send().unwrap();
            assert_eq!(r.status().as_u16(), 307);
            assert!(
                r.headers()["location"]
                    .to_str()
                    .unwrap()
                    .starts_with("/login")
            );
            let login = c.get(u("/login")).send().unwrap().text().unwrap();
            assert!(login.contains("type=\"password\"") && login.contains("/_next/static/"));
            assert_eq!(alice("/").send().unwrap().status().as_u16(), 200);
            // the catch-all: unknown paths are one and the same 200 shell
            let a = c.get(u("/rh0123456789ab")).send().unwrap();
            assert_eq!(a.status().as_u16(), 200);
            let (a, b) = (
                a.text().unwrap(),
                c.get(u("/pricing")).send().unwrap().text().unwrap(),
            );
            assert_eq!(a, b);
            assert!(a.contains("_buildManifest.js") && a.contains("page-abc123.js"));
            // what a spec-less agent can learn from
            let manifest = c
                .get(u("/_next/static/rhBuild01/_buildManifest.js"))
                .send()
                .unwrap()
                .text()
                .unwrap();
            assert!(manifest.contains("\"/orders/[id]\"") && manifest.contains("__rewrites"));
            let chunk = c
                .get(u("/_next/static/chunks/app/(main)/settings/page-abc123.js"))
                .send()
                .unwrap()
                .text()
                .unwrap();
            assert!(chunk.contains("\"/api/profile\"") && chunk.contains("api.example.invalid"));
            assert!(
                c.get(u("/sitemap.xml"))
                    .send()
                    .unwrap()
                    .text()
                    .unwrap()
                    .contains("/pricing")
            );
            assert_eq!(
                c.get(u("/_next/static/nope.js"))
                    .send()
                    .unwrap()
                    .status()
                    .as_u16(),
                404
            );
            // the API needs a Bearer token
            assert_eq!(
                c.get(u("/api/orders")).send().unwrap().status().as_u16(),
                401
            );
            assert_eq!(alice("/api/orders").send().unwrap().status().as_u16(), 200);
            // bug 1: bob's order 3 for alice
            let idor = alice("/api/orders/3").send().unwrap().status().as_u16();
            // bug 2: a quote in q leaks a SQL error and a stack trace
            let leak = alice("/api/orders?q=%27").send().unwrap();
            let (leak_status, leak_body) = (leak.status().as_u16(), leak.text().unwrap());
            // bug 3: bad paging
            let paging = alice("/api/orders?limit=-1")
                .send()
                .unwrap()
                .status()
                .as_u16();
            if clean {
                assert_eq!((idor, leak_status, paging), (404, 200, 400));
            } else {
                assert_eq!((idor, leak_status, paging), (200, 500, 500));
                assert!(leak_body.contains("SQLITE_ERROR") && leak_body.contains(".js:"));
            }
            // an order of your own is readable in both
            assert_eq!(
                alice("/api/orders/1").send().unwrap().status().as_u16(),
                200
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn change_spec(extra: &str) -> SuiteSpec {
        parse_suite(
            &format!(
                r#"
name = "d"
kind = "agent"
[target]
server = "s.py"
spec = "o.json"
[target.repo]
commits = ["a", "b"]
[change]
operations = ["GET /search"]
{extra}
[[expect]]
id = "a"
rule = "server_error"
"#
            ),
            "t",
        )
        .unwrap()
    }

    #[test]
    fn the_agent_diff_suite_file_is_a_valid_change_suite_over_real_fixture_directories() {
        let root = crate_root();
        let text = std::fs::read_to_string(root.join("tests/eval/agent-diff.toml")).unwrap();
        let s = parse_suite(&text, "agent-diff").unwrap();
        let c = s.change.as_ref().expect("a [change] table");
        assert_eq!(c.operations, ["GET /search"]);
        assert!(c.planned_first && (c.min_sent - 1.0).abs() < 1e-9);
        let commits = &s.target.repo.as_ref().unwrap().commits;
        assert_eq!(commits.len(), 2);
        assert!(commits.iter().all(|d| root.join(d).is_dir()), "{commits:?}");
    }

    #[test]
    fn memory_blocks_are_validated_and_the_shipped_suite_has_one() {
        let suite = |kind: &str, extra: &str, memory: &str| {
            let t = format!(
                "name = \"m\"\nkind = \"{kind}\"\n[target]\nserver = \"s.py\"\nroles = \"r\"\n{extra}\n{memory}\n[[expect]]\nid = \"a\"\nrule = \"x\"\n"
            );
            parse_suite(&t, "t")
                .map(|s| s.memory.map(|m| m.runs))
                .map_err(|e| format!("{e:#}"))
        };
        assert_eq!(
            suite("agent", "", "[memory]"),
            Ok(Some(2)),
            "two runs by default"
        );
        assert_eq!(suite("agent", "", "[memory]\nruns = 3"), Ok(Some(3)));
        assert_eq!(suite("agent", "", ""), Ok(None));
        assert!(
            suite("qa", "", "[memory]")
                .unwrap_err()
                .contains("kind agent")
        );
        for runs in ["runs = 1", "runs = 6"] {
            assert!(
                suite("agent", "", &format!("[memory]\n{runs}"))
                    .unwrap_err()
                    .contains("2..=5"),
                "{runs}"
            );
        }
        assert!(
            suite(
                "agent",
                "[target.repo]\ncommits = [\"a\", \"b\"]",
                "[memory]"
            )
            .unwrap_err()
            .contains("cannot be combined")
        );
        assert!(suite("agent", "", "[memory]\nbogus = 1").is_err());
        let text =
            std::fs::read_to_string(crate_root().join("tests/eval/agent-memory.toml")).unwrap();
        let s = parse_suite(&text, "agent-memory").unwrap();
        assert_eq!(s.memory.as_ref().map(|m| m.runs), Some(2));
        assert_eq!(s.expect.len(), 7, "the same seven seeded bugs as agent-api");
    }

    /// A two-run series: run 1 found one authz defect, run 2 found it again.
    fn memory_series(
        still_open: bool,
        probe_first: bool,
        drop_case: bool,
    ) -> (SuiteSpec, Vec<crate::agent::AgentRunReport>) {
        use crate::agent::fixtures::{planned, report, result};
        use crate::agent::memory::{DefectLine, SinceLastRun};
        use crate::agent::{OracleCheck, OracleOutcome, Severity, TriagedDefect, Verdict};
        let fp = crate::agent::memory::fingerprint("authz", "/admin");
        let defect = || TriagedDefect {
            id: "DEF-001".into(),
            severity: "critical".into(),
            component: "/admin".into(),
            rule: "authz".into(),
            fingerprint: fp.clone(),
            case_ids: vec!["TC-001".into()],
            ..Default::default()
        };
        let line = DefectLine {
            fingerprint: fp.clone(),
            rule: "authz".into(),
            endpoint: "/admin".into(),
            ..Default::default()
        };
        let mk = |id: &str, since: SinceLastRun, order: &[(&str, bool)]| {
            let mut r = report(id);
            r.triaged_defects = vec![defect()];
            let mut res = result("TC-001", "authz", "FAIL");
            res.oracle = Some(OracleOutcome {
                verdict: Verdict::Fail,
                checks: vec![OracleCheck {
                    code: "authz".into(),
                    verdict: Verdict::Fail,
                    severity: Some(Severity::Critical),
                    detail: "d".into(),
                }],
                warnings: vec![],
                exploratory: false,
            });
            r.executed_results = vec![res];
            r.planned_cases = order
                .iter()
                .map(|(comp, probe)| {
                    let mut c = planned(&format!("TC-{:03}", comp.len()), "authz", "GET", comp);
                    if *probe {
                        c.regression_of = vec![fp.clone()];
                    }
                    c
                })
                .collect();
            r.since_last_run = Some(since);
            r
        };
        let first = mk(
            "run-1",
            SinceLastRun {
                first_run: true,
                committed: true,
                new: vec![line.clone()],
                ..Default::default()
            },
            &[("/", false), ("/admin", false), ("/about", false)],
        );
        let mut order = if probe_first {
            vec![("/admin", true), ("/", false), ("/about", false)]
        } else {
            vec![("/", false), ("/admin", true), ("/about", false)]
        };
        if drop_case {
            order.pop();
        }
        let last = mk(
            "run-2",
            SinceLastRun {
                committed: true,
                still_open: if still_open {
                    vec![line.clone()]
                } else {
                    vec![]
                },
                new: if still_open { vec![] } else { vec![line] },
                ..Default::default()
            },
            &order,
        );
        let spec = parse_suite(
            "name = \"m\"\nkind = \"agent\"\n[target]\nserver = \"s.py\"\n[memory]\n[[expect]]\nid = \"a\"\nrule = \"authz\"\ncomponent = \"/admin\"\n",
            "t",
        )
        .unwrap();
        (spec, vec![first, last])
    }

    #[test]
    fn memory_checks_name_what_a_series_got_wrong() {
        let names = |cs: &[Check]| {
            cs.iter()
                .filter(|c| !c.ok)
                .map(|c| c.name.clone())
                .collect::<Vec<_>>()
        };
        let (spec, reps) = memory_series(true, true, false);
        let cs = memory_checks(&spec, &reps);
        assert_eq!(cs.len(), 4);
        assert!(names(&cs).is_empty(), "{cs:?}");
        // the defect is reported new again instead of still open
        let (spec, reps) = memory_series(false, true, false);
        assert_eq!(
            names(&memory_checks(&spec, &reps)),
            ["memory: seeded defects still open"]
        );
        // the probe is not first
        let (spec, reps) = memory_series(true, false, false);
        assert_eq!(
            names(&memory_checks(&spec, &reps)),
            ["memory: regression probes lead the plan"]
        );
        // memory dropped a case
        let (spec, reps) = memory_series(true, true, true);
        assert_eq!(
            names(&memory_checks(&spec, &reps)),
            ["memory: no case dropped"]
        );
        // a run with no memory section at all
        let (spec, mut reps) = memory_series(true, true, false);
        reps[0].since_last_run = None;
        reps[1].since_last_run = None;
        assert!(
            names(&memory_checks(&spec, &reps))
                .contains(&"memory: first run remembered".to_string())
        );
    }

    #[test]
    fn change_blocks_are_validated() {
        let suite = |kind: &str, repo: &str, change: &str| {
            let t = format!(
                "name = \"d\"\nkind = \"{kind}\"\n[target]\nserver = \"s.py\"\nroles = \"r\"\n{repo}\n{change}\n[[expect]]\nid = \"a\"\nrule = \"x\"\n"
            );
            parse_suite(&t, "t")
                .map(|_| ())
                .map_err(|e| format!("{e:#}"))
        };
        let two = "[target.repo]\ncommits = [\"a\", \"b\"]";
        let one = "[target.repo]\ncommits = [\"a\"]";
        let ch = "[change]\noperations = [\"GET /x\"]";
        assert!(suite("agent", two, ch).is_ok());
        assert!(suite("agent", one, ch).unwrap_err().contains("two commits"));
        assert!(suite("agent", "", ch).unwrap_err().contains("two commits"));
        assert!(suite("qa", two, ch).unwrap_err().contains("kind agent"));
        assert!(
            suite("agent", two, "[change]\noperations = []")
                .unwrap_err()
                .contains("at least one operation")
        );
        for bad in ["min_sent = 2.0", "bogus = 1"] {
            assert!(
                suite("agent", two, &format!("{ch}\n{bad}")).is_err(),
                "{bad}"
            );
        }
    }

    fn change_report(
        ops: &[&str],
        cases: &[(&str, &[&str])],
        sent: usize,
    ) -> crate::agent::AgentRunReport {
        use crate::agent::fixtures::{planned, report};
        let mut rep = report("run-x");
        rep.planned_cases = cases
            .iter()
            .enumerate()
            .map(|(i, (comp, tagged))| {
                let mut c = planned(&format!("TC-{:03}", i + 1), "boundary", "GET", comp);
                c.changed_ops = tagged.iter().map(|s| s.to_string()).collect();
                c
            })
            .collect();
        let mut ci = crate::agent::ChangeImpact {
            status: "applied".into(),
            changed_files_total: 2,
            ..Default::default()
        };
        ci.operations = ops
            .iter()
            .map(|o| crate::agent::ChangedOperation {
                operation: o.to_string(),
                via: "route".into(),
                files: vec![],
                detail: String::new(),
            })
            .collect();
        ci.coverage = ops
            .iter()
            .map(|o| crate::agent::ChangedOpCoverage {
                operation: o.to_string(),
                planned: rep
                    .planned_cases
                    .iter()
                    .filter(|c| c.changed_ops.iter().any(|x| x == o))
                    .count(),
                executed: sent,
                ..Default::default()
            })
            .collect();
        rep.change_impact = Some(ci);
        rep
    }

    #[test]
    fn change_checks_require_the_right_operations_planned_first_and_sent() {
        let c = change_spec("").change.unwrap();
        let ok = |v: &[Check]| v.iter().all(|c| c.ok);
        let good = change_report(
            &["GET /search"],
            &[
                ("/search", &["GET /search"]),
                ("/search", &["GET /search"]),
                ("/", &[]),
                ("/.env", &[]),
            ],
            2,
        );
        let v = change_checks(&c, &good);
        assert_eq!(v.len(), 3);
        assert!(ok(&v), "{v:?}");
        // another operation was reported
        let other = change_report(&["GET /orders"], &[("/orders", &["GET /orders"])], 1);
        assert!(!change_checks(&c, &other)[0].ok);
        // an unchanged case ahead of a changed one (the root probe is allowed to lead)
        let late = change_report(
            &["GET /search"],
            &[
                ("/", &[]),
                ("/search", &["GET /search"]),
                ("/admin", &[]),
                ("/search", &["GET /search"]),
            ],
            2,
        );
        let v = change_checks(&c, &late);
        assert!(v[0].ok && !v[1].ok, "{v:?}");
        // planned but not sent (dropped by a cut)
        let cut = change_report(
            &["GET /search"],
            &[("/search", &["GET /search"]), ("/search", &["GET /search"])],
            1,
        );
        let v = change_checks(&c, &cut);
        assert!(!v[2].ok, "{v:?}");
        // a run without change impact says so instead of passing
        let mut none = good.clone();
        none.change_impact = None;
        assert!(!ok(&change_checks(&c, &none)));
        // the suite holds only when every run held
        let mut s = change_spec("");
        s.thresholds.max_false_positives = 0;
        let mut r1 = run(1.0, 0, "NO_GO", 1, 1.0);
        let mut r2 = run(1.0, 0, "NO_GO", 1, 1.0);
        r1.checks = change_checks(&c, &good);
        r2.checks = change_checks(&c, &cut);
        let res = summarize_suite(&s, 2, vec![r1.clone(), r2], None);
        assert!(!res.passed);
        assert!(check(&res, "changed operations").ok);
        assert!(!check(&res, "changed operations covered").ok);
        let res = summarize_suite(&s, 2, vec![r1.clone(), r1], None);
        assert!(
            check(&res, "changed operations planned first").ok && res.passed,
            "{:?}",
            res.checks
        );
    }

    #[test]
    fn the_fixture_repo_has_the_base_commit_tagged_and_the_change_on_top() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipping: no git");
            return;
        }
        let root = crate_root();
        let dest = std::env::temp_dir().join(format!("rh-eval-repo-{}", std::process::id()));
        let commits = vec![
            "tests/fixtures/qa-api-src/base".to_string(),
            "tests/fixtures/qa-api-src/change".to_string(),
        ];
        build_fixture_repo(&root, &commits, &dest).unwrap();
        let (files, _) = {
            let mut cmd = Command::new("git");
            cmd.current_dir(&dest)
                .args(["diff", "--name-only", "base...HEAD"]);
            let out =
                crate::tools::run_capped(&mut cmd, Duration::from_secs(20), 4096, None).unwrap();
            (out.stdout_lossy(), out.success())
        };
        assert_eq!(
            files.lines().collect::<Vec<_>>(),
            ["app/search.py", "docs/CHANGELOG.md"]
        );
        assert!(dest.join("app/orders.py").is_file());
        // rebuilding starts from nothing
        build_fixture_repo(&root, &commits, &dest).unwrap();
        assert!(build_fixture_repo(&root, &["nope".to_string()], &dest).is_err());
        let _ = std::fs::remove_dir_all(&dest);
    }

    /// Dev entry point: runs the real fixtures end to end in its own process.
    /// `EVAL_SUITES=qa-repo EVAL_K=1 cargo test -j 2 eval::tests::live -- --ignored --nocapture`
    #[test]
    #[ignore = "runs the fixtures end to end (needs python3; minutes)"]
    fn live_eval() {
        let suites = std::env::var("EVAL_SUITES").unwrap_or_else(|_| "all".into());
        let k = std::env::var("EVAL_K")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        let out = std::env::var("EVAL_OUT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("readyhai-eval-live"));
        let s = run_eval(EvalOpts {
            suites: vec![suites],
            k,
            root: Some(crate_root()),
            out,
            ..Default::default()
        })
        .unwrap();
        eprintln!("exit code would be {}", s.exit_code());
    }
}
