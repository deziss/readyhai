//! Senior-QA data model. QA checks record cases/results/defects into the
//! per-run `QaCollector`; every Defect is ALSO returned as a Finding so the
//! gate, baseline, SARIF and JUnit keep working unchanged.
use crate::model::{Category, Finding, FindingStatus, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Area {
    Api,
    Ui,
    Perf,
    Resilience,
    Suite,
    Release,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Technique {
    Positive,
    Boundary,
    Equivalence,
    Negative,
    AuthMatrix,
    StateTransition,
    Contract,
    Exploratory,
    Regression,
    PerfBaseline,
    Resilience,
    Static,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    P1,
    P2,
    P3,
    P4,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseSource {
    Deterministic,
    Llm,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Stable id, e.g. "api.GET./orders/{id}.authz.user".
    pub id: String,
    pub area: Area,
    pub technique: Technique,
    pub title: String,
    pub priority: Priority,
    /// Component under test: "GET /orders/{id}", a page URL, a journey name, a file.
    pub component: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default)]
    pub expected: String,
    pub source: CaseSource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Pass,
    Fail,
    /// Could not run (dependency failed, precondition missing).
    Blocked,
    Skipped,
    /// Failed, then passed on rerun.
    Flaky,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    HttpExchange,
    Har,
    Screenshot,
    Trace,
    Video,
    LogCluster,
    Junit,
    K6Summary,
    Other,
}

/// Pointer to a redacted artifact under runs/<id>/artifacts/ (relative path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub path: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub case_id: String,
    pub status: ResultStatus,
    #[serde(default)]
    pub actual: String,
    #[serde(default)]
    pub duration_ms: u128,
    #[serde(default = "one")]
    pub attempts: u32,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Set when the result produced a defect.
    #[serde(default)]
    pub defect_id: Option<String>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defect {
    /// Short stable id within the run, e.g. "D-007".
    pub id: String,
    /// Finding rule, e.g. "qa.api.bola".
    pub rule: String,
    pub category: Category,
    pub severity: Severity,
    pub priority: Priority,
    pub area: Area,
    pub title: String,
    pub component: String,
    #[serde(default)]
    pub environment: String,
    /// Human steps; the last one is usually a copy-pasteable curl / Playwright snippet.
    /// Credentials appear only as $RH_<ROLE>_TOKEN placeholders.
    #[serde(default)]
    pub steps_to_reproduce: Vec<String>,
    #[serde(default)]
    pub expected: String,
    #[serde(default)]
    pub actual: String,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Reproduced N times out of M attempts.
    #[serde(default)]
    pub reproduced: (u32, u32),
    /// Case ids that exposed it.
    #[serde(default)]
    pub cases: Vec<String>,
    #[serde(default)]
    pub remediation: String,
    /// Identity key for the fingerprint (no volatile data: no ids, no timings).
    pub fp_key: String,
    /// Filled when the report is built.
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub status: FindingStatus,
    /// True when the defect is new versus the baseline.
    #[serde(default)]
    pub regression: bool,
    /// Optional AI-written prose, rendered in a clearly marked block. Never used for decisions.
    #[serde(default)]
    pub ai_note: Option<String>,
}

impl Defect {
    /// The Finding twin of this defect (same rule + fp_key → same fingerprint).
    pub fn to_finding(&self, check: &str) -> Finding {
        let mut detail = String::new();
        if !self.expected.is_empty() {
            detail.push_str(&format!("Expected: {}\n", self.expected));
        }
        if !self.actual.is_empty() {
            detail.push_str(&format!("Actual: {}\n", self.actual));
        }
        if !self.steps_to_reproduce.is_empty() {
            detail.push_str("Repro:\n");
            for (i, s) in self.steps_to_reproduce.iter().enumerate() {
                detail.push_str(&format!("{}. {s}\n", i + 1));
            }
        }
        Finding::new(
            check,
            &self.rule,
            self.category,
            self.severity,
            self.title.clone(),
            self.component.clone(),
        )
        .detail(detail.trim_end().to_string())
        .remediation(self.remediation.clone())
        .fp_key(self.fp_key.clone())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Cell {
    Pass,
    Fail,
    Untested,
    NotApplicable,
}

/// rows × columns; cells keyed by (row, column).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageMatrix {
    pub rows: Vec<String>,
    pub columns: Vec<String>,
    /// (row index, column index, cell)
    pub cells: Vec<(usize, usize, Cell)>,
    /// Lookup tables over the three vectors above (not serialized, rebuilt when they drift).
    #[serde(skip)]
    index: CoverageIndex,
}

/// Hash lookups for `CoverageMatrix::set`, so building a matrix of N operations is linear in N
/// instead of a scan of every row and cell per update.
#[derive(Debug, Clone, Default)]
struct CoverageIndex {
    rows: HashMap<String, usize>,
    columns: HashMap<String, usize>,
    cells: HashMap<(usize, usize), usize>,
    /// Lengths of the vectors the maps describe; a mismatch (a deserialized matrix, a direct
    /// push) triggers a rebuild.
    seen: (usize, usize, usize),
}

impl CoverageMatrix {
    pub fn set(&mut self, row: &str, col: &str, cell: Cell) {
        self.sync();
        let r = Self::idx(&mut self.index.rows, &mut self.rows, row);
        let c = Self::idx(&mut self.index.columns, &mut self.columns, col);
        match self.index.cells.get(&(r, c)) {
            Some(&i) => {
                let x = &mut self.cells[i];
                // Fail wins over Pass; anything wins over Untested.
                if !(x.2 == Cell::Fail && cell == Cell::Pass) {
                    x.2 = cell;
                }
            }
            None => {
                self.index.cells.insert((r, c), self.cells.len());
                self.cells.push((r, c, cell));
            }
        }
        self.index.seen = (self.rows.len(), self.columns.len(), self.cells.len());
    }

    fn idx(map: &mut HashMap<String, usize>, v: &mut Vec<String>, s: &str) -> usize {
        if let Some(&i) = map.get(s) {
            return i;
        }
        v.push(s.to_string());
        map.insert(s.to_string(), v.len() - 1);
        v.len() - 1
    }

    fn sync(&mut self) {
        if self.index.seen == (self.rows.len(), self.columns.len(), self.cells.len()) {
            return;
        }
        let mut ix = CoverageIndex::default();
        for (i, r) in self.rows.iter().enumerate() {
            ix.rows.entry(r.clone()).or_insert(i);
        }
        for (i, c) in self.columns.iter().enumerate() {
            ix.columns.entry(c.clone()).or_insert(i);
        }
        for (i, x) in self.cells.iter().enumerate() {
            ix.cells.entry((x.0, x.1)).or_insert(i);
        }
        ix.seen = (self.rows.len(), self.columns.len(), self.cells.len());
        self.index = ix;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanItem {
    pub component: String,
    pub area: Area,
    /// 1..=25 (impact 1..5 × likelihood 1..5)
    pub risk: u8,
    pub reasons: Vec<String>,
    /// Cases budgeted for this item.
    pub budget: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub title: String,
    /// low | medium | high
    pub level: String,
    pub mitigation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitCriterion {
    pub name: String,
    pub met: bool,
    /// Unmet blocking criteria force No-Go.
    pub blocking: bool,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Recommendation {
    Go,
    ConditionalGo,
    NoGo,
    /// Not enough was executed to recommend anything (fewer than half of the planned cases ran,
    /// or a requested core area never ran). Neither a pass nor a proven failure: never "Go".
    Inconclusive,
}

impl Recommendation {
    /// Process exit code of `readyhai qa` for this recommendation: 0 Go, 1 Conditional Go,
    /// 2 No-Go and Inconclusive (no evidence is not a pass).
    pub fn exit_code(self) -> i32 {
        match self {
            Recommendation::Go => 0,
            Recommendation::ConditionalGo => 1,
            Recommendation::NoGo | Recommendation::Inconclusive => 2,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResultCounts {
    pub planned: usize,
    pub executed: usize,
    pub passed: usize,
    pub failed: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub flaky: usize,
}

/// What QA checks append to during a run (Ctx.qa.collector).
#[derive(Debug, Default)]
pub struct QaCollector {
    pub plan: Vec<PlanItem>,
    pub cases: Vec<TestCase>,
    pub results: Vec<TestResult>,
    pub defects: Vec<Defect>,
    pub coverage: CoverageMatrix,
    pub risks: Vec<Risk>,
    pub notes: Vec<String>,
    /// Out-of-scope items / unsupported spec parts (listed, never silently passed).
    pub untested: Vec<String>,
    /// Filled by triage: final defect id -> (rule, fp_key) of EVERY raw defect folded into it
    /// (the surviving one included), so the status of a merged defect is judged over all of its
    /// members' fingerprints, not the first one's.
    pub merged: std::collections::BTreeMap<String, Vec<(String, String)>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QaReport {
    pub recommendation: Recommendation,
    pub conditions: Vec<String>,
    pub executive_summary: String,
    #[serde(default)]
    pub ai_summary: Option<String>,
    /// "offline" | "lan-llm" | "deterministic"
    pub mode: String,
    pub environment: String,
    pub scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub roles: Vec<String>,
    pub plan: Vec<PlanItem>,
    pub counts: ResultCounts,
    pub cases: Vec<TestCase>,
    pub results: Vec<TestResult>,
    pub defects: Vec<Defect>,
    pub coverage: CoverageMatrix,
    pub risks: Vec<Risk>,
    pub exit_criteria: Vec<ExitCriterion>,
    pub notes: Vec<String>,
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn set_keeps_one_cell_per_row_and_column_and_the_old_precedence() {
        let mut m = CoverageMatrix::default();
        m.set("GET /a", "anon", Cell::Untested);
        m.set("GET /a", "anon", Cell::Pass);
        m.set("GET /a", "role", Cell::Fail);
        m.set("GET /b", "anon", Cell::Pass);
        assert_eq!(m.rows, ["GET /a", "GET /b"]);
        assert_eq!(m.columns, ["anon", "role"]);
        assert_eq!(
            m.cells,
            [(0, 0, Cell::Pass), (0, 1, Cell::Fail), (1, 0, Cell::Pass)]
        );
        // Fail wins over a later Pass; anything else overwrites
        m.set("GET /a", "role", Cell::Pass);
        assert_eq!(m.cells[1].2, Cell::Fail);
        m.set("GET /a", "anon", Cell::Untested);
        assert_eq!(m.cells[0].2, Cell::Untested);
        assert_eq!(m.cells.len(), 3);
    }

    #[test]
    fn a_deserialized_or_hand_edited_matrix_is_indexed_again() {
        let mut m = CoverageMatrix::default();
        m.set("r1", "c1", Cell::Pass);
        let mut back: CoverageMatrix =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        // the index is not serialized: setting a known cell must update it, not append a copy
        back.set("r1", "c1", Cell::Fail);
        back.set("r2", "c1", Cell::Pass);
        assert_eq!(back.rows, ["r1", "r2"]);
        assert_eq!(back.cells, [(0, 0, Cell::Fail), (1, 0, Cell::Pass)]);
        // rows pushed behind its back are picked up too
        back.rows.push("r3".into());
        back.set("r3", "c1", Cell::Untested);
        assert_eq!(back.rows.len(), 3);
        assert_eq!(back.cells.last(), Some(&(2, 0, Cell::Untested)));
        let json = serde_json::to_value(&back).unwrap();
        assert!(
            json.get("index").is_none(),
            "the index must not be serialized"
        );
    }

    #[test]
    fn building_a_large_matrix_is_linear() {
        let mut m = CoverageMatrix::default();
        let t = std::time::Instant::now();
        for i in 0..5000 {
            for c in ["anon", "invalid", "functional", "stateful", "alice", "bob"] {
                m.set(&format!("GET /r{i}/{{id}}"), c, Cell::Untested);
            }
        }
        assert_eq!(m.cells.len(), 30_000);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            t.elapsed()
        );
    }
}
