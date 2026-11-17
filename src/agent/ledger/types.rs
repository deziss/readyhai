use super::super::types::{CaseExecutionResult, CoverageCell, TriagedDefect};

pub struct LedgerInput<'a> {
    pub results: &'a [CaseExecutionResult],
    pub defects: &'a [TriagedDefect],
    pub dry_run: bool,
    /// Set when a budget limit cut the run short.
    pub budget_stop: Option<&'a str>,
}

pub fn bucket(r: &CaseExecutionResult) -> &'static str {
    match r.status.as_str() {
        "PASS" => "pass",
        "WARN" => "warn",
        "FAIL" => "fail",
        "INCONCLUSIVE" => "inconclusive",
        "BLOCKED" => "blocked",
        "NOT_APPLICABLE" => "not_applicable",
        _ => "skipped",
    }
}

pub fn add(cell: &mut CoverageCell, r: &CaseExecutionResult) {
    cell.planned += 1;
    match bucket(r) {
        "pass" => cell.pass += 1,
        "warn" => cell.warn += 1,
        "fail" => cell.fail += 1,
        "inconclusive" => cell.inconclusive += 1,
        "blocked" => cell.blocked += 1,
        "not_applicable" => cell.not_applicable += 1,
        _ => cell.skipped += 1,
    }
    if r.flaky {
        cell.flaky += 1;
    }
    cell.case_ids.push(r.case_id.clone());
    if let Some(f) = &r.evidence_file {
        cell.evidence_files.push(f.clone());
    }
}

/// Cases that gave an answer the oracle could judge: pass + warn + fail.
pub fn conclusive(c: &CoverageCell) -> usize {
    c.pass + c.warn + c.fail
}

/// Cases that could have gained evidence: planned, minus not applicable, minus not executed.
pub fn applicable(c: &CoverageCell) -> usize {
    c.planned.saturating_sub(c.not_applicable + c.skipped)
}

/// Conclusive share of the applicable cases, in whole percent (rounded down: 49.6% is not 50%).
/// None when nothing was applicable.
pub fn confidence_pct(conclusive: usize, applicable: usize) -> Option<u32> {
    (applicable > 0).then(|| (conclusive * 100 / applicable) as u32)
}

pub fn status_of(c: &CoverageCell) -> &'static str {
    if conclusive(c) == 0 {
        "not_evaluated"
    } else if c.fail > 0 {
        "fail"
    } else if c.warn + c.inconclusive + c.blocked + c.skipped > 0 {
        "partial"
    } else {
        "pass"
    }
}

pub fn describe(c: &CoverageCell) -> String {
    let na = if c.not_applicable > 0 {
        format!(", {} not applicable", c.not_applicable)
    } else {
        String::new()
    };
    format!(
        "{}: {} passed, {} failed, {} warning(s), {} inconclusive, {} blocked, {} not executed{na} of {} planned",
        c.technique, c.pass, c.fail, c.warn, c.inconclusive, c.blocked, c.skipped, c.planned
    )
}

pub fn points(c: &CoverageCell) -> f64 {
    c.pass as f64 + 0.5 * c.warn as f64
}

/// The cells of several techniques as one. `technique` labels it (`describe` starts with it).
pub fn merge(technique: &str, cells: &[&CoverageCell]) -> CoverageCell {
    let mut m = CoverageCell {
        technique: technique.to_string(),
        ..Default::default()
    };
    for c in cells {
        m.planned += c.planned;
        m.pass += c.pass;
        m.warn += c.warn;
        m.fail += c.fail;
        m.inconclusive += c.inconclusive;
        m.blocked += c.blocked;
        m.skipped += c.skipped;
        m.flaky += c.flaky;
        m.not_applicable += c.not_applicable;
        m.case_ids.extend(c.case_ids.iter().cloned());
        m.evidence_files.extend(c.evidence_files.iter().cloned());
    }
    m
}

pub fn rank(v: &str) -> Option<u8> {
    match v {
        "GO" => Some(0),
        "CONDITIONAL_GO" => Some(1),
        "NO_GO" => Some(2),
        _ => None,
    }
}
