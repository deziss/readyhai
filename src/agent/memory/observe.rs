//! Observation reduction: turns run facts into memory observations deterministically.

use std::collections::{BTreeMap, BTreeSet};

use super::sanitize::{
    clean_endpoint, clean_ident, clean_method, clean_severity, fingerprint, valid_fingerprint,
};
use super::types::{
    BaselinesInEffect, MAX_ENDPOINT, MAX_IDENT, MAX_LISTED, MAX_REPRO, ProbeLine, RunAggregate,
};
use crate::agent::oracle::Technique;
use crate::agent::triage::{SAME_ERROR_PREFIX, endpoint_template, path_of};
use crate::agent::types::{CaseExecutionResult, CleanupReport, PlannedCase, TriagedDefect};

// ---------------------------------------------------------------- case classes

/// `technique|METHOD|endpoint|role`: the unit the memory reasons about. A defect's reproduction is
/// a class, a flaky history is per class, the planner tags every case of a class.
pub fn class_key(technique: &str, method: &str, component: &str, role: &str) -> String {
    format!(
        "{}|{}|{}|{}",
        Technique::parse(technique).as_str(),
        clean_method(method),
        clean_endpoint(component),
        clean_ident(&role.to_ascii_lowercase(), 32)
    )
}

pub fn class_of(c: &PlannedCase) -> String {
    class_key(
        &c.technique,
        &c.method,
        &c.component,
        c.role.as_deref().unwrap_or(""),
    )
}

/// `METHOD endpoint` of a class key.
pub fn op_of_class(class: &str) -> String {
    let mut p = class.split('|');
    let (_t, m, e) = (
        p.next(),
        p.next().unwrap_or("OTHER"),
        p.next().unwrap_or(""),
    );
    format!("{m} {e}")
}

pub fn op_of_case(c: &PlannedCase) -> String {
    op_of_class(&class_of(c))
}

/// The case class a result belongs to: that of its planned case (a mutation or burst sub-case
/// belongs to its parent), the teardown's own class for a `CLEANUP-n` result.
pub(crate) fn result_class(r: &CaseExecutionResult, by_id: &BTreeMap<&str, &PlannedCase>) -> String {
    if r.case_id.starts_with("CLEANUP-") {
        return format!("cleanup|DELETE|{}|", clean_endpoint(&r.component));
    }
    let base = r
        .case_id
        .strip_suffix("-M1")
        .or_else(|| r.case_id.strip_suffix("-B"))
        .unwrap_or(&r.case_id);
    match by_id.get(r.case_id.as_str()).or_else(|| by_id.get(base)) {
        Some(c) => class_of(c),
        None => class_key(&r.technique, &r.method, &r.component, ""),
    }
}

pub(crate) fn is_cleanup(class: &str) -> bool {
    class.starts_with("cleanup|")
}

// ---------------------------------------------------------------- what a run observed

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassObs {
    pub pass: u32,
    pub fail: u32,
    pub warn: u32,
    pub inconclusive: u32,
    pub blocked: u32,
    pub flaky: u32,
}

impl ClassObs {
    /// Every executed case of the class passed (and at least one ran): a defect that failed here
    /// is fixed.
    pub fn clean(&self) -> bool {
        self.pass > 0 && self.fail + self.warn + self.inconclusive + self.blocked + self.flaky == 0
    }

    pub(crate) fn outcome(&self) -> Option<char> {
        if self.flaky > 0 {
            Some('k')
        } else if self.fail > 0 {
            Some('f')
        } else if self.pass + self.warn > 0 {
            Some('p')
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OpObs {
    pub planned: u32,
    pub executed: u32,
    pub pass: u32,
    pub fail: u32,
    pub inconclusive: u32,
    pub techniques: BTreeSet<String>,
}

impl OpObs {
    pub(crate) fn last_result(&self) -> &'static str {
        if self.executed == 0 {
            "not_run"
        } else if self.fail > 0 {
            "fail"
        } else if self.pass == self.executed {
            "pass"
        } else {
            "inconclusive"
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObservedDefect {
    /// This run's id of it (`DEF-001`).
    pub id: String,
    pub fingerprint: String,
    pub rule: String,
    pub endpoint: String,
    pub methods: Vec<String>,
    pub technique: String,
    pub severity: String,
    pub repro: Vec<String>,
}

/// Everything the memory takes from one finished run. Built from deterministic results only.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    pub run_id: String,
    pub dry_run: bool,
    pub planned: usize,
    pub totals: RunAggregate,
    pub defects: Vec<ObservedDefect>,
    pub classes: BTreeMap<String, ClassObs>,
    pub ops: BTreeMap<String, OpObs>,
    pub baselines: Option<BaselinesInEffect>,
    pub probes: Vec<ProbeLine>,
}

pub struct RunFacts<'a> {
    pub run_id: &'a str,
    pub dry_run: bool,
    /// Every planned case (kept, dropped and follow-ups).
    pub cases: &'a [PlannedCase],
    pub results: &'a [CaseExecutionResult],
    pub defects: &'a [TriagedDefect],
    pub cleanup: Option<&'a CleanupReport>,
    pub baselines: Option<BaselinesInEffect>,
}

/// Reduce a finished run to what the memory keeps. Only statuses, check codes, fingerprints and
/// sanitized endpoint templates are read: no title, evidence, reproduction command, response text
/// or LLM note ever enters the observation.
pub fn observe(f: &RunFacts) -> Observation {
    let by_id: BTreeMap<&str, &PlannedCase> = f.cases.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut obs = Observation {
        run_id: clean_ident(f.run_id, MAX_IDENT),
        dry_run: f.dry_run,
        planned: f.cases.len(),
        baselines: f.baselines.clone(),
        ..Default::default()
    };
    for c in f.cases {
        let op = obs.ops.entry(op_of_case(c)).or_default();
        op.planned += 1;
        if !c.regression_of.is_empty() {
            obs.probes.push(ProbeLine {
                case_id: clean_ident(&c.id, 24),
                class: class_of(c),
                defects: c.regression_of.clone(),
            });
        }
    }
    obs.probes.truncate(MAX_LISTED);
    let t = &mut obs.totals;
    for r in f.results {
        match r.status.as_str() {
            "PASS" => t.pass += 1,
            "FAIL" => t.fail += 1,
            "INCONCLUSIVE" => t.inconclusive += 1,
            "BLOCKED" => t.blocked += 1,
            "SKIPPED" => {
                t.skipped += 1;
                continue;
            }
            "NOT_APPLICABLE" => continue, // nothing was sent, nothing was skipped
            _ => {}
        }
        t.executed += 1;
        if r.flaky {
            t.flaky += 1;
        }
        let class = result_class(r, &by_id);
        let c = obs.classes.entry(class.clone()).or_default();
        match r.status.as_str() {
            "PASS" => c.pass += 1,
            "FAIL" => c.fail += 1,
            "WARN" => c.warn += 1,
            "INCONCLUSIVE" => c.inconclusive += 1,
            "BLOCKED" => c.blocked += 1,
            _ => {}
        }
        if r.flaky {
            c.flaky += 1;
        }
        if !is_cleanup(&class) {
            let op = obs.ops.entry(op_of_class(&class)).or_default();
            op.executed += 1;
            match r.status.as_str() {
                "PASS" | "WARN" => op.pass += 1,
                "FAIL" => op.fail += 1,
                _ => op.inconclusive += 1,
            }
            op.techniques
                .insert(class.split('|').next().unwrap_or("other").to_string());
        }
    }
    // a resource the teardown removed and the read-back confirmed gone is a pass of that class
    if let Some(cl) = f.cleanup {
        let bad: BTreeSet<&str> = cl
            .leftovers
            .iter()
            .filter(|l| l.reason.starts_with("delete_not_effective"))
            .map(|l| l.path.as_str())
            .collect();
        for r in &cl.resources {
            let path = r.teardown_path();
            if !bad.contains(path.as_str()) && cl.confirmed_gone > 0 {
                obs.classes
                    .entry(format!("cleanup|DELETE|{}|", clean_endpoint(&path)))
                    .or_default()
                    .pass += 1;
            }
        }
    }
    let results_by_id: BTreeMap<&str, &CaseExecutionResult> =
        f.results.iter().map(|r| (r.case_id.as_str(), r)).collect();
    for d in f.defects {
        let fingerprint = if valid_fingerprint(&d.fingerprint) {
            d.fingerprint.clone()
        } else {
            // a defect from a report written before fingerprints existed
            fingerprint(&d.rule, &endpoint_template(path_of(&d.component)))
        };
        let merged = d.title.starts_with(SAME_ERROR_PREFIX);
        let members: Vec<&CaseExecutionResult> = d
            .case_ids
            .iter()
            .filter_map(|id| results_by_id.get(id.as_str()).copied())
            .collect();
        let mut repro: Vec<String> = members.iter().map(|m| result_class(m, &by_id)).collect();
        repro.sort();
        repro.dedup();
        repro.truncate(MAX_REPRO);
        let mut methods: Vec<String> = members.iter().map(|m| clean_method(&m.method)).collect();
        methods.sort();
        methods.dedup();
        obs.defects.push(ObservedDefect {
            id: clean_ident(&d.id, 24),
            fingerprint,
            rule: clean_ident(&d.rule, MAX_IDENT),
            endpoint: if merged {
                clean_ident(&d.component, MAX_ENDPOINT)
            } else {
                clean_endpoint(&d.component)
            },
            methods,
            technique: members
                .first()
                .map(|m| Technique::parse(&m.technique).as_str().to_string())
                .unwrap_or_default(),
            severity: clean_severity(&d.severity),
            repro,
        });
    }
    obs
}
