//! Test case registration, results recording, skips, and rerun tracking.
use std::collections::HashMap;

use super::types::Runner;
use crate::model::{Category, Severity};
use crate::qa::api::defect_types::{DefectRef, NewDefect, Reruns};
use crate::qa::api::spec::Op;
use crate::qa::model::{Area, CaseSource, Priority, ResultStatus, Technique, TestCase, TestResult};

/// A failed API case is re-run up to this many times to tell a flaky failure from a real one.
pub const MAX_RERUN: u32 = 2;

impl<'a> Runner<'a> {
    pub fn add_case(
        &self,
        id: &str,
        op: &Op,
        tech: Technique,
        prio: Priority,
        title: &str,
        role: Option<&str>,
        steps: Vec<String>,
        expected: &str,
    ) {
        let c = TestCase {
            id: id.to_string(),
            area: Area::Api,
            technique: tech,
            title: title.to_string(),
            priority: prio,
            component: op.key(),
            role: role.map(String::from),
            steps,
            expected: expected.to_string(),
            source: CaseSource::Deterministic,
        };
        self.my_cases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((id.to_string(), op.key()));
        self.qa.with(|c0| c0.cases.push(c));
    }

    /// Safety net: a failed case of this runner without a defect (a lifecycle step that returned
    /// 4xx, an assertion nobody attached a finding to) gets a `qa.api.case_failed` defect, so no
    /// failure is ever invisible to the gate, the report and the recommendation.
    pub fn explain_failures(&mut self) {
        let mine: HashMap<String, String> = self
            .my_cases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(id, comp)| (id.clone(), comp.clone()))
            .collect();
        let orphans: Vec<(String, String, String, Vec<String>)> = self.qa.with(|c| {
            let cand: Vec<(&TestResult, &String)> = c
                .results
                .iter()
                .filter(|r| r.status == ResultStatus::Fail && r.defect_id.is_none())
                .filter_map(|r| Some((r, mine.get(&r.case_id)?)))
                .collect();
            if cand.is_empty() {
                return vec![];
            }
            // one pass over the cases instead of one search per orphan
            let wanted: std::collections::HashSet<&str> =
                cand.iter().map(|(r, _)| r.case_id.as_str()).collect();
            let mut steps: HashMap<&str, &Vec<String>> = HashMap::with_capacity(wanted.len());
            for x in &c.cases {
                if wanted.contains(x.id.as_str()) {
                    steps.entry(x.id.as_str()).or_insert(&x.steps);
                }
            }
            cand.into_iter()
                .map(|(r, comp)| {
                    let st = steps.get(r.case_id.as_str()).map(|s| (*s).clone());
                    (
                        r.case_id.clone(),
                        comp.clone(),
                        r.actual.clone(),
                        st.unwrap_or_default(),
                    )
                })
                .collect()
        });
        if orphans.is_empty() {
            return;
        }
        let mut defect_of_case: HashMap<String, String> = HashMap::new();
        let mut steps_of_defect: HashMap<String, Vec<String>> = HashMap::new();
        for (cid, comp, actual, steps) in orphans {
            let base = self.base.clone();
            let d = self.defect(NewDefect {
                rule: "qa.api.case_failed",
                cat: Category::Quality,
                sev: Severity::Medium,
                prio: Priority::P3,
                title: format!("{comp}: case {cid} failed"),
                expected: "the case passes".into(),
                actual: actual.clone(),
                fp: cid.clone(),
                remediation: "Re-run the case (steps to reproduce) and compare the response with the documented behaviour.",
                area_cases: &cid,
                component: comp,
                role: None,
                method: "GET",
                url: &base,
                body: None,
                ex: None,
            });
            if !steps.is_empty() {
                steps_of_defect.insert(d.id.clone(), steps);
            }
            defect_of_case.insert(cid, d.id);
        }
        // one pass over the results and the defects, however many orphans there were
        self.qa.with(|c| {
            for r in c.results.iter_mut() {
                if let Some(id) = defect_of_case.get(&r.case_id) {
                    r.defect_id = Some(id.clone());
                }
            }
            for x in c.defects.iter_mut() {
                if let Some(st) = steps_of_defect.get(&x.id) {
                    x.steps_to_reproduce = st.clone();
                }
            }
        });
    }

    pub fn result(
        &self,
        case_id: &str,
        status: ResultStatus,
        actual: &str,
        ms: u128,
        defects: &[DefectRef],
    ) {
        self.result_n(case_id, status, actual, ms, defects, 1);
    }

    pub fn result_n(
        &self,
        case_id: &str,
        status: ResultStatus,
        actual: &str,
        ms: u128,
        defects: &[DefectRef],
        attempts: u32,
    ) {
        let r = TestResult {
            case_id: case_id.to_string(),
            status,
            actual: actual.to_string(),
            duration_ms: ms,
            attempts,
            evidence: defects.iter().filter_map(|d| d.ev.clone()).collect(),
            defect_id: defects.first().map(|d| d.id.clone()),
        };
        self.qa.with(|c| c.results.push(r));
    }

    pub fn skip(&self, case_id: &str, why: &str) {
        self.result(case_id, ResultStatus::Skipped, why, 0, &[]);
    }

    /// Re-run a failed probe up to `MAX_RERUN` times (budget permitting, keeping `reserve`
    /// requests for later checks). `again` returns Some(true) when the failure reproduced,
    /// Some(false) when it passed, None when it could not run. The first attempt counts as a failure.
    pub fn rerun(
        &mut self,
        reserve: usize,
        mut again: impl FnMut(&mut Self) -> Option<bool>,
    ) -> Reruns {
        let mut rr = Reruns {
            attempts: 1,
            fails: 1,
        };
        for _ in 0..MAX_RERUN {
            if self.qa.remaining() <= reserve {
                break;
            }
            match again(self) {
                Some(failed) => {
                    rr.attempts += 1;
                    if failed {
                        rr.fails += 1;
                    }
                }
                None => break,
            }
        }
        rr
    }

    /// Record "reproduced N of M attempts" on the defects behind a re-run case.
    pub fn note_reproduced(&self, defs: &[DefectRef], rr: &Reruns) {
        if rr.attempts <= 1 {
            return;
        }
        self.qa.with(|c| {
            for d in c
                .defects
                .iter_mut()
                .filter(|d| defs.iter().any(|x| x.id == d.id))
            {
                // the creating attempt already counted as (1,1)
                d.reproduced.0 += rr.fails - 1;
                d.reproduced.1 += rr.attempts - 1;
            }
        });
    }
}
