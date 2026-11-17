mod journeys;
mod pages;

pub use journeys::{process_forms, process_journeys, process_state_graph};
pub use pages::process_pages;

use crate::model::{Category, Severity};
use crate::qa::model::*;
use super::model::UiReport;

#[derive(Default)]
pub struct Built {
    pub cases: Vec<TestCase>,
    pub results: Vec<TestResult>,
    pub defects: Vec<Defect>,
    pub coverage: CoverageMatrix,
    pub notes: Vec<String>,
}

pub struct B<'a> {
    pub out: Built,
    pub env: &'a str,
    pub n: usize,
}

impl B<'_> {
    pub fn defect(
        &mut self,
        rule: &str,
        cat: Category,
        sev: Severity,
        title: String,
        component: String,
        fp: String,
    ) -> usize {
        self.n += 1;
        let pri = match sev {
            Severity::Critical => Priority::P1,
            Severity::High => Priority::P1,
            Severity::Medium => Priority::P2,
            Severity::Low => Priority::P3,
            Severity::Info => Priority::P4,
        };
        self.out.defects.push(Defect {
            id: format!("UI-{:03}", self.n),
            rule: rule.into(),
            category: cat,
            severity: sev,
            priority: pri,
            area: Area::Ui,
            title,
            component,
            environment: self.env.into(),
            steps_to_reproduce: vec![],
            expected: String::new(),
            actual: String::new(),
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![],
            remediation: String::new(),
            fp_key: fp,
            fingerprint: String::new(),
            status: Default::default(),
            regression: false,
            ai_note: None,
        });
        self.out.defects.len() - 1
    }

    pub fn case(
        &mut self,
        id: String,
        tech: Technique,
        pri: Priority,
        title: String,
        comp: String,
        role: Option<String>,
        steps: Vec<String>,
        expected: &str,
    ) {
        self.out.cases.push(TestCase {
            id,
            area: Area::Ui,
            technique: tech,
            title,
            priority: pri,
            component: comp,
            role,
            steps,
            expected: expected.into(),
            source: CaseSource::Deterministic,
        });
    }

    pub fn result(
        &mut self,
        case_id: &str,
        fail: Option<&Defect>,
        actual: String,
        evidence: Vec<Evidence>,
    ) {
        self.out.results.push(TestResult {
            case_id: case_id.into(),
            status: if fail.is_some() {
                ResultStatus::Fail
            } else {
                ResultStatus::Pass
            },
            actual,
            duration_ms: 0,
            attempts: 1,
            evidence,
            defect_id: fail.map(|d| d.id.clone()),
        });
    }
}

pub fn ev(kind: EvidenceKind, path: &str, note: &str) -> Evidence {
    Evidence {
        kind,
        path: format!("ui/{path}"),
        note: note.into(),
    }
}

/// Pure transformation of the runner report. `unmap` rewrites container URLs back to the real target.
pub fn build(rep: &UiReport, env: &str, unmap: &dyn Fn(&str) -> String) -> Built {
    let mut b = B {
        out: Built::default(),
        env,
        n: 0,
    };
    b.out.notes.extend(rep.notes.iter().cloned());
    let mut m = CoverageMatrix::default();

    process_pages(&mut b, rep, &mut m, unmap);
    process_forms(&mut b, rep, &mut m, unmap);
    process_journeys(&mut b, rep, &mut m);
    process_state_graph(&mut b, rep);

    b.out.coverage = m;
    b.out
}
