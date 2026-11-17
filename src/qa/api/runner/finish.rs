//! Check completion, evidence status calculation, and latency aggregation.
use std::collections::HashMap;

use super::types::Runner;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::api::defect_types::NewDefect;
use crate::qa::api::helpers::latency_note;
use crate::qa::api::latency;
use crate::qa::model::{Priority, ResultStatus};

impl<'a> Runner<'a> {
    /// The check status the executed evidence supports, or None to derive it from the findings.
    /// Counted over the cases THIS runner planned: no case executed = Errored (`strict`; Partial
    /// otherwise), more than half blocked or skipped = Partial, nothing planned = Skipped. A run
    /// whose only unexecuted cases are the read-only skips of a non-nonprod host is Skipped, not
    /// Errored: that gap is policy, not a failure.
    pub fn evidence_status(&self, strict: bool) -> Option<CheckStatus> {
        let mine: Vec<String> = self
            .my_cases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|m| m.0.clone())
            .collect();
        let mine_set: std::collections::HashSet<&str> = mine.iter().map(String::as_str).collect();
        if mine.is_empty() {
            return Some(CheckStatus::Skipped(format!(
                "no case was planned for {}",
                self.check
            )));
        }
        let results: HashMap<String, (ResultStatus, String)> = self.qa.with(|c| {
            c.results
                .iter()
                .filter(|r| mine_set.contains(r.case_id.as_str()))
                .map(|r| (r.case_id.clone(), (r.status, r.actual.clone())))
                .collect()
        });
        let (mut executed, mut blocked, mut skipped, mut read_only) =
            (0usize, 0usize, 0usize, 0usize);
        let mut why: HashMap<String, usize> = HashMap::new();
        for id in &mine {
            match results.get(id) {
                Some((ResultStatus::Pass | ResultStatus::Fail | ResultStatus::Flaky, _)) => {
                    executed += 1
                }
                Some((st, actual)) => {
                    if *st == ResultStatus::Blocked {
                        blocked += 1;
                    } else {
                        skipped += 1;
                        if actual.starts_with("read-only") {
                            read_only += 1;
                        }
                    }
                    *why.entry(actual.chars().take(90).collect()).or_default() += 1;
                }
                None => skipped += 1,
            }
        }
        let planned = mine.len();
        let top = why
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
            .map(|(w, n)| format!("; most common: {w} (x{n})"))
            .unwrap_or_default();
        if executed == 0 {
            if blocked == 0 && read_only == skipped {
                return Some(CheckStatus::Skipped(
                    "every case writes and the host is not nonprod (read-only)".into(),
                ));
            }
            let m = format!(
                "no case executed: {blocked} blocked, {skipped} skipped of {planned} planned{top}"
            );
            return Some(if strict {
                CheckStatus::Errored(m)
            } else {
                CheckStatus::Partial(m)
            });
        }
        if (blocked + skipped) * 2 > planned {
            return Some(CheckStatus::Partial(format!(
                "{} of {planned} cases blocked or skipped ({blocked} blocked, {skipped} skipped): the run covers only part of the API{top}",
                blocked + skipped
            )));
        }
        None
    }

    /// Findings + the evidence-based status (see `evidence_status`).
    pub fn finish(&mut self, strict: bool) -> CheckOutput {
        let f = std::mem::take(&mut self.findings);
        let mut out = CheckOutput::findings(f);
        out.status = self.evidence_status(strict);
        out
    }

    pub fn finish_latency(&mut self) {
        let mut keys: Vec<_> = self.lat.keys().cloned().collect();
        keys.sort();
        for k in keys {
            let p95 = latency::p95(&self.lat[&k]);
            let n = self.lat[&k].len();
            self.qa.with(|c| c.notes.push(latency_note(&k, p95, n)));
            if latency::is_slow(p95)
                && n >= 2
                && let (Some(op), Some((ex, url))) = (
                    self.spec
                        .ops
                        .iter()
                        .find(|o| {
                            k.strip_prefix(o.method.as_str())
                                .and_then(|r| r.strip_prefix(' '))
                                == Some(o.path.as_str())
                        })
                        .cloned(),
                    self.slowest.get(&k).cloned(),
                )
            {
                self.defect(NewDefect {
                    rule: "qa.api.slow_response",
                    cat: Category::Performance,
                    sev: Severity::Low,
                    prio: Priority::P3,
                    title: format!("{k} is slow (p95 {p95} ms)"),
                    expected: format!("p95 under {} ms", latency::SLOW_P95_MS),
                    actual: format!("p95={p95}ms over {n} requests"),
                    fp: format!("{k}|slow"),
                    remediation: "Profile the endpoint; add caching, pagination or async processing.",
                    area_cases: &format!("api.{}.{}.perf", op.method, op.path),
                    component: k.clone(),
                    role: None,
                    method: &op.method,
                    url: &url,
                    body: None,
                    ex: Some(&ex),
                });
            }
        }
    }
}
