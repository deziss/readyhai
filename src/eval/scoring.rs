//! Scoring engine: matches observations against expectations and calculates precision, recall, and suite statistics.

use super::types::{Allow, Check, Expect, Observed, RunScore, SuiteResult, SuiteSpec, round3};
use std::collections::BTreeMap;

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

pub(crate) fn expect_matches(e: &Expect, o: &Observed) -> bool {
    matches(&e.rule, e.component.as_deref(), e.title.as_deref(), o)
}

fn allow_matches(a: &Allow, o: &Observed) -> bool {
    matches(&a.rule, a.component.as_deref(), a.title.as_deref(), o)
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
