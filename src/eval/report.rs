//! Markdown report generator and summary formatting for evaluation results.

use super::types::EvalSummary;

fn mark(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

/// `12%`, or `-` when there is no number (not an agent suite, or nothing was executed).
pub(crate) fn pct(x: Option<f64>) -> String {
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
