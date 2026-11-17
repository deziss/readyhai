//! Plain-text rendering of memory for CLI output and inspection.

use super::sanitize::sev_rank;
use super::types::{BaselineState, DefectStatus, KnownDefect, Memory};

/// The memory as the CLI shows it.
pub fn render_text(m: &Memory, today: &str) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "Agent memory for {} (key {}, schema {})\n  created {} · updated {} · {} run(s) remembered\n",
        m.target, m.target_key, m.schema, m.created, m.updated, m.runs.len()
    ));
    if let Some(r) = m.runs.last() {
        o.push_str(&format!(
            "  last run {} at {}: {} cases executed, {} defect(s), verdict {}\n",
            r.run_id,
            r.at,
            r.executed,
            r.defects,
            if r.verdict.is_empty() {
                "-"
            } else {
                &r.verdict
            }
        ));
    }
    let count = |s: DefectStatus| m.defects.values().filter(|d| d.status == s).count();
    o.push_str(&format!(
        "\nKnown defects: {} open, {} regressed, {} fixed\n",
        count(DefectStatus::Open),
        count(DefectStatus::Regressed),
        count(DefectStatus::Fixed)
    ));
    let mut ds: Vec<(&String, &KnownDefect)> = m.defects.iter().collect();
    ds.sort_by(|a, b| {
        (sev_rank(&a.1.severity), &a.1.endpoint, a.0).cmp(&(
            sev_rank(&b.1.severity),
            &b.1.endpoint,
            b.0,
        ))
    });
    for (fp, d) in ds {
        o.push_str(&format!(
            "  [{:<9}] {:<8} {} {}  {}  first {} · last {} · seen {}x\n",
            d.status.as_str(),
            d.severity,
            d.rule,
            d.endpoint,
            fp,
            d.first_seen,
            d.last_seen,
            d.runs_seen
        ));
        if let Some(a) = &d.accepted {
            o.push_str(&format!(
                "      accepted by {} until {}{}: {}\n",
                a.by,
                a.expires,
                if a.is_effective(today) {
                    ""
                } else {
                    " (EXPIRED, blocking again)"
                },
                a.reason
            ));
        }
    }
    let flaky: Vec<_> = m.flaky.iter().filter(|(_, f)| f.flaky > 0).collect();
    o.push_str(&format!("\nKnown flaky case classes: {}\n", flaky.len()));
    for (k, f) in flaky {
        o.push_str(&format!(
            "  {k}  pass {} · fail {} · flaky {} (last {} run(s))\n",
            f.pass,
            f.fail,
            f.flaky,
            f.recent.len()
        ));
    }
    let failing = m
        .operations
        .iter()
        .filter(|(_, v)| v.last_result == "fail")
        .count();
    o.push_str(&format!(
        "\nOperations: {} remembered, {} failed last time they ran\n",
        m.operations.len(),
        failing
    ));
    let b = |s: &BaselineState| match (&s.exists, &s.accepted) {
        (true, Some(d)) => format!("yes (accepted {d})"),
        (true, None) => "yes".to_string(),
        _ => "no".to_string(),
    };
    o.push_str(&format!(
        "Baselines: perf {} · spec {} · visual {}\n",
        b(&m.baselines.perf),
        b(&m.baselines.spec),
        b(&m.baselines.visual)
    ));
    o
}
