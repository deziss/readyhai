//! Offline trend dashboard: one JSON line per run in <data>/index.jsonl, rendered to static HTML.
use crate::model::*;
use anyhow::Result;
use minijinja::{AutoEscape, Environment};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Counts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndexLine {
    pub id: String,
    pub target: String,
    pub target_key: String,
    pub kind: String,
    pub date: String,
    pub verdict: String,
    #[serde(default)]
    pub recommendation: Option<String>,
    pub counts: Counts,
    pub new: usize,
    #[serde(default)]
    pub pass_rate: Option<f64>,
    #[serde(default)]
    pub defects: Option<usize>,
    #[serde(default)]
    pub p95: Option<f64>,
}

fn parse_p95(notes: &[String]) -> Option<f64> {
    for n in notes {
        if let Some(i) = n.find("perf p95=") {
            let t: String = n[i + 9..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            if let Ok(v) = t.parse() {
                return Some(v);
            }
        }
    }
    None
}

pub fn index_line(run: &Run) -> IndexLine {
    let mut c = Counts::default();
    let mut new = 0;
    for f in run.findings.iter().filter(|f| f.status != FindingStatus::Suppressed) {
        match f.severity {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Info => c.info += 1,
        }
        if f.status == FindingStatus::New {
            new += 1;
        }
    }
    let q = run.qa.as_ref();
    let mut notes = run.notes.clone();
    if let Some(q) = q {
        notes.extend(q.notes.iter().cloned());
    }
    IndexLine {
        id: run.id.clone(),
        target: run.target.raw.clone(),
        target_key: crate::engine::target_key(&run.target),
        kind: format!("{:?}", run.target.kind).to_lowercase(),
        date: run.started.clone(),
        verdict: format!("{:?}", run.verdict).to_uppercase(),
        recommendation: q.map(|q| match q.recommendation {
            crate::qa::model::Recommendation::Go => "GO",
            crate::qa::model::Recommendation::ConditionalGo => "CONDITIONAL GO",
            crate::qa::model::Recommendation::NoGo => "NO-GO",
        }.to_string()),
        counts: c,
        new,
        pass_rate: q.filter(|q| q.counts.executed > 0).map(|q| q.counts.passed as f64 / q.counts.executed as f64),
        defects: q.map(|q| q.defects.len()),
        p95: parse_p95(&notes),
    }
}

/// Best-effort: never fails a scan.
pub fn append_index(run: &Run) {
    let p = crate::engine::data_dir().join("index.jsonl");
    let _ = append_to(&p, &index_line(run));
}

fn append_to(p: &Path, l: &IndexLine) -> Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p)?;
    writeln!(f, "{}", serde_json::to_string(l)?)?;
    Ok(())
}

fn read_index(p: &Path) -> Vec<IndexLine> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn total(l: &IndexLine) -> usize {
    let c = &l.counts;
    c.critical + c.high + c.medium + c.low + c.info
}

/// Inline SVG polyline points (120x28) for values; None when < 2 points.
fn spark(vals: &[f64], max: f64) -> Option<String> {
    if vals.len() < 2 {
        return None;
    }
    let max = if max <= 0.0 { 1.0 } else { max };
    let step = 116.0 / (vals.len() - 1) as f64;
    Some(vals.iter().enumerate().map(|(i, v)| format!("{:.1},{:.1}", 2.0 + i as f64 * step, 26.0 - (v / max).clamp(0.0, 1.0) * 24.0)).collect::<Vec<_>>().join(" "))
}

fn row(l: &IndexLine, data: &Path) -> Value {
    let rep = data.join("runs").join(&l.id).join("report");
    let link = if rep.is_dir() && l.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        Some(format!("{}/", rep.display()))
    } else {
        None
    };
    json!({
        "id": l.id, "target": l.target, "date": l.date, "kind": l.kind, "verdict": l.verdict,
        "rec": l.recommendation, "total": total(l), "crit": l.counts.critical, "high": l.counts.high, "new": l.new,
        "pass_rate": l.pass_rate.map(|p| format!("{:.0}%", p * 100.0)),
        "defects": l.defects, "p95": l.p95.map(|p| format!("{p:.0} ms")), "link": link,
    })
}

pub fn render(lines: &[IndexLine], data: &Path) -> Result<String> {
    let mut env = Environment::new();
    env.set_auto_escape_callback(|_| AutoEscape::Html);
    env.add_template("dashboard.html.j2", include_str!("../templates/dashboard.html.j2"))?;
    let mut by: BTreeMap<&str, Vec<&IndexLine>> = BTreeMap::new();
    for l in lines {
        by.entry(&l.target_key).or_default().push(l);
    }
    let mut targets = vec![];
    for (_, mut v) in by {
        v.sort_by(|a, b| a.date.cmp(&b.date));
        let last30: Vec<&&IndexLine> = v.iter().rev().take(30).rev().collect();
        let fv: Vec<f64> = last30.iter().map(|l| total(l) as f64).collect();
        let fmax = fv.iter().cloned().fold(0.0, f64::max);
        let pv: Vec<f64> = last30.iter().filter_map(|l| l.pass_rate).collect();
        let latest = v[v.len() - 1];
        targets.push(json!({
            "target": latest.target, "kind": latest.kind, "latest": row(latest, data), "runs_n": v.len(),
            "spark_findings": spark(&fv, fmax), "spark_pass": spark(&pv, 1.0),
            "runs": v.iter().rev().take(30).map(|l| row(l, data)).collect::<Vec<_>>(),
        }));
    }
    let mut all: Vec<&IndexLine> = lines.iter().collect();
    all.sort_by(|a, b| b.date.cmp(&a.date));
    let overall: Vec<Value> = all.iter().take(200).map(|l| row(l, data)).collect();
    Ok(env.get_template("dashboard.html.j2")?.render(json!({
        "targets": targets, "overall": overall, "count": lines.len(), "version": crate::engine::VERSION,
    }))?)
}

pub fn generate(out: &Path) -> Result<PathBuf> {
    let data = crate::engine::data_dir();
    let lines = read_index(&data.join("index.jsonl"));
    std::fs::create_dir_all(out)?;
    let p = out.join("index.html");
    std::fs::write(&p, render(&lines, &data)?)?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: &str, d: &str, f: usize) -> IndexLine {
        IndexLine {
            id: id.into(), target: "http://<b>x</b>".into(), target_key: "k1".into(), kind: "web".into(), date: d.into(),
            verdict: "FAIL".into(), recommendation: Some("NO-GO".into()),
            counts: Counts { high: f, ..Default::default() }, new: f, pass_rate: Some(0.75), defects: Some(2), p95: Some(120.0),
        }
    }

    #[test]
    fn index_roundtrip_and_p95() {
        let l = line("r1", "2026-10-25", 3);
        let s = serde_json::to_string(&l).unwrap();
        assert!(!s.contains('\n'));
        assert_eq!(serde_json::from_str::<IndexLine>(&s).unwrap(), l);
        assert_eq!(parse_p95(&["x".into(), "perf p95=123ms rps=4".into()]), Some(123.0));
        assert_eq!(parse_p95(&[]), None);
        let p = std::env::temp_dir().join(format!("rh-idx-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        append_to(&p, &l).unwrap();
        append_to(&p, &line("r2", "2026-10-26", 1)).unwrap();
        assert_eq!(read_index(&p).len(), 2);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn index_from_run() {
        let r = crate::qa::report::tests::sample_run(crate::qa::model::Recommendation::NoGo);
        let l = index_line(&r);
        assert_eq!(l.recommendation.as_deref(), Some("NO-GO"));
        assert_eq!(l.pass_rate, Some(0.75));
        assert_eq!(l.defects, Some(1));
        assert_eq!(l.p95, Some(120.0));
    }

    #[test]
    fn dashboard_renders_escaped() {
        let h = render(&[line("r1", "2026-10-25", 3), line("r2", "2026-10-26", 1)], Path::new("/nonexistent")).unwrap();
        assert!(h.contains("&lt;b&gt;x&lt;") && !h.contains("<b>x"));
        assert!(!h.contains("<b>x</b>"));
        assert!(h.contains("<polyline"));
        assert!(h.contains("NO-GO") && !h.contains("<script"));
    }
}
