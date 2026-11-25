use anyhow::{Result, anyhow};
use minijinja::value::Serde;
use minijinja::{AutoEscape, Environment};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

use super::helpers::{b64, defects_sorted, lc, looks_like_code, prio_str, rec_text, status_label};
use crate::model::{FindingStatus, Run};
use crate::qa::model::{Cell, CoverageMatrix, Evidence, EvidenceKind, ResultCounts};

struct EvOut {
    link: Option<String>,
    data_uri: Option<String>,
}

fn safe_rel(p: &str) -> Option<PathBuf> {
    let pb = Path::new(p);
    if p.is_empty()
        || pb.is_absolute()
        || pb
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return None;
    }
    Some(pb.to_path_buf())
}

fn stage_evidence(run_dir: &Path, out: Option<&Path>, ev: &Evidence, n: usize) -> EvOut {
    let (Some(out), Some(rel)) = (out, safe_rel(&ev.path)) else {
        return EvOut {
            link: None,
            data_uri: None,
        };
    };
    let src = [run_dir.join("artifacts").join(&rel), run_dir.join(&rel)]
        .into_iter()
        .find(|p| p.is_file());
    let Some(src) = src else {
        return EvOut {
            link: None,
            data_uri: None,
        };
    };
    let base: String = src
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let name = format!("{n:03}-{base}");
    let dir = out.join("evidence");
    if std::fs::create_dir_all(&dir).is_err() || std::fs::copy(&src, dir.join(&name)).is_err() {
        return EvOut {
            link: None,
            data_uri: None,
        };
    }
    let ext = src
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mime = match ext.as_str() {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        _ => None,
    };
    let data_uri = match (ev.kind, mime) {
        (EvidenceKind::Screenshot, Some(m)) => std::fs::read(&src)
            .ok()
            .filter(|b| b.len() <= 300 * 1024)
            .map(|b| format!("data:{m};base64,{}", b64(&b))),
        _ => None,
    };
    EvOut {
        link: Some(format!("evidence/{name}")),
        data_uri,
    }
}

fn bar(counts: &ResultCounts) -> Vec<Value> {
    let total = (counts.passed + counts.failed + counts.blocked + counts.skipped + counts.flaky)
        .max(1) as f64;
    let mut x = 0.0;
    let mut v = vec![];
    for (label, n, cls) in [
        ("passed", counts.passed, "pass"),
        ("failed", counts.failed, "fail"),
        ("flaky", counts.flaky, "flaky"),
        ("blocked", counts.blocked, "blocked"),
        ("skipped", counts.skipped, "skip"),
    ] {
        let w = n as f64 / total * 600.0;
        v.push(json!({"label": label, "n": n, "cls": cls, "x": format!("{x:.1}"), "w": format!("{w:.1}")}));
        x += w;
    }
    v
}

fn coverage_ctx(m: &CoverageMatrix) -> Value {
    const MAX: usize = 60;
    let mut grid = vec![vec!["untested"; m.columns.len()]; m.rows.len()];
    for (r, c, cell) in &m.cells {
        if *r < grid.len() && *c < m.columns.len() {
            grid[*r][*c] = match cell {
                Cell::Pass => "pass",
                Cell::Fail => "fail",
                Cell::Untested => "untested",
                Cell::NotApplicable => "na",
            };
        }
    }
    let rows: Vec<Value> = m
        .rows
        .iter()
        .enumerate()
        .take(MAX)
        .map(|(i, r)| json!({"name": r, "cells": grid[i]}))
        .collect();
    json!({"columns": m.columns, "rows": rows, "truncated": m.rows.len().saturating_sub(MAX), "total": m.rows.len()})
}

pub fn qa_html(run: &Run, out: Option<&Path>) -> Result<String> {
    let q = run.qa.as_ref().ok_or_else(|| anyhow!("not a QA run"))?;
    let mut env = Environment::new();
    env.set_auto_escape_callback(|_| AutoEscape::Html);
    env.add_template(
        "qa-report.html.j2",
        include_str!("../../../templates/qa-report.html.j2"),
    )?;
    let run_dir = crate::engine::run_dir(&run.id);
    let mut n = 0usize;
    let defects: Vec<Value> = defects_sorted(q)
        .iter()
        .map(|d| {
            let ev: Vec<Value> = d
                .evidence
                .iter()
                .map(|e| {
                    n += 1;
                    let o = stage_evidence(&run_dir, out, e, n);
                    json!({"kind": lc(&e.kind), "path": e.path, "note": e.note, "link": o.link, "data": o.data_uri})
                })
                .collect();
            let (last, steps) = match d.steps_to_reproduce.split_last() {
                Some((l, s)) if looks_like_code(l) => (Some(l.clone()), s.to_vec()),
                _ => (None, d.steps_to_reproduce.clone()),
            };
            json!({
                "id": d.id, "rule": d.rule, "title": d.title, "priority": prio_str(d.priority),
                "severity": d.severity.as_str(), "component": d.component, "area": lc(&d.area),
                "status": status_label(d.status), "regression": d.regression,
                "steps": steps, "code": last, "expected": d.expected, "actual": d.actual,
                "evidence": ev, "remediation": d.remediation, "ai_note": d.ai_note,
                "reproduced": format!("{}/{}", d.reproduced.0, d.reproduced.1),
                "environment": d.environment,
            })
        })
        .collect();
    let mut techniques: Vec<String> = q.cases.iter().map(|c| lc(&c.technique)).collect();
    techniques.sort();
    techniques.dedup();
    let mut areas: Vec<String> = q.cases.iter().map(|c| lc(&c.area)).collect();
    areas.sort();
    areas.dedup();
    let non_qa: Vec<Value> = run
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::Suppressed && !f.rule.starts_with("qa."))
        .take(10)
        .map(|f| json!({"severity": f.severity.as_str(), "title": f.title, "location": f.location, "rule": f.rule}))
        .collect();
    let (rec, rec_class) = rec_text(q.recommendation);
    let ctx = json!({
        "target": run.target.raw, "run_id": run.id, "date": run.started.get(..10).unwrap_or(&run.started),
        "version": run.version, "profile": lc(&run.profile), "mode": q.mode, "environment": q.environment,
        "rec": rec, "rec_class": rec_class, "conditions": q.conditions,
        "summary": q.executive_summary, "ai_summary": q.ai_summary,
        "scope": q.scope, "out_of_scope": q.out_of_scope, "roles": q.roles, "areas": areas, "techniques": techniques,
        "counts": q.counts, "bar": bar(&q.counts),
        "coverage": coverage_ctx(&q.coverage), "defects": defects,
        "risks": q.risks, "exit": q.exit_criteria,
        "categories": run.categories, "top_findings": non_qa,
        "errors": run.errors.iter().take(10).map(|e| json!({"count": e.count, "source": e.source, "signature": e.signature, "example": e.example})).collect::<Vec<_>>(),
        "checks": run.checks.iter().map(|c| json!({"id": c.id, "title": c.title, "status": c.status.label(), "reason": c.status.reason().unwrap_or(""), "findings": c.findings})).collect::<Vec<_>>(),
        "notes": q.notes, "verdict": format!("{:?}", run.verdict).to_uppercase(),
    });
    Ok(env.get_template("qa-report.html.j2")?.render(Serde(&ctx))?)
}
