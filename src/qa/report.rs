//! QA test-summary report: HTML (+PDF via the playwright runner), Markdown and
//! bug-tracker / test-management exports. Everything is derived from `run.qa`.
use crate::model::*;
use crate::qa::model::*;
use anyhow::{anyhow, Result};
use minijinja::{AutoEscape, Environment};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const QA_FORMATS: &[&str] = &["qa", "pdf", "md", "jira", "gitlab", "testrail", "xray"];

// ------------------------------------------------------------------ helpers

fn lc<T: std::fmt::Debug>(v: &T) -> String {
    format!("{v:?}").to_lowercase()
}

fn rec_text(r: Recommendation) -> (&'static str, &'static str) {
    match r {
        Recommendation::Go => ("GO", "go"),
        Recommendation::ConditionalGo => ("CONDITIONAL GO", "cgo"),
        Recommendation::NoGo => ("NO-GO", "nogo"),
    }
}

fn prio_str(p: Priority) -> &'static str {
    match p {
        Priority::P1 => "P1",
        Priority::P2 => "P2",
        Priority::P3 => "P3",
        Priority::P4 => "P4",
    }
}

pub fn jira_priority(p: Priority) -> &'static str {
    match p {
        Priority::P1 => "Highest",
        Priority::P2 => "High",
        Priority::P3 => "Medium",
        Priority::P4 => "Low",
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::with_capacity(data.len() * 4 / 3 + 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}

/// Spreadsheet formula injection: a cell that starts with = + - @ (or TAB / CR) is evaluated by
/// Excel / LibreOffice / Sheets. Defect text comes from specs and pages we do not control, so
/// such a cell is prefixed with an apostrophe (the OWASP-recommended neutralisation).
pub fn csv_neutralize(s: &str) -> std::borrow::Cow<'_, str> {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        std::borrow::Cow::Owned(format!("'{s}"))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// RFC 4180 field quoting (after formula neutralisation).
pub fn csv_field(s: &str) -> String {
    let s = csv_neutralize(s);
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.into_owned()
    }
}

// ------------------------------------------------------- markup escaping

/// Escape text for INLINE Markdown (GitHub/GitLab flavour): one line, no emphasis / links /
/// images / raw HTML / tables / headings / list markers, and no @mention pings. Defect text comes
/// from spec and page sources, so nothing in it may become markup.
pub fn md_inline(s: &str) -> String {
    let one: String = s.chars().map(|c| if matches!(c, '\n' | '\r' | '\t') { ' ' } else { c }).collect();
    let chars: Vec<char> = one.trim().chars().collect();
    let mut o = String::with_capacity(chars.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        let alnum = |j: Option<usize>| j.and_then(|j| chars.get(j)).map(|x| x.is_alphanumeric()).unwrap_or(false);
        match c {
            '\\' | '`' | '*' | '[' | ']' | '<' | '>' | '|' | '~' => {
                o.push('\\');
                o.push(c);
            }
            // intraword underscores (snake_case, $RH_USER_TOKEN) are plain text in CommonMark
            '_' if !(alnum(i.checked_sub(1)) && alnum(Some(i + 1))) => {
                o.push('\\');
                o.push(c);
            }
            '#' | '-' | '+' if i == 0 => {
                o.push('\\');
                o.push(c);
            }
            '@' => o.push_str("@\u{200B}"),
            _ => o.push(c),
        }
    }
    // "1. text" at the start would become an ordered list
    if let Some(d) = o.find(|c: char| !c.is_ascii_digit()) {
        if d > 0 && o[d..].starts_with(['.', ')']) {
            o.insert(d, '\\');
        }
    }
    o
}

/// Multi-line text as Markdown paragraphs: each line escaped, hard line breaks kept.
pub fn md_lines(s: &str) -> String {
    s.lines().map(md_inline).collect::<Vec<_>>().join("  \n")
}

/// A fenced code block whose fence is longer than any backtick run in `body`, so the content can
/// never close it early (a spec value containing ``` stays inside the block).
pub fn md_fence(body: &str, lang: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in body.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let f = "`".repeat((longest + 1).max(3));
    format!("{f}{lang}\n{}\n{f}\n", body.trim_end_matches('\n'))
}

/// Escape text for Jira wiki markup (inline).
pub fn jira_text(s: &str) -> String {
    let one: String = s.chars().map(|c| if matches!(c, '\n' | '\r' | '\t') { ' ' } else { c }).collect();
    let t = one.trim();
    let chars: Vec<char> = t.chars().collect();
    let mut o = String::with_capacity(t.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        let prev_ws = i == 0 || chars[i - 1].is_whitespace();
        let next_nonws = chars.get(i + 1).map(|n| !n.is_whitespace()).unwrap_or(false);
        match c {
            '\\' | '{' | '}' | '[' | ']' | '|' | '*' | '_' | '^' | '~' => {
                o.push('\\');
                o.push(c);
            }
            // -strike- / +underline+ / !image! / ??cite?? / list markers only start at a word boundary
            '-' | '+' | '#' | '!' | '?' if prev_ws && (next_nonws || i == 0) => {
                o.push('\\');
                o.push(c);
            }
            _ => o.push(c),
        }
    }
    // headings / block quotes must start a line
    let lower = o.to_ascii_lowercase();
    let heading = lower.len() > 2 && lower.starts_with('h') && lower.as_bytes()[1].is_ascii_digit() && lower[2..].starts_with('.');
    if heading || lower.starts_with("bq.") {
        o.insert(0, ' ');
    }
    o
}

/// Body of a Jira `{code}` block: only the closing macro matters, neutralise every `{code`.
pub fn jira_code(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.to_ascii_lowercase().find("{code") {
        out.push_str(&rest[..i]);
        out.push_str("{ code");
        rest = &rest[i + 5..];
    }
    out.push_str(rest);
    out
}

fn csv_row(fields: &[String]) -> String {
    let mut l = fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(",");
    l.push_str("\r\n");
    l
}

fn defects_sorted(q: &QaReport) -> Vec<&Defect> {
    let mut d: Vec<&Defect> = q.defects.iter().collect();
    d.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.severity.cmp(&a.severity)).then(a.id.cmp(&b.id)));
    d
}

// ----------------------------------------------------------------- evidence

/// Where an evidence file ended up in the report folder.
struct EvOut {
    link: Option<String>,
    data_uri: Option<String>,
}

fn safe_rel(p: &str) -> Option<PathBuf> {
    let pb = Path::new(p);
    if p.is_empty() || pb.is_absolute() || pb.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return None;
    }
    Some(pb.to_path_buf())
}

fn stage_evidence(run_dir: &Path, out: Option<&Path>, ev: &Evidence, n: usize) -> EvOut {
    let (Some(out), Some(rel)) = (out, safe_rel(&ev.path)) else { return EvOut { link: None, data_uri: None } };
    let src = [run_dir.join("artifacts").join(&rel), run_dir.join(&rel)].into_iter().find(|p| p.is_file());
    let Some(src) = src else { return EvOut { link: None, data_uri: None } };
    let base: String = src
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let name = format!("{n:03}-{base}");
    let dir = out.join("evidence");
    if std::fs::create_dir_all(&dir).is_err() || std::fs::copy(&src, dir.join(&name)).is_err() {
        return EvOut { link: None, data_uri: None };
    }
    let ext = src.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
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
    EvOut { link: Some(format!("evidence/{name}")), data_uri }
}

// --------------------------------------------------------------------- HTML

fn bar(counts: &ResultCounts) -> Vec<Value> {
    let total = (counts.passed + counts.failed + counts.blocked + counts.skipped + counts.flaky).max(1) as f64;
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
    env.add_template("qa-report.html.j2", include_str!("../../templates/qa-report.html.j2"))?;
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
    Ok(env.get_template("qa-report.html.j2")?.render(ctx)?)
}

fn looks_like_code(s: &str) -> bool {
    let t = s.trim_start();
    t.starts_with("curl") || t.starts_with("npx") || t.starts_with("await ") || t.contains('\n') || t.starts_with("$ ")
}

fn status_label(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::New => "new",
        FindingStatus::Existing => "existing",
        FindingStatus::Suppressed => "suppressed",
    }
}

// ----------------------------------------------------------------- Markdown

/// Table cell: inline-escaped (which also escapes `|`), single line.
fn md_cell(s: &str) -> String {
    md_inline(s)
}

pub fn markdown(run: &Run) -> Result<String> {
    let q = run.qa.as_ref().ok_or_else(|| anyhow!("not a QA run"))?;
    let (rec, _) = rec_text(q.recommendation);
    let mut m = format!("# QA test summary report\n\n**Target:** {}  \n**Environment:** {}  \n**Run:** {} ({})  \n**ReadyHai:** {} · mode {} · profile {}\n\n", md_inline(&run.target.raw), md_inline(&q.environment), md_inline(&run.id), md_inline(&run.started), md_inline(&run.version), md_inline(&q.mode), lc(&run.profile));
    m.push_str(&format!("## Recommendation: {rec}\n\n"));
    for c in &q.conditions {
        m.push_str(&format!("- {}\n", md_inline(c)));
    }
    m.push_str(&format!("\n## Executive summary\n\n{}\n\n", md_lines(&q.executive_summary)));
    if let Some(a) = &q.ai_summary {
        m.push_str(&format!("> AI-written summary (advisory): {}\n\n", a.lines().map(md_inline).collect::<Vec<_>>().join("\n> ")));
    }
    let c = &q.counts;
    m.push_str(&format!("## Results\n\n| Planned | Executed | Passed | Failed | Blocked | Skipped | Flaky |\n|---|---|---|---|---|---|---|\n| {} | {} | {} | {} | {} | {} | {} |\n\n", c.planned, c.executed, c.passed, c.failed, c.blocked, c.skipped, c.flaky));
    let ds = defects_sorted(q);
    m.push_str(&format!("## Defects ({})\n\n", ds.len()));
    if !ds.is_empty() {
        m.push_str("| ID | Priority | Severity | Component | Title | Status |\n|---|---|---|---|---|---|\n");
        for d in &ds {
            m.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n", md_cell(&d.id), prio_str(d.priority), d.severity.as_str(), md_cell(&d.component), md_cell(&d.title), status_label(d.status)));
        }
        m.push('\n');
    }
    for d in &ds {
        m.push_str(&format!("### {} {}\n\n{} · {} · {}\n\n", md_inline(&d.id), md_inline(&d.title), prio_str(d.priority), d.severity.as_str(), md_inline(&d.component)));
        m.push_str("**Steps to reproduce**\n\n");
        for (i, s) in d.steps_to_reproduce.iter().enumerate() {
            if looks_like_code(s) {
                m.push_str(&format!("\n{}", md_fence(s, "sh")));
            } else {
                m.push_str(&format!("{}. {}\n", i + 1, md_inline(s)));
            }
        }
        m.push_str(&format!("\n**Expected:** {}\n\n**Actual:** {}\n\n", md_lines(&d.expected), md_lines(&d.actual)));
        if !d.remediation.is_empty() {
            m.push_str(&format!("**Remediation:** {}\n\n", md_lines(&d.remediation)));
        }
    }
    m.push_str("## Exit criteria\n\n| Criterion | Met | Blocking | Detail |\n|---|---|---|---|\n");
    for e in &q.exit_criteria {
        m.push_str(&format!("| {} | {} | {} | {} |\n", md_cell(&e.name), if e.met { "yes" } else { "NO" }, if e.blocking { "yes" } else { "no" }, md_cell(&e.detail)));
    }
    if !q.notes.is_empty() {
        m.push_str("\n## Notes\n\n");
        for n in &q.notes {
            m.push_str(&format!("- {}\n", md_cell(n)));
        }
    }
    m.push_str(&format!("\n---\nGenerated by ReadyHai {}.\n", md_inline(&run.version)));
    Ok(m)
}

// ---------------------------------------------------------------- trackers

fn jira_description(d: &Defect) -> String {
    let mut s = String::from("h3. Steps\n");
    for st in &d.steps_to_reproduce {
        if looks_like_code(st) {
            s.push_str(&format!("{{code}}\n{}\n{{code}}\n", jira_code(st)));
        } else {
            s.push_str(&format!("# {}\n", jira_text(st)));
        }
    }
    s.push_str(&format!("*Expected*: {}\n*Actual*: {}\n", jira_text(&d.expected), jira_text(&d.actual)));
    if !d.remediation.is_empty() {
        s.push_str(&format!("*Remediation*: {}\n", jira_text(&d.remediation)));
    }
    s.push_str(&format!("*Severity*: {} | *Rule*: {} | *Environment*: {}\n", d.severity.as_str(), jira_text(&d.rule), jira_text(&d.environment)));
    s
}

pub fn jira_csv(q: &QaReport) -> String {
    let mut o = csv_row(&["Summary", "Issue Type", "Priority", "Labels", "Component", "Description"].map(String::from));
    for d in defects_sorted(q) {
        o.push_str(&csv_row(&[
            d.title.clone(), "Bug".into(), jira_priority(d.priority).into(),
            format!("readyhai qa-{}", lc(&d.area)), d.component.clone(), jira_description(d),
        ]));
    }
    o
}

fn md_description(d: &Defect) -> String {
    let mut s = format!("**Severity:** {} · **Priority:** {} · **Component:** {}\n\n### Steps to reproduce\n", d.severity.as_str(), prio_str(d.priority), md_inline(&d.component));
    let mut n = 0;
    for st in &d.steps_to_reproduce {
        if looks_like_code(st) {
            s.push_str(&format!("\n{}", md_fence(st, "sh")));
        } else {
            n += 1;
            s.push_str(&format!("{n}. {}\n", md_inline(st)));
        }
    }
    s.push_str(&format!("\n**Expected:** {}\n\n**Actual:** {}\n", md_lines(&d.expected), md_lines(&d.actual)));
    if !d.remediation.is_empty() {
        s.push_str(&format!("\n**Remediation:** {}\n", md_lines(&d.remediation)));
    }
    s
}

pub fn gitlab_json(q: &QaReport) -> Value {
    Value::Array(
        defects_sorted(q)
            .iter()
            .map(|d| {
                json!({
                    "title": d.title, "description": md_description(d),
                    "labels": ["readyhai", "bug", format!("qa-{}", lc(&d.area)), prio_str(d.priority), format!("severity::{}", d.severity.as_str())],
                })
            })
            .collect(),
    )
}

pub fn testrail_csv(q: &QaReport) -> String {
    let mut o = csv_row(&["Title", "Section", "Type", "Priority", "Preconditions", "Steps", "Expected Result"].map(String::from));
    for c in &q.cases {
        let steps = c.steps.iter().enumerate().map(|(i, s)| format!("{}. {s}", i + 1)).collect::<Vec<_>>().join("\n");
        let pre = c.role.as_ref().map(|r| format!("Role: {r}")).unwrap_or_default();
        o.push_str(&csv_row(&[
            c.title.clone(), lc(&c.area), lc(&c.technique), prio_str(c.priority).into(), pre, steps, c.expected.clone(),
        ]));
    }
    o
}

pub fn xray_csv(q: &QaReport) -> String {
    let mut o = csv_row(&["Test Summary", "Test Type", "Action", "Data", "Result"].map(String::from));
    for c in &q.cases {
        if c.steps.is_empty() {
            o.push_str(&csv_row(&[c.title.clone(), "Manual".into(), String::new(), String::new(), c.expected.clone()]));
        }
        for (i, s) in c.steps.iter().enumerate() {
            let last = i + 1 == c.steps.len();
            o.push_str(&csv_row(&[
                c.title.clone(), "Manual".into(), s.clone(), c.component.clone(),
                if last { c.expected.clone() } else { String::new() },
            ]));
        }
    }
    o
}

// ------------------------------------------------------------------- write

/// Write the QA-specific formats. Returns the files written.
pub fn write_formats(run: &Run, dir: &Path, formats: &[String]) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut out = vec![];
    let want_html = formats.iter().any(|f| matches!(f.as_str(), "qa" | "html" | "pdf"));
    let mut html_done = false;
    for f in formats {
        if !QA_FORMATS.contains(&f.as_str()) && f != "html" {
            continue;
        }
        let is_qa_fmt = QA_FORMATS.contains(&f.as_str());
        let Some(q) = &run.qa else {
            if is_qa_fmt {
                eprintln!("note: format '{f}' needs a QA run (readyhai qa); skipped");
            }
            continue;
        };
        let (name, body): (&str, String) = match f.as_str() {
            "qa" | "html" | "pdf" => {
                if html_done || !want_html {
                    continue;
                }
                html_done = true;
                ("qa-report.html", qa_html(run, Some(dir))?)
            }
            "md" => ("qa-report.md", markdown(run)?),
            "jira" => ("defects.jira.csv", jira_csv(q)),
            "gitlab" => ("defects.gitlab.json", serde_json::to_string_pretty(&gitlab_json(q))?),
            "testrail" => ("testcases.testrail.csv", testrail_csv(q)),
            "xray" => ("testcases.xray.csv", xray_csv(q)),
            _ => continue,
        };
        let p = dir.join(name);
        std::fs::write(&p, body)?;
        out.push(p);
    }
    if formats.iter().any(|f| f == "pdf") && run.qa.is_some() {
        if !html_done {
            let p = dir.join("qa-report.html");
            std::fs::write(&p, qa_html(run, Some(dir))?)?;
            out.push(p);
        }
        match render_pdf(dir) {
            Ok(p) => out.push(p),
            Err(e) => eprintln!("note: PDF not rendered ({e}); qa-report.html is complete"),
        }
    }
    Ok(out)
}

/// Render dir/qa-report.html to dir/qa-report.pdf with the playwright runner image (offline, read-only).
fn render_pdf(dir: &Path) -> Result<PathBuf> {
    use std::process::{Command, Stdio};
    let (image, _) = crate::tools::image_for("playwright");
    if crate::tools::local_image_id(&image).is_none() {
        return Err(anyhow!("playwright image '{image}' not available locally"));
    }
    let dir = std::fs::canonicalize(dir)?;
    let o = Command::new("docker")
        .args(["run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", "/tmp:rw,mode=1777", "--user", "65534:65534", "-v"])
        .arg(format!("{}:/out", dir.display()))
        .arg(&image)
        .args(["node", "/runner/pdf.mjs", "/out/qa-report.html", "/out/qa-report.pdf"])
        .stdin(Stdio::null())
        .output()?;
    let p = dir.join("qa-report.pdf");
    if !o.status.success() || !p.is_file() {
        return Err(anyhow!("docker run failed: {}", String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("")));
    }
    Ok(p)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{Category, FindingStatus, Severity};

    pub(crate) fn sample_qa(rec: Recommendation) -> QaReport {
        let d = Defect {
            id: "D-001".into(), rule: "qa.api.bola".into(), category: Category::Security, severity: Severity::High,
            priority: Priority::P1, area: Area::Api, title: "<script>alert(1)</script>, \"quoted\"\nline".into(),
            component: "GET /orders/{id}".into(), environment: "staging".into(),
            steps_to_reproduce: vec!["Login as user".into(), "curl -H \"Authorization: Bearer $RH_USER_TOKEN\" https://x/orders/2".into()],
            expected: "403".into(), actual: "200 with other user's order".into(),
            evidence: vec![Evidence { kind: EvidenceKind::Screenshot, path: "shots/a.png".into(), note: String::new() }],
            reproduced: (3, 3), cases: vec![], remediation: "Check ownership".into(), fp_key: "k".into(),
            fingerprint: String::new(), status: FindingStatus::New, regression: true, ai_note: Some("<b>ai</b>".into()),
        };
        let mut cov = CoverageMatrix::default();
        cov.set("GET /orders", "authz", Cell::Fail);
        cov.set("GET /orders", "positive", Cell::Pass);
        QaReport {
            recommendation: rec, conditions: vec!["Fix D-001".into()], executive_summary: "All good, mostly.".into(),
            ai_summary: Some("AI says <i>hi</i>".into()), mode: "deterministic".into(), environment: "staging".into(),
            scope: vec!["API".into()], out_of_scope: vec!["Load".into()], roles: vec!["user".into()], plan: vec![],
            counts: ResultCounts { planned: 5, executed: 4, passed: 3, failed: 1, ..Default::default() },
            cases: vec![TestCase { id: "c1".into(), area: Area::Api, technique: Technique::AuthMatrix, title: "Orders, authz".into(),
                priority: Priority::P1, component: "GET /orders/{id}".into(), role: Some("user".into()),
                steps: vec!["Login".into(), "GET order 2".into()], expected: "403".into(), source: CaseSource::Deterministic }],
            results: vec![], defects: vec![d], coverage: cov,
            risks: vec![Risk { title: "r".into(), level: "high".into(), mitigation: "m".into() }],
            exit_criteria: vec![ExitCriterion { name: "No P1".into(), met: false, blocking: true, detail: "1 open".into() }],
            notes: vec!["perf p95=120ms".into()],
        }
    }

    pub(crate) fn sample_run(rec: Recommendation) -> Run {
        Run {
            id: "r1".into(), version: "0.1.0".into(),
            target: Target { kind: TargetKind::Web, raw: "http://a".into(), path: None, image: None, url: Some("http://a".into()), openapi: None, host: None, apk: None, device: None },
            profile: Profile::Quick, started: "2026-10-25T10:00:00Z".into(), finished: "f".into(), verdict: Verdict::Fail,
            reasons: vec![], categories: vec![], checks: vec![], findings: vec![], fixed: 0, notes: vec![], errors: vec![],
            qa: Some(sample_qa(rec)),
        }
    }

    #[test]
    fn html_escaped_and_badges() {
        let h = qa_html(&sample_run(Recommendation::NoGo), None).unwrap();
        assert!(h.contains("&lt;script&gt;alert(1)"));
        assert!(!h.contains("<script>"));
        assert!(!h.contains("<b>ai</b>"));
        assert!(h.contains("Content-Security-Policy"));
        assert!(h.contains("NO-GO"));
        assert!(h.contains("AI-written summary"));
        assert!(qa_html(&sample_run(Recommendation::Go), None).unwrap().contains(">GO<"));
        assert!(qa_html(&sample_run(Recommendation::ConditionalGo), None).unwrap().contains("CONDITIONAL GO"));
    }

    #[test]
    fn csv_quoting_and_jira() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(jira_priority(Priority::P1), "Highest");
        assert_eq!(jira_priority(Priority::P2), "High");
        assert_eq!(jira_priority(Priority::P3), "Medium");
        assert_eq!(jira_priority(Priority::P4), "Low");
        let q = sample_qa(Recommendation::NoGo);
        let j = jira_csv(&q);
        assert!(j.starts_with("Summary,Issue Type,Priority,Labels,Component,Description\r\n"));
        assert!(j.contains("Highest") && j.contains("readyhai qa-api") && j.contains("{code}") && j.contains("h3. Steps"));
        assert!(j.contains("\"\"quoted\"\""));
    }

    #[test]
    fn exports_have_no_secrets() {
        let q = sample_qa(Recommendation::NoGo);
        let all = format!("{}{}{}{}{}", jira_csv(&q), gitlab_json(&q), testrail_csv(&q), xray_csv(&q), markdown(&sample_run(Recommendation::NoGo)).unwrap());
        assert!(all.contains("$RH_USER_TOKEN"));
        let re = regex::Regex::new(r"Bearer\s+[A-Za-z0-9._-]{16,}").unwrap();
        assert!(!re.is_match(&all));
        assert!(xray_csv(&q).lines().count() >= 3);
        assert_eq!(gitlab_json(&q)[0]["labels"][0], "readyhai");
    }

    #[test]
    fn markdown_sanity_and_write() {
        let m = markdown(&sample_run(Recommendation::ConditionalGo)).unwrap();
        assert!(m.contains("## Recommendation: CONDITIONAL GO") && m.contains("### D-001") && m.contains("```sh") && m.contains("## Exit criteria"));
        let dir = std::env::temp_dir().join(format!("rh-qa-{}", std::process::id()));
        let files = write_formats(&sample_run(Recommendation::Go), &dir, &["qa".into(), "md".into(), "jira".into(), "gitlab".into(), "testrail".into(), "xray".into()]).unwrap();
        assert_eq!(files.len(), 6);
        // non-QA run: skipped
        let mut r = sample_run(Recommendation::Go);
        r.qa = None;
        assert!(write_formats(&r, &dir, &["md".into()]).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn hostile_defect() -> Defect {
        let mut q = sample_qa(Recommendation::NoGo);
        let mut d = q.defects.remove(0);
        d.title = "=HYPERLINK(\"http://evil/\",\"x\") [click](javascript:alert(1)) <img src=x onerror=alert(1)> @admin".into();
        d.component = "+cmd|' /C calc'!A0 GET /a`b".into();
        d.expected = "- @SUM(1+1)\n# not a heading\n1. not a list".into();
        d.actual = "{code}\n{panel}h1. pwned{panel}".into();
        d.remediation = "*bold* _it_ ~~x~~ {noformat}".into();
        d.steps_to_reproduce = vec![
            "Open {code}http://x/{code} and [[link]]".into(),
            "curl -sS 'http://x/```\nrm -rf /```' # code fence breakout".into(),
        ];
        d
    }

    #[test]
    fn markdown_helpers_escape_markup() {
        assert_eq!(md_inline("a_b_c"), "a_b_c", "intraword underscores stay");
        assert_eq!(md_inline("_x_ *y* `z`"), "\\_x\\_ \\*y\\* \\`z\\`");
        assert_eq!(md_inline("1. first"), "1\\. first");
        assert_eq!(md_inline("# h"), "\\# h");
        assert_eq!(md_inline("- item"), "\\- item");
        assert_eq!(md_inline("[a](b) <i>|"), "\\[a\\](b) \\<i\\>\\|");
        assert!(md_inline("@admin ping").starts_with("@\u{200B}admin"));
        assert_eq!(md_inline("a\nb\r\nc"), "a b  c");
        // a fence is always longer than the longest backtick run inside the body
        assert_eq!(md_fence("x```y", "sh"), "````sh\nx```y\n````\n");
        assert_eq!(md_fence("plain", ""), "```\nplain\n```\n");
        assert_eq!(md_fence("a``````b", "sh").lines().next().unwrap(), "```````sh");
    }

    #[test]
    fn markdown_report_cannot_be_hijacked_by_spec_text() {
        let mut r = sample_run(Recommendation::NoGo);
        r.qa.as_mut().unwrap().defects = vec![hostile_defect()];
        let m = markdown(&r).unwrap();
        // no live link / image / raw html / mention from the defect text
        assert_eq!(m.matches("<img").count(), m.matches("\\<img").count(), "every < is escaped: {m}");
        assert!(m.contains("\\[click\\](javascript:alert(1))"));
        assert!(!m.contains("@admin"), "mentions are neutralised");
        // the heading, the table row and the headings-in-text stay inert
        assert!(m.contains("### D-001 \\=HYPERLINK") || m.contains("### D-001 =HYPERLINK"));
        assert!(!m.lines().any(|l| l.trim_start().starts_with("# not a heading")));
        assert!(m.contains("\\# not a heading") && m.contains("1\\. not a list"));
        // the code step with ``` is inside a LONGER fence
        assert!(m.contains("````sh\ncurl -sS 'http://x/```\nrm -rf /```' # code fence breakout\n````\n"), "{m}");
        // fence balance: every line made only of backticks opens/closes with matching lengths
        let fences: Vec<&str> = m.lines().filter(|l| l.starts_with("```")).collect();
        assert_eq!(fences.len() % 2, 0, "{fences:?}");
    }

    #[test]
    fn gitlab_description_is_escaped_too() {
        let mut q = sample_qa(Recommendation::NoGo);
        q.defects = vec![hostile_defect()];
        let g = gitlab_json(&q);
        let desc = g[0]["description"].as_str().unwrap();
        assert_eq!(desc.matches("<img").count(), desc.matches("\\<img").count());
        assert!(!desc.contains("@admin"));
        assert!(desc.contains("````sh\ncurl -sS 'http://x/```"));
        // the title is a plain field, untouched
        assert!(g[0]["title"].as_str().unwrap().starts_with("=HYPERLINK"));
    }

    #[test]
    fn jira_text_cannot_open_macros_or_close_the_code_block() {
        assert_eq!(jira_text("{code}x{code}"), "\\{code\\}x\\{code\\}");
        assert_eq!(jira_text("*b* _i_ [l] |t|"), "\\*b\\* \\_i\\_ \\[l\\] \\|t\\|");
        assert_eq!(jira_text("snake-case and a - b"), "snake-case and a - b", "mid-word dashes are not strike-through");
        assert_eq!(jira_text("-struck-"), "\\-struck-");
        assert!(jira_text("h1. title").starts_with(' '), "headings must start a line");
        assert!(jira_text("bq. quote").starts_with(' '));
        assert_eq!(jira_code("a{code}b{CODE:java}c"), "a{ code}b{ code:java}c");
        let d = hostile_defect();
        let desc = jira_description(&d);
        // exactly one {code} pair (the curl step); nothing from the spec can add another
        assert_eq!(desc.matches("{code}").count(), 2, "{desc}");
        assert!(!desc.contains("{panel}") && !desc.contains("{noformat}"));
        assert!(desc.contains("\\{panel\\}"));
    }

    #[test]
    fn csv_formula_injection_is_neutralised_in_every_export() {
        for bad in ["=1+1", "+1", "-1+2", "@SUM(A1)", "\t=1", "\r=1"] {
            let f = csv_field(bad);
            assert!(f.trim_start_matches('"').starts_with('\''), "{bad:?} -> {f:?}");
        }
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a=b"), "a=b", "only a LEADING sign is dangerous");
        assert_eq!(csv_field("=a,b"), "\"'=a,b\"", "quoting still applies after neutralising");
        let mut q = sample_qa(Recommendation::NoGo);
        q.defects = vec![hostile_defect()];
        q.cases[0].title = "=cmd|' /C calc'!A0".into();
        q.cases[0].steps = vec!["+SUM(1)".into(), "@x".into()];
        q.cases[0].expected = "-2".into();
        // parse every cell back: none may start with a formula trigger
        let all = [jira_csv(&q), testrail_csv(&q), xray_csv(&q)];
        for csv in &all {
            for rec in split_csv(csv).iter().skip(1) {
                for cell in rec {
                    assert!(!cell.starts_with(['=', '+', '-', '@', '\t', '\r']), "formula cell {cell:?} in {csv}");
                }
            }
        }
        assert!(all[0].contains("\"'=HYPERLINK"), "the defect title cell is prefixed");
    }

    /// Minimal RFC 4180 reader for the assertions above.
    fn split_csv(s: &str) -> Vec<Vec<String>> {
        let (mut rows, mut row, mut cell, mut q) = (vec![], vec![], String::new(), false);
        let mut it = s.chars().peekable();
        while let Some(c) = it.next() {
            match (c, q) {
                ('"', true) if it.peek() == Some(&'"') => {
                    cell.push('"');
                    it.next();
                }
                ('"', _) => q = !q,
                (',', false) => row.push(std::mem::take(&mut cell)),
                ('\r', false) => {}
                ('\n', false) => {
                    row.push(std::mem::take(&mut cell));
                    rows.push(std::mem::take(&mut row));
                }
                (c, _) => cell.push(c),
            }
        }
        rows
    }

    #[test]
    fn b64_ok() {
        assert_eq!(b64(b"Man"), "TWFu");
        assert_eq!(b64(b"Ma"), "TWE=");
        assert_eq!(b64(b"M"), "TQ==");
    }
}
