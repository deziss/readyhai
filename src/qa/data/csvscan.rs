//! CSV/TSV fixture scans: required-column nulls and duplicate primary keys.
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::{Area, ResultStatus};

use super::data_files;
use crate::qa::suite::common::{Def, MAX_ITEM_DEFECTS, no_snapshot, out, read, record};

/// Split one CSV line honouring double-quoted fields (minimal RFC-4180).
pub(crate) fn split_csv_line(line: &str, delim: char) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        if quoted {
            if c == '"' {
                if it.peek() == Some(&'"') {
                    cur.push('"');
                    it.next();
                } else {
                    quoted = false;
                }
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            quoted = true;
        } else if c == delim {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    fields.push(cur);
    fields
}

pub(crate) fn delimiter(path: &str) -> char {
    if path.ends_with(".tsv") { '\t' } else { ',' }
}

/// Columns QA conventionally treats as required unless the header says otherwise
/// (`*optional*`, `*_null*`, `*[]`).
fn header_required(col: &str) -> bool {
    let l = col.trim().to_lowercase();
    if l.is_empty() || l.contains("optional") || l.contains("_null") || l.ends_with("[]") {
        return false;
    }
    l == "id"
        || l.ends_with("_id")
        || l.ends_with("_email")
        || l == "email"
        || l.ends_with("_name")
        || l == "name"
        || l.ends_with("_date")
        || l == "status"
        || l.ends_with("_at")
}

pub(crate) fn csv_tables(ctx: &Ctx) -> Vec<(String, Vec<String>, Vec<Vec<String>>)> {
    let Some(snap) = &ctx.snapshot else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in data_files(snap, &[".csv", ".tsv"]) {
        let Some(text) = read(snap, &f) else {
            continue;
        };
        let d = delimiter(&f);
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let Some(head) = lines.next() else {
            continue;
        };
        let header = split_csv_line(head, d);
        if header.len() < 2 {
            continue; // not tabular enough to trust a header
        }
        let rows: Vec<Vec<String>> = lines.map(|l| split_csv_line(l, d)).collect();
        out.push((f, header, rows));
    }
    out
}

fn not_applicable() -> anyhow::Result<CheckOutput> {
    Ok(CheckOutput::status(CheckStatus::NotApplicable(
        "no CSV/TSV fixtures found".into(),
    )))
}

pub(crate) fn null_violation(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    if ctx.snapshot.is_none() {
        return no_snapshot();
    }
    let tables = csv_tables(ctx);
    if tables.is_empty() {
        return not_applicable();
    }
    let mut defs: Vec<Def> = Vec::new();
    let mut cells = 0usize;
    let mut cols = 0usize;
    for (file, header, rows) in &tables {
        for (ci, col) in header.iter().enumerate() {
            if !header_required(col) {
                continue;
            }
            cols += 1;
            let mut bad: Vec<usize> = Vec::new();
            for (ri, row) in rows.iter().enumerate() {
                let v = row.get(ci).map(|s| s.trim()).unwrap_or("");
                let nullish = v.is_empty()
                    || matches!(
                        v.to_lowercase().as_str(),
                        "null" | "none" | "nan" | "n/a" | "na" | "-"
                    );
                if nullish {
                    bad.push(ri + 2); // 1-based line number incl. the header row
                }
            }
            cells += rows.len();
            if !bad.is_empty() {
                let shown: Vec<String> = bad.iter().take(5).map(|r| r.to_string()).collect();
                let more = if bad.len() > 5 { ", …" } else { "" };
                defs.push(Def {
                    rule: "qa.data.null-violation",
                    cat: Category::Quality,
                    sev: Severity::Medium,
                    area: Area::Data,
                    title: format!("Column \"{}\" has {} null/empty value(s)", col, bad.len()),
                    component: file.clone(),
                    expected: "Every row carries a value in a required column".into(),
                    actual: format!("Empty at line(s) {}{}", shown.join(", "), more),
                    remediation: "Backfill the fixture or rename the column to mark it optional"
                        .into(),
                    fp_key: format!("{file}|{col}"),
                    steps: vec![format!("Open {file}"), format!("Check column {col}")],
                });
            }
        }
    }
    let n = defs.len();
    defs.truncate(MAX_ITEM_DEFECTS);
    let status = if n > 0 {
        ResultStatus::Fail
    } else {
        ResultStatus::Pass
    };
    Ok(out(record(
        ctx,
        "qa.data.null-violation",
        Area::Data,
        "data.csv.nulls",
        "Required CSV columns have no null/empty values",
        "fixtures",
        status,
        &format!("{n}/{cols} required column(s) violated across {cells} scanned data row(s)"),
        defs,
    )))
}

pub(crate) fn duplicate_key(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    if ctx.snapshot.is_none() {
        return no_snapshot();
    }
    let tables = csv_tables(ctx);
    if tables.is_empty() {
        return not_applicable();
    }
    let mut defs: Vec<Def> = Vec::new();
    for (file, header, rows) in &tables {
        let stem = file
            .rsplit('/')
            .next()
            .unwrap_or("")
            .split('.')
            .next()
            .unwrap_or("")
            .to_lowercase();
        let Some(ki) = header.iter().position(|c| {
            let l = c.trim().to_lowercase();
            l == "id" || l == format!("{stem}_id")
        }) else {
            continue;
        };
        let col = header[ki].trim().to_string();
        let mut seen: std::collections::BTreeMap<&str, Vec<usize>> = Default::default();
        for (ri, row) in rows.iter().enumerate() {
            if let Some(v) = row.get(ki) {
                let v = v.trim();
                if !v.is_empty() {
                    seen.entry(v).or_default().push(ri + 2);
                }
            }
        }
        for (val, lines) in seen.iter().filter(|(_, l)| l.len() > 1).take(20) {
            let shown = lines
                .iter()
                .take(5)
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            defs.push(Def {
                rule: "qa.data.duplicate-key",
                cat: Category::Quality,
                sev: Severity::Medium,
                area: Area::Data,
                title: format!("Duplicate {col} \"{val}\" in fixture"),
                component: file.clone(),
                expected: "Fixture keys are unique".into(),
                actual: format!(
                    "\"{val}\" appears {} time(s) at line(s) {shown}",
                    lines.len()
                ),
                remediation: "De-duplicate the rows or give each record a distinct key".into(),
                fp_key: format!("{file}|{col}|{val}"),
                steps: vec![format!("Open {file}"), format!("Compare {col} values")],
            });
        }
    }
    let n = defs.len();
    defs.truncate(MAX_ITEM_DEFECTS);
    let status = if n > 0 {
        ResultStatus::Fail
    } else {
        ResultStatus::Pass
    };
    Ok(out(record(
        ctx,
        "qa.data.duplicate-key",
        Area::Data,
        "data.csv.duplicate-key",
        "Fixture primary keys are unique",
        "fixtures",
        status,
        &format!("{n} duplicate key(s) found"),
        defs,
    )))
}
