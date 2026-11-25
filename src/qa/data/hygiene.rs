//! Fixture hygiene: leaked PII, stale year literals, and orphaned foreign keys
//! between CSV tables.
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::{Area, ResultStatus};

use super::csvscan::csv_tables;
use super::data_files;
use crate::qa::suite::common::{Def, MAX_ITEM_DEFECTS, no_snapshot, out, re, read, record};

pub(crate) fn pii_exposed(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let files = data_files(
        snap,
        &[
            ".csv", ".tsv", ".json", ".sql", ".txt", ".yml", ".yaml", ".xml",
        ],
    );
    if files.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no fixture data files found".into(),
        )));
    }
    let email = re(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b");
    let ssn = re(r"\b\d{3}-\d{2}-\d{4}\b");
    let card = re(r"\b(?:\d[ -]?){13,18}\d\b");
    let phone = re(r"\b\+?\d{1,3}[ .()-]?\(?\d{2,4}\)?[ .()-]?\d{3,4}[ .()-]?\d{3,4}\b");
    // Fixture-looking domains are fine; anything else looks like a real mailbox.
    let safe_domain = |s: &str| {
        let s = s.to_lowercase();
        s.contains("example.")
            || s.contains(".test")
            || s.contains(".invalid")
            || s.contains("localhost")
            || s.contains("email.com")
            || s.contains("sample.")
    };
    let mut defs: Vec<Def> = Vec::new();
    for f in &files {
        let Some(text) = read(snap, f) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            let mut hits: Vec<&str> = Vec::new();
            if let Some(m) = ssn.find(line) {
                hits.push(match m.as_str() {
                    "000-00-0000" | "123-45-6789" => "", // obvious dummies
                    _ => "SSN-like value",
                });
            }
            if let Some(m) = email.find(line)
                && !safe_domain(m.as_str())
            {
                hits.push("non-example email address");
            }
            for cap in phone.find_iter(line).take(3) {
                let t = cap.as_str();
                let digits: usize = t.chars().filter(char::is_ascii_digit).count();
                if (9..=15).contains(&digits) && !t.chars().all(|c| c == '0') {
                    hits.push("phone-like value");
                    break;
                }
            }
            for cap in card.find_iter(line).take(3) {
                let t = cap.as_str();
                let digits: usize = t.chars().filter(char::is_ascii_digit).count();
                if (13..=19).contains(&digits) && !looks_like_version(t) {
                    hits.push("card/account-number-like value");
                    break;
                }
            }
            let hits: Vec<&str> = hits.into_iter().filter(|h| !h.is_empty()).collect();
            if !hits.is_empty() {
                defs.push(Def {
                    rule: "qa.data.pii-exposed",
                    cat: Category::Security,
                    sev: Severity::High,
                    area: Area::Security,
                    title: format!("Possible real PII in fixture ({})", hits.join(", ")),
                    component: format!("{f}:{}", i + 1),
                    expected: "Fixtures use synthetic data (example.com, reserved test numbers)"
                        .into(),
                    actual: line.trim().chars().take(120).collect(),
                    remediation: "Replace with synthetic values or a data generator (faker)".into(),
                    fp_key: format!("{f}:{}", i + 1),
                    steps: vec![format!("Open {f}"), format!("Inspect line {}", i + 1)],
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
        "qa.data.pii-exposed",
        Area::Security,
        "data.pii",
        "Fixtures contain no real-looking PII",
        "fixtures",
        status,
        &format!(
            "{n} line(s) with possible PII across {} fixture file(s)",
            files.len()
        ),
        defs,
    )))
}

/// Heuristic: dotted version-ish strings ("1.2.3.4") are not card numbers.
fn looks_like_version(s: &str) -> bool {
    s.split('.').count() >= 3 && s.split('.').all(|p| p.len() <= 3)
}

pub(crate) fn stale_dates(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let files = data_files(snap, &[".csv", ".tsv", ".json", ".sql", ".yml", ".yaml"]);
    if files.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no fixture data files found".into(),
        )));
    }
    let year_in_date = re(r"\b(19\d{2}|20[0-2]\d)-(0?[1-9]|1[0-2])-(0?[1-9]|[12]\d|3[01])\b");
    // Compare against this time next year so the check stays quiet until a year really ages.
    let now_year = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        (secs / 31_557_600 + 1970) as i32 // ~365.25-day years; good enough for a staleness floor
    };
    let stale_before = now_year - 1;
    let mut defs: Vec<Def> = Vec::new();
    for f in &files {
        let Some(text) = read(snap, f) else {
            continue;
        };
        let mut stale: Vec<(usize, String)> = Vec::new();
        for (i, line) in text.lines().enumerate() {
            for cap in year_in_date.find_iter(line) {
                let y: i32 = cap.as_str()[..4].parse().unwrap_or(stale_before);
                if y < stale_before {
                    stale.push((i + 1, cap.as_str().to_string()));
                    break;
                }
            }
        }
        if !stale.is_empty() {
            let sample: Vec<String> = stale
                .iter()
                .take(3)
                .map(|(l, d)| format!("{d} (line {l})"))
                .collect();
            defs.push(Def {
                rule: "qa.data.stale-dates",
                cat: Category::Quality,
                sev: Severity::Low,
                area: Area::Data,
                title: format!("{} line(s) use dates older than {}", stale.len(), stale_before),
                component: f.clone(),
                expected: "Date fixtures are kept current (relative dates preferred)".into(),
                actual: sample.join("; "),
                remediation:
                    "Regenerate fixtures with recent dates or compute them relative to today"
                        .into(),
                fp_key: format!("{f}|stale"),
                steps: vec![format!("Open {f}"), "Refresh the dates".into()],
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
        "qa.data.stale-dates",
        Area::Data,
        "data.stale-dates",
        "Fixture dates are recent",
        "fixtures",
        status,
        &format!("{n} fixture file(s) with stale dates"),
        defs,
    )))
}

pub(crate) fn orphan_reference(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    if ctx.snapshot.is_none() {
        return no_snapshot();
    }
    let tables = csv_tables(ctx);
    if tables.len() < 2 {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "need at least two CSV tables to cross-check references".into(),
        )));
    }
    // Parent keys: the "id" column of every table, keyed by table stem.
    let mut parent_ids: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        Default::default();
    for (file, header, rows) in &tables {
        let stem = file
            .rsplit('/')
            .next()
            .unwrap_or("")
            .split('.')
            .next()
            .unwrap_or("")
            .to_lowercase();
        let Some(ii) = header
            .iter()
            .position(|c| c.trim().eq_ignore_ascii_case("id"))
        else {
            continue;
        };
        let ids = rows
            .iter()
            .filter_map(|r| r.get(ii).map(|v| v.trim().to_string()))
            .filter(|v| !v.is_empty())
            .collect();
        parent_ids.insert(stem, ids);
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
        for (ci, col) in header.iter().enumerate() {
            let l = col.trim().to_lowercase();
            let Some(target) = l.strip_suffix("_id") else {
                continue;
            };
            // Accept singular/plural matching against a table stem ("user_id" -> users or user).
            let parent = [
                target.to_string(),
                format!("{target}s"),
                target.trim_end_matches('s').to_string(),
            ]
            .into_iter()
            .find(|p| parent_ids.contains_key(p) && *p != stem);
            let Some(parent) = parent else { continue };
            let keys = &parent_ids[&parent];
            let mut orphans: Vec<(usize, String)> = Vec::new();
            for (ri, row) in rows.iter().enumerate() {
                if let Some(v) = row.get(ci) {
                    let v = v.trim();
                    if !v.is_empty() && !keys.contains(v) {
                        orphans.push((ri + 2, v.to_string()));
                    }
                }
            }
            if !orphans.is_empty() {
                let sample: Vec<String> = orphans
                    .iter()
                    .take(5)
                    .map(|(l, v)| format!("{v} (line {l})"))
                    .collect();
                defs.push(Def {
                    rule: "qa.data.orphan-reference",
                    cat: Category::Quality,
                    sev: Severity::Medium,
                    area: Area::Data,
                    title: format!(
                        "{col} references values missing from {parent} fixture ({} orphan(s))",
                        orphans.len()
                    ),
                    component: file.clone(),
                    expected: format!("Every {col} matches an id in the {parent} fixture"),
                    actual: sample.join("; "),
                    remediation: "Add the missing parent rows or correct the child references"
                        .into(),
                    fp_key: format!("{file}|{col}"),
                    steps: vec![
                        format!("Open {file}"),
                        format!("Compare {col} against the {parent} ids"),
                    ],
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
        "qa.data.orphan-reference",
        Area::Data,
        "data.orphan-reference",
        "Fixture foreign keys resolve",
        "fixtures",
        status,
        &format!("{n} orphaned reference column(s)"),
        defs,
    )))
}
