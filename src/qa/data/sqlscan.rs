//! SQL seed-fixture hygiene: INSERTs without a WHERE-safe companion, unbalanced quotes,
//! and `DELETE`/`TRUNCATE`/`DROP` statements shipped inside *test fixtures* (a fixture that
//! wipes a table is an accident waiting for a shared staging DB).
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::{Area, ResultStatus};

use super::data_files;
use crate::qa::suite::common::{Def, MAX_ITEM_DEFECTS, no_snapshot, out, re, read, record};

pub(crate) fn sql_fixture(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let files = data_files(snap, &[".sql"]);
    if files.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no SQL fixtures found".into(),
        )));
    }
    let destructive = re(r"(?im)^\s*(DELETE\s+FROM|TRUNCATE|DROP\s+(TABLE|DATABASE))\b");
    let unbalanced = |line: &str| -> bool {
        !line.trim_start().starts_with("--") && line.matches('\'').count() % 2 == 1
    };
    let mut defs: Vec<Def> = Vec::new();
    for f in &files {
        let Some(text) = read(snap, f) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if let Some(m) = destructive.find(line) {
                defs.push(Def {
                    rule: "qa.data.sql-fixture",
                    cat: Category::Quality,
                    sev: Severity::High,
                    area: Area::Data,
                    title: format!(
                        "Destructive SQL (\"{}\") inside a test fixture",
                        m.as_str().trim()
                    ),
                    component: format!("{f}:{}", i + 1),
                    expected: "Fixtures only add data; teardown lives in test code or migrations"
                        .into(),
                    actual: line.trim().chars().take(120).collect(),
                    remediation:
                        "Move the cleanup into test teardown, or guard it against non-test DBs"
                            .into(),
                    fp_key: format!("{f}:{}", i + 1),
                    steps: vec![format!("Open {f}"), format!("Inspect line {}", i + 1)],
                });
            } else if unbalanced(line) {
                defs.push(Def {
                    rule: "qa.data.sql-fixture",
                    cat: Category::Quality,
                    sev: Severity::Medium,
                    area: Area::Data,
                    title: "Unbalanced single quote in SQL fixture".into(),
                    component: format!("{f}:{}", i + 1),
                    expected: "String literals are closed".into(),
                    actual: line.trim().chars().take(120).collect(),
                    remediation: "Close the literal or escape embedded quotes ('')".into(),
                    fp_key: format!("{f}:quotes:{}", i + 1),
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
        "qa.data.sql-fixture",
        Area::Data,
        "data.sql.hygiene",
        "SQL fixtures are additive and syntactically sound",
        "fixtures",
        status,
        &format!("{n} issue(s) across {} SQL fixture(s)", files.len()),
        defs,
    )))
}
