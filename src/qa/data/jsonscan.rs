//! JSON fixture scans: fixtures that do not even parse would poison every test that loads them.
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::{Area, ResultStatus};

use super::data_files;
use crate::qa::suite::common::{Def, MAX_ITEM_DEFECTS, no_snapshot, out, read, record};

pub(crate) fn invalid_format(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let files = data_files(snap, &[".json", ".jsonc"]);
    if files.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no JSON fixtures found".into(),
        )));
    }
    let mut defs: Vec<Def> = Vec::new();
    for f in &files {
        let Some(text) = read(snap, f) else {
            continue;
        };
        if f.ends_with(".jsonc") {
            continue; // comments are legal in .jsonc; serde would false-positive
        }
        if let Err(e) = serde_json::from_str::<serde_json::Value>(&text) {
            defs.push(Def {
                rule: "qa.data.invalid-format",
                cat: Category::Quality,
                sev: Severity::High,
                area: Area::Data,
                title: "JSON fixture does not parse".into(),
                component: f.clone(),
                expected: "Fixture files are valid JSON".into(),
                actual: e.to_string(),
                remediation: "Fix the syntax (quotes, commas, brackets) so tests can load it"
                    .into(),
                fp_key: f.clone(),
                steps: vec![format!("Open {f}"), "Run it through a JSON linter".into()],
            });
        }
    }
    let n = defs.len();
    defs.truncate(MAX_ITEM_DEFECTS);
    let status = if n > 0 { ResultStatus::Fail } else { ResultStatus::Pass };
    Ok(out(record(
        ctx,
        "qa.data.invalid-format",
        Area::Data,
        "data.json.parse",
        "JSON fixtures parse",
        "fixtures",
        status,
        &format!("{n} of {} JSON fixture(s) fail to parse", files.len()),
        defs,
    )))
}
