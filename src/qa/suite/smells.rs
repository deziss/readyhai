use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::*;

use super::common::{Def, MAX_ITEM_DEFECTS, is_test_path, no_snapshot, out, re, read, record};

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Smells {
    pub(crate) no_assert: Vec<String>,
    pub(crate) skipped: Vec<String>,
    pub(crate) sleeps: Vec<String>,
}

pub(crate) fn py_assertive(body: &str) -> bool {
    body.contains("assert")
        || body.contains("pytest.raises")
        || body.contains("pytest.fail")
        || body.contains(".raises(")
        || body.contains("pytest.warns")
        || body.contains("expect(")
}

pub(crate) fn scan_smells(file: &str, text: &str, s: &mut Smells) {
    let ext = file.rsplit('.').next().unwrap_or("");
    let lines: Vec<&str> = text.lines().collect();
    let loc = |i: usize| format!("{file}:{}", i + 1);
    let sleep_py = re(r"\btime\.sleep\(\s*([0-9.]+)");
    let sleep_js = re(r"\bsetTimeout\([^;]*?,\s*([0-9_]+)\s*\)");
    let sleep_java = re(r"\bThread\.sleep\(\s*([0-9_]+)");
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        if t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        match ext {
            "py" => {
                if t.starts_with("@pytest.mark.skip")
                    || t.starts_with("@unittest.skip")
                    || t.starts_with("@skip")
                {
                    s.skipped.push(loc(i));
                }
                if let Some(c) = sleep_py.captures(l)
                    && c[1].parse::<f64>().unwrap_or(1.0) >= 1.0
                {
                    s.sleeps.push(loc(i));
                }
            }
            "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => {
                if re(r"\b(?:it|test|describe)\.skip\(|\bx(?:it|describe|test)\(").is_match(l) {
                    s.skipped.push(loc(i));
                }
                if let Some(c) = sleep_js.captures(l)
                    && c[1].replace('_', "").parse::<u64>().unwrap_or(0) >= 1000
                {
                    s.sleeps.push(loc(i));
                }
            }
            "java" | "kt" => {
                if t.starts_with("@Disabled") || t.starts_with("@Ignore") {
                    s.skipped.push(loc(i));
                }
                if let Some(c) = sleep_java.captures(l)
                    && c[1].replace('_', "").parse::<u64>().unwrap_or(0) >= 1000
                {
                    s.sleeps.push(loc(i));
                }
            }
            _ => {}
        }
    }
    match ext {
        "py" => {
            let def = re(r"^(\s*)(?:async\s+)?def\s+(test_\w*)\s*\(");
            let mut i = 0;
            while i < lines.len() {
                if let Some(c) = def.captures(lines[i]) {
                    let ind = c[1].len();
                    let mut j = i + 1;
                    let mut body = String::new();
                    while j < lines.len() {
                        let l = lines[j];
                        if !l.trim().is_empty() && l.len() - l.trim_start().len() <= ind {
                            break;
                        }
                        body.push_str(l);
                        body.push('\n');
                        j += 1;
                    }
                    if !py_assertive(&body) {
                        s.no_assert.push(format!("{}:{} {}", file, i + 1, &c[2]));
                    }
                    i = j.max(i + 1);
                } else {
                    i += 1;
                }
            }
        }
        "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => {
            let start = re(r#"^\s*(?:it|test)\(\s*['"`]([^'"`]*)['"`]"#);
            for (i, l) in lines.iter().enumerate() {
                if let Some(c) = start.captures(l) {
                    let (mut depth, mut seen, mut body) = (0i32, false, String::new());
                    for l2 in &lines[i..] {
                        for ch in l2.chars() {
                            if ch == '{' {
                                depth += 1;
                                seen = true;
                            } else if ch == '}' {
                                depth -= 1;
                            }
                        }
                        body.push_str(l2);
                        body.push('\n');
                        if seen && depth <= 0 {
                            break;
                        }
                    }
                    if seen
                        && !(body.contains("expect")
                            || body.contains("assert")
                            || body.contains(".should"))
                    {
                        s.no_assert.push(format!("{}:{} {}", file, i + 1, &c[1]));
                    }
                }
            }
        }
        _ => {}
    }
}

/// `file:line rest` -> (file, line, rest).
pub(crate) fn split_loc(entry: &str) -> (String, String, String) {
    let (loc, rest) = entry.split_once(' ').unwrap_or((entry, ""));
    let (file, line) = loc.rsplit_once(':').unwrap_or((loc, ""));
    (file.to_string(), line.to_string(), rest.to_string())
}

/// One defect per smell. Identity never uses a line number: a test without assertions is keyed by
/// file + test name; skipped tests / sleeps by file + their ordinal within the file, so adding one
/// more of them in a file that already has some is a new fingerprint.
pub(crate) fn smell_defs(s: &Smells) -> Vec<Def> {
    let mut defs: Vec<Def> = vec![];
    let mk = |kind: &str, file: &str, line: &str, name: &str, key: String| {
        let (title, expected, rem) = match kind {
            "no_assert" => (
                format!("Test `{name}` has no assertions ({file})"),
                "every test asserts something",
                "Add assertions.",
            ),
            "skipped" => (
                format!("Skipped test in {file}"),
                "no test is silently skipped",
                "Fix or delete the skipped test.",
            ),
            _ => (
                format!("Sleep of 1s or more in a test ({file})"),
                "tests do not rely on sleeps",
                "Replace the sleep with polling or a fake clock.",
            ),
        };
        Def {
            rule: "qa.suite.test_smells",
            cat: Category::Quality,
            sev: Severity::Low,
            area: Area::Suite,
            title,
            component: file.to_string(),
            expected: expected.into(),
            actual: format!(
                "{file}:{line}{}",
                if name.is_empty() {
                    String::new()
                } else {
                    format!(" {name}")
                }
            ),
            remediation: rem.into(),
            fp_key: key,
            steps: vec![format!("Open {file}:{line}")],
        }
    };
    let mut ordinal: std::collections::BTreeMap<(String, &str), usize> = Default::default();
    for (kind, items) in [
        ("no_assert", &s.no_assert),
        ("skipped", &s.skipped),
        ("sleep", &s.sleeps),
    ] {
        for e in items.iter() {
            if defs.len() >= MAX_ITEM_DEFECTS {
                break;
            }
            let (file, line, name) = split_loc(e);
            let key = if kind == "no_assert" {
                format!("smell:no_assert:{file}:{name}")
            } else {
                let n = ordinal.entry((file.clone(), kind)).or_insert(0);
                *n += 1;
                format!("smell:{kind}:{file}:{n}")
            };
            defs.push(mk(kind, &file, &line, &name, key));
        }
    }
    let total = s.no_assert.len() + s.skipped.len() + s.sleeps.len();
    if total > defs.len() {
        defs.push(Def {
            rule: "qa.suite.test_smells",
            cat: Category::Quality,
            sev: Severity::Low,
            area: Area::Suite,
            title: format!("{} more test smells", total - defs.len()),
            component: "tests".into(),
            expected: "every test asserts, none are silently skipped or rely on sleeps".into(),
            actual: format!(
                "{} smell(s) beyond the first {MAX_ITEM_DEFECTS}",
                total - defs.len()
            ),
            remediation:
                "Add assertions, delete or fix skipped tests, replace sleeps with polling/fakes."
                    .into(),
            fp_key: "smell:overflow".into(),
            steps: vec![],
        });
    }
    defs
}

pub(crate) fn smells(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let mut s = Smells::default();
    let mut n_tests = 0;
    for f in &snap.files {
        if !is_test_path(f) || f.contains("node_modules/") {
            continue;
        }
        let ext = f.rsplit('.').next().unwrap_or("");
        if !matches!(
            ext,
            "py" | "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" | "java" | "kt"
        ) {
            continue;
        }
        if let Some(t) = read(snap, f) {
            n_tests += 1;
            scan_smells(f, &t, &mut s);
        }
    }
    if n_tests == 0 {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no test files".into(),
        )));
    }
    let total = s.no_assert.len() + s.skipped.len() + s.sleeps.len();
    let defs = smell_defs(&s);
    let st = if defs.is_empty() {
        ResultStatus::Pass
    } else {
        ResultStatus::Fail
    };
    Ok(out(record(
        ctx,
        "qa.suite.smells",
        Area::Suite,
        "suite.smells",
        "Tests are meaningful and stable",
        "tests",
        st,
        &format!("{total} smell(s) in {n_tests} test file(s)"),
        defs,
    )))
}
