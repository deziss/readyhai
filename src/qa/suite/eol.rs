use serde_json::Value;
use std::collections::BTreeSet;

use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Severity};
use crate::qa::model::*;
use crate::snapshot::Snapshot;

use super::common::{Def, no_snapshot, out, re, read, record};

pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub(crate) fn day_num(date: &str) -> Option<i64> {
    let mut it = date.get(..10)?.split('-');
    let y = it.next()?.parse().ok()?;
    let m = it.next()?.parse().ok()?;
    let d = it.next()?.parse().ok()?;
    Some(days_from_civil(y, m, d))
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Runtime {
    pub(crate) product: &'static str,
    pub(crate) version: String,
    pub(crate) source: String,
    /// "exact" (image tag, .python-version, ...) or "min" (>= range lower bound).
    pub(crate) exact: bool,
}

#[derive(Debug, PartialEq)]
pub(crate) enum EolState {
    Eol(String),
    Soon(String, i64),
}

pub(crate) fn debian_codename(t: &str) -> Option<&'static str> {
    Some(match t {
        "jessie" => "8",
        "stretch" => "9",
        "buster" => "10",
        "bullseye" => "11",
        "bookworm" => "12",
        "trixie" => "13",
        _ => return None,
    })
}

pub(crate) fn ubuntu_codename(t: &str) -> Option<&'static str> {
    Some(match t {
        "xenial" => "16.04",
        "bionic" => "18.04",
        "focal" => "20.04",
        "jammy" => "22.04",
        "noble" => "24.04",
        _ => return None,
    })
}

pub(crate) fn from_images(text: &str, file: &str) -> Vec<Runtime> {
    let from = re(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?");
    let mut stages: Vec<String> = vec![];
    let mut out = vec![];
    for c in from.captures_iter(text) {
        let img = c[1].to_string();
        let alias = c.get(2).map(|a| a.as_str().to_lowercase());
        if !stages.contains(&img.to_lowercase()) && !img.contains("$") {
            let base = img.split('@').next().unwrap_or("");
            let last = base.rsplit('/').next().unwrap_or("");
            let (name, tag) = last.split_once(':').unwrap_or((last, ""));
            let product = match name {
                "python" => Some("python"),
                "node" => Some("nodejs"),
                "ubuntu" => Some("ubuntu"),
                "debian" => Some("debian"),
                "alpine" => Some("alpine"),
                "golang" => Some("go"),
                "postgres" => Some("postgresql"),
                _ => None,
            };
            if let Some(p) = product {
                let version = tag_version(p, tag);
                if let Some(v) = version {
                    out.push(Runtime {
                        product: p,
                        version: v,
                        source: file.to_string(),
                        exact: true,
                    });
                }
            }
        }
        if let Some(a) = alias {
            stages.push(a);
        }
    }
    out
}

pub(crate) fn tag_version(product: &str, tag: &str) -> Option<String> {
    if tag.is_empty() || tag == "latest" {
        return None;
    }
    let head = tag.split('-').next().unwrap_or(tag);
    if product == "debian"
        && let Some(v) = debian_codename(head)
    {
        return Some(v.into());
    }
    if product == "ubuntu"
        && let Some(v) = ubuntu_codename(head)
    {
        return Some(v.into());
    }
    if let Some(c) = re(r"^v?(\d+(?:\.\d+)*)").captures(head) {
        return Some(c[1].to_string());
    }
    // python:3.8-slim-bookworm etc. handled above; debian "bookworm-slim" handled by head.
    None
}

pub(crate) fn range_min(spec: &str) -> Option<(String, bool)> {
    let s = spec.trim();
    let c = re(r"^(>=|>|==|~=|\^|~|<=|<)?\s*v?(\d+(?:\.\d+)*)").captures(s)?;
    let op = c.get(1).map(|m| m.as_str()).unwrap_or("");
    let exact = op.is_empty() || op == "==";
    if op.starts_with('<') {
        return None;
    }
    Some((c[2].to_string(), exact))
}

pub(crate) fn runtime_hints(snap: &Snapshot) -> Vec<Runtime> {
    let mut v = vec![];
    for f in &snap.files {
        let name = f.rsplit('/').next().unwrap_or(f);
        match name {
            "pyproject.toml" => {
                if let Some(t) = read(snap, f)
                    && let Some(c) =
                        re(r#"(?m)^\s*requires-python\s*=\s*["']([^"']+)["']"#).captures(&t)
                {
                    // first clause only (">=3.8,<4")
                    let first = c[1].split(',').next().unwrap_or("");
                    if let Some((ver, exact)) = range_min(first) {
                        v.push(Runtime {
                            product: "python",
                            version: ver,
                            source: f.clone(),
                            exact,
                        });
                    }
                }
            }
            "package.json" if !f.contains("node_modules/") => {
                if let Some(j) = read(snap, f).and_then(|t| serde_json::from_str::<Value>(&t).ok())
                    && let Some(n) = j.pointer("/engines/node").and_then(|x| x.as_str())
                {
                    let first = n
                        .split("||")
                        .next()
                        .unwrap_or(n)
                        .split_whitespace()
                        .next()
                        .unwrap_or("");
                    let first = first.trim_end_matches(".x").trim_end_matches(".*");
                    if let Some((ver, exact)) = range_min(first) {
                        v.push(Runtime {
                            product: "nodejs",
                            version: ver,
                            source: f.clone(),
                            exact,
                        });
                    }
                }
            }
            ".python-version" | ".nvmrc" | ".node-version" => {
                if let Some(t) = read(snap, f)
                    && let Some(c) = re(r"(\d+(?:\.\d+)*)").captures(t.trim())
                {
                    let p = if name == ".python-version" {
                        "python"
                    } else {
                        "nodejs"
                    };
                    v.push(Runtime {
                        product: p,
                        version: c[1].to_string(),
                        source: f.clone(),
                        exact: true,
                    });
                }
            }
            _ => {}
        }
    }
    v
}

/// Look up `version` in the EOL table, trying progressively shorter prefixes (3.8.10 -> 3.8 -> 3).
pub(crate) fn eol_date(table: &Value, product: &str, version: &str) -> Option<(String, String)> {
    let cycles = table.get(product)?.as_array()?;
    let parts: Vec<&str> = version.split('.').collect();
    for n in (1..=parts.len()).rev() {
        let cand = parts[..n].join(".");
        if let Some(c) = cycles
            .iter()
            .find(|c| c.get("cycle").and_then(|x| x.as_str()) == Some(cand.as_str()))
        {
            let e = match c.get("eol") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Bool(true)) => "1970-01-01".into(),
                _ => return None,
            };
            return Some((cand, e));
        }
    }
    None
}

pub(crate) fn eol_state(table: &Value, rt: &Runtime, today: &str) -> Option<(String, EolState)> {
    let (cycle, date) = eol_date(table, rt.product, &rt.version)?;
    let (t, e) = (day_num(today)?, day_num(&date)?);
    if e < t {
        Some((cycle, EolState::Eol(date)))
    } else if e - t <= 180 {
        Some((cycle, EolState::Soon(date, e - t)))
    } else {
        None
    }
}

pub(crate) fn eol_eval(ctx: &Ctx, table: &Value, rts: &[Runtime], today: &str) -> Vec<Finding> {
    let mut defs = vec![];
    let mut seen = BTreeSet::new();
    for rt in rts {
        let Some((cycle, st)) = eol_state(table, rt, today) else {
            continue;
        };
        if !seen.insert((rt.product, cycle.clone(), rt.source.clone())) {
            continue;
        }
        let (sev, title, actual) = match (&st, rt.exact) {
            (EolState::Eol(d), true) => (
                Severity::High,
                format!("{} {} reached end of life on {d}", rt.product, cycle),
                format!("{} {} (EOL {d}) in {}", rt.product, cycle, rt.source),
            ),
            (EolState::Eol(d), false) => (
                Severity::Low,
                format!(
                    "{} {} (EOL {d}) is still within the supported range",
                    rt.product, cycle
                ),
                format!(
                    "{} declares support from {} (EOL {d})",
                    rt.source, rt.version
                ),
            ),
            (EolState::Soon(d, n), true) => (
                Severity::Medium,
                format!(
                    "{} {} reaches end of life in {n} days ({d})",
                    rt.product, cycle
                ),
                format!("{} {} (EOL {d}) in {}", rt.product, cycle, rt.source),
            ),
            (EolState::Soon(d, n), false) => (
                Severity::Low,
                format!(
                    "{} {} (declared minimum) ends support in {n} days ({d})",
                    rt.product, cycle
                ),
                format!("{} declares support from {}", rt.source, rt.version),
            ),
        };
        defs.push(Def {
            rule: "qa.release.eol_runtime",
            cat: Category::SupplyChain,
            sev,
            area: Area::Release,
            title,
            component: rt.source.clone(),
            expected: "runtimes and base images are inside their vendor support window".into(),
            actual,
            remediation: format!("Upgrade {} to a supported release.", rt.product),
            fp_key: format!("eol:{}:{}:{}", rt.product, cycle, rt.source),
            steps: vec![format!(
                "Check {} against https://endoflife.date/{}",
                rt.source, rt.product
            )],
        });
    }
    let n = defs.len();
    let st = if n == 0 {
        ResultStatus::Pass
    } else {
        ResultStatus::Fail
    };
    record(
        ctx,
        "qa.release.eol",
        Area::Release,
        "release.eol",
        "Runtimes are supported",
        ".",
        st,
        &format!(
            "{} runtime reference(s) checked, {n} at or near EOL",
            rts.len()
        ),
        defs,
    )
}

pub(crate) fn eol(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let table = crate::bundle::endoflife();
    let mut rts = vec![];
    for f in &ctx.facts.dockerfiles {
        if let Some(t) = read(snap, f) {
            rts.extend(from_images(&t, f));
        }
    }
    rts.extend(runtime_hints(snap));
    if rts.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no runtime versions detected".into(),
        )));
    }
    Ok(out(eol_eval(ctx, &table, &rts, &crate::engine::today())))
}
