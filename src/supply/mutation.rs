use anyhow::Result;
use serde_json::Value;

use super::api_contract::{MAX_READ, read_snap};
use super::helpers::sv;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Severity};

/// Mutation score below this (percent) is a finding.
const MIN_MUTATION_SCORE: f64 = 60.0;

#[derive(Debug, Clone, PartialEq)]
pub struct MutationScore {
    pub tool: &'static str,
    pub detected: u64,
    /// Detected + survived (compile/unviable/ignored mutants excluded).
    pub total: u64,
}

impl MutationScore {
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.detected as f64 * 100.0 / self.total as f64
        }
    }
}

/// cargo-mutants `mutants.out/outcomes.json`.
pub fn parse_cargo_mutants(json: &str) -> Option<MutationScore> {
    let v: Value = serde_json::from_str(json).ok()?;
    let (mut caught, mut missed, mut timeout) = (0u64, 0u64, 0u64);
    if let Some(a) = v.get("outcomes").and_then(|x| x.as_array()) {
        for o in a {
            if o.get("scenario").and_then(|s| s.as_str()) == Some("Baseline") {
                continue;
            }
            match sv(o, "summary") {
                "CaughtMutant" => caught += 1,
                "MissedMutant" => missed += 1,
                "Timeout" => timeout += 1,
                _ => {}
            }
        }
    } else {
        let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        caught = n("caught");
        missed = n("missed");
        timeout = n("timeout");
    }
    Some(MutationScore {
        tool: "cargo-mutants",
        detected: caught + timeout,
        total: caught + timeout + missed,
    })
}

/// Stryker `reports/mutation/mutation.json` (mutation-testing-elements schema).
pub fn parse_stryker(json: &str) -> Option<MutationScore> {
    let v: Value = serde_json::from_str(json).ok()?;
    let files = v.get("files")?.as_object()?;
    let (mut det, mut surv) = (0u64, 0u64);
    for f in files.values() {
        for m in f.get("mutants")?.as_array()? {
            match sv(m, "status") {
                "Killed" | "Timeout" => det += 1,
                "Survived" | "NoCoverage" => surv += 1,
                _ => {}
            }
        }
    }
    Some(MutationScore {
        tool: "stryker",
        detected: det,
        total: det + surv,
    })
}

/// mutmut 3 `mutants/**/*.meta`: `exit_code_by_key` (0 = survived, null = not checked).
pub fn parse_mutmut_meta(json: &str) -> Option<MutationScore> {
    let v: Value = serde_json::from_str(json).ok()?;
    let m = v.get("exit_code_by_key")?.as_object()?;
    let (mut det, mut surv) = (0u64, 0u64);
    for c in m.values() {
        match c.as_i64() {
            Some(0) => surv += 1,
            Some(1 | 3 | 36 | -24) => det += 1,
            _ => {}
        }
    }
    Some(MutationScore {
        tool: "mutmut",
        detected: det,
        total: det + surv,
    })
}

pub(crate) fn mutation(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no repo snapshot".into(),
        )));
    };
    let ends = |f: &str, s: &str| f == s || f.ends_with(&format!("/{s}"));
    let mut reports: Vec<(String, MutationScore)> = vec![];
    let mut mutmut_meta: Option<(String, u64, u64)> = None;
    let mut v2_cache = false;
    let mut configured: Vec<&str> = vec![];
    for f in &snap.files {
        let leaf = f.rsplit('/').next().unwrap_or(f);
        let parsed = if ends(f, "mutants.out/outcomes.json") {
            read_snap(ctx, f, 64 * 1024 * 1024).and_then(|t| parse_cargo_mutants(&t))
        } else if ends(f, "reports/mutation/mutation.json") {
            read_snap(ctx, f, 64 * 1024 * 1024).and_then(|t| parse_stryker(&t))
        } else {
            None
        };
        if let Some(p) = parsed {
            reports.push((f.clone(), p));
        } else if leaf.ends_with(".meta") && f.split('/').any(|p| p == "mutants") {
            if let Some(p) = read_snap(ctx, f, MAX_READ).and_then(|t| parse_mutmut_meta(&t)) {
                let e = mutmut_meta.get_or_insert((f.clone(), 0, 0));
                e.1 += p.detected;
                e.2 += p.total;
            }
        } else if leaf == ".mutmut-cache" {
            v2_cache = true;
        } else if (ends(f, ".cargo/mutants.toml") || leaf == "mutants.toml")
            && !configured.contains(&"cargo-mutants")
        {
            configured.push("cargo-mutants");
        } else if leaf.starts_with("stryker.conf") || leaf.starts_with(".stryker.conf") {
            configured.push("Stryker");
        }
    }
    if let Some((f, det, total)) = mutmut_meta {
        reports.push((
            f.rsplit_once('/')
                .map(|x| x.0)
                .unwrap_or("mutants")
                .to_string(),
            MutationScore {
                tool: "mutmut",
                detected: det,
                total,
            },
        ));
    }
    if reports.is_empty() {
        let hint = if v2_cache {
            "mutmut v2 cache (.mutmut-cache) is SQLite; upgrade to mutmut 3 or run it in CI and keep mutants/"
        } else if !configured.is_empty() {
            "mutation config found but no report; run it in CI and keep the report (cargo mutants -> mutants.out/outcomes.json, stryker -> reports/mutation/mutation.json)"
        } else {
            "no mutation testing set up; try `cargo mutants`, Stryker or mutmut and keep the report"
        };
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(hint.into())));
    }
    let mut findings = vec![];
    let mut scored = 0;
    for (path, s) in &reports {
        if s.total == 0 {
            continue;
        }
        scored += 1;
        let pct = s.percent();
        if pct < MIN_MUTATION_SCORE {
            findings.push(
                Finding::new(
                    "qa.suite.mutation",
                    "qa.suite.low_mutation_score",
                    Category::Quality,
                    Severity::Medium,
                    format!(
                        "Mutation score is {pct:.0}% (below {MIN_MUTATION_SCORE:.0}%) [{}]",
                        s.tool
                    ),
                    path.clone(),
                )
                .fp_key(format!("{}|{path}", s.tool))
                .detail(format!(
                    "{} of {} viable mutants were detected by the tests ({}).",
                    s.detected, s.total, s.tool
                ))
                .remediation("Add assertions for the surviving mutants; review the report's survivors first."),
            );
        }
    }
    if scored == 0 {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "mutation report holds no scored mutants".into(),
        )));
    }
    Ok(CheckOutput::findings(findings))
}
