use std::collections::BTreeSet;
use std::fs;
use serde_json::Value;

use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Severity};
use crate::qa::model::*;

use super::common::{Def, MAX_ITEM_DEFECTS, out, record, untested};

pub(crate) fn sbom_licenses(j: &Value) -> Vec<(String, String)> {
    let mut v = vec![];
    for c in j
        .get("components")
        .and_then(|x| x.as_array())
        .into_iter()
        .flatten()
    {
        let name = c.get("name").and_then(|x| x.as_str()).unwrap_or("?");
        let ver = c.get("version").and_then(|x| x.as_str()).unwrap_or("");
        let id = if ver.is_empty() {
            name.to_string()
        } else {
            format!("{name}@{ver}")
        };
        let mut any = false;
        for l in c
            .get("licenses")
            .and_then(|x| x.as_array())
            .into_iter()
            .flatten()
        {
            let s = l
                .pointer("/license/id")
                .or_else(|| l.pointer("/license/name"))
                .or_else(|| l.get("expression"))
                .and_then(|x| x.as_str());
            if let Some(s) = s {
                v.push((id.clone(), s.to_string()));
                any = true;
            }
        }
        if !any {
            v.push((id, "UNKNOWN".into()));
        }
    }
    v
}

pub(crate) fn deny_matches(deny: &[String], lic: &str) -> bool {
    let l = lic.to_lowercase();
    deny.iter().any(|d| {
        let d = d.trim().to_lowercase();
        if d.is_empty() {
            return false;
        }
        match d.strip_suffix('*') {
            Some(p) => l.starts_with(p),
            None => l == d,
        }
    })
}

pub(crate) fn parse_deny(env: &str) -> Vec<String> {
    env.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub(crate) fn licenses_eval(ctx: &Ctx, j: &Value, deny: &[String]) -> Vec<Finding> {
    let all = sbom_licenses(j);
    let distinct: BTreeSet<&str> = all.iter().map(|(_, l)| l.as_str()).collect();
    if deny.is_empty() {
        // Without a deny policy compliance was not evaluated: Skipped + an untested note.
        let why = format!(
            "licence compliance not evaluated: {} component licence(s), {} distinct, but no deny policy is configured (set [license] deny in readyhai.toml or READYHAI_LICENSE_DENY)",
            all.len(),
            distinct.len()
        );
        untested(ctx, &why);
        if let Some(qa) = &ctx.qa {
            qa.with(|c| c.notes.push(why.clone()));
        }
        return record(
            ctx,
            "qa.release.licenses",
            Area::Release,
            "release.licenses",
            "Dependency licences comply with policy",
            "sbom",
            ResultStatus::Skipped,
            &format!(
                "{} distinct licence(s) found; no deny policy, so none was judged",
                distinct.len()
            ),
            vec![],
        );
    }
    let bad: Vec<(String, String)> = all
        .iter()
        .filter(|(_, l)| deny_matches(deny, l))
        .cloned()
        .collect();
    let mut defs = vec![];
    // One defect per (package, denied licence); the version is not part of the identity, so a
    // version bump does not re-open an accepted finding but a NEW package does gate.
    let mut seen = BTreeSet::new();
    for (comp, lic) in bad.iter() {
        let name = comp
            .rsplit_once('@')
            .filter(|(n, _)| !n.is_empty())
            .map(|x| x.0)
            .unwrap_or(comp);
        if !seen.insert((name.to_string(), lic.clone())) {
            continue;
        }
        if defs.len() >= MAX_ITEM_DEFECTS {
            break;
        }
        defs.push(Def {
            rule: "qa.release.license",
            cat: Category::SupplyChain,
            sev: Severity::High,
            area: Area::Release,
            title: format!("{comp} uses a denied licence ({lic})"),
            component: name.to_string(),
            expected: format!("no licence matching deny list ({})", deny.join(", ")),
            actual: format!("{comp}: {lic}"),
            remediation: "Replace the dependency, obtain a commercial licence, or adjust the policy with legal sign-off.".into(),
            fp_key: format!("license:{name}:{lic}"),
            steps: vec![format!("Inspect licenses[] of {comp} in sbom.cdx.json")],
        });
    }
    if seen.len() > MAX_ITEM_DEFECTS {
        defs.push(Def {
            rule: "qa.release.license",
            cat: Category::SupplyChain,
            sev: Severity::High,
            area: Area::Release,
            title: format!(
                "{} more dependencies use a denied licence",
                seen.len() - MAX_ITEM_DEFECTS
            ),
            component: "sbom.cdx.json".into(),
            expected: format!("no licence matching deny list ({})", deny.join(", ")),
            actual: bad
                .iter()
                .skip(MAX_ITEM_DEFECTS)
                .take(50)
                .map(|(c, l)| format!("{c}: {l}"))
                .collect::<Vec<_>>()
                .join("\n"),
            remediation: "Replace the dependencies or adjust the policy with legal sign-off."
                .into(),
            fp_key: "license:overflow".into(),
            steps: vec![],
        });
    }
    let st = if defs.is_empty() {
        ResultStatus::Pass
    } else {
        ResultStatus::Fail
    };
    record(
        ctx,
        "qa.release.licenses",
        Area::Release,
        "release.licenses",
        "Dependency licences comply with policy",
        "sbom",
        st,
        &format!("{} denied of {} component licence(s)", bad.len(), all.len()),
        defs,
    )
}

pub(crate) fn licenses(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let p = ctx.out_dir().join("sbom.cdx.json");
    let Some(j) = fs::read_to_string(&p)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    else {
        untested(
            ctx,
            "licence policy not evaluated: no sbom.cdx.json (tool.sbom_cve did not run)",
        );
        record(
            ctx,
            "qa.release.licenses",
            Area::Release,
            "release.licenses",
            "Dependency licences comply with policy",
            "sbom",
            ResultStatus::Blocked,
            "no SBOM available",
            vec![],
        );
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "no sbom.cdx.json in run output".into(),
        )));
    };
    let mut deny = ctx.cfg.license.deny.clone();
    deny.extend(parse_deny(
        &std::env::var("READYHAI_LICENSE_DENY").unwrap_or_default(),
    ));
    let findings = licenses_eval(ctx, &j, &deny);
    if deny.is_empty() {
        // no policy = nothing was judged: Skipped (visible), never a green "licences comply"
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "no licence deny policy configured (set [license] deny or READYHAI_LICENSE_DENY): licences were listed, not judged".into(),
        )));
    }
    Ok(out(findings))
}
