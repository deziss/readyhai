//! Specialized functional probes: pagination boundary tests, rate limit probes, and spec breaking changes.
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::model::{Category, Severity};
use crate::qa::api::baseline::stage_dir;
use crate::qa::api::contract;
use crate::qa::api::defect_types::{NewDefect, Req};
use crate::qa::api::exec;
use crate::qa::api::helpers::blocked_reason;
use crate::qa::api::runner::Runner;
use crate::qa::api::spec::{self, Op, Spec};
use crate::qa::api::synth;
use crate::qa::model::{Priority, ResultStatus, Technique};
use crate::qa::roles::Role;

pub fn pagination(r: &mut Runner, op: &Op, role: Option<&Role>, reserve: usize) {
    if op.method != "GET" {
        return;
    }
    let ids = r.ids_for(op);
    let pv = r.id_map(op, ids.first());
    for (name, val) in synth::pagination_probes(op) {
        let cid = format!("api.{}.{}.pagination.{name}.{val}", op.method, op.path);
        let url = r.url(op, &pv, &[(name.clone(), val.clone())]);
        r.add_case(
            &cid,
            op,
            Technique::Boundary,
            Priority::P3,
            &format!("pagination {name}={val}"),
            role.map(|x| x.name.as_str()),
            vec![exec::curl_repro("GET", &url, role, None)],
            "no 5xx for edge paging values",
        );
        let kind = format!("pagination.{name}={val}");
        let probe = |r: &mut Runner| {
            r.send(&Req {
                op,
                role,
                case_id: &cid,
                kind: &kind,
                method: "GET",
                url: &url,
                body: None,
                contract: false,
            })
        };
        match probe(r) {
            Ok((ex, _)) if ex.status == 0 => r.result(
                &cid,
                ResultStatus::Blocked,
                &format!("transport error: {}", ex.error.unwrap_or_default()),
                ex.ms,
                &[],
            ),
            Ok((ex, defs))
                if defs.is_empty() && blocked_reason(op, ex.status, !ids.is_empty()).is_some() =>
            {
                // a 401/403/429/redirect says nothing about paging edge cases
                r.result(
                    &cid,
                    ResultStatus::Blocked,
                    &format!(
                        "HTTP {}: {}",
                        ex.status,
                        blocked_reason(op, ex.status, !ids.is_empty()).unwrap_or_default()
                    ),
                    ex.ms,
                    &[],
                )
            }
            Ok((ex, defs)) if defs.is_empty() => r.result(
                &cid,
                ResultStatus::Pass,
                &format!("HTTP {}", ex.status),
                ex.ms,
                &[],
            ),
            Ok((ex, defs)) => {
                let rr = r.rerun(reserve, |me| {
                    probe(me).ok().map(|(e, d)| e.status != 0 && !d.is_empty())
                });
                r.note_reproduced(&defs, &rr);
                r.result_n(
                    &cid,
                    rr.status(),
                    &format!("HTTP {}", ex.status),
                    ex.ms,
                    &defs,
                    rr.attempts,
                );
            }
            Err(e) => r.skip(&cid, &e),
        }
    }
}

pub fn rate_limit_probe(
    r: &mut Runner,
    cheapest: Option<(String, u128)>,
    roles: &[&Role],
) {
    let Some((key, _)) = cheapest else { return };
    let Some(op) = r.spec.ops.iter().find(|o| o.key() == key).cloned() else {
        return;
    };
    let role = roles
        .iter()
        .find(|x| x.expects(&op.path) != Some(false))
        .copied();
    let url = r.url(&op, &HashMap::new(), &[]);
    let mut limited = false;
    let mut n = 0;
    for _ in 0..15 {
        match exec::send(r.qa, role, "GET", &url, None, &[]) {
            Ok(ex) => {
                n += 1;
                if ex.status == 429 {
                    limited = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let msg = if limited {
        format!("rate limiting observed on {key} (429 within {n} rapid requests)")
    } else {
        format!(
            "no rate limiting observed on {key} after {n} rapid requests (informational, not a defect)"
        )
    };
    r.qa.with(|c| c.notes.push(msg));
}

/// Compare the spec with the baseline spec (removed endpoints/fields, new required fields).
/// The current spec is always staged in the run dir so `baseline accept` can promote it; the first
/// run seeds the baseline.
pub fn breaking(r: &mut Runner, data: &Path) -> anyhow::Result<()> {
    let dir = data.join("baselines");
    let path = dir.join(format!(
        "{}.spec-full.json",
        crate::engine::target_key(&r.ctx.target)
    ));
    let st = stage_dir(&r.ctx.run_dir);
    std::fs::create_dir_all(&st)?;
    std::fs::write(st.join("spec-full.json"), serde_json::to_vec(&r.spec.raw)?)?;
    // A baseline that exists but cannot be read back is NOT silently replaced: it is kept as a
    // `.corrupt-<run>` backup, the run says so, and only then is a fresh baseline seeded.
    let loaded: Option<Spec> = match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        // unreadable for another reason (permissions, not a directory): leave it alone and say so
        Err(e) => anyhow::bail!(
            "cannot read the spec baseline {} (left untouched): {e}",
            path.display()
        ),
        Ok(t) => match serde_json::from_str::<Value>(&t)
            .map_err(|e| e.to_string())
            .and_then(|v| spec::parse(v).map_err(|e| format!("{e:#}")))
        {
            Ok(old) => Some(old),
            Err(why) => {
                let bak = path.with_extension(format!("json.corrupt-{}", r.ctx.run_id));
                let kept = std::fs::copy(&path, &bak).is_ok();
                r.qa.with(|c| {
                    c.notes.push(format!(
                        "spec baseline {} is corrupt ({why}): {}; no breaking-change comparison this run, a fresh baseline is stored from the current spec",
                        path.display(),
                        if kept { format!("backup kept as {}", bak.display()) } else { "COULD NOT back it up".into() }
                    ))
                });
                if !kept {
                    return Ok(()); // never overwrite what we could not preserve
                }
                None
            }
        },
    };
    match loaded {
        Some(old) => {
            for b in contract::breaking_changes(&old, &r.spec) {
                let base = r.base.clone();
                r.defect(NewDefect {
                    rule: "qa.api.breaking_change",
                    cat: Category::Quality,
                    sev: Severity::Medium,
                    prio: Priority::P3,
                    title: format!("Breaking API change on {}: {}", b.op, b.what),
                    expected: "backward-compatible API".into(),
                    actual: b.what.clone(),
                    fp: b.key.clone(),
                    remediation: "Version the API or restore the removed/required element; if the change is intended run `readyhai baseline accept <run>`.",
                    area_cases: "api.contract.breaking",
                    component: b.op.clone(),
                    role: None,
                    method: "GET",
                    url: &base,
                    body: None,
                    ex: None,
                });
            }
        }
        None => {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&path, serde_json::to_vec(&r.spec.raw)?)?;
            r.qa.with(|c| {
                c.notes.push(
                    "spec baseline stored (no breaking-change comparison on first run)".into(),
                )
            });
        }
    }
    Ok(())
}
