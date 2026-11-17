//! API functional test execution: positive, boundary, negative, and robustness checks.
use std::path::Path;

pub mod case_runner;
pub mod probes;

#[allow(unused_imports)]
pub use case_runner::{CaseRun, Outcome, run_case};
#[allow(unused_imports)]
pub use probes::{breaking, pagination, rate_limit_probe};

use crate::ctx::Ctx;
use crate::model::{CheckOutput, Profile};
use crate::qa::api::helpers::{not_applicable, unlikely_ids};
use crate::qa::api::planning::{plan_order, stateful_reserve};
use crate::qa::api::runner::{Runner, scratch_id};
use crate::qa::api::synth::{self, Case, Expect};
use crate::qa::model::{Cell, Priority, ResultStatus, Technique};

pub fn functional(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    functional_in(ctx, &crate::engine::data_dir())
}

/// `functional` with an explicit data dir (baselines), so tests never touch the real one.
pub fn functional_in(ctx: &Ctx, data: &Path) -> anyhow::Result<CheckOutput> {
    let Some(mut r) = Runner::new(ctx, "qa.api.functional")? else {
        return Ok(not_applicable());
    };
    let spec = r.spec.clone();
    let qa = r.qa;
    qa.with(|c| {
        c.untested.extend(spec.untested.iter().cloned());
        c.notes.extend(spec.notes.iter().cloned());
        // Operations beyond the cap are never planned: their coverage cell says Untested
        // instead of the matrix not knowing them (a missing row would read as "nothing to test").
        for k in &spec.over_cap {
            c.coverage.set(k, "functional", Cell::Untested);
        }
        if spec.over_cap_total > spec.over_cap.len() {
            c.notes.push(format!(
                "{} more operation(s) over the {}-operation cap are not listed in the coverage matrix",
                spec.over_cap_total - spec.over_cap.len(),
                spec.cap
            ));
        }
    });
    let deep = ctx.profile == Profile::Deep;
    let roles = r.usable_roles();
    let reserve = stateful_reserve(ctx, roles.len());
    let mut stopped: Option<String> = None;
    let mut cheapest: Option<(String, u128)> = None;
    // Is the target answering at all? Only then is silence on a malformed input a possible crash.
    if !r.alive() {
        qa.with(|c| c.notes.push("API target did not answer the initial probe: transport failures are reported as blocked, not as crashes".into()));
    }
    // Highest plan risk first; each operation gets at most its plan budget of cases.
    for pl in plan_order(qa, &spec) {
        let op = pl.op;
        if matches!(op.method.as_str(), "HEAD" | "OPTIONS") {
            continue;
        }
        let k = op.key();
        if stopped.is_none() && qa.remaining() <= reserve {
            stopped = Some(if reserve > 0 {
                "request budget reserved for the stateful checks".to_string()
            } else {
                "request budget exhausted".to_string()
            });
        }
        let role = roles
            .iter()
            .find(|x| x.expects(&op.path) != Some(false))
            .copied();
        // Real (harvested) ids are for reads only. A write (PUT/PATCH/DELETE/...) gets an id
        // nobody owns, so no generated body can ever modify or delete a real record; the case
        // then proves validation/contract, and a 404 for the unknown id is Blocked, not Pass.
        let idv = if stopped.is_some() || op.is_write() {
            vec![]
        } else {
            r.ids_for(op)
        };
        // PUT/PATCH get a resource THIS run created (so server-side validation is reachable, not
        // hidden behind a 404); everything else that writes gets the unlikely id.
        let scratch = if stopped.is_none() {
            scratch_id(&mut r, op, role)
        } else {
            None
        };
        let has_id = !idv.is_empty() || scratch.is_some();
        let ids0 = if op.is_write() {
            match &scratch {
                Some(id) => r.id_map(op, Some(id)),
                None => unlikely_ids(op),
            }
        } else {
            r.id_map(op, idv.first())
        };
        let mut cases: Vec<Case> = synth::generate(op, &r.tag, deep, &ids0);
        // Extra positive cases for the other harvested ids (catches per-record contract bugs).
        if !op.is_write() {
            for (i, id) in idv.iter().enumerate().skip(1) {
                let mut c = cases[0].clone();
                c.kind = format!("positive.{}", i + 1);
                c.path_vals = r.id_map(op, Some(id));
                cases.push(c);
            }
        }
        // writes: the positive case is covered by the stateful lifecycle
        cases.retain(|c| !(op.is_write() && c.kind.starts_with("positive")));
        let budget = pl.budget.max(1);
        if cases.len() > budget {
            let dropped = cases.len() - budget;
            cases.truncate(budget);
            qa.with(|c| c.untested.push(format!("{k}: {dropped} generated case(s) beyond the plan budget ({budget}) were not run")));
        }
        if let Some(why) = &stopped {
            qa.with(|c| c.untested.push(format!("{k}: {why}")));
        }
        let (mut op_fail, mut n_pass) = (false, 0usize);
        for case in cases {
            let cid = format!("api.{}.{}.{}", op.method, op.path, case.kind);
            let url = r.url(op, &case.path_vals, &case.query);
            let curl = crate::qa::api::exec::curl_repro(&op.method, &url, role, case.body.as_ref());
            let exp = match case.expect {
                Expect::Success => "2xx and a body matching the documented schema",
                Expect::Reject => "4xx (400/422) rejection of the invalid input",
                Expect::NoServerError => "no 5xx and no verbatim reflection",
            };
            r.add_case(
                &cid,
                op,
                case.technique,
                if case.kind == "positive" {
                    Priority::P2
                } else {
                    Priority::P3
                },
                &case.title,
                role.map(|x| x.name.as_str()),
                vec![curl],
                exp,
            );
            if op.is_write() && !qa.nonprod {
                r.skip(&cid, "read-only: host not nonprod");
                continue;
            }
            if let Some(why) = &stopped {
                r.skip(&cid, why); // planned but never run: counts against "cases executed"
                continue;
            }
            let cr = CaseRun {
                op,
                case: &case,
                role,
                cid: &cid,
                url: &url,
                has_id,
            };
            let out = match run_case(&mut r, &cr, true) {
                Ok(o) => o,
                Err(e) if e.contains("budget") => {
                    r.skip(&cid, &e);
                    stopped = Some(e);
                    continue;
                }
                Err(e) => {
                    r.skip(&cid, &e);
                    continue;
                }
            };
            let (mut status, mut attempts) = (out.status, 1);
            if status == ResultStatus::Fail && !op.is_write() {
                let rr = r.rerun(reserve, |me| {
                    run_case(me, &cr, false)
                        .ok()
                        .map(|o| o.status == ResultStatus::Fail)
                });
                r.note_reproduced(&out.defs, &rr);
                status = rr.status();
                attempts = rr.attempts;
            }
            match status {
                ResultStatus::Fail | ResultStatus::Flaky => op_fail = true,
                ResultStatus::Pass => {
                    n_pass += 1;
                    if case.expect == Expect::Success
                        && !op.is_write()
                        && op.path_params().count() == 0
                    {
                        let e = cheapest.get_or_insert((k.clone(), u128::MAX));
                        if out.ms < e.1 {
                            *e = (k.clone(), out.ms);
                        }
                    }
                }
                _ => {}
            }
            r.result_n(&cid, status, &out.actual, out.ms, &out.defs, attempts);
        }
        // "functional" is Pass only when something actually ran and passed.
        let cell = if op_fail {
            Cell::Fail
        } else if n_pass > 0 {
            Cell::Pass
        } else {
            Cell::Untested
        };
        qa.with(|c| c.coverage.set(&k, "functional", cell));
        if stopped.is_none() {
            pagination(&mut r, op, role, reserve);
        } else {
            for (name, val) in synth::pagination_probes(op)
                .into_iter()
                .filter(|_| op.method == "GET")
            {
                let cid = format!("api.{}.{}.pagination.{name}.{val}", op.method, op.path);
                r.add_case(
                    &cid,
                    op,
                    Technique::Boundary,
                    Priority::P3,
                    &format!("pagination {name}={val}"),
                    role.map(|x| x.name.as_str()),
                    vec![],
                    "no 5xx for edge paging values",
                );
                r.skip(
                    &cid,
                    stopped.as_deref().unwrap_or("request budget exhausted"),
                );
            }
        }
    }
    if stopped.is_none() && ctx.profile >= Profile::Standard {
        rate_limit_probe(&mut r, cheapest, &roles);
    }
    r.explain_failures();
    // Cleanup first: nothing below may skip it (errors here only become notes).
    r.run_cleanup();
    if let Err(e) = breaking(&mut r, data) {
        qa.with(|c| {
            c.notes
                .push(format!("spec baseline comparison skipped: {e:#}"))
        });
    }
    r.finish_latency();
    Ok(r.finish(true))
}
