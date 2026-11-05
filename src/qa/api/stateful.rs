//! Stateful CRUD lifecycle (nonprod only): create -> read -> update -> BOLA -> delete.
use super::exec::{self, Exchange};
use super::spec::Op;
use super::{DefectRef, NewDefect, Req, Runner, created_id, field, not_applicable, plan_order};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::*;
use crate::qa::roles::Role;
use serde_json::Value;

struct Step<'a> {
    op: &'a Op,
    cid: String,
    title: String,
    role: Option<&'a Role>,
    method: &'a str,
    url: String,
    body: Option<Value>,
    expected: &'a str,
    contract: bool,
}

fn step(r: &mut Runner, s: &Step) -> Option<(Exchange, Vec<DefectRef>)> {
    r.add_case(
        &s.cid,
        s.op,
        Technique::StateTransition,
        Priority::P2,
        &s.title,
        s.role.map(|x| x.name.as_str()),
        vec![exec::curl_repro(s.method, &s.url, s.role, s.body.as_ref())],
        s.expected,
    );
    match r.send(&Req {
        op: s.op,
        role: s.role,
        case_id: &s.cid,
        kind: "state",
        method: s.method,
        url: &s.url,
        body: s.body.as_ref(),
        contract: s.contract,
    }) {
        Ok((ex, d)) if ex.status != 0 => Some((ex, d)),
        Ok((ex, _)) => {
            r.result(
                &s.cid,
                ResultStatus::Blocked,
                &format!("transport error: {}", ex.error.unwrap_or_default()),
                ex.ms,
                &[],
            );
            None
        }
        Err(e) => {
            r.skip(&s.cid, &e);
            None
        }
    }
}

fn ok_result(r: &Runner, cid: &str, ex: &Exchange, pass: bool, note: &str, defs: &[DefectRef]) {
    let st = if pass && defs.is_empty() {
        ResultStatus::Pass
    } else {
        ResultStatus::Fail
    };
    r.result(
        cid,
        st,
        format!("HTTP {} {note}", ex.status).trim(),
        ex.ms,
        defs,
    );
}

/// Statuses a role-B request can get that say nothing about ownership enforcement: its own
/// credential was refused (401), it was rate limited (429), the request was redirected, or the
/// input was rejected before any ownership check could matter. Not a Pass, not counted as a role
/// that tested authorization.
pub fn bola_blocked(status: u16) -> Option<&'static str> {
    match status {
        401 => Some("the role's credential was rejected (401)"),
        429 => Some("rate limited (429)"),
        300..=399 => Some("redirect not followed"),
        400 | 405 | 415 | 422 => Some("input rejected before ownership could be judged"),
        _ => None,
    }
}

/// Does the re-read response carry `newv` in `field`? Looks through `{data:{...}}` wrappers.
fn persisted(ex: &Exchange, field_name: &str, newv: &Value) -> bool {
    ex.json()
        .and_then(|j| field(&j, field_name).cloned())
        .map(|v| &v == newv)
        .unwrap_or(false)
}

pub(super) fn mutate(body: &Value, op: &Op) -> Option<(Value, String, Value)> {
    let o = body.as_object()?;
    let props = super::synth::flatten(op.body.as_ref()?);
    let props = props.get("properties")?.as_object()?.clone();
    for (k, v) in o {
        // a body key the PUT schema does not declare is not mutable here: try the next key
        // (never abort the whole mutation, that would silently skip the update step)
        let Some(ps) = props.get(k) else { continue };
        if let Some(s) = v.as_str()
            && ps.get("format").is_none()
            && ps.get("enum").is_none()
        {
            let max = ps.get("maxLength").and_then(|m| m.as_u64()).unwrap_or(1000) as usize;
            let mut n = format!("{s}-upd");
            super::synth::truncate_str(&mut n, max.min(super::synth::MAX_STR));
            if n != s {
                let mut b = o.clone();
                b.insert(k.clone(), Value::String(n.clone()));
                return Some((Value::Object(b), k.clone(), Value::String(n)));
            }
        }
    }
    None
}

pub fn run(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(mut r) = Runner::new(ctx, "qa.api.stateful")? else {
        return Ok(not_applicable());
    };
    if !r.qa.nonprod {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "read-only: host not nonprod".into(),
        )));
    }
    let spec = r.spec.clone();
    let qa = r.qa;
    let roles = r.usable_roles();
    let a = roles
        .iter()
        .find(|x| !x.name.to_ascii_lowercase().contains("admin"))
        .or(roles.first())
        .copied();
    let Some(a) = a else {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "no role with a usable credential".into(),
        )));
    };
    let b = roles
        .iter()
        .filter(|x| x.name != a.name)
        .find(|x| !x.name.to_ascii_lowercase().contains("admin"))
        .copied();
    let mut resources = 0;
    // Highest plan risk first (the request budget is shared and may run out).
    let order = plan_order(qa, &spec);
    for post in order
        .iter()
        .map(|p| &p.op)
        .filter(|o| o.method == "POST" && o.path_params().count() == 0)
    {
        let prefix = format!("{}/{{", post.path.trim_end_matches('/'));
        let find = |m: &str| {
            spec.ops.iter().find(|o| {
                o.method == m
                    && o.path.starts_with(&prefix)
                    && o.path[prefix.len()..].find('/').is_none()
                    && o.path_params().count() == 1
            })
        };
        let Some(get) = find("GET") else { continue };
        let put = find("PUT").or_else(|| find("PATCH"));
        let del = find("DELETE");
        let pk = post.key();
        let body = post
            .body
            .as_ref()
            .map(|b| super::synth::synth(b, "body", &r.tag, 0));
        let purl = r.url(post, &Default::default(), &[]);
        let ccid = format!("api.POST.{}.state.create", post.path);
        let Some((ex, mut defs)) = step(
            &mut r,
            &Step {
                op: post,
                cid: ccid.clone(),
                title: format!("{pk}: create a resource"),
                role: Some(a),
                method: "POST",
                url: purl.clone(),
                body: body.clone(),
                expected: "2xx and an id (Location or body)",
                contract: true,
            },
        ) else {
            continue;
        };
        let id = created_id(&ex);
        if !ex.is_2xx() || id.is_none() {
            // 5xx / defects from send(): a real failure. A rejected generated body or a response
            // without an id only means the lifecycle could not run: Blocked, never a silent Fail.
            let hard = !ex.is_2xx() && (ex.status >= 500 || !defs.is_empty());
            let why = if !ex.is_2xx() {
                format!("HTTP {}: lifecycle not run", ex.status)
            } else {
                "created, but no id in Location/body: lifecycle not run".into()
            };
            r.result(
                &ccid,
                if hard {
                    ResultStatus::Fail
                } else {
                    ResultStatus::Blocked
                },
                &why,
                ex.ms,
                &defs,
            );
            qa.with(|c| {
                c.coverage.set(
                    &pk,
                    "stateful",
                    if hard { Cell::Fail } else { Cell::Untested },
                )
            });
            continue;
        }
        let id = id.unwrap();
        resources += 1;
        // Cleanup is registered the moment the resource exists, before any later step can fail
        // or return early; a lifecycle that deletes it successfully un-registers it again.
        r.register_created(post, &ex, Some(a));
        ok_result(&r, &ccid, &ex, true, "", &defs);
        defs.clear();
        let mut fail = false;
        // lifecycle steps that were planned but could not run (coverage is not Pass with these)
        let mut skipped_steps: Vec<String> = vec![];
        let ipv = r.id_map(get, Some(&id));
        let gurl = r.url(get, &ipv, &[]);
        // read + echo
        let rcid = format!("api.GET.{}.state.read", get.path);
        if let Some((ex, mut defs)) = step(
            &mut r,
            &Step {
                op: get,
                cid: rcid.clone(),
                title: format!("{}: read back the created resource", get.key()),
                role: Some(a),
                method: "GET",
                url: gurl.clone(),
                body: None,
                expected: "200 and the submitted fields echoed",
                contract: true,
            },
        ) {
            let mut pass = ex.is_2xx();
            if let (Some(Value::Object(sent)), Some(got)) = (&body, ex.json()) {
                for (k, v) in sent {
                    if (v.is_string() || v.is_number())
                        && field(&got, k).map(|g| g != v).unwrap_or(false)
                    {
                        pass = false;
                        defs.push(r.defect(NewDefect {
                            rule: "qa.api.persistence_failure",
                            cat: Category::Quality,
                            sev: Severity::Medium,
                            prio: Priority::P2,
                            title: format!(
                                "{} does not return what {pk} stored ('{k}')",
                                get.key()
                            ),
                            expected: "created field echoed on read".into(),
                            actual: format!("field '{k}' differs after create"),
                            fp: format!("{}|echo|{k}", get.key()),
                            remediation: "Persist and return the submitted values faithfully.",
                            area_cases: &rcid,
                            component: get.key(),
                            role: Some(a),
                            method: "GET",
                            url: &gurl,
                            body: None,
                            ex: Some(&ex),
                        }));
                    }
                }
            }
            fail |= !pass;
            ok_result(&r, &rcid, &ex, pass, "", &defs);
        } else {
            skipped_steps.push("read-back (blocked or skipped)".into());
        }
        // update + persisted + idempotent
        let mutated = match (put, body.as_ref()) {
            (Some(put), Some(b0)) => {
                let m = mutate(b0, put);
                if m.is_none() {
                    skipped_steps.push(format!(
                        "update (no string field of the body can be changed through {})",
                        put.key()
                    ));
                }
                m.map(|m| (put, m))
            }
            (Some(put), None) => {
                skipped_steps.push(format!(
                    "update ({} needs a body the create did not send)",
                    put.key()
                ));
                None
            }
            _ => None, // the spec has no PUT/PATCH for the item: nothing was planned
        };
        if let Some((put, (nb, field, newv))) = mutated {
            let uurl = r.url(put, &r.id_map(put, Some(&id)), &[]);
            let ucid = format!("api.{}.{}.state.update", put.method, put.path);
            if let Some((ex, defs)) = step(
                &mut r,
                &Step {
                    op: put,
                    cid: ucid.clone(),
                    title: format!("{}: update the resource", put.key()),
                    role: Some(a),
                    method: &put.method,
                    url: uurl.clone(),
                    body: Some(nb.clone()),
                    expected: "2xx",
                    contract: true,
                },
            ) {
                fail |= !ex.is_2xx();
                ok_result(&r, &ucid, &ex, ex.is_2xx(), "", &defs);
                if ex.is_2xx() {
                    let pcid = format!("api.GET.{}.state.persisted", get.path);
                    if let Some((ex2, mut defs)) = step(
                        &mut r,
                        &Step {
                            op: get,
                            cid: pcid.clone(),
                            title: format!("{}: update persisted", get.key()),
                            role: Some(a),
                            method: "GET",
                            url: gurl.clone(),
                            body: None,
                            expected: "updated value visible on re-read",
                            contract: false,
                        },
                    ) {
                        let pass = persisted(&ex2, &field, &newv);
                        if !pass {
                            defs.push(r.defect(NewDefect {
                                rule: "qa.api.persistence_failure",
                                cat: Category::Quality,
                                sev: Severity::Medium,
                                prio: Priority::P2,
                                title: format!(
                                    "{} succeeded but the change to '{field}' is not persisted",
                                    put.key()
                                ),
                                expected: "updated value on re-read".into(),
                                actual: "re-read returns the old value".into(),
                                fp: format!("{}|persist|{field}", put.key()),
                                remediation: "Persist updates before returning success.",
                                area_cases: &pcid,
                                component: put.key(),
                                role: Some(a),
                                method: "GET",
                                url: &gurl,
                                body: None,
                                ex: Some(&ex2),
                            }));
                            fail = true;
                        }
                        ok_result(&r, &pcid, &ex2, pass, "", &defs);
                    } else {
                        skipped_steps.push("update-persisted re-read (blocked or skipped)".into());
                    }
                    if put.method == "PUT" {
                        let icid = format!("api.PUT.{}.state.idempotent", put.path);
                        if let Some((ex2, mut defs)) = step(
                            &mut r,
                            &Step {
                                op: put,
                                cid: icid.clone(),
                                title: format!("{}: repeat identical PUT", put.key()),
                                role: Some(a),
                                method: "PUT",
                                url: uurl.clone(),
                                body: Some(nb.clone()),
                                expected: "same status and body shape as the first PUT",
                                contract: false,
                            },
                        ) {
                            let shape = |e: &Exchange| {
                                e.json().and_then(|j| {
                                    j.as_object().map(|o| {
                                        let mut k: Vec<_> = o.keys().cloned().collect();
                                        k.sort();
                                        k
                                    })
                                })
                            };
                            let same = ex2.status == ex.status && shape(&ex2) == shape(&ex);
                            if !same {
                                defs.push(r.defect(NewDefect {
                                    rule: "qa.api.idempotency",
                                    cat: Category::Quality,
                                    sev: Severity::Low,
                                    prio: Priority::P3,
                                    title: format!("{} is not idempotent", put.key()),
                                    expected: "second identical PUT behaves like the first".into(),
                                    actual: format!("HTTP {} then HTTP {}", ex.status, ex2.status),
                                    fp: format!("{}|idempotency", put.key()),
                                    remediation: "Make PUT idempotent.",
                                    area_cases: &icid,
                                    component: put.key(),
                                    role: Some(a),
                                    method: "PUT",
                                    url: &uurl,
                                    body: Some(&nb),
                                    ex: Some(&ex2),
                                }));
                            }
                            fail |= !same;
                            ok_result(&r, &icid, &ex2, same, "", &defs);
                        } else {
                            skipped_steps.push("idempotent PUT repeat (blocked or skipped)".into());
                        }
                    }
                } else {
                    skipped_steps
                        .push("update-persisted and idempotency (the update was not 2xx)".into());
                }
            } else {
                skipped_steps.push("update (blocked or skipped)".into());
            }
        }
        // BOLA: only against a resource that is NOT public by design (an unsecured operation, or a
        // GET that answers an anonymous caller with 2xx, cannot be broken object-level auth), and
        // role B must actually be heard: a 401/429/redirect says nothing and is Blocked.
        match b {
            None => {
                skipped_steps.push("BOLA (needs a second non-admin role with credentials)".into());
                qa.with(|c| {
                    c.notes.push(
                        "BOLA checks skipped: need a second non-admin role with credentials".into(),
                    )
                })
            }
            Some(b) => {
                let admin_like = |role: &Role, path: &str| {
                    role.expects(path) == Some(true)
                        && role.name.to_ascii_lowercase().contains("admin")
                };
                let gpath = r.path_of(get, &ipv);
                if admin_like(b, &gpath) {
                    skipped_steps.push(format!("BOLA (role '{}' is admin-like)", b.name));
                    qa.with(|c| {
                        c.notes.push(format!(
                            "BOLA skipped for {}: role '{}' is admin-like",
                            get.key(),
                            b.name
                        ))
                    });
                } else {
                    // public by behaviour: an anonymous GET of the created resource succeeds
                    let anon_reads = get.secured
                        && exec::send(r.qa, None, "GET", &gurl, None, &[])
                            .map(|e| e.is_2xx())
                            .unwrap_or(false);
                    let mut targets: Vec<(&Op, &str, Option<Value>)> = vec![(get, "GET", None)];
                    if let (Some(p), Some(b0)) = (put, body.as_ref()) {
                        targets.push((
                            p,
                            p.method.as_str(),
                            mutate(b0, p).map(|x| x.0).or_else(|| Some(b0.clone())),
                        ));
                    }
                    for (op, m, bd) in targets {
                        if !op.secured || (m == "GET" && anon_reads) {
                            qa.with(|c| {
                                c.notes.push(format!(
                                    "BOLA skipped for {}: {}",
                                    op.key(),
                                    if !op.secured {
                                        "the operation is public in the spec (no security)"
                                    } else {
                                        "an anonymous GET of the created resource returns 2xx (public by behaviour)"
                                    }
                                ))
                            });
                            continue;
                        }
                        let url = r.url(op, &r.id_map(op, Some(&id)), &[]);
                        let cid = format!("api.{m}.{}.state.bola.{}", op.path, b.name);
                        if let Some((ex, mut defs)) = step(
                            &mut r,
                            &Step {
                                op,
                                cid: cid.clone(),
                                title: format!(
                                    "{}: other role '{}' accesses {}'s resource",
                                    op.key(),
                                    b.name,
                                    a.name
                                ),
                                role: Some(b),
                                method: m,
                                url: url.clone(),
                                body: bd.clone(),
                                expected: "403/404 for a resource owned by another user",
                                contract: false,
                            },
                        ) {
                            let bad = ex.is_2xx();
                            if bad {
                                defs.push(r.defect(NewDefect {
                                    rule: "qa.api.bola", cat: Category::Security, sev: Severity::Critical, prio: Priority::P1,
                                    title: format!("BOLA/IDOR: role '{}' can {} a resource created by '{}' via {}", b.name, if m == "GET" { "read" } else { "modify" }, a.name, op.key()),
                                    expected: "403/404 (ownership enforced per object)".into(), actual: format!("HTTP {}", ex.status),
                                    fp: format!("{}|{}", op.key(), b.name),
                                    remediation: "Authorize every object access against the caller's ownership/tenant. Ignore this finding if the resource is shared by design.",
                                    area_cases: &cid, component: op.key(), role: Some(b), method: m, url: &url, body: bd.as_ref(), ex: Some(&ex),
                                }));
                                fail = true;
                            }
                            match bola_blocked(ex.status).filter(|_| defs.is_empty() && !bad) {
                                Some(why) => {
                                    skipped_steps.push(format!(
                                        "BOLA {} as '{}': {why}",
                                        op.key(),
                                        b.name
                                    ));
                                    r.result(
                                        &cid,
                                        ResultStatus::Blocked,
                                        &format!(
                                            "HTTP {}: {why}; ownership enforcement not tested",
                                            ex.status
                                        ),
                                        ex.ms,
                                        &[],
                                    );
                                }
                                None => ok_result(&r, &cid, &ex, !bad, "", &defs),
                            }
                        } else {
                            skipped_steps.push(format!(
                                "BOLA {} as '{}' (blocked or skipped)",
                                op.key(),
                                b.name
                            ));
                        }
                    }
                }
            }
        }
        // delete + gone
        if let Some(del) = del {
            let durl = r.url(del, &r.id_map(del, Some(&id)), &[]);
            let dcid = format!("api.DELETE.{}.state.delete", del.path);
            if let Some((ex, defs)) = step(
                &mut r,
                &Step {
                    op: del,
                    cid: dcid.clone(),
                    title: format!("{}: delete the resource", del.key()),
                    role: Some(a),
                    method: "DELETE",
                    url: durl.clone(),
                    body: None,
                    expected: "2xx/204",
                    contract: true,
                },
            ) {
                let okd = ex.is_2xx();
                fail |= !okd;
                ok_result(&r, &dcid, &ex, okd, "", &defs);
                if okd {
                    let gcid = format!("api.GET.{}.state.gone", get.path);
                    if let Some((ex2, mut defs)) = step(
                        &mut r,
                        &Step {
                            op: get,
                            cid: gcid.clone(),
                            title: format!("{}: deleted resource is gone", get.key()),
                            role: Some(a),
                            method: "GET",
                            url: gurl.clone(),
                            body: None,
                            expected: "404 or 410",
                            contract: false,
                        },
                    ) {
                        let gone = matches!(ex2.status, 404 | 410);
                        if ex2.is_2xx() {
                            defs.push(r.defect(NewDefect {
                                rule: "qa.api.delete_not_effective", cat: Category::Quality, sev: Severity::High, prio: Priority::P2,
                                title: format!("{} returns success but the resource still exists", del.key()), expected: "404/410 after DELETE".into(),
                                actual: format!("DELETE HTTP {} then GET HTTP {}", ex.status, ex2.status), fp: format!("{}|delete_not_effective", del.key()),
                                remediation: "Actually remove (or soft-delete and hide) the resource.", area_cases: &gcid, component: del.key(),
                                role: Some(a), method: "GET", url: &gurl, body: None, ex: Some(&ex2),
                            }));
                            fail = true;
                            if !r.cleanup.iter().any(|(u, _)| *u == durl) {
                                r.cleanup.push((durl.clone(), a.name.clone()));
                            }
                        } else if gone {
                            // deleted AND proven gone: nothing is left to clean up
                            r.forget_cleanup(&durl);
                        }
                        fail |= !gone && !ex2.is_2xx();
                        ok_result(&r, &gcid, &ex2, gone, "", &defs);
                    } else {
                        skipped_steps.push("delete-then-gone re-read (blocked or skipped)".into());
                    }
                }
            } else {
                skipped_steps.push("delete (blocked or skipped)".into());
            }
        }
        // (no DELETE in the spec: `register_created` already recorded the leaked resource)
        let cell = if fail {
            Cell::Fail
        } else if skipped_steps.is_empty() {
            Cell::Pass
        } else {
            // some lifecycle steps never ran: the lifecycle is not proven
            Cell::Untested
        };
        if !skipped_steps.is_empty() {
            qa.with(|c| {
                c.notes.push(format!(
                    "stateful: {pk}: {} lifecycle step(s) skipped, coverage is not Pass: {}",
                    skipped_steps.len(),
                    skipped_steps.join("; ")
                ))
            });
        }
        qa.with(|c| c.coverage.set(&pk, "stateful", cell));
    }
    r.explain_failures();
    r.run_cleanup();
    qa.with(|c| {
        c.notes.push(format!(
            "stateful: {resources} resource(s) created, tagged '{}'",
            r.tag
        ))
    });
    Ok(r.finish(false))
}
