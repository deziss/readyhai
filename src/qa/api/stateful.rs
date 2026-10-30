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

/// Does the re-read response carry `newv` in `field`? Looks through `{data:{...}}` wrappers.
fn persisted(ex: &Exchange, field_name: &str, newv: &Value) -> bool {
    ex.json()
        .and_then(|j| field(&j, field_name).cloned())
        .map(|v| &v == newv)
        .unwrap_or(false)
}

fn mutate(body: &Value, op: &Op) -> Option<(Value, String, Value)> {
    let o = body.as_object()?;
    let props = super::synth::flatten(op.body.as_ref()?);
    let props = props.get("properties")?.as_object()?.clone();
    for (k, v) in o {
        let ps = props.get(k)?;
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
        ok_result(&r, &ccid, &ex, true, "", &defs);
        defs.clear();
        let mut fail = false;
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
        }
        // update + persisted + idempotent
        if let (Some(put), Some(b0)) = (put, body.as_ref())
            && let Some((nb, field, newv)) = mutate(b0, put)
        {
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
                            ok_result(&r, &icid, &ex2, same, "", &defs);
                        }
                    }
                }
            }
        }
        // BOLA
        match b {
            None => qa.with(|c| {
                c.notes.push(
                    "BOLA checks skipped: need a second non-admin role with credentials".into(),
                )
            }),
            Some(b) => {
                let admin_like = |role: &Role, path: &str| {
                    role.expects(path) == Some(true)
                        && role.name.to_ascii_lowercase().contains("admin")
                };
                let gpath = r.path_of(get, &ipv);
                if admin_like(b, &gpath) {
                    qa.with(|c| {
                        c.notes.push(format!(
                            "BOLA skipped for {}: role '{}' is admin-like",
                            get.key(),
                            b.name
                        ))
                    });
                } else {
                    let mut targets: Vec<(&Op, &str, Option<Value>)> = vec![(get, "GET", None)];
                    if let (Some(p), Some(b0)) = (put, body.as_ref()) {
                        targets.push((
                            p,
                            p.method.as_str(),
                            mutate(b0, p).map(|x| x.0).or_else(|| Some(b0.clone())),
                        ));
                    }
                    for (op, m, bd) in targets {
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
                            ok_result(&r, &cid, &ex, !bad, "", &defs);
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
                            r.cleanup.push((durl.clone(), a.name.clone()));
                        }
                        ok_result(&r, &gcid, &ex2, gone, "", &defs);
                    }
                }
            }
        } else {
            qa.with(|c| {
                c.notes.push(format!(
                    "leftover: {pk} created resource {id} and the spec has no DELETE to clean up"
                ))
            });
        }
        qa.with(|c| {
            c.coverage
                .set(&pk, "stateful", if fail { Cell::Fail } else { Cell::Pass })
        });
    }
    r.explain_failures();
    r.run_cleanup();
    qa.with(|c| {
        c.notes.push(format!(
            "stateful: {resources} resource(s) created, tagged '{}'",
            r.tag
        ))
    });
    Ok(CheckOutput::findings(std::mem::take(&mut r.findings)))
}
