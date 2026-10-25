//! Auth matrix: every operation x {anonymous, invalid token, each role}.
use super::synth;
use super::{DefectRef, NewDefect, Req, Runner, not_applicable};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Severity};
use crate::qa::model::*;

pub fn run(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(mut r) = Runner::new(ctx)? else { return Ok(not_applicable()) };
    let spec = r.spec.clone();
    let qa = r.qa;
    for rl in &qa.roles.roles {
        if !super::exec::role_usable(qa, rl) {
            qa.with(|c| c.notes.push(format!("role '{}' skipped: credential not available (env var {} unset?)", rl.name, rl.placeholder())));
        }
    }
    let roles = r.usable_roles();
    let mut stopped = false;
    for op in spec.ops.iter() {
        if matches!(op.method.as_str(), "HEAD" | "OPTIONS") {
            continue;
        }
        let key = op.key();
        if stopped {
            qa.with(|c| c.untested.push(format!("{key}: request budget exhausted (auth matrix)")));
            continue;
        }
        if op.is_write() && !qa.nonprod {
            qa.with(|c| {
                c.coverage.set(&key, "anon", Cell::Untested);
                c.untested.push(format!("{key}: auth matrix skipped (read-only: host not nonprod)"));
            });
            continue;
        }
        // Resource ids: real ones for reads, an unlikely one for writes (never touch real data).
        let ids = r.ids_for(op);
        let id = if op.is_write() { Some("999999".to_string()) } else { ids.first().cloned() };
        let pv = r.id_map(op, id.as_ref());
        let q: Vec<(String, String)> = op.params.iter().filter(|p| p.loc == "query" && p.required).map(|p| (p.name.clone(), synth::value_str(&synth::synth(&p.schema, &p.name, &r.tag, 0)))).collect();
        let body = op.body.as_ref().map(|b| synth::synth(b, "body", &r.tag, 0));
        let url = r.url(op, &pv, &q);
        let path = r.path_of(op, &pv);

        // anonymous + invalid token
        for (col, extra) in [("anon", vec![]), ("invalid", vec![("Authorization".to_string(), "Bearer readyhai-invalid-token".to_string())])] {
            if !op.secured {
                qa.with(|c| c.coverage.set(&key, col, Cell::NotApplicable));
                continue;
            }
            let cid = format!("api.{}.{}.authz.{col}", op.method, op.path);
            let exp = if col == "anon" { "401/403 without credentials" } else { "401 for an invalid token" };
            r.add_case(&cid, op, Technique::AuthMatrix, Priority::P1, &format!("{key} with {col} credentials"), None, vec![super::exec::curl_repro(&op.method, &url, None, body.as_ref())], exp);
            r.extra = extra;
            let res = r.send(&Req { op, role: None, case_id: &cid, kind: col, method: &op.method, url: &url, body: body.as_ref(), contract: false });
            r.extra = vec![];
            match res {
                Ok((ex, mut defs)) => {
                    let mut st = ResultStatus::Pass;
                    if ex.is_2xx() {
                        st = ResultStatus::Fail;
                        let d = r.defect(NewDefect {
                            rule: "qa.api.authz_missing", cat: Category::Security, sev: Severity::High, prio: Priority::P1,
                            title: format!("{key} is reachable with {} credentials", if col == "anon" { "no" } else { "invalid" }),
                            expected: format!("{exp} (operation is secured in the spec)"), actual: format!("HTTP {}", ex.status),
                            fp: format!("{key}|{col}"), remediation: "Enforce authentication on this route (default-deny middleware).",
                            area_cases: &cid, component: key.clone(), role: None, method: &op.method, url: &url, body: body.as_ref(), ex: Some(&ex),
                        });
                        defs.push(d);
                        if op.is_write() {
                            r.register_created(op, &ex, None);
                        }
                    } else if col == "invalid" && ex.status != 401 && ex.status < 500 && ex.status != 403 {
                        st = ResultStatus::Pass; // 400/404 etc: not exposed
                    }
                    if ex.status >= 500 {
                        st = ResultStatus::Fail;
                    }
                    let cell = if st == ResultStatus::Pass { Cell::Pass } else { Cell::Fail };
                    qa.with(|c| c.coverage.set(&key, col, cell));
                    r.result(&cid, st, &format!("HTTP {}", ex.status), ex.ms, &defs);
                }
                Err(e) => {
                    if e.contains("budget") {
                        stopped = true;
                    }
                    r.skip(&cid, &e);
                    qa.with(|c| c.coverage.set(&key, col, Cell::Untested));
                    if stopped {
                        break;
                    }
                }
            }
        }
        if stopped {
            continue;
        }
        for role in &roles {
            let exp = role.expects(&path);
            let col = role.name.as_str();
            let Some(allowed) = exp else {
                qa.with(|c| c.coverage.set(&key, col, Cell::Untested));
                continue;
            };
            if allowed && op.is_write() {
                qa.with(|c| c.coverage.set(&key, col, Cell::Untested));
                continue; // allowed writes are exercised by the stateful lifecycle
            }
            let cid = format!("api.{}.{}.authz.{col}", op.method, op.path);
            let e = if allowed { "access allowed (not 401/403)" } else { "401/403/404 (role is denied this path)" };
            r.add_case(&cid, op, Technique::AuthMatrix, Priority::P1, &format!("{key} as role {col}"), Some(col), vec![super::exec::curl_repro(&op.method, &url, Some(role), body.as_ref())], e);
            match r.send(&Req { op, role: Some(role), case_id: &cid, kind: col, method: &op.method, url: &url, body: body.as_ref(), contract: false }) {
                Ok((ex, mut defs)) => {
                    let mut st = ResultStatus::Pass;
                    if !allowed && ex.is_2xx() {
                        st = ResultStatus::Fail;
                        let d: DefectRef = r.defect(NewDefect {
                            rule: "qa.api.privilege_escalation", cat: Category::Security, sev: Severity::High, prio: Priority::P1,
                            title: format!("Role '{col}' can access {key} although roles.toml denies it"), expected: e.to_string(),
                            actual: format!("HTTP {}", ex.status), fp: format!("{key}|{col}"),
                            remediation: "Enforce role-based authorization on the server, not only in the UI.",
                            area_cases: &cid, component: key.clone(), role: Some(role), method: &op.method, url: &url, body: body.as_ref(), ex: Some(&ex),
                        });
                        defs.push(d);
                        if op.is_write() {
                            r.register_created(op, &ex, Some(role));
                        }
                    } else if allowed && matches!(ex.status, 401 | 403) {
                        st = ResultStatus::Fail;
                    }
                    if ex.status >= 500 {
                        st = ResultStatus::Fail;
                    }
                    let cell = if st == ResultStatus::Pass { Cell::Pass } else { Cell::Fail };
                    qa.with(|c| c.coverage.set(&key, col, cell));
                    r.result(&cid, st, &format!("HTTP {}", ex.status), ex.ms, &defs);
                }
                Err(e) => {
                    r.skip(&cid, &e);
                    qa.with(|c| c.coverage.set(&key, col, Cell::Untested));
                }
            }
        }
    }
    r.run_cleanup();
    Ok(CheckOutput::findings(std::mem::take(&mut r.findings)))
}
