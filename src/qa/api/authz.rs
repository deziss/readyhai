//! Auth matrix: every operation x {anonymous, invalid token, each role}. Runs FIRST among the API
//! checks (P1 cases must not be starved by the shared request budget) and in plan-risk order.
use super::synth;
use super::{DefectRef, NewDefect, Req, Runner, not_applicable, plan_order};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Severity};
use crate::qa::model::*;
use crate::qa::roles::Role;

/// Who sends the request and what the spec / roles.toml say about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    Anon,
    Invalid,
    /// A configured role; `allowed` comes from its allow/deny globs.
    Role { allowed: bool },
}

/// Pure judgement of one response (status 0 = no response): the result status and the rule of
/// the defect to raise, if any. 5xx is Fail without a rule here: `Runner::send` already raised
/// `qa.api.server_error` for it.
pub fn judge(subject: Subject, status: u16) -> (ResultStatus, Option<&'static str>) {
    if status == 0 {
        return (ResultStatus::Blocked, None);
    }
    let ok2 = (200..300).contains(&status);
    let denied = matches!(status, 401 | 403);
    match subject {
        Subject::Anon | Subject::Invalid if ok2 => (ResultStatus::Fail, Some("qa.api.authz_missing")),
        Subject::Role { allowed: false } if ok2 => (ResultStatus::Fail, Some("qa.api.privilege_escalation")),
        Subject::Role { allowed: true } if denied => (ResultStatus::Fail, Some("qa.api.access_denied")),
        _ if status >= 500 => (ResultStatus::Fail, None),
        _ => (ResultStatus::Pass, None),
    }
}

struct Col<'a> {
    name: String,
    subject: Subject,
    role: Option<&'a Role>,
    extra: Vec<(String, String)>,
    expected: String,
    title: String,
    cid: String,
}

pub fn run(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(mut r) = Runner::new(ctx, "qa.api.authz")? else { return Ok(not_applicable()) };
    let spec = r.spec.clone();
    let qa = r.qa;
    for rl in &qa.roles.roles {
        if !super::exec::role_usable(qa, rl) {
            qa.with(|c| c.notes.push(format!("role '{}' skipped: credential not available (env var {} unset?)", rl.name, rl.placeholder())));
        }
    }
    let roles = r.usable_roles();
    // Leave 40% of the budget to the functional and stateful checks.
    let reserve = qa.max_requests * 4 / 10;
    let mut stopped: Option<String> = None;
    for pl in plan_order(qa, &spec) {
        let op = &pl.op;
        if matches!(op.method.as_str(), "HEAD" | "OPTIONS") {
            continue;
        }
        let key = op.key();
        if op.is_write() && !qa.nonprod {
            qa.with(|c| {
                c.coverage.set(&key, "anon", Cell::Untested);
                c.untested.push(format!("{key}: auth matrix skipped (read-only: host not nonprod)"));
            });
            continue;
        }
        if stopped.is_none() && qa.remaining() <= reserve {
            stopped = Some("request budget reserved for the functional and stateful checks".into());
        }
        if let Some(why) = &stopped {
            qa.with(|c| c.untested.push(format!("{key}: {why} (auth matrix)")));
        }
        // Resource ids: real ones for reads, an unlikely one for writes (never touch real data).
        let ids = if stopped.is_some() { vec![] } else { r.ids_for(op) };
        let id = if op.is_write() { Some("999999".to_string()) } else { ids.first().cloned() };
        let pv = r.id_map(op, id.as_ref());
        let q: Vec<(String, String)> = op.params.iter().filter(|p| p.loc == "query" && p.required).map(|p| (p.name.clone(), synth::value_str(&synth::synth(&p.schema, &p.name, &r.tag, 0)))).collect();
        let body = op.body.as_ref().map(|b| synth::synth(b, "body", &r.tag, 0));
        let url = r.url(op, &pv, &q);
        let path = r.path_of(op, &pv);
        let curl = |role: Option<&Role>| super::exec::curl_repro(&op.method, &url, role, body.as_ref());

        let mut cols: Vec<Col> = vec![];
        for (name, extra) in [("anon", vec![]), ("invalid", vec![("Authorization".to_string(), "Bearer readyhai-invalid-token".to_string())])] {
            if !op.secured {
                qa.with(|c| c.coverage.set(&key, name, Cell::NotApplicable));
                continue;
            }
            cols.push(Col {
                name: name.into(),
                subject: if name == "anon" { Subject::Anon } else { Subject::Invalid },
                role: None,
                extra,
                expected: if name == "anon" { "401/403 without credentials" } else { "401 for an invalid token" }.into(),
                title: format!("{key} with {name} credentials"),
                cid: format!("api.{}.{}.authz.{name}", op.method, op.path),
            });
        }
        for role in &roles {
            let col = role.name.as_str();
            let Some(allowed) = role.expects(&path) else {
                qa.with(|c| c.coverage.set(&key, col, Cell::Untested));
                continue;
            };
            if allowed && op.is_write() {
                qa.with(|c| c.coverage.set(&key, col, Cell::Untested));
                continue; // allowed writes are exercised by the stateful lifecycle
            }
            cols.push(Col {
                name: col.into(),
                subject: Subject::Role { allowed },
                role: Some(role),
                extra: vec![],
                expected: if allowed { "access allowed (not 401/403)" } else { "401/403/404 (role is denied this path)" }.into(),
                title: format!("{key} as role {col}"),
                cid: format!("api.{}.{}.authz.{col}", op.method, op.path),
            });
        }

        for c in cols {
            r.add_case(&c.cid, op, Technique::AuthMatrix, Priority::P1, &c.title, c.role.map(|x| x.name.as_str()), vec![curl(c.role)], &c.expected);
            if let Some(why) = &stopped {
                r.skip(&c.cid, why);
                qa.with(|x| x.coverage.set(&key, &c.name, Cell::Untested));
                continue;
            }
            let attempt = |r: &mut Runner| -> Result<(super::exec::Exchange, Vec<DefectRef>), String> {
                r.extra = c.extra.clone();
                let res = r.send(&Req { op, role: c.role, case_id: &c.cid, kind: &c.name, method: &op.method, url: &url, body: body.as_ref(), contract: false });
                r.extra = vec![];
                res
            };
            match attempt(&mut r) {
                Ok((ex, mut defs)) => {
                    let (mut st, rule) = judge(c.subject, ex.status);
                    if let Some(rule) = rule {
                        defs.push(raise(&mut r, rule, &key, &c, &ex, op, &url, body.as_ref()));
                        if op.is_write() {
                            r.register_created(op, &ex, c.role);
                        }
                    }
                    if st != ResultStatus::Pass && st != ResultStatus::Blocked && !op.is_write() {
                        // is the failure stable? (read-only requests only; writes are never repeated)
                        let rr = r.rerun(reserve, |me| attempt(me).ok().map(|(e, _)| judge(c.subject, e.status).0 == ResultStatus::Fail));
                        r.note_reproduced(&defs, &rr);
                        st = rr.status();
                        let cell = if st == ResultStatus::Pass { Cell::Pass } else { Cell::Fail };
                        qa.with(|x| x.coverage.set(&key, &c.name, cell));
                        r.result_n(&c.cid, st, &format!("HTTP {}", ex.status), ex.ms, &defs, rr.attempts);
                        continue;
                    }
                    let cell = match st {
                        ResultStatus::Pass => Cell::Pass,
                        ResultStatus::Blocked => Cell::Untested,
                        _ => Cell::Fail,
                    };
                    qa.with(|x| x.coverage.set(&key, &c.name, cell));
                    let actual = if ex.status == 0 { format!("transport error: {}", ex.error.clone().unwrap_or_default()) } else { format!("HTTP {}", ex.status) };
                    r.result(&c.cid, st, &actual, ex.ms, &defs);
                }
                Err(e) => {
                    if e.contains("budget") {
                        stopped = Some(e.clone());
                    }
                    r.skip(&c.cid, &e);
                    qa.with(|x| x.coverage.set(&key, &c.name, Cell::Untested));
                }
            }
        }
    }
    r.explain_failures();
    r.run_cleanup();
    Ok(CheckOutput::findings(std::mem::take(&mut r.findings)))
}

#[allow(clippy::too_many_arguments)]
fn raise(r: &mut Runner, rule: &str, key: &str, c: &Col, ex: &super::exec::Exchange, op: &super::spec::Op, url: &str, body: Option<&serde_json::Value>) -> DefectRef {
    let rule: &'static str = match rule {
        "qa.api.authz_missing" => "qa.api.authz_missing",
        "qa.api.privilege_escalation" => "qa.api.privilege_escalation",
        _ => "qa.api.access_denied",
    };
    let (cat, sev, prio, title, remediation) = match rule {
        "qa.api.authz_missing" => (
            Category::Security, Severity::High, Priority::P1,
            format!("{key} is reachable with {} credentials", if c.name == "anon" { "no" } else { "invalid" }),
            "Enforce authentication on this route (default-deny middleware).",
        ),
        "qa.api.privilege_escalation" => (
            Category::Security, Severity::High, Priority::P1,
            format!("Role '{}' can access {key} although roles.toml denies it", c.name),
            "Enforce role-based authorization on the server, not only in the UI.",
        ),
        _ => (
            Category::Quality, Severity::Medium, Priority::P2,
            format!("Role '{}' is denied {key} although roles.toml allows it", c.name),
            "Check the role's credentials/permissions and the allow globs in roles.toml; if access is intentionally denied, fix roles.toml.",
        ),
    };
    let expected = match rule {
        "qa.api.authz_missing" => format!("{} (operation is secured in the spec)", c.expected),
        _ => c.expected.clone(),
    };
    r.defect(NewDefect {
        rule, cat, sev, prio, title, expected, actual: format!("HTTP {}", ex.status), fp: format!("{key}|{}", c.name),
        remediation, area_cases: &c.cid, component: key.to_string(), role: c.role, method: &op.method, url, body, ex: Some(ex),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judgement_table() {
        use ResultStatus::*;
        assert_eq!(judge(Subject::Anon, 401), (Pass, None));
        assert_eq!(judge(Subject::Anon, 200), (Fail, Some("qa.api.authz_missing")));
        assert_eq!(judge(Subject::Invalid, 204), (Fail, Some("qa.api.authz_missing")));
        assert_eq!(judge(Subject::Invalid, 400), (Pass, None));
        assert_eq!(judge(Subject::Role { allowed: false }, 200), (Fail, Some("qa.api.privilege_escalation")));
        assert_eq!(judge(Subject::Role { allowed: false }, 403), (Pass, None));
        assert_eq!(judge(Subject::Role { allowed: true }, 200), (Pass, None));
        assert_eq!(judge(Subject::Role { allowed: true }, 404), (Pass, None));
        assert_eq!(judge(Subject::Role { allowed: true }, 403), (Fail, Some("qa.api.access_denied")));
        assert_eq!(judge(Subject::Anon, 502), (Fail, None));
        // a transport failure proves nothing: never a Pass
        assert_eq!(judge(Subject::Anon, 0), (Blocked, None));
        assert_eq!(judge(Subject::Role { allowed: false }, 0), (Blocked, None));
    }
}
