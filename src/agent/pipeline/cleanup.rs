//! Tracking, harvest, teardown, and defect emission for resources created during agent execution.

use serde_json::{json, Value};
use std::time::{Duration, Instant};

use super::super::exec::{
    auth_for, confirm_deleted_resolved, curl_auth_arg, evidence_rel_path, resolve_auth, Auth,
    Clients, Credentials, DeleteCheck, OutReq,
};
use super::super::oracle::{OracleCheck, OracleOutcome, Severity, Verdict};
use super::super::types::{
    id_from_body, is_creation, path_of_url, CaseExecutionResult, CleanupReport, CreatedLedger,
    CreatedResource, Leftover, PlannedCase,
};

pub(crate) const TEARDOWN_MAX: usize = 200;
pub(crate) const TEARDOWN_WALL: Duration = Duration::from_secs(60);

/// Prefix of the leftover reason (and the oracle check code) for a resource that a 2xx DELETE did
/// not remove.
pub(crate) const DELETE_NOT_EFFECTIVE: &str = "delete_not_effective";

/// Record what the run created, from the results themselves: a POST that answered 2xx (or a PUT
/// that answered 201) with an id or a Location header, and every POST step of a stateful chain.
/// Anything created but not identifiable (no id, repeated attempts) goes to `unidentified`.
/// The executor already calls `record_created`-style recording on every 2xx creation while it
/// runs (tagged with the case id); what it recorded counts as identified here and duplicates are
/// ignored, so a resource is neither recorded twice nor also reported as unidentified.
pub(crate) fn harvest_created(
    results: &[CaseExecutionResult],
    cases: &[PlannedCase],
    ledger: &CreatedLedger,
) -> Vec<Leftover> {
    let mut unidentified = vec![];
    let ids: std::collections::HashSet<&str> = results.iter().map(|r| r.case_id.as_str()).collect();
    for r in results.iter().filter(|r| r.status != "SKIPPED") {
        // `<id>-B` is the concurrency burst as a sub-case; its first response is one of the burst's
        // requests, not a separate attempt, and the main result carries a copy of its codes
        let is_burst_sub = r.case_id.ends_with("-B")
            && r.evidence_detail
                .as_ref()
                .is_some_and(|d| d.get("burst_of").is_some());
        let role = cases
            .iter()
            .find(|c| c.id == r.case_id)
            .and_then(|c| match auth_for(c) {
                Auth::Role(role) => Some(role),
                _ => None,
            });
        // creations the executor recorded itself for this very result (tagged with its case id)
        let by_executor = ledger.recorded_for_case(&r.case_id);
        let mut identified = if r.stateful_chain.is_none() && !is_burst_sub {
            by_executor
        } else {
            0
        };
        if let (Some(code), Some(d)) = (r.status_code, r.evidence_detail.as_ref())
            && r.stateful_chain.is_none()
            && !is_burst_sub
            && by_executor == 0
            && is_creation(&r.method, code)
        {
            let url = d["request"]["url"].as_str().unwrap_or("");
            let req_path = path_of_url(url).unwrap_or_else(|| r.component.clone());
            let location = d["response"]["headers"]
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|h| {
                    (h[0].as_str().map(str::to_ascii_lowercase).as_deref() == Some("location"))
                        .then(|| h[1].as_str().map(str::to_string))
                        .flatten()
                })
                .and_then(|loc| {
                    reqwest::Url::parse(url)
                        .ok()?
                        .join(&loc)
                        .ok()
                        .filter(|l| {
                            Some(l.origin()) == reqwest::Url::parse(url).ok().map(|u| u.origin())
                        })
                        .map(|l| l.path().to_string())
                });
            let body_id = id_from_body(d["response"]["body_excerpt"].as_str().unwrap_or(""));
            let ok = match (&location, &body_id) {
                (Some(loc), _) => {
                    let last = loc
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    ledger.record_resource(CreatedResource {
                        method: r.method.to_ascii_uppercase(),
                        path: req_path.clone(),
                        id: body_id.clone().unwrap_or(last),
                        delete_path: Some(loc.clone()),
                        role: role.clone(),
                        case_id: Some(r.case_id.clone()),
                    })
                }
                (None, Some(id)) => {
                    ledger.record_with(&r.method, &req_path, id, role.as_deref(), Some(&r.case_id))
                }
                (None, None) => false,
            };
            if ok {
                identified += 1;
            }
        }
        let mut chain_recorded = if r.stateful_chain.is_some() {
            by_executor
        } else {
            0
        };
        for s in r.stateful_chain.iter().flatten() {
            if is_creation(&s.method, s.status_code) {
                if chain_recorded > 0 {
                    chain_recorded -= 1; // the executor recorded this creation with its real id
                    continue;
                }
                let id = s
                    .extracted_values
                    .iter()
                    .filter(|(k, _)| {
                        let k = k.to_ascii_lowercase();
                        k == "id" || k == "_id" || k == "uuid" || k.ends_with("_id")
                    })
                    .min_by_key(|(k, _)| k.len())
                    .map(|(_, v)| v.clone());
                let path = s
                    .resolved_path
                    .split(['?', '#'])
                    .next()
                    .unwrap_or("")
                    .to_string();
                match id {
                    Some(id) if ledger.record_with(&s.method, &path, &id, Some(&s.actor), Some(&r.case_id)) => {
                        identified += 1
                    }
                    Some(_) => {}
                    None => unidentified.push(Leftover {
                        method: s.method.to_ascii_uppercase(),
                        path,
                        id: "(unknown)".into(),
                        reason: "created by a stateful step but the response carried no id, so it cannot be deleted automatically".into(),
                    }),
                }
            }
        }
        // a concurrency burst fires N more requests; only their status codes are stored
        let counted_in_sub = !is_burst_sub && ids.contains(format!("{}-B", r.case_id).as_str());
        if r.stateful_chain.is_none() && !counted_in_sub {
            let burst_created = r
                .concurrency_burst_results
                .iter()
                .flatten()
                .filter(|c| is_creation(&r.method, **c))
                .count();
            // the executor records each burst response under the sub-case's id (`<id>-B`)
            let burst_id = if is_burst_sub {
                r.case_id.clone()
            } else {
                format!("{}-B", r.case_id)
            };
            let burst_recorded = ledger.recorded_for_case(&burst_id);
            for _ in 0..burst_created.saturating_sub(burst_recorded) {
                unidentified.push(Leftover {
                    method: r.method.to_ascii_uppercase(),
                    path: r.component.split(['?', '#']).next().unwrap_or("").to_string(),
                    id: "(unknown)".into(),
                    reason: format!("{}: a concurrency-burst request created a resource and only its status code was stored, so it cannot be deleted automatically", r.case_id),
                });
            }
        }
        // 2xx creations beyond the identified one (flaky re-runs, adaptive mutation probes) left
        // resources whose ids were not stored
        if r.stateful_chain.is_none()
            && !is_burst_sub
            && is_creation(&r.method, r.status_code.unwrap_or(0))
        {
            let created_attempts = r
                .attempts
                .iter()
                .filter(|a| a.status_code.is_some_and(|c| is_creation(&r.method, c)))
                .count();
            let missing = created_attempts.max(1).saturating_sub(identified);
            for _ in 0..missing {
                unidentified.push(Leftover {
                    method: r.method.to_ascii_uppercase(),
                    path: r.component.split(['?', '#']).next().unwrap_or("").to_string(),
                    id: "(unknown)".into(),
                    reason: format!("{} answered 2xx without an id in the stored response (or on a re-run / mutation probe), so the created resource cannot be deleted automatically", r.case_id),
                });
            }
        }
    }
    unidentified
}

/// DELETE what the run created, newest first, on the run's own origin only. `nonprod` must come
/// from the scope check: on anything not confirmed nonprod nothing is sent and every resource is
/// listed as left over. The run budget is deliberately not consulted: cleanup matters most when the
/// budget ran out. A 2xx DELETE is not trusted: a follow-up GET (`exec::confirm_deleted_as`, with
/// the creating role's credential) must find the resource gone (404/410). One that is still there
/// is a leftover with reason `delete_not_effective` (and becomes a defect of that name); a read-back
/// that proves nothing (401/403/5xx/transport error) keeps the DELETE's word and is counted as
/// unconfirmed. Returns what was deleted and what is left.
pub(crate) fn teardown(
    target: &str,
    ledger: &CreatedLedger,
    unidentified: Vec<Leftover>,
    creds: &Credentials,
    nonprod: bool,
    dry_run: bool,
    timeout: Duration,
) -> CleanupReport {
    let resources = ledger.entries();
    let mut rep = CleanupReport {
        created: resources.len() + unidentified.len(),
        resources: resources.clone(),
        leftovers: unidentified,
        ..Default::default()
    };
    let left = |r: &CreatedResource, why: String| Leftover {
        method: r.method.clone(),
        path: r.teardown_path(),
        id: r.id.clone(),
        reason: why,
    };
    if resources.is_empty() {
        rep.skipped = Some(
            if rep.created > 0 {
                "no created resource could be identified for deletion"
            } else if dry_run {
                "dry-run: no state-changing request was sent"
            } else {
                "the run created nothing"
            }
            .into(),
        );
        return rep;
    }
    if dry_run {
        rep.skipped = Some("dry-run".into());
        rep.leftovers.extend(
            resources
                .iter()
                .map(|r| left(r, "dry-run: teardown not attempted".into())),
        );
        return rep;
    }
    if !nonprod {
        rep.skipped =
            Some("target is not confirmed nonprod by the scope file, so no DELETE was sent".into());
        rep.leftovers.extend(
            resources
                .iter()
                .map(|r| left(r, "target not confirmed nonprod: delete it by hand".into())),
        );
        return rep;
    }
    let Some(origin) = reqwest::Url::parse(target)
        .ok()
        .map(|u| u.origin().ascii_serialization())
        .filter(|o| o.starts_with("http"))
    else {
        rep.skipped = Some("target is not an http(s) URL".into());
        rep.leftovers.extend(
            resources
                .iter()
                .map(|r| left(r, "no origin to delete from".into())),
        );
        return rep;
    };
    let client = match reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("ReadyHai-Agent/1.0 teardown")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            rep.skipped = Some(format!("could not build the HTTP client: {e}"));
            rep.leftovers.extend(
                resources
                    .iter()
                    .map(|r| left(r, "teardown not attempted".into())),
            );
            return rep;
        }
    };
    // read-back client: same target, same credential rules as every other request of the run
    let readback = reqwest::Url::parse(target)
        .ok()
        .and_then(|u| Clients::new(timeout, &u).ok());
    let t0 = Instant::now();
    for (n, r) in resources.iter().rev().enumerate() {
        if n >= TEARDOWN_MAX || t0.elapsed() >= TEARDOWN_WALL {
            rep.leftovers.push(left(r, "teardown limit reached".into()));
            continue;
        }
        let url = format!("{origin}{}", r.teardown_path());
        let auth_role = r
            .role
            .as_deref()
            .filter(|role| creds.has_role(role))
            .or_else(|| creds.has_role("admin").then_some("admin"))
            .or_else(|| creds.has_role("user").then_some("user"));
        let resolved = auth_role
            .map(|role| resolve_auth(&Auth::Role(role.to_string()), creds))
            .unwrap_or_else(|| resolve_auth(&Auth::None, creds));
        rep.attempted += 1;
        let del_res = if let Some(cl) = readback.as_ref() {
            cl.send_resolved(
                &OutReq {
                    method: "DELETE",
                    url: &url,
                    body: None,
                    headers: &[],
                    bearer: resolved.bearer.as_ref(),
                },
                &resolved,
            )
            .map(|seen| seen.status)
        } else {
            client
                .delete(&url)
                .send()
                .map(|resp| resp.status().as_u16())
                .map_err(|e| e.to_string())
        };
        match del_res {
            Ok(c) => {
                if c == 404 || c == 410 {
                    rep.deleted += 1;
                    rep.confirmed_gone += 1;
                } else if (200..300).contains(&c) {
                    let check = readback
                        .as_ref()
                        .map(|cl| {
                            confirm_deleted_resolved(cl, target, &r.teardown_path(), &resolved)
                        })
                        .unwrap_or(DeleteCheck::Unknown);
                    match check {
                        DeleteCheck::Gone => {
                            rep.deleted += 1;
                            rep.confirmed_gone += 1;
                        }
                        DeleteCheck::StillPresent(g) => {
                            rep.still_present += 1;
                            rep.leftovers.push(left(
                                r,
                                format!(
                                    "{DELETE_NOT_EFFECTIVE}: DELETE answered HTTP {c}, but a follow-up GET still answers HTTP {g}: the resource was not removed"
                                ),
                            ));
                        }
                        DeleteCheck::Unknown => {
                            rep.deleted += 1;
                            rep.unconfirmed += 1;
                        }
                    }
                } else {
                    rep.leftovers
                        .push(left(r, format!("DELETE answered HTTP {c}")));
                }
            }
            Err(e) => rep.leftovers.push(left(
                r,
                format!(
                    "DELETE failed: {}",
                    crate::llm::untrusted::clean(&e.to_string(), 160)
                ),
            )),
        }
    }
    rep
}

pub(crate) fn http_codes(s: &str) -> Vec<u16> {
    s.split("HTTP ")
        .skip(1)
        .filter_map(|t| t.get(..3)?.parse().ok())
        .collect()
}

pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// One FAIL result (`CLEANUP-NNN`) per resource a 2xx DELETE did not remove, so the triager turns
/// each into a `delete_not_effective` defect (Medium, quality) with its own evidence file. The
/// request/response pair is the teardown's DELETE and the confirming GET.
pub(crate) fn delete_check_results(
    target: &str,
    cleanup: &CleanupReport,
) -> Vec<CaseExecutionResult> {
    let origin = reqwest::Url::parse(target)
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_default();
    cleanup
        .leftovers
        .iter()
        .filter(|l| l.reason.starts_with(DELETE_NOT_EFFECTIVE))
        .enumerate()
        .map(|(i, l)| {
            let id = format!("CLEANUP-{:03}", i + 1);
            let made = cleanup
                .resources
                .iter()
                .find(|r| r.teardown_path() == l.path && r.id == l.id);
            let codes = http_codes(&l.reason);
            let (del, get) = (codes.first().copied(), codes.get(1).copied());
            let url = format!("{origin}{}", l.path);
            let auth = made
                .and_then(|r| r.role.as_deref())
                .and_then(|role| curl_auth_arg(&Auth::Role(role.to_string())))
                .map(|a| format!(" {a}"))
                .unwrap_or_default();
            let curl = format!(
                "curl -sS -i -X DELETE{auth} {u} && curl -sS -i{auth} {u}",
                u = shell_quote(&url)
            );
            let title = format!("Teardown: DELETE {} did not remove the resource", l.path);
            let outcome = OracleOutcome {
                verdict: Verdict::Fail,
                checks: vec![OracleCheck {
                    code: DELETE_NOT_EFFECTIVE.into(),
                    verdict: Verdict::Fail,
                    severity: Some(Severity::Medium),
                    detail: l.reason.clone(),
                }],
                warnings: vec![],
                exploratory: false,
            };
            let evidence_file = evidence_rel_path(&id);
            let detail = json!({
                "case_id": id, "title": title, "technique": "state_transition",
                "request": {"method": "DELETE", "url": url, "curl": curl, "created_by": made.and_then(|r| r.case_id.clone()), "auth": made.and_then(|r| r.role.as_ref()).map(|r| format!("role:{r} (token not recorded)")).unwrap_or_else(|| "none".into())},
                "response": {"delete_status": del, "readback_get_status": get, "note": "the resource is still readable after the DELETE"},
                "oracle": serde_json::to_value(&outcome).unwrap_or(Value::Null),
            });
            CaseExecutionResult { blocked_reason: None, redirect_chain: vec![],
                case_id: id,
                title,
                component: l.path.clone(),
                method: "DELETE".into(),
                technique: "state_transition".into(),
                status: "FAIL".into(),
                status_code: get,
                latency_ms: 0,
                reproduction_curl: curl,
                request_payload: None,
                evidence: format!("DELETE {} answered HTTP {}; GET still answers HTTP {}", l.path, del.unwrap_or(0), get.unwrap_or(0)),
                content_type: None,
                is_spa_shell: false,
                failure_reason: Some(l.reason.clone()),
                expected_status: None,
                oracle: Some(outcome),
                flaky: false,
                attempts: vec![],
                evidence_file: Some(evidence_file),
                evidence_detail: Some(detail),
                stateful_chain: None,
                concurrency_burst_results: None,
            }
        })
        .collect()
}

pub(crate) fn target_is_nonprod(target: &str) -> bool {
    match crate::scope::active() {
        Ok(scope) => crate::scope::check(target, scope.as_ref()).unwrap_or(false),
        Err(_) => false,
    }
}
