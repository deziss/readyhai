//! Independent verifier. Before a FAIL reaches triage and the ledger, it is replayed `k` times and
//! only kept as a defect when it reproduces.
//!
//! * The request is rebuilt from the stored case (`exec::build_request`: method, URL, body, probe
//!   headers; no credential is stored anywhere) and the credential is attached afresh through
//!   `exec::resolve_auth` and `Clients::send`, so the host-binding, certificate-validation and
//!   no-redirect rules of the executor apply unchanged.
//! * Each replay is judged by the same oracle (`oracle::judge`) as the original. A replay
//!   *reproduces* the failure when it fails again with at least one of the original failing checks.
//!   A PASS is a non-reproduction. Anything that cannot be judged (an inconclusive verdict, a
//!   different failure, a transport error, a budget or cancellation stop) is not a vote: the case
//!   is then `Unverified` and stays what it was, never demoted on partial evidence.
//! * Only safe methods (GET/HEAD/OPTIONS) are repeated freely. A write-method FAIL is re-executed
//!   only when the original case created its own resource (a 2xx creation, a stateful chain that
//!   builds its own object) or targets an id no record has (`999999`, `readyhai-nonexistent`);
//!   otherwise it is marked `unverified-write` and not replayed. Resources a replay creates are
//!   recorded on the run's `CreatedLedger` (so teardown removes them) and those that cannot be
//!   identified are returned as leftovers.
//! * Replays are charged to the `RunBudget` (requests, per-host rate) and stop at cancellation.
//!
//! Verdicts: `Confirmed` (all k reproduce), `Flaky` (some), `NotReproduced` (none), `Unverified`.
//! Policy (`apply`): NotReproduced becomes INCONCLUSIVE (not a defect); Flaky stays FAIL, flagged,
//! for critical/high failures and becomes WARN otherwise; Confirmed and Unverified keep FAIL.
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::Duration;

use super::budget::RunBudget;
use super::exec::{
    Clients, Credentials, OutReq, RequestSpec, ResolvedAuth, build_request, is_mutating,
    resolve_auth,
};
use super::oracle::{self, Observation, OracleOutcome, Severity, Verdict};
use super::types::{
    CaseExecutionResult, Leftover, PlannedCase, ReplayRecord, StatefulStep, VerificationRecord,
    VerificationSummary, VerifyVerdict, current_ledger, is_creation, record_creation_response,
};
use crate::llm::untrusted::redact_then_truncate;

/// Replays per failed case when nothing else is configured.
pub const DEFAULT_K: u32 = 2;
/// Upper bound for `READYHAI_VERIFY_K`.
pub const MAX_K: u32 = 5;
/// Stop verifying after this many candidates in a row ended in a transport error.
const MAX_UNREACHABLE: u32 = 3;

/// `READYHAI_VERIFY_K` text to a replay count: unset or unparsable = 2, capped at 5, `0` = off.
pub fn parse_k(raw: Option<&str>) -> u32 {
    match raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<u32>().ok())
    {
        Some(n) => n.min(MAX_K),
        None => DEFAULT_K,
    }
}

pub fn k_from_env() -> u32 {
    parse_k(std::env::var("READYHAI_VERIFY_K").ok().as_deref())
}

pub struct VerifyOptions<'a> {
    /// Replays per failed case; 0 = verification off.
    pub k: u32,
    /// Ids of planned cases the agent's memory knows as flaky: their failures get [`MAX_K`]
    /// replays (when verification is on at all).
    pub raise_k: &'a BTreeSet<String>,
    pub dry_run: bool,
    pub is_spa_target: bool,
    pub credentials: &'a Credentials,
    pub timeout: Duration,
}

/// No case is known as flaky: every failure gets the run's k.
pub fn no_raise() -> &'static BTreeSet<String> {
    static NONE: BTreeSet<String> = BTreeSet::new();
    &NONE
}

/// Replays for one failed case: the run's k, or the maximum when memory knows the case as flaky.
fn k_for(r: &CaseExecutionResult, opts: &VerifyOptions) -> u32 {
    let base = r
        .case_id
        .strip_suffix("-M1")
        .or_else(|| r.case_id.strip_suffix("-B"))
        .unwrap_or(&r.case_id);
    if opts.k > 0 && opts.k < MAX_K && opts.raise_k.contains(base) {
        MAX_K
    } else {
        opts.k
    }
}

pub struct VerifyOutcome {
    pub summary: VerificationSummary,
    /// Resources a replay created whose id was not announced: they cannot be torn down by id.
    pub unidentified: Vec<Leftover>,
}

// ---------------------------------------------------------------- what may be replayed

/// An id that no record has: what the planner puts into write cases (`plan::fill_path`) and what the
/// adaptive mutation uses for integers, so a write there cannot modify or delete real data.
pub fn targets_unlikely_id(component: &str) -> bool {
    let path = component.split(['?', '#']).next().unwrap_or("");
    path.split('/').any(|seg| {
        let s = seg.to_ascii_lowercase();
        s.contains("nonexistent")
            || (s.len() >= 6 && s.chars().all(|c| c == '9'))
            || s.ends_with("-000000999999")
    })
}

enum Plan {
    Http(PlannedCase),
    Chain(PlannedCase, Vec<StatefulStep>),
    Skip(String),
}

fn plan_for(r: &CaseExecutionResult, cases: &[PlannedCase], dry_run: bool) -> Plan {
    let mutated = |base: &PlannedCase| {
        // the same shape `exec::run_mutation` judged: the base case with the mutated payload
        let mut m = base.clone();
        m.id = r.case_id.clone();
        m.title = r.title.clone();
        m.payload = r.request_payload.clone();
        m.expected_status = None;
        m.expected_behavior =
            "Schema-conforming adversarial input is handled without a server error".into();
        m.concurrency_burst = None;
        m.stateful_steps = None;
        m.contract = None;
        m
    };
    let case = if let Some(c) = cases.iter().find(|c| c.id == r.case_id) {
        c.clone()
    } else if let Some(base) = r
        .case_id
        .strip_suffix("-M1")
        .and_then(|b| cases.iter().find(|c| c.id == b))
    {
        mutated(base)
    } else if r.case_id.ends_with("-B") {
        return Plan::Skip(
            "concurrency burst: replaying it would fire N more requests at the target, so it was not repeated"
                .into(),
        );
    } else {
        return Plan::Skip(
            "no planned case matches this result, so the request cannot be rebuilt".into(),
        );
    };
    if let Some(steps) = case.stateful_steps.clone().filter(|s| !s.is_empty()) {
        // a chain builds its own resource and acts on that one only
        return if dry_run && steps.iter().any(|s| is_mutating(&s.method)) {
            Plan::Skip("dry-run: state-changing chain not replayed".into())
        } else {
            Plan::Chain(case, steps)
        };
    }
    if is_mutating(&case.method) {
        if dry_run {
            return Plan::Skip("dry-run: state-changing request not replayed".into());
        }
        let created_own = is_creation(&case.method, r.status_code.unwrap_or(0));
        if !created_own && !targets_unlikely_id(&case.component) {
            return Plan::Skip(format!(
                "unverified-write: {} {} changes state on a resource this case did not create and whose id is not a throw-away one, so it was not replayed",
                case.method.to_ascii_uppercase(),
                case.component.split(['?', '#']).next().unwrap_or("")
            ));
        }
    }
    Plan::Http(case)
}

// ---------------------------------------------------------------- judging a replay

fn severity_of(r: &CaseExecutionResult) -> Severity {
    r.oracle
        .as_ref()
        .and_then(|o| o.max_fail_severity())
        .unwrap_or(Severity::High)
}

fn fail_codes(o: &OracleOutcome) -> BTreeSet<String> {
    o.checks
        .iter()
        .filter(|c| c.verdict == Verdict::Fail)
        .map(|c| c.code.clone())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vote {
    Reproduced,
    NotReproduced,
    /// Could not be judged: not a vote either way.
    Indeterminate,
}

/// How a replay's judgement counts. `same_status`: the replay got the same HTTP status the original
/// failure had.
/// * a fail with at least one of the original failing checks: reproduced;
/// * a PASS: not reproduced;
/// * INCONCLUSIVE: the checks that failed originally no longer fail, but the oracle has no
///   assertion left to pass (e.g. a 200 where a 500 was seen, on a case with no stated
///   expectation). That is a non-reproduction when the status moved, and unjudgeable when the
///   server said the same thing again (the same answer judged differently is not a vote);
/// * a failure of a different kind: not a vote (something else is wrong; do not dismiss it).
fn vote(orig: &BTreeSet<String>, o: &OracleOutcome, same_status: bool) -> Vote {
    match o.verdict {
        Verdict::Fail if orig.is_empty() || !fail_codes(o).is_disjoint(orig) => Vote::Reproduced,
        Verdict::Pass => Vote::NotReproduced,
        Verdict::Inconclusive if !same_status => Vote::NotReproduced,
        _ => Vote::Indeterminate,
    }
}

fn spa_shell(ct: &str, body: &str, is_spa_target: bool) -> bool {
    ct.to_ascii_lowercase().contains("html")
        && is_spa_target
        && [
            "__NEXT_DATA__",
            "/_next/static/",
            "__NUXT__",
            "ng-version",
            "data-reactroot",
            "<app-root",
            "id=\"root\"",
            "id=\"app\"",
            "/@vite/client",
        ]
        .iter()
        .any(|m| body.contains(m))
}

/// One replay as stored in the report plus what only the evidence file keeps.
struct Replay {
    rec: ReplayRecord,
    vote: Vote,
    excerpt: Option<String>,
    reason: Option<String>,
}

impl Replay {
    fn errored(n: u32, note: String) -> Replay {
        Replay {
            rec: ReplayRecord {
                replay: n,
                status_code: None,
                latency_ms: 0,
                verdict: "ERROR".into(),
                reproduced: false,
                note: Some(note),
            },
            vote: Vote::Indeterminate,
            excerpt: None,
            reason: None,
        }
    }
}

struct Ctx<'a> {
    clients: &'a Clients,
    target: &'a str,
    /// `host:port`, the budget's rate-limit key.
    host: &'a str,
    opts: &'a VerifyOptions<'a>,
}

fn replay_http(
    ctx: &Ctx,
    case: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    orig: &BTreeSet<String>,
    orig_status: Option<u16>,
    n: u32,
    unidentified: &mut Vec<Leftover>,
) -> Replay {
    let out = OutReq {
        method: spec.method,
        url: &spec.url,
        body: spec.body.as_ref(),
        headers: &spec.extra_headers,
        bearer: auth.bearer.as_ref(),
    };
    let seen = match ctx.clients.send(&out) {
        Ok(s) => s,
        Err(e) => {
            return Replay::errored(
                n,
                format!("not completed: {}", redact_then_truncate(&e, 200)),
            );
        }
    };
    let role = match &spec.auth {
        super::exec::Auth::Role(r) => Some(r.as_str()),
        _ => None,
    };
    let rid = format!("{}-V{n}", case.id);
    if is_creation(spec.method, seen.status)
        && !record_creation_response(
            None,
            spec.method,
            &spec.url,
            seen.status,
            &seen.headers,
            &seen.body,
            role,
            Some(&rid),
        )
    {
        unidentified.push(Leftover {
            method: spec.method.to_string(),
            path: spec.path.split(['?', '#']).next().unwrap_or("").to_string(),
            id: "(unknown)".into(),
            reason: format!("{rid}: a verification replay created a resource (HTTP {}) and no id could be read from the response, so it cannot be deleted automatically", seen.status),
        });
    }
    let shell = spa_shell(&seen.content_type, &seen.body, ctx.opts.is_spa_target);
    let outcome = oracle::judge(
        case,
        &Observation {
            status: seen.status,
            content_type: &seen.content_type,
            headers: &seen.headers,
            body: &seen.body,
            sent_values: &spec.sent_values,
            is_spa_shell: shell,
            authenticated: auth.authenticated,
            https: spec.url.starts_with("https://"),
            request_body: spec.body.as_ref().map(|(_, b)| b.as_str()),
            origin: spec.origin(),
            latency_ms: seen.latency_ms,
        },
    );
    let v = vote(orig, &outcome, orig_status == Some(seen.status));
    Replay {
        rec: ReplayRecord {
            replay: n,
            status_code: Some(seen.status),
            latency_ms: seen.latency_ms,
            verdict: outcome.verdict.label().into(),
            reproduced: v == Vote::Reproduced,
            note: match v {
                Vote::Indeterminate => {
                    Some("could not be judged against the original failure".into())
                }
                _ => None,
            },
        },
        vote: v,
        excerpt: Some(redact_then_truncate(&seen.body, 300)),
        reason: outcome.reason(),
    }
}

fn replay_chain(
    ctx: &Ctx,
    case: &PlannedCase,
    steps: &[StatefulStep],
    orig: &BTreeSet<String>,
    n: u32,
    budget: &mut RunBudget,
    unidentified: &mut Vec<Leftover>,
) -> Replay {
    let rid = format!("{}-V{n}", case.id);
    let run = super::stateful::execute_stateful_scenario(
        ctx.clients,
        ctx.target,
        steps,
        ctx.opts.credentials,
        budget,
        ctx.host,
        &rid,
    );
    // chain steps that created something but were not recorded with an id cannot be torn down
    let made = run
        .steps
        .iter()
        .filter(|s| is_creation(&s.method, s.status_code))
        .count();
    let recorded = current_ledger().map_or(0, |l| l.recorded_for_case(&rid));
    for s in run
        .steps
        .iter()
        .filter(|s| is_creation(&s.method, s.status_code))
        .skip(recorded)
        .take(made.saturating_sub(recorded))
    {
        unidentified.push(Leftover {
            method: s.method.to_ascii_uppercase(),
            path: s.resolved_path.split(['?', '#']).next().unwrap_or("").to_string(),
            id: "(unknown)".into(),
            reason: format!("{rid}: a verification replay created a resource in a stateful chain and no id was recorded, so it cannot be deleted automatically"),
        });
    }
    if let Some(why) = &run.skipped {
        return Replay::errored(n, format!("chain not run: {why}"));
    }
    let Some(outcome) = run.outcome.as_ref() else {
        return Replay::errored(n, "chain produced no verdict".into());
    };
    let v = vote(orig, outcome, true);
    Replay {
        rec: ReplayRecord {
            replay: n,
            status_code: Some(run.final_status),
            latency_ms: run.total_latency_ms,
            verdict: outcome.verdict.label().into(),
            reproduced: v == Vote::Reproduced,
            note: match v {
                Vote::Indeterminate => {
                    Some("could not be judged against the original failure".into())
                }
                _ => None,
            },
        },
        vote: v,
        excerpt: Some(redact_then_truncate(&run.summary, 300)),
        reason: outcome.reason(),
    }
}

// ---------------------------------------------------------------- one candidate

fn record_for(
    r: &CaseExecutionResult,
    k: u32,
    sev: Severity,
    replays: Vec<Replay>,
    note: Option<String>,
    forced: Option<VerifyVerdict>,
) -> (VerificationRecord, Vec<Replay>) {
    let completed = replays
        .iter()
        .filter(|p| p.vote != Vote::Indeterminate)
        .count() as u32;
    let reproduced = replays
        .iter()
        .filter(|p| p.vote == Vote::Reproduced)
        .count() as u32;
    let verdict = forced.unwrap_or(if completed < k {
        VerifyVerdict::Unverified
    } else if reproduced == k {
        VerifyVerdict::Confirmed
    } else if reproduced == 0 {
        VerifyVerdict::NotReproduced
    } else {
        VerifyVerdict::Flaky
    });
    let rec = VerificationRecord {
        case_id: r.case_id.clone(),
        method: r.method.clone(),
        component: r.component.clone(),
        verdict,
        severity: sev.as_str().into(),
        k,
        completed,
        reproduced,
        replays: replays.iter().map(|p| p.rec.clone()).collect(),
        note,
        original_status: r.status.clone(),
        final_status: r.status.clone(),
        evidence_file: r.evidence_file.clone(),
    };
    (rec, replays)
}

/// Apply the verdict to the result: status, flaky flag, reason, and the replay evidence that goes
/// into the case's evidence file (`verification` section).
fn apply(r: &mut CaseExecutionResult, rec: &mut VerificationRecord, replays: &[Replay]) {
    let original = r
        .failure_reason
        .clone()
        .unwrap_or_else(|| "no reason recorded".into());
    let high = matches!(rec.severity.as_str(), "critical" | "high");
    match rec.verdict {
        VerifyVerdict::Confirmed | VerifyVerdict::Unverified => {}
        VerifyVerdict::NotReproduced => {
            r.status = "INCONCLUSIVE".into();
            r.failure_reason = Some(format!(
                "not reproduced: failed on the original run, but 0 of {} independent replay(s) reproduced it, so it is not reported as a defect. Original failure: {original}",
                rec.k
            ));
        }
        VerifyVerdict::Flaky => {
            r.flaky = true;
            if !high {
                r.status = "WARN".into();
            }
            r.failure_reason = Some(format!(
                "flaky: reproduced on {} of {} independent replay(s){}. Original failure: {original}",
                rec.reproduced,
                rec.k,
                if high {
                    "; kept as FAIL because the failure is high/critical severity"
                } else {
                    ""
                }
            ));
        }
    }
    rec.final_status = r.status.clone();
    if let Some(d) = r.evidence_detail.as_mut() {
        d["verification"] = json!({
            "verdict": rec.verdict.as_str(),
            "k": rec.k,
            "completed": rec.completed,
            "reproduced": rec.reproduced,
            "original_status": rec.original_status,
            "final_status": rec.final_status,
            "note": rec.note,
            "replays": replays.iter().map(|p| json!({
                "replay": p.rec.replay,
                "status_code": p.rec.status_code,
                "latency_ms": p.rec.latency_ms,
                "verdict": p.rec.verdict,
                "reproduced": p.rec.reproduced,
                "note": p.rec.note,
                "reason": p.reason,
                "response_excerpt": p.excerpt,
            })).collect::<Vec<_>>(),
        });
    }
}

// ---------------------------------------------------------------- the run

/// Replay every FAIL in `results` and apply the verdicts in place. Needs the planned `cases` to
/// rebuild requests. Safe to call with nothing failed (returns an empty summary).
pub fn verify_failures(
    results: &mut [CaseExecutionResult],
    cases: &[PlannedCase],
    target: &str,
    opts: &VerifyOptions,
    budget: &mut RunBudget,
) -> VerifyOutcome {
    let mut out = VerifyOutcome {
        summary: VerificationSummary {
            k: opts.k,
            ..Default::default()
        },
        unidentified: vec![],
    };
    if opts.k == 0 {
        out.summary.stopped = Some("disabled (READYHAI_VERIFY_K=0)".into());
        return out;
    }
    let candidates: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, r)| r.status == "FAIL")
        .map(|(i, _)| i)
        .collect();
    if candidates.is_empty() {
        return out;
    }
    let parsed = reqwest::Url::parse(target)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some());
    let clients = parsed
        .as_ref()
        .and_then(|u| Clients::new(opts.timeout, u).ok());
    let host = parsed
        .as_ref()
        .map(|u| {
            format!(
                "{}:{}",
                u.host_str().unwrap_or(""),
                u.port_or_known_default().unwrap_or(0)
            )
        })
        .unwrap_or_default();
    let mut stop: Option<String> = match (&parsed, &clients) {
        (None, _) => Some("target is not an http(s) URL".into()),
        (_, None) => Some("could not build the HTTP client".into()),
        _ => None,
    };
    let requests_before = budget.requests_used();
    let mut unreachable_in_a_row = 0u32;

    for i in candidates {
        let k = k_for(&results[i], opts);
        let sev = severity_of(&results[i]);
        let orig: BTreeSet<String> = results[i]
            .oracle
            .as_ref()
            .map(fail_codes)
            .unwrap_or_default();
        let orig_status = results[i].status_code;
        let plan = plan_for(&results[i], cases, opts.dry_run);
        let (mut rec, replays) = match plan {
            Plan::Skip(why) => record_for(
                &results[i],
                k,
                sev,
                vec![],
                Some(why),
                Some(VerifyVerdict::Unverified),
            ),
            _ if stop.is_some() || budget.is_cancelled() => {
                let why = stop.clone().unwrap_or_else(|| "run cancelled".into());
                stop.get_or_insert_with(|| why.clone());
                record_for(
                    &results[i],
                    k,
                    sev,
                    vec![],
                    Some(format!("not replayed: {why}")),
                    Some(VerifyVerdict::Unverified),
                )
            }
            Plan::Http(case) => {
                let ctx = Ctx {
                    clients: clients.as_ref().expect("checked above"),
                    target,
                    host: &host,
                    opts,
                };
                match build_request(&case, target) {
                    Err(e) => record_for(
                        &results[i],
                        k,
                        sev,
                        vec![],
                        Some(format!("the request could not be rebuilt: {e}")),
                        Some(VerifyVerdict::Unverified),
                    ),
                    Ok(spec) => {
                        let auth = resolve_auth(&spec.auth, opts.credentials);
                        let mut replays = vec![];
                        for n in 1..=k {
                            if let Err(m) = budget.take_request(&host) {
                                stop.get_or_insert(m.clone());
                                replays.push(Replay::errored(n, format!("not sent: {m}")));
                                break;
                            }
                            let p = replay_http(
                                &ctx,
                                &case,
                                &spec,
                                &auth,
                                &orig,
                                orig_status,
                                n,
                                &mut out.unidentified,
                            );
                            let transport = p.rec.status_code.is_none();
                            replays.push(p);
                            if transport {
                                break; // a transport error is not a verdict and is not retried
                            }
                        }
                        let note = stop.as_ref().map(|m| format!("replays stopped: {m}"));
                        record_for(&results[i], k, sev, replays, note, None)
                    }
                }
            }
            Plan::Chain(case, steps) => {
                let ctx = Ctx {
                    clients: clients.as_ref().expect("checked above"),
                    target,
                    host: &host,
                    opts,
                };
                match super::stateful::preflight(&steps, opts.credentials) {
                    Err(why) => record_for(
                        &results[i],
                        k,
                        sev,
                        vec![],
                        Some(format!("chain cannot be replayed: {why}")),
                        Some(VerifyVerdict::Unverified),
                    ),
                    Ok(()) => {
                        let mut replays = vec![];
                        for n in 1..=k {
                            if budget.is_cancelled() {
                                stop.get_or_insert("run cancelled".into());
                                replays.push(Replay::errored(n, "not run: run cancelled".into()));
                                break;
                            }
                            let p = replay_chain(
                                &ctx,
                                &case,
                                &steps,
                                &orig,
                                n,
                                budget,
                                &mut out.unidentified,
                            );
                            let incomplete = p.vote == Vote::Indeterminate;
                            replays.push(p);
                            if incomplete {
                                // a chain that cannot be completed (budget, setup) will not complete again
                                if let Some(s) = budget.stopped() {
                                    stop.get_or_insert(s.to_string());
                                }
                                break;
                            }
                        }
                        let note = stop.as_ref().map(|m| format!("replays stopped: {m}"));
                        record_for(&results[i], k, sev, replays, note, None)
                    }
                }
            }
        };
        if k > opts.k {
            let why = format!(
                "k raised from {} to {k}: this case class was flaky in earlier runs (agent memory)",
                opts.k
            );
            rec.note = Some(match rec.note.take() {
                Some(n) => format!("{n}; {why}"),
                None => why,
            });
        }
        let transport_only = !replays.is_empty()
            && replays.iter().all(|p| {
                p.rec.status_code.is_none()
                    && p.rec
                        .note
                        .as_deref()
                        .is_some_and(|n| n.starts_with("not completed"))
            });
        if transport_only {
            unreachable_in_a_row += 1;
            if unreachable_in_a_row >= MAX_UNREACHABLE {
                stop.get_or_insert("target unreachable during verification".into());
            }
        } else if !replays.is_empty() {
            unreachable_in_a_row = 0;
        }
        apply(&mut results[i], &mut rec, &replays);
        out.summary.records.push(rec);
    }
    out.summary.replay_requests = budget.requests_used().saturating_sub(requests_before);
    out.summary.stopped = stop;
    out.summary.tally();
    out
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::exec::{ExecOptions, execute_cases_with};
    use crate::agent::types::CreatedLedger;
    use crate::agent::types::fixtures::planned;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// (method, path, auth) per request.
    type Log = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

    struct Srv {
        base: String,
        log: Log,
    }

    impl Srv {
        fn count(&self, method: &str, path: &str) -> usize {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|(m, p, _)| m == method && p == path)
                .count()
        }
        fn total(&self) -> usize {
            self.log.lock().unwrap().len()
        }
    }

    /// `route(method, path, nth)` -> (status, content type, body); `nth` counts requests for
    /// that method+path starting at 1.
    fn serve(
        route: impl Fn(&str, &str, usize) -> (u16, &'static str, String) + Send + Sync + 'static,
    ) -> Srv {
        serve_auth(move |m, p, n, _| route(m, p, n))
    }

    /// Like [`serve`], with the request's `Authorization` header as a 4th argument.
    fn serve_auth(
        route: impl Fn(&str, &str, usize, Option<&str>) -> (u16, &'static str, String)
        + Send
        + Sync
        + 'static,
    ) -> Srv {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log: Log = Arc::default();
        let hits: Arc<Mutex<std::collections::HashMap<String, usize>>> = Arc::default();
        let route = Arc::new(route);
        let lg = log.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (lg, hits, route) = (lg.clone(), hits.clone(), route.clone());
                std::thread::spawn(move || {
                    let mut s = s;
                    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let head_end = loop {
                        let n = s.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let mut first = head.lines().next().unwrap_or("").split_whitespace();
                    let (method, target) = (
                        first.next().unwrap_or("").to_string(),
                        first.next().unwrap_or("/").to_string(),
                    );
                    let path = target.split('?').next().unwrap_or("/").to_string();
                    let auth = head.lines().find_map(|l| {
                        l.to_ascii_lowercase()
                            .starts_with("authorization:")
                            .then(|| l["authorization:".len()..].trim().to_string())
                    });
                    let clen = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + clen {
                        let n = s.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let nth = {
                        let mut h = hits.lock().unwrap();
                        let e = h.entry(format!("{method} {path}")).or_insert(0);
                        *e += 1;
                        *e
                    };
                    lg.lock()
                        .unwrap()
                        .push((method.clone(), path.clone(), auth.clone()));
                    let (code, ctype, body) = route(&method, &path, nth, auth.as_deref());
                    let _ = write!(
                        s,
                        "HTTP/1.1 {code} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                });
            }
        });
        Srv { base, log }
    }

    fn case(id: &str, tech: &str, method: &str, comp: &str) -> PlannedCase {
        let mut c = planned(id, tech, method, comp);
        c.role = Some("anon".into());
        c
    }

    fn exec_opts() -> ExecOptions {
        ExecOptions {
            dry_run: false,
            is_spa_target: false,
            credentials: Credentials::none(),
            reruns: 0, // the executor must not do the verifier's job here
            timeout: Duration::from_secs(5),
        }
    }

    fn vopts(creds: &Credentials, k: u32) -> VerifyOptions<'_> {
        VerifyOptions {
            k,
            raise_k: no_raise(),
            dry_run: false,
            is_spa_target: false,
            credentials: creds,
            timeout: Duration::from_secs(5),
        }
    }

    fn budget(max_requests: usize) -> RunBudget {
        RunBudget::new(100, max_requests, Duration::from_secs(60), 0.0)
    }

    /// Execute then verify with separate budgets; returns (results, outcome).
    fn run(
        srv: &Srv,
        cases: &[PlannedCase],
        k: u32,
        verify_budget: &mut RunBudget,
    ) -> (Vec<CaseExecutionResult>, VerifyOutcome) {
        let mut results = execute_cases_with(cases, &srv.base, &exec_opts(), &mut budget(500));
        let creds = Credentials::none();
        let o = verify_failures(
            &mut results,
            cases,
            &srv.base,
            &vopts(&creds, k),
            verify_budget,
        );
        (results, o)
    }

    fn status<'a>(r: &'a [CaseExecutionResult], id: &str) -> &'a CaseExecutionResult {
        r.iter().find(|r| r.case_id == id).unwrap()
    }

    #[test]
    fn k_comes_from_the_environment_text_with_a_default_and_a_cap() {
        assert_eq!(parse_k(None), 2);
        assert_eq!(parse_k(Some("")), 2);
        assert_eq!(parse_k(Some("banana")), 2);
        assert_eq!(parse_k(Some("-1")), 2);
        assert_eq!(parse_k(Some("3")), 3);
        assert_eq!(parse_k(Some(" 5 ")), 5);
        assert_eq!(parse_k(Some("99")), 5, "capped at 5");
        assert_eq!(parse_k(Some("0")), 0, "0 switches verification off");
    }

    #[test]
    fn unlikely_ids_are_recognised() {
        for c in [
            "/orders/999999",
            "/o/999999999?x=1",
            "/x/readyhai-nonexistent",
            "/u/00000000-0000-4000-8000-000000999999",
        ] {
            assert!(targets_unlikely_id(c), "{c}");
        }
        for c in [
            "/orders/1",
            "/orders/99999",
            "/orders/12999999",
            "/orders",
            "/users/alice",
        ] {
            assert!(!targets_unlikely_id(c), "{c}");
        }
    }

    #[test]
    fn a_deterministic_fail_is_confirmed_and_stays_a_defect() {
        let srv = serve(|_, p, _| match p {
            "/search" => (
                500,
                "text/plain",
                "Traceback (most recent call last):\n  File \"a.py\"".into(),
            ),
            _ => (404, "application/json", "{}".into()),
        });
        let mut c = case("TC-001", "injection", "GET", "/search");
        c.payload = Some("q='".into());
        let (results, o) = run(&srv, &[c], 2, &mut budget(50));
        let r = status(&results, "TC-001");
        assert_eq!(r.status, "FAIL");
        assert!(!r.flaky);
        let rec = o.summary.record("TC-001").unwrap();
        assert_eq!(rec.verdict, VerifyVerdict::Confirmed);
        assert_eq!((rec.k, rec.completed, rec.reproduced), (2, 2, 2));
        assert_eq!(rec.ratio().as_deref(), Some("2/2"));
        assert_eq!(rec.replays.len(), 2);
        assert!(
            rec.replays
                .iter()
                .all(|p| p.reproduced && p.status_code == Some(500))
        );
        assert_eq!(
            srv.count("GET", "/search"),
            3,
            "the original plus two replays"
        );
        assert_eq!(o.summary.replay_requests, 2);
        assert_eq!((o.summary.confirmed, o.summary.replayed), (1, 1));
        assert_eq!(o.summary.pass_k, Some(1.0));
        // the replays are written into the case's evidence file
        let v = &r.evidence_detail.as_ref().unwrap()["verification"];
        assert_eq!(v["verdict"], "confirmed");
        assert_eq!(v["replays"].as_array().unwrap().len(), 2);
        assert_eq!(v["replays"][0]["status_code"], 500);
        assert!(
            v["replays"][0]["response_excerpt"]
                .as_str()
                .unwrap()
                .contains("Traceback")
        );
        assert_eq!(rec.evidence_file, r.evidence_file);
    }

    #[test]
    fn a_case_known_as_flaky_is_replayed_with_the_maximum_k() {
        let srv = serve(|_, p, _| match p {
            "/search" | "/find" => (
                500,
                "text/plain",
                "Traceback (most recent call last)".into(),
            ),
            _ => (404, "application/json", "{}".into()),
        });
        let mut a = case("TC-001", "injection", "GET", "/search");
        a.payload = Some("q='".into());
        let mut b = case("TC-002", "injection", "GET", "/find");
        b.payload = Some("q='".into());
        let cases = [a, b];
        let raise: BTreeSet<String> = ["TC-002".to_string()].into();
        let creds = Credentials::none();
        let mut results = execute_cases_with(&cases, &srv.base, &exec_opts(), &mut budget(500));
        let mut o = vopts(&creds, 2);
        o.raise_k = &raise;
        let out = verify_failures(&mut results, &cases, &srv.base, &o, &mut budget(100));
        let (ra, rb) = (
            out.summary.record("TC-001").unwrap(),
            out.summary.record("TC-002").unwrap(),
        );
        assert_eq!((ra.k, ra.replays.len()), (2, 2));
        assert_eq!((rb.k, rb.replays.len()), (MAX_K, MAX_K as usize));
        assert_eq!(rb.ratio().as_deref(), Some("5/5"));
        assert!(
            rb.note
                .as_deref()
                .unwrap()
                .contains("flaky in earlier runs")
        );
        assert!(ra.note.is_none());
        assert_eq!(out.summary.k, 2, "the run's own k is unchanged");
        // verification off stays off, whatever memory says
        let mut results = execute_cases_with(&cases, &srv.base, &exec_opts(), &mut budget(500));
        let mut o = vopts(&creds, 0);
        o.raise_k = &raise;
        let out = verify_failures(&mut results, &cases, &srv.base, &o, &mut budget(100));
        assert!(out.summary.records.is_empty());
    }

    #[test]
    fn contract_and_latency_findings_are_confirmed_by_replays_and_a_one_off_slow_answer_is_not() {
        use crate::agent::types::ResponseContract;
        let srv = serve(|_, p, nth| match p {
            // bug 5 of the QA fixture: the required `total` is missing, every time
            "/orders/2" => (200, "application/json", r#"{"id":2}"#.into()),
            "/slow" => {
                std::thread::sleep(Duration::from_millis(1100));
                (200, "application/json", "{}".into())
            }
            "/once-slow" => {
                if nth == 1 {
                    std::thread::sleep(Duration::from_millis(1100));
                }
                (200, "application/json", "{}".into())
            }
            _ => (404, "application/json", "{}".into()),
        });
        let order = serde_json::json!({"type":"object","required":["id","total"],"properties":{
            "id":{"type":"integer"},"total":{"type":"integer"}}});
        let read = |id: &str, comp: &str, schema: Option<Value>, latency: bool| {
            let mut c = case(id, "state_transition", "GET", comp);
            c.expected_status = Some(200);
            c.contract = Some(ResponseContract {
                responses: [("200".to_string(), schema)].into(),
                latency,
            });
            c
        };
        let cases = [
            read("TC-001", "/orders/2", Some(order), false),
            read("TC-002", "/slow", None, true),
            read("TC-003", "/once-slow", None, true),
        ];
        let (results, o) = run(&srv, &cases, 2, &mut budget(50));

        let c = status(&results, "TC-001");
        assert_eq!(c.status, "FAIL", "{:?}", c.failure_reason);
        assert_eq!(
            c.oracle.as_ref().unwrap().first_fail().unwrap().code,
            "contract_fields"
        );
        let rec = o.summary.record("TC-001").unwrap();
        assert_eq!(
            (rec.verdict, rec.ratio().as_deref()),
            (VerifyVerdict::Confirmed, Some("2/2"))
        );

        let c = status(&results, "TC-002");
        assert_eq!(c.status, "FAIL", "{:?}", c.failure_reason);
        assert_eq!(
            c.oracle.as_ref().unwrap().first_fail().unwrap().code,
            "slow_response"
        );
        let rec = o.summary.record("TC-002").unwrap();
        assert_eq!(
            (rec.verdict, rec.ratio().as_deref()),
            (VerifyVerdict::Confirmed, Some("2/2"))
        );
        assert!(
            rec.replays.iter().all(|p| p.latency_ms > 1000),
            "{:?}",
            rec.replays
        );

        // slow once, fast on both replays: not a slow endpoint, so not a defect
        let c = status(&results, "TC-003");
        assert_eq!(c.status, "INCONCLUSIVE", "{:?}", c.failure_reason);
        assert_eq!(
            o.summary.record("TC-003").unwrap().verdict,
            VerifyVerdict::NotReproduced
        );
    }

    #[test]
    fn a_fail_the_fixture_serves_only_once_is_not_reproduced_and_becomes_inconclusive() {
        let srv = serve(|_, p, nth| match p {
            "/once" if nth == 1 => (500, "text/plain", "boom".into()),
            "/once" => (200, "application/json", "{\"ok\":true}".into()),
            _ => (404, "application/json", "{}".into()),
        });
        let c = case("TC-001", "boundary", "GET", "/once");
        let (results, o) = run(&srv, &[c], 2, &mut budget(50));
        let r = status(&results, "TC-001");
        assert_eq!(
            r.status, "INCONCLUSIVE",
            "{:?} {:?}",
            r.failure_reason, o.summary
        );
        assert!(
            r.failure_reason
                .as_deref()
                .unwrap()
                .starts_with("not reproduced")
        );
        assert!(
            r.failure_reason
                .as_deref()
                .unwrap()
                .contains("server error HTTP 500"),
            "the original failure stays in the note"
        );
        let rec = o.summary.record("TC-001").unwrap();
        assert_eq!(rec.verdict, VerifyVerdict::NotReproduced);
        assert_eq!(
            (rec.original_status.as_str(), rec.final_status.as_str()),
            ("FAIL", "INCONCLUSIVE")
        );
        assert_eq!(
            (
                o.summary.not_reproduced,
                o.summary.confirmed,
                o.summary.pass_k
            ),
            (1, 0, Some(0.0))
        );
        // the oracle verdict of the original run is kept as evidence
        assert!(r.oracle.as_ref().unwrap().first_fail().is_some());
    }

    #[test]
    fn a_flaky_high_failure_stays_fail_with_the_flag_and_a_flaky_medium_one_becomes_warn() {
        // original + first replay fail, second replay passes: 1 of 2 reproduced
        let srv = serve(|_, p, nth| match p {
            // /search leaks a trace (high); /list is a bare 500 (medium)
            "/search" if nth <= 2 => (
                500,
                "text/plain",
                "Traceback (most recent call last):\n  x".into(),
            ),
            "/list" if nth <= 2 => (500, "text/plain", "boom".into()),
            "/search" | "/list" => (200, "application/json", "{\"results\":[]}".into()),
            _ => (404, "application/json", "{}".into()),
        });
        let mut high = case("TC-001", "injection", "GET", "/search");
        high.payload = Some("q='".into());
        let medium = case("TC-002", "boundary", "GET", "/list");
        let (results, o) = run(&srv, &[high, medium], 2, &mut budget(50));
        let h = status(&results, "TC-001");
        assert_eq!(
            h.status, "FAIL",
            "a high-severity failure is never demoted for flakiness"
        );
        assert!(h.flaky);
        assert!(
            h.failure_reason
                .as_deref()
                .unwrap()
                .contains("flaky: reproduced on 1 of 2")
        );
        let m = status(&results, "TC-002");
        assert_eq!(m.status, "WARN");
        assert!(m.flaky);
        let rec = o.summary.record("TC-001").unwrap();
        assert_eq!(rec.verdict, VerifyVerdict::Flaky);
        assert_eq!(rec.ratio().as_deref(), Some("1/2"));
        assert_eq!(rec.severity, "high");
        assert_eq!(o.summary.flaky, 2);
        assert_eq!(o.summary.pass_k, Some(0.0));
    }

    #[test]
    fn replays_are_charged_to_the_budget_and_an_exhausted_budget_leaves_the_fail_unverified() {
        let srv = serve(|_, p, _| match p {
            "/search" => (
                500,
                "text/plain",
                "Traceback (most recent call last):\n  x".into(),
            ),
            _ => (404, "application/json", "{}".into()),
        });
        let mut c = case("TC-001", "injection", "GET", "/search");
        c.payload = Some("q='".into());
        let mut b = budget(1); // one replay request is all there is
        let (results, o) = run(&srv, &[c], 3, &mut b);
        assert_eq!(b.requests_used(), 1, "never more than the budget allows");
        assert_eq!(
            srv.count("GET", "/search"),
            2,
            "original + exactly one replay"
        );
        let r = status(&results, "TC-001");
        assert_eq!(
            r.status, "FAIL",
            "an unfinished verification never demotes a failure"
        );
        let rec = o.summary.record("TC-001").unwrap();
        assert_eq!(rec.verdict, VerifyVerdict::Unverified);
        assert_eq!((rec.completed, rec.reproduced), (1, 1));
        assert!(
            o.summary
                .stopped
                .as_deref()
                .unwrap()
                .contains("request budget exhausted"),
            "{:?}",
            o.summary.stopped
        );
        assert_eq!(o.summary.replay_requests, 1);
        assert_eq!(o.summary.pass_k, None, "nothing was fully replayed");
        // a budget with room for everything sends exactly k replays
        let mut b2 = budget(50);
        let c2 = {
            let mut c = case("TC-001", "injection", "GET", "/search");
            c.payload = Some("q='".into());
            c
        };
        let (_, o2) = run(&srv, &[c2], 3, &mut b2);
        assert_eq!(b2.requests_used(), 3);
        assert_eq!(
            o2.summary.record("TC-001").unwrap().verdict,
            VerifyVerdict::Confirmed
        );
    }

    #[test]
    fn a_cancelled_run_sends_no_replay() {
        let srv = serve(|_, _, _| {
            (
                500,
                "text/plain",
                "Traceback (most recent call last):\n  x".into(),
            )
        });
        let mut c = case("TC-001", "injection", "GET", "/search");
        c.payload = Some("q='".into());
        let mut results =
            execute_cases_with(&[c.clone()], &srv.base, &exec_opts(), &mut budget(50));
        assert_eq!(results[0].status, "FAIL");
        let sent_before = srv.total();
        let token = crate::agent::types::CancelToken::new();
        token.cancel();
        let mut b = budget(50).with_cancel(token);
        let creds = Credentials::none();
        let o = verify_failures(&mut results, &[c], &srv.base, &vopts(&creds, 2), &mut b);
        assert_eq!(
            srv.total(),
            sent_before,
            "nothing was sent after cancellation"
        );
        assert_eq!(
            o.summary.record("TC-001").unwrap().verdict,
            VerifyVerdict::Unverified
        );
        assert_eq!(results[0].status, "FAIL");
        assert_eq!(o.summary.stopped.as_deref(), Some("run cancelled"));
    }

    #[test]
    fn verification_off_or_nothing_failed_sends_nothing() {
        let srv = serve(|_, _, _| (200, "application/json", "{}".into()));
        let c = case("TC-001", "boundary", "GET", "/ok");
        let (_, o) = run(&srv, std::slice::from_ref(&c), 2, &mut budget(50));
        assert_eq!(o.summary.candidates, 0);
        assert_eq!(srv.total(), 1);
        let srv2 = serve(|_, _, _| (500, "text/plain", "x".into()));
        let (r, o2) = run(&srv2, &[c], 0, &mut budget(50));
        assert_eq!(srv2.total(), 1, "k = 0: no replay");
        assert_eq!(r[0].status, "FAIL");
        assert!(
            o2.summary
                .stopped
                .as_deref()
                .unwrap()
                .starts_with("disabled")
        );
        assert!(o2.summary.records.is_empty());
    }

    #[test]
    fn a_write_fail_is_replayed_only_when_the_case_made_its_own_resource_or_uses_a_throwaway_id() {
        // POST /made answers 201 with an id but is judged a FAIL by an expected status; the
        // replays create more orders, which land on the run's ledger
        let n = Arc::new(AtomicUsize::new(100));
        let nn = n.clone();
        let srv = serve(move |m, p, _| match (m, p) {
            ("POST", "/made") => (
                201,
                "application/json",
                format!("{{\"id\": {}}}", nn.fetch_add(1, Ordering::SeqCst)),
            ),
            ("PUT", "/orders/999999") => (500, "application/json", "{\"error\":\"x\"}".into()),
            ("PUT", "/orders/7") => (500, "application/json", "{\"error\":\"x\"}".into()),
            _ => (404, "application/json", "{}".into()),
        });
        let mut made = case("TC-001", "boundary", "POST", "/made");
        made.payload = Some("{\"item\":\"a\"}".into());
        made.expected_status = Some(400);
        let throwaway = case("TC-002", "boundary", "PUT", "/orders/999999");
        let real = case("TC-003", "boundary", "PUT", "/orders/7");
        let ledger = CreatedLedger::new();
        let (results, o) = {
            let _scope = ledger.install();
            run(&srv, &[made, throwaway, real], 2, &mut budget(50))
        };
        assert_eq!(status(&results, "TC-001").status, "FAIL");
        let a = o.summary.record("TC-001").unwrap();
        assert_eq!((a.verdict, a.reproduced), (VerifyVerdict::Confirmed, 2));
        assert_eq!(srv.count("POST", "/made"), 3);
        let b = o.summary.record("TC-002").unwrap();
        assert_eq!(b.verdict, VerifyVerdict::Confirmed, "{:?}", b.note);
        assert_eq!(srv.count("PUT", "/orders/999999"), 3);
        let c = o.summary.record("TC-003").unwrap();
        assert_eq!(c.verdict, VerifyVerdict::Unverified);
        assert!(
            c.note.as_deref().unwrap().starts_with("unverified-write"),
            "{:?}",
            c.note
        );
        assert_eq!(c.replays.len(), 0);
        assert_eq!(
            srv.count("PUT", "/orders/7"),
            1,
            "a write on a real record is sent once, never repeated"
        );
        assert_eq!(status(&results, "TC-003").status, "FAIL", "not demoted");
        // the resources the replays created are on the ledger with the replay's case id, ready for teardown
        let made_by_replays: Vec<_> = ledger
            .entries()
            .into_iter()
            .filter(|r| {
                r.case_id
                    .as_deref()
                    .is_some_and(|c| c.starts_with("TC-001-V"))
            })
            .collect();
        assert_eq!(made_by_replays.len(), 2, "{:?}", ledger.entries());
        assert!(o.unidentified.is_empty());
    }

    #[test]
    fn a_replay_that_creates_a_resource_without_an_id_is_reported_as_unidentified() {
        let srv = serve(|m, p, _| match (m, p) {
            ("POST", "/made") => (201, "application/json", "{}".into()),
            _ => (404, "application/json", "{}".into()),
        });
        let mut made = case("TC-001", "boundary", "POST", "/made");
        made.expected_status = Some(400);
        let ledger = CreatedLedger::new();
        let (_, o) = {
            let _scope = ledger.install();
            run(&srv, &[made], 2, &mut budget(50))
        };
        assert_eq!(o.unidentified.len(), 2, "one per replay");
        assert!(o.unidentified[0].reason.contains("TC-001-V1"));
    }

    #[test]
    fn credentials_are_attached_afresh_and_only_to_the_target() {
        let srv = serve(|_, p, _| match p {
            "/me" => (
                500,
                "text/plain",
                "Traceback (most recent call last):\n  x".into(),
            ),
            _ => (404, "application/json", "{}".into()),
        });
        let mut c = case("TC-001", "injection", "GET", "/me");
        c.role = Some("user".into());
        c.payload = Some("q='".into());
        let creds = Credentials::none().with("user", "tok-user");
        let mut results = execute_cases_with(
            &[c.clone()],
            &srv.base,
            &ExecOptions {
                credentials: creds.clone(),
                ..exec_opts()
            },
            &mut budget(50),
        );
        let o = verify_failures(
            &mut results,
            &[c],
            &srv.base,
            &vopts(&creds, 2),
            &mut budget(50),
        );
        assert_eq!(
            o.summary.record("TC-001").unwrap().verdict,
            VerifyVerdict::Confirmed
        );
        let log = srv.log.lock().unwrap();
        assert_eq!(log.len(), 3);
        assert!(
            log.iter()
                .all(|(_, _, a)| a.as_deref() == Some("Bearer tok-user")),
            "{log:?}"
        );
        // nothing stored in the report carries the token
        let json = serde_json::to_string(&o.summary).unwrap();
        assert!(!json.contains("tok-user"));
        let detail = results[0].evidence_detail.as_ref().unwrap().to_string();
        assert!(!detail.contains("tok-user"), "{detail}");
    }

    #[test]
    fn a_burst_result_is_not_replayed_and_stays_a_failure() {
        let mut r = crate::agent::types::fixtures::result("TC-001-B", "state_transition", "FAIL");
        r.method = "POST".into();
        r.component = "/orders".into();
        let c = case("TC-001", "state_transition", "POST", "/orders");
        let srv = serve(|_, _, _| (200, "application/json", "{}".into()));
        let creds = Credentials::none();
        let mut res = vec![r];
        let o = verify_failures(
            &mut res,
            &[c],
            &srv.base,
            &vopts(&creds, 2),
            &mut budget(50),
        );
        let rec = o.summary.record("TC-001-B").unwrap();
        assert_eq!(rec.verdict, VerifyVerdict::Unverified);
        assert!(rec.note.as_deref().unwrap().contains("concurrency burst"));
        assert_eq!(res[0].status, "FAIL");
        assert_eq!(srv.total(), 0);
    }

    #[test]
    fn an_adaptive_mutation_sub_case_is_replayed_with_its_mutated_payload() {
        let srv = serve(|_, p, _| match p {
            "/search" => (
                500,
                "text/plain",
                "Traceback (most recent call last):\n  x".into(),
            ),
            _ => (404, "application/json", "{}".into()),
        });
        let mut base = case("TC-001", "injection", "GET", "/search");
        base.payload = Some("q=ok".into());
        let mut r = crate::agent::types::fixtures::result("TC-001-M1", "injection", "FAIL");
        r.method = "GET".into();
        r.component = "/search".into();
        r.request_payload = Some("q='mutated".into());
        r.oracle = Some(OracleOutcome {
            verdict: Verdict::Fail,
            checks: vec![crate::agent::oracle::OracleCheck {
                code: "server_error".into(),
                verdict: Verdict::Fail,
                severity: Some(Severity::High),
                detail: "server error".into(),
            }],
            warnings: vec![],
            exploratory: false,
        });
        let creds = Credentials::none();
        let mut res = vec![r];
        let o = verify_failures(
            &mut res,
            &[base],
            &srv.base,
            &vopts(&creds, 2),
            &mut budget(50),
        );
        assert_eq!(
            o.summary.record("TC-001-M1").unwrap().verdict,
            VerifyVerdict::Confirmed
        );
        let seen: Vec<String> = srv
            .log
            .lock()
            .unwrap()
            .iter()
            .map(|(_, p, _)| p.clone())
            .collect();
        assert_eq!(seen.len(), 2);
    }
    #[test]
    fn replay_votes_follow_the_original_failing_checks() {
        use crate::agent::oracle::OracleCheck;
        let outcome = |v: Verdict, codes: &[&str]| OracleOutcome {
            verdict: v,
            checks: codes
                .iter()
                .map(|c| OracleCheck {
                    code: (*c).into(),
                    verdict: v,
                    severity: Some(Severity::High),
                    detail: String::new(),
                })
                .collect(),
            warnings: vec![],
            exploratory: false,
        };
        let orig: BTreeSet<String> = ["server_error".to_string()].into();
        assert_eq!(
            vote(&orig, &outcome(Verdict::Fail, &["server_error"]), true),
            Vote::Reproduced
        );
        assert_eq!(
            vote(
                &orig,
                &outcome(Verdict::Fail, &["server_error", "x"]),
                false
            ),
            Vote::Reproduced
        );
        assert_eq!(
            vote(&orig, &outcome(Verdict::Pass, &["ok"]), true),
            Vote::NotReproduced
        );
        // a different failure is neither a reproduction nor a clean bill
        assert_eq!(
            vote(&orig, &outcome(Verdict::Fail, &["expected_status"]), false),
            Vote::Indeterminate
        );
        // inconclusive: the status moved => the failure is gone; the same answer judged inconclusively is no vote
        assert_eq!(
            vote(
                &orig,
                &outcome(Verdict::Inconclusive, &["no_assertion"]),
                false
            ),
            Vote::NotReproduced
        );
        assert_eq!(
            vote(
                &orig,
                &outcome(Verdict::Inconclusive, &["no_assertion"]),
                true
            ),
            Vote::Indeterminate
        );
        // no original oracle: any failure reproduces
        assert_eq!(
            vote(
                &BTreeSet::new(),
                &outcome(Verdict::Fail, &["anything"]),
                true
            ),
            Vote::Reproduced
        );
    }

    // ------------------------------------------------------------ inside a whole run

    fn run_opts(k: u32) -> crate::agent::pipeline::RunOptions {
        crate::agent::pipeline::RunOptions {
            budget: RunBudget::new(80, 800, Duration::from_secs(120), 0.0),
            credentials: Credentials::none(),
            llm: crate::agent::pipeline::LlmMode::Off,
            reruns: 0,
            verify_k: k,
            request_timeout: Duration::from_secs(5),
            lookup_requester_ip: false,
            workers: 4,
            memory_dir: None,
        }
    }

    fn run_req(target: &str) -> crate::agent::types::AgentRunRequest {
        crate::agent::types::AgentRunRequest {
            target: target.into(),
            profile: "standard".into(),
            spec_url: None,
            custom_instructions: None,
            max_steps: None,
            dry_run: false,
            thinking: false,
            model_tier: "high".into(),
            thinking_budget_tokens: 8192,
            repo: None,
            diff_base: None,
        }
    }

    /// `/.env` always leaks; `/.git/config` leaks on its 2nd request only (discovery probes it once,
    /// the executor's request is the 2nd) and is a 404 otherwise, replays included.
    fn leaky_srv() -> Srv {
        serve(|m, p, nth| match (m, p) {
            ("GET", "/") => (
                200,
                "text/html",
                "<html><head><title>fixture</title></head><body>hi</body></html>".into(),
            ),
            ("GET", "/.env") => (
                200,
                "text/plain",
                "DB_PASSWORD=hunter2\nSECRET_KEY=abc123\n".into(),
            ),
            ("GET", "/.git/config") if nth == 2 => (
                200,
                "text/plain",
                "[core]\n\trepositoryformatversion = 0\n".into(),
            ),
            _ => (404, "application/json", "{\"error\":\"not found\"}".into()),
        })
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rh-verify-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_run_verifies_before_triage_and_only_reproducible_failures_become_defects() {
        let srv = leaky_srv();
        let base = tmpdir("run");
        let rep = crate::agent::pipeline::run_with(
            &base,
            &run_req(&srv.base),
            "run-verify",
            run_opts(2),
            Some(false),
        )
        .unwrap();
        let by_component = |c: &str| {
            rep.executed_results
                .iter()
                .find(|r| r.component == c)
                .unwrap()
        };
        let env = by_component("/.env");
        let git = by_component("/.git/config");
        assert_eq!(env.status, "FAIL", "{:?}", env.failure_reason);
        assert_eq!(
            git.status, "INCONCLUSIVE",
            "served once: not a defect ({:?})",
            git.failure_reason
        );
        assert!(
            git.failure_reason
                .as_deref()
                .unwrap()
                .starts_with("not reproduced")
        );
        assert_eq!(
            srv.count("GET", "/.env"),
            4,
            "discovery + original + 2 replays"
        );
        assert_eq!(
            srv.count("GET", "/.git/config"),
            4,
            "discovery + original + 2 replays"
        );
        // defects: the leak is verified 2/2, the one-off is not a defect
        let d = rep
            .triaged_defects
            .iter()
            .find(|d| d.component == "/.env")
            .expect("defect for /.env");
        assert!(
            d.verified
                && d.reproduced.as_deref() == Some("2/2")
                && d.verification.as_deref() == Some("confirmed"),
            "{d:?}"
        );
        assert!(
            rep.triaged_defects
                .iter()
                .all(|d| d.component != "/.git/config")
        );
        // ledger: summary, pass^k, gate
        let l = rep.evidence_ledger.as_ref().unwrap();
        let v = l.verification.as_ref().expect("verification summary");
        assert_eq!(
            (v.k, v.confirmed, v.not_reproduced, v.unverified),
            (2, 1, 1, 0),
            "{v:?}"
        );
        assert_eq!(v.pass_k, Some(0.5));
        assert_eq!(
            l.gate_verdict, "NO_GO",
            "the confirmed critical leak blocks"
        );
        assert!(
            l.executive_summary.contains("pass^2 50%"),
            "{}",
            l.executive_summary
        );
        // the replays count against the run budget and are logged
        let b = rep.budget.as_ref().unwrap();
        assert!(b.requests >= 4 && b.requests <= b.max_requests, "{b:?}");
        assert!(
            rep.steps
                .iter()
                .any(|s| s.agent == "Verifier" && s.details.contains("1 confirmed")),
            "{:?}",
            rep.steps
                .iter()
                .map(|s| (&s.agent, &s.details))
                .collect::<Vec<_>>()
        );
        assert!(
            rep.notes
                .iter()
                .any(|n| n.starts_with("verification:") && n.contains("INCONCLUSIVE"))
        );
        assert_eq!(rep.stage_sources["verifier"], "deterministic, k=2");
        // evidence file carries the replays
        let ev = std::fs::read_to_string(
            base.join("run-verify")
                .join(env.evidence_file.as_ref().unwrap()),
        )
        .unwrap();
        let ev: Value = serde_json::from_str(&ev).unwrap();
        assert_eq!(ev["verification"]["verdict"], "confirmed");
        assert_eq!(ev["verification"]["replays"].as_array().unwrap().len(), 2);
        // reports: a Verification section and the per-defect status
        let html = crate::agent::report::generate_agent_html_report(&rep);
        assert!(
            html.contains("Verification (independent replay)")
                && html.contains("Verified 2/2")
                && html.contains("pass^k"),
            "html"
        );
        let md = crate::agent::report::generate_agent_markdown_report(&rep);
        assert!(
            md.contains("## Verification")
                && md.contains("Verified 2/2")
                && md.contains("Not reproduced"),
            "md"
        );
        // persisted report round-trips with the new fields
        let back = crate::agent::store::load_agent_run_in(&base, "run-verify").unwrap();
        let bd = back
            .triaged_defects
            .iter()
            .find(|d| d.component == "/.env")
            .unwrap();
        assert!(bd.verified && back.evidence_ledger.unwrap().verification.unwrap().replayed == 2);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn with_verification_off_the_run_behaves_as_before_and_says_so() {
        let srv = leaky_srv();
        let base = tmpdir("off");
        let rep = crate::agent::pipeline::run_with(
            &base,
            &run_req(&srv.base),
            "run-noverify",
            run_opts(0),
            Some(false),
        )
        .unwrap();
        assert_eq!(srv.count("GET", "/.env"), 2, "discovery + original");
        assert_eq!(srv.count("GET", "/.git/config"), 2, "discovery + original");
        assert!(
            rep.executed_results
                .iter()
                .filter(|r| r.status == "FAIL")
                .count()
                >= 2,
            "both leaks stay FAIL"
        );
        assert!(
            rep.triaged_defects
                .iter()
                .all(|d| !d.verified && d.verification.is_none())
        );
        let v = rep.evidence_ledger.unwrap().verification.unwrap();
        assert_eq!(v.k, 0);
        assert!(v.stopped.unwrap().starts_with("disabled"));
        assert_eq!(rep.stage_sources["verifier"], "off");
        let _ = std::fs::remove_dir_all(&base);
    }
    #[test]
    fn a_stateful_chain_is_replayed_end_to_end_and_the_orders_it_made_are_torn_down_later() {
        use crate::agent::types::StatefulStep;
        // BOLA: anyone can read any order
        let next = Arc::new(AtomicUsize::new(300));
        let n2 = next.clone();
        let srv = serve_auth(move |m, p, _, auth| match (m, p, auth) {
            ("POST", "/orders", Some("Bearer tok-user")) => (
                201,
                "application/json",
                format!("{{\"id\": {}}}", n2.fetch_add(1, Ordering::SeqCst)),
            ),
            // owner and bob can read, strangers cannot: bob reading it is the isolation breach
            ("GET", p, Some("Bearer tok-user" | "Bearer tok-bob")) if p.starts_with("/orders/") => {
                (200, "application/json", "{\"id\": 1}".into())
            }
            ("GET", p, _) if p.starts_with("/orders/") => (401, "application/json", "{}".into()),
            _ => (404, "application/json", "{}".into()),
        });
        let step = |n: u32, actor: &str, method: &str, path: &str| StatefulStep {
            step_number: n,
            actor: actor.into(),
            method: method.into(),
            path: path.into(),
            payload: None,
            extract_vars: None,
            expected_status: None,
            violation_condition: None,
        };
        let mut create = step(1, "user", "POST", "/orders");
        create.payload = Some("{\"item\": \"a\"}".into());
        create.extract_vars = Some(vec!["id".into()]);
        let mut read = step(2, "bob", "GET", "/orders/{{id}}");
        read.violation_condition = Some("status == 200".into());
        let mut chain = case("TC-001", "authz", "POST", "/orders");
        chain.role = Some("user".into());
        chain.stateful_steps = Some(vec![create, read]);
        let creds = Credentials::none()
            .with("user", "tok-user")
            .with("bob", "tok-bob");
        let ledger = CreatedLedger::new();
        let mut results = {
            let _scope = ledger.install();
            execute_cases_with(
                &[chain.clone()],
                &srv.base,
                &ExecOptions {
                    credentials: creds.clone(),
                    ..exec_opts()
                },
                &mut budget(100),
            )
        };
        assert_eq!(results[0].status, "FAIL", "{:?}", results[0].failure_reason);
        let made_by_exec = srv.count("POST", "/orders");
        let o = {
            let _scope = ledger.install();
            verify_failures(
                &mut results,
                &[chain],
                &srv.base,
                &vopts(&creds, 2),
                &mut budget(100),
            )
        };
        let rec = o.summary.record("TC-001").unwrap();
        assert_eq!(
            (rec.verdict, rec.reproduced),
            (VerifyVerdict::Confirmed, 2),
            "{rec:?}"
        );
        assert_eq!(
            srv.count("POST", "/orders"),
            made_by_exec + 2,
            "each replay builds its own order"
        );
        assert_eq!(results[0].status, "FAIL");
        assert!(
            o.summary.replay_requests >= 2 * 3,
            "a chain replay is charged per request: {}",
            o.summary.replay_requests
        );
        let by_replays = ledger
            .entries()
            .iter()
            .filter(|r| {
                r.case_id
                    .as_deref()
                    .is_some_and(|c| c.starts_with("TC-001-V"))
            })
            .count();
        assert_eq!(by_replays, 2, "{:?}", ledger.entries());
        assert!(o.unidentified.is_empty(), "{:?}", o.unidentified);
        // a chain whose credential is missing for the replay is unverified, not guessed
        let mut again = vec![results.remove(0)];
        again[0].status = "FAIL".into();
        let mut chain2 = case("TC-001", "authz", "POST", "/orders");
        chain2.stateful_steps = results_chain_steps();
        let none = Credentials::none();
        let o2 = verify_failures(
            &mut again,
            &[chain2],
            &srv.base,
            &vopts(&none, 2),
            &mut budget(100),
        );
        assert_eq!(
            o2.summary.record("TC-001").unwrap().verdict,
            VerifyVerdict::Unverified
        );
        assert!(
            o2.summary
                .record("TC-001")
                .unwrap()
                .note
                .as_deref()
                .unwrap()
                .contains("cannot be replayed")
        );
    }

    fn results_chain_steps() -> Option<Vec<crate::agent::types::StatefulStep>> {
        use crate::agent::types::StatefulStep;
        let mk = |n: u32, actor: &str, method: &str, path: &str| StatefulStep {
            step_number: n,
            actor: actor.into(),
            method: method.into(),
            path: path.into(),
            payload: Some("{\"item\": \"a\"}".into()).filter(|_| method == "POST"),
            extract_vars: (method == "POST").then(|| vec!["id".to_string()]),
            expected_status: None,
            violation_condition: (method == "GET").then(|| "status == 200".to_string()),
        };
        Some(vec![
            mk(1, "user", "POST", "/orders"),
            mk(2, "bob", "GET", "/orders/{{id}}"),
        ])
    }
}
