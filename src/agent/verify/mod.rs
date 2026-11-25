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

pub mod juror;
pub mod options;
pub mod plan;
pub mod replay;

#[cfg(test)]
mod tests;

pub use juror::{JurorVerdict, audit_defects_with_juror, evaluate_with_juror, parse_juror_verdict};
pub use options::{DEFAULT_K, MAX_K, VerifyOptions, VerifyOutcome, k_from_env, no_raise, parse_k};
pub use plan::targets_unlikely_id;

use std::collections::BTreeSet;

use super::budget::RunBudget;
use super::exec::{Clients, build_request, resolve_auth};
use super::oast::OastCollector;
use super::types::{
    CaseExecutionResult, PlannedCase, ProbeOracle, VerificationSummary, VerifyVerdict,
};

pub(crate) use options::{MAX_UNREACHABLE, k_for};
pub(crate) use plan::{Plan, Vote, fail_codes, plan_for, severity_of, spa_shell, vote};
pub(crate) use replay::{Ctx, Replay, apply, record_for, replay_chain, replay_http};

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
    let oast = cases
        .iter()
        .any(|c| matches!(c.probe_oracle, Some(ProbeOracle::OastCallback { .. })))
        .then(OastCollector::start)
        .and_then(Result::ok);
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
                    oast: oast.as_ref(),
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
                                budget,
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
                    oast: oast.as_ref(),
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
