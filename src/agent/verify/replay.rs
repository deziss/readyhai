use serde_json::json;
use std::collections::BTreeSet;

use crate::agent::budget::RunBudget;
use crate::agent::exec::{
    Auth, Clients, ProbeOutcome, RequestSpec, ResolvedAuth, follows_redirects,
    send_with_probe_oracle,
};
use crate::agent::oast::OastCollector;
use super::options::VerifyOptions;
use crate::agent::oracle::{self, Observation, Severity};
use super::plan::{Vote, spa_shell, vote};
use crate::agent::types::{
    CaseExecutionResult, Leftover, PlannedCase, ReplayRecord, StatefulStep, VerificationRecord,
    VerifyVerdict, current_ledger, is_creation, record_creation_response,
};
use crate::llm::untrusted::redact_then_truncate;

pub(crate) struct Replay {
    pub(crate) rec: ReplayRecord,
    pub(crate) vote: Vote,
    pub(crate) excerpt: Option<String>,
    pub(crate) reason: Option<String>,
}

impl Replay {
    pub(crate) fn errored(n: u32, note: String) -> Replay {
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

pub(crate) struct Ctx<'a> {
    pub(crate) clients: &'a Clients,
    pub(crate) target: &'a str,
    /// `host:port`, the budget's rate-limit key.
    pub(crate) host: &'a str,
    pub(crate) opts: &'a VerifyOptions<'a>,
    pub(crate) oast: Option<&'a OastCollector>,
}

pub(crate) fn replay_http(
    ctx: &Ctx,
    budget: &mut RunBudget,
    case: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    orig: &BTreeSet<String>,
    orig_status: Option<u16>,
    n: u32,
    unidentified: &mut Vec<Leftover>,
) -> Replay {
    // a replay sees what the executor saw: a case judged on the answer after a same-origin
    // redirect is replayed through the same redirect
    let sent = send_with_probe_oracle(
        ctx.clients,
        ctx.target,
        ctx.host,
        budget,
        case,
        spec,
        auth,
        follows_redirects(case),
        ctx.oast,
    );
    let ProbeOutcome { seen, evidence, .. } = match sent {
        Ok(p) => p,
        Err(e) => {
            return Replay::errored(
                n,
                format!("not completed: {}", redact_then_truncate(&e, 200)),
            );
        }
    };
    let role = match &spec.auth {
        Auth::Role(r) => Some(r.as_str()),
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
            probe: Some(&evidence),
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

pub(crate) fn replay_chain(
    ctx: &Ctx,
    case: &PlannedCase,
    steps: &[StatefulStep],
    orig: &BTreeSet<String>,
    n: u32,
    budget: &mut RunBudget,
    unidentified: &mut Vec<Leftover>,
) -> Replay {
    let rid = format!("{}-V{n}", case.id);
    let run = crate::agent::stateful::execute_stateful_scenario(
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

pub(crate) fn record_for(
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
pub(crate) fn apply(r: &mut CaseExecutionResult, rec: &mut VerificationRecord, replays: &[Replay]) {
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
