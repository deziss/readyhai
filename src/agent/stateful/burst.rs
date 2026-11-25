use std::sync::Arc;

use super::models::BurstRun;
use crate::agent::budget::RunBudget;
use crate::agent::exec::role_of;
use crate::agent::exec::{
    Bearer, Clients, OutReq, RequestSpec, ResolvedAuth, Seen, is_safe_method, needs_validated_tls,
};
use crate::agent::oracle::BurstResponse;
use crate::agent::types::{current_ledger, record_creation_response};
use crate::llm::untrusted::redact_then_truncate;

/// Fire `burst_size` (2..=10) simultaneous copies of `spec`. Every request, including the two
/// read-backs, is charged to the run budget and its per-host rate limit; if the budget cannot
/// pay for at least two burst requests nothing is sent. Credentials follow the same rules as any
/// other request ([`Clients::send`]).
pub fn run_concurrency_burst(
    clients: &Clients,
    spec: &RequestSpec,
    bearer: Option<&Bearer>,
    burst_size: usize,
    budget: &mut RunBudget,
    host: &str,
    case_id: &str,
) -> Result<BurstRun, String> {
    let auth = ResolvedAuth {
        bearer: bearer.cloned(),
        extra_headers: vec![],
        authenticated: bearer.is_some(),
        real: needs_validated_tls(bearer),
        note: None,
    };
    run_concurrency_burst_auth(clients, spec, &auth, burst_size, budget, host, case_id)
}

/// [`run_concurrency_burst`] supporting multi-modal credentials (`Bearer`, `Cookie`, custom headers).
pub fn run_concurrency_burst_auth(
    clients: &Clients,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    burst_size: usize,
    budget: &mut RunBudget,
    host: &str,
    case_id: &str,
) -> Result<BurstRun, String> {
    let count = burst_size.clamp(2, 10);
    // the run's ledger is thread-local and does not reach the burst threads: hand them a clone, so
    // every 2xx creation a burst request produces is recorded (and torn down) like any other
    let ledger = current_ledger();
    let role = role_of(&spec.auth);
    let bearer = auth.bearer.as_ref();
    let mut notes = vec![];
    let read = |url: &str| {
        clients
            .send_resolved(
                &OutReq {
                    method: "GET",
                    url,
                    body: None,
                    headers: &[],
                    bearer,
                },
                auth,
            )
            .ok()
            .filter(|s| (200..=299).contains(&s.status))
            .map(|s| s.body)
    };
    // before: a safe read of the resource, to compare with after
    let mutating = !is_safe_method(spec.method);
    let pre_read = if mutating && budget.take_request(host).is_ok() {
        read(&spec.url)
    } else {
        None
    };
    // the burst itself is paid for up front, one request at a time (this paces it too)
    let mut granted = 0;
    for _ in 0..count {
        if budget.take_request(host).is_err() {
            break;
        }
        granted += 1;
    }
    if granted < 2 {
        return Err(format!(
            "the run budget allows only {granted} more request(s); a burst needs at least 2"
        ));
    }
    if granted < count {
        notes.push(format!(
            "burst reduced from {count} to {granted} by the run budget"
        ));
    }
    let barrier = Arc::new(std::sync::Barrier::new(granted));
    let mut results: Vec<Result<Seen, String>> = Vec::with_capacity(granted);
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..granted)
            .map(|_| {
                let b = barrier.clone();
                let led = ledger.clone();
                s.spawn(move || {
                    b.wait(); // all threads release at once
                    let r = clients.send_resolved(
                        &OutReq {
                            method: spec.method,
                            url: &spec.url,
                            body: spec.body.as_ref(),
                            headers: &spec.extra_headers,
                            bearer,
                        },
                        auth,
                    );
                    if let (Ok(seen), Some(l)) = (&r, led.as_ref()) {
                        record_creation_response(
                            Some(l),
                            spec.method,
                            &spec.url,
                            seen.status,
                            &seen.headers,
                            &seen.body,
                            role,
                            Some(case_id),
                        );
                    }
                    r
                })
            })
            .collect();
        for h in handles {
            results.push(h.join().unwrap_or(Err("thread panicked".to_string())));
        }
    });
    let mut responses = vec![];
    for r in results {
        match r {
            Ok(s) => responses.push(BurstResponse {
                status: s.status,
                body: s.body,
            }),
            Err(e) => notes.push(format!(
                "a burst request failed: {}",
                redact_then_truncate(&e, 160)
            )),
        }
    }
    let post_read = if pre_read.is_some() && budget.take_request(host).is_ok() {
        read(&spec.url)
    } else {
        None
    };
    let status_codes = responses.iter().map(|r| r.status).collect();
    Ok(BurstRun {
        requested: granted,
        responses,
        status_codes,
        pre_read,
        post_read,
        notes,
    })
}
