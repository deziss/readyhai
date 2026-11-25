use serde_json::{Value, json};

use super::auth::{Auth, ResolvedAuth};
use super::builder::{RequestSpec, is_safe_method};
use super::clients::{Seen, follow_curl, follows_redirects};
use super::delete::note_creation;
use super::dispatch::{Ctx, NEXT_STEP_AUTH_WALL, evidence_rel_path};
use super::probe::{ProbeOutcome, send_with_probe_oracle};
use crate::agent::budget::RunBudget;
use crate::agent::oracle::{
    self, Observation, OracleOutcome, Severity, Technique, Verdict, is_cors_case,
};
use crate::agent::types::{
    AttemptRecord, BlockReason, CaseExecutionResult, PlannedCase, RedirectHop, SRC_AUTH_WALL,
    SRC_NOT_APPLICABLE,
};
use crate::llm::{is_sensitive_key, redact_for_llm};

pub(crate) fn skeleton(
    c: &PlannedCase,
    status: &str,
    reason: String,
    curl: String,
) -> CaseExecutionResult {
    CaseExecutionResult {
        blocked_reason: None,
        redirect_chain: vec![],
        case_id: c.id.clone(),
        title: c.title.clone(),
        component: c.component.clone(),
        method: c.method.clone(),
        technique: c.technique.clone(),
        status: status.into(),
        status_code: None,
        latency_ms: 0,
        reproduction_curl: curl,
        request_payload: c.payload.clone(),
        evidence: String::new(),
        content_type: None,
        is_spa_shell: false,
        failure_reason: Some(reason),
        response_status: None,
        response_body: None,
        expected_status: c.expected_status,
        oracle: None,
        flaky: false,
        attempts: vec![],
        evidence_file: None,
        evidence_detail: None,
        stateful_chain: None,
        concurrency_burst_results: None,
    }
}

pub(crate) fn skipped(
    c: &PlannedCase,
    reason: impl Into<String>,
    curl: String,
) -> CaseExecutionResult {
    skeleton(c, "SKIPPED", reason.into(), curl)
}

/// The result of a planner-made ledger row ([`SRC_NOT_APPLICABLE`], [`SRC_AUTH_WALL`]): nothing is
/// sent, no step or request is spent. NOT_APPLICABLE counts toward no denominator; BLOCKED with
/// `AuthWall` says what the user has to provide.
pub(crate) fn ledger_row_result(c: &PlannedCase) -> Option<CaseExecutionResult> {
    let (status, reason, why) = match c.source.as_deref()? {
        SRC_NOT_APPLICABLE => (
            "NOT_APPLICABLE",
            BlockReason::NoSurface,
            format!(
                "no input surface: nothing on the discovered route(s) takes input that {} tests could exercise ({}). Not counted toward coverage",
                c.technique, c.input_hint
            ),
        ),
        SRC_AUTH_WALL => (
            "BLOCKED",
            BlockReason::AuthWall,
            format!(
                "auth wall: the discovered route(s) are behind a login and no credential was available, so the {} tests were not run ({}). Next step: {NEXT_STEP_AUTH_WALL}",
                c.technique, c.input_hint
            ),
        ),
        _ => return None,
    };
    let mut r = skeleton(c, status, why, String::new());
    r.blocked_reason = Some(reason);
    r.evidence = c.input_hint.clone();
    Some(r)
}

/// Is this answer an auth wall for this case? Only when no credential was sent, and never for a
/// case whose raw status is the evidence (authorization, a sensitive-file probe, a forged token, a
/// CORS probe, an expected denial or redirect). A FAIL stays a FAIL. A redirect to a login page
/// relabels a PASS too (the page the case targeted was never reached); a 401 or a password form
/// only relabels an INCONCLUSIVE.
pub(crate) fn auth_wall_of(
    c: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    seen: &Seen,
    chain: &[RedirectHop],
    outcome: &OracleOutcome,
) -> Option<oracle::WallSignal> {
    if auth.authenticated
        || spec.auth == Auth::Forged
        || Technique::parse(&c.technique) == Technique::Authz
        || is_cors_case(c)
        || oracle::is_sensitive_path(&c.component)
        || oracle::expects_denial(c)
        || oracle::expects_redirect(c)
    {
        return None;
    }
    // a case aimed at a login page is not walled off by the redirects that page does (/login to
    // /login/): only what the final answer says counts
    let chain = if oracle::is_login_location(&c.component) {
        &[]
    } else {
        chain
    };
    let w = oracle::auth_wall_signal(
        seen.status,
        &seen.content_type,
        &seen.headers,
        &seen.body,
        chain,
    )?;
    match outcome.verdict {
        Verdict::Fail => None,
        Verdict::Inconclusive => Some(w),
        Verdict::Pass => w.redirected.then_some(w),
    }
}

pub(crate) fn spa_shell(ct: &str, body: &str, is_spa_target: bool) -> bool {
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

pub(crate) fn redacted_headers(h: &[(String, String)]) -> Vec<Value> {
    h.iter()
        .map(|(k, v)| {
            json!([
                k,
                if is_sensitive_key(k) {
                    "[REDACTED]".to_string()
                } else {
                    redact_for_llm(v)
                }
            ])
        })
        .collect()
}

/// Status string of an oracle outcome (a PASS with advisory warnings is a WARN).
pub(crate) fn status_of_outcome(o: &OracleOutcome) -> &'static str {
    match o.verdict {
        Verdict::Fail => "FAIL",
        Verdict::Inconclusive => "INCONCLUSIVE",
        Verdict::Pass if !o.warnings.is_empty() => "WARN",
        Verdict::Pass => "PASS",
    }
}

pub(crate) struct HttpOut {
    pub(crate) res: CaseExecutionResult,
    /// First response (before any re-run); None when nothing was received.
    pub(crate) first: Option<Seen>,
}

/// Send one case (plus safe re-runs of a FAIL), judge it, and build its result and evidence.
pub(crate) fn exec_http(
    ctx: &Ctx,
    budget: &mut RunBudget,
    c: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    curl: String,
) -> HttpOut {
    let https = spec.url.starts_with("https://");
    // only a safe request may be repeated: re-sending a POST would create a second record
    let total = if is_safe_method(spec.method) {
        1 + ctx.opts.reruns
    } else {
        1
    };
    let follow = follows_redirects(c);
    let mut first_chain: Vec<RedirectHop> = vec![];
    let mut first_final_url = spec.url.clone();
    let mut attempts: Vec<(Option<Seen>, Option<OracleOutcome>, Option<String>)> = vec![];
    for attempt in 0..total {
        if let Err(m) = budget.take_request(ctx.host) {
            if attempt == 0 {
                return HttpOut {
                    res: skipped(c, m, curl),
                    first: None,
                };
            }
            attempts.push((None, None, Some(format!("re-run not sent: {m}"))));
            break;
        }
        let sent = send_with_probe_oracle(
            ctx.clients,
            ctx.target,
            ctx.host,
            budget,
            c,
            spec,
            auth,
            follow,
            ctx.oast,
        );
        match sent {
            Ok(ProbeOutcome {
                seen,
                chain,
                final_url,
                evidence,
            }) => {
                if attempt == 0 {
                    first_chain = chain;
                    first_final_url = final_url;
                }
                note_creation(&c.id, spec, &seen);
                let shell = spa_shell(&seen.content_type, &seen.body, ctx.opts.is_spa_target);
                let outcome = oracle::judge(
                    c,
                    &Observation {
                        status: seen.status,
                        content_type: &seen.content_type,
                        headers: &seen.headers,
                        body: &seen.body,
                        sent_values: &spec.sent_values,
                        is_spa_shell: shell,
                        authenticated: auth.authenticated,
                        https,
                        request_body: spec.body.as_ref().map(|(_, b)| b.as_str()),
                        origin: spec.origin(),
                        latency_ms: seen.latency_ms,
                        probe: Some(&evidence),
                    },
                );
                let again = outcome.verdict == Verdict::Fail;
                attempts.push((Some(seen), Some(outcome), None));
                if !again {
                    break; // only a FAIL is worth re-running
                }
            }
            Err(e) => {
                attempts.push((None, None, Some(e)));
                break; // a transport error is not a verdict, and is not retried
            }
        }
    }

    let records: Vec<AttemptRecord> = attempts
        .iter()
        .enumerate()
        .map(|(i, (s, o, e))| AttemptRecord {
            attempt: i as u32 + 1,
            status_code: s.as_ref().map(|s| s.status),
            verdict: o
                .as_ref()
                .map(|o| o.verdict.label().to_string())
                .or_else(|| e.as_ref().map(|_| "ERROR".to_string()))
                .unwrap_or_default(),
        })
        .collect();

    // first attempt decides the shape of the result
    let (first_seen, first_outcome, first_err) = attempts.remove(0);
    let curl = if first_chain.is_empty() {
        curl
    } else {
        follow_curl(&curl)
    };
    let mut res = skeleton(c, "BLOCKED", String::new(), curl.clone());
    res.redirect_chain = first_chain.clone();
    res.failure_reason = None;
    res.attempts = records;
    res.evidence_file = Some(evidence_rel_path(&c.id));
    let mut detail = json!({
        "case_id": c.id, "title": c.title, "technique": c.technique, "expected_status": c.expected_status, "expected_behavior": c.expected_behavior,
        "request": {"method": spec.method, "url": spec.url, "curl": curl, "payload": c.payload, "auth": match &spec.auth { Auth::None => "none".to_string(), Auth::Forged => "forged-token".to_string(), Auth::Role(r) => format!("role:{r} (token not recorded)") }, "auth_note": auth.note},
    });

    let (Some(seen), Some(outcome)) = (first_seen, first_outcome) else {
        let e = first_err.unwrap_or_else(|| "unknown error".into());
        res.status = "BLOCKED".into();
        res.blocked_reason = Some(BlockReason::Transport);
        res.failure_reason = Some(format!("Connection error: {e}"));
        res.evidence = format!(
            "request failed: {}",
            crate::llm::untrusted::redact_then_truncate(&e, 300)
        );
        detail["response"] = json!({"error": crate::llm::untrusted::redact_then_truncate(&e, 300)});
        res.evidence_detail = Some(detail);
        return HttpOut { res, first: None };
    };

    // flaky: failed first, but a completed re-run did not reproduce it
    let reruns_done: Vec<&OracleOutcome> =
        attempts.iter().filter_map(|(_, o, _)| o.as_ref()).collect();
    let non_repro = reruns_done
        .iter()
        .filter(|o| o.verdict != Verdict::Fail)
        .count();
    let flaky = outcome.verdict == Verdict::Fail && non_repro > 0;
    // A High/Critical failure is never demoted just because a re-run looked different: a
    // security finding that appears once is still a finding. Only Medium/Low become WARN.
    let severe = outcome.max_fail_severity().unwrap_or(Severity::High) >= Severity::High;

    res.status_code = Some(seen.status);
    res.response_status = Some(seen.status);
    res.response_body = Some(seen.body.clone());
    res.latency_ms = seen.latency_ms;
    res.content_type = Some(seen.content_type.clone());
    res.is_spa_shell = spa_shell(&seen.content_type, &seen.body, ctx.opts.is_spa_target);
    res.flaky = flaky;
    res.status = if flaky && !severe {
        "WARN".into()
    } else {
        status_of_outcome(&outcome).into()
    };
    res.failure_reason = if flaky {
        Some(format!(
            "flaky: failed on attempt 1, but {non_repro} of {} re-run(s) did not reproduce it{}. Original failure: {}",
            reruns_done.len(),
            if severe {
                "; kept as FAIL because the failure is high/critical severity"
            } else {
                ""
            },
            outcome.reason().unwrap_or_default()
        ))
    } else {
        outcome.reason()
    };
    // redact FIRST, then cut: a secret straddling the cut must not survive as a prefix
    res.evidence = if seen.body.is_empty() {
        format!(
            "{} {} bytes=0 content-type={}",
            spec.method, seen.status, seen.content_type
        )
    } else {
        crate::llm::untrusted::redact_then_truncate(&seen.body, 300)
    };
    if !first_chain.is_empty() {
        // the judged response is the final one: say how it was reached
        let hops: Vec<String> = first_chain
            .iter()
            .map(|h| format!("{} {}", h.status, h.location))
            .collect();
        res.evidence = crate::llm::untrusted::redact_then_truncate(
            &format!(
                "followed {} redirect(s) ({}), judged HTTP {}: {}",
                first_chain.len(),
                hops.join(" -> "),
                seen.status,
                res.evidence
            ),
            300,
        );
    }
    detail["response"] = json!({
        "status": seen.status, "content_type": seen.content_type, "latency_ms": seen.latency_ms,
        "headers": redacted_headers(&seen.headers),
        "body_excerpt": crate::llm::untrusted::redact_then_truncate(&seen.body, 4000),
    });
    if !first_chain.is_empty() {
        detail["response"]["final_url"] = json!(crate::llm::untrusted::redact_then_truncate(
            &first_final_url,
            300
        ));
        detail["redirect_chain"] = serde_json::to_value(&first_chain).unwrap_or(Value::Null);
    }
    if let Some(w) = auth_wall_of(c, spec, auth, &seen, &first_chain, &outcome) {
        // no credential, and the target asked for one: not a verdict on the app, not a failure
        let who = match &spec.auth {
            Auth::Role(r) => format!(" for role '{r}'"),
            _ => String::new(),
        };
        res.status = "BLOCKED".into();
        res.blocked_reason = Some(BlockReason::AuthWall);
        res.failure_reason = Some(format!(
            "auth wall: {}. No credential was available{who}, so what sits behind the login was not tested. Next step: {NEXT_STEP_AUTH_WALL}",
            w.what
        ));
        detail["auth_wall"] = json!(w.what);
    }
    detail["oracle"] = serde_json::to_value(&outcome).unwrap_or(Value::Null);
    detail["attempts"] = serde_json::to_value(&res.attempts).unwrap_or(Value::Null);
    detail["flaky"] = json!(flaky);
    res.oracle = Some(outcome);
    res.evidence_detail = Some(detail);
    HttpOut {
        res,
        first: Some(seen),
    }
}
