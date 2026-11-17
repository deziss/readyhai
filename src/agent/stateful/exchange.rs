use std::time::Instant;

use super::models::StatefulScenarioResult;
use super::violation::Actor;
use crate::agent::budget::RunBudget;
use crate::agent::exec::role_of;
use crate::agent::exec::{
    Bearer, Clients, Credentials, OutReq, RequestSpec, Seen, body_and_type,
    curl_for_auth, normalize_component, resolve_auth,
};
use crate::agent::oracle::{StatefulFacts, Verdict, judge_stateful};
use crate::agent::types::{StatefulStepExecution, record_creation_response};
use crate::llm::untrusted::redact_then_truncate;

pub(crate) struct Runner<'a> {
    pub(crate) clients: &'a Clients,
    /// Id of the case the chain belongs to (tags what the chain creates in the ledger).
    pub(crate) case_id: &'a str,
    pub(crate) base: String,
    pub(crate) creds: &'a Credentials,
    pub(crate) budget: &'a mut RunBudget,
    pub(crate) host: &'a str,
    pub(crate) log: Vec<StatefulStepExecution>,
    pub(crate) curls: Vec<String>,
    pub(crate) latency: u64,
    pub(crate) last_status: u16,
}

pub(crate) struct Exchange<'a> {
    pub(crate) step_number: u32,
    /// Shown in the report, e.g. "bob" or "alice (owner control)".
    pub(crate) label: String,
    pub(crate) actor: &'a Actor,
    pub(crate) method: &'static str,
    pub(crate) path: String,
    /// The path with secret-keyed variables redacted (what is stored and put in the curl).
    pub(crate) disp_path: String,
    pub(crate) payload: Option<String>,
    pub(crate) disp_payload: Option<String>,
}

impl Runner<'_> {
    /// Send one request. Err(reason) means it was not sent or failed before a response.
    pub(crate) fn exchange(&mut self, e: &Exchange) -> Result<(Seen, usize), String> {
        self.budget
            .take_request(self.host)
            .map_err(|m| format!("budget exceeded before step {}: {m}", e.step_number))?;
        let path = normalize_component(&e.path)
            .map_err(|m| format!("step {} cannot be sent: {m}", e.step_number))?;
        let url = format!("{}{}", self.base, path);
        let auth = resolve_auth(&e.actor.auth(), self.creds);
        let bearer: Option<&Bearer> = auth.bearer.as_ref();
        let body = e.payload.as_deref().map(body_and_type);
        // reproduction: same request, redacted values, token as a placeholder
        let disp_url = format!(
            "{}{}",
            self.base,
            normalize_component(&e.disp_path).unwrap_or_else(|_| e.disp_path.clone())
        );
        let disp_spec = RequestSpec {
            method: e.method,
            url: disp_url,
            path: e.disp_path.clone(),
            body: e.disp_payload.as_deref().map(body_and_type),
            auth: e.actor.auth(),
            sent_values: vec![],
            extra_headers: vec![],
        };
        self.curls.push(curl_for_auth(&disp_spec, self.creds));
        let t0 = Instant::now();
        let sent = self.clients.send_resolved(
            &OutReq {
                method: e.method,
                url: &url,
                body: body.as_ref(),
                headers: &[],
                bearer,
            },
            &auth,
        );
        let latency = t0.elapsed().as_millis() as u64;
        self.latency += latency;
        match sent {
            Ok(seen) => {
                // every 2xx POST of the chain (the creating step, or any other) goes on the run's
                // ledger with its real id; a path that was redacted for display is not recorded
                // (the pipeline reports it as unidentified instead of deleting a wrong path)
                if e.path == e.disp_path {
                    record_creation_response(
                        None,
                        e.method,
                        &url,
                        seen.status,
                        &seen.headers,
                        &seen.body,
                        role_of(&e.actor.auth()),
                        Some(self.case_id),
                    );
                }
                self.last_status = seen.status;
                self.log.push(StatefulStepExecution {
                    step_number: e.step_number,
                    actor: e.label.clone(),
                    method: e.method.to_string(),
                    resolved_path: e.disp_path.clone(),
                    status_code: seen.status,
                    latency_ms: latency,
                    extracted_values: std::collections::HashMap::new(),
                    passed: true,
                    violation_triggered: false,
                    error_detail: None,
                });
                let idx = self.log.len() - 1;
                Ok((seen, idx))
            }
            Err(m) => {
                let reason = format!(
                    "step {} transport error: {}",
                    e.step_number,
                    redact_then_truncate(&m, 300)
                );
                self.log.push(StatefulStepExecution {
                    step_number: e.step_number,
                    actor: e.label.clone(),
                    method: e.method.to_string(),
                    resolved_path: e.disp_path.clone(),
                    status_code: 0,
                    latency_ms: latency,
                    extracted_values: std::collections::HashMap::new(),
                    passed: false,
                    violation_triggered: false,
                    error_detail: Some(reason.clone()),
                });
                Err(reason)
            }
        }
    }

    pub(crate) fn finish(self, facts: StatefulFacts, summary: String) -> StatefulScenarioResult {
        let outcome = judge_stateful(&facts);
        let failure_reason = outcome.reason();
        StatefulScenarioResult {
            skipped: None,
            passed: outcome.verdict == Verdict::Pass,
            violation_triggered: outcome.verdict == Verdict::Fail,
            setup_failed: matches!(facts, StatefulFacts::Setup { .. }),
            failure_reason,
            outcome: Some(outcome),
            steps: self.log,
            reproduction_curl: self.curls.join("\n"),
            final_status: self.last_status,
            total_latency_ms: self.latency,
            summary,
        }
    }
}

pub(crate) fn skipped_result(reason: String) -> StatefulScenarioResult {
    StatefulScenarioResult {
        skipped: Some(reason.clone()),
        outcome: None,
        steps: vec![],
        reproduction_curl: String::new(),
        final_status: 0,
        total_latency_ms: 0,
        summary: format!("stateful check skipped: {reason}"),
        passed: false,
        violation_triggered: false,
        setup_failed: false,
        failure_reason: Some(reason),
    }
}

pub(crate) fn status_matches(expected: u16, got: u16) -> bool {
    if (200..=299).contains(&expected) {
        (200..=299).contains(&got)
    } else {
        got == expected
    }
}
