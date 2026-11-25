use std::time::Duration;

use super::auth::ResolvedAuth;
use super::builder::{RequestSpec, build_request};
use super::clients::{Clients, Followed, MAX_REDIRECTS, Seen};
use super::delete::{note_creation, out_req};
use crate::agent::budget::RunBudget;
use crate::agent::oracle;
use crate::agent::types::{PlannedCase, ProbeOracle, RedirectHop};

/// Output of sending one primary case along with any companion baseline/control/OAST probes.
pub struct ProbeOutcome {
    pub seen: Seen,
    pub chain: Vec<RedirectHop>,
    pub final_url: String,
    pub evidence: oracle::ProbeEvidence,
}

fn send_companion(
    clients: &Clients,
    target: &str,
    host: &str,
    budget: &mut RunBudget,
    template: &PlannedCase,
    payload: &str,
    auth: &ResolvedAuth,
) -> Result<oracle::ProbeSnapshot, String> {
    budget.take_request(host)?;
    let mut comp = template.clone();
    comp.payload = Some(payload.to_string());
    comp.probe_oracle = None;
    let spec = build_request(&comp, target)?;
    let req = out_req(&spec, auth.bearer.as_ref());
    let seen = clients.send_resolved(&req, auth)?;
    note_creation(&template.id, &spec, &seen);
    Ok(oracle::ProbeSnapshot {
        status: seen.status,
        body: seen.body,
        latency_ms: seen.latency_ms,
    })
}

fn substitute_oast_spec(spec: &RequestSpec, placeholder: &str, cb_url: &str) -> RequestSpec {
    let mut s = spec.clone();
    if !placeholder.is_empty() {
        let mut encoded = reqwest::Url::parse("http://localhost/").ok();
        let cb_enc = if let Some(ref mut u) = encoded {
            u.query_pairs_mut().append_pair("u", cb_url);
            u.query()
                .and_then(|q| q.strip_prefix("u="))
                .unwrap_or(cb_url)
                .to_string()
        } else {
            cb_url.to_string()
        };
        s.url = s.url.replace(placeholder, &cb_enc);
        if let Some((_, ref mut b)) = s.body {
            *b = b.replace(placeholder, cb_url);
        }
        for (_, v) in &mut s.extra_headers {
            *v = v.replace(placeholder, cb_url);
        }
    }
    s
}

/// Send the primary request for `case` plus any companion baseline, control, or OAST wait required
/// by `case.probe_oracle`. Assumes the caller already budgeted the primary request.
pub fn send_with_probe_oracle(
    clients: &Clients,
    target: &str,
    host: &str,
    budget: &mut RunBudget,
    case: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    follow_redirects: bool,
    oast: Option<&crate::agent::oast::OastCollector>,
) -> Result<ProbeOutcome, String> {
    let mut evidence = oracle::ProbeEvidence::default();
    let mut active_spec_owned: Option<RequestSpec> = None;
    let mut oast_token: Option<(String, u64)> = None;

    match &case.probe_oracle {
        Some(ProbeOracle::BooleanDiff {
            baseline_payload, ..
        })
        | Some(ProbeOracle::TimeDelay {
            baseline_payload, ..
        }) => {
            if let Ok(snap) =
                send_companion(clients, target, host, budget, case, baseline_payload, auth)
            {
                evidence.baseline = Some(snap);
            }
        }
        Some(ProbeOracle::OastCallback {
            placeholder,
            wait_ms,
        }) => {
            if let Some(col) = oast {
                let (tok, cb_url) = col.issue_token();
                active_spec_owned = Some(substitute_oast_spec(spec, placeholder, &cb_url));
                oast_token = Some((tok, (*wait_ms).min(2000)));
            } else {
                evidence.oast_unavailable = true;
            }
        }
        _ => {}
    }

    let send_spec = active_spec_owned.as_ref().unwrap_or(spec);
    let req = out_req(send_spec, auth.bearer.as_ref());
    let Followed {
        seen,
        chain,
        final_url,
    } = if follow_redirects {
        clients
            .send_following_resolved(&req, auth, MAX_REDIRECTS, &mut || budget.take_request(host))?
    } else {
        clients.send_resolved(&req, auth).map(|seen| Followed {
            seen,
            chain: vec![],
            final_url: send_spec.url.clone(),
        })?
    };

    if let Some(ProbeOracle::BooleanDiff { false_payload, .. }) = &case.probe_oracle
        && let Ok(snap) = send_companion(clients, target, host, budget, case, false_payload, auth)
    {
        evidence.control = Some(snap);
    }
    if let (Some((tok, wait_ms)), Some(col)) = (oast_token, oast)
        && let Some(hit) = col.wait_for_hit(&tok, Duration::from_millis(wait_ms))
    {
        evidence.oast_hit = true;
        evidence.oast_detail = Some(hit.summary());
    }

    Ok(ProbeOutcome {
        seen,
        chain,
        final_url,
        evidence,
    })
}
