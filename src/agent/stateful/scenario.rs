use serde_json::Value;
use std::collections::HashMap;

use super::exchange::{Exchange, Runner, skipped_result, status_matches};
use super::models::StatefulScenarioResult;
use super::preflight::{access_index, preflight};
use super::vars::{extract_json_values, placeholder_names, storable_value, substitute_vars};
use super::violation::{Actor, actor_of, evaluate_violation, extract_violation_tag};
use crate::agent::budget::RunBudget;
use crate::agent::exec::{Clients, Credentials, is_safe_method, normalize_method};
use crate::agent::oracle::{StatefulFacts, Verdict, judge_stateful};
use crate::agent::types::StatefulStep;

/// Execute a stateful scenario chain step by step.
pub fn execute_stateful_scenario(
    clients: &Clients,
    target: &str,
    steps: &[StatefulStep],
    creds: &Credentials,
    budget: &mut RunBudget,
    host: &str,
    case_id: &str,
) -> StatefulScenarioResult {
    if let Err(why) = preflight(steps, creds) {
        return skipped_result(why);
    }
    let access_idx = access_index(steps);
    let mut run = Runner {
        clients,
        case_id,
        base: target.trim_end_matches('/').to_string(),
        creds,
        budget,
        host,
        log: Vec::with_capacity(steps.len() + 3),
        curls: vec![],
        latency: 0,
        last_status: 0,
    };
    // real values for requests, redacted values for everything that is stored
    let mut ctx: HashMap<String, String> = HashMap::new();
    let mut disp: HashMap<String, String> = HashMap::new();
    let creator_actor = actor_of(&steps[0].actor);

    for (i, step) in steps.iter().enumerate() {
        let actor = actor_of(&step.actor);
        let method = normalize_method(&step.method).unwrap_or("GET"); // validated in preflight
        let is_access = access_idx == Some(i);
        let path = substitute_vars(&step.path, &ctx);
        let payload = step.payload.as_deref().map(|p| substitute_vars(p, &ctx));
        // a placeholder that is still there means an earlier step did not yield its value
        let unresolved: Vec<String> = placeholder_names(&path)
            .into_iter()
            .chain(payload.iter().flat_map(|p| placeholder_names(p)))
            .collect();
        if let Some(name) = unresolved.first() {
            let reason = format!(
                "unresolved placeholder {{{{{name}}}}} in step {}: an earlier step did not return it, so the request was not sent",
                step.step_number
            );
            return run.finish(
                StatefulFacts::Setup {
                    step: step.step_number,
                    status: None,
                    reason: reason.clone(),
                },
                reason,
            );
        }
        let disp_path = substitute_vars(&step.path, &disp);
        let disp_payload = step.payload.as_deref().map(|p| substitute_vars(p, &disp));

        if !is_access {
            // an ordinary step
            let ex = Exchange {
                step_number: step.step_number,
                label: step.actor.clone(),
                actor: &actor,
                method,
                path: path.clone(),
                disp_path: disp_path.clone(),
                payload: payload.clone(),
                disp_payload: disp_payload.clone(),
            };
            let (seen, idx) = match run.exchange(&ex) {
                Ok(x) => x,
                Err(reason) => {
                    return run.finish(
                        StatefulFacts::Setup {
                            step: step.step_number,
                            status: None,
                            reason: reason.clone(),
                        },
                        reason,
                    );
                }
            };
            // extract (primary object only), keep the real value for chaining, store it redacted
            if let Ok(json) = serde_json::from_str::<Value>(&seen.body) {
                let mut got = HashMap::new();
                extract_json_values(&json, step.extract_vars.as_deref(), &mut got);
                for (k, v) in got {
                    run.log[idx]
                        .extracted_values
                        .insert(k.clone(), storable_value(&k, &v));
                    disp.insert(k.clone(), storable_value(&k, &v));
                    ctx.insert(k, v);
                }
            }
            if let Some(cond_raw) = step.violation_condition.as_deref() {
                let (code, expr) = extract_violation_tag(cond_raw);
                if evaluate_violation(expr, seen.status, &seen.body) {
                    let detail = format!(
                        "{method} {} violated '{cond_raw}' (HTTP {})",
                        run.log[idx].resolved_path, seen.status
                    );
                    run.log[idx].violation_triggered = true;
                    run.log[idx].passed = false;
                    run.log[idx].error_detail = Some(detail.clone());
                    return run.finish(
                        StatefulFacts::Violation {
                            step: step.step_number,
                            code: code.to_string(),
                            severity: crate::agent::oracle::Severity::High,
                            detail: detail.clone(),
                        },
                        detail,
                    );
                }
                // A security probe step with no required exact status that was safely blocked with
                // 4xx does not fail: the invariant held.
                if step.expected_status.is_none() && (400..=499).contains(&seen.status) {
                    let n = steps.len();
                    return run.finish(
                        StatefulFacts::Workflow { failed_step: None },
                        format!(
                            "stateful chain of {n} step(s) blocked probe cleanly (HTTP {})",
                            seen.status
                        ),
                    );
                }
            }
            let ok = match step.expected_status {
                Some(e) => status_matches(e, seen.status),
                None => seen.status < 400,
            };
            if !ok {
                let detail = match step.expected_status {
                    Some(e) => format!(
                        "step {} expected HTTP {e} but received {}",
                        step.step_number, seen.status
                    ),
                    None => format!("step {} failed with HTTP {}", step.step_number, seen.status),
                };
                run.log[idx].passed = false;
                run.log[idx].error_detail = Some(detail.clone());
                let facts = if access_idx.is_some_and(|a| i < a) {
                    StatefulFacts::Setup {
                        step: step.step_number,
                        status: Some(seen.status),
                        reason: format!(
                            "{} {} answered unexpectedly",
                            method, run.log[idx].resolved_path
                        ),
                    }
                } else {
                    StatefulFacts::Workflow {
                        failed_step: Some((step.step_number, step.expected_status, seen.status)),
                    }
                };
                return run.finish(facts, detail);
            }
            continue;
        }

        // ---- the access step: another actor reads (or touches) the created resource
        // owner control: the creator must be able to read the resource at this very path
        let control_ex = Exchange {
            step_number: step.step_number,
            label: format!("{} (owner control)", steps[0].actor),
            actor: &creator_actor,
            method: "GET",
            path: path.clone(),
            disp_path: disp_path.clone(),
            payload: None,
            disp_payload: None,
        };
        let owner_control = match run.exchange(&control_ex) {
            Ok((s, _)) => Some(s.status),
            Err(reason) => {
                return run.finish(
                    StatefulFacts::Setup {
                        step: step.step_number,
                        status: None,
                        reason: reason.clone(),
                    },
                    reason,
                );
            }
        };
        let ex = Exchange {
            step_number: step.step_number,
            label: step.actor.clone(),
            actor: &actor,
            method,
            path: path.clone(),
            disp_path: disp_path.clone(),
            payload: payload.clone(),
            disp_payload: disp_payload.clone(),
        };
        let (seen, idx) = match run.exchange(&ex) {
            Ok(x) => x,
            Err(reason) => {
                return run.finish(
                    StatefulFacts::Setup {
                        step: step.step_number,
                        status: None,
                        reason: reason.clone(),
                    },
                    reason,
                );
            }
        };
        let second = seen.status;
        let safe = is_safe_method(method);
        let (mut anon_status, mut reproduced) = (None, None);
        if (200..=299).contains(&second)
            && safe
            && owner_control.is_some_and(|c| (200..=299).contains(&c))
        {
            // a public resource answers without credentials too
            if !actor.is_anon() {
                let anon = Actor::Anon;
                let anon_ex = Exchange {
                    step_number: step.step_number,
                    label: "anon (public-access check)".into(),
                    actor: &anon,
                    method,
                    path: path.clone(),
                    disp_path: disp_path.clone(),
                    payload: None,
                    disp_payload: None,
                };
                anon_status = run.exchange(&anon_ex).ok().map(|(s, _)| s.status);
            } else {
                anon_status = Some(second);
            }
            if !anon_status.is_some_and(|s| (200..=299).contains(&s)) {
                // confirm with one safe re-run before recording a finding
                let again = Exchange {
                    step_number: step.step_number,
                    label: format!("{} (re-run)", step.actor),
                    actor: &actor,
                    method,
                    path: path.clone(),
                    disp_path: disp_path.clone(),
                    payload: None,
                    disp_payload: None,
                };
                reproduced = run
                    .exchange(&again)
                    .ok()
                    .map(|(s, _)| (200..=299).contains(&s.status));
            }
        }
        let facts = StatefulFacts::CrossActor {
            second_actor_anon: actor.is_anon(),
            safe_method: safe,
            owner_control,
            second_status: second,
            anon_status,
            reproduced,
        };
        let verdict_is_fail = judge_stateful(&facts).verdict == Verdict::Fail;
        run.log[idx].violation_triggered = verdict_is_fail
            && step
                .violation_condition
                .as_deref()
                .is_none_or(|c| evaluate_violation(c, second, &seen.body));
        run.log[idx].passed = !verdict_is_fail;
        let summary = format!(
            "{} {} by '{}': HTTP {second} (owner control: {})",
            method,
            run.log[idx].resolved_path,
            step.actor,
            owner_control
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into())
        );
        return run.finish(facts, summary);
    }

    let n = steps.len();
    run.finish(
        StatefulFacts::Workflow { failed_step: None },
        format!("stateful chain of {n} step(s) answered as expected"),
    )
}
