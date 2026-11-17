use std::time::Duration;

use crate::agent::budget::RunBudget;
use crate::agent::types::{CaseExecutionResult, PlannedCase, ProbeOracle};
use super::auth::resolve_auth;
use super::builder::{build_request, curl_for, curl_for_auth, is_mutating};
use super::clients::Clients;
use super::credentials::Credentials;
use super::http::{exec_http, ledger_row_result, skeleton, skipped};
use super::subcases::{run_burst, run_mutation, run_stateful_case};

/// What to do about an auth wall; shared by the BLOCKED results, the ledger's blockers and the report.
pub const NEXT_STEP_AUTH_WALL: &str = "provide test accounts: `readyhai roles init --spec <openapi.json>` writes a roles.toml skeleton; set RH_<ROLE>_TOKEN (e.g. RH_USER_TOKEN) or use a storageState login, then re-run";

#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Never send POST/PUT/PATCH/DELETE.
    pub dry_run: bool,
    pub is_spa_target: bool,
    pub credentials: Credentials,
    /// Extra attempts for a FAIL (flaky detection). Only safe methods are ever repeated.
    pub reruns: u32,
    pub timeout: Duration,
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            dry_run: false,
            is_spa_target: false,
            credentials: Credentials::from_env(),
            reruns: 2,
            timeout: Duration::from_secs(10),
        }
    }
}

pub(crate) fn safe_id(id: &str) -> String {
    let s: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if s.is_empty() { "case".into() } else { s }
}

pub fn evidence_rel_path(case_id: &str) -> String {
    format!("evidence/{}.json", safe_id(case_id))
}

/// Execute `cases` against `target` with default options (used by the operator "retest" action).
pub fn execute_cases(
    cases: &[PlannedCase],
    target: &str,
    is_spa_target: bool,
) -> Vec<CaseExecutionResult> {
    let opts = ExecOptions {
        is_spa_target,
        ..ExecOptions::default()
    };
    execute_cases_with(cases, target, &opts, &mut RunBudget::from_env())
}

pub(crate) struct Ctx<'a> {
    pub(crate) clients: &'a Clients,
    pub(crate) target: &'a str,
    /// `host:port`, the budget's rate-limit key.
    pub(crate) host: &'a str,
    pub(crate) opts: &'a ExecOptions,
    pub(crate) oast: Option<&'a crate::agent::oast::OastCollector>,
}

/// Hooks around every case an execution starts. The lead's area workers use them to take turns for
/// state-changing cases (so what the target hands out is the same whatever the worker count) and to
/// report progress while the run is still going.
pub trait CaseGate: Sync {
    /// Called before a case starts; may block.
    fn enter(&self, c: &PlannedCase);
    /// Called when a case (and its sub-cases) is done, with the results it produced.
    fn leave(&self, c: &PlannedCase, results: &[CaseExecutionResult]);
}

/// Run every case. A case yields its own result first; an adaptive-mutation probe or a
/// concurrency burst it triggered follows as a separate sub-case result.
pub fn execute_cases_with(
    cases: &[PlannedCase],
    target: &str,
    opts: &ExecOptions,
    budget: &mut RunBudget,
) -> Vec<CaseExecutionResult> {
    execute_cases_gated(cases, target, opts, budget, None)
}

/// [`execute_cases_with`] with a [`CaseGate`] called around every case that is actually started
/// (cases that cannot be started at all, a target that is not http(s), skip it).
pub fn execute_cases_gated(
    cases: &[PlannedCase],
    target: &str,
    opts: &ExecOptions,
    budget: &mut RunBudget,
    gate: Option<&dyn CaseGate>,
) -> Vec<CaseExecutionResult> {
    let curl_of = |c: &PlannedCase| {
        build_request(c, target)
            .map(|s| curl_for(&s))
            .unwrap_or_default()
    };
    let parsed = reqwest::Url::parse(target)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some());
    let Some(parsed) = parsed else {
        return cases.iter().map(|c| skipped(c, "target is not an http(s) URL: the agent only probes over HTTP, nothing was executed", curl_of(c))).collect();
    };
    let clients = match Clients::new(opts.timeout, &parsed) {
        Ok(c) => c,
        Err(e) => {
            return cases
                .iter()
                .map(|c| {
                    skeleton(
                        c,
                        "BLOCKED",
                        format!("could not build the HTTP client: {e}"),
                        curl_of(c),
                    )
                })
                .collect();
        }
    };
    let host = format!(
        "{}:{}",
        parsed.host_str().unwrap_or(""),
        parsed.port_or_known_default().unwrap_or(0)
    );
    let oast = cases
        .iter()
        .any(|c| matches!(c.probe_oracle, Some(ProbeOracle::OastCallback { .. })))
        .then(crate::agent::oast::OastCollector::start)
        .and_then(Result::ok);
    let ctx = Ctx {
        clients: &clients,
        target,
        host: &host,
        opts,
        oast: oast.as_ref(),
    };
    cases
        .iter()
        .flat_map(|c| {
            if let Some(g) = gate {
                g.enter(c);
            }
            let r = run_case(&ctx, c, budget);
            if let Some(g) = gate {
                g.leave(c, &r);
            }
            r
        })
        .collect()
}

pub(crate) fn run_case(ctx: &Ctx, c: &PlannedCase, budget: &mut RunBudget) -> Vec<CaseExecutionResult> {
    if let Some(row) = ledger_row_result(c) {
        return vec![row];
    }
    if let Some(steps) = &c.stateful_steps
        && !steps.is_empty()
    {
        return vec![run_stateful_case(ctx, c, steps, budget)];
    }
    let spec = match build_request(c, ctx.target) {
        Ok(s) => s,
        Err(e) => {
            return vec![skipped(
                c,
                format!("invalid case, not sent: {e}"),
                String::new(),
            )];
        }
    };
    let curl = curl_for_auth(&spec, &ctx.opts.credentials);
    if ctx.opts.dry_run && is_mutating(spec.method) {
        return vec![skipped(
            c,
            format!(
                "dry_run: state-changing method {} was not sent",
                spec.method
            ),
            curl,
        )];
    }
    if let Err(m) = budget.take_step() {
        return vec![skipped(c, m, curl)];
    }
    let auth = resolve_auth(&spec.auth, &ctx.opts.credentials);
    let out = exec_http(ctx, budget, c, &spec, &auth, curl.clone());
    let mut results = vec![out.res];
    let Some(first) = out.first else {
        return results; // not sent (budget) or transport error: nothing to mutate or burst
    };

    // Adaptive schema-feedback mutation: a 400/422 that discloses its schema earns one probe with
    // schema-conforming adversarial values. It is a separate sub-case (own curl, own verdict).
    if (first.status == 400 || first.status == 422)
        && !(ctx.opts.dry_run && is_mutating(spec.method))
        && let Some((sub, info)) = run_mutation(ctx, budget, c, &first, &auth)
    {
        let base = &mut results[0];
        base.evidence.push_str(&format!(
            " [adaptive mutation sub-case {}: HTTP {}]",
            sub.case_id,
            sub.status_code.unwrap_or(0)
        ));
        if let Some(d) = base.evidence_detail.as_mut() {
            d["adaptive_mutation"] = info;
        }
        results.push(sub);
    }

    // Concurrency burst (TOCTOU): a separate sub-case judged by invariants only. It needs a
    // request the target accepts (2xx): a burst of 401s or 400s compares nothing.
    if let Some(n) = c.concurrency_burst.filter(|n| *n > 1)
        && !ctx.opts.dry_run
        && (200..=299).contains(&first.status)
        && let Some(sub) = run_burst(ctx, budget, c, &spec, &auth, n as usize)
    {
        if let Some(codes) = sub.concurrency_burst_results.clone() {
            results[0].concurrency_burst_results = Some(codes);
        }
        results.push(sub);
    }
    results
}
