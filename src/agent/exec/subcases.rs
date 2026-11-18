use serde_json::{Value, json};

use crate::agent::budget::RunBudget;
use crate::agent::oracle::{self, BurstFacts};
use crate::agent::types::{CaseExecutionResult, PlannedCase, StatefulStep};
use super::auth::ResolvedAuth;
use super::builder::{RequestSpec, build_request, curl_for_auth, is_mutating};
use super::clients::Seen;
use super::dispatch::{Ctx, evidence_rel_path};
use super::http::{exec_http, skeleton, skipped, status_of_outcome};

const MAX_BURST: usize = 10;

pub(crate) fn run_stateful_case(
    ctx: &Ctx,
    c: &PlannedCase,
    steps: &[StatefulStep],
    budget: &mut RunBudget,
) -> CaseExecutionResult {
    if ctx.opts.dry_run && steps.iter().any(|s| is_mutating(&s.method)) {
        return skipped(
            c,
            "dry_run: state-changing steps in stateful scenario were not sent",
            String::new(),
        );
    }
    // nothing is sent (and no step is spent) when the chain cannot be judged: missing
    // credentials, unresolved placeholders, steps that are not about one resource
    if let Err(why) = crate::agent::stateful::preflight(steps, &ctx.opts.credentials) {
        return skipped(c, format!("stateful check skipped: {why}"), String::new());
    }
    if let Err(m) = budget.take_step() {
        return skipped(c, m, String::new());
    }
    let r = crate::agent::stateful::execute_stateful_scenario(
        ctx.clients,
        ctx.target,
        steps,
        &ctx.opts.credentials,
        budget,
        ctx.host,
        &c.id,
    );
    if let Some(why) = &r.skipped {
        return skipped(
            c,
            format!("stateful check skipped: {why}"),
            r.reproduction_curl.clone(),
        );
    }
    let outcome = r.outcome.clone().unwrap_or_else(|| {
        crate::agent::oracle::judge_stateful(&crate::agent::oracle::StatefulFacts::Setup {
            step: 0,
            status: None,
            reason: "no outcome".into(),
        })
    });
    let mut res = skeleton(
        c,
        status_of_outcome(&outcome),
        String::new(),
        r.reproduction_curl.clone(),
    );
    res.status_code = Some(r.final_status);
    res.response_status = Some(r.final_status);
    res.latency_ms = r.total_latency_ms;
    res.stateful_chain = Some(r.steps.clone());
    res.evidence_file = Some(evidence_rel_path(&c.id));
    res.failure_reason = outcome.reason();
    res.evidence = r.summary.clone();
    let detail = json!({
        "case_id": c.id,
        "title": c.title,
        "technique": c.technique,
        "stateful_chain": r.steps,
        "reproduction_curl": r.reproduction_curl,
        "oracle": serde_json::to_value(&outcome).unwrap_or(Value::Null),
    });
    res.oracle = Some(outcome);
    res.evidence_detail = Some(detail);
    res
}

/// Adaptive schema-feedback mutation as its own sub-case `<id>-M1`: own request, own curl, own
/// oracle verdict. Returns the sub-case and the summary stored on the base case's evidence.
pub(crate) fn run_mutation(
    ctx: &Ctx,
    budget: &mut RunBudget,
    c: &PlannedCase,
    first: &Seen,
    auth: &ResolvedAuth,
) -> Option<(CaseExecutionResult, Value)> {
    let feedback =
        crate::agent::mutation::extract_schema_feedback(first.status, &first.content_type, &first.body)?;
    let mutated_payload =
        crate::agent::mutation::mutate_payload(c.payload.as_deref(), &feedback, &c.technique)?;
    let mut m = c.clone();
    m.id = format!("{}-M1", c.id);
    m.title = format!("{} [adaptive schema mutation]", c.title);
    m.payload = Some(mutated_payload.clone());
    m.expected_status = None;
    m.expected_behavior =
        "Schema-conforming adversarial input is handled without a server error".into();
    m.concurrency_burst = None;
    m.stateful_steps = None;
    // its own question is a server error; the base case already judged the response contract
    m.contract = None;
    let spec = build_request(&m, ctx.target).ok()?;
    let curl = curl_for_auth(&spec, &ctx.opts.credentials);
    let out = exec_http(ctx, budget, &m, &spec, auth, curl);
    let (sub, mut_first) = (out.res, out.first);
    mut_first.as_ref()?; // budget stopped it or the transport failed: no sub-case to report
    let mutated_status = sub.status_code.unwrap_or(0);
    let penetrated = mutated_status != 400 && mutated_status != 422;
    let info = json!({
        "sub_case_id": sub.case_id,
        "framework": feedback.framework_hint,
        "required_fields": feedback.required_fields.iter().map(|f| &f.name).collect::<Vec<_>>(),
        "mutated_payload": crate::llm::untrusted::redact_then_truncate(&mutated_payload, 400),
        "mutated_status": mutated_status,
        "penetrated_validation": penetrated,
        "mutated_verdict": sub.oracle.as_ref().map(|o| o.verdict.label()),
    });
    let mut sub = sub;
    if let Some(d) = sub.evidence_detail.as_mut() {
        d["mutation_of"] = json!(c.id);
    }
    Some((sub, info))
}

/// Concurrency burst as its own sub-case `<id>-B`. Charged to the run budget and rate limit.
pub(crate) fn run_burst(
    ctx: &Ctx,
    budget: &mut RunBudget,
    c: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    n: usize,
) -> Option<CaseExecutionResult> {
    let mut b = c.clone();
    b.id = format!("{}-B", c.id);
    b.title = format!("{} [concurrency burst x{}]", c.title, n.clamp(2, MAX_BURST));
    let curl = format!(
        "for i in $(seq 1 {}); do {} & done; wait",
        n.clamp(2, MAX_BURST),
        curl_for_auth(spec, &ctx.opts.credentials)
    );
    let run = match crate::agent::stateful::run_concurrency_burst_auth(
        ctx.clients,
        spec,
        auth,
        n,
        budget,
        ctx.host,
        &b.id,
    ) {
        Ok(r) => r,
        Err(why) => {
            return Some(skipped(
                &b,
                format!("concurrency burst not run: {why}"),
                curl,
            ));
        }
    };
    let outcome = oracle::judge_burst_on_path(
        &BurstFacts {
            method: spec.method,
            requested: run.requested,
            responses: &run.responses,
            pre_read: run.pre_read.as_deref(),
            post_read: run.post_read.as_deref(),
        },
        &c.component,
    );
    let mut res = skeleton(&b, status_of_outcome(&outcome), String::new(), curl.clone());
    res.status_code = run.responses.first().map(|r| r.status);
    res.failure_reason = outcome.reason();
    res.evidence_file = Some(evidence_rel_path(&b.id));
    res.concurrency_burst_results = Some(run.status_codes.clone());
    res.evidence = format!(
        "{} concurrent {} request(s): statuses {:?}",
        run.requested, spec.method, run.status_codes
    );
    res.evidence_detail = Some(json!({
        "case_id": b.id, "title": b.title, "technique": b.technique, "burst_of": c.id,
        "request": {"method": spec.method, "url": spec.url, "curl": curl, "payload": c.payload},
        "concurrency_burst": {
            "requested": run.requested, "status_codes": run.status_codes, "notes": run.notes,
            "pre_read": run.pre_read.as_deref().map(|s| crate::llm::untrusted::redact_then_truncate(s, 600)),
            "post_read": run.post_read.as_deref().map(|s| crate::llm::untrusted::redact_then_truncate(s, 600)),
        },
        "oracle": serde_json::to_value(&outcome).unwrap_or(Value::Null),
    }));
    res.oracle = Some(outcome);
    Some(res)
}
