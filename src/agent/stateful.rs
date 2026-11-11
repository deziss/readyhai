//! Stateful scenario chains and the TOCTOU concurrency burst.
//!
//! A chain is "actor A creates a resource, actor B tries to read it" (BOLA/IDOR). The executor
//! collects facts; `oracle::judge_stateful` decides. What it guarantees:
//!
//! * both actors' credentials are required, otherwise the chain is skipped (nothing is sent);
//! * `{{placeholders}}` must resolve before a request is built, otherwise nothing is sent;
//! * the creating POST and the reading GET are about the same resource path;
//! * ids are taken only from the response's top-level / primary object, never from nested
//!   sub-resources;
//! * a second actor's 401/403/429/3xx is not evidence of isolation (INCONCLUSIVE); an
//!   owner-control read must prove the resource exists first;
//! * a "second actor can read it" finding is confirmed by one safe GET re-run and dropped when the
//!   same GET works without credentials (a public resource);
//! * values extracted from responses under secret-looking keys (token, key, secret, password,
//!   session, auth) are redacted before they are stored, and reproduction curls carry
//!   `${RH_<ROLE>_TOKEN}` placeholders, never a token.
//!
//! The concurrency burst reports facts (responses plus a before/after read); the verdict is
//! `oracle::judge_burst`: only a violated invariant can fail it.

use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use super::budget::RunBudget;
use super::exec::role_of;
use super::exec::{
    Auth, Bearer, Clients, Credentials, OutReq, RequestSpec, ResolvedAuth, Seen, body_and_type,
    curl_for_auth, is_safe_method, needs_validated_tls, normalize_component, normalize_method,
    resolve_auth,
};
use super::oracle::{BurstResponse, OracleOutcome, StatefulFacts, judge_stateful, primary_object};
use super::types::{StatefulStep, StatefulStepExecution, current_ledger, record_creation_response};
use crate::llm::untrusted::redact_then_truncate;
use crate::llm::{is_sensitive_key, redact_for_llm};

/// Keys extracted from a response even when the step names none.
pub const DEFAULT_ID_KEYS: [&str; 6] = [
    "id",
    "uuid",
    "item_id",
    "order_id",
    "user_id",
    "resource_id",
];

#[derive(Debug, Clone)]
pub struct StatefulScenarioResult {
    /// Why nothing (or nothing conclusive) was run: the chain is SKIPPED, not judged.
    pub skipped: Option<String>,
    /// The oracle's verdict for the chain.
    pub outcome: Option<OracleOutcome>,
    pub steps: Vec<StatefulStepExecution>,
    /// One curl per request, tokens as `${RH_<ROLE>_TOKEN}` placeholders.
    pub reproduction_curl: String,
    pub final_status: u16,
    pub total_latency_ms: u64,
    /// One-line, redacted description of what happened.
    pub summary: String,
    // views of `outcome`, kept for callers that only need a flag
    pub passed: bool,
    pub violation_triggered: bool,
    pub setup_failed: bool,
    pub failure_reason: Option<String>,
}

// ---------------------------------------------------------------- variables

fn placeholder_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\{\{\s*([^{}\s]*)\s*\}\}").unwrap())
}

/// Names of every `{{name}}` / `{{ name }}` in `s`.
pub fn placeholder_names(s: &str) -> Vec<String> {
    placeholder_re()
        .captures_iter(s)
        .map(|c| c[1].to_string())
        .collect()
}

/// Substitute context variables `{{var}}` and `{{ var }}` in a string. Unknown placeholders are
/// left in place (the caller must reject them: see [`placeholder_names`]).
pub fn substitute_vars(template: &str, context: &HashMap<String, String>) -> String {
    placeholder_re()
        .replace_all(template, |c: &regex::Captures| match context.get(&c[1]) {
            Some(v) => v.clone(),
            None => c[0].to_string(),
        })
        .into_owned()
}

/// Key names whose values must never be stored: token, key, secret, password, session, auth.
pub fn is_secret_key(k: &str) -> bool {
    if is_sensitive_key(k) {
        return true;
    }
    let low = k.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "session",
        "credential",
        "cookie",
        "jwt",
        "bearer",
        "signature",
        "private",
    ]
    .iter()
    .any(|s| low.contains(s))
        || (low.contains("auth") && !low.contains("author"))
        || low.ends_with("key")
        || low.starts_with("key_")
        || low.starts_with("key-")
}

/// A value as it may be stored: redacted when its key looks secret, otherwise scrubbed.
pub fn storable_value(key: &str, value: &str) -> String {
    if is_secret_key(key) {
        "[REDACTED]".to_string()
    } else {
        redact_for_llm(value)
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None, // objects and arrays are not identifiers
    }
}

/// Extract ids (and any `wanted` names) from the response's top-level or primary object only:
/// never from nested sub-resources (`owner.id`) and never from list items. A top-level object
/// with no identifier of its own is looked through once, into its envelope (`data`, `result`...).
pub fn extract_json_values(
    val: &Value,
    wanted: Option<&[String]>,
    out: &mut HashMap<String, String>,
) {
    let is_wanted = |k: &str| {
        wanted.is_some_and(|w| w.iter().any(|t| t.eq_ignore_ascii_case(k)))
            || DEFAULT_ID_KEYS.contains(&k.to_ascii_lowercase().as_str())
    };
    let Some(top) = val.as_object() else { return };
    let obj = if top
        .keys()
        .any(|k| is_wanted(k) || k.eq_ignore_ascii_case("_id"))
    {
        top
    } else {
        match primary_object(val) {
            Some(o) => o,
            None => return,
        }
    };
    for (k, v) in obj {
        if is_wanted(k)
            && let Some(s) = scalar(v)
        {
            out.insert(k.clone(), s);
        }
    }
    // a step that asks for `item_id` gets the primary `id` when the response has no such key
    if let Some(w) = wanted
        && let Some(id) = out.get("id").cloned()
    {
        for name in w {
            if !out.contains_key(name) && (name == "id" || name.ends_with("_id")) {
                out.insert(name.clone(), id.clone());
            }
        }
    }
}

// ---------------------------------------------------------------- actors

#[derive(Debug, Clone, PartialEq, Eq)]
enum Actor {
    Anon,
    Forged,
    Role(String),
}

fn actor_of(s: &str) -> Actor {
    let a = s.trim().to_ascii_lowercase();
    match a.as_str() {
        "anon" | "anonymous" | "none" | "" => Actor::Anon,
        "forged" => Actor::Forged,
        _ => Actor::Role(a),
    }
}

impl Actor {
    fn auth(&self) -> Auth {
        match self {
            Actor::Anon => Auth::None,
            Actor::Forged => Auth::Forged,
            Actor::Role(r) => Auth::Role(r.clone()),
        }
    }
    fn is_anon(&self) -> bool {
        *self == Actor::Anon
    }
}

/// Resolve bearer header for an actor (kept for callers that only need the header value).
pub fn actor_bearer(actor: &str, creds: &Credentials) -> Option<String> {
    resolve_auth(&actor_of(actor).auth(), creds)
        .bearer
        .map(|b| b.header)
}

/// Evaluate whether a violation condition is met.
pub fn evaluate_violation(condition: &str, status: u16, _body: &str) -> bool {
    let cond = condition.trim().to_ascii_lowercase();
    if cond == "bola" || cond == "idor" {
        // BOLA violation: an unauthorized cross-tenant actor obtained 2xx
        return (200..=299).contains(&status);
    }
    // Handle OR expressions: "status == 200 || status == 204"
    if cond.contains("||") {
        return cond
            .split("||")
            .any(|part| evaluate_violation(part, status, _body));
    }
    // Handle AND expressions: "status != 403 && status != 404"
    if cond.contains("&&") {
        return cond
            .split("&&")
            .all(|part| evaluate_violation(part, status, _body));
    }

    let part = cond.trim();
    if let Some(rest) = part.strip_prefix("status ==")
        && let Ok(expected) = rest.trim().parse::<u16>()
    {
        return status == expected;
    }
    if let Some(rest) = part.strip_prefix("status !=")
        && let Ok(expected) = rest.trim().parse::<u16>()
    {
        return status != expected;
    }
    if let Some(rest) = part.strip_prefix("status <")
        && let Ok(threshold) = rest.trim().parse::<u16>()
    {
        return status < threshold;
    }
    if let Some(rest) = part.strip_prefix("status >=")
        && let Ok(threshold) = rest.trim().parse::<u16>()
    {
        return status >= threshold;
    }
    if part == "status in 200..=299" || part == "2xx" {
        return (200..=299).contains(&status);
    }
    if let Some(sub) = part.strip_prefix("body_contains:") {
        let needle = sub.trim();
        return !needle.is_empty() && _body.to_ascii_lowercase().contains(needle);
    }
    if let Some(sub) = part.strip_prefix("unescaped:") {
        let needle = sub.trim();
        let trimmed = _body.trim_start();
        let is_json = trimmed.starts_with('{') || trimmed.starts_with('[');
        return (200..=299).contains(&status)
            && !is_json
            && !needle.is_empty()
            && _body.to_ascii_lowercase().contains(needle);
    }
    if let Some(kv) = part.strip_prefix("json_eq:")
        && let Some((k, v)) = kv.split_once('=')
        && let Ok(parsed) = serde_json::from_str::<Value>(_body)
    {
        return json_has_key_eq(&parsed, k.trim(), v.trim());
    }
    if let Some(kv) = part.strip_prefix("json_lt:")
        && let Some((k, v)) = kv.split_once('=')
        && let Ok(limit) = v.trim().parse::<f64>()
        && let Ok(parsed) = serde_json::from_str::<Value>(_body)
    {
        return json_has_key_lt(&parsed, k.trim(), limit);
    }
    false
}

fn json_has_key_eq(v: &Value, key: &str, want: &str) -> bool {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if k.eq_ignore_ascii_case(key) {
                    let matched = match child {
                        Value::String(s) => s.eq_ignore_ascii_case(want),
                        Value::Bool(b) => {
                            want.eq_ignore_ascii_case(if *b { "true" } else { "false" })
                        }
                        Value::Number(n) => n.to_string() == want,
                        _ => false,
                    };
                    if matched {
                        return true;
                    }
                }
                if json_has_key_eq(child, key, want) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => arr.iter().any(|x| json_has_key_eq(x, key, want)),
        _ => false,
    }
}

fn json_has_key_lt(v: &Value, key: &str, limit: f64) -> bool {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if k.eq_ignore_ascii_case(key)
                    && let Some(n) = child.as_f64()
                    && n < limit
                {
                    return true;
                }
                if json_has_key_lt(child, key, limit) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => arr.iter().any(|x| json_has_key_lt(x, key, limit)),
        _ => false,
    }
}

fn extract_violation_tag(raw: &str) -> (&str, &str) {
    let t = raw.trim();
    if let Some(rest) = t.strip_prefix("mass_assignment:") {
        ("mass_assignment", rest.trim())
    } else if let Some(rest) = t.strip_prefix("business_logic:") {
        ("business_logic", rest.trim())
    } else if let Some(rest) = t.strip_prefix("stored_xss:") {
        ("stored_xss", rest.trim())
    } else {
        ("business_logic", t)
    }
}

// ---------------------------------------------------------------- preflight

/// `/items/{{id}}` -> `/items`. None when the path has no trailing placeholder segment.
fn strip_trailing_placeholder(path: &str) -> Option<String> {
    let p = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .trim_end_matches('/');
    let (head, last) = p.rsplit_once('/')?;
    (last.starts_with("{{") && last.ends_with("}}")).then(|| head.to_string())
}

fn path_only(path: &str) -> String {
    let p = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .trim_end_matches('/');
    if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    }
}

/// Index of the access step: the last step that carries a violation condition.
fn access_index(steps: &[StatefulStep]) -> Option<usize> {
    steps.iter().rposition(|s| {
        s.violation_condition.as_deref().is_some_and(|c| {
            let t = c.trim();
            !t.starts_with("mass_assignment:")
                && !t.starts_with("business_logic:")
                && !t.starts_with("stored_xss:")
        })
    })
}

/// Everything that can be decided without sending a request. `Err` = skip the chain, with a note.
pub fn preflight(steps: &[StatefulStep], creds: &Credentials) -> Result<(), String> {
    if steps.is_empty() {
        return Err("the scenario has no steps".into());
    }
    // 1. methods: an unknown verb is rejected, never silently turned into GET
    for s in steps {
        if normalize_method(&s.method).is_none() {
            return Err(format!(
                "method '{}' in step {} is not allowed (GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE only)",
                s.method.chars().take(16).collect::<String>(),
                s.step_number
            ));
        }
    }
    // 2. every real actor needs its credential: a two-actor check with one token proves nothing
    let mut roles: Vec<String> = vec![];
    for s in steps {
        if let Actor::Role(r) = actor_of(&s.actor)
            && !roles.contains(&r)
        {
            roles.push(r);
        }
    }
    let missing: Vec<String> = roles
        .iter()
        .filter(|r| !creds.has_role(r))
        .map(|r| format!("'{r}' (set {})", Credentials::env_var(r)))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "missing credential for role {}; a stateful check needs the token of every actor it uses, nothing was sent",
            missing.join(", ")
        ));
    }
    // 3. placeholders must be produced by an earlier step before they are used
    let mut known: Vec<String> = vec![];
    for (i, s) in steps.iter().enumerate() {
        for text in std::iter::once(s.path.as_str()).chain(s.payload.as_deref()) {
            for name in placeholder_names(text) {
                // an id-like name may be filled by the default extraction of any earlier step
                let ok = known.iter().any(|k| k.eq_ignore_ascii_case(&name))
                    || (i > 0 && DEFAULT_ID_KEYS.contains(&name.to_ascii_lowercase().as_str()));
                if !ok {
                    return Err(format!(
                        "unresolved placeholder {{{{{name}}}}} in step {}: no earlier step extracts it",
                        s.step_number
                    ));
                }
            }
        }
        known.extend(s.extract_vars.iter().flatten().cloned());
    }
    // 4. shape of a cross-actor check
    if let Some(ai) = access_index(steps) {
        if ai == 0 {
            return Err("the access step has no creating step before it".into());
        }
        let creator = &steps[0];
        let access = &steps[ai];
        let (ca, aa) = (actor_of(&creator.actor), actor_of(&access.actor));
        if ca.is_anon() {
            return Err("the creating step is anonymous: there is no owner to isolate from".into());
        }
        if ca == aa {
            return Err(format!(
                "both steps use the same actor '{}': that is not a cross-actor check",
                creator.actor
            ));
        }
        match strip_trailing_placeholder(&access.path) {
            None => {
                return Err(
                    "the access step does not address the created resource (no trailing {{id}} segment)"
                        .into(),
                );
            }
            Some(base) => {
                if base != path_only(&creator.path) {
                    return Err(format!(
                        "the creating step and the access step are not the same resource: {} vs {}",
                        path_only(&creator.path),
                        base
                    ));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- runner

struct Runner<'a> {
    clients: &'a Clients,
    /// Id of the case the chain belongs to (tags what the chain creates in the ledger).
    case_id: &'a str,
    base: String,
    creds: &'a Credentials,
    budget: &'a mut RunBudget,
    host: &'a str,
    log: Vec<StatefulStepExecution>,
    curls: Vec<String>,
    latency: u64,
    last_status: u16,
}

struct Exchange<'a> {
    step_number: u32,
    /// Shown in the report, e.g. "bob" or "alice (owner control)".
    label: String,
    actor: &'a Actor,
    method: &'static str,
    path: String,
    /// The path with secret-keyed variables redacted (what is stored and put in the curl).
    disp_path: String,
    payload: Option<String>,
    disp_payload: Option<String>,
}

impl Runner<'_> {
    /// Send one request. Err(reason) means it was not sent or failed before a response.
    fn exchange(&mut self, e: &Exchange) -> Result<(Seen, usize), String> {
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
                    extracted_values: HashMap::new(),
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
                    extracted_values: HashMap::new(),
                    passed: false,
                    violation_triggered: false,
                    error_detail: Some(reason.clone()),
                });
                Err(reason)
            }
        }
    }

    fn finish(self, facts: StatefulFacts, summary: String) -> StatefulScenarioResult {
        let outcome = judge_stateful(&facts);
        let failure_reason = outcome.reason();
        use super::oracle::Verdict;
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

fn skipped_result(reason: String) -> StatefulScenarioResult {
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

fn status_matches(expected: u16, got: u16) -> bool {
    if (200..=299).contains(&expected) {
        (200..=299).contains(&got)
    } else {
        got == expected
    }
}

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
                            severity: super::oracle::Severity::High,
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
        let verdict_is_fail = judge_stateful(&facts).verdict == super::oracle::Verdict::Fail;
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

// ---------------------------------------------------------------- concurrency burst

/// What a burst saw. The verdict is `oracle::judge_burst`.
#[derive(Debug, Clone)]
pub struct BurstRun {
    pub requested: usize,
    pub responses: Vec<BurstResponse>,
    pub status_codes: Vec<u16>,
    /// Bodies of a safe GET of the same URL before / after the burst (state-changing bursts only).
    pub pre_read: Option<String>,
    pub post_read: Option<String>,
    pub notes: Vec<String>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn step(n: u32, actor: &str, method: &str, path: &str) -> StatefulStep {
        StatefulStep {
            step_number: n,
            actor: actor.into(),
            method: method.into(),
            path: path.into(),
            payload: None,
            extract_vars: None,
            expected_status: None,
            violation_condition: None,
        }
    }

    fn chain() -> Vec<StatefulStep> {
        let mut create = step(1, "alice", "POST", "/api/items");
        create.extract_vars = Some(vec!["id".into()]);
        let mut read = step(2, "bob", "GET", "/api/items/{{id}}");
        read.violation_condition = Some("status == 200".into());
        vec![create, read]
    }

    fn creds() -> Credentials {
        Credentials::none().with("alice", "a").with("bob", "b")
    }

    #[test]
    fn test_variable_substitution() {
        let mut ctx = HashMap::new();
        ctx.insert("item_id".into(), "item_987".into());
        ctx.insert("tenant".into(), "acme".into());

        let path = substitute_vars("/api/{{tenant}}/items/{{item_id}}", &ctx);
        assert_eq!(path, "/api/acme/items/item_987");

        let body = substitute_vars("{\"ref\": \"{{ item_id }}\"}", &ctx);
        assert_eq!(body, "{\"ref\": \"item_987\"}");
        // unknown placeholders survive substitution so the caller can reject them
        let left = substitute_vars("/x/{{ nope }}/{{tenant}}", &ctx);
        assert_eq!(left, "/x/{{ nope }}/acme");
        assert_eq!(placeholder_names(&left), ["nope"]);
        assert!(
            placeholder_names("{\"a\":{\"b\":1}}").is_empty(),
            "JSON braces are not placeholders"
        );
    }

    #[test]
    fn ids_come_from_the_top_level_or_primary_object_only() {
        let ex = |json: &str, wanted: Option<Vec<String>>| {
            let v: Value = serde_json::from_str(json).unwrap();
            let mut out = HashMap::new();
            extract_json_values(&v, wanted.as_deref(), &mut out);
            out
        };
        // a nested sub-resource's id never wins or leaks in
        let o = ex(
            r#"{"id": "ord_1", "owner": {"id": 77, "uuid": "u-9"}, "items": [{"id": 5}]}"#,
            None,
        );
        assert_eq!(o.get("id").map(String::as_str), Some("ord_1"));
        assert!(!o.contains_key("uuid"), "{o:?}");
        // an envelope is looked through exactly once, into the primary object
        let o = ex(
            r#"{"status": "ok", "data": {"id": "ord_2", "nested": {"uuid": "u-1"}}}"#,
            Some(vec!["token".into(), "id".into()]),
        );
        assert_eq!(o.get("id").map(String::as_str), Some("ord_2"));
        assert!(
            !o.contains_key("uuid"),
            "nested uuid must not be extracted: {o:?}"
        );
        // a list response has no primary object
        assert!(ex(r#"[{"id": 1}, {"id": 2}]"#, None).is_empty());
        // numbers become strings; an explicit name is aliased to the primary id
        let o = ex(r#"{"id": 4}"#, Some(vec!["item_id".into()]));
        assert_eq!(
            (
                o.get("id").map(String::as_str),
                o.get("item_id").map(String::as_str)
            ),
            (Some("4"), Some("4"))
        );
        // wanted secret names are extractable (chaining), but never by default
        let o = ex(r#"{"id": 1, "token": "tok_x"}"#, None);
        assert!(!o.contains_key("token"));
        let o = ex(r#"{"id": 1, "token": "tok_x"}"#, Some(vec!["token".into()]));
        assert_eq!(o.get("token").map(String::as_str), Some("tok_x"));
    }

    #[test]
    fn secret_looking_keys_are_redacted_before_they_are_stored() {
        for k in [
            "token",
            "access_token",
            "api_key",
            "apiKey",
            "secret",
            "client_secret",
            "password",
            "session",
            "session_id",
            "Authorization",
            "auth",
            "key",
            "jwt",
        ] {
            assert!(is_secret_key(k), "{k}");
            assert_eq!(storable_value(k, "value-1"), "[REDACTED]", "{k}");
        }
        for k in [
            "id",
            "uuid",
            "item_id",
            "order_id",
            "author_id",
            "title",
            "name",
        ] {
            assert!(!is_secret_key(k), "{k}");
        }
        assert_eq!(storable_value("id", "item_9"), "item_9");
        // even under an innocent key, secret-looking content is scrubbed
        assert!(!storable_value("note", "password=hunter2hunter2").contains("hunter2"));
    }

    #[test]
    fn test_violation_condition_evaluation() {
        assert!(evaluate_violation("status == 200", 200, ""));
        assert!(!evaluate_violation("status == 200", 403, ""));

        assert!(evaluate_violation(
            "status == 200 || status == 204",
            204,
            ""
        ));
        assert!(evaluate_violation(
            "status != 403 && status != 404",
            200,
            ""
        ));
        assert!(!evaluate_violation(
            "status != 403 && status != 404",
            403,
            ""
        ));

        assert!(evaluate_violation("bola", 200, ""));
        assert!(!evaluate_violation("bola", 403, ""));

        let (tag, expr) = extract_violation_tag("stored_xss:unescaped:<img src=x onerror=");
        assert_eq!(tag, "stored_xss");
        assert!(evaluate_violation(
            expr,
            200,
            "<ul><li><img src=x onerror=\"alert(1)\"></li></ul>"
        ));
        assert!(!evaluate_violation(
            expr,
            200,
            "<ul><li>&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</li></ul>"
        ));
    }

    #[test]
    fn preflight_decides_everything_that_needs_no_request() {
        assert!(preflight(&chain(), &creds()).is_ok());
        // credentials of every actor
        let e = preflight(&chain(), &Credentials::none().with("alice", "a")).unwrap_err();
        assert!(
            e.contains("missing credential") && e.contains("'bob'") && e.contains("RH_BOB_TOKEN"),
            "{e}"
        );
        assert!(
            preflight(&chain(), &Credentials::none())
                .unwrap_err()
                .contains("'alice'")
        );
        // an anonymous second actor needs no token
        let mut anon = chain();
        anon[1].actor = "anon".into();
        assert!(preflight(&anon, &Credentials::none().with("alice", "a")).is_ok());
        // unknown verbs are rejected, never turned into GET
        let mut bad = chain();
        bad[1].method = "TRACE".into();
        assert!(
            preflight(&bad, &creds())
                .unwrap_err()
                .contains("not allowed")
        );
        // lower-case verbs are fine (normalised)
        let mut low = chain();
        low[0].method = "post".into();
        assert!(preflight(&low, &creds()).is_ok());
        // placeholders must be producible by an earlier step
        let mut ph = chain();
        ph[1].path = "/api/items/{{nope}}".into();
        assert!(preflight(&ph, &creds()).unwrap_err().contains("{{nope}}"));
        let mut first = chain();
        first[0].path = "/api/items/{{id}}".into();
        assert!(
            preflight(&first, &creds())
                .unwrap_err()
                .contains("unresolved placeholder"),
            "no step before the first can fill it"
        );
        // one resource: POST /api/items pairs with GET /api/items/{{id}} only
        let mut other = chain();
        other[1].path = "/api/orders/{{id}}".into();
        assert!(
            preflight(&other, &creds())
                .unwrap_err()
                .contains("not the same resource")
        );
        let mut nested = chain();
        nested[1].path = "/api/items/{{id}}/history".into();
        assert!(preflight(&nested, &creds()).is_err());
        let mut slash = chain();
        slash[0].path = "/api/items/".into();
        assert!(
            preflight(&slash, &creds()).is_ok(),
            "a trailing slash is the same resource"
        );
        let mut noph = chain();
        noph[1].path = "/api/items".into();
        assert!(
            preflight(&noph, &creds())
                .unwrap_err()
                .contains("does not address the created resource")
        );
        // same actor, anonymous creator, missing creating step
        let mut same = chain();
        same[1].actor = "Alice".into();
        assert!(
            preflight(&same, &creds())
                .unwrap_err()
                .contains("same actor")
        );
        let mut anon_creator = chain();
        anon_creator[0].actor = "anon".into();
        assert!(preflight(&anon_creator, &creds()).is_err());
        assert!(preflight(&chain()[1..], &creds()).is_err());
        assert!(preflight(&[], &creds()).is_err());
    }

    #[test]
    fn actor_bearer_resolves_roles_and_never_invents_a_token() {
        let c = creds();
        assert_eq!(actor_bearer("alice", &c).as_deref(), Some("Bearer a"));
        assert_eq!(actor_bearer("ALICE", &c).as_deref(), Some("Bearer a"));
        assert_eq!(actor_bearer("anon", &c), None);
        assert_eq!(actor_bearer("carol", &c), None);
        assert!(
            actor_bearer("forged", &c)
                .unwrap()
                .starts_with("Bearer forged.")
        );
    }
}
