//! OpenAPI specification-driven planning (schema sampling, contracts, negative probes, and bursts).

use super::super::change::ChangeSet;
use super::super::discover::SpecDoc;
use super::super::exec::Credentials;
use super::super::oracle::Technique;
use super::super::types::{PlannedCase, ResponseContract, StatefulStep};
use super::helpers::{mk, user_or_anon};
use super::types::{Depth, NULL, SQLI, XSS};
use crate::llm::untrusted::clean;
use crate::qa::api::spec::Op as ApiOp;
use crate::qa::api::synth::{self, Expect};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

fn resolve<'a>(doc: &'a Value, v: &'a Value) -> &'a Value {
    let mut cur = v;
    for _ in 0..6 {
        match cur
            .get("$ref")
            .and_then(|r| r.as_str())
            .and_then(|r| r.strip_prefix('#'))
        {
            Some(ptr) => match doc.pointer(ptr) {
                Some(t) => cur = t,
                None => return cur,
            },
            None => return cur,
        }
    }
    cur
}

fn op_value<'a>(doc: &'a Value, path: &str, method: &str) -> Option<&'a Value> {
    doc.get("paths")?
        .get(path)?
        .get(method.to_ascii_lowercase())
}

pub(crate) struct Param {
    pub(crate) name: String,
    pub(crate) loc: String,
    pub(crate) ty: String,
    pub(crate) format: String,
    pub(crate) required: bool,
    /// A value the spec's own schema accepts (first enum value, default, example, else a type sample).
    pub(crate) sample: String,
}

/// A value for a parameter that satisfies its schema, so a case that is not about that parameter
/// does not trip the target's input validation (a required `?q=` left out answers 400).
pub(crate) fn sample_value(schema: &Value, ty: &str, format: &str) -> String {
    let given = schema
        .get("enum")
        .and_then(|e| e.get(0))
        .or_else(|| schema.get("default"))
        .or_else(|| schema.get("example"));
    let from_schema = match given {
        Some(Value::String(s)) => Some(s.clone()),
        Some(v @ (Value::Number(_) | Value::Bool(_))) => Some(v.to_string()),
        _ => None,
    };
    if let Some(v) = from_schema.filter(|v| !v.is_empty() && !v.contains(['&', '=', '#'])) {
        return v;
    }
    match ty {
        "integer" | "number" => schema
            .get("minimum")
            .and_then(Value::as_i64)
            .map_or(1, |m| m.max(1))
            .to_string(),
        "boolean" => "true".into(),
        _ if format == "uuid" => "00000000-0000-4000-8000-000000000001".into(),
        _ => {
            let min = schema["minLength"].as_u64().unwrap_or(0).min(256) as usize;
            "test".repeat(min.div_ceil(4).max(1))
        }
    }
}

/// The required query parameters of an operation as a `k=v&k2=v2` payload (the executor puts the
/// payload of GET/HEAD/OPTIONS in the query string), or `None` when none is required or the method
/// carries its payload in a body.
pub(crate) fn required_query(params: &[Param], method: &str) -> Option<String> {
    if !matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return None;
    }
    let pairs: Vec<String> = params
        .iter()
        .filter(|p| p.loc == "query" && p.required)
        .map(|p| format!("{}={}", p.name, p.sample))
        .collect();
    (!pairs.is_empty()).then(|| pairs.join("&"))
}

fn op_params(doc: &Value, path: &str, method: &str) -> Vec<Param> {
    let mut out = vec![];
    let item = doc.get("paths").and_then(|p| p.get(path));
    let op = op_value(doc, path, method);
    for list in [
        item.and_then(|i| i.get("parameters")),
        op.and_then(|o| o.get("parameters")),
    ]
    .into_iter()
    .flatten()
    {
        for p in list.as_array().into_iter().flatten() {
            let p = resolve(doc, p);
            let schema = resolve(doc, p.get("schema").unwrap_or(&NULL));
            let ty = schema["type"].as_str().unwrap_or("string").to_string();
            let format = schema["format"].as_str().unwrap_or("").to_string();
            out.push(Param {
                name: p["name"].as_str().unwrap_or("").to_string(),
                loc: p["in"].as_str().unwrap_or("").to_string(),
                required: p["required"].as_bool().unwrap_or(false),
                sample: sample_value(schema, &ty, &format),
                ty,
                format,
            });
        }
    }
    out.retain(|p| !p.name.is_empty());
    out
}

/// Fill `{param}` placeholders with sample values. `write` (PUT/PATCH/DELETE) uses ids no record has,
/// never `1`: an authenticated write case must not be able to modify or delete a real record.
fn fill_path(tpl: &str, params: &[Param], write: bool) -> String {
    let mut out = String::new();
    let mut rest = tpl;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find('}').map(|j| j + i) else {
            break;
        };
        let name = &rest[i + 1..j];
        let p = params.iter().find(|p| p.loc == "path" && p.name == name);
        let lname = name.to_ascii_lowercase();
        let v = match p {
            Some(p) if p.format == "uuid" && write => "00000000-0000-4000-8000-000000999999",
            Some(p) if p.format == "uuid" => "00000000-0000-4000-8000-000000000001",
            Some(p) if p.ty == "integer" || p.ty == "number" => {
                if write {
                    "999999"
                } else {
                    "1"
                }
            }
            _ if lname == "id" || lname.ends_with("id") => {
                if write {
                    "999999"
                } else {
                    "1"
                }
            }
            _ if write => "readyhai-nonexistent",
            _ => "test",
        };
        out.push_str(v);
        rest = &rest[j + 1..];
    }
    out.push_str(rest);
    out
}

fn schema_required(doc: &Value, schema: &Value) -> Vec<String> {
    let s = resolve(doc, schema);
    let s = if s["type"] == "array" {
        resolve(doc, s.get("items").unwrap_or(&NULL))
    } else {
        s
    };
    s["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .take(20)
        .map(String::from)
        .collect()
}

fn response_required_fields(doc: &Value, op: &Value) -> Vec<String> {
    let responses = &op["responses"];
    for code in ["200", "201", "2XX", "default"] {
        if let Some(r) = responses.get(code) {
            let r = resolve(doc, r);
            if let Some(schema) = r["content"]["application/json"].get("schema") {
                return schema_required(doc, schema);
            }
        }
    }
    vec![]
}

fn request_first_property(doc: &Value, op: &Value) -> Option<String> {
    let rb = resolve(doc, op.get("requestBody")?);
    let schema = resolve(doc, rb["content"]["application/json"].get("schema")?);
    let props = schema.get("properties")?.as_object()?;
    props
        .iter()
        .find(|(_, v)| resolve(doc, v)["type"] == "string")
        .map(|(k, _)| k.clone())
        .or_else(|| props.keys().next().cloned())
}

/// A valid JSON request body for `method path`, synthesised from the spec's request schema (required
/// fields filled, `$ref`s resolved), so a create step is not rejected by validation before it can
/// create anything. `None` when the operation declares no JSON object body.
pub(crate) fn synth_request_body(doc: &Value, path: &str, method: &str) -> Option<String> {
    let rb = resolve(doc, op_value(doc, path, method)?.get("requestBody")?);
    let schema = rb
        .get("content")?
        .as_object()?
        .iter()
        .find(|(k, _)| k.contains("json"))?
        .1
        .get("schema")?;
    let schema = crate::qa::api::spec::resolve(doc, schema);
    let body = crate::qa::api::synth::synth(&schema, "body", "readyhai-", 0);
    body.is_object().then(|| body.to_string())
}

/// `/items/{id}` is the item path of `/items`: one extra segment, and it is a single placeholder.
pub(crate) fn is_item_path_of(base: &str, path: &str) -> bool {
    let Some(rest) = path.strip_prefix(base).and_then(|r| r.strip_prefix('/')) else {
        return false;
    };
    rest.len() > 2
        && rest.starts_with('{')
        && rest.ends_with('}')
        && !rest[1..rest.len() - 1].contains(['{', '}', '/'])
}

/// Login / token / password endpoints: hammering them locks accounts and sends mail.
pub(crate) fn is_credential_flow(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "login", "logout", "signin", "signup", "register", "auth", "token", "password", "reset",
        "verify", "otp",
    ]
    .iter()
    .any(|k| p.contains(k))
}

/// Largest response schema carried inside a planned case (the plan is stored with the report).
pub(crate) const MAX_CONTRACT_SCHEMA: usize = 16 * 1024;

/// What the spec documents about the responses of `api`, for the oracle: every documented status,
/// the schemas a 2xx body is validated against. `oversized` counts schemas left out for size.
fn contract_of(api: &ApiOp, latency: bool, oversized: &mut usize) -> ResponseContract {
    let responses = api
        .responses
        .iter()
        .map(|(status, schema)| {
            let schema = schema
                .as_ref()
                .filter(|_| status.starts_with('2') || status == "DEFAULT")
                .filter(|s| {
                    let fits = s.to_string().len() <= MAX_CONTRACT_SCHEMA;
                    if !fits {
                        *oversized += 1;
                    }
                    fits
                })
                .cloned();
            (status.clone(), schema)
        })
        .collect();
    ResponseContract { responses, latency }
}

/// Order of the generated invalid inputs when only a few fit the budget: the limits that most often
/// meet unguarded code first (an oversized string, a number out of range), then a missing required
/// field, then the type confusions.
fn probe_rank(kind: &str) -> u8 {
    match kind.split('.').nth(1).unwrap_or("") {
        "maxlen" => 0,
        "min" | "max" | "enum" => 1,
        "missing" => 2,
        "minlen" | "wrongtype" => 3,
        _ => 4,
    }
}

/// Invalid input that breaks the spec's own constraints, from the QA engine's generator
/// (`qa::api::synth::generate`): a string one character over its `maxLength`, a number past its
/// `minimum`/`maximum`, a required field left out. Each must be rejected with a 4xx: a 5xx is a
/// server error, a 2xx is invalid input accepted. A write goes to an id nobody owns (never to a
/// harvested record); a read goes to a record that exists.
fn probe_cases(
    spec: &SpecDoc,
    api: &ApiOp,
    ids: &BTreeMap<String, Vec<String>>,
    role: &str,
    contract: &ResponseContract,
    limit: usize,
) -> Vec<PlannedCase> {
    if !matches!(api.method.as_str(), "GET" | "POST" | "PUT" | "PATCH")
        || is_credential_flow(&api.path)
    {
        return vec![];
    }
    let write = api.is_write();
    let path_ids: HashMap<String, String> = if write {
        crate::qa::api::unlikely_ids(api)
    } else {
        crate::qa::api::collection_of(api)
            .and_then(|(list, param)| {
                ids.get(&list)
                    .and_then(|v| v.first())
                    .map(|id| HashMap::from([(param, id.clone())]))
            })
            .unwrap_or_default()
    };
    let mut cases: Vec<synth::Case> = synth::generate(api, "readyhai-", false, &path_ids)
        .into_iter()
        .filter(|c| c.expect == Expect::Reject)
        .collect();
    cases.sort_by_key(|c| probe_rank(&c.kind)); // stable: ties keep the generator's order
    // a write on an id that is not there mostly meets a 404 before its validation: fewer of them
    let limit = if write && api.path_params().next().is_some() {
        limit.div_ceil(2)
    } else {
        limit
    };
    cases.truncate(limit);
    let label = format!("{} {}", api.method, api.path);
    cases
        .into_iter()
        .map(|c| {
            let mut pc = mk(
                if c.technique == crate::qa::model::Technique::Boundary {
                    "boundary"
                } else {
                    "negative"
                },
                format!("{} on {label}", c.title),
                &api.method,
                synth::build_url(&spec.base_path, &api.path, &c.path_vals, &c.query),
                "Input that breaks a constraint of the spec's own schema",
                c.body.as_ref().map(|b| b.to_string()),
                "Invalid input is rejected with a 4xx client error",
                None,
                "medium",
                role,
                "openapi",
            );
            pc.secured = Some(api.secured);
            pc.contract = Some(contract.clone());
            pc
        })
        .collect()
}

/// Operations a changed-operation case set is planned for even when the profile plans none: every
/// kind of probe, with the deep profile's per-operation probe limit.
const CHANGED_PROBES_PER_OP: usize = 8;
/// Most concurrency bursts planned for changed operations (each sends 5 parallel creates).
const MAX_CHANGED_BURSTS: usize = 3;

/// `max_ops`: the profile's baseline (the top operations by risk), None when the profile plans no
/// spec cases (quick). `focus`: the operations the code diff touched. They are planned in full
/// whatever the profile says, ahead of the baseline, and are never held back by the limits that
/// ration the baseline (forged-token cases, injection cases, probe totals, one burst, one chain).
pub(crate) fn spec_cases(
    spec: &SpecDoc,
    ids: &BTreeMap<String, Vec<String>>,
    creds: &Credentials,
    depth: Depth,
    max_ops: Option<usize>,
    focus: Option<&ChangeSet>,
    notes: &mut Vec<String>,
) -> Vec<PlannedCase> {
    let acting = user_or_anon(creds);
    let user = acting.as_str();
    let actor = creds.actor();
    let api_ops = spec.api_ops();
    let mut oversized = 0;
    let is_changed = |o: &crate::qa::plan::Op| focus.is_some_and(|f| f.contains(o));
    let mut sorted: Vec<&crate::qa::plan::Op> = spec.ops.iter().collect();
    sorted.sort_by_key(|o| std::cmp::Reverse(crate::qa::plan::score(o, None, false).0)); // stable: ties keep spec order
    // the changed operations first, then the profile's baseline (which is all of `ops` when
    // nothing changed)
    let mut ops: Vec<&crate::qa::plan::Op> =
        sorted.iter().copied().filter(|o| is_changed(o)).collect();
    ops.extend(
        sorted
            .iter()
            .copied()
            .take(max_ops.unwrap_or(0))
            .filter(|o| !is_changed(o)),
    );
    let (mut authz, mut inj, mut neg, mut bound, mut forged, mut base, mut probes) =
        (vec![], vec![], vec![], vec![], vec![], vec![], vec![]);
    let mut forged_n = 0;
    let mut inj_n = 0;
    for op in &ops {
        let changed_op = is_changed(op);
        let marks = [
            authz.len(),
            inj.len(),
            neg.len(),
            bound.len(),
            forged.len(),
            base.len(),
            probes.len(),
        ];
        let api = api_ops
            .iter()
            .find(|a| a.method == op.method && a.path == op.path);
        let params = op_params(&spec.doc, &op.path, &op.method);
        let is_write = matches!(op.method.as_str(), "PUT" | "PATCH" | "DELETE");
        let comp = format!(
            "{}{}",
            spec.base_path,
            fill_path(&op.path, &params, is_write)
        );
        let opv = op_value(&spec.doc, &op.path, &op.method)
            .cloned()
            .unwrap_or(Value::Null);
        let label = format!("{} {}", op.method, op.path);
        if op.secured {
            let mut c = mk(
                "authz",
                format!("Unauthenticated {label} is rejected"),
                &op.method,
                comp.clone(),
                "Call the operation without credentials",
                required_query(&params, &op.method),
                "HTTP 401 or 403",
                Some(401),
                "critical",
                "anon",
                "openapi",
            );
            c.secured = Some(true);
            authz.push(c);
            if forged_n < 3 || changed_op {
                if !changed_op {
                    forged_n += 1;
                }
                let mut c = mk(
                    "authz",
                    format!("Forged bearer token is rejected on {label}"),
                    &op.method,
                    comp.clone(),
                    "Send a syntactically valid but forged bearer token",
                    required_query(&params, &op.method),
                    "HTTP 401 or 403",
                    Some(401),
                    "critical",
                    "forged",
                    "openapi",
                );
                c.secured = Some(true);
                forged.push(c);
            }
        }
        let qparams: Vec<&Param> = params.iter().filter(|p| p.loc == "query").collect();
        if let (Some(q), true) = (qparams.first(), (inj_n < 4 || changed_op) && !op.has_body) {
            if !changed_op {
                inj_n += 1;
            }
            let mut c = mk(
                "injection",
                format!("Script injection through ?{} on {label}", q.name),
                &op.method,
                comp.clone(),
                "Inject a script vector into a query parameter",
                Some(format!("{}={XSS}", q.name)),
                "Payload is not reflected unescaped and causes no server error",
                None,
                "high",
                user,
                "openapi",
            );
            c.secured = Some(op.secured);
            inj.push(c);
            let mut c = mk(
                "injection",
                format!("SQL injection through ?{} on {label}", q.name),
                &op.method,
                comp.clone(),
                "Inject a SQL tautology into a query parameter",
                Some(format!("{}={SQLI}", q.name)),
                "No SQL error is disclosed and no server error occurs",
                None,
                "high",
                user,
                "openapi",
            );
            c.secured = Some(op.secured);
            inj.push(c);
        }
        if op.has_body {
            let field = request_first_property(&spec.doc, &opv).unwrap_or_else(|| "name".into());
            let mut c = mk(
                "negative",
                format!("Malformed JSON body is rejected on {label}"),
                &op.method,
                comp.clone(),
                "Send syntactically invalid JSON",
                Some("{\"".into()),
                "Malformed input must be rejected with a 4xx client error",
                None,
                "high",
                user,
                "openapi",
            );
            c.secured = Some(op.secured);
            neg.push(c);
            let mut c = mk(
                "boundary",
                format!("Oversized `{field}` is handled on {label}"),
                &op.method,
                comp.clone(),
                "5000-character string in the first string field",
                Some(serde_json::json!({ field.clone(): "A".repeat(5000) }).to_string()),
                "Oversized input is handled without a server error",
                None,
                "medium",
                user,
                "openapi",
            );
            c.secured = Some(op.secured);
            bound.push(c);
        } else if op.method == "GET" {
            let fields = response_required_fields(&spec.doc, &opv);
            if !op.secured || actor.is_some() {
                // the records the collection endpoint showed when there are any, else the stand-in id
                let found = api
                    .and_then(crate::qa::api::collection_of)
                    .and_then(|(list, param)| ids.get(&list).map(|v| (param, v)));
                let reads: Vec<(String, String)> = match found {
                    Some((param, found)) => found
                        .iter()
                        .map(|id| {
                            (
                                format!(
                                    "{}{}",
                                    spec.base_path,
                                    op.path.replace(&format!("{{{param}}}"), &synth::pct(id))
                                ),
                                format!(
                                    "{label} (id {}) answers 2xx and honours its contract",
                                    clean(id, 40)
                                ),
                            )
                        })
                        .collect(),
                    None => vec![(
                        comp.clone(),
                        format!("{label} answers 2xx and honours its contract"),
                    )],
                };
                let contract_role = if op.secured {
                    if super::super::oracle::is_privileged_api_path(&op.path) {
                        creds.admin_role().unwrap_or_else(|| user.to_string())
                    } else {
                        user.to_string()
                    }
                } else {
                    "anon".to_string()
                };
                for (read_comp, title) in reads {
                    let mut c = mk(
                        "state_transition",
                        title,
                        "GET",
                        read_comp,
                        "Plain read of the operation",
                        required_query(&params, "GET"),
                        "HTTP 2xx with the documented required fields",
                        Some(200),
                        "medium",
                        &contract_role,
                        "openapi",
                    );
                    c.secured = Some(op.secured);
                    c.expect_fields = fields.clone();
                    c.expected_content_type = Some("json".into())
                        .filter(|_| opv["responses"].to_string().contains("application/json"));
                    // the documented statuses, the 2xx body schema and the QA latency limit
                    c.contract = api.map(|a| contract_of(a, true, &mut oversized));
                    base.push(c);
                }
            }
        }
        // boundary / negative probes from the spec's constraints, as the acting role
        if let Some(api) = api
            && (!op.secured || actor.is_some())
        {
            let contract = contract_of(api, false, &mut oversized);
            probes.extend(probe_cases(
                spec,
                api,
                ids,
                if op.secured { user } else { "anon" },
                &contract,
                if changed_op {
                    CHANGED_PROBES_PER_OP
                } else {
                    depth.probes_per_op()
                },
            ));
        }
        if changed_op {
            let label = op.component();
            let tag = |v: &mut Vec<PlannedCase>, from: usize| {
                for c in &mut v[from..] {
                    c.changed_ops.push(label.clone());
                }
            };
            tag(&mut authz, marks[0]);
            tag(&mut inj, marks[1]);
            tag(&mut neg, marks[2]);
            tag(&mut bound, marks[3]);
            tag(&mut forged, marks[4]);
            tag(&mut base, marks[5]);
            tag(&mut probes, marks[6]);
        }
    }
    // the total ration is for the baseline; what tests a changed operation is not cut by it
    let (changed_probes, mut other_probes): (Vec<_>, Vec<_>) =
        probes.into_iter().partition(|c| !c.changed_ops.is_empty());
    other_probes.truncate(depth.probes_total());
    let mut probes = changed_probes;
    probes.extend(other_probes);
    if !probes.is_empty() {
        notes.push(format!(
            "{} boundary/negative probe(s) planned from the spec's own constraints (the QA engine's case generator)",
            probes.len()
        ));
    }
    if oversized > 0 {
        notes.push(format!(
            "{oversized} response schema(s) over {MAX_CONTRACT_SCHEMA} bytes were not carried into the plan: those bodies are not validated"
        ));
    }
    let mut stateful_bola = vec![];
    let mut toctou_burst = vec![];

    // BOLA needs one resource seen from two actors: a POST that creates it and the GET of the SAME
    // resource by id (`POST /items` with `GET /items/{id}`), never an unrelated pair.
    let pairs: Vec<(&crate::qa::plan::Op, &crate::qa::plan::Op)> = spec
        .ops
        .iter()
        .filter(|o| o.method == "POST" && o.has_body)
        .filter_map(|post| {
            let base = post.path.trim_end_matches('/');
            spec.ops
                .iter()
                .find(|g| g.method == "GET" && is_item_path_of(base, &g.path))
                .map(|g| (post, g))
        })
        .collect();
    // the chain of a changed operation first; the baseline's own (the first pair) when the profile
    // plans spec cases at all
    let mut chains = vec![];
    if let Some(pair) = pairs.iter().find(|(p, g)| is_changed(p) || is_changed(g)) {
        chains.push(*pair);
    }
    if max_ops.is_some()
        && let Some(first) = pairs.first()
        && !chains
            .iter()
            .any(|(p, g)| p.path == first.0.path && g.path == first.1.path)
    {
        chains.push(*first);
    }
    for (post_op, get_op) in chains {
        let post_params = op_params(&spec.doc, &post_op.path, &post_op.method);
        let post_comp = format!(
            "{}{}",
            spec.base_path,
            fill_path(post_op.path.trim_end_matches('/'), &post_params, false)
        );
        // the read path is the creating path plus the id of what was created
        let get_step_path = format!("{post_comp}/{{{{id}}}}");

        let step1 = StatefulStep {
            step_number: 1,
            actor: "alice".into(),
            method: "POST".into(),
            path: post_comp.clone(),
            payload: Some(
                synth_request_body(&spec.doc, &post_op.path, "POST").unwrap_or_else(|| {
                    r#"{"item": "Alice Confidential Record", "name": "Confidential"}"#.into()
                }),
            ),
            extract_vars: Some(vec![
                "id".into(),
                "uuid".into(),
                "order_id".into(),
                "item_id".into(),
            ]),
            expected_status: Some(201),
            violation_condition: None,
        };
        let step2 = StatefulStep {
            step_number: 2,
            actor: "bob".into(),
            method: "GET".into(),
            path: get_step_path,
            payload: None,
            extract_vars: None,
            expected_status: None,
            violation_condition: Some("status == 200 || status == 204".into()),
        };

        let mut c = mk(
            "authz",
            format!(
                "Stateful BOLA tenant isolation (POST {} -> GET {})",
                post_op.path, get_op.path
            ),
            "POST",
            post_comp,
            "Alice creates private resource; Bob attempts cross-tenant access",
            None,
            "Alice reads her own resource; Bob does not (HTTP 404, or a confirmed 2xx is a breach). Needs RH_ALICE_TOKEN and RH_BOB_TOKEN",
            None,
            "critical",
            "alice",
            "openapi",
        );
        c.secured = Some(true);
        c.stateful_steps = Some(vec![step1, step2]);
        c.changed_ops = [post_op, get_op]
            .into_iter()
            .filter(|o| is_changed(o))
            .map(|o| o.component())
            .collect();
        stateful_bola.push(c);
    }

    // TOCTOU burst on a spec-declared create operation. Never on PUT/DELETE of an existing object
    // (it would modify or delete the owner's data N times) and never on credential flows. The body
    // is synthesised from the operation's request schema, so every copy is valid and reaches the
    // handler instead of bouncing off validation; an operation with no usable JSON object schema
    // gets no burst (nothing is invented).
    let burst_candidates: Vec<(&crate::qa::plan::Op, String)> = ops
        .iter()
        .copied()
        .filter(|o| o.method == "POST" && o.has_body && !is_credential_flow(&o.path))
        .filter_map(|o| synth_request_body(&spec.doc, &o.path, "POST").map(|b| (o, b)))
        .collect();
    // changed creates first (a few: each burst is five parallel writes), then the baseline's one
    let mut bursts: Vec<(&crate::qa::plan::Op, String)> = burst_candidates
        .iter()
        .filter(|(o, _)| is_changed(o))
        .take(MAX_CHANGED_BURSTS)
        .cloned()
        .collect();
    if max_ops.is_some()
        && let Some(first) = burst_candidates.iter().find(|(o, _)| !is_changed(o))
    {
        bursts.push(first.clone());
    }
    for (mutating_op, payload) in bursts {
        let params = op_params(&spec.doc, &mutating_op.path, &mutating_op.method);
        let comp = format!(
            "{}{}",
            spec.base_path,
            fill_path(&mutating_op.path, &params, false)
        );
        let mut c = mk(
            "boundary",
            format!(
                "TOCTOU concurrency burst on {} {}",
                mutating_op.method, mutating_op.path
            ),
            &mutating_op.method,
            comp,
            "Rapid parallel concurrency burst to detect race conditions",
            Some(payload),
            "Concurrent creations hand out distinct ids and no acknowledged update is lost",
            None,
            "high",
            user,
            "openapi",
        );
        c.secured = Some(mutating_op.secured);
        c.concurrency_burst = Some(5);
        if is_changed(mutating_op) {
            c.changed_ops = vec![mutating_op.component()];
        }
        toctou_burst.push(c);
    }

    [
        authz,
        inj,
        neg,
        bound,
        forged,
        base,
        probes,
        stateful_bola,
        toctou_burst,
    ]
    .concat()
}
