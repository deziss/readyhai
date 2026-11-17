//! Common helper utilities for API spec parameter synthesis, collection parsing, and ID extraction.
use serde_json::Value;
use std::collections::HashMap;

use super::contract;
use super::exec::Exchange;
use super::spec::Op;
use super::synth;
use crate::model::{CheckOutput, CheckStatus};

pub const UNLIKELY_ID: &str = "999999";

pub fn unlikely_ids(op: &Op) -> HashMap<String, String> {
    op.path_params()
        .map(|p| {
            let v = if let Some(e) = p
                .schema
                .get("enum")
                .and_then(|e| e.as_array())
                .and_then(|e| e.first())
            {
                synth::value_str(e)
            } else if p.schema.get("format").and_then(|f| f.as_str()) == Some("uuid") {
                "00000000-0000-4000-8000-000000999999".to_string()
            } else {
                UNLIKELY_ID.to_string()
            };
            (p.name.clone(), v)
        })
        .collect()
}

/// Per-endpoint latency note of the API checks: `latency <METHOD /path> p95=<ms>ms (n=<requests>)`.
/// The trend dashboard (`dashboard::parse_p95`) falls back to the worst of these when a run has
/// no k6 result; change both together.
pub fn latency_note(key: &str, p95_ms: u128, n: usize) -> String {
    format!("latency {key} p95={p95_ms}ms (n={n})")
}

/// Ids harvested per collection: enough to look at a few real records, never a crawl.
pub const MAX_IDS: usize = 3;

/// `GET /x/{param}` reads one item of the collection `/x`: (`/x`, `param`). None unless the path
/// is `<collection>/{param}` with exactly one path parameter.
pub fn collection_of(op: &Op) -> Option<(String, String)> {
    let last = op.path_params().last()?;
    let i = op.path.rfind('/')?;
    if op.path[i + 1..] != format!("{{{}}}", last.name) || op.path_params().count() != 1 {
        return None;
    }
    Some((op.path[..i].to_string(), last.name.clone()))
}

/// Add the ids of the items of a list response to `found` (named by `param`, `id`, `uuid` or
/// `_id`; at most [`MAX_IDS`] in all, no duplicates).
pub fn ids_in_list(list: &Value, param: &str, found: &mut Vec<String>) {
    for it in list_items(list) {
        let v = [param, "id", "uuid", "_id"]
            .iter()
            .find_map(|k| field(&it, k))
            .map(synth::value_str);
        if let Some(v) = v
            && !found.contains(&v)
            && found.len() < MAX_IDS
        {
            found.push(v);
        }
    }
}

/// Wrapper keys APIs put around the resource: `{"data": {...}}`, `{"result": {...}}`, JSON:API attributes.
pub const ENVELOPES: [&str; 4] = ["data", "result", "item", "payload"];

/// `name` from a response object, looking through a `{data:{...}}`-style wrapper (and JSON:API
/// `data.attributes`) when it is not at the top level.
pub fn field<'a>(j: &'a Value, name: &str) -> Option<&'a Value> {
    if let Some(v) = j.get(name) {
        return Some(v);
    }
    for w in ENVELOPES {
        if let Some(inner) = j.get(w) {
            if let Some(v) = inner.get(name) {
                return Some(v);
            }
            if let Some(v) = inner.get("attributes").and_then(|a| a.get(name)) {
                return Some(v);
            }
        }
    }
    None
}

/// Items of a list response: a top-level array, the first array-valued key, or the same inside an envelope.
pub fn list_items(j: &Value) -> Vec<Value> {
    if let Some(a) = j.as_array() {
        return a.clone();
    }
    let first_array = |o: &Value| {
        o.as_object()
            .and_then(|m| m.values().find_map(|v| v.as_array().cloned()))
    };
    if let Some(a) = first_array(j) {
        return a;
    }
    for w in ENVELOPES {
        if let Some(inner) = j.get(w)
            && let Some(a) = inner.as_array().cloned().or_else(|| first_array(inner))
        {
            return a;
        }
    }
    vec![]
}

/// New resource id from Location header (last segment) or JSON id/uuid/_id (also inside `{data:{...}}`).
pub fn created_id(ex: &Exchange) -> Option<String> {
    if let Some(l) = ex.header("location") {
        let seg = l
            .split(['?', '#'])
            .next()
            .unwrap_or("")
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("");
        if !seg.is_empty() {
            return Some(seg.to_string());
        }
    }
    let j = ex.json()?;
    ["id", "uuid", "_id"]
        .iter()
        .find_map(|k| field(&j, k))
        .map(synth::value_str)
}

pub fn not_applicable() -> CheckOutput {
    CheckOutput::status(CheckStatus::NotApplicable(
        "no OpenAPI spec found (use --spec)".into(),
    ))
}

/// First line of an error body worth grouping on (see `contract::body_fingerprint`); explicit
/// marker when the body is empty so triage does not merge unrelated empty 500s.
pub(crate) fn body_fp_or_empty(body: &str) -> String {
    let f = contract::body_fingerprint(body);
    if f.is_empty() { String::new() } else { f }
}

/// Why a response says nothing about the case (credentials / data / rate limit), if so.
pub fn blocked_reason(op: &Op, status: u16, has_id: bool) -> Option<String> {
    match status {
        401 | 403 => Some("no authorized role or valid credential available".into()),
        404 if !has_id && op.path_params().count() > 0 => {
            Some("no valid resource id available".into())
        }
        429 => Some("rate limited".into()),
        300..=399 => Some("redirect not followed (other host or too many hops)".into()),
        _ => None,
    }
}
