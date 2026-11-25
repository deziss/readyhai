//! Contract validation, schema enforcement, latency checks, and JSON structure oracles.

use regex::Regex;
use std::sync::OnceLock;

use super::super::triage::severity_for;
use super::super::types::{PlannedCase, ProbeOracle, ResponseContract};
use super::expectations::{is_rejection, not_exercised};
use super::types::{Observation, OracleCheck, Technique, Verdict, chk};
use crate::qa::api::{contract, latency};

pub(crate) fn json_of(body: &str) -> Option<serde_json::Value> {
    serde_json::from_str(body.trim()).ok()
}

/// The object a response is "about": the top-level object, or the single envelope object
/// (`data`, `result`, `item`, ...) when the top level carries no identifier of its own. Never a
/// nested sub-resource (`owner`, `tenant`, ...), and never an array element.
pub fn primary_object(
    v: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    let m = v.as_object()?;
    if ["id", "uuid", "_id"].iter().any(|k| m.contains_key(*k)) {
        return Some(m);
    }
    for w in [
        "data", "result", "item", "resource", "record", "entity", "object", "payload", "created",
    ] {
        if let Some(serde_json::Value::Object(inner)) = m.get(w) {
            return Some(inner);
        }
    }
    Some(m)
}

pub(crate) fn json_scalar_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub use super::signatures::traversal_signature;

pub(crate) fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Did the request carry a directory-traversal sequence (plain, percent- or double-encoded)?
pub(crate) fn is_traversal_probe(case: &PlannedCase, o: &Observation) -> bool {
    std::iter::once(case.component.as_str())
        .chain(o.sent_values.iter().map(String::as_str))
        .any(|raw| {
            let once = pct_decode(raw);
            let twice = pct_decode(&once);
            [raw.to_string(), once, twice].iter().any(|v| {
                let l = v.to_ascii_lowercase();
                l.contains("../")
                    || l.contains("..\\")
                    || l.contains("etc/passwd")
                    || l.contains("win.ini")
                    || l.contains("boot.ini")
            })
        })
}

const PRIVILEGED_KEYS: [&str; 14] = [
    "role",
    "roles",
    "is_admin",
    "isadmin",
    "admin",
    "is_superuser",
    "issuperuser",
    "superuser",
    "is_staff",
    "permissions",
    "scope",
    "scopes",
    "account_tier",
    "is_verified",
];

fn same_json(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value::*;
    match (a, b) {
        (String(x), Bool(y)) | (Bool(y), String(x)) => x.eq_ignore_ascii_case(&y.to_string()),
        (String(x), Number(y)) | (Number(y), String(x)) => *x == y.to_string(),
        _ => a == b,
    }
}

/// Privileged attributes of the request body that the response echoes back with the same value:
/// the server bound a client-supplied role/admin flag to the object (mass assignment).
pub(crate) fn mass_assignment_reflection(o: &Observation) -> Option<String> {
    let body = o.request_body?;
    if !(200..=299).contains(&o.status) {
        return None;
    }
    let sent: Vec<(String, serde_json::Value)> = match json_of(body) {
        Some(serde_json::Value::Object(m)) => m.into_iter().collect(),
        Some(_) => return None,
        None => body
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(pct_decode(v))))
            .collect(),
    };
    let sent: Vec<_> = sent
        .into_iter()
        .filter(|(k, _)| PRIVILEGED_KEYS.contains(&k.to_ascii_lowercase().as_str()))
        .collect();
    if sent.is_empty() {
        return None;
    }
    let resp = json_of(o.body)?;
    let obj = primary_object(&resp)?;
    for (k, v) in &sent {
        if let Some((_, got)) = obj.iter().find(|(rk, _)| rk.eq_ignore_ascii_case(k))
            && same_json(v, got)
        {
            return Some(format!(
                "the response echoes the injected privileged attribute '{k}' = {} (mass assignment / BOPLA)",
                crate::llm::untrusted::redact_then_truncate(&v.to_string(), 40)
            ));
        }
    }
    None
}

/// "a" or "an" for the word that follows ("an injection", "a boundary").
pub(crate) fn a_or_an(word: &str) -> &'static str {
    if word
        .chars()
        .next()
        .is_some_and(|c| "aeiouAEIOU".contains(c))
    {
        "an"
    } else {
        "a"
    }
}

/// A boundary/negative/injection case with no explicit expectation passes only on class-specific
/// evidence. The absence of a server error is not evidence.
pub(crate) fn class_evidence(
    case: &PlannedCase,
    o: &Observation,
    tech: Technique,
    out: &mut Vec<OracleCheck>,
) {
    let code = o.status;
    let verb_probe = tech == Technique::Negative
        && matches!(
            case.method.trim().to_ascii_uppercase().as_str(),
            "HEAD" | "OPTIONS"
        );
    if is_rejection(code) {
        out.push(chk(
            "validation_rejection",
            Verdict::Pass,
            None,
            format!("explicit input rejection: HTTP {code}"),
        ));
    } else if verb_probe && ((200..=299).contains(&code) || matches!(code, 405 | 501)) {
        out.push(chk(
            "verb_handling",
            Verdict::Pass,
            None,
            format!(
                "the {} verb was answered cleanly (HTTP {code})",
                case.method.to_ascii_uppercase()
            ),
        ));
    } else if tech == Technique::Boundary
        && case.method.trim().eq_ignore_ascii_case("GET")
        && (200..=299).contains(&code)
        && (case.title.to_ascii_lowercase().contains("tolerance")
            || case.title.to_ascii_lowercase().contains("numeric boundary")
            || case.title.to_ascii_lowercase().contains("integer overflow"))
    {
        out.push(chk(
            "boundary_tolerance",
            Verdict::Pass,
            None,
            format!("query input boundary handled cleanly without server error (HTTP {code})"),
        ));
    } else {
        let why = not_exercised(code)
            .map(|w| format!(" ({w})"))
            .unwrap_or_default();
        out.push(chk(
            "no_class_evidence",
            Verdict::Inconclusive,
            None,
            format!(
                "HTTP {code}{why} without a server error: {} {} case needs class-specific evidence (an explicit 4xx validation response, or a checked reflection) to pass, and the absence of a 5xx alone proves nothing",
                a_or_an(tech.as_str()),
                tech.as_str()
            ),
        ));
    }
}

/// Judge a response against the documented contract of its operation, with the QA engine's own
/// validators (`qa::api::contract`, `qa::api::latency`): an undocumented status, a 2xx body that
/// breaks its schema (`contract_fields`), a slow answer. Returns true when a body schema was
/// applied, which supersedes the bare required-field check.
pub(crate) fn contract_checks(
    c: &ResponseContract,
    o: &Observation,
    tech: Technique,
    out: &mut Vec<OracleCheck>,
    warnings: &mut Vec<String>,
) -> bool {
    let code = o.status;
    if contract::undocumented(&c.responses, code) {
        out.push(chk(
            "undocumented_status",
            Verdict::Fail,
            Some(severity_for("undocumented_status", tech)),
            format!("HTTP {code} is not a response the spec documents for this operation"),
        ));
    }
    if !(200..=299).contains(&code) {
        return false;
    }
    if c.latency {
        let ms = u128::from(o.latency_ms);
        out.push(if latency::is_slow(ms) {
            chk(
                "slow_response",
                Verdict::Fail,
                Some(severity_for("slow_response", tech)),
                format!(
                    "answered in {ms} ms, over the {} ms p95 limit",
                    latency::SLOW_P95_MS
                ),
            )
        } else {
            chk(
                "latency",
                Verdict::Pass,
                None,
                format!("answered in {ms} ms (limit {} ms)", latency::SLOW_P95_MS),
            )
        });
    }
    if !matches!(contract::schema_in(&c.responses, code), Some(Some(_))) {
        return false;
    }
    let Some(body) = json_of(o.body) else {
        warnings.push(
            "the response body is not (complete) JSON: the documented schema was not checked"
                .into(),
        );
        return false;
    };
    out.push(match contract::schema_mismatch(&c.responses, code, &body) {
        Some(m) => chk(
            "contract_fields",
            Verdict::Fail,
            Some(severity_for("contract_fields", tech)),
            format!("response violates the documented schema ({m})"),
        ),
        None => chk(
            "contract_fields",
            Verdict::Pass,
            None,
            "response matches the documented schema",
        ),
    });
    true
}

fn find_sensitive_json_keys(
    v: &serde_json::Value,
    explicit: bool,
    depth: usize,
    nodes: &mut usize,
    hits: &mut Vec<String>,
) {
    if depth > 8 || *nodes > 256 || hits.len() >= 5 {
        return;
    }
    *nodes += 1;
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                let lk = k.to_ascii_lowercase();
                let is_secret = matches!(
                    lk.as_str(),
                    "password_hash"
                        | "hashed_password"
                        | "password_digest"
                        | "pwd_hash"
                        | "salt"
                        | "totp_secret"
                        | "mfa_secret"
                        | "two_factor_secret"
                        | "private_key"
                        | "signing_key"
                        | "client_secret"
                        | "secret_key"
                        | "ssn"
                        | "credit_card"
                        | "card_number"
                        | "cvv"
                ) || (explicit
                    && matches!(lk.as_str(), "api_key" | "apikey" | "secret"));
                if is_secret {
                    let exposed = match val {
                        serde_json::Value::Null => false,
                        serde_json::Value::String(s) => {
                            let t = s.trim();
                            !t.is_empty()
                                && !t.chars().all(|c| c == '*')
                                && !t.eq_ignore_ascii_case("<redacted>")
                                && !t.eq_ignore_ascii_case("redacted")
                        }
                        _ => true,
                    };
                    if exposed && !hits.contains(k) {
                        hits.push(k.clone());
                    }
                }
                find_sensitive_json_keys(val, explicit, depth + 1, nodes, hits);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter().take(20) {
                find_sensitive_json_keys(item, explicit, depth + 1, nodes, hits);
            }
        }
        _ => {}
    }
}

pub(crate) fn excessive_data_exposure_check(
    case: &PlannedCase,
    o: &Observation,
    checks: &mut Vec<OracleCheck>,
) {
    if !(200..300).contains(&o.status) {
        return;
    }
    let explicit = matches!(case.probe_oracle, Some(ProbeOracle::ExcessiveDataExposure));
    let trimmed = o.body.trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        if explicit {
            checks.push(chk(
                "excessive_data_exposure",
                Verdict::Pass,
                None,
                "response body is not JSON containing sensitive fields",
            ));
        }
        return;
    }
    let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return;
    };
    let mut hits = Vec::new();
    let mut nodes = 0usize;
    find_sensitive_json_keys(&val, explicit, 0, &mut nodes, &mut hits);
    if !hits.is_empty() {
        checks.push(chk(
            "excessive_data_exposure",
            Verdict::Fail,
            Some(severity_for(
                "excessive_data_exposure",
                Technique::parse(&case.technique),
            )),
            format!(
                "response exposes unmasked sensitive JSON field(s): {}",
                hits.join(", ")
            ),
        ));
    } else if explicit {
        checks.push(chk(
            "excessive_data_exposure",
            Verdict::Pass,
            None,
            "no unmasked sensitive fields exposed in JSON response",
        ));
    }
}
