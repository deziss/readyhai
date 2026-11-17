//! Concurrency and race-condition burst oracles (TOCTOU, duplicate creation, lost update, redemption bypass).

use super::super::triage::severity_for;
use super::contract::{json_of, json_scalar_string, primary_object};
use super::types::{chk, outcome, OracleOutcome, Technique, Verdict};

/// One response of a concurrent burst (body capped by the executor).
#[derive(Debug, Clone)]
pub struct BurstResponse {
    pub status: u16,
    pub body: String,
}

pub struct BurstFacts<'a> {
    pub method: &'a str,
    pub requested: usize,
    pub responses: &'a [BurstResponse],
    /// Body of a safe GET of the same URL before / after the burst.
    pub pre_read: Option<&'a str>,
    pub post_read: Option<&'a str>,
}

const COUNTER_KEYS: [&str; 14] = [
    "count",
    "counter",
    "total",
    "quantity",
    "qty",
    "stock",
    "balance",
    "remaining",
    "inventory",
    "likes",
    "votes",
    "version",
    "seq",
    "uses",
];

fn counters(body: &str) -> Vec<(String, f64)> {
    let Some(v) = json_of(body) else {
        return vec![];
    };
    let Some(obj) = primary_object(&v) else {
        return vec![];
    };
    obj.iter()
        .filter(|(k, _)| COUNTER_KEYS.contains(&k.to_ascii_lowercase().as_str()))
        .filter_map(|(k, v)| v.as_f64().map(|n| (k.to_ascii_lowercase(), n)))
        .collect()
}

/// Concurrency verdict from invariants only. "Every request answered 2xx" is not a race: FAIL needs
/// a violated invariant (duplicate created ids, lost increment, balance/stock underflow, or
/// concurrent multiple redemption on single-use flows).
pub fn judge_burst(f: &BurstFacts) -> OracleOutcome {
    judge_burst_on_path(f, "")
}

/// [`judge_burst`] with endpoint path context so single-use/redemption endpoints can also detect
/// missing idempotency / concurrency locking (`409 Conflict`).
pub fn judge_burst_on_path(f: &BurstFacts, path: &str) -> OracleOutcome {
    let mut checks = vec![];
    let mut warnings = vec![];
    let method = f.method.to_ascii_uppercase();
    let ok: Vec<&BurstResponse> = f
        .responses
        .iter()
        .filter(|r| (200..=299).contains(&r.status))
        .collect();
    let n5xx = f.responses.iter().filter(|r| r.status >= 500).count();
    if n5xx > 0 {
        warnings.push(format!(
            "{n5xx} of {} concurrent requests answered HTTP 5xx; a server error is judged by the single-request case, it is not an invariant violation here",
            f.responses.len()
        ));
    }
    if f.responses.len() < 2 {
        checks.push(chk(
            "race_condition",
            Verdict::Inconclusive,
            None,
            format!(
                "only {} of {} concurrent responses were received: nothing to compare",
                f.responses.len(),
                f.requested
            ),
        ));
        return outcome(checks, warnings);
    }
    let mut evaluated = false;
    let mut distinct_created_ids = 0usize;

    // invariant A: concurrent creations must not hand out the same id twice
    if method == "POST" {
        let ids: Vec<String> = ok
            .iter()
            .filter_map(|r| {
                let v = json_of(&r.body)?;
                let obj = primary_object(&v)?;
                ["id", "uuid", "_id"]
                    .iter()
                    .find_map(|k| obj.get(*k).and_then(json_scalar_string))
            })
            .collect();
        if ids.len() >= 2 {
            evaluated = true;
            let mut seen = std::collections::BTreeSet::new();
            let dup = ids.iter().find(|i| !seen.insert((*i).clone())).cloned();
            distinct_created_ids = seen.len();
            match dup {
                Some(d) => checks.push(chk(
                    "race_condition",
                    Verdict::Fail,
                    Some(severity_for("race_condition", Technique::Other)),
                    format!(
                        "{} concurrent creations returned only {} distinct ids (duplicate id '{}')",
                        ids.len(),
                        seen.len(),
                        crate::llm::untrusted::redact_then_truncate(&d, 40)
                    ),
                )),
                None => checks.push(chk(
                    "race_condition",
                    Verdict::Pass,
                    None,
                    format!(
                        "{} concurrent creations returned {} distinct ids",
                        ids.len(),
                        ids.len()
                    ),
                )),
            }
        }
    }

    // invariant B: acknowledged increments must show up when the resource is read back
    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS")
        && let (Some(pre), Some(post)) = (f.pre_read, f.post_read)
    {
        let (pre_c, post_c) = (counters(pre), counters(post));
        let mut per_key: std::collections::BTreeMap<String, Vec<f64>> = Default::default();
        for r in &ok {
            for (k, v) in counters(&r.body) {
                per_key.entry(k).or_default().push(v);
            }
        }
        for (key, vals) in per_key.iter().filter(|(_, v)| v.len() >= 2) {
            let (Some(a), Some(b)) = (
                pre_c.iter().find(|(k, _)| k == key).map(|(_, v)| *v),
                post_c.iter().find(|(k, _)| k == key).map(|(_, v)| *v),
            ) else {
                continue;
            };
            let delta = (b - a).abs();
            if delta == 0.0 {
                continue; // the burst did not touch this field: not a counter of ours
            }
            evaluated = true;
            let mut distinct: Vec<f64> = vals.clone();
            distinct.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
            distinct.dedup();
            let dup = distinct.len() < vals.len();
            let k = ok.len() as f64;
            if dup && delta + 0.5 < k {
                checks.push(chk(
                    "race_condition",
                    Verdict::Fail,
                    Some(severity_for("race_condition", Technique::Other)),
                    format!(
                        "lost update: {} requests were acknowledged but counter '{key}' moved by {delta} on re-read, and several responses reported the same new value",
                        ok.len()
                    ),
                ));
            } else {
                checks.push(chk(
                    "race_condition",
                    Verdict::Pass,
                    None,
                    format!(
                        "counter '{key}' moved by {delta} for {} acknowledged requests",
                        ok.len()
                    ),
                ));
            }
        }
    }

    // invariant C: concurrent state transitions must never drive finite resource counters negative
    let pre_neg: std::collections::BTreeSet<String> = f
        .pre_read
        .map(|p| {
            counters(p)
                .into_iter()
                .filter(|(_, v)| *v < 0.0)
                .map(|(k, _)| k)
                .collect()
        })
        .unwrap_or_default();
    let finite_keys = ["balance", "stock", "remaining", "inventory"];
    let mut neg_hit: Option<(String, f64)> = None;
    for body_counters in f
        .post_read
        .into_iter()
        .map(counters)
        .chain(ok.iter().map(|r| counters(&r.body)))
    {
        for (k, v) in body_counters {
            if finite_keys.contains(&k.as_str()) && v < 0.0 && !pre_neg.contains(&k) {
                neg_hit = Some((k, v));
                break;
            }
        }
        if neg_hit.is_some() {
            break;
        }
    }
    if let Some((k, v)) = neg_hit {
        evaluated = true;
        checks.push(chk(
            "race_condition",
            Verdict::Fail,
            Some(severity_for("race_condition", Technique::Other)),
            format!("TOCTOU underflow: concurrent requests drove '{k}' negative ({v})"),
        ));
    }

    // invariant D: single-use redemption flows must allow at most one concurrent success
    // unless each request demonstrably created a distinct object id.
    let pl = path.to_ascii_lowercase();
    let is_single_use_flow = [
        "/redeem",
        "/coupon",
        "/voucher",
        "/claim",
        "/vote",
        "/checkout",
        "/approve",
    ]
    .iter()
    .any(|kw| pl.contains(kw));
    if !evaluated && is_single_use_flow && distinct_created_ids <= 1 {
        evaluated = true;
        if ok.len() >= 2 {
            checks.push(chk(
                "race_condition",
                Verdict::Fail,
                Some(severity_for("race_condition", Technique::Other)),
                format!(
                    "{} of {} concurrent identical requests succeeded on single-use flow '{path}' without conflict rejection",
                    ok.len(),
                    f.requested
                ),
            ));
        } else {
            checks.push(chk(
                "race_condition",
                Verdict::Pass,
                None,
                format!(
                    "only {} of {} concurrent requests succeeded on '{path}'; duplicates were safely rejected",
                    ok.len(),
                    f.requested
                ),
            ));
        }
    }

    if !evaluated {
        checks.push(chk(
            "race_condition",
            Verdict::Inconclusive,
            None,
            format!(
                "{} of {} concurrent requests answered 2xx, but no invariant could be evaluated (no created ids or counter to compare); concurrent success alone is not evidence of a race",
                ok.len(),
                f.requested
            ),
        ));
    }
    outcome(checks, warnings)
}
