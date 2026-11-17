//! Specialized verification probes: boolean diff, time delay, SSTI, open redirect, OAST, GraphQL introspection, and DOM XSS.

use super::super::triage::severity_for;
use super::super::types::{PlannedCase, ProbeOracle};
use super::signatures::has_dom_xss_sink_flow;
use super::types::{chk, Observation, OracleCheck, Severity, Technique, Verdict};

/// Normalize volatile digits and whitespace so timestamps/request IDs don't masquerade as boolean diffs.
pub(crate) fn normalize_diff_body(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(8192));
    let mut prev_space = false;
    for c in s.chars().take(8192) {
        if c.is_ascii_digit() {
            out.push('0');
            prev_space = false;
        } else if c.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

pub(crate) fn body_meaningfully_differs(
    status_a: u16,
    body_a: &str,
    status_b: u16,
    body_b: &str,
) -> bool {
    if status_a != status_b {
        return true;
    }
    let na = normalize_diff_body(body_a);
    let nb = normalize_diff_body(body_b);
    if na == nb {
        return false;
    }
    let max_len = na.len().max(nb.len());
    let delta = na.len().abs_diff(nb.len());
    if delta >= 24 && (delta * 100) >= max_len.saturating_mul(15) {
        return true;
    }
    let set_a: std::collections::HashSet<&str> = na
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 3)
        .collect();
    let set_b: std::collections::HashSet<&str> = nb
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 3)
        .collect();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        return na != nb;
    }
    let inter = set_a.intersection(&set_b).count();
    (inter * 100) < (union * 80)
}

pub(crate) fn redirect_targets_host(location: &str, canary_host: &str) -> bool {
    let loc = location.trim();
    let needle = canary_host.to_ascii_lowercase();
    // Protocol-relative or backslash-prefixed bypasses (e.g. //canary.invalid or /\canary.invalid)
    let stripped = loc.trim_start_matches('/').trim_start_matches('\\');
    if let Ok(u) = reqwest::Url::parse(loc)
        && let Some(h) = u.host_str()
    {
        let h = h.to_ascii_lowercase();
        return h == needle || h.ends_with(&format!(".{needle}"));
    }
    if (loc.starts_with("//") || loc.starts_with("/\\"))
        && let Some(host_part) = stripped.split(['/', '?', '#']).next()
    {
        let h = host_part
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        return h == needle || h.ends_with(&format!(".{needle}"));
    }
    false
}

pub(crate) fn probe_oracle_checks(
    case: &PlannedCase,
    o: &Observation,
    _tech: Technique,
    checks: &mut Vec<OracleCheck>,
) {
    let Some(oracle_kind) = &case.probe_oracle else {
        return;
    };
    match oracle_kind {
        ProbeOracle::BooleanDiff { .. } => {
            let Some(ev) = o.probe else {
                checks.push(chk(
                    "blind_boolean_injection",
                    Verdict::Inconclusive,
                    None,
                    "boolean differential probe lacked baseline/control responses",
                ));
                return;
            };
            let (Some(base), Some(ctrl)) = (&ev.baseline, &ev.control) else {
                checks.push(chk(
                    "blind_boolean_injection",
                    Verdict::Inconclusive,
                    None,
                    "boolean differential probe lacked baseline or false control",
                ));
                return;
            };
            let true_vs_false =
                body_meaningfully_differs(o.status, o.body, ctrl.status, &ctrl.body);
            let true_matches_base =
                !body_meaningfully_differs(base.status, &base.body, o.status, o.body);
            let true_returns_more = (200..300).contains(&o.status)
                && (o.status != ctrl.status || o.body.len() > ctrl.body.len().saturating_add(20));
            if true_vs_false && (true_matches_base || true_returns_more) {
                checks.push(chk(
                    "blind_boolean_injection",
                    Verdict::Fail,
                    Some(severity_for("blind_boolean_injection", Technique::Injection)),
                    format!(
                        "true predicate (HTTP {}, {}B) diverged meaningfully from false control (HTTP {}, {}B)",
                        o.status,
                        o.body.len(),
                        ctrl.status,
                        ctrl.body.len()
                    ),
                ));
            } else {
                checks.push(chk(
                    "blind_boolean_injection",
                    Verdict::Pass,
                    None,
                    "true and false predicates did not induce a boolean response divergence",
                ));
            }
        }
        ProbeOracle::TimeDelay { min_delay_ms, .. } => {
            let Some(base) = o.probe.and_then(|ev| ev.baseline.as_ref()) else {
                checks.push(chk(
                    "blind_time_injection",
                    Verdict::Inconclusive,
                    None,
                    "time-delay probe lacked baseline latency measurement",
                ));
                return;
            };
            let required_delta = ((*min_delay_ms) * 3) / 4;
            if o.latency_ms >= *min_delay_ms
                && o.latency_ms >= base.latency_ms.saturating_add(required_delta)
            {
                checks.push(chk(
                    "blind_time_injection",
                    Verdict::Fail,
                    Some(severity_for("blind_time_injection", Technique::Injection)),
                    format!(
                        "delayed payload took {}ms vs {}ms baseline (threshold {}ms)",
                        o.latency_ms, base.latency_ms, min_delay_ms
                    ),
                ));
            } else {
                checks.push(chk(
                    "blind_time_injection",
                    Verdict::Pass,
                    None,
                    format!(
                        "response latency ({}ms) remained within baseline ({}ms + <{}ms)",
                        o.latency_ms, base.latency_ms, required_delta
                    ),
                ));
            }
        }
        ProbeOracle::Ssti { expected_eval } => {
            let literal_in_payload = case
                .payload
                .as_deref()
                .is_some_and(|p| p.contains(expected_eval.as_str()));
            let in_baseline = o
                .probe
                .and_then(|ev| ev.baseline.as_ref())
                .is_some_and(|b| b.body.contains(expected_eval.as_str()));
            if !expected_eval.is_empty()
                && !literal_in_payload
                && !in_baseline
                && o.body.contains(expected_eval.as_str())
            {
                checks.push(chk(
                    "ssti",
                    Verdict::Fail,
                    Some(severity_for("ssti", Technique::Injection)),
                    format!(
                        "template expression evaluated server-side (rendered '{}')",
                        expected_eval
                    ),
                ));
            } else {
                checks.push(chk(
                    "ssti",
                    Verdict::Pass,
                    None,
                    "template expression was not evaluated server-side",
                ));
            }
        }
        ProbeOracle::OpenRedirect { canary_host } => {
            let loc = o
                .headers
                .iter()
                .find(|(k, _)| k == "location")
                .map(|(_, v)| v.as_str());
            if (300..=399).contains(&o.status)
                && let Some(loc_val) = loc
                && redirect_targets_host(loc_val, canary_host)
            {
                checks.push(chk(
                    "open_redirect",
                    Verdict::Fail,
                    Some(severity_for("open_redirect", Technique::Negative)),
                    format!(
                        "HTTP {} Location redirects to untrusted host '{canary_host}'",
                        o.status
                    ),
                ));
            } else {
                checks.push(chk(
                    "open_redirect",
                    Verdict::Pass,
                    None,
                    "response does not redirect to attacker-controlled origin",
                ));
            }
        }
        ProbeOracle::OastCallback { .. } => {
            let Some(ev) = o.probe else {
                checks.push(chk(
                    "oast_callback",
                    Verdict::Inconclusive,
                    None,
                    "OAST callback evidence not collected",
                ));
                return;
            };
            if ev.oast_unavailable {
                checks.push(chk(
                    "oast_callback",
                    Verdict::Inconclusive,
                    None,
                    "OAST callback listener unavailable during execution",
                ));
            } else if ev.oast_hit {
                let detail = ev
                    .oast_detail
                    .as_deref()
                    .unwrap_or("callback received on OAST listener");
                checks.push(chk(
                    "oast_callback",
                    Verdict::Fail,
                    Some(severity_for("oast_callback", Technique::Injection)),
                    format!("out-of-band HTTP callback observed: {detail}"),
                ));
            } else {
                checks.push(chk(
                    "oast_callback",
                    Verdict::Pass,
                    None,
                    "no out-of-band callback received",
                ));
            }
        }
        ProbeOracle::ExcessiveDataExposure => {}
        ProbeOracle::GraphqlIntrospection => {
            if !(200..300).contains(&o.status) {
                checks.push(chk(
                    "graphql_introspection",
                    Verdict::Pass,
                    None,
                    format!(
                        "GraphQL introspection did not expose schema (HTTP {})",
                        o.status
                    ),
                ));
                return;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(o.body)
                && v.pointer("/data/__schema/types").is_some()
            {
                checks.push(chk(
                    "graphql_introspection",
                    Verdict::Fail,
                    Some(severity_for("graphql_introspection", Technique::Other)),
                    "GraphQL endpoint returned full __schema.types to introspection query",
                ));
            } else {
                checks.push(chk(
                    "graphql_introspection",
                    Verdict::Pass,
                    None,
                    "GraphQL endpoint did not return __schema.types",
                ));
            }
        }
        ProbeOracle::DomXss { .. } => {
            if let Some(evidence) = has_dom_xss_sink_flow(o.body) {
                checks.push(chk(
                    "dom_xss",
                    Verdict::Fail,
                    Some(Severity::High),
                    format!("untrusted DOM source flows into dangerous sink: {evidence}"),
                ));
            } else {
                checks.push(chk(
                    "dom_xss",
                    Verdict::Pass,
                    None,
                    "no untrusted DOM source-to-sink flow detected in HTML/script response",
                ));
            }
        }
    }
}
