//! Central oracle evaluation engine: dispatches security checks, contract enforcement, and invariants.

use super::super::triage::severity_for;
use super::super::types::PlannedCase;
use super::contract::{
    class_evidence, contract_checks, excessive_data_exposure_check, is_traversal_probe, json_of,
    mass_assignment_reflection, traversal_signature,
};
use super::expectations::{
    derive_expectation, expectation_checks, is_rejection, Expect,
};
use super::access::{cors_check, denied_check, sensitive_checks};
use super::probes::probe_oracle_checks;
use super::signatures::{disclosure_signature, is_sensitive_path};
use super::types::{chk, is_cors_case, Observation, OracleCheck, OracleOutcome, Technique, Verdict};

pub fn judge(case: &PlannedCase, o: &Observation) -> OracleOutcome {
    let tech = Technique::parse(&case.technique);
    let code = o.status;
    let ct = o.content_type.to_ascii_lowercase();
    let html = ct.contains("html");
    let mut checks: Vec<OracleCheck> = vec![];
    let mut warnings: Vec<String> = vec![];
    let exploratory = case.source.as_deref() == Some("llm");

    // 1. a 5xx after any input (negative/injection/boundary especially) is a failure
    if (500..=599).contains(&code) {
        let sev = severity_for("server_error", tech);
        let after = match tech {
            Technique::Injection => "injection-style input",
            Technique::Boundary => "boundary input",
            Technique::Negative => "malformed/negative input",
            _ => "the request",
        };
        checks.push(chk(
            "server_error",
            Verdict::Fail,
            Some(sev),
            format!("server error HTTP {code} after {after}"),
        ));
    } else {
        checks.push(chk(
            "no_server_error",
            Verdict::Pass,
            None,
            format!("HTTP {code}, no server error"),
        ));
    }

    // 2. stack traces / SQL errors / internal paths in any body
    if let Some(sig) = disclosure_signature(o.body) {
        checks.push(chk(
            "error_disclosure",
            Verdict::Fail,
            Some(severity_for("error_disclosure", tech)),
            format!("response discloses {sig}"),
        ));
    }

    // 3. sensitive files: the only question is "is it readable"
    let sensitive = is_sensitive_path(&case.component);
    if sensitive {
        sensitive_checks(case, o, &mut checks);
    }

    // 3b. CORS probe: the answer is the Access-Control-Allow-Origin header, not the status class
    let cors = is_cors_case(case) || o.origin.is_some();
    if cors {
        cors_check(o, &mut checks, &mut warnings);
    }

    // 4. status expectation (expected_status, else expected_behavior)
    if !cors {
        let exp = derive_expectation(case, tech);
        if exp == Expect::Denied && !sensitive {
            denied_check(case, o, tech, &mut checks);
        } else if exp != Expect::Denied {
            expectation_checks(case, o, tech, exp, &mut checks);
        }
    }

    // 5. reflected payloads (HTML only: a JSON/plain response echoing text is not executable)
    let markup_sent = o.sent_values.iter().any(|v| v.contains('<'));
    if (html || ct.is_empty()) && !o.body.is_empty() {
        let reflected = o.sent_values.iter().any(|v| {
            let danger = v.contains('<')
                || v.to_ascii_lowercase().contains("onerror=")
                || v.to_ascii_lowercase().contains("javascript:");
            danger && v.len() >= 5 && o.body.contains(v.as_str())
        });
        if reflected {
            checks.push(chk(
                "injection_reflection",
                Verdict::Fail,
                Some(severity_for("injection_reflection", tech)),
                "injected markup was reflected unescaped in an HTML response",
            ));
        } else if tech == Technique::Injection && markup_sent {
            checks.push(chk(
                "injection_reflection",
                Verdict::Pass,
                None,
                "injected markup was not reflected unescaped",
            ));
        }
    } else if tech == Technique::Injection
        && markup_sent
        && !ct.is_empty()
        && !html
        && (200..=299).contains(&code)
    {
        // class evidence for an XSS probe: a non-HTML body cannot execute markup in a browser
        checks.push(chk(
            "injection_reflection",
            Verdict::Pass,
            None,
            format!(
                "non-HTML response ({}): injected markup cannot execute",
                o.content_type
            ),
        ));
    }
    if let Some(canary) = o
        .sent_values
        .iter()
        .flat_map(|v| v.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')))
        .find(|w| w.starts_with("CANARY_"))
    {
        if o.body.contains(canary) {
            checks.push(chk(
                "injection_reflection",
                Verdict::Fail,
                Some(severity_for("injection_reflection", tech)),
                format!("canary '{canary}' came back in the response"),
            ));
        } else if code < 500 {
            checks.push(chk(
                "injection_reflection",
                Verdict::Pass,
                None,
                format!("canary token '{canary}' was not reflected in the response"),
            ));
        }
    }

    // 5b. path traversal: file content that only a traversal can have produced
    if is_traversal_probe(case, o) {
        if let Some(sig) = traversal_signature(o.body) {
            checks.push(chk(
                "path_traversal",
                Verdict::Fail,
                Some(severity_for("path_traversal", tech)),
                format!("response contains {sig} after a directory-traversal sequence"),
            ));
        } else if is_rejection(code)
            || (case
                .expected_behavior
                .to_ascii_lowercase()
                .contains("sanitized or blocked")
                && (200..=299).contains(&code))
        {
            checks.push(chk(
                "path_traversal",
                Verdict::Pass,
                None,
                "traversal sequences did not disclose system files or cause server errors",
            ));
        }
    }

    // 5bb. SQL / NoSQL / Operator injection probes: verify no database errors or disclosure signatures
    if tech == Technique::Injection {
        let is_db_probe = case.title.to_ascii_lowercase().contains("sql")
            || case.title.to_ascii_lowercase().contains("nosql")
            || case.title.to_ascii_lowercase().contains("injection probe")
            || case
                .expected_behavior
                .to_ascii_lowercase()
                .contains("no sql error")
            || case
                .expected_behavior
                .to_ascii_lowercase()
                .contains("no database or server error");
        if is_db_probe
            && ((200..=299).contains(&code) || is_rejection(code))
            && code < 500
            && disclosure_signature(o.body).is_none()
        {
            checks.push(chk(
                "injection_sanitized",
                Verdict::Pass,
                None,
                "injected operators and payloads were sanitized without database error or server crash",
            ));
        }
    }

    // 5c. mass assignment: a privileged attribute we injected is echoed back
    if let Some(detail) = mass_assignment_reflection(o) {
        checks.push(chk(
            "mass_assignment",
            Verdict::Fail,
            Some(severity_for("mass_assignment", tech)),
            detail,
        ));
    }

    // 6. contract: what the spec documents about the response (statuses, 2xx body schema, latency)
    //    when the plan carries it; otherwise just the field names the spec marks required
    let schema_judged = case
        .contract
        .as_ref()
        .is_some_and(|c| contract_checks(c, o, tech, &mut checks, &mut warnings));
    if !schema_judged && !case.expect_fields.is_empty() && (200..=299).contains(&code) {
        match json_of(o.body) {
            None => checks.push(chk(
                "contract_fields",
                Verdict::Inconclusive,
                None,
                "response is not JSON; required fields could not be checked",
            )),
            Some(v) => {
                let obj = match &v {
                    serde_json::Value::Array(a) => a.first().cloned(),
                    other => Some(other.clone()),
                };
                match obj {
                    Some(serde_json::Value::Object(m)) => {
                        let missing: Vec<&str> = case
                            .expect_fields
                            .iter()
                            .filter(|f| !m.contains_key(f.as_str()))
                            .map(|s| s.as_str())
                            .collect();
                        if missing.is_empty() {
                            checks.push(chk(
                                "contract_fields",
                                Verdict::Pass,
                                None,
                                "all required response fields present",
                            ));
                        } else {
                            checks.push(chk(
                                "contract_fields",
                                Verdict::Fail,
                                Some(severity_for("contract_fields", tech)),
                                format!(
                                    "required response field(s) missing: {}",
                                    missing.join(", ")
                                ),
                            ));
                        }
                    }
                    _ => checks.push(chk(
                        "contract_fields",
                        Verdict::Inconclusive,
                        None,
                        "no object in the response to check required fields against",
                    )),
                }
            }
        }
    }
    if let Some(want) = case
        .expected_content_type
        .as_deref()
        .filter(|w| !w.is_empty())
        && (200..=299).contains(&code)
    {
        if ct.contains(&want.to_ascii_lowercase()) {
            checks.push(chk(
                "content_type",
                Verdict::Pass,
                None,
                format!("content-type contains {want}"),
            ));
        } else {
            checks.push(chk(
                "content_type",
                Verdict::Fail,
                Some(severity_for("content_type", tech)),
                format!("expected content-type {want}, got '{}'", o.content_type),
            ));
        }
    }

    // 7. session cookie hygiene is advisory (case becomes WARN, not FAIL)
    if tech == Technique::StateTransition {
        for (k, v) in o.headers.iter().filter(|(k, _)| k == "set-cookie") {
            let _ = k;
            let name = v.split('=').next().unwrap_or("").trim().to_string();
            let ln = name.to_ascii_lowercase();
            if ["sess", "sid", "auth", "token", "jwt", "login"]
                .iter()
                .any(|s| ln.contains(s))
            {
                let low = v.to_ascii_lowercase();
                if !low.contains("httponly") {
                    warnings.push(format!("session cookie '{name}' is missing HttpOnly"));
                }
                if o.https && !low.contains("secure") {
                    warnings.push(format!(
                        "session cookie '{name}' is missing Secure over HTTPS"
                    ));
                }
            }
        }
    }

    // 7b. Specialized verification oracles (BooleanDiff, TimeDelay, SSTI, OpenRedirect, OAST)
    probe_oracle_checks(case, o, tech, &mut checks);

    // 7c. Excessive Data Exposure (unmasked secret/hash/PII keys in 2xx JSON responses)
    excessive_data_exposure_check(case, o, &mut checks);

    // 8. an LLM-proposed case brings its own expectation. That is a hypothesis, not evidence:
    //    only deterministic invariant checks (5xx, disclosure, reflection, traversal, mass
    //    assignment, CORS, authz on a route discovery/spec says is protected) may fail it.
    if exploratory {
        for c in checks.iter_mut() {
            if c.verdict == Verdict::Fail
                && matches!(
                    c.code.as_str(),
                    "expected_status" | "expected_redirect" | "content_type"
                )
            {
                c.verdict = Verdict::Inconclusive;
                c.severity = None;
                c.detail = format!(
                    "exploratory case: the LLM-proposed expectation is unconfirmed, no deterministic invariant was violated ({})",
                    c.detail
                );
            }
        }
    }

    // 9. verdict
    let has_fail = checks.iter().any(|c| c.verdict == Verdict::Fail);
    let decisive = checks.iter().any(|c| {
        matches!(
            c.code.as_str(),
            "expected_status"
                | "expected_redirect"
                | "authz"
                | "sensitive_exposure"
                | "injection_reflection"
                | "path_traversal"
                | "contract_fields"
                | "content_type"
                | "cors"
                | "blind_boolean_injection"
                | "blind_time_injection"
                | "ssti"
                | "open_redirect"
                | "oast_callback"
                | "excessive_data_exposure"
                | "injection_sanitized"
                | "boundary_tolerance"
        )
    });
    let robustness = matches!(
        tech,
        Technique::Boundary | Technique::Negative | Technique::Injection
    );
    if !has_fail && !decisive {
        if robustness {
            class_evidence(case, o, tech, &mut checks);
        } else {
            checks.push(chk(
                "no_assertion",
                Verdict::Inconclusive,
                None,
                "no machine-checkable expectation for this case (expected_status/expected_behavior)",
            ));
        }
    }
    let verdict = if checks.iter().any(|c| c.verdict == Verdict::Fail) {
        Verdict::Fail
    } else if checks.iter().any(|c| c.verdict == Verdict::Inconclusive) {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    };
    OracleOutcome {
        verdict,
        checks,
        warnings,
        exploratory,
    }
}
