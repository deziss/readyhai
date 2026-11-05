//! Stateful Scenario Chains & TOCTOU Concurrency Burst Engine.
//!
//! Enables multi-step adversarial workflows (e.g. Alice creates private resource -> Bob accesses it: BOLA/IDOR)
//! and rapid parallel concurrency bursts to expose race conditions and TOCTOU vulnerabilities.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::budget::RunBudget;
use super::exec::{Credentials, normalize_method};
use super::types::{StatefulStep, StatefulStepExecution};

const BODY_CAP: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct StatefulScenarioResult {
    pub passed: bool,
    pub violation_triggered: bool,
    pub setup_failed: bool,
    pub steps: Vec<StatefulStepExecution>,
    pub failure_reason: Option<String>,
    pub reproduction_curl: String,
    pub final_status: u16,
    pub total_latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyBurstResult {
    pub status_codes: Vec<u16>,
    pub has_race_condition: bool,
    pub explanation: Option<String>,
}

/// Substitute context variables `{{var}}` and `{{ var }}` in a string.
pub fn substitute_vars(template: &str, context: &HashMap<String, String>) -> String {
    let mut res = template.to_string();
    for (k, v) in context {
        let pattern1 = format!("{{{{{}}}}}", k);
        let pattern2 = format!("{{{{ {} }}}}", k);
        res = res.replace(&pattern1, v).replace(&pattern2, v);
    }
    res
}

/// Recursively extract JSON values into a string map.
pub fn extract_json_values(
    val: &Value,
    wanted: Option<&[String]>,
    out: &mut HashMap<String, String>,
) {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let k_lower = k.to_ascii_lowercase();
                let should_extract = wanted
                    .map_or(false, |w| w.iter().any(|target| target.eq_ignore_ascii_case(k)))
                    || matches!(
                        k_lower.as_str(),
                        "id" | "uuid" | "key" | "token" | "item_id" | "order_id" | "user_id" | "resource_id"
                    );

                if should_extract {
                    let s = match v {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        other => other.to_string(),
                    };
                    out.insert(k.clone(), s);
                }
                extract_json_values(v, wanted, out);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                extract_json_values(item, wanted, out);
            }
        }
        _ => {}
    }
}

/// Resolve bearer token for an actor.
pub fn actor_bearer(actor: &str, creds: &Credentials) -> Option<String> {
    let a = actor.trim().to_ascii_lowercase();
    if matches!(a.as_str(), "anon" | "anonymous" | "none") {
        return None;
    }
    if a == "forged" {
        return Some("Bearer forged.signature.token123".to_string());
    }
    creds.token(&a).map(|t| format!("Bearer {t}"))
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
    if let Some(rest) = part.strip_prefix("status ==") {
        if let Ok(expected) = rest.trim().parse::<u16>() {
            return status == expected;
        }
    }
    if let Some(rest) = part.strip_prefix("status !=") {
        if let Ok(expected) = rest.trim().parse::<u16>() {
            return status != expected;
        }
    }
    if let Some(rest) = part.strip_prefix("status <") {
        if let Ok(threshold) = rest.trim().parse::<u16>() {
            return status < threshold;
        }
    }
    if let Some(rest) = part.strip_prefix("status >=") {
        if let Ok(threshold) = rest.trim().parse::<u16>() {
            return status >= threshold;
        }
    }
    if part == "status in 200..=299" || part == "2xx" {
        return (200..=299).contains(&status);
    }
    false
}

/// Build a single curl command string for reproduction.
fn format_step_curl(
    method: &str,
    url: &str,
    bearer: Option<&str>,
    payload: Option<&str>,
) -> String {
    let mut parts = vec![format!("curl -sS -i -X {method} '{url}'")];
    if let Some(b) = bearer {
        parts.push(format!("-H 'Authorization: {b}'"));
    }
    if let Some(p) = payload {
        let ct = if p.trim_start().starts_with('{') || p.trim_start().starts_with('[') {
            "application/json"
        } else {
            "application/x-www-form-urlencoded"
        };
        parts.push(format!("-H 'Content-Type: {ct}'"));
        parts.push(format!("--data '{}'", p.replace('\'', "'\\''")));
    }
    parts.join(" ")
}

/// Execute a stateful scenario chain step-by-step.
pub fn execute_stateful_scenario(
    client: &reqwest::blocking::Client,
    target: &str,
    steps: &[StatefulStep],
    creds: &Credentials,
    budget: &mut RunBudget,
    host: &str,
) -> StatefulScenarioResult {
    let mut context: HashMap<String, String> = HashMap::new();
    let mut step_records: Vec<StatefulStepExecution> = Vec::with_capacity(steps.len());
    let mut curl_repros: Vec<String> = Vec::new();
    let mut total_latency = 0u64;
    let mut last_status = 0u16;
    let base_target = target.trim_end_matches('/');

    for step in steps {
        if let Err(m) = budget.take_request(host) {
            let reason = format!("Budget exceeded before step {}: {m}", step.step_number);
            return StatefulScenarioResult {
                passed: false,
                violation_triggered: false,
                setup_failed: true,
                steps: step_records,
                failure_reason: Some(reason),
                reproduction_curl: curl_repros.join("\n"),
                final_status: last_status,
                total_latency_ms: total_latency,
            };
        }

        let resolved_path = substitute_vars(&step.path, &context);
        let path_norm = if resolved_path.starts_with('/') {
            resolved_path.clone()
        } else {
            format!("/{resolved_path}")
        };
        let full_url = format!("{base_target}{path_norm}");

        let resolved_payload = step
            .payload
            .as_deref()
            .map(|p| substitute_vars(p, &context));

        let method_str = normalize_method(&step.method).unwrap_or("GET");
        let bearer = actor_bearer(&step.actor, creds);
        let step_curl = format_step_curl(
            method_str,
            &full_url,
            bearer.as_deref(),
            resolved_payload.as_deref(),
        );
        curl_repros.push(step_curl);

        let t0 = Instant::now();
        let method = match reqwest::Method::from_bytes(method_str.as_bytes()) {
            Ok(m) => m,
            Err(e) => {
                let reason = format!("Invalid HTTP method '{}' in step {}: {e}", method_str, step.step_number);
                return StatefulScenarioResult {
                    passed: false,
                    violation_triggered: false,
                    setup_failed: true,
                    steps: step_records,
                    failure_reason: Some(reason),
                    reproduction_curl: curl_repros.join("\n"),
                    final_status: last_status,
                    total_latency_ms: total_latency,
                };
            }
        };

        let mut rb = client.request(method, &full_url);
        if let Some(b) = &bearer {
            rb = rb.header("Authorization", b);
        }
        if let Some(body) = &resolved_payload {
            let ct = if body.trim_start().starts_with('{') || body.trim_start().starts_with('[') {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };
            rb = rb.header("Content-Type", ct).body(body.clone());
        }

        let resp_result = rb.send();
        let step_latency = t0.elapsed().as_millis() as u64;
        total_latency += step_latency;

        let resp = match resp_result {
            Ok(r) => r,
            Err(e) => {
                let reason = format!("Step {} transport error: {e}", step.step_number);
                step_records.push(StatefulStepExecution {
                    step_number: step.step_number,
                    actor: step.actor.clone(),
                    method: method_str.to_string(),
                    resolved_path: path_norm,
                    status_code: 0,
                    latency_ms: step_latency,
                    extracted_values: HashMap::new(),
                    passed: false,
                    violation_triggered: false,
                    error_detail: Some(reason.clone()),
                });
                return StatefulScenarioResult {
                    passed: false,
                    violation_triggered: false,
                    setup_failed: true,
                    steps: step_records,
                    failure_reason: Some(reason),
                    reproduction_curl: curl_repros.join("\n"),
                    final_status: 0,
                    total_latency_ms: total_latency,
                };
            }
        };

        let status = resp.status().as_u16();
        last_status = status;

        let mut body_buf = Vec::new();
        let _ = resp.take(BODY_CAP as u64).read_to_end(&mut body_buf);
        let body_str = String::from_utf8_lossy(&body_buf).into_owned();

        // Extract values from JSON response
        let mut extracted = HashMap::new();
        if let Ok(json_val) = serde_json::from_str::<Value>(&body_str) {
            extract_json_values(&json_val, step.extract_vars.as_deref(), &mut extracted);
            // If explicit wanted vars were requested, ensure any generic "id" is mapped to named keys like "item_id"
            if let Some(wanted) = &step.extract_vars {
                for w in wanted {
                    if !extracted.contains_key(w) {
                        if let Some(id_val) = extracted.get("id").cloned() {
                            if w.ends_with("_id") || w == "id" {
                                extracted.insert(w.clone(), id_val);
                            }
                        }
                    }
                }
            }
        }

        // Merge into scenario context
        for (k, v) in &extracted {
            context.insert(k.clone(), v.clone());
        }

        // Check violation condition
        let mut step_passed = true;
        let mut step_violation = false;
        let mut failure_reason = None;

        if let Some(cond) = &step.violation_condition {
            if evaluate_violation(cond, status, &body_str) {
                step_passed = false;
                step_violation = true;
                failure_reason = Some(format!(
                    "Security violation triggered on step {} (actor '{}', {} {}): condition '{}' met with HTTP {}",
                    step.step_number, step.actor, method_str, path_norm, cond, status
                ));
            }
        }

        if step_passed {
            if let Some(expected) = step.expected_status {
                let matches_expected = if expected == 201 {
                    status == 200 || status == 201
                } else {
                    status == expected
                };

                if !matches_expected {
                    step_passed = false;
                    failure_reason = Some(format!(
                        "Step {} expected status {} but received {}",
                        step.step_number, expected, status
                    ));
                }
            } else if status >= 400 {
                step_passed = false;
                failure_reason = Some(format!(
                    "Step {} failed with HTTP {}",
                    step.step_number, status
                ));
            }
        }

        step_records.push(StatefulStepExecution {
            step_number: step.step_number,
            actor: step.actor.clone(),
            method: method_str.to_string(),
            resolved_path: path_norm.clone(),
            status_code: status,
            latency_ms: step_latency,
            extracted_values: extracted,
            passed: step_passed,
            violation_triggered: step_violation,
            error_detail: failure_reason.clone(),
        });

        if !step_passed {
            let is_setup = step.step_number == 1 && step.violation_condition.is_none();
            let reason_text = if is_setup {
                format!(
                    "Prerequisite setup step 1 not met (actor '{}', {} {}): received HTTP {} ({})",
                    step.actor,
                    method_str,
                    path_norm,
                    status,
                    if status == 401 || status == 403 {
                        "authentication credentials required or denied"
                    } else if status == 404 {
                        "endpoint not found"
                    } else if status == 405 {
                        "method not allowed"
                    } else {
                        "resource setup prerequisite failed"
                    }
                )
            } else {
                failure_reason.unwrap_or_else(|| "Stateful step failed".into())
            };

            return StatefulScenarioResult {
                passed: false,
                violation_triggered: step_violation,
                setup_failed: is_setup,
                steps: step_records,
                failure_reason: Some(reason_text),
                reproduction_curl: curl_repros.join("\n"),
                final_status: last_status,
                total_latency_ms: total_latency,
            };
        }
    }

    StatefulScenarioResult {
        passed: true,
        violation_triggered: false,
        setup_failed: false,
        steps: step_records,
        failure_reason: None,
        reproduction_curl: curl_repros.join("\n"),
        final_status: last_status,
        total_latency_ms: total_latency,
    }
}

/// Fire N concurrent requests in parallel using multithreading to check for TOCTOU / race conditions.
pub fn execute_concurrency_burst(
    client: &reqwest::blocking::Client,
    url: &str,
    method: &str,
    payload: Option<&str>,
    bearer: Option<&str>,
    burst_size: usize,
) -> ConcurrencyBurstResult {
    let count = burst_size.clamp(2, 20);
    let barrier = Arc::new(std::sync::Barrier::new(count));
    let method_upper = method.to_ascii_uppercase();

    let mut results: Vec<Result<u16, String>> = Vec::with_capacity(count);

    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(count);
        for _ in 0..count {
            let b = barrier.clone();
            let c = client;
            let u = url;
            let m = &method_upper;
            let p = payload;
            let auth = bearer;

            handles.push(s.spawn(move || {
                b.wait(); // All threads release simultaneously at the barrier
                let req_method = match reqwest::Method::from_bytes(m.as_bytes()) {
                    Ok(meth) => meth,
                    Err(_) => reqwest::Method::POST,
                };
                let mut req = c.request(req_method, u);
                if let Some(tok) = auth {
                    req = req.header("Authorization", tok);
                }
                if let Some(body) = p {
                    let ct = if body.trim_start().starts_with('{') || body.trim_start().starts_with('[') {
                        "application/json"
                    } else {
                        "application/x-www-form-urlencoded"
                    };
                    req = req.header("Content-Type", ct).body(body.to_string());
                }
                match req.send() {
                    Ok(resp) => Ok(resp.status().as_u16()),
                    Err(e) => Err(e.to_string()),
                }
            }));
        }

        for h in handles {
            results.push(h.join().unwrap_or(Err("thread panicked".to_string())));
        }
    });

    let mut status_codes: Vec<u16> = Vec::new();
    for res in results {
        if let Ok(st) = res {
            status_codes.push(st);
        }
    }

    let has_500 = status_codes.iter().any(|&s| s >= 500);
    let success_count = status_codes.iter().filter(|&&s| s == 200 || s == 201).count();

    if has_500 {
        ConcurrencyBurstResult {
            status_codes,
            has_race_condition: true,
            explanation: Some(
                "Burst triggered HTTP 500 server crash, indicating unhandled deadlock or database race condition."
                    .to_string(),
            ),
        }
    } else if success_count == count && count > 1 && matches!(method_upper.as_str(), "POST" | "DELETE" | "PATCH") {
        ConcurrencyBurstResult {
            status_codes,
            has_race_condition: true,
            explanation: Some(format!(
                "All {count} concurrent mutating requests succeeded (2xx) without mutual exclusion or concurrency collision handling."
            )),
        }
    } else {
        ConcurrencyBurstResult {
            status_codes,
            has_race_condition: false,
            explanation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn test_variable_substitution() {
        let mut ctx = HashMap::new();
        ctx.insert("item_id".into(), "item_987".into());
        ctx.insert("tenant".into(), "acme".into());

        let path = substitute_vars("/api/{{tenant}}/items/{{item_id}}", &ctx);
        assert_eq!(path, "/api/acme/items/item_987");

        let body = substitute_vars("{\"ref\": \"{{ item_id }}\"}", &ctx);
        assert_eq!(body, "{\"ref\": \"item_987\"}");
    }

    #[test]
    fn test_json_value_extraction() {
        let json_str = r#"{
            "status": "success",
            "data": {
                "id": "ord_12345",
                "token": "tok_xyz999",
                "nested": {
                    "uuid": "u-001"
                }
            }
        }"#;
        let v: Value = serde_json::from_str(json_str).unwrap();
        let mut out = HashMap::new();
        extract_json_values(&v, Some(&["token".into(), "id".into()]), &mut out);

        assert_eq!(out.get("id").map(|s| s.as_str()), Some("ord_12345"));
        assert_eq!(out.get("token").map(|s| s.as_str()), Some("tok_xyz999"));
        assert_eq!(out.get("uuid").map(|s| s.as_str()), Some("u-001"));
    }

    #[test]
    fn test_violation_condition_evaluation() {
        assert!(evaluate_violation("status == 200", 200, ""));
        assert!(!evaluate_violation("status == 200", 403, ""));

        assert!(evaluate_violation("status == 200 || status == 204", 204, ""));
        assert!(evaluate_violation("status != 403 && status != 404", 200, ""));
        assert!(!evaluate_violation("status != 403 && status != 404", 403, ""));

        assert!(evaluate_violation("bola", 200, ""));
        assert!(!evaluate_violation("bola", 403, ""));
    }

    #[test]
    fn test_stateful_scenario_execution_mock() {
        // Start a mock server
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");

        std::thread::spawn(move || {
            // First request: POST /items by Alice -> return 201 with id
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let body = "{\"id\": \"item_456\"}";
                let resp = format!(
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }

            // Second request: GET /items/item_456 by Bob -> return 403 Forbidden (BOLA protected)
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let body = "{\"error\": \"Access denied\"}";
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let creds = Credentials::none()
            .with("alice", "test-token-alice")
            .with("bob", "test-token-bob");
        let mut budget = RunBudget::new(10, 50, Duration::from_secs(10), 0.0);

        let steps = vec![
            StatefulStep {
                step_number: 1,
                actor: "alice".into(),
                method: "POST".into(),
                path: "/items".into(),
                payload: Some("{\"title\": \"Secret\"}".into()),
                extract_vars: Some(vec!["id".into()]),
                expected_status: Some(201),
                violation_condition: None,
            },
            StatefulStep {
                step_number: 2,
                actor: "bob".into(),
                method: "GET".into(),
                path: "/items/{{id}}".into(),
                payload: None,
                extract_vars: None,
                expected_status: Some(403),
                violation_condition: Some("status == 200 || status == 204".into()),
            },
        ];

        let result = execute_stateful_scenario(
            &client,
            &base_url,
            &steps,
            &creds,
            &mut budget,
            &format!("127.0.0.1:{port}"),
        );

        assert!(result.passed, "Scenario should pass: Bob got 403 on Alice's item: {:?}", result.failure_reason);
        assert_eq!(result.steps.len(), 2);
        assert_eq!(result.steps[0].status_code, 201);
        assert_eq!(result.steps[0].extracted_values.get("id").map(|s| s.as_str()), Some("item_456"));
        assert_eq!(result.steps[1].resolved_path, "/items/item_456");
        assert_eq!(result.steps[1].status_code, 403);
    }

    #[test]
    fn test_concurrency_burst_execution() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/race");
        let counter = Arc::new(AtomicUsize::new(0));
        let c_clone = counter.clone();

        std::thread::spawn(move || {
            for _ in 0..4 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let count = c_clone.fetch_add(1, Ordering::SeqCst);
                    let status_line = if count == 0 {
                        "HTTP/1.1 200 OK\r\n"
                    } else {
                        "HTTP/1.1 409 Conflict\r\n"
                    };
                    let resp = format!("{status_line}Connection: close\r\nContent-Length: 2\r\n\r\nOK");
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
            }
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();

        let burst = execute_concurrency_burst(&client, &url, "POST", Some("{\"claim\":1}"), None, 4);
        assert_eq!(burst.status_codes.len(), 4);
        assert!(!burst.has_race_condition, "409 correctly handled conflict");
    }
}
