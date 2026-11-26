//! Bounded multi-turn ReAct Lead Loop (Phase 4).
//!
//! After Wave 1 + deterministic Wave 2 finish, summarizes high-signal redacted anomalies
//! (5xx stack traces, reflected parameters, created tokens/records, path hints) across waves,
//! synthesizes adaptive follow-up hypotheses via the LLM (validated strictly through `plan::validate_raw`)
//! with an offline deterministic rule fallback, executes within spare budget while reserving capacity
//! for `verify` + cleanup, and stops early when no new anomalies emerge.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Duration;

use super::budget::{RunBudget, SliceLimits};
use super::discover::Discovery;
use super::exec::{Credentials, ExecOptions, execute_cases_with};
use super::lead::Area;
use super::oracle::Verdict;
use super::plan::{Depth, Known, RawCase, key_of, validate_raw};
use super::triage::path_of;
use super::types::{CaseExecutionResult, CreatedLedger, PlannedCase, ProbeOracle};
use crate::llm::{Budget, LlmConfig, untrusted};

pub const MAX_REACT_WAVES: usize = 2;
pub const MAX_REACT_CASES_PER_WAVE: usize = 6;

#[derive(Debug, Clone, Default)]
pub struct ReactOutcome {
    pub added_cases: Vec<PlannedCase>,
    pub added_results: Vec<CaseExecutionResult>,
    pub waves_run: usize,
    pub llm_used: bool,
    pub notes: Vec<String>,
}

/// Anomaly signature detected by the OODA loop observer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OodaAnomaly {
    pub anomaly_type: String,
    pub dedup_key: String,
    pub component: String,
    pub method: String,
    pub status_code: Option<u16>,
    pub signals: Vec<String>,
    pub request_payload: Option<String>,
    pub evidence: String,
    pub body_excerpt: String,
    pub hinted_params: Vec<String>,
    pub hinted_routes: Vec<String>,
    pub reflection_signature: Option<String>,
}

pub type Anomaly = OodaAnomaly;

fn body_excerpt(r: &CaseExecutionResult) -> &str {
    if let Some(b) = r.response_body.as_deref() {
        return b;
    }
    r.evidence_detail
        .as_ref()
        .and_then(|d| d.get("response"))
        .and_then(|resp| resp.get("body_excerpt"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn has_fail_check(r: &CaseExecutionResult, codes: &[&str]) -> bool {
    r.oracle.as_ref().is_some_and(|o| {
        o.checks
            .iter()
            .any(|c| c.verdict == Verdict::Fail && codes.iter().any(|want| c.code == *want))
    })
}

/// OODA Loop Observer & Orienter: scans execution results for anomalies and categorizes signatures:
/// - `sql_leak`: 500 stack traces, SQL syntax errors, database driver exceptions leaking source/queries
/// - `authz_leak`: 403 authorization leaks, revealed roles/tenants, newly minted auth tokens
/// - `schema_leak`: 422/400 validation leaks, exposed schema constraints, parameter types
/// - `ssti_reflection`: template engine error disclosures, evaluated math expressions (`105623`)
/// - `canary_reflection`: reflected user inputs, canary tokens in response body
pub fn detect_ooda_anomaly(r: &CaseExecutionResult) -> Option<OodaAnomaly> {
    if matches!(r.status.as_str(), "SKIPPED" | "NOT_APPLICABLE") {
        return None;
    }

    let status = r.response_status.or(r.status_code);
    let body = r
        .response_body
        .as_deref()
        .unwrap_or_else(|| body_excerpt(r));
    let low_body = body.to_ascii_lowercase();
    let low_ev = r.evidence.to_ascii_lowercase();
    let low_fail = r
        .failure_reason
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();

    let is_500 = status.is_some_and(|s| s >= 500);
    let is_403 = status.is_some_and(|s| s == 403);
    let is_422 = status.is_some_and(|s| s == 422 || s == 400);

    // Canary reflection detection
    let has_canary_oracle = has_fail_check(r, &["injection_reflection", "canary_reflection"]);
    let has_canary_kw = low_ev.contains("canary")
        || low_body.contains("canary")
        || low_body.contains("rh-canary")
        || low_ev.contains("reflected_input")
        || low_ev.contains("reflection");
    let reflects_payload = r.request_payload.as_deref().is_some_and(|p| {
        let t = p.trim();
        !t.is_empty()
            && (t.to_ascii_lowercase().contains("canary")
                || t.contains("<script")
                || (t.len() >= 4 && !t.starts_with('{') && body.contains(t)))
    });
    let is_canary = has_canary_oracle || (r.status == "FAIL" && has_canary_kw) || reflects_payload;

    // SSTI reflection detection
    let has_ssti_oracle = has_fail_check(r, &["ssti"]);
    let ssti_indicators = [
        "templatesyntaxerror",
        "template",
        "jinja",
        "freemarker",
        "twig",
        "velocity",
        "mako",
        "render(",
        "105623",
        "{{1337*79}}",
        "${1337*79}",
    ];
    let has_ssti_kw = low_fail.contains("ssti")
        || low_ev.contains("ssti")
        || ssti_indicators.iter().any(|ind| low_body.contains(ind));
    let is_ssti = has_ssti_oracle
        || ((is_500 || r.status == "FAIL") && has_ssti_kw)
        || low_body.contains("105623");

    // SQL leak detection
    let has_sql_oracle = has_fail_check(r, &["sqli", "sql_injection"]);
    let sql_indicators = [
        "syntaxerror",
        "unterminated quoted string",
        "quoted string at or near",
        "at or near '",
        "sql syntax",
        "mysql",
        "postgresql",
        "postgres",
        "sqlite",
        "sqlite3",
        "ora-",
        "psycopg2",
        "sequelize",
        "hibernate",
        "database error",
        "sql error",
        "unclosed quotation mark",
        "column does not exist",
        "table does not exist",
        "relation does not exist",
        "sqlstate",
        "pg::",
    ];
    let has_sql_kw = low_ev.contains("sql")
        || low_fail.contains("sql")
        || sql_indicators
            .iter()
            .any(|ind| low_body.contains(ind) || low_ev.contains(ind) || low_fail.contains(ind));
    let is_sql = has_sql_oracle || ((is_500 || r.status == "FAIL") && has_sql_kw);

    // AuthZ leak detection (403 authorization leak or created auth tokens)
    let has_auth_oracle = has_fail_check(r, &["authz", "broken_auth"]);
    let auth_indicators = [
        "role",
        "permission",
        "unauthorized",
        "forbidden",
        "scope",
        "tenant",
        "claim",
        "policy",
        "jwt",
        "rbac",
        "missing authority",
        "access denied",
        "principal",
    ];
    let has_auth_kw = auth_indicators
        .iter()
        .any(|ind| low_body.contains(ind) || low_ev.contains(ind) || low_fail.contains(ind));
    let is_auth_token_created = status.is_some_and(|s| matches!(s, 200 | 201))
        && matches!(r.method.as_str(), "POST" | "PUT" | "PATCH")
        && !r.is_spa_shell
        && r.technique != "boundary"
        && r.technique != "negative"
        && (low_body.contains("\"token\"")
            || low_body.contains("\"access_token\"")
            || low_body.contains("\"jwt\"")
            || low_body.contains("\"role\""));
    let is_auth = (is_403 && (has_auth_kw || !body.trim().is_empty()))
        || has_auth_oracle
        || is_auth_token_created;

    // Schema leak detection (422/400 validation leaks)
    let schema_indicators = [
        "validation",
        "schema",
        "missing required",
        "value_error",
        "pydantic",
        "fastapi",
        "field required",
        "unprocessable",
        "constraint",
        "expected type",
        "invalid parameter",
        "loc",
    ];
    let has_schema_kw = schema_indicators
        .iter()
        .any(|ind| low_body.contains(ind) || low_ev.contains(ind) || low_fail.contains(ind));
    let is_schema = is_422 && (has_schema_kw || !body.trim().is_empty());

    // 500 stack trace indicators
    let stack_trace_indicators = [
        "traceback",
        "stacktrace",
        "nullpointer",
        "internalservererror",
        "internal server error",
        "exception",
        "at line",
        "fatal error",
        "panic at",
        "debug_backtrace",
        "server_error",
        "typeerror",
        "indexerror",
    ];
    let has_stack_trace = is_500
        || ((is_500 || r.status == "FAIL")
            && stack_trace_indicators.iter().any(|ind| {
                low_body.contains(ind) || low_ev.contains(ind) || low_fail.contains(ind)
            }));

    let has_oracle_fail = has_fail_check(
        r,
        &[
            "error_disclosure",
            "stack_trace",
            "server_error",
            "injection_reflection",
            "blind_boolean_injection",
            "blind_time_injection",
            "ssrf_oast",
            "ssti",
        ],
    );

    if !is_canary
        && !is_ssti
        && !is_sql
        && !is_auth
        && !is_schema
        && !has_stack_trace
        && !has_oracle_fail
    {
        return None;
    }

    // Orient: Categorize anomaly signatures into canonical taxonomy
    let anomaly_type = if is_ssti {
        "ssti_reflection"
    } else if is_sql {
        "sql_leak"
    } else if is_canary {
        "canary_reflection"
    } else if is_403 || (is_auth && !is_500) {
        "authz_leak"
    } else if is_422 || (is_schema && !is_500) {
        "schema_leak"
    } else if has_stack_trace || is_500 {
        "sql_leak"
    } else if is_auth {
        "authz_leak"
    } else if is_schema {
        "schema_leak"
    } else {
        "sql_leak"
    };

    let mut signals = Vec::new();
    signals.push(anomaly_type.to_string());
    if is_500 {
        signals.push("http_5xx".to_string());
    }
    if is_403 {
        signals.push("authz_leak".to_string());
    }
    if is_422 {
        signals.push("schema_leak".to_string());
    }
    if is_canary {
        signals.push("reflected_input".to_string());
    }
    if is_auth_token_created {
        signals.push("created_auth_token".to_string());
    }
    if has_fail_check(
        r,
        &[
            "blind_boolean_injection",
            "blind_time_injection",
            "ssrf_oast",
            "ssti",
        ],
    ) {
        signals.push("oob_or_timing_signal".to_string());
    }

    let norm_path = path_of(&r.component);
    let dedup_key = format!(
        "{}:{}:{}:{}",
        anomaly_type,
        r.method,
        norm_path,
        signals.join(",")
    );
    let hinted_params = extract_hinted_params(body, r.request_payload.as_deref());
    let hinted_routes = extract_hinted_routes(body, &r.component);

    let reflection_sig = if is_canary {
        r.request_payload.clone().or_else(|| Some("canary".into()))
    } else {
        None
    };

    Some(OodaAnomaly {
        anomaly_type: anomaly_type.to_string(),
        dedup_key,
        component: r.component.clone(),
        method: r.method.clone(),
        status_code: status,
        signals,
        request_payload: r.request_payload.clone(),
        evidence: if r.evidence.is_empty() {
            body_excerpt(r).to_string()
        } else {
            r.evidence.clone()
        },
        body_excerpt: untrusted::redact_then_truncate(body, 280),
        hinted_params,
        hinted_routes,
        reflection_signature: reflection_sig,
    })
}

/// Anomaly candidate predicate maintaining backwards compatibility with lead loops.
pub fn is_anomaly_candidate(r: &CaseExecutionResult) -> bool {
    detect_ooda_anomaly(r).is_some()
}

/// OODA Loop Decider: synthesizes a precision mutation probe targeting the observed anomaly signature.
pub fn synthesize_mutation_probe(anomaly: &OodaAnomaly, target: &str) -> PlannedCase {
    let component = if !anomaly.component.trim().is_empty() {
        path_of(&anomaly.component).to_string()
    } else if let Ok(u) = reqwest::Url::parse(target) {
        let p = u.path();
        if p.is_empty() || p == "/" {
            "/".to_string()
        } else {
            p.to_string()
        }
    } else if target.starts_with('/') {
        target.to_string()
    } else {
        path_of(target).to_string()
    };

    let method = if matches!(anomaly.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        anomaly.method.clone()
    } else {
        "GET".to_string()
    };

    let mut headers = Vec::new();
    let mut content_type = None;
    let mut probe_oracle = None;
    let mut expected_status = None;
    let mut risk_level = "high".to_string();
    let role = Some("anon".to_string());
    let mut secured = None;

    let (technique, title, input_hint, payload, expected_behavior) = match anomaly
        .anomaly_type
        .as_str()
    {
        "authz_leak" => {
            secured = Some(true);
            expected_status = Some(403);
            risk_level = "critical".into();
            headers = vec![
                ("X-Role".into(), "admin".into()),
                ("X-Tenant-Id".into(), "tenant-001".into()),
            ];
            content_type = Some("application/json".into());
            (
                "authz".to_string(),
                format!("OODA AuthZ privilege escalation mutation probe on {method} {component}"),
                format!(
                    "Precision mutation derived from 403 authorization leak anomaly: {}",
                    anomaly.signals.join(", ")
                ),
                Some(json!({"role": "admin", "tenant_id": "tenant-001"}).to_string()),
                "Server must reject unauthorized role tampering and enforce tenant isolation"
                    .to_string(),
            )
        }
        "schema_leak" => {
            let param = anomaly
                .hinted_params
                .first()
                .map(String::as_str)
                .unwrap_or("id");
            expected_status = Some(400);
            risk_level = "medium".into();
            content_type = Some("application/json".into());
            let p = if method == "GET" {
                format!("{param}=1000000")
            } else {
                json!({ param: 1000000 }).to_string()
            };
            (
                "boundary".to_string(),
                format!(
                    "OODA Schema boundary mutation probe on {method} {component} via `{param}`"
                ),
                format!(
                    "Precision mutation derived from 422/400 schema leak anomaly via parameter `{param}`"
                ),
                Some(p),
                "Server must gracefully reject or validate out-of-bound parameter".to_string(),
            )
        }
        "ssti_reflection" => {
            let param = anomaly
                .hinted_params
                .first()
                .map(String::as_str)
                .unwrap_or("q");
            probe_oracle = Some(ProbeOracle::Ssti {
                expected_eval: "105623".into(),
            });
            let p = if method == "GET" {
                format!("{param}={{{{1337*79}}}}")
            } else {
                json!({ param: "{{1337*79}}" }).to_string()
            };
            (
                "injection".to_string(),
                format!("OODA SSTI mutation probe on {method} {component} via `{param}`"),
                format!(
                    "Precision mutation derived from template rendering anomaly via param `{param}`"
                ),
                Some(p),
                "Server must not evaluate template syntax in user input".to_string(),
            )
        }
        "canary_reflection" => {
            let param = anomaly
                .hinted_params
                .first()
                .map(String::as_str)
                .unwrap_or("q");
            let canary = anomaly
                .reflection_signature
                .as_deref()
                .unwrap_or("<rh-canary-01>");
            let p = if method == "GET" {
                format!("{param}={canary}")
            } else {
                json!({ param: canary }).to_string()
            };
            (
                "injection".to_string(),
                format!("OODA Canary reflection XSS probe on {method} {component} via `{param}`"),
                format!(
                    "Precision mutation derived from canary string reflection anomaly via `{param}`"
                ),
                Some(p),
                "Input must be sanitized and HTML-encoded before reflection".to_string(),
            )
        }
        _ => {
            // "sql_leak" and default database/server errors
            let param = anomaly
                .hinted_params
                .first()
                .map(String::as_str)
                .unwrap_or("q");
            expected_status = Some(400);
            let p = if method == "GET" {
                format!("{param}=' OR '1'='1--")
            } else {
                content_type = Some("application/json".into());
                json!({ param: "' OR '1'='1--" }).to_string()
            };
            (
                "injection".to_string(),
                format!("OODA SQL injection mutation probe on {method} {component} via `{param}`"),
                format!(
                    "Precision mutation derived from SQL error leak: {}",
                    anomaly.body_excerpt
                ),
                Some(p),
                "Database query must be parameterized and not disclose syntax errors".to_string(),
            )
        }
    };

    let mut probe = PlannedCase {
        id: String::new(),
        title,
        component,
        method,
        technique,
        input_hint,
        payload,
        headers,
        content_type,
        probe_oracle,
        expected_behavior,
        expected_status,
        risk_level,
        role,
        secured,
        route_status: anomaly.status_code,
        expect_fields: Vec::new(),
        expected_content_type: None,
        source: Some("ooda".into()),
        stateful_steps: None,
        concurrency_burst: None,
        contract: None,
        changed_ops: Vec::new(),
        area: String::new(),
        regression_of: Vec::new(),
        history_priority: false,
        intel_note: String::new(),
    };
    probe.area = Area::classify(&probe).as_str().to_string();
    probe
}

/// Oscillation Damper preventing runaway cycles and redundant probe generation in the OODA loop.
#[derive(Debug, Clone)]
pub struct OscillationDamper {
    seen_signatures: HashSet<String>,
    adaptive_counts: HashMap<String, usize>,
    max_adaptive_per_endpoint: usize,
}

impl Default for OscillationDamper {
    fn default() -> Self {
        Self::new(3)
    }
}

impl OscillationDamper {
    pub fn new(max_adaptive_per_endpoint: usize) -> Self {
        Self {
            seen_signatures: HashSet::new(),
            adaptive_counts: HashMap::new(),
            max_adaptive_per_endpoint,
        }
    }

    /// Seeds baseline/historical cases so adaptive waves do not duplicate their payloads.
    pub fn seed_seen(&mut self, case: &PlannedCase) {
        let norm_path = path_of(&case.component).to_string();
        let payload_str = case.payload.as_deref().unwrap_or("");
        let sig = format!("{}:{}:{}", case.method, norm_path, payload_str);
        self.seen_signatures.insert(sig);
    }

    /// Checks if a proposed case oscillates (duplicates an earlier probe or exceeds endpoint cap).
    /// Returns true if the probe should be damped (suppressed).
    pub fn should_damp(&mut self, case: &PlannedCase) -> bool {
        let norm_path = path_of(&case.component).to_string();
        let payload_str = case.payload.as_deref().unwrap_or("");
        let sig = format!("{}:{}:{}", case.method, norm_path, payload_str);

        if !self.seen_signatures.insert(sig) {
            return true; // Suppress duplicate payload
        }

        let count = self.adaptive_counts.entry(norm_path).or_insert(0);
        *count += 1;
        if *count > self.max_adaptive_per_endpoint {
            return true; // Exceeded per-endpoint probe limit
        }

        false
    }

    pub fn tracked_count(&self) -> usize {
        self.seen_signatures.len()
    }
}

fn param_hint_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:render|eval|compile|param(?:eter)?|field|key)\s*(?:\(|:|is|=)?\s*['"`]?([a-zA-Z_][a-zA-Z0-9_]{0,24})"#)
            .expect("valid param regex")
    })
}

fn route_hint_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(/(?:api|admin|internal|v[12]|graphql)[a-zA-Z0-9_./-]*)"#)
            .expect("valid route regex")
    })
}

fn extract_payload_keys(payload: Option<&str>) -> Vec<String> {
    let mut keys = Vec::new();
    let Some(p) = payload.map(str::trim).filter(|s| !s.is_empty()) else {
        return keys;
    };
    if p.starts_with('{')
        && let Ok(Value::Object(map)) = serde_json::from_str::<Value>(p)
    {
        for k in map.keys() {
            if !k.trim().is_empty() && !keys.contains(k) {
                keys.push(k.clone());
            }
        }
        return keys;
    }
    for pair in p.split('&') {
        if let Some((k, _)) = pair.split_once('=') {
            let clean = k.trim().to_string();
            if !clean.is_empty() && !keys.contains(&clean) {
                keys.push(clean);
            }
        }
    }
    keys
}

fn extract_hinted_params(body: &str, req_payload: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let low = body.to_ascii_lowercase();
    let interesting = low.contains("traceback")
        || low.contains("template")
        || low.contains("syntaxerror")
        || low.contains("param")
        || low.contains("render(")
        || low.contains("keyerror")
        || low.contains("missing")
        || low.contains("ssti");
    if interesting {
        for cap in param_hint_re().captures_iter(body) {
            if let Some(m) = cap.get(1) {
                let name = m.as_str().trim();
                let nl = name.to_ascii_lowercase();
                if !matches!(
                    nl.as_str(),
                    "none" | "null" | "true" | "false" | "error" | "string" | "int" | "for" | "in"
                ) && !out.iter().any(|x| x == name)
                {
                    out.push(name.to_string());
                }
            }
        }
        for common in [
            "tpl", "template", "q", "query", "cmd", "url", "file", "name",
        ] {
            if (low.contains(&format!("{common} param")) || low.contains(&format!("'{common}'")))
                && !out.iter().any(|x| x == common)
            {
                out.push(common.to_string());
            }
        }
    }
    for k in extract_payload_keys(req_payload) {
        if !out.contains(&k) {
            out.push(k);
        }
    }
    if let Ok(val) = serde_json::from_str::<Value>(body)
        && let Some(detail) = val.get("detail").and_then(|d| d.as_array())
    {
        for err in detail {
            if let Some(loc) = err.get("loc").and_then(|l| l.as_array()) {
                for part in loc {
                    if let Some(s) = part.as_str()
                        && !matches!(s, "body" | "query" | "header" | "path")
                        && !out.contains(&s.to_string())
                    {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

fn extract_hinted_routes(body: &str, current_component: &str) -> Vec<String> {
    let mut out = Vec::new();
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed.starts_with("<!") || trimmed.starts_with("<html") {
        return out;
    }
    let cur_path = path_of(current_component);
    for cap in route_hint_re().captures_iter(trimmed) {
        if let Some(m) = cap.get(1) {
            let candidate = m
                .as_str()
                .trim_end_matches(['.', ',', ';', ')', ']', '"', '\'']);
            if candidate != cur_path && candidate.len() > 2 && !out.iter().any(|x| x == candidate) {
                out.push(candidate.to_string());
            }
        }
    }
    out
}

fn extract_anomalies(
    results: &[CaseExecutionResult],
    existing_ssti_paths: &HashSet<String>,
    seen_anomalies: &HashSet<String>,
) -> Vec<OodaAnomaly> {
    let mut out = Vec::new();
    let mut seen_this_wave = HashSet::new();

    for r in results {
        let Some(anomaly) = detect_ooda_anomaly(r) else {
            continue;
        };

        let norm_path = path_of(&r.component);
        if anomaly.anomaly_type == "ssti_reflection" && existing_ssti_paths.contains(norm_path) {
            continue;
        }

        if seen_anomalies.contains(&anomaly.dedup_key)
            || !seen_this_wave.insert(anomaly.dedup_key.clone())
        {
            continue;
        }

        out.push(anomaly);
    }
    out
}

fn enrich_react_oracle(c: &mut PlannedCase) {
    if c.probe_oracle.is_some() {
        return;
    }
    let payload = c.payload.as_deref().unwrap_or("");
    if payload.contains("{{1337*79}}")
        || payload.contains("${1337*79}")
        || payload.contains("<%= 1337*79 %>")
    {
        c.probe_oracle = Some(ProbeOracle::Ssti {
            expected_eval: "105623".into(),
        });
    } else if payload.contains("{{OAST_URL}}") {
        c.probe_oracle = Some(ProbeOracle::OastCallback {
            placeholder: "{{OAST_URL}}".into(),
            wait_ms: 800,
        });
    } else if payload.contains("evil.invalid") {
        c.probe_oracle = Some(ProbeOracle::OpenRedirect {
            canary_host: "evil.invalid".into(),
        });
    }
}

fn propose_via_llm(
    cfg: &LlmConfig,
    llm_budget: &mut Budget,
    wave: usize,
    anomalies: &[OodaAnomaly],
    disc: &Discovery,
    creds: &Credentials,
    seen_keys: &mut HashSet<String>,
    next_id: &mut usize,
    cap: usize,
    notes: &mut Vec<String>,
) -> Option<Vec<PlannedCase>> {
    let known = Known::new(&disc.routes);
    let routes_summary: Vec<Value> = disc
        .routes
        .iter()
        .filter(|r| !r.catch_all && !r.is_spa_shell)
        .take(30)
        .map(|r| {
            json!({
                "path": r.path,
                "method": r.method,
                "status_code": r.status_code,
                "is_api": r.is_api,
                "auth_wall": r.auth_wall,
                "input_surface": format!("{:?}", r.input_surface),
            })
        })
        .collect();
    let anomaly_summary: Vec<Value> = anomalies
        .iter()
        .take(10)
        .map(|a| {
            json!({
                "anomaly_type": a.anomaly_type,
                "method": a.method,
                "component": a.component,
                "status_code": a.status_code,
                "signals": a.signals,
                "request_payload": a.request_payload,
                "hinted_params": a.hinted_params,
                "hinted_routes": a.hinted_routes,
                "body_excerpt": a.body_excerpt,
            })
        })
        .collect();

    let system = crate::agent::prompts::build_adaptive_mutator_system_prompt();
    let user_prompt = crate::agent::prompts::build_adaptive_mutator_user_prompt(
        wave,
        &routes_summary,
        &anomaly_summary,
        None,
        cap,
    );
    let prompt = if user_prompt.contains("<data>") {
        user_prompt
    } else {
        format!("<data>\n{user_prompt}\n</data>")
    };

    #[derive(Debug, Deserialize)]
    struct AdaptiveMutatorOutput {
        #[serde(default)]
        hypothesis: Option<String>,
        #[serde(default)]
        cases: Vec<RawCase>,
    }

    let res =
        crate::llm::ask_typed::<AdaptiveMutatorOutput>(cfg, llm_budget, &system, &prompt, |p| {
            if p.cases.len() > MAX_REACT_CASES_PER_WAVE * 2 {
                anyhow::bail!("too many cases returned by ReAct planner");
            }
            Ok(())
        });

    match res {
        Ok(out) => {
            if let Some(hypo) = out.hypothesis {
                notes.push(format!("react wave {wave}: OODA LLM hypothesis: {hypo}"));
            }
            if out.cases.is_empty() {
                return Some(Vec::new());
            }
            let mut valid = Vec::new();
            for raw in out.cases {
                if valid.len() >= cap {
                    break;
                }
                match validate_raw(&raw, &known, creds) {
                    Ok(mut c) => {
                        c.source = Some("llm".into());
                        enrich_react_oracle(&mut c);
                        let key = key_of(&c);
                        if !seen_keys.insert(key) {
                            continue;
                        }
                        *next_id += 1;
                        c.id = format!("R{:03}", *next_id);
                        c.area = Area::classify(&c).as_str().to_string();
                        valid.push(c);
                    }
                    Err(e) => {
                        notes.push(format!("react wave {wave}: rejected LLM proposal: {e}"));
                    }
                }
            }
            if valid.is_empty() { None } else { Some(valid) }
        }
        Err(e) => {
            notes.push(format!(
                "react wave {wave}: LLM adaptive proposal failed ({e}); using deterministic fallback"
            ));
            None
        }
    }
}

fn synthesize_offline_followups(
    anomalies: &[OodaAnomaly],
    disc: &Discovery,
    creds: &Credentials,
    seen_keys: &mut HashSet<String>,
    existing_ssti_paths: &mut HashSet<String>,
    next_id: &mut usize,
    cap: usize,
) -> Vec<PlannedCase> {
    let mut out = Vec::new();
    let actor = creds.actor();
    let known_paths: BTreeSet<String> = disc
        .routes
        .iter()
        .filter(|r| !r.catch_all)
        .map(|r| path_of(&r.path).to_string())
        .collect();

    for a in anomalies {
        if out.len() >= cap {
            break;
        }
        let norm_path = path_of(&a.component);
        if !known_paths.contains(norm_path) {
            continue;
        }
        if a.anomaly_type == "ssti_reflection" && existing_ssti_paths.contains(norm_path) {
            continue;
        }

        let mut probe = synthesize_mutation_probe(a, norm_path);
        if let Some(act) = &actor {
            probe.role = Some(act.clone());
        }

        let key = key_of(&probe);
        if seen_keys.insert(key) {
            *next_id += 1;
            probe.id = format!("R{:03}", *next_id);
            if a.anomaly_type == "ssti_reflection" {
                existing_ssti_paths.insert(norm_path.to_string());
            }
            out.push(probe);
        }
    }
    out
}

/// Bounded multi-turn ReAct adaptive execution loop across post-Wave 1/2 HTTP anomalies.
/// Implements the closed-loop OODA cycle: Observe -> Orient -> Decide -> Act with loop bounds and oscillation damping.
#[allow(clippy::too_many_arguments)]
pub fn run_adaptive_waves(
    target: &str,
    depth: Depth,
    disc: &Discovery,
    exec_opts: &ExecOptions,
    created: &CreatedLedger,
    mut llm: Option<(&LlmConfig, &mut Budget)>,
    budget: &mut RunBudget,
    existing_cases: &[PlannedCase],
    existing_results: &[CaseExecutionResult],
) -> ReactOutcome {
    let mut outcome = ReactOutcome::default();
    if depth == Depth::Quick || exec_opts.dry_run || budget.is_cancelled() {
        return outcome;
    }

    let reserve_requests = (budget.max_requests() / 3).max(15);
    let reserve_steps = (budget.max_steps() / 4).max(8);

    let mut seen_keys: HashSet<String> = existing_cases.iter().map(key_of).collect();
    let mut existing_ssti_paths: HashSet<String> = existing_cases
        .iter()
        .filter(|c| matches!(c.probe_oracle, Some(ProbeOracle::Ssti { .. })))
        .map(|c| path_of(&c.component).to_string())
        .collect();
    let mut seen_anomalies = HashSet::new();
    let mut damper = OscillationDamper::default();
    for c in existing_cases {
        damper.seed_seen(c);
    }

    let mut frontier = existing_results.to_vec();
    let mut next_id = 0usize;

    for wave in 1..=MAX_REACT_WAVES {
        // --- Loop bounds check ---
        if budget.is_cancelled() || budget.wall_left() < Duration::from_secs(2) {
            break;
        }
        let avail_steps = budget.steps_left().saturating_sub(reserve_steps);
        let avail_reqs = budget.requests_left().saturating_sub(reserve_requests);
        if avail_steps == 0 || avail_reqs == 0 {
            outcome.notes.push(format!(
                "react wave {wave}: stopped cleanly to preserve verification/cleanup budget"
            ));
            break;
        }

        // --- Step 1: OBSERVE & ORIENT ---
        let anomalies = extract_anomalies(&frontier, &existing_ssti_paths, &seen_anomalies);
        if anomalies.is_empty() {
            break;
        }
        for a in &anomalies {
            seen_anomalies.insert(a.dedup_key.clone());
        }

        let cap = MAX_REACT_CASES_PER_WAVE.min(avail_steps).min(avail_reqs);
        if cap == 0 {
            break;
        }

        outcome.notes.push(format!(
            "ooda wave {wave} orient: observed {} anomalies ({})",
            anomalies.len(),
            anomalies
                .iter()
                .map(|a| a.anomaly_type.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));

        // --- Step 2: DECIDE ---
        let mut proposals = None;
        if let Some((cfg, llm_budget)) = llm.as_mut() {
            let cfg = *cfg;
            let llm_budget: &mut Budget = llm_budget;
            if let Some(cases) = propose_via_llm(
                cfg,
                llm_budget,
                wave,
                &anomalies,
                disc,
                &exec_opts.credentials,
                &mut seen_keys,
                &mut next_id,
                cap,
                &mut outcome.notes,
            ) {
                outcome.llm_used = true;
                proposals = Some(cases);
            }
        }

        let candidate_cases = proposals.unwrap_or_else(|| {
            synthesize_offline_followups(
                &anomalies,
                disc,
                &exec_opts.credentials,
                &mut seen_keys,
                &mut existing_ssti_paths,
                &mut next_id,
                cap,
            )
        });

        // --- Step 3: OSCILLATION DAMPING ---
        let mut wave_cases = Vec::new();
        for case in candidate_cases {
            if !damper.should_damp(&case) {
                wave_cases.push(case);
            } else {
                outcome.notes.push(format!(
                    "ooda wave {wave}: damped oscillating probe on {} {}",
                    case.method, case.component
                ));
            }
        }

        if wave_cases.is_empty() {
            outcome.notes.push(format!(
                "ooda wave {wave}: all candidate probes damped; exiting loop early"
            ));
            break;
        }

        // --- Step 4: ACT ---
        let req_grant = avail_reqs.min(
            wave_cases
                .len()
                .saturating_mul(3 + exec_opts.reruns as usize),
        );
        if req_grant == 0 {
            break;
        }
        let mut slice = budget.slice(
            "react_lead",
            SliceLimits {
                steps: wave_cases.len(),
                requests: req_grant,
                wall: budget.wall_left().min(Duration::from_secs(60)),
                llm_calls: 0,
            },
        );
        let _installed = created.install();
        let wave_results = execute_cases_with(&wave_cases, target, exec_opts, &mut slice);
        budget.absorb(&slice.usage());

        outcome.waves_run += 1;
        frontier = wave_results.clone();
        outcome.added_cases.extend(wave_cases);
        outcome.added_results.extend(wave_results);
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::pipeline::{LlmMode, RunOptions, run_with};
    use crate::agent::types::AgentRunRequest;
    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn mock_llm_react_loop_adapts_on_wave2_exposes_chained_endpoint_and_bounds_waves() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new()
                    .route(
                        "/",
                        get(|| async {
                            (
                                StatusCode::OK,
                                [(
                                    axum::http::header::CONTENT_TYPE,
                                    "text/html; charset=utf-8",
                                )],
                                "<html><body><a href=\"/api/ping\">Ping</a></body></html>",
                            )
                        }),
                    )
                    .route(
                        "/api/ping",
                        get(|Query(q): Query<HashMap<String, String>>| async move {
                            let tpl = q.get("tpl").map(String::as_str).unwrap_or("");
                            if tpl.contains("{{1337*79}}") {
                                return (
                                    StatusCode::OK,
                                    Json(json!({ "rendered": "105623" })),
                                );
                            }
                            let v = q
                                .get("q")
                                .or_else(|| q.get("host"))
                                .map(String::as_str)
                                .unwrap_or("ok");
                            if v.contains('\'') || v.contains("alert") {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({
                                        "error": "traceback: see query handler at /api/ping for SSTI tpl param"
                                    })),
                                )
                            } else {
                                (StatusCode::OK, Json(json!({ "pong": v })))
                            }
                        }),
                    );

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://127.0.0.1:{}", addr.port())).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let base_url = rx.recv().unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = Arc::clone(&calls);
        let saw_fence = Arc::new(AtomicUsize::new(0));
        let fence_ref = Arc::clone(&saw_fence);
        let m = crate::llm::mock::start(move |body| {
            if body.contains("<data>") && body.contains("SECURITY RULES") {
                fence_ref.fetch_add(1, Ordering::SeqCst);
            }
            if body.contains("adaptive security tester") || body.contains("anomalies") {
                let rn = calls_ref.fetch_add(1, Ordering::SeqCst);
                if rn == 0 {
                    r#"{"cases":[
                        {"title":"ReAct SSTI follow-up via tpl param","component":"/api/ping","method":"GET","technique":"injection","payload":{"tpl":"{{1337*79}}"},"risk_level":"critical"},
                        {"title":"ReAct hallucinated route must be rejected","component":"/api/never/existed","method":"GET","technique":"injection","payload":{"q":"1"}}
                    ]}"#
                    .into()
                } else {
                    r#"{"cases":[]}"#.into()
                }
            } else {
                r#"{"cases":[]}"#.into()
            }
        });

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let llm_cache = std::env::temp_dir().join(format!("rh-react-llm-{nonce}"));
        let run_base = std::env::temp_dir().join(format!("rh-react-run-{nonce}"));
        std::fs::create_dir_all(&run_base).unwrap();
        let mut cfg = crate::llm::mock::cfg(&m.base, &llm_cache);
        cfg.model = format!("react-test-{nonce}");

        let req = AgentRunRequest {
            target: base_url,
            profile: "standard".into(),
            spec_url: None,
            custom_instructions: None,
            max_steps: None,
            dry_run: false,
            thinking: false,
            model_tier: "balanced".into(),
            thinking_budget_tokens: 1024,
            repo: None,
            diff_base: None,
        };
        let budget = RunBudget::new(80, 200, Duration::from_secs(60), 0.0);
        let opts = RunOptions {
            budget,
            credentials: Credentials::default(),
            llm: LlmMode::Use(Box::new(cfg)),
            reruns: 0,
            verify_k: 1,
            request_timeout: Duration::from_secs(5),
            lookup_requester_ip: false,
            workers: 2,
            memory_dir: None,
            data_dir: Some(
                std::env::temp_dir().join(format!("rh-react-data-{}", std::process::id())),
            ),
        };

        let rep = run_with(&run_base, &req, "react-llm", opts, Some(true)).unwrap();
        let _ = std::fs::remove_dir_all(&llm_cache);
        let _ = std::fs::remove_dir_all(&run_base);

        assert!(
            rep.steps.iter().any(|s| s.action == "ReAct Adaptive Loop"),
            "expected ReAct Adaptive Loop step in report: {:?}",
            rep.steps
        );
        assert_eq!(
            rep.stage_sources.get("react_lead").map(String::as_str),
            Some("llm+deterministic"),
            "expected LLM adaptive source tag in report: {:?}",
            rep.stage_sources
        );
        assert!(
            rep.planned_cases
                .iter()
                .all(|c| c.component != "/api/never/existed"),
            "hallucinated route must never pass validate_raw"
        );
        assert!(
            saw_fence.load(Ordering::SeqCst) > 0,
            "anomalies prompt must fence data with <data> and include SECURITY RULES"
        );
        assert!(
            calls.load(Ordering::SeqCst) <= MAX_REACT_WAVES,
            "ReAct LLM calls exceeded MAX_REACT_WAVES: {}",
            calls.load(Ordering::SeqCst)
        );
        assert!(
            rep.triaged_defects
                .iter()
                .any(|d| d.component.contains("/api/ping") && d.rule == "ssti"),
            "expected LLM-proposed SSTI follow-up via tpl param to fail & triage: {:?}",
            rep.triaged_defects
        );
    }

    #[test]
    fn offline_react_fallback_chains_error_disclosure_and_reflected_input_without_llm() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new()
                    .route(
                        "/",
                        get(|| async {
                            (
                                StatusCode::OK,
                                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                                "<html><body><a href=\"/api/calc\">Calc</a></body></html>",
                            )
                        }),
                    )
                    // Returns 500 on malformed quotes (anomaly in Wave 1), AND evaluates SSTI `{{1337*79}}`
                    // under query param `q`.
                    .route(
                        "/api/calc",
                        get(|Query(q): Query<HashMap<String, String>>| async move {
                            let v = q.get("q").map(String::as_str).unwrap_or("");
                            if v.contains("{{1337*79}}") {
                                (StatusCode::OK, Json(json!({ "result": 105623 })))
                            } else if v.contains('\'') || v.contains("script") {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({ "error": "TemplateSyntaxError in render(q)" })),
                                )
                            } else {
                                (StatusCode::OK, Json(json!({ "value": v })))
                            }
                        }),
                    );

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://127.0.0.1:{}", addr.port()))
                    .unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let base_url = rx.recv().unwrap();

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let run_base = std::env::temp_dir().join(format!("rh-react-off-{nonce}"));
        std::fs::create_dir_all(&run_base).unwrap();

        let req = AgentRunRequest {
            target: base_url,
            profile: "standard".into(),
            spec_url: None,
            custom_instructions: None,
            max_steps: None,
            dry_run: false,
            thinking: false,
            model_tier: "balanced".into(),
            thinking_budget_tokens: 1024,
            repo: None,
            diff_base: None,
        };
        let budget = RunBudget::new(80, 200, Duration::from_secs(60), 0.0);
        let opts = RunOptions {
            budget,
            credentials: Credentials::default(),
            llm: LlmMode::Off,
            reruns: 0,
            verify_k: 2,
            request_timeout: Duration::from_secs(5),
            lookup_requester_ip: false,
            workers: 2,
            memory_dir: None,
            data_dir: Some(
                std::env::temp_dir().join(format!("rh-react-data-{}", std::process::id())),
            ),
        };

        let rep = run_with(&run_base, &req, "react-offline", opts, Some(true)).unwrap();
        let _ = std::fs::remove_dir_all(&run_base);

        assert!(
            rep.steps.iter().any(|s| s.action == "ReAct Adaptive Loop"),
            "offline ReAct must run when Wave 1 produces 500 error anomaly: {:?}",
            rep.steps
        );
        let ssti = rep
            .triaged_defects
            .iter()
            .find(|d| d.component.contains("/api/calc") && d.rule == "ssti")
            .unwrap_or_else(|| {
                panic!(
                    "expected offline ReAct SSTI follow-up to confirm SSTI on /api/calc; defects={:?}",
                    rep.triaged_defects
                )
            });
        assert!(
            ssti.verified,
            "SSTI from offline ReAct wave must verify cleanly"
        );
    }

    #[test]
    fn test_react_anomaly_detector() {
        let mut result = CaseExecutionResult::default();
        result.status = "FAIL".into();
        result.response_status = Some(500);
        result.response_body =
            Some(r#"{"error":"InternalServerError: NullPointer at AuthService.java:42"}"#.into());
        assert!(is_anomaly_candidate(&result));

        let mut auth_res = CaseExecutionResult::default();
        auth_res.status = "FAIL".into();
        auth_res.response_status = Some(403);
        auth_res.response_body =
            Some(r#"{"error":"Forbidden: requires role 'admin' for tenant_id"}"#.into());
        assert!(is_anomaly_candidate(&auth_res));

        let mut schema_res = CaseExecutionResult::default();
        schema_res.status = "FAIL".into();
        schema_res.response_status = Some(422);
        schema_res.response_body =
            Some(r#"{"detail":[{"loc":["body","user_id"],"msg":"field required"}]}"#.into());
        assert!(is_anomaly_candidate(&schema_res));

        let mut pass_res = CaseExecutionResult::default();
        pass_res.status = "PASS".into();
        pass_res.response_status = Some(200);
        pass_res.response_body = Some(r#"{"status":"ok"}"#.into());
        assert!(!is_anomaly_candidate(&pass_res));
    }

    #[test]
    fn test_ooda_closed_loop_controller() {
        let mut observation = CaseExecutionResult::default();
        observation.status = "FAIL".into();
        observation.response_status = Some(500);
        observation.response_body =
            Some("SyntaxError: unterminated quoted string at or near 'admin'".into());
        let anomaly = detect_ooda_anomaly(&observation).expect("should detect SQL anomaly");
        assert_eq!(anomaly.anomaly_type, "sql_leak");
        let probe = synthesize_mutation_probe(&anomaly, "http://localhost:3000/api/users");
        assert!(probe.method == "GET" || probe.method == "POST");
    }

    #[test]
    fn test_ooda_anomaly_categorization_signatures() {
        // 1. sql_leak
        let mut sql_obs = CaseExecutionResult::default();
        sql_obs.status = "FAIL".into();
        sql_obs.response_status = Some(500);
        sql_obs.response_body = Some("pg::SQLException: column \"secret\" does not exist".into());
        let a = detect_ooda_anomaly(&sql_obs).unwrap();
        assert_eq!(a.anomaly_type, "sql_leak");

        // 2. authz_leak
        let mut auth_obs = CaseExecutionResult::default();
        auth_obs.status = "FAIL".into();
        auth_obs.response_status = Some(403);
        auth_obs.response_body =
            Some("Access Denied: missing required permission 'admin:read'".into());
        let a = detect_ooda_anomaly(&auth_obs).unwrap();
        assert_eq!(a.anomaly_type, "authz_leak");

        // 3. schema_leak
        let mut schema_obs = CaseExecutionResult::default();
        schema_obs.status = "FAIL".into();
        schema_obs.response_status = Some(422);
        schema_obs.response_body = Some(
            "{\"detail\":[{\"loc\":[\"body\",\"account_id\"],\"msg\":\"field required\"}]}".into(),
        );
        let a = detect_ooda_anomaly(&schema_obs).unwrap();
        assert_eq!(a.anomaly_type, "schema_leak");

        // 4. ssti_reflection
        let mut ssti_obs = CaseExecutionResult::default();
        ssti_obs.status = "FAIL".into();
        ssti_obs.response_status = Some(500);
        ssti_obs.response_body =
            Some("TemplateSyntaxError: unexpected char in render(template)".into());
        let a = detect_ooda_anomaly(&ssti_obs).unwrap();
        assert_eq!(a.anomaly_type, "ssti_reflection");

        // 5. canary_reflection
        let mut canary_obs = CaseExecutionResult::default();
        canary_obs.status = "FAIL".into();
        canary_obs.request_payload = Some("CANARY_TEST_XYZ".into());
        canary_obs.response_body = Some("<div>Hello CANARY_TEST_XYZ</div>".into());
        let a = detect_ooda_anomaly(&canary_obs).unwrap();
        assert_eq!(a.anomaly_type, "canary_reflection");
    }

    #[test]
    fn test_ooda_synthesize_mutation_probes_for_all_types() {
        let types = [
            "sql_leak",
            "authz_leak",
            "schema_leak",
            "ssti_reflection",
            "canary_reflection",
        ];
        for t in types {
            let anomaly = OodaAnomaly {
                anomaly_type: t.to_string(),
                dedup_key: format!("{t}:GET:/api/test:sig"),
                component: "/api/test".into(),
                method: "GET".into(),
                status_code: Some(500),
                signals: vec![t.to_string()],
                request_payload: None,
                evidence: "leak evidence".into(),
                body_excerpt: "leak excerpt".into(),
                hinted_params: vec!["param1".into()],
                hinted_routes: Vec::new(),
                reflection_signature: Some("canary_str".into()),
            };
            let probe = synthesize_mutation_probe(&anomaly, "http://localhost:3000");
            assert_eq!(probe.component, "/api/test");
            assert_eq!(probe.method, "GET");
            assert!(probe.payload.is_some());
        }
    }

    #[test]
    fn test_ooda_oscillation_damping() {
        let mut damper = OscillationDamper::new(2);
        let base_anomaly = OodaAnomaly {
            anomaly_type: "sql_leak".into(),
            dedup_key: "k".into(),
            component: "/api/items".into(),
            method: "GET".into(),
            status_code: Some(500),
            signals: vec!["sql_leak".into()],
            request_payload: None,
            evidence: "".into(),
            body_excerpt: "".into(),
            hinted_params: vec!["q".into()],
            hinted_routes: Vec::new(),
            reflection_signature: None,
        };
        let mut case = synthesize_mutation_probe(&base_anomaly, "http://localhost:3000");
        case.payload = Some("q=1".into());

        // 1. First probe accepted
        assert!(!damper.should_damp(&case));

        // 2. Exact same probe suppressed by oscillation damping
        assert!(damper.should_damp(&case));

        // 3. Different payload accepted (count = 2)
        case.payload = Some("q=2".into());
        assert!(!damper.should_damp(&case));

        // 4. Third distinct payload on same endpoint damped by endpoint cap (limit = 2)
        case.payload = Some("q=3".into());
        assert!(damper.should_damp(&case));
    }
}
