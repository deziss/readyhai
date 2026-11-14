//! GraphQL QA Engine (`qa.graphql`): Schema introspection, query depth DoS fuzzing,
//! field-level authorization (FLA) checks, and robustness/error leak detection.
use super::model::*;
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};
use crate::qa::QaCtx;
use crate::qa::api::exec;
use anyhow::Result;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

static SEQ: AtomicUsize = AtomicUsize::new(1);

const INTROSPECTION_QUERY: &str = r#"query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type { name kind ofType { name kind ofType { name kind } } }
        }
        type { name kind ofType { name kind } }
      }
    }
  }
}"#;

const SENSITIVE_KEYWORDS: &[&str] = &[
    "admin", "users", "account", "token", "secret", "permission", "billing", "audit", "creditcard", "credential"
];

pub fn checks() -> Vec<Check> {
    vec![
        Check::new(
            "qa.graphql",
            "GraphQL QA: schema introspection, query depth DoS, field authz & error leaks",
            &[TargetKind::Web],
            Profile::Quick,
            run,
        )
        .qa(),
    ]
}

pub fn run(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(qa) = &ctx.qa else {
        return Ok(CheckOutput::status(CheckStatus::Skipped("only under readyhai qa".into())));
    };

    let target_url = ctx.target.raw.trim_end_matches('/');
    let Some(graphql_ep) = discover_endpoint(qa, target_url)? else {
        qa.with(|c| {
            c.notes.push("GraphQL check: no active GraphQL endpoint discovered on target".into());
        });
        return Ok(CheckOutput::status(CheckStatus::Skipped("no GraphQL endpoint found".into())));
    };

    let mut findings = Vec::new();
    let mut cases_run = 0;

    // 1. Schema Introspection
    cases_run += 1;
    let intro_case_id = "graphql.introspection".to_string();
    qa.with(|c| {
        c.cases.push(TestCase {
            id: intro_case_id.clone(),
            area: Area::Api,
            technique: Technique::Contract,
            title: "GraphQL Schema Introspection Probe".into(),
            priority: Priority::P3,
            component: "POST GraphQL".into(),
            role: None,
            steps: vec![format!("Send standard introspection query to {graphql_ep}")],
            expected: "Valid GraphQL schema or gracefully disabled introspection".into(),
            source: CaseSource::Deterministic,
        });
    });

    let intro_body = json!({ "query": INTROSPECTION_QUERY });
    let intro_resp = exec::send(qa, None, "POST", &graphql_ep, Some(&intro_body), &[("Content-Type", "application/json")])?;
    
    let schema_data = if intro_resp.status == 200 && intro_resp.parsed.is_some() {
        let root = intro_resp.parsed.as_deref().unwrap();
        root.get("data").and_then(|d| d.get("__schema")).cloned()
    } else {
        None
    };

    if let Some(schema) = &schema_data {
        qa.with(|c| {
            c.results.push(TestResult {
                case_id: intro_case_id.clone(),
                status: ResultStatus::Pass,
                actual: "Introspection query answered with valid GraphQL schema".into(),
                duration_ms: intro_resp.ms,
                attempts: 1,
                evidence: vec![],
                defect_id: None,
            });
        });

        // Advisory: Introspection enabled in production
        if !qa.nonprod {
            let def_id = format!("D-GQ-{:03}", SEQ.fetch_add(1, Ordering::SeqCst));
            let d = Defect {
                id: def_id.clone(),
                rule: "qa.graphql.introspection_enabled".into(),
                category: Category::Quality,
                severity: Severity::Low,
                priority: Priority::P4,
                area: Area::Api,
                title: "GraphQL schema introspection enabled on production host".into(),
                component: "GraphQL".into(),
                environment: "prod".into(),
                expected: "Introspection disabled in production to prevent schema enumeration".into(),
                actual: format!("Server at {graphql_ep} returned complete __schema definition"),
                steps_to_reproduce: vec![
                    format!("curl -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ __schema {{ types {{ name }} }} }}\"}}' {graphql_ep}")
                ],
                evidence: vec![],
                reproduced: (1, 1),
                cases: vec![intro_case_id.clone()],
                remediation: "Disable schema introspection on production deployments (e.g., validation rules or server configuration).".into(),
                fp_key: format!("qa.graphql.introspection_enabled|{graphql_ep}"),
                fingerprint: String::new(),
                status: Default::default(),
                regression: false,
                ai_note: None,
            };
            findings.push(d.to_finding("qa.graphql"));
            qa.with(|c| c.defects.push(d));
        }

        // 2. Field-Level Authorization (FLA) Checks
        cases_run += check_field_authz(qa, &graphql_ep, schema, &mut findings)?;
    } else {
        qa.with(|c| {
            c.results.push(TestResult {
                case_id: intro_case_id.clone(),
                status: ResultStatus::Pass,
                actual: format!("Introspection query returned HTTP status {}", intro_resp.status),
                duration_ms: intro_resp.ms,
                attempts: 1,
                evidence: vec![],
                defect_id: None,
            });
        });
    }

    // 3. Query Depth / Circular Nesting DoS Fuzzing
    cases_run += check_query_depth_dos(qa, &graphql_ep, &mut findings)?;

    // 4. Malformed Query Robustness & Error Leak Fuzzing
    cases_run += check_malformed_syntax_robustness(qa, &graphql_ep, &mut findings)?;

    qa.with(|c| {
        c.notes.push(format!("GraphQL QA completed on {graphql_ep} ({cases_run} cases executed)"));
    });

    Ok(CheckOutput::findings(findings))
}

/// Discovers the active GraphQL endpoint by checking standard path candidates.
fn discover_endpoint(qa: &QaCtx, base: &str) -> Result<Option<String>> {
    let candidates = if base.ends_with("/graphql") || base.ends_with("/query") {
        vec![base.to_string()]
    } else {
        vec![
            format!("{base}/graphql"),
            format!("{base}/api/graphql"),
            format!("{base}/query"),
            format!("{base}/v1/graphql"),
        ]
    };

    let probe_body = json!({ "query": "query { __typename }" });
    for cand in candidates {
        if let Ok(resp) = exec::send(qa, None, "POST", &cand, Some(&probe_body), &[("Content-Type", "application/json")]) {
            if resp.status == 200 && resp.body.contains("__typename") {
                return Ok(Some(cand));
            }
            if resp.status == 200 && resp.body.contains("errors") && resp.body.contains("GraphQL") {
                return Ok(Some(cand));
            }
        }
    }
    Ok(None)
}

/// Tests query depth limits and nesting DoS resilience.
fn check_query_depth_dos(qa: &QaCtx, ep: &str, findings: &mut Vec<Finding>) -> Result<usize> {
    let case_id = "graphql.query_depth.nesting_dos".to_string();
    qa.with(|c| {
        c.cases.push(TestCase {
            id: case_id.clone(),
            area: Area::Api,
            technique: Technique::Negative,
            title: "GraphQL Deep Query Nesting / Complexity Limit Probe".into(),
            priority: Priority::P2,
            component: "GraphQL".into(),
            role: None,
            steps: vec!["Submit deeply nested circular alias query (10 levels deep)".into()],
            expected: "Server enforces max query depth and rejects with 400 Bad Request".into(),
            source: CaseSource::Deterministic,
        });
    });

    // Synthesize deeply nested query
    let deep_query = "query DeepNest { __schema { types { fields { type { ofType { ofType { ofType { ofType { ofType { ofType { name } } } } } } } } } } }";
    let body = json!({ "query": deep_query });
    let resp = exec::send(qa, None, "POST", ep, Some(&body), &[("Content-Type", "application/json")])?;

    let is_fail = resp.status >= 500 || resp.timed_out;
    if is_fail {
        let def_id = format!("D-GQ-{:03}", SEQ.fetch_add(1, Ordering::SeqCst));
        let d = Defect {
            id: def_id.clone(),
            rule: "qa.graphql.deep_nesting_dos".into(),
            category: Category::Security,
            severity: Severity::High,
            priority: Priority::P2,
            area: Area::Api,
            title: "GraphQL query depth exhaustion leads to server error or timeout".into(),
            component: "GraphQL".into(),
            environment: if qa.nonprod { "nonprod".into() } else { "prod".into() },
            expected: "Server enforces max depth / complexity validation (HTTP 400)".into(),
            actual: format!("Server failed with status {} or timeout on depth 10 nesting query", resp.status),
            steps_to_reproduce: vec![
                format!("curl -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{}\"}}' {}", deep_query, ep)
            ],
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![case_id.clone()],
            remediation: "Implement query depth limiting (e.g. max depth <= 6) and query complexity analysis middleware.".into(),
            fp_key: format!("qa.graphql.deep_nesting_dos|{ep}"),
            fingerprint: String::new(),
            status: Default::default(),
            regression: false,
            ai_note: None,
        };
        findings.push(d.to_finding("qa.graphql"));
        qa.with(|c| {
            c.defects.push(d);
            c.results.push(TestResult {
                case_id,
                status: ResultStatus::Fail,
                actual: format!("Deep query triggered HTTP {}", resp.status),
                duration_ms: resp.ms,
                attempts: 1,
                evidence: vec![],
                defect_id: Some(def_id),
            });
        });
    } else {
        qa.with(|c| {
            c.results.push(TestResult {
                case_id,
                status: ResultStatus::Pass,
                actual: format!("Deep nesting handled safely (status {})", resp.status),
                duration_ms: resp.ms,
                attempts: 1,
                evidence: vec![],
                defect_id: None,
            });
        });
    }

    Ok(1)
}

/// Identifies sensitive schema fields and validates field-level authorization.
fn check_field_authz(qa: &QaCtx, ep: &str, schema: &Value, findings: &mut Vec<Finding>) -> Result<usize> {
    let mut cases = 0;
    let Some(types) = schema.get("types").and_then(|t| t.as_array()) else {
        return Ok(0);
    };

    // Find Query root type fields
    let query_type_name = schema.get("queryType")
        .and_then(|q| q.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("Query");

    let query_fields = types.iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(query_type_name))
        .and_then(|t| t.get("fields"))
        .and_then(|f| f.as_array());

    let Some(fields) = query_fields else {
        return Ok(0);
    };

    // Check for sensitive field names
    for field in fields {
        let Some(name) = field.get("name").and_then(|n| n.as_str()) else { continue };
        let is_sensitive = SENSITIVE_KEYWORDS.iter().any(|k| name.to_lowercase().contains(k));
        if !is_sensitive { continue; }

        cases += 1;
        let case_id = format!("graphql.authz.{name}");
        qa.with(|c| {
            c.cases.push(TestCase {
                id: case_id.clone(),
                area: Area::Api,
                technique: Technique::AuthMatrix,
                title: format!("GraphQL Field-Level Authz for `{name}`"),
                priority: Priority::P1,
                component: format!("GraphQL query.{name}"),
                role: Some("anonymous".into()),
                steps: vec![format!("Query sensitive field `{name}` without authentication token")],
                expected: "HTTP 401/403 or GraphQL errors indicating access denied".into(),
                source: CaseSource::Deterministic,
            });
        });

        let query = format!("query {{ {name} {{ __typename }} }}");
        let body = json!({ "query": query });
        let resp = exec::send(qa, None, "POST", ep, Some(&body), &[("Content-Type", "application/json")])?;

        // If anonymous caller got 200 OK with actual data and no auth errors, flag BFLA/Authz gap
        let has_data = resp.parsed.as_deref()
            .and_then(|p| p.get("data"))
            .and_then(|d| d.get(name))
            .map(|v| !v.is_null())
            .unwrap_or(false);

        let has_auth_error = resp.body.contains("Unauthorized") 
            || resp.body.contains("Forbidden") 
            || resp.body.contains("unauthenticated")
            || resp.body.contains("access denied");

        if has_data && !has_auth_error {
            let def_id = format!("D-GQ-{:03}", SEQ.fetch_add(1, Ordering::SeqCst));
            let d = Defect {
                id: def_id.clone(),
                rule: "qa.graphql.authz_missing".into(),
                category: Category::Security,
                severity: Severity::High,
                priority: Priority::P1,
                area: Area::Api,
                title: format!("Sensitive GraphQL query `{name}` accessible without authentication"),
                component: format!("GraphQL query.{name}"),
                environment: if qa.nonprod { "nonprod".into() } else { "prod".into() },
                expected: "Sensitive fields require valid authenticated session and permissions".into(),
                actual: format!("Anonymous query returned HTTP 200 and data: {}", resp.redacted_body().chars().take(200).collect::<String>()),
                steps_to_reproduce: vec![
                    format!("curl -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{}\"}}' {}", query, ep)
                ],
                evidence: vec![],
                reproduced: (1, 1),
                cases: vec![case_id.clone()],
                remediation: format!("Enforce authentication and field-level authorization directives (@auth/@requires) on `{name}`."),
                fp_key: format!("qa.graphql.authz_missing|{ep}|{name}"),
                fingerprint: String::new(),
                status: Default::default(),
                regression: false,
                ai_note: None,
            };
            findings.push(d.to_finding("qa.graphql"));
            qa.with(|c| {
                c.defects.push(d);
                c.results.push(TestResult {
                    case_id,
                    status: ResultStatus::Fail,
                    actual: "Sensitive data returned to anonymous caller".into(),
                    duration_ms: resp.ms,
                    attempts: 1,
                    evidence: vec![],
                    defect_id: Some(def_id),
                });
            });
        } else {
            qa.with(|c| {
                c.results.push(TestResult {
                    case_id,
                    status: ResultStatus::Pass,
                    actual: "Sensitive field correctly guarded or rejected".into(),
                    duration_ms: resp.ms,
                    attempts: 1,
                    evidence: vec![],
                    defect_id: None,
                });
            });
        }

        if cases >= 5 { break; } // Cap at 5 sensitive fields to conserve request budget
    }

    Ok(cases)
}

/// Sends malformed syntax and checks for proper error handling and stack trace leaks.
fn check_malformed_syntax_robustness(qa: &QaCtx, ep: &str, findings: &mut Vec<Finding>) -> Result<usize> {
    let case_id = "graphql.robustness.syntax_error".to_string();
    qa.with(|c| {
        c.cases.push(TestCase {
            id: case_id.clone(),
            area: Area::Api,
            technique: Technique::Negative,
            title: "GraphQL Malformed Syntax and Error Leak Probe".into(),
            priority: Priority::P3,
            component: "GraphQL".into(),
            role: None,
            steps: vec!["Submit malformed GraphQL query string `query { broken (`".into()],
            expected: "HTTP 400 with standard GraphQL error object, no stack trace or internal leak".into(),
            source: CaseSource::Deterministic,
        });
    });

    let malformed_body = json!({ "query": "query { broken (" });
    let resp = exec::send(qa, None, "POST", ep, Some(&malformed_body), &[("Content-Type", "application/json")])?;

    // Check for stack trace leak
    let has_leak = crate::qa::api::contract::leak_kind(&resp.body).is_some();
    if has_leak || resp.status >= 500 {
        let def_id = format!("D-GQ-{:03}", SEQ.fetch_add(1, Ordering::SeqCst));
        let (rule, title, sev) = if has_leak {
            ("qa.graphql.error_leak", "GraphQL syntax error leaks internal stack trace or debug information", Severity::Medium)
        } else {
            ("qa.graphql.server_error", "GraphQL malformed syntax triggers unhandled 5xx server error", Severity::High)
        };

        let d = Defect {
            id: def_id.clone(),
            rule: rule.into(),
            category: if has_leak { Category::Security } else { Category::Quality },
            severity: sev,
            priority: Priority::P2,
            area: Area::Api,
            title: title.into(),
            component: "GraphQL".into(),
            environment: if qa.nonprod { "nonprod".into() } else { "prod".into() },
            expected: "Client syntax errors should return 400 Bad Request with sanitized message".into(),
            actual: format!("Server returned HTTP {} with body: {}", resp.status, resp.redacted_body().chars().take(200).collect::<String>()),
            steps_to_reproduce: vec![
                format!("curl -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ broken (\"}}' {}", ep)
            ],
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![case_id.clone()],
            remediation: "Ensure GraphQL parse errors return sanitized 400 responses and suppress internal exception stack traces.".into(),
            fp_key: format!("{rule}|{ep}"),
            fingerprint: String::new(),
            status: Default::default(),
            regression: false,
            ai_note: None,
        };
        findings.push(d.to_finding("qa.graphql"));
        qa.with(|c| {
            c.defects.push(d);
            c.results.push(TestResult {
                case_id,
                status: ResultStatus::Fail,
                actual: format!("HTTP {} / stack trace detected", resp.status),
                duration_ms: resp.ms,
                attempts: 1,
                evidence: vec![],
                defect_id: Some(def_id),
            });
        });
    } else {
        qa.with(|c| {
            c.results.push(TestResult {
                case_id,
                status: ResultStatus::Pass,
                actual: "Syntax error safely rejected with sanitized error format".into(),
                duration_ms: resp.ms,
                attempts: 1,
                evidence: vec![],
                defect_id: None,
            });
        });
    }

    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_keywords_matching() {
        assert!(SENSITIVE_KEYWORDS.iter().any(|k| "adminStats".to_lowercase().contains(k)));
        assert!(SENSITIVE_KEYWORDS.iter().any(|k| "listUsers".to_lowercase().contains(k)));
        assert!(SENSITIVE_KEYWORDS.iter().any(|k| "userToken".to_lowercase().contains(k)));
        assert!(!SENSITIVE_KEYWORDS.iter().any(|k| "publicArticles".to_lowercase().contains(k)));
    }

    #[test]
    fn test_introspection_query_well_formed() {
        assert!(INTROSPECTION_QUERY.contains("__schema"));
        assert!(INTROSPECTION_QUERY.contains("queryType"));
        assert!(INTROSPECTION_QUERY.contains("types"));
    }

    #[test]
    fn test_schema_field_extraction() {
        let schema_json = json!({
            "queryType": { "name": "Query" },
            "types": [
                {
                    "name": "Query",
                    "fields": [
                        { "name": "publicPosts" },
                        { "name": "adminUsers" },
                        { "name": "secretTokens" }
                    ]
                }
            ]
        });

        let query_fields = schema_json.get("types")
            .and_then(|t| t.as_array())
            .unwrap()
            .iter()
            .find(|t| t.get("name").and_then(|n| n.as_str()) == Some("Query"))
            .and_then(|t| t.get("fields"))
            .and_then(|f| f.as_array())
            .unwrap();

        let sensitive_fields: Vec<&str> = query_fields
            .iter()
            .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
            .filter(|name| SENSITIVE_KEYWORDS.iter().any(|k| name.to_lowercase().contains(k)))
            .collect();

        assert_eq!(sensitive_fields, vec!["adminUsers", "secretTokens"]);
    }
}
