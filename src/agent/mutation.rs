//! Adaptive Schema Feedback Mutation Engine.
//!
//! When an API endpoint responds with HTTP 400 or 422, it frequently discloses
//! the exact JSON schema it expected (e.g. FastAPI/Pydantic `detail`, Zod `errors`/`issues`,
//! Django REST field mappings, or Spring Boot `errors`).
//!
//! This module parses those validation error payloads, extracts the required field names
//! and expected data types, and dynamically mutates adversarial test payloads to penetrate
//! past the input validation barrier and reach deeper application handlers.

use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredField {
    pub name: String,
    pub expected_type: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemaFeedback {
    pub framework_hint: Option<String>,
    pub required_fields: Vec<DiscoveredField>,
}

impl SchemaFeedback {
    pub fn is_empty(&self) -> bool {
        self.required_fields.is_empty()
    }
}

/// Parse HTTP 400 / 422 response bodies to extract schema expectations.
pub fn extract_schema_feedback(status: u16, content_type: &str, body: &str) -> Option<SchemaFeedback> {
    if status != 400 && status != 422 {
        return None;
    }
    let trimmed = body.trim_start();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return None;
    }
    let lower_ct = content_type.to_ascii_lowercase();
    if !lower_ct.is_empty() && !lower_ct.contains("json") && !lower_ct.contains("problem") {
        return None;
    }

    let v: Value = serde_json::from_str(trimmed).ok()?;
    let mut fields: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut framework_hint = None;

    // 1. FastAPI / Pydantic: {"detail": [{"loc": ["body", "param"], "msg": "...", "type": "..."}]}
    if let Some(detail_arr) = v.get("detail").and_then(Value::as_array) {
        framework_hint = Some("FastAPI / Pydantic".into());
        for item in detail_arr {
            if let Some(loc) = item.get("loc").and_then(Value::as_array) {
                if let Some(last) = loc.last().and_then(Value::as_str) {
                    if last != "body" && last != "query" && last != "header" && last != "path" {
                        let exp_type = item.get("type").and_then(Value::as_str).map(|s| s.to_string());
                        fields.entry(last.to_string()).or_insert(exp_type);
                    }
                }
            }
        }
    }

    // 2. Zod / Express / NestJS: {"errors": [...]} or {"issues": [...]}
    for key in ["errors", "issues"] {
        if let Some(err_arr) = v.get(key).and_then(Value::as_array) {
            for item in err_arr {
                if let Some(path) = item.get("path").and_then(Value::as_array) {
                    if let Some(field) = path.last().and_then(Value::as_str) {
                        let exp = item.get("expected").and_then(Value::as_str).map(|s| s.to_string());
                        framework_hint = Some("Zod / Express".into());
                        fields.entry(field.to_string()).or_insert(exp);
                    }
                } else if let Some(field) = item.get("field").and_then(Value::as_str) {
                    // Spring Boot: {"errors": [{"field": "id", "defaultMessage": "..."}]}
                    framework_hint = Some("Spring Boot".into());
                    fields.entry(field.to_string()).or_insert(None);
                }
            }
        }
    }

    // 3. Django REST Framework: {"field_name": ["This field is required."]}
    if fields.is_empty() && v.is_object() {
        if let Some(map) = v.as_object() {
            for (k, val) in map {
                if matches!(
                    k.as_str(),
                    "detail" | "message" | "error" | "status" | "timestamp" | "path" | "code"
                ) {
                    continue;
                }
                if let Some(arr) = val.as_array() {
                    let has_req_msg = arr.iter().any(|msg| {
                        msg.as_str()
                            .map(|m| {
                                let l = m.to_ascii_lowercase();
                                l.contains("required") || l.contains("blank") || l.contains("null")
                            })
                            .unwrap_or(false)
                    });
                    if has_req_msg {
                        framework_hint = Some("Django REST Framework".into());
                        fields.entry(k.clone()).or_insert(None);
                    }
                }
            }
        }
    }

    if fields.is_empty() {
        return None;
    }

    let required_fields = fields
        .into_iter()
        .map(|(name, expected_type)| DiscoveredField { name, expected_type })
        .collect();

    Some(SchemaFeedback {
        framework_hint,
        required_fields,
    })
}

/// Generates an adversarial mutation payload tailored to the discovered missing fields.
pub fn mutate_payload(
    original_payload: Option<&str>,
    feedback: &SchemaFeedback,
    technique: &str,
) -> Option<String> {
    if feedback.is_empty() {
        return None;
    }

    let mut obj = match original_payload {
        Some(s) if s.trim_start().starts_with('{') => {
            serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!({}))
        }
        _ => json!({}),
    };

    if !obj.is_object() {
        obj = json!({});
    }

    let map = obj.as_object_mut()?;

    for field in &feedback.required_fields {
        let is_numeric = field.expected_type.as_deref().map(|t| {
            let l = t.to_ascii_lowercase();
            l.contains("int") || l.contains("float") || l.contains("number")
        }).unwrap_or(false);

        let is_bool = field.expected_type.as_deref().map(|t| {
            t.to_ascii_lowercase().contains("bool")
        }).unwrap_or(false);

        let val = if is_bool {
            json!(true)
        } else if is_numeric {
            match technique {
                "boundary" => json!(999999999),
                "negative" => json!(-1),
                _ => json!(1),
            }
        } else {
            match technique {
                "injection" => json!("'\"><script>alert(1)</script>' OR '1'='1' --"),
                "boundary" => json!("A".repeat(1024)),
                "authz" => json!("00000000-0000-0000-0000-000000000000"),
                "negative" => json!(""),
                _ => json!("readyhai_mutated_canary"),
            }
        };

        map.insert(field.name.clone(), val);
    }

    Some(serde_json::to_string(&obj).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fastapi_pydantic_validation() {
        let body = r#"{
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "workspace_id"],
                    "msg": "Field required",
                    "input": {}
                },
                {
                    "type": "string_type",
                    "loc": ["body", "tenant_slug"],
                    "msg": "Input should be a valid string",
                    "input": 123
                }
            ]
        }"#;

        let fb = extract_schema_feedback(422, "application/json", body).expect("should extract feedback");
        assert_eq!(fb.framework_hint.as_deref(), Some("FastAPI / Pydantic"));
        assert_eq!(fb.required_fields.len(), 2);
        assert_eq!(fb.required_fields[0].name, "tenant_slug");
        assert_eq!(fb.required_fields[1].name, "workspace_id");

        let mutated = mutate_payload(None, &fb, "injection").expect("should mutate");
        assert!(mutated.contains("workspace_id"));
        assert!(mutated.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn parses_zod_express_validation() {
        let body = r#"{
            "errors": [
                {
                    "path": ["auth", "token"],
                    "message": "Required",
                    "code": "invalid_type",
                    "expected": "string"
                }
            ]
        }"#;

        let fb = extract_schema_feedback(400, "application/json", body).expect("should extract feedback");
        assert_eq!(fb.framework_hint.as_deref(), Some("Zod / Express"));
        assert_eq!(fb.required_fields.len(), 1);
        assert_eq!(fb.required_fields[0].name, "token");
    }

    #[test]
    fn parses_django_rest_validation() {
        let body = r#"{
            "organization_id": ["This field is required."],
            "api_key": ["This field may not be blank."]
        }"#;

        let fb = extract_schema_feedback(400, "application/json", body).expect("should extract feedback");
        assert_eq!(fb.framework_hint.as_deref(), Some("Django REST Framework"));
        assert_eq!(fb.required_fields.len(), 2);
    }
}
