//! Semantic route and parameter discovery leveraging LLM reasoning and tech-adapted heuristics.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::agent::recon::SynthesizedDirectives;
use crate::agent::types::{DiscoveredRoute, InputSurface, TargetTechProfile};
use crate::llm::untrusted::{self, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed};

/// A semantic route candidate predicted via LLM reasoning or technology fingerprint heuristics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticRoute {
    pub path: String,
    pub method: String,
    #[serde(default)]
    pub reasoning: String,
    #[serde(default)]
    pub input_surface: Option<String>,
    #[serde(default)]
    pub suggested_params: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SemanticRoutesWrapper {
    routes: Vec<SemanticRoute>,
}

/// Parses raw JSON into a list of `SemanticRoute` predictions.
/// Supports both JSON array and `{ "routes": [...] }` wrapper, with or without markdown code fences.
pub fn parse_semantic_routes(raw: &str) -> Result<Vec<SemanticRoute>> {
    let cleaned = raw.trim();
    let json_str = if cleaned.starts_with("```") {
        let trimmed_start = cleaned
            .trim_start_matches("```json")
            .trim_start_matches("```");
        if let Some(end) = trimmed_start.rfind("```") {
            &trimmed_start[..end]
        } else {
            trimmed_start
        }
    } else {
        cleaned
    };

    let trimmed = json_str.trim();

    // Try parsing as direct array first
    if let Ok(routes) = serde_json::from_str::<Vec<SemanticRoute>>(trimmed) {
        return sanitize_routes(routes);
    }

    // Try parsing as wrapped object
    if let Ok(wrapper) = serde_json::from_str::<SemanticRoutesWrapper>(trimmed) {
        return sanitize_routes(wrapper.routes);
    }

    // Try parsing as arbitrary Value with "routes" or "endpoints" key
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(arr) = val.get("routes").or_else(|| val.get("endpoints")).and_then(|v| v.as_array())
    {
        let mut list = Vec::new();
        for item in arr {
            if let Ok(r) = serde_json::from_value::<SemanticRoute>(item.clone()) {
                list.push(r);
            }
        }
        if !list.is_empty() {
            return sanitize_routes(list);
        }
    }

    anyhow::bail!("failed to parse semantic routes from payload");
}

fn sanitize_routes(routes: Vec<SemanticRoute>) -> Result<Vec<SemanticRoute>> {
    let mut clean = Vec::new();
    for mut r in routes {
        let path = r.path.trim();
        if !path.starts_with('/') {
            r.path = format!("/{path}");
        } else {
            r.path = path.to_string();
        }
        r.method = r.method.trim().to_uppercase();
        if matches!(r.method.as_str(), "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS") {
            clean.push(r);
        }
    }
    if clean.is_empty() {
        anyhow::bail!("no valid HTTP routes found in semantic route payload");
    }
    Ok(clean)
}

const SEMANTIC_DISCOVERY_ROLE: &str = "\
You are a Principal Security Researcher specializing in Shadow API & Attack Surface Discovery. \
Based on target reconnaissance, technology stack fingerprinting, and known routes, \
predict undocumented, shadow, internal, actuator, and administrative API endpoints with their expected parameters. \
Format: [{\"path\": string, \"method\": \"GET\"|\"POST\"|\"PUT\"|\"PATCH\"|\"DELETE\", \"reasoning\": string, \"suggested_params\": [string]}]. \
Every path must start with '/'. Do not repeat known endpoints.";

/// Discovers high-probability shadow endpoints and parameter schemas using LLM reasoning
/// when available, falling back deterministically to tech-adapted framework routes.
pub fn discover_semantic_routes(
    mut llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    tech: &TargetTechProfile,
    known_routes: &[DiscoveredRoute],
    directives: Option<&SynthesizedDirectives>,
) -> Vec<DiscoveredRoute> {
    let known_paths: Vec<&str> = known_routes.iter().map(|r| r.path.as_str()).collect();

    // 1. If LLM is available, perform intelligent semantic prediction
    if let Some((cfg, ref mut budget)) = llm.take() {
        let known_samples: Vec<serde_json::Value> = known_routes
            .iter()
            .take(40)
            .map(|r| serde_json::json!({"path": r.path, "method": r.method, "status": r.status_code}))
            .collect();

        let focus = directives
            .map(|d| d.focus_areas.as_slice())
            .unwrap_or(&[]);

        let facts = serde_json::json!({
            "target": target,
            "architecture": tech.app_architecture,
            "framework": tech.primary_framework,
            "detected_signals": tech.detected_signals,
            "known_endpoints": known_samples,
            "focus_areas": focus,
        });

        let prompt = format!(
            "Target tech profile:\n{}\n\n\
            Predict up to 10 hidden or undocumented shadow endpoints and RBAC boundaries characteristic of this tech stack.",
            fence_capped(&facts, 2000)
        );

        let res = ask_typed::<Vec<SemanticRoute>>(
            cfg,
            budget,
            &untrusted::system(SEMANTIC_DISCOVERY_ROLE),
            &prompt,
            |routes| {
                if routes.is_empty() {
                    anyhow::bail!("empty semantic routes returned");
                }
                Ok(())
            },
        );

        if let Ok(routes) = res {
            let mapped = convert_to_discovered_routes(&routes, &known_paths);
            if !mapped.is_empty() {
                return mapped;
            }
        }
    }

    // 2. Deterministic framework-adapted semantic heuristics
    let mut candidates: Vec<SemanticRoute> = Vec::new();
    let signals_lower: Vec<String> = tech.detected_signals.iter().map(|s| s.to_lowercase()).collect();
    let fw_lower = tech.primary_framework.to_lowercase();
    let is_spring = fw_lower.contains("spring") || signals_lower.iter().any(|s| s.contains("actuator") || s.contains("spring"));
    let is_express = fw_lower.contains("express") || signals_lower.iter().any(|s| s.contains("node") || s.contains("express"));
    let is_django = fw_lower.contains("django") || signals_lower.iter().any(|s| s.contains("django") || s.contains("python"));
    let is_php = tech.is_php || fw_lower.contains("laravel") || fw_lower.contains("php") || signals_lower.iter().any(|s| s.contains("php") || s.contains("laravel"));

    if is_spring {
        candidates.push(SemanticRoute {
            path: "/actuator/health".into(),
            method: "GET".into(),
            reasoning: "Spring Boot Actuator health probe".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
        candidates.push(SemanticRoute {
            path: "/actuator/info".into(),
            method: "GET".into(),
            reasoning: "Spring Boot Actuator metadata disclosure endpoint".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
        candidates.push(SemanticRoute {
            path: "/actuator/env".into(),
            method: "GET".into(),
            reasoning: "Spring Boot Actuator environment configuration inspection".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
        candidates.push(SemanticRoute {
            path: "/actuator/metrics".into(),
            method: "GET".into(),
            reasoning: "Spring Boot Actuator runtime telemetry metrics".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
    }

    if is_express {
        candidates.push(SemanticRoute {
            path: "/api/health".into(),
            method: "GET".into(),
            reasoning: "Node/Express healthcheck probe".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
        candidates.push(SemanticRoute {
            path: "/metrics".into(),
            method: "GET".into(),
            reasoning: "Prometheus standard telemetry metric path".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
        candidates.push(SemanticRoute {
            path: "/api/version".into(),
            method: "GET".into(),
            reasoning: "Standard Express API version discovery".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
    }

    if is_django {
        candidates.push(SemanticRoute {
            path: "/admin/login/".into(),
            method: "GET".into(),
            reasoning: "Standard Django admin portal login route".into(),
            input_surface: Some("form".into()),
            suggested_params: vec!["username".into(), "password".into()],
        });
        candidates.push(SemanticRoute {
            path: "/api/schema/".into(),
            method: "GET".into(),
            reasoning: "Django REST Framework OpenAPI/Swagger schema exporter".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
    }

    if is_php {
        candidates.push(SemanticRoute {
            path: "/telescope".into(),
            method: "GET".into(),
            reasoning: "Laravel Telescope debug dashboard".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
        candidates.push(SemanticRoute {
            path: "/_ignition/health-check".into(),
            method: "GET".into(),
            reasoning: "Laravel Ignition error handler and healthcheck route".into(),
            input_surface: Some("none".into()),
            suggested_params: vec![],
        });
    }

    // Directives-guided shadow endpoints
    if let Some(dir) = directives {
        for fa in &dir.focus_areas {
            let lower = fa.to_lowercase();
            if lower.contains("tenant") || lower.contains("bola") || lower.contains("idor") {
                candidates.push(SemanticRoute {
                    path: "/api/v1/tenant/settings".into(),
                    method: "GET".into(),
                    reasoning: "BOLA/IDOR tenant boundary inferred from directives".into(),
                    input_surface: Some("none".into()),
                    suggested_params: vec!["tenant_id".into()],
                });
                candidates.push(SemanticRoute {
                    path: "/api/v1/users/{id}/permissions".into(),
                    method: "GET".into(),
                    reasoning: "Authorization privilege escalation route inferred from directives".into(),
                    input_surface: Some("none".into()),
                    suggested_params: vec!["id".into()],
                });
            }
        }
    }

    // Universal baseline shadow API endpoints
    candidates.push(SemanticRoute {
        path: "/api/v1/internal/health".into(),
        method: "GET".into(),
        reasoning: "Standard enterprise internal service health endpoint".into(),
        input_surface: Some("none".into()),
        suggested_params: vec![],
    });
    candidates.push(SemanticRoute {
        path: "/api/v1/status".into(),
        method: "GET".into(),
        reasoning: "API status and health monitoring endpoint".into(),
        input_surface: Some("none".into()),
        suggested_params: vec![],
    });

    convert_to_discovered_routes(&candidates, &known_paths)
}

fn convert_to_discovered_routes(
    candidates: &[SemanticRoute],
    known_paths: &[&str],
) -> Vec<DiscoveredRoute> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for c in candidates {
        let key = format!("{}:{}", c.method.to_uppercase(), c.path);
        if seen.insert(key) && !known_paths.contains(&c.path.as_str()) {
            let has_body = matches!(c.method.as_str(), "POST" | "PUT" | "PATCH");
            let surface = if has_body {
                InputSurface::Json
            } else if !c.suggested_params.is_empty() {
                InputSurface::Query
            } else {
                InputSurface::None
            };

            out.push(DiscoveredRoute {
                path: c.path.clone(),
                method: c.method.clone(),
                status_code: 200,
                content_type: "application/json".to_string(),
                is_spa_shell: false,
                is_api: true,
                title: Some(format!("Semantic shadow route: {}", c.reasoning)),
                has_form: matches!(c.input_surface.as_deref(), Some("form")),
                secured: Some(true),
                has_body,
                source: "semantic".to_string(),
                final_url: None,
                redirect_chain: Vec::new(),
                auth_wall: false,
                catch_all: false,
                input_surface: surface,
            });
        }
    }

    out
}
