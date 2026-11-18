use super::*;
use reqwest::header::{HeaderMap, HeaderValue};

#[test]
fn test_parse_synthesized_directives_json() {
    let raw = r#"{
        "focus_areas": ["BOLA/IDOR on /api/v1/tenant", "JWT algorithm confusion", "Prompt injection canary"],
        "boundary_rules": ["Stay within /api paths", "Do not fuzz destructive deletion"],
        "rules_of_engagement": "Adversarial assessment targeting authorization boundaries and input sanitization",
        "canary_token": "CANARY_RECON_7A3B"
    }"#;
    let res = super::directives::parse_directives_response(raw).expect("parse failed");
    assert_eq!(res.focus_areas.len(), 3);
    assert_eq!(res.canary_token, "CANARY_RECON_7A3B");
    assert!(res.as_custom_instructions().contains("BOLA/IDOR"));
    assert!(res.as_custom_instructions().contains("CANARY_RECON_7A3B"));
}

#[test]
fn test_parse_synthesized_directives_with_markdown_fence() {
    let raw = r#"```json
    {
        "focus_areas": ["Rate limit boundary spikers", "GraphQL query depth attack"],
        "boundary_rules": ["Stay within scope"],
        "rules_of_engagement": "Adversarial readiness test",
        "canary_token": "CANARY_RECON_F1E2"
    }
    ```"#;
    let res = super::directives::parse_directives_response(raw).expect("parse fenced json failed");
    assert_eq!(res.focus_areas.len(), 2);
    assert_eq!(res.canary_token, "CANARY_RECON_F1E2");
}

#[test]
fn test_probe_target_recon_with_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::SERVER, HeaderValue::from_static("nginx/1.24.0"));
    headers.insert(reqwest::header::SET_COOKIE, HeaderValue::from_static("session_id=abc123; HttpOnly; Secure"));
    headers.insert(
        reqwest::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'"),
    );

    let recon = probe_target_recon("https://api.example.com", Some(&headers));
    assert_eq!(recon.server.as_deref(), Some("nginx/1.24.0"));
    assert_eq!(recon.cookies, vec!["session_id=abc123"]);
    assert!(recon.tech_signals.iter().any(|s| s.contains("nginx")));
    // Since CSP was provided, CSP should NOT be in security_headers_missing
    assert!(!recon.security_headers_missing.iter().any(|h| h.contains("CSP")));
    // But other headers like HSTS, X-Frame-Options should be listed as missing
    assert!(recon.security_headers_missing.iter().any(|h| h.contains("HSTS")));
}

#[test]
fn test_synthesize_directives_deterministic() {
    let directives = synthesize_directives(None, "https://api.example.com", Some("https://api.example.com/openapi.json"), None);
    assert!(!directives.focus_areas.is_empty());
    assert!(!directives.boundary_rules.is_empty());
    assert!(!directives.rules_of_engagement.is_empty());
    assert!(directives.canary_token.starts_with("CANARY_RECON_"));
    assert!(directives.focus_areas.iter().any(|f| f.contains("BOLA/IDOR")));
    assert!(directives.focus_areas.iter().any(|f| f.contains("OpenAPI")));

    let instructions = directives.as_custom_instructions();
    assert!(instructions.contains("=== RULES OF ENGAGEMENT ==="));
    assert!(instructions.contains("=== FOCUS AREAS ==="));
    assert!(instructions.contains("=== BOUNDARY RULES ==="));
    assert!(instructions.contains(&directives.canary_token));
}
