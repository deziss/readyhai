//! Dynamic agent directives synthesis and target reconnaissance models.

use anyhow::{Context, Result};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::llm::untrusted::{self, clean, fence_capped};
use crate::llm::{Budget, LlmConfig, ask_typed};

/// Synthesized security directives governing the agent's exploration and testing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedDirectives {
    pub focus_areas: Vec<String>,
    pub boundary_rules: Vec<String>,
    pub rules_of_engagement: String,
    pub canary_token: String,
}

impl SynthesizedDirectives {
    pub fn new(
        focus_areas: Vec<String>,
        boundary_rules: Vec<String>,
        rules_of_engagement: String,
        canary_token: String,
    ) -> Self {
        Self {
            focus_areas,
            boundary_rules,
            rules_of_engagement,
            canary_token,
        }
    }

    /// Formats the directives into a structured system prompt / custom instructions string.
    pub fn as_custom_instructions(&self) -> String {
        let mut out = String::new();
        out.push_str("=== RULES OF ENGAGEMENT ===\n");
        out.push_str(&self.rules_of_engagement);
        out.push_str("\n\n=== FOCUS AREAS ===\n");
        for fa in &self.focus_areas {
            out.push_str(&format!("- {fa}\n"));
        }
        out.push_str("\n=== BOUNDARY RULES ===\n");
        for br in &self.boundary_rules {
            out.push_str(&format!("- {br}\n"));
        }
        out.push_str("\n=== CANARY TOKEN ===\n");
        out.push_str(&format!("Canary: {}\n", self.canary_token));
        out
    }
}

/// Fingerprinting and security posture observation from pre-flight reconnaissance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetRecon {
    pub target: String,
    pub server: Option<String>,
    pub tech_signals: Vec<String>,
    pub security_headers_missing: Vec<String>,
    pub cookies: Vec<String>,
    pub status_code: Option<u16>,
}

/// Generates a deterministic, collision-resistant canary token for target boundary verification.
pub fn generate_canary_token(target: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(target.as_bytes());
    hasher.update(b"readyhai-canary-recon-directive");
    let result = hasher.finalize();
    format!(
        "CANARY_RECON_{:08X}",
        u32::from_be_bytes(result[0..4].try_into().unwrap_or([0x7A, 0x3B, 0x00, 0x01]))
    )
}

/// Helper to populate `TargetRecon` fields from observed headers and status code.
pub fn populate_recon_from_headers(
    recon: &mut TargetRecon,
    headers: &HeaderMap,
    status: Option<u16>,
) {
    recon.status_code = status;

    if let Some(srv) = headers.get(reqwest::header::SERVER).and_then(|v| v.to_str().ok()) {
        recon.server = Some(srv.to_string());
        recon.tech_signals.push(format!("Server: {srv}"));
    }

    if let Some(powered) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        recon.tech_signals.push(format!("X-Powered-By: {powered}"));
    }

    // Check for cookies
    for cookie_header in headers.get_all(reqwest::header::SET_COOKIE) {
        if let Ok(c_str) = cookie_header.to_str() {
            let cookie_name = c_str.split(';').next().unwrap_or("").trim().to_string();
            if !cookie_name.is_empty() {
                recon.cookies.push(cookie_name);
            }
        }
    }

    // Standard defensive security headers
    let expected_sec_headers = [
        ("content-security-policy", "Content-Security-Policy (CSP)"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("strict-transport-security", "Strict-Transport-Security (HSTS)"),
        ("x-frame-options", "X-Frame-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ];

    for (header_key, header_label) in expected_sec_headers {
        if !headers.contains_key(header_key) {
            recon.security_headers_missing.push(header_label.to_string());
        }
    }
}

/// Probes the target or evaluates provided headers to build pre-flight reconnaissance.
pub fn probe_target_recon(target: &str, headers: Option<&HeaderMap>) -> TargetRecon {
    let mut recon = TargetRecon {
        target: target.to_string(),
        ..Default::default()
    };

    if let Some(h) = headers {
        populate_recon_from_headers(&mut recon, h, None);
        return recon;
    }

    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build();

    if let Ok(cl) = client
        && let Ok(resp) = cl.get(target).send()
    {
        let status = resp.status().as_u16();
        let resp_headers = resp.headers().clone();
        populate_recon_from_headers(&mut recon, &resp_headers, Some(status));
    }

    recon
}

/// Parses raw LLM JSON response into `SynthesizedDirectives`.
pub fn parse_directives_response(raw: &str) -> Result<SynthesizedDirectives> {
    let cleaned = raw.trim();
    // Strip markdown json block fences if present
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

    let directives: SynthesizedDirectives =
        serde_json::from_str(json_str.trim()).context("failed to deserialize SynthesizedDirectives")?;

    if directives.focus_areas.is_empty() {
        anyhow::bail!("synthesized directives contain empty focus_areas");
    }

    Ok(directives)
}

const DIRECTIVES_SYNTHESIZER_ROLE: &str = "\
You are a Principal Security Architect and Autonomous QA Directives Engine. \
Analyze target reconnaissance data, technology signals, and API specifications to synthesize \
custom Rules of Engagement, critical security focus areas, boundary guardrails, and canary verification tokens. \
Return ONLY valid JSON matching this schema: \
{\
  \"focus_areas\": [\"string\"],\
  \"boundary_rules\": [\"string\"],\
  \"rules_of_engagement\": \"string\",\
  \"canary_token\": \"string\"\
}";

/// Synthesizes dynamic agent directives using LLM reasoning when available, falling back
/// deterministically to recon-based rules.
pub fn synthesize_directives(
    mut llm: Option<(&LlmConfig, &mut Budget)>,
    target: &str,
    spec_url: Option<&str>,
    headers: Option<&HeaderMap>,
) -> SynthesizedDirectives {
    let recon = probe_target_recon(target, headers);
    let default_canary = generate_canary_token(target);

    // If LLM is available, attempt multi-factor directive synthesis
    if let Some((cfg, ref mut budget)) = llm.take() {
        let recon_facts = serde_json::json!({
            "target": target,
            "spec_url": spec_url,
            "server": recon.server,
            "tech_signals": recon.tech_signals,
            "missing_security_headers": recon.security_headers_missing,
            "cookies": recon.cookies,
            "suggested_canary": default_canary,
        });

        let prompt = format!(
            "Target Reconnaissance:\n{}\n\n\
            Synthesize adversarial directives for an autonomous security software factory testing this target.\n\
            Emphasize critical authorization boundaries (BOLA/IDOR), token handling, input sanitization, \
            and strict boundary guardrails preventing uncontained damage. Use the suggested canary token if suitable.",
            fence_capped(&recon_facts, 2000)
        );

        let res = ask_typed::<SynthesizedDirectives>(
            cfg,
            budget,
            &untrusted::system(DIRECTIVES_SYNTHESIZER_ROLE),
            &prompt,
            |d| {
                if d.focus_areas.is_empty() || d.boundary_rules.is_empty() || d.rules_of_engagement.is_empty() {
                    anyhow::bail!("incomplete directives synthesized by LLM");
                }
                Ok(())
            },
        );

        if let Ok(mut directives) = res {
            if directives.canary_token.trim().is_empty() {
                directives.canary_token = default_canary;
            }
            return directives;
        }
    }

    // Deterministic fallback synthesis based on recon findings
    let mut focus_areas = Vec::new();
    let mut boundary_rules = Vec::new();

    // Default high-impact security focus areas
    focus_areas.push("BOLA/IDOR authorization boundaries on resource endpoints".to_string());
    focus_areas.push("JWT algorithm confusion and weak authentication boundaries".to_string());
    focus_areas.push("Input sanitization, injection vectors, and boundary limits".to_string());

    if !recon.security_headers_missing.is_empty() {
        focus_areas.push(format!(
            "Missing defensive headers evaluation: {}",
            recon.security_headers_missing.join(", ")
        ));
    }

    if !recon.cookies.is_empty() {
        focus_areas.push("Session cookie security, SameSite enforcement, and CSRF protection".to_string());
    }

    if spec_url.is_some() {
        focus_areas.push("OpenAPI specification schema conformance and unexpected parameter injection".to_string());
    }

    focus_areas.push("Prompt injection canary and LLM interface boundaries".to_string());

    boundary_rules.push("Stay strictly within target origin and API path prefixes".to_string());
    boundary_rules.push("Do not fuzz destructive deletion or unconfirmed data purging".to_string());
    boundary_rules.push("Honor rate limits and abort on consecutive 429/503 responses".to_string());
    boundary_rules.push(format!("Use canary token {} for input taint tracking", default_canary));

    let rules_of_engagement = format!(
        "Autonomous adversarial QA assessment targeting authorization boundaries, input sanitization, and state integrity on {target}"
    );

    SynthesizedDirectives {
        focus_areas,
        boundary_rules,
        rules_of_engagement,
        canary_token: default_canary,
    }
}
