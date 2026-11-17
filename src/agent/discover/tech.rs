//! Target technology and application framework fingerprinting.
use serde_json::Value;
use std::collections::BTreeMap;

use crate::agent::types::{DiscoveredRoute, TargetTechProfile};

/// An OpenAPI document found for the target.
#[derive(Debug, Clone)]
pub struct SpecDoc {
    pub doc: Value,
    pub ops: Vec<crate::qa::plan::Op>,
    /// Path prefix from `servers[0].url` (e.g. "/api/v1"), "" when none.
    pub base_path: String,
    pub source: String,
}

impl SpecDoc {
    /// The operations in the QA engine's model (parameters, body and response schemas): the form
    /// its shared generators and validators take. Empty when the document is not OpenAPI 3.x.
    pub fn api_ops(&self) -> Vec<crate::qa::api::spec::Op> {
        crate::qa::api::spec::parse(self.doc.clone())
            .map(|s| s.ops)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub routes: Vec<DiscoveredRoute>,
    pub tech: TargetTechProfile,
    pub spec: Option<SpecDoc>,
    pub notes: Vec<String>,
    /// Ids of records that exist, by spec collection path (`/orders` -> ["1", "2"]), read from the
    /// collection endpoints by [`harvest_ids`]. Empty until then.
    pub ids: BTreeMap<String, Vec<String>>,
    /// How the target answers paths that cannot exist (None: not calibrated).
    pub soft404: Option<crate::agent::types::Soft404Fingerprint>,
    /// API hosts referenced by the app (JS chunks, XHR) that are outside scope: reported, never called.
    pub api_hosts_seen: Vec<String>,
    /// API hosts referenced by the app that scope.toml lists explicitly. Requests of the agent go
    /// to the target origin only, so these are reported (and probed for a spec), not tested.
    pub api_hosts_in_scope: Vec<String>,
}

pub fn detect_target_tech(
    headers: &reqwest::header::HeaderMap,
    body: &str,
    status_code: u16,
    content_type: &str,
) -> TargetTechProfile {
    let body_lower = body.to_lowercase();
    let set_cookie = headers
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let x_powered_by = headers
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let expires = headers
        .get("expires")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut signals = Vec::new();

    // 1. PHP signatures
    let has_phpsessid = set_cookie.contains("PHPSESSID");
    let has_php_expires = expires.contains("Thu, 19 Nov 1981");
    let has_php_powered = x_powered_by.to_lowercase().contains("php");
    let has_php_links = body_lower.contains(".php");
    let has_wordpress = body_lower.contains("/wp-content/themes/")
        || body_lower.contains("/wp-content/plugins/")
        || body_lower.contains("/wp-includes/")
        || set_cookie.contains("wordpress_");
    let has_laravel = set_cookie.contains("laravel_session")
        || set_cookie.contains("XSRF-TOKEN")
        || body_lower.contains("laravel");

    let is_php = has_phpsessid
        || has_php_expires
        || has_php_powered
        || has_php_links
        || has_wordpress
        || has_laravel;
    if has_phpsessid {
        signals.push("PHPSESSID session cookie active".to_string());
    }
    if has_php_expires {
        signals.push("Standard PHP session_start cache limiter headers detected".to_string());
    }
    if has_php_powered {
        signals.push(format!("X-Powered-By: {}", x_powered_by));
    }
    if has_wordpress {
        signals.push("WordPress theme & plugin assets identified".to_string());
    }
    if has_laravel {
        signals.push("Laravel session / CSRF token cookies detected".to_string());
    }
    let mk =
        |is_spa: bool, arch: &str, fw: &str, signals: Vec<String>, is_php: bool, api_only: bool| {
            TargetTechProfile {
                is_spa,
                app_architecture: arch.to_string(),
                primary_framework: fw.to_string(),
                detected_signals: signals,
                is_php,
                is_api_only: api_only,
            }
        };
    if is_php {
        let (arch, fw) = if has_wordpress {
            ("WordPress (PHP/HTML MPA)", "WordPress")
        } else if has_laravel {
            ("Laravel (PHP/HTML MPA)", "Laravel")
        } else {
            ("PHP & HTML (Server-Side MPA)", "PHP")
        };
        return mk(false, arch, fw, signals, true, false);
    }

    // 2. Python / Django / Flask
    if set_cookie.contains("csrftoken")
        || set_cookie.contains("sessionid")
        || server.to_lowercase().contains("gunicorn")
    {
        signals.push("Django / Python session cookie and WSGI headers detected".to_string());
        return mk(
            false,
            "Python (Django/HTML MPA)",
            "Django",
            signals,
            false,
            false,
        );
    }
    // 3. Java / Spring
    if set_cookie.contains("JSESSIONID") {
        signals.push("Java / Spring JSESSIONID cookie detected".to_string());
        return mk(
            false,
            "Java / Spring (HTML MPA)",
            "Spring",
            signals,
            false,
            false,
        );
    }
    // 4. SPA signatures
    let has_next = body.contains("__NEXT_DATA__") || body.contains("/_next/static/");
    let has_nuxt =
        body.contains("__NUXT__") || body.contains("/_nuxt/") || body.contains("data-v-");
    let has_angular = body.contains("ng-version") || body.contains("<app-root");
    let has_react = body.contains("data-reactroot") || body.contains("react-dom");
    let has_svelte = body.contains("__sveltekit") || body.contains("svelte-");
    let has_vite = body.contains("/@vite/client") || body.contains("/src/main.tsx");
    if has_next {
        signals.push(
            "Next.js hydration payload (__NEXT_DATA__) and static chunks detected".to_string(),
        );
        return mk(
            true,
            "SPA (Next.js/React)",
            "Next.js",
            signals,
            false,
            false,
        );
    }
    if has_nuxt {
        signals.push("Nuxt / Vue client hydration bundle detected".to_string());
        return mk(true, "SPA (Nuxt/Vue)", "Nuxt/Vue", signals, false, false);
    }
    if has_angular {
        signals.push("Angular ng-version runtime and <app-root> tag detected".to_string());
        return mk(true, "SPA (Angular)", "Angular", signals, false, false);
    }
    if has_react || has_vite {
        signals.push("Client-side React virtual DOM / Vite client bundle detected".to_string());
        return mk(true, "SPA (React)", "React", signals, false, false);
    }
    if has_svelte {
        signals.push("SvelteKit client hydration detected".to_string());
        return mk(true, "SPA (SvelteKit)", "SvelteKit", signals, false, false);
    }
    // 5. REST API
    let is_json = content_type.contains("application/json")
        || content_type.contains("application/problem+json");
    if is_json || (status_code == 401 && !content_type.contains("text/html")) {
        signals.push("JSON Content-Type response without HTML rendering detected".to_string());
        return mk(false, "REST API (JSON)", "REST API", signals, false, true);
    }
    // 6. server-rendered HTML
    signals.push(
        "Server-side rendered HTML5 markup; zero client-side SPA hydration scripts".to_string(),
    );
    mk(
        false,
        "Traditional Web App (HTML5/SSR)",
        "HTML5",
        signals,
        false,
        false,
    )
}
