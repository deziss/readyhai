//! Target discovery, route detection, and technology profiling data models.

use serde::{Deserialize, Serialize};

/// One hop of a redirect chain: the status that redirected and where it pointed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedirectHop {
    pub status: u16,
    pub location: String,
}

/// Where a route takes input. `None` = nothing an input-class test (injection, boundary,
/// negative) could exercise, so those techniques are not planned there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSurface {
    #[default]
    None,
    Query,
    Form,
    Json,
    Spec,
}

/// Soft-404 calibration: how the target answers paths that cannot exist. A route whose response
/// matches is a catch-all (SPA shell / custom not-found page), not a real route.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Soft404Fingerprint {
    pub status: u16,
    /// Body length in bytes (matching allows a +/-5% tolerance).
    pub len: usize,
    /// Hash of the normalised visible text (tokens, numbers, timestamps stripped).
    pub text_hash: String,
}

/// Why a case could not produce evidence. A BLOCKED case is not a failure and not a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// The route sits behind a login wall and no role/credential was provided.
    AuthWall,
    /// The request would leave the allowed scope.
    OutOfScope,
    /// Nothing on the route accepts input for this technique.
    NoSurface,
    /// Transport error: no HTTP answer.
    Transport,
}

/// Something that kept the run from gathering evidence, and what the user can do about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocker {
    pub reason: BlockReason,
    pub detail: String,
    pub next_step: String,
    #[serde(default)]
    pub case_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveredRoute {
    pub path: String,
    pub method: String,
    pub status_code: u16,
    pub content_type: String,
    pub is_spa_shell: bool,
    pub is_api: bool,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub has_form: bool,
    /// From the OpenAPI spec: does the operation declare security? None = no spec information.
    #[serde(default)]
    pub secured: Option<bool>,
    #[serde(default)]
    pub has_body: bool,
    /// crawl | probe | openapi | manifest | js | sitemap | xhr
    #[serde(default)]
    pub source: String,
    /// URL the route finally answered from after same-origin redirects (None: no redirect).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    /// Redirect hops before the final answer; `status_code` is the FIRST hop's status.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_chain: Vec<RedirectHop>,
    /// 401, or a redirect to a login/sign-in/SSO page, or a password form: needs credentials.
    #[serde(default)]
    pub auth_wall: bool,
    /// The response matches the soft-404 fingerprint: not a real route.
    #[serde(default)]
    pub catch_all: bool,
    #[serde(default)]
    pub input_surface: InputSurface,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTechProfile {
    pub is_spa: bool,
    pub app_architecture: String,
    pub primary_framework: String,
    pub detected_signals: Vec<String>,
    pub is_php: bool,
    pub is_api_only: bool,
}

impl Default for TargetTechProfile {
    fn default() -> Self {
        Self {
            is_spa: false,
            app_architecture: "Traditional Web / API".to_string(),
            primary_framework: "Unknown".to_string(),
            detected_signals: vec![],
            is_php: false,
            is_api_only: false,
        }
    }
}
