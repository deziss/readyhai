use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Default, Deserialize)]
pub struct UiReport {
    #[serde(default)]
    pub pages: Vec<UiPage>,
    #[serde(default)]
    pub forms: Vec<UiForm>,
    #[serde(default)]
    pub journeys: Vec<UiJourney>,
    #[serde(default)]
    pub state_graph: Option<UiStateGraph>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct UiStateGraph {
    #[serde(default)]
    pub states: Vec<UiStateNode>,
    #[serde(default)]
    pub transitions: Vec<UiStateTransition>,
    #[serde(default)]
    pub dead_ends: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Default, Deserialize, Clone)]
pub struct UiStateNode {
    pub id: String,
    pub route: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub dom_fingerprint: String,
    #[serde(default)]
    pub interactive_elements: usize,
    #[serde(default)]
    pub dead_end: bool,
}

#[allow(dead_code)]
#[derive(Debug, Default, Deserialize, Clone)]
pub struct UiStateTransition {
    pub from: String,
    pub to: String,
    pub action: String,
    pub target: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiPage {
    pub url: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub viewports: BTreeMap<String, UiViewport>,
    #[serde(default)]
    pub axe: Option<Vec<UiAxe>>,
    #[serde(default)]
    pub vitals: Option<UiVitals>,
    #[serde(default)]
    pub shots: Vec<UiShot>,
    /// HTTP status of the navigation (0 = no response). None when the runner did not report it.
    #[serde(default)]
    pub status: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiViewport {
    #[serde(default)]
    pub overflow: bool,
    #[serde(default)]
    pub scroll_width: u32,
    #[serde(default)]
    pub inner_width: u32,
    #[serde(default)]
    pub clipped: Vec<serde_json::Value>,
    #[serde(default)]
    pub small_targets: u32,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiAxe {
    pub id: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub help: String,
    #[serde(default)]
    pub nodes: u32,
    #[serde(default)]
    pub target: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiVitals {
    #[serde(default)]
    pub lcp_ms: f64,
    #[serde(default)]
    pub cls: f64,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiShot {
    pub viewport: u32,
    pub file: String,
    #[serde(default)]
    pub diff_ratio: Option<f64>,
    #[serde(default)]
    pub diff_file: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiForm {
    pub page: String,
    pub form: String,
    pub field: String,
    pub value_kind: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub client_blocked: bool,
    #[serde(default)]
    pub server_status: Option<u16>,
    #[serde(default)]
    pub error_shown: bool,
    #[serde(default)]
    pub gap: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiJourney {
    pub name: String,
    pub role: String,
    pub status: String,
    #[serde(default)]
    pub failed_step: Option<usize>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub trace: Option<String>,
    #[serde(default)]
    pub screenshot: Option<String>,
    #[serde(default)]
    pub healed_locators: Vec<UiHealedLocator>,
}

#[allow(dead_code)]
#[derive(Debug, Default, Deserialize, Clone)]
pub struct UiHealedLocator {
    #[serde(default)]
    pub original: String,
    #[serde(default)]
    pub healed_by: String,
    #[serde(default)]
    pub healed_selector: String,
}
