//! Default value provider functions for serde deserialization.

pub fn default_true() -> bool {
    true
}

pub fn default_model_tier() -> String {
    "high".to_string()
}

pub fn default_reasoning_tokens() -> u32 {
    8192
}

pub fn default_profile() -> String {
    "standard".to_string()
}

pub fn default_method() -> String {
    "GET".to_string()
}

pub fn default_oast_wait_ms() -> u64 {
    350
}
