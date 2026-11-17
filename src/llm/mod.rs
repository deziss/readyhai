//! LLM provider abstraction plus a single-shot strict-JSON layer (ask_json) for the optional LAN LLM.
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod budget;
pub mod catalog;
pub mod client;
pub mod config;
pub mod probe;
pub mod redact;
pub mod untrusted;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
mod tests;

pub use budget::{
    Budget, CallParams, ask_json, ask_json_with, ask_typed, call_params, parse_json_object,
    strip_think, write_atomic,
};
pub use catalog::{
    ANSWER_HEADROOM, CATALOG, CALL_SHARE_OF_BUDGET, CHAT_MAX_TOKENS, CLIENT_BACKSTOP_SECS,
    DOWNGRADE_FLOOR_TOKENS, ENV_ALLOW_CLOUD, ENV_API_KEY, ENV_MODEL, ENV_MODELS, ENV_PROVIDER,
    ENV_TIMEOUT_SECS, ENV_URL, HIGH_TIER_BUDGET, LATENCY_PROBE_TIMEOUT, MAX_OUTPUT_TOKENS,
    MAX_SERVER_ERROR_RETRIES, MAX_THINKING_BUDGET, MAX_TIMEOUT_DOWNGRADES, MIN_CALL_SECS,
    MIN_THINKING_BUDGET, ProviderDescriptor, SLOW_LATENCY, STRUCTURED_TEMPERATURE, Transport,
    call_timeout_secs, clamp_thinking_budget, max_tokens_with_thinking, provider,
};
pub use client::{
    AnthropicClient, ChatClient, Msg, OpenAiClient, Reply, ToolCall, ToolDef, client,
    is_timeout_error, key_configured,
};
pub use config::{
    ApiKey, LlmConfig, container_loopback_to_host, env_requested, is_public_host, parse_model_list,
    public_host_of, validate_base_url,
};
pub use probe::{LatencyReport, latency_report, probe, probe_latency, probe_status, query_models};
pub use redact::{is_sensitive_key, redact_for_llm, redact_value, redact_value_capped};
