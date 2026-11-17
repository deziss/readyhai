//! LLM provider metadata catalog, transport definitions, and constants.

use std::time::Duration;

/// Smallest reasoning budget Anthropic accepts.
pub const MIN_THINKING_BUDGET: u32 = 1024;
/// Largest reasoning budget a run may ask for, whatever the request says.
pub const MAX_THINKING_BUDGET: u32 = 32_768;
/// Room left for the JSON answer after the reasoning budget.
pub const ANSWER_HEADROOM: u32 = 2048;
/// Hard ceiling for `max_tokens` on any call.
pub const MAX_OUTPUT_TOKENS: u32 = MAX_THINKING_BUDGET + ANSWER_HEADROOM + 6144;
/// Temperature of every structured planning / triage / verdict call.
pub const STRUCTURED_TEMPERATURE: f64 = 0.1;

/// Clamp a requested reasoning budget into `MIN_THINKING_BUDGET..=MAX_THINKING_BUDGET`.
pub fn clamp_thinking_budget(n: u32) -> u32 {
    n.clamp(MIN_THINKING_BUDGET, MAX_THINKING_BUDGET)
}

/// `max_tokens` for a call that reasons: budget + answer headroom, saturating and capped
/// (`budget + 2048` used to overflow `u32` for a hostile budget).
pub fn max_tokens_with_thinking(budget: u32) -> u32 {
    clamp_thinking_budget(budget)
        .saturating_add(ANSWER_HEADROOM)
        .min(MAX_OUTPUT_TOKENS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    OpenAiChat,
    AnthropicMessages,
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderDescriptor {
    pub id: &'static str,
    /// Extra ids that select this same descriptor (`READYHAI_LLM_PROVIDER=custom`).
    pub aliases: &'static [&'static str],
    pub transport: Transport,
    pub base_url: &'static str,
    /// Deprecated provider-specific URL variable, read only when `READYHAI_LLM_URL` is unset. The generic
    /// provider keeps `READYHAI_VLLM_URL` here; its `base_url` is empty on purpose (no baked-in LAN address).
    pub legacy_url_env: Option<&'static str>,
    pub api_key_env: Option<&'static str>,
    pub default_model: &'static str,
    pub local: bool,
}

/// Generic base-URL override, valid for every provider (OpenAI-compatible or Anthropic transport).
pub const ENV_URL: &str = "READYHAI_LLM_URL";
/// Generic API key, valid for every provider; wins over the provider's own key variable.
pub const ENV_API_KEY: &str = "READYHAI_LLM_API_KEY";
/// Model, or a comma-separated list: the first is primary, the rest are tried in order on failure.
pub const ENV_MODEL: &str = "READYHAI_LLM_MODEL";
/// Alias of [`ENV_MODEL`], read only when that one is unset.
pub const ENV_MODELS: &str = "READYHAI_LLM_MODELS";
pub const ENV_PROVIDER: &str = "READYHAI_LLM_PROVIDER";
pub const ENV_ALLOW_CLOUD: &str = "READYHAI_LLM_ALLOW_CLOUD";
/// Fixed per-call timeout in whole seconds, replacing the size-based one (see [`call_timeout_secs`]).
pub const ENV_TIMEOUT_SECS: &str = "READYHAI_LLM_TIMEOUT_SECS";
/// Shortest timeout a call is given, even when its share of the run budget is smaller.
pub const MIN_CALL_SECS: u64 = 10;
/// Share of the run's remaining LLM time one call (with its retries) may use.
pub const CALL_SHARE_OF_BUDGET: f64 = 0.6;

/// Per-call timeout for a request that may produce `max_tokens` tokens: `20 s + max_tokens / 40`
/// (a slow server makes about 40 tokens/s), clamped to 30..=300 s. A fixed 60 s killed every
/// reasoning call (Max Pro asks for ~35k tokens) while a 1-token probe does not need minutes.
pub fn call_timeout_secs(max_tokens: u32) -> u64 {
    (20 + u64::from(max_tokens) / 40).clamp(30, 300)
}

/// Reachability / latency probe ceiling: a slower answer than this is reported as a timeout.
pub const LATENCY_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// A probe answer slower than this means long reasoning calls will not fit (see `probe_latency`).
pub const SLOW_LATENCY: Duration = Duration::from_secs(10);
/// Thinking budget of the High tier, the ceiling a slow endpoint is held to.
pub const HIGH_TIER_BUDGET: u32 = 8192;
/// After a timeout a call is retried smaller at most this many times before the next model is tried.
pub const MAX_TIMEOUT_DOWNGRADES: usize = 2;
/// Smallest `max_tokens` a timeout downgrade goes down to.
pub const DOWNGRADE_FLOOR_TOKENS: u32 = 1024;
/// A server error (5xx) is retried once, then the next model in the chain is tried.
pub const MAX_SERVER_ERROR_RETRIES: u32 = 1;

/// Client-level timeout of structured calls: only a backstop, every request sets its own.
pub const CLIENT_BACKSTOP_SECS: u64 = 3660;

/// `max_tokens` the tool-calling chat clients ask for (Anthropic sends it; OpenAI-compatible servers
/// default to something comparable): the size their timeout is derived from.
pub const CHAT_MAX_TOKENS: u32 = 4096;

pub const CATALOG: &[ProviderDescriptor] = &[
    ProviderDescriptor {
        id: "ollama",
        aliases: &[],
        transport: Transport::OpenAiChat,
        base_url: "http://localhost:11434/v1",
        legacy_url_env: None,
        api_key_env: None,
        default_model: "qwen2.5-coder",
        local: true,
    },
    // The generic OpenAI-compatible provider (vLLM, LiteLLM, llama.cpp, TGI, a gateway ...). The id
    // stays "vllm" for reports and saved runs; it needs READYHAI_LLM_URL because it has no address.
    ProviderDescriptor {
        id: "vllm",
        aliases: &["openai-compatible", "custom"],
        transport: Transport::OpenAiChat,
        base_url: "",
        legacy_url_env: Some("READYHAI_VLLM_URL"),
        api_key_env: None,
        default_model: "qwen3.8-flash-next",
        local: true,
    },
    ProviderDescriptor {
        id: "openai",
        aliases: &[],
        transport: Transport::OpenAiChat,
        base_url: "https://api.openai.com/v1",
        legacy_url_env: None,
        api_key_env: Some("OPENAI_API_KEY"),
        default_model: "gpt-4.1",
        local: false,
    },
    ProviderDescriptor {
        id: "anthropic",
        aliases: &[],
        transport: Transport::AnthropicMessages,
        base_url: "https://api.anthropic.com",
        legacy_url_env: None,
        api_key_env: Some("ANTHROPIC_API_KEY"),
        default_model: "claude-sonnet-5-5",
        local: false,
    },
    ProviderDescriptor {
        id: "openrouter",
        aliases: &[],
        transport: Transport::OpenAiChat,
        base_url: "https://openrouter.ai/api/v1",
        legacy_url_env: None,
        api_key_env: Some("OPENROUTER_API_KEY"),
        default_model: "anthropic/claude-sonnet-5-5",
        local: false,
    },
];

/// The provider with this id or alias (case-insensitive).
pub fn provider(id: &str) -> Option<&'static ProviderDescriptor> {
    let id = id.trim().to_ascii_lowercase();
    CATALOG
        .iter()
        .find(|p| p.id == id || p.aliases.contains(&id.as_str()))
}

/// Every accepted provider id, aliases included, for error messages.
pub fn provider_ids() -> String {
    CATALOG
        .iter()
        .flat_map(|p| std::iter::once(p.id).chain(p.aliases.iter().copied()))
        .collect::<Vec<_>>()
        .join(", ")
}
