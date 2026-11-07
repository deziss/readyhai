//! LLM provider abstraction plus a single-shot strict-JSON layer (ask_json) for the optional LAN LLM.
#![allow(dead_code)]
use anyhow::{Result, bail};
use regex::Regex;
use serde_json::{Value, json};
use std::sync::OnceLock;
use std::time::Duration;

pub mod untrusted;

/// Smallest reasoning budget Anthropic accepts.
pub const MIN_THINKING_BUDGET: u32 = 1024;
/// Largest reasoning budget a run may ask for, whatever the request says.
pub const MAX_THINKING_BUDGET: u32 = 32_768;
/// Room left for the JSON answer after the reasoning budget.
const ANSWER_HEADROOM: u32 = 2048;
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
const MIN_CALL_SECS: u64 = 10;
/// Share of the run's remaining LLM time one call (with its retries) may use.
const CALL_SHARE_OF_BUDGET: f64 = 0.6;

/// Per-call timeout for a request that may produce `max_tokens` tokens: `20 s + max_tokens / 40`
/// (a slow server makes about 40 tokens/s), clamped to 30..=300 s. A fixed 60 s killed every
/// reasoning call (Max Pro asks for ~35k tokens) while a 1-token probe does not need minutes.
pub fn call_timeout_secs(max_tokens: u32) -> u64 {
    (20 + u64::from(max_tokens) / 40).clamp(30, 300)
}

/// Reachability / latency probe ceiling: a slower answer than this is reported as a timeout.
const LATENCY_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// A probe answer slower than this means long reasoning calls will not fit (see `probe_latency`).
pub const SLOW_LATENCY: Duration = Duration::from_secs(10);
/// Thinking budget of the High tier, the ceiling a slow endpoint is held to.
pub const HIGH_TIER_BUDGET: u32 = 8192;
/// After a timeout a call is retried smaller at most this many times before the next model is tried.
const MAX_TIMEOUT_DOWNGRADES: usize = 2;
/// Smallest `max_tokens` a timeout downgrade goes down to.
const DOWNGRADE_FLOOR_TOKENS: u32 = 1024;
/// A server error (5xx) is retried once, then the next model in the chain is tried.
const MAX_SERVER_ERROR_RETRIES: u32 = 1;

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
fn provider_ids() -> String {
    CATALOG
        .iter()
        .flat_map(|p| std::iter::once(p.id).chain(p.aliases.iter().copied()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A credential. `Debug` never shows the value, so a config can be logged or put in an error.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(k: impl Into<String>) -> Self {
        ApiKey(k.into())
    }
    /// The raw value. Only the code that builds a request header should call this.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

/// Split a model setting on commas: trimmed, empties dropped, duplicates removed, order kept.
pub fn parse_model_list(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in s.split(',').map(str::trim).filter(|m| !m.is_empty()) {
        if !out.iter().any(|x| x == m) {
            out.push(m.to_string());
        }
    }
    out
}

/// Parse a configured base URL: http(s), with a host, and nothing secret in it (credentials belong in
/// `READYHAI_LLM_API_KEY`; a query string would also break the paths appended to it). The message never
/// echoes the value, so a mistyped secret does not reach a log. Returns the trimmed original text.
pub fn validate_base_url(raw: &str) -> Result<String> {
    let t = raw.trim();
    let Ok(u) = reqwest::Url::parse(t) else {
        bail!("LLM base URL is not a valid URL (expected e.g. http://localhost:8000/v1)")
    };
    if !matches!(u.scheme(), "http" | "https") {
        bail!("LLM base URL must start with http:// or https://");
    }
    if u.host_str().is_none_or(str::is_empty) {
        bail!("LLM base URL has no host");
    }
    if !u.username().is_empty() || u.password().is_some() {
        bail!("LLM base URL must not embed credentials; put the key in {ENV_API_KEY}");
    }
    if u.query().is_some() || u.fragment().is_some() {
        bail!(
            "LLM base URL must be a plain base (scheme://host[:port]/path) without a query string or fragment"
        );
    }
    Ok(t.to_string())
}

/// Inside the ReadyHai image (`READYHAI_IN_CONTAINER=1`) "localhost" is the container itself, so
/// the `.env` URL a developer uses on the host (`http://localhost:8000/v1`) would never connect.
/// Rewrite a loopback host to `host.docker.internal` (mapped to the host gateway by compose).
pub fn container_loopback_to_host(raw: &str) -> String {
    let Ok(mut u) = reqwest::Url::parse(raw.trim()) else {
        return raw.to_string();
    };
    let loopback = u.host_str().is_some_and(|h| {
        h.eq_ignore_ascii_case("localhost")
            || h.trim_matches(|c| c == '[' || c == ']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if loopback && u.set_host(Some("host.docker.internal")).is_ok() {
        let out = u.to_string();
        // Url adds a trailing "/" to a bare origin; keep the user's form otherwise.
        if !raw.trim().ends_with('/') && out.ends_with('/') && u.path() == "/" {
            return out.trim_end_matches('/').to_string();
        }
        return out;
    }
    raw.to_string()
}

fn is_non_public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_unspecified()
                // 100.64.0.0/10: carrier-grade NAT, the range Tailscale-style overlays use
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(m) => is_non_public_ip(IpAddr::V4(m)),
            None => {
                v.is_loopback()
                    || v.is_unspecified()
                    || v.is_unique_local()
                    || v.is_unicast_link_local()
            }
        },
    }
}

/// True when `host` is a name or address on the public internet. Not public: loopback, RFC 1918,
/// link-local, unique-local and CGNAT addresses; `.local` / `.lan` / `.internal` (which covers
/// `host.docker.internal`) / `.localhost` / `.home.arpa` names; and single-label names (`localhost`,
/// `gpu-box`, a compose service name). A name is judged by its spelling, never resolved.
pub fn is_public_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.is_empty() {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return !is_non_public_ip(ip);
    }
    if !h.contains('.') {
        return false;
    }
    const PRIVATE_SUFFIXES: [&str; 5] = [".local", ".lan", ".internal", ".localhost", ".home.arpa"];
    !PRIVATE_SUFFIXES.iter().any(|s| h.ends_with(s))
}

/// The host of `url` when it is public. An unparseable URL counts as public (fail closed).
pub fn public_host_of(url: &str) -> Option<String> {
    let host = reqwest::Url::parse(url.trim())
        .ok()
        .and_then(|u| u.host_str().map(str::to_string));
    match host {
        Some(h) => is_public_host(&h).then_some(h),
        None => Some("<unparseable>".into()),
    }
}

/// True when any variable that asks for an LLM is set (used to say why a requested LLM was not used).
pub fn env_requested() -> bool {
    [ENV_PROVIDER, ENV_URL, "READYHAI_VLLM_URL"]
        .iter()
        .any(|k| std::env::var(k).is_ok_and(|v| !v.trim().is_empty()))
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: &'static ProviderDescriptor,
    /// The primary model: what `describe()` and run reports show, and what is tried first.
    pub model: String,
    /// Every configured model, primary first. Calls that fail on one move on to the next
    /// (see [`LlmConfig::model_chain`]).
    pub models: Vec<String>,
    pub allow_cloud: bool,
    /// Base URL override: `READYHAI_LLM_URL` (or the deprecated `READYHAI_VLLM_URL`), or a test mock.
    pub base_override: Option<String>,
    /// `READYHAI_LLM_API_KEY`. Wins over the provider's own key variable. Debug-safe.
    pub api_key: Option<ApiKey>,
    /// Overrides <data_dir>/llm-cache (tests).
    pub cache_dir: Option<std::path::PathBuf>,
    /// Total attempts per call for 429 / 5xx / timeouts (1 = no retry).
    pub max_attempts: u32,
    /// First backoff step; doubles per attempt (a `Retry-After` header wins, capped at 30 s).
    pub retry_base_ms: u64,
    /// Extended Thinking / CoT reasoning active.
    pub thinking: bool,
    /// Token budget allocated to reasoning (e.g. 1024..=32768).
    pub thinking_budget_tokens: u32,
    /// Model tier (low, medium, high, max, max_pro).
    pub model_tier: String,
    /// `READYHAI_LLM_TIMEOUT_SECS`: one timeout for every call instead of the size-based one.
    pub timeout_override: Option<Duration>,
    /// Latest moment the current call (all its downgrade retries included) may run until; set
    /// from the run's LLM budget so one slow call cannot use up the time of every later stage.
    pub call_deadline: Option<std::time::Instant>,
}

impl LlmConfig {
    /// The timeout of one call that may produce `max_tokens` tokens ([`call_timeout_secs`], unless
    /// `READYHAI_LLM_TIMEOUT_SECS` is set).
    pub fn call_timeout(&self, max_tokens: u32) -> Duration {
        let t = self
            .timeout_override
            .unwrap_or_else(|| Duration::from_secs(call_timeout_secs(max_tokens)));
        match self.call_deadline {
            // the floor applies to the budget share only, never raising a shorter configured timeout
            Some(d) => t.min(
                d.saturating_duration_since(std::time::Instant::now())
                    .max(Duration::from_secs(MIN_CALL_SECS)),
            ),
            None => t,
        }
    }

    /// The call's deadline has passed: no further (downgraded) attempt.
    fn past_call_deadline(&self) -> bool {
        self.call_deadline
            .is_some_and(|d| std::time::Instant::now() >= d)
    }

    /// The same config without reasoning: what gate and triage calls use. Such a call is a short
    /// summary of facts already computed, so it is capped at 2048 tokens and sends no
    /// `reasoning_effort` whatever tier the planner runs at.
    pub fn without_thinking(&self) -> Self {
        let mut c = self.clone();
        c.thinking = false;
        c
    }

    /// For a slow endpoint: the High tier (8192-token budget) in place of a bigger one. None when
    /// thinking is off or the config is not above High already.
    pub fn capped_to_high_tier(&self) -> Option<Self> {
        let top = matches!(
            self.model_tier.to_ascii_lowercase().as_str(),
            "max" | "max_pro"
        );
        if !self.thinking || !(top || self.thinking_budget_tokens > HIGH_TIER_BUDGET) {
            return None;
        }
        let mut c = self.clone();
        if top {
            c.model_tier = "high".into();
        }
        c.thinking_budget_tokens = c.thinking_budget_tokens.min(HIGH_TIER_BUDGET);
        Some(c)
    }

    pub fn from_env() -> Result<Self> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// As [`LlmConfig::from_env`] over any variable lookup, so the rules can be tested without touching
    /// the process environment. Empty values count as unset (an `.env` file lists every name).
    ///
    /// * provider: `READYHAI_LLM_PROVIDER`, default the generic OpenAI-compatible one (`vllm`).
    /// * URL: `READYHAI_LLM_URL` for any provider, else the provider's deprecated URL variable.
    /// * key: `READYHAI_LLM_API_KEY` (a provider's own key variable is read at call time).
    /// * models: `READYHAI_LLM_MODEL`, else `READYHAI_LLM_MODELS`; comma-separated, first is primary.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let val = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let provider_id = val(ENV_PROVIDER).unwrap_or_else(|| "vllm".to_string());
        let models = val(ENV_MODEL).or_else(|| val(ENV_MODELS));
        let allow_cloud = matches!(get(ENV_ALLOW_CLOUD).as_deref(), Some("1") | Some("true"));
        let mut cfg = Self::resolve(Some(&provider_id), models.as_deref(), allow_cloud)?;
        let url = val(ENV_URL).or_else(|| cfg.provider.legacy_url_env.and_then(&val));
        if let Some(u) = url {
            let u = if matches!(get("READYHAI_IN_CONTAINER").as_deref(), Some("1")) {
                container_loopback_to_host(&u)
            } else {
                u
            };
            cfg = cfg.with_base_url(&u)?;
        }
        if let Some(k) = val(ENV_API_KEY) {
            cfg.api_key = Some(ApiKey::new(k));
        }
        if let Some(t) = val(ENV_TIMEOUT_SECS) {
            cfg.timeout_override = Some(match t.parse::<u64>() {
                Ok(n) if (1..=3600).contains(&n) => Duration::from_secs(n),
                _ => bail!("{ENV_TIMEOUT_SECS} must be a whole number of seconds from 1 to 3600"),
            });
        }
        Ok(cfg)
    }

    pub fn resolve(
        provider_id: Option<&str>,
        model: Option<&str>,
        allow_cloud: bool,
    ) -> Result<Self> {
        let Some(id) = provider_id else {
            bail!("{ENV_PROVIDER} not set")
        };
        let Some(p) = provider(id) else {
            bail!("unknown LLM provider '{id}' (known: {})", provider_ids())
        };
        if !p.local && !allow_cloud {
            bail!(
                "provider '{id}' is a cloud provider; set READYHAI_LLM_ALLOW_CLOUD=1 to allow sending (redacted) findings off-box"
            );
        }
        let mut models = model.map(parse_model_list).unwrap_or_default();
        if models.is_empty() {
            models.push(p.default_model.to_string());
        }
        Ok(LlmConfig {
            provider: p,
            model: models[0].clone(),
            models,
            allow_cloud,
            base_override: None,
            api_key: None,
            cache_dir: None,
            max_attempts: 3,
            retry_base_ms: 500,
            thinking: false,
            thinking_budget_tokens: 8192,
            model_tier: "high".to_string(),
            timeout_override: None,
            call_deadline: None,
        })
    }

    /// Point this config at `url` (any provider). Refused when the URL is malformed, carries
    /// credentials, or is a public host while the provider is a local one and cloud is not allowed.
    pub fn with_base_url(mut self, url: &str) -> Result<Self> {
        self.base_override = Some(validate_base_url(url)?);
        self.guard()?;
        Ok(self)
    }

    /// The off-box guard, checked when the config is built and again before anything is sent:
    /// a cloud provider, or a local provider pointed at a public host, needs
    /// `READYHAI_LLM_ALLOW_CLOUD=1`.
    pub fn guard(&self) -> Result<()> {
        if self.allow_cloud {
            return Ok(());
        }
        if !self.provider.local {
            bail!(
                "cloud provider '{}' refused (READYHAI_LLM_ALLOW_CLOUD not set)",
                self.provider.id
            );
        }
        if let Some(host) = self.base_override.as_deref().and_then(public_host_of) {
            bail!(
                "LLM URL host '{host}' is a public address, but provider '{}' is a local one: sending findings off-box is refused. Set READYHAI_LLM_ALLOW_CLOUD=1 to allow it, or use a loopback, private (RFC 1918), .local/.lan/.internal or single-label host",
                self.provider.id
            );
        }
        Ok(())
    }

    pub fn with_thinking(mut self, thinking: bool, tier: &str, budget: u32) -> Self {
        self.thinking = thinking;
        self.model_tier = tier.to_string();
        self.thinking_budget_tokens = clamp_thinking_budget(budget);
        self
    }

    /// Models to try, in order: the primary `model`, then the rest of `models` (no duplicates).
    pub fn model_chain(&self) -> Vec<&str> {
        let mut v = vec![self.model.as_str()];
        for m in &self.models {
            if !v.contains(&m.as_str()) {
                v.push(m);
            }
        }
        v
    }

    /// What reasoning settings a structured call really carries, for the run log. The request's
    /// token budget is not "forwarded" as such: OpenAI-compatible servers get `reasoning_effort`
    /// (from the tier) and a `max_tokens` cap; Anthropic thinking blocks require temperature 1.0,
    /// so they are not attached to planning/verdict calls, which stay at a low temperature.
    pub fn thinking_summary(&self) -> String {
        let p = call_params(self);
        let temp = p
            .temperature
            .map(|t| format!("temperature {t}"))
            .unwrap_or_else(|| "provider-default temperature".into());
        if !self.thinking {
            return format!("thinking off; max_tokens {}, {temp}", p.max_tokens);
        }
        match (p.anthropic_thinking, p.reasoning_effort) {
            (Some(b), _) => format!(
                "thinking block attached (budget {b} tokens), max_tokens {}, {temp}",
                p.max_tokens
            ),
            (None, Some(e)) => format!(
                "reasoning_effort={e} (tier '{}'), max_tokens cap {} (budget {} tokens is a cap, not a reasoning allocation), {temp}",
                self.model_tier, p.max_tokens, self.thinking_budget_tokens
            ),
            (None, None) => format!(
                "requested (tier '{}', budget {} tokens) but NOT sent: Anthropic extended thinking forces temperature 1.0, so structured planning/verdict calls run without it at {temp}, max_tokens {}",
                self.model_tier, self.thinking_budget_tokens, p.max_tokens
            ),
        }
    }

    pub fn base_url(&self) -> Result<String> {
        if let Some(b) = &self.base_override {
            return Ok(b.clone());
        }
        if !self.provider.base_url.is_empty() {
            return Ok(self.provider.base_url.to_string());
        }
        bail!("{} base URL not set (export {ENV_URL})", self.provider.id)
    }

    /// "provider/model" for logs and reports (the real values, never a literal), plus how many
    /// fallback models are configured. Never includes the API key.
    pub fn describe(&self) -> String {
        let extra = self.model_chain().len() - 1;
        match extra {
            0 => format!("{}/{}", self.provider.id, self.model),
            1 => format!("{}/{} (+1 fallback)", self.provider.id, self.model),
            n => format!("{}/{} (+{n} fallbacks)", self.provider.id, self.model),
        }
    }

    /// Resolve the configured provider and probe it once. Err carries the human reason the
    /// caller should log when it falls back to deterministic behaviour.
    pub fn connect_from_env() -> std::result::Result<Self, String> {
        let cfg = Self::from_env().map_err(|e| format!("LLM not configured: {e}"))?;
        let base = cfg
            .base_url()
            .map_err(|e| format!("LLM not configured: {e}"))?;
        if probe(&cfg) {
            Ok(cfg)
        } else {
            Err(format!("LLM {} unreachable at {base}", cfg.describe()))
        }
    }
}

#[derive(Debug, Clone)]
pub struct Msg {
    pub role: String, // "user" | "assistant"
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub schema: Value,
}

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
}

pub trait ChatClient {
    fn chat(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Result<Reply>;
}

pub struct OpenAiClient {
    pub cfg: LlmConfig,
}
pub struct AnthropicClient {
    pub cfg: LlmConfig,
}

pub fn client(cfg: LlmConfig) -> Box<dyn ChatClient> {
    match cfg.provider.transport {
        Transport::OpenAiChat => Box::new(OpenAiClient { cfg }),
        Transport::AnthropicMessages => Box::new(AnthropicClient { cfg }),
    }
}

fn openai_body(model: &str, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Value {
    let mut msgs = vec![json!({"role": "system", "content": system})];
    msgs.extend(
        messages
            .iter()
            .map(|m| json!({"role": m.role, "content": m.content})),
    );
    let mut b = json!({"model": model, "messages": msgs});
    if !tools.is_empty() {
        b["tools"] = tools
            .iter()
            .map(|t| json!({"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.schema}}))
            .collect();
    }
    b
}

fn anthropic_body(model: &str, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Value {
    let mut b = json!({
        "model": model,
        "max_tokens": 4096,
        "system": system,
        "messages": messages.iter().map(|m| json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
    });
    if !tools.is_empty() {
        b["tools"] = tools
            .iter()
            .map(
                |t| json!({"name": t.name, "description": t.description, "input_schema": t.schema}),
            )
            .collect();
    }
    b
}

impl OpenAiClient {
    /// Request body for the primary model.
    pub fn body(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Value {
        self.body_for(&self.cfg.model, system, messages, tools)
    }

    pub fn body_for(
        &self,
        model: &str,
        system: &str,
        messages: &[Msg],
        tools: &[ToolDef],
    ) -> Value {
        openai_body(model, system, messages, tools)
    }
}

impl AnthropicClient {
    /// Request body for the primary model.
    pub fn body(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Value {
        self.body_for(&self.cfg.model, system, messages, tools)
    }

    pub fn body_for(
        &self,
        model: &str,
        system: &str,
        messages: &[Msg],
        tools: &[ToolDef],
    ) -> Value {
        anthropic_body(model, system, messages, tools)
    }
}

/// The key to send: `READYHAI_LLM_API_KEY` (held in the config) for any provider, else the provider's
/// own variable (`OPENAI_API_KEY` ...). Local providers need none. Errors name the variable, never a value.
fn key(cfg: &LlmConfig) -> Result<Option<String>> {
    key_with(cfg, |k| std::env::var(k).ok())
}

fn key_with(cfg: &LlmConfig, get: impl Fn(&str) -> Option<String>) -> Result<Option<String>> {
    let found = match (&cfg.api_key, cfg.provider.api_key_env) {
        (Some(k), _) => Some(k.expose().to_string()),
        (None, Some(e)) => match get(e).map(|v| v.trim().to_string()) {
            Some(v) if !v.is_empty() => Some(v),
            _ => bail!("{e} not set (or set {ENV_API_KEY})"),
        },
        (None, None) => None,
    };
    if let Some(k) = &found
        && k.bytes().any(|b| b.is_ascii_control())
    {
        bail!("the LLM API key contains a control character (a stray newline?) and cannot be sent");
    }
    Ok(found)
}

/// Whether a key would be sent with calls to this config (generic or provider-specific). A fact for
/// status screens; the value itself never leaves this module.
pub fn key_configured(cfg: &LlmConfig) -> bool {
    matches!(key(cfg), Ok(Some(_)))
}

/// Attach the credentials and transport headers: `Authorization: Bearer` for OpenAI-compatible
/// servers, `x-api-key` plus `anthropic-version` for the Anthropic Messages API. The key header is
/// marked sensitive so it never shows up in a debug dump of the request.
fn authorize(
    cfg: &LlmConfig,
    rq: reqwest::blocking::RequestBuilder,
    key: &Option<String>,
) -> reqwest::blocking::RequestBuilder {
    match cfg.provider.transport {
        Transport::OpenAiChat => match key {
            Some(k) => rq.bearer_auth(k),
            None => rq,
        },
        Transport::AnthropicMessages => {
            let rq = rq.header("anthropic-version", "2023-06-01");
            match key.as_deref().map(reqwest::header::HeaderValue::from_str) {
                Some(Ok(mut v)) => {
                    v.set_sensitive(true);
                    rq.header("x-api-key", v)
                }
                _ => rq,
            }
        }
    }
}

fn http(timeout: Duration) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()?)
}

/// Run `call` for the primary model and, when it fails (an error after its retries, a non-success
/// status, an unusable answer), for each following model in `cfg.model_chain()` until one succeeds.
/// A single configured model returns its own error unchanged; several return one error naming every
/// model that failed. Nothing in an error is a credential.
fn try_models<T>(cfg: &LlmConfig, mut call: impl FnMut(&str) -> Result<T>) -> Result<T> {
    let chain = cfg.model_chain();
    let mut failed: Vec<String> = Vec::new();
    for (i, model) in chain.iter().enumerate() {
        match call(model) {
            Ok(v) => return Ok(v),
            Err(e) if chain.len() == 1 => return Err(e),
            Err(e) => {
                let why: String = format!("{e:#}").chars().take(300).collect();
                if let Some(next) = chain.get(i + 1) {
                    eprintln!("llm: model '{model}' failed ({why}); falling back to '{next}'");
                }
                failed.push(format!("'{model}': {why}"));
            }
        }
    }
    bail!(
        "all {} configured models failed: {}",
        chain.len(),
        failed.join("; ")
    )
}

// ---------------------------------------------------------------- retry with backoff

/// Statuses worth another attempt: rate limit, request timeout, transient server errors.
fn retryable_status(code: u16) -> bool {
    matches!(code, 408 | 425 | 429) || ((500..=599).contains(&code) && !matches!(code, 501 | 505))
}

/// Delay before attempt `attempt + 1` (0-based): Retry-After if sane, else base * 2^attempt (+ jitter).
fn backoff(cfg: &LlmConfig, attempt: u32, retry_after: Option<&str>) -> Duration {
    if let Some(secs) = retry_after.and_then(|v| v.trim().parse::<u64>().ok()) {
        return Duration::from_secs(secs.min(30))
            .max(Duration::from_millis(cfg.retry_base_ms.min(1)));
    }
    let base = cfg.retry_base_ms.saturating_mul(1u64 << attempt.min(6));
    let jitter = if base >= 2 {
        rand::random_range(0..=base / 4)
    } else {
        0
    };
    Duration::from_millis(base.saturating_add(jitter))
}

/// Client-level timeout of structured calls: only a backstop, every request sets its own.
const CLIENT_BACKSTOP_SECS: u64 = 3660;

/// `max_tokens` the tool-calling chat clients ask for (Anthropic sends it; OpenAI-compatible servers
/// default to something comparable): the size their timeout is derived from.
const CHAT_MAX_TOKENS: u32 = 4096;

/// A call that hit its per-call timeout. It is never retried identically (the same request would
/// time out again): `raw_chat` sends a smaller one, anything else moves on to the next model.
#[derive(Debug)]
struct CallTimedOut(String);

impl std::fmt::Display for CallTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CallTimedOut {}

/// True when `e` is a per-call timeout (as opposed to a refusal, a bad status or an unusable answer).
pub fn is_timeout_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<CallTimedOut>().is_some()
}

/// Send the request built by `build`. 429 (and 408/425) are retried with the server's `Retry-After`
/// or exponential backoff up to `cfg.max_attempts`; a 5xx is retried once; a timeout is an error
/// ([`CallTimedOut`]) at once. Connection refusals and 4xx (except 408/425/429) fail immediately:
/// they will not heal by waiting. The caller sets the per-call timeout on the request.
fn send_retrying(
    cfg: &LlmConfig,
    build: impl Fn() -> reqwest::blocking::RequestBuilder,
) -> Result<reqwest::blocking::Response> {
    let attempts = cfg.max_attempts.max(1);
    let mut server_retries = 0;
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..attempts {
        let delay;
        match build().send() {
            Ok(r) => {
                let code = r.status().as_u16();
                if !retryable_status(code) || attempt + 1 == attempts {
                    return Ok(r);
                }
                if code >= 500 {
                    if server_retries >= MAX_SERVER_ERROR_RETRIES {
                        return Ok(r);
                    }
                    server_retries += 1;
                }
                delay = backoff(
                    cfg,
                    attempt,
                    r.headers().get("retry-after").and_then(|v| v.to_str().ok()),
                );
                last = Some(anyhow::anyhow!("HTTP {code}"));
            }
            Err(e) if e.is_timeout() => {
                return Err(CallTimedOut("LLM request timed out".into()).into());
            }
            Err(e) => return Err(e.into()),
        }
        std::thread::sleep(delay);
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("LLM request failed")))
}

impl ChatClient for OpenAiClient {
    fn chat(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Result<Reply> {
        self.cfg.guard()?;
        let url = format!(
            "{}/chat/completions",
            self.cfg.base_url()?.trim_end_matches('/')
        );
        let key = key(&self.cfg)?;
        let c = http(self.cfg.call_timeout(CHAT_MAX_TOKENS))?;
        try_models(&self.cfg, |model| {
            let body = self.body_for(model, system, messages, tools);
            let r = send_retrying(&self.cfg, || {
                authorize(&self.cfg, c.post(&url).json(&body), &key)
            })?;
            let v: Value = r.error_for_status()?.json()?;
            let m = &v["choices"][0]["message"];
            let mut r = Reply {
                text: m["content"].as_str().unwrap_or("").to_string(),
                tool_calls: vec![],
            };
            for tc in m["tool_calls"].as_array().into_iter().flatten() {
                r.tool_calls.push(ToolCall {
                    id: tc["id"].as_str().unwrap_or("").into(),
                    name: tc["function"]["name"].as_str().unwrap_or("").into(),
                    args: serde_json::from_str(
                        tc["function"]["arguments"].as_str().unwrap_or("{}"),
                    )
                    .unwrap_or(json!({})),
                });
            }
            Ok(r)
        })
    }
}

impl ChatClient for AnthropicClient {
    fn chat(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Result<Reply> {
        self.cfg.guard()?;
        let url = format!("{}/v1/messages", self.cfg.base_url()?.trim_end_matches('/'));
        let key = key(&self.cfg)?;
        let c = http(self.cfg.call_timeout(CHAT_MAX_TOKENS))?;
        try_models(&self.cfg, |model| {
            let body = self.body_for(model, system, messages, tools);
            let r = send_retrying(&self.cfg, || {
                authorize(&self.cfg, c.post(&url).json(&body), &key)
            })?;
            let v: Value = r.error_for_status()?.json()?;
            let mut r = Reply::default();
            for c in v["content"].as_array().into_iter().flatten() {
                match c["type"].as_str() {
                    Some("text") => r.text += c["text"].as_str().unwrap_or(""),
                    Some("tool_use") => r.tool_calls.push(ToolCall {
                        id: c["id"].as_str().unwrap_or("").into(),
                        name: c["name"].as_str().unwrap_or("").into(),
                        args: c["input"].clone(),
                    }),
                    _ => {}
                }
            }
            Ok(r)
        })
    }
}

// ---------------------------------------------------------------- redaction

/// Key names whose values are credentials. Matches by suffix/substring so `DB_PASSWORD`,
/// `stripe_secret`, `x-api-key`, `accessKey`, `Authorization` and `Set-Cookie` all count.
pub fn is_sensitive_key(name: &str) -> bool {
    let low = name
        .trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace())
        .to_ascii_lowercase();
    if low.is_empty() {
        return false;
    }
    let compact: String = low.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    const CONTAINS: [&str; 14] = [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "accesskey",
        "privatekey",
        "credential",
        "authorization",
        "cookie",
        "sessionid",
        "signature",
        "bearer",
    ];
    if CONTAINS.iter().any(|k| compact.contains(k)) {
        return true;
    }
    if low == "key"
        || low == "pwd"
        || low == "pass"
        || low == "auth"
        || low == "session"
        || low == "sid"
    {
        return true;
    }
    if low.ends_with("_key")
        || low.ends_with("-key")
        || low.ends_with("_pwd")
        || low.ends_with("_pass")
        || low.ends_with("_auth")
    {
        return true;
    }
    // camelCase ...Key (e.g. stripeKey) from the original spelling
    let orig = name.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
    orig.len() > 3
        && orig.ends_with("Key")
        && orig.chars().next().is_some_and(|c| c.is_ascii_lowercase())
}

struct Redactors {
    plain: Vec<(Regex, &'static str)>,
    kv: Regex,
}

fn redactors() -> &'static Redactors {
    static R: OnceLock<Redactors> = OnceLock::new();
    R.get_or_init(|| Redactors {
        plain: [
            (r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "[REDACTED]"),
            (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)", "[REDACTED]"),
            (r"\b(?:sk|pk|rk|ghp|gho|ghs|xox[a-z]|AKIA|AIza)[A-Za-z0-9_\-]{12,}", "[REDACTED]"),
            (r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{6,}", "Bearer [REDACTED]"),
            (r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/:@]+:[^\s/@]+@", "${1}[REDACTED]@"),
            (r"\b[0-9a-fA-F]{32,}\b", "[REDACTED]"),
        ]
        .into_iter()
        .map(|(p, r)| (Regex::new(p).unwrap(), r))
        .collect(),
        // key (optionally quoted) <sep> value, where the key's NAME decides (see is_sensitive_key)
        kv: Regex::new(r#"(["']?)([A-Za-z_][A-Za-z0-9_.\-]{0,63})(["']?\s*[:=]\s*)("(?:[^"\\\n]|\\.){0,512}"|'[^'\n]{0,512}'|[^\s,;&"'<>}\]]{1,512})"#).unwrap(),
    })
}

/// Strip things that look like credentials before any text leaves the box.
pub fn redact_for_llm(text: &str) -> String {
    let r = redactors();
    let mut s = text.to_string();
    for (re, rep) in &r.plain {
        s = re.replace_all(&s, *rep).into_owned();
    }
    r.kv.replace_all(&s, |c: &regex::Captures| {
        if is_sensitive_key(&c[2]) {
            format!("{}{}{}\"[REDACTED]\"", &c[1], &c[2], &c[3])
        } else {
            c[0].to_string()
        }
    })
    .into_owned()
}

/// Redact a JSON value structurally: values under credential-looking key names are replaced
/// wholesale (whatever their type), every other string leaf goes through [`redact_for_llm`].
pub fn redact_value(v: &Value) -> Value {
    redact_value_capped(v, usize::MAX)
}

/// As [`redact_value`], then each string leaf is truncated to `max_leaf` chars (redaction first).
pub fn redact_value_capped(v: &Value, max_leaf: usize) -> Value {
    match v {
        Value::String(s) => {
            let r = redact_for_llm(s);
            if r.chars().count() > max_leaf {
                Value::String(r.chars().take(max_leaf).collect())
            } else {
                Value::String(r)
            }
        }
        Value::Array(a) => {
            Value::Array(a.iter().map(|x| redact_value_capped(x, max_leaf)).collect())
        }
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, val)| {
                    if is_sensitive_key(k) && !val.is_null() {
                        (k.clone(), Value::String("[REDACTED]".into()))
                    } else {
                        (k.clone(), redact_value_capped(val, max_leaf))
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

// ---------------------------------------------------------------- single-shot strict-JSON layer

/// GET {base}/models with a 2s timeout: the HTTP status, or None when it is refused (off-box guard),
/// unconfigured or unreachable. The key is sent exactly as on a real call.
pub fn probe_status(cfg: &LlmConfig) -> Option<u16> {
    cfg.guard().ok()?;
    let base = cfg.base_url().ok()?;
    let c = http(Duration::from_secs(2)).ok()?;
    let key = key(cfg).ok().flatten();
    let rq = c.get(format!("{}/models", base.trim_end_matches('/')));
    authorize(cfg, rq, &key)
        .send()
        .ok()
        .map(|r| r.status().as_u16())
}

/// Reachability probe: True on any HTTP answer < 500.
pub fn probe(cfg: &LlmConfig) -> bool {
    matches!(probe_status(cfg), Some(code) if code < 500)
}

/// One real chat completion of a single token with a tiny prompt, one attempt, no retry: how long the
/// endpoint takes to answer when it has to generate (`/models` answering only says the server is up).
/// Ok carries the latency (any 2xx answer); a timeout is the typed timeout error ([`is_timeout_error`]).
pub fn probe_latency(cfg: &LlmConfig) -> Result<Duration> {
    cfg.guard()?;
    let base = cfg.base_url()?;
    let timeout = cfg
        .timeout_override
        .map_or(LATENCY_PROBE_TIMEOUT, |t| t.min(LATENCY_PROBE_TIMEOUT));
    let c = http(timeout)?;
    let key = key(cfg)?;
    let base = base.trim_end_matches('/');
    let rq = match cfg.provider.transport {
        Transport::OpenAiChat => c.post(format!("{base}/chat/completions")).json(&json!({
            "model": cfg.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            "temperature": 0,
        })),
        Transport::AnthropicMessages => c.post(format!("{base}/v1/messages")).json(&json!({
            "model": cfg.model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "ping"}],
        })),
    };
    let t0 = std::time::Instant::now();
    match authorize(cfg, rq, &key).send() {
        Ok(r) if r.status().is_success() => Ok(t0.elapsed()),
        Ok(r) => bail!("latency probe failed: HTTP {}", r.status().as_u16()),
        Err(e) if e.is_timeout() => Err(CallTimedOut(format!(
            "latency probe timed out after {} s",
            timeout.as_secs()
        ))
        .into()),
        Err(_) => bail!("latency probe failed: connection error"),
    }
}

/// What a latency probe means for a run: the words for `llm_status` and whether the endpoint is
/// too slow for long reasoning calls (answers in more than [`SLOW_LATENCY`], or does not answer a
/// 1-token request in time although `/models` did).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyReport {
    pub summary: String,
    pub slow: bool,
}

pub fn latency_report(probe: &Result<Duration>) -> LatencyReport {
    match probe {
        Ok(d) => LatencyReport {
            summary: format!("latency {} ms", d.as_millis()),
            slow: *d > SLOW_LATENCY,
        },
        Err(e) => LatencyReport {
            summary: format!("{e}"),
            slow: is_timeout_error(e),
        },
    }
}

/// Fetch list of models from provider /models endpoint.
pub fn query_models(cfg: &LlmConfig) -> Result<Value> {
    cfg.guard()?;
    let base = cfg.base_url()?;
    let c = http(Duration::from_secs(3))?;
    let key = key(cfg).ok().flatten();
    let rq = c.get(format!("{}/models", base.trim_end_matches('/')));
    let r = authorize(cfg, rq, &key)
        .send()?
        .error_for_status()?
        .json()?;
    Ok(r)
}

/// Per-run call and wall-clock budget. Cache hits are free. A run hands one of these to every LLM
/// stage (`RunBudget::llm_budget`) and reads the totals back with `RunBudget::sync_llm`, so calls
/// and time count against the run's own budget.
#[derive(Debug)]
pub struct Budget {
    pub max_calls: usize,
    pub max_total: Duration,
    pub calls: usize,
    /// Time spent inside provider calls (successful or not).
    pub elapsed: Duration,
    started: std::time::Instant,
    /// The run's wall-clock deadline: no call starts after it.
    deadline: Option<std::time::Instant>,
    /// What the LLM layer did that a reader of the run should know (a call that timed out and was
    /// retried smaller, ...). The caller moves these into the run's notes.
    pub notes: Vec<String>,
}

impl Budget {
    pub fn new(max_calls: usize, max_total: Duration) -> Self {
        Budget {
            max_calls,
            max_total,
            calls: 0,
            elapsed: Duration::ZERO,
            started: std::time::Instant::now(),
            deadline: None,
            notes: Vec::new(),
        }
    }
    pub fn per_run() -> Self {
        Self::new(20, Duration::from_secs(300))
    }
    pub fn with_deadline(mut self, deadline: std::time::Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed.as_millis() as u64
    }
    pub fn remaining_calls(&self) -> usize {
        self.max_calls.saturating_sub(self.calls)
    }
    /// LLM time left: the smaller of the time budget and the run's wall-clock deadline.
    pub fn time_left(&self) -> Duration {
        let budget = self.max_total.saturating_sub(self.started.elapsed());
        match self.deadline {
            Some(d) => budget.min(d.saturating_duration_since(std::time::Instant::now())),
            None => budget,
        }
    }
    /// Deadline for the next call: a share of the time left, so a slow planner call (a large
    /// reasoning budget on a small model) leaves time for the gate and triage calls after it.
    pub fn call_deadline(&self) -> std::time::Instant {
        let share = self
            .time_left()
            .mul_f64(CALL_SHARE_OF_BUDGET)
            .max(Duration::from_secs(MIN_CALL_SECS));
        std::time::Instant::now() + share
    }
    fn check(&self) -> Result<()> {
        if self.calls >= self.max_calls {
            bail!("LLM call budget exhausted ({} calls)", self.max_calls);
        }
        if self.started.elapsed() >= self.max_total {
            bail!("LLM time budget exhausted");
        }
        if self
            .deadline
            .is_some_and(|d| std::time::Instant::now() >= d)
        {
            bail!("run wall-clock budget exhausted: no further LLM call");
        }
        Ok(())
    }
}

/// Remove `<think>…</think>` blocks (Qwen3 reasoning); an unclosed block drops the rest.
pub fn strip_think(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("<think>") {
        out.push_str(&rest[..i]);
        match rest[i..].find("</think>") {
            Some(j) => rest = &rest[i + j + "</think>".len()..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Parse the first JSON object in model text (after stripping think blocks and code fences).
pub fn parse_json_object(text: &str) -> Result<Value> {
    let t = strip_think(text);
    let (Some(a), Some(b)) = (t.find('{'), t.rfind('}')) else {
        bail!("no JSON object in reply")
    };
    if b < a {
        bail!("no JSON object in reply");
    }
    let v: Value =
        serde_json::from_str(&t[a..=b]).map_err(|e| anyhow::anyhow!("malformed JSON: {e}"))?;
    if !v.is_object() {
        bail!("reply is not a JSON object");
    }
    Ok(v)
}

fn cache_path(cfg: &LlmConfig, system: &str, prompt: &str) -> std::path::PathBuf {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let budget_str = cfg.thinking_budget_tokens.to_string();
    for part in [
        cfg.provider.id,
        "\0",
        cfg.model.as_str(),
        "\0",
        if cfg.thinking { "thinking" } else { "normal" },
        "\0",
        cfg.model_tier.as_str(),
        "\0",
        budget_str.as_str(),
        "\0",
        system,
        "\0",
        prompt,
    ] {
        h.update(part.as_bytes());
    }
    let dir = cfg
        .cache_dir
        .clone()
        .unwrap_or_else(|| crate::engine::data_dir().join("llm-cache"));
    dir.join(format!("{}.json", hex::encode(h.finalize())))
}

/// Write via a sibling temp file + rename so a reader never sees a torn file.
pub fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// The model's answer text. The `reasoning` / `reasoning_content` fields are NEVER the answer:
/// a model that only produced reasoning (e.g. ran out of tokens while thinking) is an error.
fn openai_answer(v: &Value) -> Result<String> {
    let msg = &v["choices"][0]["message"];
    let content = msg["content"].as_str().unwrap_or("").to_string();
    if content.trim().is_empty() {
        let reasoning_only = msg["reasoning"]
            .as_str()
            .or_else(|| msg["reasoning_content"].as_str())
            .is_some_and(|r| !r.trim().is_empty());
        if reasoning_only {
            bail!(
                "LLM returned reasoning but no answer content (finish_reason={})",
                v["choices"][0]["finish_reason"].as_str().unwrap_or("?")
            );
        }
        bail!("LLM returned empty content");
    }
    Ok(content)
}

/// How one structured (planning / triage / verdict) call is sent. Pure, so it can be tested
/// without a server: every number is clamped and nothing here can overflow.
#[derive(Debug, Clone, PartialEq)]
pub struct CallParams {
    pub max_tokens: u32,
    /// None = leave it to the provider default (only when the API forbids a custom value).
    pub temperature: Option<f64>,
    /// Anthropic extended-thinking budget when a thinking block is attached.
    pub anthropic_thinking: Option<u32>,
    /// OpenAI-style `reasoning_effort`.
    pub reasoning_effort: Option<&'static str>,
}

pub fn call_params(cfg: &LlmConfig) -> CallParams {
    match cfg.provider.transport {
        Transport::OpenAiChat => {
            let effort = cfg
                .thinking
                .then(|| match cfg.model_tier.to_ascii_lowercase().as_str() {
                    "low" => "low",
                    "medium" => "medium",
                    "high" | "max" | "max_pro" => "high",
                    _ => "medium",
                });
            CallParams {
                max_tokens: if cfg.thinking {
                    max_tokens_with_thinking(cfg.thinking_budget_tokens).max(4096)
                } else {
                    2048
                },
                temperature: Some(STRUCTURED_TEMPERATURE),
                anthropic_thinking: None,
                reasoning_effort: effort,
            }
        }
        // A thinking block forces temperature 1.0 on this API. Planning and verdict-adjacent calls
        // must stay near-deterministic, so they never carry one.
        Transport::AnthropicMessages => CallParams {
            max_tokens: 2048,
            temperature: Some(STRUCTURED_TEMPERATURE),
            anthropic_thinking: None,
            reasoning_effort: None,
        },
    }
}

/// The next, smaller request after a timeout: half the `max_tokens` (never below
/// [`DOWNGRADE_FLOOR_TOKENS`]) and no `reasoning_effort`. None when that changes nothing (the request is
/// already at the floor with no reasoning), because repeating the identical request is pointless.
fn downgrade(max_tokens: u32, has_effort: bool) -> Option<u32> {
    let next = (max_tokens / 2).max(DOWNGRADE_FLOOR_TOKENS).min(max_tokens);
    (next < max_tokens || has_effort).then_some(next)
}

/// How one attempt of a structured call is shaped (see [`downgrade`]).
#[derive(Clone, Copy)]
struct Shape {
    max_tokens: u32,
    effort: Option<&'static str>,
}

impl Shape {
    fn describe(&self) -> String {
        match self.effort {
            Some(e) => format!("max_tokens {} with reasoning_effort {e}", self.max_tokens),
            None => format!("max_tokens {}", self.max_tokens),
        }
    }
}

/// One request of a structured call, as shaped by `shape`, with its own timeout.
#[allow(clippy::too_many_arguments)]
fn raw_once(
    cfg: &LlmConfig,
    c: &reqwest::blocking::Client,
    base: &str,
    key: &Option<String>,
    model: &str,
    system: &str,
    prompt: &str,
    p: &CallParams,
    shape: Shape,
) -> Result<String> {
    let timeout = cfg.call_timeout(shape.max_tokens);
    match cfg.provider.transport {
        Transport::OpenAiChat => {
            let url = format!("{}/chat/completions", base.trim_end_matches('/'));
            let mut body = json!({
                "model": model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                "max_tokens": shape.max_tokens,
                "response_format": {"type": "json_object"},
            });
            if let Some(t) = p.temperature {
                body["temperature"] = json!(t);
            }
            if let Some(e) = shape.effort {
                body["reasoning_effort"] = json!(e);
            }
            // Servers that reject an optional field answer 400: drop the optional fields (first the
            // response format and reasoning effort, then the temperature) and ask again.
            for attempt in 0..3 {
                let r = send_retrying(cfg, || {
                    authorize(cfg, c.post(&url).timeout(timeout).json(&body), key)
                })?;
                if r.status().as_u16() == 400 && attempt < 2 {
                    if let Some(o) = body.as_object_mut() {
                        if attempt == 0 {
                            o.remove("response_format");
                            o.remove("reasoning_effort");
                        } else {
                            o.remove("temperature");
                        }
                    }
                    continue;
                }
                let v: Value = r.error_for_status()?.json()?;
                return openai_answer(&v);
            }
            bail!("LLM rejected the request")
        }
        Transport::AnthropicMessages => {
            let mut b = anthropic_body(
                model,
                system,
                &[Msg {
                    role: "user".into(),
                    content: prompt.into(),
                }],
                &[],
            );
            b["max_tokens"] = json!(shape.max_tokens);
            if let Some(t) = p.temperature {
                b["temperature"] = json!(t);
            }
            if let Some(budget) = p.anthropic_thinking {
                b["thinking"] = json!({ "type": "enabled", "budget_tokens": budget });
            }
            let url = format!("{}/v1/messages", base.trim_end_matches('/'));
            let r = send_retrying(cfg, || {
                authorize(cfg, c.post(&url).timeout(timeout).json(&b), key)
            })?;
            let v: Value = r.error_for_status()?.json()?;
            let text = v["content"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c["text"].as_str())
                .collect::<String>();
            if text.trim().is_empty() {
                bail!("LLM returned empty content");
            }
            Ok(text)
        }
    }
}

/// A structured single-shot call. Each request gets a timeout sized to the answer it may produce
/// ([`LlmConfig::call_timeout`]). When one times out it is not repeated as it was: it is sent again
/// with half the `max_tokens` and no `reasoning_effort`, at most [`MAX_TIMEOUT_DOWNGRADES`] times,
/// and then the next model in the chain is tried. What happened goes to `notes` (never a key).
fn raw_chat(
    cfg: &LlmConfig,
    system: &str,
    prompt: &str,
    notes: &mut Vec<String>,
) -> Result<String> {
    let base = cfg.base_url()?;
    // each request carries its own timeout; the client's is only a backstop above the largest one
    let c = http(Duration::from_secs(CLIENT_BACKSTOP_SECS))?;
    let key = key(cfg)?;
    let p = call_params(cfg);
    try_models(cfg, |model| {
        let mut shape = Shape {
            max_tokens: p.max_tokens,
            effort: p.reasoning_effort,
        };
        let mut trail: Vec<String> = Vec::new();
        loop {
            match raw_once(cfg, &c, &base, &key, model, system, prompt, &p, shape) {
                Err(e) if is_timeout_error(&e) => {
                    let after = cfg.call_timeout(shape.max_tokens);
                    let after = match after.as_secs() {
                        0 => format!("{} ms", after.as_millis()),
                        n => format!("{n} s"),
                    };
                    trail.push(format!("{after} at {}", shape.describe()));
                    let next = downgrade(shape.max_tokens, shape.effort.is_some())
                        .filter(|_| trail.len() <= MAX_TIMEOUT_DOWNGRADES)
                        .filter(|_| !cfg.past_call_deadline());
                    let Some(max_tokens) = next else {
                        let why = format!(
                            "'{model}' timed out {} time(s): {}",
                            trail.len(),
                            trail.join(", ")
                        );
                        notes.push(format!("LLM call gave up: {why}"));
                        return Err(CallTimedOut(format!("LLM request timed out: {why}")).into());
                    };
                    shape = Shape {
                        max_tokens,
                        effort: None,
                    };
                }
                done => {
                    if done.is_ok() && !trail.is_empty() {
                        notes.push(format!(
                            "LLM call to '{model}' timed out ({}); the retry with {} succeeded",
                            trail.join(", "),
                            shape.describe()
                        ));
                    }
                    return done;
                }
            }
        }
    })
}

/// One single-shot call that must return a JSON object. Cached on disk by
/// sha256(provider+model+system+prompt); cache hits do not consume budget. Callers must already
/// have redacted/fenced `prompt` (see [`untrusted`]).
pub fn ask_json(cfg: &LlmConfig, budget: &mut Budget, system: &str, prompt: &str) -> Result<Value> {
    ask_json_with(cfg, budget, system, prompt, |_| Ok(()))
}

/// As [`ask_json`], but `validate` is the schema check. Output that fails it is an error, is NEVER
/// written to the cache, and a cached entry that no longer passes it is ignored and re-asked.
pub fn ask_json_with(
    cfg: &LlmConfig,
    budget: &mut Budget,
    system: &str,
    prompt: &str,
    validate: impl Fn(&Value) -> Result<()>,
) -> Result<Value> {
    cfg.guard()?;
    let path = cache_path(cfg, system, prompt);
    if let Ok(s) = std::fs::read_to_string(&path) {
        if let Ok(v) = parse_json_object(&s)
            && validate(&v).is_ok()
        {
            return Ok(v);
        }
        let _ = std::fs::remove_file(&path);
    }
    budget.check()?;
    budget.calls += 1;
    let t0 = std::time::Instant::now();
    let mut bounded = cfg.clone();
    let d = budget.call_deadline();
    bounded.call_deadline = Some(cfg.call_deadline.map_or(d, |c| c.min(d)));
    let reply = raw_chat(&bounded, system, prompt, &mut budget.notes);
    budget.elapsed += t0.elapsed();
    let text = reply?;
    let v = parse_json_object(&text)?;
    validate(&v).map_err(|e| anyhow::anyhow!("LLM output failed schema validation: {e}"))?;
    let _ = write_atomic(&path, v.to_string().as_bytes());
    Ok(v)
}

/// Typed variant: the reply must deserialize into `T` (serde) and pass `check`. Anything else is an error
/// and is not cached.
pub fn ask_typed<T: serde::de::DeserializeOwned>(
    cfg: &LlmConfig,
    budget: &mut Budget,
    system: &str,
    prompt: &str,
    check: impl Fn(&T) -> Result<()>,
) -> Result<T> {
    let v = ask_json_with(cfg, budget, system, prompt, |v| {
        let t: T = serde_json::from_value(v.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
        check(&t)
    })?;
    serde_json::from_value(v).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn one_call_gets_only_a_share_of_the_run_budget() {
        let b = Budget::new(20, Duration::from_secs(300));
        let left = b
            .call_deadline()
            .saturating_duration_since(std::time::Instant::now());
        assert!(
            left <= Duration::from_secs(181) && left >= Duration::from_secs(170),
            "{left:?}"
        );
        // a 34k-token Max Pro call would get 300 s alone; under the deadline it gets the share
        let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
        assert_eq!(c.call_timeout(34_816), Duration::from_secs(300));
        c.call_deadline = Some(b.call_deadline());
        assert!(c.call_timeout(34_816) <= Duration::from_secs(181));
        // an exhausted budget still allows the minimum, never zero
        c.call_deadline = Some(std::time::Instant::now());
        assert_eq!(c.call_timeout(34_816), Duration::from_secs(MIN_CALL_SECS));
        assert!(c.past_call_deadline());
    }

    #[test]
    fn container_rewrites_loopback_llm_url() {
        assert_eq!(
            container_loopback_to_host("http://localhost:6130/v1"),
            "http://host.docker.internal:6130/v1"
        );
        assert_eq!(
            container_loopback_to_host("http://127.0.0.1:8000"),
            "http://host.docker.internal:8000"
        );
        assert_eq!(
            container_loopback_to_host("http://vllm.lan:8000/v1"),
            "http://vllm.lan:8000/v1"
        );
        let get = |inside: bool| {
            move |k: &str| match k {
                "READYHAI_LLM_URL" => Some("http://localhost:6130/v1".to_string()),
                "READYHAI_IN_CONTAINER" if inside => Some("1".to_string()),
                _ => None,
            }
        };
        let c = LlmConfig::from_vars(get(true)).unwrap();
        assert_eq!(c.base_url().unwrap(), "http://host.docker.internal:6130/v1");
        let h = LlmConfig::from_vars(get(false)).unwrap();
        assert_eq!(h.base_url().unwrap(), "http://localhost:6130/v1");
    }

    #[test]
    fn cloud_guard() {
        assert!(LlmConfig::resolve(Some("anthropic"), None, false).is_err());
        let c = LlmConfig::resolve(Some("anthropic"), None, true).unwrap();
        assert_eq!(c.model, "claude-sonnet-5-5");
        let o = LlmConfig::resolve(Some("ollama"), Some("x"), false).unwrap();
        assert_eq!(o.model, "x");
        assert!(LlmConfig::resolve(Some("nope"), None, true).is_err());
        assert!(LlmConfig::resolve(None, None, true).is_err());
    }

    #[test]
    fn no_hardcoded_lan_address_in_catalog() {
        for p in CATALOG {
            assert!(
                !p.base_url.contains("10.10."),
                "{} bakes in a LAN address",
                p.id
            );
            // a built-in base is loopback or a public name, never a private LAN address
            if let Some(h) = reqwest::Url::parse(p.base_url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
            {
                assert!(
                    !h.starts_with("192.168.") && !h.starts_with("10.") && !h.starts_with("172."),
                    "{} bakes in a private address {h}",
                    p.id
                );
            }
        }
        let g = provider("vllm").unwrap();
        assert_eq!(g.base_url, "");
        assert_eq!(g.legacy_url_env, Some("READYHAI_VLLM_URL"));
        // the generic provider is the only one without an address; only it has a legacy URL variable
        assert!(
            CATALOG
                .iter()
                .all(|p| (p.base_url.is_empty() && p.legacy_url_env.is_some()) == (p.id == "vllm"))
        );
    }

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    fn model_of(body: &str) -> String {
        serde_json::from_str::<Value>(body).unwrap()["model"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn models_seen(m: &mock::Mock) -> Vec<String> {
        m.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| model_of(r.split("\r\n\r\n").nth(1).unwrap()))
            .collect()
    }

    #[test]
    fn provider_aliases_select_the_generic_descriptor() {
        let g = provider("vllm").unwrap();
        for a in [
            "openai-compatible",
            "custom",
            "CUSTOM",
            " Openai-Compatible ",
        ] {
            assert!(std::ptr::eq(provider(a).unwrap(), g), "{a}");
        }
        let c = LlmConfig::resolve(Some("custom"), None, false).unwrap();
        assert_eq!(c.provider.id, "vllm");
        assert_eq!(c.describe(), "vllm/qwen3.8-flash-next");
        let mut seen = std::collections::HashSet::new();
        for p in CATALOG {
            for id in std::iter::once(p.id).chain(p.aliases.iter().copied()) {
                assert!(seen.insert(id), "duplicate provider id/alias {id}");
            }
        }
        assert!(provider("nope").is_none());
        let e = LlmConfig::resolve(Some("nope"), None, true)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("custom") && e.contains("openai-compatible"),
            "{e}"
        );
    }

    #[test]
    fn llm_url_overrides_the_base_of_every_provider() {
        let c = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", "ollama"),
            ("READYHAI_LLM_URL", "http://gpu-box:8080/v1"),
        ]))
        .unwrap();
        assert_eq!(c.provider.id, "ollama");
        assert_eq!(c.base_url().unwrap(), "http://gpu-box:8080/v1");
        for id in ["openai", "anthropic", "openrouter"] {
            let with = LlmConfig::from_vars(vars(&[
                ("READYHAI_LLM_PROVIDER", id),
                ("READYHAI_LLM_ALLOW_CLOUD", "1"),
                ("READYHAI_LLM_URL", "https://llm-proxy.example.com/gw"),
            ]))
            .unwrap();
            assert_eq!(with.base_url().unwrap(), "https://llm-proxy.example.com/gw");
            let without = LlmConfig::from_vars(vars(&[
                ("READYHAI_LLM_PROVIDER", id),
                ("READYHAI_LLM_ALLOW_CLOUD", "1"),
            ]))
            .unwrap();
            assert_eq!(without.base_url().unwrap(), without.provider.base_url);
        }
    }

    #[test]
    fn llm_url_is_what_the_call_really_hits() {
        let m = mock::start(|_| "{\"ok\": true}".into());
        let mut c = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", "ollama"),
            ("READYHAI_LLM_URL", m.base.as_str()),
        ]))
        .unwrap();
        c.cache_dir = Some(tmpdir("url-wire"));
        assert_eq!(
            ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
            true
        );
        assert_eq!(m.chat_hits.load(Ordering::SeqCst), 1);
        assert!(probe(&c));
    }

    #[test]
    fn llm_url_alone_selects_the_generic_provider() {
        let c = LlmConfig::from_vars(vars(&[("READYHAI_LLM_URL", "http://localhost:8000/v1")]))
            .unwrap();
        assert_eq!(c.provider.id, "vllm");
        assert_eq!(c.model, "qwen3.8-flash-next");
        assert_eq!(c.base_url().unwrap(), "http://localhost:8000/v1");
        // no URL at all: configured, but with nowhere to send, and the error says what to export
        let c = LlmConfig::from_vars(vars(&[])).unwrap();
        assert_eq!(c.provider.id, "vllm");
        let e = c.base_url().unwrap_err().to_string();
        assert!(e.contains("READYHAI_LLM_URL"), "{e}");
        // the alias ids select the same generic provider
        for id in ["openai-compatible", "custom"] {
            let c = LlmConfig::from_vars(vars(&[
                ("READYHAI_LLM_PROVIDER", id),
                ("READYHAI_LLM_URL", "http://localhost:8000/v1"),
            ]))
            .unwrap();
            assert_eq!(c.provider.id, "vllm");
        }
    }

    #[test]
    fn vllm_url_is_a_deprecated_fallback_alias() {
        let old = "http://old-box:8000/v1";
        let c = LlmConfig::from_vars(vars(&[("READYHAI_VLLM_URL", old)])).unwrap();
        assert_eq!((c.provider.id, c.base_url().unwrap()), ("vllm", old.into()));
        // READYHAI_LLM_URL wins when both are set
        let c = LlmConfig::from_vars(vars(&[
            ("READYHAI_VLLM_URL", old),
            ("READYHAI_LLM_URL", "http://new-box:8000/v1"),
        ]))
        .unwrap();
        assert_eq!(c.base_url().unwrap(), "http://new-box:8000/v1");
        // the alias belongs to the generic provider only: it never redirects another one
        let c = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", "ollama"),
            ("READYHAI_VLLM_URL", old),
        ]))
        .unwrap();
        assert_eq!(c.base_url().unwrap(), "http://localhost:11434/v1");
    }

    #[test]
    fn empty_variables_count_as_unset() {
        let c = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", ""),
            ("READYHAI_LLM_URL", "  "),
            ("READYHAI_VLLM_URL", ""),
            ("READYHAI_LLM_API_KEY", ""),
            ("READYHAI_LLM_MODEL", ""),
            ("READYHAI_LLM_MODELS", " "),
        ]))
        .unwrap();
        assert_eq!(c.provider.id, "vllm");
        assert!(c.base_override.is_none() && c.api_key.is_none());
        assert_eq!(c.models, [c.provider.default_model]);
    }

    #[test]
    fn base_url_validation_rejects_secrets_and_never_echoes_them() {
        for bad in [
            "not a url",
            "ftp://host/v1",
            "file:///etc/passwd",
            "http://",
            "http://svc:s3cretpw@host:8000/v1",
            "http://host:8000/v1?api_key=tok-9f8e7d",
            "http://host:8000/v1#tok-9f8e7d",
        ] {
            let e = validate_base_url(bad).unwrap_err().to_string();
            assert!(
                !e.contains("s3cretpw") && !e.contains("tok-9f8e7d"),
                "{bad}: {e}"
            );
            assert!(
                LlmConfig::from_vars(vars(&[("READYHAI_LLM_URL", bad)])).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            validate_base_url("  http://host:8000/v1/ ").unwrap(),
            "http://host:8000/v1/"
        );
    }

    #[test]
    fn public_host_classification() {
        for h in [
            "localhost",
            "127.0.0.1",
            "127.5.5.5",
            "[::1]",
            "::1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.5",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
            "gpu-box",
            "ollama",
            "vllm.lan",
            "gpu.local",
            "host.docker.internal",
            "svc.ns.svc.cluster.local",
            "box.corp.internal",
            "GPU.LAN.",
            "app.localhost",
            "nas.home.arpa",
        ] {
            assert!(!is_public_host(h), "{h} must not count as public");
        }
        for h in [
            "api.openai.com",
            "llm.example.com",
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "172.15.255.255",
            "100.128.0.1",
            "100.63.255.255",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "example.lan.com",
            "internal.example.com",
        ] {
            assert!(is_public_host(h), "{h} must count as public");
        }
        assert_eq!(
            public_host_of("https://llm.example.com/v1").as_deref(),
            Some("llm.example.com")
        );
        assert_eq!(public_host_of("http://10.0.0.5:8000/v1"), None);
        assert!(public_host_of("garbage").is_some(), "fails closed");
    }

    #[test]
    fn public_url_with_a_local_provider_needs_allow_cloud() {
        let public = "https://llm.example.com/v1";
        let e = LlmConfig::from_vars(vars(&[("READYHAI_LLM_URL", public)]))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("READYHAI_LLM_ALLOW_CLOUD")
                && e.contains("llm.example.com")
                && e.contains("refused"),
            "{e}"
        );
        // the deprecated variable and other local providers are guarded the same way
        assert!(LlmConfig::from_vars(vars(&[("READYHAI_VLLM_URL", public)])).is_err());
        assert!(
            LlmConfig::from_vars(vars(&[
                ("READYHAI_LLM_PROVIDER", "ollama"),
                ("READYHAI_LLM_URL", public)
            ]))
            .is_err()
        );
        for flag in ["1", "true"] {
            assert!(
                LlmConfig::from_vars(vars(&[
                    ("READYHAI_LLM_URL", public),
                    ("READYHAI_LLM_ALLOW_CLOUD", flag)
                ]))
                .is_ok(),
                "{flag}"
            );
        }
        for private in [
            "http://127.0.0.1:8000/v1",
            "http://10.0.0.5:8000/v1",
            "http://gpu-box:8000/v1",
            "http://vllm.lan/v1",
            "http://host.docker.internal:11434/v1",
            "http://[::1]:8000/v1",
        ] {
            assert!(
                LlmConfig::from_vars(vars(&[("READYHAI_LLM_URL", private)])).is_ok(),
                "{private}"
            );
        }
        // a cloud provider stays refused without the flag, whatever the URL
        assert!(
            LlmConfig::from_vars(vars(&[
                ("READYHAI_LLM_PROVIDER", "openai"),
                ("READYHAI_LLM_URL", "http://10.0.0.5/v1")
            ]))
            .is_err()
        );
        // a config assembled by hand cannot get around it: nothing is sent, nothing is probed
        let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
        c.base_override = Some(public.into());
        assert!(c.guard().is_err());
        assert!(
            ask_json(&c, &mut Budget::per_run(), "s", "p")
                .unwrap_err()
                .to_string()
                .contains("refused")
        );
        assert!(!probe(&c) && probe_status(&c).is_none());
        assert!(query_models(&c).is_err());
        assert!(client(c).chat("s", &[], &[]).is_err());
    }

    #[test]
    fn generic_api_key_wins_over_the_provider_key() {
        let provider_env = |k: &str| (k == "OPENAI_API_KEY").then(|| "provider-key".to_string());
        let own = LlmConfig::resolve(Some("openai"), None, true).unwrap();
        assert_eq!(
            key_with(&own, provider_env).unwrap().as_deref(),
            Some("provider-key")
        );
        let generic = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", "openai"),
            ("READYHAI_LLM_ALLOW_CLOUD", "1"),
            ("READYHAI_LLM_API_KEY", " generic-key\n"),
        ]))
        .unwrap();
        assert_eq!(
            key_with(&generic, provider_env).unwrap().as_deref(),
            Some("generic-key")
        );
        assert_eq!(
            key_with(&generic, |_| None).unwrap().as_deref(),
            Some("generic-key"),
            "the provider variable is not needed"
        );
        // neither set: the error names the variables, never a value
        let e = key_with(&own, |_| None).unwrap_err().to_string();
        assert!(
            e.contains("OPENAI_API_KEY") && e.contains("READYHAI_LLM_API_KEY"),
            "{e}"
        );
        assert!(key_with(&own, |_| Some("  ".into())).is_err());
        // local providers need no key, but accept the generic one
        let local = LlmConfig::resolve(Some("ollama"), None, false).unwrap();
        assert_eq!(key_with(&local, |_| Some("x".into())).unwrap(), None);
        let local_keyed = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", "ollama"),
            ("READYHAI_LLM_API_KEY", "local-key"),
        ]))
        .unwrap();
        assert_eq!(
            key_with(&local_keyed, |_| None).unwrap().as_deref(),
            Some("local-key")
        );
        // a key that cannot be a header value is an error, not a silently dropped header
        let bad = LlmConfig::from_vars(vars(&[("READYHAI_LLM_API_KEY", "a\nb")])).unwrap();
        let e = key_with(&bad, |_| None).unwrap_err().to_string();
        assert!(
            e.contains("control character") && !e.contains("a\nb"),
            "{e}"
        );
    }

    #[test]
    fn key_goes_out_as_bearer_or_x_api_key_and_is_never_shown() {
        const K: &str = "generic-test-key-0123456789abcdef";
        let wire = |m: &mock::Mock| m.requests.lock().unwrap()[0].to_ascii_lowercase();
        let secret = K.to_ascii_lowercase();

        // OpenAI-compatible: bearer
        let m = mock::start(|_| "{\"ok\": true}".into());
        let mut c = mock::cfg(&m.base, &tmpdir("key-openai"));
        c.api_key = Some(ApiKey::new(K));
        ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap();
        let raw = wire(&m);
        assert!(
            raw.contains(&format!("authorization: bearer {secret}")),
            "{raw}"
        );
        assert!(!raw.contains("x-api-key"));

        // Anthropic transport: x-api-key plus the version header, no bearer
        let m = mock::start_status(|_, _| {
            (
                200,
                json!({"content": [{"type": "text", "text": "{\"ok\": true}"}]}).to_string(),
            )
        });
        let mut a = LlmConfig::resolve(Some("anthropic"), None, true).unwrap();
        a.base_override = Some(m.base.clone());
        a.cache_dir = Some(tmpdir("key-anthropic"));
        a.retry_base_ms = 1;
        a.api_key = Some(ApiKey::new(K));
        ask_json(&a, &mut Budget::per_run(), "s", "p").unwrap();
        let raw = wire(&m);
        assert!(raw.contains(&format!("x-api-key: {secret}")), "{raw}");
        assert!(raw.contains("anthropic-version: 2023-06-01"));
        assert!(!raw.contains("authorization"));
        // the status probe authenticates the same way
        assert_eq!(probe_status(&a), Some(200));

        // nothing a human or a log can see carries it
        for s in [
            format!("{a:?}"),
            a.describe(),
            a.thinking_summary(),
            format!("{:?}", ApiKey::new(K)),
        ] {
            assert!(!s.contains(K), "{s}");
        }
        assert!(format!("{a:?}").contains("<redacted>"));
        let bad = mock::start_status(|_, _| (401, "{}".into()));
        let mut c = mock::cfg(&bad.base, &tmpdir("key-err"));
        c.api_key = Some(ApiKey::new(K));
        let e = format!(
            "{:#}",
            ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap_err()
        );
        assert!(e.contains("401") && !e.contains(K), "{e}");
    }

    #[test]
    fn model_list_parsing() {
        assert_eq!(parse_model_list("a, b ,,a,c"), ["a", "b", "c"]);
        assert!(parse_model_list(" , ").is_empty());
        let c = LlmConfig::from_vars(vars(&[("READYHAI_LLM_MODEL", "m1, m2,m3")])).unwrap();
        assert_eq!(c.model, "m1");
        assert_eq!(c.models, ["m1", "m2", "m3"]);
        assert_eq!(c.describe(), "vllm/m1 (+2 fallbacks)");
        // READYHAI_LLM_MODELS is an alias, used only when READYHAI_LLM_MODEL is unset
        let c = LlmConfig::from_vars(vars(&[("READYHAI_LLM_MODELS", "x,y")])).unwrap();
        assert_eq!(
            (c.model.as_str(), c.describe()),
            ("x", "vllm/x (+1 fallback)".into())
        );
        let c = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_MODEL", "only"),
            ("READYHAI_LLM_MODELS", "x,y"),
        ]))
        .unwrap();
        assert_eq!(c.models, ["only"]);
        assert_eq!(c.describe(), "vllm/only");
        // nothing (or only separators): the provider default
        for v in [vars(&[]), vars(&[("READYHAI_LLM_MODEL", ",")])] {
            let c = LlmConfig::from_vars(v).unwrap();
            assert_eq!(c.models, ["qwen3.8-flash-next"]);
        }
        let o = LlmConfig::resolve(Some("ollama"), Some("p,q"), false).unwrap();
        assert_eq!((o.model.as_str(), o.models.len()), ("p", 2));
        // `model` stays the source of truth for the primary even when a caller reassigns it
        let mut c = LlmConfig::resolve(Some("ollama"), Some("m1,m2,m3"), false).unwrap();
        c.model = "other".into();
        assert_eq!(c.model_chain(), ["other", "m1", "m2", "m3"]);
        c.model = "m2".into();
        assert_eq!(c.model_chain(), ["m2", "m1", "m3"]);
    }

    fn fallback_cfg(m: &mock::Mock, name: &str, models: &str) -> LlmConfig {
        let mut c = mock::cfg(&m.base, &tmpdir(name));
        c.models = parse_model_list(models);
        c.model = c.models[0].clone();
        c
    }

    #[test]
    fn failed_calls_fall_back_to_the_next_model_in_order() {
        // m1: 500 (retried once), m2: 404 (not retried), m3: answers
        let m = mock::start_status(|_, body| match model_of(body).as_str() {
            "m1" => (500, "{}".into()),
            "m2" => (404, "{}".into()),
            _ => (200, ok_body("{\"ok\": true}")),
        });
        let c = fallback_cfg(&m, "fallback", "m1,m2,m3");
        let mut b = Budget::per_run();
        assert_eq!(ask_json(&c, &mut b, "s", "p").unwrap()["ok"], true);
        assert_eq!(models_seen(&m), ["m1", "m1", "m2", "m3"]);
        assert_eq!(b.calls, 1, "fallbacks are part of one logical call");

        // an unusable answer (reasoning only / empty) is a failure too
        let m = mock::start_status(|_, body| {
            if model_of(body) == "m1" {
                (200, ok_body(""))
            } else {
                (200, ok_body("{\"ok\": true}"))
            }
        });
        let c = fallback_cfg(&m, "fallback-empty", "m1,m2");
        assert_eq!(
            ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
            true
        );
        assert_eq!(models_seen(&m), ["m1", "m2"]);

        // a healthy primary never touches the fallbacks
        let m = mock::start(|_| "{\"ok\": true}".into());
        let c = fallback_cfg(&m, "fallback-unused", "m1,m2");
        ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap();
        assert_eq!(models_seen(&m), ["m1"]);
    }

    #[test]
    fn when_every_model_fails_the_error_names_them_all() {
        let m = mock::start_status(|_, _| (401, "{}".into()));
        let c = fallback_cfg(&m, "fallback-all", "m1,m2");
        let e = ask_json(&c, &mut Budget::per_run(), "s", "p")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("all 2 configured models failed")
                && e.contains("'m1'")
                && e.contains("'m2'"),
            "{e}"
        );
        assert_eq!(models_seen(&m), ["m1", "m2"], "401 is not retried");
        // one model: its own error, unchanged
        let m = mock::start_status(|_, _| (401, "{}".into()));
        let c = fallback_cfg(&m, "fallback-one", "m1");
        let e = ask_json(&c, &mut Budget::per_run(), "s", "p")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("configured models") && e.contains("401"), "{e}");
    }

    #[test]
    fn chat_clients_fall_back_too() {
        let msgs = [Msg {
            role: "user".into(),
            content: "hi".into(),
        }];
        // OpenAI-compatible
        let m = mock::start_status(|_, body| match model_of(body).as_str() {
            "m1" => (400, "{}".into()),
            _ => (200, ok_body("hello")),
        });
        let c = fallback_cfg(&m, "chat-openai", "m1,m2");
        assert_eq!(client(c).chat("sys", &msgs, &[]).unwrap().text, "hello");
        assert_eq!(models_seen(&m), ["m1", "m2"]);

        // Anthropic Messages, through both chat() and the single-shot path
        let answer = |body: &str| match model_of(body).as_str() {
            "m1" => (400, "{}".to_string()),
            _ => (
                200,
                json!({"content": [{"type": "text", "text": "{\"ok\": true}"}]}).to_string(),
            ),
        };
        let m = mock::start_status(move |_, body| answer(body));
        let mut a = LlmConfig::resolve(Some("anthropic"), Some("m1,m2"), true).unwrap();
        a.base_override = Some(m.base.clone());
        a.cache_dir = Some(tmpdir("chat-anthropic"));
        a.retry_base_ms = 1;
        a.api_key = Some(ApiKey::new("k"));
        assert_eq!(
            client(a.clone()).chat("sys", &msgs, &[]).unwrap().text,
            "{\"ok\": true}"
        );
        assert_eq!(models_seen(&m), ["m1", "m2"]);
        assert_eq!(
            ask_json(&a, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
            true
        );
        assert_eq!(models_seen(&m), ["m1", "m2", "m1", "m2"]);
    }

    fn tool() -> ToolDef {
        ToolDef {
            name: "t".into(),
            description: "d".into(),
            schema: json!({"type": "object"}),
        }
    }

    #[test]
    fn body_shapes() {
        let msgs = [Msg {
            role: "user".into(),
            content: "hi".into(),
        }];
        let o = OpenAiClient {
            cfg: LlmConfig::resolve(Some("ollama"), None, false).unwrap(),
        };
        let b = o.body("sys", &msgs, &[tool()]);
        assert_eq!(b["messages"][0]["role"], "system");
        assert_eq!(b["tools"][0]["function"]["name"], "t");
        let a = AnthropicClient {
            cfg: LlmConfig::resolve(Some("anthropic"), None, true).unwrap(),
        };
        let b = a.body("sys", &msgs, &[tool()]);
        assert_eq!(b["system"], "sys");
        assert_eq!(b["tools"][0]["input_schema"]["type"], "object");
        assert_eq!(b["messages"][0]["content"], "hi");
    }

    #[test]
    fn think_and_json() {
        let v = parse_json_object("<think>hmm {x}</think>\n```json\n{\"a\": 1}\n```").unwrap();
        assert_eq!(v["a"], 1);
        assert!(parse_json_object("not json").is_err());
        assert!(parse_json_object("{broken").is_err());
        assert_eq!(strip_think("a<think>b"), "a");
    }

    #[test]
    fn probe_and_cloud() {
        let d = std::env::temp_dir().join("rh-llm-probe");
        let m = mock::start(|_| "{}".into());
        assert!(probe(&mock::cfg(&m.base, &d)));
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!("http://{}/v1", l.local_addr().unwrap());
        drop(l);
        let t = std::time::Instant::now();
        assert!(!probe(&mock::cfg(&dead, &d)));
        assert!(t.elapsed().as_secs() < 3);
        let mut c = LlmConfig::resolve(Some("anthropic"), None, true).unwrap();
        c.allow_cloud = false;
        let mut b = Budget::per_run();
        assert!(
            ask_json(&c, &mut b, "s", "p")
                .unwrap_err()
                .to_string()
                .contains("refused")
        );
    }

    #[test]
    fn cache_and_budget() {
        let d = std::env::temp_dir().join(format!("rh-llm-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let m = mock::start(|_| "<think>x</think>{\"ok\": true}".into());
        let c = mock::cfg(&m.base, &d);
        let mut b = Budget::new(2, Duration::from_secs(60));
        assert_eq!(ask_json(&c, &mut b, "s", "p1").unwrap()["ok"], true);
        assert_eq!(ask_json(&c, &mut b, "s", "p1").unwrap()["ok"], true);
        assert_eq!(m.chat_hits.load(Ordering::SeqCst), 1);
        assert!(ask_json(&c, &mut b, "s", "p2").is_ok());
        assert!(
            ask_json(&c, &mut b, "s", "p3")
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
        assert_eq!(m.chat_hits.load(Ordering::SeqCst), 2);
    }

    fn tmpdir(n: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rh-llm-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn ok_body(content: &str) -> String {
        json!({"choices": [{"message": {"role": "assistant", "content": content}}]}).to_string()
    }

    #[test]
    fn retries_429_and_5xx_with_backoff_then_succeeds() {
        let m = mock::start_status(|hit, _| match hit {
            0 => (429, "{\"error\":\"slow down\"}".into()),
            1 => (503, "{\"error\":\"busy\"}".into()),
            _ => (200, ok_body("{\"ok\": true}")),
        });
        let c = mock::cfg(&m.base, &tmpdir("retry"));
        let mut b = Budget::per_run();
        assert_eq!(ask_json(&c, &mut b, "s", "p").unwrap()["ok"], true);
        assert_eq!(
            m.chat_hits.load(Ordering::SeqCst),
            3,
            "two transient failures then success"
        );
        assert_eq!(b.calls, 1, "retries are one logical call");
    }

    #[test]
    fn gives_up_after_max_attempts_and_does_not_retry_client_errors() {
        let m = mock::start_status(|_, _| (500, "{\"error\":\"boom\"}".into()));
        let c = mock::cfg(&m.base, &tmpdir("giveup"));
        assert!(ask_json(&c, &mut Budget::per_run(), "s", "p").is_err());
        assert_eq!(
            m.chat_hits.load(Ordering::SeqCst),
            2,
            "a 5xx is retried once, not max_attempts times"
        );

        // 429 keeps the full retry budget (Retry-After is honoured by the mock as 0)
        let m = mock::start_status(|_, _| (429, "{\"error\":\"slow\"}".into()));
        let c = mock::cfg(&m.base, &tmpdir("giveup-429"));
        assert!(ask_json(&c, &mut Budget::per_run(), "s", "p").is_err());
        assert_eq!(m.chat_hits.load(Ordering::SeqCst) as u32, c.max_attempts);

        let m = mock::start_status(|_, _| (401, "{\"error\":\"nope\"}".into()));
        let c = mock::cfg(&m.base, &tmpdir("noretry"));
        assert!(ask_json(&c, &mut Budget::per_run(), "s", "p").is_err());
        assert_eq!(m.chat_hits.load(Ordering::SeqCst), 1, "401 is not retried");
    }

    /// A server that accepts connections and never answers; the counter is how many arrived.
    fn silent_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/v1", l.local_addr().unwrap());
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a2 = accepted.clone();
        std::thread::spawn(move || {
            let mut held = vec![];
            for s in l.incoming().flatten() {
                a2.fetch_add(1, Ordering::SeqCst);
                held.push(s); // accept and never answer
            }
        });
        (base, accepted)
    }

    fn body_of(req: &str) -> Value {
        serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap()
    }

    fn sent_bodies(m: &mock::Mock) -> Vec<Value> {
        m.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| body_of(r))
            .collect()
    }

    #[test]
    fn a_timeout_is_not_retried_identically() {
        let (base, accepted) = silent_server();
        let mut c = mock::cfg(&base, &tmpdir("timeout"));
        c.timeout_override = Some(Duration::from_millis(200));
        let t = std::time::Instant::now();
        // 2048 tokens -> one smaller request (1024); then nothing would change, so it stops
        let e = ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap_err();
        assert!(is_timeout_error(&e), "{e:#}");
        assert!(e.to_string().contains("timed out"), "{e:#}");
        assert!(e.to_string().contains("max_tokens"), "{e:#}");
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "{e:#}");
        assert!(t.elapsed() < Duration::from_secs(5));

        // the chat clients send once per model and do not repeat a timed-out request
        let before = accepted.load(Ordering::SeqCst);
        let msgs = [Msg {
            role: "user".into(),
            content: "hi".into(),
        }];
        let e = client(c).chat("sys", &msgs, &[]).unwrap_err();
        assert!(is_timeout_error(&e), "{e:#}");
        assert_eq!(accepted.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn call_timeout_scales_with_the_answer_size() {
        // 20 s + max_tokens / 40, clamped to 30..=300
        assert_eq!(call_timeout_secs(1), 30);
        assert_eq!(call_timeout_secs(400), 30);
        assert_eq!(call_timeout_secs(2048), 71);
        assert_eq!(call_timeout_secs(10_240), 276);
        assert_eq!(call_timeout_secs(34_816), 300);
        assert_eq!(call_timeout_secs(u32::MAX), 300);
        let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
        assert_eq!(c.call_timeout(10_240), Duration::from_secs(276));
        c.timeout_override = Some(Duration::from_secs(45));
        assert_eq!(c.call_timeout(10_240), Duration::from_secs(45));
        assert_eq!(c.call_timeout(1), Duration::from_secs(45));
    }

    #[test]
    fn timeout_env_override() {
        let base = ("READYHAI_LLM_URL", "http://localhost:8000/v1");
        let get = |v: &str| LlmConfig::from_vars(vars(&[base, ("READYHAI_LLM_TIMEOUT_SECS", v)]));
        assert_eq!(
            get("45").unwrap().timeout_override,
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            get(" 7 ").unwrap().timeout_override,
            Some(Duration::from_secs(7))
        );
        assert_eq!(get("").unwrap().timeout_override, None, "empty is unset");
        assert!(
            LlmConfig::from_vars(vars(&[base]))
                .unwrap()
                .timeout_override
                .is_none()
        );
        for bad in ["abc", "0", "-3", "3601", "1.5"] {
            let e = get(bad).unwrap_err().to_string();
            assert!(e.contains("READYHAI_LLM_TIMEOUT_SECS"), "{bad}: {e}");
        }
    }

    #[test]
    fn downgrade_halves_tokens_to_a_floor_and_stops_when_nothing_changes() {
        assert_eq!(downgrade(34_816, true), Some(17_408));
        assert_eq!(downgrade(2048, false), Some(1024));
        assert_eq!(downgrade(1500, false), Some(1024));
        assert_eq!(
            downgrade(1024, true),
            Some(1024),
            "dropping the effort is a change"
        );
        assert_eq!(downgrade(1024, false), None);
        assert_eq!(downgrade(512, false), None, "never grows");
    }

    fn thinking_cfg(m: &mock::Mock, name: &str, models: &str) -> LlmConfig {
        let mut c = fallback_cfg(m, name, models);
        c.thinking = true;
        c.thinking_budget_tokens = 8192;
        c.model_tier = "high".into();
        c.timeout_override = Some(Duration::from_millis(500));
        c
    }

    fn max_tokens_of(b: &Value) -> u64 {
        b["max_tokens"].as_u64().unwrap()
    }

    #[test]
    fn a_timed_out_call_is_retried_smaller_and_without_reasoning() {
        // answers fast once the request is under 6000 tokens; a bigger one outlasts the 500 ms timeout
        let m = mock::start_status(|_, body| {
            let big = serde_json::from_str::<Value>(body).unwrap()["max_tokens"]
                .as_u64()
                .unwrap()
                > 6000;
            if big {
                std::thread::sleep(Duration::from_millis(650));
            }
            (200, ok_body("{\"ok\": true}"))
        });
        let c = thinking_cfg(&m, "downgrade-ok", "m1");
        let mut b = Budget::per_run();
        assert_eq!(ask_json(&c, &mut b, "s", "p").unwrap()["ok"], true);
        let bodies = sent_bodies(&m);
        assert_eq!(bodies.len(), 2, "{bodies:?}");
        assert_eq!(max_tokens_of(&bodies[0]), 10_240);
        assert_eq!(bodies[0]["reasoning_effort"], "high");
        assert_eq!(max_tokens_of(&bodies[1]), 5120);
        assert!(bodies[1].get("reasoning_effort").is_none(), "{}", bodies[1]);
        assert_eq!(b.calls, 1, "the retry is part of one logical call");
        let note = b.notes.join(" | ");
        assert!(
            note.contains("timed out") && note.contains("succeeded") && note.contains("5120"),
            "{note}"
        );
        assert!(!note.contains("Bearer"), "{note}");
    }

    #[test]
    fn at_most_two_downgrades_then_the_next_model() {
        // m1 never answers in time; m2 answers
        let m = mock::start_status(|_, body| {
            if model_of(body) == "m1" {
                std::thread::sleep(Duration::from_millis(550));
            }
            (200, ok_body("{\"ok\": true}"))
        });
        let c = thinking_cfg(&m, "downgrade-chain", "m1,m2");
        let mut b = Budget::per_run();
        assert_eq!(ask_json(&c, &mut b, "s", "p").unwrap()["ok"], true);
        assert_eq!(models_seen(&m), ["m1", "m1", "m1", "m2"]);
        let sizes: Vec<u64> = sent_bodies(&m).iter().map(max_tokens_of).collect();
        // the next model starts again from the full request
        assert_eq!(sizes, [10_240, 5120, 2560, 10_240]);
        assert!(
            b.notes.iter().any(|n| n.contains("gave up")),
            "{:?}",
            b.notes
        );

        // with no model left the error says what was tried
        let m = mock::start_status(|_, _| {
            std::thread::sleep(Duration::from_millis(550));
            (200, ok_body("{}"))
        });
        let c = thinking_cfg(&m, "downgrade-exhausted", "m1");
        let e = ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap_err();
        assert!(is_timeout_error(&e), "{e:#}");
        let msg = e.to_string();
        assert!(
            msg.contains("3 time(s)")
                && msg.contains("max_tokens 10240")
                && msg.contains("max_tokens 2560"),
            "{msg}"
        );
    }

    #[test]
    fn a_server_error_is_retried_once_then_the_next_model_is_tried() {
        let m = mock::start_status(|_, body| {
            if model_of(body) == "m1" {
                (500, "{}".into())
            } else {
                (200, ok_body("{\"ok\": true}"))
            }
        });
        let c = fallback_cfg(&m, "five-hundred", "m1,m2");
        assert_eq!(
            ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
            true
        );
        assert_eq!(models_seen(&m), ["m1", "m1", "m2"]);
        // a 500 that heals on the retry stays on the same model
        let m = mock::start_status(|hit, _| {
            if hit == 0 {
                (500, "{}".into())
            } else {
                (200, ok_body("{\"ok\": true}"))
            }
        });
        let c = fallback_cfg(&m, "five-hundred-heals", "m1,m2");
        ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap();
        assert_eq!(models_seen(&m), ["m1", "m1"]);
    }

    #[test]
    fn probe_latency_sends_a_one_token_completion() {
        let m = mock::start(|_| {
            std::thread::sleep(Duration::from_millis(120));
            "x".into()
        });
        let c = mock::cfg(&m.base, &tmpdir("latency"));
        let d = probe_latency(&c).unwrap();
        assert!(
            d >= Duration::from_millis(120) && d < Duration::from_secs(5),
            "{d:?}"
        );
        let bodies = sent_bodies(&m);
        assert_eq!(bodies.len(), 1);
        assert_eq!(max_tokens_of(&bodies[0]), 1);
        assert!(bodies[0].get("reasoning_effort").is_none());
        assert!(
            bodies[0].to_string().len() < 200,
            "tiny prompt: {}",
            bodies[0]
        );
        let r = latency_report(&Ok(d));
        assert!(
            r.summary.starts_with("latency ") && r.summary.ends_with(" ms"),
            "{r:?}"
        );
        assert!(!r.slow);
    }

    #[test]
    fn probe_latency_times_out_although_models_answers() {
        let m = mock::start_status(|_, _| {
            std::thread::sleep(Duration::from_millis(700));
            (200, ok_body("x"))
        });
        let mut c = mock::cfg(&m.base, &tmpdir("latency-slow"));
        c.timeout_override = Some(Duration::from_millis(300));
        let e = probe_latency(&c).unwrap_err();
        assert!(is_timeout_error(&e), "{e:#}");
        assert!(probe(&c), "/models answers: the server is up");
        let r = latency_report(&Err(e));
        assert!(r.slow && r.summary.contains("timed out"), "{r:?}");
        // an HTTP error is a failed probe, not a slow endpoint
        let bad = mock::start_status(|_, _| (401, "{}".into()));
        let c = mock::cfg(&bad.base, &tmpdir("latency-401"));
        let r = latency_report(&probe_latency(&c));
        assert!(!r.slow && r.summary.contains("401"), "{r:?}");
        // unreachable
        let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
        c.base_override = Some("http://127.0.0.1:1/v1".into());
        assert!(probe_latency(&c).is_err());
    }

    #[test]
    fn latency_above_ten_seconds_is_slow() {
        assert!(!latency_report(&Ok(Duration::from_millis(840))).slow);
        assert!(!latency_report(&Ok(SLOW_LATENCY)).slow);
        assert!(latency_report(&Ok(Duration::from_millis(10_001))).slow);
        assert_eq!(
            latency_report(&Ok(Duration::from_millis(840))).summary,
            "latency 840 ms"
        );
    }

    #[test]
    fn a_slow_endpoint_caps_thinking_at_the_high_tier() {
        let base = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
        let think =
            |on: bool, tier: &str, budget: u32| base.clone().with_thinking(on, tier, budget);
        let c = think(true, "max_pro", 32_768);
        let capped = c.capped_to_high_tier().unwrap();
        assert_eq!(capped.model_tier, "high");
        assert_eq!(capped.thinking_budget_tokens, 8192);
        assert_eq!(call_params(&capped).max_tokens, 10_240);
        assert!(think(true, "high", 8192).capped_to_high_tier().is_none());
        assert!(think(true, "medium", 2048).capped_to_high_tier().is_none());
        assert!(think(false, "max", 32_768).capped_to_high_tier().is_none());
        // a big budget under a lower tier name is held to the High budget, the name is kept
        let k = think(true, "medium", 20_000).capped_to_high_tier().unwrap();
        assert_eq!(
            (k.model_tier.as_str(), k.thinking_budget_tokens),
            ("medium", 8192)
        );
    }

    #[test]
    fn gate_and_triage_calls_never_think() {
        let m = mock::start(|_| "{\"ok\": true}".into());
        let mut c = mock::cfg(&m.base, &tmpdir("light"));
        c = c.with_thinking(true, "max_pro", 32_768);
        // the planner's config reasons ...
        ask_json(&c, &mut Budget::per_run(), "s", "planner").unwrap();
        // ... the gate's and the triager's do not
        ask_json(&c.without_thinking(), &mut Budget::per_run(), "s", "gate").unwrap();
        let bodies = sent_bodies(&m);
        assert_eq!(max_tokens_of(&bodies[0]), 34_816);
        assert_eq!(bodies[0]["reasoning_effort"], "high");
        assert_eq!(max_tokens_of(&bodies[1]), 2048);
        assert!(bodies[1].get("reasoning_effort").is_none(), "{}", bodies[1]);
    }

    #[test]
    fn reasoning_field_is_never_the_answer() {
        let m = mock::start_status(|_, _| {
            (200, json!({"choices": [{"finish_reason": "length", "message": {"role": "assistant", "content": "", "reasoning": "thinking... {\"ok\": true}"}}]}).to_string())
        });
        let d = tmpdir("reasoning");
        let c = mock::cfg(&m.base, &d);
        let e = ask_json(&c, &mut Budget::per_run(), "s", "p")
            .unwrap_err()
            .to_string();
        assert!(e.contains("reasoning"), "{e}");
        assert!(
            !d.exists() || std::fs::read_dir(&d).map(|r| r.count()).unwrap_or(0) == 0,
            "nothing cached"
        );
    }

    #[test]
    fn schema_invalid_output_is_not_cached_and_valid_is() {
        let m = mock::start_status(|hit, _| {
            if hit == 0 {
                (200, ok_body("{\"wrong\": 1}"))
            } else {
                (200, ok_body("{\"summary\": \"fine\"}"))
            }
        });
        let d = tmpdir("schema");
        let c = mock::cfg(&m.base, &d);
        let need_summary = |v: &Value| {
            if v["summary"].is_string() {
                Ok(())
            } else {
                bail!("summary missing")
            }
        };
        let mut b = Budget::per_run();
        let e = ask_json_with(&c, &mut b, "s", "p", need_summary)
            .unwrap_err()
            .to_string();
        assert!(e.contains("schema"), "{e}");
        assert!(
            !d.exists() || std::fs::read_dir(&d).unwrap().count() == 0,
            "invalid output must not be cached"
        );
        // same prompt again: asks the model again (nothing was cached), now valid, now cached
        assert_eq!(
            ask_json_with(&c, &mut b, "s", "p", need_summary).unwrap()["summary"],
            "fine"
        );
        assert_eq!(m.chat_hits.load(Ordering::SeqCst), 2);
        assert_eq!(
            ask_json_with(&c, &mut b, "s", "p", need_summary).unwrap()["summary"],
            "fine"
        );
        assert_eq!(
            m.chat_hits.load(Ordering::SeqCst),
            2,
            "valid output served from cache"
        );
        // a cached entry that fails a stricter validator is ignored and re-asked
        let strict = |v: &Value| {
            if v["other"].is_string() {
                Ok(())
            } else {
                bail!("other missing")
            }
        };
        assert!(ask_json_with(&c, &mut b, "s", "p", strict).is_err());
        assert_eq!(m.chat_hits.load(Ordering::SeqCst), 3);
    }

    #[derive(serde::Deserialize, Debug)]
    struct Out {
        items: Vec<String>,
    }

    #[test]
    fn ask_typed_validates_with_serde() {
        let m = mock::start(|_| "{\"items\": \"not-a-list\"}".into());
        let c = mock::cfg(&m.base, &tmpdir("typed"));
        assert!(ask_typed::<Out>(&c, &mut Budget::per_run(), "s", "p", |_| Ok(())).is_err());
        let m = mock::start(|_| "{\"items\": [\"a\"]}".into());
        let c = mock::cfg(&m.base, &tmpdir("typed2"));
        let o = ask_typed::<Out>(&c, &mut Budget::per_run(), "s", "p", |o| {
            if o.items.is_empty() {
                bail!("empty")
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(o.items, ["a"]);
    }

    #[test]
    fn redaction() {
        let t = "key sk-abcdef0123456789ABCD jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdefgh12345 password=hunter22x hash 0123456789abcdef0123456789abcdef ok";
        let r = redact_for_llm(t);
        assert!(
            !r.contains("sk-abc")
                && !r.contains("eyJ")
                && !r.contains("hunter22")
                && !r.contains("0123456789abcdef0123")
        );
        assert!(r.contains("ok"));
    }

    #[test]
    fn redaction_by_key_name_suffix_in_text() {
        let t = "DB_PASSWORD=s3cr3tvalue\nSTRIPE_SECRET: abc123\nAPP_KEY=base64:zzzz\n{\"admin_password\": \"p@ss\", \"user\": \"bob\"}\nAuthorization: Bearer abcdef.ghijkl.mnopqr\npostgres://svc:pw1234@db.internal/x\nplain: value";
        let r = redact_for_llm(t);
        for leak in [
            "s3cr3tvalue",
            "abc123",
            "base64:zzzz",
            "p@ss",
            "abcdef.ghijkl",
            "pw1234",
        ] {
            assert!(!r.contains(leak), "leaked {leak} in {r}");
        }
        assert!(
            r.contains("\"user\": \"bob\"")
                && r.contains("plain: value")
                && r.contains("db.internal"),
            "{r}"
        );
    }

    #[test]
    fn redact_value_is_structural() {
        let tok_secret = format!("abcdef{}", "123456");
        let tok_val = format!("token={tok_secret}");
        let v = json!({"PASSWORD": "x", "db": {"user_secret": ["a", "b"], "host": "h"}, "arr": [{"api_key": 1}, tok_val], "n": 5, "nul": null});
        let r = redact_value(&v);
        assert_eq!(r["PASSWORD"], "[REDACTED]");
        assert_eq!(r["db"]["user_secret"], "[REDACTED]");
        assert_eq!(r["db"]["host"], "h");
        assert_eq!(r["arr"][0]["api_key"], "[REDACTED]");
        assert!(!r["arr"][1].as_str().unwrap().contains(&tok_secret));
        assert_eq!(r["n"], 5);
        assert!(
            is_sensitive_key("x-api-key")
                && is_sensitive_key("stripeKey")
                && is_sensitive_key("MY_SECRET")
                && !is_sensitive_key("monkey")
                && !is_sensitive_key("title")
        );
    }

    #[test]
    fn atomic_write_replaces_whole_file() {
        let d = tmpdir("atomic");
        let p = d.join("sub").join("f.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two-two").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two-two");
        assert!(
            std::fs::read_dir(p.parent().unwrap()).unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
        );
    }

    #[test]
    fn thinking_budget_arithmetic_cannot_overflow_and_is_clamped() {
        // `budget + 2048` used to overflow u32 for a hostile budget
        for hostile in [
            0,
            1,
            1023,
            8192,
            32768,
            32769,
            u32::MAX - 2047,
            u32::MAX - 1,
            u32::MAX,
        ] {
            let m = max_tokens_with_thinking(hostile);
            assert!(
                m <= MAX_OUTPUT_TOKENS && m > MIN_THINKING_BUDGET,
                "{hostile} -> {m}"
            );
            let c = clamp_thinking_budget(hostile);
            assert!(
                (MIN_THINKING_BUDGET..=MAX_THINKING_BUDGET).contains(&c),
                "{hostile} -> {c}"
            );
        }
        assert_eq!(
            max_tokens_with_thinking(u32::MAX),
            MAX_THINKING_BUDGET + 2048
        );
        assert_eq!(clamp_thinking_budget(0), MIN_THINKING_BUDGET);
        let cfg = LlmConfig::resolve(Some("ollama"), None, false)
            .unwrap()
            .with_thinking(true, "high", u32::MAX);
        assert_eq!(cfg.thinking_budget_tokens, MAX_THINKING_BUDGET);
        // even a config that bypassed `with_thinking` (pub field) cannot overflow the request
        for provider in ["ollama", "anthropic"] {
            let mut c = LlmConfig::resolve(Some(provider), None, true).unwrap();
            c.thinking = true;
            c.thinking_budget_tokens = u32::MAX;
            let p = call_params(&c);
            assert!(p.max_tokens <= MAX_OUTPUT_TOKENS, "{provider}: {p:?}");
            assert_eq!(p.temperature, Some(STRUCTURED_TEMPERATURE), "{provider}");
        }
    }

    #[test]
    fn thinking_never_forces_temperature_one_on_structured_calls() {
        // OpenAI-compatible: reasoning effort rides along, temperature stays low
        let mut o = LlmConfig::resolve(Some("ollama"), None, false)
            .unwrap()
            .with_thinking(true, "max", 8192);
        let p = call_params(&o);
        assert_eq!(
            (p.temperature, p.reasoning_effort, p.anthropic_thinking),
            (Some(0.1), Some("high"), None)
        );
        o.thinking = false;
        assert_eq!(call_params(&o).reasoning_effort, None);
        // Anthropic: a thinking block would force temperature 1.0, so none is attached
        let a = LlmConfig::resolve(Some("anthropic"), None, true)
            .unwrap()
            .with_thinking(true, "high", 16000);
        let p = call_params(&a);
        assert_eq!(
            (p.temperature, p.anthropic_thinking, p.max_tokens),
            (Some(0.1), None, 2048)
        );
        // the log says what was sent, not that the budget was "forwarded"
        let s = a.thinking_summary();
        assert!(
            s.contains("NOT sent") && s.contains("temperature 1.0"),
            "{s}"
        );
        let s = o.with_thinking(true, "medium", 4096).thinking_summary();
        assert!(
            s.contains("reasoning_effort=medium")
                && s.contains("cap, not a reasoning allocation")
                && !s.contains("forwarded"),
            "{s}"
        );
    }

    #[test]
    fn structured_call_carries_a_low_temperature_and_a_bounded_max_tokens_on_the_wire() {
        let m = mock::start(|_| "{\"ok\": true}".into());
        let mut c = mock::cfg(&m.base, &tmpdir("wire-temp"));
        c.thinking = true;
        c.thinking_budget_tokens = u32::MAX;
        c.model_tier = "high".into();
        assert_eq!(
            ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
            true
        );
        let raw = m.requests.lock().unwrap()[0].clone();
        let body: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["temperature"], 0.1, "{body}");
        assert_eq!(body["reasoning_effort"], "high");
        let max = body["max_tokens"].as_u64().unwrap();
        assert!(max <= MAX_OUTPUT_TOKENS as u64 && max >= 4096, "{max}");
    }

    #[test]
    fn calls_and_time_are_recorded_on_the_budget() {
        let m = mock::start(|_| {
            std::thread::sleep(Duration::from_millis(20));
            "{\"ok\": true}".into()
        });
        let c = mock::cfg(&m.base, &tmpdir("budget-time"));
        let mut b = Budget::per_run();
        ask_json(&c, &mut b, "s", "p").unwrap();
        ask_json(&c, &mut b, "s", "p").unwrap(); // cached: free
        assert_eq!(b.calls, 1);
        assert!(b.elapsed_ms() >= 20, "{}", b.elapsed_ms());
        // a failed call is still a call and its time still counts
        let bad = mock::start_status(|_, _| (401, "{}".into()));
        let c = mock::cfg(&bad.base, &tmpdir("budget-time-bad"));
        let mut b2 = Budget::per_run();
        assert!(ask_json(&c, &mut b2, "s", "p").is_err());
        assert_eq!(b2.calls, 1);
    }

    #[test]
    fn connect_from_env_reports_a_reason() {
        let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
        c.base_override = Some("http://127.0.0.1:1/v1".into());
        assert!(!probe(&c));
        assert_eq!(c.describe(), "vllm/qwen3.8-flash-next");
    }
}

/// Minimal OpenAI-compatible mock server for tests.
#[cfg(test)]
pub mod mock {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    pub struct Mock {
        pub base: String,
        pub chat_hits: Arc<AtomicUsize>,
        /// Raw request text (head + body) of every non-/models call, in order.
        pub requests: Arc<Mutex<Vec<String>>>,
    }

    /// `handler(request_body) -> assistant message content`; /models answers 200.
    pub fn start(handler: impl Fn(&str) -> String + Send + 'static) -> Mock {
        start_status(move |_, body| {
            (200, serde_json::json!({"choices": [{"message": {"role": "assistant", "content": handler(body)}}]}).to_string())
        })
    }

    /// `handler(hit_index, request_body) -> (http_status, response_body)` for the chat endpoint.
    pub fn start_status(handler: impl Fn(usize, &str) -> (u16, String) + Send + 'static) -> Mock {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/v1", l.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let r2 = requests.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let (head_end, clen) = loop {
                    let n = s.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break (buf.len(), 0);
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let t = String::from_utf8_lossy(&buf).to_string();
                    if let Some(i) = t.find("\r\n\r\n") {
                        let cl = t[..i]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        break (i + 4, cl);
                    }
                };
                while buf.len() < head_end + clen {
                    let n = s.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let t = String::from_utf8_lossy(&buf).to_string();
                let body = t.get(head_end..).unwrap_or("").to_string();
                let (code, resp) = if t.starts_with("GET /v1/models") {
                    (200, r#"{"data":[{"id":"mock"}]}"#.to_string())
                } else {
                    r2.lock().unwrap().push(t.clone());
                    let i = h2.fetch_add(1, Ordering::SeqCst);
                    handler(i, &body)
                };
                let extra = if code == 429 {
                    "Retry-After: 0\r\n"
                } else {
                    ""
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp.len(),
                    resp
                );
            }
        });
        Mock {
            base,
            chat_hits: hits,
            requests,
        }
    }

    pub fn cfg(base: &str, dir: &std::path::Path) -> super::LlmConfig {
        let mut c = super::LlmConfig::resolve(Some("vllm"), None, false).unwrap();
        c.base_override = Some(base.to_string());
        c.cache_dir = Some(dir.to_path_buf());
        c.retry_base_ms = 1;
        c
    }
}
