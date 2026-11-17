//! LLM configuration, environment resolution, and network scope safety guards.

use anyhow::{Result, bail};
use std::time::Duration;

use super::budget::call_params;
use super::catalog::{
    ENV_ALLOW_CLOUD, ENV_API_KEY, ENV_MODEL, ENV_MODELS, ENV_PROVIDER, ENV_TIMEOUT_SECS, ENV_URL,
    HIGH_TIER_BUDGET, MIN_CALL_SECS, ProviderDescriptor, call_timeout_secs, clamp_thinking_budget,
    provider, provider_ids,
};
use super::probe::probe;

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
    pub fn past_call_deadline(&self) -> bool {
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
        let url = val(ENV_URL).or_else(|| cfg.provider.legacy_url_env.and_then(val));
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
            retry_base_ms: 1000,
            thinking: false,
            thinking_budget_tokens: 2048,
            model_tier: "medium".into(),
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
