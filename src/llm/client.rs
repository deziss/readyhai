//! Multi-provider chat client abstractions, HTTP transport, retries, and authentication.

use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::time::Duration;

use super::catalog::{CHAT_MAX_TOKENS, ENV_API_KEY, MAX_SERVER_ERROR_RETRIES, Transport};
use super::config::LlmConfig;

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

pub(crate) fn openai_body(model: &str, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Value {
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

pub(crate) fn anthropic_body(
    model: &str,
    system: &str,
    messages: &[Msg],
    tools: &[ToolDef],
) -> Value {
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
pub(crate) fn key(cfg: &LlmConfig) -> Result<Option<String>> {
    key_with(cfg, |k| std::env::var(k).ok())
}

pub(crate) fn key_with(
    cfg: &LlmConfig,
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<String>> {
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
pub(crate) fn authorize(
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

pub(crate) fn http(timeout: Duration) -> Result<reqwest::blocking::Client> {
    let b = crate::network::utils::with_connect_timeout(reqwest::blocking::Client::builder());
    Ok(b.timeout(timeout)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30))
        .build()?)
}

/// Run `call` for the primary model and, when it fails (an error after its retries, a non-success
/// status, an unusable answer), for each following model in `cfg.model_chain()` until one succeeds.
/// A single configured model returns its own error unchanged; several return one error naming every
/// model that failed. Nothing in an error is a credential.
pub(crate) fn try_models<T>(cfg: &LlmConfig, mut call: impl FnMut(&str) -> Result<T>) -> Result<T> {
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
pub(crate) fn retryable_status(code: u16) -> bool {
    matches!(code, 408 | 425 | 429) || ((500..=599).contains(&code) && !matches!(code, 501 | 505))
}

/// Delay before attempt `attempt + 1` (0-based): Retry-After if sane, else base * 2^attempt (+ jitter).
pub(crate) fn backoff(cfg: &LlmConfig, attempt: u32, retry_after: Option<&str>) -> Duration {
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

/// A call that hit its per-call timeout. It is never retried identically (the same request would
/// time out again): `raw_chat` sends a smaller one, anything else moves on to the next model.
#[derive(Debug)]
pub(crate) struct CallTimedOut(pub(crate) String);

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
pub(crate) fn send_retrying(
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
