//! LLM provider abstraction plus a single-shot strict-JSON layer (ask_json) for the optional LAN LLM.
#![allow(dead_code)]
use anyhow::{Result, bail};
use regex::Regex;
use serde_json::{Value, json};
use std::sync::OnceLock;
use std::time::Duration;

pub mod untrusted;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    OpenAiChat,
    AnthropicMessages,
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderDescriptor {
    pub id: &'static str,
    pub transport: Transport,
    pub base_url: &'static str,
    /// For vllm: base_url is empty on purpose (no baked-in LAN address); READYHAI_VLLM_URL must supply it.
    pub base_url_env: Option<&'static str>,
    pub api_key_env: Option<&'static str>,
    pub default_model: &'static str,
    pub local: bool,
}

pub const CATALOG: &[ProviderDescriptor] = &[
    ProviderDescriptor {
        id: "ollama",
        transport: Transport::OpenAiChat,
        base_url: "http://localhost:11434/v1",
        base_url_env: None,
        api_key_env: None,
        default_model: "qwen2.5-coder",
        local: true,
    },
    ProviderDescriptor {
        id: "vllm",
        transport: Transport::OpenAiChat,
        base_url: "",
        base_url_env: Some("READYHAI_VLLM_URL"),
        api_key_env: None,
        default_model: "qwen3.8-flash-next",
        local: true,
    },
    ProviderDescriptor {
        id: "openai",
        transport: Transport::OpenAiChat,
        base_url: "https://api.openai.com/v1",
        base_url_env: None,
        api_key_env: Some("OPENAI_API_KEY"),
        default_model: "gpt-4.1",
        local: false,
    },
    ProviderDescriptor {
        id: "anthropic",
        transport: Transport::AnthropicMessages,
        base_url: "https://api.anthropic.com",
        base_url_env: None,
        api_key_env: Some("ANTHROPIC_API_KEY"),
        default_model: "claude-sonnet-5-5",
        local: false,
    },
    ProviderDescriptor {
        id: "openrouter",
        transport: Transport::OpenAiChat,
        base_url: "https://openrouter.ai/api/v1",
        base_url_env: None,
        api_key_env: Some("OPENROUTER_API_KEY"),
        default_model: "anthropic/claude-sonnet-5-5",
        local: false,
    },
];

pub fn provider(id: &str) -> Option<&'static ProviderDescriptor> {
    CATALOG.iter().find(|p| p.id == id)
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: &'static ProviderDescriptor,
    pub model: String,
    pub allow_cloud: bool,
    /// Overrides the provider base URL (tests).
    pub base_override: Option<String>,
    /// Overrides <data_dir>/llm-cache (tests).
    pub cache_dir: Option<std::path::PathBuf>,
    /// Total attempts per call for 429 / 5xx / timeouts (1 = no retry).
    pub max_attempts: u32,
    /// First backoff step; doubles per attempt (a `Retry-After` header wins, capped at 30 s).
    pub retry_base_ms: u64,
}

impl LlmConfig {
    pub fn from_env() -> Result<Self> {
        let explicit = std::env::var("READYHAI_LLM_PROVIDER").ok();
        let provider_id = explicit.unwrap_or_else(|| "vllm".to_string());
        Self::resolve(
            Some(&provider_id),
            std::env::var("READYHAI_LLM_MODEL").ok().as_deref(),
            matches!(
                std::env::var("READYHAI_LLM_ALLOW_CLOUD").as_deref(),
                Ok("1") | Ok("true")
            ),
        )
    }

    pub fn resolve(
        provider_id: Option<&str>,
        model: Option<&str>,
        allow_cloud: bool,
    ) -> Result<Self> {
        let Some(id) = provider_id else {
            bail!("READYHAI_LLM_PROVIDER not set")
        };
        let Some(p) = provider(id) else {
            bail!("unknown LLM provider '{id}'")
        };
        if !p.local && !allow_cloud {
            bail!(
                "provider '{id}' is a cloud provider; set READYHAI_LLM_ALLOW_CLOUD=1 to allow sending (redacted) findings off-box"
            );
        }
        Ok(LlmConfig {
            provider: p,
            model: model.unwrap_or(p.default_model).to_string(),
            allow_cloud,
            base_override: None,
            cache_dir: None,
            max_attempts: 3,
            retry_base_ms: 500,
        })
    }

    pub fn base_url(&self) -> Result<String> {
        if let Some(b) = &self.base_override {
            return Ok(b.clone());
        }
        if let Some(e) = self.provider.base_url_env
            && let Ok(v) = std::env::var(e)
            && !v.trim().is_empty()
        {
            return Ok(v);
        }
        if !self.provider.base_url.is_empty() {
            return Ok(self.provider.base_url.to_string());
        }
        match self.provider.base_url_env {
            Some(e) => bail!("{} base URL not set (export {e})", self.provider.id),
            None => bail!("{} base URL not set", self.provider.id),
        }
    }

    /// "provider/model" for logs and reports (the real values, never a literal).
    pub fn describe(&self) -> String {
        format!("{}/{}", self.provider.id, self.model)
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

impl OpenAiClient {
    pub fn body(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Value {
        let mut msgs = vec![json!({"role": "system", "content": system})];
        msgs.extend(
            messages
                .iter()
                .map(|m| json!({"role": m.role, "content": m.content})),
        );
        let mut b = json!({"model": self.cfg.model, "messages": msgs});
        if !tools.is_empty() {
            b["tools"] = tools
                .iter()
                .map(|t| json!({"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.schema}}))
                .collect();
        }
        b
    }
}

impl AnthropicClient {
    pub fn body(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Value {
        let mut b = json!({
            "model": self.cfg.model,
            "max_tokens": 4096,
            "system": system,
            "messages": messages.iter().map(|m| json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
        });
        if !tools.is_empty() {
            b["tools"] = tools.iter().map(|t| json!({"name": t.name, "description": t.description, "input_schema": t.schema})).collect();
        }
        b
    }
}

fn key(cfg: &LlmConfig) -> Result<Option<String>> {
    match cfg.provider.api_key_env {
        Some(e) => Ok(Some(
            std::env::var(e).map_err(|_| anyhow::anyhow!("{e} not set"))?,
        )),
        None => Ok(None),
    }
}

fn http(timeout: Duration) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()?)
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

/// Send the request built by `build`, retrying 429/5xx/timeouts with exponential backoff.
/// Connection refusals and 4xx (except 408/425/429) fail immediately: they will not heal by waiting.
fn send_retrying(
    cfg: &LlmConfig,
    build: impl Fn() -> reqwest::blocking::RequestBuilder,
) -> Result<reqwest::blocking::Response> {
    let attempts = cfg.max_attempts.max(1);
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..attempts {
        let delay;
        match build().send() {
            Ok(r) => {
                let code = r.status().as_u16();
                if !retryable_status(code) || attempt + 1 == attempts {
                    return Ok(r);
                }
                delay = backoff(
                    cfg,
                    attempt,
                    r.headers().get("retry-after").and_then(|v| v.to_str().ok()),
                );
                last = Some(anyhow::anyhow!("HTTP {code}"));
            }
            Err(e) if e.is_timeout() => {
                if attempt + 1 == attempts {
                    return Err(anyhow::anyhow!(
                        "LLM request timed out after {attempts} attempts: {e}"
                    ));
                }
                delay = backoff(cfg, attempt, None);
                last = Some(e.into());
            }
            Err(e) => return Err(e.into()),
        }
        std::thread::sleep(delay);
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("LLM request failed")))
}

impl ChatClient for OpenAiClient {
    fn chat(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Result<Reply> {
        let url = format!(
            "{}/chat/completions",
            self.cfg.base_url()?.trim_end_matches('/')
        );
        let body = self.body(system, messages, tools);
        let key = key(&self.cfg)?;
        let c = http(Duration::from_secs(120))?;
        let r = send_retrying(&self.cfg, || {
            let rq = c.post(&url).json(&body);
            match &key {
                Some(k) => rq.bearer_auth(k),
                None => rq,
            }
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
                args: serde_json::from_str(tc["function"]["arguments"].as_str().unwrap_or("{}"))
                    .unwrap_or(json!({})),
            });
        }
        Ok(r)
    }
}

impl ChatClient for AnthropicClient {
    fn chat(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Result<Reply> {
        let url = format!("{}/v1/messages", self.cfg.base_url()?.trim_end_matches('/'));
        let body = self.body(system, messages, tools);
        let key = key(&self.cfg)?;
        let c = http(Duration::from_secs(120))?;
        let r = send_retrying(&self.cfg, || {
            let rq = c
                .post(&url)
                .header("anthropic-version", "2023-06-01")
                .json(&body);
            match &key {
                Some(k) => rq.header("x-api-key", k),
                None => rq,
            }
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

/// Reachability probe: GET {base}/models with a 2s timeout. True on any HTTP answer < 500.
pub fn probe(cfg: &LlmConfig) -> bool {
    let Ok(base) = cfg.base_url() else {
        return false;
    };
    let Ok(c) = http(Duration::from_secs(2)) else {
        return false;
    };
    let mut rq = c.get(format!("{}/models", base.trim_end_matches('/')));
    if let Ok(Some(k)) = key(cfg) {
        rq = rq.bearer_auth(k);
    }
    matches!(rq.send(), Ok(r) if r.status().as_u16() < 500)
}

/// Fetch list of models from provider /models endpoint.
pub fn query_models(cfg: &LlmConfig) -> Result<Value> {
    let base = cfg.base_url()?;
    let c = http(Duration::from_secs(3))?;
    let mut rq = c.get(format!("{}/models", base.trim_end_matches('/')));
    if let Ok(Some(k)) = key(cfg) {
        rq = rq.bearer_auth(k);
    }
    let r = rq.send()?.error_for_status()?.json()?;
    Ok(r)
}

/// Per-run call and wall-clock budget. Cache hits are free.
#[derive(Debug)]
pub struct Budget {
    pub max_calls: usize,
    pub max_total: Duration,
    pub calls: usize,
    started: std::time::Instant,
}

impl Budget {
    pub fn new(max_calls: usize, max_total: Duration) -> Self {
        Budget {
            max_calls,
            max_total,
            calls: 0,
            started: std::time::Instant::now(),
        }
    }
    pub fn per_run() -> Self {
        Self::new(20, Duration::from_secs(300))
    }
    fn check(&self) -> Result<()> {
        if self.calls >= self.max_calls {
            bail!("LLM call budget exhausted ({} calls)", self.max_calls);
        }
        if self.started.elapsed() >= self.max_total {
            bail!("LLM time budget exhausted");
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
    for part in [
        cfg.provider.id,
        "\0",
        cfg.model.as_str(),
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

fn raw_chat(cfg: &LlmConfig, system: &str, prompt: &str) -> Result<String> {
    let base = cfg.base_url()?;
    let c = http(Duration::from_secs(60))?;
    let key = key(cfg)?;
    match cfg.provider.transport {
        Transport::OpenAiChat => {
            let url = format!("{}/chat/completions", base.trim_end_matches('/'));
            let mut body = json!({
                "model": cfg.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 2048,
                "response_format": {"type": "json_object"},
            });
            for attempt in 0..2 {
                let r = send_retrying(cfg, || {
                    let rq = c.post(&url).json(&body);
                    match &key {
                        Some(k) => rq.bearer_auth(k),
                        None => rq,
                    }
                })?;
                if r.status().as_u16() == 400 && attempt == 0 {
                    body.as_object_mut().map(|o| o.remove("response_format"));
                    continue;
                }
                let v: Value = r.error_for_status()?.json()?;
                return openai_answer(&v);
            }
            bail!("LLM rejected the request")
        }
        Transport::AnthropicMessages => {
            let a = AnthropicClient { cfg: cfg.clone() };
            let mut b = a.body(
                system,
                &[Msg {
                    role: "user".into(),
                    content: prompt.into(),
                }],
                &[],
            );
            b["max_tokens"] = json!(2048);
            b["temperature"] = json!(0.1);
            let url = format!("{}/v1/messages", base.trim_end_matches('/'));
            let r = send_retrying(cfg, || {
                let rq = c
                    .post(&url)
                    .header("anthropic-version", "2023-06-01")
                    .json(&b);
                match &key {
                    Some(k) => rq.header("x-api-key", k),
                    None => rq,
                }
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
    if !cfg.provider.local && !cfg.allow_cloud {
        bail!(
            "cloud provider '{}' refused (READYHAI_LLM_ALLOW_CLOUD not set)",
            cfg.provider.id
        );
    }
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
    let text = raw_chat(cfg, system, prompt)?;
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
        }
        assert_eq!(provider("vllm").unwrap().base_url, "");
        assert_eq!(
            provider("vllm").unwrap().base_url_env,
            Some("READYHAI_VLLM_URL")
        );
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
        assert_eq!(m.chat_hits.load(Ordering::SeqCst) as u32, c.max_attempts);

        let m = mock::start_status(|_, _| (401, "{\"error\":\"nope\"}".into()));
        let c = mock::cfg(&m.base, &tmpdir("noretry"));
        assert!(ask_json(&c, &mut Budget::per_run(), "s", "p").is_err());
        assert_eq!(m.chat_hits.load(Ordering::SeqCst), 1, "401 is not retried");
    }

    #[test]
    fn timeout_is_retried() {
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
        let mut c = mock::cfg(&base, &tmpdir("timeout"));
        c.max_attempts = 2;
        let cfg = c.clone();
        let t = std::time::Instant::now();
        let r = send_retrying(&cfg, || {
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_millis(150))
                .build()
                .unwrap()
                .get(format!("{base}/models"))
        });
        assert!(r.is_err() && r.unwrap_err().to_string().contains("timed out"));
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        assert!(t.elapsed() < Duration::from_secs(5));
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
        let v = json!({"PASSWORD": "x", "db": {"user_secret": ["a", "b"], "host": "h"}, "arr": [{"api_key": 1}, "token=abcdef123456"], "n": 5, "nul": null});
        let r = redact_value(&v);
        assert_eq!(r["PASSWORD"], "[REDACTED]");
        assert_eq!(r["db"]["user_secret"], "[REDACTED]");
        assert_eq!(r["db"]["host"], "h");
        assert_eq!(r["arr"][0]["api_key"], "[REDACTED]");
        assert!(!r["arr"][1].as_str().unwrap().contains("abcdef123456"));
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
