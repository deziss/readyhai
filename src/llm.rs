//! LLM provider abstraction plus a single-shot strict-JSON layer (ask_json) for the optional LAN LLM.
#![allow(dead_code)]
use anyhow::{Result, bail};
use regex::Regex;
use serde_json::{Value, json};

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
    /// For vllm: base_url is empty and READYHAI_VLLM_URL supplies it.
    pub base_url_env: Option<&'static str>,
    pub api_key_env: Option<&'static str>,
    pub default_model: &'static str,
    pub local: bool,
}

pub const CATALOG: &[ProviderDescriptor] = &[
    ProviderDescriptor { id: "ollama", transport: Transport::OpenAiChat, base_url: "http://localhost:11434/v1", base_url_env: None, api_key_env: None, default_model: "qwen2.5-coder", local: true },
    ProviderDescriptor { id: "vllm", transport: Transport::OpenAiChat, base_url: "http://10.10.110.42:13320/v1", base_url_env: Some("READYHAI_VLLM_URL"), api_key_env: None, default_model: "qwen3.8-flash-next", local: true },
    ProviderDescriptor { id: "openai", transport: Transport::OpenAiChat, base_url: "https://api.openai.com/v1", base_url_env: None, api_key_env: Some("OPENAI_API_KEY"), default_model: "gpt-4.1", local: false },
    ProviderDescriptor { id: "anthropic", transport: Transport::AnthropicMessages, base_url: "https://api.anthropic.com", base_url_env: None, api_key_env: Some("ANTHROPIC_API_KEY"), default_model: "claude-sonnet-5-5", local: false },
    ProviderDescriptor { id: "openrouter", transport: Transport::OpenAiChat, base_url: "https://openrouter.ai/api/v1", base_url_env: None, api_key_env: Some("OPENROUTER_API_KEY"), default_model: "anthropic/claude-sonnet-5-5", local: false },
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
}

impl LlmConfig {
    pub fn from_env() -> Result<Self> {
        let explicit = std::env::var("READYHAI_LLM_PROVIDER").ok();
        let provider_id = explicit.unwrap_or_else(|| "vllm".to_string());
        Self::resolve(
            Some(&provider_id),
            std::env::var("READYHAI_LLM_MODEL").ok().as_deref(),
            matches!(std::env::var("READYHAI_LLM_ALLOW_CLOUD").as_deref(), Ok("1") | Ok("true")),
        )
    }

    pub fn resolve(provider_id: Option<&str>, model: Option<&str>, allow_cloud: bool) -> Result<Self> {
        let Some(id) = provider_id else { bail!("READYHAI_LLM_PROVIDER not set") };
        let Some(p) = provider(id) else { bail!("unknown LLM provider '{id}'") };
        if !p.local && !allow_cloud {
            bail!("provider '{id}' is a cloud provider; set READYHAI_LLM_ALLOW_CLOUD=1 to allow sending (redacted) findings off-box");
        }
        Ok(LlmConfig { provider: p, model: model.unwrap_or(p.default_model).to_string(), allow_cloud, base_override: None, cache_dir: None })
    }

    pub fn base_url(&self) -> Result<String> {
        if let Some(b) = &self.base_override {
            return Ok(b.clone());
        }
        if let Some(e) = self.provider.base_url_env {
            if let Ok(v) = std::env::var(e) {
                if !v.trim().is_empty() {
                    return Ok(v);
                }
            }
        }
        if !self.provider.base_url.is_empty() {
            return Ok(self.provider.base_url.to_string());
        }
        bail!("{} base URL not set", self.provider.id)
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
        msgs.extend(messages.iter().map(|m| json!({"role": m.role, "content": m.content})));
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
        Some(e) => Ok(Some(std::env::var(e).map_err(|_| anyhow::anyhow!("{e} not set"))?)),
        None => Ok(None),
    }
}

impl ChatClient for OpenAiClient {
    fn chat(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Result<Reply> {
        let url = format!("{}/chat/completions", self.cfg.base_url()?.trim_end_matches('/'));
        let mut rq = reqwest::blocking::Client::new().post(url).json(&self.body(system, messages, tools));
        if let Some(k) = key(&self.cfg)? {
            rq = rq.bearer_auth(k);
        }
        let v: Value = rq.send()?.error_for_status()?.json()?;
        let m = &v["choices"][0]["message"];
        let mut r = Reply { text: m["content"].as_str().unwrap_or("").to_string(), tool_calls: vec![] };
        for tc in m["tool_calls"].as_array().into_iter().flatten() {
            r.tool_calls.push(ToolCall {
                id: tc["id"].as_str().unwrap_or("").into(),
                name: tc["function"]["name"].as_str().unwrap_or("").into(),
                args: serde_json::from_str(tc["function"]["arguments"].as_str().unwrap_or("{}")).unwrap_or(json!({})),
            });
        }
        Ok(r)
    }
}

impl ChatClient for AnthropicClient {
    fn chat(&self, system: &str, messages: &[Msg], tools: &[ToolDef]) -> Result<Reply> {
        let url = format!("{}/v1/messages", self.cfg.base_url()?.trim_end_matches('/'));
        let mut rq = reqwest::blocking::Client::new().post(url).header("anthropic-version", "2023-06-01").json(&self.body(system, messages, tools));
        if let Some(k) = key(&self.cfg)? {
            rq = rq.header("x-api-key", k);
        }
        let v: Value = rq.send()?.error_for_status()?.json()?;
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

/// Strip things that look like credentials before any text leaves the box.
pub fn redact_for_llm(text: &str) -> String {
    let pats = [
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
        r"\b(?:sk|pk|rk|ghp|gho|ghs|xox[a-z]|AKIA|AIza)[A-Za-z0-9_\-]{12,}",
        r"(?i)\b(bearer|token|secret|password|passwd|api[_-]?key)(\s*[:=]\s*|\s+)[^\s,;]{6,}",
        r"\b[0-9a-fA-F]{32,}\b",
    ];
    let mut s = text.to_string();
    for p in pats {
        if let Ok(re) = Regex::new(p) {
            s = re.replace_all(&s, "[REDACTED]").into_owned();
        }
    }
    s
}

// ---------------------------------------------------------------- single-shot strict-JSON layer

/// Reachability probe: GET {base}/models with a 2s timeout. True on any HTTP answer < 500.
pub fn probe(cfg: &LlmConfig) -> bool {
    let Ok(base) = cfg.base_url() else { return false };
    let Ok(c) = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(2)).build() else { return false };
    let mut rq = c.get(format!("{}/models", base.trim_end_matches('/')));
    if let Ok(Some(k)) = key(cfg) {
        rq = rq.bearer_auth(k);
    }
    matches!(rq.send(), Ok(r) if r.status().as_u16() < 500)
}

/// Fetch list of models from provider /models endpoint.
pub fn query_models(cfg: &LlmConfig) -> Result<Value> {
    let base = cfg.base_url()?;
    let c = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(3)).build()?;
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
    pub max_total: std::time::Duration,
    pub calls: usize,
    started: std::time::Instant,
}

impl Budget {
    pub fn new(max_calls: usize, max_total: std::time::Duration) -> Self {
        Budget { max_calls, max_total, calls: 0, started: std::time::Instant::now() }
    }
    pub fn per_run() -> Self {
        Self::new(20, std::time::Duration::from_secs(300))
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
    let (Some(a), Some(b)) = (t.find('{'), t.rfind('}')) else { bail!("no JSON object in reply") };
    if b < a {
        bail!("no JSON object in reply");
    }
    let v: Value = serde_json::from_str(&t[a..=b]).map_err(|e| anyhow::anyhow!("malformed JSON: {e}"))?;
    if !v.is_object() {
        bail!("reply is not a JSON object");
    }
    Ok(v)
}

fn cache_path(cfg: &LlmConfig, system: &str, prompt: &str) -> std::path::PathBuf {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in [cfg.model.as_str(), "\0", system, "\0", prompt] {
        h.update(part.as_bytes());
    }
    let dir = cfg.cache_dir.clone().unwrap_or_else(|| crate::engine::data_dir().join("llm-cache"));
    dir.join(format!("{}.json", hex::encode(h.finalize())))
}

fn raw_chat(cfg: &LlmConfig, system: &str, prompt: &str) -> Result<String> {
    let base = cfg.base_url()?;
    let http = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(60)).build()?;
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
                let mut rq = http.post(&url).json(&body);
                if let Some(k) = key(cfg)? {
                    rq = rq.bearer_auth(k);
                }
                let r = rq.send()?;
                if r.status().as_u16() == 400 && attempt == 0 {
                    body.as_object_mut().map(|o| o.remove("response_format"));
                    continue;
                }
                let v: Value = r.error_for_status()?.json()?;
                let msg = &v["choices"][0]["message"];
                let content = msg["content"].as_str().unwrap_or("").to_string();
                if !content.trim().is_empty() {
                    return Ok(content);
                }
                if let Some(reasoning) = msg["reasoning"].as_str().or_else(|| msg["reasoning_content"].as_str()) {
                    if reasoning.contains("{") && reasoning.contains("}") {
                        return Ok(reasoning.to_string());
                    }
                }
                return Ok(content);
            }
            bail!("LLM rejected the request")
        }
        Transport::AnthropicMessages => {
            let c = AnthropicClient { cfg: cfg.clone() };
            let mut b = c.body(system, &[Msg { role: "user".into(), content: prompt.into() }], &[]);
            b["max_tokens"] = json!(800);
            b["temperature"] = json!(0.1);
            let mut rq = http.post(format!("{}/v1/messages", base.trim_end_matches('/'))).header("anthropic-version", "2023-06-01").json(&b);
            if let Some(k) = key(cfg)? {
                rq = rq.header("x-api-key", k);
            }
            let v: Value = rq.send()?.error_for_status()?.json()?;
            Ok(v["content"].as_array().into_iter().flatten().filter_map(|c| c["text"].as_str()).collect::<String>())
        }
    }
}

/// One single-shot call that must return a JSON object. Cached on disk by
/// sha256(model+system+prompt); cache hits do not consume budget. Callers
/// must already have redacted `prompt`.
pub fn ask_json(cfg: &LlmConfig, budget: &mut Budget, system: &str, prompt: &str) -> Result<Value> {
    if !cfg.provider.local && !cfg.allow_cloud {
        bail!("cloud provider '{}' refused (READYHAI_LLM_ALLOW_CLOUD not set)", cfg.provider.id);
    }
    let path = cache_path(cfg, system, prompt);
    if let Ok(s) = std::fs::read_to_string(&path) {
        if let Ok(v) = parse_json_object(&s) {
            return Ok(v);
        }
    }
    budget.check()?;
    budget.calls += 1;
    let text = raw_chat(cfg, system, prompt)?;
    let v = parse_json_object(&text)?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(&path, v.to_string());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn tool() -> ToolDef {
        ToolDef { name: "t".into(), description: "d".into(), schema: json!({"type": "object"}) }
    }

    #[test]
    fn body_shapes() {
        let msgs = [Msg { role: "user".into(), content: "hi".into() }];
        let o = OpenAiClient { cfg: LlmConfig::resolve(Some("ollama"), None, false).unwrap() };
        let b = o.body("sys", &msgs, &[tool()]);
        assert_eq!(b["messages"][0]["role"], "system");
        assert_eq!(b["tools"][0]["function"]["name"], "t");
        let a = AnthropicClient { cfg: LlmConfig::resolve(Some("anthropic"), None, true).unwrap() };
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
        assert!(ask_json(&c, &mut b, "s", "p").unwrap_err().to_string().contains("refused"));
    }

    #[test]
    fn cache_and_budget() {
        let d = std::env::temp_dir().join(format!("rh-llm-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let m = mock::start(|_| "<think>x</think>{\"ok\": true}".into());
        let c = mock::cfg(&m.base, &d);
        let mut b = Budget::new(2, std::time::Duration::from_secs(60));
        assert_eq!(ask_json(&c, &mut b, "s", "p1").unwrap()["ok"], true);
        assert_eq!(ask_json(&c, &mut b, "s", "p1").unwrap()["ok"], true);
        assert_eq!(m.chat_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(ask_json(&c, &mut b, "s", "p2").is_ok());
        assert!(ask_json(&c, &mut b, "s", "p3").unwrap_err().to_string().contains("budget"));
        assert_eq!(m.chat_hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn redaction() {
        let t = "key sk-abcdef0123456789ABCD jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdefgh12345 password=hunter22x hash 0123456789abcdef0123456789abcdef ok";
        let r = redact_for_llm(t);
        assert!(!r.contains("sk-abc") && !r.contains("eyJ") && !r.contains("hunter22") && !r.contains("0123456789abcdef0123"));
        assert!(r.contains("ok"));
    }
}

/// Minimal OpenAI-compatible mock server for tests.
#[cfg(test)]
pub mod mock {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub struct Mock {
        pub base: String,
        pub chat_hits: Arc<AtomicUsize>,
    }

    /// `handler(request_body) -> assistant message content`; /models answers 200.
    pub fn start(handler: impl Fn(&str) -> String + Send + 'static) -> Mock {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/v1", l.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
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
                        let cl = t[..i].lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
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
                let resp = if t.starts_with("GET /v1/models") {
                    r#"{"data":[{"id":"mock"}]}"#.to_string()
                } else {
                    h2.fetch_add(1, Ordering::SeqCst);
                    serde_json::json!({"choices": [{"message": {"role": "assistant", "content": handler(&body)}}]}).to_string()
                };
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", resp.len(), resp);
            }
        });
        Mock { base, chat_hits: hits }
    }

    pub fn cfg(base: &str, dir: &std::path::Path) -> super::LlmConfig {
        let mut c = super::LlmConfig::resolve(Some("vllm"), None, false).unwrap();
        c.base_override = Some(base.to_string());
        c.cache_dir = Some(dir.to_path_buf());
        c
    }
}
