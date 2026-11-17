//! Per-run token and latency budget enforcement, disk caching, and structured single-shot JSON queries.

use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::time::Duration;

use super::catalog::{
    CALL_SHARE_OF_BUDGET, CLIENT_BACKSTOP_SECS, DOWNGRADE_FLOOR_TOKENS, MAX_TIMEOUT_DOWNGRADES,
    MIN_CALL_SECS, STRUCTURED_TEMPERATURE, Transport, max_tokens_with_thinking,
};
use super::client::{
    CallTimedOut, Msg, anthropic_body, authorize, http, is_timeout_error, key, send_retrying,
    try_models,
};
use super::config::LlmConfig;

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
pub(crate) fn downgrade(max_tokens: u32, has_effort: bool) -> Option<u32> {
    let next = (max_tokens / 2).max(DOWNGRADE_FLOOR_TOKENS).min(max_tokens);
    (next < max_tokens || has_effort).then_some(next)
}

/// How one attempt of a structured call is shaped (see [`downgrade`]).
#[derive(Clone, Copy)]
pub(crate) struct Shape {
    pub(crate) max_tokens: u32,
    pub(crate) effort: Option<&'static str>,
}

impl Shape {
    pub(crate) fn describe(&self) -> String {
        match self.effort {
            Some(e) => format!("max_tokens {} with reasoning_effort {e}", self.max_tokens),
            None => format!("max_tokens {}", self.max_tokens),
        }
    }
}

/// One request of a structured call, as shaped by `shape`, with its own timeout.
#[allow(clippy::too_many_arguments)]
pub(crate) fn raw_once(
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
pub(crate) fn raw_chat(
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
