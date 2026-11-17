//! LLM reachability probing, latency benchmarking, and endpoint query helpers.

use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::time::Duration;

use super::catalog::{LATENCY_PROBE_TIMEOUT, SLOW_LATENCY, Transport};
use super::client::{CallTimedOut, authorize, http, is_timeout_error, key};
use super::config::LlmConfig;

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
