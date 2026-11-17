//! Minimal OpenAI-compatible mock server for tests.

#![cfg(test)]

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
        (
            200,
            serde_json::json!({"choices": [{"message": {"role": "assistant", "content": handler(body)}}]}).to_string(),
        )
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
