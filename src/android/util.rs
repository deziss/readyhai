//! String helpers, regex caching, process execution, and HTTP form/multipart encoding.
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub(crate) fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).unwrap())
}

/// Redact emails, bearer/JWT tokens, key=value secrets and long hex/base64-ish blobs.
pub fn redact(s: &str) -> String {
    static EMAIL: OnceLock<Regex> = OnceLock::new();
    static KV: OnceLock<Regex> = OnceLock::new();
    static JWT: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    static LONG: OnceLock<Regex> = OnceLock::new();
    let s = re(&EMAIL, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").replace_all(s, "<email>");
    let s = re(
        &KV,
        r"(?i)\b(token|secret|password|passwd|pwd|api[_-]?key|authorization|bearer)(\s*[=:]\s*|\s+)\S+",
    )
    .replace_all(&s, "$1=<redacted>");
    let s = re(
        &JWT,
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
    )
    .replace_all(&s, "<jwt>");
    let s = re(&HEX, r"\b[0-9a-fA-F]{24,}\b").replace_all(&s, "<hex>");
    let s = re(&LONG, r"[A-Za-z0-9+/_-]{40,}={0,2}").replace_all(&s, "<blob>");
    s.into_owned()
}

pub(crate) fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('_');
            dash = true;
        }
    }
    let t = out.trim_end_matches('_');
    t.chars().take(60).collect()
}

pub(crate) fn vs<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

/// Run a command with a hard timeout; returns (exit code, stdout, stderr).
pub(crate) fn run_cmd(cmd: &mut Command, secs: u64) -> Result<(i32, String, String)> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn")?;
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t1 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t2 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let end = Instant::now() + Duration::from_secs(secs);
    let code = loop {
        if let Some(st) = child.try_wait()? {
            break st.code().unwrap_or(-1);
        }
        if Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out after {secs}s");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let o = String::from_utf8_lossy(&t1.join().unwrap_or_default()).into_owned();
    let e = String::from_utf8_lossy(&t2.join().unwrap_or_default()).into_owned();
    Ok((code, o, e))
}

/// Hand-built multipart/form-data body with a single file field.
pub fn multipart_body(boundary: &str, field: &str, filename: &str, bytes: &[u8]) -> Vec<u8> {
    let safe: String = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || ".-_".contains(*c))
        .collect();
    let mut b = Vec::with_capacity(bytes.len() + 256);
    b.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{safe}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    b.extend_from_slice(bytes);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    b
}

fn urlencode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

pub fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub(crate) fn rand_hex(n: usize) -> String {
    use rand::RngExt;
    let mut r = rand::rng();
    (0..n)
        .map(|_| format!("{:02x}", r.random::<u8>()))
        .collect()
}
