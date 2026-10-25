//! HTTP execution: throttled, write-guarded, redacted exchanges + curl repros.
use crate::ctx::Ctx;
use crate::qa::QaCtx;
use crate::qa::model::{Evidence, EvidenceKind};
use crate::qa::roles::{AuthKind, Role};
use anyhow::{Result, bail};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const MAX_BODY: usize = 8 * 1024;

#[derive(Debug, Clone, Default)]
pub struct Exchange {
    pub method: String,
    pub url: String,
    /// 0 = transport error (see `error`).
    pub status: u16,
    /// Redacted: set-cookie / authorization / cookie values are masked.
    pub headers: Vec<(String, String)>,
    /// Truncated to 8KB. NOT redacted (kept for detection); `redacted_body()` for storage.
    pub body: String,
    pub ms: u128,
    pub error: Option<String>,
}

impl Exchange {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|x| x.1.as_str())
    }
    pub fn json(&self) -> Option<Value> {
        serde_json::from_str(&self.body).ok()
    }
    pub fn is_2xx(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn redacted_body(&self) -> String {
        crate::logs::redact(&self.body)
    }
}

pub fn is_write(method: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
}

/// Pure write guard: writes only on nonprod hosts.
pub fn write_guard(method: &str, nonprod: bool) -> Result<()> {
    if is_write(method) && !nonprod {
        bail!("read-only: host not nonprod");
    }
    Ok(())
}

pub fn client() -> Result<&'static Client> {
    static C: OnceLock<Client> = OnceLock::new();
    if let Some(c) = C.get() {
        return Ok(c);
    }
    let policy = reqwest::redirect::Policy::custom(|a| {
        let first = a.previous().first().and_then(|u| u.host_str().map(str::to_owned));
        if a.previous().len() >= 5 || first.as_deref() != a.url().host_str() { a.stop() } else { a.follow() }
    });
    let c = Client::builder().timeout(Duration::from_secs(15)).redirect(policy).user_agent("readyhai-qa").build()?;
    Ok(C.get_or_init(|| c))
}

fn mask_header(k: &str, v: &str) -> String {
    match k.to_ascii_lowercase().as_str() {
        "set-cookie" | "authorization" | "cookie" | "proxy-authorization" | "x-api-key" => "[REDACTED]".into(),
        _ => v.to_string(),
    }
}

/// Send one request. `role = None` means anonymous. Errors only for budget exhaustion or a
/// refused write; transport failures come back as status 0 with `error`.
pub fn send(
    qa: &QaCtx,
    role: Option<&Role>,
    method: &str,
    url: &str,
    body: Option<&Value>,
    extra: &[(&str, &str)],
) -> Result<Exchange> {
    write_guard(method, qa.nonprod)?;
    qa.throttle()?;
    let c = client()?;
    let m = reqwest::Method::from_bytes(method.to_ascii_uppercase().as_bytes())?;
    let mut rb = c.request(m, url).header("Accept", "application/json, text/html;q=0.5");
    if let Some(r) = role {
        if let Some((k, v)) = r.credential() {
            rb = rb.header(k, v);
        } else if r.auth == AuthKind::Cookie {
            if let Some(ck) = r.cookie_header(&qa.roles.dir) {
                rb = rb.header("Cookie", ck);
            }
        }
    }
    for (k, v) in extra {
        rb = rb.header(*k, *v);
    }
    if let Some(b) = body {
        rb = rb.json(b);
    }
    let t0 = Instant::now();
    let mut ex = Exchange { method: method.to_ascii_uppercase(), url: url.to_string(), ..Default::default() };
    match rb.send() {
        Ok(resp) => {
            ex.status = resp.status().as_u16();
            ex.headers = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), mask_header(k.as_str(), v.to_str().unwrap_or(""))))
                .collect();
            let bytes = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
            let cut = bytes.len().min(MAX_BODY);
            ex.body = String::from_utf8_lossy(&bytes[..cut]).into_owned();
        }
        Err(e) => ex.error = Some(e.to_string()),
    }
    ex.ms = t0.elapsed().as_millis();
    Ok(ex)
}

/// True when this role has a usable credential (env var set / cookie file readable).
pub fn role_usable(qa: &QaCtx, r: &Role) -> bool {
    r.credential().is_some() || (r.auth == AuthKind::Cookie && r.cookie_header(&qa.roles.dir).is_some())
}

/// Copy-pasteable curl with `$RH_<ROLE>_TOKEN` placeholders (never real secrets).
pub fn curl_repro(method: &str, url: &str, role: Option<&Role>, body: Option<&Value>) -> String {
    let mut s = format!("curl -sS -i -X {} '{}'", method.to_ascii_uppercase(), url.replace('\'', "%27"));
    if let Some(r) = role {
        let ph = r.placeholder();
        match r.auth {
            AuthKind::Bearer => s.push_str(&format!(" -H \"Authorization: Bearer {ph}\"")),
            AuthKind::Basic => s.push_str(&format!(" -H \"Authorization: Basic {ph}\"")),
            AuthKind::Header => {
                s.push_str(&format!(" -H \"{}: {ph}\"", r.header_name.clone().unwrap_or_else(|| "X-API-Key".into())))
            }
            AuthKind::Cookie => s.push_str(&format!(" -H \"Cookie: {}\"", ph.replace("_TOKEN", "_COOKIE"))),
            AuthKind::None => {}
        }
    }
    if let Some(b) = body {
        let t = b.to_string();
        if t.len() > 2000 {
            s.push_str(&format!(" -H 'Content-Type: application/json' -d '<{}-byte JSON body, see evidence>'", t.len()));
        } else {
            s.push_str(&format!(" -H 'Content-Type: application/json' -d '{}'", t.replace('\'', "'\\''")));
        }
    }
    s
}

fn short_hash(s: &str) -> String {
    crate::model::sha256_hex(s.as_bytes())[..12].to_string()
}

/// Save a redacted exchange to artifacts/api/<case-hash>.json.
pub fn save_evidence(ctx: &Ctx, case_id: &str, role: Option<&str>, req_body: Option<&Value>, ex: &Exchange) -> Option<Evidence> {
    let rel = format!("api/{}.json", short_hash(case_id));
    let dir = ctx.run_dir.join("artifacts").join("api");
    std::fs::create_dir_all(&dir).ok()?;
    let req = req_body.map(|b| {
        let t = b.to_string();
        crate::logs::redact(&t.chars().take(MAX_BODY).collect::<String>())
    });
    let doc = json!({
        "case": case_id,
        "request": {"method": ex.method, "url": ex.url, "role": role, "body": req},
        "response": {"status": ex.status, "headers": ex.headers, "body": ex.redacted_body(), "ms": ex.ms, "error": ex.error},
    });
    std::fs::write(ctx.run_dir.join("artifacts").join(&rel), serde_json::to_vec_pretty(&doc).ok()?).ok()?;
    Some(Evidence { kind: EvidenceKind::HttpExchange, path: rel, note: format!("{} {} -> {}", ex.method, ex.url, ex.status) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qa::roles::Roles;

    fn role(name: &str) -> Role {
        let r: Roles = toml::from_str(&format!("[[role]]\nname=\"{name}\"\nauth=\"bearer\"\ntoken_env=\"RH_NOPE_X\"\n")).unwrap();
        r.roles[0].clone()
    }

    #[test]
    fn curl_has_placeholder_not_secret() {
        // SAFETY of test: env var holds a fake value; must never show up in the repro.
        unsafe { std::env::set_var("RH_NOPE_X", "super-secret-value") };
        let r = role("alice");
        let c = curl_repro("POST", "http://h/x", Some(&r), Some(&json!({"a":"it's"})));
        assert!(c.contains("$RH_ALICE_TOKEN"));
        assert!(!c.contains("super-secret-value"));
        assert!(c.contains("-X POST"));
        assert!(c.contains("it'\\''s"));
        let anon = curl_repro("get", "http://h/y", None, None);
        assert!(!anon.contains("Authorization"));
    }

    #[test]
    fn writes_refused_when_not_nonprod() {
        assert!(write_guard("POST", false).is_err());
        assert!(write_guard("delete", false).is_err());
        assert!(write_guard("GET", false).is_ok());
        assert!(write_guard("PUT", true).is_ok());
        let qa = QaCtx::new(Roles::default(), None, None, false);
        let e = send(&qa, None, "POST", "http://127.0.0.1:1/x", None, &[]).unwrap_err();
        assert!(e.to_string().contains("read-only"));
        assert_eq!(qa.requests_made(), 0, "refused writes must not consume or send requests");
    }

    #[test]
    fn headers_masked() {
        assert_eq!(mask_header("Set-Cookie", "a=b"), "[REDACTED]");
        assert_eq!(mask_header("Content-Type", "x"), "x");
    }
}
