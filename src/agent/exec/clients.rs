use std::io::Read;
use std::time::{Duration, Instant};

use crate::agent::oracle::{self, Technique};
use crate::agent::types::{PlannedCase, ProbeOracle, RedirectHop};
use super::auth::{Auth, Bearer, ResolvedAuth, auth_for};

pub const METHODS: [&str; 7] = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
pub const MAX_REDIRECTS: usize = 5;
pub const BODY_CAP: usize = 64 * 1024;

/// What one response looked like.
pub struct Seen {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub latency_ms: u64,
}

/// One outgoing request. `bearer` is the only way a credential can be attached.
pub struct OutReq<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub body: Option<&'a (String, String)>,
    pub headers: &'a [(String, String)],
    pub bearer: Option<&'a Bearer>,
}

/// The HTTP clients of one run, bound to its target.
///
/// * `lax` accepts invalid certificates (so an unauthenticated probe of a self-signed staging
///   host still works) and is never used for a request that carries a real credential;
/// * `strict` validates certificates and carries every real credential;
/// * a credential is attached only when the request URL has the target's scheme, host and port.
pub struct Clients {
    strict: Option<reqwest::blocking::Client>,
    lax: reqwest::blocking::Client,
    target: reqwest::Url,
}

fn base_builder(timeout: Duration) -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        // a redirect is an observation, and it must never carry credentials to another host
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("ReadyHai-Agent/1.0")
}

fn err_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

impl Clients {
    pub fn new(timeout: Duration, target: &reqwest::Url) -> Result<Self, reqwest::Error> {
        let lax = base_builder(timeout)
            .danger_accept_invalid_certs(true)
            .build()?;
        let strict = base_builder(timeout).build().ok();
        Ok(Clients {
            strict,
            lax,
            target: target.clone(),
        })
    }

    /// Exact scheme + host + port match with the run's target.
    pub fn is_target_url(&self, url: &str) -> bool {
        reqwest::Url::parse(url).is_ok_and(|u| {
            u.scheme() == self.target.scheme()
                && u.host_str().is_some()
                && u.host_str() == self.target.host_str()
                && u.port_or_known_default() == self.target.port_or_known_default()
        })
    }

    pub fn send(&self, r: &OutReq) -> Result<Seen, String> {
        self.send_with_auth(r, &[], false)
    }

    pub fn send_resolved(&self, r: &OutReq, auth: &ResolvedAuth) -> Result<Seen, String> {
        self.send_with_auth(r, &auth.extra_headers, auth.real)
    }

    pub fn send_with_auth(
        &self,
        r: &OutReq,
        extra_auth: &[(String, String)],
        extra_real: bool,
    ) -> Result<Seen, String> {
        let has_creds = r.bearer.is_some() || !extra_auth.is_empty();
        if has_creds && !self.is_target_url(r.url) {
            return Err(format!(
                "credentials withheld: the request host is not the run's target host ({})",
                self.target.host_str().unwrap_or("?")
            ));
        }
        let real = needs_validated_tls(r.bearer) || extra_real;
        let client = if real {
            self.strict.as_ref().ok_or_else(|| {
                "credentials withheld: a certificate-validating HTTP client is unavailable"
                    .to_string()
            })?
        } else {
            &self.lax
        };
        let t0 = Instant::now();
        let method = reqwest::Method::from_bytes(r.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut rb = client.request(method, r.url);
        if let Some(b) = r.bearer {
            rb = rb.header("Authorization", b.header.as_str());
        }
        for (k, v) in extra_auth {
            rb = rb.header(k.as_str(), v.as_str());
        }
        for (k, v) in r.headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        if let Some((ct, body)) = r.body {
            rb = rb.header("Content-Type", ct.as_str()).body(body.clone());
        }
        let resp = rb.send().map_err(|e| {
            let m = err_chain(&e);
            let l = m.to_ascii_lowercase();
            if real && (l.contains("certificate") || l.contains("tls") || l.contains("ssl")) {
                format!(
                    "{m} (credentials are only sent with certificate validation enabled; fix the target certificate or test without a credential)"
                )
            } else {
                m
            }
        })?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let content_type = headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let mut buf = Vec::new();
        let _ = resp.take(BODY_CAP as u64).read_to_end(&mut buf);
        Ok(Seen {
            status,
            content_type,
            headers,
            body: String::from_utf8_lossy(&buf).into_owned(),
            latency_ms: t0.elapsed().as_millis() as u64,
        })
    }
}

/// A response after the same-origin redirects the executor followed.
pub struct Followed {
    pub seen: Seen,
    /// The hops that were followed, in order (empty: the first response was the answer).
    pub chain: Vec<RedirectHop>,
    /// The URL that gave `seen`.
    pub final_url: String,
}

impl Clients {
    /// [`Clients::send`], then follow redirects to the run's own origin, at most `max_hops`. Every
    /// hop goes through `send`, so the credential rules hold on each of them. The chain ends, and
    /// the last response is returned as the 3xx it is, at a redirect to another origin, a missing
    /// or unusable `Location`, a loop, or when `on_hop` refuses (the run budget). A failing hop is
    /// an error. A request with a body is never redirected: only reads follow.
    pub fn send_following(
        &self,
        r: &OutReq,
        max_hops: usize,
        on_hop: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Followed, String> {
        self.send_following_with_auth(r, &[], false, max_hops, on_hop)
    }

    pub fn send_following_resolved(
        &self,
        r: &OutReq,
        auth: &ResolvedAuth,
        max_hops: usize,
        on_hop: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Followed, String> {
        self.send_following_with_auth(r, &auth.extra_headers, auth.real, max_hops, on_hop)
    }

    pub fn send_following_with_auth(
        &self,
        r: &OutReq,
        extra_auth: &[(String, String)],
        extra_real: bool,
        max_hops: usize,
        on_hop: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Followed, String> {
        let mut seen = self.send_with_auth(r, extra_auth, extra_real)?;
        let mut chain: Vec<RedirectHop> = vec![];
        let mut url = r.url.to_string();
        let mut visited = vec![url.clone()];
        let mut total_ms = seen.latency_ms;
        while r.body.is_none()
            && chain.len() < max_hops
            && matches!(seen.status, 301 | 302 | 303 | 307 | 308)
        {
            let Some(loc) = seen
                .headers
                .iter()
                .find(|(k, _)| k == "location")
                .map(|(_, v)| v.trim().to_string())
                .filter(|l| !l.is_empty())
            else {
                break;
            };
            let Some(next) = reqwest::Url::parse(&url)
                .ok()
                .and_then(|b| b.join(&loc).ok())
            else {
                break;
            };
            if !self.is_target_url(next.as_str()) || visited.iter().any(|v| v == next.as_str()) {
                break;
            }
            if on_hop().is_err() {
                break;
            }
            chain.push(RedirectHop {
                status: seen.status,
                location: crate::llm::untrusted::redact_then_truncate(&loc, 200),
            });
            let hop = OutReq {
                method: r.method,
                url: next.as_str(),
                body: None,
                headers: r.headers,
                bearer: r.bearer,
            };
            seen = self
                .send_with_auth(&hop, extra_auth, extra_real)
                .map_err(|e| {
                    format!(
                        "following the redirect to {} failed: {e}",
                        crate::llm::untrusted::redact_then_truncate(next.path(), 80)
                    )
                })?;
            total_ms += seen.latency_ms;
            url = next.to_string();
            visited.push(url.clone());
        }
        seen.latency_ms = total_ms;
        Ok(Followed {
            seen,
            chain,
            final_url: url,
        })
    }
}

/// Does the executor follow a same-origin redirect for this case? Only a safe GET/HEAD read that
/// is a liveness, content or robustness check. An authorization case, a sensitive-file probe, a
/// forged-token request and a case that expects a redirect or a denial keep the raw status: that
/// status is the evidence.
pub fn follows_redirects(c: &PlannedCase) -> bool {
    matches!(
        c.method.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD"
    ) && Technique::parse(&c.technique) != Technique::Authz
        && auth_for(c) != Auth::Forged
        && !matches!(c.probe_oracle, Some(ProbeOracle::OpenRedirect { .. }))
        && !oracle::is_sensitive_path(&c.component)
        && !oracle::expects_redirect(c)
        && !oracle::expects_denial(c)
}

/// The reproduction command of a request whose redirects were followed.
pub(crate) fn follow_curl(curl: &str) -> String {
    curl.replacen(
        "curl -sS",
        &format!("curl -sS -L --max-redirs {MAX_REDIRECTS}"),
        1,
    )
}

/// A real test credential travels only through the client that validates certificates.
pub fn needs_validated_tls(b: Option<&Bearer>) -> bool {
    b.is_some_and(|b| b.real)
}
