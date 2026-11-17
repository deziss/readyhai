//! Authentication middleware, token verification, and authorization policies.

use super::types::{App, BANNED_TOKENS, MIN_TOKEN_CHARS, Principal};
use anyhow::{Result, bail};
use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use crate::scope::Scope;

/// Token policy: no token, no server. There is deliberately no development fallback.
pub fn validate_token(raw: Option<&str>) -> Result<String> {
    let t = raw.unwrap_or("");
    if t.chars().count() < MIN_TOKEN_CHARS {
        bail!(
            "READYHAI_TOKEN is not set or shorter than {MIN_TOKEN_CHARS} characters; refusing to start an unauthenticated API (try: openssl rand -hex 24)"
        );
    }
    if !t.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        bail!(
            "READYHAI_TOKEN must be printable ASCII without spaces (it travels in an HTTP header)"
        );
    }
    if BANNED_TOKENS.contains(&t) {
        bail!("READYHAI_TOKEN is a publicly known example token; generate your own");
    }
    Ok(t.to_string())
}

pub fn validate_principal(raw: Option<&str>) -> Result<String> {
    let p = raw.unwrap_or("api-token");
    if p.is_empty()
        || p.len() > 64
        || !p
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._@:-".contains(c))
    {
        bail!("READYHAI_PRINCIPAL must be 1-64 characters of [A-Za-z0-9._@:-]");
    }
    Ok(p.to_string())
}

/// `READYHAI_SCOPE` at startup: unset/blank means no scope file (public hosts get full testing,
/// internal hosts are refused); anything else must exist, be a file and parse, or the server does
/// not start. Failing here beats answering every request with a 500 (or, worse, running unscoped).
pub fn validate_scope_path(raw: Option<&str>) -> Result<Option<PathBuf>> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        eprintln!(
            "no READYHAI_SCOPE: public hosts get full testing, internal hosts (localhost, RFC1918, metadata) are refused"
        );
        return Ok(None);
    };
    let p = PathBuf::from(raw);
    let sc = Scope::load(&p).map_err(|e| anyhow::anyhow!("READYHAI_SCOPE: {e:#}"))?;
    eprintln!(
        "scope: {} host entr{} from {}",
        sc.hosts.len(),
        if sc.hosts.len() == 1 { "y" } else { "ies" },
        p.display()
    );
    Ok(Some(p))
}

pub fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(json!({"error": "missing or bad bearer token"})),
    )
        .into_response()
}

pub fn bearer_ok(app: &App, h: &HeaderMap) -> bool {
    let Some(v) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some((scheme, tok)) = v.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    let got: [u8; 32] = Sha256::digest(tok.as_bytes()).into();
    got.iter()
        .zip(app.token_digest.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Paths served without a token (GET only): the health probe and the SVG status badges, which are
/// read-only and render only a sanitised status/score from the query string (no run data, no secrets).
pub const PUBLIC_GET: &[&str] = &[
    "/health",
    "/api/badges/gate",
    "/api/badges/ledger",
    "/api/badges/network",
];

pub fn is_public_get(path: &str) -> bool {
    PUBLIC_GET.contains(&path)
}

/// The single authentication point: `Authorization: Bearer <token>` on everything except
/// the public GETs in [`PUBLIC_GET`] (/health and the badges).
/// Handlers never check credentials themselves, so a new route cannot forget to.
pub async fn require_auth(State(app): State<Arc<App>>, mut req: Request, next: Next) -> Response {
    let public = req.method() == Method::GET && is_public_get(req.uri().path());
    if !public {
        if !bearer_ok(&app, req.headers()) {
            return unauthorized();
        }
        req.extensions_mut()
            .insert(Principal(app.principal.clone()));
    }
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    resp
}
