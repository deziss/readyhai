//! Authentication middleware, token verification, and authorization policies.

use super::types::{App, BANNED_TOKENS, MIN_TOKEN_CHARS, Principal};
use crate::scope::Scope;
use anyhow::{Result, bail};
use axum::Extension;
use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

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

pub fn forbidden(role: &str, action: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": format!("role {role} may not {action} this route"),
            "role": role,
            "required": action,
        })),
    )
        .into_response()
}

/// Paths served without a token (GET only): the health probe and the three SVG status badges.
/// Those exact paths render only an allowlisted verdict or integer score from the query string and
/// never any run data; the run-derived badge routes (`/api/badges/gate/{id}`,
/// `/api/badges/ledger/{id}`) are deliberately NOT public — a run id's results stay behind auth.
pub const PUBLIC_GET: &[&str] = &[
    "/health",
    "/api/badges/gate",
    "/api/badges/ledger",
    "/api/badges/network",
];

pub fn is_public_get(path: &str) -> bool {
    PUBLIC_GET.contains(&path)
}

/// What key am I, and what may I do? UI/clients use this to hide what the caller
/// cannot use; RBAC off reports the legacy single-admin mode.
pub async fn whoami(
    Extension(who): Extension<Principal>,
    State(app): State<Arc<App>>,
) -> Json<serde_json::Value> {
    Json(json!({
        "name": who.name,
        "role": who.role.as_str(),
        "rbac": if app.rbac.enabled { "on" } else { "off" },
        "permissions": {
            "read": who.role.allows(super::rbac::Action::Read),
            "operate": who.role.allows(super::rbac::Action::Operate),
            "govern": who.role.allows(super::rbac::Action::Admin),
        },
    }))
}

/// The single authentication + authorization point: `Authorization: Bearer <token>`
/// on everything except the public GETs in [`PUBLIC_GET`]; then the RBAC matrix
/// (role × action) when RBAC is enabled. Handlers never check credentials or roles
/// themselves, so a new route cannot forget to (an unclassified write is Admin).
pub async fn require_auth(State(app): State<Arc<App>>, mut req: Request, next: Next) -> Response {
    let public = req.method() == Method::GET && is_public_get(req.uri().path());
    let ident = if public {
        None
    } else {
        let Some(v) = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        else {
            return unauthorized();
        };
        let Some((scheme, tok)) = v.split_once(' ') else {
            return unauthorized();
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            return unauthorized();
        }
        match app
            .rbac
            .authenticate(tok, &app.token_digest, &app.principal)
        {
            Some((name, role)) => {
                let action = super::rbac::action_for(req.method(), req.uri().path());
                if app.rbac.enabled && !role.allows(action) {
                    return forbidden(
                        role.as_str(),
                        match action {
                            super::rbac::Action::Operate => "trigger work (needs operator)",
                            super::rbac::Action::Admin => "govern (needs admin)",
                            super::rbac::Action::Read => "read",
                        },
                    );
                }
                Some(Principal { name, role })
            }
            None => return unauthorized(),
        }
    };
    if let Some(p) = ident {
        req.extensions_mut().insert(p);
    }
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    resp
}
