//! The cross-target vulnerability database over REST: the UI's Vulns view and the
//! `readyhai vulns` CLI are the two faces of the same file (see `src/vulndb.rs`).
//!
//! Reads are open to any authenticated role (GET classifies as Read in the RBAC
//! matrix and the database is ordinary scan data, not governance data). Triage is
//! a governing action: `POST /api/vulns/{fingerprint}` is not in the route matrix,
//! so the middleware's fail-closed rule makes it admin-only exactly like
//! `PUT /api/settings`.

use super::guards::{err, offload};
use crate::vulndb;
use axum::Json;
use axum::extract::{Path as AxPath, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

/// The five severity words the database stores (lowercase [`crate::model::Severity`]).
const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// `?status=&severity=&target=` on `GET /api/vulns`. A blank value means no filter.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct VulnsQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub target: Option<String>,
    pub verification: Option<String>,
}

/// Body of `POST /api/vulns/{fingerprint}`.
#[derive(Debug, Deserialize)]
pub struct VulnsStatusPut {
    pub status: String,
}

/// Blank-filter-value → `None`; a non-blank value that fails `valid` → the given 400,
/// left in `response` for the caller to return.
fn filter_value(
    name: &str,
    raw: Option<&str>,
    valid: &[&str],
    response: &mut Option<Response>,
) -> Option<String> {
    let v = raw.map(str::trim).filter(|s| !s.is_empty())?;
    let lowered = v.to_ascii_lowercase();
    if valid.contains(&lowered.as_str()) {
        Some(lowered)
    } else {
        *response = Some(err(
            StatusCode::BAD_REQUEST,
            format!("{name} must be one of {}", valid.join("|")),
        ));
        None
    }
}

/// `GET /api/vulns`: the whole database, severity then recency, as
/// `{"count":n,"vulns":[...]}`. `status`/`severity` are exact-match filters (an
/// invalid value is a 400, not a silent empty list); `target` matches the stored
/// canonical target, the raw string, or its target key.
pub async fn api_vulns_get(Query(q): Query<VulnsQuery>) -> Response {
    let mut bad = None;
    let status = filter_value("status", q.status.as_deref(), &vulndb::STATUSES, &mut bad);
    let severity = filter_value("severity", q.severity.as_deref(), &SEVERITIES, &mut bad);
    let verification = filter_value(
        "verification",
        q.verification.as_deref(),
        &vulndb::VERIFICATIONS,
        &mut bad,
    );
    if let Some(r) = bad {
        return r;
    }
    let target = q
        .target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let filter = vulndb::Filter {
        target,
        status,
        severity,
        verification,
    };
    match offload(move || vulndb::list(&filter)).await {
        Ok(rows) => Json(json!({"count": rows.len(), "vulns": rows})).into_response(),
        Err(r) => r,
    }
}

/// `POST /api/vulns/{fingerprint}`: triage one record (`open`, `accepted`,
/// `forgotten`). Unique 6+ character fingerprint prefixes resolve as in the CLI.
/// `400` on an unknown status, `404` on no (or ambiguous) match, `403` for a
/// viewer when RBAC is on.
pub async fn api_vulns_status_post(
    AxPath(fp): AxPath<String>,
    Json(body): Json<VulnsStatusPut>,
) -> Response {
    let status = body.status.trim().to_ascii_lowercase();
    if !vulndb::valid_status(&status) {
        return err(
            StatusCode::BAD_REQUEST,
            format!("status must be one of {}", vulndb::STATUSES.join("|")),
        );
    }
    let probe = fp.clone();
    match offload(move || vulndb::set_status(&probe, &status)).await {
        Ok(Ok(true)) => Json(json!({"ok": true})).into_response(),
        Ok(Ok(false)) => err(
            StatusCode::NOT_FOUND,
            format!("no vulnerability with fingerprint {fp} (or the prefix is ambiguous)"),
        ),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
        Err(r) => r,
    }
}
