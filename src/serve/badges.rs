//! SVG badge generators for CI/CD status and PR markdown embeds.
//!
//! Badge text is never caller prose. The public badges accept only a fixed vocabulary (the
//! engine's real verdicts, or an integer score), and everything else renders `n/a`; nothing from a
//! query string is ever interpolated into the SVG. The `/{id}` variants derive their text from a
//! stored run instead, so a badge can say something true about an actual scan.

use super::guards::{err, offload};
use super::types::BadgeQuery;
use super::worker::read_json;
use axum::extract::{Path, Query};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Verdicts a badge is allowed to display. Anything else is `n/a`, never a colour-coded pass.
pub const BADGE_VERDICTS: &[&str] = &["PASS", "WARN", "FAIL"];

pub fn svg_response(svg: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'",
            ),
        ],
        svg,
    )
        .into_response()
}

/// Maps free text onto the verdict allowlist; `None` for anything unrecognised.
pub fn badge_verdict(input: Option<&str>) -> Option<&'static str> {
    let input = input?.trim();
    BADGE_VERDICTS
        .iter()
        .find(|v| v.eq_ignore_ascii_case(input))
        .copied()
}

/// Parses a badge score into `0..=100`. Accepts `88` and `88/100`; rejects anything else, so a
/// caller cannot put arbitrary text (or an out-of-range number) on a badge.
pub fn badge_score(input: Option<&str>) -> Option<u32> {
    let raw = input?.trim().split('/').next()?.trim();
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u32>().ok().map(|v| v.min(100))
}

/// Renders a two-part badge. `label` is always one of this module's fixed strings, never caller
/// text, so its width can be estimated from the character count.
pub(crate) fn badge_svg(label: &str, color: &str, text: &str) -> String {
    let label_width = (label.chars().count() * 6 + 12) as u32;
    let value_width = (text.chars().count() * 7 + 12) as u32;
    let width = label_width + value_width;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{label}: {text}">
  <clipPath id="a"><rect width="{width}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)">
    <rect width="{label_width}" height="20" fill="#1e293b"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="{}" y="140" transform="scale(.1)" fill="#fff">{label}</text>
    <text x="{}" y="140" transform="scale(.1)" fill="#fff" font-weight="bold">{text}</text>
  </g>
</svg>"##,
        label_width * 5 + 10,
        (label_width + value_width / 2) * 10,
    )
}

/// Colour for an allowlisted verdict; grey for anything not measured.
pub(crate) fn verdict_color(verdict: Option<&'static str>) -> &'static str {
    match verdict {
        Some("PASS") => "#22c55e",
        Some("WARN") => "#eab308",
        Some("FAIL") => "#ef4444",
        _ => "#6b7280",
    }
}

/// Text for an allowlisted verdict; the literal `n/a` for anything else.
fn verdict_text(verdict: Option<&'static str>) -> &'static str {
    match verdict {
        Some(v @ ("PASS" | "WARN" | "FAIL")) => v,
        _ => "n/a",
    }
}

/// Badge for a caller-supplied verdict. The label says so explicitly: nothing here is tied to a
/// scan, so it cannot be presented as ReadyHai's own attestation.
pub fn gate_svg(status: Option<&str>) -> String {
    let verdict = badge_verdict(status);
    badge_svg("reported", verdict_color(verdict), verdict_text(verdict))
}

pub fn ledger_svg(score: Option<&str>) -> String {
    let text = match badge_score(score) {
        Some(v) => v.to_string(),
        None => "n/a".to_string(),
    };
    badge_svg("reported ledger", "#3b82f6", &text)
}

pub fn network_svg(status: Option<&str>) -> String {
    let verdict = badge_verdict(status);
    badge_svg(
        "reported network",
        verdict_color(verdict),
        verdict_text(verdict),
    )
}

pub async fn badge_gate(Query(q): Query<BadgeQuery>) -> Response {
    svg_response(gate_svg(q.status.as_deref()))
}

pub async fn badge_ledger(Query(q): Query<BadgeQuery>) -> Response {
    svg_response(ledger_svg(q.score.as_deref()))
}

pub async fn badge_network(Query(q): Query<BadgeQuery>) -> Response {
    svg_response(network_svg(q.status.as_deref()))
}

/// Gate badge for one stored scan: the verdict in `<data>/runs/<id>/run.json`, or `n/a` before the
/// scan has produced one. Authenticated, because a run id belongs to somebody's private scan.
pub async fn badge_gate_run(Path(id): Path<String>) -> Response {
    if !crate::engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "invalid run id");
    }
    let verdict = match offload(move || read_json(&id, "run.json")).await {
        Ok(Some(json)) => json
            .get("verdict")
            .and_then(|v| v.as_str())
            .map(String::from),
        Ok(None) => return err(StatusCode::NOT_FOUND, "no such run"),
        Err(r) => return r,
    };
    let verdict = badge_verdict(verdict.as_deref());
    svg_response(badge_svg(
        "ReadyHai",
        verdict_color(verdict),
        verdict_text(verdict),
    ))
}

/// Evidence-ledger badge for one stored agent run: its recorded readiness score, or `n/a` when the
/// run has no scored ledger (a discovery-only scan scores nothing).
pub async fn badge_ledger_run(Path(id): Path<String>) -> Response {
    if !crate::engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "invalid run id");
    }
    let score = match offload(move || ledger_score(&id)).await {
        Ok(Ok(v)) => v,
        Ok(Err(r)) | Err(r) => return r,
    };
    let text = match badge_score(score.as_deref()) {
        Some(v) => v.to_string(),
        None => "n/a".to_string(),
    };
    svg_response(badge_svg("Evidence Ledger", "#3b82f6", &text))
}

fn ledger_score(id: &str) -> Result<Option<String>, Response> {
    let report = match crate::agent::load_agent_run(id) {
        Ok(r) => r,
        Err(_) => return Err(err(StatusCode::NOT_FOUND, "no such run")),
    };
    let Some(ledger) = report.evidence_ledger else {
        return Ok(None);
    };
    // A discovery scan stamps a ledger with placeholder scores; only an evaluated run has a number.
    if !ledger.evaluated
        || ledger.gate_verdict == "SCANNED"
        || ledger.gate_verdict == "NOT_EVALUATED"
    {
        return Ok(None);
    }
    Ok(Some(ledger.overall_readiness.to_string()))
}
