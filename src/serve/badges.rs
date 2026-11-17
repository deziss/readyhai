//! SVG badge generators for CI/CD status and PR markdown embeds.

use super::eval_api::xml_escape;
use super::types::{BADGE_VALUE_MAX, BadgeQuery};
use axum::extract::Query;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

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

pub fn gate_svg(status: Option<&str>) -> String {
    let (color, text) = match status.map(|s| s.trim().to_uppercase()).as_deref() {
        Some("PASS") => ("#22c55e", "PASS"),
        Some("WARN") => ("#eab308", "WARN"),
        Some("FAIL") => ("#ef4444", "FAIL"),
        _ => ("#6b7280", "n/a"),
    };
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="128" height="20" role="img" aria-label="ReadyHai: {text}">
  <linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="a"><rect width="128" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)">
    <rect width="68" height="20" fill="#1e293b"/>
    <rect x="68" width="60" height="20" fill="{color}"/>
    <rect width="128" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="350" y="140" transform="scale(.1)" fill="#fff">ReadyHai</text>
    <text x="980" y="140" transform="scale(.1)" fill="#fff" font-weight="bold">{text}</text>
  </g>
</svg>"##
    )
}

pub fn ledger_svg(score: Option<&str>) -> String {
    let score = xml_escape(score.unwrap_or("n/a"), BADGE_VALUE_MAX);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="148" height="20" role="img" aria-label="Ledger: {score}">
  <clipPath id="a"><rect width="148" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)">
    <rect width="88" height="20" fill="#0f172a"/>
    <rect x="88" width="60" height="20" fill="#3b82f6"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="450" y="140" transform="scale(.1)" fill="#fff">Evidence Ledger</text>
    <text x="1180" y="140" transform="scale(.1)" fill="#fff" font-weight="bold">{score}</text>
  </g>
</svg>"##
    )
}

pub fn network_svg(status: Option<&str>) -> String {
    let status = xml_escape(status.unwrap_or("n/a"), BADGE_VALUE_MAX);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="156" height="20" role="img" aria-label="Network: {status}">
  <clipPath id="a"><rect width="156" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)">
    <rect width="84" height="20" fill="#18181b"/>
    <rect x="84" width="72" height="20" fill="#10b981"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="430" y="140" transform="scale(.1)" fill="#fff">Network Mesh</text>
    <text x="1200" y="140" transform="scale(.1)" fill="#fff" font-weight="bold">{status}</text>
  </g>
</svg>"##
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
