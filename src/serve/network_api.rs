//! Network Lab HTTP handlers (routes, packet regressions, curl tests, HAR exports).

use super::guards::{blocking, err, guard};
use super::types::App;
use crate::network;
use anyhow::Result;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;

pub async fn get_requester_ip(headers: HeaderMap) -> Response {
    let Ok(info) = tokio::task::spawn_blocking(network::detect_requester_public_ip).await else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "ip detection failed");
    };
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string());

    (
        StatusCode::OK,
        Json(json!({
            "egress_public_ip": info.egress_public_ip,
            "ip_type": info.ip_type,
            "is_private": info.is_private,
            "allowlist_guidance": info.allowlist_guidance,
            "detected_via": info.detected_via,
            "detected_at": info.detected_at,
            "client_inbound_ip": client_ip,
        })),
    )
        .into_response()
}

pub async fn network_route<T: serde::Serialize + Send + 'static>(
    app: &App,
    target: &str,
    intrusive: bool,
    run: impl FnOnce(String) -> Result<T> + Send + 'static,
) -> Response {
    let eg = match guard(app, target, intrusive).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    match blocking(app, move || run(eg.url)).await {
        Ok(Ok(report)) => Json(report).into_response(),
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
        Err(r) => r,
    }
}

pub async fn network_regress(
    State(app): State<Arc<App>>,
    Json(req): Json<network::RegressRequest>,
) -> Response {
    let (intrusive, target) = (req.is_intrusive(), req.target.clone());
    network_route(&app, &target, intrusive, move |url| {
        let mut req = req;
        req.target = url;
        network::run_regress_test(&req)
    })
    .await
}

pub async fn network_curl(
    State(app): State<Arc<App>>,
    Json(req): Json<network::CurlTestRequest>,
) -> Response {
    let (intrusive, target) = (req.is_intrusive(), req.target.clone());
    network_route(&app, &target, intrusive, move |url| {
        let mut req = req;
        req.target = url;
        network::execute_curl_test(&req)
    })
    .await
}

pub async fn network_deep_audit(
    State(app): State<Arc<App>>,
    Json(req): Json<network::DeepAuditRequest>,
) -> Response {
    let target = req.target.clone();
    network_route(&app, &target, false, move |url| {
        let mut req = req;
        req.target = url;
        network::run_deep_audit(&req)
    })
    .await
}

pub async fn network_multi_region(
    State(app): State<Arc<App>>,
    Json(req): Json<network::MultiRegionRequest>,
) -> Response {
    let target = req.target.clone();
    network_route(&app, &target, false, move |url| {
        let mut req = req;
        req.target = url;
        network::run_multi_region_audit(&req)
    })
    .await
}

pub async fn network_export_har(Json(report): Json<network::RegressReport>) -> Response {
    Json(network::generate_har_from_regress(&report)).into_response()
}
