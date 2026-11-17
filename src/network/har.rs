//! HTTP Archive (HAR 1.2) serializer for regression test results.

use super::types::RegressReport;
use serde_json::json;

pub fn generate_har_from_regress(report: &RegressReport) -> serde_json::Value {
    let mut entries = Vec::new();

    for it in &report.iterations {
        let headers: Vec<serde_json::Value> = it
            .response_headers
            .iter()
            .map(|(k, v)| json!({"name": k, "value": v}))
            .collect();

        let mime = it
            .response_headers
            .get("content-type")
            .cloned()
            .unwrap_or_else(|| "text/html; charset=utf-8".into());

        let body_snippet = it.response_body_snippet.clone().unwrap_or_default();
        let body_len = body_snippet.len();

        let dns = it.dns_lookup_ms as i64;
        let connect = it.tcp_connect_ms as i64;
        let wait = it.ttfb_ms as i64;
        let receive = (it.duration_ms as i64 - wait).max(0);

        let http_version = it.http_version.clone().unwrap_or_default();
        let mut entry = json!({
            "startedDateTime": it.timestamp,
            "time": it.duration_ms,
            "request": {
                "method": report.method,
                "url": report.target,
                "httpVersion": http_version,
                "cookies": [],
                "headers": [
                    { "name": "User-Agent", "value": format!("ReadyHai-NetworkLab/{}", crate::engine::VERSION) },
                    { "name": "Accept", "value": "*/*" }
                ],
                "queryString": [],
                "headersSize": -1,
                "bodySize": 0
            },
            "response": {
                "status": it.status_code,
                "statusText": if it.success { "OK" } else { "Error" },
                "httpVersion": http_version,
                "cookies": [],
                "headers": headers,
                "content": {
                    "size": body_len,
                    "mimeType": mime,
                    "text": body_snippet
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": body_len
            },
            "cache": {},
            // -1 = not measured (HAR convention)
            "timings": {
                "blocked": -1,
                "dns": dns,
                "connect": connect,
                "ssl": -1,
                "send": -1,
                "wait": wait,
                "receive": receive
            },
            "connection": it.session_id
        });
        if let Some(ip) = &it.resolved_ip {
            entry["serverIPAddress"] = json!(ip);
        }
        entries.push(entry);
    }

    json!({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "ReadyHai Autonomous QA Gate",
                "version": crate::engine::VERSION
            },
            "pages": [
                {
                    "startedDateTime": report.iterations.first().map(|i| i.timestamp.as_str()).unwrap_or(""),
                    "id": "page_readyhai_regression",
                    "title": format!("ReadyHai Regression Audit - {}", report.target),
                    "pageTimings": {
                        "onContentLoad": report.p50_latency_ms,
                        "onLoad": report.p90_latency_ms
                    }
                }
            ],
            "entries": entries
        }
    })
}

