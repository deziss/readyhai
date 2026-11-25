//! Scans and report artifact HTTP endpoint handlers.

use super::agent_api::{read_report_file, regenerate_reports};
use super::guards::{err, offload};
use super::types::{App, MAX_LISTED_RUNS, TriggerScanReq};
use super::worker::{enqueue, prepare_scan, read_json, run_in_progress};
use crate::engine::{self, ScanOpts};
use crate::model::Profile;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;

pub async fn list_checks(State(app): State<Arc<App>>) -> Response {
    let list: Vec<_> = crate::checks::all(app.plugins.as_deref())
        .into_iter()
        .map(|c| json!({"id": c.id, "title": c.title, "kinds": c.kinds, "min_profile": c.min_profile, "tool": c.tool, "intrusive": c.intrusive}))
        .collect();
    Json(list).into_response()
}

pub async fn create_run(State(app): State<Arc<App>>, Json(opts): Json<ScanOpts>) -> Response {
    let opts = match prepare_scan(&app, opts).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    match enqueue(&app, opts) {
        Ok(id) => (
            StatusCode::ACCEPTED,
            Json(json!({"id": id, "state": "queued"})),
        )
            .into_response(),
        Err(r) => r,
    }
}

pub async fn get_run(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    match offload(move || get_run_blocking(&id)).await {
        Ok(r) | Err(r) => r,
    }
}

pub fn get_run_blocking(id: &str) -> Response {
    let Some(status) = read_json(id, "status.json") else {
        return err(StatusCode::NOT_FOUND, "no such run");
    };
    let mut out = status;
    if let Some(mut run) = read_json(id, "run.json") {
        run.as_object_mut().map(|o| o.remove("findings"));
        out["state"] = json!("done");
        for k in ["verdict", "reasons", "categories", "checks"] {
            out[k] = run[k].clone();
        }
        out["run"] = run;
    }
    Json(out).into_response()
}

pub async fn get_findings(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    match offload(move || read_json(&id, "run.json")).await {
        Ok(Some(r)) => Json(r["findings"].clone()).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "run not finished or not found"),
        Err(r) => r,
    }
}

pub async fn get_report(Path((id, fmt)): Path<(String, String)>) -> Response {
    let (file, ctype) = match fmt.as_str() {
        "html" => ("readyhai-report.html", "text/html; charset=utf-8"),
        "json" => ("readyhai-report.json", "application/json"),
        "sarif" => ("readyhai-report.sarif", "application/sarif+json"),
        "junit" => ("readyhai-report.junit.xml", "application/xml"),
        _ => return err(StatusCode::BAD_REQUEST, "format: html|json|sarif|junit"),
    };
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    let path = engine::run_dir(&id).join("report").join(file);
    match offload(move || read_report_file(&path)).await {
        Ok(Some(b)) => (
            [
                (header::CONTENT_TYPE, ctype),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
                ),
            ],
            b,
        )
            .into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "report not ready"),
        Err(r) => r,
    }
}

pub async fn api_scans_create(
    State(app): State<Arc<App>>,
    Json(req): Json<TriggerScanReq>,
) -> Response {
    let target = req.target.trim().to_string();
    if target.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "Target repository or directory cannot be empty",
        );
    }
    let (profile, profile_name) = match req.profile.to_lowercase().as_str() {
        "quick" => (Profile::Quick, "quick"),
        "standard" => (Profile::Standard, "standard"),
        "deep" => (Profile::Deep, "deep"),
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                "profile must be quick|standard|deep",
            );
        }
    };
    let opts = ScanOpts {
        target: target.clone(),
        profile: Some(profile),
        // Operator toggles: READYHAI_SETTINGS wins; else <data>/settings.toml
        // (the file the Settings UI writes). The orchestrator re-reads per run.
        settings: super::settings_api::scan_settings_path(),
        ..Default::default()
    };
    // Same precheck as POST /runs: allowed roots for paths, scope for every network destination.
    let opts = match prepare_scan(&app, opts).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    match enqueue(&app, opts) {
        Ok(id) => (
            StatusCode::ACCEPTED,
            Json(json!({"id": id, "state": "queued", "target": target, "profile": profile_name})),
        )
            .into_response(),
        Err(r) => r,
    }
}

pub async fn api_scans_list() -> Response {
    match offload(api_scans_list_blocking).await {
        Ok(r) | Err(r) => r,
    }
}

pub fn api_scans_list_blocking() -> Response {
    let Ok(rd) = std::fs::read_dir(engine::data_dir().join("runs")) else {
        return Json(json!({"scans": []})).into_response();
    };
    let mut ids: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| engine::valid_run_id(n))
        .collect();
    ids.sort_unstable_by(|a, b| b.cmp(a));
    ids.truncate(MAX_LISTED_RUNS);

    let scans: Vec<serde_json::Value> = ids
        .into_iter()
        .map(|id| {
            let run_val = read_json(&id, "run.json");
            let st = read_json(&id, "status.json");
            let target_raw = run_val
                .as_ref()
                .and_then(|r| r["target"]["raw"].as_str())
                .or_else(|| st.as_ref().and_then(|s| s["target"].as_str()))
                .unwrap_or_default();

            let rep_dir = engine::run_dir(&id).join("report");
            let has_html = rep_dir.join("readyhai-report.html").exists() || run_val.is_some();
            let has_json = rep_dir.join("readyhai-report.json").exists() || run_val.is_some();
            let has_sarif = rep_dir.join("readyhai-report.sarif").exists() || run_val.is_some();
            let has_junit = rep_dir.join("readyhai-report.junit.xml").exists() || run_val.is_some();

            let findings_count = run_val
                .as_ref()
                .and_then(|r| r["findings"].as_array())
                .map(|f| f.len())
                .unwrap_or(0);
            let hard_fail_count = run_val
                .as_ref()
                .and_then(|r| r["findings"].as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("critical"))
                        .count()
                })
                .unwrap_or(0);

            let kind = run_val
                .as_ref()
                .and_then(|r| r["target"]["kind"].as_str())
                .unwrap_or("repo");
            let profile = run_val
                .as_ref()
                .and_then(|r| r["profile"].as_str())
                .unwrap_or("quick");
            let verdict = run_val
                .as_ref()
                .and_then(|r| r["verdict"].as_str())
                .unwrap_or("UNKNOWN");
            let state = st
                .as_ref()
                .and_then(|s| s["state"].as_str())
                .unwrap_or(if run_val.is_some() { "done" } else { "unknown" });
            let started = run_val
                .as_ref()
                .and_then(|r| r["started"].as_str())
                .or_else(|| st.as_ref().and_then(|s| s["started"].as_str()));
            let finished = run_val.as_ref().and_then(|r| r["finished"].as_str());
            let reasons = run_val
                .as_ref()
                .and_then(|r| r["reasons"].as_array())
                .cloned()
                .unwrap_or_default();
            let categories = run_val
                .as_ref()
                .and_then(|r| r["categories"].as_object())
                .cloned()
                .unwrap_or_default();

            json!({
                "id": id,
                "target": target_raw,
                "kind": kind,
                "profile": profile,
                "verdict": verdict,
                "state": state,
                "started": started,
                "finished": finished,
                "reasons": reasons,
                "findings_count": findings_count,
                "hard_fail_count": hard_fail_count,
                "categories": categories,
                "reports": {
                    "html": has_html,
                    "json": has_json,
                    "sarif": has_sarif,
                    "junit": has_junit,
                }
            })
        })
        .collect();

    Json(json!({"scans": scans})).into_response()
}

pub async fn api_scan_get(Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    match offload(move || api_scan_get_blocking(&id)).await {
        Ok(r) | Err(r) => r,
    }
}

/// Render a finished core run's reports into `<run>/report`, atomically, if they are missing.
/// Does nothing (and never recreates the directory) when the run has been deleted meanwhile.
pub fn regenerate_scan_reports(id: &str, run_val: serde_json::Value) {
    let rep_dir = engine::run_dir(id).join("report");
    if let Ok(run_struct) = serde_json::from_value::<crate::model::Run>(run_val) {
        let _ = regenerate_reports(&[engine::run_dir(id)], &rep_dir, |tmp| {
            crate::report::write(
                &run_struct,
                tmp,
                &["html".into(), "json".into(), "sarif".into(), "junit".into()],
            )
            .map(|_| ())
        });
    }
}

pub fn api_scan_get_blocking(id: &str) -> Response {
    let st = read_json(id, "status.json");
    let Some(run_val) = read_json(id, "run.json") else {
        if let Some(status) = st {
            let target = status["target"].as_str().unwrap_or_default();
            return Json(json!({
                "id": id,
                "version": engine::VERSION,
                "target": { "kind": "repo", "raw": target, "path": "" },
                "profile": "quick",
                "started": engine::now(),
                "finished": null,
                "verdict": if status["state"].as_str() == Some("error") { "FAIL" } else { "RUNNING" },
                "state": status["state"],
                "reasons": if status["state"].as_str() == Some("error") { vec![status["error"].as_str().unwrap_or("scan error").to_string()] } else { vec!["Scan in progress...".to_string()] },
                "findings": [],
                "checks": [],
                "categories": []
            })).into_response();
        }
        return err(StatusCode::NOT_FOUND, "scan run not found");
    };
    if !engine::run_dir(id)
        .join("report")
        .join("readyhai-report.html")
        .exists()
    {
        regenerate_scan_reports(id, run_val.clone());
    }
    Json(run_val).into_response()
}

pub async fn api_scan_report(Path((id, fmt)): Path<(String, String)>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    let (file, ctype) = match fmt.as_str() {
        "html" => ("readyhai-report.html", "text/html; charset=utf-8"),
        "json" => ("readyhai-report.json", "application/json"),
        "sarif" => ("readyhai-report.sarif", "application/sarif+json"),
        "junit" => ("readyhai-report.junit.xml", "application/xml"),
        _ => return err(StatusCode::BAD_REQUEST, "format: html|json|sarif|junit"),
    };
    match offload(move || api_scan_report_blocking(&id, &fmt, file, ctype)).await {
        Ok(r) | Err(r) => r,
    }
}

pub fn api_scan_report_blocking(id: &str, fmt: &str, file: &str, ctype: &str) -> Response {
    let rep_file = engine::run_dir(id).join("report").join(file);
    if !rep_file.exists()
        && let Some(run_val) = read_json(id, "run.json")
    {
        regenerate_scan_reports(id, run_val);
    }
    match read_report_file(&rep_file) {
        Some(b) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, ctype.parse().unwrap());
            if fmt == "html" {
                headers.insert(
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
                        .parse()
                        .unwrap(),
                );
            } else {
                let ext = if fmt == "junit" { "xml" } else { fmt };
                headers.insert(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"readyhai-{id}-{fmt}.{ext}\"")
                        .parse()
                        .unwrap(),
                );
            }
            (headers, b).into_response()
        }
        None => err(StatusCode::NOT_FOUND, "report not ready or not found"),
    }
}

/// Deleting a queued run cancels it (the worker skips runs whose directory is gone); a running
/// one is refused with 409 rather than having its directory removed underneath the scan. A
/// directory that cannot be removed is an error, not a silent "deleted".
pub async fn api_scan_delete(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    if !engine::valid_run_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad run id");
    }
    if run_in_progress(&app, &id) {
        return err(
            StatusCode::CONFLICT,
            "run is in progress; delete it after it finishes",
        );
    }
    let rid = id.clone();
    let res = offload(move || -> Result<bool, std::io::Error> {
        let dir = engine::run_dir(&rid);
        if !dir.exists() {
            return Ok(false);
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(true)
    })
    .await;
    match res {
        Ok(Ok(true)) => (StatusCode::OK, Json(json!({"deleted": id}))).into_response(),
        Ok(Ok(false)) => err(StatusCode::NOT_FOUND, "run not found"),
        Ok(Err(e)) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not delete run {id}: {}", e.kind()),
        ),
        Err(r) => r,
    }
}

/// Last [`MAX_LISTED_RUNS`] runs (newest first): id, state, target, verdict.
pub fn list_runs_json() -> Vec<serde_json::Value> {
    let Ok(rd) = std::fs::read_dir(engine::data_dir().join("runs")) else {
        return vec![];
    };
    let mut ids: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| engine::valid_run_id(n))
        .collect();
    ids.sort_unstable_by(|a, b| b.cmp(a)); // ids start with a UTC timestamp
    ids.truncate(MAX_LISTED_RUNS);
    ids.into_iter()
        .map(|id| {
            let st = read_json(&id, "status.json");
            let run = read_json(&id, "run.json");
            json!({
                "id": id,
                "state": st.as_ref().and_then(|s| s["state"].as_str()).unwrap_or(if run.is_some() { "done" } else { "unknown" }),
                "target": run.as_ref().and_then(|r| r["target"]["raw"].as_str()),
                "verdict": run.as_ref().and_then(|r| r["verdict"].as_str()),
            })
        })
        .collect()
}

pub async fn list_runs() -> Response {
    match offload(list_runs_json).await {
        Ok(l) => Json(l).into_response(),
        Err(r) => r,
    }
}
