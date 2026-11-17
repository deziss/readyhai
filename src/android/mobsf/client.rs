//! HTTP client for interacting with the MobSF REST API.
use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use std::time::{Duration, Instant};

use crate::android::util::{form_body, multipart_body, rand_hex};

pub(crate) fn mobsf_scan(base: &str, key: &str, app: &std::path::Path) -> Result<Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1500))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    // readiness
    let end = Instant::now() + Duration::from_secs(120);
    loop {
        match client
            .get(format!("{base}/"))
            .timeout(Duration::from_secs(5))
            .send()
        {
            Ok(_) => break,
            Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_secs(2)),
            Err(e) => bail!("MobSF not ready after 120s: {e}"),
        }
    }
    let fname = app
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("app.apk")
        .to_string();
    let bytes = std::fs::read(app)?;
    let boundary = format!("----readyhai{}", rand_hex(8));
    let r = client
        .post(format!("{base}/api/v1/upload"))
        .header("Authorization", key)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(multipart_body(&boundary, "file", &fname, &bytes))
        .send()?;
    let st = r.status();
    let up: Value = r
        .json()
        .with_context(|| format!("MobSF upload response (HTTP {st})"))?;
    let hash = up
        .get("hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("MobSF upload gave no hash (HTTP {st})"))?
        .to_string();
    let scan_type = up
        .get("scan_type")
        .and_then(|h| h.as_str())
        .unwrap_or("apk")
        .to_string();
    let file_name = up
        .get("file_name")
        .and_then(|h| h.as_str())
        .unwrap_or(&fname)
        .to_string();
    let post_form = |path: &str, pairs: &[(&str, &str)]| -> Result<reqwest::blocking::Response> {
        Ok(client
            .post(format!("{base}{path}"))
            .header("Authorization", key)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body(pairs))
            .send()?)
    };
    let r = post_form(
        "/api/v1/scan",
        &[
            ("hash", &hash),
            ("scan_type", &scan_type),
            ("file_name", &file_name),
        ],
    )?;
    if !r.status().is_success() {
        bail!("MobSF scan failed: HTTP {}", r.status());
    }
    let _ = r.bytes(); // synchronous scan: body is the report; we re-fetch a canonical copy below
    let r = post_form("/api/v1/report_json", &[("hash", &hash)])?;
    if !r.status().is_success() {
        bail!("MobSF report_json failed: HTTP {}", r.status());
    }
    let mut rep: Value = r.json().context("MobSF report_json body")?;
    if let Ok(r) = post_form("/api/v1/scorecard", &[("hash", &hash)])
        && r.status().is_success()
        && let Ok(sc) = r.json::<Value>()
    {
        rep["_scorecard"] = sc;
    }
    Ok(rep)
}
