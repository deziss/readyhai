//! Browser & client-side security verification for ReadyHai Agent (Phase 5).
//!
//! Combines Playwright real-Chromium instrumentation (`agent_browser.mjs`, when Docker + image
//! exist) with deterministic offline HTML/DOM sink & Stored XSS verification:
//! - DOM XSS source-to-sink analysis (`oracle::has_dom_xss_sink_flow`) + `ProbeOracle::DomXss`
//! - Stored XSS HTML form/endpoint write -> unescaped HTML render verification (`StatefulStep`)
//! - Client-side secret/JWT storage leaks, cookie HttpOnly/Secure hygiene, `.js.map` exposure,
//!   and iframe clickjacking reports from Chromium (all raw secrets strictly redacted).

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use super::budget::{RunBudget, SliceLimits};
use super::discover::Discovery;
use super::exec::{
    Auth, Clients, Credentials, ExecOptions, OutReq, execute_cases_with, resolve_auth,
};
use super::oracle::{
    OracleCheck, OracleOutcome, Severity, Verdict, has_dom_xss_sink_flow, is_login_location,
};
use super::plan::Depth;
use super::types::{CaseExecutionResult, CreatedLedger, PlannedCase, ProbeOracle, StatefulStep};
use crate::llm::untrusted::redact_then_truncate;

const MAX_HTML_PEEKS: usize = 6;
const MAX_SYNTHETIC_CASES: usize = 8;
const STORED_XSS_CANARY: &str = "<img src=x onerror=\"window.__rh_xss_hit('sxss')\">";
const STORED_XSS_MARKER: &str = "<img src=x onerror=";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserSecOutcome {
    pub added_cases: Vec<PlannedCase>,
    pub added_results: Vec<CaseExecutionResult>,
    pub source: &'static str,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserSecReport {
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub xss_hits: Vec<BrowserXssHit>,
    #[serde(default)]
    pub dom_sinks: Vec<BrowserDomSink>,
    #[serde(default)]
    pub storage_leaks: Vec<BrowserStorageLeak>,
    #[serde(default)]
    pub cookie_issues: Vec<BrowserCookieIssue>,
    #[serde(default)]
    pub sourcemaps: Vec<BrowserSourcemap>,
    #[serde(default)]
    pub clickjacking: Vec<BrowserClickjacking>,
    #[serde(default)]
    pub postmessage_issues: Vec<BrowserPostMessageIssue>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserXssHit {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub probe_url: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserDomSink {
    #[serde(default)]
    pub sink: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub sample: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserStorageLeak {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub store: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub preview: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserCookieIssue {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserSourcemap {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserClickjacking {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserPostMessageIssue {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub snippet: String,
}

fn path_of_url(raw: &str) -> String {
    if let Ok(u) = reqwest::Url::parse(raw) {
        let p = u.path();
        if p.is_empty() { "/".into() } else { p.into() }
    } else {
        let p = raw.split(['?', '#']).next().unwrap_or("/");
        if p.starts_with('/') {
            p.into()
        } else {
            format!("/{p}")
        }
    }
}

fn target_host_key(u: &reqwest::Url) -> String {
    let host = u.host_str().unwrap_or("localhost");
    match u.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

fn jwt_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?").unwrap()
    })
}

/// Strictly mask any JWT/secret preview before storing in cases, results, or evidence files.
fn redact_secret_preview(raw: &str, kind: &str) -> String {
    let scrubbed = jwt_re().replace_all(raw, "[REDACTED_JWT]");
    let cleaned = redact_then_truncate(scrubbed.as_ref(), 80);
    if kind.eq_ignore_ascii_case("jwt")
        || cleaned.contains("[REDACTED_JWT]")
        || (!cleaned.contains("redacted") && !cleaned.contains("REDACTED") && raw.len() >= 12)
    {
        format!("[REDACTED kind={kind} len={}]", raw.len())
    } else {
        cleaned
    }
}

fn target_url_for_component(target: &str, component: &str) -> String {
    let base = target.trim_end_matches('/');
    if component.starts_with('/') {
        format!("{base}{component}")
    } else {
        format!("{base}/{component}")
    }
}

/// Convert a Chromium `agent_browser.mjs` JSON report into planned cases and oracle-backed results.
pub fn results_from_browser_report(
    rep: &BrowserSecReport,
    target: &str,
) -> (Vec<PlannedCase>, Vec<CaseExecutionResult>) {
    let mut cases = Vec::new();
    let mut results = Vec::new();
    let mut dedup: HashSet<(String, String)> = HashSet::new();
    let mut seq = 0usize;

    let mut push_finding = |code: &str,
                            severity: Severity,
                            title: String,
                            component: String,
                            detail: String,
                            evidence: String,
                            probe_oracle: Option<ProbeOracle>,
                            extra_detail: Value| {
        if !dedup.insert((code.to_string(), component.clone())) {
            return;
        }
        seq += 1;
        let id = format!("PW{seq:03}");
        let risk = match severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        };
        let case = PlannedCase {
            id,
            title,
            component: component.clone(),
            method: "GET".into(),
            technique: "browser_security".into(),
            input_hint: format!("Verified in headless Chromium ({code})"),
            payload: None,
            headers: Vec::new(),
            content_type: None,
            probe_oracle,
            expected_behavior: format!("Client/browser security control '{code}' must hold"),
            expected_status: None,
            risk_level: risk.into(),
            role: Some("anon".into()),
            secured: None,
            route_status: Some(200),
            expect_fields: Vec::new(),
            expected_content_type: None,
            source: Some("playwright_browser_security".into()),
            stateful_steps: None,
            concurrency_burst: None,
            contract: None,
            changed_ops: Vec::new(),
            area: "ui".into(),
            regression_of: Vec::new(),
            history_priority: false,
        };
        let url = target_url_for_component(target, &component);
        let curl = format!("curl -sS {}", shell_quote(&url));
        let res = fail_result_for(
            &case,
            code,
            severity,
            redact_then_truncate(&detail, 260),
            redact_then_truncate(&evidence, 300),
            curl,
            extra_detail,
        );
        cases.push(case);
        results.push(res);
    };

    for hit in &rep.xss_hits {
        let comp = path_of_url(&hit.url);
        let safe_detail = redact_then_truncate(&hit.detail, 200);
        let safe_probe = redact_then_truncate(&hit.probe_url, 220);
        if hit.kind == "stored_xss" {
            push_finding(
                "stored_xss",
                Severity::High,
                format!("Stored XSS executed in Chromium on {comp}"),
                comp,
                format!("Chromium executed stored XSS canary: {safe_detail}"),
                format!("url={safe_probe}; {safe_detail}"),
                None,
                json!({
                    "browser": "chromium",
                    "kind": hit.kind,
                    "id": redact_then_truncate(&hit.id, 64),
                    "probe_url": safe_probe,
                }),
            );
        } else {
            push_finding(
                "dom_xss",
                Severity::High,
                format!("DOM XSS executed in Chromium on {comp} ({})", hit.kind),
                comp,
                format!(
                    "Chromium executed DOM XSS canary via {}: {safe_detail}",
                    hit.kind
                ),
                format!("probe={safe_probe}; {safe_detail}"),
                None,
                json!({
                    "browser": "chromium",
                    "kind": hit.kind,
                    "id": redact_then_truncate(&hit.id, 64),
                    "probe_url": safe_probe,
                }),
            );
        }
    }

    // Only promote sink calls where a test canary/HTML tag actually reached the runtime sink
    // (avoids noisy false positives from bundled frameworks calling `new Function("return this")`).
    for sink in &rep.dom_sinks {
        let low = sink.sample.to_ascii_lowercase();
        let tainted_sample = low.contains("__rh_xss_hit")
            || low.contains("<img")
            || low.contains("<script")
            || low.contains("onerror=")
            || low.contains("javascript:");
        if !tainted_sample {
            continue;
        }
        let comp = path_of_url(&sink.url);
        let safe_sample = redact_then_truncate(&sink.sample, 160);
        push_finding(
            "dom_xss",
            Severity::High,
            format!("Tainted DOM sink `{}` observed on {comp}", sink.sink),
            comp,
            format!(
                "Untrusted/canary input reached `{}` sink in Chromium",
                sink.sink
            ),
            format!("sink={} sample={safe_sample}", sink.sink),
            None,
            json!({
                "browser": "chromium",
                "sink": sink.sink,
                "sample": safe_sample,
            }),
        );
    }

    for leak in &rep.storage_leaks {
        let comp = path_of_url(&leak.url);
        let safe_store = redact_then_truncate(&leak.store, 40);
        let safe_key = redact_then_truncate(&leak.key, 64);
        let safe_kind = redact_then_truncate(&leak.kind, 40);
        let safe_preview = redact_secret_preview(&leak.preview, &safe_kind);
        let sev = if safe_kind.eq_ignore_ascii_case("jwt") {
            Severity::High
        } else {
            Severity::Medium
        };
        push_finding(
            "client_secret_leak",
            sev,
            format!(
                "Sensitive credential exposed in browser {safe_store} (`{safe_key}`) on {comp}"
            ),
            comp,
            format!("Chromium detected `{safe_kind}` (`{safe_key}`) in `{safe_store}`"),
            format!("store={safe_store} key={safe_key} kind={safe_kind} preview={safe_preview}"),
            None,
            json!({
                "browser": "chromium",
                "store": safe_store,
                "key": safe_key,
                "kind": safe_kind,
                "preview": safe_preview,
            }),
        );
    }

    for ck in &rep.cookie_issues {
        if ck.missing.is_empty() {
            continue;
        }
        let comp = path_of_url(&ck.url);
        let safe_name = redact_then_truncate(&ck.name, 64);
        let missing_str = ck.missing.join(", ");
        let sev = if ck
            .missing
            .iter()
            .any(|m| m.eq_ignore_ascii_case("HttpOnly"))
        {
            Severity::Medium
        } else {
            Severity::Low
        };
        push_finding(
            "cookie_hygiene",
            sev,
            format!("Auth/session cookie `{safe_name}` missing flag(s): {missing_str}"),
            comp,
            format!("Cookie `{safe_name}` observed in Chromium without {missing_str}"),
            format!("cookie={safe_name} missing={missing_str}"),
            None,
            json!({
                "browser": "chromium",
                "cookie_name": safe_name,
                "missing": ck.missing,
            }),
        );
    }

    for sm in &rep.sourcemaps {
        let comp = path_of_url(&sm.url);
        push_finding(
            "sourcemap_exposure",
            Severity::Medium,
            format!("JavaScript source map publicly accessible at {comp}"),
            comp,
            format!(
                "Public `.js.map` exposed ({} bytes) allowing full source reconstruction",
                sm.size_bytes
            ),
            format!("sourcemap bytes={}", sm.size_bytes),
            None,
            json!({
                "browser": "chromium",
                "size_bytes": sm.size_bytes,
            }),
        );
    }

    for cj in &rep.clickjacking {
        let comp = path_of_url(&cj.url);
        let safe_reason = redact_then_truncate(&cj.reason, 200);
        push_finding(
            "clickjacking",
            Severity::Medium,
            format!("Page frameable in cross-origin iframe (clickjacking) on {comp}"),
            comp,
            safe_reason.clone(),
            safe_reason,
            None,
            json!({
                "browser": "chromium",
                "frameable": true,
            }),
        );
    }

    (cases, results)
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn is_danger_route(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    [
        "/delete",
        "/remove",
        "/destroy",
        "/drop",
        "/reset",
        "/purge",
        "/truncate",
        "/logout",
        "/signout",
    ]
    .iter()
    .any(|kw| low.contains(kw))
}

fn looks_like_api_or_static(path: &str) -> bool {
    let low = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if low.starts_with("/api/")
        || low == "/api"
        || low.starts_with("/graphql")
        || low.starts_with("/_")
    {
        return true;
    }
    [
        ".json", ".xml", ".yaml", ".yml", ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".map", ".txt",
    ]
    .iter()
    .any(|ext| low.ends_with(ext))
}

#[derive(Debug, Clone)]
struct ParsedHtmlForm {
    action_path: String,
    field_names: Vec<String>,
    hidden_fields: Vec<(String, String)>,
}

fn attr_value(tag: &str, name: &str) -> Option<String> {
    static PATS: std::sync::Mutex<Option<BTreeMap<String, Regex>>> = std::sync::Mutex::new(None);
    let mut guard = PATS.lock().ok()?;
    let map = guard.get_or_insert_with(BTreeMap::new);
    let key = name.to_ascii_lowercase();
    let re = map.entry(key.clone()).or_insert_with(|| {
        Regex::new(&format!(
            r#"(?is)\b{key}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+))"#
        ))
        .unwrap()
    });
    let caps = re.captures(tag)?;
    caps.get(1)
        .or_else(|| caps.get(2))
        .or_else(|| caps.get(3))
        .map(|m| m.as_str().trim().to_string())
}

fn resolve_same_origin_action(target: &str, page_path: &str, action: &str) -> Option<String> {
    let base = reqwest::Url::parse(target).ok()?;
    let page_url = base.join(page_path).ok()?;
    let trimmed = action.trim();
    let dest = if trimmed.is_empty() {
        page_url
    } else {
        page_url.join(trimmed).ok()?
    };
    if dest.origin() != base.origin() {
        return None;
    }
    let p = dest.path().to_string();
    Some(if p.is_empty() { "/".into() } else { p })
}

/// Extract non-password, non-destructive HTML `<form method="post">` definitions for Stored XSS checks.
fn extract_post_html_forms(target: &str, page_path: &str, html: &str) -> Vec<ParsedHtmlForm> {
    static FORM_RE: OnceLock<Regex> = OnceLock::new();
    static CTRL_RE: OnceLock<Regex> = OnceLock::new();
    let form_re = FORM_RE.get_or_init(|| Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form>").unwrap());
    let ctrl_re = CTRL_RE.get_or_init(|| Regex::new(r"(?is)<(input|textarea)\b([^>]*)>").unwrap());

    let mut out = Vec::new();
    for cap in form_re.captures_iter(html) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let inner = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let method = attr_value(attrs, "method")
            .unwrap_or_else(|| "get".into())
            .to_ascii_lowercase();
        if method != "post" {
            continue;
        }
        let action_raw = attr_value(attrs, "action").unwrap_or_default();
        let Some(action_path) = resolve_same_origin_action(target, page_path, &action_raw) else {
            continue;
        };
        if is_login_location(&action_path) || is_danger_route(&action_path) {
            continue;
        }

        let mut has_password = false;
        let mut field_names = Vec::new();
        let mut hidden_fields = Vec::new();

        for ctrl in ctrl_re.captures_iter(inner) {
            let tag = ctrl
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let cattrs = ctrl.get(2).map(|m| m.as_str()).unwrap_or("");
            let input_type = attr_value(cattrs, "type")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if input_type == "password" {
                has_password = true;
                break;
            }
            let Some(name) = attr_value(cattrs, "name").filter(|n| !n.is_empty()) else {
                continue;
            };
            if tag == "textarea" {
                field_names.push(name);
            } else if input_type == "hidden" {
                let val = attr_value(cattrs, "value").unwrap_or_default();
                hidden_fields.push((name, val));
            } else if matches!(
                input_type.as_str(),
                "" | "text" | "search" | "email" | "url" | "tel"
            ) {
                field_names.push(name);
            }
        }
        if has_password || field_names.is_empty() {
            continue;
        }
        out.push(ParsedHtmlForm {
            action_path,
            field_names,
            hidden_fields,
        });
    }
    out
}

fn form_urlencoded_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn try_playwright_browser_security(
    target: &str,
    disc: &Discovery,
    exec_opts: &ExecOptions,
    work_dir: &Path,
    run_id: &str,
    allow_writes: bool,
) -> Result<Option<BrowserSecReport>, String> {
    if std::env::var("READYHAI_AGENT_BROWSER")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "off" | "0" | "false"
            )
        })
        .unwrap_or(false)
    {
        return Ok(None);
    }
    if crate::bundle::offline() {
        return Ok(None);
    }
    let docker = crate::tools::Docker::detect(&crate::engine::data_dir());
    if !docker.available {
        return Ok(None);
    }
    let image = crate::qa::ui::playwright_image();
    if crate::tools::local_image_id(&image).is_none() {
        return Ok(None);
    }

    let out = work_dir.join("browser-sec-out");
    let src = work_dir.join("browser-sec-src");
    for p in [&out, &src] {
        std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        crate::snapshot::set_mode(p, 0o777);
    }
    let _ = std::fs::remove_file(out.join("browser-sec.json"));

    let (cbase, gw) = crate::qa::ui::container_base(target);
    let mut roles_json: Vec<Value> = Vec::new();
    if let Some(primary) = exec_opts.credentials.actor()
        && let Some(tok) = exec_opts.credentials.token(&primary)
    {
        roles_json.push(json!({ "name": primary, "bearer_token": tok }));
    }
    if exec_opts.credentials.has_role("bob")
        && let Some(tok) = exec_opts.credentials.token("bob")
        && roles_json.iter().all(|r| r["name"] != "bob")
    {
        roles_json.push(json!({ "name": "bob", "bearer_token": tok }));
    }

    let mut allowed_hosts = Vec::new();
    if let Ok(u) = reqwest::Url::parse(&cbase)
        && let Some(h) = u.host_str()
    {
        allowed_hosts.push(h.to_string());
    }
    if let Ok(u) = reqwest::Url::parse(target)
        && let Some(h) = u.host_str()
        && !allowed_hosts.iter().any(|x| x.eq_ignore_ascii_case(h))
    {
        allowed_hosts.push(h.to_string());
    }

    let mut seed_urls = vec![cbase.clone()];
    for r in &disc.routes {
        if r.catch_all || is_login_location(&r.path) || looks_like_api_or_static(&r.path) {
            continue;
        }
        if r.method.eq_ignore_ascii_case("GET") && seed_urls.len() < 8 {
            seed_urls.push(target_url_for_component(&cbase, &r.path));
        }
    }

    let input_path = out.join("browser-sec-input.json");
    let input = json!({
        "base_url": cbase,
        "allowed_hosts": allowed_hosts,
        "nonprod": allow_writes,
        "max_pages": 8,
        "deadline_ms": 45_000,
        "out_dir": "/out",
        "roles": roles_json,
        "seed_urls": seed_urls,
        "probe_dom_xss": true,
        "probe_stored_xss": allow_writes,
        "probe_sourcemaps": true,
        "probe_clickjacking": true,
    });
    std::fs::write(
        &input_path,
        serde_json::to_vec_pretty(&input).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    crate::snapshot::set_mode(&input_path, 0o600);

    let mut ts = crate::tools::ToolSpec::new(
        "playwright",
        &[
            "node",
            "/runner/agent_browser.mjs",
            "/out/browser-sec-input.json",
        ],
    );
    ts.image = Some(image);
    ts.network = true;
    ts.host_gateway = gw;
    ts.memory = "2g".into();
    ts.timeout_secs = 90;

    let run = docker
        .run_dirs(run_id, &src, &out, &ts)
        .map_err(|e| format!("{e:#}"));
    // Never leave credentials on disk after runner execution.
    let _ = std::fs::remove_file(&input_path);
    let run = run?;

    let rep_path = out.join("browser-sec.json");
    let Ok(raw) = std::fs::read_to_string(&rep_path) else {
        return Err(format!(
            "agent_browser.mjs produced no report (exit {}): {}",
            run.exit_code,
            redact_then_truncate(&run.stderr_tail, 200)
        ));
    };
    let parsed: BrowserSecReport =
        serde_json::from_str(&raw).map_err(|e| format!("invalid browser-sec.json: {e}"))?;
    Ok(Some(parsed))
}

fn collect_html_snapshots(
    target: &str,
    disc: &Discovery,
    exec_opts: &ExecOptions,
    budget: &mut RunBudget,
    existing_results: &[CaseExecutionResult],
) -> BTreeMap<String, String> {
    let mut html_by_path: BTreeMap<String, String> = BTreeMap::new();

    // Reuse HTML already observed during discovery/Wave 1-2 first.
    for r in existing_results {
        let p = path_of_url(&r.component);
        if is_login_location(&p) || is_danger_route(&p) || r.blocked_reason.is_some() {
            continue;
        }
        let ct_html = r
            .content_type
            .as_deref()
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("html"));
        let status_ok = r.status_code.is_some_and(|s| (200..300).contains(&s));
        if !ct_html || !status_ok || r.is_spa_shell {
            continue;
        }
        if let Some(excerpt) = r
            .evidence_detail
            .as_ref()
            .and_then(|d| d.get("response"))
            .and_then(|resp| resp.get("body_excerpt"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            html_by_path.entry(p).or_insert_with(|| excerpt.to_string());
        }
    }

    // Collect non-API, non-login, non-catchall GET HTML route candidates.
    let mut peek_paths: Vec<String> = Vec::new();
    let mut seen_peek: HashSet<String> = HashSet::new();
    for r in &disc.routes {
        if r.catch_all || !r.method.eq_ignore_ascii_case("GET") {
            continue;
        }
        let p = path_of_url(&r.path);
        if p.contains('{')
            || is_login_location(&p)
            || is_danger_route(&p)
            || looks_like_api_or_static(&p)
        {
            continue;
        }
        // Only peek routes that either are already known HTML routes or appear browser-facing.
        let known_html = html_by_path.contains_key(&p)
            || r.content_type.to_ascii_lowercase().contains("html")
            || (r.content_type.is_empty() && (200..300).contains(&r.status_code));
        // Skip routes where earlier runs saw an auth wall / non-HTML answer.
        let blocked_or_json = existing_results.iter().any(|res| {
            path_of_url(&res.component) == p
                && (res.blocked_reason.is_some()
                    || res.is_spa_shell
                    || res
                        .content_type
                        .as_deref()
                        .is_some_and(|ct| ct.to_ascii_lowercase().contains("json")))
        });
        if known_html && !blocked_or_json && seen_peek.insert(p.clone()) {
            peek_paths.push(p);
        }
    }
    peek_paths.truncate(MAX_HTML_PEEKS);

    if peek_paths.is_empty() {
        return html_by_path;
    }

    let Ok(base_url) = reqwest::Url::parse(target) else {
        return html_by_path;
    };
    let Ok(clients) = Clients::new(exec_opts.timeout, &base_url) else {
        return html_by_path;
    };
    let host_key = target_host_key(&base_url);
    let auth = match exec_opts.credentials.actor() {
        Some(role) => resolve_auth(&Auth::Role(role), &exec_opts.credentials),
        None => resolve_auth(&Auth::None, &exec_opts.credentials),
    };

    for p in peek_paths {
        // Need full HTML body because evidence excerpts cut at ~400 bytes, while `<form>` / `<script>` can follow later.
        if budget.requests_left() <= 16 || budget.is_cancelled() {
            break;
        }
        if budget.take_request(&host_key).is_err() {
            break;
        }
        let Ok(u) = base_url.join(&p) else {
            continue;
        };
        let req = OutReq {
            method: "GET",
            url: u.as_str(),
            body: None,
            headers: &[],
            bearer: auth.bearer.as_ref(),
        };
        if let Ok(followed) =
            clients.send_following(&req, 2, &mut || budget.take_request(&host_key))
        {
            let seen = followed.seen;
            if (200..300).contains(&seen.status)
                && seen.content_type.to_ascii_lowercase().contains("html")
                && !super::oracle::has_password_field(&seen.body)
            {
                html_by_path.insert(p, seen.body);
            }
        }
    }

    html_by_path
}

/// Execute browser-based (Playwright when available) and deterministic DOM/Stored XSS verification.
#[allow(clippy::too_many_arguments)]
pub fn run_browser_security(
    target: &str,
    depth: Depth,
    disc: &Discovery,
    exec_opts: &ExecOptions,
    created: &CreatedLedger,
    work_dir: &Path,
    run_id: &str,
    allow_writes: bool,
    budget: &mut RunBudget,
    existing_results: &[CaseExecutionResult],
) -> BrowserSecOutcome {
    let mut outcome = BrowserSecOutcome::default();
    if exec_opts.dry_run
        || depth == Depth::Quick
        || budget.is_cancelled()
        || budget.wall_left() < Duration::from_secs(2)
    {
        return outcome;
    }

    // `verify::verify_failures` charges requests (never steps), so keep a modest request
    // reserve for verification/cleanup and only a tiny step guard after Lead + ReAct finish.
    let reserve_requests = (budget.max_requests() / 6).max(12);
    let reserve_steps = (budget.max_steps() / 16).clamp(1, 6);
    if budget.steps_left() <= reserve_steps || budget.requests_left() <= reserve_requests {
        return outcome;
    }

    // 1. Optional real Chromium pass when Docker + Playwright image are locally installed.
    let mut pw_used = false;
    match try_playwright_browser_security(target, disc, exec_opts, work_dir, run_id, allow_writes) {
        Ok(Some(pw_rep)) => {
            pw_used = true;
            outcome.notes.extend(pw_rep.notes.iter().cloned());
            let (pw_cases, pw_results) = results_from_browser_report(&pw_rep, target);
            outcome.added_cases.extend(pw_cases);
            outcome.added_results.extend(pw_results);
        }
        Ok(None) => {}
        Err(msg) => outcome
            .notes
            .push(format!("playwright browser security skipped: {msg}")),
    }

    // 2. Deterministic offline HTTP + DOM-sink + Stored-XSS verification (works in air-gapped CI
    //    and enables verify_k >= 2 replay via execute_cases_with -> verify.rs).
    let html_pages = collect_html_snapshots(target, disc, exec_opts, budget, existing_results);
    let mut synth_cases: Vec<PlannedCase> = Vec::new();
    let mut seen_dom_paths: HashSet<String> = outcome
        .added_results
        .iter()
        .filter(|r| {
            r.oracle.as_ref().is_some_and(|o| {
                o.checks
                    .iter()
                    .any(|c| c.code == "dom_xss" && c.verdict == Verdict::Fail)
            })
        })
        .map(|r| path_of_url(&r.component))
        .collect();
    let mut seen_stored_paths: HashSet<String> = outcome
        .added_results
        .iter()
        .filter(|r| {
            r.oracle.as_ref().is_some_and(|o| {
                o.checks
                    .iter()
                    .any(|c| c.code == "stored_xss" && c.verdict == Verdict::Fail)
            })
        })
        .map(|r| path_of_url(&r.component))
        .collect();
    let mut next_id = 0usize;

    for (path, html) in &html_pages {
        if synth_cases.len() >= MAX_SYNTHETIC_CASES {
            break;
        }
        if has_dom_xss_sink_flow(html).is_some() && seen_dom_paths.insert(path.clone()) {
            next_id += 1;
            synth_cases.push(make_browser_finding_case(
                format!("BS{next_id:03}"),
                format!("DOM XSS source-to-sink flow verification on GET {path}"),
                path.clone(),
                "GET",
                Some(ProbeOracle::DomXss {
                    canary: "window.__rh_xss_hit".into(),
                }),
                "Client scripts must sanitize URL/location sources before HTML/eval sinks".into(),
                "high",
            ));
        }

        if allow_writes
            && synth_cases.len() < MAX_SYNTHETIC_CASES
            && !is_login_location(path)
            && !is_danger_route(path)
        {
            for form in extract_post_html_forms(target, path, html) {
                if synth_cases.len() >= MAX_SYNTHETIC_CASES
                    || !seen_stored_paths.insert(path.clone())
                {
                    break;
                }
                next_id += 1;
                let mut body_parts: Vec<String> = form
                    .field_names
                    .iter()
                    .enumerate()
                    .map(|(i, k)| {
                        let v = if i == 0 { STORED_XSS_CANARY } else { "test" };
                        format!(
                            "{}={}",
                            form_urlencoded_encode(k),
                            form_urlencoded_encode(v)
                        )
                    })
                    .collect();
                for (hk, hv) in &form.hidden_fields {
                    body_parts.push(format!(
                        "{}={}",
                        form_urlencoded_encode(hk),
                        form_urlencoded_encode(hv)
                    ));
                }
                let form_payload = body_parts.join("&");

                let poster = exec_opts
                    .credentials
                    .actor()
                    .unwrap_or_else(|| "anon".into());
                let viewer = if exec_opts.credentials.has_role("bob") && poster != "bob" {
                    "bob".to_string()
                } else {
                    poster.clone()
                };

                let mut case = make_browser_finding_case(
                    format!("BS{next_id:03}"),
                    format!(
                        "Stored XSS HTML persistence check ({} -> GET {path})",
                        form.action_path
                    ),
                    path.clone(),
                    "GET",
                    None,
                    "Submitted HTML/script input must be output-encoded before rendering in HTML"
                        .into(),
                    "high",
                );
                case.role = Some(poster.clone());
                case.stateful_steps = Some(vec![
                    StatefulStep {
                        step_number: 1,
                        actor: poster,
                        method: "POST".into(),
                        path: form.action_path.clone(),
                        payload: Some(form_payload),
                        extract_vars: None,
                        expected_status: None,
                        violation_condition: None,
                    },
                    StatefulStep {
                        step_number: 2,
                        actor: viewer,
                        method: "GET".into(),
                        path: path.clone(),
                        payload: None,
                        extract_vars: None,
                        expected_status: Some(200),
                        violation_condition: Some(format!(
                            "stored_xss:unescaped:{STORED_XSS_MARKER}"
                        )),
                    },
                ]);
                synth_cases.push(case);
            }
        }
    }

    if !synth_cases.is_empty() {
        let avail_steps = budget.steps_left().saturating_sub(reserve_steps);
        let avail_reqs = budget.requests_left().saturating_sub(reserve_requests);
        let keep = synth_cases.len().min(avail_steps).min(avail_reqs / 2);
        synth_cases.truncate(keep);
        if !synth_cases.is_empty() {
            let mut slice = budget.slice(
                "browser_security",
                SliceLimits {
                    steps: synth_cases.len(),
                    requests: avail_reqs.min(synth_cases.len() * (3 + exec_opts.reruns as usize)),
                    wall: budget.wall_left().min(Duration::from_secs(45)),
                    llm_calls: 0,
                },
            );
            let _installed = created.install();
            let res = execute_cases_with(&synth_cases, target, exec_opts, &mut slice);
            budget.absorb(&slice.usage());
            outcome.added_cases.extend(synth_cases);
            outcome.added_results.extend(res);
        }
    }

    outcome.source = if pw_used {
        "playwright+deterministic"
    } else {
        "deterministic"
    };
    outcome
}

fn make_browser_finding_case(
    id: String,
    title: String,
    component: String,
    method: &str,
    probe_oracle: Option<ProbeOracle>,
    expected_behavior: String,
    risk_level: &str,
) -> PlannedCase {
    PlannedCase {
        id,
        title,
        component,
        method: method.to_string(),
        technique: "browser_security".into(),
        input_hint: "Browser security verification".into(),
        payload: None,
        headers: Vec::new(),
        content_type: None,
        probe_oracle,
        expected_behavior,
        expected_status: None,
        risk_level: risk_level.to_string(),
        role: Some("anon".into()),
        secured: None,
        route_status: Some(200),
        expect_fields: Vec::new(),
        expected_content_type: None,
        source: Some("browser_security".into()),
        stateful_steps: None,
        concurrency_burst: None,
        contract: None,
        changed_ops: Vec::new(),
        area: "ui".into(),
        regression_of: Vec::new(),
        history_priority: false,
    }
}

fn fail_result_for(
    case: &PlannedCase,
    code: &str,
    severity: Severity,
    detail: String,
    evidence: String,
    repro_curl: String,
    extra_detail: Value,
) -> CaseExecutionResult {
    let outcome = OracleOutcome {
        verdict: Verdict::Fail,
        checks: vec![OracleCheck {
            code: code.to_string(),
            verdict: Verdict::Fail,
            severity: Some(severity),
            detail: detail.clone(),
        }],
        warnings: Vec::new(),
        exploratory: false,
    };
    CaseExecutionResult {
        case_id: case.id.clone(),
        title: case.title.clone(),
        component: case.component.clone(),
        method: case.method.clone(),
        technique: case.technique.clone(),
        status: "FAIL".into(),
        status_code: Some(200),
        latency_ms: 1,
        reproduction_curl: repro_curl,
        request_payload: case.payload.clone(),
        evidence,
        content_type: Some("text/html".into()),
        is_spa_shell: false,
        failure_reason: Some(detail),
        blocked_reason: None,
        expected_status: None,
        oracle: Some(outcome),
        flaky: false,
        attempts: Vec::new(),
        evidence_file: Some(evidence_rel_path(&case.id)),
        evidence_detail: Some(extra_detail),
        stateful_chain: None,
        concurrency_burst_results: None,
        redirect_chain: Vec::new(),
    }
}

use super::exec::evidence_rel_path;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::exec::Credentials;
    use crate::agent::pipeline::{LlmMode, RunOptions, run_with};
    use crate::agent::types::AgentRunRequest;
    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{Html, IntoResponse};
    use axum::routing::get;
    use std::sync::{Arc, Mutex, mpsc};
    use tokio::net::TcpListener;

    #[test]
    fn parses_playwright_browser_sec_report_with_dom_xss_storage_secrets_sourcemaps_cookies_and_clickjacking()
     {
        let raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInNlY3JldCI6Imh1bnRlcjIifQ.sig1234567890";
        let rep: BrowserSecReport = serde_json::from_value(json!({
            "base_url": "https://app.example.test",
            "xss_hits": [
                {
                    "kind": "dom_hash",
                    "id": "dom-hash-0",
                    "url": "https://app.example.test/dom",
                    "probe_url": "https://app.example.test/dom#<img src=x onerror=\"window.__rh_xss_hit('dom-hash-0','hash')\">",
                    "detail": "hash"
                },
                {
                    "kind": "stored_xss",
                    "id": "stored-form-1-0",
                    "url": "https://app.example.test/comments",
                    "probe_url": "https://app.example.test/comments",
                    "detail": "Stored XSS canary executed for role 'bob'"
                }
            ],
            "storage_leaks": [
                {
                    "url": "https://app.example.test/dashboard",
                    "store": "localStorage",
                    "key": "auth_token",
                    "kind": "jwt",
                    "preview": raw_jwt
                }
            ],
            "cookie_issues": [
                {
                    "url": "https://app.example.test/",
                    "name": "session_id",
                    "missing": ["HttpOnly", "Secure"]
                }
            ],
            "sourcemaps": [
                {
                    "url": "https://app.example.test/assets/app.js.map",
                    "size_bytes": 4096
                }
            ],
            "clickjacking": [
                {
                    "url": "https://app.example.test/transfer",
                    "reason": "Page loaded inside <iframe> without X-Frame-Options or CSP frame-ancestors"
                }
            ]
        }))
        .unwrap();

        let (cases, results) = results_from_browser_report(&rep, "https://app.example.test");
        assert!(
            results.len() >= 6,
            "expected all 6 browser security findings, got {}",
            results.len()
        );
        assert_eq!(cases.len(), results.len());

        let codes: Vec<&str> = results
            .iter()
            .filter_map(|r| r.oracle.as_ref())
            .flat_map(|o| o.checks.iter().map(|c| c.code.as_str()))
            .collect();
        for expected in [
            "dom_xss",
            "stored_xss",
            "client_secret_leak",
            "cookie_hygiene",
            "sourcemap_exposure",
            "clickjacking",
        ] {
            assert!(
                codes.contains(&expected),
                "missing check code {expected} in {codes:?}"
            );
        }

        let serialized = serde_json::to_string(&results).unwrap();
        assert!(
            !serialized.contains(raw_jwt),
            "raw JWT leaked into BrowserSec result JSON!"
        );
        assert!(
            !serialized.contains("eyJhbGciOiJIUzI1NiIs"),
            "JWT header/payload leaked without redaction!"
        );
    }

    #[test]
    fn agent_detects_dom_xss_and_stored_xss_with_clean_control_and_verifies_k() {
        let comments: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = mpsc::channel();
        let comments_bg = Arc::clone(&comments);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new()
                    .route(
                        "/",
                        get(|| async {
                            Html(
                                r#"<!doctype html><html><body>
                                <a href="/dom">DOM Viewer</a>
                                <a href="/comments">Comments</a>
                                <a href="/safe">Safe Viewer</a>
                                </body></html>"#,
                            )
                        }),
                    )
                    .route(
                        "/dom",
                        get(|| async {
                            Html(
                                r#"<!doctype html><html><body>
                                <div id="out"></div>
                                <script>document.getElementById('out').innerHTML = location.hash;</script>
                                </body></html>"#,
                            )
                        }),
                    )
                    .route(
                        "/safe",
                        get(|| async {
                            Html(
                                r#"<!doctype html><html><body>
                                <div id="safe"></div>
                                <script>document.getElementById('safe').textContent = location.hash;</script>
                                </body></html>"#,
                            )
                        }),
                    )
                    .route(
                        "/comments",
                        get(|State(store): State<Arc<Mutex<Vec<String>>>>| async move {
                            let list = store.lock().unwrap().join("</li><li>");
                            Html(format!(
                                r#"<!doctype html><html><body>
                                <form method="POST" action="/comments">
                                  <input type="text" name="comment" />
                                  <button type="submit">Post</button>
                                </form>
                                <ul><li>{list}</li></ul>
                                </body></html>"#
                            ))
                        })
                        .post(
                            |State(store): State<Arc<Mutex<Vec<String>>>>,
                             headers: HeaderMap,
                             body: axum::body::Bytes| async move {
                                let auth = headers
                                    .get(axum::http::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("");
                                if auth != "Bearer alice-token" && auth != "Bearer bob-token" {
                                    return (
                                        StatusCode::UNAUTHORIZED,
                                        Html("Unauthorized".to_string()),
                                    )
                                        .into_response();
                                }
                                let raw = String::from_utf8_lossy(&body);
                                let text = if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                                    v.get("comment")
                                        .or_else(|| v.get("message"))
                                        .or_else(|| v.get("body"))
                                        .or_else(|| v.get("text"))
                                        .and_then(Value::as_str)
                                        .unwrap_or("")
                                        .to_string()
                                } else {
                                    reqwest::Url::parse(&format!("http://localhost/?{raw}"))
                                        .ok()
                                        .and_then(|u| {
                                            u.query_pairs()
                                                .find(|(k, _)| {
                                                    k == "comment" || k == "message" || k == "body"
                                                })
                                                .map(|(_, v)| v.into_owned())
                                        })
                                        .unwrap_or_default()
                                };
                                store.lock().unwrap().push(text);
                                (StatusCode::CREATED, Html("Stored".to_string())).into_response()
                            },
                        ),
                    )
                    .with_state(comments_bg);

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://127.0.0.1:{}", addr.port())).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let base_url = rx.recv().unwrap();

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let run_base = std::env::temp_dir().join(format!("rh-browsersec-{nonce}"));
        std::fs::create_dir_all(&run_base).unwrap();

        let req = AgentRunRequest {
            target: base_url,
            profile: "standard".into(),
            spec_url: None,
            custom_instructions: None,
            max_steps: None,
            dry_run: false,
            thinking: false,
            model_tier: "balanced".into(),
            thinking_budget_tokens: 1024,
            repo: None,
            diff_base: None,
        };
        let budget = RunBudget::new(90, 240, Duration::from_secs(60), 0.0);
        let opts = RunOptions {
            budget,
            credentials: Credentials::none()
                .with("alice", "alice-token")
                .with("bob", "bob-token"),
            llm: LlmMode::Off,
            reruns: 0,
            verify_k: 2,
            request_timeout: Duration::from_secs(5),
            lookup_requester_ip: false,
            workers: 2,
            memory_dir: None,
        };

        let rep = run_with(&run_base, &req, "browser-sec-test", opts, Some(true)).unwrap();
        let _ = std::fs::remove_dir_all(&run_base);

        assert!(
            rep.stage_sources.contains_key("browser_security"),
            "expected browser_security in stage_sources: {:?}",
            rep.stage_sources
        );
        assert!(
            rep.triaged_defects
                .iter()
                .any(|d| d.rule == "dom_xss" && d.component.contains("/dom") && d.verified),
            "expected verified dom_xss defect on /dom, got: {:?}",
            rep.triaged_defects
        );
        assert!(
            rep.triaged_defects
                .iter()
                .any(|d| d.rule == "stored_xss" && d.component.contains("/comments") && d.verified),
            "expected verified stored_xss defect on /comments, got: {:?}",
            rep.triaged_defects
        );
        assert!(
            rep.triaged_defects
                .iter()
                .all(|d| !d.component.contains("/safe")),
            "clean control /safe produced a false positive defect: {:?}",
            rep.triaged_defects
        );
    }
}
