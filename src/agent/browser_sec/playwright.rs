use std::path::Path;
use serde_json::{Value, json};

use super::html_analyzer::looks_like_api_or_static;
use super::models::{BrowserSecReport, target_url_for_component};
use crate::agent::discover::Discovery;
use crate::agent::exec::ExecOptions;
use crate::agent::oracle::is_login_location;
use crate::llm::untrusted::redact_then_truncate;

pub(crate) fn try_playwright_browser_security(
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
