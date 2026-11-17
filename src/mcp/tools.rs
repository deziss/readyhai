use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::engine;
use super::agent_bridge::{
    Runner, agent_cancel, agent_discover, agent_status_in, run_id_arg, start_swarm, swarm_request,
};
use super::protocol::untrusted;
use super::scanner::{summarize, tool_findings, tool_scan};

pub fn tool_defs() -> Value {
    json!([
        {"name": "readyhai_scan",
         "description": "Run a ReadyHai production-readiness scan (repo path, image, URL, apk) and return a verdict summary. Can take minutes.",
         "inputSchema": {"type": "object", "properties": {
            "target": {"type": "string", "description": "repo path, image, URL, apk, or user@host"},
            "profile": {"type": "string", "enum": ["quick", "standard", "deep"], "default": "quick"},
            "openapi": {"type": "string"},
            "os": {"type": "string", "enum": ["linux", "macos", "windows"]},
            "device": {"type": "string"},
            "no_tools": {"type": "boolean"}}, "required": ["target"]}},
        {"name": "readyhai_checks", "description": "List available checks.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "readyhai_run", "description": "Summary of a past run by id.",
         "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
        {"name": "readyhai_findings", "description": "Findings of a past run as JSON.",
         "inputSchema": {"type": "object", "properties": {
            "id": {"type": "string"},
            "severity_min": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
            "status": {"type": "string", "enum": ["new", "existing", "suppressed"]},
            "limit": {"type": "integer", "default": 50}}, "required": ["id"]}},
        {"name": "readyhai_agent_swarm",
         "description": "Launch an autonomous multi-agent QA and adversarial security testing swarm against a web target and return its run id immediately (a run can take minutes). Poll readyhai_agent_status with that id; readyhai_agent_cancel stops it. The swarm does recon, endpoint discovery, adaptive schema fuzzing and OWASP defect triage and ends with an Evidence Ledger and a production-readiness gate verdict (GO, CONDITIONAL_GO, NO_GO). Over MCP it is a dry run by default: no state-changing request (POST/PUT/PATCH/DELETE) is sent.",
         "inputSchema": {"type": "object", "additionalProperties": false, "properties": {
            "target": {"type": "string", "description": "HTTP/HTTPS target origin or URL"},
            "directives": {"type": "string", "maxLength": 2000, "description": "Custom instructions or test focus (e.g. authz bypass, IDOR, prompt injection)"},
            "profile": {"type": "string", "enum": ["quick", "standard", "deep"], "default": "standard"},
            "max_steps": {"type": "integer", "minimum": 1, "maximum": 50, "default": 15},
            "dry_run": {"type": "boolean", "default": true, "description": "true (default): never send state-changing requests. false is refused unless the server sets READYHAI_MCP_ALLOW_WRITES=1, and only a nonprod target is allowed."},
            "spec_url": {"type": "string", "description": "OpenAPI spec URL"},
            "repo": {"type": "string", "description": "Local checkout of the service under test, under READYHAI_ALLOWED_ROOTS. With diff_base the run plans around what the code changed: changed operations get the full case set, planned first. Needs spec_url."},
            "diff_base": {"type": "string", "description": "Git ref the change is measured from (git diff <diff_base>...HEAD in repo), e.g. origin/main. Needs repo."},
            "thinking": {"type": "boolean", "default": true, "description": "Ask the provider for extended reasoning (planning/verdict calls still run at low temperature)"},
            "thinking_budget_tokens": {"type": "integer", "minimum": 1024, "maximum": 32768, "default": 8192},
            "model_tier": {"type": "string", "enum": ["low", "medium", "high", "max", "max_pro"], "default": "high"}}, "required": ["target"]}},
        {"name": "readyhai_agent_status",
         "description": "Status of an agent run started with readyhai_agent_swarm: running / completed / failed / cancelled, progress, per-area progress of the lead's workers (auth, contract, state, ui: cases, sent, fail, budget used/allocated, wave-2 additions) and, once finished, the gate verdict, the defects and `since_last_run` (what is new, still open, fixed, regressed, flaky or accepted compared with the previous run against the same target).",
         "inputSchema": {"type": "object", "additionalProperties": false, "properties": {
            "id": {"type": "string", "description": "run id returned by readyhai_agent_swarm"}}, "required": ["id"]}},
        {"name": "readyhai_agent_cancel",
         "description": "Ask a running agent run to stop at its next step. The run still triages and records what it already did, with status cancelled.",
         "inputSchema": {"type": "object", "additionalProperties": false, "properties": {
            "id": {"type": "string", "description": "run id returned by readyhai_agent_swarm"}}, "required": ["id"]}},
        {"name": "readyhai_agent_discover",
         "description": "Fast reconnaissance and endpoint discovery for a web application. Discovers same-host routes, SPA shell technology, framework detection, and OpenAPI specifications.",
         "inputSchema": {"type": "object", "additionalProperties": false, "properties": {
            "target": {"type": "string", "description": "HTTP/HTTPS target origin"}}, "required": ["target"]}}
    ])
}

pub fn call_tool(name: &str, args: &Value) -> Result<String> {
    match name {
        "readyhai_scan" => tool_scan(args),
        "readyhai_checks" => {
            let list: Vec<Value> = crate::checks::all(
                std::env::var("READYHAI_PLUGINS")
                    .ok()
                    .map(PathBuf::from)
                    .as_deref(),
            )
            .into_iter()
            .map(|c| {
                json!({"id": c.id, "title": c.title, "kinds": c.kinds, "min_profile": c.min_profile, "tool": c.tool, "intrusive": c.intrusive})
            })
            .collect();
            Ok(serde_json::to_string_pretty(&list)?)
        }
        "readyhai_run" => {
            let id = args.get("id").and_then(|v| v.as_str()).unwrap_or("");
            Ok(summarize(&engine::load_run(id)?))
        }
        "readyhai_findings" => tool_findings(args),
        "readyhai_agent_swarm"
        | "readyhai_agent_status"
        | "readyhai_agent_cancel"
        | "readyhai_agent_discover" => {
            let scope = crate::scope::Scope::load_default()?;
            call_agent_tool(
                name,
                args,
                scope.as_ref(),
                &crate::agent::agent_runs_dir(),
                Box::new(|req, id| {
                    let opts = crate::agent::RunOptions::default()
                        .with_max_steps(req.max_steps.unwrap_or(15));
                    crate::agent::run_agentic_loop_with(req, id, opts)
                }),
            )
        }
        _ => bail!("unknown tool '{name}'"),
    }
}

/// The agent tools. Every result may carry text the target controls (route paths and titles,
/// defect titles, notes), so every result gets the same UNTRUSTED banner the scan tools use.
pub fn call_agent_tool(
    name: &str,
    args: &Value,
    scope: Option<&crate::scope::Scope>,
    base: &Path,
    runner: Runner,
) -> Result<String> {
    match name {
        "readyhai_agent_swarm" => start_swarm(swarm_request(args)?, scope, runner),
        "readyhai_agent_status" => {
            agent_status_in(base, &run_id_arg("readyhai_agent_status", args)?)
        }
        "readyhai_agent_cancel" => agent_cancel(&run_id_arg("readyhai_agent_cancel", args)?),
        "readyhai_agent_discover" => agent_discover(args, scope),
        _ => bail!("unknown tool '{name}'"),
    }
    .map(untrusted)
}
