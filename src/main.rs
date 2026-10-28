mod agent;
mod android;
mod baseline;
mod bundle;
mod checks;
mod config;
mod ctx;
mod dashboard;
mod engine;
mod facts;
mod host;
mod llm;
mod logs;
mod mcp;
pub mod network;
mod model;
mod policy;
mod qa;
mod report;
mod rules;
mod scope;
mod serve;
mod snapshot;
mod tools;
mod web;

use clap::{Parser, Subcommand};
use engine::ScanOpts;
use model::{CheckStatus, FindingStatus, Os, Profile, Run};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "readyhai", version, about = "Ready hai? Self-hosted QA tester + production-readiness gate")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan a target: ./repo | git:<url> | image:<ref> | https://app | ssh://user@host[:port] | android:app.apk
    Scan {
        target: String,
        #[arg(long, value_enum, default_value = "quick")]
        profile: Profile,
        /// OpenAPI spec URL (web targets)
        #[arg(long)]
        openapi: Option<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Rules of engagement for web targets
        #[arg(long, env = "READYHAI_SCOPE")]
        scope: Option<PathBuf>,
        /// readyhai.toml (default: <repo>/readyhai.toml)
        #[arg(long)]
        config: Option<PathBuf>,
        /// Baseline JSON (default: per-target file in the data dir)
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long, value_delimiter = ',', default_value = "html,json")]
        format: Vec<String>,
        #[arg(long, default_value = "readyhai-report")]
        out: PathBuf,
        /// Native checks only (no containers)
        #[arg(long)]
        no_tools: bool,
        /// Host OS for ssh:// targets
        #[arg(long, value_enum)]
        os: Option<Os>,
        /// SSH private key for ssh:// targets (default: ssh-agent / ~/.ssh/config)
        #[arg(long)]
        key: Option<PathBuf>,
        /// adb serial or host:port of an attached Android device/emulator
        #[arg(long)]
        device: Option<String>,
        /// External plugin directory (plugins/<name>/plugin.toml)
        #[arg(long, env = "READYHAI_PLUGINS")]
        plugins: Option<PathBuf>,
    },
    /// Senior-QA run against a running app (+ optional repo): functional API/UI tests,
    /// auth/role matrix, perf baseline, release quality → QA test summary report
    Qa {
        /// App base URL (must be in scope.toml; writes only on env=nonprod hosts)
        url: String,
        /// Source repo of the app (adds repo/readiness/suite checks)
        #[arg(long)]
        repo: Option<PathBuf>,
        /// OpenAPI spec: file path or URL (default: discovered from the app)
        #[arg(long)]
        spec: Option<String>,
        /// roles.toml with test accounts (keep outside the repo, chmod 600)
        #[arg(long, env = "READYHAI_ROLES")]
        roles: Option<PathBuf>,
        /// UI journeys file (YAML/JSON steps)
        #[arg(long)]
        journeys: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "quick")]
        profile: Profile,
        #[arg(long, env = "READYHAI_SCOPE")]
        scope: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long, value_delimiter = ',', default_value = "html,json")]
        format: Vec<String>,
        #[arg(long, default_value = "readyhai-report")]
        out: PathBuf,
        #[arg(long)]
        no_tools: bool,
        #[arg(long, env = "READYHAI_PLUGINS")]
        plugins: Option<PathBuf>,
    },
    /// Offline bundle: export (connected machine) / import (air-gapped machine)
    Bundle {
        #[command(subcommand)]
        cmd: BundleCmd,
    },
    /// Show mode (offline / lan-llm), tools, DB age, LLM reachability, disk
    Doctor,
    /// Baseline management
    Baseline {
        #[command(subcommand)]
        cmd: BaselineCmd,
    },
    /// List checks
    Checks,
    /// Scanner images and databases
    Tools {
        #[command(subcommand)]
        cmd: ToolsCmd,
    },
    /// Autonomous Agentic AI QA run (Planner -> Explorer -> Triager -> Readiness Gate)
    Agent {
        target: String,
        /// Maximum autonomous exploration iterations
        #[arg(long, default_value_t = 5)]
        max_steps: usize,
    },
    /// REST API + job worker
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
    },
    /// Offline static dashboard of all runs (trend per target)
    Dashboard {
        #[arg(long, default_value = "readyhai-dashboard")]
        out: PathBuf,
    },
    /// MCP server over stdio (tools: scan, checks, run, findings) for agents like Claude Code
    Mcp,
    /// Health probe for the container HEALTHCHECK
    Ping {
        #[arg(long, default_value = "http://127.0.0.1:8080/health")]
        url: String,
    },
}

#[derive(Subcommand)]
enum BaselineCmd {
    /// Accept a run's findings as the baseline (only new findings gate afterwards)
    Accept {
        run: String,
        /// Write here instead of the per-target default (e.g. .readyhai/baseline.json to commit it)
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum BundleCmd {
    Export {
        #[arg(long, default_value = "readyhai-bundle.tar")]
        out: PathBuf,
        /// core (no zap/mobsf) | full
        #[arg(long, default_value = "core")]
        set: String,
        /// Optional GGUF model for fully air-gapped AI
        #[arg(long)]
        with_model: Option<PathBuf>,
    },
    Import { bundle: PathBuf },
}

#[derive(Subcommand)]
enum ToolsCmd {
    /// Pull pinned scanner images (--lock writes resolved digests)
    Pull {
        #[arg(long)]
        lock: Option<PathBuf>,
    },
    /// Refresh vulnerability DB + rule packs (the only networked step)
    Update,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("readyhai: error: {e:#}");
            ExitCode::from(3)
        }
    }
}

fn run() -> anyhow::Result<u8> {
    match Cli::parse().cmd {
        Cmd::Scan { target, profile, openapi, policy, scope, config, baseline, format, out, no_tools, os, key, device, plugins } => {
            let opts = ScanOpts {
                target,
                profile: Some(profile),
                openapi,
                policy,
                scope,
                config,
                baseline,
                no_tools,
                os,
                key,
                device,
                plugins,
                ..Default::default()
            };
            let id = engine::new_run_id();
            eprintln!("readyhai {} · run {id} · {} · profile {:?}", engine::VERSION, opts.target, profile);
            let run = engine::scan(&opts, &id)?;
            let files = report::write(&run, &out, &format)?;
            print_summary(&run);
            for f in files {
                eprintln!("report: {}", f.display());
            }
            Ok(run.verdict.exit_code() as u8)
        }
        Cmd::Qa { url, repo, spec, roles, journeys, profile, scope, policy, config, baseline, format, out, no_tools, plugins } => {
            let opts = ScanOpts {
                target: url,
                profile: Some(profile),
                openapi: spec,
                policy,
                scope,
                config,
                baseline,
                no_tools,
                plugins,
                repo,
                roles,
                journeys,
                qa: true,
                ..Default::default()
            };
            let id = engine::new_run_id();
            eprintln!("readyhai {} · QA run {id} · {} · profile {:?}", engine::VERSION, opts.target, profile);
            let run = engine::scan(&opts, &id)?;
            let files = report::write(&run, &out, &format)?;
            print_summary(&run);
            if let Some(q) = &run.qa {
                eprintln!("  QA recommendation: {:?} — {} defect(s), {} case(s)", q.recommendation, q.defects.len(), q.cases.len());
            }
            for f in files {
                eprintln!("report: {}", f.display());
            }
            Ok(run.verdict.exit_code() as u8)
        }
        Cmd::Bundle { cmd: BundleCmd::Export { out, set, with_model } } => {
            bundle::export(&out, &set, with_model.as_deref())?;
            Ok(0)
        }
        Cmd::Bundle { cmd: BundleCmd::Import { bundle: b } } => {
            bundle::import(&b)?;
            Ok(0)
        }
        Cmd::Doctor => {
            bundle::doctor()?;
            Ok(0)
        }
        Cmd::Baseline { cmd: BaselineCmd::Accept { run, out } } => {
            let r = engine::load_run(&run)?;
            let path = out.unwrap_or_else(|| engine::default_baseline_path(&r.target));
            let b = baseline::Baseline::from_run(&r, engine::now());
            b.save(&path)?;
            eprintln!("baseline: {} fingerprints → {}", b.fingerprints.len(), path.display());
            if r.qa.is_some() {
                match qa::perf::accept_baseline(&engine::target_key(&r.target)) {
                    Ok(()) => eprintln!("baseline: perf baseline promoted from the last run"),
                    Err(e) => eprintln!("baseline: no perf baseline to promote ({e:#})"),
                }
            }
            Ok(0)
        }
        Cmd::Checks => {
            let plugins = std::env::var("READYHAI_PLUGINS").ok().map(PathBuf::from);
            for c in checks::all(plugins.as_deref()) {
                let kinds: Vec<String> = c.kinds.iter().map(|k| format!("{k:?}").to_lowercase()).collect();
                println!(
                    "{:<26} {:<12} {:<9} {:<12} {}{}",
                    c.id,
                    kinds.join(","),
                    format!("{:?}", c.min_profile).to_lowercase(),
                    c.tool.as_deref().unwrap_or("native"),
                    c.title,
                    if c.intrusive { " [intrusive]" } else { "" }
                );
            }
            Ok(0)
        }
        Cmd::Tools { cmd: ToolsCmd::Pull { lock } } => {
            tools::tools_pull(lock.as_deref())?;
            Ok(0)
        }
        Cmd::Tools { cmd: ToolsCmd::Update } => {
            tools::tools_update(&tools::Docker::detect(&engine::data_dir()))?;
            Ok(0)
        }
        Cmd::Agent { target, max_steps: _ } => {
            let req = agent::AgentRunRequest {
                target: target.clone(),
                profile: "standard".to_string(),
                spec_url: None,
                custom_instructions: None,
                dry_run: false,
            };
            let run_id = engine::new_run_id();
            eprintln!("readyhai agent: starting autonomous loop for {target} (run {run_id})...");
            let report = agent::run_agentic_loop(&req, &run_id)?;
            let verdict = report.evidence_ledger.as_ref().map(|l| l.gate_verdict.as_str()).unwrap_or("UNKNOWN");
            let score = report.evidence_ledger.as_ref().map(|l| l.overall_readiness).unwrap_or(0);
            let summary = report.evidence_ledger.as_ref().map(|l| l.executive_summary.as_str()).unwrap_or("No summary");
            println!("
=== ReadyHai Agentic QA Report ===");
            println!("Run ID:       {}", report.id);
            println!("Target:       {}", report.target);
            println!("Model:        {} ({})", report.model, report.provider);
            println!("Gate Verdict: {}", verdict);
            println!("Readiness:    {}%", score);
            println!("Summary:      {}", summary);
            println!("Defects:      {}", report.triaged_defects.len());
            println!("Test Cases:   {}", report.executed_results.len());
            Ok(if verdict == "GO" { 0 } else { 1 })
        }
        Cmd::Serve { bind } => {
            serve::serve(&bind)?;
            Ok(0)
        }
        Cmd::Dashboard { out } => {
            let p = dashboard::generate(&out)?;
            eprintln!("dashboard: {}", p.display());
            Ok(0)
        }
        Cmd::Mcp => {
            mcp::serve_stdio()?;
            Ok(0)
        }
        Cmd::Ping { url } => {
            let ok = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()?
                .get(&url)
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            Ok(if ok { 0 } else { 1 })
        }
    }
}

fn print_summary(run: &Run) {
    eprintln!();
    for c in &run.checks {
        let mark = match c.status {
            CheckStatus::Passed => "ok  ",
            CheckStatus::Failed => "FAIL",
            CheckStatus::Partial(_) => "part",
            CheckStatus::Skipped(_) => "skip",
            CheckStatus::NotApplicable(_) => "n/a ",
            CheckStatus::Errored(_) => "ERR ",
        };
        let why = c.status.reason().map(|r| format!(" — {r}")).unwrap_or_default();
        eprintln!("  [{mark}] {:<26} {:>3} finding(s){why}", c.id, c.findings);
    }
    let new = run.findings.iter().filter(|f| f.status == FindingStatus::New).count();
    let sup = run.findings.iter().filter(|f| f.status == FindingStatus::Suppressed).count();
    eprintln!(
        "\n  findings: {} total · {new} new · {sup} suppressed · {} fixed since baseline",
        run.findings.len(),
        run.fixed
    );
    for n in &run.notes {
        eprintln!("  note: {n}");
    }
    eprintln!("\n  Ready hai? {:?}", run.verdict);
    for r in &run.reasons {
        eprintln!("   - {r}");
    }
    eprintln!();
}
