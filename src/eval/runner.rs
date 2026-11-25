//! Evaluation runner orchestrator: runs suites in loop, manages temp directories, and evaluates passes.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::time::Instant;

use super::fixture::{ENV_LOCK, EnvGuard, Fixture, exec_agent, exec_qa, exec_repo, rel, role_env};
use super::parser::{load_suites, resolve_root};
use super::report::{pct, render_markdown};
use super::scoring::{score_run, summarize_suite};
use super::types::{EvalOpts, EvalSummary, RunScore, SuiteKind, SuiteResult, SuiteSpec};

const SCOPE_TOML: &str = "# Written by `readyhai eval`: the fixture runs on loopback and may be attacked.\n\
[[hosts]]\nhost = \"127.0.0.1\"\nenv = \"nonprod\"\n\n\
[[hosts]]\nhost = \"localhost\"\nenv = \"nonprod\"\n";

fn run_suite(spec: &SuiteSpec, k: usize, root: &Path, work: &Path, scope: &Path) -> SuiteResult {
    let mut runs = vec![];
    let mut error = None;
    for i in 1..=k {
        eprintln!("eval: {} run {i}/{k} ({:?})", spec.name, spec.kind);
        match run_once(spec, i, root, work, scope) {
            Ok(r) => {
                eprintln!(
                    "eval:   {} recall {:.2} · precision {:.2} · {} false positive(s) · inconclusive {} · {} request(s) · {:.1}s · {}",
                    spec.name,
                    r.recall,
                    r.precision,
                    r.false_positives.len(),
                    pct(r.inconclusive_rate),
                    r.requests,
                    r.seconds,
                    r.verdict
                );
                runs.push(r);
            }
            Err(e) => {
                eprintln!("eval:   {} run {i} failed: {e:#}", spec.name);
                error = Some(format!("run {i}: {e:#}"));
                break;
            }
        }
    }
    summarize_suite(spec, k, runs, error)
}

fn run_once(
    spec: &SuiteSpec,
    i: usize,
    root: &Path,
    work: &Path,
    scope: &Path,
) -> Result<RunScore> {
    let dir = work.join(format!("{}-{i}", spec.name));
    let data = dir.join("data");
    std::fs::create_dir_all(&data)?;

    let mut env = EnvGuard::new();
    env.set("READYHAI_DATA", &data);
    env.set("READYHAI_SCOPE", scope);
    env.set("READYHAI_OFFLINE", "1");
    for k in [
        "READYHAI_LLM_PROVIDER",
        "READYHAI_LLM_MODEL",
        "READYHAI_LLM_MODELS",
        "READYHAI_LLM_URL",
        "READYHAI_LLM_API_KEY",
        "READYHAI_LLM_ALLOW_CLOUD",
        "READYHAI_VLLM_URL",
        "READYHAI_PLUGINS",
        "READYHAI_ROLES",
        "READYHAI_ALLOWED_ROOTS",
        "READYHAI_AGENT_MAX_STEPS",
        "READYHAI_AGENT_MAX_REQUESTS",
        "READYHAI_AGENT_MAX_SECONDS",
        "READYHAI_AGENT_RATE_PER_HOST",
        "READYHAI_AGENT_MAX_LLM_CALLS",
        "READYHAI_AGENT_WORKERS",
        "READYHAI_AGENT_MEMORY",
    ] {
        env.unset(k);
    }
    for (role, token) in &spec.target.tokens {
        env.set(&role_env(role), token);
    }

    let fixture = match &spec.target.server {
        Some(s) => Some(Fixture::start(
            &rel(root, s),
            &dir.join("requests.log"),
            &spec.target.server_args,
        )?),
        None => None,
    };
    let url = fixture.as_ref().map(Fixture::url).unwrap_or_default();

    let started = Instant::now();
    let outcome = match spec.kind {
        SuiteKind::Qa => exec_qa(spec, root, &url)?,
        SuiteKind::Agent => exec_agent(spec, root, &dir, &url, &spec.thresholds)?,
        SuiteKind::Repo => exec_repo(spec, root)?,
    };
    let seconds = started.elapsed().as_secs_f64();
    let requests = fixture.as_ref().map_or(0, Fixture::requests);
    let mut score = score_run(
        spec,
        i,
        &outcome.verdict,
        &outcome.observed,
        requests,
        seconds,
    );
    score.checks = outcome.checks;
    Ok(score.with_stats(outcome.stats))
}

/// Run the selected suites `k` times each and write `eval-report.json` / `eval-report.md`.
pub fn run_eval(opts: EvalOpts) -> Result<EvalSummary> {
    if opts.k == 0 {
        bail!("k must be at least 1");
    }
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = resolve_root(&opts)?;
    let suites = load_suites(&root, &opts)?;

    let work = std::env::temp_dir().join(format!(
        "readyhai-eval-{}-{}",
        std::process::id(),
        crate::engine::new_run_id()
    ));
    std::fs::create_dir_all(&work)?;
    let scope = work.join("scope.toml");
    std::fs::write(&scope, SCOPE_TOML)?;

    let started = crate::engine::now();
    let results: Vec<SuiteResult> = suites
        .iter()
        .map(|s| run_suite(s, opts.k, &root, &work, &scope))
        .collect();
    if std::env::var_os("READYHAI_EVAL_KEEP").is_some() {
        eprintln!("eval: kept run data in {}", work.display());
    } else {
        let _ = std::fs::remove_dir_all(&work);
    }

    let mut summary = EvalSummary {
        version: crate::engine::VERSION.to_string(),
        started,
        k: opts.k,
        passed: results.iter().all(|s| s.passed),
        suites: results,
        report_json: opts.out.join("eval-report.json"),
        report_md: opts.out.join("eval-report.md"),
    };
    std::fs::create_dir_all(&opts.out).with_context(|| format!("create {}", opts.out.display()))?;
    std::fs::write(&summary.report_json, serde_json::to_vec_pretty(&summary)?)?;
    let md = render_markdown(&summary);
    std::fs::write(&summary.report_md, &md)?;
    summary.report_json = summary
        .report_json
        .canonicalize()
        .unwrap_or(summary.report_json);
    summary.report_md = summary
        .report_md
        .canonicalize()
        .unwrap_or(summary.report_md);

    eprintln!("\n{md}");
    eprintln!("eval: report: {}", summary.report_json.display());
    eprintln!("eval: report: {}", summary.report_md.display());
    Ok(summary)
}
