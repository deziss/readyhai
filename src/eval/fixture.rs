//! Fixture server lifecycle, process execution isolation, and test runner dispatch.

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::checks::{agent_defects, agent_stats, build_fixture_repo, change_checks, memory_checks};
use super::types::{Check, Observed, RunStats, SuiteSpec, Thresholds};

/// Serialises everything that mutates process environment.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Sets/unsets variables and restores the previous values on drop.
pub(crate) struct EnvGuard(Vec<(String, Option<OsString>)>);

impl EnvGuard {
    pub(crate) fn new() -> Self {
        EnvGuard(vec![])
    }
    pub(crate) fn set(&mut self, k: &str, v: impl AsRef<std::ffi::OsStr>) {
        self.0.push((k.to_string(), std::env::var_os(k)));
        // SAFETY: run_eval holds ENV_LOCK and starts no threads while the environment changes.
        unsafe { std::env::set_var(k, v) };
    }
    pub(crate) fn unset(&mut self, k: &str) {
        self.0.push((k.to_string(), std::env::var_os(k)));
        // SAFETY: see `set`.
        unsafe { std::env::remove_var(k) };
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.0.drain(..).rev() {
            // SAFETY: see `set`.
            unsafe {
                match v {
                    Some(v) => std::env::set_var(&k, v),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }
}

pub(crate) fn role_env(role: &str) -> String {
    let key: String = role
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("RH_{key}_TOKEN")
}

// ------------------------------------------------------------------ fixture server

/// A fixture server child process on a free loopback port. Killed on drop.
pub struct Fixture {
    child: Child,
    pub port: u16,
    log: PathBuf,
    /// Requests already in the log when the server became ready (our own readiness probe).
    baseline: usize,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn python() -> String {
    std::env::var("READYHAI_EVAL_PYTHON").unwrap_or_else(|_| "python3".into())
}

fn free_port() -> Result<u16> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("bind a free loopback port")?;
    Ok(l.local_addr()?.port())
}

fn count_lines(p: &Path) -> usize {
    std::fs::read_to_string(p)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

impl Fixture {
    /// Start the server as `script PORT LOGFILE [args...]`.
    pub fn start(script: &Path, log: &Path, args: &[String]) -> Result<Fixture> {
        if !script.is_file() {
            bail!("fixture server {} not found", script.display());
        }
        let port = free_port()?;
        std::fs::write(log, b"")?;
        let child = Command::new(python())
            .arg(script)
            .arg(port.to_string())
            .arg(log)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| {
                format!(
                    "start {} (python3 missing? set READYHAI_EVAL_PYTHON)",
                    script.display()
                )
            })?;
        let mut f = Fixture {
            child,
            port,
            log: log.to_path_buf(),
            baseline: 0,
        };
        f.wait_ready()?;
        f.baseline = count_lines(&f.log);
        Ok(f)
    }

    fn wait_ready(&mut self) -> Result<()> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(Some(st)) = self.child.try_wait() {
                bail!("fixture server exited at start ({st})");
            }
            if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                if s.write_all(b"GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                    .is_ok()
                {
                    let mut buf = String::new();
                    let _ = s.read_to_string(&mut buf);
                    if buf.starts_with("HTTP/1.") && buf.contains(" 200 ") {
                        return Ok(());
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!("fixture server did not answer /health within 15s")
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Requests the target saw since it was ready.
    pub fn requests(&self) -> usize {
        count_lines(&self.log).saturating_sub(self.baseline)
    }
}

// ------------------------------------------------------------------ executors

pub(crate) struct Outcome {
    pub(crate) verdict: String,
    pub(crate) observed: Vec<Observed>,
    /// Run-level checks beyond recall and false positives (`[change]`).
    pub(crate) checks: Vec<Check>,
    /// Evidence quality of an agent run (cases by status, confidence, blockers).
    pub(crate) stats: RunStats,
}

pub(crate) fn rel(root: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

fn parse_profile(s: &str) -> Result<crate::model::Profile> {
    use crate::model::Profile;
    Ok(match s.to_ascii_lowercase().as_str() {
        "quick" => Profile::Quick,
        "standard" => Profile::Standard,
        "deep" => Profile::Deep,
        other => bail!("unknown profile '{other}' (quick|standard|deep)"),
    })
}

pub(crate) fn exec_qa(spec: &SuiteSpec, root: &Path, base_url: &str) -> Result<Outcome> {
    let t = &spec.target;
    let opts = crate::engine::ScanOpts {
        target: base_url.to_string(),
        profile: Some(parse_profile(&t.profile)?),
        openapi: t.spec.as_ref().map(|s| rel(root, s).display().to_string()),
        roles: t.roles.as_ref().map(|r| rel(root, r)),
        no_tools: true,
        qa: true,
        ..Default::default()
    };
    let id = crate::engine::new_run_id();
    let run = crate::engine::scan(&opts, &id)?;
    let qa = run.qa.as_ref().context("the run produced no QA report")?;
    let observed = qa
        .defects
        .iter()
        .filter(|d| d.status != crate::model::FindingStatus::Suppressed)
        .map(|d| Observed {
            rules: vec![d.rule.clone()],
            component: d.component.clone(),
            title: d.title.clone(),
        })
        .collect();
    Ok(Outcome {
        verdict: format!("{:?}/{:?}", qa.recommendation, run.verdict),
        observed,
        checks: vec![],
        stats: RunStats::default(),
    })
}

pub(crate) fn exec_repo(spec: &SuiteSpec, root: &Path) -> Result<Outcome> {
    let t = &spec.target;
    let path = rel(root, t.path.as_deref().unwrap_or("."));
    let opts = crate::engine::ScanOpts {
        target: path.display().to_string(),
        profile: Some(parse_profile(&t.profile)?),
        no_tools: true,
        qa: true,
        ..Default::default()
    };
    let id = crate::engine::new_run_id();
    let run = crate::engine::scan(&opts, &id)?;
    let observed = run
        .findings
        .iter()
        .filter(|f| f.status != crate::model::FindingStatus::Suppressed)
        .map(|f| Observed {
            rules: vec![f.rule.clone()],
            component: f.location.clone(),
            title: f.title.clone(),
        })
        .collect();
    Ok(Outcome {
        verdict: format!("{:?}", run.verdict),
        observed,
        checks: vec![],
        stats: RunStats::default(),
    })
}

/// One agent run against the fixture, as the suite file describes it.
fn agent_run_once(
    spec: &SuiteSpec,
    root: &Path,
    work: &Path,
    base_url: &str,
    limits: &Thresholds,
) -> Result<crate::agent::AgentRunReport> {
    use crate::agent::{self, Credentials, LlmMode, RunBudget, RunOptions};
    let t = &spec.target;
    let max_steps = t.max_steps.unwrap_or(50);
    // the source repo of a change-aware run: built fresh for every run
    let repo = match &t.repo {
        Some(r) => {
            let dest = work.join("src-repo");
            build_fixture_repo(root, &r.commits, &dest)?;
            Some(dest.display().to_string())
        }
        None => None,
    };
    // serde defaults fill every field a newer AgentRunRequest may have.
    let req: agent::AgentRunRequest = serde_json::from_value(serde_json::json!({
        "target": base_url,
        "profile": t.profile,
        "spec_url": t.spec.as_ref().map(|s| rel(root, s).display().to_string()),
        "dry_run": false,
        "thinking": false,
        "repo": repo,
        "diff_base": repo
            .as_ref()
            .filter(|_| {
                spec.target
                    .repo
                    .as_ref()
                    .is_some_and(|r| r.diff_base.unwrap_or(r.commits.len() > 1))
            })
            .map(|_| "base"),
    }))?;
    let mut budget = RunBudget::default().with_max_steps(max_steps);
    if let Some(r) = limits.max_requests {
        budget = budget.with_max_requests(r);
    }
    if let Some(s) = limits.max_seconds {
        budget = budget.with_max_wall(Duration::from_secs_f64(s));
    }
    let mut creds = Credentials::none();
    for (role, token) in &t.tokens {
        creds = creds.with(role, token);
    }
    let mut ro = RunOptions::default();
    ro.budget = budget;
    ro.credentials = creds;
    ro.llm = LlmMode::Off;
    ro.lookup_requester_ip = false;

    let id = crate::engine::new_run_id();
    let rep = agent::run_agentic_loop_with(&req, &id, ro)?;
    if let Some(e) = &rep.error {
        bail!("agent run {}: {e}", rep.status);
    }
    Ok(rep)
}

pub(crate) fn exec_agent(
    spec: &SuiteSpec,
    root: &Path,
    work: &Path,
    base_url: &str,
    limits: &Thresholds,
) -> Result<Outcome> {
    let n = spec.memory.as_ref().map_or(1, |m| m.runs);
    let mut reports = vec![];
    for i in 1..=n {
        if n > 1 {
            eprintln!(
                "eval:   {} agent run {i}/{n} in the same data directory",
                spec.name
            );
        }
        reports.push(agent_run_once(spec, root, work, base_url, limits)?);
    }
    let rep = reports.last().expect("at least one run");
    let observed = agent_defects(rep).into_iter().map(|(o, _)| o).collect();
    let verdict = rep
        .evidence_ledger
        .as_ref()
        .map(|l| l.gate_verdict.clone())
        .unwrap_or_else(|| "UNKNOWN".into());
    let mut checks = spec
        .change
        .as_ref()
        .map(|c| change_checks(c, rep))
        .unwrap_or_default();
    if spec.memory.is_some() {
        checks.extend(memory_checks(spec, &reports));
    }
    if spec
        .target
        .repo
        .as_ref()
        .is_some_and(|r| r.require_source_context)
    {
        let linked: Vec<String> = rep
            .triaged_defects
            .iter()
            .filter_map(|d| {
                d.source_context
                    .as_deref()
                    .filter(|s| s.contains(':'))
                    .map(|s| format!("{} ({s})", d.component))
            })
            .collect();
        checks.push(Check {
            name: "whitebox source linkage".into(),
            ok: !linked.is_empty(),
            detail: if linked.is_empty() {
                "expected at least one defect with file:line source_context".into()
            } else {
                format!("linked {}", linked.join(", "))
            },
        });
    }
    Ok(Outcome {
        verdict,
        observed,
        checks,
        stats: agent_stats(rep),
    })
}
