//! Core scan orchestrator pipeline.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use anyhow::{Context, Result, bail};

use super::deadline::{DeadlineGuard, deadline_passed};
use super::git::{clone_url, git_clone, git_timeout};
use super::storage::{data_dir, default_baseline_path, now, run_dir, today, write_atomic};
use super::target_parser::parse_target;
use super::types::{ScanOpts, VERSION};
use crate::baseline::{self, Baseline};
use crate::checks;
use crate::config::TargetConfig;
use crate::ctx::Ctx;
use crate::facts::Facts;
use crate::model::*;
use crate::policy::{self, Policy};
use crate::scope::{self, Scope};
use crate::snapshot;
use crate::tools::Docker;

/// Status for a check that returned an error. Tool output over the read cap is incomplete
/// coverage (`Partial`, a warning): not a pass, and not a crash of the check.
pub fn error_status(e: &anyhow::Error) -> CheckStatus {
    if crate::tools::is_oversize(e) {
        CheckStatus::Partial(format!("{e:#}"))
    } else {
        CheckStatus::Errored(format!("{e:#}"))
    }
}

pub fn scan(opts: &ScanOpts, run_id: &str) -> Result<Run> {
    let started = now();
    let _deadline = DeadlineGuard::new(run_id, opts.deadline);
    if opts.server {
        crate::mcp::precheck(opts)?;
    }
    let profile = opts.profile.unwrap_or(Profile::Quick);
    let mut target = parse_target(&opts.target, opts.openapi.clone())?;
    if let Some(h) = target.host.as_mut() {
        h.os = opts.os.unwrap_or(Os::Linux);
        h.key = opts.key.clone();
        if opts.server && h.key.is_none() && std::env::var("SSH_AUTH_SOCK").is_err() {
            bail!("server mode: host targets need ssh-agent (SSH_AUTH_SOCK)");
        }
    }
    if target.kind == TargetKind::Android {
        if opts.server
            && !opts.allowed_roots.iter().any(|r| {
                r.canonicalize()
                    .map(|r| target.apk.as_ref().is_some_and(|a| a.starts_with(r)))
                    .unwrap_or(false)
            })
        {
            bail!("apk is outside READYHAI_ALLOWED_ROOTS");
        }
        target.device = opts.device.clone();
    }
    let dir = run_dir(run_id);
    let src = dir.join("src");
    std::fs::create_dir_all(dir.join("out"))?;
    std::fs::create_dir_all(dir.join("artifacts"))?;
    let docker = Docker::detect(&data_dir());
    let mut notes = vec![];

    if opts.server
        && let Some(p) = &target.path
        && !opts
            .allowed_roots
            .iter()
            .any(|r| r.canonicalize().map(|r| p.starts_with(r)).unwrap_or(false))
    {
        bail!("path is outside READYHAI_ALLOWED_ROOTS");
    }

    // Web scope. A scope file that is configured but unusable aborts the run: never "no scope".
    let scope = match &opts.scope {
        Some(p) => {
            crate::scope::set_active(p);
            Some(Scope::load(p)?)
        }
        None => crate::scope::from_env()?,
    };
    let mut nonprod = false;
    if let Some(url) = &target.url {
        nonprod = scope::check(url, scope.as_ref())?;
    }

    let mut cfg = match &opts.config {
        Some(p) => TargetConfig::load(p)?.unwrap_or_default(),
        None => TargetConfig::default(),
    };
    let mut snap = None;
    // Composite QA run: web target + optional repo.
    if let Some(r) = &opts.repo {
        if target.kind != TargetKind::Web {
            bail!("--repo is only valid with a web target (readyhai qa <url> --repo DIR)");
        }
        let r = r
            .canonicalize()
            .with_context(|| format!("repo {}", r.display()))?;
        if opts.server
            && !opts
                .allowed_roots
                .iter()
                .any(|a| a.canonicalize().map(|a| r.starts_with(a)).unwrap_or(false))
        {
            bail!("repo is outside READYHAI_ALLOWED_ROOTS");
        }
        target.path = Some(r);
    }
    let snapshot_repo =
        target.kind == TargetKind::Repo || target.path.is_some() && target.kind == TargetKind::Web;
    match target.kind {
        _ if snapshot_repo => {
            let source = match &target.path {
                Some(p) => p.clone(),
                None => {
                    let url = clone_url(&target.raw)?;
                    let clone = dir.join("clone");
                    git_clone(&url, &clone, git_timeout(run_id))?;
                    target.path = Some(clone.clone());
                    clone
                }
            };
            if opts.config.is_none()
                && let Some(c) = TargetConfig::load(&source.join("readyhai.toml"))?
            {
                cfg = c;
                notes.push("using readyhai.toml from target".into());
                if !cfg.suppress.is_empty() {
                    notes.push(format!(
                        "{} suppression(s) come from the target's own readyhai.toml — review them",
                        cfg.suppress.len()
                    ));
                }
                // An untrusted repo must not grant its own tests network access in server/MCP mode.
                if opts.server
                    && let Some(t) = cfg.test.as_mut()
                    && t.network
                {
                    t.network = false;
                    notes.push(
                        "server mode: ignored network=true from the target's readyhai.toml [test]"
                            .into(),
                    );
                }
            }
            let s = snapshot::take(&source, &src, &cfg.snapshot.deny, &cfg.snapshot.skip_dirs)?;
            if !s.denied.is_empty() {
                notes.push(format!(
                    "{} secret-bearing file(s) withheld from all tools (never read)",
                    s.denied.len()
                ));
            }
            if !s.dropped_symlinks.is_empty() {
                notes.push(format!(
                    "{} symlink(s) dropped from snapshot",
                    s.dropped_symlinks.len()
                ));
            }
            if dir.join("clone").exists() {
                let _ = std::fs::remove_dir_all(dir.join("clone"));
            }
            snap = Some(s);
        }
        TargetKind::Image => {
            std::fs::create_dir_all(&src)?;
            snapshot::set_mode(&src, 0o755);
            if docker.available && !opts.no_tools {
                docker.export_image(
                    run_id,
                    target.image.as_deref().unwrap_or_default(),
                    &src.join("image.tar"),
                )?;
                snapshot::set_mode(&src.join("image.tar"), 0o644);
            }
        }
        _ => {}
    }
    for w in crate::tools::pin_warnings() {
        notes.push(w);
    }

    let facts = snap
        .as_ref()
        .map(crate::rules::detect_facts)
        .unwrap_or_else(Facts::default);
    let has_repo = snap.is_some();
    let qa = if opts.qa {
        let roles = match &opts.roles {
            Some(p) => crate::qa::roles::Roles::load(p)?,
            None => Default::default(),
        };
        notes.extend(roles.warnings.iter().cloned());
        if !nonprod {
            notes.push("QA: host is tagged env = \"prod\" in scope.toml — read-only testing (no writes, forms, load or fault injection)".into());
        }
        Some(crate::qa::QaCtx::new(
            roles,
            opts.openapi.clone(),
            opts.journeys.clone(),
            nonprod,
        ))
    } else {
        None
    };
    let ctx = Ctx {
        run_id: run_id.into(),
        target: target.clone(),
        profile,
        run_dir: dir.clone(),
        snapshot: snap,
        facts,
        docker,
        cfg,
        error_lines: Default::default(),
        nonprod,
        qa,
    };

    let mut results = vec![];
    let mut findings: Vec<Finding> = vec![];
    // Operator settings: tri-state toggles per check / integration category.
    // Re-read every run so edits apply without restart. Never weakens a gate:
    // it can only ADD skips (or lift settings-added skips), never bypass
    // profile/kind/docker/intrusive-nonprod checks.
    let settings_path = opts
        .settings
        .clone()
        .or_else(crate::settings::settings_path_from_env);
    let settings = crate::settings::Settings::load(settings_path.as_deref())?;
    if let Some(p) = &settings_path
        && settings.override_count() > 0
    {
        notes.push(format!(
            "settings: {} override(s) from {}",
            settings.override_count(),
            p.display()
        ));
    }
    // On-the-go setup: pre-provision plugin packs this scan would select
    // (digest-pinned image pull + cache dir seeding) so the first plugin check
    // doesn't stall on a big pull inside its own budget. Best-effort notes only.
    if !opts.no_tools
        && ctx.docker.available
        && let Some(pdir) = &opts.plugins
    {
        notes.extend(crate::tools::ensure_packs(
            pdir,
            &settings,
            target.kind,
            has_repo,
            profile,
            crate::bundle::offline(),
            &crate::tools::setup_pull,
            &|r| crate::tools::local_image_id(r).is_some(),
            &|| crate::tools::setup_seed_cache(&ctx.docker.cache_dir),
        ));
    }
    for c in checks::all(opts.plugins.as_deref()) {
        let kind_ok =
            c.kinds.contains(&target.kind) || has_repo && c.kinds.contains(&TargetKind::Repo);
        if !kind_ok || profile < c.min_profile || c.qa && ctx.qa.is_none() {
            continue;
        }
        let t0 = Instant::now();
        let status_findings: (CheckStatus, Vec<Finding>) = if let Some(reason) = settings.skip(
            &c.id,
            c.tool.is_some(),
            c.id.starts_with("plugin."),
            c.intrusive,
        ) {
            (CheckStatus::Skipped(reason), vec![])
        } else if c.tool.is_some() && opts.no_tools {
            (CheckStatus::Skipped("--no-tools".into()), vec![])
        } else if c.tool.is_some() && !ctx.docker.available {
            (CheckStatus::Skipped("docker not available".into()), vec![])
        } else if deadline_passed(run_id) {
            (
                CheckStatus::Skipped("run wall-clock deadline exceeded".into()),
                vec![],
            )
        } else if c.intrusive && (profile != Profile::Deep || !nonprod) {
            (
                CheckStatus::Skipped(
                    "intrusive: needs --profile deep and a nonprod host (any host not marked env = \"prod\" in scope.toml)".into(),
                ),
                vec![],
            )
        } else {
            eprintln!("  · {} …", c.id);
            match catch_unwind(AssertUnwindSafe(|| (c.run)(&ctx))) {
                Ok(Ok(out)) => {
                    let st = out.status.unwrap_or(if out.findings.is_empty() {
                        CheckStatus::Passed
                    } else {
                        CheckStatus::Failed
                    });
                    (st, out.findings)
                }
                Ok(Err(e)) => (error_status(&e), vec![]),
                Err(_) => (CheckStatus::Errored("check panicked".into()), vec![]),
            }
        };
        let (status, mut fs) = status_findings;
        for f in &mut fs {
            if f.check.is_empty() {
                f.check = c.id.clone();
            }
            f.finalize();
        }
        results.push(CheckResult {
            id: c.id.clone(),
            title: c.title.clone(),
            tool: c.tool.clone(),
            status,
            findings: fs.len(),
            duration_ms: t0.elapsed().as_millis(),
        });
        findings.extend(fs);
    }
    ctx.docker.reap(run_id);
    if deadline_passed(run_id) {
        bail!("run exceeded its wall-clock deadline; partial results discarded (no verdict)");
    }
    let errors = crate::logs::cluster(
        &ctx.error_lines
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default(),
    );

    // Dedup by fingerprint, then gate.
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.fingerprint.clone()));
    notes.extend(policy::apply_suppressions(
        &mut findings,
        &ctx.cfg.suppress,
        &today(),
    ));
    let bpath = opts
        .baseline
        .clone()
        .unwrap_or_else(|| default_baseline_path(&target));
    let base = Baseline::load(&bpath)?;
    if base.is_none() {
        notes.push("no baseline yet: every finding counts as new (accept one with `readyhai baseline accept <run>`)".into());
    }
    let fixed = baseline::apply(&mut findings, base.as_ref());
    findings.sort_by(|a, b| {
        (a.status as u8)
            .cmp(&(b.status as u8))
            .then(b.severity.cmp(&a.severity))
            .then(a.rule.cmp(&b.rule))
    });
    // Global vulnerability database: remember this run's actionable findings across targets
    // (`readyhai vulns`). Advisory on purpose — the hook cannot fail, and its outcome is a
    // note in the report like any other side effect. Suppressions are already applied, so a
    // suppressed finding is not recorded.
    if let Some(note) = crate::vulndb::record_run(&settings, &target.raw, &findings) {
        notes.push(note);
    }
    let pol = Policy::load(opts.policy.as_deref())?;
    let (verdict, reasons) = policy::verdict(&pol, &findings, &results);

    let run = Run {
        id: run_id.into(),
        version: VERSION.into(),
        target,
        profile,
        started,
        finished: now(),
        verdict,
        reasons,
        categories: policy::summarize(&findings),
        checks: results,
        findings,
        fixed,
        notes,
        errors,
        qa: None,
    };
    let mut run = run;
    if let Some(q) = &ctx.qa {
        let env_cfg = crate::llm::LlmConfig::from_env();
        let configured = env_cfg
            .as_ref()
            .ok()
            .filter(|c| c.base_url().is_ok()) // no base URL = not configured
            .cloned();
        // Offline = no internet/registries. A LAN LLM is still allowed; cloud providers are
        // already refused unless READYHAI_LLM_ALLOW_CLOUD is set.
        let cfg = configured.clone().filter(crate::llm::probe);
        let mode = match (crate::bundle::offline(), cfg.is_some()) {
            (true, true) => "offline+lan-llm",
            (true, false) => "offline",
            (false, true) => "lan-llm",
            (false, false) => "deterministic",
        };
        let mut report = crate::qa::build_report(q, &run, mode);
        if configured.is_some() && cfg.is_none() {
            report.notes.push(
                "LLM configured but unreachable (2s probe): report is deterministic-only".into(),
            );
        }
        // a requested LLM that the config refuses (cloud provider or public URL without
        // READYHAI_LLM_ALLOW_CLOUD, bad URL, unknown provider) must not vanish silently
        if let Err(e) = &env_cfg
            && crate::llm::env_requested()
        {
            report
                .notes
                .push(format!("LLM not used: {e}; report is deterministic-only"));
        }
        if let Some(c) = &cfg {
            crate::qa::ai::enrich(&mut report, &run, c);
        }
        run.qa = Some(report);
    }
    write_atomic(
        &dir.join("run.json"),
        serde_json::to_string_pretty(&run)?.as_bytes(),
    )?;
    let _ = crate::report::write(
        &run,
        &dir.join("report"),
        &["html".into(), "json".into(), "sarif".into(), "junit".into()],
    );
    crate::dashboard::append_index(&run);
    Ok(run)
}
