use super::docker::{DOCKER_QUICK, read_out, rewrite_scrubbed};
use super::parsers::{
    first_line, parse_checkov, parse_dockle, parse_gitleaks, parse_grep_findings, parse_grype,
    parse_hadolint, parse_image_inspect, scrub_checkov, scrub_gitleaks, scrub_semgrep,
};
use super::pinning::{add_warning, missing_image};
use super::process::run_capped;
use super::sarif_junit::parse_junit;
use super::types::{
    JunitCase, OutTooLarge, TOOL_STDOUT_CAP, ToolSpec, gate, is_oversize, out_err, partial,
    tool_failed,
};
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};
use anyhow::{Result, bail};
use std::path::Path;
use std::process::Command;

/// Age in days of the grype DB under `<cache>/grype` (mtime of `vulnerability.db` / `metadata.json`,
/// falling back to the newest file in the tree).
pub fn db_age_days(cache: &Path) -> Option<u64> {
    let files: Vec<_> = walkdir::WalkDir::new(cache.join("grype"))
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    let key = |n: &str| {
        files
            .iter()
            .filter(|e| e.file_name().to_str() == Some(n))
            .filter_map(|e| e.metadata().ok()?.modified().ok())
            .max()
    };
    let newest = key("vulnerability.db")
        .or_else(|| key("metadata.json"))
        .or_else(|| {
            files
                .iter()
                .filter_map(|e| e.metadata().ok()?.modified().ok())
                .max()
        })?;
    Some(
        std::time::SystemTime::now()
            .duration_since(newest)
            .ok()?
            .as_secs()
            / 86400,
    )
}

fn has_rules_in(cache: &Path, dir: &str) -> bool {
    std::fs::read_dir(cache.join(dir))
        .map(|d| {
            d.filter_map(|e| e.ok()).any(|e| {
                let p = e.path();
                matches!(p.extension().and_then(|x| x.to_str()), Some("yml" | "yaml"))
            })
        })
        .unwrap_or(false)
}

fn has_rules(cache: &Path) -> bool {
    has_rules_in(cache, "semgrep")
}

fn run_rule_scanner(
    ctx: &Ctx,
    check_id: &str,
    tool: &str,
    entrypoint: Option<&str>,
    out_file: &str,
    extra_args: &[&str],
    rules_dir: &str,
) -> Result<CheckOutput> {
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    if let Some(o) = missing_image(tool) {
        return Ok(o);
    }
    if !has_rules(&ctx.docker.cache_dir) && !has_rules_in(&ctx.docker.cache_dir, "opengrep") {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "rules missing: run `readyhai tools update`".into(),
        )));
    }
    let out_arg = format!("/out/{out_file}");
    let mut args = vec!["scan", "--config", rules_dir];
    args.extend_from_slice(extra_args);
    args.extend_from_slice(&[
        "--metrics=off",
        "--disable-version-check",
        "--json",
        "-o",
        &out_arg,
        "/src",
    ]);
    let mut spec = ToolSpec::new(tool, &args);
    spec.entrypoint = entrypoint.map(str::to_string);
    spec.memory = "3g".into();
    spec.timeout_secs = 900;
    let r = ctx.docker.run(ctx, &spec)?;
    let f = match read_out(ctx, out_file) {
        Ok(t) => parse_grep_findings(&t, check_id),
        Err(e) => Err(out_err(e, || tool_failed(tool, &r))),
    };
    rewrite_scrubbed(ctx, out_file, scrub_semgrep);
    Ok(CheckOutput::findings(f?))
}

fn repo_like() -> Vec<TargetKind> {
    vec![TargetKind::Repo]
}

pub fn checks() -> Vec<Check> {
    let mut v = vec![];

    v.push(
        Check::new(
            "tool.gitleaks",
            "Secret scan (gitleaks)",
            &repo_like(),
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("gitleaks") {
                    return Ok(o);
                }
                let mut spec = ToolSpec::new(
                    "gitleaks",
                    &[
                        "dir",
                        "/src",
                        "--redact",
                        "--no-banner",
                        "--exit-code",
                        "0",
                        "--report-format",
                        "json",
                        "--report-path",
                        "/out/gitleaks.json",
                    ],
                );
                spec.timeout_secs = 300;
                let r = ctx.docker.run(ctx, &spec)?;
                let f = match read_out(ctx, "gitleaks.json") {
                    Ok(t) => parse_gitleaks(&t),
                    // Never "no findings" for output that was too big to read.
                    Err(e) if is_oversize(&e) => Err(e),
                    Err(_) if r.exit_code != 0 => Err(tool_failed("gitleaks", &r)),
                    Err(_) => Ok(vec![]),
                };
                rewrite_scrubbed(ctx, "gitleaks.json", scrub_gitleaks);
                Ok(CheckOutput::findings(f?))
            },
        )
        .tool("gitleaks"),
    );

    v.push(
        Check::new(
            "tool.sbom_cve",
            "SBOM + known vulnerabilities (syft + grype)",
            &[TargetKind::Repo, TargetKind::Image],
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                let cache = &ctx.docker.cache_dir;
                for t in ["syft", "grype"] {
                    if let Some(o) = missing_image(t) {
                        return Ok(o);
                    }
                }
                if !cache.join("grype").is_dir() {
                    return Ok(CheckOutput::status(CheckStatus::Skipped(
                        "vuln DB missing: run `readyhai tools update`".into(),
                    )));
                }
                let source = if ctx.target.kind == TargetKind::Image {
                    "docker-archive:/src/image.tar"
                } else {
                    "dir:/src"
                };
                let mut syft = ToolSpec::new(
                    "syft",
                    &["scan", source, "-o", "cyclonedx-json=/out/sbom.cdx.json"],
                );
                syft.env
                    .push(("SYFT_CHECK_FOR_APP_UPDATE".into(), "false".into()));
                let r = ctx.docker.run(ctx, &syft)?;
                if r.exit_code != 0 {
                    return Err(tool_failed("syft", &r));
                }
                let mut grype = ToolSpec::new(
                    "grype",
                    &[
                        "sbom:/out/sbom.cdx.json",
                        "-o",
                        "json",
                        "--file",
                        "/out/grype.json",
                    ],
                );
                grype.env = vec![
                    ("GRYPE_DB_CACHE_DIR".into(), "/cache/grype".into()),
                    ("GRYPE_DB_AUTO_UPDATE".into(), "false".into()),
                    ("GRYPE_CHECK_FOR_APP_UPDATE".into(), "false".into()),
                ];
                if crate::bundle::offline() {
                    // ReadyHai does its own age check below; the offline DB is legitimately old.
                    grype
                        .env
                        .push(("GRYPE_DB_VALIDATE_AGE".into(), "false".into()));
                }
                let r = ctx.docker.run(ctx, &grype)?;
                if r.exit_code != 0 {
                    return Err(tool_failed("grype", &r));
                }
                let findings = parse_grype(&read_out(ctx, "grype.json")?)?;
                let mut notes = vec![];
                if ctx.facts.unpinned_deps > 0 {
                    notes.push(format!(
                        "{} of {} deps unpinned; CVE coverage incomplete — scan the built image",
                        ctx.facts.unpinned_deps, ctx.facts.total_deps
                    ));
                }
                if let Some(d) = db_age_days(cache) {
                    if d > 7 {
                        let how = if crate::bundle::offline() {
                            "import a fresh bundle"
                        } else {
                            "run `readyhai tools update`"
                        };
                        notes.push(format!("vuln DB is {d} days old; {how}"));
                    }
                    if d > 30 {
                        add_warning(format!("vuln DB is {d} days old — CVE coverage is stale"));
                    }
                }
                Ok(partial(notes, findings))
            },
        )
        .tool("grype"),
    );

    v.push(
        Check::new(
            "tool.semgrep",
            "Static analysis (semgrep)",
            &repo_like(),
            Profile::Quick,
            |ctx| {
                run_rule_scanner(
                    ctx,
                    "tool.semgrep",
                    "semgrep",
                    Some("semgrep"),
                    "semgrep.json",
                    &[],
                    "/cache/semgrep",
                )
            },
        )
        .tool("semgrep"),
    );

    v.push(
        Check::new(
            "tool.opengrep",
            "Static taint analysis (opengrep)",
            &repo_like(),
            Profile::Standard,
            |ctx| {
                let rules = if has_rules_in(&ctx.docker.cache_dir, "opengrep") {
                    "/cache/opengrep"
                } else {
                    "/cache/semgrep"
                };
                run_rule_scanner(
                    ctx,
                    "tool.opengrep",
                    "opengrep",
                    None,
                    "opengrep.json",
                    &["--taint-intrafile"],
                    rules,
                )
            },
        )
        .tool("opengrep"),
    );

    v.push(
        Check::new(
            "tool.hadolint",
            "Dockerfile lint (hadolint)",
            &repo_like(),
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("hadolint") {
                    return Ok(o);
                }
                if ctx.facts.dockerfiles.is_empty() {
                    return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                        "no Dockerfiles".into(),
                    )));
                }
                let mut spec = ToolSpec::new("hadolint", &["-f", "json", "--no-fail"]);
                spec.entrypoint = Some("/bin/hadolint".into());
                for d in &ctx.facts.dockerfiles {
                    spec.args.push(format!("/src/{d}"));
                }
                let r = ctx.docker.run(ctx, &spec)?;
                if r.stdout_truncated {
                    return Err(OutTooLarge {
                        name: "hadolint stdout".into(),
                        cap: TOOL_STDOUT_CAP as u64,
                    }
                    .into());
                }
                if r.stdout.trim().is_empty() && r.exit_code != 0 {
                    return Err(tool_failed("hadolint", &r));
                }
                Ok(CheckOutput::findings(parse_hadolint(&r.stdout)?))
            },
        )
        .tool("hadolint"),
    );

    v.push(
        Check::new(
            "tool.checkov",
            "IaC misconfiguration (checkov)",
            &repo_like(),
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("checkov") {
                    return Ok(o);
                }
                let f = &ctx.facts;
                let tf = ctx
                    .snapshot
                    .as_ref()
                    .map(|s| s.files.iter().any(|p| p.ends_with(".tf")))
                    .unwrap_or(false);
                if f.k8s_files.is_empty()
                    && f.compose_files.is_empty()
                    && f.dockerfiles.is_empty()
                    && !tf
                {
                    return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                        "no k8s/compose/Dockerfile/terraform files".into(),
                    )));
                }
                let mut spec = ToolSpec::new(
                    "checkov",
                    &[
                        "-d",
                        "/src",
                        "--skip-framework",
                        "secrets",
                        "--skip-download",
                        "--quiet",
                        "--soft-fail",
                        "-o",
                        "json",
                        "--output-file-path",
                        "/out",
                    ],
                );
                spec.entrypoint = Some("checkov".into());
                spec.env
                    .push(("CKV_IGNORE_HIDDEN_DIRECTORIES".into(), "true".into()));
                let r = ctx.docker.run(ctx, &spec)?;
                let found = match read_out(ctx, "results_json.json") {
                    Ok(t) => parse_checkov(&t),
                    Err(e) => Err(out_err(e, || tool_failed("checkov", &r))),
                };
                rewrite_scrubbed(ctx, "results_json.json", scrub_checkov);
                Ok(CheckOutput::findings(found?))
            },
        )
        .tool("checkov"),
    );

    v.push(
        Check::new(
            "tool.dockle",
            "Image best practices (dockle)",
            &[TargetKind::Image],
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                if let Some(o) = missing_image("dockle") {
                    return Ok(o);
                }
                let mut spec = ToolSpec::new(
                    "dockle",
                    &[
                        "-f",
                        "json",
                        "-o",
                        "/out/dockle.json",
                        "--input",
                        "/src/image.tar",
                        "--exit-code",
                        "0",
                    ],
                );
                spec.entrypoint = Some("dockle".into());
                let r = ctx.docker.run(ctx, &spec)?;
                let txt = read_out(ctx, "dockle.json")
                    .map_err(|e| out_err(e, || tool_failed("dockle", &r)))?;
                let image = ctx
                    .target
                    .image
                    .clone()
                    .unwrap_or_else(|| ctx.target.raw.clone());
                Ok(CheckOutput::findings(parse_dockle(&txt, &image)?))
            },
        )
        .tool("dockle"),
    );

    v.push(
        Check::new(
            "image.inspect",
            "Image configuration",
            &[TargetKind::Image],
            Profile::Quick,
            |ctx| {
                if let Some(o) = gate(ctx) {
                    return Ok(o);
                }
                let Some(image) = ctx.target.image.clone() else {
                    return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                        "no image".into(),
                    )));
                };
                let o = run_capped(
                    Command::new("docker").args(["image", "inspect", &image]),
                    DOCKER_QUICK,
                    8 << 20,
                    None,
                )?;
                if !o.success() {
                    bail!(
                        "docker image inspect {image}: {}",
                        if o.timed_out {
                            "timed out".to_string()
                        } else {
                            o.stderr_lossy().trim().to_string()
                        }
                    );
                }
                Ok(CheckOutput::findings(parse_image_inspect(
                    &o.stdout_lossy(),
                    &image,
                )?))
            },
        )
        .tool("docker"),
    );

    v.push(Check::new(
        "tests.own",
        "Project's own tests",
        &repo_like(),
        Profile::Standard,
        |ctx| {
            if let Some(o) = gate(ctx) {
                return Ok(o);
            }
            let Some(t) = ctx.cfg.test.clone() else {
                return Ok(CheckOutput::status(CheckStatus::NotApplicable(
                    "add [test] image+command to readyhai.toml".into(),
                )));
            };
            let mut spec = ToolSpec::new("tests", &["-c", &t.command]);
            spec.image = Some(t.image.clone());
            spec.entrypoint = Some("sh".into());
            spec.network = t.network;
            spec.workdir = Some("/src".into());
            spec.timeout_secs = t.timeout_secs;
            // /src is read-only: tests must write caches (pytest, .pyc, node_modules/.cache) to /tmp.
            let r = ctx.docker.run(ctx, &spec)?;
            let xml = match read_out(ctx, "junit.xml") {
                Ok(x) => x,
                Err(e) if is_oversize(&e) => return Err(e),
                Err(_) => {
                    return Ok(CheckOutput::status(CheckStatus::Errored(format!(
                        "no /out/junit.xml (exit {}; /src is read-only, write caches to /tmp): {}",
                        r.exit_code,
                        first_line(r.stderr_tail.trim(), 200)
                    ))));
                }
            };
            Ok(junit_output(&xml, r.exit_code))
        },
    ));

    v
}

pub fn junit_output(xml: &str, exit_code: i32) -> CheckOutput {
    let cases = parse_junit(xml);
    if cases.is_empty() {
        return CheckOutput::status(CheckStatus::Errored(format!(
            "junit.xml has no test cases (exit {exit_code})"
        )));
    }
    let failed: Vec<&JunitCase> = cases.iter().filter(|c| c.failed).collect();
    let errors = cases.iter().filter(|c| c.errored).count();
    if failed.is_empty() && errors > 0 {
        return CheckOutput::status(CheckStatus::Errored(format!(
            "{errors} test errors (environment?)"
        )));
    }
    let findings = failed
        .iter()
        .map(|c| {
            Finding::new(
                "tests.own",
                "tests.failed",
                Category::Quality,
                Severity::High,
                format!("Test failed: {}", c.name),
                format!("{}::{}", c.suite, c.name),
            )
            .detail(first_line(&c.message, 300))
            .fp_key(format!("{}::{}", c.suite, c.name))
        })
        .collect();
    CheckOutput::findings(findings)
}
