use std::fs;
use std::path::Path;

use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::*;
use crate::snapshot::Snapshot;

use super::common::{Def, no_snapshot, out, record, untested};

#[derive(Debug, PartialEq)]
pub(crate) enum MigTool {
    Alembic(String),
    Prisma,
    Flyway,
}

pub(crate) fn detect_migrations(files: &[String]) -> Vec<MigTool> {
    let mut v = vec![];
    for f in files {
        if f == "alembic.ini" || f.ends_with("/alembic.ini") {
            let dir = f
                .trim_end_matches("alembic.ini")
                .trim_end_matches('/')
                .to_string();
            let has_versions = files
                .iter()
                .any(|x| x.contains("/versions/") && x.ends_with(".py"));
            if has_versions && !v.contains(&MigTool::Alembic(dir.clone())) {
                v.push(MigTool::Alembic(dir));
            }
        }
    }
    if files.iter().any(|f| f.ends_with("prisma/schema.prisma"))
        && files.iter().any(|f| f.contains("prisma/migrations/"))
    {
        v.push(MigTool::Prisma);
    }
    if files
        .iter()
        .any(|f| f.contains("db/migration/V") && f.ends_with(".sql"))
    {
        v.push(MigTool::Flyway);
    }
    v
}

/// Shell script run inside the app image. Exit code identifies the failing step.
const ALEMBIC_SCRIPT: &str = "echo '##STEP upgrade head'; alembic upgrade head || exit 11; \
echo '##STEP downgrade base'; alembic downgrade base || exit 12; \
echo '##STEP upgrade head (again)'; alembic upgrade head || exit 13";

/// Exit codes that say the TOOLING failed, not the migration: docker run error (125), command
/// not invokable (126) / not found (127: no alembic in the image), SIGKILL/OOM (137), SIGTERM (143).
/// They must not be reported as a migration defect.
pub(crate) fn infra_exit(code: i32) -> Option<&'static str> {
    Some(match code {
        125 => "docker could not run the container (exit 125)",
        126 => "the migration command is not executable in the image (exit 126)",
        127 => {
            "alembic/sh not found in the image (exit 127): is alembic installed in the [test] image?"
        }
        137 => "the container was killed (exit 137: OOM or SIGKILL)",
        143 => "the container was terminated (exit 143)",
        _ => return None,
    })
}

pub(crate) fn step_for_exit(code: i32) -> &'static str {
    match code {
        11 => "alembic upgrade head",
        12 => "alembic downgrade base",
        13 => "alembic upgrade head (after downgrade)",
        _ => "container start / alembic setup",
    }
}

/// Hardening flags shared by both containers. The migration check cannot use `Docker::run`
/// (tools.rs): that API forces `--network none|bridge`, and the app container must reach a
/// sibling database container over a per-run `--internal` network (no internet, no host).
/// So we build the `docker run` ourselves with the same hardening: cap-drop ALL,
/// no-new-privileges, read-only rootfs, pids/memory limits, readyhai.run label, non-root.
pub(crate) fn hardening(run: &str, name: &str, net: &str, mem: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "--rm",
        "--name",
        name,
        "--label",
        &format!("readyhai.run={run}"),
        "--network",
        net,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--pids-limit",
        "512",
        "--memory",
        mem,
        "--cpus",
        "2",
        "--log-driver",
        "none",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    v.shrink_to_fit();
    v
}

pub(crate) fn pg_args(run: &str, name: &str, net: &str) -> Vec<String> {
    let mut v = vec!["run".to_string(), "-d".into()];
    v.extend(hardening(run, name, net, "512m"));
    v.extend(
        [
            "--user",
            "70:70",
            "--tmpfs",
            "/var/lib/postgresql/data:rw,uid=70,gid=70,mode=0700,size=512m",
            "--tmpfs",
            "/var/run/postgresql:rw,uid=70,gid=70,mode=0755",
            "--tmpfs",
            "/tmp:rw,size=64m",
            // value is forwarded from the process environment so it never appears in argv
            "-e",
            "POSTGRES_PASSWORD",
            "-e",
            "POSTGRES_DB=app",
            "postgres:16-alpine",
        ]
        .map(String::from),
    );
    v
}

pub(crate) fn app_args(
    run: &str,
    name: &str,
    net: &str,
    src: &Path,
    workdir: &str,
    image: &str,
) -> Vec<String> {
    let mut v = vec!["run".to_string()];
    v.extend(hardening(run, name, net, "1g"));
    v.extend([
        "--user".to_string(),
        "65534:65534".into(),
        "--tmpfs".into(),
        "/tmp:rw,exec,size=256m,mode=1777".into(),
        "-e".into(),
        "HOME=/tmp".into(),
        "-e".into(),
        "PYTHONDONTWRITEBYTECODE=1".into(),
        "-e".into(),
        "DATABASE_URL".into(),
        "-e".into(),
        "SQLALCHEMY_URL".into(),
        "-v".into(),
        format!("{}:/src:ro", src.display()),
        "-w".into(),
        format!("/src/{workdir}").trim_end_matches('/').to_string(),
        "--entrypoint".into(),
        "sh".into(),
        image.into(),
        "-c".into(),
        ALEMBIC_SCRIPT.into(),
    ]);
    v
}

/// Removes the database container and the per-run network on every exit path.
struct MigEnv {
    run: String,
    pg: String,
    net: String,
}

impl Drop for MigEnv {
    fn drop(&mut self) {
        use std::process::Command;
        let _ = Command::new("docker").args(["rm", "-f", &self.pg]).output();
        if let Ok(o) = Command::new("docker")
            .args([
                "ps",
                "-aq",
                "--filter",
                &format!("label=readyhai.run={}", self.run),
                "--filter",
                &format!("network={}", self.net),
            ])
            .output()
        {
            let ids: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(String::from)
                .collect();
            if !ids.is_empty() {
                let _ = Command::new("docker")
                    .arg("rm")
                    .arg("-f")
                    .args(&ids)
                    .output();
            }
        }
        let _ = Command::new("docker")
            .args(["network", "rm", &self.net])
            .output();
    }
}

pub(crate) struct MigOutcome {
    pub(crate) exit: i32,
    pub(crate) tail: Vec<String>,
}

pub(crate) fn run_alembic(
    ctx: &Ctx,
    snap: &Snapshot,
    dir: &str,
    image: &str,
    timeout_secs: u64,
) -> anyhow::Result<MigOutcome> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let tag: u16 = rand::random();
    let run = ctx.run_id.clone();
    let clean = |s: &str| {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
    };
    let net = format!("readyhai-{}-mig", clean(&run));
    let pg = format!("readyhai-{}-mig-pg-{tag:04x}", clean(&run));
    let app = format!("readyhai-{}-mig-app-{tag:04x}", clean(&run));
    let pw: String = (0..24)
        .map(|_| (b'a' + rand::random::<u8>() % 26) as char)
        .collect();
    let _guard = MigEnv {
        run: run.clone(),
        pg: pg.clone(),
        net: net.clone(),
    };

    let o = Command::new("docker")
        .args([
            "network",
            "create",
            "--internal",
            "--label",
            &format!("readyhai.run={run}"),
            &net,
        ])
        .output()?;
    if !o.status.success() {
        anyhow::bail!(
            "docker network create: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    let o = Command::new("docker")
        .args(pg_args(&run, &pg, &net))
        .env("POSTGRES_PASSWORD", &pw)
        .output()?;
    if !o.status.success() {
        anyhow::bail!(
            "starting postgres: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    let mut ready = false;
    for _ in 0..40 {
        let ok = Command::new("docker")
            .args([
                "exec",
                &pg,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
                "-d",
                "app",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    if !ready {
        anyhow::bail!("postgres did not become ready within 40s");
    }
    let url = format!("postgresql://postgres:{pw}@{pg}:5432/app");
    let log = std::env::temp_dir().join(format!("readyhai-mig-{}-{tag:04x}.log", clean(&run)));
    let f = fs::File::create(&log)?;
    let f2 = f.try_clone()?;
    let mut child = Command::new("docker")
        .args(app_args(&run, &app, &net, &snap.root, dir, image))
        .env("DATABASE_URL", &url)
        .env("SQLALCHEMY_URL", &url)
        .stdin(Stdio::null())
        .stdout(f)
        .stderr(f2)
        .spawn()?;
    let start = Instant::now();
    let code = loop {
        if let Some(s) = child.try_wait()? {
            break s.code().unwrap_or(-1);
        }
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            let _ = Command::new("docker").args(["rm", "-f", &app]).output();
            let _ = child.kill();
            let _ = child.wait();
            break 124;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let text = fs::read_to_string(&log).unwrap_or_default();
    let _ = fs::remove_file(&log);
    let lines: Vec<String> = text
        .lines()
        .map(|l| crate::logs::redact(&l.replace(&pw, "[REDACTED]")))
        .collect();
    let tail = lines[lines.len().saturating_sub(40)..].to_vec();
    Ok(MigOutcome { exit: code, tail })
}

pub(crate) fn migrations(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let tools = detect_migrations(&snap.files);
    if tools.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no migrations found".into(),
        )));
    }
    let mut dir = None;
    for t in &tools {
        match t {
            MigTool::Alembic(d) => dir = Some(d.clone()),
            MigTool::Prisma => untested(
                ctx,
                "prisma migrations detected: up/down/up run not implemented yet",
            ),
            MigTool::Flyway => untested(
                ctx,
                "flyway migrations detected: up/down/up run not implemented yet",
            ),
        }
    }
    let Some(dir) = dir else {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "only prisma/flyway migrations found; runner not implemented".into(),
        )));
    };
    let case = "release.migrations";
    let Some(tcfg) = &ctx.cfg.test else {
        untested(
            ctx,
            "alembic migrations not run: set [test] image in readyhai.toml",
        );
        record(
            ctx,
            "qa.release.migrations",
            Area::Release,
            case,
            "Migrations apply, roll back and re-apply",
            &dir,
            ResultStatus::Skipped,
            "no [test] image configured",
            vec![],
        );
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "set [test] image in readyhai.toml to run migrations".into(),
        )));
    };
    if !ctx.docker.available || !matches!(ctx.docker.mode, crate::tools::MountMode::Bind) {
        untested(
            ctx,
            "alembic migrations not run: docker (bind-mount mode) unavailable",
        );
        record(
            ctx,
            "qa.release.migrations",
            Area::Release,
            case,
            "Migrations apply, roll back and re-apply",
            &dir,
            ResultStatus::Blocked,
            "docker unavailable",
            vec![],
        );
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "docker (bind-mount mode) required for migrations".into(),
        )));
    }
    let res = run_alembic(ctx, snap, &dir, &tcfg.image, tcfg.timeout_secs.min(600))?;
    if res.exit == 0 {
        return Ok(out(record(
            ctx,
            "qa.release.migrations",
            Area::Release,
            case,
            "Migrations apply, roll back and re-apply",
            &dir,
            ResultStatus::Pass,
            "alembic upgrade/downgrade/upgrade succeeded",
            vec![],
        )));
    }
    if let Some(why) = infra_exit(res.exit) {
        // Tooling failure: the migration was never judged. Blocked result, errored check, no defect.
        untested(ctx, &format!("alembic migrations not verified: {why}"));
        let tail = res
            .tail
            .iter()
            .rev()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ");
        record(
            ctx,
            "qa.release.migrations",
            Area::Release,
            case,
            "Migrations apply, roll back and re-apply",
            &dir,
            ResultStatus::Blocked,
            &format!("{why}; last output: {tail}"),
            vec![],
        );
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "migration run did not complete: {why}"
        ))));
    }
    let step = if res.exit == 124 {
        "timeout"
    } else {
        step_for_exit(res.exit)
    };
    let comp = if dir.is_empty() {
        "alembic".to_string()
    } else {
        format!("{dir}/alembic")
    };
    let def = Def {
        rule: "qa.release.migration_failure",
        cat: Category::Reliability,
        sev: Severity::High,
        area: Area::Release,
        title: format!("Database migration failed at step: {step}"),
        component: comp,
        expected: "alembic upgrade head, downgrade base and upgrade head all succeed on an empty database".into(),
        actual: format!("exit {} at '{step}'. Last output:\n{}", res.exit, res.tail.join("\n")),
        remediation: "Fix the failing migration (write a real downgrade or mark the revision irreversible) and re-run.".into(),
        fp_key: format!("migration:{step}"),
        steps: vec![
            format!("docker run postgres:16-alpine on an internal network, run the app image `{}` with DATABASE_URL set", tcfg.image),
            "alembic upgrade head && alembic downgrade base && alembic upgrade head".into(),
        ],
    };
    Ok(out(record(
        ctx,
        "qa.release.migrations",
        Area::Release,
        case,
        "Migrations apply, roll back and re-apply",
        &dir,
        ResultStatus::Fail,
        &format!("failed at {step}"),
        vec![def],
    )))
}
