use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use super::baseline::{copy_dir_pngs, visual_baseline_dir};
use super::builder::build;
use super::image::{HINT, container_base, is_missing_image, origin, playwright_image, set_mode};
use super::model::UiReport;
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus, Finding, Profile, TargetKind};
use crate::tools::ToolSpec;

/// Removes out/secrets on drop, so role cookies never outlive the run (even on error).
pub struct SecretsGuard(pub PathBuf);
impl Drop for SecretsGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn load_journeys(path: &Path) -> Result<Vec<serde_json::Value>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("journeys file {}", path.display()))?;
    let v: serde_json::Value =
        serde_norway::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(match v {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(mut o) => match o.remove("journeys") {
            Some(serde_json::Value::Array(a)) => a,
            _ => vec![serde_json::Value::Object(o)],
        },
        _ => vec![],
    })
}

pub fn run(ctx: &Ctx) -> Result<CheckOutput> {
    let qa = ctx.qa.as_ref().context("not a QA run")?;
    let url = ctx.target.url.clone().context("no target url")?;
    if !ctx.docker.available {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "docker not available".into(),
        )));
    }
    let (cbase, gw) = container_base(&url);
    let out = ctx.out_dir();
    std::fs::create_dir_all(&out)?;

    let standard = ctx.profile >= Profile::Standard;
    let mut modes = vec!["crawl", "responsive", "a11y", "vitals"];
    let journeys = match (&qa.journeys, standard) {
        (Some(p), true) => load_journeys(p)?,
        _ => vec![],
    };
    if standard {
        if qa.nonprod {
            modes.push("forms");
        }
        if !journeys.is_empty() {
            modes.push("journeys");
        }
        modes.push("visual");
    }

    // Role storageState → out/secrets (deleted by the guard).
    let secrets = out.join("secrets");
    let _guard = SecretsGuard(secrets.clone());
    let mut roles = vec![];
    let mut notes = vec![];
    if !journeys.is_empty() {
        std::fs::create_dir_all(&secrets)?;
        set_mode(&secrets, 0o700);
        for r in &qa.roles.roles {
            let Some(ss) = &r.storage_state else { continue };
            let src = qa.roles.dir.join(ss);
            let dst = secrets.join(format!("{}.json", r.name));
            if std::fs::copy(&src, &dst).is_ok() {
                // Owner-only; the runner is started as the owner's uid (ts.user below).
                set_mode(&dst, 0o600);
                roles.push(serde_json::json!({"name": r.name, "storage_state_path": format!("/out/secrets/{}.json", r.name)}));
            } else {
                notes.push(format!(
                    "role {}: storageState not readable, UI journeys skipped for this role",
                    r.name
                ));
            }
        }
    }

    // Visual baselines.
    let bdir = visual_baseline_dir(
        &crate::engine::data_dir(),
        &crate::engine::target_key(&ctx.target),
    );
    let have_baseline = copy_dir_pngs(&bdir, &out.join("visual-baseline"), false) > 0;
    let _ = std::fs::remove_dir_all(out.join("shots"));

    let input = serde_json::json!({
        "base_url": cbase, "max_pages": 20, "modes": modes,
        "viewports": [[375, 812], [768, 1024], [1366, 768]],
        "nonprod": qa.nonprod, "roles": roles, "journeys": journeys,
        "visual_baseline_dir": "/out/visual-baseline", "axe": true,
    });
    let _ = std::fs::remove_file(out.join("qa-ui.json"));
    std::fs::write(
        out.join("qa-ui-input.json"),
        serde_json::to_vec_pretty(&input)?,
    )?;

    let mut ts = ToolSpec::new(
        "playwright",
        &["node", "/runner/qa.mjs", "/out/qa-ui-input.json"],
    );
    #[cfg(unix)]
    if !roles.is_empty() {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::metadata(&secrets) {
            ts.user = Some(format!("{}:{}", m.uid(), m.gid()));
        }
    }
    ts.image = Some(playwright_image());
    ts.network = true;
    ts.host_gateway = gw;
    ts.memory = "2g".into();
    ts.timeout_secs = 660;
    ts.tmpfs = vec!["/home/pwuser:rw,size=256m,mode=1777".into()];
    ts.env = vec![("PLAYWRIGHT_BROWSERS_PATH".into(), "/ms-playwright".into())];
    let run = match ctx.docker.run(ctx, &ts) {
        Ok(r) => r,
        Err(e) if is_missing_image(&e.to_string()) => {
            return Ok(CheckOutput::status(CheckStatus::Skipped(HINT.into())));
        }
        Err(e) => return Err(e),
    };
    let Ok(text) = std::fs::read_to_string(out.join("qa-ui.json")) else {
        if is_missing_image(&run.stderr_tail) {
            return Ok(CheckOutput::status(CheckStatus::Skipped(HINT.into())));
        }
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "qa.mjs produced no report (exit {}): {}",
            run.exit_code,
            run.stderr_tail.chars().take(300).collect::<String>()
        ))));
    };
    let rep: UiReport = serde_json::from_str(&text).context("parse qa-ui.json")?;

    let (corigin, oorigin) = (origin(&cbase), origin(&url));
    let unmap = move |s: &str| s.replace(&corigin, &oorigin);
    let env = if qa.nonprod {
        "nonprod"
    } else {
        "unclassified (writes disabled)"
    };
    let mut built = build(&rep, &format!("{env}: {url}"), &unmap);
    built.notes.extend(notes);

    // Evidence → run_dir/artifacts/ui/, and first-run baseline.
    let art = ctx.run_dir.join("artifacts").join("ui");
    for sub in ["shots", "traces"] {
        if let Ok(rd) = std::fs::read_dir(out.join(sub)) {
            let _ = std::fs::create_dir_all(art.join(sub));
            for e in rd.flatten() {
                let _ = std::fs::copy(e.path(), art.join(sub).join(e.file_name()));
            }
        }
    }
    if !have_baseline && rep.pages.iter().any(|p| !p.shots.is_empty()) {
        let n = copy_dir_pngs(&out.join("shots"), &bdir, true);
        if n > 0 {
            built.notes.push(format!("UI visual: no baseline existed, stored {n} screenshot(s) as the baseline ({}). Next run compares against them; promote a later run with `readyhai baseline accept <run>`.", bdir.display()));
        }
    }
    if !modes.contains(&"forms") {
        built.notes.push(if standard && !qa.nonprod {
            "UI forms not tested: target not tagged nonprod".into()
        } else {
            "UI forms/journeys/visual run only in the standard profile".to_string()
        });
    }

    let findings: Vec<Finding> = built
        .defects
        .iter()
        .map(|d| d.to_finding("qa.ui"))
        .collect();
    qa.with(|c| {
        c.cases.extend(built.cases);
        c.results.extend(built.results);
        c.defects.extend(built.defects);
        for (r, col, cell) in built
            .coverage
            .cells
            .iter()
            .map(|(r, c, x)| (&built.coverage.rows[*r], &built.coverage.columns[*c], *x))
        {
            c.coverage.set(r, col, cell);
        }
        c.notes.extend(built.notes);
    });
    Ok(CheckOutput::findings(findings))
}

pub fn checks() -> Vec<Check> {
    vec![
        Check::new(
            "qa.ui",
            "UI exploratory QA: responsive, a11y, forms, journeys, visual, vitals (Playwright)",
            &[TargetKind::Web],
            Profile::Quick,
            run,
        )
        .qa()
        .tool("playwright"),
    ]
}
