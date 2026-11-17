//! MobSF static analysis integration.
use anyhow::Result;

pub mod client;
pub mod container;
pub mod mapping;

pub use container::parse_docker_port;
pub use mapping::{map_report, scrub_report};

use crate::android::staging::stage_app;
use crate::android::util::rand_hex;
use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus};

pub fn run_mobsf(ctx: &Ctx) -> Result<CheckOutput> {
    if ctx.target.apk.is_none() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no APK/AAB given".into(),
        )));
    }
    if !ctx.docker.available {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "docker not available".into(),
        )));
    }
    let Some((app, _)) = stage_app(ctx)? else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no APK/AAB given".into(),
        )));
    };
    let key = rand_hex(24);
    let (guard, port) = container::start_mobsf(ctx, &key)?;
    let rep = client::mobsf_scan(&format!("http://127.0.0.1:{port}"), &key, &app);
    drop(guard);
    let rep = rep?;
    let clean = scrub_report(&rep);
    std::fs::create_dir_all(ctx.out_dir())?;
    std::fs::write(
        ctx.out_dir().join("mobsf.json"),
        serde_json::to_string_pretty(&clean)?,
    )?;
    Ok(CheckOutput::findings(map_report(&rep)))
}
