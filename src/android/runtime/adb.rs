//! ADB device interactions, APK installation, execution, and runtime monitoring.
use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use std::collections::BTreeSet;
use std::process::Command;
use std::time::Duration;

use super::logcat::{is_emulator, scan_logcat};
use crate::android::staging::stage_app;
use crate::android::util::{redact, run_cmd, slug};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity};

struct Adb {
    dev: String,
}

impl Adb {
    fn run(&self, args: &[&str], secs: u64) -> Result<(i32, String, String)> {
        run_cmd(
            Command::new("adb").arg("-s").arg(&self.dev).args(args),
            secs,
        )
    }
    fn pkgs(&self) -> Result<BTreeSet<String>> {
        let (_, o, _) = self.run(&["shell", "pm", "list", "packages"], 60)?;
        Ok(o.lines()
            .filter_map(|l| l.trim().strip_prefix("package:"))
            .map(|s| s.trim().to_string())
            .collect())
    }
}

fn package_from_mobsf(ctx: &Ctx) -> Option<String> {
    let t = std::fs::read_to_string(ctx.out_dir().join("mobsf.json")).ok()?;
    let v: Value = serde_json::from_str(&t).ok()?;
    let p = v.get("package_name")?.as_str()?.to_string();
    (!p.is_empty()).then_some(p)
}

pub fn run_runtime(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(dev) = ctx.target.device.clone() else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "attach a device/emulator and pass --device <serial|host:port>".into(),
        )));
    };
    if run_cmd(Command::new("adb").arg("version"), 10).is_err() {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "adb not installed".into(),
        )));
    }
    let Some((app, ext)) = stage_app(ctx)? else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no APK given".into(),
        )));
    };
    if ext != "apk" {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "adb install needs an .apk (AAB/XAPK not supported)".into(),
        )));
    }
    if dev.contains(':') && !dev.starts_with("emulator-") {
        let _ = run_cmd(Command::new("adb").args(["connect", &dev]), 20);
    }
    let adb = Adb { dev: dev.clone() };
    let (_, st, _) = adb
        .run(&["get-state"], 20)
        .map_err(|e| anyhow!("adb get-state: {e}"))?;
    if st.trim() != "device" {
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "device {dev} state is '{}', expected 'device'",
            st.trim()
        ))));
    }
    let before = adb.pkgs()?;
    let apk_s = app.to_string_lossy().to_string();
    let (code, o, e) = adb.run(&["install", "-r", "-t", &apk_s], 300)?;
    if code != 0 || o.contains("Failure") {
        bail!("adb install failed: {}", redact(format!("{o} {e}").trim()));
    }
    let after = adb.pkgs()?;
    let pkg = package_from_mobsf(ctx)
        .or_else(|| after.difference(&before).next().cloned())
        .ok_or_else(|| anyhow!("cannot determine package name (run android.mobsf first or uninstall the app beforehand)"))?;
    let preinstalled = before.contains(&pkg);

    let result = (|| -> Result<CheckOutput> {
        let _ = adb.run(&["logcat", "-c"], 20);
        adb.run(
            &[
                "shell",
                "monkey",
                "-p",
                &pkg,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            60,
        )?;
        std::thread::sleep(Duration::from_secs(20));
        if matches!(ctx.profile, Profile::Deep) {
            let qemu = adb
                .run(&["shell", "getprop", "ro.kernel.qemu"], 15)
                .map(|r| r.1)
                .unwrap_or_default();
            if is_emulator(&dev, &qemu) {
                let _ = adb.run(
                    &[
                        "shell",
                        "monkey",
                        "-p",
                        &pkg,
                        "--throttle",
                        "200",
                        "--pct-syskeys",
                        "0",
                        "-v",
                        "1500",
                    ],
                    600,
                );
            }
        }
        let (_, log, _) = adb.run(&["logcat", "-d", "-v", "brief", "*:E"], 60)?;
        let sc = scan_logcat(&log, &pkg);
        for l in &sc.error_lines {
            ctx.error_line("android.logcat", l);
        }
        let mut fs = vec![];
        for (kind, title, detail) in sc.events {
            let rule = if kind == "anr" {
                "android.anr"
            } else {
                "android.crash"
            };
            let t = if kind == "anr" {
                format!("ANR: {title}")
            } else {
                format!("App crash: {title}")
            };
            let mut f = Finding::new(
                "android.runtime",
                rule,
                Category::Reliability,
                Severity::High,
                t,
                pkg.clone(),
            );
            f.detail = detail;
            f.fp_key = Some(format!("{rule}:{pkg}:{}", slug(&title)));
            fs.push(f);
        }
        Ok(CheckOutput::findings(fs))
    })();
    if !preinstalled {
        let _ = adb.run(&["uninstall", &pkg], 60);
    }
    result
}
