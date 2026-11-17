//! Application staging for Android APK/AAB targets.
use anyhow::{Context, Result, bail};
use std::path::PathBuf;

use crate::ctx::Ctx;

/// Copy the APK/AAB into <run>/src/app.<ext> (mode 644). Returns (path, ext).
pub(crate) fn stage_app(ctx: &Ctx) -> Result<Option<(PathBuf, String)>> {
    let Some(apk) = ctx.target.apk.clone() else {
        return Ok(None);
    };
    if !apk.is_file() {
        bail!("APK not found: {}", apk.display());
    }
    let ext = apk
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .filter(|e| matches!(e.as_str(), "apk" | "aab" | "xapk" | "zip"))
        .unwrap_or_else(|| "apk".into());
    let dir = ctx.src_dir();
    std::fs::create_dir_all(&dir).context("create src dir")?;
    let dst = dir.join(format!("app.{ext}"));
    std::fs::copy(&apk, &dst).context("copy app into run dir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o644));
    }
    Ok(Some((dst, ext)))
}
