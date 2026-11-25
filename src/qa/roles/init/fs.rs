use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Where the file goes without `--out`: `<config>/readyhai/secrets/roles.toml`
/// (`$XDG_CONFIG_HOME`, else `~/.config`): outside any repo, next to the other test secrets.
pub fn default_out() -> Result<PathBuf> {
    default_out_in(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

pub fn default_out_in(xdg: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    let base = match xdg.filter(|v| !v.is_empty()) {
        Some(x) => PathBuf::from(x),
        None => PathBuf::from(
            home.filter(|v| !v.is_empty())
                .context("HOME is not set: pass --out")?,
        )
        .join(".config"),
    };
    Ok(base.join("readyhai").join("secrets").join("roles.toml"))
}

/// Write `text` to `out`, mode 0600 (a new directory 0700). An existing file is refused unless
/// `force`; a symlink at `out` is always refused.
pub fn write_secret_file(out: &Path, text: &str, force: bool) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty())
        && !dir.exists()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    if std::fs::symlink_metadata(out).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!(
            "{} is a symlink: refusing to write through it",
            out.display()
        );
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if force {
        o.create(true);
    } else {
        o.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(out).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!("{} exists: pass --force to overwrite it", out.display())
        } else {
            anyhow::Error::new(e).context(format!("write {}", out.display()))
        }
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.set_len(0)?;
    f.write_all(text.as_bytes())?;
    Ok(())
}
