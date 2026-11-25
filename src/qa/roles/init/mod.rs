//! `readyhai roles init`: derive a roles.toml skeleton from an OpenAPI 3.x spec.
//!
//! What the spec says is turned into test accounts and an expected-access matrix:
//! * `components.securitySchemes` (http bearer / basic, apiKey, oauth2, openIdConnect) decide
//!   how a role authenticates (`auth`, header name);
//! * per-operation `security` (falling back to the global one) and `x-roles` /
//!   `x-required-roles` decide which operations a role may reach;
//! * OAuth2 scope names and role names that look privileged (`admin`, `root`, `internal`, ...)
//!   split the accounts into an admin and ordinary users; paths only they can reach become
//!   `deny` globs of the ordinary roles.
//!
//! The file holds env var NAMES only (`RH_<ROLE>_TOKEN`), never a secret value. The result is a
//! starting point to review: the globs are derived, not known.

pub mod derive;
pub mod fs;
pub mod openapi;
pub mod render;
pub mod trie;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use derive::{Derived, DerivedRole, derive};
#[allow(unused_imports)]
pub use fs::{default_out, write_secret_file};
#[allow(unused_imports)]
pub use render::render;

use crate::qa::api::spec::{MAX_SPEC_BYTES, parse_text};
use anyhow::{Context, Result, bail};
use render::auth_str;
use std::path::{Path, PathBuf};

/// `readyhai roles init --spec FILE [--out FILE|-] [--force]`. Returns the path written (None
/// for stdout).
pub fn run(spec: &str, out: Option<&Path>, force: bool) -> Result<Option<PathBuf>> {
    if spec.starts_with("http://") || spec.starts_with("https://") {
        bail!(
            "--spec must be a local file (download it first): roles init makes no network requests"
        );
    }
    if std::fs::metadata(spec).is_ok_and(|m| m.len() > MAX_SPEC_BYTES) {
        bail!("spec {spec} is larger than {} MiB", MAX_SPEC_BYTES >> 20);
    }
    let text = std::fs::read_to_string(spec).with_context(|| format!("read spec {spec}"))?;
    let doc = parse_text(&text)?;
    drop(text);
    let derived = derive(&doc)?;
    let file = Path::new(spec)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let body = render(&derived, &file);
    if out == Some(Path::new("-")) {
        print!("{body}");
        return Ok(None);
    }
    let path = match out {
        Some(p) => p.to_path_buf(),
        None => default_out()?,
    };
    write_secret_file(&path, &body, force)?;
    eprintln!(
        "roles init: {} role(s) for {} operation(s) -> {} (mode 0600)",
        derived.roles.len(),
        derived.operations,
        path.display()
    );
    for r in &derived.roles {
        eprintln!(
            "  {:<12} {:<7} allow {} / deny {} glob(s)",
            r.name,
            auth_str(r.auth),
            r.allow.len(),
            r.deny.len()
        );
    }
    for w in &derived.warnings {
        eprintln!("  note: {w}");
    }
    eprintln!("Review allow/deny, export the RH_* variables (test accounts only), then:");
    eprintln!(
        "  readyhai qa <url> --spec {spec} --roles {}",
        path.display()
    );
    Ok(Some(path))
}
