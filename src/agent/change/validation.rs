use std::path::{Path, PathBuf};

/// A git ref is passed to `git diff` as `<ref>...HEAD`, so it must be a plain revision: no option
/// (leading `-`), no range (`..`), no whitespace or shell/glob characters.
pub fn validate_diff_base(base: &str) -> Result<(), String> {
    let ok_char = |c: char| c.is_ascii_alphanumeric() || "._/@^~+-".contains(c);
    if base.is_empty() || base.chars().count() > 200 {
        return Err("diff_base must be 1 to 200 characters".into());
    }
    if base.starts_with('-') || base.contains("..") || !base.chars().all(ok_char) {
        return Err(
            "diff_base must be a plain git ref or commit (letters, digits and . _ / @ ^ ~ + -)"
                .into(),
        );
    }
    Ok(())
}

/// The repo directory, canonical. Whether git accepts it as a repository is git's call.
pub fn resolve_repo(repo: &str) -> Result<PathBuf, String> {
    let p = Path::new(repo.trim());
    let c = p
        .canonicalize()
        .map_err(|_| "repo is not an existing directory".to_string())?;
    if !c.is_dir() {
        return Err("repo is not an existing directory".into());
    }
    Ok(c)
}

/// Validate the two request fields together; `roots` confines the repo (REST and MCP pass the
/// server's allowed roots, the CLI passes None). Returns the canonical repo and the ref.
pub fn validate_request(
    repo: &str,
    diff_base: Option<&str>,
    roots: Option<&[PathBuf]>,
) -> Result<(PathBuf, Option<String>), String> {
    let root = resolve_repo(repo)?;
    if let Some(roots) = roots
        && !crate::mcp::under_roots(&root, roots)
    {
        return Err("repo is outside READYHAI_ALLOWED_ROOTS".into());
    }
    let base = match diff_base.map(str::trim).filter(|b| !b.is_empty()) {
        Some(b) => {
            validate_diff_base(b)?;
            Some(b.to_string())
        }
        None => None,
    };
    Ok((root, base))
}
