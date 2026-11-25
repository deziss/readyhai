//! Target parsing, URI classification, and target normalization.

use std::path::Path;

use anyhow::{Result, bail};

use crate::model::{HostSpec, Os, Target, TargetKind};
use crate::scope;

pub fn parse_target(raw: &str, openapi: Option<String>) -> Result<Target> {
    let mut t = Target {
        kind: TargetKind::Repo,
        raw: raw.to_string(),
        path: None,
        image: None,
        url: None,
        openapi,
        host: None,
        apk: None,
        device: None,
    };
    if let Some(img) = raw.strip_prefix("image:") {
        if img.is_empty() || img.starts_with('-') || img.contains(char::is_whitespace) {
            bail!("invalid image reference");
        }
        t.kind = TargetKind::Image;
        t.image = Some(img.to_string());
    } else if let Some(rest) = raw.strip_prefix("ssh://") {
        t.kind = TargetKind::Host;
        t.host = Some(parse_ssh(rest)?);
    } else if let Some(p) = raw.strip_prefix("android:") {
        let p = Path::new(p);
        let ok = p.is_file()
            && matches!(
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("apk" | "aab")
            );
        if !ok {
            bail!("android target must be android:<path to .apk/.aab>");
        }
        t.kind = TargetKind::Android;
        t.apk = Some(p.canonicalize()?);
    } else if raw.starts_with("git:")
        || raw.ends_with(".git")
        || raw.starts_with("https://github.com/")
        || raw.starts_with("http://github.com/")
        || raw.starts_with("https://gitlab.com/")
        || raw.starts_with("http://gitlab.com/")
    {
        t.kind = TargetKind::Repo;
    } else if raw.starts_with("http://") || raw.starts_with("https://") {
        t.kind = TargetKind::Web;
        // Use the WHATWG-normalised form everywhere downstream: it is the one the scope check
        // saw, so no tool can parse the authority differently (backslash/userinfo tricks).
        t.url = Some(scope::parse_web_url(raw)?.to_string());
    } else {
        let p = Path::new(raw);
        if !p.is_dir() {
            bail!("target '{raw}' is not a directory, image:<ref>, http(s):// URL or git:<url>");
        }
        t.path = Some(p.canonicalize()?);
    }
    Ok(t)
}

/// user@host[:port] — strict charset so nothing reaches ssh as an option.
pub fn parse_ssh(rest: &str) -> Result<HostSpec> {
    let rest = rest.trim_end_matches('/');
    let (user, hostport) = rest
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("ssh target must be ssh://user@host[:port]"))?;
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (
            h,
            p.parse::<u16>()
                .map_err(|_| anyhow::anyhow!("bad ssh port"))?,
        ),
        _ => (hostport, 22),
    };
    let ok = |s: &str| {
        !s.is_empty()
            && !s.starts_with('-')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    };
    if !ok(user) || !ok(host) {
        bail!("invalid ssh user or host");
    }
    Ok(HostSpec {
        user: user.into(),
        host: host.into(),
        port,
        os: Os::Linux,
        key: None,
    })
}
