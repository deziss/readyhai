use std::path::Path;

pub const HINT: &str = "build the runner: docker build -t readyhai/playwright-runner:local runners/playwright, or pull it: docker pull ghcr.io/deziss/readyhai-playwright-runner:latest";

pub const LOCAL_IMAGE: &str = "readyhai/playwright-runner:local";
pub const PUBLISHED_IMAGE: &str = "ghcr.io/deziss/readyhai-playwright-runner:latest";

/// Runner image: READYHAI_PLAYWRIGHT_IMAGE, else the local build, else the published image.
pub fn playwright_image() -> String {
    pick_image(
        std::env::var("READYHAI_PLAYWRIGHT_IMAGE").ok(),
        crate::tools::local_image_id(LOCAL_IMAGE).is_some(),
    )
}

pub fn pick_image(env: Option<String>, local_present: bool) -> String {
    match env.map(|s| s.trim().to_string()) {
        Some(e) if !e.is_empty() => e,
        _ if local_present => LOCAL_IMAGE.into(),
        _ => PUBLISHED_IMAGE.into(),
    }
}

pub fn is_missing_image(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("unable to find image")
        || l.contains("pull access denied")
        || l.contains("no such image")
}

pub fn is_local(url: &str) -> bool {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let auth = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = auth
        .strip_prefix('[')
        .map(|r| r.split(']').next().unwrap_or(r))
        .unwrap_or_else(|| auth.split(':').next().unwrap_or(auth));
    matches!(
        host,
        "localhost" | "127.0.0.1" | "::1" | "0.0.0.0" | "host.docker.internal"
    ) || host.ends_with(".localhost")
}

/// (container-reachable base URL, needs host gateway). Same rewrite as web.rs.
pub fn container_base(url: &str) -> (String, bool) {
    if !is_local(url) {
        return (url.to_string(), false);
    }
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let (auth, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let port = if auth.starts_with('[') {
        auth.rsplit_once("]:").map(|x| x.1)
    } else {
        auth.rsplit_once(':').map(|x| x.1)
    };
    let port = port.filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    let a = match port {
        Some(p) => format!("host.docker.internal:{p}"),
        None => "host.docker.internal".into(),
    };
    (format!("{scheme}://{a}{tail}"), true)
}

pub fn origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    format!(
        "{scheme}://{}",
        rest.split(['/', '?', '#']).next().unwrap_or("")
    )
}

pub fn set_mode(p: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (p, mode);
}
