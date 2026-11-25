//! WHATWG URL parsing and host normalization.

use anyhow::{Result, anyhow, bail};

/// Lowercase, no IPv6 brackets, no trailing dot: the form hosts are compared in.
pub fn norm_host(h: &str) -> String {
    let h = h.trim().to_ascii_lowercase();
    let h = h
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(&h);
    h.trim_end_matches('.').to_string()
}

/// Parse an http(s) URL with the WHATWG parser (the one reqwest uses). Everything that decides
/// "which host will this request hit" must go through here: a hand-rolled authority splitter
/// disagrees with the real client on inputs like `http://evil.example\@allowed.example/`.
pub fn parse_web_url(url: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(url.trim()).map_err(|e| anyhow!("invalid URL: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        bail!(
            "only http:// and https:// targets are accepted (got '{}')",
            u.scheme()
        );
    }
    if u.host_str().is_none_or(str::is_empty) {
        bail!("no host in URL");
    }
    Ok(u)
}

/// Host of an http(s) URL, as the HTTP client will resolve it.
pub fn url_host(url: &str) -> Result<String> {
    Ok(parse_web_url(url)?
        .host_str()
        .map(norm_host)
        .unwrap_or_default())
}
