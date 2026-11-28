use anyhow::Result;
use reqwest::blocking::Client;
use std::time::Duration;

/// Follow at most 5 redirects, and never to another host (scope/SSRF guard).
pub fn same_host_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|a| {
        let first = a
            .previous()
            .first()
            .and_then(|u| u.host_str().map(str::to_owned));
        if a.previous().len() >= 5 {
            a.stop()
        } else if first.as_deref() != a.url().host_str() {
            a.stop()
        } else {
            a.follow()
        }
    })
}

pub fn client(redirects: bool) -> Result<Client> {
    let mut b = crate::network::utils::with_connect_timeout(Client::builder())
        .timeout(Duration::from_secs(15))
        .redirect(if redirects {
            same_host_redirects()
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent("readyhai");
    // Running on the bare host (not in the readyhai container) `host.docker.internal` does not
    // resolve; the scanned app is then on this machine's loopback.
    {
        use std::net::ToSocketAddrs;
        if ("host.docker.internal", 80).to_socket_addrs().is_err() {
            b = b.resolve(
                "host.docker.internal",
                std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            );
        }
    }
    Ok(b.build()?)
}

/// Host part of an http(s) URL (no userinfo, no port).
/// Host as the HTTP client will resolve it (WHATWG URL parsing), so scope and
/// loopback decisions match the connection actually made.
pub fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| {
                h.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_ascii_lowercase()
            })
        })
        .unwrap_or_default()
}

pub fn is_local(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0") || host.ends_with(".localhost")
}

pub fn origin_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    format!("{scheme}://{auth}")
}

/// Rewrite loopback hosts so a container can reach the host machine.
pub fn container_url(url: &str) -> (String, bool) {
    let h = host_of(url);
    if is_local(&h) {
        let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
        let (auth, tail) = match rest.find(['/', '?', '#']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let port = if h == "::1" {
            auth.rsplit_once("]:").map(|x| x.1)
        } else {
            auth.rsplit_once(':').map(|x| x.1)
        };
        let port = port.filter(|p| p.chars().all(|c| c.is_ascii_digit()));
        let a = match port {
            Some(p) => format!("host.docker.internal:{p}"),
            None => "host.docker.internal".to_string(),
        };
        (format!("{scheme}://{a}{tail}"), true)
    } else {
        // an explicit host.docker.internal target still needs the host-gateway mapping on Linux
        (url.to_string(), h == "host.docker.internal")
    }
}

pub fn discover_openapi(base: &str) -> Option<String> {
    let c = client(true).ok()?;
    let origin = origin_of(base);
    for p in [
        "/openapi.json",
        "/docs/openapi.json",
        "/api/openapi.json",
        "/swagger.json",
    ] {
        let u = format!("{origin}{p}");
        if let Ok(r) = c.get(&u).send()
            && r.status().is_success()
        {
            let ct = r
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            if ct.contains("json") || ct.contains("yaml") {
                return Some(u);
            }
        }
    }
    None
}

pub fn has_shell_unsafe_chars(url: &str) -> bool {
    url.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '\'' | '"' | '`' | ';' | '$' | '\\' | '&' | '|' | '<' | '>' | '(' | ')'
            )
    })
}
