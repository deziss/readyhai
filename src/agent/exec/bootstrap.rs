use std::collections::BTreeMap;
use serde_json::Value;

use super::clients::{Clients, OutReq};
use super::credentials::strip_ctl;

/// Mode used by [`LoginBootstrap`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LoginMode {
    #[default]
    Form,
    Json,
}

/// Optional login-endpoint bootstrap to obtain session cookies and/or a bearer token.
/// Never serialized into reports or prompts; credentials travel only to the validated target origin.
#[derive(Clone)]
pub struct LoginBootstrap {
    pub login_url: String,
    pub method: String,
    pub mode: LoginMode,
    pub username: String,
    pub password: String,
    pub user_field: String,
    pub pass_field: String,
    pub csrf_page_url: Option<String>,
    pub csrf_field: Option<String>,
    pub token_json_path: Option<String>,
}

impl Default for LoginBootstrap {
    fn default() -> Self {
        LoginBootstrap {
            login_url: String::new(),
            method: "POST".into(),
            mode: LoginMode::Form,
            username: String::new(),
            password: String::new(),
            user_field: "username".into(),
            pass_field: "password".into(),
            csrf_page_url: None,
            csrf_field: None,
            token_json_path: None,
        }
    }
}

impl std::fmt::Debug for LoginBootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginBootstrap")
            .field("login_url", &self.login_url)
            .field("mode", &self.mode)
            .finish()
    }
}

pub(crate) fn extract_set_cookies(headers: &[(String, String)], jar: &mut BTreeMap<String, String>) {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("set-cookie")
            && let Some(nv) = v.split(';').next()
            && let Some((name, val)) = nv.split_once('=')
        {
            let n = strip_ctl(name);
            let val = strip_ctl(val);
            if !n.is_empty() {
                jar.insert(n, val);
            }
        }
    }
}

pub(crate) fn format_cookie_jar(jar: &BTreeMap<String, String>) -> String {
    jar.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(crate) fn extract_csrf_from_html(html: &str, custom_field: Option<&str>) -> Option<(String, String)> {
    // Match hidden inputs or meta csrf-token without allocating huge captures.
    let input_re = regex::Regex::new(r#"(?is)<input\b[^>]*>"#).ok()?;
    let attr_name = regex::Regex::new(r#"(?i)\bname\s*=\s*["']([^"']+)["']"#).ok()?;
    let attr_val = regex::Regex::new(r#"(?i)\bvalue\s*=\s*["']([^"']*)["']"#).ok()?;
    let candidates: Vec<&str> = match custom_field {
        Some(f) => vec![f],
        None => vec![
            "_csrf",
            "csrf_token",
            "csrftoken",
            "csrfmiddlewaretoken",
            "authenticity_token",
            "__requestverificationtoken",
            "_token",
        ],
    };
    for m in input_re.find_iter(html) {
        let tag = m.as_str();
        let Some(n) = attr_name
            .captures(tag)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
        else {
            continue;
        };
        if candidates.iter().any(|c| n.eq_ignore_ascii_case(c))
            && let Some(v) = attr_val
                .captures(tag)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str())
            && !v.is_empty()
        {
            return Some((n.to_string(), v.to_string()));
        }
    }
    let meta_re = regex::Regex::new(
        r#"(?is)<meta\b[^>]*\bname\s*=\s*["']csrf-token["'][^>]*\bcontent\s*=\s*["']([^"']+)["']"#,
    )
    .ok()?;
    if let Some(v) = meta_re
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .filter(|s| !s.is_empty())
    {
        let field = custom_field.unwrap_or("_csrf").to_string();
        return Some((field, v.to_string()));
    }
    None
}

pub(crate) fn extract_json_path(v: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = v;
    for seg in path.split('.').filter(|s| !s.is_empty()) {
        cur = cur.get(seg)?;
    }
    cur.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Execute a login bootstrap round-trip against the target server.
pub(crate) fn perform_login(
    clients: &Clients,
    role: &str,
    cfg: &LoginBootstrap,
) -> Result<(Option<String>, Option<String>), String> {
    if !clients.is_target_url(&cfg.login_url) {
        return Err("credentials withheld: login_url is outside the target origin".into());
    }
    let mut jar = BTreeMap::new();
    let mut csrf_pair: Option<(String, String)> = None;
    if let Some(csrf_url) = &cfg.csrf_page_url {
        if !clients.is_target_url(csrf_url) {
            return Err("credentials withheld: csrf_page_url is outside the target origin".into());
        }
        let seen = clients.send_with_auth(
            &OutReq {
                method: "GET",
                url: csrf_url,
                body: None,
                headers: &[],
                bearer: None,
            },
            &[],
            true,
        )?;
        extract_set_cookies(&seen.headers, &mut jar);
        csrf_pair = extract_csrf_from_html(&seen.body, cfg.csrf_field.as_deref());
    }
    let body = match cfg.mode {
        LoginMode::Form => {
            let mut dummy = reqwest::Url::parse("http://localhost/").map_err(|e| e.to_string())?;
            {
                let mut qp = dummy.query_pairs_mut();
                qp.append_pair(&cfg.user_field, &cfg.username);
                qp.append_pair(&cfg.pass_field, &cfg.password);
                if let Some((ck, cv)) = &csrf_pair {
                    qp.append_pair(ck, cv);
                }
            }
            (
                "application/x-www-form-urlencoded".to_string(),
                dummy.query().unwrap_or("").to_string(),
            )
        }
        LoginMode::Json => {
            let mut obj = serde_json::Map::new();
            obj.insert(cfg.user_field.clone(), Value::String(cfg.username.clone()));
            obj.insert(cfg.pass_field.clone(), Value::String(cfg.password.clone()));
            if let Some((ck, cv)) = &csrf_pair {
                obj.insert(ck.clone(), Value::String(cv.clone()));
            }
            (
                "application/json".to_string(),
                Value::Object(obj).to_string(),
            )
        }
    };
    let mut login_auth_hdrs = Vec::new();
    if !jar.is_empty() {
        login_auth_hdrs.push(("Cookie".to_string(), format_cookie_jar(&jar)));
    }
    let seen = clients.send_with_auth(
        &OutReq {
            method: cfg.method.trim(),
            url: &cfg.login_url,
            body: Some(&body),
            headers: &[],
            bearer: None,
        },
        &login_auth_hdrs,
        true,
    )?;
    if !(200..400).contains(&seen.status) {
        return Err(format!(
            "login bootstrap for role '{role}' returned HTTP {}",
            seen.status
        ));
    }
    extract_set_cookies(&seen.headers, &mut jar);
    let mut got_any = false;
    let mut out_cookie = None;
    if !jar.is_empty() {
        out_cookie = Some(format_cookie_jar(&jar));
        got_any = true;
    }
    let mut out_token = None;
    if let Ok(json_val) = serde_json::from_str::<Value>(seen.body.trim()) {
        let token = cfg
            .token_json_path
            .as_deref()
            .and_then(|p| extract_json_path(&json_val, p))
            .or_else(|| {
                ["access_token", "token", "jwt", "id_token"]
                    .into_iter()
                    .find_map(|p| extract_json_path(&json_val, p))
            });
        if let Some(tok) = token {
            let cleaned = strip_ctl(&tok);
            if !cleaned.is_empty() {
                out_token = Some(cleaned);
                got_any = true;
            }
        }
    }
    if !got_any {
        return Err(format!(
            "login bootstrap for role '{role}' yielded neither Set-Cookie nor token"
        ));
    }
    Ok((out_cookie, out_token))
}
