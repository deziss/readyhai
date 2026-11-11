//! Explorer: turns planned cases into real HTTP requests, judges them with the oracle, re-runs
//! safe failures to detect flakiness, and writes down exactly what was sent (reproduction curl)
//! and seen.
//!
//! Credential rules (all enforced in [`Clients::send`], the only place a request leaves the box):
//! * `RH_<ROLE>_TOKEN` is attached only when the request's scheme, host and port equal the run's
//!   target (exact match);
//! * it is attached only through a client that validates TLS certificates: requests that carry a
//!   real credential never go through the client that accepts invalid certificates;
//! * a redirect is followed only for a safe GET/HEAD liveness/content/robustness case, only to the
//!   same origin (exact scheme, host and port), at most [`MAX_REDIRECTS`] hops, and every hop goes
//!   through [`Clients::send`] again: a credential cannot follow a `Location` to another host.
//!   Authorization cases, sensitive-file probes and forged-token requests are never redirected:
//!   their raw status is the evidence.
//!
//! Verdict rules: every outcome (the base request, an adaptive-mutation probe, a concurrency
//! burst, a stateful chain) is judged by `oracle` (`judge`, `judge_burst`, `judge_stateful`) with
//! severities from `triage::severity_for`. A mutation probe and a burst are their own sub-cases
//! (`<id>-M1`, `<id>-B`) with their own curl and evidence; they never overwrite the base verdict.
use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::budget::RunBudget;
use super::oracle::{
    self, BurstFacts, CORS_PROBE_ORIGIN, Observation, OracleOutcome, Severity, Technique, Verdict,
    is_cors_case,
};
use super::types::{
    AttemptRecord, BlockReason, CaseExecutionResult, PlannedCase, ProbeOracle, RedirectHop,
    SRC_AUTH_WALL, SRC_NOT_APPLICABLE, record_creation_response,
};
use crate::llm::{is_sensitive_key, redact_for_llm};

pub const METHODS: [&str; 7] = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
const BODY_CAP: usize = 64 * 1024;
const FORGED_TOKEN: &str = "forged.signature.token123";
const MAX_BURST: usize = 10;
/// Most same-origin redirects the executor follows for one request.
pub const MAX_REDIRECTS: usize = 5;
/// What to do about an auth wall; shared by the BLOCKED results, the ledger's blockers and the report.
pub const NEXT_STEP_AUTH_WALL: &str = "provide test accounts: `readyhai roles init --spec <openapi.json>` writes a roles.toml skeleton; set RH_<ROLE>_TOKEN (e.g. RH_USER_TOKEN) or use a storageState login, then re-run";

/// Canonical upper-case method if (and only if) it is on the allow-list.
pub fn normalize_method(m: &str) -> Option<&'static str> {
    let u = m.trim().to_ascii_uppercase();
    METHODS.iter().copied().find(|k| *k == u)
}

/// State-changing method, whatever its case ("post" is POST).
pub fn is_mutating(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Safe (read-only) method: the only ones the agent ever repeats.
pub fn is_safe_method(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

// ---------------------------------------------------------------- credentials

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

#[derive(Clone, Debug)]
enum HeaderEnvKind {
    FullVar(String),
    ValueVar { name: String, var: String },
}

/// Test credentials per role. Sources: `RH_<ROLE>_TOKEN`, `RH_<ROLE>_COOKIE`, `RH_<ROLE>_HEADER`
/// environment variables, `roles.toml`, login bootstrap, or programmatic builders. The server's
/// own tokens are never used, and secret values never appear in reports or Debug output.
#[derive(Clone, Default)]
pub struct Credentials {
    tokens: BTreeMap<String, String>,
    cookies: BTreeMap<String, String>,
    headers: BTreeMap<String, (String, String)>,
    token_envs: BTreeMap<String, String>,
    header_envs: BTreeMap<String, HeaderEnvKind>,
    pending_logins: BTreeMap<String, LoginBootstrap>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut roles: BTreeSet<&str> = self.tokens.keys().map(String::as_str).collect();
        roles.extend(self.cookies.keys().map(String::as_str));
        roles.extend(self.headers.keys().map(String::as_str));
        f.debug_struct("Credentials")
            .field("roles", &roles.into_iter().collect::<Vec<_>>())
            .finish()
    }
}

fn role_key(role: &str) -> String {
    role.trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn strip_ctl(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
        .collect()
}

fn extract_set_cookies(headers: &[(String, String)], jar: &mut BTreeMap<String, String>) {
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

fn format_cookie_jar(jar: &BTreeMap<String, String>) -> String {
    jar.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn extract_csrf_from_html(html: &str, custom_field: Option<&str>) -> Option<(String, String)> {
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

fn extract_json_path(v: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = v;
    for seg in path.split('.').filter(|s| !s.is_empty()) {
        cur = cur.get(seg)?;
    }
    cur.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

impl Credentials {
    pub fn none() -> Self {
        Credentials::default()
    }

    pub fn from_env() -> Self {
        let mut c = Self::from_env_pairs(std::env::vars());
        if let Ok(path) = std::env::var("RH_ROLES_FILE")
            && !path.trim().is_empty()
            && let Ok(roles) = crate::qa::roles::Roles::load(std::path::Path::new(path.trim()))
        {
            c = c.with_roles(&roles);
        }
        c
    }

    /// Deterministic builder from arbitrary `(key, value)` environment pairs (used by tests and `from_env`).
    pub fn from_env_pairs<I, K, V>(vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let map: BTreeMap<String, String> = vars
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let mut c = Credentials::default();
        for (k, v) in &map {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(role) = k.strip_prefix("RH_").and_then(|r| r.strip_suffix("_TOKEN"))
                && !role.is_empty()
            {
                c = c.with(role, trimmed);
            } else if let Some(role) = k
                .strip_prefix("RH_")
                .and_then(|r| r.strip_suffix("_COOKIE"))
                && !role.is_empty()
            {
                c = c.with_cookie(role, trimmed);
            } else if let Some(role) = k
                .strip_prefix("RH_")
                .and_then(|r| r.strip_suffix("_HEADER"))
                && !role.is_empty()
            {
                if let Some((hname, hval)) = trimmed.split_once(':') {
                    let hn = hname.trim();
                    let hv = hval.trim();
                    if !hn.is_empty() && !hv.is_empty() {
                        c = c.with_header(role, hn, hv);
                        c.header_envs
                            .insert(role_key(role), HeaderEnvKind::FullVar(k.clone()));
                    }
                } else {
                    let name_var = format!("RH_{}_HEADER_NAME", role_key(role));
                    let hname = map
                        .get(&name_var)
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .unwrap_or("X-API-Key");
                    c = c.with_header(role, hname, trimmed);
                    c.header_envs.insert(
                        role_key(role),
                        HeaderEnvKind::ValueVar {
                            name: hname.to_string(),
                            var: k.clone(),
                        },
                    );
                }
            } else if let Some(role) = k
                .strip_prefix("RH_")
                .and_then(|r| r.strip_suffix("_LOGIN_URL"))
                && !role.is_empty()
            {
                let rk = role_key(role);
                let user = map
                    .get(&format!("RH_{rk}_USER"))
                    .map(|s| s.trim())
                    .unwrap_or("");
                let pass = map
                    .get(&format!("RH_{rk}_PASS"))
                    .map(|s| s.trim())
                    .unwrap_or("");
                if !user.is_empty() && !pass.is_empty() {
                    let mode = match map
                        .get(&format!("RH_{rk}_LOGIN_MODE"))
                        .map(|s| s.trim().to_ascii_lowercase())
                        .as_deref()
                    {
                        Some("json") => LoginMode::Json,
                        _ => LoginMode::Form,
                    };
                    let csrf_page_url = map
                        .get(&format!("RH_{rk}_CSRF_URL"))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    c.pending_logins.insert(
                        rk,
                        LoginBootstrap {
                            login_url: trimmed.to_string(),
                            mode,
                            username: user.to_string(),
                            password: pass.to_string(),
                            csrf_page_url,
                            ..LoginBootstrap::default()
                        },
                    );
                }
            }
        }
        c
    }

    pub fn with(mut self, role: &str, token: &str) -> Self {
        let cleaned = strip_ctl(token);
        if !cleaned.is_empty() {
            self.tokens.insert(role_key(role), cleaned);
        }
        self
    }

    pub fn with_cookie(mut self, role: &str, cookie: &str) -> Self {
        let cleaned = strip_ctl(cookie);
        if !cleaned.is_empty() {
            self.cookies.insert(role_key(role), cleaned);
        }
        self
    }

    pub fn with_header(mut self, role: &str, header_name: &str, value: &str) -> Self {
        let pair = (header_name.trim().to_string(), value.trim().to_string());
        if sanitize_custom_headers(std::slice::from_ref(&pair), true).is_ok() && !pair.1.is_empty()
        {
            self.headers.insert(role_key(role), pair);
        }
        self
    }

    /// Merge role credentials from [`crate::qa::roles::Roles`]. Secret values remain read from env
    /// or `storageState` on disk and are excluded from Debug/reports.
    pub fn with_roles(mut self, roles: &crate::qa::roles::Roles) -> Self {
        use crate::qa::roles::AuthKind;
        for role in &roles.roles {
            let rk = role_key(&role.name);
            match role.auth {
                AuthKind::Bearer => {
                    if let Some((_, val)) = role.credential() {
                        let tok = val.strip_prefix("Bearer ").unwrap_or(&val).trim();
                        self = self.with(&role.name, tok);
                        if let Some(ev) = &role.token_env {
                            self.token_envs.insert(rk, ev.clone());
                        }
                    }
                }
                AuthKind::Header => {
                    if let Some((hname, hval)) = role.credential() {
                        self = self.with_header(&role.name, &hname, &hval);
                        if let Some(ev) = &role.token_env {
                            self.header_envs.insert(
                                rk,
                                HeaderEnvKind::ValueVar {
                                    name: hname,
                                    var: ev.clone(),
                                },
                            );
                        }
                    }
                }
                AuthKind::Basic => {
                    if let Some((hname, hval)) = role.credential() {
                        self = self.with_header(&role.name, &hname, &hval);
                    }
                }
                AuthKind::Cookie => {
                    if let Some(ck) = role.cookie_header(&roles.dir) {
                        self = self.with_cookie(&role.name, &ck);
                    }
                }
                AuthKind::None => {}
            }
        }
        self
    }

    pub fn token(&self, role: &str) -> Option<&str> {
        self.tokens.get(&role_key(role)).map(|s| s.as_str())
    }

    pub fn cookie(&self, role: &str) -> Option<&str> {
        self.cookies.get(&role_key(role)).map(|s| s.as_str())
    }

    pub fn header(&self, role: &str) -> Option<(&str, &str)> {
        self.headers
            .get(&role_key(role))
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Name of the environment variable that supplies `role`'s bearer token.
    pub fn env_var(role: &str) -> String {
        format!("RH_{}_TOKEN", role_key(role))
    }

    pub fn cookie_env_var(role: &str) -> String {
        format!("RH_{}_COOKIE", role_key(role))
    }

    pub fn header_env_var(role: &str) -> String {
        format!("RH_{}_HEADER", role_key(role))
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.token(role).is_some() || self.cookie(role).is_some() || self.header(role).is_some()
    }

    pub fn has_pending_logins(&self) -> bool {
        !self.pending_logins.is_empty()
    }

    /// Authenticate via a login page/endpoint on the validated target origin and capture resulting
    /// `Set-Cookie` and/or JSON token credentials for `role`.
    pub fn bootstrap_login(
        &mut self,
        clients: &Clients,
        role: &str,
        cfg: &LoginBootstrap,
    ) -> Result<(), String> {
        if !clients.is_target_url(&cfg.login_url) {
            return Err("credentials withheld: login_url is outside the target origin".into());
        }
        let mut jar = BTreeMap::new();
        let mut csrf_pair: Option<(String, String)> = None;
        if let Some(csrf_url) = &cfg.csrf_page_url {
            if !clients.is_target_url(csrf_url) {
                return Err(
                    "credentials withheld: csrf_page_url is outside the target origin".into(),
                );
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
                let mut dummy =
                    reqwest::Url::parse("http://localhost/").map_err(|e| e.to_string())?;
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
        if !jar.is_empty() {
            let ck = format_cookie_jar(&jar);
            self.cookies.insert(role_key(role), ck);
            got_any = true;
        }
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
                    self.tokens.insert(role_key(role), cleaned);
                    got_any = true;
                }
            }
        }
        if !got_any {
            return Err(format!(
                "login bootstrap for role '{role}' yielded neither Set-Cookie nor token"
            ));
        }
        Ok(())
    }

    /// Execute any env-configured `RH_<ROLE>_LOGIN_URL` bootstraps, returning status notes.
    pub fn bootstrap_pending(&mut self, clients: &Clients) -> Vec<String> {
        let pending: Vec<(String, LoginBootstrap)> = self
            .pending_logins
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.pending_logins.clear();
        let mut notes = Vec::new();
        for (rk, cfg) in pending {
            let role_lower = rk.to_ascii_lowercase();
            match self.bootstrap_login(clients, &role_lower, &cfg) {
                Ok(()) => notes.push(format!(
                    "login bootstrap obtained credentials for role '{role_lower}'"
                )),
                Err(why) => {
                    notes.push(format!("login bootstrap for '{role_lower}' skipped: {why}"))
                }
            }
        }
        notes
    }

    /// The role the planner acts as in ordinary authenticated cases: `user`, else `alice` (the
    /// first actor of the stateful chains), else the first configured role that does not look
    /// privileged. None without a credential, or with privileged ones only: an administrator
    /// token is never picked to probe with.
    pub fn actor(&self) -> Option<String> {
        ["user", "alice"]
            .into_iter()
            .find(|r| self.has_role(r))
            .map(String::from)
            .or_else(|| {
                let mut keys: BTreeSet<&str> = self.tokens.keys().map(String::as_str).collect();
                keys.extend(self.cookies.keys().map(String::as_str));
                keys.extend(self.headers.keys().map(String::as_str));
                keys.into_iter()
                    .find(|k| {
                        !["ADMIN", "ROOT", "SUPER", "SYSTEM"]
                            .iter()
                            .any(|p| k.contains(p))
                    })
                    .map(|k| k.to_ascii_lowercase())
            })
    }

    /// Return the first configured Bearer token that parses as a 3-part JWT, preferring a
    /// non-privileged role so privilege-escalation tampering starts from ordinary claims.
    pub fn jwt_sample(&self) -> Option<(String, &str)> {
        let is_priv = |k: &str| {
            ["ADMIN", "ROOT", "SUPER", "SYSTEM", "STAFF"]
                .iter()
                .any(|p| k.to_ascii_uppercase().contains(p))
        };
        let mut sorted: Vec<(&String, &String)> = self.tokens.iter().collect();
        sorted.sort_by_key(|(k, _)| is_priv(k));
        sorted
            .into_iter()
            .find(|(_, v)| v.split('.').count() == 3)
            .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
    }

    /// Return all configured non-admin role names in deterministic order.
    pub fn non_admin_roles(&self) -> Vec<String> {
        let mut keys: BTreeSet<String> = self
            .tokens
            .keys()
            .chain(self.cookies.keys())
            .chain(self.headers.keys())
            .filter(|k| {
                !["ADMIN", "ROOT", "SUPER", "SYSTEM", "STAFF"]
                    .iter()
                    .any(|p| k.contains(p))
            })
            .map(|k| k.to_ascii_lowercase())
            .collect();
        let mut out = Vec::new();
        for pref in ["user", "alice", "bob"] {
            if keys.remove(pref) {
                out.push(pref.to_string());
            }
        }
        out.extend(keys);
        out
    }

    /// Return the first configured privileged/admin role (`admin`, `superadmin`, `root`, `staff`),
    /// used strictly for positive baseline contract reads on privileged endpoints.
    pub fn admin_role(&self) -> Option<String> {
        let mut keys: BTreeSet<String> = self
            .tokens
            .keys()
            .chain(self.cookies.keys())
            .chain(self.headers.keys())
            .filter(|k| {
                let up = k.to_ascii_uppercase();
                ["ADMIN", "ROOT", "SUPER", "SYSTEM", "STAFF"]
                    .iter()
                    .any(|p| up.contains(p))
            })
            .map(|k| k.to_ascii_lowercase())
            .collect();
        for pref in ["admin", "superadmin", "superuser", "staff", "root"] {
            if keys.remove(pref) {
                return Some(pref.to_string());
            }
        }
        keys.into_iter().next()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    None,
    Forged,
    Role(String),
}

/// Explicit `role` wins; legacy cases (no role) are inferred from the title/hint like before.
pub fn auth_for(case: &PlannedCase) -> Auth {
    if let Some(r) = case
        .role
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        return match r.to_ascii_lowercase().as_str() {
            "anon" | "anonymous" | "none" | "unauthenticated" | "raw_jwt" => Auth::None,
            "forged" => Auth::Forged,
            _ => Auth::Role(r.to_string()),
        };
    }
    let title = case.title.to_ascii_lowercase();
    let hint = case.input_hint.to_ascii_lowercase();
    if title.contains("forged") {
        return Auth::Forged;
    }
    if case.technique == "authz"
        && (title.contains("unauth")
            || hint.contains("without auth")
            || hint.contains("no auth")
            || case.expected_status.is_some_and(|s| s == 401 || s == 403)
            || case.component.starts_with("/."))
    {
        return Auth::None;
    }
    if case.technique == "authz" {
        return Auth::None;
    }
    Auth::Role("user".into())
}

/// An `Authorization: Bearer ...` value ready to send. `real` = it is a configured test
/// credential (RH_<ROLE>_TOKEN), not the public forged-token constant.
#[derive(Clone)]
pub struct Bearer {
    pub header: String,
    pub real: bool,
}

impl std::fmt::Debug for Bearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bearer(real={}, ..)", self.real)
    }
}

pub struct ResolvedAuth {
    pub bearer: Option<Bearer>,
    pub extra_headers: Vec<(String, String)>,
    pub authenticated: bool,
    pub real: bool,
    pub note: Option<String>,
}

pub fn resolve_auth(auth: &Auth, creds: &Credentials) -> ResolvedAuth {
    match auth {
        Auth::None => ResolvedAuth {
            bearer: None,
            extra_headers: vec![],
            authenticated: false,
            real: false,
            note: None,
        },
        Auth::Forged => ResolvedAuth {
            bearer: Some(Bearer {
                header: format!("Bearer {FORGED_TOKEN}"),
                real: false,
            }),
            extra_headers: vec![],
            authenticated: true,
            real: false,
            note: None,
        },
        Auth::Role(r) => {
            let bearer = creds.token(r).map(|t| Bearer {
                header: format!("Bearer {t}"),
                real: true,
            });
            let mut extra_headers = Vec::new();
            if let Some(ck) = creds.cookie(r) {
                extra_headers.push(("Cookie".into(), ck.to_string()));
            }
            if let Some((hk, hv)) = creds.header(r) {
                extra_headers.push((hk.to_string(), hv.to_string()));
            }
            let authenticated = bearer.is_some() || !extra_headers.is_empty();
            if authenticated {
                ResolvedAuth {
                    bearer,
                    extra_headers,
                    authenticated: true,
                    real: true,
                    note: None,
                }
            } else {
                ResolvedAuth {
                    bearer: None,
                    extra_headers: vec![],
                    authenticated: false,
                    real: false,
                    note: Some(format!(
                        "no credential for role '{r}': request sent without Authorization (set {})",
                        Credentials::env_var(r)
                    )),
                }
            }
        }
    }
}

// ---------------------------------------------------------------- request construction

#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub method: &'static str,
    pub url: String,
    /// Path (+query from the component) as sent.
    pub path: String,
    /// (content-type, body) for body methods.
    pub body: Option<(String, String)>,
    pub auth: Auth,
    /// Decoded query/body values we sent (for reflection checks).
    pub sent_values: Vec<String>,
    /// Extra request headers (the CORS probe's `Origin`).
    pub extra_headers: Vec<(String, String)>,
}

impl RequestSpec {
    /// The `Origin` header this request carries, if any.
    pub fn origin(&self) -> Option<&str> {
        self.extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
            .map(|(_, v)| v.as_str())
    }
}

pub fn normalize_component(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("empty component".into());
    }
    if t.len() > 2048 {
        return Err("component longer than 2048 bytes".into());
    }
    if t.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("component contains whitespace or control characters".into());
    }
    if t.starts_with("//") || t.contains("://") {
        return Err("component must be a path on the target, not an absolute URL".into());
    }
    if t.contains('{') || t.contains('}') {
        return Err("unresolved path template placeholder".into());
    }
    Ok(if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    })
}

fn form_key_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.\-\[\]]*=").unwrap())
}

fn looks_like_form(p: &str) -> bool {
    form_key_re().is_match(p.trim_start())
}

/// Payload as decoded key/value pairs: JSON object, `k=v&k2=v2`, or free text (`q=`).
pub fn payload_pairs(p: &str) -> Vec<(String, String)> {
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(p.trim()) {
        return m
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    match v {
                        Value::String(s) => s,
                        other => other.to_string(),
                    },
                )
            })
            .collect();
    }
    if looks_like_form(p) {
        return p
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (kv.to_string(), String::new()),
            })
            .collect();
    }
    vec![("q".to_string(), p.to_string())]
}

/// (content-type, body) for a body payload: JSON, form-encoded or plain text.
pub fn body_and_type(p: &str) -> (String, String) {
    let t = p.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        ("application/json".into(), p.to_string())
    } else if looks_like_form(p) {
        ("application/x-www-form-urlencoded".into(), p.to_string())
    } else {
        ("text/plain".into(), p.to_string())
    }
}

fn string_leaves(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| string_leaves(x, out)),
        Value::Object(m) => m.values().for_each(|x| string_leaves(x, out)),
        _ => {}
    }
}

/// Safe, bounded validation of custom request headers. Rejects control/CRLF/NUL bytes,
/// invalid token names, and hop-by-hop smuggling headers. `allow_auth_header` is only enabled
/// for internal deterministic token-tampering probes (`role = "raw_jwt"`), never for LLM cases.
pub fn sanitize_custom_headers(
    headers: &[(String, String)],
    allow_auth_header: bool,
) -> Result<Vec<(String, String)>, String> {
    if headers.len() > 16 {
        return Err("too many custom headers (max 16)".into());
    }
    let mut out = Vec::with_capacity(headers.len());
    for (k, v) in headers {
        let name = k.trim();
        if name.is_empty() || name.len() > 64 {
            return Err("invalid custom header name length".into());
        }
        if !name.bytes().all(|b| {
            b.is_ascii_graphic()
                && !matches!(
                    b,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        }) {
            return Err(format!("invalid character in header name '{name}'"));
        }
        if v.len() > 1024
            || v.chars()
                .any(|c| c == '\r' || c == '\n' || c == '\0' || (c.is_control() && c != '\t'))
        {
            return Err(format!("control or oversized value in header '{name}'"));
        }
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "te"
                | "trailer"
                | "upgrade"
                | "proxy-connection"
        ) {
            return Err(format!("hop-by-hop header '{name}' is not allowed"));
        }
        if matches!(
            lower.as_str(),
            "authorization" | "proxy-authorization" | "cookie"
        ) && (!allow_auth_header || lower != "authorization")
        {
            return Err(format!("credential header '{name}' cannot be overridden"));
        }
        out.push((name.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Validate an explicit `Content-Type` header override against control/CRLF injection.
pub fn validate_content_type(ct: &str) -> Result<String, String> {
    let t = ct.trim();
    if t.is_empty() || t.len() > 128 {
        return Err("content_type must be 1..=128 characters".into());
    }
    if t.chars().any(|c| c.is_control()) || !t.contains('/') {
        return Err("invalid content_type".into());
    }
    Ok(t.to_string())
}

/// Validate and build the request for a case. Errors mean "this case must not be sent".
pub fn build_request(case: &PlannedCase, target: &str) -> Result<RequestSpec, String> {
    let method = normalize_method(&case.method).ok_or_else(|| {
        format!(
            "method '{}' is not allowed (GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE only)",
            case.method.chars().take(16).collect::<String>()
        )
    })?;
    let base = reqwest::Url::parse(target).map_err(|e| format!("bad target URL: {e}"))?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err("target is not an http(s) URL".into());
    }
    let path = normalize_component(&case.component)?;
    let mut url = reqwest::Url::parse(&format!("{}{}", target.trim_end_matches('/'), path))
        .map_err(|e| format!("bad URL: {e}"))?;
    if url.host_str() != base.host_str()
        || url.port_or_known_default() != base.port_or_known_default()
        || url.scheme() != base.scheme()
    {
        return Err("request would leave the target origin".into());
    }
    let allow_auth_hdr = case
        .role
        .as_deref()
        .is_some_and(|r| r.trim().eq_ignore_ascii_case("raw_jwt"))
        && case.source.as_deref() != Some("llm");
    let custom_headers = sanitize_custom_headers(&case.headers, allow_auth_hdr)?;
    let explicit_ct = match case.content_type.as_deref() {
        Some(ct) => Some(validate_content_type(ct)?),
        None => None,
    };
    let mut sent_values: Vec<String> = url.query_pairs().map(|(_, v)| v.into_owned()).collect();
    let mut body = None;
    if let Some(p) = case.payload.as_deref().filter(|p| !p.is_empty()) {
        if matches!(method, "GET" | "HEAD" | "OPTIONS") {
            // payloads for bodiless methods belong in the query string
            let pairs = payload_pairs(p);
            url.query_pairs_mut()
                .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            sent_values.extend(pairs.into_iter().map(|(_, v)| v));
        } else {
            let (inferred_ct, b) = body_and_type(p);
            let ct = explicit_ct.clone().unwrap_or(inferred_ct);
            match serde_json::from_str::<Value>(&b) {
                Ok(v) if ct.starts_with("application/json") => string_leaves(&v, &mut sent_values),
                _ => sent_values.extend(payload_pairs(p).into_iter().map(|(_, v)| v)),
            }
            sent_values.push(p.to_string());
            body = Some((ct, b));
        }
    }
    let mut extra_headers = vec![];
    for (k, v) in custom_headers {
        if k.eq_ignore_ascii_case("content-type") && body.is_some() {
            continue;
        }
        extra_headers.push((k, v));
    }
    if body.is_none()
        && let Some(ct) = explicit_ct
        && !extra_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        extra_headers.push(("Content-Type".to_string(), ct));
    }
    if is_cors_case(case)
        && !extra_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("origin"))
    {
        // a CORS probe is only meaningful with a foreign Origin
        extra_headers.push(("Origin".to_string(), CORS_PROBE_ORIGIN.to_string()));
        extra_headers.push((
            "Access-Control-Request-Method".to_string(),
            "GET".to_string(),
        ));
    }
    let auth = if allow_auth_hdr {
        Auth::None
    } else {
        auth_for(case)
    };
    Ok(RequestSpec {
        method,
        path: path.clone(),
        url: url.to_string(),
        body,
        auth,
        sent_values,
        extra_headers,
    })
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Secret-safe curl auth arguments for `auth` given configured `creds`.
/// Uses shell placeholders (`${RH_<ROLE>_TOKEN}`, `${RH_<ROLE>_COOKIE}`, `${RH_<ROLE>_HEADER}`)
/// and never writes raw secret values into repro strings.
pub fn curl_auth_args_for(auth: &Auth, creds: &Credentials) -> Vec<String> {
    match auth {
        Auth::None => vec![],
        Auth::Forged => vec![format!(
            "-H {}",
            sq(&format!("Authorization: Bearer {FORGED_TOKEN}"))
        )],
        Auth::Role(r) => {
            let rk = role_key(r);
            let mut args = Vec::new();
            let has_token = creds.token(r).is_some();
            let has_cookie = creds.cookie(r).is_some();
            let has_header = creds.header(r).is_some();
            if has_token || (!has_cookie && !has_header) {
                let var = creds
                    .token_envs
                    .get(&rk)
                    .cloned()
                    .unwrap_or_else(|| Credentials::env_var(r));
                args.push(format!("-H \"Authorization: Bearer ${{{var}}}\""));
            }
            if has_cookie {
                args.push(format!(
                    "-H \"Cookie: ${{{}}}\"",
                    Credentials::cookie_env_var(r)
                ));
            }
            if has_header {
                match creds.header_envs.get(&rk) {
                    Some(HeaderEnvKind::ValueVar { name, var }) => {
                        args.push(format!("-H \"{name}: ${{{var}}}\""));
                    }
                    Some(HeaderEnvKind::FullVar(var)) => {
                        args.push(format!("-H \"${{{var}}}\""));
                    }
                    None => {
                        if let Some((name, _)) = creds.header(r) {
                            args.push(format!(
                                "-H \"{name}: ${{{}}}\"",
                                Credentials::header_env_var(r)
                            ));
                        }
                    }
                }
            }
            args
        }
    }
}

/// The curl `-H` argument for an actor. Tokens are never written: a real role becomes the
/// `${RH_<ROLE>_TOKEN}` placeholder (double-quoted so the shell expands it from the environment).
pub fn curl_auth_arg(auth: &Auth) -> Option<String> {
    match auth {
        Auth::Role(r) => Some(format!(
            "-H \"Authorization: Bearer ${{{}}}\"",
            Credentials::env_var(r)
        )),
        Auth::Forged => Some(format!(
            "-H {}",
            sq(&format!("Authorization: Bearer {FORGED_TOKEN}"))
        )),
        Auth::None => None,
    }
}

/// Reproduction command using configured multi-modal credentials (`Token`, `Cookie`, `Header`),
/// with secret placeholders instead of raw values.
pub fn curl_for_auth(spec: &RequestSpec, creds: &Credentials) -> String {
    let mut p: Vec<String> = vec!["curl -sS".into()];
    if spec.method == "HEAD" {
        p.push("-I -X HEAD".into());
    } else {
        p.push(format!("-i -X {}", spec.method));
    }
    p.extend(curl_auth_args_for(&spec.auth, creds));
    for (k, v) in &spec.extra_headers {
        p.push(format!("-H {}", sq(&format!("{k}: {v}"))));
    }
    if let Some((ct, body)) = &spec.body {
        p.push(format!("-H {}", sq(&format!("Content-Type: {ct}"))));
        p.push(format!("--data-raw {}", sq(body)));
    }
    p.push(sq(&spec.url));
    p.join(" ")
}

/// Reproduction command: same method, same URL (incl. query), same body, every dynamic string
/// single-quoted. The token comes from the environment, never from the report.
pub fn curl_for(spec: &RequestSpec) -> String {
    let mut p: Vec<String> = vec!["curl -sS".into()];
    if spec.method == "HEAD" {
        p.push("-I -X HEAD".into());
    } else {
        p.push(format!("-i -X {}", spec.method));
    }
    if let Some(a) = curl_auth_arg(&spec.auth) {
        p.push(a);
    }
    for (k, v) in &spec.extra_headers {
        p.push(format!("-H {}", sq(&format!("{k}: {v}"))));
    }
    if let Some((ct, body)) = &spec.body {
        p.push(format!("-H {}", sq(&format!("Content-Type: {ct}"))));
        p.push(format!("--data-raw {}", sq(body)));
    }
    p.push(sq(&spec.url));
    p.join(" ")
}

// ---------------------------------------------------------------- transport

/// What one response looked like.
pub struct Seen {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub latency_ms: u64,
}

/// One outgoing request. `bearer` is the only way a credential can be attached.
pub struct OutReq<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub body: Option<&'a (String, String)>,
    pub headers: &'a [(String, String)],
    pub bearer: Option<&'a Bearer>,
}

/// The HTTP clients of one run, bound to its target.
///
/// * `lax` accepts invalid certificates (so an unauthenticated probe of a self-signed staging
///   host still works) and is never used for a request that carries a real credential;
/// * `strict` validates certificates and carries every real credential;
/// * a credential is attached only when the request URL has the target's scheme, host and port.
pub struct Clients {
    strict: Option<reqwest::blocking::Client>,
    lax: reqwest::blocking::Client,
    target: reqwest::Url,
}

fn base_builder(timeout: Duration) -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        // a redirect is an observation, and it must never carry credentials to another host
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("ReadyHai-Agent/1.0")
}

fn err_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

impl Clients {
    pub fn new(timeout: Duration, target: &reqwest::Url) -> Result<Self, reqwest::Error> {
        let lax = base_builder(timeout)
            .danger_accept_invalid_certs(true)
            .build()?;
        let strict = base_builder(timeout).build().ok();
        Ok(Clients {
            strict,
            lax,
            target: target.clone(),
        })
    }

    /// Exact scheme + host + port match with the run's target.
    pub fn is_target_url(&self, url: &str) -> bool {
        reqwest::Url::parse(url).is_ok_and(|u| {
            u.scheme() == self.target.scheme()
                && u.host_str().is_some()
                && u.host_str() == self.target.host_str()
                && u.port_or_known_default() == self.target.port_or_known_default()
        })
    }

    pub fn send(&self, r: &OutReq) -> Result<Seen, String> {
        self.send_with_auth(r, &[], false)
    }

    pub fn send_resolved(&self, r: &OutReq, auth: &ResolvedAuth) -> Result<Seen, String> {
        self.send_with_auth(r, &auth.extra_headers, auth.real)
    }

    pub fn send_with_auth(
        &self,
        r: &OutReq,
        extra_auth: &[(String, String)],
        extra_real: bool,
    ) -> Result<Seen, String> {
        let has_creds = r.bearer.is_some() || !extra_auth.is_empty();
        if has_creds && !self.is_target_url(r.url) {
            return Err(format!(
                "credentials withheld: the request host is not the run's target host ({})",
                self.target.host_str().unwrap_or("?")
            ));
        }
        let real = needs_validated_tls(r.bearer) || extra_real;
        let client = if real {
            self.strict.as_ref().ok_or_else(|| {
                "credentials withheld: a certificate-validating HTTP client is unavailable"
                    .to_string()
            })?
        } else {
            &self.lax
        };
        let t0 = Instant::now();
        let method = reqwest::Method::from_bytes(r.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut rb = client.request(method, r.url);
        if let Some(b) = r.bearer {
            rb = rb.header("Authorization", b.header.as_str());
        }
        for (k, v) in extra_auth {
            rb = rb.header(k.as_str(), v.as_str());
        }
        for (k, v) in r.headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        if let Some((ct, body)) = r.body {
            rb = rb.header("Content-Type", ct.as_str()).body(body.clone());
        }
        let resp = rb.send().map_err(|e| {
            let m = err_chain(&e);
            let l = m.to_ascii_lowercase();
            if real && (l.contains("certificate") || l.contains("tls") || l.contains("ssl")) {
                format!(
                    "{m} (credentials are only sent with certificate validation enabled; fix the target certificate or test without a credential)"
                )
            } else {
                m
            }
        })?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let content_type = headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let mut buf = Vec::new();
        let _ = resp.take(BODY_CAP as u64).read_to_end(&mut buf);
        Ok(Seen {
            status,
            content_type,
            headers,
            body: String::from_utf8_lossy(&buf).into_owned(),
            latency_ms: t0.elapsed().as_millis() as u64,
        })
    }
}

/// A response after the same-origin redirects the executor followed.
pub struct Followed {
    pub seen: Seen,
    /// The hops that were followed, in order (empty: the first response was the answer).
    pub chain: Vec<RedirectHop>,
    /// The URL that gave `seen`.
    pub final_url: String,
}

impl Clients {
    /// [`Clients::send`], then follow redirects to the run's own origin, at most `max_hops`. Every
    /// hop goes through `send`, so the credential rules hold on each of them. The chain ends, and
    /// the last response is returned as the 3xx it is, at a redirect to another origin, a missing
    /// or unusable `Location`, a loop, or when `on_hop` refuses (the run budget). A failing hop is
    /// an error. A request with a body is never redirected: only reads follow.
    pub fn send_following(
        &self,
        r: &OutReq,
        max_hops: usize,
        on_hop: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Followed, String> {
        self.send_following_with_auth(r, &[], false, max_hops, on_hop)
    }

    pub fn send_following_resolved(
        &self,
        r: &OutReq,
        auth: &ResolvedAuth,
        max_hops: usize,
        on_hop: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Followed, String> {
        self.send_following_with_auth(r, &auth.extra_headers, auth.real, max_hops, on_hop)
    }

    pub fn send_following_with_auth(
        &self,
        r: &OutReq,
        extra_auth: &[(String, String)],
        extra_real: bool,
        max_hops: usize,
        on_hop: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Followed, String> {
        let mut seen = self.send_with_auth(r, extra_auth, extra_real)?;
        let mut chain: Vec<RedirectHop> = vec![];
        let mut url = r.url.to_string();
        let mut visited = vec![url.clone()];
        let mut total_ms = seen.latency_ms;
        while r.body.is_none()
            && chain.len() < max_hops
            && matches!(seen.status, 301 | 302 | 303 | 307 | 308)
        {
            let Some(loc) = seen
                .headers
                .iter()
                .find(|(k, _)| k == "location")
                .map(|(_, v)| v.trim().to_string())
                .filter(|l| !l.is_empty())
            else {
                break;
            };
            let Some(next) = reqwest::Url::parse(&url)
                .ok()
                .and_then(|b| b.join(&loc).ok())
            else {
                break;
            };
            if !self.is_target_url(next.as_str()) || visited.iter().any(|v| v == next.as_str()) {
                break;
            }
            if on_hop().is_err() {
                break;
            }
            chain.push(RedirectHop {
                status: seen.status,
                location: crate::llm::untrusted::redact_then_truncate(&loc, 200),
            });
            let hop = OutReq {
                method: r.method,
                url: next.as_str(),
                body: None,
                headers: r.headers,
                bearer: r.bearer,
            };
            seen = self
                .send_with_auth(&hop, extra_auth, extra_real)
                .map_err(|e| {
                    format!(
                        "following the redirect to {} failed: {e}",
                        crate::llm::untrusted::redact_then_truncate(next.path(), 80)
                    )
                })?;
            total_ms += seen.latency_ms;
            url = next.to_string();
            visited.push(url.clone());
        }
        seen.latency_ms = total_ms;
        Ok(Followed {
            seen,
            chain,
            final_url: url,
        })
    }
}

/// Does the executor follow a same-origin redirect for this case? Only a safe GET/HEAD read that
/// is a liveness, content or robustness check. An authorization case, a sensitive-file probe, a
/// forged-token request and a case that expects a redirect or a denial keep the raw status: that
/// status is the evidence.
pub fn follows_redirects(c: &PlannedCase) -> bool {
    matches!(
        c.method.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD"
    ) && Technique::parse(&c.technique) != Technique::Authz
        && auth_for(c) != Auth::Forged
        && !matches!(c.probe_oracle, Some(ProbeOracle::OpenRedirect { .. }))
        && !oracle::is_sensitive_path(&c.component)
        && !oracle::expects_redirect(c)
        && !oracle::expects_denial(c)
}

/// The reproduction command of a request whose redirects were followed.
fn follow_curl(curl: &str) -> String {
    curl.replacen(
        "curl -sS",
        &format!("curl -sS -L --max-redirs {MAX_REDIRECTS}"),
        1,
    )
}

/// A real test credential travels only through the client that validates certificates.
pub fn needs_validated_tls(b: Option<&Bearer>) -> bool {
    b.is_some_and(|b| b.real)
}

/// What a read-back after a DELETE found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteCheck {
    /// 404 or 410: the resource is no longer there.
    Gone,
    /// A 2xx answer to the GET: the DELETE did not remove it (carries the status).
    StillPresent(u16),
    /// Anything else (401/403, 3xx, 5xx, a transport error, a path that is not a path on the
    /// target): the read-back proves nothing either way.
    Unknown,
}

/// GET `path` on `base`'s origin, anonymously, after a DELETE of it: 404/410 is [`DeleteCheck::Gone`],
/// 2xx is [`DeleteCheck::StillPresent`], anything else [`DeleteCheck::Unknown`]. A target that needs
/// a credential to read answers 401 here, so use [`confirm_deleted_as`] with the deleting role's
/// bearer when the DELETE itself needed one.
pub fn confirm_deleted(clients: &Clients, base: &str, path: &str) -> DeleteCheck {
    confirm_deleted_as(clients, base, path, None)
}

/// [`confirm_deleted`] with an optional credential. `path` is the full path on the origin of `base`
/// (what teardown deletes, e.g. `/api/orders/12`). The GET goes through [`Clients::send`], so a
/// credential is attached only to the run's own target (exact scheme, host and port) and only over
/// a certificate-validating client; the read-back never leaves that target, redirects are not
/// followed (a 3xx is `Unknown`), and it is not charged to the run budget (teardown is not either).
pub fn confirm_deleted_as(
    clients: &Clients,
    base: &str,
    path: &str,
    bearer: Option<&Bearer>,
) -> DeleteCheck {
    let auth = ResolvedAuth {
        bearer: bearer.cloned(),
        extra_headers: vec![],
        authenticated: bearer.is_some(),
        real: needs_validated_tls(bearer),
        note: None,
    };
    confirm_deleted_resolved(clients, base, path, &auth)
}

/// [`confirm_deleted_as`] supporting full multi-modal credentials (`Bearer`, `Cookie`, custom headers).
pub fn confirm_deleted_resolved(
    clients: &Clients,
    base: &str,
    path: &str,
    auth: &ResolvedAuth,
) -> DeleteCheck {
    let Ok(path) = normalize_component(path) else {
        return DeleteCheck::Unknown;
    };
    let Some(origin) = reqwest::Url::parse(base)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .map(|u| u.origin().ascii_serialization())
    else {
        return DeleteCheck::Unknown;
    };
    let url = format!("{origin}{path}");
    if !clients.is_target_url(&url) {
        return DeleteCheck::Unknown;
    }
    let req = OutReq {
        method: "GET",
        url: &url,
        body: None,
        headers: &[],
        bearer: auth.bearer.as_ref(),
    };
    match clients.send_resolved(&req, auth) {
        Ok(seen) => match seen.status {
            404 | 410 => DeleteCheck::Gone,
            200..=299 => DeleteCheck::StillPresent(seen.status),
            _ => DeleteCheck::Unknown,
        },
        Err(_) => DeleteCheck::Unknown,
    }
}

fn out_req<'a>(spec: &'a RequestSpec, bearer: Option<&'a Bearer>) -> OutReq<'a> {
    OutReq {
        method: spec.method,
        url: &spec.url,
        body: spec.body.as_ref(),
        headers: &spec.extra_headers,
        bearer,
    }
}

/// Role that sent `spec` (the same role deletes what it created, when a token is configured).
pub(crate) fn role_of(auth: &Auth) -> Option<&str> {
    match auth {
        Auth::Role(r) => Some(r.as_str()),
        _ => None,
    }
}

/// Record on the run's ledger what a 2xx creating request produced (no-op for anything else, and
/// when no ledger is installed on this thread). Called for every attempt of every request the
/// executor sends: normal cases, re-runs and the adaptive-mutation probe (both go through
/// [`exec_http`]).
fn note_creation(case_id: &str, spec: &RequestSpec, seen: &Seen) {
    record_creation_response(
        None,
        spec.method,
        &spec.url,
        seen.status,
        &seen.headers,
        &seen.body,
        role_of(&spec.auth),
        Some(case_id),
    );
}

// ---------------------------------------------------------------- execution

#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Never send POST/PUT/PATCH/DELETE.
    pub dry_run: bool,
    pub is_spa_target: bool,
    pub credentials: Credentials,
    /// Extra attempts for a FAIL (flaky detection). Only safe methods are ever repeated.
    pub reruns: u32,
    pub timeout: Duration,
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            dry_run: false,
            is_spa_target: false,
            credentials: Credentials::from_env(),
            reruns: 2,
            timeout: Duration::from_secs(10),
        }
    }
}

fn safe_id(id: &str) -> String {
    let s: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if s.is_empty() { "case".into() } else { s }
}

pub fn evidence_rel_path(case_id: &str) -> String {
    format!("evidence/{}.json", safe_id(case_id))
}

fn skeleton(c: &PlannedCase, status: &str, reason: String, curl: String) -> CaseExecutionResult {
    CaseExecutionResult {
        blocked_reason: None,
        redirect_chain: vec![],
        case_id: c.id.clone(),
        title: c.title.clone(),
        component: c.component.clone(),
        method: c.method.clone(),
        technique: c.technique.clone(),
        status: status.into(),
        status_code: None,
        latency_ms: 0,
        reproduction_curl: curl,
        request_payload: c.payload.clone(),
        evidence: String::new(),
        content_type: None,
        is_spa_shell: false,
        failure_reason: Some(reason),
        expected_status: c.expected_status,
        oracle: None,
        flaky: false,
        attempts: vec![],
        evidence_file: None,
        evidence_detail: None,
        stateful_chain: None,
        concurrency_burst_results: None,
    }
}

fn skipped(c: &PlannedCase, reason: impl Into<String>, curl: String) -> CaseExecutionResult {
    skeleton(c, "SKIPPED", reason.into(), curl)
}

/// The result of a planner-made ledger row ([`SRC_NOT_APPLICABLE`], [`SRC_AUTH_WALL`]): nothing is
/// sent, no step or request is spent. NOT_APPLICABLE counts toward no denominator; BLOCKED with
/// `AuthWall` says what the user has to provide.
fn ledger_row_result(c: &PlannedCase) -> Option<CaseExecutionResult> {
    let (status, reason, why) = match c.source.as_deref()? {
        SRC_NOT_APPLICABLE => (
            "NOT_APPLICABLE",
            BlockReason::NoSurface,
            format!(
                "no input surface: nothing on the discovered route(s) takes input that {} tests could exercise ({}). Not counted toward coverage",
                c.technique, c.input_hint
            ),
        ),
        SRC_AUTH_WALL => (
            "BLOCKED",
            BlockReason::AuthWall,
            format!(
                "auth wall: the discovered route(s) are behind a login and no credential was available, so the {} tests were not run ({}). Next step: {NEXT_STEP_AUTH_WALL}",
                c.technique, c.input_hint
            ),
        ),
        _ => return None,
    };
    let mut r = skeleton(c, status, why, String::new());
    r.blocked_reason = Some(reason);
    r.evidence = c.input_hint.clone();
    Some(r)
}

/// Is this answer an auth wall for this case? Only when no credential was sent, and never for a
/// case whose raw status is the evidence (authorization, a sensitive-file probe, a forged token, a
/// CORS probe, an expected denial or redirect). A FAIL stays a FAIL. A redirect to a login page
/// relabels a PASS too (the page the case targeted was never reached); a 401 or a password form
/// only relabels an INCONCLUSIVE.
fn auth_wall_of(
    c: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    seen: &Seen,
    chain: &[RedirectHop],
    outcome: &OracleOutcome,
) -> Option<oracle::WallSignal> {
    if auth.authenticated
        || spec.auth == Auth::Forged
        || Technique::parse(&c.technique) == Technique::Authz
        || is_cors_case(c)
        || oracle::is_sensitive_path(&c.component)
        || oracle::expects_denial(c)
        || oracle::expects_redirect(c)
    {
        return None;
    }
    // a case aimed at a login page is not walled off by the redirects that page does (/login to
    // /login/): only what the final answer says counts
    let chain = if oracle::is_login_location(&c.component) {
        &[]
    } else {
        chain
    };
    let w = oracle::auth_wall_signal(
        seen.status,
        &seen.content_type,
        &seen.headers,
        &seen.body,
        chain,
    )?;
    match outcome.verdict {
        Verdict::Fail => None,
        Verdict::Inconclusive => Some(w),
        Verdict::Pass => w.redirected.then_some(w),
    }
}

fn spa_shell(ct: &str, body: &str, is_spa_target: bool) -> bool {
    ct.to_ascii_lowercase().contains("html")
        && is_spa_target
        && [
            "__NEXT_DATA__",
            "/_next/static/",
            "__NUXT__",
            "ng-version",
            "data-reactroot",
            "<app-root",
            "id=\"root\"",
            "id=\"app\"",
            "/@vite/client",
        ]
        .iter()
        .any(|m| body.contains(m))
}

fn redacted_headers(h: &[(String, String)]) -> Vec<Value> {
    h.iter()
        .map(|(k, v)| {
            json!([
                k,
                if is_sensitive_key(k) {
                    "[REDACTED]".to_string()
                } else {
                    redact_for_llm(v)
                }
            ])
        })
        .collect()
}

/// Status string of an oracle outcome (a PASS with advisory warnings is a WARN).
fn status_of_outcome(o: &OracleOutcome) -> &'static str {
    match o.verdict {
        Verdict::Fail => "FAIL",
        Verdict::Inconclusive => "INCONCLUSIVE",
        Verdict::Pass if !o.warnings.is_empty() => "WARN",
        Verdict::Pass => "PASS",
    }
}

/// Execute `cases` against `target` with default options (used by the operator "retest" action).
pub fn execute_cases(
    cases: &[PlannedCase],
    target: &str,
    is_spa_target: bool,
) -> Vec<CaseExecutionResult> {
    let opts = ExecOptions {
        is_spa_target,
        ..ExecOptions::default()
    };
    execute_cases_with(cases, target, &opts, &mut RunBudget::from_env())
}

struct Ctx<'a> {
    clients: &'a Clients,
    target: &'a str,
    /// `host:port`, the budget's rate-limit key.
    host: &'a str,
    opts: &'a ExecOptions,
    oast: Option<&'a super::oast::OastCollector>,
}

/// Output of sending one primary case along with any companion baseline/control/OAST probes.
pub struct ProbeOutcome {
    pub seen: Seen,
    pub chain: Vec<RedirectHop>,
    pub final_url: String,
    pub evidence: oracle::ProbeEvidence,
}

fn send_companion(
    clients: &Clients,
    target: &str,
    host: &str,
    budget: &mut RunBudget,
    template: &PlannedCase,
    payload: &str,
    auth: &ResolvedAuth,
) -> Result<oracle::ProbeSnapshot, String> {
    budget.take_request(host)?;
    let mut comp = template.clone();
    comp.payload = Some(payload.to_string());
    comp.probe_oracle = None;
    let spec = build_request(&comp, target)?;
    let req = out_req(&spec, auth.bearer.as_ref());
    let seen = clients.send_resolved(&req, auth)?;
    note_creation(&template.id, &spec, &seen);
    Ok(oracle::ProbeSnapshot {
        status: seen.status,
        body: seen.body,
        latency_ms: seen.latency_ms,
    })
}

fn substitute_oast_spec(spec: &RequestSpec, placeholder: &str, cb_url: &str) -> RequestSpec {
    let mut s = spec.clone();
    if !placeholder.is_empty() {
        let mut encoded = reqwest::Url::parse("http://localhost/").ok();
        let cb_enc = if let Some(ref mut u) = encoded {
            u.query_pairs_mut().append_pair("u", cb_url);
            u.query()
                .and_then(|q| q.strip_prefix("u="))
                .unwrap_or(cb_url)
                .to_string()
        } else {
            cb_url.to_string()
        };
        s.url = s.url.replace(placeholder, &cb_enc);
        if let Some((_, ref mut b)) = s.body {
            *b = b.replace(placeholder, cb_url);
        }
        for (_, v) in &mut s.extra_headers {
            *v = v.replace(placeholder, cb_url);
        }
    }
    s
}

/// Send the primary request for `case` plus any companion baseline, control, or OAST wait required
/// by `case.probe_oracle`. Assumes the caller already budgeted the primary request.
pub fn send_with_probe_oracle(
    clients: &Clients,
    target: &str,
    host: &str,
    budget: &mut RunBudget,
    case: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    follow_redirects: bool,
    oast: Option<&super::oast::OastCollector>,
) -> Result<ProbeOutcome, String> {
    let mut evidence = oracle::ProbeEvidence::default();
    let mut active_spec_owned: Option<RequestSpec> = None;
    let mut oast_token: Option<(String, u64)> = None;

    match &case.probe_oracle {
        Some(ProbeOracle::BooleanDiff {
            baseline_payload, ..
        })
        | Some(ProbeOracle::TimeDelay {
            baseline_payload, ..
        }) => {
            if let Ok(snap) =
                send_companion(clients, target, host, budget, case, baseline_payload, auth)
            {
                evidence.baseline = Some(snap);
            }
        }
        Some(ProbeOracle::OastCallback {
            placeholder,
            wait_ms,
        }) => {
            if let Some(col) = oast {
                let (tok, cb_url) = col.issue_token();
                active_spec_owned = Some(substitute_oast_spec(spec, placeholder, &cb_url));
                oast_token = Some((tok, (*wait_ms).min(2000)));
            } else {
                evidence.oast_unavailable = true;
            }
        }
        _ => {}
    }

    let send_spec = active_spec_owned.as_ref().unwrap_or(spec);
    let req = out_req(send_spec, auth.bearer.as_ref());
    let Followed {
        seen,
        chain,
        final_url,
    } = if follow_redirects {
        clients
            .send_following_resolved(&req, auth, MAX_REDIRECTS, &mut || budget.take_request(host))?
    } else {
        clients.send_resolved(&req, auth).map(|seen| Followed {
            seen,
            chain: vec![],
            final_url: send_spec.url.clone(),
        })?
    };

    if let Some(ProbeOracle::BooleanDiff { false_payload, .. }) = &case.probe_oracle
        && let Ok(snap) = send_companion(clients, target, host, budget, case, false_payload, auth)
    {
        evidence.control = Some(snap);
    }
    if let (Some((tok, wait_ms)), Some(col)) = (oast_token, oast)
        && let Some(hit) = col.wait_for_hit(&tok, Duration::from_millis(wait_ms))
    {
        evidence.oast_hit = true;
        evidence.oast_detail = Some(hit.summary());
    }

    Ok(ProbeOutcome {
        seen,
        chain,
        final_url,
        evidence,
    })
}

/// Hooks around every case an execution starts. The lead's area workers use them to take turns for
/// state-changing cases (so what the target hands out is the same whatever the worker count) and to
/// report progress while the run is still going.
pub trait CaseGate: Sync {
    /// Called before a case starts; may block.
    fn enter(&self, c: &PlannedCase);
    /// Called when a case (and its sub-cases) is done, with the results it produced.
    fn leave(&self, c: &PlannedCase, results: &[CaseExecutionResult]);
}

/// Run every case. A case yields its own result first; an adaptive-mutation probe or a
/// concurrency burst it triggered follows as a separate sub-case result.
pub fn execute_cases_with(
    cases: &[PlannedCase],
    target: &str,
    opts: &ExecOptions,
    budget: &mut RunBudget,
) -> Vec<CaseExecutionResult> {
    execute_cases_gated(cases, target, opts, budget, None)
}

/// [`execute_cases_with`] with a [`CaseGate`] called around every case that is actually started
/// (cases that cannot be started at all, a target that is not http(s), skip it).
pub fn execute_cases_gated(
    cases: &[PlannedCase],
    target: &str,
    opts: &ExecOptions,
    budget: &mut RunBudget,
    gate: Option<&dyn CaseGate>,
) -> Vec<CaseExecutionResult> {
    let curl_of = |c: &PlannedCase| {
        build_request(c, target)
            .map(|s| curl_for(&s))
            .unwrap_or_default()
    };
    let parsed = reqwest::Url::parse(target)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some());
    let Some(parsed) = parsed else {
        return cases.iter().map(|c| skipped(c, "target is not an http(s) URL: the agent only probes over HTTP, nothing was executed", curl_of(c))).collect();
    };
    let clients = match Clients::new(opts.timeout, &parsed) {
        Ok(c) => c,
        Err(e) => {
            return cases
                .iter()
                .map(|c| {
                    skeleton(
                        c,
                        "BLOCKED",
                        format!("could not build the HTTP client: {e}"),
                        curl_of(c),
                    )
                })
                .collect();
        }
    };
    let host = format!(
        "{}:{}",
        parsed.host_str().unwrap_or(""),
        parsed.port_or_known_default().unwrap_or(0)
    );
    let oast = cases
        .iter()
        .any(|c| matches!(c.probe_oracle, Some(ProbeOracle::OastCallback { .. })))
        .then(super::oast::OastCollector::start)
        .and_then(Result::ok);
    let ctx = Ctx {
        clients: &clients,
        target,
        host: &host,
        opts,
        oast: oast.as_ref(),
    };
    cases
        .iter()
        .flat_map(|c| {
            if let Some(g) = gate {
                g.enter(c);
            }
            let r = run_case(&ctx, c, budget);
            if let Some(g) = gate {
                g.leave(c, &r);
            }
            r
        })
        .collect()
}

fn run_stateful_case(
    ctx: &Ctx,
    c: &PlannedCase,
    steps: &[super::types::StatefulStep],
    budget: &mut RunBudget,
) -> CaseExecutionResult {
    if ctx.opts.dry_run && steps.iter().any(|s| is_mutating(&s.method)) {
        return skipped(
            c,
            "dry_run: state-changing steps in stateful scenario were not sent",
            String::new(),
        );
    }
    // nothing is sent (and no step is spent) when the chain cannot be judged: missing
    // credentials, unresolved placeholders, steps that are not about one resource
    if let Err(why) = super::stateful::preflight(steps, &ctx.opts.credentials) {
        return skipped(c, format!("stateful check skipped: {why}"), String::new());
    }
    if let Err(m) = budget.take_step() {
        return skipped(c, m, String::new());
    }
    let r = super::stateful::execute_stateful_scenario(
        ctx.clients,
        ctx.target,
        steps,
        &ctx.opts.credentials,
        budget,
        ctx.host,
        &c.id,
    );
    if let Some(why) = &r.skipped {
        return skipped(
            c,
            format!("stateful check skipped: {why}"),
            r.reproduction_curl.clone(),
        );
    }
    let outcome = r.outcome.clone().unwrap_or_else(|| {
        super::oracle::judge_stateful(&super::oracle::StatefulFacts::Setup {
            step: 0,
            status: None,
            reason: "no outcome".into(),
        })
    });
    let mut res = skeleton(
        c,
        status_of_outcome(&outcome),
        String::new(),
        r.reproduction_curl.clone(),
    );
    res.status_code = Some(r.final_status);
    res.latency_ms = r.total_latency_ms;
    res.stateful_chain = Some(r.steps.clone());
    res.evidence_file = Some(evidence_rel_path(&c.id));
    res.failure_reason = outcome.reason();
    res.evidence = r.summary.clone();
    let detail = json!({
        "case_id": c.id,
        "title": c.title,
        "technique": c.technique,
        "stateful_chain": r.steps,
        "reproduction_curl": r.reproduction_curl,
        "oracle": serde_json::to_value(&outcome).unwrap_or(Value::Null),
    });
    res.oracle = Some(outcome);
    res.evidence_detail = Some(detail);
    res
}

fn run_case(ctx: &Ctx, c: &PlannedCase, budget: &mut RunBudget) -> Vec<CaseExecutionResult> {
    if let Some(row) = ledger_row_result(c) {
        return vec![row];
    }
    if let Some(steps) = &c.stateful_steps
        && !steps.is_empty()
    {
        return vec![run_stateful_case(ctx, c, steps, budget)];
    }
    let spec = match build_request(c, ctx.target) {
        Ok(s) => s,
        Err(e) => {
            return vec![skipped(
                c,
                format!("invalid case, not sent: {e}"),
                String::new(),
            )];
        }
    };
    let curl = curl_for_auth(&spec, &ctx.opts.credentials);
    if ctx.opts.dry_run && is_mutating(spec.method) {
        return vec![skipped(
            c,
            format!(
                "dry_run: state-changing method {} was not sent",
                spec.method
            ),
            curl,
        )];
    }
    if let Err(m) = budget.take_step() {
        return vec![skipped(c, m, curl)];
    }
    let auth = resolve_auth(&spec.auth, &ctx.opts.credentials);
    let out = exec_http(ctx, budget, c, &spec, &auth, curl.clone());
    let mut results = vec![out.res];
    let Some(first) = out.first else {
        return results; // not sent (budget) or transport error: nothing to mutate or burst
    };

    // Adaptive schema-feedback mutation: a 400/422 that discloses its schema earns one probe with
    // schema-conforming adversarial values. It is a separate sub-case (own curl, own verdict).
    if (first.status == 400 || first.status == 422)
        && !(ctx.opts.dry_run && is_mutating(spec.method))
        && let Some((sub, info)) = run_mutation(ctx, budget, c, &first, &auth)
    {
        let base = &mut results[0];
        base.evidence.push_str(&format!(
            " [adaptive mutation sub-case {}: HTTP {}]",
            sub.case_id,
            sub.status_code.unwrap_or(0)
        ));
        if let Some(d) = base.evidence_detail.as_mut() {
            d["adaptive_mutation"] = info;
        }
        results.push(sub);
    }

    // Concurrency burst (TOCTOU): a separate sub-case judged by invariants only. It needs a
    // request the target accepts (2xx): a burst of 401s or 400s compares nothing.
    if let Some(n) = c.concurrency_burst.filter(|n| *n > 1)
        && !ctx.opts.dry_run
        && (200..=299).contains(&first.status)
        && let Some(sub) = run_burst(ctx, budget, c, &spec, &auth, n as usize)
    {
        if let Some(codes) = sub.concurrency_burst_results.clone() {
            results[0].concurrency_burst_results = Some(codes);
        }
        results.push(sub);
    }
    results
}

struct HttpOut {
    res: CaseExecutionResult,
    /// First response (before any re-run); None when nothing was received.
    first: Option<Seen>,
}

/// Send one case (plus safe re-runs of a FAIL), judge it, and build its result and evidence.
fn exec_http(
    ctx: &Ctx,
    budget: &mut RunBudget,
    c: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    curl: String,
) -> HttpOut {
    let https = spec.url.starts_with("https://");
    // only a safe request may be repeated: re-sending a POST would create a second record
    let total = if is_safe_method(spec.method) {
        1 + ctx.opts.reruns
    } else {
        1
    };
    let follow = follows_redirects(c);
    let mut first_chain: Vec<RedirectHop> = vec![];
    let mut first_final_url = spec.url.clone();
    let mut attempts: Vec<(Option<Seen>, Option<OracleOutcome>, Option<String>)> = vec![];
    for attempt in 0..total {
        if let Err(m) = budget.take_request(ctx.host) {
            if attempt == 0 {
                return HttpOut {
                    res: skipped(c, m, curl),
                    first: None,
                };
            }
            attempts.push((None, None, Some(format!("re-run not sent: {m}"))));
            break;
        }
        let sent = send_with_probe_oracle(
            ctx.clients,
            ctx.target,
            ctx.host,
            budget,
            c,
            spec,
            auth,
            follow,
            ctx.oast,
        );
        match sent {
            Ok(ProbeOutcome {
                seen,
                chain,
                final_url,
                evidence,
            }) => {
                if attempt == 0 {
                    first_chain = chain;
                    first_final_url = final_url;
                }
                note_creation(&c.id, spec, &seen);
                let shell = spa_shell(&seen.content_type, &seen.body, ctx.opts.is_spa_target);
                let outcome = oracle::judge(
                    c,
                    &Observation {
                        status: seen.status,
                        content_type: &seen.content_type,
                        headers: &seen.headers,
                        body: &seen.body,
                        sent_values: &spec.sent_values,
                        is_spa_shell: shell,
                        authenticated: auth.authenticated,
                        https,
                        request_body: spec.body.as_ref().map(|(_, b)| b.as_str()),
                        origin: spec.origin(),
                        latency_ms: seen.latency_ms,
                        probe: Some(&evidence),
                    },
                );
                let again = outcome.verdict == Verdict::Fail;
                attempts.push((Some(seen), Some(outcome), None));
                if !again {
                    break; // only a FAIL is worth re-running
                }
            }
            Err(e) => {
                attempts.push((None, None, Some(e)));
                break; // a transport error is not a verdict, and is not retried
            }
        }
    }

    let records: Vec<AttemptRecord> = attempts
        .iter()
        .enumerate()
        .map(|(i, (s, o, e))| AttemptRecord {
            attempt: i as u32 + 1,
            status_code: s.as_ref().map(|s| s.status),
            verdict: o
                .as_ref()
                .map(|o| o.verdict.label().to_string())
                .or_else(|| e.as_ref().map(|_| "ERROR".to_string()))
                .unwrap_or_default(),
        })
        .collect();

    // first attempt decides the shape of the result
    let (first_seen, first_outcome, first_err) = attempts.remove(0);
    let curl = if first_chain.is_empty() {
        curl
    } else {
        follow_curl(&curl)
    };
    let mut res = skeleton(c, "BLOCKED", String::new(), curl.clone());
    res.redirect_chain = first_chain.clone();
    res.failure_reason = None;
    res.attempts = records;
    res.evidence_file = Some(evidence_rel_path(&c.id));
    let mut detail = json!({
        "case_id": c.id, "title": c.title, "technique": c.technique, "expected_status": c.expected_status, "expected_behavior": c.expected_behavior,
        "request": {"method": spec.method, "url": spec.url, "curl": curl, "payload": c.payload, "auth": match &spec.auth { Auth::None => "none".to_string(), Auth::Forged => "forged-token".to_string(), Auth::Role(r) => format!("role:{r} (token not recorded)") }, "auth_note": auth.note},
    });

    let (Some(seen), Some(outcome)) = (first_seen, first_outcome) else {
        let e = first_err.unwrap_or_else(|| "unknown error".into());
        res.status = "BLOCKED".into();
        res.blocked_reason = Some(BlockReason::Transport);
        res.failure_reason = Some(format!("Connection error: {e}"));
        res.evidence = format!(
            "request failed: {}",
            crate::llm::untrusted::redact_then_truncate(&e, 300)
        );
        detail["response"] = json!({"error": crate::llm::untrusted::redact_then_truncate(&e, 300)});
        res.evidence_detail = Some(detail);
        return HttpOut { res, first: None };
    };

    // flaky: failed first, but a completed re-run did not reproduce it
    let reruns_done: Vec<&OracleOutcome> =
        attempts.iter().filter_map(|(_, o, _)| o.as_ref()).collect();
    let non_repro = reruns_done
        .iter()
        .filter(|o| o.verdict != Verdict::Fail)
        .count();
    let flaky = outcome.verdict == Verdict::Fail && non_repro > 0;
    // A High/Critical failure is never demoted just because a re-run looked different: a
    // security finding that appears once is still a finding. Only Medium/Low become WARN.
    let severe = outcome.max_fail_severity().unwrap_or(Severity::High) >= Severity::High;

    res.status_code = Some(seen.status);
    res.latency_ms = seen.latency_ms;
    res.content_type = Some(seen.content_type.clone());
    res.is_spa_shell = spa_shell(&seen.content_type, &seen.body, ctx.opts.is_spa_target);
    res.flaky = flaky;
    res.status = if flaky && !severe {
        "WARN".into()
    } else {
        status_of_outcome(&outcome).into()
    };
    res.failure_reason = if flaky {
        Some(format!(
            "flaky: failed on attempt 1, but {non_repro} of {} re-run(s) did not reproduce it{}. Original failure: {}",
            reruns_done.len(),
            if severe {
                "; kept as FAIL because the failure is high/critical severity"
            } else {
                ""
            },
            outcome.reason().unwrap_or_default()
        ))
    } else {
        outcome.reason()
    };
    // redact FIRST, then cut: a secret straddling the cut must not survive as a prefix
    res.evidence = if seen.body.is_empty() {
        format!(
            "{} {} bytes=0 content-type={}",
            spec.method, seen.status, seen.content_type
        )
    } else {
        crate::llm::untrusted::redact_then_truncate(&seen.body, 300)
    };
    if !first_chain.is_empty() {
        // the judged response is the final one: say how it was reached
        let hops: Vec<String> = first_chain
            .iter()
            .map(|h| format!("{} {}", h.status, h.location))
            .collect();
        res.evidence = crate::llm::untrusted::redact_then_truncate(
            &format!(
                "followed {} redirect(s) ({}), judged HTTP {}: {}",
                first_chain.len(),
                hops.join(" -> "),
                seen.status,
                res.evidence
            ),
            300,
        );
    }
    detail["response"] = json!({
        "status": seen.status, "content_type": seen.content_type, "latency_ms": seen.latency_ms,
        "headers": redacted_headers(&seen.headers),
        "body_excerpt": crate::llm::untrusted::redact_then_truncate(&seen.body, 4000),
    });
    if !first_chain.is_empty() {
        detail["response"]["final_url"] = json!(crate::llm::untrusted::redact_then_truncate(
            &first_final_url,
            300
        ));
        detail["redirect_chain"] = serde_json::to_value(&first_chain).unwrap_or(Value::Null);
    }
    if let Some(w) = auth_wall_of(c, spec, auth, &seen, &first_chain, &outcome) {
        // no credential, and the target asked for one: not a verdict on the app, not a failure
        let who = match &spec.auth {
            Auth::Role(r) => format!(" for role '{r}'"),
            _ => String::new(),
        };
        res.status = "BLOCKED".into();
        res.blocked_reason = Some(BlockReason::AuthWall);
        res.failure_reason = Some(format!(
            "auth wall: {}. No credential was available{who}, so what sits behind the login was not tested. Next step: {NEXT_STEP_AUTH_WALL}",
            w.what
        ));
        detail["auth_wall"] = json!(w.what);
    }
    detail["oracle"] = serde_json::to_value(&outcome).unwrap_or(Value::Null);
    detail["attempts"] = serde_json::to_value(&res.attempts).unwrap_or(Value::Null);
    detail["flaky"] = json!(flaky);
    res.oracle = Some(outcome);
    res.evidence_detail = Some(detail);
    HttpOut {
        res,
        first: Some(seen),
    }
}

/// Adaptive schema-feedback mutation as its own sub-case `<id>-M1`: own request, own curl, own
/// oracle verdict. Returns the sub-case and the summary stored on the base case's evidence.
fn run_mutation(
    ctx: &Ctx,
    budget: &mut RunBudget,
    c: &PlannedCase,
    first: &Seen,
    auth: &ResolvedAuth,
) -> Option<(CaseExecutionResult, Value)> {
    let feedback =
        super::mutation::extract_schema_feedback(first.status, &first.content_type, &first.body)?;
    let mutated_payload =
        super::mutation::mutate_payload(c.payload.as_deref(), &feedback, &c.technique)?;
    let mut m = c.clone();
    m.id = format!("{}-M1", c.id);
    m.title = format!("{} [adaptive schema mutation]", c.title);
    m.payload = Some(mutated_payload.clone());
    m.expected_status = None;
    m.expected_behavior =
        "Schema-conforming adversarial input is handled without a server error".into();
    m.concurrency_burst = None;
    m.stateful_steps = None;
    // its own question is a server error; the base case already judged the response contract
    m.contract = None;
    let spec = build_request(&m, ctx.target).ok()?;
    let curl = curl_for_auth(&spec, &ctx.opts.credentials);
    let out = exec_http(ctx, budget, &m, &spec, auth, curl);
    let (sub, mut_first) = (out.res, out.first);
    mut_first.as_ref()?; // budget stopped it or the transport failed: no sub-case to report
    let mutated_status = sub.status_code.unwrap_or(0);
    let penetrated = mutated_status != 400 && mutated_status != 422;
    let info = json!({
        "sub_case_id": sub.case_id,
        "framework": feedback.framework_hint,
        "required_fields": feedback.required_fields.iter().map(|f| &f.name).collect::<Vec<_>>(),
        "mutated_payload": crate::llm::untrusted::redact_then_truncate(&mutated_payload, 400),
        "mutated_status": mutated_status,
        "penetrated_validation": penetrated,
        "mutated_verdict": sub.oracle.as_ref().map(|o| o.verdict.label()),
    });
    let mut sub = sub;
    if let Some(d) = sub.evidence_detail.as_mut() {
        d["mutation_of"] = json!(c.id);
    }
    Some((sub, info))
}

/// Concurrency burst as its own sub-case `<id>-B`. Charged to the run budget and rate limit.
fn run_burst(
    ctx: &Ctx,
    budget: &mut RunBudget,
    c: &PlannedCase,
    spec: &RequestSpec,
    auth: &ResolvedAuth,
    n: usize,
) -> Option<CaseExecutionResult> {
    let mut b = c.clone();
    b.id = format!("{}-B", c.id);
    b.title = format!("{} [concurrency burst x{}]", c.title, n.clamp(2, MAX_BURST));
    let curl = format!(
        "for i in $(seq 1 {}); do {} & done; wait",
        n.clamp(2, MAX_BURST),
        curl_for_auth(spec, &ctx.opts.credentials)
    );
    let run = match super::stateful::run_concurrency_burst_auth(
        ctx.clients,
        spec,
        auth,
        n,
        budget,
        ctx.host,
        &b.id,
    ) {
        Ok(r) => r,
        Err(why) => {
            return Some(skipped(
                &b,
                format!("concurrency burst not run: {why}"),
                curl,
            ));
        }
    };
    let outcome = oracle::judge_burst_on_path(
        &BurstFacts {
            method: spec.method,
            requested: run.requested,
            responses: &run.responses,
            pre_read: run.pre_read.as_deref(),
            post_read: run.post_read.as_deref(),
        },
        &c.component,
    );
    let mut res = skeleton(&b, status_of_outcome(&outcome), String::new(), curl.clone());
    res.status_code = run.responses.first().map(|r| r.status);
    res.failure_reason = outcome.reason();
    res.evidence_file = Some(evidence_rel_path(&b.id));
    res.concurrency_burst_results = Some(run.status_codes.clone());
    res.evidence = format!(
        "{} concurrent {} request(s): statuses {:?}",
        run.requested, spec.method, run.status_codes
    );
    res.evidence_detail = Some(json!({
        "case_id": b.id, "title": b.title, "technique": b.technique, "burst_of": c.id,
        "request": {"method": spec.method, "url": spec.url, "curl": curl, "payload": c.payload},
        "concurrency_burst": {
            "requested": run.requested, "status_codes": run.status_codes, "notes": run.notes,
            "pre_read": run.pre_read.as_deref().map(|s| crate::llm::untrusted::redact_then_truncate(s, 600)),
            "post_read": run.post_read.as_deref().map(|s| crate::llm::untrusted::redact_then_truncate(s, 600)),
        },
        "oracle": serde_json::to_value(&outcome).unwrap_or(Value::Null),
    }));
    res.oracle = Some(outcome);
    Some(res)
}

/// In-process mirror of `tests/fixtures/qa-api/server.py` (the orders API) for tests that need a
/// real server: token auth (`alice-token`, `bob-token`, `admin-token`), `POST /orders` validated
/// like the fixture's `validate`, `GET`/`DELETE /orders/{id}` (a DELETE that keeps the order when
/// `delete_noop`: the fixture's seeded bug 6), `/boom` (500) and `/redir` (302). Plain `std::net`,
/// one thread per connection, `Connection: close`.
#[cfg(test)]
pub(crate) mod fixture {
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    pub struct Api {
        pub base: String,
        /// One `"METHOD /path"` per request, in arrival order.
        pub log: Arc<Mutex<Vec<String>>>,
        orders: Arc<Mutex<BTreeMap<u64, String>>>,
        stop: Arc<AtomicBool>,
        addr: std::net::SocketAddr,
    }

    impl Api {
        pub fn requests(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
        /// Ids of the orders that exist now.
        pub fn order_ids(&self) -> Vec<u64> {
            self.orders.lock().unwrap().keys().copied().collect()
        }
    }

    impl Drop for Api {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.addr); // wake the accept loop
        }
    }

    /// server.py's `validate`: why `POST /orders` would answer 422, if it would.
    pub fn order_input_error(b: &Value) -> Option<String> {
        let Some(o) = b.as_object() else {
            return Some("body must be an object".into());
        };
        for f in ["item", "qty"] {
            if o.get(f).is_none_or(Value::is_null) {
                return Some(format!("missing {f}"));
            }
        }
        if !o["item"].as_str().is_some_and(|s| !s.is_empty()) {
            return Some("item must be a non-empty string".into());
        }
        if !o["qty"].as_i64().is_some_and(|q| (1..=100).contains(&q)) {
            return Some("qty must be an integer 1..100".into());
        }
        match o.get("note") {
            Some(n) if !n.is_null() && !n.is_string() => Some("note must be a string".into()),
            _ => None,
        }
    }

    fn token_user(auth: &str) -> Option<&'static str> {
        match auth {
            "Bearer alice-token" => Some("alice"),
            "Bearer bob-token" => Some("bob"),
            "Bearer admin-token" => Some("admin"),
            _ => None,
        }
    }

    fn reply(s: &mut TcpStream, code: u16, headers: &[(&str, &str)], body: &Value) {
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        let mut h = format!(
            "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (k, v) in headers {
            h.push_str(&format!("{k}: {v}\r\n"));
        }
        h.push_str("\r\n");
        let _ = s.write_all(h.as_bytes());
        let _ = s.write_all(body.as_bytes());
    }

    fn serve_one(
        mut s: TcpStream,
        orders: &Mutex<BTreeMap<u64, String>>,
        next: &Mutex<u64>,
        log: &Mutex<Vec<String>>,
        delete_noop: bool,
    ) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head_end = loop {
            let Ok(n) = s.read(&mut tmp) else { return };
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap_or("").split_whitespace();
        let (method, target) = (
            first.next().unwrap_or("").to_string(),
            first.next().unwrap_or("").to_string(),
        );
        let header = |name: &str| {
            lines
                .clone()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_string())
        };
        let len: usize = header("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + len {
            match s.read(&mut tmp) {
                Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
                _ => break,
            }
        }
        let body: Option<Value> = serde_json::from_slice(&buf[head_end..]).ok();
        let path = target
            .split('?')
            .next()
            .unwrap_or("/")
            .trim_end_matches('/')
            .to_string();
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path
        };
        log.lock().unwrap().push(format!("{method} {path}"));
        let m = method.as_str();
        if (m, path.as_str()) == ("GET", "/health") {
            return reply(&mut s, 200, &[], &json!({"status": "ok"}));
        }
        let Some(user) = token_user(&header("authorization").unwrap_or_default()) else {
            return reply(&mut s, 401, &[], &json!({"error": "unauthorized"}));
        };
        match (m, path.as_str()) {
            ("GET", "/boom") => reply(&mut s, 500, &[], &json!({"error": "internal"})),
            ("GET", "/redir") => reply(
                &mut s,
                302,
                &[("Location", "http://other.invalid/x")],
                &Value::Null,
            ),
            ("POST", "/orders") => {
                let b = body.unwrap_or(Value::Null);
                if let Some(e) = order_input_error(&b) {
                    return reply(&mut s, 422, &[], &json!({"error": e}));
                }
                let id = {
                    let mut n = next.lock().unwrap();
                    *n += 1;
                    *n - 1
                };
                orders.lock().unwrap().insert(id, user.to_string());
                let loc = format!("/orders/{id}");
                reply(
                    &mut s,
                    201,
                    &[("Location", &loc)],
                    &json!({"id": id, "item": b["item"], "qty": b["qty"], "owner": user}),
                );
            }
            (_, p) if p.starts_with("/orders/") => {
                let Ok(id) = p["/orders/".len()..].parse::<u64>() else {
                    return reply(&mut s, 400, &[], &json!({"error": "bad id"}));
                };
                let owner = orders.lock().unwrap().get(&id).cloned();
                let Some(owner) = owner else {
                    return reply(&mut s, 404, &[], &json!({"error": "not found"}));
                };
                match m {
                    "GET" => reply(&mut s, 200, &[], &json!({"id": id, "owner": owner})),
                    "DELETE" if owner != user && user != "admin" => {
                        reply(&mut s, 403, &[], &json!({"error": "forbidden"}))
                    }
                    "DELETE" => {
                        if !delete_noop {
                            orders.lock().unwrap().remove(&id);
                        }
                        reply(&mut s, 204, &[], &Value::Null)
                    }
                    _ => reply(&mut s, 404, &[], &json!({"error": "no such route"})),
                }
            }
            _ => reply(&mut s, 404, &[], &json!({"error": "no such route"})),
        }
    }

    /// Start the fixture with orders 1 and 2 (alice) and 3 (bob) present.
    pub fn start(delete_noop: bool) -> Api {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().unwrap();
        let orders = Arc::new(Mutex::new(BTreeMap::from([
            (1, "alice".to_string()),
            (2, "alice".to_string()),
            (3, "bob".to_string()),
        ])));
        let next = Arc::new(Mutex::new(4u64));
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (o2, n2, l2, s2) = (orders.clone(), next.clone(), log.clone(), stop.clone());
        std::thread::spawn(move || {
            for conn in l.incoming() {
                if s2.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(c) = conn else { continue };
                let (o, n, lg) = (o2.clone(), n2.clone(), l2.clone());
                std::thread::spawn(move || serve_one(c, &o, &n, &lg, delete_noop));
            }
        });
        Api {
            base: format!("http://{addr}"),
            log,
            orders,
            stop,
            addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(method: &str, component: &str, payload: Option<&str>) -> PlannedCase {
        PlannedCase {
            id: "TC-001".into(),
            title: "t".into(),
            component: component.into(),
            method: method.into(),
            technique: "boundary".into(),
            input_hint: String::new(),
            payload: payload.map(String::from),
            headers: vec![],
            content_type: None,
            probe_oracle: None,
            expected_behavior: String::new(),
            expected_status: None,
            risk_level: "low".into(),
            role: None,
            secured: None,
            route_status: None,
            expect_fields: vec![],
            expected_content_type: None,
            source: None,
            stateful_steps: None,
            concurrency_burst: None,
            contract: None,
            changed_ops: vec![],
            area: String::new(),
            regression_of: vec![],
            history_priority: false,
        }
    }

    #[test]
    fn only_the_seven_http_methods_are_allowed() {
        for m in ["GET", "head", "Options", "POST", "put", "PATCH", "delete"] {
            assert!(
                build_request(&case(m, "/x", None), "http://h").is_ok(),
                "{m}"
            );
        }
        for m in [
            "TRACE",
            "CONNECT",
            "PROPFIND",
            "",
            "GET /x HTTP/1.1\r\nX:",
            "G ET",
        ] {
            assert!(
                build_request(&case(m, "/x", None), "http://h").is_err(),
                "{m:?} must be rejected"
            );
        }
    }

    #[test]
    fn components_cannot_leave_the_target_or_inject() {
        for bad in [
            "http://evil.test/x",
            "//evil.test/x",
            "/a b",
            "/a\r\nHost: evil",
            "",
            "/orders/{id}",
        ] {
            assert!(
                build_request(&case("GET", bad, None), "http://h").is_err(),
                "{bad:?}"
            );
        }
        let ok = build_request(&case("GET", "orders", None), "http://h:8080/").unwrap();
        assert_eq!(ok.url, "http://h:8080/orders");
    }

    #[test]
    fn get_payload_goes_to_the_query_string_not_the_body() {
        let s = build_request(
            &case("GET", "/search", Some("q=\"><script>alert(1)</script>")),
            "http://h",
        )
        .unwrap();
        assert!(s.body.is_none());
        assert!(s.url.starts_with("http://h/search?q="), "{}", s.url);
        assert!(
            s.sent_values
                .iter()
                .any(|v| v == "\"><script>alert(1)</script>")
        );
        let j = build_request(
            &case("HEAD", "/search", Some("{\"a\": 1, \"b\": \"x y\"}")),
            "http://h",
        )
        .unwrap();
        assert!(
            j.body.is_none()
                && j.url.contains("a=1")
                && (j.url.contains("b=x+y") || j.url.contains("b=x%20y")),
            "{}",
            j.url
        );
        let free = build_request(&case("GET", "/s?z=1", Some("' OR '1'='1")), "http://h").unwrap();
        assert!(
            free.url.contains("z=1") && free.url.contains("q="),
            "{}",
            free.url
        );
        let post = build_request(
            &case("POST", "/orders", Some("{\"item\": \"a\"}")),
            "http://h",
        )
        .unwrap();
        assert_eq!(post.body.as_ref().unwrap().0, "application/json");
        let bad_json = build_request(&case("POST", "/orders", Some("{\"")), "http://h").unwrap();
        assert_eq!(
            bad_json.body.unwrap().0,
            "application/json",
            "malformed JSON is still sent as JSON: that is the test"
        );
        let form = build_request(&case("POST", "/f", Some("data=AAA&x=1")), "http://h").unwrap();
        assert_eq!(form.body.unwrap().0, "application/x-www-form-urlencoded");
    }

    #[test]
    fn curl_uses_the_same_method_url_body_and_single_quotes() {
        let mut c = case("PATCH", "/o/1", Some("{\"note\": \"it's\"}"));
        c.role = Some("user".into());
        let s = build_request(&c, "http://h").unwrap();
        let curl = curl_for(&s);
        assert!(curl.contains("-X PATCH"), "{curl}");
        assert!(curl.contains("'http://h/o/1'"), "{curl}");
        assert!(
            curl.contains("--data-raw '{\"note\": \"it'\\''s\"}'"),
            "{curl}"
        );
        assert!(
            curl.contains("Authorization: Bearer ${RH_USER_TOKEN}"),
            "{curl}"
        );
        // a hostile path cannot break out of the quotes
        let h = build_request(&case("GET", "/x'$(id)'", None), "http://h").unwrap();
        let hc = curl_for(&h);
        assert!(hc.ends_with("'http://h/x'\\''$(id)'\\'''"), "{hc}");
        assert!(
            !hc.contains("\"http"),
            "URL must not be double-quoted: {hc}"
        );
        let head = curl_for(&build_request(&case("HEAD", "/x", None), "http://h").unwrap());
        assert!(head.contains("-I -X HEAD"), "{head}");
        let g = curl_for(&build_request(&case("GET", "/s", Some("q=1")), "http://h").unwrap());
        assert!(g.contains("-X GET") && !g.contains("--data"), "{g}");
    }

    #[test]
    fn auth_roles_and_env_names() {
        let mut c = case("GET", "/x", None);
        assert_eq!(auth_for(&c), Auth::Role("user".into()));
        c.technique = "authz".into();
        assert_eq!(auth_for(&c), Auth::None);
        c.title = "Forged JWT".into();
        assert_eq!(auth_for(&c), Auth::Forged);
        c.role = Some("Admin".into());
        assert_eq!(auth_for(&c), Auth::Role("Admin".into()));
        assert_eq!(Credentials::env_var("shop-admin"), "RH_SHOP_ADMIN_TOKEN");
        let creds = Credentials::none().with("admin", "tok");
        assert_eq!(creds.token("ADMIN"), Some("tok"));
        assert!(
            !format!("{creds:?}").contains("tok\""),
            "Debug must not print tokens"
        );
    }

    #[test]
    fn the_acting_role_is_user_then_alice_then_any_unprivileged_role_never_an_admin() {
        let with = |roles: &[&str]| {
            roles
                .iter()
                .fold(Credentials::none(), |c, r| c.with(r, "tok"))
        };
        assert_eq!(Credentials::none().actor(), None);
        assert_eq!(
            with(&["alice", "bob", "admin"]).actor().as_deref(),
            Some("alice")
        );
        assert_eq!(with(&["alice", "user"]).actor().as_deref(), Some("user"));
        assert_eq!(
            with(&["viewer", "admin"]).actor().as_deref(),
            Some("viewer")
        );
        assert_eq!(
            with(&["shop-admin"]).actor(),
            None,
            "an administrator is never the actor"
        );
        assert_eq!(with(&["Root", "admin"]).actor(), None);
        // the role name round-trips through the token lookup
        let c = with(&["read-only"]);
        let a = c.actor().unwrap();
        assert!(c.has_role(&a), "{a}");
    }

    // ---- confirm_deleted

    fn clients_for(base: &str) -> Clients {
        Clients::new(Duration::from_secs(5), &reqwest::Url::parse(base).unwrap()).unwrap()
    }

    fn bearer(token: &str) -> Bearer {
        Bearer {
            header: format!("Bearer {token}"),
            real: true,
        }
    }

    fn delete(api: &fixture::Api, path: &str, token: &str) -> u16 {
        let c = clients_for(&api.base);
        let b = bearer(token);
        c.send(&OutReq {
            method: "DELETE",
            url: &format!("{}{path}", api.base),
            body: None,
            headers: &[],
            bearer: Some(&b),
        })
        .unwrap()
        .status
    }

    #[test]
    fn a_deleted_resource_reads_back_as_gone() {
        let api = fixture::start(false);
        let c = clients_for(&api.base);
        let admin = bearer("admin-token");
        assert_eq!(
            confirm_deleted_as(&c, &api.base, "/orders/3", Some(&admin)),
            DeleteCheck::StillPresent(200),
            "before the DELETE the order is there"
        );
        assert_eq!(delete(&api, "/orders/3", "admin-token"), 204);
        assert_eq!(
            confirm_deleted_as(&c, &api.base, "/orders/3", Some(&admin)),
            DeleteCheck::Gone
        );
        assert_eq!(api.order_ids(), vec![1, 2]);
    }

    #[test]
    fn a_delete_that_kept_the_resource_reads_back_as_still_present() {
        let api = fixture::start(true); // the fixture's seeded "DELETE answers 204 but deletes nothing"
        let c = clients_for(&api.base);
        let alice = bearer("alice-token");
        assert_eq!(delete(&api, "/orders/1", "alice-token"), 204);
        assert_eq!(
            confirm_deleted_as(&c, &api.base, "/orders/1", Some(&alice)),
            DeleteCheck::StillPresent(200)
        );
        assert_eq!(api.order_ids(), vec![1, 2, 3]);
    }

    #[test]
    fn a_read_back_that_proves_nothing_is_unknown() {
        let api = fixture::start(false);
        let c = clients_for(&api.base);
        let alice = bearer("alice-token");
        // no credential on an authenticated API: 401 is not "gone" and not "present"
        assert_eq!(
            confirm_deleted(&c, &api.base, "/orders/1"),
            DeleteCheck::Unknown
        );
        // server error, redirect (never followed), transport error
        assert_eq!(
            confirm_deleted_as(&c, &api.base, "/boom", Some(&alice)),
            DeleteCheck::Unknown
        );
        assert_eq!(
            confirm_deleted_as(&c, &api.base, "/redir", Some(&alice)),
            DeleteCheck::Unknown
        );
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        assert_eq!(
            confirm_deleted(&clients_for(&dead), &dead, "/orders/1"),
            DeleteCheck::Unknown
        );
        // not a path on the target: nothing is sent
        let before = api.requests().len();
        for bad in [
            "",
            "//evil.test/x",
            "http://evil.test/x",
            "/a b",
            "/a\r\nHost: evil",
            "/orders/{id}",
        ] {
            assert_eq!(
                confirm_deleted_as(&c, &api.base, bad, Some(&alice)),
                DeleteCheck::Unknown,
                "{bad:?}"
            );
        }
        assert_eq!(
            confirm_deleted(&c, "not a url", "/orders/1"),
            DeleteCheck::Unknown
        );
        assert_eq!(
            confirm_deleted(&c, "ftp://127.0.0.1/", "/orders/1"),
            DeleteCheck::Unknown
        );
        assert_eq!(
            api.requests().len(),
            before,
            "refused read-backs sent nothing"
        );
    }

    #[test]
    fn the_read_back_never_leaves_the_runs_target_and_never_carries_a_credential_elsewhere() {
        let target = fixture::start(false);
        let other = fixture::start(false);
        let c = clients_for(&target.base);
        let alice = bearer("alice-token");
        // a credential is withheld from any other host, and nothing is sent to it at all
        assert_eq!(
            confirm_deleted_as(&c, &other.base, "/orders/1", Some(&alice)),
            DeleteCheck::Unknown
        );
        assert_eq!(
            confirm_deleted(&c, &other.base, "/orders/1"),
            DeleteCheck::Unknown
        );
        assert!(other.requests().is_empty(), "{:?}", other.requests());
        // on the target the credential is attached: the same GET that was 401 is now a 200
        assert_eq!(
            confirm_deleted(&c, &target.base, "/orders/1"),
            DeleteCheck::Unknown
        );
        assert_eq!(
            confirm_deleted_as(&c, &target.base, "/orders/1", Some(&alice)),
            DeleteCheck::StillPresent(200)
        );
        // a base with a path or query is reduced to its origin, as teardown does
        assert_eq!(
            confirm_deleted_as(
                &c,
                &format!("{}/app/?x=1", target.base),
                "/orders/1",
                Some(&alice)
            ),
            DeleteCheck::StillPresent(200)
        );
    }
}

#[cfg(test)]
mod custom_header_tests {
    use super::*;

    fn base_case(method: &str, component: &str) -> PlannedCase {
        crate::agent::types::fixtures::planned("TC-H1", "injection", method, component)
    }

    #[test]
    fn custom_headers_and_content_type_propagate_to_request_and_curl() {
        let mut c = base_case("POST", "/xml");
        c.payload = Some("<root>hi</root>".into());
        c.content_type = Some("application/xml".into());
        c.headers = vec![
            ("X-Forwarded-For".into(), "127.0.0.1".into()),
            ("X-Original-URL".into(), "/admin".into()),
        ];
        c.role = Some("user".into());
        let spec = build_request(&c, "http://127.0.0.1:8080").unwrap();
        assert_eq!(spec.body.as_ref().unwrap().0, "application/xml");
        assert!(
            spec.extra_headers
                .iter()
                .any(|(k, v)| k == "X-Forwarded-For" && v == "127.0.0.1")
        );
        assert!(
            spec.extra_headers
                .iter()
                .any(|(k, v)| k == "X-Original-URL" && v == "/admin")
        );
        let curl = curl_for(&spec);
        assert!(curl.contains("Content-Type: application/xml"), "{curl}");
        assert!(curl.contains("X-Forwarded-For: 127.0.0.1"), "{curl}");
        assert!(curl.contains("X-Original-URL: /admin"), "{curl}");
    }

    #[test]
    fn custom_headers_reject_crlf_and_credential_overrides() {
        let mut crlf = base_case("GET", "/admin");
        crlf.headers = vec![("X-Test".into(), "1\r\nEvil: true".into())];
        assert!(build_request(&crlf, "http://127.0.0.1:8080").is_err());

        let mut auth_override = base_case("GET", "/admin");
        auth_override.role = Some("user".into());
        auth_override.headers = vec![("Authorization".into(), "Bearer hijack".into())];
        assert!(build_request(&auth_override, "http://127.0.0.1:8080").is_err());

        let mut cookie_override = base_case("GET", "/admin");
        cookie_override.role = Some("user".into());
        cookie_override.headers = vec![("Cookie".into(), "sid=evil".into())];
        assert!(build_request(&cookie_override, "http://127.0.0.1:8080").is_err());

        let mut bad_ct = base_case("POST", "/xml");
        bad_ct.payload = Some("x".into());
        bad_ct.content_type = Some("text/plain\r\nX-Injected: 1".into());
        assert!(build_request(&bad_ct, "http://127.0.0.1:8080").is_err());
    }
}

#[cfg(test)]
mod multimodal_auth_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn credentials_support_cookie_header_and_env_parsing_without_leaking_secrets() {
        let creds = Credentials::from_env_pairs([
            (
                "RH_USER_COOKIE".to_string(),
                "session=sec-cookie; csrf=xyz".to_string(),
            ),
            (
                "RH_SVC_HEADER".to_string(),
                "X-API-Key: sec-apikey".to_string(),
            ),
            ("RH_CAROL_HEADER".to_string(), "carol-raw".to_string()),
            (
                "RH_CAROL_HEADER_NAME".to_string(),
                "X-Carol-Auth".to_string(),
            ),
            (
                "RH_ADMIN_COOKIE".to_string(),
                "session=root-cookie".to_string(),
            ),
        ]);

        assert!(creds.has_role("user"));
        assert!(creds.has_role("svc"));
        assert!(creds.has_role("carol"));
        assert!(creds.has_role("admin"));
        assert_eq!(creds.actor().as_deref(), Some("user"));

        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("sec-cookie"), "{dbg}");
        assert!(!dbg.contains("sec-apikey"), "{dbg}");
        assert!(!dbg.contains("carol-raw"), "{dbg}");

        let auth_u = resolve_auth(&Auth::Role("user".into()), &creds);
        assert!(auth_u.authenticated);
        assert!(auth_u.real);
        assert!(
            auth_u
                .extra_headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("Cookie")
                    && v == "session=sec-cookie; csrf=xyz")
        );

        let auth_s = resolve_auth(&Auth::Role("svc".into()), &creds);
        assert!(auth_s.authenticated);
        assert!(auth_s.real);
        assert!(
            auth_s
                .extra_headers
                .iter()
                .any(|(k, v)| k == "X-API-Key" && v == "sec-apikey")
        );

        let auth_c = resolve_auth(&Auth::Role("carol".into()), &creds);
        assert!(auth_c.authenticated);
        assert!(
            auth_c
                .extra_headers
                .iter()
                .any(|(k, v)| k == "X-Carol-Auth" && v == "carol-raw")
        );

        let mut case = crate::agent::types::fixtures::planned("TC-MA1", "authz", "GET", "/me");
        case.role = Some("user".into());
        let spec = build_request(&case, "http://127.0.0.1:8080").unwrap();
        let curl = curl_for_auth(&spec, &creds);
        assert!(curl.contains("${RH_USER_COOKIE}"), "{curl}");
        assert!(!curl.contains("sec-cookie"), "{curl}");

        let mut svc_case = crate::agent::types::fixtures::planned("TC-MA2", "authz", "GET", "/svc");
        svc_case.role = Some("svc".into());
        let svc_spec = build_request(&svc_case, "http://127.0.0.1:8080").unwrap();
        let svc_curl = curl_for_auth(&svc_spec, &creds);
        assert!(svc_curl.contains("${RH_SVC_HEADER}"), "{svc_curl}");
        assert!(!svc_curl.contains("sec-apikey"), "{svc_curl}");
    }

    #[test]
    fn cookie_and_header_credentials_are_withheld_off_origin() {
        let target = fixture::start(false);
        let other = fixture::start(false);
        let target_u = reqwest::Url::parse(&target.base).unwrap();
        let clients = Clients::new(Duration::from_secs(2), &target_u).unwrap();
        let creds = Credentials::none().with_cookie("user", "sid=secret");
        let auth = resolve_auth(&Auth::Role("user".into()), &creds);

        let err = clients
            .send_resolved(
                &OutReq {
                    method: "GET",
                    url: &format!("{}/orders", other.base),
                    body: None,
                    headers: &[],
                    bearer: auth.bearer.as_ref(),
                },
                &auth,
            )
            .err()
            .expect("must refuse sending cookies to off-origin host");
        assert!(err.contains("credentials withheld"), "{err}");
    }

    #[test]
    fn login_bootstrap_handles_csrf_cookies_and_json_token() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let base = format!("http://127.0.0.1:{}", addr.port());
        let h = std::thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = l.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = req.lines().next().unwrap_or("");
                let resp = if first.starts_with("GET /login ") {
                    "HTTP/1.1 200 OK\r\nSet-Cookie: pre=p1; Path=/\r\nContent-Type: text/html\r\nContent-Length: 55\r\nConnection: close\r\n\r\n<form><input type=\"hidden\" name=\"_csrf\" value=\"tok99\"/></form>"
                } else if first.starts_with("POST /login ") {
                    let has_pre = req.to_ascii_lowercase().contains("cookie: pre=p1");
                    let has_csrf = req.contains("_csrf=tok99");
                    if has_pre
                        && has_csrf
                        && req.contains("username=alice")
                        && req.contains("password=pw")
                    {
                        "HTTP/1.1 200 OK\r\nSet-Cookie: sid=sess42; HttpOnly\r\nContent-Type: application/json\r\nContent-Length: 24\r\nConnection: close\r\n\r\n{\"access_token\":\"jwt42\"}"
                    } else {
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad"
                    }
                } else if first.starts_with("GET /me ") {
                    if req.to_ascii_lowercase().contains("sid=sess42")
                        && req
                            .to_ascii_lowercase()
                            .contains("authorization: bearer jwt42")
                    {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    } else {
                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno"
                    }
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let base_u = reqwest::Url::parse(&base).unwrap();
        let clients = Clients::new(Duration::from_secs(2), &base_u).unwrap();
        let mut creds = Credentials::none();
        creds
            .bootstrap_login(
                &clients,
                "user",
                &LoginBootstrap {
                    login_url: format!("{base}/login"),
                    csrf_page_url: Some(format!("{base}/login")),
                    mode: LoginMode::Form,
                    username: "alice".into(),
                    password: "pw".into(),
                    ..LoginBootstrap::default()
                },
            )
            .unwrap();
        assert_eq!(creds.token("user"), Some("jwt42"));
        assert!(creds.cookie("user").unwrap().contains("sid=sess42"));

        let auth = resolve_auth(&Auth::Role("user".into()), &creds);
        let seen = clients
            .send_resolved(
                &OutReq {
                    method: "GET",
                    url: &format!("{base}/me"),
                    body: None,
                    headers: &[],
                    bearer: auth.bearer.as_ref(),
                },
                &auth,
            )
            .unwrap();
        assert_eq!(seen.status, 200);
        let _ = h.join();
    }

    #[test]
    fn roles_toml_cookie_and_header_integration() {
        let dir = std::env::temp_dir().join(format!(
            "readyhai_roles_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let storage_path = dir.join("user_state.json");
        std::fs::write(
            &storage_path,
            r#"{"cookies":[{"name":"sid","value":"cookie-from-state"},{"name":"pref","value":"1"}]}"#,
        )
        .unwrap();
        let roles_path = dir.join("roles.toml");
        std::fs::write(
            &roles_path,
            r#"
[[role]]
name = "viewer"
auth = "cookie"
storage_state = "user_state.json"

[[role]]
name = "svc_ext"
auth = "header"
header_name = "X-Service-Key"
token_env = "PATH"
"#,
        )
        .unwrap();
        let roles = crate::qa::roles::Roles::load(&roles_path).unwrap();
        let creds = Credentials::none().with_roles(&roles);
        assert!(creds.has_role("viewer"));
        assert_eq!(
            creds.cookie("viewer"),
            Some("sid=cookie-from-state; pref=1")
        );
        assert!(creds.has_role("svc_ext"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
