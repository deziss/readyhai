use std::collections::{BTreeMap, BTreeSet};

pub use super::auth::*;
pub use super::bootstrap::*;
use super::builder::sanitize_custom_headers;
use super::clients::Clients;

#[derive(Clone, Debug)]
pub(crate) enum HeaderEnvKind {
    FullVar(String),
    ValueVar { name: String, var: String },
}

/// Test credentials per role. Sources: `RH_<ROLE>_TOKEN`, `RH_<ROLE>_COOKIE`, `RH_<ROLE>_HEADER`
/// environment variables, `roles.toml`, login bootstrap, or programmatic builders. The server's
/// own tokens are never used, and secret values never appear in reports or Debug output.
#[derive(Clone, Default)]
pub struct Credentials {
    pub(crate) tokens: BTreeMap<String, String>,
    pub(crate) cookies: BTreeMap<String, String>,
    pub(crate) headers: BTreeMap<String, (String, String)>,
    pub(crate) token_envs: BTreeMap<String, String>,
    pub(crate) header_envs: BTreeMap<String, HeaderEnvKind>,
    pub(crate) pending_logins: BTreeMap<String, LoginBootstrap>,
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

pub(crate) fn role_key(role: &str) -> String {
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

pub(crate) fn strip_ctl(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
        .collect()
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
        let (cookie, token) = super::bootstrap::perform_login(clients, role, cfg)?;
        if let Some(ck) = cookie {
            self.cookies.insert(role_key(role), ck);
        }
        if let Some(tok) = token {
            self.tokens.insert(role_key(role), tok);
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
