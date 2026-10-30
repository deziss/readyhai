//! Test-account roles for authenticated QA (roles.toml, kept OUTSIDE the target
//! repo, mode 0600). Secret values are resolved from env vars at request time
//! and never stored in any serialized structure.
use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    /// Authorization: Bearer $token_env
    Bearer,
    /// Authorization: Basic base64($username_env:$password_env)
    Basic,
    /// <header_name>: $token_env
    Header,
    /// Playwright storageState file (UI) + its cookies (API)
    Cookie,
    None,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Role {
    pub name: String,
    pub auth: AuthKind,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub username_env: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,
    /// For auth = "cookie": storageState JSON path (relative to roles.toml).
    #[serde(default)]
    pub storage_state: Option<PathBuf>,
    /// Path globs this role SHOULD reach (e.g. "/api/orders/**").
    #[serde(default)]
    pub allow: Vec<String>,
    /// Path globs this role must NOT reach (e.g. "/api/admin/**").
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Roles {
    #[serde(default, rename = "role")]
    pub roles: Vec<Role>,
    #[serde(skip)]
    pub dir: PathBuf,
    #[serde(skip)]
    pub warnings: Vec<String>,
}

fn set(globs: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        b.add(Glob::new(g)?);
    }
    Ok(b.build()?)
}

impl Roles {
    pub fn load(path: &Path) -> Result<Roles> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("roles file {}", path.display()))?;
        let mut r: Roles =
            toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        r.dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(m) = std::fs::metadata(path)
                && m.permissions().mode() & 0o077 != 0
            {
                r.warnings.push(format!(
                    "{} is readable by group/others — chmod 600 it",
                    path.display()
                ));
            }
        }
        let mut names = std::collections::HashSet::new();
        for role in &r.roles {
            if !names.insert(role.name.clone()) {
                bail!("duplicate role '{}'", role.name);
            }
            if !role
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                bail!("role name '{}' must be [A-Za-z0-9_-]", role.name);
            }
            set(&role.allow)?;
            set(&role.deny)?;
        }
        Ok(r)
    }

    pub fn names(&self) -> Vec<String> {
        self.roles.iter().map(|r| r.name.clone()).collect()
    }
}

impl Role {
    /// Placeholder used in repro steps instead of the secret.
    pub fn placeholder(&self) -> String {
        format!(
            "$RH_{}_TOKEN",
            self.name.to_ascii_uppercase().replace('-', "_")
        )
    }

    /// (header name, header value) resolved from env at call time. None for auth=none/cookie
    /// or when the env var is unset.
    pub fn credential(&self) -> Option<(String, String)> {
        let env = |k: &Option<String>| {
            k.as_ref()
                .and_then(|k| std::env::var(k).ok())
                .filter(|v| !v.is_empty())
        };
        match self.auth {
            AuthKind::Bearer => {
                env(&self.token_env).map(|t| ("Authorization".into(), format!("Bearer {t}")))
            }
            AuthKind::Header => {
                let name = self
                    .header_name
                    .clone()
                    .unwrap_or_else(|| "X-API-Key".into());
                env(&self.token_env).map(|t| (name, t))
            }
            AuthKind::Basic => {
                let (u, p) = (env(&self.username_env)?, env(&self.password_env)?);
                Some((
                    "Authorization".into(),
                    format!("Basic {}", b64(format!("{u}:{p}").as_bytes())),
                ))
            }
            AuthKind::Cookie | AuthKind::None => None,
        }
    }

    /// Cookie header built from the storageState file (for API calls as this role).
    pub fn cookie_header(&self, roles_dir: &Path) -> Option<String> {
        let p = roles_dir.join(self.storage_state.as_ref()?);
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()?;
        let pairs: Vec<String> = v["cookies"]
            .as_array()?
            .iter()
            .filter_map(|c| Some(format!("{}={}", c["name"].as_str()?, c["value"].as_str()?)))
            .collect();
        (!pairs.is_empty()).then(|| pairs.join("; "))
    }

    /// Expected access for a request path: Some(true) allowed, Some(false) denied,
    /// None when the role file says nothing about it. Deny wins.
    pub fn expects(&self, path: &str) -> Option<bool> {
        if set(&self.deny).map(|s| s.is_match(path)).unwrap_or(false) {
            return Some(false);
        }
        if set(&self.allow).map(|s| s.is_match(path)).unwrap_or(false) {
            return Some(true);
        }
        None
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for ch in data.chunks(3) {
        let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= ch.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_and_expectations() {
        let r: Roles = toml::from_str(
            r#"
[[role]]
name = "admin"
auth = "bearer"
token_env = "RH_TEST_ADMIN_TOKEN_UNSET"
allow = ["/api/**"]

[[role]]
name = "user"
auth = "basic"
username_env = "RH_U"
password_env = "RH_P"
allow = ["/api/orders/**"]
deny = ["/api/admin/**"]
"#,
        )
        .unwrap();
        let user = &r.roles[1];
        assert_eq!(user.expects("/api/admin/users"), Some(false));
        assert_eq!(user.expects("/api/orders/7"), Some(true));
        assert_eq!(user.expects("/health"), None);
        assert_eq!(r.roles[0].placeholder(), "$RH_ADMIN_TOKEN");
        assert!(r.roles[0].credential().is_none());
        assert_eq!(b64(b"qa:pw"), "cWE6cHc=");
    }
}
