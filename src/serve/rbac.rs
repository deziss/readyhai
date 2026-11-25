//! Role-based access control for `readyhai serve` (SaaS-style multi-key auth).
//!
//! Model: three roles, one permission matrix, many keys.
//!   Viewer   — read: runs, findings, reports, checks, status.
//!   Operator — Viewer + trigger work: scans, agent runs, network lab, eval, mutate, cancel.
//!   Admin    — Operator + governance: approve/reject, memory accept/forget, delete,
//!              fix (opens PRs).
//!
//! Toggled from the operator side only, three ways (most specific wins):
//!   * `READYHAI_RBAC=off|on|auto` env (auto = ON when a key file exists, else OFF)
//!   * `[rbac] enabled = true|false` in `rbac.toml` (used when env is `auto`)
//!   * when everything is off, behavior is exactly the legacy single-`READYHAI_TOKEN`
//!     mode and the boot token is Admin. When ON, the boot token still authenticates
//!     as break-glass Admin unless `READYHAI_RBAC_BOOT_ADMIN=0`.
//!
//! Keys are held as SHA-256 digests in memory; the file may carry `key = "..."`
//! (hashed at boot) or `key_sha256 = "<hex>"` to keep plaintext out of files.

use super::types::{BANNED_TOKENS, MIN_TOKEN_CHARS};
use anyhow::{Result, anyhow};
use axum::http::Method;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            _ => Err(anyhow!(
                "unknown role {s:?} (expected viewer|operator|admin)"
            )),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
    pub fn allows(&self, action: Action) -> bool {
        match action {
            // Any authenticated role may read; unauthenticated is 401 before this.
            Action::Read => true,
            Action::Operate => *self >= Role::Operator,
            Action::Admin => *self >= Role::Admin,
        }
    }
}

/// Request class, derived from method + path (never from caller-supplied data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Operate,
    Admin,
}

/// Write-path classification. The matrix lives here, next to the middleware, so a
/// new route cannot forget to classify itself: an unclassified write is Admin
/// (fail closed). GET/HEAD are always Read (public GETs are answered before auth).
pub fn action_for(method: &Method, path: &str) -> Action {
    // The middleware runs before routing; a query string must not change a verdict.
    let path = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    if method == Method::GET || method == Method::HEAD {
        return Action::Read;
    }
    if path == "/" || path == "/ui" {
        return Action::Read;
    }
    // Run/scan sub-resources: {id}/approve|reject and deletes are governance,
    // {id}/cancel is work, other writes under a run are work.
    for root in ["/api/agent/runs/", "/api/scans/", "/runs/"] {
        if let Some(rest) = path.strip_prefix(root) {
            let (_id, sub) = match rest.split_once('/') {
                Some((id, sub)) => (id, sub),
                None => (rest, ""),
            };
            if method == Method::DELETE {
                return Action::Admin;
            }
            return match sub {
                "" | "cancel" | "report" | "findings" => Action::Operate,
                "approve" | "reject" => Action::Admin,
                _ => Action::Admin,
            };
        }
    }
    // Governance first (a prefix below could shadow them otherwise):
    if path == "/api/fix"
        || path == "/api/agent/memory/accept"
        || path == "/api/agent/memory/forget"
        || (path.starts_with("/api/agent/memory/") && method == Method::DELETE)
    {
        return Action::Admin;
    }
    // Work triggers:
    if matches!(
        path,
        "/runs"
            | "/api/scans"
            | "/api/agent/run"
            | "/api/agent/retest"
            | "/api/agent/requester-ip"
            | "/api/network/requester-ip"
    ) || path.starts_with("/api/agent/discover")
        || path.starts_with("/api/agent/directives")
        || path.starts_with("/api/agent/crawl")
        || path.starts_with("/api/network/")
        || path == "/api/eval-ai"
        || path == "/api/mutate"
        || path == "/api/github/pr-comment"
    {
        return Action::Operate;
    }
    Action::Admin // fail closed: unclassified writes are governance-only
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub name: String,
    pub role: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub key_sha256: String,
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RbacFile {
    rbac: RbacFlags,
    #[serde(default)]
    key: Vec<KeyEntry>,
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RbacFlags {
    enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub role: Role,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Rbac {
    pub enabled: bool,
    pub keys: Vec<Identity>,
}

fn sha(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

fn const_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim().trim_start_matches("sha256:");
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(s.as_bytes()[i * 2])? << 4) | nib(s.as_bytes()[i * 2 + 1])?;
    }
    Some(out)
}

impl Rbac {
    /// Resolve the toggle + keyring. `file` = READYHAI_RBAC_FILE path (or None).
    /// Env toggle (most specific): READYHAI_RBAC = on|off|auto (default).
    /// Auto = ON when the file exists; `[rbac] enabled` in the file applies under auto.
    /// `on` with no file or zero keys is a boot error (fail closed, loudly).
    pub fn load(file: Option<&Path>) -> Result<Rbac> {
        let path = file.filter(|p| p.is_file());
        let flag = std::env::var("READYHAI_RBAC")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "auto".into());
        if !matches!(flag.as_str(), "on" | "off" | "auto") {
            return Err(anyhow!("READYHAI_RBAC must be on|off|auto, got {flag:?}"));
        }
        let mut parsed = RbacFile::default();
        if let Some(p) = path {
            let text = std::fs::read_to_string(p)?;
            parsed = toml::from_str(&text).map_err(|e| anyhow!("{}: {e}", p.display()))?;
        } else if flag == "on" {
            return Err(anyhow!(
                "READYHAI_RBAC=on but no key file; point READYHAI_RBAC_FILE at an rbac.toml"
            ));
        }
        let enabled = match flag.as_str() {
            "on" => true,
            "off" => false,
            _ => match parsed.rbac.enabled {
                Some(v) => v,
                None => path.is_some(),
            },
        };
        let mut keys: Vec<Identity> = Vec::new();
        for k in parsed.key {
            let role = Role::parse(&k.role).map_err(|e| anyhow!("key {:?}: {e}", k.name))?;
            if k.name.is_empty()
                || k.name.len() > 64
                || !k
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._@:-".contains(c))
            {
                return Err(anyhow!(
                    "key name {:?}: 1-64 chars of [A-Za-z0-9._@:-]",
                    k.name
                ));
            }
            let digest = match (k.key.is_empty(), k.key_sha256.is_empty()) {
                (false, true) => {
                    if k.key.chars().count() < MIN_TOKEN_CHARS {
                        return Err(anyhow!(
                            "key {:?}: shorter than {MIN_TOKEN_CHARS} chars",
                            k.name
                        ));
                    }
                    if BANNED_TOKENS.contains(&k.key.as_str()) {
                        return Err(anyhow!("key {:?}: publicly known example token", k.name));
                    }
                    sha(&k.key)
                }
                (true, false) => unhex32(&k.key_sha256)
                    .ok_or_else(|| anyhow!("key {:?}: key_sha256 must be 64 hex chars", k.name))?,
                _ => {
                    return Err(anyhow!(
                        "key {:?}: set exactly one of key / key_sha256",
                        k.name
                    ));
                }
            };
            if keys.iter().any(|i| i.digest == digest) {
                return Err(anyhow!("key {:?}: duplicate key material", k.name));
            }
            if keys.iter().any(|i| i.name == k.name) {
                return Err(anyhow!("key {:?}: duplicate name", k.name));
            }
            keys.push(Identity {
                name: k.name,
                role,
                digest,
            });
        }
        if enabled && keys.is_empty() {
            return Err(anyhow!(
                "RBAC is enabled but no [[key]] entries exist; refusing to start a server nobody can call"
            ));
        }
        Ok(Rbac { enabled, keys })
    }

    /// Which toggle rule decided today's state, for status endpoints and logs.
    pub fn toggle_mode() -> &'static str {
        match std::env::var("READYHAI_RBAC")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .as_deref()
        {
            Some("on") => "on",
            Some("off") => "off",
            _ => "auto",
        }
    }

    /// Authenticate a bearer token → (identity name, role).
    /// RBAC off: only the legacy boot token, as Admin (exact legacy behavior).
    /// RBAC on: keyring first; the boot token stays break-glass Admin unless
    /// READYHAI_RBAC_BOOT_ADMIN=0.
    pub fn authenticate(
        &self,
        token: &str,
        legacy_digest: &[u8; 32],
        legacy_principal: &str,
    ) -> Option<(String, Role)> {
        let d = sha(token);
        if let Some(id) = self.keys.iter().find(|i| const_eq(&i.digest, &d)) {
            return Some((id.name.clone(), id.role));
        }
        let boot_ok = std::env::var("READYHAI_RBAC_BOOT_ADMIN")
            .map(|v| v != "0")
            .unwrap_or(true);
        if const_eq(&d, legacy_digest) && (!self.enabled || boot_ok) {
            return Some((legacy_principal.to_string(), Role::Admin));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rh-rbac-{name}-{}.toml", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn role_order_and_matrix() {
        assert!(Role::Viewer < Role::Operator && Role::Operator < Role::Admin);
        assert!(Role::Viewer.allows(Action::Read));
        assert!(!Role::Viewer.allows(Action::Operate));
        assert!(Role::Operator.allows(Action::Operate));
        assert!(!Role::Operator.allows(Action::Admin));
        assert!(Role::Admin.allows(Action::Admin));
        assert_eq!(Role::parse("OPERATOR").unwrap(), Role::Operator);
        assert!(Role::parse("root").is_err());
    }

    #[test]
    fn action_matrix_classifies_every_surface() {
        let g = |p: &str| action_for(&Method::GET, p);
        let p = |path: &str| action_for(&Method::POST, path);
        let d = |path: &str| action_for(&Method::DELETE, path);
        assert_eq!(g("/runs/run-1/findings"), Action::Read);
        assert_eq!(g("/health"), Action::Read);
        // a query string must not downgrade a POST
        assert_eq!(action_for(&Method::POST, "/runs?x=1"), Action::Operate);
        assert_eq!(p("/runs"), Action::Operate);
        assert_eq!(p("/api/scans"), Action::Operate);
        assert_eq!(p("/api/network/curl"), Action::Operate);
        assert_eq!(p("/api/mutate"), Action::Operate);
        assert_eq!(p("/api/fix"), Action::Admin);
        assert_eq!(p("/api/agent/memory/accept"), Action::Admin);
        assert_eq!(p("/api/agent/runs/r1/approve"), Action::Admin);
        assert_eq!(p("/api/agent/runs/r1/reject"), Action::Admin);
        assert_eq!(p("/api/agent/runs/r1/cancel"), Action::Operate);
        assert_eq!(d("/api/scans/r1"), Action::Admin);
        assert_eq!(d("/api/agent/runs/r1"), Action::Admin);
        assert_eq!(d("/api/agent/memory"), Action::Admin);
        // fail closed: an unclassified write is Admin
        assert_eq!(p("/api/brand-new-thing"), Action::Admin);
    }

    #[test]
    fn load_toggle_matrix_and_key_validation() {
        let _g = crate::engine::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("READYHAI_RBAC") };
        // auto + no file = off, legacy
        let r = Rbac::load(None).unwrap();
        assert!(!r.enabled);

        let f = write_tmp(
            "keys",
            "[[key]]\nname = \"ci\"\nrole = \"operator\"\nkey = \"ci-key-0123456789abcdef\"\n[[key]]\nname = \"secops\"\nrole = \"admin\"\nkey_sha256 = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n",
        );
        // auto + file = on
        let r = Rbac::load(Some(&f)).unwrap();
        assert!(r.enabled);
        assert_eq!(r.keys.len(), 2);
        assert_eq!(r.keys[0].role, Role::Operator);
        // explicit env off wins over the file existing
        unsafe { std::env::set_var("READYHAI_RBAC", "off") };
        assert!(!Rbac::load(Some(&f)).unwrap().enabled);
        // env on with no file = error
        unsafe { std::env::set_var("READYHAI_RBAC", "on") };
        assert!(Rbac::load(None).is_err());
        unsafe { std::env::remove_var("READYHAI_RBAC") };
        // file-side toggle: [rbac] enabled = false under auto
        let off = write_tmp(
            "off",
            "[rbac]\nenabled = false\n[[key]]\nname = \"a\"\nrole = \"viewer\"\nkey = \"aaaa-0123456789abcdef\"\n",
        );
        assert!(!Rbac::load(Some(&off)).unwrap().enabled);
        let _ = std::fs::remove_file(off);

        // short key rejected
        let bad = write_tmp(
            "short",
            "[[key]]\nname = \"a\"\nrole = \"viewer\"\nkey = \"short\"\n",
        );
        assert!(Rbac::load(Some(&bad)).is_err());
        // empty keyring with enabled = error
        let empty = write_tmp("empty", "[rbac]\nenabled = true\n");
        assert!(Rbac::load(Some(&empty)).is_err());
        // duplicate key material
        let dup = write_tmp(
            "dup",
            "[[key]]\nname = \"a\"\nrole = \"viewer\"\nkey = \"aaaa-0123456789abcdef\"\n[[key]]\nname = \"b\"\nrole = \"viewer\"\nkey = \"aaaa-0123456789abcdef\"\n",
        );
        assert!(Rbac::load(Some(&dup)).is_err());
        // unknown field rejected
        let unk = write_tmp(
            "unk",
            "[[key]]\nname = \"a\"\nrole = \"viewer\"\nkey = \"aaaa-0123456789abcdef\"\nextra = 1\n",
        );
        assert!(Rbac::load(Some(&unk)).is_err());
        for p in [f, bad, empty, dup, unk] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn authenticate_keyring_and_break_glass() {
        let _g = crate::engine::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("READYHAI_RBAC_BOOT_ADMIN") };
        let legacy = Sha256::digest(b"boot-token-0123456789abcdef").into();
        let f = write_tmp(
            "auth",
            "[[key]]\nname = \"bot\"\nrole = \"operator\"\nkey = \"bot-key-0123456789abcdef\"\n",
        );
        let r = Rbac::load(Some(&f)).unwrap();
        assert_eq!(
            r.authenticate("bot-key-0123456789abcdef", &legacy, "boot"),
            Some(("bot".into(), Role::Operator))
        );
        // break-glass boot token still admin when RBAC on
        assert_eq!(
            r.authenticate("boot-token-0123456789abcdef", &legacy, "boot"),
            Some(("boot".into(), Role::Admin))
        );
        assert_eq!(
            r.authenticate("nope-nope-nope-nope-1234", &legacy, "boot"),
            None
        );
        // boot admin can be disabled
        unsafe { std::env::set_var("READYHAI_RBAC_BOOT_ADMIN", "0") };
        assert_eq!(
            r.authenticate("boot-token-0123456789abcdef", &legacy, "boot"),
            None
        );
        unsafe {
            std::env::remove_var("READYHAI_RBAC_BOOT_ADMIN");
            std::env::remove_var("READYHAI_RBAC");
        }
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn legacy_mode_authenticates_only_boot_token() {
        let _g = crate::engine::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("READYHAI_RBAC") };
        let r = Rbac::load(None).unwrap();
        assert!(!r.enabled);
        let legacy = Sha256::digest(b"boot-token-0123456789abcdef").into();
        assert_eq!(
            r.authenticate("boot-token-0123456789abcdef", &legacy, "boot"),
            Some(("boot".into(), Role::Admin))
        );
        assert!(r.authenticate("other", &legacy, "boot").is_none());
    }
}
