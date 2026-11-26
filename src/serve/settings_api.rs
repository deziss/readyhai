//! Operator settings over REST: effective toggles, the editable data-dir copy,
//! the check catalog with effective decisions, and an RBAC status summary.
//!
//! The writable file is always `<data>/settings.toml`. An operator `--settings`
//! / `READYHAI_SETTINGS` file outranks it for scans (flag > env > data dir), so
//! responses mark `shadowing_env` and say which file scans actually use. Writes
//! are admin-gated by the RBAC middleware (PUT/DELETE classify as govern).

use super::guards::err;
use super::types::App;
use crate::engine;
use crate::settings::{Integrations, Settings, TriState};
use axum::Json;
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;

/// Data-dir file the UI edits. `<data>/settings.toml`.
pub fn data_settings_path() -> PathBuf {
    engine::data_dir().join("settings.toml")
}

/// Path that `serve`-launched scans actually use. Same rule the scan routes apply
/// (see `scan_settings_path`): operator env file wins; else the data-dir file.
pub fn scan_settings_path() -> Option<PathBuf> {
    crate::settings::settings_path_from_env().or_else(|| {
        let d = data_settings_path();
        d.is_file().then_some(d)
    })
}

fn effective() -> (Settings, Option<PathBuf>) {
    let path = scan_settings_path();
    match Settings::load(path.as_deref()) {
        Ok(s) => (s, path),
        // A broken effective file must still answer (the run itself hard-errors);
        // report defaults with the error visible so the UI can say why.
        Err(_) => (Settings::default(), path),
    }
}

fn tri(t: TriState) -> &'static str {
    match t {
        TriState::Auto => "auto",
        TriState::On => "on",
        TriState::Off => "off",
    }
}

fn body(s: &Settings, path: Option<PathBuf>, version: u64, shadowing: bool) -> Value {
    json!({
        "path": path,
        "exists": path.as_ref().is_some_and(|p| p.is_file()),
        "editable": true,
        "version": version,
        "effective": {
            "integrations": {
                "tools": tri(s.integrations.tools),
                "plugins": tri(s.integrations.plugins),
                "intrusive": tri(s.integrations.intrusive),
            },
            "vulndb": {
                "enabled": s.vulndb.enabled,
                "path": s.vulndb.path.clone(),
            },
            "exploits": {
                "enabled": s.exploits.enabled,
                "max_probes": s.exploits.max_probes,
            },
            "toggle": s.toggle.iter().map(|t| json!({"id": t.id, "enabled": tri(t.enabled)})).collect::<Vec<_>>(),
        },
        "override_count": s.override_count(),
        "shadowing_env": shadowing,
    })
}

fn shadowing_env() -> bool {
    // An operator READYHAI_SETTINGS file outranks whatever the UI edits in the
    // data dir; the UI must say so instead of confusing.
    crate::settings::settings_path_from_env().is_some()
}

/// Version token = mtime+size of the data-dir file, so a concurrent writer is visible.
fn version_of() -> u64 {
    let p = data_settings_path();
    match std::fs::metadata(&p) {
        Ok(m) => {
            let t = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            t ^ (m.len() << 1)
        }
        Err(_) => 0,
    }
}

pub async fn api_settings_get() -> Response {
    let (s, path) = effective();
    Json(body(&s, path, version_of(), shadowing_env())).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TriToggle {
    id: String,
    enabled: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TriIntegrations {
    tools: Option<String>,
    plugins: Option<String>,
    intrusive: Option<String>,
}

/// A `[vulndb] path` in a PUT: a string sets it, `null` clears it, and an absent key
/// leaves it alone. Deserialization is manual: `#[serde(default)]` on the field only
/// fires when the key is absent, so an untagged/plain `Option` would collapse an
/// explicit `null` and a `null` could never clear the path.
#[derive(Default)]
enum PathPut {
    /// Key absent from the request — leave the stored path alone.
    #[default]
    Keep,
    /// Explicit JSON null — clear the stored path. An `Option` field cannot express
    /// this: serde turns null into "absent" before the inner type is consulted.
    Clear,
    Set(String),
}

impl<'de> Deserialize<'de> for PathPut {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        match v {
            Value::Null => Ok(PathPut::Clear),
            Value::String(s) => Ok(PathPut::Set(s)),
            _ => Err(serde::de::Error::custom(
                "vulndb.path must be a string or null",
            )),
        }
    }
}

/// Optional `[vulndb]` half of a PUT. Absent means "leave the section alone" — a Save
/// from the integrations UI must not silently re-enable recording.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VulnDbPut {
    enabled: Option<bool>,
    #[serde(default)]
    path: PathPut,
}

/// Optional `[exploits]` half of a PUT; same carry-over semantics as `[vulndb]`.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ExploitsPut {
    enabled: Option<bool>,
    max_probes: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SettingsPut {
    integrations: Option<TriIntegrations>,
    toggle: Option<Vec<TriToggle>>,
    vulndb: Option<VulnDbPut>,
    exploits: Option<ExploitsPut>,
}

fn bad(e: impl std::fmt::Display) -> Response {
    err(StatusCode::BAD_REQUEST, e.to_string())
}

pub async fn api_settings_put(Json(req): Json<SettingsPut>) -> Response {
    let parse = |s: &Option<String>| -> Result<Option<TriState>, String> {
        s.as_deref()
            .map(TriState::parse)
            .transpose()
            .map_err(|e| e.to_string())
    };
    let mut settings = Settings::default();
    if let Some(i) = req.integrations {
        match (parse(&i.tools), parse(&i.plugins), parse(&i.intrusive)) {
            (Ok(tools), Ok(plugins), Ok(intrusive)) => {
                settings.integrations = Integrations {
                    tools: tools.unwrap_or_default(),
                    plugins: plugins.unwrap_or_default(),
                    intrusive: intrusive.unwrap_or_default(),
                };
            }
            _ => return bad("integrations values must be auto|on|off"),
        }
    }
    if let Some(t) = req.toggle {
        for tt in t {
            match TriState::parse(&tt.enabled) {
                Ok(enabled) => settings
                    .toggle
                    .push(crate::settings::Toggle { id: tt.id, enabled }),
                Err(e) => return bad(e),
            }
        }
    }
    // `[vulndb]` is carried over from the file this PUT replaces unless the request
    // changes it, so saving integrations or toggles never re-enables recording on its own.
    let file = data_settings_path();
    settings.vulndb = Settings::load(file.is_file().then_some(&file))
        .unwrap_or_default()
        .vulndb;
    if let Some(v) = req.vulndb {
        if let Some(enabled) = v.enabled {
            settings.vulndb.enabled = enabled;
        }
        match v.path {
            PathPut::Keep => {}
            PathPut::Clear => settings.vulndb.path = None,
            PathPut::Set(p) => settings.vulndb.path = Some(p),
        }
    }
    // `[exploits]` carries over like `[vulndb]`: a save from another card must not
    // silently re-enable request-sending verification.
    settings.exploits = Settings::load(file.is_file().then_some(&file))
        .unwrap_or_default()
        .exploits;
    if let Some(x) = req.exploits {
        if let Some(enabled) = x.enabled {
            settings.exploits.enabled = enabled;
        }
        if let Some(max) = x.max_probes {
            settings.exploits.max_probes = max;
        }
    }
    if let Err(e) = settings.validate() {
        return bad(e);
    }
    let text = match toml::to_string(&settings) {
        Ok(t) => t,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {e}")),
    };
    let path = data_settings_path();
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    // Atomic: write beside, rename over. A partially-written settings file would
    // hard-fail every queued scan (settings files are validated, not ignored).
    let tmp = path.with_extension("toml.tmp");
    if let Err(e) = std::fs::write(&tmp, &text).and_then(|()| std::fs::rename(&tmp, &path)) {
        let _ = std::fs::remove_file(&tmp);
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    let (s, p) = effective();
    let mut v = body(&s, p, version_of(), shadowing_env());
    v["note"] = json!("saved; scans pick the file up on their next run");
    Json(v).into_response()
}

pub async fn api_settings_delete() -> Response {
    let path = data_settings_path();
    if path.is_file()
        && let Err(e) = std::fs::remove_file(&path)
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    // Delete means "back to defaults" — if an operator env file is configured, it
    // still applies; the response's shadowing_env/path say what scans will use.
    let (s, p) = effective();
    let mut v = body(&s, p, version_of(), shadowing_env());
    v["note"] = json!("data-dir settings removed");
    Json(v).into_response()
}

#[derive(Deserialize)]
pub struct ChecksQuery {
    /// Limit the catalog to checks usable on this target kind (repo|image|web|host|android).
    pub kind: Option<String>,
}

pub async fn api_settings_checks(
    State(app): State<Arc<App>>,
    Query(q): Query<ChecksQuery>,
) -> Response {
    let kind = match q.kind.as_deref() {
        None | Some("") => None,
        Some(k) => match serde_json::from_str::<crate::model::TargetKind>(&format!("\"{k}\"")) {
            Ok(k) => Some(k),
            Err(_) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "kind must be repo|image|web|host|android",
                );
            }
        },
    };
    let (settings, _) = effective();
    let plugins = app.plugins.clone();
    let res = tokio::task::spawn_blocking(move || {
        let checks = crate::checks::all(plugins.as_deref());
        anyhow::Ok(
            checks
                .into_iter()
                .filter(|c| !c.qa)
                .filter(|c| kind.is_none_or(|k| c.kinds.contains(&k)))
                .map(|c| {
                    let reason = settings.skip(
                        &c.id,
                        c.tool.is_some(),
                        c.id.starts_with("plugin."),
                        c.intrusive,
                    );
                    let (enabled, decided_by) = match &reason {
                        Some(r) if r.contains("kill switch") => (false, "integrations"),
                        Some(_) => (false, "settings"),
                        None => (true, "auto"),
                    };
                    json!({
                        "id": c.id,
                        "title": c.title,
                        "source": if c.id.starts_with("plugin.") { "plugin" } else { "builtin" },
                        "kinds": c.kinds,
                        "profile": c.min_profile,
                        "intrusive": c.intrusive,
                        "enabled": enabled,
                        "decided_by": decided_by,
                        "reason": reason,
                    })
                })
                .collect::<Vec<Value>>(),
        )
    })
    .await;
    match res {
        Ok(Ok(v)) => Json(json!({ "checks": v })).into_response(),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("catalog: {e}")),
    }
}

pub async fn api_rbac_get(
    State(app): State<Arc<App>>,
    Extension(who): Extension<super::types::Principal>,
) -> Response {
    // GET classifies as Read in the route matrix, but the key inventory is
    // governance data: only admins see it (403 mirrors the middleware body).
    if app.rbac.enabled && !who.role.allows(super::rbac::Action::Admin) {
        return super::auth::forbidden(who.role.as_str(), "view the RBAC keyring (needs admin)");
    }
    let mut counts: serde_json::Map<String, Value> = serde_json::Map::new();
    for role in ["viewer", "operator", "admin"] {
        counts.insert(role.into(), json!(0));
    }
    let keys: Vec<Value> = app
        .rbac
        .keys
        .iter()
        .map(|k| {
            *counts.get_mut(k.role.as_str()).unwrap() =
                json!(counts[k.role.as_str()].as_u64().unwrap() + 1);
            // Key material never leaves the process; show a short digest prefix.
            let fp = format!("{:02x}{:02x}{:02x}", k.digest[0], k.digest[1], k.digest[2]);
            json!({"name": k.name, "role": k.role.as_str(), "fingerprint": fp})
        })
        .collect();
    Json(json!({
        "enabled": app.rbac.enabled,
        "mode": crate::serve::rbac::Rbac::toggle_mode(),
        "file": std::env::var("READYHAI_RBAC_FILE").ok().map(PathBuf::from),
        "boot_admin": std::env::var("READYHAI_RBAC_BOOT_ADMIN")
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(true),
        "keys": keys,
        "counts": Value::Object(counts),
    }))
    .into_response()
}
