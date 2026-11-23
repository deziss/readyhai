//! Operator settings layer: tri-state toggles for tool integrations (tools, plugins,
//! intrusive class) and per-check enable/disable by id or glob.
//!
//! Layering (operator-owned only — a scanned target's own repo is NEVER consulted, and
//! server mode ignores anything the target could supply):
//!   `--settings <file>` > `READYHAI_SETTINGS` env > none (everything `auto`).
//!
//! Tri-state: `auto` = today's behaviour (kind/profile/intrusive gates only);
//! `on` = never skipped *by settings* (it does NOT bypass the profile, scope-nonprod,
//! `--no-tools` or docker gates); `off` = skipped with a visible reason.
//! Rule resolution per check id: exact `[[toggle]]` first, then the LAST matching glob
//! `[[toggle]]`, then the category kill-switch, then auto. `integrations.intrusive`
//! only accepts auto/off — settings can never force an intrusive check to run.
use anyhow::{Result, anyhow};
use globset::Glob;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub integrations: Integrations,
    /// Per-check toggles, evaluated in file order (last match wins).
    #[serde(default)]
    pub toggle: Vec<Toggle>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Integrations {
    /// Checks backed by a pinned container tool (`tools.lock.toml` images).
    pub tools: TriState,
    /// Plugin checks (`plugin.*`) from the plugins dir.
    pub plugins: TriState,
    /// Kill switch for the intrusive class; `on` is rejected at load.
    pub intrusive: TriState,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", try_from = "String")]
pub enum TriState {
    #[default]
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Toggle {
    /// Check id or glob, e.g. "tool.nuclei" or "plugin.*".
    pub id: String,
    pub enabled: TriState,
}

impl TryFrom<String> for TriState {
    type Error = String;
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        TriState::parse(&s).map_err(|e| e.to_string())
    }
}

impl TriState {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "on" | "true" | "1" => Ok(Self::On),
            "off" | "false" | "0" => Ok(Self::Off),
            _ => Err(anyhow!("expected auto|on|off, got {s:?}")),
        }
    }
}

/// What a disabled decision looks like to the run: a Skipped status with reason.
/// Surfaced in the report like every other skip, so a toggle never hides coverage.
impl Settings {
    /// Load + validate. `None` path or missing file = defaults (all auto). A file
    /// that fails to parse is a hard error — a silently-ignored settings file must
    /// never flip an integration the operator meant to keep off.
    pub fn load(path: Option<&Path>) -> Result<Settings> {
        let Some(p) = path else { return Ok(Settings::default()) };
        if !p.is_file() {
            if p == Path::new("") {
                return Ok(Settings::default());
            }
            return Err(anyhow!("settings file {} not found", p.display()));
        }
        let text = std::fs::read_to_string(p)?;
        let s: Settings =
            toml::from_str(&text).map_err(|e| anyhow!("{}: {e}", p.display()))?;
        s.validate()?;
        Ok(s)
    }

    pub fn validate(&self) -> Result<()> {
        if self.integrations.intrusive == TriState::On {
            return Err(anyhow!(
                "integrations.intrusive cannot be 'on': intrusive checks require --profile deep and a nonprod host; allowed: auto|off"
            ));
        }
        for t in &self.toggle {
            if t.id.is_empty() {
                return Err(anyhow!("toggle entry with empty id"));
            }
            Glob::new(&t.id)
                .map_err(|e| anyhow!("toggle id {:?} is not a valid glob: {e}", t.id))?;
        }
        Ok(())
    }

    /// Skip reason for a check, if settings disable it. Exact id > last matching
    /// glob > category switch > auto (None).
    pub fn skip(
        &self,
        id: &str,
        is_tool: bool,
        is_plugin: bool,
        intrusive: bool,
    ) -> Option<String> {
        let mut decision = TriState::Auto;
        // Category first; toggles below can override it either way.
        if is_tool && self.integrations.tools != TriState::Auto {
            decision = self.integrations.tools;
        } else if is_plugin && self.integrations.plugins != TriState::Auto {
            decision = self.integrations.plugins;
        }
        // Exact id beats all globs; among globs the last defined wins. A glob
        // toggle only resets an explicit category decision when it is itself
        // explicit (an `auto` glob means "leave the category verdict alone").
        for t in &self.toggle {
            if t.id == id {
                decision = t.enabled;
                break;
            }
            if t.id.contains(['*', '?'])
                && Glob::new(&t.id)
                    .map(|g| g.compile_matcher().is_match(id))
                    .unwrap_or(false)
                && (t.enabled != TriState::Auto || decision == TriState::Auto)
            {
                decision = t.enabled;
            }
        }
        // The intrusive kill switch can only ADD a skip, never remove one.
        if self.integrations.intrusive == TriState::Off && intrusive {
            return Some("integrations.intrusive = off (operator kill switch)".into());
        }
        match decision {
            TriState::Off => Some(if is_plugin {
                format!("disabled by settings (plugin {id})")
            } else {
                format!("disabled by settings (check {id})")
            }),
            _ => None,
        }
    }

    /// Count of explicit toggles + non-auto switches, for doctor output.
    pub fn override_count(&self) -> usize {
        let cats = [
            self.integrations.tools,
            self.integrations.plugins,
            self.integrations.intrusive,
        ];
        self.toggle.len() + cats.iter().filter(|c| **c != TriState::Auto).count()
    }
}

/// Resolution used by CLI/serve: explicit `--settings` path, else `READYHAI_SETTINGS`.
pub fn settings_path_from_env() -> Option<std::path::PathBuf> {
    std::env::var("READYHAI_SETTINGS")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t: &str) -> Settings {
        toml::from_str(t).expect("valid test settings")
    }

    #[test]
    fn defaults_are_all_auto() {
        let st = Settings::default();
        assert_eq!(st.skip("tool.nuclei", true, false, false), None);
        assert_eq!(st.skip("plugin.trivy", false, true, false), None);
        assert_eq!(st.override_count(), 0);
    }

    #[test]
    fn kill_switch_disables_category() {
        let st = s("[integrations]\ntools = \"off\"\nplugins = \"off\"\n");
        assert!(st.skip("tool.nuclei", true, false, false).is_some());
        assert!(st.skip("plugin.httpx", false, true, false).is_some());
        assert_eq!(st.skip("web.headers", false, false, false), None);
    }

    #[test]
    fn exact_toggle_overrides_kill_switch() {
        let st = s("[integrations]\ntools = \"off\"\n[[toggle]]\nid = \"tool.nuclei\"\nenabled = \"on\"\n");
        assert!(st.skip("tool.nuclei", true, false, false).is_none());
        assert!(st.skip("tool.grype", true, false, false).is_some());
    }

    #[test]
    fn glob_toggle_last_match_wins() {
        let st = s("[[toggle]]\nid = \"plugin.*\"\nenabled = \"off\"\n[[toggle]]\nid = \"plugin.kube*\"\nenabled = \"on\"\n");
        assert!(st.skip("plugin.httpx", false, true, false).is_some());
        assert_eq!(st.skip("plugin.kube-linter", false, true, false), None);
    }

    #[test]
    fn intrusive_kill_switch_cannot_be_on() {
        let st = s("[integrations]\nintrusive = \"off\"\n");
        assert!(st.skip("tool.zap_active", true, false, true).is_some());
        assert_eq!(st.skip("tool.zap_baseline", true, false, false), None);
        let mut v = s("");
        v.integrations.intrusive = TriState::On;
        assert!(v.validate().is_err());
        s("[integrations]\nintrusive = \"off\"\n")
            .validate()
            .expect("off is allowed");
    }

    #[test]
    fn unknown_keys_and_bad_toggles_are_rejected() {
        assert!(toml::from_str::<Settings>("bogus = 1").is_err());
        assert!(toml::from_str::<Settings>("[integrations]\nnope = \"off\"").is_err());
        // an unparseable enabled value is a load error, not a silent auto
        assert!(toml::from_str::<Settings>("[[toggle]]\nid = \"x\"\nenabled = \"maybe\"")
            .is_err());
        let bad = Settings {
            toggle: vec![Toggle { id: "".into(), enabled: TriState::Off }],
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        let bad_glob = Settings {
            toggle: vec![Toggle { id: "tool.[[".into(), enabled: TriState::Off }],
            ..Default::default()
        };
        assert!(bad_glob.validate().is_err());
    }

    #[test]
    fn tri_state_parses_aliases() {
        assert_eq!(TriState::parse("ON").unwrap(), TriState::On);
        assert_eq!(TriState::parse("false").unwrap(), TriState::Off);
        assert!(TriState::parse("yes").is_err());
    }
}
