//! Check registry ("mods"). Built-in modules contribute `checks()`; external
//! plugins (plugins/<name>/plugin.toml) are loaded by `tools::plugin_checks`.
//! The engine filters by target kind and profile.
use crate::ctx::Ctx;
use crate::model::{CheckOutput, Profile, TargetKind};

pub type RunFn = Box<dyn Fn(&Ctx) -> anyhow::Result<CheckOutput> + Send + Sync>;

pub struct Check {
    pub id: String,
    pub title: String,
    pub kinds: Vec<TargetKind>,
    pub min_profile: Profile,
    /// Container-backed tool name (reported; check is skipped when docker is absent).
    pub tool: Option<String>,
    /// Intrusive checks need a scope.toml entry tagged nonprod.
    pub intrusive: bool,
    /// Senior-QA check: runs only under `readyhai qa`.
    pub qa: bool,
    pub run: RunFn,
}

impl Check {
    pub fn new(
        id: &str,
        title: &str,
        kinds: &[TargetKind],
        min_profile: Profile,
        run: impl Fn(&Ctx) -> anyhow::Result<CheckOutput> + Send + Sync + 'static,
    ) -> Self {
        Check {
            id: id.into(),
            title: title.into(),
            kinds: kinds.to_vec(),
            min_profile,
            tool: None,
            intrusive: false,
            qa: false,
            run: Box::new(run),
        }
    }
    pub fn tool(mut self, tool: &str) -> Self {
        self.tool = Some(tool.into());
        self
    }
    #[allow(dead_code)]
    pub fn qa(mut self) -> Self {
        self.qa = true;
        self
    }
    pub fn intrusive(mut self) -> Self {
        self.intrusive = true;
        self
    }
}

pub fn all(plugin_dir: Option<&std::path::Path>) -> Vec<Check> {
    let mut v = crate::rules::checks();
    v.extend(crate::tools::checks());
    v.extend(crate::web::checks());
    v.extend(crate::host::checks());
    v.extend(crate::android::checks());
    v.extend(crate::qa::checks());
    v.extend(crate::supply::checks());
    if let Some(d) = plugin_dir {
        v.extend(crate::tools::plugin_checks(d));
    }
    v
}
