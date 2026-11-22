//! Sandboxed container tools, parsers, plugins (owned by the tools agent).

pub mod checks;
pub mod docker;
pub mod parsers;
pub mod pinning;
pub mod plugins;
pub mod policy;
pub mod process;
pub mod sarif_junit;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export public and crate-visible items for backward compatibility
#[allow(unused_imports)]
pub use checks::{checks, db_age_days, junit_output};
#[allow(unused_imports)]
pub use docker::{Docker, reap_dead_runs, reap_run, reap_run_within};
#[allow(unused_imports)]
pub(crate) use docker::{read_out, read_text_capped};
#[allow(unused_imports)]
pub use parsers::{
    parse_checkov, parse_dockle, parse_gitleaks, parse_grype, parse_hadolint, parse_image_inspect,
    scrub_checkov, scrub_gitleaks, scrub_semgrep,
};
#[cfg(test)]
#[allow(unused_imports)]
pub use parsers::{parse_opengrep, parse_semgrep};
#[allow(unused_imports)]
pub use pinning::{
    add_warning, image_for, image_present, lock_entries, local_image_id, pin_warnings, tools_pull,
    tools_pull_filtered, tools_update,
};
#[allow(unused_imports)]
pub(crate) use pinning::missing_image;
#[allow(unused_imports)]
pub use plugins::{
    PluginDiag, PluginLoad, plugin_checks, plugin_diags, plugin_image_refs, plugins_dir,
};
#[allow(unused_imports)]
pub use policy::validate_create_policy;
#[allow(unused_imports)]
pub use process::run_capped;
#[allow(unused_imports)]
pub use sarif_junit::{parse_junit, parse_sarif_report};
#[allow(unused_imports)]
pub use types::{
    Captured, JunitCase, LockEntry, MountMode, OutTooLarge, TOOL_STDOUT_CAP, ToolRun, ToolSpec,
    is_oversize, out_err, tool_failed,
};
#[allow(unused_imports)]
pub(crate) use types::{MAX_OUT_BYTES, gate, partial};
