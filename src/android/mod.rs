//! Android targets: MobSF static (short-lived per-scan container, REST API) +
//! BYO-device ADB runtime (owned by the android agent).

pub mod mobsf;
pub mod runtime;
pub mod staging;
pub mod util;

#[cfg(test)]
pub(crate) mod tests;

use crate::checks::Check;
use crate::model::{Profile, TargetKind};

#[allow(unused_imports)]
pub use mobsf::{map_report, parse_docker_port, run_mobsf, scrub_report};

#[allow(unused_imports)]
pub use runtime::{LogScan, is_emulator, run_runtime, scan_logcat};

#[allow(unused_imports)]
pub use util::{form_body, multipart_body, redact};

pub fn checks() -> Vec<Check> {
    vec![
        Check::new(
            "android.mobsf",
            "Android static analysis (MobSF)",
            &[TargetKind::Android],
            Profile::Quick,
            mobsf::run_mobsf,
        )
        .tool("mobsf"),
        Check::new(
            "android.runtime",
            "Android runtime: install, launch, logcat crashes/ANRs",
            &[TargetKind::Android],
            Profile::Standard,
            runtime::run_runtime,
        ),
    ]
}
