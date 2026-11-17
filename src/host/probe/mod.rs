//! Target host OS probe parsing and analysis.

pub mod common;
pub mod linux;
pub mod macos;
pub mod sbom;
pub mod windows;

pub use sbom::sbom_from_probe;

use serde_json::Value;

use crate::host::types::ProbeResult;
use crate::model::Os;

pub fn parse_probe(os: Os, v: &Value, who: &str) -> ProbeResult {
    let mut r = ProbeResult::default();
    r.partial = common::strs(&v["partial"]);

    // sshd (linux + macos)
    if os != Os::Windows {
        common::check_sshd(v, who, &mut r);
    }

    // disks (linux + macos)
    common::check_disks(v, who, &mut r);

    match os {
        Os::Linux => linux::check_linux(v, who, &mut r),
        Os::Macos => macos::check_macos(v, who, &mut r),
        Os::Windows => windows::check_windows(v, who, &mut r),
    }

    if os == Os::Linux {
        r.sbom = sbom_from_probe(v);
    }

    r
}
