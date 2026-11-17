//! Host targets over SSH: probe scripts piped over the system OpenSSH client,
//! parsed into findings; Lynis from a cached tarball; package CVEs via grype.

pub mod lynis;
pub mod probe;
pub mod redact;
pub mod runner;
pub mod ssh;
pub mod types;

#[cfg(test)]
pub(crate) mod tests;

#[allow(unused_imports)]
pub use lynis::{fetch_lynis, lynis_findings, parse_lynis};

#[allow(unused_imports)]
pub use probe::{parse_probe, sbom_from_probe};

#[allow(unused_imports)]
pub use redact::redact_line;

#[allow(unused_imports)]
pub use runner::checks;

#[allow(unused_imports)]
pub use ssh::{run_ssh, ssh_args};

#[allow(unused_imports)]
pub use types::{
    LINUX_SH, LYNIS_URL, LYNIS_VERSION, LynisReport, MACOS_SH, ProbeResult, SshOut, WINDOWS_PS1,
};
