//! Common types and constants for SSH host inspection and auditing.
use serde_json::Value;

use crate::model::Finding;

pub const LINUX_SH: &str = include_str!("../../probe/linux.sh");
pub const MACOS_SH: &str = include_str!("../../probe/macos.sh");
pub const WINDOWS_PS1: &str = include_str!("../../probe/windows.ps1");

pub const LYNIS_VERSION: &str = "3.1.6";
pub const LYNIS_URL: &str = "https://downloads.cisofy.com/lynis/lynis-3.1.6.tar.gz";

#[derive(Debug, Default)]
pub struct ProbeResult {
    pub findings: Vec<Finding>,
    /// (source, redacted line)
    pub error_lines: Vec<(String, String)>,
    pub partial: Vec<String>,
    pub sbom: Option<Value>,
}

#[derive(Debug, Default)]
pub struct SshOut {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

#[derive(Debug, Default)]
pub struct LynisReport {
    pub warnings: Vec<(String, String)>,
    pub suggestions: Vec<(String, String)>,
    pub hardening_index: Option<u32>,
    pub uid: Option<u32>,
}
