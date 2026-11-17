//! Common helpers for JSON probe extraction and cross-platform checks (sshd, disks).
use serde_json::Value;

use crate::host::types::ProbeResult;
use crate::model::{Category, Finding, Severity};

pub(crate) fn g<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    let mut c = v;
    for p in path {
        c = c.get(*p).unwrap_or(&Value::Null);
    }
    c
}

pub(crate) fn gs<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    g(v, path).as_str().unwrap_or("")
}

pub(crate) fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn check_sshd(v: &Value, who: &str, r: &mut ProbeResult) {
    let sec = |s: &str| format!("{who}:{s}");
    if gs(v, &["sshd", "permitrootlogin"]).eq_ignore_ascii_case("yes") {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.ssh_root_login",
                Category::Security,
                Severity::High,
                "SSH permits root login",
                sec("sshd"),
            )
            .detail("PermitRootLogin yes")
            .remediation(
                "Set `PermitRootLogin prohibit-password` (or no) in sshd_config and reload sshd.",
            )
            .fp_key(format!("{who}|ssh_root")),
        );
    }
    if gs(v, &["sshd", "passwordauthentication"]).eq_ignore_ascii_case("yes") {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.ssh_password_auth",
                Category::Security,
                Severity::Medium,
                "SSH password authentication enabled",
                sec("sshd"),
            )
            .detail("PasswordAuthentication yes")
            .remediation("Use keys: set `PasswordAuthentication no` in sshd_config.")
            .fp_key(format!("{who}|ssh_pw")),
        );
    }
}

pub(crate) fn check_disks(v: &Value, who: &str, r: &mut ProbeResult) {
    let sec = |s: &str| format!("{who}:{s}");
    for d in v["disks"].as_array().cloned().unwrap_or_default() {
        let pct = d["use_pct"].as_u64().unwrap_or(0);
        let mount = d["mount"].as_str().unwrap_or("?");
        if pct > 85 {
            let sev = if pct > 95 {
                Severity::High
            } else {
                Severity::Medium
            };
            r.findings.push(
                Finding::new(
                    "host.probe",
                    "host.disk_full",
                    Category::Reliability,
                    sev,
                    format!("Filesystem {mount} is {pct}% full"),
                    sec(&format!("disk:{mount}")),
                )
                .detail(format!("{mount} at {pct}%"))
                .remediation("Free space or grow the volume before it fills.")
                .fp_key(format!("{who}|disk|{mount}")),
            );
        }
    }
}
