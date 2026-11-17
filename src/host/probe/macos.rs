//! macOS probe output analysis.
use serde_json::{Value, json};

use super::common::strs;
use crate::host::redact::redact_line;
use crate::host::types::ProbeResult;
use crate::model::{Category, Finding, Severity};

pub(crate) fn check_macos(v: &Value, who: &str, r: &mut ProbeResult) {
    let sec = |s: &str| format!("{who}:{s}");

    if v["sip_enabled"] == json!(false) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.sip_disabled",
                Category::Security,
                Severity::High,
                "System Integrity Protection is disabled",
                sec("sip"),
            )
            .remediation("Re-enable SIP from Recovery: `csrutil enable`.")
            .fp_key(format!("{who}|sip")),
        );
    }

    if v["gatekeeper_enabled"] == json!(false) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.gatekeeper_off",
                Category::Security,
                Severity::Medium,
                "Gatekeeper is disabled",
                sec("gatekeeper"),
            )
            .remediation("Run `sudo spctl --master-enable`.")
            .fp_key(format!("{who}|gatekeeper")),
        );
    }

    if v["filevault_on"] == json!(false) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.filevault_off",
                Category::Security,
                Severity::Medium,
                "FileVault disk encryption is off",
                sec("filevault"),
            )
            .remediation("Enable FileVault in System Settings > Privacy & Security.")
            .fp_key(format!("{who}|filevault")),
        );
    }

    if v["firewall_enabled"] == json!(false) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.mac_firewall_off",
                Category::Security,
                Severity::Medium,
                "Application firewall is off",
                sec("firewall"),
            )
            .remediation("Enable the macOS firewall (System Settings > Network > Firewall).")
            .fp_key(format!("{who}|firewall")),
        );
    }

    for l in strs(&v["error_lines"]) {
        r.error_lines.push(("host.oslog".into(), redact_line(&l)));
    }
}
