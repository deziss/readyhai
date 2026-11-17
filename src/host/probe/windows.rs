//! Windows probe output analysis.
use serde_json::{Value, json};

use super::common::{gs, strs};
use crate::host::redact::redact_line;
use crate::host::types::ProbeResult;
use crate::model::{Category, Finding, Severity};

pub(crate) fn check_windows(v: &Value, who: &str, r: &mut ProbeResult) {
    let sec = |s: &str| format!("{who}:{s}");

    if v["language_mode"]
        .as_str()
        .is_some_and(|m| m != "FullLanguage")
    {
        r.partial.push(format!(
            "PowerShell LanguageMode is {}",
            gs(v, &["language_mode"])
        ));
        r.partial.dedup();
    }
    if v["elevated"] == json!(false) && !r.partial.iter().any(|p| p.contains("not elevated")) {
        r.partial
            .push("not elevated: Defender/SMB/update data may be missing".into());
    }

    let d = &v["defender"];
    if d["realtime"] == json!(false) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.defender_off",
                Category::Security,
                Severity::High,
                "Defender real-time protection is off",
                sec("defender"),
            )
            .remediation("Enable real-time protection (or confirm another EDR is active).")
            .fp_key(format!("{who}|defender_off")),
        );
    }
    if let Some(age) = d["signature_age_days"].as_f64()
        && age > 3.0
    {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.defender_stale",
                Category::Security,
                Severity::Medium,
                format!("Defender signatures are {age:.0} days old"),
                sec("defender"),
            )
            .remediation("Run `Update-MpSignature` and check update connectivity.")
            .fp_key(format!("{who}|defender_stale")),
        );
    }

    for p in v["firewall"].as_array().cloned().unwrap_or_default() {
        if p["enabled"] == json!(false) {
            let n = p["name"].as_str().unwrap_or("?");
            r.findings.push(
                Finding::new(
                    "host.probe",
                    "host.firewall_off",
                    Category::Security,
                    Severity::High,
                    format!("Windows Firewall {n} profile is off"),
                    sec(&format!("firewall:{n}")),
                )
                .remediation("Run `Set-NetFirewallProfile -Profile <name> -Enabled True`.")
                .fp_key(format!("{who}|fw|{n}")),
            );
        }
    }

    if v["smb1_enabled"] == json!(true) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.smb1",
                Category::Security,
                Severity::High,
                "SMBv1 is enabled",
                sec("smb"),
            )
            .remediation("Run `Set-SmbServerConfiguration -EnableSMB1Protocol $false`.")
            .fp_key(format!("{who}|smb1")),
        );
    }

    if v["rdp"]["enabled"] == json!(true) && v["rdp"]["nla"] == json!(false) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.rdp_no_nla",
                Category::Security,
                Severity::High,
                "RDP enabled without Network Level Authentication",
                sec("rdp"),
            )
            .remediation("Require NLA for Remote Desktop.")
            .fp_key(format!("{who}|rdp_nla")),
        );
    }

    let pu = &v["pending_updates"];
    let count = pu["count"].as_u64().unwrap_or(0);
    let secu = pu["security"].as_u64().unwrap_or(0);
    if secu > 0 {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.pending_updates",
                Category::Security,
                Severity::High,
                format!("{secu} security updates pending ({count} total)"),
                sec("updates"),
            )
            .remediation("Install pending Windows updates.")
            .fp_key(format!("{who}|updates")),
        );
    } else if count > 0 {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.pending_updates",
                Category::Security,
                Severity::Medium,
                format!("{count} updates pending"),
                sec("updates"),
            )
            .remediation("Install pending Windows updates.")
            .fp_key(format!("{who}|updates")),
        );
    }

    for l in strs(&v["error_lines"]) {
        r.error_lines
            .push(("host.eventlog".into(), redact_line(&l)));
    }
}
