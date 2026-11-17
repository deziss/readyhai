//! Linux probe output analysis.
use serde_json::{Value, json};

use super::common::{gs, strs};
use crate::host::redact::redact_line;
use crate::host::types::ProbeResult;
use crate::model::{Category, Finding, Severity};

pub(crate) fn check_linux(v: &Value, who: &str, r: &mut ProbeResult) {
    let sec = |s: &str| format!("{who}:{s}");

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
            .detail(format!("manager: {}", gs(pu, &["manager"])))
            .remediation("Apply pending updates and reboot if a kernel/libc update is included.")
            .fp_key(format!("{who}|updates")),
        );
    } else if count > 0 {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.pending_updates",
                Category::Security,
                Severity::Medium,
                format!("{count} package updates pending"),
                sec("updates"),
            )
            .detail(format!(
                "manager: {} (security flag not detectable offline)",
                gs(pu, &["manager"])
            ))
            .remediation("Apply pending updates.")
            .fp_key(format!("{who}|updates")),
        );
    }

    let fu = strs(&v["failed_units"]);
    if !fu.is_empty() {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.failed_units",
                Category::Reliability,
                Severity::Medium,
                format!("{} failed systemd units", fu.len()),
                sec("systemd"),
            )
            .detail(fu.join(", "))
            .remediation("Inspect with `systemctl status <unit>` and `journalctl -u <unit>`.")
            .fp_key(format!("{who}|failed_units")),
        );
    }

    let fw = &v["firewall"];
    if fw["any_active"] == json!(false) && fw["unknown"] != json!(true) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.no_firewall",
                Category::Security,
                Severity::Medium,
                "No active host firewall",
                sec("firewall"),
            )
            .detail(format!(
                "ufw={} firewalld={} nftables={} iptables={}",
                gs(fw, &["ufw"]),
                gs(fw, &["firewalld"]),
                gs(fw, &["nftables"]),
                gs(fw, &["iptables"])
            ))
            .remediation(
                "Enable ufw/firewalld (or nftables rules) with a default-deny inbound policy.",
            )
            .fp_key(format!("{who}|firewall")),
        );
    }

    let u0 = strs(&v["uid0_extra"]);
    if !u0.is_empty() {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.uid0_extra",
                Category::Security,
                Severity::High,
                format!("Extra UID 0 accounts: {}", u0.join(", ")),
                sec("accounts"),
            )
            .detail("Accounts other than root have UID 0.")
            .remediation("Remove or re-number these accounts.")
            .fp_key(format!("{who}|uid0")),
        );
    }

    if let Some(n) = v["nopasswd_sudo"].as_u64()
        && n > 0
    {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.nopasswd_sudo",
                Category::Security,
                Severity::Medium,
                format!("{n} sudoers NOPASSWD entries"),
                sec("sudoers"),
            )
            .detail("Passwordless sudo is configured.")
            .remediation("Restrict NOPASSWD to specific commands or remove it.")
            .fp_key(format!("{who}|nopasswd")),
        );
    }

    if v["time_sync"] == json!(false) {
        r.findings.push(
            Finding::new(
                "host.probe",
                "host.no_time_sync",
                Category::Reliability,
                Severity::Low,
                "Clock is not synchronized",
                sec("time"),
            )
            .detail("No NTP synchronization detected.")
            .remediation("Enable chrony or systemd-timesyncd.")
            .fp_key(format!("{who}|time_sync")),
        );
    }

    for c in v["docker"].as_array().cloned().unwrap_or_default() {
        let n = c["restarts"].as_u64().unwrap_or(0);
        let name = c["name"].as_str().unwrap_or("?");
        let st = c["status"].as_str().unwrap_or("");
        if n > 3 || st.starts_with("Restarting") {
            r.findings.push(
                Finding::new(
                    "host.probe",
                    "host.container_restarting",
                    Category::Reliability,
                    Severity::Medium,
                    format!("Container {name} restarted {n} times"),
                    sec(&format!("docker:{name}")),
                )
                .detail(st.to_string())
                .remediation(
                    "Check `docker logs` and add a proper healthcheck / fix the crash loop.",
                )
                .fp_key(format!("{who}|container|{name}")),
            );
        }
    }

    for l in strs(&v["error_lines"]) {
        r.error_lines.push(("host.journal".into(), redact_line(&l)));
    }
}
