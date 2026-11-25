use serde_json::Value;

use super::*;
use crate::host::types::ProbeResult;
use crate::model::{HostSpec, Os, Severity};

fn fx(n: &str) -> Value {
    let p = format!(
        "{}/tests/fixtures/host-probe/{n}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn rules(r: &ProbeResult) -> Vec<String> {
    r.findings.iter().map(|f| f.rule.clone()).collect()
}

fn sev(r: &ProbeResult, rule: &str) -> Severity {
    r.findings.iter().find(|f| f.rule == rule).unwrap().severity
}

#[test]
fn linux_golden() {
    let r = parse_probe(Os::Linux, &fx("linux"), "root@h");
    let ids = rules(&r);
    for x in [
        "host.ssh_root_login",
        "host.ssh_password_auth",
        "host.uid0_extra",
        "host.nopasswd_sudo",
        "host.no_firewall",
        "host.pending_updates",
        "host.failed_units",
        "host.disk_full",
        "host.no_time_sync",
        "host.container_restarting",
    ] {
        assert!(ids.iter().any(|i| i == x), "missing {x}: {ids:?}");
    }
    assert_eq!(sev(&r, "host.pending_updates"), Severity::High);
    assert_eq!(
        r.findings
            .iter()
            .filter(|f| f.rule == "host.disk_full")
            .count(),
        2
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.rule == "host.disk_full" && f.severity == Severity::High)
    );
    assert_eq!(r.error_lines.len(), 3);
    assert!(r.error_lines.iter().all(|(s, _)| s == "host.journal"));
    assert!(!r.error_lines[0].1.contains("hunter2"));
    assert!(r.findings.iter().all(|f| f.location.starts_with("root@h")));
    let s = r.sbom.unwrap();
    assert_eq!(s["bomFormat"], "CycloneDX");
    assert!(
        s["components"][1]["purl"]
            .as_str()
            .unwrap()
            .starts_with("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.12?distro=ubuntu-22.04")
    );
}

#[test]
fn macos_golden() {
    let r = parse_probe(Os::Macos, &fx("macos"), "u@m");
    let ids = rules(&r);
    for x in [
        "host.sip_disabled",
        "host.gatekeeper_off",
        "host.filevault_off",
        "host.mac_firewall_off",
    ] {
        assert!(ids.iter().any(|i| i == x), "{x}");
    }
    assert_eq!(sev(&r, "host.sip_disabled"), Severity::High);
    assert_eq!(r.partial.len(), 1);
    assert_eq!(r.error_lines[0].0, "host.oslog");
    assert!(r.sbom.is_none());
}

#[test]
fn windows_golden() {
    let r = parse_probe(Os::Windows, &fx("windows"), "u@w");
    let ids = rules(&r);
    for x in [
        "host.defender_off",
        "host.defender_stale",
        "host.firewall_off",
        "host.smb1",
        "host.rdp_no_nla",
        "host.pending_updates",
    ] {
        assert!(ids.iter().any(|i| i == x), "{x}");
    }
    assert_eq!(ids.iter().filter(|i| *i == "host.firewall_off").count(), 1);
    assert!(r.partial.iter().any(|p| p.contains("ConstrainedLanguage")));
    assert!(r.partial.iter().any(|p| p.contains("not elevated")));
    assert_eq!(r.error_lines[0].0, "host.eventlog");
}

#[test]
fn redaction() {
    assert_eq!(
        redact_line("db password=hunter2 failed"),
        "db password=[REDACTED] failed"
    );
    assert!(redact_line("API_KEY: abc123xyz ok").contains("[REDACTED]"));
    assert!(!redact_line("Authorization: Bearer abc.def.ghijk").contains("abc.def"));
    assert!(!redact_line("key AKIAIOSFODNN7EXAMPLE x").contains("AKIA"));
    assert!(!redact_line("postgres://u:pw123@db/x").contains("pw123"));
    let long = "a1".repeat(30);
    assert_eq!(
        redact_line(&format!("sha {long} end")),
        "sha [REDACTED] end"
    );
    assert_eq!(
        redact_line("normal kernel message: oom"),
        "normal kernel message: oom"
    );
    assert_eq!(
        redact_line("/usr/lib/x86_64-linux-gnu/some/very/long/path/libfoo.so.1.2"),
        "/usr/lib/x86_64-linux-gnu/some/very/long/path/libfoo.so.1.2"
    );
}

#[test]
fn ssh_args_safe() {
    let h = HostSpec {
        user: "me".into(),
        host: "10.0.0.5".into(),
        port: 2222,
        os: Os::Linux,
        key: Some("/k/id".into()),
    };
    let a = ssh_args(&h, "sh -s").unwrap();
    assert!(
        a.windows(2)
            .any(|w| w == ["-o", "StrictHostKeyChecking=yes"])
    );
    assert!(a.windows(2).any(|w| w == ["-o", "BatchMode=yes"]));
    assert!(a.windows(2).any(|w| w == ["-p", "2222"]));
    assert!(a.windows(2).any(|w| w == ["-o", "IdentitiesOnly=yes"]));
    let dd = a.iter().position(|x| x == "--").unwrap();
    assert_eq!(a[dd + 1], "me@10.0.0.5");
    assert_eq!(a[dd + 2], "sh -s");
    assert!(a.iter().position(|x| x == "-i").unwrap() < dd);
    let mut bad = h.clone();
    bad.host = "-oProxyCommand=x".into();
    assert!(ssh_args(&bad, "x").is_err());
    let mut nokey = h.clone();
    nokey.key = None;
    assert!(!ssh_args(&nokey, "x").unwrap().iter().any(|x| x == "-i"));
}

#[test]
fn lynis_parse() {
    let r = parse_lynis(
        "#uid=1000\nwarning[]=AUTH-9286|Pwd aging|-|-|\nsuggestion[]=SSH-7440|Harden sshd|x|y|\nhardening_index=58\n",
    );
    assert_eq!(r.uid, Some(1000));
    let f = lynis_findings(&r, "u@h");
    assert_eq!(f.len(), 3);
    assert_eq!(f[0].rule, "lynis.AUTH-9286");
    assert_eq!(f[0].severity, Severity::Medium);
    assert_eq!(f[1].severity, Severity::Low);
    assert_eq!(f[2].rule, "lynis.hardening_index");
}

#[test]
fn scripts_embedded() {
    assert!(LINUX_SH.starts_with("#!/bin/sh"));
    assert!(WINDOWS_PS1.contains("ConvertTo-Json -Depth 8 -Compress"));
    assert!(
        checks()
            .iter()
            .map(|c| c.id.as_str())
            .eq(["host.probe", "host.cve", "host.lynis"])
    );
}
