//! Host targets over SSH: probe scripts piped over the system OpenSSH client,
//! parsed into findings; Lynis from a cached tarball; package CVEs via grype.
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::*;
use crate::tools::{ToolSpec, parse_grype};
use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const LINUX_SH: &str = include_str!("../probe/linux.sh");
const MACOS_SH: &str = include_str!("../probe/macos.sh");
const WINDOWS_PS1: &str = include_str!("../probe/windows.ps1");

pub const LYNIS_VERSION: &str = "3.1.6";
pub const LYNIS_URL: &str = "https://downloads.cisofy.com/lynis/lynis-3.1.6.tar.gz";

// ---------------------------------------------------------------- redaction

fn re(cell: &'static OnceLock<Regex>, p: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(p).expect("static regex"))
}

/// Mask obvious secrets in a log line (password=..., token=..., bearer ..., AWS key ids,
/// URL credentials, long hex/base64 blobs).
pub fn redact_line(line: &str) -> String {
    static KV: OnceLock<Regex> = OnceLock::new();
    static BEARER: OnceLock<Regex> = OnceLock::new();
    static AKIA: OnceLock<Regex> = OnceLock::new();
    static URLC: OnceLock<Regex> = OnceLock::new();
    static LONG: OnceLock<Regex> = OnceLock::new();
    let s = re(&KV, r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(["']?\s*[=:]\s*["']?)[^\s"',;&]+"#)
        .replace_all(line, "${1}${2}[REDACTED]");
    let s = re(&BEARER, r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}")
        .replace_all(&s, "${1} [REDACTED]");
    let s = re(&AKIA, r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").replace_all(&s, "[REDACTED]");
    let s = re(&URLC, r"://[^/\s:@]+:[^@\s]+@").replace_all(&s, "://[REDACTED]@");
    let s = re(&LONG, r"[A-Za-z0-9+/_=-]{33,}").replace_all(&s, |c: &regex::Captures| {
        let t = &c[0];
        let pathlike = t.matches('/').count() > 2;
        let has_digit = t.chars().any(|c| c.is_ascii_digit());
        let has_alpha = t.chars().any(|c| c.is_ascii_alphabetic());
        if !pathlike && has_digit && has_alpha {
            "[REDACTED]".to_string()
        } else {
            t.to_string()
        }
    });
    s.into_owned()
}

// ---------------------------------------------------------------- ssh

fn loc(h: &HostSpec) -> String {
    format!("{}@{}", h.user, h.host)
}

fn bad_name(s: &str) -> bool {
    s.is_empty() || s.starts_with('-') || s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Full ssh argv (without the program name): options, `--`, destination, remote command.
pub fn ssh_args(h: &HostSpec, remote_cmd: &str) -> Result<Vec<String>> {
    if bad_name(&h.user) || bad_name(&h.host) {
        bail!("invalid ssh user/host: {}@{}", h.user, h.host);
    }
    let mut a: Vec<String> = vec![
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "LogLevel=ERROR",
        "-p",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    a.push(h.port.to_string());
    if let Some(k) = &h.key {
        a.push("-i".into());
        a.push(k.to_string_lossy().into_owned());
        a.push("-o".into());
        a.push("IdentitiesOnly=yes".into());
    }
    a.push("--".into());
    a.push(loc(h));
    a.push(remote_cmd.to_string());
    Ok(a)
}

pub struct SshOut {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Run `ssh` with `stdin` piped in; kill after `timeout`.
pub fn run_ssh(
    h: &HostSpec,
    remote_cmd: &str,
    stdin: Vec<u8>,
    timeout: Duration,
) -> Result<SshOut> {
    let args = ssh_args(h, remote_cmd)?;
    let mut child = Command::new("ssh")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot run `ssh` (OpenSSH client not installed?)")?;
    let mut sin = child.stdin.take().unwrap();
    let w = std::thread::spawn(move || {
        let _ = sin.write_all(&stdin);
    });
    let mut so = child.stdout.take().unwrap();
    let ro = std::thread::spawn(move || {
        let mut b = vec![];
        let _ = so.read_to_end(&mut b);
        b
    });
    let mut se = child.stderr.take().unwrap();
    let re_ = std::thread::spawn(move || {
        let mut b = vec![];
        let _ = se.by_ref().take(64 * 1024).read_to_end(&mut b);
        let _ = std::io::copy(&mut se, &mut std::io::sink());
        String::from_utf8_lossy(&b).into_owned()
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("ssh to {} timed out after {}s", loc(h), timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = w.join();
    let stdout = ro.join().unwrap_or_default();
    let stderr = re_.join().unwrap_or_default();
    Ok(SshOut {
        code: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

/// Turn ssh's own failures (exit 255) into actionable errors.
fn ssh_failure(h: &HostSpec, o: &SshOut) -> anyhow::Error {
    let e = o.stderr.trim();
    if e.contains("Host key verification failed")
        || e.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
    {
        return anyhow!(
            "host key not in known_hosts: run ssh-keyscan -p {} {} and verify the fingerprint, then add it to ~/.ssh/known_hosts",
            h.port,
            h.host
        );
    }
    if e.contains("Permission denied") {
        return anyhow!(
            "ssh authentication failed for {} (BatchMode: key or agent required)",
            loc(h)
        );
    }
    anyhow!(
        "ssh to {} failed (exit {}): {}",
        loc(h),
        o.code,
        e.lines().last().unwrap_or("")
    )
}

fn remote_cmd(os: Os) -> &'static str {
    match os {
        // Slurp the script, then exec so that commands in it cannot consume the script from stdin.
        Os::Linux => "s=$(cat); exec sh -c \"$s\" </dev/null",
        Os::Macos => "s=$(cat); exec bash -c \"$s\" </dev/null",
        Os::Windows => "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
    }
}

fn script(os: Os) -> &'static str {
    match os {
        Os::Linux => LINUX_SH,
        Os::Macos => MACOS_SH,
        Os::Windows => WINDOWS_PS1,
    }
}

// ---------------------------------------------------------------- probe parsing

#[derive(Debug, Default)]
pub struct ProbeResult {
    pub findings: Vec<Finding>,
    /// (source, redacted line)
    pub error_lines: Vec<(String, String)>,
    pub partial: Vec<String>,
    pub sbom: Option<Value>,
}

fn g<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    let mut c = v;
    for p in path {
        c = c.get(*p).unwrap_or(&Value::Null);
    }
    c
}
fn gs<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    g(v, path).as_str().unwrap_or("")
}
fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_probe(os: Os, v: &Value, who: &str) -> ProbeResult {
    let mut r = ProbeResult::default();
    let sec = |s: &str| format!("{who}:{s}");
    let mut add = |rule: &str,
                   cat: Category,
                   sev: Severity,
                   title: String,
                   section: &str,
                   detail: String,
                   fix: &str,
                   key: &str| {
        let f = Finding::new("host.probe", rule, cat, sev, title, sec(section))
            .detail(detail)
            .remediation(fix)
            .fp_key(format!("{who}|{key}"));
        r.findings.push(f);
    };
    r.partial = strs(&v["partial"]);

    // sshd (linux + macos)
    if os != Os::Windows {
        if gs(v, &["sshd", "permitrootlogin"]).eq_ignore_ascii_case("yes") {
            add(
                "host.ssh_root_login",
                Category::Security,
                Severity::High,
                "SSH permits root login".into(),
                "sshd",
                "PermitRootLogin yes".into(),
                "Set `PermitRootLogin prohibit-password` (or no) in sshd_config and reload sshd.",
                "ssh_root",
            );
        }
        if gs(v, &["sshd", "passwordauthentication"]).eq_ignore_ascii_case("yes") {
            add(
                "host.ssh_password_auth",
                Category::Security,
                Severity::Medium,
                "SSH password authentication enabled".into(),
                "sshd",
                "PasswordAuthentication yes".into(),
                "Use keys: set `PasswordAuthentication no` in sshd_config.",
                "ssh_pw",
            );
        }
    }

    // disks (linux + macos)
    for d in v["disks"].as_array().cloned().unwrap_or_default() {
        let pct = d["use_pct"].as_u64().unwrap_or(0);
        let mount = d["mount"].as_str().unwrap_or("?");
        if pct > 85 {
            let sev = if pct > 95 {
                Severity::High
            } else {
                Severity::Medium
            };
            add(
                "host.disk_full",
                Category::Reliability,
                sev,
                format!("Filesystem {mount} is {pct}% full"),
                &format!("disk:{mount}"),
                format!("{mount} at {pct}%"),
                "Free space or grow the volume before it fills.",
                &format!("disk|{mount}"),
            );
        }
    }

    match os {
        Os::Linux => {
            let pu = &v["pending_updates"];
            let count = pu["count"].as_u64().unwrap_or(0);
            let secu = pu["security"].as_u64().unwrap_or(0);
            if secu > 0 {
                add(
                    "host.pending_updates",
                    Category::Security,
                    Severity::High,
                    format!("{secu} security updates pending ({count} total)"),
                    "updates",
                    format!("manager: {}", gs(pu, &["manager"])),
                    "Apply pending updates and reboot if a kernel/libc update is included.",
                    "updates",
                );
            } else if count > 0 {
                add(
                    "host.pending_updates",
                    Category::Security,
                    Severity::Medium,
                    format!("{count} package updates pending"),
                    "updates",
                    format!(
                        "manager: {} (security flag not detectable offline)",
                        gs(pu, &["manager"])
                    ),
                    "Apply pending updates.",
                    "updates",
                );
            }
            let fu = strs(&v["failed_units"]);
            if !fu.is_empty() {
                add(
                    "host.failed_units",
                    Category::Reliability,
                    Severity::Medium,
                    format!("{} failed systemd units", fu.len()),
                    "systemd",
                    fu.join(", "),
                    "Inspect with `systemctl status <unit>` and `journalctl -u <unit>`.",
                    "failed_units",
                );
            }
            let fw = &v["firewall"];
            if fw["any_active"] == json!(false) && fw["unknown"] != json!(true) {
                add(
                    "host.no_firewall",
                    Category::Security,
                    Severity::Medium,
                    "No active host firewall".into(),
                    "firewall",
                    format!(
                        "ufw={} firewalld={} nftables={} iptables={}",
                        gs(fw, &["ufw"]),
                        gs(fw, &["firewalld"]),
                        gs(fw, &["nftables"]),
                        gs(fw, &["iptables"])
                    ),
                    "Enable ufw/firewalld (or nftables rules) with a default-deny inbound policy.",
                    "firewall",
                );
            }
            let u0 = strs(&v["uid0_extra"]);
            if !u0.is_empty() {
                add(
                    "host.uid0_extra",
                    Category::Security,
                    Severity::High,
                    format!("Extra UID 0 accounts: {}", u0.join(", ")),
                    "accounts",
                    "Accounts other than root have UID 0.".into(),
                    "Remove or re-number these accounts.",
                    "uid0",
                );
            }
            if let Some(n) = v["nopasswd_sudo"].as_u64()
                && n > 0
            {
                add(
                    "host.nopasswd_sudo",
                    Category::Security,
                    Severity::Medium,
                    format!("{n} sudoers NOPASSWD entries"),
                    "sudoers",
                    "Passwordless sudo is configured.".into(),
                    "Restrict NOPASSWD to specific commands or remove it.",
                    "nopasswd",
                );
            }
            if v["time_sync"] == json!(false) {
                add(
                    "host.no_time_sync",
                    Category::Reliability,
                    Severity::Low,
                    "Clock is not synchronized".into(),
                    "time",
                    "No NTP synchronization detected.".into(),
                    "Enable chrony or systemd-timesyncd.",
                    "time_sync",
                );
            }
            for c in v["docker"].as_array().cloned().unwrap_or_default() {
                let n = c["restarts"].as_u64().unwrap_or(0);
                let name = c["name"].as_str().unwrap_or("?");
                let st = c["status"].as_str().unwrap_or("");
                if n > 3 || st.starts_with("Restarting") {
                    add(
                        "host.container_restarting",
                        Category::Reliability,
                        Severity::Medium,
                        format!("Container {name} restarted {n} times"),
                        &format!("docker:{name}"),
                        st.to_string(),
                        "Check `docker logs` and add a proper healthcheck / fix the crash loop.",
                        &format!("container|{name}"),
                    );
                }
            }
            for l in strs(&v["error_lines"]) {
                r.error_lines.push(("host.journal".into(), redact_line(&l)));
            }
        }
        Os::Macos => {
            if v["sip_enabled"] == json!(false) {
                add(
                    "host.sip_disabled",
                    Category::Security,
                    Severity::High,
                    "System Integrity Protection is disabled".into(),
                    "sip",
                    String::new(),
                    "Re-enable SIP from Recovery: `csrutil enable`.",
                    "sip",
                );
            }
            if v["gatekeeper_enabled"] == json!(false) {
                add(
                    "host.gatekeeper_off",
                    Category::Security,
                    Severity::Medium,
                    "Gatekeeper is disabled".into(),
                    "gatekeeper",
                    String::new(),
                    "Run `sudo spctl --master-enable`.",
                    "gatekeeper",
                );
            }
            if v["filevault_on"] == json!(false) {
                add(
                    "host.filevault_off",
                    Category::Security,
                    Severity::Medium,
                    "FileVault disk encryption is off".into(),
                    "filevault",
                    String::new(),
                    "Enable FileVault in System Settings > Privacy & Security.",
                    "filevault",
                );
            }
            if v["firewall_enabled"] == json!(false) {
                add(
                    "host.mac_firewall_off",
                    Category::Security,
                    Severity::Medium,
                    "Application firewall is off".into(),
                    "firewall",
                    String::new(),
                    "Enable the macOS firewall (System Settings > Network > Firewall).",
                    "firewall",
                );
            }
            for l in strs(&v["error_lines"]) {
                r.error_lines.push(("host.oslog".into(), redact_line(&l)));
            }
        }
        Os::Windows => {
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
            if v["elevated"] == json!(false)
                && !r.partial.iter().any(|p| p.contains("not elevated"))
            {
                r.partial
                    .push("not elevated: Defender/SMB/update data may be missing".into());
            }
            let d = &v["defender"];
            if d["realtime"] == json!(false) {
                add(
                    "host.defender_off",
                    Category::Security,
                    Severity::High,
                    "Defender real-time protection is off".into(),
                    "defender",
                    String::new(),
                    "Enable real-time protection (or confirm another EDR is active).",
                    "defender_off",
                );
            }
            if let Some(age) = d["signature_age_days"].as_f64()
                && age > 3.0
            {
                add(
                    "host.defender_stale",
                    Category::Security,
                    Severity::Medium,
                    format!("Defender signatures are {age:.0} days old"),
                    "defender",
                    String::new(),
                    "Run `Update-MpSignature` and check update connectivity.",
                    "defender_stale",
                );
            }
            for p in v["firewall"].as_array().cloned().unwrap_or_default() {
                if p["enabled"] == json!(false) {
                    let n = p["name"].as_str().unwrap_or("?");
                    add(
                        "host.firewall_off",
                        Category::Security,
                        Severity::High,
                        format!("Windows Firewall {n} profile is off"),
                        &format!("firewall:{n}"),
                        String::new(),
                        "Run `Set-NetFirewallProfile -Profile <name> -Enabled True`.",
                        &format!("fw|{n}"),
                    );
                }
            }
            if v["smb1_enabled"] == json!(true) {
                add(
                    "host.smb1",
                    Category::Security,
                    Severity::High,
                    "SMBv1 is enabled".into(),
                    "smb",
                    String::new(),
                    "Run `Set-SmbServerConfiguration -EnableSMB1Protocol $false`.",
                    "smb1",
                );
            }
            if v["rdp"]["enabled"] == json!(true) && v["rdp"]["nla"] == json!(false) {
                add(
                    "host.rdp_no_nla",
                    Category::Security,
                    Severity::High,
                    "RDP enabled without Network Level Authentication".into(),
                    "rdp",
                    String::new(),
                    "Require NLA for Remote Desktop.",
                    "rdp_nla",
                );
            }
            let pu = &v["pending_updates"];
            let count = pu["count"].as_u64().unwrap_or(0);
            let secu = pu["security"].as_u64().unwrap_or(0);
            if secu > 0 {
                add(
                    "host.pending_updates",
                    Category::Security,
                    Severity::High,
                    format!("{secu} security updates pending ({count} total)"),
                    "updates",
                    String::new(),
                    "Install pending Windows updates.",
                    "updates",
                );
            } else if count > 0 {
                add(
                    "host.pending_updates",
                    Category::Security,
                    Severity::Medium,
                    format!("{count} updates pending"),
                    "updates",
                    String::new(),
                    "Install pending Windows updates.",
                    "updates",
                );
            }
            for l in strs(&v["error_lines"]) {
                r.error_lines
                    .push(("host.eventlog".into(), redact_line(&l)));
            }
        }
    }
    if os == Os::Linux {
        r.sbom = sbom_from_probe(v);
    }
    r
}

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Minimal CycloneDX 1.5 SBOM from the Linux package inventory (None if no packages).
pub fn sbom_from_probe(v: &Value) -> Option<Value> {
    let pk = v["packages"].as_array()?;
    if pk.is_empty() {
        return None;
    }
    let id = gs(v, &["os", "id"]).to_ascii_lowercase();
    let ver = gs(v, &["os", "version"]);
    let (typ, ns) = match id.as_str() {
        "ubuntu" | "debian" | "raspbian" | "kali" | "linuxmint" | "pop" => {
            ("deb", if id == "ubuntu" { "ubuntu" } else { "debian" })
        }
        "alpine" => ("apk", "alpine"),
        "" => return None,
        other => ("rpm", other),
    };
    let distro = if ver.is_empty() {
        id.clone()
    } else {
        format!("{id}-{ver}")
    };
    let mut comps: Vec<Value> = vec![json!({"type":"operating-system","name":id,"version":ver})];
    for p in pk {
        let (n, vr) = (
            p["name"].as_str().unwrap_or(""),
            p["version"].as_str().unwrap_or(""),
        );
        if n.is_empty() {
            continue;
        }
        comps.push(json!({
            "type": "library", "name": n, "version": vr,
            "purl": format!("pkg:{typ}/{ns}/{}@{}?distro={}", pct(n), pct(vr), pct(&distro)),
        }));
    }
    Some(json!({"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":comps}))
}

// ---------------------------------------------------------------- lynis

#[derive(Debug, Default, PartialEq)]
pub struct LynisReport {
    pub warnings: Vec<(String, String)>,
    pub suggestions: Vec<(String, String)>,
    pub hardening_index: Option<u32>,
    pub uid: Option<u32>,
}

pub fn parse_lynis(report: &str) -> LynisReport {
    let mut r = LynisReport::default();
    for line in report.lines() {
        let line = line.trim();
        if let Some(u) = line.strip_prefix("#uid=") {
            r.uid = u.parse().ok();
        } else if let Some(x) = line.strip_prefix("hardening_index=") {
            r.hardening_index = x.trim().parse().ok();
        } else if let Some(x) = line.strip_prefix("warning[]=") {
            let mut p = x.split('|');
            r.warnings.push((
                p.next().unwrap_or("").to_string(),
                p.next().unwrap_or("").to_string(),
            ));
        } else if let Some(x) = line.strip_prefix("suggestion[]=") {
            let mut p = x.split('|');
            r.suggestions.push((
                p.next().unwrap_or("").to_string(),
                p.next().unwrap_or("").to_string(),
            ));
        }
    }
    r
}

pub fn lynis_findings(r: &LynisReport, who: &str) -> Vec<Finding> {
    let mut out = vec![];
    let mk = |id: &str, text: &str, sev: Severity| {
        let id = if id.is_empty() { "UNKNOWN" } else { id };
        Finding::new(
            "host.lynis",
            &format!("lynis.{id}"),
            Category::Security,
            sev,
            text.to_string(),
            who.to_string(),
        )
        .fp_key(format!("{who}|{id}"))
        .remediation("See `lynis show details <ID>` for the hardening guidance.")
    };
    for (id, t) in &r.warnings {
        out.push(mk(id, t, Severity::Medium));
    }
    for (id, t) in &r.suggestions {
        out.push(mk(id, t, Severity::Low));
    }
    if let Some(h) = r.hardening_index
        && h < 65
    {
        out.push(
            Finding::new(
                "host.lynis",
                "lynis.hardening_index",
                Category::Security,
                Severity::Low,
                format!("Lynis hardening index is {h} (< 65)"),
                who.to_string(),
            )
            .fp_key(format!("{who}|hardening_index")),
        );
    }
    out
}

fn lynis_tarball(cache: &Path) -> PathBuf {
    cache.join("lynis").join("lynis.tar.gz")
}

/// Download the pinned Lynis tarball into `<cache>/lynis/lynis.tar.gz` (called from `tools update`).
/// Verifies against a published .sha256 when available; otherwise records the hash in a sibling
/// `lynis.tar.gz.sha256` file marked "unverified".
pub fn fetch_lynis(cache_dir: &Path) -> Result<()> {
    let dir = cache_dir.join("lynis");
    std::fs::create_dir_all(&dir)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let resp = client
        .get(LYNIS_URL)
        .send()?
        .error_for_status()
        .context("downloading lynis")?;
    let bytes = resp.bytes()?;
    if bytes.len() < 100_000 {
        bail!("lynis download too small ({} bytes)", bytes.len());
    }
    let got = sha256_hex(&bytes);
    let published = client
        .get(format!("{LYNIS_URL}.sha256"))
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.text().ok())
        .and_then(|t| t.split_whitespace().next().map(|s| s.to_ascii_lowercase()))
        .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()));
    let note = match published {
        Some(want) if want == got => "verified against published sha256",
        Some(want) => bail!("lynis sha256 mismatch: published {want}, got {got}"),
        None => "unverified (no published sha256); pin this hash",
    };
    std::fs::write(lynis_tarball(cache_dir), &bytes)?;
    std::fs::write(
        dir.join("lynis.tar.gz.sha256"),
        format!("{got}  lynis-{LYNIS_VERSION}.tar.gz  {note}\n"),
    )?;
    Ok(())
}

// ---------------------------------------------------------------- checks

fn spec(ctx: &Ctx) -> Result<&HostSpec> {
    ctx.target
        .host
        .as_ref()
        .ok_or_else(|| anyhow!("host target has no ssh spec"))
}

fn probe_check(ctx: &Ctx) -> Result<CheckOutput> {
    let h = spec(ctx)?;
    let who = loc(h);
    let o = run_ssh(
        h,
        remote_cmd(h.os),
        script(h.os).as_bytes().to_vec(),
        Duration::from_secs(120),
    )?;
    if o.stdout.is_empty() || (o.code == 255 && o.stdout.is_empty()) {
        return Err(ssh_failure(h, &o));
    }
    let text = String::from_utf8_lossy(&o.stdout);
    // Windows PowerShell may prefix a BOM or banner; take the JSON object span.
    let start = text.find('{').ok_or_else(|| {
        anyhow!(
            "probe produced no JSON (exit {}): {}",
            o.code,
            o.stderr.trim()
        )
    })?;
    let end = text
        .rfind('}')
        .ok_or_else(|| anyhow!("probe output truncated"))?;
    let mut v: Value =
        serde_json::from_str(&text[start..=end]).context("probe output is not valid JSON")?;
    // never persist unredacted log lines
    if let Some(a) = v.get_mut("error_lines").and_then(|x| x.as_array_mut()) {
        for l in a.iter_mut() {
            if let Some(s) = l.as_str() {
                *l = Value::String(redact_line(s));
            }
        }
    }
    let out = ctx.out_dir();
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("host-probe.json"), serde_json::to_vec_pretty(&v)?)?;
    let r = parse_probe(h.os, &v, &who);
    if let Some(s) = &r.sbom {
        std::fs::write(out.join("host-sbom.cdx.json"), serde_json::to_vec(s)?)?;
    }
    for (src, l) in &r.error_lines {
        ctx.error_line(src, l);
    }
    let status = if r.partial.is_empty() {
        None
    } else {
        Some(CheckStatus::Partial(r.partial.join("; ")))
    };
    Ok(CheckOutput {
        status,
        findings: r.findings,
    })
}

fn cve_check(ctx: &Ctx) -> Result<CheckOutput> {
    let h = spec(ctx)?;
    if h.os != Os::Linux {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            match h.os {
                Os::Windows => "Windows package CVE matching not supported in v1",
                _ => "package CVE matching only supported for Linux hosts in v1",
            }
            .into(),
        )));
    }
    if !ctx.docker.available {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "docker not available".into(),
        )));
    }
    if !ctx.out_dir().join("host-sbom.cdx.json").exists() {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "no package inventory (host.probe produced none)".into(),
        )));
    }
    let cache = &ctx.docker.cache_dir;
    if !cache.join("grype").is_dir() {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "vuln DB missing: run `readyhai tools update`".into(),
        )));
    }
    std::fs::create_dir_all(ctx.src_dir())?; // docker runner mounts /src
    let mut grype = ToolSpec::new(
        "grype",
        &[
            "sbom:/out/host-sbom.cdx.json",
            "-o",
            "json",
            "--file",
            "/out/host-grype.json",
        ],
    );
    grype.env = vec![
        ("GRYPE_DB_CACHE_DIR".into(), "/cache/grype".into()),
        ("GRYPE_DB_AUTO_UPDATE".into(), "false".into()),
        ("GRYPE_CHECK_FOR_APP_UPDATE".into(), "false".into()),
    ];
    let r = ctx.docker.run(ctx, &grype)?;
    if r.exit_code != 0 {
        bail!("grype exited {}: {}", r.exit_code, r.stderr_tail.trim());
    }
    let txt = std::fs::read_to_string(ctx.out_dir().join("host-grype.json"))
        .context("grype did not write /out/host-grype.json")?;
    let who = loc(h);
    let mut fs = parse_grype(&txt)?;
    for f in &mut fs {
        f.check = "host.cve".into();
        f.location = format!("{who}:{}", f.package.clone().unwrap_or_default());
    }
    Ok(CheckOutput::findings(fs))
}

fn lynis_check(ctx: &Ctx) -> Result<CheckOutput> {
    let h = spec(ctx)?;
    if h.os == Os::Windows {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "Lynis supports Linux/macOS only".into(),
        )));
    }
    let tb = lynis_tarball(&ctx.docker.cache_dir);
    if !tb.is_file() {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "lynis tarball missing: run `readyhai tools update`".into(),
        )));
    }
    let data = std::fs::read(&tb)?;
    let cmd = r##"d=$(mktemp -d) && tar xz -C "$d" && cd "$d"/lynis && { echo "#uid=$(id -u)"; sh ./lynis audit system --quick --no-colors --no-log --report-file "$d/r.dat" >/dev/null 2>&1; cat "$d/r.dat"; }; rm -rf "$d""##;
    let o = run_ssh(h, cmd, data, Duration::from_secs(600))?;
    if o.stdout.is_empty() {
        return Err(ssh_failure(h, &o));
    }
    let rep = parse_lynis(&String::from_utf8_lossy(&o.stdout));
    if rep.hardening_index.is_none() && rep.warnings.is_empty() && rep.suggestions.is_empty() {
        bail!("lynis produced no report: {}", o.stderr.trim());
    }
    let findings = lynis_findings(&rep, &loc(h));
    let status = match rep.uid {
        Some(u) if u != 0 => Some(CheckStatus::Partial(
            "lynis ran unprivileged: some tests skipped".into(),
        )),
        _ => None,
    };
    Ok(CheckOutput { status, findings })
}

pub fn checks() -> Vec<Check> {
    let k = [TargetKind::Host];
    vec![
        Check::new(
            "host.probe",
            "Host probe (OS, ssh, firewall, updates, logs)",
            &k,
            Profile::Quick,
            probe_check,
        ),
        Check::new(
            "host.cve",
            "Host package vulnerabilities (grype)",
            &k,
            Profile::Quick,
            cve_check,
        )
        .tool("grype"),
        Check::new(
            "host.lynis",
            "Host hardening audit (lynis)",
            &k,
            Profile::Standard,
            lynis_check,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(checks().iter().map(|c| c.id.as_str()).eq([
            "host.probe",
            "host.cve",
            "host.lynis"
        ]));
    }
}
