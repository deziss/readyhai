//! SSH client execution, command escaping, and remote OS script execution.
use anyhow::{Context, Result, anyhow, bail};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::host::types::{LINUX_SH, MACOS_SH, SshOut, WINDOWS_PS1};
use crate::model::{HostSpec, Os};

pub(crate) fn loc(h: &HostSpec) -> String {
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
pub(crate) fn ssh_failure(h: &HostSpec, o: &SshOut) -> anyhow::Error {
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

pub(crate) fn remote_cmd(os: Os) -> &'static str {
    match os {
        // Slurp the script, then exec so that commands in it cannot consume the script from stdin.
        Os::Linux => "s=$(cat); exec sh -c \"$s\" </dev/null",
        Os::Macos => "s=$(cat); exec bash -c \"$s\" </dev/null",
        Os::Windows => "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
    }
}

pub(crate) fn script(os: Os) -> &'static str {
    match os {
        Os::Linux => LINUX_SH,
        Os::Macos => MACOS_SH,
        Os::Windows => WINDOWS_PS1,
    }
}
