//! Check executors for host probe, package CVE detection, and Lynis audits.
use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use std::time::Duration;

use super::lynis::{lynis_findings, lynis_tarball, parse_lynis};
use super::probe::parse_probe;
use super::redact::redact_line;
use super::ssh::{loc, remote_cmd, run_ssh, script, ssh_failure};
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus, HostSpec, Os, Profile, TargetKind};
use crate::tools::{ToolSpec, parse_grype};

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
