//! Android targets: MobSF static (short-lived per-scan container, REST API) +
//! BYO-device ADB runtime (owned by the android agent).
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};
use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub fn checks() -> Vec<Check> {
    vec![
        Check::new(
            "android.mobsf",
            "Android static analysis (MobSF)",
            &[TargetKind::Android],
            Profile::Quick,
            run_mobsf,
        )
        .tool("mobsf"),
        Check::new(
            "android.runtime",
            "Android runtime: install, launch, logcat crashes/ANRs",
            &[TargetKind::Android],
            Profile::Standard,
            run_runtime,
        ),
    ]
}

// ---------------------------------------------------------------- staging

/// Copy the APK/AAB into <run>/src/app.<ext> (mode 644). Returns (path, ext).
fn stage_app(ctx: &Ctx) -> Result<Option<(PathBuf, String)>> {
    let Some(apk) = ctx.target.apk.clone() else {
        return Ok(None);
    };
    if !apk.is_file() {
        bail!("APK not found: {}", apk.display());
    }
    let ext = apk
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .filter(|e| matches!(e.as_str(), "apk" | "aab" | "xapk" | "zip"))
        .unwrap_or_else(|| "apk".into());
    let dir = ctx.src_dir();
    std::fs::create_dir_all(&dir).context("create src dir")?;
    let dst = dir.join(format!("app.{ext}"));
    std::fs::copy(&apk, &dst).context("copy app into run dir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o644));
    }
    Ok(Some((dst, ext)))
}

// ---------------------------------------------------------------- helpers

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).unwrap())
}

/// Redact emails, bearer/JWT tokens, key=value secrets and long hex/base64-ish blobs.
pub fn redact(s: &str) -> String {
    static EMAIL: OnceLock<Regex> = OnceLock::new();
    static KV: OnceLock<Regex> = OnceLock::new();
    static JWT: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    static LONG: OnceLock<Regex> = OnceLock::new();
    let s = re(&EMAIL, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").replace_all(s, "<email>");
    let s = re(&KV, r"(?i)\b(token|secret|password|passwd|pwd|api[_-]?key|authorization|bearer)(\s*[=:]\s*|\s+)\S+")
        .replace_all(&s, "$1=<redacted>");
    let s = re(
        &JWT,
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
    )
    .replace_all(&s, "<jwt>");
    let s = re(&HEX, r"\b[0-9a-fA-F]{24,}\b").replace_all(&s, "<hex>");
    let s = re(&LONG, r"[A-Za-z0-9+/_-]{40,}={0,2}").replace_all(&s, "<blob>");
    s.into_owned()
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('_');
            dash = true;
        }
    }
    let t = out.trim_end_matches('_');
    t.chars().take(60).collect()
}

fn vs<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

/// Run a command with a hard timeout; returns (exit code, stdout, stderr).
fn run_cmd(cmd: &mut Command, secs: u64) -> Result<(i32, String, String)> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn")?;
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t1 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t2 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let end = Instant::now() + Duration::from_secs(secs);
    let code = loop {
        if let Some(st) = child.try_wait()? {
            break st.code().unwrap_or(-1);
        }
        if Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out after {secs}s");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let o = String::from_utf8_lossy(&t1.join().unwrap_or_default()).into_owned();
    let e = String::from_utf8_lossy(&t2.join().unwrap_or_default()).into_owned();
    Ok((code, o, e))
}

// ---------------------------------------------------------------- MobSF: HTTP helpers

/// Hand-built multipart/form-data body with a single file field.
pub fn multipart_body(boundary: &str, field: &str, filename: &str, bytes: &[u8]) -> Vec<u8> {
    let safe: String = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || ".-_".contains(*c))
        .collect();
    let mut b = Vec::with_capacity(bytes.len() + 256);
    b.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{safe}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    b.extend_from_slice(bytes);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    b
}

fn urlencode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

pub fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn rand_hex(n: usize) -> String {
    use rand::Rng;
    let mut r = rand::rng();
    (0..n)
        .map(|_| format!("{:02x}", r.random::<u8>()))
        .collect()
}

// ---------------------------------------------------------------- MobSF: container

struct MobsfContainer {
    name: String,
}

impl Drop for MobsfContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdin(Stdio::null())
            .output();
    }
}

/// Parse `docker port` output ("127.0.0.1:49153" / "0.0.0.0:49153\n[::]:49153") to a port.
pub fn parse_docker_port(out: &str) -> Option<u16> {
    out.lines()
        .find_map(|l| l.trim().rsplit(':').next()?.parse::<u16>().ok())
}

fn start_mobsf(ctx: &Ctx, key: &str) -> Result<(MobsfContainer, u16)> {
    let (image, _) = crate::tools::image_for("mobsf");
    let name = format!("readyhai-mobsf-{}-{}", ctx.run_id, rand_hex(3));
    let label = format!("readyhai.run={}", ctx.run_id);
    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "-d",
        "--name",
        &name,
        "--label",
        &label,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "1024",
        "--memory",
        "2g",
        "--cpus",
        "2",
        // MobSF needs a writable home; tmpfs keeps nothing after the scan.
        "--tmpfs",
        "/home/mobsf/.MobSF:rw,exec,uid=9901,gid=9901,size=1g",
        "--tmpfs",
        "/tmp:rw,exec,size=1g",
        "-e",
        "MOBSF_API_KEY", // value passed via env, never on the command line
        "-p",
        "127.0.0.1::8000",
        &image,
    ]);
    cmd.env("MOBSF_API_KEY", key);
    let (code, out, err) = run_cmd(&mut cmd, 300)?;
    if code != 0 {
        bail!("docker run mobsf failed: {}", err.trim());
    }
    let guard = MobsfContainer {
        name: if out.trim().is_empty() {
            name
        } else {
            out.trim().to_string()
        },
    };
    let (_, p, _) = run_cmd(
        Command::new("docker").args(["port", &guard.name, "8000/tcp"]),
        15,
    )?;
    let port =
        parse_docker_port(&p).ok_or_else(|| anyhow!("cannot determine MobSF published port"))?;
    Ok((guard, port))
}

fn mobsf_scan(base: &str, key: &str, app: &std::path::Path) -> Result<Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1500))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    // readiness
    let end = Instant::now() + Duration::from_secs(120);
    loop {
        match client
            .get(format!("{base}/"))
            .timeout(Duration::from_secs(5))
            .send()
        {
            Ok(_) => break,
            Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_secs(2)),
            Err(e) => bail!("MobSF not ready after 120s: {e}"),
        }
    }
    let fname = app
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("app.apk")
        .to_string();
    let bytes = std::fs::read(app)?;
    let boundary = format!("----readyhai{}", rand_hex(8));
    let r = client
        .post(format!("{base}/api/v1/upload"))
        .header("Authorization", key)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(multipart_body(&boundary, "file", &fname, &bytes))
        .send()?;
    let st = r.status();
    let up: Value = r
        .json()
        .with_context(|| format!("MobSF upload response (HTTP {st})"))?;
    let hash = up
        .get("hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("MobSF upload gave no hash (HTTP {st})"))?
        .to_string();
    let scan_type = up
        .get("scan_type")
        .and_then(|h| h.as_str())
        .unwrap_or("apk")
        .to_string();
    let file_name = up
        .get("file_name")
        .and_then(|h| h.as_str())
        .unwrap_or(&fname)
        .to_string();
    let post_form = |path: &str, pairs: &[(&str, &str)]| -> Result<reqwest::blocking::Response> {
        Ok(client
            .post(format!("{base}{path}"))
            .header("Authorization", key)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body(pairs))
            .send()?)
    };
    let r = post_form(
        "/api/v1/scan",
        &[
            ("hash", &hash),
            ("scan_type", &scan_type),
            ("file_name", &file_name),
        ],
    )?;
    if !r.status().is_success() {
        bail!("MobSF scan failed: HTTP {}", r.status());
    }
    let _ = r.bytes(); // synchronous scan: body is the report; we re-fetch a canonical copy below
    let r = post_form("/api/v1/report_json", &[("hash", &hash)])?;
    if !r.status().is_success() {
        bail!("MobSF report_json failed: HTTP {}", r.status());
    }
    let mut rep: Value = r.json().context("MobSF report_json body")?;
    if let Ok(r) = post_form("/api/v1/scorecard", &[("hash", &hash)])
        && r.status().is_success()
        && let Ok(sc) = r.json::<Value>()
    {
        rep["_scorecard"] = sc;
    }
    Ok(rep)
}

// ---------------------------------------------------------------- MobSF: scrub + map

fn count_of(v: &Value) -> usize {
    match v {
        Value::Array(a) => a
            .iter()
            .map(|x| match x {
                Value::Object(o) => o
                    .values()
                    .filter_map(|y| y.as_array())
                    .map(|y| y.len())
                    .sum::<usize>()
                    .max(1),
                _ => 1,
            })
            .sum(),
        Value::Object(o) => o.len(),
        Value::Null => 0,
        _ => 1,
    }
}

/// Remove secret-bearing sections: keep only counts (and secret key names).
pub fn scrub_report(rep: &Value) -> Value {
    let mut v = rep.clone();
    let Some(o) = v.as_object_mut() else { return v };
    if let Some(s) = o.get("secrets").cloned() {
        let types: BTreeSet<String> = s
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(|x| {
                        redact(x.split('=').next().unwrap_or("").trim())
                            .chars()
                            .take(60)
                            .collect::<String>()
                    })
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        o.insert(
            "secrets".into(),
            json!({"count": count_of(&s), "types": types}),
        );
    }
    for k in [
        "strings",
        "urls",
        "emails",
        "firebase_urls",
        "domains",
        "files",
        "apkid_strings",
    ] {
        if let Some(s) = o.get(k).cloned() {
            o.insert(k.into(), json!({"count": count_of(&s)}));
        }
    }
    v
}

fn sev_of(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "high" | "critical" => Some(Severity::High),
        "warning" | "medium" | "warn" => Some(Severity::Medium),
        "info" | "low" => Some(Severity::Low),
        _ => None, // secure / good / suppressed / unknown
    }
}

fn mk(rule: &str, sev: Severity, title: &str, detail: &str, loc: &str) -> Finding {
    let mut f = Finding::new(
        "android.mobsf",
        rule,
        Category::Security,
        sev,
        title.chars().take(160).collect::<String>(),
        loc,
    );
    f.detail = redact(detail).chars().take(600).collect();
    f
}

fn manifest_special(text: &str) -> Option<(&'static str, Severity)> {
    let t = text.to_ascii_lowercase();
    if t.contains("debuggable") {
        Some(("debuggable", Severity::High))
    } else if t.contains("allowbackup")
        || t.contains("allow backup")
        || t.contains("can be backed up")
    {
        Some(("allow_backup", Severity::Medium))
    } else if t.contains("cleartext") || t.contains("clear text") || t.contains("clear_text") {
        Some(("cleartext_traffic", Severity::Medium))
    } else {
        None
    }
}

pub fn map_report(rep: &Value) -> Vec<Finding> {
    let mut out: Vec<Finding> = vec![];
    let mut seen = BTreeSet::new();
    let mut push = |out: &mut Vec<Finding>, f: Finding| {
        if seen.insert(format!("{}|{}", f.rule, f.location)) {
            out.push(f);
        }
    };

    // manifest
    let ma = rep.get("manifest_analysis");
    let items: Vec<&Value> = match ma {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(o) => o
            .get("manifest_findings")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default(),
        None => vec![],
    };
    for it in items {
        let sev_s = if !vs(it, "severity").is_empty() {
            vs(it, "severity")
        } else {
            vs(it, "stat")
        };
        let Some(mut sev) = sev_of(sev_s) else {
            continue;
        };
        let title = vs(it, "title");
        let desc = if !vs(it, "description").is_empty() {
            vs(it, "description")
        } else {
            vs(it, "desc")
        };
        let key = if !vs(it, "rule").is_empty() {
            vs(it, "rule").to_string()
        } else {
            slug(title)
        };
        let mut rule = format!("mobsf.manifest_analysis.{}", slug(&key));
        if let Some((k, s)) = manifest_special(&format!("{key} {title}")) {
            rule = format!("mobsf.manifest_analysis.{k}");
            sev = s;
        }
        let comp = it
            .get("component")
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let detail = if comp.is_empty() {
            desc.to_string()
        } else {
            format!("{desc} Components: {comp}")
        };
        push(
            &mut out,
            mk(&rule, sev, title, &detail, "AndroidManifest.xml"),
        );
    }

    // code analysis
    if let Some(fs) = rep
        .pointer("/code_analysis/findings")
        .and_then(|x| x.as_object())
    {
        for (id, f) in fs {
            let md = f.get("metadata").unwrap_or(&Value::Null);
            let Some(sev) = sev_of(vs(md, "severity")) else {
                continue;
            };
            let files: Vec<&String> = f
                .get("files")
                .and_then(|x| x.as_object())
                .map(|o| o.keys().collect())
                .unwrap_or_default();
            let loc = files
                .first()
                .map(|s| s.as_str())
                .unwrap_or("AndroidManifest.xml");
            let mut fnd = mk(
                &format!("mobsf.code_analysis.{}", slug(id)),
                sev,
                vs(md, "description"),
                &format!("{} ({} file(s))", vs(md, "description"), files.len()),
                loc,
            );
            if let Some(cwe) = md.get("cwe").and_then(|c| c.as_str()) {
                fnd.ids
                    .push(cwe.split(':').next().unwrap_or(cwe).to_string());
            }
            if fnd.title.is_empty() {
                fnd.title = id.clone();
            }
            fnd.fp_key = Some(id.clone());
            push(&mut out, fnd);
        }
    }

    // binary analysis (list of entries or object of file -> entry)
    let bins: Vec<&Value> = match rep.get("binary_analysis") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Object(o)) => o.values().collect(),
        _ => vec![],
    };
    for b in bins {
        let Some(sev) = sev_of(vs(b, "severity")) else {
            continue;
        };
        let t = if !vs(b, "title").is_empty() {
            vs(b, "title")
        } else {
            vs(b, "name")
        };
        let loc = if !vs(b, "file").is_empty() {
            vs(b, "file")
        } else {
            "AndroidManifest.xml"
        };
        push(
            &mut out,
            mk(
                &format!(
                    "mobsf.binary_analysis.{}",
                    slug(&format!("{t}_{}", vs(b, "description")))
                ),
                sev,
                t,
                vs(b, "description"),
                loc,
            ),
        );
    }

    // network security
    if let Some(a) = rep
        .pointer("/network_security/network_findings")
        .and_then(|x| x.as_array())
    {
        for n in a {
            let Some(sev) = sev_of(vs(n, "severity")) else {
                continue;
            };
            let d = vs(n, "description");
            let rule = match manifest_special(d) {
                Some((k, _)) => format!("mobsf.network_security.{k}"),
                None => format!("mobsf.network_security.{}", slug(d)),
            };
            push(
                &mut out,
                mk(&rule, sev, d, d, "network_security_config.xml"),
            );
        }
    }

    // certificate
    if let Some(a) = rep
        .pointer("/certificate_analysis/certificate_findings")
        .and_then(|x| x.as_array())
    {
        for c in a {
            let (s, t, d) = match c {
                Value::Array(x) => (
                    x.first().and_then(|y| y.as_str()).unwrap_or(""),
                    x.get(1).and_then(|y| y.as_str()).unwrap_or(""),
                    x.get(2).and_then(|y| y.as_str()).unwrap_or(""),
                ),
                _ => (vs(c, "severity"), vs(c, "title"), vs(c, "description")),
            };
            let Some(sev) = sev_of(s) else { continue };
            push(
                &mut out,
                mk(
                    &format!("mobsf.certificate.{}", slug(t)),
                    sev,
                    t,
                    d,
                    "META-INF/CERT",
                ),
            );
        }
    }

    // permissions
    if let Some(p) = rep.get("permissions").and_then(|x| x.as_object()) {
        let d: Vec<&str> = p
            .iter()
            .filter(|(_, v)| vs(v, "status") == "dangerous")
            .map(|(k, _)| k.as_str())
            .collect();
        if !d.is_empty() {
            push(
                &mut out,
                mk(
                    "mobsf.permissions.dangerous",
                    Severity::Low,
                    &format!("{} dangerous permission(s) requested", d.len()),
                    &d.join(", "),
                    "AndroidManifest.xml",
                ),
            );
        }
    }

    // trackers
    let tr = rep
        .pointer("/trackers/detected_trackers")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    if tr > 0 {
        let names: Vec<&str> = rep
            .pointer("/trackers/trackers")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().map(|t| vs(t, "name")).collect())
            .unwrap_or_default();
        push(
            &mut out,
            mk(
                "mobsf.trackers.detected",
                Severity::Low,
                &format!("{tr} embedded tracker(s) detected"),
                &names.join(", "),
                "app",
            ),
        );
    }

    // secrets: count only
    let sc = rep.get("secrets").map(count_of).unwrap_or(0);
    if sc > 0 {
        push(
            &mut out,
            mk(
                "mobsf.secrets.hardcoded",
                Severity::Medium,
                &format!("{sc} potential hardcoded secret(s) in the app (values withheld)"),
                "See MobSF; values are never stored by readyhai.",
                "app",
            ),
        );
    }

    // target SDK
    let tsdk = rep.get("target_sdk").and_then(|x| {
        x.as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .or_else(|| x.as_u64().map(|n| n as u32))
    });
    if let Some(t) = tsdk
        && t < 33
    {
        let mut f = Finding::new(
            "android.mobsf",
            "mobsf.target_sdk.outdated",
            Category::SupplyChain,
            Severity::Medium,
            "outdated targetSdkVersion",
            "AndroidManifest.xml",
        );
        f.detail = format!(
            "targetSdkVersion {t} < 33; Google Play requires a recent target API level and newer platform protections are skipped."
        );
        f.remediation = "Raise targetSdkVersion and retest.".into();
        push(&mut out, f);
    }
    out
}

fn run_mobsf(ctx: &Ctx) -> Result<CheckOutput> {
    if ctx.target.apk.is_none() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no APK/AAB given".into(),
        )));
    }
    if !ctx.docker.available {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "docker not available".into(),
        )));
    }
    let Some((app, _)) = stage_app(ctx)? else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no APK/AAB given".into(),
        )));
    };
    let key = rand_hex(24);
    let (guard, port) = start_mobsf(ctx, &key)?;
    let rep = mobsf_scan(&format!("http://127.0.0.1:{port}"), &key, &app);
    drop(guard);
    let rep = rep?;
    let clean = scrub_report(&rep);
    std::fs::create_dir_all(ctx.out_dir())?;
    std::fs::write(
        ctx.out_dir().join("mobsf.json"),
        serde_json::to_string_pretty(&clean)?,
    )?;
    Ok(CheckOutput::findings(map_report(&rep)))
}

// ---------------------------------------------------------------- runtime (adb)

/// Emulator if serial is `emulator-*` or ro.kernel.qemu == 1.
pub fn is_emulator(serial: &str, qemu_prop: &str) -> bool {
    serial.starts_with("emulator-") || qemu_prop.trim() == "1"
}

#[derive(Debug, Default, PartialEq)]
pub struct LogScan {
    /// (kind "crash"|"anr", title, detail)
    pub events: Vec<(String, String, String)>,
    pub error_lines: Vec<String>,
}

struct LogLine<'a> {
    tag: &'a str,
    pid: &'a str,
    msg: &'a str,
}

fn parse_brief(l: &str) -> Option<(char, LogLine<'_>)> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r"^([EWIDVFA])/([^(]+?)\s*\(\s*(\d+)\):\s?(.*)$");
    let c = r.captures(l)?;
    let lv = c.get(1)?.as_str().chars().next()?;
    Some((
        lv,
        LogLine {
            tag: c.get(2)?.as_str(),
            pid: c.get(3)?.as_str(),
            msg: c.get(4)?.as_str(),
        },
    ))
}

pub fn scan_logcat(text: &str, pkg: &str) -> LogScan {
    let mut sc = LogScan::default();
    // crash blocks keyed by pid, in order
    struct Blk {
        lines: Vec<String>,
        pid: String,
    }
    let mut blocks: Vec<Blk> = vec![];
    for raw in text.lines() {
        let Some((lv, ll)) = parse_brief(raw) else {
            continue;
        };
        if lv != 'E' && lv != 'F' {
            // "Process <pkg> (pid N) has died"
            if ll.msg.contains(pkg) && ll.msg.contains("has died") {
                sc.events.push((
                    "crash".into(),
                    format!("Process {pkg} has died"),
                    redact(ll.msg),
                ));
            }
            continue;
        }
        if ll.tag == "AndroidRuntime" {
            if ll.msg.starts_with("FATAL EXCEPTION") {
                blocks.push(Blk {
                    lines: vec![ll.msg.to_string()],
                    pid: ll.pid.to_string(),
                });
            } else if let Some(b) = blocks.last_mut().filter(|b| b.pid == ll.pid) {
                b.lines.push(ll.msg.to_string());
            }
            continue;
        }
        if ll.msg.contains(&format!("ANR in {pkg}")) {
            sc.events
                .push(("anr".into(), redact(ll.msg), String::new()));
        }
        if ll.msg.contains(pkg) || ll.tag.contains(pkg) {
            sc.error_lines
                .push(redact(&format!("{}: {}", ll.tag, ll.msg)));
        }
    }
    for b in blocks {
        if !b.lines.iter().any(|l| l.contains(pkg)) {
            continue;
        }
        let body: Vec<&String> = b
            .lines
            .iter()
            .skip(1)
            .filter(|l| !l.trim_start().starts_with("Process:"))
            .collect();
        let first = body
            .first()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "FATAL EXCEPTION".into());
        let detail = body
            .iter()
            .take(5)
            .map(|s| s.trim())
            .collect::<Vec<_>>()
            .join("\n");
        for l in &b.lines {
            sc.error_lines.push(redact(l));
        }
        sc.events
            .push(("crash".into(), redact(&first), redact(&detail)));
    }
    sc
}

struct Adb {
    dev: String,
}

impl Adb {
    fn run(&self, args: &[&str], secs: u64) -> Result<(i32, String, String)> {
        run_cmd(
            Command::new("adb").arg("-s").arg(&self.dev).args(args),
            secs,
        )
    }
    fn pkgs(&self) -> Result<BTreeSet<String>> {
        let (_, o, _) = self.run(&["shell", "pm", "list", "packages"], 60)?;
        Ok(o.lines()
            .filter_map(|l| l.trim().strip_prefix("package:"))
            .map(|s| s.trim().to_string())
            .collect())
    }
}

fn package_from_mobsf(ctx: &Ctx) -> Option<String> {
    let t = std::fs::read_to_string(ctx.out_dir().join("mobsf.json")).ok()?;
    let v: Value = serde_json::from_str(&t).ok()?;
    let p = v.get("package_name")?.as_str()?.to_string();
    (!p.is_empty()).then_some(p)
}

fn run_runtime(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(dev) = ctx.target.device.clone() else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "attach a device/emulator and pass --device <serial|host:port>".into(),
        )));
    };
    if run_cmd(Command::new("adb").arg("version"), 10).is_err() {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "adb not installed".into(),
        )));
    }
    let Some((app, ext)) = stage_app(ctx)? else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no APK given".into(),
        )));
    };
    if ext != "apk" {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "adb install needs an .apk (AAB/XAPK not supported)".into(),
        )));
    }
    if dev.contains(':') && !dev.starts_with("emulator-") {
        let _ = run_cmd(Command::new("adb").args(["connect", &dev]), 20);
    }
    let adb = Adb { dev: dev.clone() };
    let (_, st, _) = adb
        .run(&["get-state"], 20)
        .map_err(|e| anyhow!("adb get-state: {e}"))?;
    if st.trim() != "device" {
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "device {dev} state is '{}', expected 'device'",
            st.trim()
        ))));
    }
    let before = adb.pkgs()?;
    let apk_s = app.to_string_lossy().to_string();
    let (code, o, e) = adb.run(&["install", "-r", "-t", &apk_s], 300)?;
    if code != 0 || o.contains("Failure") {
        bail!("adb install failed: {}", redact(format!("{o} {e}").trim()));
    }
    let after = adb.pkgs()?;
    let pkg = package_from_mobsf(ctx)
        .or_else(|| after.difference(&before).next().cloned())
        .ok_or_else(|| anyhow!("cannot determine package name (run android.mobsf first or uninstall the app beforehand)"))?;
    let preinstalled = before.contains(&pkg);

    let result = (|| -> Result<CheckOutput> {
        let _ = adb.run(&["logcat", "-c"], 20);
        adb.run(
            &[
                "shell",
                "monkey",
                "-p",
                &pkg,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            60,
        )?;
        std::thread::sleep(Duration::from_secs(20));
        if matches!(ctx.profile, Profile::Deep) {
            let qemu = adb
                .run(&["shell", "getprop", "ro.kernel.qemu"], 15)
                .map(|r| r.1)
                .unwrap_or_default();
            if is_emulator(&dev, &qemu) {
                let _ = adb.run(
                    &[
                        "shell",
                        "monkey",
                        "-p",
                        &pkg,
                        "--throttle",
                        "200",
                        "--pct-syskeys",
                        "0",
                        "-v",
                        "1500",
                    ],
                    600,
                );
            }
        }
        let (_, log, _) = adb.run(&["logcat", "-d", "-v", "brief", "*:E"], 60)?;
        let sc = scan_logcat(&log, &pkg);
        for l in &sc.error_lines {
            ctx.error_line("android.logcat", l);
        }
        let mut fs = vec![];
        for (kind, title, detail) in sc.events {
            let rule = if kind == "anr" {
                "android.anr"
            } else {
                "android.crash"
            };
            let t = if kind == "anr" {
                format!("ANR: {title}")
            } else {
                format!("App crash: {title}")
            };
            let mut f = Finding::new(
                "android.runtime",
                rule,
                Category::Reliability,
                Severity::High,
                t,
                pkg.clone(),
            );
            f.detail = detail;
            f.fp_key = Some(format!("{rule}:{pkg}:{}", slug(&title)));
            fs.push(f);
        }
        Ok(CheckOutput::findings(fs))
    })();
    if !preinstalled {
        let _ = adb.run(&["uninstall", &pkg], 60);
    }
    result
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(n: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/android/{n}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn mapping_counts_and_severities() {
        let rep: Value = serde_json::from_str(&fixture("mobsf_report.json")).unwrap();
        let fs = map_report(&rep);
        let by = |r: &str| {
            fs.iter().find(|f| f.rule == r).unwrap_or_else(|| {
                panic!(
                    "missing {r}: {:?}",
                    fs.iter().map(|f| &f.rule).collect::<Vec<_>>()
                )
            })
        };
        assert_eq!(
            by("mobsf.manifest_analysis.debuggable").severity,
            Severity::High
        );
        assert_eq!(
            by("mobsf.manifest_analysis.allow_backup").severity,
            Severity::Medium
        );
        assert_eq!(
            by("mobsf.manifest_analysis.cleartext_traffic").severity,
            Severity::Medium
        );
        assert_eq!(
            by("mobsf.manifest_analysis.exported_activity").severity,
            Severity::Medium
        );
        assert_eq!(
            by("mobsf.manifest_analysis.target_sdk_info").severity,
            Severity::Low
        );
        assert!(!fs.iter().any(|f| f.rule.ends_with("good_one")));
        assert_eq!(
            by("mobsf.code_analysis.android_sql_raw_query").severity,
            Severity::High
        );
        assert_eq!(
            by("mobsf.code_analysis.android_sql_raw_query").ids,
            vec!["CWE-89"]
        );
        assert_eq!(
            by("mobsf.code_analysis.android_insecure_random").location,
            "jakhar/aseem/diva/Other.java"
                .to_string()
                .min("jakhar/aseem/diva/Rng.java".to_string())
        );
        assert_eq!(by("mobsf.permissions.dangerous").severity, Severity::Low);
        assert!(
            by("mobsf.permissions.dangerous")
                .detail
                .contains("WRITE_EXTERNAL_STORAGE")
        );
        assert!(
            !by("mobsf.permissions.dangerous")
                .detail
                .contains("INTERNET")
        );
        assert_eq!(by("mobsf.trackers.detected").severity, Severity::Low);
        assert_eq!(
            by("mobsf.target_sdk.outdated").category,
            Category::SupplyChain
        );
        assert_eq!(by("mobsf.secrets.hardcoded").severity, Severity::Medium);
        assert!(fs.iter().any(|f| f.rule.starts_with("mobsf.certificate.")));
        assert!(
            fs.iter()
                .any(|f| f.rule.starts_with("mobsf.binary_analysis."))
        );
        assert!(
            fs.iter()
                .any(|f| f.rule.starts_with("mobsf.network_security."))
        );
        assert!(fs.iter().all(|f| f.check == "android.mobsf"));
    }

    #[test]
    fn secrets_never_leak() {
        let raw = fixture("mobsf_report.json");
        let rep: Value = serde_json::from_str(&raw).unwrap();
        let all = serde_json::to_string(&map_report(&rep)).unwrap();
        let saved = serde_json::to_string(&scrub_report(&rep)).unwrap();
        for bad in [
            "AIzaSyFAKE",
            "wJalrFAKE",
            "SUPERSECRETURLTOKEN",
            "FAKEPASSWORD",
            "dev@fake.example.com",
        ] {
            assert!(!all.contains(bad), "finding leaked {bad}");
            assert!(!saved.contains(bad), "saved report leaked {bad}");
        }
        let s: Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(s["secrets"]["count"], 2);
        assert_eq!(s["urls"]["count"], 1);
        assert_eq!(s["package_name"], "jakhar.aseem.diva");
    }

    #[test]
    fn crash_parsing() {
        let sc = scan_logcat(&fixture("logcat.txt"), "jakhar.aseem.diva");
        let crashes: Vec<_> = sc.events.iter().filter(|e| e.0 == "crash").collect();
        let anrs: Vec<_> = sc.events.iter().filter(|e| e.0 == "anr").collect();
        assert_eq!(crashes.len(), 1);
        assert_eq!(anrs.len(), 1);
        assert!(crashes[0].1.starts_with("java.lang.NullPointerException"));
        assert_eq!(crashes[0].2.lines().count(), 5);
        assert!(crashes[0].2.contains("MainActivity.onCreate"));
        assert!(!sc.events.iter().any(|e| e.1.contains("not ours")));
        assert!(anrs[0].1.contains("ANR in jakhar.aseem.diva"));
        let joined = sc.error_lines.join("\n");
        assert!(!joined.contains("dev@fake.example.com"));
        assert!(!joined.contains("abcdef0123456789abcdef0123456789abcd"));
        assert!(!joined.contains("other.app"));
        assert!(joined.contains("Failed to load config"));
    }

    #[test]
    fn multipart_and_form() {
        let b = multipart_body("BND", "file", "a b/../x.apk", b"PK\x03\x04");
        let t = String::from_utf8_lossy(&b).to_string();
        assert!(t.starts_with(
            "--BND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ab..x.apk\""
        ));
        assert!(t.contains("\r\n\r\nPK"));
        assert!(t.ends_with("\r\n--BND--\r\n"));
        assert_eq!(
            form_body(&[("hash", "ab"), ("file_name", "a b.apk")]),
            "hash=ab&file_name=a%20b.apk"
        );
    }

    #[test]
    fn emulator_and_port() {
        assert!(is_emulator("emulator-5554", ""));
        assert!(is_emulator("10.0.0.5:5555", "1\n"));
        assert!(!is_emulator("R58M123ABC", "0"));
        assert_eq!(parse_docker_port("127.0.0.1:49153\n"), Some(49153));
        assert_eq!(parse_docker_port("0.0.0.0:32768\n[::]:32768"), Some(32768));
        assert_eq!(parse_docker_port(""), None);
    }

    #[test]
    fn redaction() {
        let r = redact(
            "user a@b.io password=hunter2 Bearer abcdefabcdefabcdefabcdefabcdef12 eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4",
        );
        assert!(
            !r.contains("a@b.io")
                && !r.contains("hunter2")
                && !r.contains("eyJhbGci")
                && !r.contains("abcdefabcdef")
        );
    }
}
