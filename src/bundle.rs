//! Offline bundle export/import + doctor (owned by the offline agent).
use crate::engine;
use crate::tools::{self, Docker};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(test)]
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const EMBEDDED_EOL: &str = include_str!("../data/endoflife.json");
const EOL_PRODUCTS: [&str; 10] = [
    "python",
    "nodejs",
    "go",
    "postgresql",
    "ubuntu",
    "debian",
    "alpine",
    "php",
    "ruby",
    "dotnet",
];

/// True when READYHAI_OFFLINE=1: any registry pull / DB update must hard-fail.
pub fn offline() -> bool {
    matches!(
        std::env::var("READYHAI_OFFLINE").as_deref(),
        Ok("1" | "true")
    )
}

fn cache_eol_path() -> PathBuf {
    engine::data_dir().join("cache").join("endoflife.json")
}

/// End-of-life snapshot `{product: [{cycle, eol, lts}]}`: the bundle/`tools update` cache first,
/// the snapshot embedded in the binary otherwise.
#[allow(dead_code)]
pub fn endoflife() -> Value {
    if let Ok(t) = std::fs::read_to_string(cache_eol_path())
        && let Ok(v) = serde_json::from_str::<Value>(&t)
        && v.is_object()
    {
        return v;
    }
    serde_json::from_str(EMBEDDED_EOL).unwrap_or_else(|_| json!({}))
}

// ---------------------------------------------------------------- manifest

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageEntry {
    pub tool: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub created: String,
    pub set: String,
    pub files: Vec<FileEntry>,
    pub images: Vec<ImageEntry>,
}

/// Streaming sha256 (files can be many GB).
pub fn sha256_file(p: &Path) -> Result<(String, u64)> {
    let f = std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?;
    let mut r = BufReader::with_capacity(1 << 20, f);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n_total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        n_total += n as u64;
    }
    Ok((hex::encode(h.finalize()), n_total))
}

/// Hash every regular file under `dir` (except manifest.json).
pub fn build_files(dir: &Path) -> Result<Vec<FileEntry>> {
    let mut v = vec![];
    for e in walkdir::WalkDir::new(dir).sort_by_file_name() {
        let e = e?;
        if !e.file_type().is_file() {
            continue;
        }
        let rel = e
            .path()
            .strip_prefix(dir)?
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "manifest.json" {
            continue;
        }
        let (sha256, size) = sha256_file(e.path())?;
        v.push(FileEntry {
            path: rel,
            sha256,
            size,
        });
    }
    Ok(v)
}

/// Verify every manifest entry against `dir`; fails on any mismatch, missing file or path escape.
pub fn verify_manifest(dir: &Path, m: &Manifest) -> Result<()> {
    for f in &m.files {
        if !safe_rel(&f.path) {
            bail!("manifest path escapes the bundle: {}", f.path);
        }
        let p = dir.join(&f.path);
        let (got, size) =
            sha256_file(&p).with_context(|| format!("manifest file missing: {}", f.path))?;
        if got != f.sha256 || size != f.size {
            bail!(
                "sha256 mismatch for {} (bundle is corrupt or tampered)",
                f.path
            );
        }
    }
    Ok(())
}

fn safe_rel(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && Path::new(p).components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

// ---------------------------------------------------------------- tar helpers (system tar)

/// List a tar and reject absolute paths, `..` components and link entries.
pub fn check_tar_safe(tar: &Path) -> Result<()> {
    let o = Command::new("tar")
        .arg("-tf")
        .arg(tar)
        .stdin(Stdio::null())
        .output()
        .context("running tar")?;
    if !o.status.success() {
        bail!(
            "tar -tf failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    for name in String::from_utf8_lossy(&o.stdout).lines() {
        let n = name.trim_end_matches('/');
        if name.starts_with('/') || n.split('/').any(|c| c == "..") || name.contains('\\') {
            bail!("unsafe path in bundle tar: {name}");
        }
    }
    let o = Command::new("tar")
        .arg("-tvf")
        .arg(tar)
        .stdin(Stdio::null())
        .output()
        .context("running tar")?;
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        match line.chars().next() {
            Some('-') | Some('d') => {}
            _ => bail!("unsupported entry type in bundle tar (links/devices rejected): {line}"),
        }
    }
    Ok(())
}

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let o = cmd
        .stdin(Stdio::null())
        .output()
        .with_context(|| what.to_string())?;
    if !o.status.success() {
        bail!("{what}: {}", String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    let mut s = src.as_os_str().to_os_string();
    s.push("/.");
    run(Command::new("cp").arg("-a").arg(&s).arg(dst), "cp -a")
}

/// Copy `<cache>/<sub>` to `dest` through `docker cp` (works for dirs the host user cannot read).
fn copy_cache_dir(image: &str, cache: &Path, sub: &str, dest: &Path) -> Result<()> {
    let o = Command::new("docker")
        .arg("create")
        .arg("-v")
        .arg(format!(
            "{}:/cache:ro",
            std::path::absolute(cache)?.display()
        ))
        .arg(image)
        .arg("x")
        .stdin(Stdio::null())
        .output()
        .context("docker create")?;
    if !o.status.success() {
        bail!(
            "docker create: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    let ctr = String::from_utf8_lossy(&o.stdout).trim().to_string();
    std::fs::create_dir_all(dest)?;
    let r = run(
        Command::new("docker")
            .arg("cp")
            .arg(format!("{ctr}:/cache/{sub}/."))
            .arg(dest),
        &format!("docker cp cache/{sub}"),
    );
    let _ = Command::new("docker").args(["rm", "-f", &ctr]).output();
    r?;
    run(
        Command::new("chmod").arg("-R").arg("u+rwX").arg(dest),
        "chmod",
    )?;
    // interrupted downloads from earlier runs are not part of the DB
    if let Ok(rd) = std::fs::read_dir(dest) {
        for e in rd.filter_map(|e| e.ok()) {
            if e.file_name()
                .to_string_lossy()
                .starts_with("grype-db-download")
            {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    Ok(())
}

fn human(n: u64) -> String {
    let n = n as f64;
    if n >= 1e9 {
        format!("{:.2} GB", n / 1e9)
    } else {
        format!("{:.1} MB", n / 1e6)
    }
}

fn tmp_name(prefix: &str) -> String {
    format!("{prefix}-{:08x}", rand::random::<u32>())
}

// ---------------------------------------------------------------- export

fn fetch_endoflife(dest: &Path) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("readyhai")
        .build()?;
    let mut all = serde_json::Map::new();
    for p in EOL_PRODUCTS {
        let slug = if p == "alpine" { "alpine-linux" } else { p };
        let r = client
            .get(format!("https://endoflife.date/api/{slug}.json"))
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<Value>());
        match r {
            Ok(Value::Array(a)) => {
                let slim: Vec<Value> = a
                    .iter()
                    .map(|c| json!({"cycle": c["cycle"], "eol": c["eol"], "lts": c["lts"]}))
                    .collect();
                all.insert(p.to_string(), Value::Array(slim));
            }
            Ok(_) => eprintln!("  endoflife {p}: unexpected response"),
            Err(e) => eprintln!("  endoflife {p}: {e}"),
        }
    }
    if all.is_empty() {
        bail!("no endoflife data fetched");
    }
    std::fs::write(dest, serde_json::to_vec(&Value::Object(all))?)?;
    Ok(())
}

/// `readyhai bundle export` — run on a network-capable machine.
pub fn export(out: &Path, set: &str, model: Option<&Path>) -> Result<()> {
    if offline() {
        bail!(
            "offline mode: bundle export needs a network-capable machine (unset READYHAI_OFFLINE)"
        );
    }
    if !matches!(set, "core" | "full") {
        bail!("--set must be core or full");
    }
    let data = engine::data_dir();
    let docker = Docker::detect(&data);
    if !docker.available {
        bail!("docker not available: cannot save tool images");
    }
    let filter: Option<BTreeSet<String>> = std::env::var("READYHAI_BUNDLE_TOOLS")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());
    let current = tools::lock_entries();
    let mut wanted: BTreeSet<String> = current.keys().cloned().collect();
    if set == "core" {
        wanted.remove("zap");
        wanted.remove("mobsf");
    }
    if let Some(f) = &filter {
        wanted.retain(|t| f.contains(t));
    }
    if wanted.is_empty() {
        bail!("no tools selected");
    }

    let staging = data.join("bundles").join(tmp_name(".staging"));
    std::fs::create_dir_all(staging.join("bin"))?;
    std::fs::create_dir_all(staging.join("images"))?;
    std::fs::create_dir_all(staging.join("cache"))?;
    let res = (|| -> Result<u64> {
        eprintln!("[1/5] pulling images and recording IDs");
        let lock_tmp = staging.join("tools.lock.toml");
        tools::tools_pull_filtered(Some(&lock_tmp), Some(&wanted))?;
        eprintln!("[2/5] updating vuln DB, rules, lynis");
        tools::tools_update(&docker)?;
        eprintln!("[3/5] endoflife snapshot");
        let eol = docker.cache_dir.join("endoflife.json");
        if let Err(e) = fetch_endoflife(&eol) {
            eprintln!("  endoflife fetch failed ({e:#}); the embedded snapshot will be used");
        }

        eprintln!("[4/5] saving images");
        let text = std::fs::read_to_string(&lock_tmp)?;
        let lock: toml::Table = toml::from_str(&text)?;
        let mut images = vec![];
        for t in &wanted {
            let ent = lock.get("tools").and_then(|x| x.get(t.as_str()));
            let id = ent
                .and_then(|e| e.get("id"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let image = ent
                .and_then(|e| e.get("image"))
                .and_then(|v| v.as_str())
                .unwrap_or(t)
                .to_string();
            let Some(id) = id else {
                eprintln!(
                    "  skipping {t}: image {image} is not present locally (not pulled/built)"
                );
                continue;
            };
            eprintln!("  docker save {t} ({image})");
            let dest = staging.join("images").join(format!("{t}.tar"));
            run(
                Command::new("docker")
                    .arg("save")
                    .arg("-o")
                    .arg(&dest)
                    .arg(&id),
                &format!("docker save {t}"),
            )?;
            images.push(ImageEntry {
                tool: t.clone(),
                reference: image,
                id,
            });
        }
        if images.is_empty() {
            bail!("no images could be saved");
        }

        eprintln!("[5/5] assembling bundle");
        let me = std::env::current_exe()?;
        std::fs::copy(&me, staging.join("bin").join("readyhai"))?;
        // Tool containers run as nobody and create 0700 dirs; `docker cp` reads them regardless.
        let helper = images[0].id.clone();
        for d in ["grype", "semgrep", "lynis"] {
            let src = docker.cache_dir.join(d);
            if src.is_dir() {
                copy_cache_dir(
                    &helper,
                    &docker.cache_dir,
                    d,
                    &staging.join("cache").join(d),
                )?;
            }
        }
        if eol.is_file() {
            std::fs::copy(&eol, staging.join("cache").join("endoflife.json"))?;
        }
        if let Some(m) = model {
            std::fs::create_dir_all(staging.join("model"))?;
            let name = m.file_name().ok_or_else(|| anyhow!("bad model path"))?;
            std::fs::copy(m, staging.join("model").join(name)).context("copying model")?;
        }
        let man = Manifest {
            version: engine::VERSION.to_string(),
            created: engine::now(),
            set: set.to_string(),
            files: build_files(&staging)?,
            images,
        };
        std::fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&man)?,
        )?;
        if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        run(
            Command::new("tar")
                .arg("-cf")
                .arg(out)
                .arg("-C")
                .arg(&staging)
                .arg("."),
            "tar -cf",
        )?;
        Ok(std::fs::metadata(out)?.len())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    let size = res?;
    eprintln!("bundle written: {} ({})", out.display(), human(size));
    Ok(())
}

// ---------------------------------------------------------------- import

/// `readyhai bundle import` — run on the air-gapped machine.
pub fn import(bundle: &Path) -> Result<()> {
    if !bundle.is_file() {
        bail!("bundle not found: {}", bundle.display());
    }
    check_tar_safe(bundle)?;
    let data = engine::data_dir();
    let root = data.join("bundles");
    std::fs::create_dir_all(&root)?;
    let tmp = root.join(tmp_name(".incoming"));
    std::fs::create_dir_all(&tmp)?;
    let r = import_into(bundle, &data, &root, &tmp);
    if tmp.exists() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    r
}

fn import_into(bundle: &Path, data: &Path, root: &Path, tmp: &Path) -> Result<()> {
    eprintln!("extracting {}", bundle.display());
    run(
        Command::new("tar")
            .arg("-xf")
            .arg(bundle)
            .arg("-C")
            .arg(tmp)
            .arg("--no-same-owner"),
        "tar -xf",
    )?;
    let man: Manifest = serde_json::from_slice(
        &std::fs::read(tmp.join("manifest.json")).context("manifest.json missing")?,
    )
    .context("manifest.json invalid")?;
    eprintln!("verifying {} files", man.files.len());
    verify_manifest(tmp, &man)?;
    for im in &man.images {
        if !safe_rel(&im.tool) || im.tool.contains('/') {
            bail!("bad tool name in manifest: {}", im.tool);
        }
    }

    let docker = Docker::detect(data);
    if !docker.available {
        bail!("docker not available: cannot load images");
    }
    let mut loaded = vec![];
    for im in &man.images {
        eprintln!("docker load {}", im.tool);
        let tar = tmp.join("images").join(format!("{}.tar", im.tool));
        run(
            Command::new("docker").arg("load").arg("-i").arg(&tar),
            &format!("docker load {}", im.tool),
        )?;
        let got = tools::local_image_id(&im.id)
            .ok_or_else(|| anyhow!("{}: image {} not present after load", im.tool, im.id))?;
        if got != im.id {
            bail!("{}: loaded image id {got} != manifest {}", im.tool, im.id);
        }
        loaded.push(im.tool.clone());
    }

    std::fs::write(
        data.join("tools.lock.toml"),
        std::fs::read(tmp.join("tools.lock.toml")).context("tools.lock.toml missing")?,
    )?;
    let cache = data.join("cache");
    std::fs::create_dir_all(&cache)?;
    if tmp.join("cache").is_dir() {
        copy_tree(&tmp.join("cache"), &cache)?;
    }
    // tool containers run as nobody and only read the cache
    let _ = Command::new("chmod")
        .arg("-R")
        .arg("a+rX")
        .arg(&cache)
        .status();

    let stamp: String = man
        .created
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let dest = root.join(&stamp);
    if dest.exists() {
        std::fs::remove_dir_all(&dest)?;
    }
    // images are loaded into docker; drop the duplicate tars to save disk
    let _ = std::fs::remove_dir_all(tmp.join("images"));
    let _ = std::fs::remove_dir_all(tmp.join("cache"));
    std::fs::rename(tmp, &dest)?;

    println!(
        "bundle imported: {} (readyhai {}, set {}, created {})",
        dest.display(),
        man.version,
        man.set,
        man.created
    );
    println!("  images loaded: {}", loaded.join(", "));
    println!(
        "  lock installed: {}",
        data.join("tools.lock.toml").display()
    );
    println!("  cache: {}", cache.display());
    if let Some(d) = tools::db_age_days(&cache) {
        println!("  vuln DB age: {d} day(s)");
    }
    if dest.join("bin").join("readyhai").is_file() {
        println!(
            "  bundled binary: {}",
            dest.join("bin").join("readyhai").display()
        );
    }
    if dest.join("model").is_dir() {
        println!("  model: {}", dest.join("model").display());
    }
    Ok(())
}

// ---------------------------------------------------------------- doctor

fn probe_llm() -> (String, bool) {
    let cfg = match crate::llm::LlmConfig::from_env() {
        Ok(c) => c,
        Err(e) => return (format!("no provider ({e})"), false),
    };
    let base = match cfg.base_url() {
        Ok(b) => b,
        Err(e) => return (format!("{} ({e})", cfg.provider.id), false),
    };
    let url = format!("{}/models", base.trim_end_matches('/'));
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(e) => return (format!("{e}"), false),
    };
    match client.get(&url).send() {
        Ok(r) => (
            format!(
                "{} @ {base} answered HTTP {}",
                cfg.provider.id,
                r.status().as_u16()
            ),
            true,
        ),
        Err(_) => (
            format!("{} @ {base} unreachable (2s)", cfg.provider.id),
            false,
        ),
    }
}

fn free_disk_kb(dir: &Path) -> Option<u64> {
    let mut d = dir.to_path_buf();
    while !d.exists() {
        d = d.parent()?.to_path_buf();
    }
    let o = Command::new("df").arg("-Pk").arg(&d).output().ok()?;
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()
}

fn mtime_date(p: &Path) -> Option<String> {
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    let d = time::OffsetDateTime::from(t).date();
    Some(d.to_string())
}

pub fn doctor() -> Result<()> {
    let data = engine::data_dir();
    let cache = data.join("cache");
    let (llm_note, llm_ok) = probe_llm();
    let mode = if llm_ok {
        "lan-llm"
    } else if offline() {
        "offline"
    } else {
        "deterministic"
    };
    println!("readyhai {} doctor", engine::VERSION);
    println!(
        "mode:        {mode}{}",
        if offline() {
            " (READYHAI_OFFLINE=1: no pulls, no DB updates)"
        } else {
            ""
        }
    );
    println!("llm:         {llm_note}");
    println!("data dir:    {}", data.display());

    let dv = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    match &dv {
        Some(v) => println!("docker:      server {v}"),
        None => println!("! docker:    not available (container tools will be skipped)"),
    }

    println!("tools:");
    for (name, e) in tools::lock_entries() {
        let by_id =
            e.id.as_deref()
                .filter(|i| tools::local_image_id(i).is_some());
        let present = dv.is_some() && tools::image_present(&name);
        let pinned = by_id.is_some() || e.digest.starts_with("sha256:");
        let id =
            e.id.as_deref()
                .map(|i| {
                    i.trim_start_matches("sha256:")
                        .chars()
                        .take(12)
                        .collect::<String>()
                })
                .unwrap_or_else(|| "-".into());
        let mark = if present { " " } else { "!" };
        println!(
            "{mark} {:<12} present={:<5} pinned={:<5} id={id}  {}",
            name, present, pinned, e.image
        );
    }

    match tools::db_age_days(&cache) {
        Some(d) if d > 30 => println!("! grype DB:  {d} day(s) old (> 30: stale)"),
        Some(d) if d > 7 => println!("! grype DB:  {d} day(s) old (> 7: scans are Partial)"),
        Some(d) => println!("  grype DB:  {d} day(s) old"),
        None => println!(
            "! grype DB:  missing ({})",
            if offline() {
                "import a bundle"
            } else {
                "run `readyhai tools update`"
            }
        ),
    }
    let rules = std::fs::read_dir(cache.join("semgrep"))
        .map(|d| {
            d.filter_map(|e| e.ok()).any(|e| {
                matches!(
                    e.path().extension().and_then(|x| x.to_str()),
                    Some("yml" | "yaml")
                )
            })
        })
        .unwrap_or(false);
    println!(
        "{} semgrep rules: {}",
        if rules { " " } else { "!" },
        if rules { "present" } else { "missing" }
    );
    let lynis = cache.join("lynis").join("lynis.tar.gz").is_file();
    println!(
        "{} lynis:      {}",
        if lynis { " " } else { "!" },
        if lynis { "present" } else { "missing" }
    );
    match mtime_date(&cache.join("endoflife.json")) {
        Some(d) => println!("  endoflife: snapshot {d}"),
        None => println!("  endoflife: embedded snapshot (no cached copy)"),
    }
    match free_disk_kb(&data) {
        Some(kb) if kb < 5 * 1024 * 1024 => println!(
            "! disk free: {} (low; bundles are 3-9 GB)",
            human(kb * 1024)
        ),
        Some(kb) => println!("  disk free: {}", human(kb * 1024)),
        None => println!("! disk free: unknown"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rh-{n}-{:08x}", rand::random::<u32>()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn manifest_build_verify_and_tamper() {
        let d = tmpdir("manifest");
        std::fs::create_dir_all(d.join("images")).unwrap();
        std::fs::write(d.join("images/a.tar"), b"image-bytes").unwrap();
        std::fs::write(d.join("tools.lock.toml"), b"[tools]\n").unwrap();
        let m = Manifest {
            version: "t".into(),
            created: "now".into(),
            set: "core".into(),
            files: build_files(&d).unwrap(),
            images: vec![],
        };
        assert_eq!(m.files.len(), 2);
        verify_manifest(&d, &m).unwrap();
        std::fs::write(d.join("images/a.tar"), b"image-byteX").unwrap();
        let e = verify_manifest(&d, &m).unwrap_err().to_string();
        assert!(e.contains("mismatch"), "{e}");
        std::fs::write(d.join("images/a.tar"), b"image-bytes").unwrap();
        std::fs::remove_file(d.join("tools.lock.toml")).unwrap();
        assert!(verify_manifest(&d, &m).is_err());
        let mut bad = m.clone();
        bad.files[0].path = "../escape".into();
        assert!(
            verify_manifest(&d, &bad)
                .unwrap_err()
                .to_string()
                .contains("escapes")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tar_traversal_rejected() {
        let d = tmpdir("tar");
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(d.join("evil.txt"), b"x").unwrap();
        std::fs::write(sub.join("ok.txt"), b"x").unwrap();
        let good = d.join("good.tar");
        run(
            Command::new("tar")
                .arg("-cf")
                .arg(&good)
                .arg("-C")
                .arg(&sub)
                .arg("."),
            "tar",
        )
        .unwrap();
        check_tar_safe(&good).unwrap();
        let dotdot = d.join("dotdot.tar");
        run(
            Command::new("tar")
                .arg("-cPf")
                .arg(&dotdot)
                .arg("-C")
                .arg(&sub)
                .arg("../evil.txt"),
            "tar",
        )
        .unwrap();
        assert!(
            check_tar_safe(&dotdot)
                .unwrap_err()
                .to_string()
                .contains("unsafe")
        );
        let abs = d.join("abs.tar");
        run(
            Command::new("tar")
                .arg("-cPf")
                .arg(&abs)
                .arg(d.join("evil.txt")),
            "tar",
        )
        .unwrap();
        assert!(
            check_tar_safe(&abs)
                .unwrap_err()
                .to_string()
                .contains("unsafe")
        );
        let lnk = d.join("lnk.tar");
        std::os::unix::fs::symlink("/etc/passwd", sub.join("l")).unwrap();
        run(
            Command::new("tar")
                .arg("-cf")
                .arg(&lnk)
                .arg("-C")
                .arg(&sub)
                .arg("l"),
            "tar",
        )
        .unwrap();
        assert!(check_tar_safe(&lnk).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn export_refused_offline() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("READYHAI_OFFLINE", "1") };
        let e = export(Path::new("/tmp/x.tar"), "core", None)
            .unwrap_err()
            .to_string();
        unsafe { std::env::remove_var("READYHAI_OFFLINE") };
        assert!(e.contains("offline"), "{e}");
    }

    #[test]
    fn embedded_endoflife_parses() {
        let v: Value = serde_json::from_str(EMBEDDED_EOL).unwrap();
        for p in EOL_PRODUCTS {
            assert!(v[p].as_array().is_some_and(|a| !a.is_empty()), "{p}");
        }
        assert!(endoflife().is_object());
    }
}
