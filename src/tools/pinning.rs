use super::docker::{DOCKER_QUICK, Docker, exec, mkdir_open};
use super::policy::Mount;
use super::process::run_capped;
use super::types::{LockEntry, LockFile, ToolSpec};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

const EMBEDDED_LOCK: &str = include_str!("../../tools.lock.toml");

/// Lock precedence: READYHAI_TOOLS_LOCK env file > <data>/tools.lock.toml (installed by `bundle import`) > embedded.
pub(crate) fn pick_lock_text(env_path: Option<&str>, data: &Path) -> String {
    if let Some(p) = env_path
        && let Ok(t) = std::fs::read_to_string(p)
    {
        return t;
    }
    if let Ok(t) = std::fs::read_to_string(data.join("tools.lock.toml")) {
        return t;
    }
    EMBEDDED_LOCK.to_string()
}

pub(crate) fn lock_text() -> String {
    let env = std::env::var("READYHAI_TOOLS_LOCK").ok();
    pick_lock_text(env.as_deref(), &crate::engine::data_dir())
}

pub(crate) fn load_lock() -> LockFile {
    toml::from_str(&lock_text()).unwrap_or_default()
}

/// Lock entries (tool -> entry) as currently resolved.
pub fn lock_entries() -> BTreeMap<String, LockEntry> {
    load_lock().tools
}

/// ID of a local image (`docker image inspect`), None when it is not present.
pub fn local_image_id(reference: &str) -> Option<String> {
    let o = run_capped(
        Command::new("docker").args(["image", "inspect", "--format", "{{.Id}}", reference]),
        DOCKER_QUICK,
        8192,
        None,
    )
    .ok()?;
    if !o.success() {
        return None;
    }
    let t = o.stdout_lossy().trim().to_string();
    if t.is_empty() { None } else { Some(t) }
}

/// Resolve a lock entry to (reference, pinned, by_id). `exists` tells whether a ref is present locally.
pub(crate) fn resolve_entry(e: &LockEntry, exists: &dyn Fn(&str) -> bool) -> (String, bool, bool) {
    if let Some(id) = e.id.as_deref().filter(|i| i.starts_with("sha256:"))
        && exists(id)
    {
        return (id.to_string(), true, true);
    }
    let (r, p) = ref_with_digest(&e.image, &e.digest);
    (r, p, false)
}

/// (reference, pinned, run-by-id) for a tool.
pub(crate) fn image_ref(tool: &str) -> (String, bool, bool) {
    let lock = load_lock();
    match lock.tools.get(tool) {
        Some(e) => resolve_entry(e, &|r| local_image_id(r).is_some()),
        None => (tool.to_string(), false, false),
    }
}

/// Image reference for a tool (the local image ID when the lock has one and it is loaded,
/// else repo@digest when pinned) and whether it is pinned.
pub fn image_for(tool: &str) -> (String, bool) {
    let r = image_ref(tool);
    (r.0, r.1)
}

/// True when the tool's image is available locally (by ID or by reference).
pub fn image_present(tool: &str) -> bool {
    let lock = load_lock();
    match lock.tools.get(tool) {
        Some(e) => {
            e.id.as_deref()
                .map(|i| local_image_id(i).is_some())
                .unwrap_or(false)
                || local_image_id(&ref_with_digest(&e.image, &e.digest).0).is_some()
                || local_image_id(&e.image).is_some()
        }
        None => local_image_id(tool).is_some(),
    }
}

/// Skipped result when the tool's image is not available locally and we cannot pull (offline).
pub(crate) fn missing_image(tool: &str) -> Option<crate::model::CheckOutput> {
    if crate::bundle::offline() && !image_present(tool) {
        return Some(crate::model::CheckOutput::status(
            crate::model::CheckStatus::Skipped(format!("image not in bundle: {tool}")),
        ));
    }
    None
}

/// Add a free-form warning to the set the engine surfaces next to pin warnings.
pub fn add_warning(w: String) {
    if let Ok(mut g) = PIN_WARNINGS.lock() {
        g.insert(w);
    }
}

pub(crate) fn ref_with_digest(image: &str, digest: &str) -> (String, bool) {
    if digest.starts_with("sha256:") {
        let slash = image.rfind('/').map(|i| i + 1).unwrap_or(0);
        let repo = match image[slash..].find(':') {
            Some(i) => &image[..slash + i],
            None => image,
        };
        (format!("{repo}@{digest}"), true)
    } else {
        (image.to_string(), image.contains("@sha256:"))
    }
}

static PIN_WARNINGS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

pub(crate) fn warn_unpinned(tool: &str, image: &str) {
    if let Ok(mut g) = PIN_WARNINGS.lock() {
        g.insert(format!(
            "tool image {tool} unpinned ({image}) — run `readyhai tools pull --lock`"
        ));
    }
}

/// Warnings about images that ran without a digest pin; the engine surfaces these.
pub fn pin_warnings() -> Vec<String> {
    PIN_WARNINGS
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default()
}

/// `readyhai tools pull [--lock]`
pub fn tools_pull(write_lock: Option<&Path>) -> Result<()> {
    tools_pull_filtered(write_lock, None)
}

/// Like `tools_pull`, restricted to the named tools (the rest of the lock is kept as-is).
pub fn tools_pull_filtered(
    write_lock: Option<&Path>,
    only: Option<&BTreeSet<String>>,
) -> Result<()> {
    if crate::bundle::offline() {
        bail!("offline mode: use `readyhai bundle import`");
    }
    let mut lock = load_lock();
    for (name, e) in lock.tools.iter_mut() {
        if only.is_some_and(|o| !o.contains(name)) {
            continue;
        }
        eprintln!("pulling {name}: {}", e.image);
        let mut attempts = 0;
        let max_attempts = 3;
        let mut success = false;
        while attempts < max_attempts {
            attempts += 1;
            match Command::new("docker").args(["pull", &e.image]).status() {
                Ok(st) if st.success() => {
                    success = true;
                    break;
                }
                Ok(_) => {
                    eprintln!("  pull failed for {} (attempt {attempts}/{max_attempts})", e.image);
                    if attempts < max_attempts {
                        std::thread::sleep(Duration::from_millis(1000 * (1 << (attempts - 1))));
                    }
                }
                Err(err) => {
                    eprintln!("  docker pull error for {}: {err} (attempt {attempts}/{max_attempts})", e.image);
                    if attempts == max_attempts {
                        return Err(err).context("docker pull");
                    }
                    std::thread::sleep(Duration::from_millis(1000 * (1 << (attempts - 1))));
                }
            }
        }
        if !success {
            eprintln!("  all pull attempts failed for {}", e.image);
            if write_lock.is_some() {
                e.id = local_image_id(&e.image);
            }
            continue;
        }
        if write_lock.is_some() {
            let o = Command::new("docker")
                .args([
                    "image",
                    "inspect",
                    "--format",
                    "{{index .RepoDigests 0}}",
                    &e.image,
                ])
                .output()?;
            let t = String::from_utf8_lossy(&o.stdout);
            if let Some((_, d)) = t.trim().split_once('@') {
                e.digest = d.to_string();
            }
            e.id = local_image_id(&e.image);
        }
    }
    if let Some(p) = write_lock {
        let body = toml::to_string_pretty(&lock)?;
        std::fs::write(
            p,
            format!(
                "# Pinned tool images (digests written by `readyhai tools pull --lock`).\n{body}"
            ),
        )?;
        eprintln!("wrote {}", p.display());
    }
    Ok(())
}

/// `readyhai tools update` — the only networked step: vuln DBs + rule packs into cache.
pub fn tools_update(docker: &Docker) -> Result<()> {
    if crate::bundle::offline() {
        bail!("offline mode: use `readyhai bundle import`");
    }
    mkdir_open(&docker.cache_dir);
    mkdir_open(&docker.cache_dir.join("grype"));
    mkdir_open(&docker.cache_dir.join("semgrep"));
    mkdir_open(&docker.cache_dir.join("opengrep"));
    mkdir_open(&docker.cache_dir.join("osv-scanner"));
    mkdir_open(&docker.cache_dir.join("nuclei"));
    if docker.available {
        let mut spec = ToolSpec::new("grype", &["db", "update"]);
        spec.timeout_secs = 3600; // slow links: the DB is a ~100 MB+ download
        spec.network = true;
        spec.cache_rw = true;
        spec.env = vec![
            ("GRYPE_DB_CACHE_DIR".into(), "/cache/grype".into()),
            ("GRYPE_CHECK_FOR_APP_UPDATE".into(), "false".into()),
        ];
        let mounts = [Mount {
            host: docker.cache_dir.clone(),
            dst: "/cache",
            rw: true,
        }];
        let r = exec(docker, "update", &mounts, &spec)?;
        if r.exit_code != 0 {
            bail!("grype db update failed: {}", r.stderr_tail.trim());
        }
        eprintln!("grype DB updated");
        match osv_db_update(docker) {
            Ok(()) => eprintln!("osv-scanner offline DBs updated"),
            Err(e) => eprintln!(
                "osv-scanner DB update failed (tool.osv_reachability will be skipped): {e:#}"
            ),
        }
        match nuclei_templates_update(docker) {
            Ok(()) => eprintln!("nuclei templates updated"),
            Err(e) => eprintln!(
                "nuclei templates update failed (tool.nuclei will fall back to runtime download if networked): {e:#}"
            ),
        }
    } else {
        eprintln!("docker not available: skipping grype DB update");
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(180))
        .user_agent("readyhai")
        .build()?;
    let resp = client
        .get("https://semgrep.dev/c/p/default")
        .send()?
        .error_for_status()?;
    let body = resp.text()?;
    if body.trim().is_empty() {
        bail!("empty semgrep ruleset");
    }
    std::fs::write(docker.cache_dir.join("semgrep").join("default.yml"), &body)?;
    std::fs::write(docker.cache_dir.join("opengrep").join("default.yml"), &body)?;
    eprintln!("semgrep & opengrep rules updated");
    match crate::host::fetch_lynis(&docker.cache_dir) {
        Ok(()) => eprintln!("lynis tarball cached (checksum recorded, upstream publishes none)"),
        Err(e) => eprintln!("lynis fetch failed (host.lynis will be skipped): {e:#}"),
    }
    Ok(())
}

/// Populate `<cache>/osv-scanner` for `tool.osv_reachability`: scanning a tiny seed project with
/// `--download-offline-databases` makes osv-scanner fetch the per-ecosystem DB zips it needs.
fn osv_db_update(docker: &Docker) -> Result<()> {
    let seed = docker.cache_dir.join("osv-seed");
    mkdir_open(&seed);
    let files: [(&str, &str); 4] = [
        (
            "go.mod",
            "module seed\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.7\n",
        ),
        ("requirements.txt", "requests==2.0.0\n"),
        (
            "package-lock.json",
            r#"{"name":"seed","lockfileVersion":3,"requires":true,"packages":{"":{"name":"seed","dependencies":{"minimist":"1.2.0"}},"node_modules/minimist":{"version":"1.2.0"}}}"#,
        ),
        (
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"time\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        ),
    ];
    for (n, c) in files {
        std::fs::write(seed.join(n), c)?;
    }
    let mut spec = ToolSpec::new(
        "osv-scanner",
        &[
            "scan",
            "source",
            "--download-offline-databases",
            "--offline-vulnerabilities",
            "--no-call-analysis",
            "go",
            "--format",
            "json",
            "--output-file",
            "/tmp/osv-seed.json",
            "-r",
            "/cache/osv-seed",
        ],
    );
    spec.timeout_secs = 3600;
    spec.network = true;
    spec.cache_rw = true;
    spec.env = vec![(
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY".into(),
        "/cache/osv-scanner".into(),
    )];
    let mounts = [Mount {
        host: docker.cache_dir.clone(),
        dst: "/cache",
        rw: true,
    }];
    let r = exec(docker, "update", &mounts, &spec)?;
    // Exit 1 = vulnerabilities found (expected for the seed); anything else is a real failure.
    if r.exit_code > 1 {
        bail!("{}", r.stderr_tail.trim());
    }
    Ok(())
}

/// Populate `<cache>/nuclei` for offline/fast `tool.nuclei` scans.
fn nuclei_templates_update(docker: &Docker) -> Result<()> {
    let mut spec = ToolSpec::new(
        "nuclei",
        &["-update-templates", "-ud", "/cache/nuclei", "-silent"],
    );
    spec.timeout_secs = 1800;
    spec.network = true;
    spec.cache_rw = true;
    spec.tmpfs = vec![
        "/tmp:rw,mode=1777".into(),
        "/home/nuclei:rw,mode=1777".into(),
    ];
    spec.env = vec![("HOME".into(), "/home/nuclei".into())];
    let mounts = [Mount {
        host: docker.cache_dir.clone(),
        dst: "/cache",
        rw: true,
    }];
    let r = exec(docker, "update", &mounts, &spec)?;
    if r.exit_code != 0 {
        bail!("{}", r.stderr_tail.trim());
    }
    Ok(())
}
