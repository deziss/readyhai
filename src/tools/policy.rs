use super::docker::Docker;
use super::types::MountMode;
use anyhow::{Result, anyhow, bail};
use std::path::{Path, PathBuf};

pub(crate) struct Mount {
    pub(crate) host: PathBuf,
    pub(crate) dst: &'static str,
    pub(crate) rw: bool,
}

pub(crate) const ALLOWED_DST: [&str; 3] = ["/src", "/out", "/cache"];

/// Defense in depth over the docker flag list (everything before the image).
pub fn validate_create_policy(args: &[String]) -> Result<()> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = args.get(i + 1).map(|s| s.as_str()).unwrap_or("");
        if a.contains("docker.sock") {
            bail!("create-policy: docker socket mount rejected");
        }
        match a {
            "--privileged" | "--privileged=true" => bail!("create-policy: --privileged rejected"),
            "--network" | "--net" | "--pid" | "--ipc" | "--userns" | "--uts" if next == "host" => {
                bail!("create-policy: host namespace rejected")
            }
            "--network=host" | "--net=host" | "--pid=host" | "--ipc=host" | "--userns=host" => {
                bail!("create-policy: host namespace rejected")
            }
            "--cap-add" => bail!("create-policy: --cap-add rejected"),
            "-v" | "--volume" => {
                let dst = next.split(':').nth(1).unwrap_or("");
                if !ALLOWED_DST.contains(&dst) {
                    bail!("create-policy: extra bind mount rejected: {next}");
                }
                i += 1;
            }
            "--mount" => {
                let dst = next
                    .split(',')
                    .find_map(|kv| {
                        kv.strip_prefix("dst=")
                            .or_else(|| kv.strip_prefix("target="))
                    })
                    .unwrap_or("");
                if !ALLOWED_DST.contains(&dst) {
                    bail!("create-policy: extra mount rejected: {next}");
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

pub(crate) fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub(crate) fn abs(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

pub(crate) fn mount_args(docker: &Docker, m: &Mount) -> Result<Vec<String>> {
    let host = abs(&m.host);
    match &docker.mode {
        MountMode::Bind => Ok(vec![
            "-v".into(),
            format!(
                "{}:{}:{}",
                host.display(),
                m.dst,
                if m.rw { "rw" } else { "ro" }
            ),
        ]),
        MountMode::Volume { name, data_root } => {
            let root = abs(data_root);
            let rel = host.strip_prefix(&root).map_err(|_| {
                anyhow!(
                    "{} is outside the data volume {}",
                    host.display(),
                    root.display()
                )
            })?;
            let mut s = format!(
                "type=volume,src={name},dst={},volume-subpath={}",
                m.dst,
                rel.to_string_lossy()
            );
            if !m.rw {
                s.push_str(",readonly");
            }
            Ok(vec!["--mount".into(), s])
        }
    }
}
