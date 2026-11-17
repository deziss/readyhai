//! MobSF container management via Docker.
use anyhow::{Result, anyhow, bail};
use std::process::{Command, Stdio};

use crate::android::util::{rand_hex, run_cmd};
use crate::ctx::Ctx;

pub(crate) struct MobsfContainer {
    pub(crate) name: String,
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

pub(crate) fn start_mobsf(ctx: &Ctx, key: &str) -> Result<(MobsfContainer, u16)> {
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
