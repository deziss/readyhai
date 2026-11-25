//! Docker Compose hardening and configuration auditing.

use super::dockerfile::{has_healthcheck, parse_stages};
use super::facts::{Skips, base, dir, normalize, read, read_checked};
use super::{na, non_empty_map, path, truthy};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Finding, Severity};
use crate::snapshot::Snapshot;
use regex::Regex;
use serde_norway::Value;

pub(crate) fn test_string(v: &Value) -> String {
    match v.as_sequence() {
        Some(s) => s
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        None => v.as_str().unwrap_or("").to_string(),
    }
}

/// True when the service's `build:` Dockerfile (context + dockerfile) or, for `image:` services, a
/// repo Dockerfile in a directory named like the image, defines a HEALTHCHECK.
pub(crate) fn image_dockerfile_has_healthcheck(
    ctx: &Ctx,
    snap: &Snapshot,
    svc: &Value,
    file: &str,
) -> bool {
    let hc = |p: &str| {
        read(snap, p).is_some_and(|t| parse_stages(&t).last().is_some_and(has_healthcheck))
    };
    if let Some(build) = svc.get("build") {
        let ctxdir = build
            .as_str()
            .or_else(|| build.get("context").and_then(Value::as_str))
            .unwrap_or(".");
        let dfname = build
            .get("dockerfile")
            .and_then(Value::as_str)
            .unwrap_or("Dockerfile");
        let ctx_path = normalize(&format!("{}/{ctxdir}", dir(file)));
        return hc(&normalize(&format!("{ctx_path}/{dfname}")));
    }
    let Some(img) = svc.get("image").and_then(Value::as_str) else {
        return false;
    };
    let name = img
        .rsplit('/')
        .next()
        .unwrap_or(img)
        .split([':', '@'])
        .next()
        .unwrap_or("");
    !name.is_empty()
        && ctx
            .facts
            .dockerfiles
            .iter()
            .any(|d| base(dir(d)) == name && hc(d))
}

pub(crate) fn compose_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.compose";
    if ctx.facts.compose_files.is_empty() {
        return na("no compose file");
    }
    let url_re = Regex::new(r#"https?://[^/\s'"]+(/[^\s'"]*)?"#).unwrap();
    let mut out = vec![];
    let mut skips = Skips::default();
    for file in &ctx.facts.compose_files {
        let text = match read_checked(snap, file) {
            Ok(t) => t,
            Err(why) => {
                skips.add(file, why);
                continue;
            }
        };
        let mut root = match serde_norway::from_str::<Value>(&text) {
            Ok(r) => r,
            Err(e) => {
                skips.add(file, format!("YAML parse error: {e}"));
                continue;
            }
        };
        root.apply_merge().ok();
        let Some(services) = root.get("services").and_then(Value::as_mapping) else {
            continue;
        };
        for (k, svc) in services {
            let name = k.as_str().unwrap_or("?");
            if name.starts_with("x-") || !svc.is_mapping() {
                continue;
            }
            let mk = |r: &str, cat, sev, what: &str| {
                Finding::new(
                    C,
                    &format!("{C}.{r}"),
                    cat,
                    sev,
                    format!("Service `{name}`: {what}"),
                    file.clone(),
                )
                .fp_key(format!("{file}:{name}"))
            };
            if truthy(svc.get("privileged")) {
                out.push(
                    mk(
                        "privileged",
                        Category::Security,
                        Severity::High,
                        "privileged: true",
                    )
                    .remediation("Drop `privileged`; grant only the specific capabilities needed."),
                );
            }
            let sock = svc
                .get("volumes")
                .and_then(Value::as_sequence)
                .is_some_and(|v| {
                    v.iter().any(|e| {
                        e.as_str().is_some_and(|s| s.contains("docker.sock"))
                            || e.get("source")
                                .and_then(Value::as_str)
                                .is_some_and(|s| s.contains("docker.sock"))
                    })
                });
            if sock {
                out.push(
                    mk(
                        "docker_sock",
                        Category::Security,
                        Severity::High,
                        "mounts the Docker socket",
                    )
                    .remediation(
                        "Avoid mounting /var/run/docker.sock; it grants root on the host.",
                    ),
                );
            }
            if svc.get("network_mode").and_then(Value::as_str) == Some("host") {
                out.push(mk(
                    "host_network",
                    Category::Security,
                    Severity::Medium,
                    "network_mode: host",
                ));
            }
            let hc = svc.get("healthcheck");
            let test = match hc {
                None => None,
                Some(h) if truthy(h.get("disable")) => None,
                Some(h) => Some(h.get("test").map(test_string).unwrap_or_default()),
            }
            .filter(|t| !t.trim_start().starts_with("NONE"));
            let image_hc = test.is_none() && image_dockerfile_has_healthcheck(ctx, snap, svc, file);
            match test {
                None if image_hc => {}
                None => out.push(
                    mk(
                        "no_healthcheck",
                        Category::Reliability,
                        Severity::Medium,
                        "no healthcheck",
                    )
                    .remediation("Add a healthcheck pointing at a real readiness endpoint."),
                ),
                Some(t) if !t.is_empty() => {
                    let paths: Vec<String> = url_re
                        .captures_iter(&t)
                        .map(|c| {
                            c.get(1)
                                .map_or("/", |m| m.as_str())
                                .split('?')
                                .next()
                                .unwrap_or("/")
                                .to_string()
                        })
                        .collect();
                    if !paths.is_empty() && paths.iter().all(|p| p == "/") {
                        out.push(
                            mk(
                                "healthcheck_root_path",
                                Category::Reliability,
                                Severity::Low,
                                "healthcheck only probes `/`",
                            )
                            .remediation(
                                "Probe a dedicated /health endpoint that checks dependencies.",
                            ),
                        );
                    }
                    let tl = t.to_lowercase();
                    let used: Vec<&str> = ["curl", "wget"]
                        .into_iter()
                        .filter(|b| tl.contains(b))
                        .collect();
                    if !used.is_empty() {
                        let build = svc.get("build");
                        let ctxdir = build
                            .and_then(|b| {
                                b.as_str()
                                    .or_else(|| b.get("context").and_then(Value::as_str))
                            })
                            .unwrap_or(".");
                        let dfname = build
                            .and_then(|b| b.get("dockerfile"))
                            .and_then(Value::as_str)
                            .unwrap_or("Dockerfile");
                        let dpath = normalize(&format!("{}/{ctxdir}/{dfname}", dir(file)));
                        if build.is_some()
                            && let Some(dt) = read(snap, &dpath)
                        {
                            let stages = parse_stages(&dt);
                            let img = stages
                                .last()
                                .map(|s| s.image.to_lowercase())
                                .unwrap_or_default();
                            let slim = img.contains("slim")
                                || img.contains("alpine")
                                || img.contains("distroless");
                            let dl = dt.to_lowercase();
                            let missing: Vec<&str> = used
                                .iter()
                                .copied()
                                .filter(|b| {
                                    !dl.contains(b) && !(*b == "wget" && img.contains("alpine"))
                                })
                                .collect();
                            if slim && !missing.is_empty() {
                                out.push(
                                        mk("healthcheck_missing_binary", Category::Reliability, Severity::Medium, &format!("healthcheck uses {} but base image `{img}` does not ship it", missing.join("/")))
                                            .detail(format!("Dockerfile {dpath} never installs it, so the container will report unhealthy."))
                                            .remediation("Install the binary in the image or use a language-native healthcheck (python -c / node -e)."),
                                    );
                            }
                        }
                    }
                }
                _ => {}
            }
            let limits = non_empty_map(path(svc, &["deploy", "resources", "limits"]))
                || svc.get("mem_limit").is_some()
                || svc.get("cpus").is_some();
            if !limits {
                out.push(
                    mk(
                        "no_limits",
                        Category::Reliability,
                        Severity::Low,
                        "no CPU/memory limits",
                    )
                    .remediation("Set deploy.resources.limits or mem_limit/cpus."),
                );
            }
            if svc.get("restart").is_none() && path(svc, &["deploy", "restart_policy"]).is_none() {
                out.push(
                    mk(
                        "no_restart",
                        Category::Reliability,
                        Severity::Low,
                        "no restart policy",
                    )
                    .remediation("Set `restart: unless-stopped` (or on-failure)."),
                );
            }
        }
    }
    skips.finish(out)
}
