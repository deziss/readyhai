//! Kubernetes manifest hardening and security checks.

use super::dockerfile::image_untagged;
use super::facts::{Skips, k8s_docs_checked, read_checked};
use super::{na, non_empty_map, path, str_of, truthy};
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Finding, Severity};
use crate::snapshot::Snapshot;
use serde_norway::Value;

pub(crate) fn pod_spec<'a>(kind: &str, v: &'a Value) -> Option<&'a Value> {
    match kind {
        "Deployment" | "StatefulSet" | "DaemonSet" | "Job" => {
            path(v, &["spec", "template", "spec"])
        }
        "CronJob" => path(v, &["spec", "jobTemplate", "spec", "template", "spec"]),
        _ => None,
    }
}

pub(crate) fn non_root(sc: Option<&Value>) -> bool {
    sc.is_some_and(|s| {
        truthy(s.get("runAsNonRoot"))
            || s.get("runAsUser")
                .and_then(Value::as_u64)
                .is_some_and(|u| u != 0)
    })
}

pub(crate) fn k8s_check(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.k8s";
    if ctx.facts.k8s_files.is_empty() {
        return na("no Kubernetes manifests");
    }
    let mut out = vec![];
    let mut skips = Skips::default();
    for file in &ctx.facts.k8s_files {
        let text = match read_checked(snap, file) {
            Ok(t) => t,
            Err(why) => {
                skips.add(file, why);
                continue;
            }
        };
        // Low-severity, highly repetitive rules: one finding per file listing the objects.
        let mut grouped: std::collections::BTreeMap<&'static str, Vec<String>> = Default::default();
        // a document that does not parse is named, and the documents after it are still checked
        let (docs, doc_errors) = k8s_docs_checked(&text);
        for e in doc_errors {
            skips.add(file, e);
        }
        for doc in docs {
            let kind = str_of(doc.get("kind"));
            let name = str_of(path(&doc, &["metadata", "name"]));
            if kind == "Secret"
                && (non_empty_map(doc.get("data")) || non_empty_map(doc.get("stringData")))
            {
                out.push(
                    Finding::new(
                        C,
                        &format!("{C}.plaintext_secret"),
                        Category::Security,
                        Severity::High,
                        format!("Plaintext Secret manifest committed: {name}"),
                        file.clone(),
                    )
                    .fp_key(format!("{file}:{name}"))
                    .remediation(
                        "Use sealed-secrets / external-secrets / SOPS; rotate the exposed values.",
                    ),
                );
                continue;
            }
            let Some(pod) = pod_spec(kind, &doc) else {
                continue;
            };
            let obj = format!("{kind}/{name}");
            let mk = |r: &str, cat, sev, what: &str, id: &str| {
                Finding::new(
                    C,
                    &format!("{C}.{r}"),
                    cat,
                    sev,
                    format!("{id}: {what}"),
                    file.clone(),
                )
                .fp_key(format!("{file}:{id}"))
            };
            if truthy(pod.get("hostNetwork")) {
                out.push(mk(
                    "host_network",
                    Category::Security,
                    Severity::Medium,
                    "hostNetwork: true",
                    &obj,
                ));
            }
            let probes_expected = matches!(kind, "Deployment" | "StatefulSet");
            for c in pod
                .get("containers")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
            {
                let id = format!("{obj}/{}", str_of(c.get("name")));
                if truthy(path(c, &["securityContext", "privileged"])) {
                    out.push(
                        mk(
                            "privileged",
                            Category::Security,
                            Severity::High,
                            "privileged container",
                            &id,
                        )
                        .remediation("Remove privileged: true; add only required capabilities."),
                    );
                }
                if probes_expected {
                    let miss: Vec<&str> = ["readinessProbe", "livenessProbe"]
                        .into_iter()
                        .filter(|p| c.get(*p).is_none())
                        .collect();
                    if !miss.is_empty() {
                        out.push(
                            mk(
                                "no_probes",
                                Category::Reliability,
                                Severity::Medium,
                                &format!("missing {}", miss.join(" and ")),
                                &id,
                            )
                            .remediation(
                                "Add readiness and liveness probes against a health endpoint.",
                            ),
                        );
                    }
                }
                for p in ["readinessProbe", "livenessProbe"] {
                    if path(c, &[p, "httpGet", "path"]).and_then(Value::as_str) == Some("/") {
                        grouped
                            .entry("probe_root_path")
                            .or_default()
                            .push(format!("{id} ({p})"));
                    }
                }
                if !non_empty_map(path(c, &["resources", "limits"])) {
                    out.push(
                        mk(
                            "no_limits",
                            Category::Reliability,
                            Severity::Medium,
                            "no resource limits",
                            &id,
                        )
                        .remediation("Set resources.limits (cpu, memory)."),
                    );
                }
                if !non_root(pod.get("securityContext")) && !non_root(c.get("securityContext")) {
                    grouped.entry("run_as_root").or_default().push(id.clone());
                }
                if let Some(img) = c.get("image").and_then(Value::as_str)
                    && !img.contains('$')
                    && !img.contains('{')
                    && image_untagged(img)
                {
                    grouped
                        .entry("latest_image")
                        .or_default()
                        .push(format!("{id} ({img})"));
                }
            }
        }
        for (rule, ids) in grouped {
            let (cat, what, fix) = match rule {
                "probe_root_path" => (
                    Category::Reliability,
                    "probes only `/`",
                    "Point probes at a real health endpoint (/health, /ready).",
                ),
                "run_as_root" => (
                    Category::Security,
                    "may run as root (no runAsNonRoot / runAsUser)",
                    "Set securityContext.runAsNonRoot: true.",
                ),
                _ => (
                    Category::SupplyChain,
                    "image untagged or :latest",
                    "Pin images by version tag or digest.",
                ),
            };
            out.push(
                Finding::new(
                    C,
                    &format!("{C}.{rule}"),
                    cat,
                    Severity::Low,
                    format!("{} container(s) {what}", ids.len()),
                    file.clone(),
                )
                .detail(ids.join("\n"))
                .remediation(fix)
                .fp_key(file.clone()),
            );
        }
    }
    skips.finish(out)
}
