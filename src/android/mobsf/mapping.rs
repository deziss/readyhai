//! MobSF report scrubbing and finding mapping.
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::android::util::{redact, slug, vs};
use crate::model::{Category, Finding, Severity};

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
