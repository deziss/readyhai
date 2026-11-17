//! CycloneDX 1.5 SBOM synthesis from Linux package inventories.
use serde_json::{Value, json};

use super::common::gs;

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Minimal CycloneDX 1.5 SBOM from the Linux package inventory (None if no packages).
pub fn sbom_from_probe(v: &Value) -> Option<Value> {
    let pk = v["packages"].as_array()?;
    if pk.is_empty() {
        return None;
    }
    let id = gs(v, &["os", "id"]).to_ascii_lowercase();
    let ver = gs(v, &["os", "version"]);
    let (typ, ns) = match id.as_str() {
        "ubuntu" | "debian" | "raspbian" | "kali" | "linuxmint" | "pop" => {
            ("deb", if id == "ubuntu" { "ubuntu" } else { "debian" })
        }
        "alpine" => ("apk", "alpine"),
        "" => return None,
        other => ("rpm", other),
    };
    let distro = if ver.is_empty() {
        id.clone()
    } else {
        format!("{id}-{ver}")
    };
    let mut comps: Vec<Value> = vec![json!({"type":"operating-system","name":id,"version":ver})];
    for p in pk {
        let (n, vr) = (
            p["name"].as_str().unwrap_or(""),
            p["version"].as_str().unwrap_or(""),
        );
        if n.is_empty() {
            continue;
        }
        comps.push(json!({
            "type": "library", "name": n, "version": vr,
            "purl": format!("pkg:{typ}/{ns}/{}@{}?distro={}", pct(n), pct(vr), pct(&distro)),
        }));
    }
    Some(json!({"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":comps}))
}
