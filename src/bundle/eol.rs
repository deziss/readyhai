//! End-of-life catalog parsing and upstream synchronization.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::engine;

pub const EMBEDDED_EOL: &str = include_str!("../../data/endoflife.json");
pub const EOL_PRODUCTS: [&str; 10] = [
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

pub fn cache_eol_path() -> PathBuf {
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

pub fn fetch_endoflife(dest: &Path) -> Result<()> {
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
