//! Sibling guard mining for idiomatic authentication middleware inference.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Result;

/// Sibling guard mining: inspects source files to find which authentication middleware is standard.
pub fn mine_sibling_guards(repo: &Path) -> Vec<String> {
    let mut guard_counts: BTreeMap<String, usize> = BTreeMap::new();
    let re_express = regex::Regex::new(
        r#"(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"][^'"]+['"]\s*,\s*([a-zA-Z0-9_$]+)\s*,"#,
    )
    .ok();

    if let Ok(entries) = walkdir::WalkDir::new(repo)
        .max_depth(4)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "ts" | "mjs" | "cjs") {
                continue;
            }
            if let Ok(content) = fs::read_to_string(path)
                && let Some(re) = &re_express
            {
                for cap in re.captures_iter(&content) {
                    if let Some(guard) = cap.get(1) {
                        let g = guard.as_str().to_string();
                        if !matches!(g.as_str(), "req" | "res" | "next" | "handler") {
                            *guard_counts.entry(g).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    let mut sorted: Vec<(String, usize)> = guard_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.into_iter().map(|(g, _)| g).collect()
}
