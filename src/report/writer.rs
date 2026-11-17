//! Multi-format report dispatch and file system persistence.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::model::Run;

use super::html::html;
use super::junit::junit;
use super::pr::pr_comment;
use super::sarif::sarif;

pub fn write(run: &Run, dir: &Path, formats: &[String]) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut out = vec![];
    for f in formats {
        let (name, body) = match f.as_str() {
            "html" => ("readyhai-report.html", html(run)?),
            "json" => ("readyhai-report.json", serde_json::to_string_pretty(run)?),
            "sarif" => (
                "readyhai-report.sarif",
                serde_json::to_string_pretty(&sarif(run))?,
            ),
            "junit" => ("readyhai-report.junit.xml", junit(run)),
            "pr" => ("readyhai-pr-comment.md", pr_comment(run)),
            _ => continue,
        };
        let p = dir.join(name);
        std::fs::write(&p, body)?;
        out.push(p);
    }
    out.extend(crate::qa::report::write_formats(run, dir, formats)?);
    Ok(out)
}
