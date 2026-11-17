//! Report renderers (HTML, Markdown, SARIF, JUnit, JSON). Every piece of target- or LLM-derived
//! text is escaped for the format it lands in; nothing is invented when data is missing:
//! absent values render as "not evaluated" / "not detected".

pub mod helpers;
pub mod html;
pub mod html_sections;
pub mod junit;
pub mod markdown;
pub mod markdown_sections;
pub mod sarif;

use std::path::{Path, PathBuf};
use anyhow::Result;

use crate::agent::types::AgentRunReport;

#[allow(unused_imports)]
pub use helpers::{html_escape, md_code, md_fence, md_text, xml_escape};
pub use html::generate_agent_html_report;
pub use junit::generate_agent_junit_report;
pub use markdown::generate_agent_markdown_report;
pub use sarif::generate_agent_sarif_report;

pub fn generate_agent_report_formats(
    rep: &AgentRunReport,
    dir: &Path,
    formats: &[String],
) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut out = vec![];
    for f in formats {
        let (name, body) = match f.as_str() {
            "html" => ("readyhai-report.html", generate_agent_html_report(rep)),
            "json" => ("readyhai-report.json", serde_json::to_string_pretty(rep)?),
            "markdown" | "md" => ("readyhai-report.md", generate_agent_markdown_report(rep)),
            "sarif" => (
                "readyhai-report.sarif",
                serde_json::to_string_pretty(&generate_agent_sarif_report(rep))?,
            ),
            "junit" | "xml" => (
                "readyhai-report.junit.xml",
                generate_agent_junit_report(rep),
            ),
            _ => continue,
        };
        let p = dir.join(name);
        crate::llm::write_atomic(&p, body.as_bytes())?;
        out.push(p);
    }
    Ok(out)
}
