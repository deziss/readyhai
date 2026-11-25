use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};

use super::exporters::{gitlab_json, jira_csv, testrail_csv, xray_csv};
use super::html::qa_html;
use super::markdown::markdown;
use crate::model::Run;

pub const QA_FORMATS: &[&str] = &["qa", "pdf", "md", "jira", "gitlab", "testrail", "xray"];

/// Write the QA-specific formats. Returns the files written.
pub fn write_formats(run: &Run, dir: &Path, formats: &[String]) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut out = vec![];
    let want_html = formats
        .iter()
        .any(|f| matches!(f.as_str(), "qa" | "html" | "pdf"));
    let mut html_done = false;
    for f in formats {
        if !QA_FORMATS.contains(&f.as_str()) && f != "html" {
            continue;
        }
        let is_qa_fmt = QA_FORMATS.contains(&f.as_str());
        let Some(q) = &run.qa else {
            if is_qa_fmt {
                eprintln!("note: format '{f}' needs a QA run (readyhai qa); skipped");
            }
            continue;
        };
        let (name, body): (&str, String) = match f.as_str() {
            "qa" | "html" | "pdf" => {
                if html_done || !want_html {
                    continue;
                }
                html_done = true;
                ("qa-report.html", qa_html(run, Some(dir))?)
            }
            "md" => ("qa-report.md", markdown(run)?),
            "jira" => ("defects.jira.csv", jira_csv(q)),
            "gitlab" => (
                "defects.gitlab.json",
                serde_json::to_string_pretty(&gitlab_json(q))?,
            ),
            "testrail" => ("testcases.testrail.csv", testrail_csv(q)),
            "xray" => ("testcases.xray.csv", xray_csv(q)),
            _ => continue,
        };
        let p = dir.join(name);
        std::fs::write(&p, body)?;
        out.push(p);
    }
    if formats.iter().any(|f| f == "pdf") && run.qa.is_some() {
        if !html_done {
            let p = dir.join("qa-report.html");
            std::fs::write(&p, qa_html(run, Some(dir))?)?;
            out.push(p);
        }
        match render_pdf(dir) {
            Ok(p) => out.push(p),
            Err(e) => eprintln!("note: PDF not rendered ({e}); qa-report.html is complete"),
        }
    }
    Ok(out)
}

pub fn owner_user(dir: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::metadata(dir) {
            return format!("{}:{}", m.uid(), m.gid());
        }
    }
    let _ = dir;
    "65534:65534".into()
}

/// Render dir/qa-report.html to dir/qa-report.pdf with the playwright runner image (offline, read-only).
pub fn render_pdf(dir: &Path) -> Result<PathBuf> {
    use std::process::{Command, Stdio};
    let image = crate::qa::ui::playwright_image();
    let dir = std::fs::canonicalize(dir)?;
    let o = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,mode=1777",
            "--user",
        ])
        // The output dir belongs to the invoking user; 65534 could not write the PDF there.
        .arg(owner_user(&dir))
        .arg("-v")
        .arg(format!("{}:/out", dir.display()))
        .arg(&image)
        .args([
            "node",
            "/runner/pdf.mjs",
            "/out/qa-report.html",
            "/out/qa-report.pdf",
        ])
        .stdin(Stdio::null())
        .output()?;
    let p = dir.join("qa-report.pdf");
    if !o.status.success() || !p.is_file() {
        return Err(anyhow!(
            "docker run failed: {}",
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .last()
                .unwrap_or("")
        ));
    }
    Ok(p)
}
