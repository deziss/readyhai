use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::models::Retriever;
use crate::agent::types::ChangedOperation;
use crate::llm::untrusted::{clean, clean_output};

const RETRIEVER_OUTPUT_CAP: usize = 64 * 1024;
const MAX_CONTEXT_NOTES: usize = 5;

fn is_index(dir: &Path) -> bool {
    dir.join("manifest.json").is_file() && dir.join("chunks.jsonl").is_file()
}

/// The runner's checkout: `$READYHAI_HOME`, the working directory, or a parent of the executable.
fn runners_root() -> Option<PathBuf> {
    let has = |d: &Path| d.join("runners/context_retriever/main.py").is_file();
    if let Ok(h) = std::env::var("READYHAI_HOME") {
        let h = PathBuf::from(h);
        if has(&h) {
            return Some(h);
        }
    }
    if let Ok(cwd) = std::env::current_dir()
        && has(&cwd)
    {
        return Some(cwd);
    }
    let exe = std::env::current_exe().ok()?;
    exe.ancestors()
        .skip(1)
        .take(5)
        .find(|d| has(d))
        .map(PathBuf::from)
}

/// The retriever for `repo`, or the reason there is none. An index is looked for in
/// `$READYHAI_CONTEXT_INDEX`, then `<repo>/.readyhai/context-index`. The command is
/// `$READYHAI_CONTEXT_RETRIEVER` when set, else `python3 -m runners.context_retriever.main`.
pub fn retriever_from_env(repo: &Path) -> Result<Retriever, String> {
    let index = std::env::var("READYHAI_CONTEXT_INDEX")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .into_iter()
        .chain([repo.join(".readyhai/context-index")])
        .find(|d| is_index(d))
        .ok_or_else(|| "no context index for this repo".to_string())?;
    // the command runs in another directory: hand it an absolute path
    let index = index.canonicalize().unwrap_or(index);
    let secs = std::env::var("READYHAI_CONTEXT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
        .clamp(5, 300);
    let timeout = Duration::from_secs(secs);
    if let Some(cmd) = std::env::var("READYHAI_CONTEXT_RETRIEVER")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        return Ok(Retriever {
            index_dir: index,
            command: vec![cmd],
            cwd: None,
            timeout,
        });
    }
    let root = runners_root().ok_or_else(|| {
        "the context retriever runner (runners/context_retriever) was not found".to_string()
    })?;
    Ok(Retriever {
        index_dir: index,
        command: vec![
            "python3".into(),
            "-m".into(),
            "runners.context_retriever.main".into(),
        ],
        cwd: Some(root),
        timeout,
    })
}

/// Ask the retriever about the changed operations. Returns advisory notes (each prefixed, cleaned
/// and credential-redacted) or the reason nothing was added. The output is parsed as data only:
/// `{"evidence": [{"source", "summary"}], "synthesis": ...}`; whatever else it prints is dropped.
pub fn retrieve_context(r: &Retriever, ops: &[ChangedOperation]) -> Result<Vec<String>, String> {
    if ops.is_empty() {
        return Ok(vec![]);
    }
    let labels: Vec<String> = ops
        .iter()
        .take(8)
        .map(|o| clean(&o.operation, 80))
        .collect();
    let query = format!(
        "Handlers, input validation, authorization and error handling of: {}",
        labels.join(", ")
    );
    let (prog, lead) = r.command.split_first().ok_or("empty retriever command")?;
    let mut cmd = Command::new(prog);
    cmd.args(lead)
        .args([
            "query",
            "--no-llm",
            "--json",
            "--max-chunks",
            "6",
            "--index-dir",
        ])
        .arg(&r.index_dir)
        .arg("--query")
        .arg(&query);
    if let Some(d) = &r.cwd {
        cmd.current_dir(d);
    }
    // the retriever is a separate program: it gets no test credentials
    for (k, _) in std::env::vars().filter(|(k, _)| k.starts_with("RH_") && k.ends_with("_TOKEN")) {
        cmd.env_remove(k);
    }
    let out =
        crate::tools::run_capped(&mut cmd, r.timeout, RETRIEVER_OUTPUT_CAP, None).map_err(|e| {
            format!(
                "could not start the retriever: {}",
                clean(&e.to_string(), 120)
            )
        })?;
    if out.timed_out {
        return Err(format!(
            "the retriever timed out after {}s",
            r.timeout.as_secs()
        ));
    }
    if !out.success() {
        return Err(format!(
            "the retriever failed ({})",
            out.status
                .and_then(|s| s.code())
                .map(|c| format!("exit {c}"))
                .unwrap_or_else(|| "no exit code".into())
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| "the retriever did not print JSON".to_string())?;
    let mut notes = vec![];
    for e in v
        .get("evidence")
        .and_then(|e| e.as_array())
        .into_iter()
        .flatten()
        .take(MAX_CONTEXT_NOTES)
    {
        let src = clean_output(e.get("source").and_then(|s| s.as_str()).unwrap_or("?"), 80);
        let sum = clean_output(e.get("summary").and_then(|s| s.as_str()).unwrap_or(""), 240);
        if !sum.is_empty() {
            notes.push(format!("{src}: {sum}"));
        }
    }
    if let Some(s) = v.get("synthesis").and_then(|s| s.as_str()) {
        let s = clean_output(s, 400);
        if !s.is_empty() {
            notes.push(format!("hypothesis: {s}"));
        }
    }
    notes.truncate(MAX_CONTEXT_NOTES + 1);
    Ok(notes)
}
