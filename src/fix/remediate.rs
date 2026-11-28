//! AST and pattern-grounded remediation synthesizer.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::diff::compute_unified_diff;
use super::types::{PatchRemediation, PatchStatus, TargetDefect};

fn box_str(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

/// AST & pattern-grounded remediation synthesizer for a defect.
pub fn synthesize_remediation(
    repo: &Path,
    defect: &TargetDefect,
    sibling_guards: &[String],
) -> Result<Option<PatchRemediation>> {
    let target_path = repo.join(&defect.file);
    // Repo-level findings (location "." or a directory) have no line to patch: skip them rather
    // than failing the whole run when the "file" turns out to be the repository directory.
    if !target_path.is_file() {
        return Ok(None);
    }
    let content = fs::read_to_string(&target_path)
        .with_context(|| format!("could not read {}", target_path.display()))?;
    let lines: Vec<&str> = content.lines().collect();

    if defect.line == 0 || defect.line > lines.len() {
        return Ok(None);
    }

    let line_idx = defect.line - 1;
    let target_line = lines[line_idx];

    let default_guard = sibling_guards
        .first()
        .cloned()
        .unwrap_or_else(|| "requireAuth".to_string());

    let mut patched_lines = lines.clone();
    let mut rationale = String::new();

    // 1. Missing Auth Guard
    if defect.rule.contains("auth.missing_guard")
        || defect.rule == "qa.api.auth"
        || defect.rule == "qa.api.bola"
    {
        let re_express = regex::Regex::new(
            r#"((?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"][^'"]+['"]\s*,)\s*([a-zA-Z0-9_$]+)"#,
        )?;
        if let Some(caps) = re_express.captures(target_line) {
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let handler = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let replacement = format!("{prefix} {default_guard}, {handler}");
            patched_lines[line_idx] =
                box_str(&target_line.replacen(&format!("{prefix} {handler}"), &replacement, 1));
            rationale = format!(
                "Injected `{default_guard}` middleware into route definition adhering to sibling endpoint security conventions."
            );
        } else if target_line.contains("@app.get(") || target_line.contains("@app.post(") {
            let patched = target_line.replace(")", ", dependencies=[Depends(get_current_user)])");
            patched_lines[line_idx] = box_str(&patched);
            rationale =
                "Injected `dependencies=[Depends(get_current_user)]` auth guard to FastAPI route decorator.".to_string();
        } else if target_line.contains("@app.route(") {
            let patched = format!("{target_line}\n@login_required");
            patched_lines[line_idx] = box_str(&patched);
            rationale = "Injected `@login_required` decorator to Flask route handler.".to_string();
        } else if target_line.contains("r.Get(") || target_line.contains("r.Post(") {
            let patched = target_line.replace("r.", "r.With(authMiddleware).");
            patched_lines[line_idx] = box_str(&patched);
            rationale = "Injected `.With(authMiddleware)` to Chi route definition.".to_string();
        }
    }
    // 2. SQL Injection
    else if defect.rule.contains("sql_injection") || defect.rule == "qa.api.sqli" {
        let re_py_fsql =
            regex::Regex::new(r#"execute\s*\(\s*f["'](.*?)\{([a-zA-Z0-9_]+)\}(.*?)["']\s*\)"#)?;
        let re_py_pct =
            regex::Regex::new(r#"execute\s*\(\s*["'](.*?)(?:'%s'|%s)["']\s*%\s*([a-zA-Z0-9_]+)"#)?;
        let re_js_query =
            regex::Regex::new(r#"query\s*\(\s*`([^`]*)(\$\{[a-zA-Z0-9_]+\})([^`]*)`\s*\)"#)?;
        let re_exec_ident = regex::Regex::new(r#"execute\s*\(\s*([a-zA-Z0-9_]+)\s*\)"#)?;

        if let Some(caps) = re_py_fsql.captures(target_line) {
            let p1 = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let var = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let p2 = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let clean_p1 = p1.trim_end_matches('\'').trim_end_matches('"');
            let clean_p2 = p2.trim_start_matches('\'').trim_start_matches('"');
            let replacement = format!("execute(\"{clean_p1}%s{clean_p2}\", ({var},))");
            patched_lines[line_idx] =
                box_str(&re_py_fsql.replace(target_line, replacement.as_str()));
            rationale = "Replaced formatted f-string SQL query with parameterized placeholder (`%s`) and parameter tuple to prevent SQL injection.".to_string();
        } else if let Some(caps) = re_py_pct.captures(target_line) {
            let full_match = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let p1 = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let var = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let clean_p1 = p1.trim_end_matches('\'').trim_end_matches('"');
            let replacement = format!("execute(\"{clean_p1}%s\", ({var},)");
            patched_lines[line_idx] = box_str(&target_line.replace(full_match, &replacement));
            rationale = "Replaced `%`-interpolated SQL string with parameterized query and bound parameter tuple.".to_string();
        } else if let Some(caps) = re_exec_ident.captures(target_line) {
            let sql_var = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut found_prev = None;
            for prev_idx in (line_idx.saturating_sub(3)..line_idx).rev() {
                let prev_line = lines[prev_idx].trim();
                if prev_line.starts_with(&format!("{sql_var} = f\""))
                    || prev_line.starts_with(&format!("{sql_var} = f'"))
                {
                    found_prev = Some(prev_idx);
                    break;
                }
            }
            if let Some(prev_idx) = found_prev {
                let re_fassign = regex::Regex::new(&format!(
                    r#"{sql_var}\s*=\s*f["'](.*?)\{{([a-zA-Z0-9_]+)\}}(.*?)["']"#
                ))?;
                if let Some(acaps) = re_fassign.captures(lines[prev_idx]) {
                    let p1 = acaps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let bind_var = acaps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let p2 = acaps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let clean_p1 = p1.trim_end_matches('\'').trim_end_matches('"');
                    let clean_p2 = p2.trim_start_matches('\'').trim_start_matches('"');
                    let new_assign = format!("{sql_var} = \"{clean_p1}%s{clean_p2}\"");
                    let indent = lines[prev_idx]
                        .chars()
                        .take_while(|c| c.is_whitespace())
                        .collect::<String>();
                    patched_lines[prev_idx] = box_str(&format!("{indent}{new_assign}"));

                    let new_exec = target_line.replace(
                        &format!("execute({sql_var})"),
                        &format!("execute({sql_var}, ({bind_var},))"),
                    );
                    patched_lines[line_idx] = box_str(&new_exec);
                    rationale = format!(
                        "Parameterized `{sql_var}` query string with `%s` and passed `({bind_var},)` tuple to `execute`."
                    );
                }
            }
        } else if let Some(caps) = re_js_query.captures(target_line) {
            let p1 = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let raw_var = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let var = raw_var.trim_start_matches("${").trim_end_matches('}');
            let p2 = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let replacement = format!("query(\"{p1}$1{p2}\", [{var}])");
            patched_lines[line_idx] =
                box_str(&re_js_query.replace(target_line, replacement.as_str()));
            rationale = "Converted interpolated template string to parameterized query placeholder (`$1`) with bind variables.".to_string();
        }
    }
    // 3. Path Traversal
    else if defect.rule.contains("path_traversal") || defect.rule == "qa.api.path_traversal" {
        if target_line.contains("open(")
            || target_line.contains("fs.readFile")
            || target_line.contains("send_file(")
        {
            let indent = target_line
                .chars()
                .take_while(|c| c.is_whitespace())
                .collect::<String>();
            let sanitized = if target_line.contains("fs.readFile") {
                format!("{indent}const safePath = path.basename(filePath);\n{target_line}")
            } else {
                format!("{indent}safe_path = os.path.basename(user_path)\n{target_line}")
            };
            patched_lines[line_idx] = box_str(&sanitized);
            rationale =
                "Injected path basename sanitization to prevent directory traversal outside allowable root.".to_string();
        }
    }
    // 4. Command Execution
    else if defect.rule.contains("command_exec") || defect.rule == "qa.api.rce" {
        if target_line.contains("shell=True") {
            let patched = target_line.replace("shell=True", "shell=False");
            patched_lines[line_idx] = box_str(&patched);
            rationale =
                "Disabled `shell=True` to prevent arbitrary command injection via shell metacharacters.".to_string();
        } else if target_line.contains("child_process.exec(") {
            let patched = target_line.replace("child_process.exec(", "child_process.execFile(");
            patched_lines[line_idx] = box_str(&patched);
            rationale =
                "Replaced shell execution `exec` with argument-vector safe `execFile`.".to_string();
        }
    }
    // 5. CORS Wildcard
    else if defect.rule.contains("cors") {
        if target_line.contains("origin: \"*\"") || target_line.contains("origin: '*'") {
            let patched = target_line
                .replace(
                    "origin: \"*\"",
                    "origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000']",
                )
                .replace(
                    "origin: '*'",
                    "origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000']",
                );
            patched_lines[line_idx] = box_str(&patched);
            rationale =
                "Replaced wildcard CORS `*` with environment-configurable origin whitelist."
                    .to_string();
        }
    }
    // 6. Hardcoded Secrets
    else if defect.rule.contains("secrets.hardcoded") || defect.rule.contains("token") {
        let re_secret = regex::Regex::new(
            r#"["'](?:ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{32,}|rh_[a-zA-Z0-9]{20,})["']"#,
        )?;
        if let Some(m) = re_secret.find(target_line) {
            let patched = target_line.replace(m.as_str(), "process.env.API_SECRET_KEY || \"\"");
            patched_lines[line_idx] = box_str(&patched);
            rationale =
                "Extracted hardcoded secret credential into environment variable lookup (`process.env.API_SECRET_KEY`).".to_string();
        }
    }

    let mut patched_content = patched_lines.join("\n");
    if content.ends_with('\n') {
        patched_content.push('\n');
    }
    if patched_content == content || rationale.is_empty() {
        return Ok(None);
    }

    let diff = compute_unified_diff(&defect.file, &content, &patched_content);

    Ok(Some(PatchRemediation {
        defect_id: defect.id.clone(),
        rule: defect.rule.clone(),
        file_path: defect.file.clone(),
        line: defect.line,
        original_snippet: target_line.to_string(),
        patched_snippet: patched_lines[line_idx].to_string(),
        patched_content,
        unified_diff: diff,
        rationale,
        status: PatchStatus::Synthesized,
        verification_runner: None,
        verification_duration_ms: None,
        error_log: None,
    }))
}
