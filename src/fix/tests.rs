//! Unit tests for agentic fix synthesizer and PR generation.

use std::fs;
use std::path::PathBuf;

use crate::model::Severity;

use super::diff::compute_unified_diff;
use super::pr::generate_pr_markdown;
use super::remediate::synthesize_remediation;
use super::types::{FixReport, PatchRemediation, PatchStatus, TargetDefect};

fn test_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rh-fix-{tag}-{:08x}", rand::random::<u32>()));
    let _ = fs::create_dir_all(&d);
    d
}

#[test]
fn test_unified_diff_generation() {
    let old = "function handle(req, res) {\n  const id = req.params.id;\n  res.send(id);\n}\n";
    let new = "function handle(req, res) {\n  const id = req.params.id;\n  const safe = sanitize(id);\n  res.send(safe);\n}\n";
    let diff = compute_unified_diff("src/routes.js", old, new);
    assert!(diff.contains("--- a/src/routes.js"));
    assert!(diff.contains("+++ b/src/routes.js"));
    assert!(diff.contains("+  const safe = sanitize(id);"));
}

#[test]
fn test_remediate_missing_guard_express() {
    let dir = test_dir("express");
    let file_path = dir.join("server.js");
    let content = "const express = require('express');\nconst app = express();\napp.get('/users', listUsers);\n";
    fs::write(&file_path, content).unwrap();

    let defect = TargetDefect {
        id: "D-001".into(),
        rule: "security.auth.missing_guard".into(),
        severity: Severity::High,
        file: "server.js".into(),
        line: 3,
        title: "Endpoint lacks guard".into(),
        component: "GET /users".into(),
        reproduction: None,
    };

    let patch = synthesize_remediation(&dir, &defect, &["requireAuth".into()])
        .unwrap()
        .expect("should synthesize patch");

    assert_eq!(patch.file_path, "server.js");
    assert!(patch.patched_snippet.contains("requireAuth, listUsers"));
    assert!(
        patch
            .unified_diff
            .contains("+app.get('/users', requireAuth, listUsers);")
    );
}

/// The runner writes `patched_content` to disk. It used to write `patched_snippet` (the one fixed
/// line), which replaced the entire file with that line. Any change back to writing the snippet
/// fails this test.
#[test]
fn patched_content_is_the_whole_file_not_just_the_fixed_line() {
    let dir = test_dir("whole-file");
    let file_path = dir.join("server.js");
    let content = "const express = require('express');\nconst app = express();\napp.get('/users', listUsers);\n\nfunction listUsers(req, res) {\n  res.json([]);\n}\n\nmodule.exports = app;\n";
    fs::write(&file_path, content).unwrap();

    let defect = TargetDefect {
        id: "D-001".into(),
        rule: "security.auth.missing_guard".into(),
        severity: Severity::High,
        file: "server.js".into(),
        line: 3,
        title: "Endpoint lacks guard".into(),
        component: "GET /users".into(),
        reproduction: None,
    };

    let patch = synthesize_remediation(&dir, &defect, &["requireAuth".into()])
        .unwrap()
        .expect("should synthesize patch");

    // Same shape as the original: every untouched line survives, and the trailing newline too.
    assert_eq!(
        patch.patched_content,
        "const express = require('express');\nconst app = express();\napp.get('/users', requireAuth, listUsers);\n\nfunction listUsers(req, res) {\n  res.json([]);\n}\n\nmodule.exports = app;\n"
    );
    assert_eq!(
        patch.patched_content.lines().count(),
        content.lines().count(),
        "the patched file must keep every line"
    );
    assert!(patch.patched_content.ends_with('\n'));
    // The snippet is a strict subset; writing it would truncate the file.
    assert!(!patch.patched_snippet.contains("module.exports"));
}

#[test]
fn test_remediate_sql_injection_python() {
    let dir = test_dir("sqli");
    let file_path = dir.join("db.py");
    let content = "def get_user(user_id):\n    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n";
    fs::write(&file_path, content).unwrap();

    let defect = TargetDefect {
        id: "D-002".into(),
        rule: "security.taint.sql_injection".into(),
        severity: Severity::Critical,
        file: "db.py".into(),
        line: 2,
        title: "SQL injection".into(),
        component: "get_user".into(),
        reproduction: None,
    };

    let patch = synthesize_remediation(&dir, &defect, &[])
        .unwrap()
        .expect("should synthesize patch");

    assert!(
        patch
            .patched_snippet
            .contains("execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))")
    );
    assert!(
        patch
            .unified_diff
            .contains("+    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))")
    );
}

#[test]
fn test_remediate_command_exec() {
    let dir = test_dir("cmdi");
    let file_path = dir.join("exec.py");
    let content = "import subprocess\ndef run_cmd(cmd):\n    subprocess.run(cmd, shell=True)\n";
    fs::write(&file_path, content).unwrap();

    let defect = TargetDefect {
        id: "D-003".into(),
        rule: "security.taint.command_exec".into(),
        severity: Severity::Critical,
        file: "exec.py".into(),
        line: 3,
        title: "Command execution".into(),
        component: "run_cmd".into(),
        reproduction: None,
    };

    let patch = synthesize_remediation(&dir, &defect, &[])
        .unwrap()
        .expect("should synthesize patch");

    assert!(patch.patched_snippet.contains("shell=False"));
}

#[test]
fn test_remediate_cors_wildcard() {
    let dir = test_dir("cors");
    let file_path = dir.join("cors.js");
    let content = "const cors = require('cors');\napp.use(cors({ origin: '*' }));\n";
    fs::write(&file_path, content).unwrap();

    let defect = TargetDefect {
        id: "D-004".into(),
        rule: "security.cors.wildcard".into(),
        severity: Severity::Medium,
        file: "cors.js".into(),
        line: 2,
        title: "CORS Wildcard".into(),
        component: "cors".into(),
        reproduction: None,
    };

    let patch = synthesize_remediation(&dir, &defect, &[])
        .unwrap()
        .expect("should synthesize patch");

    assert!(
        patch
            .patched_snippet
            .contains("process.env.ALLOWED_ORIGINS")
    );
}

#[test]
fn test_remediate_hardcoded_secrets() {
    let dir = test_dir("secrets");
    let file_path = dir.join("config.js");
    let content = "const token = \"ghp_123456789012345678901234567890123456\";\n";
    fs::write(&file_path, content).unwrap();

    let defect = TargetDefect {
        id: "D-005".into(),
        rule: "security.secrets.hardcoded".into(),
        severity: Severity::High,
        file: "config.js".into(),
        line: 1,
        title: "Hardcoded secret".into(),
        component: "config".into(),
        reproduction: None,
    };

    let patch = synthesize_remediation(&dir, &defect, &[])
        .unwrap()
        .expect("should synthesize patch");

    assert!(patch.patched_snippet.contains("process.env.API_SECRET_KEY"));
}

fn pr_report() -> FixReport {
    FixReport {
        repo: "/test/repo".into(),
        total_defects_evaluated: 1,
        patches_synthesized: 1,
        patches_verified: 1,
        patches_unverified: 0,
        patches_applied: 1,
        branch_created: Some("readyhai-fix/auth".into()),
        commit_sha: Some("abc1234".into()),
        patches: vec![PatchRemediation {
            defect_id: "D-001".into(),
            rule: "security.auth.missing_guard".into(),
            file_path: "server.js".into(),
            line: 10,
            original_snippet: "app.get('/admin', handler);".into(),
            patched_snippet: "app.get('/admin', requireAuth, handler);".into(),
            patched_content: "app.get('/admin', requireAuth, handler);\n".into(),
            unified_diff: "--- a/server.js\n+++ b/server.js\n".into(),
            rationale: "Injected requireAuth".into(),
            status: PatchStatus::Verified,
            verification_runner: Some("npm test".into()),
            verification_duration_ms: Some(150),
            error_log: None,
        }],
        pr_title: "resolve 1 security defect".into(),
        pr_body: String::new(),
    }
}

#[test]
fn test_pr_markdown_structure() {
    let report = pr_report();
    let md = generate_pr_markdown(&report);
    assert!(md.contains("# 🛡️ ReadyHai Remediation"));
    assert!(md.contains("readyhai-fix/auth"));
    assert!(md.contains("npm test"));
    assert!(md.contains("requireAuth"));
    // the body must not overclaim: a green suite is not an absence of regressions
    assert!(
        !md.to_lowercase().contains("zero regressions"),
        "PR body claims zero regressions: {md}"
    );
}

#[test]
fn a_patch_that_was_never_tested_is_reported_as_unverified() {
    let mut report = pr_report();
    report.patches_verified = 0;
    report.patches_unverified = 1;
    report.patches[0].status = PatchStatus::AppliedWithoutVerification;
    report.patches[0].verification_runner = None;

    let md = generate_pr_markdown(&report);
    assert!(
        md.contains("**Patches Without Verification** | `1`"),
        "{md}"
    );
    assert!(md.contains("**not** checked"), "{md}");
    assert!(
        !md.contains("passed in"),
        "must not describe a run that never happened: {md}"
    );
}
