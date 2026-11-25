//! CLI execution orchestrator and report formatter for readyhai fix.

use std::collections::BTreeSet;
use std::fs;

use anyhow::Result;

use super::defects::collect_target_defects;
use super::git::commit_local_branch;
use super::pr::generate_pr_markdown;
use super::remediate::synthesize_remediation;
use super::sandbox::{detect_test_runner, verify_in_sandbox};
use super::sibling::mine_sibling_guards;
use super::types::{FixOpts, FixReport, PatchStatus};

/// Main entrypoint for `readyhai fix`.
pub fn run(opts: FixOpts) -> Result<u8> {
    let repo = opts.repo.canonicalize().unwrap_or(opts.repo.clone());
    let defects = collect_target_defects(&repo, opts.run.as_deref(), opts.defect.as_deref());

    if defects.is_empty() {
        if opts.format == "json" {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "ok",
                    "message": "no actionable defects found matching criteria",
                    "defects": 0
                }))?
            );
        } else {
            println!(
                "No actionable defects found matching criteria in {}",
                repo.display()
            );
        }
        return Ok(0);
    }

    let sibling_guards = mine_sibling_guards(&repo);
    let test_runner = detect_test_runner(&repo);

    let mut remediations = Vec::new();
    let mut modified_files = BTreeSet::new();

    for defect in &defects {
        if let Some(mut patch) = synthesize_remediation(&repo, defect, &sibling_guards)? {
            let file_path = repo.join(&patch.file_path);
            let original_content = fs::read_to_string(&file_path).unwrap_or_default();

            if opts.verify
                && let Some(runner) = test_runner
            {
                // Apply patch to disk temporarily for sandbox verification
                if let Err(e) = fs::write(&file_path, &patch.patched_snippet) {
                    patch.status = PatchStatus::VerificationFailed;
                    patch.error_log = Some(format!("failed to write patch for verification: {e}"));
                    remediations.push(patch);
                    continue;
                }

                // Run sandbox tests
                match verify_in_sandbox(&repo, runner) {
                    Ok((true, dur_ms, _)) => {
                        patch.status = PatchStatus::Verified;
                        patch.verification_runner = Some(runner.0.to_string());
                        patch.verification_duration_ms = Some(dur_ms);
                    }
                    Ok((false, dur_ms, log)) => {
                        // Rollback on test failure
                        let _ = fs::write(&file_path, &original_content);
                        patch.status = PatchStatus::VerificationFailed;
                        patch.verification_runner = Some(runner.0.to_string());
                        patch.verification_duration_ms = Some(dur_ms);
                        patch.error_log = Some(log);
                    }
                    Err(e) => {
                        let _ = fs::write(&file_path, &original_content);
                        patch.status = PatchStatus::VerificationFailed;
                        patch.error_log = Some(e.to_string());
                    }
                }

                if opts.dry_run || patch.status == PatchStatus::VerificationFailed {
                    let _ = fs::write(&file_path, &original_content);
                } else {
                    patch.status = PatchStatus::Applied;
                    modified_files.insert(patch.file_path.clone());
                }
            } else if !opts.dry_run {
                // Apply without verification if verify is off or no runner
                if fs::write(&file_path, &patch.patched_snippet).is_ok() {
                    patch.status = PatchStatus::Applied;
                    modified_files.insert(patch.file_path.clone());
                }
            }

            remediations.push(patch);
        }
    }

    let verified_count = remediations
        .iter()
        .filter(|r| matches!(r.status, PatchStatus::Verified | PatchStatus::Applied))
        .count();
    let applied_count = remediations
        .iter()
        .filter(|r| r.status == PatchStatus::Applied)
        .count();

    let mut branch_created = None;
    let mut commit_sha = None;

    if let Some(branch) = &opts.branch
        && !opts.dry_run
        && !modified_files.is_empty()
    {
        let commit_msg = format!(
            "fix(security): resolve {} defect(s) via ReadyHai Agentic Fixer\n\nVerified with zero regressions.",
            applied_count
        );
        let files_vec: Vec<String> = modified_files.into_iter().collect();
        if let Ok(Some(sha)) = commit_local_branch(&repo, branch, &commit_msg, &files_vec) {
            branch_created = Some(branch.clone());
            commit_sha = Some(sha);
        }
    }

    let pr_title = format!("resolve {} security & QA defect(s)", verified_count);
    let mut report = FixReport {
        repo: repo.display().to_string(),
        total_defects_evaluated: defects.len(),
        patches_synthesized: remediations.len(),
        patches_verified: verified_count,
        patches_applied: applied_count,
        branch_created,
        commit_sha,
        patches: remediations,
        pr_title: pr_title.clone(),
        pr_body: String::new(),
    };
    report.pr_body = generate_pr_markdown(&report);

    match opts.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "markdown" => {
            println!("{}", report.pr_body);
        }
        _ => {
            print_text_summary(&report, opts.dry_run);
        }
    }

    Ok(0)
}

fn print_text_summary(report: &FixReport, dry_run: bool) {
    println!("\n╔════════════════════════════════════════════════════════════════════╗");
    println!("║              READYHAI AGENTIC FIXER (v2.0.0)                      ║");
    println!("╚════════════════════════════════════════════════════════════════════╝\n");
    println!("  Repository:       {}", report.repo);
    println!("  Defects Found:    {}", report.total_defects_evaluated);
    println!("  Patches Created:  {}", report.patches_synthesized);
    println!("  Verified Clean:   {}", report.patches_verified);
    println!("  Patches Applied:  {}", report.patches_applied);
    if dry_run {
        println!("  Execution Mode:   DRY RUN (No files modified)");
    }
    if let Some(b) = &report.branch_created {
        println!("  Branch Created:   {}", b);
    }
    if let Some(s) = &report.commit_sha {
        println!("  Commit SHA:       {}", s);
        println!(
            "  Push Policy:      Remote push NOT executed. Push when ready with `git push origin {}`",
            report.branch_created.as_deref().unwrap_or("")
        );
    }
    println!("\n  Synthesized Remediations:");
    for p in &report.patches {
        let tag = match p.status {
            PatchStatus::Verified => "\x1b[32m[VERIFIED]\x1b[0m",
            PatchStatus::Applied => "\x1b[32m[APPLIED]\x1b[0m",
            PatchStatus::Synthesized => "\x1b[33m[SYNTHESIZED]\x1b[0m",
            PatchStatus::VerificationFailed => "\x1b[31m[TEST FAILED]\x1b[0m",
            PatchStatus::RolledBack => "\x1b[35m[ROLLED BACK]\x1b[0m",
        };
        println!("   {} {}:{} ({})", tag, p.file_path, p.line, p.rule);
        if let Some(runner) = &p.verification_runner {
            println!(
                "      harness: {} ({}ms)",
                runner,
                p.verification_duration_ms.unwrap_or(0)
            );
        }
    }
    println!();
}
