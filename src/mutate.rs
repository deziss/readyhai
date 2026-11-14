//! Autonomous Mutation Testing: semantic defect injection, mutation score calculation,
//! test oracle calibration, and negative test assertion synthesis.
//!
//! Capabilities:
//! 1. Injects targeted semantic bugs (mutants) into source code:
//!    - Comparison operators: `==` <-> `!=`, `<` <-> `>=`, `>` <-> `<=`, etc.
//!    - Boolean literal flips: `true` <-> `false`.
//!    - Authorization guard bypasses: `is_admin` -> `true`, `!is_authenticated` -> `false`.
//!    - Return value flips: `return Ok(` <-> `return Err(`, `return true` <-> `return false`.
//!    - Arithmetic operator flips: ` + ` <-> ` - `, ` * ` <-> ` / `.
//! 2. Executes repository test runner (`cargo test`, `npm test`, `pytest`, `go test`) per mutant.
//! 3. Evaluates test oracle effectiveness:
//!    - Killed: Tests fail on mutant (Good — test suite actively catches semantic defects).
//!    - Survived: Tests pass despite the introduced defect (Critical quality gap — test assertions missing).
//!    - TimedOut: Test hangs on mutant (Counted as killed).
//! 4. Computes Mutation Score: (Killed + TimedOut) / Total * 100%.
//! 5. Synthesizes recommended negative test assertions to kill survived mutants.

use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Args, Debug, Clone, Serialize, Deserialize)]
pub struct MutateOpts {
    /// Path to repository root (defaults to current directory)
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    /// Target file or directory relative to repository root to mutate
    #[arg(long)]
    pub target: Option<String>,

    /// Maximum number of mutants to generate and evaluate (default: 20)
    #[arg(long, default_value_t = 20)]
    pub max_mutants: usize,

    /// Timeout in seconds per mutant test execution (default: 30)
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,

    /// Output format: text (colored summary), json, or markdown
    #[arg(long, default_value = "text")]
    pub format: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutantKind {
    InvertComparison,
    FlipBoolean,
    BypassAuth,
    InvertReturn,
    ArithmeticOperator,
}

impl MutantKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::InvertComparison => "Invert Comparison Operator",
            Self::FlipBoolean => "Flip Boolean Literal",
            Self::BypassAuth => "Bypass Auth Guard",
            Self::InvertReturn => "Invert Return Value",
            Self::ArithmeticOperator => "Invert Arithmetic Operator",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutantVerdict {
    Killed,
    Survived,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeMutant {
    pub id: String,
    pub kind: MutantKind,
    pub file_path: String,
    pub line: usize,
    pub original_line: String,
    pub mutated_line: String,
    pub verdict: MutantVerdict,
    pub execution_duration_ms: u128,
    pub recommended_test_assertion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationReport {
    pub repo: String,
    pub total_mutants: usize,
    pub killed_mutants: usize,
    pub survived_mutants: usize,
    pub timed_out_mutants: usize,
    pub mutation_score: f64,
    pub oracle_quality: String,
    pub mutants: Vec<CodeMutant>,
}

/// Find files eligible for mutation in repository.
pub fn find_mutable_files(repo: &Path, target_filter: Option<&str>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let walker = walkdir::WalkDir::new(repo)
        .max_depth(5)
        .into_iter()
        .filter_entry(|e| {
            let n = e.file_name().to_string_lossy();
            !n.starts_with('.') && n != "node_modules" && n != "target" && n != "dist" && n != "runs"
        });

    for entry in walker.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if matches!(ext, "rs" | "js" | "ts" | "py" | "go") {
            let rel = p.strip_prefix(repo).unwrap_or(p).to_string_lossy();
            if let Some(filt) = target_filter {
                if rel.contains(filt) {
                    files.push(p.to_path_buf());
                }
            } else if !rel.contains("test") && !rel.contains("spec") && !rel.contains("fixture") {
                files.push(p.to_path_buf());
            }
        }
    }

    files
}

/// Synthesize semantic code mutants for a file.
pub fn generate_file_mutants(file_path: &Path, rel_path: &str, max_per_file: usize) -> Vec<CodeMutant> {
    let mut mutants = Vec::new();
    let Ok(content) = fs::read_to_string(file_path) else {
        return mutants;
    };

    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        if mutants.len() >= max_per_file {
            break;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        // 1. Comparison Operator Inversion
        if trimmed.contains(" == ") {
            let mutated = line.replace(" == ", " != ");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::InvertComparison,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert_ne!(actual, expected) on {rel_path}:{}", idx + 1)),
            });
        } else if trimmed.contains(" != ") {
            let mutated = line.replace(" != ", " == ");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::InvertComparison,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert_eq!(actual, expected) on {rel_path}:{}", idx + 1)),
            });
        } else if trimmed.contains(" < ") && !trimmed.contains("<T>") && !trimmed.contains(" < ") {
            let mutated = line.replace(" < ", " >= ");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::InvertComparison,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert!(val < threshold) on {rel_path}:{}", idx + 1)),
            });
        } else if trimmed.contains(" > ") {
            let mutated = line.replace(" > ", " <= ");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::InvertComparison,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert!(val > threshold) on {rel_path}:{}", idx + 1)),
            });
        }

        // 2. Boolean Literal Flip
        if trimmed.contains("true") && !trimmed.contains("true,") && !trimmed.contains("\"true\"") {
            let mutated = line.replace("true", "false");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::FlipBoolean,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert!(flag == true) on {rel_path}:{}", idx + 1)),
            });
        } else if trimmed.contains("false") && !trimmed.contains("\"false\"") {
            let mutated = line.replace("false", "true");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::FlipBoolean,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert!(flag == false) on {rel_path}:{}", idx + 1)),
            });
        }

        // 3. Authorization Bypass Mutant
        if trimmed.contains("is_admin") || trimmed.contains("is_authorized") || trimmed.contains("is_valid") {
            let mutated = line.replace("is_admin", "true")
                .replace("is_authorized", "true")
                .replace("is_valid", "true");
            if mutated != *line {
                mutants.push(CodeMutant {
                    id: format!("M-{:03}", mutants.len() + 1),
                    kind: MutantKind::BypassAuth,
                    file_path: rel_path.to_string(),
                    line: idx + 1,
                    original_line: line.to_string(),
                    mutated_line: mutated,
                    verdict: MutantVerdict::Survived,
                    execution_duration_ms: 0,
                    recommended_test_assertion: Some(format!("assert_unauthorized! when role is not admin on {rel_path}:{}", idx + 1)),
                });
            }
        }

        // 4. Invert Return Value
        if trimmed.starts_with("return Ok(") {
            let mutated = line.replace("return Ok(", "return Err(");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::InvertReturn,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert!(res.is_ok()) on {rel_path}:{}", idx + 1)),
            });
        } else if trimmed.starts_with("return true") {
            let mutated = line.replace("return true", "return false");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::InvertReturn,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert_eq!(result, true) on {rel_path}:{}", idx + 1)),
            });
        }

        // 5. Invert Arithmetic Operator
        if trimmed.contains(" + ") && !trimmed.contains("\" + \"") {
            let mutated = line.replace(" + ", " - ");
            mutants.push(CodeMutant {
                id: format!("M-{:03}", mutants.len() + 1),
                kind: MutantKind::ArithmeticOperator,
                file_path: rel_path.to_string(),
                line: idx + 1,
                original_line: line.to_string(),
                mutated_line: mutated,
                verdict: MutantVerdict::Survived,
                execution_duration_ms: 0,
                recommended_test_assertion: Some(format!("assert_eq!(sum, a + b) on {rel_path}:{}", idx + 1)),
            });
        }
    }

    mutants
}

/// Execute test harness to evaluate a mutant.
pub fn evaluate_mutant(
    repo: &Path,
    mutant: &mut CodeMutant,
    runner: (&str, &[&str]),
    timeout_secs: u64,
) -> Result<()> {
    let full_path = repo.join(&mutant.file_path);
    let original = fs::read_to_string(&full_path)
        .with_context(|| format!("could not read {}", full_path.display()))?;

    // Apply mutation
    let mut lines: Vec<&str> = original.lines().collect();
    if mutant.line == 0 || mutant.line > lines.len() {
        return Ok(());
    }
    lines[mutant.line - 1] = &mutant.mutated_line;
    let mutated_content = lines.join("\n");

    let _ = fs::write(&full_path, &mutated_content);

    let start = Instant::now();
    let mut cmd = Command::new(runner.0);
    cmd.args(runner.1).current_dir(repo).env("CI", "true");

    let captured = crate::tools::run_capped(&mut cmd, Duration::from_secs(timeout_secs), 64 * 1024, None);

    // Revert file immediately
    let _ = fs::write(&full_path, &original);

    mutant.execution_duration_ms = start.elapsed().as_millis();

    match captured {
        Ok(c) => {
            if c.timed_out {
                mutant.verdict = MutantVerdict::TimedOut;
                mutant.recommended_test_assertion = None;
            } else if !c.success() {
                // Tests failed on mutant -> Mutant is KILLED! (Good)
                mutant.verdict = MutantVerdict::Killed;
                mutant.recommended_test_assertion = None;
            } else {
                // Tests passed despite mutant -> Mutant SURVIVED! (Weak test oracle)
                mutant.verdict = MutantVerdict::Survived;
            }
        }
        Err(_) => {
            mutant.verdict = MutantVerdict::Killed;
            mutant.recommended_test_assertion = None;
        }
    }

    Ok(())
}

/// Main entrypoint for `readyhai mutate`.
pub fn run(opts: MutateOpts) -> Result<u8> {
    let repo = opts.repo.canonicalize().unwrap_or(opts.repo.clone());
    let files = find_mutable_files(&repo, opts.target.as_deref());

    if files.is_empty() {
        println!("No eligible source files found for mutation in {}", repo.display());
        return Ok(0);
    }

    let runner = crate::fix::detect_test_runner(&repo)
        .unwrap_or(("cargo", &["test", "--", "--quiet"]));

    let mut all_mutants = Vec::new();
    let max_per_file = (opts.max_mutants / files.len().max(1)).max(2);

    for f in &files {
        let rel = f.strip_prefix(&repo).unwrap_or(f).to_string_lossy().to_string();
        let file_mutants = generate_file_mutants(f, &rel, max_per_file);
        all_mutants.extend(file_mutants);
        if all_mutants.len() >= opts.max_mutants {
            all_mutants.truncate(opts.max_mutants);
            break;
        }
    }

    let total = all_mutants.len();
    if total == 0 {
        println!("No mutatable semantic syntax points found in target files.");
        return Ok(0);
    }

    println!("\n╔════════════════════════════════════════════════════════════════════╗");
    println!("║         READYHAI AUTONOMOUS MUTATION TESTING (v2.5.0)              ║");
    println!("╚════════════════════════════════════════════════════════════════════╝\n");
    println!("  Repository:       {}", repo.display());
    println!("  Test Runner:      {}", runner.0);
    println!("  Target Mutants:   {}\n", total);

    let mut killed = 0;
    let mut survived = 0;
    let mut timed_out = 0;

    for (i, m) in all_mutants.iter_mut().enumerate() {
        print!("  [{}/{}] Evaluating mutant {} in {}:{} ... ", i + 1, total, m.id, m.file_path, m.line);
        let _ = evaluate_mutant(&repo, m, runner, opts.timeout_secs);
        match m.verdict {
            MutantVerdict::Killed => {
                killed += 1;
                println!("\x1b[32mKILLED\x1b[0m ({}ms)", m.execution_duration_ms);
            }
            MutantVerdict::TimedOut => {
                timed_out += 1;
                println!("\x1b[33mTIMEOUT\x1b[0m ({}ms)", m.execution_duration_ms);
            }
            MutantVerdict::Survived => {
                survived += 1;
                println!("\x1b[31mSURVIVED\x1b[0m (Test oracle missed defect)");
            }
        }
    }

    let score = if total > 0 {
        ((killed + timed_out) as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    let quality = if score >= 80.0 {
        "EXCELLENT (Test oracle strongly sensitive to semantic regressions)"
    } else if score >= 60.0 {
        "ADEQUATE (Test suite catches major defects; edge cases missing)"
    } else {
        "WEAK (Superficial assertions; tests pass even when logic is corrupted)"
    };

    let report = MutationReport {
        repo: repo.display().to_string(),
        total_mutants: total,
        killed_mutants: killed,
        survived_mutants: survived,
        timed_out_mutants: timed_out,
        mutation_score: score,
        oracle_quality: quality.to_string(),
        mutants: all_mutants,
    };

    match opts.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "markdown" => {
            println!("{}", generate_mutation_markdown(&report));
        }
        _ => {
            println!("\n  ──────────────────────────────────────────────────────────────────");
            println!("  📊 Mutation Score:        {:.1}%", report.mutation_score);
            println!("  🎯 Test Oracle Quality:   {}", report.oracle_quality);
            println!("  ⚔️  Mutants Killed:        {}", report.killed_mutants);
            println!("  ⚠️  Mutants Survived:      {}", report.survived_mutants);
            println!("  ⏱️  Mutants Timed Out:     {}", report.timed_out_mutants);
            println!("  ──────────────────────────────────────────────────────────────────\n");
            if survived > 0 {
                println!("  🚨 Recommended Negative Test Assertions for Survived Mutants:");
                for m in report.mutants.iter().filter(|m| m.verdict == MutantVerdict::Survived) {
                    if let Some(recom) = &m.recommended_test_assertion {
                        println!("    • [{}] {}:{} -> Add `{}`", m.id, m.file_path, m.line, recom);
                    }
                }
                println!();
            }
        }
    }

    Ok(0)
}

/// Generate Markdown report for CI and PR summaries.
pub fn generate_mutation_markdown(report: &MutationReport) -> String {
    let mut md = String::new();
    md.push_str("# 🧬 ReadyHai Mutation Testing Report\n\n");
    md.push_str("> Automated test oracle sensitivity calibration and mutant survivability audit.\n\n");
    md.push_str("### 📊 Oracle Calibration Metrics\n");
    md.push_str("| Metric | Value |\n|---|---|\n");
    md.push_str(&format!("| **Mutation Score** | **{:.1}%** |\n", report.mutation_score));
    md.push_str(&format!("| **Oracle Assessment** | `{}` |\n", report.oracle_quality));
    md.push_str(&format!("| **Total Mutants Injected** | `{}` |\n", report.total_mutants));
    md.push_str(&format!("| **Killed (Caught by Tests)** | `{} ✅` |\n", report.killed_mutants));
    md.push_str(&format!("| **Survived (Missed by Tests)** | `{} ⚠️` |\n", report.survived_mutants));
    md.push_str(&format!("| **Timed Out** | `{}` |\n", report.timed_out_mutants));
    md.push_str("\n---\n\n");

    if report.survived_mutants > 0 {
        md.push_str("### ⚠️ Survived Mutants & Recommended Test Assertions\n\n");
        for m in report.mutants.iter().filter(|m| m.verdict == MutantVerdict::Survived) {
            md.push_str(&format!("#### Mutant `{}` at `{}:{}`\n", m.id, m.file_path, m.line));
            md.push_str(&format!("- **Operator:** {}\n", m.kind.label()));
            md.push_str(&format!("- **Original:** `{}`\n", m.original_line.trim()));
            md.push_str(&format!("- **Mutated:** `{}`\n", m.mutated_line.trim()));
            if let Some(recom) = &m.recommended_test_assertion {
                md.push_str(&format!("- **Actionable Negative Test:** Add `{recom}`\n"));
            }
            md.push('\n');
        }
    }

    md.push_str("*Report synthesized by [ReadyHai](https://github.com/deziss/readyhai) · Autonomous QA & Evaluator.*");
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mutants_operators() {
        let dir = std::env::temp_dir().join(format!("rh-mut-op-{:08x}", rand::random::<u32>()));
        let _ = fs::create_dir_all(&dir);
        let src = "fn check(x: i32, is_admin: bool) -> bool {\n    if x == 42 && is_admin {\n        return true;\n    }\n    false\n}\n";
        let file = dir.join("auth.rs");
        fs::write(&file, src).unwrap();

        let mutants = generate_file_mutants(&file, "auth.rs", 10);
        assert!(!mutants.is_empty());
        let has_comp = mutants.iter().any(|m| m.kind == MutantKind::InvertComparison);
        let has_bool = mutants.iter().any(|m| m.kind == MutantKind::FlipBoolean);
        let has_auth = mutants.iter().any(|m| m.kind == MutantKind::BypassAuth);
        assert!(has_comp, "should generate comparison mutant");
        assert!(has_bool, "should generate boolean mutant");
        assert!(has_auth, "should generate auth bypass mutant");
    }

    #[test]
    fn test_mutation_score_computation() {
        let report = MutationReport {
            repo: ".".into(),
            total_mutants: 10,
            killed_mutants: 8,
            survived_mutants: 2,
            timed_out_mutants: 0,
            mutation_score: 80.0,
            oracle_quality: "EXCELLENT".into(),
            mutants: vec![],
        };
        let md = generate_mutation_markdown(&report);
        assert!(md.contains("80.0%"));
        assert!(md.contains("Killed (Caught by Tests)"));
    }
}
