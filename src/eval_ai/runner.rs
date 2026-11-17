//! Top-level CLI command runner for eval-ai.

use std::fs;
use std::time::Instant;

use anyhow::{bail, Result};

use super::dataset::load_cases;
use super::evaluator::evaluate_cases;
use super::report::{print_markdown_report, print_table_report};
use super::types::EvalAiOpts;

/// Run evaluation over test cases and generate report.
pub fn run(opts: EvalAiOpts) -> Result<u8> {
    let t0 = Instant::now();
    let cases = load_cases(&opts)?;
    if cases.is_empty() {
        bail!("No test cases loaded for evaluation");
    }

    let report = evaluate_cases(&cases, opts.threshold, opts.red_team);

    if let Some(ref out_path) = opts.out {
        let json_data = serde_json::to_vec_pretty(&report)?;
        if let Some(p) = out_path.parent() {
            let _ = fs::create_dir_all(p);
        }
        fs::write(out_path, json_data)?;
        eprintln!("eval-ai report saved to {}", out_path.display());
    }

    match opts.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "markdown" => {
            print_markdown_report(&report, t0.elapsed().as_millis());
        }
        _ => {
            print_table_report(&report, opts.threshold, t0.elapsed().as_millis());
        }
    }

    if report.failed_cases > 0 {
        Ok(1)
    } else {
        Ok(0)
    }
}
