//! Terminal table and Markdown report formatters.

use super::types::AiEvalReport;

pub fn print_table_report(report: &AiEvalReport, threshold: f64, ms: u128) {
    println!("\n=== ReadyHai GenAI & Agent Evaluation (eval-ai) ===");
    println!(
        "Evaluation completed in {ms}ms | Threshold: {:.0}%",
        threshold * 100.0
    );
    println!(
        "Total: {} | Passed: {} | Failed: {} | Pass Rate: {:.1}%\n",
        report.total_cases,
        report.passed_cases,
        report.failed_cases,
        report.pass_rate * 100.0
    );

    println!(
        "{:<14} {:<8} {:<10} {:<12} {:<12} {:<10}",
        "Case ID", "Verdict", "RAG Score", "Faithfulness", "Relevance", "Halluc."
    );
    println!("{:-<70}", "");

    for r in &report.results {
        let verdict = if r.passed { "PASS" } else { "FAIL" };
        let (rag, faith, rel, hall) = if let Some(ref t) = r.rag_triad {
            (
                format!("{:.1}%", t.composite_score * 100.0),
                format!("{:.1}%", t.faithfulness * 100.0),
                format!("{:.1}%", t.answer_relevance * 100.0),
                t.hallucination_count.to_string(),
            )
        } else {
            ("-".into(), "-".into(), "-".into(), "0".into())
        };

        println!(
            "{:<14} {:<8} {:<10} {:<12} {:<12} {:<10}",
            r.case_id, verdict, rag, faith, rel, hall
        );

        if let Some(ref t) = r.rag_triad {
            for h in &t.hallucinations {
                println!("  [!] Hallucination: \"{}\"", h.claim);
                println!("      Reason: {}", h.reason);
                if !h.ungrounded_terms.is_empty() {
                    println!("      Ungrounded: {}", h.ungrounded_terms.join(", "));
                }
            }
        }

        if let Some(ref tr) = r.trajectory_eval
            && tr.loop_detected
        {
            println!(
                "  [!] Trajectory: Cyclic tool loop detected ({} redundant steps)",
                tr.redundant_steps
            );
        }

        if let Some(ref rt) = r.red_team {
            for f in &rt.findings {
                println!("  [!] Security: {f}");
            }
        }
    }
    println!("{:-<70}\n", "");
}

pub fn print_markdown_report(report: &AiEvalReport, ms: u128) {
    println!("# ReadyHai GenAI & Agent Evaluation Report\n");
    println!("- **Timestamp:** `{}`", report.timestamp);
    println!("- **Duration:** `{ms}ms`");
    println!(
        "- **Pass Rate:** **{:.1}%** ({}/{} passed)\n",
        report.pass_rate * 100.0,
        report.passed_cases,
        report.total_cases
    );

    println!(
        "| Case ID | Verdict | Overall Score | Faithfulness | Context Relevance | Answer Relevance | Hallucinations |"
    );
    println!("|---|---|---|---|---|---|---|");

    for r in &report.results {
        let verdict = if r.passed { "🟢 PASS" } else { "🔴 FAIL" };
        if let Some(ref t) = r.rag_triad {
            println!(
                "| `{}` | {} | **{:.1}%** | {:.1}% | {:.1}% | {:.1}% | {} |",
                r.case_id,
                verdict,
                r.overall_score * 100.0,
                t.faithfulness * 100.0,
                t.context_relevance * 100.0,
                t.answer_relevance * 100.0,
                t.hallucination_count
            );
        } else {
            println!(
                "| `{}` | {} | **{:.1}%** | - | - | - | 0 |",
                r.case_id,
                verdict,
                r.overall_score * 100.0
            );
        }
    }

    let mut all_hallucinations = Vec::new();
    for r in &report.results {
        if let Some(ref t) = r.rag_triad {
            for h in &t.hallucinations {
                all_hallucinations.push((&r.case_id, h));
            }
        }
    }

    if !all_hallucinations.is_empty() {
        println!("\n## ⚠️ Hallucination Breakdown\n");
        for (cid, h) in all_hallucinations {
            println!("> [!WARNING] **Case `{cid}`: Ungrounded Claim**");
            println!("> **Statement:** *\"{}\"*", h.claim);
            println!("> **Diagnosis:** {}", h.reason);
            if !h.ungrounded_terms.is_empty() {
                println!(
                    "> **Ungrounded Terms:** `{}`",
                    h.ungrounded_terms.join(", ")
                );
            }
            println!();
        }
    }
}
