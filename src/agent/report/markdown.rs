use crate::agent::types::AgentRunReport;

use super::helpers::{
    budget_line, count, defect_verification, llm_line, md_code, md_fence, md_text, opt,
    replays_text, score_text, status_code_text, verdict_label, verdict_of, verification_line,
};
use super::markdown_sections::{md_agents, md_change_impact, md_since_last_run};

pub fn generate_agent_markdown_report(rep: &AgentRunReport) -> String {
    let (verdict, score) = verdict_of(rep);
    let mut md = String::new();
    md.push_str("# ReadyHai Autonomous QA & Security Gate Report\n\n");
    md.push_str(&format!(
        "**Target:** {}  \n**Run ID:** {}  \n",
        md_code(&rep.target),
        md_code(&rep.id)
    ));
    md.push_str(&format!(
        "**Architecture:** {}  \n",
        md_text(rep.app_architecture.as_deref().unwrap_or("not detected"))
    ));
    md.push_str(&format!(
        "**Gate verdict:** **{}**  \n**Readiness:** **{}**  \n",
        md_text(verdict),
        md_text(&score_text(score))
    ));
    md.push_str(&format!(
        "**Provider / model:** {} / {}  \n**LLM usage:** {}  \n",
        md_text(&rep.provider),
        md_text(&rep.model),
        md_text(&llm_line(rep))
    ));
    md.push_str(&format!(
        "**Mode:** {}  \n**Run status:** {}  \n**Budget:** {}  \n**Started:** {}  \n\n",
        if rep.dry_run {
            "dry-run (no state-changing requests)"
        } else {
            "live"
        },
        md_text(&rep.status),
        md_text(&budget_line(rep)),
        md_text(&rep.started_at)
    ));
    md.push_str(&format!(
        "| Metric | Value |\n| :--- | :--- |\n| Routes discovered | {} |\n| Cases | {} |\n| PASS / FAIL / WARN | {} / {} / {} |\n| INCONCLUSIVE / BLOCKED / SKIPPED | {} / {} / {} |\n| Defects | {} |\n| Sign-off | {} |\n| Requester egress IP | {} |\n\n",
        rep.discovered_routes.len(), rep.executed_results.len(), count(rep, "PASS"), count(rep, "FAIL"), count(rep, "WARN"), count(rep, "INCONCLUSIVE"), count(rep, "BLOCKED"), count(rep, "SKIPPED"),
        rep.triaged_defects.len(), md_text(rep.approval_status.as_deref().unwrap_or("pending")), md_text(opt(&rep.requester_ip))
    ));
    if let Some(e) = &rep.error {
        md.push_str(&format!("> Run error: {}\n\n", md_text(e)));
    }

    if let Some(l) = &rep.evidence_ledger {
        md.push_str("## Evidence ledger\n\n");
        md.push_str(&format!(
            "{}\n\n_Verdict basis: {}_\n\n",
            md_text(&l.executive_summary),
            md_text(&l.verdict_basis)
        ));
        if let Some(s) = &l.ai_summary {
            md.push_str(&format!("> AI-generated, advisory: {}\n\n", md_text(s)));
        }
        md.push_str(
            "| Pillar | Score | Claim | Cases | Evidence |\n| :--- | :--- | :--- | :--- | :--- |\n",
        );
        for p in &l.pillars {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                md_text(&p.name),
                md_text(&score_text(p.score)),
                md_text(&p.claim),
                md_text(&p.case_ids.join(", ")),
                md_text(&p.evidence_files.join(", "))
            ));
        }
        md.push_str("\n| Technique | Planned | Pass | Warn | Fail | Inconclusive | Blocked | Not run | Flaky |\n| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        for c in &l.coverage {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                md_code(&c.technique),
                c.planned,
                c.pass,
                c.warn,
                c.fail,
                c.inconclusive,
                c.blocked,
                c.skipped,
                c.flaky
            ));
        }
        md.push_str("\n### Claims\n\n");
        for c in &l.claims {
            md.push_str(&format!(
                "- **{}** {} (cases: {}; evidence: {})\n",
                md_text(&c.status),
                md_text(&c.claim),
                md_text(&c.case_ids.join(", ")),
                md_text(&c.evidence_files.join(", "))
            ));
        }
        md.push_str("\n### Exit criteria\n\n");
        for e in &l.exit_criteria_checklist {
            let mark = match e.status.as_deref() {
                Some("met") => "x",
                Some("warning") => "!",
                _ => {
                    if e.met {
                        "x"
                    } else {
                        " "
                    }
                }
            };
            md.push_str(&format!(
                "- [{mark}] {} - {}\n",
                md_text(&e.criterion),
                md_text(&e.details)
            ));
        }
        md.push('\n');
        if let Some(v) = &l.verification {
            md.push_str("## Verification\n\n");
            md.push_str(&format!(
                "Every FAIL is replayed k times by an independent verifier (request rebuilt from the stored case, fresh credentials, same oracle). A failure that does not reproduce is INCONCLUSIVE, not a defect. pass^k is the share of replayed failures that reproduced on all k replays.\n\n{}\n\n",
                md_text(&verification_line(v))
            ));
            md.push_str("| Replays (k) | pass^k | Confirmed | Flaky | Not reproduced | Unverified | Replay requests |\n| ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n\n",
                v.k,
                md_text(&v.pass_k_text()),
                v.confirmed,
                v.flaky,
                v.not_reproduced,
                v.unverified,
                v.replay_requests
            ));
            if !v.records.is_empty() {
                md.push_str("| Case | Request | Verdict | Reproduced | Replays | Result | Note |\n| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");
                for r in &v.records {
                    md.push_str(&format!(
                        "| {} | {} {} | {} | {} | {} | {} -> {} | {} |\n",
                        md_code(&r.case_id),
                        md_code(&r.method),
                        md_code(&r.component),
                        verdict_label(r.verdict),
                        md_text(&r.ratio().unwrap_or_else(|| "-".into())),
                        md_text(&replays_text(r)),
                        md_text(&r.original_status),
                        md_text(&r.final_status),
                        md_text(r.note.as_deref().unwrap_or(""))
                    ));
                }
                md.push('\n');
            }
            if !rep.triaged_defects.is_empty() {
                md.push_str("| Defect | Severity | Verification | Blocking |\n| :--- | :--- | :--- | :--- |\n");
                for d in &rep.triaged_defects {
                    md.push_str(&format!(
                        "| {} | {} | {}{} | {} |\n",
                        md_text(&d.id),
                        md_text(&d.severity.to_uppercase()),
                        md_text(&defect_verification(d)),
                        if d.flaky { " (flaky)" } else { "" },
                        if crate::agent::ledger::is_blocking(d) {
                            "yes"
                        } else {
                            "no"
                        }
                    ));
                }
                md.push('\n');
            }
        }
    }

    if let Some(s) = &rep.since_last_run {
        md.push_str(&md_since_last_run(s));
    }
    if let Some(ci) = &rep.change_impact {
        md.push_str(&md_change_impact(ci));
    }
    if let Some(a) = &rep.agents {
        md.push_str(&md_agents(a));
    }

    md.push_str("## Executed scenarios\n\n| ID | Method | Component | Technique | Status | HTTP | Latency |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n");
    for c in &rep.executed_results {
        md.push_str(&format!(
            "| {} | {} | {} | {} | **{}**{} | {} | {} ms |\n",
            md_code(&c.case_id),
            md_code(&c.method),
            md_code(&c.component),
            md_code(&c.technique),
            md_text(&c.status),
            if c.flaky { " (flaky)" } else { "" },
            status_code_text(c),
            c.latency_ms
        ));
    }
    md.push_str("\n### Assertions and reproduction commands\n\n");
    for c in &rep.executed_results {
        md.push_str(&format!(
            "**{} - {}**\n\n",
            md_text(&c.case_id),
            md_text(&c.title)
        ));
        if let Some(r) = &c.failure_reason {
            md.push_str(&format!("{}\n\n", md_text(r)));
        }
        if !c.reproduction_curl.is_empty() {
            md.push_str(&md_fence(&c.reproduction_curl, "bash"));
            md.push('\n');
        }
    }

    if !rep.triaged_defects.is_empty() {
        md.push_str("## Defects\n\n| Severity | Defect | Category | Verification | Cases | Remediation |\n| :--- | :--- | :--- | :--- | :--- |\n");
        for d in &rep.triaged_defects {
            md.push_str(&format!(
                "| **{}** {} | {}{} | {} | {} | {} | {} |\n",
                md_text(&d.severity.to_uppercase()),
                md_text(&d.priority),
                md_text(&d.title),
                d.accepted
                    .as_ref()
                    .map(|a| format!(
                        " (accepted by {} until {}: does not block)",
                        md_text(&a.by),
                        md_text(&a.expires)
                    ))
                    .unwrap_or_default(),
                md_text(&d.owasp_category),
                md_text(&defect_verification(d)),
                md_text(&d.case_ids.join(", ")),
                md_text(&d.recommended_fix)
            ));
        }
        for d in rep
            .triaged_defects
            .iter()
            .filter(|d| d.source_context.is_some())
        {
            md.push_str(&format!(
                "\n> Source location for {}: {}\n",
                md_text(&d.id),
                md_text(d.source_context.as_deref().unwrap_or(""))
            ));
        }
        for d in rep.triaged_defects.iter().filter(|d| d.ai_note.is_some()) {
            md.push_str(&format!(
                "\n> AI note on {} (advisory): {}\n",
                md_text(&d.id),
                md_text(d.ai_note.as_deref().unwrap_or(""))
            ));
        }
        md.push('\n');
    }

    md.push_str("## Discovered attack surface\n\n| Method | Route | Title | Status | Source |\n| :--- | :--- | :--- | :--- | :--- |\n");
    for r in &rep.discovered_routes {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md_code(&r.method),
            md_code(&r.path),
            md_text(r.title.as_deref().unwrap_or("-")),
            if r.status_code == 0 {
                "not probed".to_string()
            } else {
                r.status_code.to_string()
            },
            md_text(&r.source)
        ));
    }
    md.push_str("\n---\n*Generated by ReadyHai.*\n");
    md
}
