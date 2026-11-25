use crate::agent::types::AgentRunReport;

use super::helpers::{
    STYLE, budget_line, cites, defect_verification, html_escape, llm_line, opt, score_text,
    status_code_text, verdict_of,
};
use super::html_sections::{
    html_agents, html_change_impact, html_ledger, html_since_last_run, html_verification,
};

pub fn generate_agent_html_report(rep: &AgentRunReport) -> String {
    let (verdict, score) = verdict_of(rep);
    let badge = match verdict {
        "GO" => "badge-go",
        "CONDITIONAL_GO" => "badge-cond",
        "NO_GO" => "badge-nogo",
        _ => "badge-ne",
    };
    let approval = rep
        .approval_status
        .as_deref()
        .unwrap_or("pending")
        .to_ascii_uppercase();
    let mut h = String::new();
    h.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>");
    h.push_str(&format!("<title>ReadyHai Executive QA &amp; Security Gate Report - {}</title><style>{STYLE}</style></head><body><div class=\"container\">", html_escape(&rep.target)));
    h.push_str("<div style=\"margin-bottom:16px\"><a href=\"readyhai-report.md\" download>Markdown</a> &middot; <a href=\"readyhai-report.sarif\" download>SARIF</a> &middot; <a href=\"readyhai-report.json\" download>JSON</a> &middot; <a href=\"readyhai-report.junit.xml\" download>JUnit</a></div>");
    h.push_str(&format!(
        "<div class=\"card\"><div class=\"lbl\"><svg viewBox=\"0 0 128 128\" width=\"18\" height=\"18\" style=\"vertical-align:-3px;margin-right:6px\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"4\" y=\"4\" width=\"120\" height=\"120\" rx=\"28\" fill=\"#0F172A\" stroke=\"#1E293B\" stroke-width=\"2\"/><path d=\"M64 25 L92 37 V64 C92 81.5 80 96.5 64 102 C48 96.5 36 81.5 36 64 V37 Z\" fill=\"#090D16\" stroke=\"#00F0FF\" stroke-width=\"5\" stroke-linejoin=\"round\"/><path d=\"M49 63 L60 74 L81 49\" fill=\"none\" stroke=\"#FFFFFF\" stroke-width=\"8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>Autonomous QA &amp; Security Gate Report</div><h1><code>{}</code></h1><div><span class=\"badge {badge}\">{}</span> <span class=\"score{}\">{}</span> <span class=\"mut\">readiness</span></div>",
        html_escape(&rep.target), html_escape(verdict), if score.is_none() { " ne" } else { "" }, score_text(score)
    ));
    let items: Vec<(&str, String)> = vec![
        ("Run ID", rep.id.clone()),
        ("Run status", rep.status.clone()),
        (
            "Architecture",
            rep.app_architecture
                .clone()
                .unwrap_or_else(|| "not detected".into()),
        ),
        (
            "Provider / model",
            format!("{} / {}", rep.provider, rep.model),
        ),
        ("LLM usage", llm_line(rep)),
        ("Started", rep.started_at.clone()),
        (
            "Finished",
            rep.finished_at
                .clone()
                .unwrap_or_else(|| "in progress".into()),
        ),
        (
            "Mode",
            if rep.dry_run {
                "dry-run (no state-changing requests)".into()
            } else {
                "live".into()
            },
        ),
        ("Budget", budget_line(rep)),
        ("Sign-off", approval.clone()),
        ("Requester egress IP", opt(&rep.requester_ip).to_string()),
        (
            "Allowlist guidance",
            opt(&rep.allowlist_guidance).to_string(),
        ),
    ];
    h.push_str("<div class=\"grid\" style=\"margin-top:16px\">");
    for (k, v) in items {
        h.push_str(&format!(
            "<div class=\"item\"><div class=\"lbl\">{}</div><div>{}</div></div>",
            html_escape(k),
            html_escape(&v)
        ));
    }
    h.push_str("</div>");
    h.push_str(&format!(
        "<p class=\"mut\">Sign-off: {} by {} &mdash; {}</p>",
        html_escape(&approval),
        html_escape(rep.approved_by.as_deref().unwrap_or("nobody yet")),
        html_escape(rep.approval_notes.as_deref().unwrap_or("no notes"))
    ));
    if let Some(e) = &rep.error {
        h.push_str(&format!(
            "<p class=\"st-FAIL\">Run error: {}</p>",
            html_escape(e)
        ));
    }
    h.push_str("</div>");

    match &rep.evidence_ledger {
        Some(l) => {
            h.push_str(&html_ledger(l));
            if let Some(v) = &l.verification {
                h.push_str(&html_verification(rep, v));
            }
        }
        None => h.push_str("<div class=\"card\"><h2>Evidence ledger</h2><p class=\"ne\">not evaluated: this run has no ledger</p></div>"),
    }
    if let Some(s) = &rep.since_last_run {
        h.push_str(&html_since_last_run(s));
    }
    if let Some(ci) = &rep.change_impact {
        h.push_str(&html_change_impact(ci));
    }
    if let Some(a) = &rep.agents {
        h.push_str(&html_agents(a));
    }

    h.push_str(&format!("<div class=\"card\"><h2>Executed cases ({})</h2><div class=\"wrap\"><table><thead><tr><th>Case</th><th>Request</th><th>Technique</th><th>Status</th></tr></thead><tbody>", rep.executed_results.len()));
    for c in &rep.executed_results {
        let checks = c
            .oracle
            .as_ref()
            .map(|o| {
                o.checks
                    .iter()
                    .map(|k| format!("{} {}: {}", k.verdict.label(), k.code, k.detail))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        h.push_str(&format!(
            "<tr><td><code>{}</code><div class=\"mut\">{}</div></td><td><code>{} {}</code><div class=\"mut\">HTTP {}</div></td><td>{}</td><td><b class=\"st-{}\">{}</b>{}<div class=\"mut\">{} ms</div></td></tr>",
            html_escape(&c.case_id), html_escape(&c.title), html_escape(&c.method), html_escape(&c.component), status_code_text(c), html_escape(&c.technique),
            html_escape(&c.status), html_escape(&c.status), if c.flaky { " (flaky)" } else { "" }, c.latency_ms
        ));
        h.push_str(&format!(
            "<tr><td colspan=\"4\"><div class=\"mut\"><b>Assertion:</b> {}</div>{}{}{}</td></tr>",
            html_escape(
                c.failure_reason
                    .as_deref()
                    .unwrap_or(if c.status == "PASS" {
                        "all assertions held"
                    } else {
                        "no reason recorded"
                    })
            ),
            if checks.is_empty() {
                String::new()
            } else {
                format!("<pre>{}</pre>", html_escape(&checks))
            },
            if c.reproduction_curl.is_empty() {
                String::new()
            } else {
                format!("<pre>{}</pre>", html_escape(&c.reproduction_curl))
            },
            c.evidence_file
                .as_ref()
                .map(|f| format!("<div class=\"mut\">evidence: {}</div>", html_escape(f)))
                .unwrap_or_default()
        ));
    }
    h.push_str("</tbody></table></div></div>");

    h.push_str(&format!(
        "<div class=\"card\"><h2>Defects ({})</h2>",
        rep.triaged_defects.len()
    ));
    if rep.triaged_defects.is_empty() {
        let evaluated = rep.evidence_ledger.as_ref().is_some_and(|l| l.evaluated);
        h.push_str(&format!("<p class=\"mut\">{}</p>", if evaluated { "No failed assertions among the executed cases (this is not proof of absence of defects)." } else { "No defects recorded; the run did not evaluate enough to conclude anything." }));
    } else {
        h.push_str("<div class=\"wrap\"><table><thead><tr><th>Severity</th><th>Defect</th><th>Cases</th><th>Fix</th></tr></thead><tbody>");
        for d in &rep.triaged_defects {
            h.push_str(&format!(
                "<tr><td><b>{}</b> {}</td><td>{}<div class=\"mut\">{} &middot; {} &middot; verification: {}</div>{}{}{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&d.severity.to_uppercase()), html_escape(&d.priority), html_escape(&d.title), html_escape(&d.owasp_category), html_escape(&d.component), html_escape(&defect_verification(d)),
                d.source_context.as_ref().map(|s| format!("<div class=\"mut\">source: {}</div>", html_escape(s))).unwrap_or_default(),
                d.accepted.as_ref().map(|a| format!("<div><span class=\"badge badge-cond\">accepted, does not block</span> by {} until {}: {}</div>", html_escape(&a.by), html_escape(&a.expires), html_escape(&a.reason))).unwrap_or_default(),
                d.ai_note.as_ref().map(|n| format!("<div><span class=\"badge badge-ne\">AI note, advisory</span> {}</div>", html_escape(n))).unwrap_or_default(),
                cites(&d.case_ids, &d.evidence_files), html_escape(&d.recommended_fix)
            ));
        }
        h.push_str("</tbody></table></div>");
    }
    h.push_str("</div>");

    h.push_str(&format!("<div class=\"card\"><h2>Discovered routes ({})</h2><div class=\"wrap\"><table><thead><tr><th>Method</th><th>Route</th><th>Status</th><th>Source</th></tr></thead><tbody>", rep.discovered_routes.len()));
    for r in &rep.discovered_routes {
        h.push_str(&format!(
            "<tr><td><code>{}</code></td><td><code>{}</code><div class=\"mut\">{}</div></td><td>{}</td><td>{}</td></tr>",
            html_escape(&r.method), html_escape(&r.path), html_escape(r.title.as_deref().unwrap_or("")), if r.status_code == 0 { "not probed".to_string() } else { r.status_code.to_string() }, html_escape(&r.source)
        ));
    }
    h.push_str("</tbody></table></div></div>");

    if !rep.steps.is_empty() || !rep.notes.is_empty() {
        h.push_str("<div class=\"card\"><h2>Agent log</h2><div class=\"wrap\"><table><thead><tr><th>Time</th><th>Agent</th><th>Action</th><th>Source</th><th>Details</th></tr></thead><tbody>");
        for s in &rep.steps {
            h.push_str(&format!(
                "<tr><td class=\"mut\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&s.timestamp),
                html_escape(&s.agent),
                html_escape(&s.action),
                html_escape(s.source.as_deref().unwrap_or("")),
                html_escape(&s.details)
            ));
        }
        h.push_str("</tbody></table></div>");
        for n in &rep.notes {
            h.push_str(&format!("<p class=\"mut\">note: {}</p>", html_escape(n)));
        }
        h.push_str("</div>");
    }
    h.push_str("<div class=\"mut\" style=\"text-align:center;margin:24px 0\">Generated by ReadyHai. Reproduction commands read tokens from RH_&lt;ROLE&gt;_TOKEN environment variables.</div></div></body></html>");
    h
}
