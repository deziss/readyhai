//! Report renderers (HTML, Markdown, SARIF, JUnit, JSON). Every piece of target- or LLM-derived
//! text is escaped for the format it lands in; nothing is invented when data is missing:
//! absent values render as "not evaluated" / "not detected".
use super::memory::{DefectLine, SinceLastRun};
use super::types::{
    AgentRunReport, AgentsReport, AreaBudget, AreaReport, CaseExecutionResult, ChangeImpact,
    EvidenceLedger, Quota, TriagedDefect, VerificationSummary, VerifyVerdict,
};

// ---------------------------------------------------------------- escaping

pub(crate) fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => o.push(c),
        }
    }
    o
}

/// XML 1.0: escape the five specials and drop characters that are not legal at all.
pub(crate) fn xml_escape(s: &str) -> String {
    let legal = |c: &char| {
        matches!(*c, '\t' | '\n' | '\r')
            || (*c as u32) >= 0x20 && !matches!(*c as u32, 0xFFFE | 0xFFFF)
    };
    html_escape(&s.chars().filter(legal).collect::<String>()).replace('\n', "&#10;")
}

/// Markdown text (table cell / inline): neutralise formatting, HTML, links and line breaks.
pub(crate) fn md_text(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' | '~' => {
                o.push('\\');
                o.push(c);
            }
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '&' => o.push_str("&amp;"),
            '\n' | '\r' | '\t' => o.push(' '),
            c if c.is_control() => {}
            c => o.push(c),
        }
    }
    o
}

/// Inline code span that cannot be broken out of (and is safe inside a table cell).
pub(crate) fn md_code(s: &str) -> String {
    // '<' and '>' are swapped for look-alikes so no renderer or sanitizer can ever see a raw tag
    let t: String = s
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '`' => '\'',
            '<' => '\u{2039}',
            '>' => '\u{203a}',
            c => c,
        })
        .collect();
    format!("`{}`", t.replace('|', "\\|"))
}

/// Fenced block whose fence is longer than any backtick run in the body.
pub(crate) fn md_fence(body: &str, lang: &str) -> String {
    let (mut longest, mut run) = (0usize, 0usize);
    for c in body.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let f = "`".repeat((longest + 1).max(3));
    format!("{f}{lang}\n{body}\n{f}\n")
}

// ---------------------------------------------------------------- shared

fn verdict_of(rep: &AgentRunReport) -> (&str, Option<u32>) {
    match &rep.evidence_ledger {
        Some(l) if l.evaluated => (l.gate_verdict.as_str(), Some(l.overall_readiness)),
        Some(l) => (l.gate_verdict.as_str(), None),
        None => ("NOT_EVALUATED", None),
    }
}

fn score_text(s: Option<u32>) -> String {
    s.map(|v| format!("{v}%"))
        .unwrap_or_else(|| "not evaluated".into())
}

fn opt(v: &Option<String>) -> &str {
    v.as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("not detected")
}

fn count(rep: &AgentRunReport, st: &str) -> usize {
    rep.executed_results
        .iter()
        .filter(|r| r.status == st)
        .count()
}

fn llm_line(rep: &AgentRunReport) -> String {
    let stages = rep
        .stage_sources
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join(", ");
    match (&rep.llm_status, stages.is_empty()) {
        (Some(s), false) => format!("{s} [{stages}]"),
        (Some(s), true) => s.clone(),
        (None, false) => stages,
        (None, true) => "not recorded".into(),
    }
}

fn budget_line(rep: &AgentRunReport) -> String {
    match &rep.budget {
        Some(b) => format!(
            "steps {}/{}, requests {}/{}, {} ms{}{}",
            b.steps,
            b.max_steps,
            b.requests,
            b.max_requests,
            b.elapsed_ms,
            if b.max_llm_calls > 0 {
                format!(
                    ", LLM calls {}/{} ({} ms)",
                    b.llm_calls, b.max_llm_calls, b.llm_ms
                )
            } else {
                String::new()
            },
            b.stopped
                .as_ref()
                .map(|s| format!(", STOPPED: {s}"))
                .unwrap_or_default()
        ),
        None => "not recorded".into(),
    }
}

fn status_code_text(c: &CaseExecutionResult) -> String {
    c.status_code
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into())
}

/// "Verified 2/2" / "Flaky 1/2" / "Unverified" / "not run" (no verifier data for the defect).
fn defect_verification(d: &TriagedDefect) -> String {
    match d.verification.as_deref() {
        Some("confirmed") => format!("Verified {}", d.reproduced.as_deref().unwrap_or("k/k")),
        Some("flaky") => format!("Flaky {}", d.reproduced.as_deref().unwrap_or("m/k")),
        Some("unverified") => "Unverified".into(),
        _ => "not run".into(),
    }
}

fn verdict_label(v: VerifyVerdict) -> &'static str {
    match v {
        VerifyVerdict::Confirmed => "Confirmed",
        VerifyVerdict::Flaky => "Flaky",
        VerifyVerdict::NotReproduced => "Not reproduced",
        VerifyVerdict::Unverified => "Unverified",
    }
}

/// "200 12 ms, 500 9 ms": what each replay saw.
fn replays_text(r: &super::types::VerificationRecord) -> String {
    if r.replays.is_empty() {
        return "none".into();
    }
    r.replays
        .iter()
        .map(|p| {
            format!(
                "#{} {} {} ms{}",
                p.replay,
                p.status_code
                    .map(|c| format!("HTTP {c}"))
                    .unwrap_or_else(|| p.verdict.clone()),
                p.latency_ms,
                if p.reproduced { " (reproduced)" } else { "" }
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn verification_line(v: &VerificationSummary) -> String {
    if v.k == 0 {
        return "off: failures were not replayed".into();
    }
    format!(
        "k={}; {} of {} failed case(s) fully replayed ({} confirmed, {} flaky, {} not reproduced); {} unverified; {} replay request(s); pass^{} = {}{}",
        v.k,
        v.replayed,
        v.candidates,
        v.confirmed,
        v.flaky,
        v.not_reproduced,
        v.unverified,
        v.replay_requests,
        v.k,
        v.pass_k_text(),
        v.stopped
            .as_ref()
            .map(|s| format!("; stopped: {s}"))
            .unwrap_or_default()
    )
}

// ---------------------------------------------------------------- HTML

const STYLE: &str = r#"
:root{--bg:#070a13;--panel:#0d1424;--border:#1a2942;--text:#e2e8f0;--cyan:#00f0ff;--ok:#10b981;--bad:#f43f5e;--warn:#f59e0b;--mut:#94a3b8}
body{margin:0;padding:24px;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.5}
.container{max-width:1200px;margin:0 auto}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px}
h1,h2{margin:0 0 12px 0}h2{font-size:16px;letter-spacing:.05em;text-transform:uppercase}
.badge{display:inline-block;padding:4px 10px;border-radius:9999px;font:700 12px monospace;text-transform:uppercase;border:1px solid}
.badge-go{color:var(--ok);border-color:var(--ok)}.badge-nogo{color:var(--bad);border-color:var(--bad)}.badge-cond,.badge-ne{color:var(--warn);border-color:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;font:12px monospace}
.item{background:#0f172a99;padding:10px 14px;border-radius:8px;border:1px solid #16243d}.lbl{color:#64748b;font-size:11px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;font-size:13px}th{background:#090e1a;color:var(--mut);text-align:left;padding:10px 14px;font-size:11px;text-transform:uppercase}
td{padding:10px 14px;border-bottom:1px solid #131f33;vertical-align:top}.wrap{overflow-x:auto;border:1px solid var(--border);border-radius:8px}
pre{margin:0;padding:8px 12px;background:#05070d;border:1px solid #16243d;border-radius:6px;font:11px monospace;color:var(--cyan);white-space:pre-wrap;word-break:break-all}
code{font-family:monospace;color:#cbd5e1}.mut{color:var(--mut);font-size:12px}.pillars{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
.pillar{background:#090f1e;border:1px solid #1a2a44;border-radius:8px;padding:16px}.score{font:700 20px monospace;color:var(--cyan)}.ne{color:var(--warn)}
.st-PASS{color:var(--ok)}.st-FAIL{color:var(--bad)}.st-WARN,.st-INCONCLUSIVE{color:var(--warn)}.st-BLOCKED,.st-SKIPPED,.st-NOT_APPLICABLE{color:var(--mut)}
@media print{body{background:#fff;color:#000}.card{background:#fff;border-color:#ccc}td,code{color:#000!important}pre{background:#f8fafc;color:#000;border-color:#ccc}}
"#;

fn cites(case_ids: &[String], files: &[String]) -> String {
    let c = if case_ids.is_empty() {
        "none".to_string()
    } else {
        case_ids.join(", ")
    };
    let f = if files.is_empty() {
        "none".to_string()
    } else {
        files.join(", ")
    };
    format!(
        "<div class=\"mut\">cases: {} &middot; evidence: {}</div>",
        html_escape(&c),
        html_escape(&f)
    )
}

fn html_ledger(l: &EvidenceLedger) -> String {
    let mut h = String::new();
    h.push_str("<div class=\"card\"><h2>Evidence ledger (computed from results)</h2>");
    h.push_str(&format!("<p>{}</p>", html_escape(&l.executive_summary)));
    h.push_str(&format!(
        "<p class=\"mut\">Verdict basis: {}</p>",
        html_escape(&l.verdict_basis)
    ));
    if let Some(a) = &l.llm_advisory {
        h.push_str(&format!(
            "<p class=\"mut\">LLM advisory (does not change the gate): verdict {}, overall {}, value {}, authority {}, safety {}, evidence {}</p>",
            html_escape(a.verdict.as_deref().unwrap_or("none")), score_text(a.overall_readiness), score_text(a.value_score), score_text(a.authority_score), score_text(a.safety_score), score_text(a.evidence_score)
        ));
    }
    if let Some(s) = &l.ai_summary {
        h.push_str(&format!(
            "<p><span class=\"badge badge-ne\">AI-generated, advisory</span> {}</p>",
            html_escape(s)
        ));
    }
    h.push_str("<div class=\"pillars\">");
    for p in &l.pillars {
        h.push_str(&format!(
            "<div class=\"pillar\"><div class=\"lbl\">{}</div><div class=\"score{}\">{}</div><div>{}</div>{}</div>",
            html_escape(&p.name), if p.score.is_none() { " ne" } else { "" }, score_text(p.score), html_escape(&p.claim), cites(&p.case_ids, &p.evidence_files)
        ));
    }
    h.push_str("</div></div>");

    h.push_str("<div class=\"card\"><h2>Technique coverage matrix</h2><div class=\"wrap\"><table><thead><tr><th>Technique</th><th>Planned</th><th>Pass</th><th>Warn</th><th>Fail</th><th>Inconclusive</th><th>Blocked</th><th>Not run</th><th>Flaky</th></tr></thead><tbody>");
    for c in &l.coverage {
        h.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&c.technique), c.planned, c.pass, c.warn, c.fail, c.inconclusive, c.blocked, c.skipped, c.flaky
        ));
    }
    h.push_str("</tbody></table></div></div>");

    h.push_str("<div class=\"card\"><h2>Claims and exit criteria</h2><div class=\"wrap\"><table><thead><tr><th>Claim</th><th>Status</th><th>Cited cases / evidence</th></tr></thead><tbody>");
    for c in &l.claims {
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&c.claim),
            html_escape(&c.status),
            cites(&c.case_ids, &c.evidence_files)
        ));
    }
    for e in &l.exit_criteria_checklist {
        h.push_str(&format!(
            "<tr><td>{} <span class=\"mut\">{}</span></td><td class=\"{}\">{}</td><td>{}</td></tr>",
            html_escape(&e.criterion),
            html_escape(&e.details),
            if e.met { "st-PASS" } else { "st-FAIL" },
            if e.met { "met" } else { "not met" },
            cites(&e.case_ids, &e.evidence_files)
        ));
    }
    h.push_str("</tbody></table></div></div>");
    h
}

fn html_verification(rep: &AgentRunReport, v: &VerificationSummary) -> String {
    let mut h = String::new();
    h.push_str("<div class=\"card\"><h2>Verification (independent replay)</h2>");
    h.push_str(&format!(
        "<p>Every FAIL is replayed k times by a verifier that rebuilds the request from the stored case, attaches fresh credentials and judges the answer with the same oracle. A failure that does not reproduce is INCONCLUSIVE, not a defect. <b>pass^k</b> is the share of replayed failures that reproduced on all k replays. State-changing requests that are not safe to repeat are marked unverified and stay as they were.</p><p class=\"mut\">{}</p>",
        html_escape(&verification_line(v))
    ));
    h.push_str("<div class=\"grid\">");
    let items: Vec<(&str, String)> = vec![
        ("Replays per failure (k)", v.k.to_string()),
        ("pass^k", v.pass_k_text()),
        ("Confirmed", v.confirmed.to_string()),
        ("Flaky", v.flaky.to_string()),
        ("Not reproduced", v.not_reproduced.to_string()),
        ("Unverified", v.unverified.to_string()),
        ("Replay requests", v.replay_requests.to_string()),
    ];
    for (k, val) in items {
        h.push_str(&format!(
            "<div class=\"item\"><div class=\"lbl\">{}</div><div>{}</div></div>",
            html_escape(k),
            html_escape(&val)
        ));
    }
    h.push_str("</div>");
    if !v.records.is_empty() {
        h.push_str("<div class=\"wrap\" style=\"margin-top:16px\"><table><thead><tr><th>Case</th><th>Verdict</th><th>Reproduced</th><th>Replays</th><th>Result</th></tr></thead><tbody>");
        for r in &v.records {
            h.push_str(&format!(
                "<tr><td><code>{}</code><div class=\"mut\">{} {}</div></td><td><b>{}</b><div class=\"mut\">{} severity</div></td><td>{}</td><td>{}{}</td><td>{} &rarr; {}{}</td></tr>",
                html_escape(&r.case_id), html_escape(&r.method), html_escape(&r.component),
                verdict_label(r.verdict), html_escape(&r.severity),
                html_escape(&r.ratio().unwrap_or_else(|| "-".into())),
                html_escape(&replays_text(r)),
                r.note.as_ref().map(|n| format!("<div class=\"mut\">{}</div>", html_escape(n))).unwrap_or_default(),
                html_escape(&r.original_status), html_escape(&r.final_status),
                r.evidence_file.as_ref().map(|f| format!("<div class=\"mut\">evidence: {}</div>", html_escape(f))).unwrap_or_default()
            ));
        }
        h.push_str("</tbody></table></div>");
    }
    let defects: Vec<&TriagedDefect> = rep.triaged_defects.iter().collect();
    if !defects.is_empty() {
        h.push_str("<div class=\"wrap\" style=\"margin-top:16px\"><table><thead><tr><th>Defect</th><th>Severity</th><th>Verification</th><th>Blocking</th></tr></thead><tbody>");
        for d in defects {
            h.push_str(&format!(
                "<tr><td><code>{}</code> {}</td><td>{}</td><td>{}{}</td><td>{}</td></tr>",
                html_escape(&d.id),
                html_escape(&d.title),
                html_escape(&d.severity.to_uppercase()),
                html_escape(&defect_verification(d)),
                if d.flaky {
                    " <span class=\"badge badge-ne\">flaky</span>"
                } else {
                    ""
                },
                if super::ledger::is_blocking(d) {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        h.push_str("</tbody></table></div>");
    }
    h.push_str("</div>");
    h
}

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

// ---------------------------------------------------------------- since last run

fn acceptance_text(l: &DefectLine) -> String {
    l.accepted
        .as_ref()
        .map(|a| format!("accepted by {} until {}: {}", a.by, a.expires, a.reason))
        .unwrap_or_default()
}

fn line_note(l: &DefectLine) -> String {
    [acceptance_text(l), l.note.clone().unwrap_or_default()]
        .into_iter()
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

fn since_title(s: &SinceLastRun) -> String {
    match (&s.previous_run, &s.previous_at) {
        (Some(r), Some(at)) => format!(
            "{}. Compared with run {r} ({at}); {} run(s) remembered.",
            s.summary_line(),
            s.runs_remembered
        ),
        _ => format!("{}.", s.summary_line()),
    }
}

fn md_defect_lines(title: &str, lines: &[DefectLine], what: &str) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut md = format!("### {title} ({})\n\n{what}\n\n", lines.len());
    md.push_str("| Severity | Defect | Rule | Endpoint | First seen | Last seen | Seen | Fingerprint | Note |\n| :--- | :--- | :--- | :--- | :--- | :--- | ---: | :--- | :--- |\n");
    for l in lines {
        md.push_str(&format!(
            "| **{}** | {} | {} | {} | {} | {} | {}x | {} | {} |\n",
            md_text(&l.severity.to_uppercase()),
            md_text(l.defect_id.as_deref().unwrap_or("-")),
            md_code(&l.rule),
            md_code(&l.endpoint),
            md_text(&l.first_seen),
            md_text(&l.last_seen),
            l.runs_seen,
            md_code(&l.fingerprint),
            md_text(&line_note(l))
        ));
    }
    md.push('\n');
    md
}

/// "Since last run": what the agent's memory says changed since the previous run against this target.
fn md_since_last_run(s: &SinceLastRun) -> String {
    let mut md = String::from("## Since last run\n\n");
    md.push_str(&format!("{}\n\n", md_text(&since_title(s))));
    md.push_str(&md_defect_lines(
        "New",
        &s.new,
        "Found in this run, never seen before.",
    ));
    md.push_str(&md_defect_lines(
        "Still open",
        &s.still_open,
        "Known from an earlier run and found again.",
    ));
    md.push_str(&md_defect_lines(
        "Fixed",
        &s.fixed,
        "Known as open; every reproduction case ran and passed in this run.",
    ));
    md.push_str(&md_defect_lines(
        "Regressed",
        &s.regressed,
        "Known as fixed and found again.",
    ));
    md.push_str(&md_defect_lines("Not re-tested", &s.not_retested, "Known as open but not seen: its reproduction cases did not run cleanly, so it is not called fixed."));
    if !s.known_flaky.is_empty() {
        md.push_str(&format!("### Known flaky ({})\n\nCase classes that failed on some attempts in the remembered runs.\n\n| Case class | Operation | Pass | Fail | Flaky |\n| :--- | :--- | ---: | ---: | ---: |\n", s.known_flaky.len()));
        for f in &s.known_flaky {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                md_code(&f.class),
                md_code(&f.operation),
                f.pass,
                f.fail,
                f.flaky
            ));
        }
        md.push('\n');
    }
    md.push_str(&md_defect_lines("Accepted", &s.accepted, "An operator accepted these until the date shown: they are listed, do not block the gate, and their failing cases are not scored."));
    md.push_str(&md_defect_lines(
        "Acceptance expired",
        &s.expired,
        "The acceptance has run out: these block again.",
    ));
    if !s.regression_probes.is_empty() {
        md.push_str(&format!(
            "### Regression probes ({})\n\nPlanned cases that re-test known defects; they come first in the plan.\n\n| Case | Case class | Defects |\n| :--- | :--- | :--- |\n",
            s.regression_probes.len()
        ));
        for p in &s.regression_probes {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                md_code(&p.case_id),
                md_code(&p.class),
                md_text(&p.defects.join(", "))
            ));
        }
        md.push('\n');
    }
    for n in &s.notes {
        md.push_str(&format!("- note: {}\n", md_text(n)));
    }
    if !s.notes.is_empty() {
        md.push('\n');
    }
    md
}

fn html_defect_lines(title: &str, lines: &[DefectLine], what: &str) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut h = format!(
        "<h3>{} ({})</h3><p class=\"mut\">{}</p><div class=\"wrap\"><table><thead><tr><th>Severity</th><th>Defect</th><th>Rule / endpoint</th><th>First / last seen</th><th>Note</th></tr></thead><tbody>",
        html_escape(title),
        lines.len(),
        html_escape(what)
    );
    for l in lines {
        h.push_str(&format!(
            "<tr><td><b>{}</b></td><td>{}<div class=\"mut\">{}</div></td><td><code>{}</code> <code>{}</code></td><td>{} / {} ({}x)</td><td>{}</td></tr>",
            html_escape(&l.severity.to_uppercase()),
            html_escape(l.defect_id.as_deref().unwrap_or("-")),
            html_escape(&l.fingerprint),
            html_escape(&l.rule),
            html_escape(&l.endpoint),
            html_escape(&l.first_seen),
            html_escape(&l.last_seen),
            l.runs_seen,
            html_escape(&line_note(l))
        ));
    }
    h.push_str("</tbody></table></div>");
    h
}

fn html_since_last_run(s: &SinceLastRun) -> String {
    let mut h = format!(
        "<div class=\"card\"><h2>Since last run</h2><p>{}</p>",
        html_escape(&since_title(s))
    );
    h.push_str(&html_defect_lines(
        "New",
        &s.new,
        "Found in this run, never seen before.",
    ));
    h.push_str(&html_defect_lines(
        "Still open",
        &s.still_open,
        "Known from an earlier run and found again.",
    ));
    h.push_str(&html_defect_lines(
        "Fixed",
        &s.fixed,
        "Known as open; every reproduction case ran and passed in this run.",
    ));
    h.push_str(&html_defect_lines(
        "Regressed",
        &s.regressed,
        "Known as fixed and found again.",
    ));
    h.push_str(&html_defect_lines("Not re-tested", &s.not_retested, "Known as open but not seen: its reproduction cases did not run cleanly, so it is not called fixed."));
    if !s.known_flaky.is_empty() {
        h.push_str(&format!("<h3>Known flaky ({})</h3><div class=\"wrap\"><table><thead><tr><th>Case class</th><th>Operation</th><th>Pass</th><th>Fail</th><th>Flaky</th></tr></thead><tbody>", s.known_flaky.len()));
        for f in &s.known_flaky {
            h.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&f.class),
                html_escape(&f.operation),
                f.pass,
                f.fail,
                f.flaky
            ));
        }
        h.push_str("</tbody></table></div>");
    }
    h.push_str(&html_defect_lines("Accepted", &s.accepted, "An operator accepted these until the date shown: they are listed, do not block the gate, and their failing cases are not scored."));
    h.push_str(&html_defect_lines(
        "Acceptance expired",
        &s.expired,
        "The acceptance has run out: these block again.",
    ));
    if !s.regression_probes.is_empty() {
        h.push_str(&format!("<h3>Regression probes ({})</h3><p class=\"mut\">Planned cases that re-test known defects; they come first in the plan.</p><div class=\"wrap\"><table><thead><tr><th>Case</th><th>Case class</th><th>Defects</th></tr></thead><tbody>", s.regression_probes.len()));
        for p in &s.regression_probes {
            h.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                html_escape(&p.case_id),
                html_escape(&p.class),
                html_escape(&p.defects.join(", "))
            ));
        }
        h.push_str("</tbody></table></div>");
    }
    for n in &s.notes {
        h.push_str(&format!("<p class=\"mut\">note: {}</p>", html_escape(n)));
    }
    h.push_str("</div>");
    h
}

// ---------------------------------------------------------------- change impact

/// Files named in the report text (the list in the data is capped at `change::MAX_LISTED_FILES`).
const SHOWN_FILES: usize = 40;

fn via_text(via: &str) -> &'static str {
    if via == "route" {
        "route matched"
    } else {
        "file changed, routes unknown"
    }
}

fn status_text(ci: &ChangeImpact) -> &'static str {
    match ci.status.as_str() {
        "applied" => "applied: changed operations were planned in full and first",
        "no_changes" => "no changed files: the plan is what the profile gives",
        "unmapped" => "no changed file maps to an operation: the plan is what the profile gives",
        "skipped" => "skipped: no OpenAPI spec to map the changes onto",
        "failed" => "failed: the plan is what the profile gives",
        _ => "unknown",
    }
}

/// (sent, planned, percent) over the cases that test a changed operation.
fn change_totals(ci: &ChangeImpact) -> (usize, usize, String) {
    let (sent, planned) = super::change::coverage_totals(&ci.coverage);
    let pct = (sent * 100)
        .checked_div(planned)
        .map_or("n/a".to_string(), |p| format!("{p}%"));
    (sent, planned, pct)
}

fn md_change_impact(ci: &ChangeImpact) -> String {
    let (sent, planned, pct) = change_totals(ci);
    let mut md = String::from("## Change impact\n\n");
    md.push_str(&format!(
        "`git diff {}...HEAD` in {}: **{}** changed file(s), **{}** changed operation(s), **{}** file(s) mapped to no operation. Status: {}.\n\n",
        md_code(&ci.diff_base).trim_matches('`'),
        md_code(&ci.repo),
        ci.changed_files_total,
        ci.operations.len(),
        ci.unmapped_total,
        md_text(status_text(ci))
    ));
    if !ci.operations.is_empty() {
        md.push_str(&format!(
            "**Coverage of changed operations:** {sent} of {planned} planned case(s) sent ({pct}).\n\n"
        ));
        md.push_str("| Operation | Found by | Files | Planned | Sent | Pass | Fail | Other | Techniques |\n| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | :--- |\n");
        for o in &ci.operations {
            let c = ci.coverage.iter().find(|c| c.operation == o.operation);
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                md_code(&o.operation),
                md_text(via_text(&o.via)),
                md_text(&o.files.join(", ")),
                c.map_or("-".into(), |c| c.planned.to_string()),
                c.map_or("-".into(), |c| c.executed.to_string()),
                c.map_or("-".into(), |c| c.pass.to_string()),
                c.map_or("-".into(), |c| c.fail.to_string()),
                c.map_or("-".into(), |c| c.inconclusive.to_string()),
                md_text(&c.map(|c| c.techniques.join(", ")).unwrap_or_default())
            ));
        }
        md.push('\n');
    }
    let list = |md: &mut String, title: &str, files: &[String], total: usize| {
        if files.is_empty() {
            return;
        }
        md.push_str(&format!("### {title} ({total})\n\n"));
        for f in files.iter().take(SHOWN_FILES) {
            md.push_str(&format!("- {}\n", md_code(f)));
        }
        if total > SHOWN_FILES.min(files.len()) {
            md.push_str(&format!(
                "- ... and {} more\n",
                total - SHOWN_FILES.min(files.len())
            ));
        }
        md.push('\n');
    };
    list(
        &mut md,
        "Changed files",
        &ci.changed_files,
        ci.changed_files_total,
    );
    list(
        &mut md,
        "Unmapped files",
        &ci.unmapped_files,
        ci.unmapped_total,
    );
    for n in &ci.notes {
        md.push_str(&format!("- {}\n", md_text(n)));
    }
    if !ci.notes.is_empty() {
        md.push('\n');
    }
    if !ci.context_notes.is_empty() {
        md.push_str("### Context from the retriever (untrusted, advisory)\n\nText from the code index. It is quoted as data, adds no test case and changes no verdict.\n\n");
        // no renderer or sanitizer may ever see a raw tag in text that came from an index
        let body: String = ci
            .context_notes
            .join("\n")
            .chars()
            .filter(|c| !c.is_control() || *c == '\n')
            .map(|c| match c {
                '<' => '\u{2039}',
                '>' => '\u{203a}',
                c => c,
            })
            .collect();
        md.push_str(&md_fence(&body, "text"));
        md.push('\n');
    }
    md
}

fn html_change_impact(ci: &ChangeImpact) -> String {
    let (sent, planned, pct) = change_totals(ci);
    let mut h = String::from("<div class=\"card\"><h2>Change impact</h2>");
    h.push_str(&format!(
        "<p><code>git diff {}...HEAD</code> in <code>{}</code>: <b>{}</b> changed file(s), <b>{}</b> changed operation(s), <b>{}</b> file(s) mapped to no operation.</p><p class=\"mut\">Status: {}</p>",
        html_escape(&ci.diff_base),
        html_escape(&ci.repo),
        ci.changed_files_total,
        ci.operations.len(),
        ci.unmapped_total,
        html_escape(status_text(ci))
    ));
    if !ci.operations.is_empty() {
        h.push_str(&format!(
            "<p><b>Coverage of changed operations:</b> {sent} of {planned} planned case(s) sent ({}).</p>",
            html_escape(&pct)
        ));
        h.push_str("<div class=\"wrap\"><table><thead><tr><th>Operation</th><th>Found by</th><th>Files</th><th>Planned</th><th>Sent</th><th>Pass</th><th>Fail</th><th>Other</th><th>Techniques</th></tr></thead><tbody>");
        for o in &ci.operations {
            let c = ci.coverage.iter().find(|c| c.operation == o.operation);
            let n = |f: fn(&super::types::ChangedOpCoverage) -> usize| {
                c.map_or("-".to_string(), |c| f(c).to_string())
            };
            h.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}<div class=\"mut\">{}</div></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&o.operation),
                html_escape(via_text(&o.via)),
                html_escape(&o.detail),
                html_escape(&o.files.join(", ")),
                n(|c| c.planned),
                n(|c| c.executed),
                n(|c| c.pass),
                n(|c| c.fail),
                n(|c| c.inconclusive),
                html_escape(&c.map(|c| c.techniques.join(", ")).unwrap_or_default())
            ));
        }
        h.push_str("</tbody></table></div>");
    }
    let list = |h: &mut String, title: &str, files: &[String], total: usize| {
        if files.is_empty() {
            return;
        }
        h.push_str(&format!("<h3>{} ({total})</h3><ul>", html_escape(title)));
        for f in files.iter().take(SHOWN_FILES) {
            h.push_str(&format!("<li><code>{}</code></li>", html_escape(f)));
        }
        if total > SHOWN_FILES.min(files.len()) {
            h.push_str(&format!(
                "<li class=\"mut\">... and {} more</li>",
                total - SHOWN_FILES.min(files.len())
            ));
        }
        h.push_str("</ul>");
    };
    list(
        &mut h,
        "Changed files",
        &ci.changed_files,
        ci.changed_files_total,
    );
    list(
        &mut h,
        "Unmapped files",
        &ci.unmapped_files,
        ci.unmapped_total,
    );
    for n in &ci.notes {
        h.push_str(&format!("<p class=\"mut\">note: {}</p>", html_escape(n)));
    }
    if !ci.context_notes.is_empty() {
        h.push_str("<h3>Context from the retriever <span class=\"badge badge-ne\">untrusted, advisory</span></h3><p class=\"mut\">Text from the code index, shown as data. It adds no test case and changes no verdict.</p>");
        h.push_str(&format!(
            "<pre>{}</pre>",
            html_escape(&ci.context_notes.join("\n"))
        ));
    }
    h.push_str("</div>");
    h
}

// ---------------------------------------------------------------- agents (the lead and its areas)

fn secs(ms: u64) -> String {
    format!("{:.1}s", ms as f64 / 1000.0)
}

/// `used/allocated` of one dimension, wave 1 and (when the area had one) wave 2.
fn used_of(a: &AreaReport, f: fn(&Quota) -> String, g: fn(&Quota) -> String) -> String {
    let one = |b: &AreaBudget| format!("{}/{}", f(&b.used), g(&b.allocated));
    match &a.wave2_budget {
        Some(w) => format!("{} + w2 {}", one(&a.budget), one(w)),
        None => one(&a.budget),
    }
}

fn area_cells(a: &AreaReport) -> [String; 5] {
    [
        used_of(a, |q| q.steps.to_string(), |q| q.steps.to_string()),
        used_of(a, |q| q.requests.to_string(), |q| q.requests.to_string()),
        used_of(a, |q| secs(q.wall_ms), |q| secs(q.wall_ms)),
        used_of(a, |q| q.llm_calls.to_string(), |q| q.llm_calls.to_string()),
        if a.defect_ids.is_empty() {
            "-".into()
        } else {
            a.defect_ids.join(", ")
        },
    ]
}

fn pool_text(a: &AgentsReport) -> String {
    let q = |q: &Quota| {
        format!(
            "{} step(s), {} request(s), {}",
            q.steps,
            q.requests,
            secs(q.wall_ms)
        )
    };
    format!(
        "pool: reserve {}; reclaimed from the areas {}; granted to wave 2 {}; left at the end {}",
        q(&a.pool_reserve),
        q(&a.pool_reclaimed),
        q(&a.pool_granted_wave2),
        q(&a.pool_left)
    )
}

fn md_agents(a: &AgentsReport) -> String {
    let mut md = String::from("## Agents\n\n");
    md.push_str(&format!(
        "The lead split the plan into areas and ran **{}** worker(s) over **{}** wave(s) ({}). Budget columns are used/allocated.\n\n{}\n\n",
        a.workers,
        a.waves,
        md_text(&a.status),
        md_text(&pool_text(a))
    ));
    md.push_str("| Area | Status | Cases | Sent | Pass | Fail | Other | Steps | Requests | Wall | LLM calls | Defects |\n| :--- | :--- | ---: | ---: | ---: | ---: | ---: | :--- | :--- | :--- | :--- | :--- |\n");
    for x in &a.areas {
        let [steps, reqs, wall, llm, defects] = area_cells(x);
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_code(&x.area),
            md_text(&x.status),
            x.cases,
            x.executed,
            x.pass,
            x.fail,
            x.warn + x.inconclusive + x.blocked + x.skipped,
            md_text(&steps),
            md_text(&reqs),
            md_text(&wall),
            md_text(&llm),
            md_text(&defects)
        ));
    }
    md.push('\n');
    for x in a
        .areas
        .iter()
        .filter(|x| x.stopped.is_some() || x.error.is_some())
    {
        md.push_str(&format!(
            "- {}: {}\n",
            md_code(&x.area),
            md_text(
                x.error
                    .as_deref()
                    .or(x.stopped.as_deref())
                    .unwrap_or_default()
            )
        ));
    }
    if !a.wave2.is_empty() {
        md.push_str("\n### Wave 2 additions\n\n| Case | Area | Rule | Origin | Why |\n| :--- | :--- | :--- | :--- | :--- |\n");
        for w in &a.wave2 {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                md_code(&w.case_id),
                md_code(&w.area),
                md_text(&w.rule),
                md_code(&w.origin),
                md_text(&w.reason)
            ));
        }
    }
    for n in &a.notes {
        md.push_str(&format!("\n- {}", md_text(n)));
    }
    md.push_str("\n\n");
    md
}

fn html_agents(a: &AgentsReport) -> String {
    let mut h = String::from("<div class=\"card\"><h2>Agents</h2>");
    h.push_str(&format!(
        "<p>The lead split the plan into areas and ran <b>{}</b> worker(s) over <b>{}</b> wave(s) ({}). Budget columns are used/allocated.</p><p class=\"mut\">{}</p>",
        a.workers,
        a.waves,
        html_escape(&a.status),
        html_escape(&pool_text(a))
    ));
    h.push_str("<div class=\"wrap\"><table><thead><tr><th>Area</th><th>Status</th><th>Cases</th><th>Sent</th><th>Pass</th><th>Fail</th><th>Other</th><th>Steps</th><th>Requests</th><th>Wall</th><th>LLM calls</th><th>Defects</th></tr></thead><tbody>");
    for x in &a.areas {
        let [steps, reqs, wall, llm, defects] = area_cells(x);
        h.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&x.area),
            html_escape(&x.status),
            x.cases,
            x.executed,
            x.pass,
            x.fail,
            x.warn + x.inconclusive + x.blocked + x.skipped,
            html_escape(&steps),
            html_escape(&reqs),
            html_escape(&wall),
            html_escape(&llm),
            html_escape(&defects)
        ));
    }
    h.push_str("</tbody></table></div>");
    for x in a
        .areas
        .iter()
        .filter(|x| x.stopped.is_some() || x.error.is_some())
    {
        h.push_str(&format!(
            "<p class=\"mut\"><code>{}</code>: {}</p>",
            html_escape(&x.area),
            html_escape(
                x.error
                    .as_deref()
                    .or(x.stopped.as_deref())
                    .unwrap_or_default()
            )
        ));
    }
    if !a.wave2.is_empty() {
        h.push_str("<h3>Wave 2 additions</h3><div class=\"wrap\"><table><thead><tr><th>Case</th><th>Area</th><th>Rule</th><th>Origin</th><th>Why</th></tr></thead><tbody>");
        for w in &a.wave2 {
            h.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                html_escape(&w.case_id),
                html_escape(&w.area),
                html_escape(&w.rule),
                html_escape(&w.origin),
                html_escape(&w.reason)
            ));
        }
        h.push_str("</tbody></table></div>");
    }
    for n in &a.notes {
        h.push_str(&format!("<p class=\"mut\">note: {}</p>", html_escape(n)));
    }
    h.push_str("</div>");
    h
}

// ---------------------------------------------------------------- Markdown

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
            md.push_str(&format!(
                "- [{}] {} - {}\n",
                if e.met { "x" } else { " " },
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
                        if super::ledger::is_blocking(d) {
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

    md.push_str("## Executed scenarios\n\n| ID | Method | Component | Technique | Status | HTTP | Latency |\n| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");
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
        md.push_str("## Defects\n\n| Severity | Defect | Category | Verification | Cases | Remediation |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n");
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

// ---------------------------------------------------------------- SARIF

fn sarif_level(sev: &str) -> &'static str {
    match sev.to_ascii_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

pub fn generate_agent_sarif_report(rep: &AgentRunReport) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = vec![];
    let mut results = vec![];
    for d in &rep.triaged_defects {
        let slug: String = d
            .owasp_category
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '-'
                }
            })
            .collect();
        let rule_id = format!("READYHAI-{}", slug.trim_matches('-'));
        let idx = match rules.iter().position(|r| r["id"] == rule_id) {
            Some(i) => i,
            None => {
                rules.push(serde_json::json!({
                    "id": rule_id, "name": d.owasp_category, "shortDescription": {"text": d.owasp_category}, "fullDescription": {"text": d.recommended_fix},
                    "defaultConfiguration": {"level": sarif_level(&d.severity)}
                }));
                rules.len() - 1
            }
        };
        let mut result = serde_json::json!({
            "ruleId": rule_id, "ruleIndex": idx, "level": sarif_level(&d.severity),
            "message": {"text": format!("{}: {}", d.title, d.recommended_fix)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": d.component}}}],
            "properties": {"defectId": d.id, "severity": d.severity, "priority": d.priority, "caseIds": d.case_ids, "evidenceFiles": d.evidence_files, "verified": d.verified, "reproduced": d.reproduced, "verification": d.verification, "flaky": d.flaky}
        });
        if !d.fingerprint.is_empty() {
            result["partialFingerprints"] = serde_json::json!({"readyhai/v1": d.fingerprint});
        }
        if let Some(sc) = &d.source_context {
            result["properties"]["sourceContext"] = serde_json::json!(sc);
        }
        if let Some(a) = &d.accepted {
            // an operator accepted it until `expires`: SARIF's own way to say "listed, not blocking"
            result["suppressions"] = serde_json::json!([{
                "kind": "external", "status": "accepted",
                "justification": format!("accepted by {} until {}: {}", a.by, a.expires, a.reason)
            }]);
        }
        results.push(result);
    }
    let mut props = serde_json::Map::new();
    if let Some(ip) = rep.requester_ip.as_deref().filter(|s| !s.is_empty()) {
        props.insert("requesterIp".into(), ip.into());
    }
    if let Some(g) = rep.allowlist_guidance.as_deref().filter(|s| !s.is_empty()) {
        props.insert("allowlistGuidance".into(), g.into());
    }
    props.insert("gateVerdict".into(), verdict_of(rep).0.into());
    if let Some(v) = rep
        .evidence_ledger
        .as_ref()
        .and_then(|l| l.verification.as_ref())
    {
        props.insert(
            "verification".into(),
            serde_json::json!({"k": v.k, "confirmed": v.confirmed, "flaky": v.flaky, "notReproduced": v.not_reproduced, "unverified": v.unverified, "passK": v.pass_k}),
        );
    }
    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ReadyHai Agent QA Gate", "version": env!("CARGO_PKG_VERSION"), "informationUri": "https://github.com/deziss/readyhai", "rules": rules}},
            "properties": props,
            "results": results
        }]
    })
}

// ---------------------------------------------------------------- JUnit

pub fn generate_agent_junit_report(rep: &AgentRunReport) -> String {
    let rs = &rep.executed_results;
    // failing cases of a defect an operator accepted (unexpired) are reported as skipped, with why
    let accepted: std::collections::BTreeMap<&str, &super::memory::Acceptance> = rep
        .triaged_defects
        .iter()
        .filter_map(|d| d.accepted.as_ref().map(|a| (d, a)))
        .flat_map(|(d, a)| d.case_ids.iter().map(move |c| (c.as_str(), a)))
        .collect();
    let is_accepted =
        |c: &CaseExecutionResult| c.status == "FAIL" && accepted.contains_key(c.case_id.as_str());
    let failures = rs
        .iter()
        .filter(|c| c.status == "FAIL" && !is_accepted(c))
        .count();
    let errors = rs.iter().filter(|c| c.status == "BLOCKED").count();
    let skipped = rs
        .iter()
        .filter(|c| c.status == "SKIPPED" || c.status == "INCONCLUSIVE" || is_accepted(c))
        .count();
    let time: f64 = rs.iter().map(|c| c.latency_ms as f64 / 1000.0).sum();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"ReadyHai QA Agent\" tests=\"{}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\" time=\"{time:.3}\">\n",
        rs.len()
    );
    let mut sysout = vec![format!("gate verdict: {}", verdict_of(rep).0)];
    if let Some(ip) = rep.requester_ip.as_deref().filter(|s| !s.is_empty()) {
        sysout.push(format!("requester egress IP: {ip}"));
    }
    if let Some(g) = rep.allowlist_guidance.as_deref().filter(|s| !s.is_empty()) {
        sysout.push(format!("allowlist guidance: {g}"));
    }
    xml.push_str(&format!(
        "  <system-out>{}</system-out>\n",
        xml_escape(&sysout.join("\n"))
    ));
    for c in rs {
        let name = xml_escape(&format!("{}: {}", c.case_id, c.title));
        let class = xml_escape(&c.technique);
        let time = c.latency_ms as f64 / 1000.0;
        let reason = c.failure_reason.as_deref().unwrap_or("");
        let body = match c.status.as_str() {
            "FAIL" if is_accepted(c) => {
                let a = accepted[c.case_id.as_str()];
                format!(
                    "<skipped message=\"{}\"/>",
                    xml_escape(&format!(
                        "accepted defect, does not block: by {} until {}: {}",
                        a.by, a.expires, a.reason
                    ))
                )
            }
            "FAIL" => format!(
                "<failure message=\"{}\" type=\"{}\">{}</failure>",
                xml_escape(if reason.is_empty() {
                    "assertion failed"
                } else {
                    reason
                }),
                xml_escape(
                    c.oracle
                        .as_ref()
                        .and_then(|o| o.first_fail())
                        .map(|k| k.code.as_str())
                        .unwrap_or("assertion")
                ),
                xml_escape(&c.reproduction_curl)
            ),
            "BLOCKED" => format!(
                "<error message=\"{}\" type=\"transport\">{}</error>",
                xml_escape(reason),
                xml_escape(&c.reproduction_curl)
            ),
            "SKIPPED" => format!("<skipped message=\"{}\"/>", xml_escape(reason)),
            "INCONCLUSIVE" => format!(
                "<skipped message=\"{}\"/>",
                xml_escape(&format!("inconclusive: {reason}"))
            ),
            _ if !reason.is_empty() => format!("<system-out>{}</system-out>", xml_escape(reason)),
            _ => String::new(),
        };
        if body.is_empty() {
            xml.push_str(&format!(
                "  <testcase classname=\"{class}\" name=\"{name}\" time=\"{time:.3}\"/>\n"
            ));
        } else {
            xml.push_str(&format!("  <testcase classname=\"{class}\" name=\"{name}\" time=\"{time:.3}\">\n    {body}\n  </testcase>\n"));
        }
    }
    xml.push_str("</testsuite>\n");
    xml
}

pub fn generate_agent_report_formats(
    rep: &AgentRunReport,
    dir: &std::path::Path,
    formats: &[String],
) -> anyhow::Result<Vec<std::path::PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut out = vec![];
    for f in formats {
        let (name, body) = match f.as_str() {
            "html" => ("readyhai-report.html", generate_agent_html_report(rep)),
            "json" => ("readyhai-report.json", serde_json::to_string_pretty(rep)?),
            "markdown" | "md" => ("readyhai-report.md", generate_agent_markdown_report(rep)),
            "sarif" => (
                "readyhai-report.sarif",
                serde_json::to_string_pretty(&generate_agent_sarif_report(rep))?,
            ),
            "junit" | "xml" => (
                "readyhai-report.junit.xml",
                generate_agent_junit_report(rep),
            ),
            _ => continue,
        };
        let p = dir.join(name);
        crate::llm::write_atomic(&p, body.as_bytes())?;
        out.push(p);
    }
    Ok(out)
}
