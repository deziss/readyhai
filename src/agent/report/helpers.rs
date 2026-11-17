use crate::agent::memory::{DefectLine, SinceLastRun};
use crate::agent::types::{
    AgentRunReport, AgentsReport, AreaBudget, AreaReport, CaseExecutionResult, ChangeImpact,
    Quota, TriagedDefect, VerificationRecord, VerificationSummary, VerifyVerdict,
};

pub const SHOWN_FILES: usize = 40;

pub const STYLE: &str = r#"
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

pub fn html_escape(s: &str) -> String {
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
pub fn xml_escape(s: &str) -> String {
    let legal = |c: &char| {
        matches!(*c, '\t' | '\n' | '\r')
            || (*c as u32) >= 0x20 && !matches!(*c as u32, 0xFFFE | 0xFFFF)
    };
    html_escape(&s.chars().filter(legal).collect::<String>()).replace('\n', "&#10;")
}

/// Markdown text (table cell / inline): neutralise formatting, HTML, links and line breaks.
pub fn md_text(s: &str) -> String {
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
pub fn md_code(s: &str) -> String {
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
pub fn md_fence(body: &str, lang: &str) -> String {
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

pub fn verdict_of(rep: &AgentRunReport) -> (&str, Option<u32>) {
    match &rep.evidence_ledger {
        Some(l) if l.evaluated => (l.gate_verdict.as_str(), Some(l.overall_readiness)),
        Some(l) => (l.gate_verdict.as_str(), None),
        None => ("NOT_EVALUATED", None),
    }
}

pub fn score_text(s: Option<u32>) -> String {
    s.map(|v| format!("{v}%"))
        .unwrap_or_else(|| "not evaluated".into())
}

pub fn opt(v: &Option<String>) -> &str {
    v.as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("not detected")
}

pub fn count(rep: &AgentRunReport, st: &str) -> usize {
    rep.executed_results
        .iter()
        .filter(|r| r.status == st)
        .count()
}

pub fn llm_line(rep: &AgentRunReport) -> String {
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

pub fn budget_line(rep: &AgentRunReport) -> String {
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

pub fn status_code_text(c: &CaseExecutionResult) -> String {
    c.status_code
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into())
}

pub fn defect_verification(d: &TriagedDefect) -> String {
    match d.verification.as_deref() {
        Some("confirmed") => format!("Verified {}", d.reproduced.as_deref().unwrap_or("k/k")),
        Some("flaky") => format!("Flaky {}", d.reproduced.as_deref().unwrap_or("m/k")),
        Some("unverified") => "Unverified".into(),
        _ => "not run".into(),
    }
}

pub fn verdict_label(v: VerifyVerdict) -> &'static str {
    match v {
        VerifyVerdict::Confirmed => "Confirmed",
        VerifyVerdict::Flaky => "Flaky",
        VerifyVerdict::NotReproduced => "Not reproduced",
        VerifyVerdict::Unverified => "Unverified",
    }
}

pub fn replays_text(r: &VerificationRecord) -> String {
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

pub fn verification_line(v: &VerificationSummary) -> String {
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

pub fn cites(case_ids: &[String], files: &[String]) -> String {
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

pub fn acceptance_text(l: &DefectLine) -> String {
    l.accepted
        .as_ref()
        .map(|a| format!("accepted by {} until {}: {}", a.by, a.expires, a.reason))
        .unwrap_or_default()
}

pub fn line_note(l: &DefectLine) -> String {
    [acceptance_text(l), l.note.clone().unwrap_or_default()]
        .into_iter()
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn since_title(s: &SinceLastRun) -> String {
    match (&s.previous_run, &s.previous_at) {
        (Some(r), Some(at)) => format!(
            "{}. Compared with run {r} ({at}); {} run(s) remembered.",
            s.summary_line(),
            s.runs_remembered
        ),
        _ => format!("{}.", s.summary_line()),
    }
}

pub fn via_text(via: &str) -> &'static str {
    if via == "route" {
        "route matched"
    } else {
        "file changed, routes unknown"
    }
}

pub fn status_text(ci: &ChangeImpact) -> &'static str {
    match ci.status.as_str() {
        "applied" => "applied: changed operations were planned in full and first",
        "no_changes" => "no changed files: the plan is what the profile gives",
        "unmapped" => "no changed file maps to an operation: the plan is what the profile gives",
        "skipped" => "skipped: no OpenAPI spec to map the changes onto",
        "failed" => "failed: the plan is what the profile gives",
        _ => "unknown",
    }
}

pub fn change_totals(ci: &ChangeImpact) -> (usize, usize, String) {
    let (sent, planned) = crate::agent::change::coverage_totals(&ci.coverage);
    let pct = (sent * 100)
        .checked_div(planned)
        .map_or("n/a".to_string(), |p| format!("{p}%"));
    (sent, planned, pct)
}

pub fn secs(ms: u64) -> String {
    format!("{:.1}s", ms as f64 / 1000.0)
}

pub fn used_of(a: &AreaReport, f: fn(&Quota) -> String, g: fn(&Quota) -> String) -> String {
    let one = |b: &AreaBudget| format!("{}/{}", f(&b.used), g(&b.allocated));
    match &a.wave2_budget {
        Some(w) => format!("{} + w2 {}", one(&a.budget), one(w)),
        None => one(&a.budget),
    }
}

pub fn area_cells(a: &AreaReport) -> [String; 5] {
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

pub fn pool_text(a: &AgentsReport) -> String {
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
