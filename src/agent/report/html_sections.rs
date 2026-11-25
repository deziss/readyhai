use crate::agent::memory::{DefectLine, SinceLastRun};
use crate::agent::types::{
    AgentRunReport, AgentsReport, ChangeImpact, EvidenceLedger, TriagedDefect, VerificationSummary,
};

use super::helpers::{
    SHOWN_FILES, area_cells, change_totals, cites, defect_verification, html_escape, line_note,
    pool_text, replays_text, score_text, status_text, verdict_label, verification_line, via_text,
};

pub fn html_ledger(l: &EvidenceLedger) -> String {
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
        let (st_class, label) = match e.status.as_deref() {
            Some("met") => ("st-PASS", "met"),
            Some("warning") => ("st-WARN", "warning"),
            Some("unmet") => ("st-FAIL", "not met"),
            _ => {
                if e.met {
                    ("st-PASS", "met")
                } else {
                    ("st-FAIL", "not met")
                }
            }
        };
        h.push_str(&format!(
            "<tr><td>{} <span class=\"mut\">{}</span></td><td class=\"{}\">{}</td><td>{}</td></tr>",
            html_escape(&e.criterion),
            html_escape(&e.details),
            st_class,
            label,
            cites(&e.case_ids, &e.evidence_files)
        ));
    }
    h.push_str("</tbody></table></div></div>");
    h
}

pub fn html_verification(rep: &AgentRunReport, v: &VerificationSummary) -> String {
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
                if crate::agent::ledger::is_blocking(d) {
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

pub fn html_defect_lines(title: &str, lines: &[DefectLine], what: &str) -> String {
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

pub fn html_since_last_run(s: &SinceLastRun) -> String {
    let mut h = format!(
        "<div class=\"card\"><h2>Since last run</h2><p>{}</p>",
        html_escape(&super::helpers::since_title(s))
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

pub fn html_change_impact(ci: &ChangeImpact) -> String {
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
            let n = |f: fn(&crate::agent::types::ChangedOpCoverage) -> usize| {
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

pub fn html_agents(a: &AgentsReport) -> String {
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
