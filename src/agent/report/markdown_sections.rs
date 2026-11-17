use crate::agent::memory::{DefectLine, SinceLastRun};
use crate::agent::types::{AgentsReport, ChangeImpact};

use super::helpers::{
    SHOWN_FILES, area_cells, change_totals, line_note, md_code, md_fence, md_text, pool_text,
    since_title, status_text, via_text,
};

pub fn md_defect_lines(title: &str, lines: &[DefectLine], what: &str) -> String {
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

pub fn md_since_last_run(s: &SinceLastRun) -> String {
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

pub fn md_change_impact(ci: &ChangeImpact) -> String {
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

pub fn md_agents(a: &AgentsReport) -> String {
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
