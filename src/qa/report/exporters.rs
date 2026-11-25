use serde_json::{Value, json};

use super::helpers::{
    csv_row, defects_sorted, jira_code, jira_priority, jira_text, lc, looks_like_code, md_fence,
    md_inline, md_lines, prio_str,
};
use crate::qa::model::{Defect, QaReport};

pub(crate) fn jira_description(d: &Defect) -> String {
    let mut s = String::from("h3. Steps\n");
    for st in &d.steps_to_reproduce {
        if looks_like_code(st) {
            s.push_str(&format!("{{code}}\n{}\n{{code}}\n", jira_code(st)));
        } else {
            s.push_str(&format!("# {}\n", jira_text(st)));
        }
    }
    s.push_str(&format!(
        "*Expected*: {}\n*Actual*: {}\n",
        jira_text(&d.expected),
        jira_text(&d.actual)
    ));
    if !d.remediation.is_empty() {
        s.push_str(&format!("*Remediation*: {}\n", jira_text(&d.remediation)));
    }
    s.push_str(&format!(
        "*Severity*: {} | *Rule*: {} | *Environment*: {}\n",
        d.severity.as_str(),
        jira_text(&d.rule),
        jira_text(&d.environment)
    ));
    s
}

pub fn jira_csv(q: &QaReport) -> String {
    let mut o = csv_row(
        &[
            "Summary",
            "Issue Type",
            "Priority",
            "Labels",
            "Component",
            "Description",
        ]
        .map(String::from),
    );
    for d in defects_sorted(q) {
        o.push_str(&csv_row(&[
            d.title.clone(),
            "Bug".into(),
            jira_priority(d.priority).into(),
            format!("readyhai qa-{}", lc(&d.area)),
            d.component.clone(),
            jira_description(d),
        ]));
    }
    o
}

fn md_description(d: &Defect) -> String {
    let mut s = format!(
        "**Severity:** {} · **Priority:** {} · **Component:** {}\n\n### Steps to reproduce\n",
        d.severity.as_str(),
        prio_str(d.priority),
        md_inline(&d.component)
    );
    let mut n = 0;
    for st in &d.steps_to_reproduce {
        if looks_like_code(st) {
            s.push_str(&format!("\n{}", md_fence(st, "sh")));
        } else {
            n += 1;
            s.push_str(&format!("{n}. {}\n", md_inline(st)));
        }
    }
    s.push_str(&format!(
        "\n**Expected:** {}\n\n**Actual:** {}\n",
        md_lines(&d.expected),
        md_lines(&d.actual)
    ));
    if !d.remediation.is_empty() {
        s.push_str(&format!(
            "\n**Remediation:** {}\n",
            md_lines(&d.remediation)
        ));
    }
    s
}

pub fn gitlab_json(q: &QaReport) -> Value {
    Value::Array(
        defects_sorted(q)
            .iter()
            .map(|d| {
                json!({
                    "title": d.title, "description": md_description(d),
                    "labels": ["readyhai", "bug", format!("qa-{}", lc(&d.area)), prio_str(d.priority), format!("severity::{}", d.severity.as_str())],
                })
            })
            .collect(),
    )
}

pub fn testrail_csv(q: &QaReport) -> String {
    let mut o = csv_row(
        &[
            "Title",
            "Section",
            "Type",
            "Priority",
            "Preconditions",
            "Steps",
            "Expected Result",
        ]
        .map(String::from),
    );
    for c in &q.cases {
        let steps = c
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| format!("{}. {s}", i + 1))
            .collect::<Vec<_>>()
            .join("\n");
        let pre = c
            .role
            .as_ref()
            .map(|r| format!("Role: {r}"))
            .unwrap_or_default();
        o.push_str(&csv_row(&[
            c.title.clone(),
            lc(&c.area),
            lc(&c.technique),
            prio_str(c.priority).into(),
            pre,
            steps,
            c.expected.clone(),
        ]));
    }
    o
}

pub fn xray_csv(q: &QaReport) -> String {
    let mut o =
        csv_row(&["Test Summary", "Test Type", "Action", "Data", "Result"].map(String::from));
    for c in &q.cases {
        if c.steps.is_empty() {
            o.push_str(&csv_row(&[
                c.title.clone(),
                "Manual".into(),
                String::new(),
                String::new(),
                c.expected.clone(),
            ]));
        }
        for (i, s) in c.steps.iter().enumerate() {
            let last = i + 1 == c.steps.len();
            o.push_str(&csv_row(&[
                c.title.clone(),
                "Manual".into(),
                s.clone(),
                c.component.clone(),
                if last {
                    c.expected.clone()
                } else {
                    String::new()
                },
            ]));
        }
    }
    o
}
