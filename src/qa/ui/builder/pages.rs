use std::collections::BTreeMap;
use crate::model::{Category, Severity};
use crate::qa::model::*;
use super::super::model::{UiReport, UiShot, UiViewport};
use super::{B, ev};

pub fn process_pages(
    b: &mut B,
    rep: &UiReport,
    m: &mut CoverageMatrix,
    unmap: &dyn Fn(&str) -> String,
) {
    // a11y per (rule id, page path): (impact, help, page url, nodes, first target). One defect per
    // item, so a NEW violation (or the same rule on a new page) is a new fingerprint and gates.
    let mut axe: BTreeMap<(String, String), (String, String, String, u32, String)> =
        Default::default();

    for p in &rep.pages {
        let url = unmap(&p.url);
        let path = if p.path.is_empty() {
            url.clone()
        } else {
            p.path.clone()
        };

        // Responsive viewports
        if !p.viewports.is_empty() {
            let bad: Vec<(&String, &UiViewport)> =
                p.viewports.iter().filter(|(_, v)| v.overflow).collect();
            let id = format!("ui.{path}.responsive");
            b.case(
                id.clone(),
                Technique::Exploratory,
                Priority::P3,
                format!(
                    "No horizontal overflow at {}",
                    p.viewports.keys().cloned().collect::<Vec<_>>().join("/")
                ),
                url.clone(),
                None,
                vec![
                    format!("Open {url} at each viewport width"),
                    "Compare scrollWidth with innerWidth".into(),
                ],
                "Page fits the viewport",
            );
            if bad.is_empty() {
                b.result(&id, None, "fits all viewports".into(), vec![]);
                m.set(&path, "responsive", Cell::Pass);
            } else {
                let widths: Vec<String> = bad.iter().map(|(w, _)| (*w).clone()).collect();
                let i = b.defect(
                    "qa.ui.responsive_overflow",
                    Category::Quality,
                    Severity::Low,
                    format!(
                        "Horizontal overflow at {} px viewport(s)",
                        widths.join(", ")
                    ),
                    url.clone(),
                    format!("qa.ui.responsive_overflow|{path}"),
                );
                let d = &mut b.out.defects[i];
                let (w0, v0) = bad[0];
                d.expected = "No horizontal scrolling; content reflows to the viewport".into();
                d.actual = format!(
                    "scrollWidth {} > innerWidth {} at {w0}px; {} element(s) clipped (e.g. {})",
                    v0.scroll_width,
                    v0.inner_width,
                    v0.clipped.len(),
                    v0.clipped
                        .first()
                        .and_then(|c| c["el"].as_str())
                        .unwrap_or("?")
                );
                d.steps_to_reproduce = vec![
                    format!("Open {url}"),
                    format!("Resize the browser to {w0}px wide"),
                    "Observe horizontal scrollbar / clipped content".into(),
                ];
                d.remediation = "Use fluid widths (max-width: 100%), responsive layout and a viewport meta tag.".into();
                d.cases.push(id.clone());
                let dd = d.clone();
                b.result(&id, Some(&dd), dd.actual.clone(), vec![]);
                m.set(&path, "responsive", Cell::Fail);
            }
            if let Some((w, v)) = p
                .viewports
                .iter()
                .find(|(w, v)| w.parse::<u32>().unwrap_or(999) <= 400 && v.small_targets > 0)
            {
                b.out.notes.push(format!(
                    "{path}: {} tap target(s) under 24px at {w}px",
                    v.small_targets
                ));
            }
        }

        // a11y
        if let Some(list) = &p.axe {
            let id = format!("ui.{path}.a11y");
            b.case(
                id.clone(),
                Technique::Exploratory,
                Priority::P2,
                "No axe-core accessibility violations".into(),
                url.clone(),
                None,
                vec![format!("Open {url}"), "Run axe-core".into()],
                "No violations",
            );
            for a in list {
                let e = axe.entry((a.id.clone(), path.clone())).or_insert((
                    a.impact.clone(),
                    a.help.clone(),
                    url.clone(),
                    0,
                    a.target.clone(),
                ));
                e.3 += a.nodes;
            }
            m.set(
                &path,
                "a11y",
                if list.is_empty() {
                    Cell::Pass
                } else {
                    Cell::Fail
                },
            );
            if list.is_empty() {
                b.result(&id, None, "no violations".into(), vec![]);
            }
        }

        // vitals
        if let Some(v) = &p.vitals {
            let id = format!("ui.{path}.vitals");
            b.case(
                id.clone(),
                Technique::Exploratory,
                Priority::P3,
                "LCP <= 2.5s and CLS <= 0.1".into(),
                url.clone(),
                None,
                vec![format!("Load {url}"), "Observe LCP and CLS".into()],
                "Good web vitals",
            );
            // No LCP at all (0) or an error / no-response navigation: the page painted nothing
            // meaningful, so "LCP 0 ms, CLS 0" is the absence of data, not a good score.
            let no_data = match p.status {
                Some(0) => Some("no HTTP response".to_string()),
                Some(st) if st >= 400 => Some(format!("the page answered HTTP {st}")),
                _ if v.lcp_ms <= 0.0 => {
                    Some("no largest contentful paint was observed (blank page?)".to_string())
                }
                _ => None,
            };
            if let Some(why) = no_data {
                b.out.results.push(TestResult {
                    case_id: id.clone(),
                    status: ResultStatus::Blocked,
                    actual: format!("web vitals not measurable: {why}"),
                    duration_ms: 0,
                    attempts: 1,
                    evidence: vec![],
                    defect_id: None,
                });
                m.set(&path, "vitals", Cell::Untested);
            } else {
                let mut failed = None;
                if v.lcp_ms > 2500.0 {
                    let i = b.defect(
                        "qa.ui.slow_page",
                        Category::Performance,
                        Severity::Medium,
                        format!("Slow LCP: {:.1}s", v.lcp_ms / 1000.0),
                        url.clone(),
                        format!("qa.ui.slow_page|lcp|{path}"),
                    );
                    b.out.defects[i].expected = "LCP <= 2.5s".into();
                    b.out.defects[i].actual = format!("LCP {:.0} ms", v.lcp_ms);
                    b.out.defects[i].steps_to_reproduce = vec![
                        format!("Open {url} in Chrome with an empty cache"),
                        "Read LCP from Performance panel".into(),
                    ];
                    b.out.defects[i].remediation = "Optimise the largest above-the-fold element: compress/preload images, cut render-blocking resources.".into();
                    b.out.defects[i].cases.push(id.clone());
                    failed = Some(b.out.defects[i].clone());
                }
                if v.cls > 0.1 {
                    let i = b.defect(
                        "qa.ui.slow_page",
                        Category::Performance,
                        Severity::Low,
                        format!("Layout shift: CLS {:.2}", v.cls),
                        url.clone(),
                        format!("qa.ui.slow_page|cls|{path}"),
                    );
                    b.out.defects[i].expected = "CLS <= 0.1".into();
                    b.out.defects[i].actual = format!("CLS {:.3}", v.cls);
                    b.out.defects[i].steps_to_reproduce = vec![
                        format!("Open {url}"),
                        "Record layout shifts in the Performance panel".into(),
                    ];
                    b.out.defects[i].remediation = "Reserve space for images/embeds (width/height, aspect-ratio) and avoid late-injected content.".into();
                    b.out.defects[i].cases.push(id.clone());
                    failed.get_or_insert(b.out.defects[i].clone());
                }
                let act = format!("LCP {:.0} ms, CLS {:.3}", v.lcp_ms, v.cls);
                b.result(&id, failed.as_ref(), act, vec![]);
                m.set(
                    &path,
                    "vitals",
                    if failed.is_some() {
                        Cell::Fail
                    } else {
                        Cell::Pass
                    },
                );
            }
        }

        // visual
        if !p.shots.is_empty() {
            let id = format!("ui.{path}.visual");
            b.case(
                id.clone(),
                Technique::Regression,
                Priority::P3,
                "Page matches visual baseline".into(),
                url.clone(),
                None,
                vec![
                    format!("Screenshot {url} at each viewport"),
                    "Diff against stored baseline".into(),
                ],
                "< 0.5% pixels changed",
            );
            let changed: Vec<&UiShot> = p
                .shots
                .iter()
                .filter(|s| s.diff_ratio.unwrap_or(0.0) > 0.005)
                .collect();
            let mut evid: Vec<Evidence> = p
                .shots
                .iter()
                .map(|s| {
                    ev(
                        EvidenceKind::Screenshot,
                        &s.file,
                        &format!("{}px", s.viewport),
                    )
                })
                .collect();
            if changed.is_empty() {
                let has_base = p.shots.iter().any(|s| s.diff_ratio.is_some());
                if has_base {
                    b.result(&id, None, "matches baseline".into(), evid);
                    m.set(&path, "visual", Cell::Pass);
                } else {
                    // nothing was compared: not a pass
                    b.out.results.push(TestResult {
                        case_id: id.clone(),
                        status: ResultStatus::Skipped,
                        actual: "no baseline yet; current shots stored as the baseline (nothing compared)".into(),
                        duration_ms: 0,
                        attempts: 1,
                        evidence: evid,
                        defect_id: None,
                    });
                    m.set(&path, "visual", Cell::Untested);
                }
            } else {
                for s in &changed {
                    if let Some(df) = &s.diff_file {
                        evid.push(ev(
                            EvidenceKind::Screenshot,
                            df,
                            &format!("diff {}px", s.viewport),
                        ));
                    }
                }
                // one defect per changed viewport (a new viewport regression is a new fingerprint)
                let mut first: Option<Defect> = None;
                for s in &changed {
                    let ratio = s.diff_ratio.unwrap_or(0.0);
                    let i = b.defect(
                        "qa.ui.visual_change",
                        Category::Quality,
                        Severity::Low,
                        format!(
                            "Visual change vs baseline at {} px ({:.1}% pixels)",
                            s.viewport,
                            ratio * 100.0
                        ),
                        url.clone(),
                        format!("qa.ui.visual_change|{path}|{}", s.viewport),
                    );
                    let d = &mut b.out.defects[i];
                    d.expected = "Page unchanged vs approved baseline".into();
                    d.actual = format!(
                        "{:.1}% of pixels differ at {} px",
                        ratio * 100.0,
                        s.viewport
                    );
                    d.steps_to_reproduce = vec![
                        format!("Open {url}"),
                        "Compare with the baseline screenshot (see evidence)".into(),
                    ];
                    d.remediation = "Needs human review: if the change is intended, accept with `readyhai baseline accept <run>`.".into();
                    d.evidence = evid.clone();
                    d.cases.push(id.clone());
                    first.get_or_insert_with(|| d.clone());
                }
                let dd = first.expect("changed is non-empty");
                b.result(
                    &id,
                    Some(&dd),
                    changed
                        .iter()
                        .map(|s| {
                            format!(
                                "{:.1}% at {}px",
                                s.diff_ratio.unwrap_or(0.0) * 100.0,
                                s.viewport
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    evid,
                );
                m.set(&path, "visual", Cell::Fail);
            }
        }
    }

    // a11y defects (one per rule id and page)
    for ((rid, path), (impact, help, url, nodes, target)) in &axe {
        let sev = if matches!(impact.as_str(), "critical" | "serious") {
            Severity::Medium
        } else {
            Severity::Low
        };
        let i = b.defect(
            "qa.ui.a11y",
            Category::Quality,
            sev,
            format!("Accessibility: {help} ({rid}, {impact}) on {path}"),
            url.clone(),
            format!("qa.ui.a11y|{rid}|{path}"),
        );
        let d = &mut b.out.defects[i];
        d.expected = "WCAG-conformant markup (axe-core reports no violation)".into();
        d.actual = format!("{nodes} element(s) on {path}; first: {target}");
        d.steps_to_reproduce = vec![
            format!("Open {url}"),
            format!("Run axe-core and look for rule `{rid}` at `{target}`"),
        ];
        d.remediation =
            format!("Fix axe rule `{rid}`: https://dequeuniversity.com/rules/axe/4.10/{rid}");
        let cid = format!("ui.{path}.a11y");
        d.cases.push(cid.clone());
        let dd = d.clone();
        if !b.out.results.iter().any(|r| r.case_id == cid) {
            b.result(
                &cid,
                Some(&dd),
                format!("axe violation {rid} ({impact})"),
                vec![],
            );
        }
    }
}
