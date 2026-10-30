//! UI exploratory QA: runs runners/playwright/qa.mjs in the Playwright runner image and
//! turns /out/qa-ui.json into test cases, results, defects and coverage.
use super::model::*;
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};
use crate::tools::ToolSpec;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const HINT: &str =
    "build the runner: docker build -t readyhai/playwright-runner:local runners/playwright";

pub fn checks() -> Vec<Check> {
    vec![
        Check::new(
            "qa.ui",
            "UI exploratory QA: responsive, a11y, forms, journeys, visual, vitals (Playwright)",
            &[TargetKind::Web],
            Profile::Quick,
            run,
        )
        .qa()
        .tool("playwright"),
    ]
}

// ---------------------------------------------------------------- runner report model

#[derive(Debug, Default, Deserialize)]
pub struct UiReport {
    #[serde(default)]
    pub pages: Vec<UiPage>,
    #[serde(default)]
    pub forms: Vec<UiForm>,
    #[serde(default)]
    pub journeys: Vec<UiJourney>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiPage {
    pub url: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub viewports: std::collections::BTreeMap<String, UiViewport>,
    #[serde(default)]
    pub axe: Option<Vec<UiAxe>>,
    #[serde(default)]
    pub vitals: Option<UiVitals>,
    #[serde(default)]
    pub shots: Vec<UiShot>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiViewport {
    #[serde(default)]
    pub overflow: bool,
    #[serde(default)]
    pub scroll_width: u32,
    #[serde(default)]
    pub inner_width: u32,
    #[serde(default)]
    pub clipped: Vec<serde_json::Value>,
    #[serde(default)]
    pub small_targets: u32,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiAxe {
    pub id: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub help: String,
    #[serde(default)]
    pub nodes: u32,
    #[serde(default)]
    pub target: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiVitals {
    #[serde(default)]
    pub lcp_ms: f64,
    #[serde(default)]
    pub cls: f64,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiShot {
    pub viewport: u32,
    pub file: String,
    #[serde(default)]
    pub diff_ratio: Option<f64>,
    #[serde(default)]
    pub diff_file: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiForm {
    pub page: String,
    pub form: String,
    pub field: String,
    pub value_kind: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub client_blocked: bool,
    #[serde(default)]
    pub server_status: Option<u16>,
    #[serde(default)]
    pub error_shown: bool,
    #[serde(default)]
    pub gap: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct UiJourney {
    pub name: String,
    pub role: String,
    pub status: String,
    #[serde(default)]
    pub failed_step: Option<usize>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub trace: Option<String>,
    #[serde(default)]
    pub screenshot: Option<String>,
}

// ---------------------------------------------------------------- report -> QA model

#[derive(Default)]
pub struct Built {
    pub cases: Vec<TestCase>,
    pub results: Vec<TestResult>,
    pub defects: Vec<Defect>,
    pub coverage: CoverageMatrix,
    pub notes: Vec<String>,
}

struct B<'a> {
    out: Built,
    env: &'a str,
    n: usize,
}

impl B<'_> {
    fn defect(
        &mut self,
        rule: &str,
        cat: Category,
        sev: Severity,
        title: String,
        component: String,
        fp: String,
    ) -> usize {
        self.n += 1;
        let pri = match sev {
            Severity::Critical => Priority::P1,
            Severity::High => Priority::P1,
            Severity::Medium => Priority::P2,
            Severity::Low => Priority::P3,
            Severity::Info => Priority::P4,
        };
        self.out.defects.push(Defect {
            id: format!("UI-{:03}", self.n),
            rule: rule.into(),
            category: cat,
            severity: sev,
            priority: pri,
            area: Area::Ui,
            title,
            component,
            environment: self.env.into(),
            steps_to_reproduce: vec![],
            expected: String::new(),
            actual: String::new(),
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![],
            remediation: String::new(),
            fp_key: fp,
            fingerprint: String::new(),
            status: Default::default(),
            regression: false,
            ai_note: None,
        });
        self.out.defects.len() - 1
    }

    fn case(
        &mut self,
        id: String,
        tech: Technique,
        pri: Priority,
        title: String,
        comp: String,
        role: Option<String>,
        steps: Vec<String>,
        expected: &str,
    ) {
        self.out.cases.push(TestCase {
            id,
            area: Area::Ui,
            technique: tech,
            title,
            priority: pri,
            component: comp,
            role,
            steps,
            expected: expected.into(),
            source: CaseSource::Deterministic,
        });
    }

    fn result(
        &mut self,
        case_id: &str,
        fail: Option<&Defect>,
        actual: String,
        evidence: Vec<Evidence>,
    ) {
        self.out.results.push(TestResult {
            case_id: case_id.into(),
            status: if fail.is_some() {
                ResultStatus::Fail
            } else {
                ResultStatus::Pass
            },
            actual,
            duration_ms: 0,
            attempts: 1,
            evidence,
            defect_id: fail.map(|d| d.id.clone()),
        });
    }
}

fn ev(kind: EvidenceKind, path: &str, note: &str) -> Evidence {
    Evidence {
        kind,
        path: format!("ui/{path}"),
        note: note.into(),
    }
}

/// Pure transformation of the runner report. `unmap` rewrites container URLs back to the real target.
pub fn build(rep: &UiReport, env: &str, unmap: &dyn Fn(&str) -> String) -> Built {
    let mut b = B {
        out: Built::default(),
        env,
        n: 0,
    };
    b.out.notes.extend(rep.notes.iter().cloned());
    let mut m = CoverageMatrix::default();
    // a11y per (rule id, page path): (impact, help, page url, nodes, first target). One defect per
    // item, so a NEW violation (or the same rule on a new page) is a new fingerprint and gates.
    let mut axe: std::collections::BTreeMap<
        (String, String),
        (String, String, String, u32, String),
    > = Default::default();

    for p in &rep.pages {
        let url = unmap(&p.url);
        let path = if p.path.is_empty() {
            url.clone()
        } else {
            p.path.clone()
        };
        // responsive
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
                    b.out.results.push(TestResult { case_id: id.clone(), status: ResultStatus::Skipped,
                        actual: "no baseline yet; current shots stored as the baseline (nothing compared)".into(), duration_ms: 0, attempts: 1, evidence: evid, defect_id: None });
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

    // forms
    for f in &rep.forms {
        let page = unmap(&f.page);
        let path = page
            .split_once("://")
            .and_then(|x| x.1.find('/').map(|i| x.1[i..].to_string()))
            .unwrap_or_else(|| page.clone());
        let id = format!("ui.{path}.{}.{}.{}", f.form, f.field, f.value_kind);
        b.case(
            id.clone(),
            Technique::Boundary,
            Priority::P2,
            format!("Field `{}` rejects {}", f.field, f.value_kind),
            page.clone(),
            None,
            vec![
                format!("Open {page}"),
                format!("Enter {} ({}) in `{}`", f.value_kind, f.value, f.field),
                "Submit the form".into(),
            ],
            "Client or server validation rejects the value with a visible error",
        );
        m.set(
            &path,
            "forms",
            if f.gap {
                Cell::Fail
            } else if m.cells.iter().any(|c| {
                m.rows.get(c.0) == Some(&path)
                    && m.columns.get(c.1).map(String::as_str) == Some("forms")
                    && c.2 == Cell::Fail
            }) {
                Cell::Fail
            } else {
                Cell::Pass
            },
        );
        if f.gap {
            let i = b.defect(
                "qa.ui.validation_gap",
                Category::Quality,
                Severity::Medium,
                format!("No validation on `{}` ({})", f.field, f.value_kind),
                page.clone(),
                format!(
                    "qa.ui.validation_gap|{path}|{}|{}|{}",
                    f.form, f.field, f.value_kind
                ),
            );
            let d = &mut b.out.defects[i];
            d.expected = "Invalid/boundary input is blocked client-side or rejected server-side with a visible error".into();
            d.actual = format!(
                "accepted: not blocked by the browser, server answered {}, no error shown",
                f.server_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into())
            );
            d.steps_to_reproduce = vec![
                format!("Open {page}"),
                format!(
                    "In {} enter `{}` into `{}` (other fields valid)",
                    f.form, f.value, f.field
                ),
                "Submit".into(),
            ];
            d.remediation = "Add input type/min/max/maxlength/required attributes and server-side validation with user-visible errors.".into();
            d.cases.push(id.clone());
            let dd = d.clone();
            b.result(&id, Some(&dd), dd.actual.clone(), vec![]);
        } else {
            let how = if f.client_blocked {
                "blocked by browser validation"
            } else if f.error_shown {
                "error shown"
            } else {
                "not accepted"
            };
            b.result(&id, None, how.into(), vec![]);
        }
    }

    // journeys
    for j in &rep.journeys {
        let id = format!("ui.journey.{}.{}", j.name, j.role);
        b.case(
            id.clone(),
            Technique::Regression,
            Priority::P1,
            format!("Journey `{}` as {}", j.name, j.role),
            j.name.clone(),
            Some(j.role.clone()),
            vec![format!("Run journey `{}` with role `{}`", j.name, j.role)],
            "All steps pass",
        );
        match j.status.as_str() {
            "pass" => {
                b.result(&id, None, "all steps passed".into(), vec![]);
                m.set(&j.name, &j.role, Cell::Pass);
            }
            "fail" => {
                let mut evid = vec![];
                if let Some(t) = &j.trace {
                    evid.push(ev(
                        EvidenceKind::Trace,
                        t,
                        "Playwright trace (npx playwright show-trace)",
                    ));
                }
                if let Some(s) = &j.screenshot {
                    evid.push(ev(EvidenceKind::Screenshot, s, "state at failure"));
                }
                let step = j.failed_step.unwrap_or(0);
                let i = b.defect(
                    "qa.ui.journey_failed",
                    Category::Quality,
                    Severity::High,
                    format!(
                        "Journey `{}` failed at step {} ({})",
                        j.name,
                        step + 1,
                        j.role
                    ),
                    j.name.clone(),
                    format!("qa.ui.journey_failed|{}|{}", j.name, j.role),
                );
                let d = &mut b.out.defects[i];
                d.expected = "Journey completes".into();
                d.actual = format!("step {} failed: {}", step + 1, j.message);
                d.steps_to_reproduce = vec![
                    format!("Run journey `{}` as role `{}`", j.name, j.role),
                    format!("Step {} fails", step + 1),
                ];
                d.evidence = evid.clone();
                d.remediation = "Open the trace to inspect DOM/network at the failing step.".into();
                d.cases.push(id.clone());
                let dd = d.clone();
                b.result(&id, Some(&dd), dd.actual.clone(), evid);
                m.set(&j.name, &j.role, Cell::Fail);
            }
            other => {
                b.out.results.push(TestResult {
                    case_id: id,
                    status: if other == "blocked" {
                        ResultStatus::Blocked
                    } else {
                        ResultStatus::Skipped
                    },
                    actual: j.message.clone(),
                    duration_ms: 0,
                    attempts: 1,
                    evidence: vec![],
                    defect_id: None,
                });
                m.set(&j.name, &j.role, Cell::Untested);
            }
        }
    }
    b.out.coverage = m;
    b.out
}

// ---------------------------------------------------------------- execution

/// Removes out/secrets on drop, so role cookies never outlive the run (even on error).
pub struct SecretsGuard(pub PathBuf);
impl Drop for SecretsGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn is_missing_image(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("unable to find image")
        || l.contains("pull access denied")
        || l.contains("no such image")
}

fn is_local(url: &str) -> bool {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let auth = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = auth
        .strip_prefix('[')
        .map(|r| r.split(']').next().unwrap_or(r))
        .unwrap_or_else(|| auth.split(':').next().unwrap_or(auth));
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0") || host.ends_with(".localhost")
}

/// (container-reachable base URL, needs host gateway). Same rewrite as web.rs.
fn container_base(url: &str) -> (String, bool) {
    if !is_local(url) {
        return (url.to_string(), false);
    }
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let (auth, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let port = if auth.starts_with('[') {
        auth.rsplit_once("]:").map(|x| x.1)
    } else {
        auth.rsplit_once(':').map(|x| x.1)
    };
    let port = port.filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    let a = match port {
        Some(p) => format!("host.docker.internal:{p}"),
        None => "host.docker.internal".into(),
    };
    (format!("{scheme}://{a}{tail}"), true)
}

fn origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    format!(
        "{scheme}://{}",
        rest.split(['/', '?', '#']).next().unwrap_or("")
    )
}

fn copy_dir_pngs(from: &Path, to: &Path, skip_diff: bool) -> usize {
    let Ok(rd) = std::fs::read_dir(from) else {
        return 0;
    };
    let _ = std::fs::create_dir_all(to);
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with(".png")
            && !(skip_diff && name.ends_with(".diff.png"))
            && std::fs::copy(e.path(), to.join(&name)).is_ok()
        {
            n += 1;
        }
    }
    n
}

/// Directory holding the accepted visual baseline PNGs of a target.
pub fn visual_baseline_dir(data: &Path, target_key: &str) -> PathBuf {
    data.join("baselines").join(target_key).join("visual")
}

/// Promote the screenshots of run `run_dir` (`artifacts/ui/shots/*.png`, diff images excluded) to
/// the visual baseline, replacing the previous PNGs. Returns how many were promoted.
pub fn accept_visual_baseline_in(data: &Path, target_key: &str, run_dir: &Path) -> Result<usize> {
    let shots = run_dir.join("artifacts").join("ui").join("shots");
    let has_png = std::fs::read_dir(&shots)
        .map(|rd| {
            rd.flatten().any(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.ends_with(".png") && !n.ends_with(".diff.png")
            })
        })
        .unwrap_or(false);
    if !has_png {
        anyhow::bail!("run recorded no UI screenshots to promote");
    }
    let dst = visual_baseline_dir(data, target_key);
    let _ = std::fs::remove_dir_all(&dst);
    let n = copy_dir_pngs(&shots, &dst, true);
    if n == 0 {
        anyhow::bail!("could not copy the run's screenshots to {}", dst.display());
    }
    Ok(n)
}

/// `baseline accept <run>` hook for the visual baselines of that run.
#[allow(dead_code)]
pub fn accept_visual_baseline(target_key: &str, run_id: &str) -> Result<usize> {
    accept_visual_baseline_in(
        &crate::engine::data_dir(),
        target_key,
        &crate::engine::run_dir(run_id),
    )
}

fn set_mode(p: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (p, mode);
}

fn load_journeys(path: &Path) -> Result<Vec<serde_json::Value>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("journeys file {}", path.display()))?;
    let v: serde_json::Value =
        serde_norway::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(match v {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(mut o) => match o.remove("journeys") {
            Some(serde_json::Value::Array(a)) => a,
            _ => vec![serde_json::Value::Object(o)],
        },
        _ => vec![],
    })
}

fn run(ctx: &Ctx) -> Result<CheckOutput> {
    let qa = ctx.qa.as_ref().context("not a QA run")?;
    let url = ctx.target.url.clone().context("no target url")?;
    if !ctx.docker.available {
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "docker not available".into(),
        )));
    }
    let (cbase, gw) = container_base(&url);
    let out = ctx.out_dir();
    std::fs::create_dir_all(&out)?;

    let standard = ctx.profile >= Profile::Standard;
    let mut modes = vec!["crawl", "responsive", "a11y", "vitals"];
    let journeys = match (&qa.journeys, standard) {
        (Some(p), true) => load_journeys(p)?,
        _ => vec![],
    };
    if standard {
        if qa.nonprod {
            modes.push("forms");
        }
        if !journeys.is_empty() {
            modes.push("journeys");
        }
        modes.push("visual");
    }

    // Role storageState → out/secrets (deleted by the guard).
    let secrets = out.join("secrets");
    let _guard = SecretsGuard(secrets.clone());
    let mut roles = vec![];
    let mut notes = vec![];
    if !journeys.is_empty() {
        std::fs::create_dir_all(&secrets)?;
        set_mode(&secrets, 0o700);
        for r in &qa.roles.roles {
            let Some(ss) = &r.storage_state else { continue };
            let src = qa.roles.dir.join(ss);
            let dst = secrets.join(format!("{}.json", r.name));
            if std::fs::copy(&src, &dst).is_ok() {
                // Owner-only; the runner is started as the owner's uid (ts.user below).
                set_mode(&dst, 0o600);
                roles.push(serde_json::json!({"name": r.name, "storage_state_path": format!("/out/secrets/{}.json", r.name)}));
            } else {
                notes.push(format!(
                    "role {}: storageState not readable, UI journeys skipped for this role",
                    r.name
                ));
            }
        }
    }

    // Visual baselines.
    let bdir = visual_baseline_dir(
        &crate::engine::data_dir(),
        &crate::engine::target_key(&ctx.target),
    );
    let have_baseline = copy_dir_pngs(&bdir, &out.join("visual-baseline"), false) > 0;
    let _ = std::fs::remove_dir_all(out.join("shots"));

    let input = serde_json::json!({
        "base_url": cbase, "max_pages": 20, "modes": modes,
        "viewports": [[375, 812], [768, 1024], [1366, 768]],
        "nonprod": qa.nonprod, "roles": roles, "journeys": journeys,
        "visual_baseline_dir": "/out/visual-baseline", "axe": true,
    });
    let _ = std::fs::remove_file(out.join("qa-ui.json"));
    std::fs::write(
        out.join("qa-ui-input.json"),
        serde_json::to_vec_pretty(&input)?,
    )?;

    let mut ts = ToolSpec::new(
        "playwright",
        &["node", "/runner/qa.mjs", "/out/qa-ui-input.json"],
    );
    #[cfg(unix)]
    if !roles.is_empty() {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::metadata(&secrets) {
            ts.user = Some(format!("{}:{}", m.uid(), m.gid()));
        }
    }
    ts.network = true;
    ts.host_gateway = gw;
    ts.memory = "2g".into();
    ts.timeout_secs = 660;
    ts.tmpfs = vec!["/home/pwuser:rw,size=256m,mode=1777".into()];
    ts.env = vec![("PLAYWRIGHT_BROWSERS_PATH".into(), "/ms-playwright".into())];
    let run = match ctx.docker.run(ctx, &ts) {
        Ok(r) => r,
        Err(e) if is_missing_image(&e.to_string()) => {
            return Ok(CheckOutput::status(CheckStatus::Skipped(HINT.into())));
        }
        Err(e) => return Err(e),
    };
    let Ok(text) = std::fs::read_to_string(out.join("qa-ui.json")) else {
        if is_missing_image(&run.stderr_tail) {
            return Ok(CheckOutput::status(CheckStatus::Skipped(HINT.into())));
        }
        return Ok(CheckOutput::status(CheckStatus::Errored(format!(
            "qa.mjs produced no report (exit {}): {}",
            run.exit_code,
            run.stderr_tail.chars().take(300).collect::<String>()
        ))));
    };
    let rep: UiReport = serde_json::from_str(&text).context("parse qa-ui.json")?;

    let (corigin, oorigin) = (origin(&cbase), origin(&url));
    let unmap = move |s: &str| s.replace(&corigin, &oorigin);
    let env = if qa.nonprod {
        "nonprod"
    } else {
        "unclassified (writes disabled)"
    };
    let mut built = build(&rep, &format!("{env}: {url}"), &unmap);
    built.notes.extend(notes);

    // Evidence → run_dir/artifacts/ui/, and first-run baseline.
    let art = ctx.run_dir.join("artifacts").join("ui");
    for sub in ["shots", "traces"] {
        if let Ok(rd) = std::fs::read_dir(out.join(sub)) {
            let _ = std::fs::create_dir_all(art.join(sub));
            for e in rd.flatten() {
                let _ = std::fs::copy(e.path(), art.join(sub).join(e.file_name()));
            }
        }
    }
    if !have_baseline && rep.pages.iter().any(|p| !p.shots.is_empty()) {
        let n = copy_dir_pngs(&out.join("shots"), &bdir, true);
        if n > 0 {
            built.notes.push(format!("UI visual: no baseline existed, stored {n} screenshot(s) as the baseline ({}). Next run compares against them; promote a later run with `readyhai baseline accept <run>`.", bdir.display()));
        }
    }
    if !modes.contains(&"forms") {
        built.notes.push(if standard && !qa.nonprod {
            "UI forms not tested: target not tagged nonprod".into()
        } else {
            "UI forms/journeys/visual run only in the standard profile".to_string()
        });
    }

    let findings: Vec<Finding> = built
        .defects
        .iter()
        .map(|d| d.to_finding("qa.ui"))
        .collect();
    qa.with(|c| {
        c.cases.extend(built.cases);
        c.results.extend(built.results);
        c.defects.extend(built.defects);
        for (r, col, cell) in built
            .coverage
            .cells
            .iter()
            .map(|(r, c, x)| (&built.coverage.rows[*r], &built.coverage.columns[*c], *x))
        {
            c.coverage.set(r, col, cell);
        }
        c.notes.extend(built.notes);
    });
    Ok(CheckOutput::findings(findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_report() {
        let text = include_str!("../../tests/fixtures/qa-ui/sample-qa-ui.json");
        let rep: UiReport = serde_json::from_str(text).unwrap();
        let b = build(&rep, "nonprod", &|s| {
            s.replace("host.docker.internal:8099", "127.0.0.1:8099")
        });
        let rules: Vec<&str> = b.defects.iter().map(|d| d.rule.as_str()).collect();
        let count = |r: &str| rules.iter().filter(|x| **x == r).count();
        assert_eq!(count("qa.ui.validation_gap"), 1);
        assert_eq!(count("qa.ui.responsive_overflow"), 1);
        assert_eq!(count("qa.ui.a11y"), 3);
        assert_eq!(count("qa.ui.journey_failed"), 1);
        assert_eq!(count("qa.ui.visual_change"), 1);
        assert_eq!(count("qa.ui.slow_page"), 2); // LCP on /, CLS on /wide.html
        let a11y: Vec<_> = b
            .defects
            .iter()
            .filter(|d| d.rule == "qa.ui.a11y")
            .collect();
        assert!(
            a11y.iter()
                .any(|d| d.title.contains("image-alt") && d.severity == Severity::Medium)
        );
        assert!(
            a11y.iter()
                .any(|d| d.title.contains("region") && d.severity == Severity::Low)
        );
        let j = b
            .defects
            .iter()
            .find(|d| d.rule == "qa.ui.journey_failed")
            .unwrap();
        assert_eq!(j.severity, Severity::High);
        assert_eq!(j.evidence.len(), 2);
        assert!(j.evidence[0].path.starts_with("ui/traces/"));
        assert!(
            b.defects
                .iter()
                .all(|d| !d.to_finding("qa.ui").rule.is_empty())
        );
        assert!(b.cases.iter().any(|c| c.id == "ui./wide.html.responsive"));
        assert!(b.cases.iter().any(|c| c.technique == Technique::Boundary));
        let m = &b.coverage;
        let cell = |r: &str, c: &str| {
            let (ri, ci) = (
                m.rows.iter().position(|x| x == r).unwrap(),
                m.columns.iter().position(|x| x == c).unwrap(),
            );
            m.cells.iter().find(|x| x.0 == ri && x.1 == ci).unwrap().2
        };
        assert_eq!(cell("/wide.html", "responsive"), Cell::Fail);
        assert_eq!(cell("login", "user"), Cell::Fail);
        assert_eq!(cell("login", "admin"), Cell::Pass);
        assert_eq!(cell("/signup.html", "forms"), Cell::Fail);
        assert!(j.component == "login");
    }

    #[test]
    fn a11y_and_visual_are_per_item() {
        let page = |u: &str, p: &str, axe: &str, shots: &str| {
            format!(r#"{{"url":"http://x{u}","path":"{p}","axe":[{axe}],"shots":[{shots}]}}"#)
        };
        let violation = |id: &str| {
            format!(r##"{{"id":"{id}","impact":"serious","help":"h","nodes":2,"target":"#t"}}"##)
        };
        let shot = |vp: u32, ratio: f64| {
            format!(r#"{{"viewport":{vp},"file":"shots/{vp}.png","diff_ratio":{ratio}}}"#)
        };
        let json = format!(
            r#"{{"pages":[{},{}]}}"#,
            page(
                "/a",
                "/a",
                &format!("{},{}", violation("image-alt"), violation("label")),
                &format!("{},{},{}", shot(375, 0.2), shot(768, 0.3), shot(1366, 0.0))
            ),
            page("/b", "/b", &violation("image-alt"), "")
        );
        let rep: UiReport = serde_json::from_str(&json).unwrap();
        let b = build(&rep, "nonprod", &|s| s.to_string());
        let a11y: Vec<&Defect> = b
            .defects
            .iter()
            .filter(|d| d.rule == "qa.ui.a11y")
            .collect();
        // same rule on two pages + a second rule on one page: three distinct fingerprints
        assert_eq!(a11y.len(), 3);
        let fps: std::collections::BTreeSet<&str> =
            a11y.iter().map(|d| d.fp_key.as_str()).collect();
        assert_eq!(fps.len(), 3);
        assert!(
            fps.contains("qa.ui.a11y|image-alt|/a")
                && fps.contains("qa.ui.a11y|image-alt|/b")
                && fps.contains("qa.ui.a11y|label|/a")
        );
        // two changed viewports of one page: two fingerprints
        let vis: Vec<&str> = b
            .defects
            .iter()
            .filter(|d| d.rule == "qa.ui.visual_change")
            .map(|d| d.fp_key.as_str())
            .collect();
        assert_eq!(
            vis,
            vec!["qa.ui.visual_change|/a|375", "qa.ui.visual_change|/a|768"]
        );
    }

    #[test]
    fn first_visual_run_compares_nothing_so_is_not_a_pass() {
        let rep: UiReport = serde_json::from_str(r#"{"pages":[{"url":"http://x/","path":"/","shots":[{"viewport":375,"file":"shots/375.png"}]}]}"#).unwrap();
        let b = build(&rep, "nonprod", &|s| s.to_string());
        let r = b
            .results
            .iter()
            .find(|r| r.case_id == "ui./.visual")
            .unwrap();
        assert_eq!(r.status, ResultStatus::Skipped);
        let m = &b.coverage;
        let (ri, ci) = (
            m.rows.iter().position(|x| x == "/").unwrap(),
            m.columns.iter().position(|x| x == "visual").unwrap(),
        );
        assert_eq!(
            m.cells.iter().find(|x| x.0 == ri && x.1 == ci).unwrap().2,
            Cell::Untested
        );
    }

    #[test]
    fn accept_visual_promotes_run_shots() {
        let d = std::env::temp_dir().join(format!("rh-vis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let run = d.join("runs/r1");
        let shots = run.join("artifacts/ui/shots");
        std::fs::create_dir_all(&shots).unwrap();
        std::fs::write(shots.join("a.png"), b"png").unwrap();
        std::fs::write(shots.join("a.diff.png"), b"diff").unwrap();
        let old = visual_baseline_dir(&d, "k");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("stale.png"), b"old").unwrap();
        assert_eq!(accept_visual_baseline_in(&d, "k", &run).unwrap(), 1);
        assert!(
            old.join("a.png").is_file()
                && !old.join("a.diff.png").exists()
                && !old.join("stale.png").exists()
        );
        assert!(accept_visual_baseline_in(&d, "k", &d.join("runs/none")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn secrets_guard_deletes() {
        let d = std::env::temp_dir().join(format!("rh-ui-secrets-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("user.json"), "{}").unwrap();
        {
            let _g = SecretsGuard(d.clone());
        }
        assert!(!d.exists());
    }

    #[test]
    fn container_rewrite() {
        assert_eq!(
            container_base("http://127.0.0.1:8099/").0,
            "http://host.docker.internal:8099/"
        );
        assert_eq!(
            container_base("https://example.com").0,
            "https://example.com"
        );
        assert_eq!(origin("http://a:1/x?y"), "http://a:1");
    }
}
