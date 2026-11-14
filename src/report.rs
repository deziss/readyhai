//! Reports: HTML (auto-escaped, CSP, no JS), JSON, SARIF 2.1.0, JUnit XML; QA formats live in qa::report.
use crate::model::*;
use anyhow::Result;
use minijinja::value::Serde;
use minijinja::{AutoEscape, Environment};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub fn write(run: &Run, dir: &Path, formats: &[String]) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut out = vec![];
    for f in formats {
        let (name, body) = match f.as_str() {
            "html" => ("readyhai-report.html", html(run)?),
            "json" => ("readyhai-report.json", serde_json::to_string_pretty(run)?),
            "sarif" => (
                "readyhai-report.sarif",
                serde_json::to_string_pretty(&sarif(run))?,
            ),
            "junit" => ("readyhai-report.junit.xml", junit(run)),
            "pr" => ("readyhai-pr-comment.md", pr_comment(run)),
            _ => continue,
        };
        let p = dir.join(name);
        std::fs::write(&p, body)?;
        out.push(p);
    }
    out.extend(crate::qa::report::write_formats(run, dir, formats)?);
    Ok(out)
}

fn sev_order(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn status_str(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::New => "new",
        FindingStatus::Existing => "existing",
        FindingStatus::Suppressed => "suppressed",
    }
}

pub fn html(run: &Run) -> Result<String> {
    let mut env = Environment::new();
    env.set_auto_escape_callback(|_| AutoEscape::Html);
    env.add_template(
        "report.html.j2",
        include_str!("../templates/report.html.j2"),
    )?;
    let mut sorted: Vec<&Finding> = run.findings.iter().collect();
    sorted.sort_by_key(|f| {
        (
            sev_order(f.severity),
            match f.status {
                FindingStatus::New => 0,
                FindingStatus::Existing => 1,
                FindingStatus::Suppressed => 2,
            },
        )
    });
    let mut groups: Vec<Value> = vec![];
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let items: Vec<Value> = sorted
            .iter()
            .filter(|f| f.severity == sev)
            .map(|f| {
                json!({
                    "severity": f.severity.as_str(), "title": f.title, "rule": f.rule, "check": f.check,
                    "category": f.category.as_str(), "location": f.location, "ids": f.ids,
                    "package": f.package, "version": f.version, "fix_version": f.fix_version,
                    "epss": f.epss.map(|e| format!("{:.1}%", e * 100.0)), "kev": f.kev,
                    "detail": f.detail, "remediation": f.remediation,
                    "status": status_str(f.status), "suppressed_reason": f.suppressed_reason,
                })
            })
            .collect();
        if !items.is_empty() {
            groups.push(json!({"severity": sev.as_str(), "items": items}));
        }
    }
    let checks: Vec<Value> = run
        .checks
        .iter()
        .map(|c| {
            json!({"id": c.id, "title": c.title, "tool": c.tool, "status": c.status.label(),
                   "reason": c.status.reason().unwrap_or(""), "findings": c.findings, "duration_ms": c.duration_ms})
        })
        .collect();
    let (verdict, class) = match run.verdict {
        Verdict::Pass => ("PASS", "pass"),
        Verdict::Warn => ("WARN", "warn"),
        Verdict::Fail => ("FAIL", "fail"),
    };
    let ctx = json!({
        "verdict": verdict, "verdict_class": class, "reasons": run.reasons,
        "target": run.target.raw, "kind": format!("{:?}", run.target.kind).to_lowercase(),
        "profile": format!("{:?}", run.profile).to_lowercase(), "run_id": run.id,
        "started": run.started, "finished": run.finished, "version": run.version,
        "fixed": run.fixed, "categories": run.categories, "checks": checks,
        "groups": groups, "finding_count": run.findings.len(), "notes": run.notes,
        "errors": run.errors.iter().map(|e| json!({"count": e.count, "source": e.source, "signature": e.signature, "example": e.example, "first_seen": e.first_seen})).collect::<Vec<_>>(),
    });
    Ok(env.get_template("report.html.j2")?.render(Serde(&ctx))?)
}

/// `GET /x`, `POST /orders/{id}`, `GET /a, GET /b`: an HTTP operation, not a file.
fn is_component(loc: &str) -> bool {
    const M: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    loc.split_once(' ')
        .is_some_and(|(m, rest)| M.contains(&m) && rest.trim_start().starts_with(['/', '{', '*']))
}

/// Percent-escape what a URI reference may not contain (spaces, quotes, `<>`, `{}`, controls,
/// non-ASCII, a stray `%`); everything else (including `?#&=:/@[]`) is kept as is.
fn uri_escape(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = String::with_capacity(s.len());
    for (i, &c) in b.iter().enumerate() {
        let keep = c.is_ascii_alphanumeric()
            || b"-._~:/?#[]@!$&'()*+,;=".contains(&c)
            || (c == b'%'
                && i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit());
        if keep {
            o.push(c as char);
        } else {
            o.push_str(&format!("%{c:02X}"));
        }
    }
    o
}

pub fn sarif(run: &Run) -> Value {
    let mut rule_ids: Vec<&str> = vec![];
    let mut rules = vec![];
    for f in &run.findings {
        if !rule_ids.contains(&f.rule.as_str()) {
            rule_ids.push(&f.rule);
            rules.push(json!({"id": f.rule, "shortDescription": {"text": f.title}}));
        }
    }
    let results: Vec<Value> = run
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                _ => "note",
            };
            let is_url = f.location.contains("://");
            // `location` is also a QA component ("GET /x", "GET /a, GET /b") or a journey name:
            // never a valid artifact URI. Those go to logicalLocations (and the message), file
            // paths and URLs to physicalLocation with every illegal URI character escaped.
            let component = !is_url && is_component(&f.location);
            let location = if component {
                json!({"logicalLocations": [{"name": f.location, "kind": "member"}]})
            } else if is_url {
                json!({"physicalLocation": {"artifactLocation": {"uri": uri_escape(&f.location)}}})
            } else {
                let mut phys = json!({"artifactLocation": {"uri": uri_escape(f.path())}});
                if let Some((_, l)) = f.location.rsplit_once(':')
                    && let Ok(n) = l.parse::<u64>()
                {
                    phys["region"] = json!({"startLine": n});
                }
                json!({"physicalLocation": phys})
            };
            let mut text = f.title.clone();
            if !f.detail.is_empty() {
                text = format!("{}: {}", f.title, f.detail);
            }
            if component {
                text = format!("{text} [{}]", f.location);
            }
            let mut r = json!({
                "ruleId": f.rule, "level": level, "message": {"text": text},
                "locations": [location],
                "partialFingerprints": {"readyhai/v1": f.fingerprint},
                "properties": {"severity": f.severity.as_str(), "category": f.category.as_str(),
                    "status": status_str(f.status), "kev": f.kev, "epss": f.epss},
            });
            if f.status == FindingStatus::Suppressed {
                r["suppressions"] = json!([{"kind": "external",
                    "justification": f.suppressed_reason.clone().unwrap_or_default()}]);
            }
            r
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "readyhai", "version": run.version,
                "informationUri": "https://github.com/deziss/readyhai", "rules": rules}},
            "results": results,
        }]
    })
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c if (c as u32) < 0x20 && !matches!(c, '\n' | '\r' | '\t') => {}
            c => o.push(c),
        }
    }
    o
}

/// A finding that fails the JUnit test of its check: new (not baselined, not suppressed) and either
/// Medium+ or a QA defect (every QA defect is a failed test, whatever its severity).
fn junit_failure(f: &Finding) -> bool {
    f.status == FindingStatus::New && (f.severity >= Severity::Medium || f.rule.starts_with("qa."))
}

fn junit_failure_case(classname: &str, f: &Finding) -> String {
    format!(
        "<testcase classname=\"{}\" name=\"{}\"><failure message=\"{}\" type=\"{}\">{}</failure></testcase>\n",
        esc(classname),
        esc(&format!("{} {}", f.rule, f.location)),
        esc(&f.title),
        f.severity.as_str(),
        esc(&f.detail)
    )
}

pub fn junit(run: &Run) -> String {
    let mut x = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"readyhai\">\n",
    );
    // Findings belong to the check that produced them (`f.check` is the check id; the engine fills
    // it in when a check leaves it empty).
    for c in &run.checks {
        let bad: Vec<&Finding> = run
            .findings
            .iter()
            .filter(|f| f.check == c.id && junit_failure(f))
            .collect();
        let (mut tests, failures, mut errors, mut skipped) = (1usize, bad.len(), 0usize, 0usize);
        let mut cases = String::new();
        match &c.status {
            CheckStatus::Errored(r) => {
                errors = 1;
                cases.push_str(&format!("<testcase classname=\"{0}\" name=\"{0}\"><error message=\"{1}\"/></testcase>\n", esc(&c.id), esc(r)));
            }
            CheckStatus::Skipped(r) | CheckStatus::NotApplicable(r) => {
                skipped = 1;
                cases.push_str(&format!("<testcase classname=\"{0}\" name=\"{0}\"><skipped message=\"{1}\"/></testcase>\n", esc(&c.id), esc(r)));
            }
            _ => cases.push_str(&format!(
                "<testcase classname=\"{0}\" name=\"{0}\"/>\n",
                esc(&c.id)
            )),
        }
        for f in &bad {
            tests += 1;
            cases.push_str(&junit_failure_case(&c.id, f));
        }
        x.push_str(&format!(
            "<testsuite name=\"{}\" tests=\"{tests}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\">\n{cases}</testsuite>\n",
            esc(&c.id)));
    }
    // Failing findings whose `check` names no registered check (e.g. a QA defect that carried its
    // rule id as the check) must not vanish from the report.
    let orphans: Vec<&Finding> = run
        .findings
        .iter()
        .filter(|f| junit_failure(f) && !run.checks.iter().any(|c| c.id == f.check))
        .collect();
    if !orphans.is_empty() {
        let cases: String = orphans
            .iter()
            .map(|f| {
                junit_failure_case(
                    if f.check.is_empty() {
                        "unattributed"
                    } else {
                        &f.check
                    },
                    f,
                )
            })
            .collect();
        x.push_str(&format!(
            "<testsuite name=\"unattributed\" tests=\"{n}\" failures=\"{n}\" errors=\"0\" skipped=\"0\">\n{cases}</testsuite>\n",
            n = orphans.len()));
    }
    x.push_str("</testsuites>\n");
    x
}

/// Hidden marker the CI bots use to find and update their own PR / MR comment.
pub const PR_COMMENT_MARKER: &str = "<!-- readyhai-pr-comment -->";
/// Most findings listed in a PR comment; the rest are counted and left to the full report.
const PR_COMMENT_MAX: usize = 15;

/// Compact Markdown summary for a pull/merge request comment: verdict, reasons, per-category
/// counts and the top new (unsuppressed) findings. All finding text goes through `md_inline`, so
/// nothing from the scanned target can become markup, links or @mentions.
pub fn pr_comment(run: &Run) -> String {
    use crate::qa::report::md_inline;
    let (icon, word) = match run.verdict {
        Verdict::Pass => ("\u{2705}", "PASS"),
        Verdict::Warn => ("\u{26a0}\u{fe0f}", "WARN"),
        Verdict::Fail => ("\u{274c}", "FAIL"),
    };
    // Inside a code span Markdown escapes render literally, so strip what could end the span
    // or break the line instead of escaping it.
    let code = |t: &str| -> String {
        t.chars()
            .map(|c| if c == '`' || c.is_control() { ' ' } else { c })
            .take(200)
            .collect::<String>()
    };
    let mut o = format!(
        "{PR_COMMENT_MARKER}\n## {icon} ReadyHai: {word}\n\nTarget `{}` \u{b7} profile `{}` \u{b7} readyhai `{}`\n\n",
        code(&run.target.raw),
        format!("{:?}", run.profile).to_lowercase(),
        code(&run.version)
    );
    if let Some(qa) = &run.qa {
        o += &format!(
            "**Recommendation:** {}\n\n",
            md_inline(&format!("{:?}", qa.recommendation))
        );
    }
    for r in &run.reasons {
        o += &format!("- {}\n", md_inline(r));
    }
    let open: Vec<&Finding> = run
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::Suppressed)
        .collect();
    let new = open
        .iter()
        .filter(|f| f.status == FindingStatus::New)
        .count();
    o += &format!(
        "\n**{}** open findings ({new} new) \u{b7} {} fixed since baseline\n\n",
        open.len(),
        run.fixed
    );
    let cats: Vec<&CategorySummary> = run
        .categories
        .iter()
        .filter(|c| c.critical + c.high + c.medium + c.low > 0)
        .collect();
    if !cats.is_empty() {
        o += "| Category | Critical | High | Medium | Low |\n|---|---:|---:|---:|---:|\n";
        for c in cats {
            o += &format!(
                "| {} | {} | {} | {} | {} |\n",
                md_inline(&c.category),
                c.critical,
                c.high,
                c.medium,
                c.low
            );
        }
        o += "\n";
    }
    let mut top: Vec<&Finding> = open.clone();
    top.sort_by_key(|f| {
        (
            f.status != FindingStatus::New,
            sev_order(f.severity),
            f.rule.clone(),
        )
    });
    if !top.is_empty() {
        o += "<details><summary>Top findings</summary>\n\n| Severity | Status | Rule | Title | Location |\n|---|---|---|---|---|\n";
        for f in top.iter().take(PR_COMMENT_MAX) {
            o += &format!(
                "| {} | {} | {} | {} | {} |\n",
                f.severity.as_str(),
                status_str(f.status),
                md_inline(&f.rule).replace('|', "\\|"),
                md_inline(&f.title).replace('|', "\\|"),
                md_inline(&f.location).replace('|', "\\|"),
            );
        }
        if top.len() > PR_COMMENT_MAX {
            o += &format!(
                "\n_{} more in the full report artifact._\n",
                top.len() - PR_COMMENT_MAX
            );
        }
        o += "\n</details>\n";
    }
    o += "\n<sub>Exit codes: 0 PASS \u{b7} 1 WARN \u{b7} 2 FAIL. Full HTML/SARIF report is attached to the pipeline run.</sub>\n";
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Run {
        let mut f1 = Finding::new(
            "web.smoke",
            "web.xss",
            Category::Security,
            Severity::High,
            "<script>alert(1)</script>",
            "http://a/x",
        );
        f1.detail = "<img src=x onerror=alert(1)>".into();
        f1.finalize();
        let mut f2 = Finding::new(
            "rules.a",
            "r.two",
            Category::Quality,
            Severity::Low,
            "low",
            "src/a.rs:12",
        );
        f2.status = FindingStatus::Suppressed;
        f2.suppressed_reason = Some("ok".into());
        f2.finalize();
        let mk = |id: &str, s: CheckStatus, n| CheckResult {
            id: id.into(),
            title: id.into(),
            tool: None,
            status: s,
            findings: n,
            duration_ms: 5,
        };
        Run {
            id: "r1".into(),
            version: "0.1.0".into(),
            target: Target {
                kind: TargetKind::Web,
                raw: "http://a".into(),
                path: None,
                image: None,
                url: Some("http://a".into()),
                openapi: None,
                host: None,
                apk: None,
                device: None,
            },
            profile: Profile::Quick,
            started: "s".into(),
            finished: "f".into(),
            verdict: Verdict::Fail,
            reasons: vec!["FAIL: 1 high".into()],
            categories: vec![CategorySummary {
                category: "security".into(),
                high: 1,
                new: 1,
                ..Default::default()
            }],
            checks: vec![
                mk("web.smoke", CheckStatus::Failed, 1),
                mk("c2", CheckStatus::Passed, 0),
                mk("c3", CheckStatus::Partial("p".into()), 0),
                mk("c4", CheckStatus::Skipped("s".into()), 0),
                mk("c5", CheckStatus::NotApplicable("n".into()), 0),
                mk("c6", CheckStatus::Errored("e".into()), 0),
            ],
            findings: vec![f1, f2],
            fixed: 3,
            notes: vec!["<b>note</b>".into()],
            errors: vec![],
            qa: None,
        }
    }

    #[test]
    fn pr_comment_summarises_and_escapes() {
        let c = pr_comment(&sample());
        assert!(c.starts_with(PR_COMMENT_MARKER));
        assert!(c.contains("ReadyHai: FAIL"));
        assert!(c.contains("readyhai `0.1.0`"));
        assert!(c.contains("| security | 0 | 1 | 0 | 0 |"));
        // Suppressed finding is not listed; the open one is, escaped.
        assert!(!c.contains("r.two"));
        assert!(c.contains("web.xss"));
        assert!(!c.contains("<script>"));
        assert!(c.contains("**1** open findings (1 new)"));
    }

    #[test]
    fn html_escapes() {
        let h = html(&sample()).unwrap();
        assert!(h.contains("&lt;script&gt;alert(1)"));
        assert!(!h.contains("<script>"));
        assert!(!h.contains("<b>note</b>"));
        assert!(h.contains("Content-Security-Policy"));
        assert!(h.contains("FAIL"));
    }

    #[test]
    fn errors_render_escaped() {
        let mut r = sample();
        r.errors = vec![ErrorCluster {
            signature: "<img src=x onerror=alert(2)> <*>".into(),
            example: "<script>alert(3)</script> failed".into(),
            count: 7,
            source: "web.console".into(),
            first_seen: "#1".into(),
        }];
        let h = html(&r).unwrap();
        assert!(h.contains("Top errors"));
        assert!(h.contains("&lt;script&gt;alert(3)"));
        assert!(h.contains("&lt;img src=x"));
        assert!(!h.contains("<script>alert(3)"));
        assert!(!html(&sample()).unwrap().contains("Top errors"));
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"errors\"") && j.contains("web.console"));
    }

    #[test]
    fn sarif_counts() {
        let s = sarif(&sample());
        let r = s["runs"][0]["results"].as_array().unwrap();
        assert_eq!(r.len(), 2);
        assert!(
            r[0]["partialFingerprints"]["readyhai/v1"]
                .as_str()
                .unwrap()
                .len()
                > 4
        );
        assert_eq!(
            r[1]["locations"][0]["physicalLocation"]["region"]["startLine"],
            12
        );
        assert_eq!(r[1]["suppressions"][0]["kind"], "external");
    }

    #[test]
    fn junit_includes_qa_defects_by_check_and_orphans() {
        let mk = |check: &str, rule: &str, sev: Severity, status: FindingStatus| {
            let mut f = Finding::new(
                check,
                rule,
                Category::Quality,
                sev,
                format!("{rule} title"),
                "GET /x",
            );
            f.status = status;
            f.finalize();
            f
        };
        let mut r = sample();
        r.checks = ["qa.api.authz", "qa.ui", "web.smoke"]
            .iter()
            .map(|id| CheckResult {
                id: (*id).into(),
                title: (*id).into(),
                tool: None,
                status: CheckStatus::Failed,
                findings: 1,
                duration_ms: 1,
            })
            .collect();
        r.findings = vec![
            mk(
                "qa.api.authz",
                "qa.api.bola",
                Severity::Critical,
                FindingStatus::New,
            ),
            // a LOW QA defect is still a failed test
            mk("qa.ui", "qa.ui.a11y", Severity::Low, FindingStatus::New),
            // baselined (existing) QA defect: not a failure
            mk(
                "qa.ui",
                "qa.ui.visual_change",
                Severity::Low,
                FindingStatus::Existing,
            ),
            // non-QA low finding: not a failure
            mk("web.smoke", "web.low", Severity::Low, FindingStatus::New),
            // QA defect whose check is its rule (matches no check): reported, not dropped
            mk(
                "qa.api.validation_missing",
                "qa.api.validation_missing",
                Severity::Medium,
                FindingStatus::New,
            ),
        ];
        let x = junit(&r);
        let suite = |name: &str| {
            let a = x
                .find(&format!("<testsuite name=\"{name}\""))
                .unwrap_or_else(|| panic!("no suite {name}: {x}"));
            let b = x[a..].find("</testsuite>").unwrap();
            x[a..a + b].to_string()
        };
        assert!(
            suite("qa.api.authz").contains("failures=\"1\"")
                && suite("qa.api.authz").contains("qa.api.bola")
        );
        let ui = suite("qa.ui");
        assert!(
            ui.contains("failures=\"1\"")
                && ui.contains("qa.ui.a11y")
                && !ui.contains("visual_change")
        );
        assert!(suite("web.smoke").contains("failures=\"0\""));
        let o = suite("unattributed");
        assert!(o.contains("qa.api.validation_missing") && o.contains("failures=\"1\""));
        assert_eq!(x.matches("<failure").count(), 3);
        assert_eq!(
            x.matches("<testsuite ").count(),
            x.matches("</testsuite>").count()
        );
    }

    #[test]
    fn junit_wellformed() {
        let x = junit(&sample());
        assert_eq!(x.matches("<testsuite ").count(), 6);
        assert_eq!(x.matches("</testsuite>").count(), 6);
        assert_eq!(x.matches("<failure").count(), 1);
        assert_eq!(x.matches("<error ").count(), 1);
        assert_eq!(x.matches("<skipped").count(), 2);
        assert!(!x.contains("<script>"));
    }

    #[test]
    fn sarif_artifact_uris_are_valid_for_qa_components_and_odd_paths() {
        let mk = |loc: &str| {
            let mut f = Finding::new(
                "qa.api.functional",
                "qa.api.bola",
                Category::Security,
                Severity::High,
                "BOLA on the order",
                loc,
            );
            f.finalize();
            f
        };
        let mut run = sample();
        run.findings = vec![
            mk("GET /orders/{id}"),
            mk("GET /a, GET /b, GET /c"),
            mk("docs/my report.md:7"),
            mk("src/a.rs:12"),
            mk("http://h/x y?q=<1>"),
            mk("login"),
        ];
        let s = sarif(&run);
        let r = s["runs"][0]["results"].as_array().unwrap();
        // an operation is a logical location + named in the message, never an artifact URI
        for i in [0, 1] {
            let loc = &r[i]["locations"][0];
            assert!(loc.get("physicalLocation").is_none(), "{loc}");
            assert_eq!(
                loc["logicalLocations"][0]["name"],
                run.findings[i].location.as_str()
            );
            assert!(
                r[i]["message"]["text"]
                    .as_str()
                    .unwrap()
                    .contains(&run.findings[i].location)
            );
        }
        // every artifact URI that IS emitted is a legal URI reference
        let legal = |u: &str| {
            u.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&c))
                && !u.contains(' ')
        };
        for x in r {
            if let Some(u) =
                x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str()
            {
                assert!(legal(u), "invalid artifact uri {u:?}");
            }
        }
        let uri = |i: usize| {
            r[i]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(uri(2), "docs/my%20report.md");
        assert_eq!(
            r[2]["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        assert_eq!(uri(3), "src/a.rs");
        assert_eq!(uri(4), "http://h/x%20y?q=%3C1%3E");
        assert_eq!(uri(5), "login");
        // a path that was already percent-encoded is not double-encoded
        assert_eq!(uri_escape("a%20b"), "a%20b");
        assert_eq!(uri_escape("100%"), "100%25");
        assert!(
            is_component("POST /x") && !is_component("src/GET /x") && !is_component("GETTING /x")
        );
    }
}
