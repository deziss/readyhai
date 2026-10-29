//! Repo-side senior-QA checks: test-suite quality (coverage, untested routes, smells)
//! and release quality (EOL runtimes, migrations up/down/up, licences).
//! Everything here reads only the snapshot and `<run>/out`; the migration check is the only
//! one that starts containers.
use super::model::*;
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};
use crate::snapshot::Snapshot;
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const MAX_READ: u64 = 4 * 1024 * 1024;

pub fn checks() -> Vec<Check> {
    let k = &[TargetKind::Repo];
    vec![
        Check::new("qa.suite.coverage", "Test coverage report", k, Profile::Quick, coverage).qa(),
        Check::new("qa.suite.routes", "Routes without tests", k, Profile::Quick, routes).qa(),
        Check::new("qa.suite.smells", "Test smells", k, Profile::Quick, smells).qa(),
        Check::new("qa.release.eol", "End-of-life runtimes", k, Profile::Quick, eol).qa(),
        Check::new("qa.release.migrations", "Database migrations up/down/up", k, Profile::Standard, migrations).qa(),
        Check::new("qa.release.licenses", "Dependency licences", k, Profile::Quick, licenses).qa(),
    ]
}

// ------------------------------------------------------------------ shared helpers

fn read(snap: &Snapshot, rel: &str) -> Option<String> {
    if snap.denied.iter().any(|d| d.path == rel) {
        return None;
    }
    let p = snap.root.join(rel);
    if fs::metadata(&p).ok()?.len() > MAX_READ {
        return None;
    }
    Some(String::from_utf8_lossy(&fs::read(p).ok()?).into_owned())
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("static regex")
}

fn is_test_path(p: &str) -> bool {
    let l = p.to_lowercase();
    let name = l.rsplit('/').next().unwrap_or("");
    l.starts_with("tests/")
        || l.starts_with("test/")
        || l.contains("/tests/")
        || l.contains("/test/")
        || l.contains("/__tests__/")
        || name.starts_with("test_")
        || name.ends_with("_test.go")
        || name.ends_with("_test.py")
        || name.contains(".spec.")
        || name.contains(".test.")
        || name.ends_with("test.java")
        || name.ends_with("tests.java")
}

fn sev_prio(s: Severity) -> Priority {
    if s >= Severity::High { Priority::P2 } else if s == Severity::Medium { Priority::P3 } else { Priority::P4 }
}

/// Per-item defects are capped; the remainder becomes ONE roll-up defect (stable key) so a huge
/// repo cannot flood the report, while anything inside the cap still has its own fingerprint.
const MAX_ITEM_DEFECTS: usize = 100;

struct Def {
    rule: &'static str,
    cat: Category,
    sev: Severity,
    area: Area,
    title: String,
    component: String,
    expected: String,
    actual: String,
    remediation: String,
    fp_key: String,
    steps: Vec<String>,
}

impl Def {
    fn into_defect(self, case_id: &str) -> Defect {
        Defect {
            id: format!("S-{}-{}", self.rule, self.fp_key),
            rule: self.rule.into(),
            category: self.cat,
            severity: self.sev,
            priority: sev_prio(self.sev),
            area: self.area,
            title: self.title,
            component: self.component,
            environment: "repo snapshot".into(),
            steps_to_reproduce: self.steps,
            expected: self.expected,
            actual: self.actual,
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![case_id.into()],
            remediation: self.remediation,
            fp_key: self.fp_key,
            fingerprint: String::new(),
            status: Default::default(),
            regression: false,
            ai_note: None,
        }
    }
}

/// Register the case and its result, push defects to the collector (when this is a QA run),
/// and return the Finding twins.
fn record(
    ctx: &Ctx,
    check: &str,
    area: Area,
    case_id: &str,
    title: &str,
    component: &str,
    status: ResultStatus,
    actual: &str,
    defs: Vec<Def>,
) -> Vec<Finding> {
    let defects: Vec<Defect> = defs.into_iter().map(|d| d.into_defect(case_id)).collect();
    let findings: Vec<Finding> = defects.iter().map(|d| d.to_finding(check)).collect();
    if let Some(qa) = &ctx.qa {
        qa.with(|c| {
            c.cases.push(TestCase {
                id: case_id.into(),
                area,
                technique: Technique::Static,
                title: title.into(),
                priority: Priority::P3,
                component: component.into(),
                role: None,
                steps: vec![],
                expected: String::new(),
                source: CaseSource::Deterministic,
            });
            c.results.push(TestResult {
                case_id: case_id.into(),
                status,
                actual: actual.into(),
                duration_ms: 0,
                attempts: 1,
                evidence: vec![],
                defect_id: defects.first().map(|d| d.id.clone()),
            });
            c.defects.extend(defects.iter().cloned());
        });
    }
    findings
}

fn untested(ctx: &Ctx, msg: &str) {
    if let Some(qa) = &ctx.qa {
        qa.with(|c| c.untested.push(msg.to_string()));
    }
}

fn out(findings: Vec<Finding>) -> CheckOutput {
    CheckOutput::findings(findings)
}

fn no_snapshot() -> anyhow::Result<CheckOutput> {
    Ok(CheckOutput::status(CheckStatus::NotApplicable("no repo snapshot".into())))
}

// ------------------------------------------------------------------ 1. coverage

#[derive(Debug, Default, PartialEq)]
struct Cov {
    /// 0.0..=1.0
    overall: f64,
    files: Vec<(String, f64)>,
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let r = Regex::new(&format!(r#"(?:^|\s){}\s*=\s*"([^"]*)""#, regex::escape(name))).ok()?;
    r.captures(tag).map(|c| c[1].to_string())
}

fn parse_cobertura(t: &str) -> Option<Cov> {
    let root = re(r"<coverage\b[^>]*>").find(t)?.as_str().to_string();
    let mut files: Vec<(String, f64)> = vec![];
    for m in re(r"<class\b[^>]*>").find_iter(t) {
        let tag = m.as_str();
        if let (Some(f), Some(r)) = (attr(tag, "filename"), attr(tag, "line-rate")) {
            if let Ok(r) = r.parse::<f64>() {
                if !files.iter().any(|(n, _)| *n == f) {
                    files.push((f, r));
                }
            }
        }
    }
    let overall = attr(&root, "line-rate")?.parse::<f64>().ok()?;
    Some(Cov { overall, files })
}

fn parse_lcov(t: &str) -> Option<Cov> {
    let (mut files, mut cur, mut lf, mut lh) = (vec![], String::new(), 0u64, 0u64);
    let (mut tf, mut th) = (0u64, 0u64);
    for l in t.lines() {
        if let Some(f) = l.strip_prefix("SF:") {
            cur = f.trim().to_string();
            lf = 0;
            lh = 0;
        } else if let Some(v) = l.strip_prefix("LF:") {
            lf = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = l.strip_prefix("LH:") {
            lh = v.trim().parse().unwrap_or(0);
        } else if l.starts_with("end_of_record") && !cur.is_empty() {
            tf += lf;
            th += lh;
            files.push((cur.clone(), if lf == 0 { 1.0 } else { lh as f64 / lf as f64 }));
            cur.clear();
        }
    }
    if files.is_empty() {
        return None;
    }
    Some(Cov { overall: if tf == 0 { 1.0 } else { th as f64 / tf as f64 }, files })
}

fn parse_jacoco(t: &str) -> Option<Cov> {
    let pkg = re(r#"<package\b[^>]*>"#);
    let sf = re(r#"<sourcefile\b[^>]*>"#);
    let ctr = re(r#"<counter\b[^>]*type="LINE"[^>]*>"#);
    // Walk in document order: remember current package, then per-sourcefile LINE counter
    // (the first LINE counter after a <sourcefile> before the next </sourcefile>).
    let mut files = vec![];
    let (mut tm, mut tc) = (0u64, 0u64);
    let mut cur_pkg = String::new();
    let mut pos = 0;
    while pos < t.len() {
        let rest = &t[pos..];
        let p = pkg.find(rest).map(|m| (m.start(), m.end(), true));
        let s = sf.find(rest).map(|m| (m.start(), m.end(), false));
        let next = match (p, s) {
            (Some(a), Some(b)) => if a.0 <= b.0 { a } else { b },
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        let tag = &rest[next.0..next.1];
        if next.2 {
            cur_pkg = attr(tag, "name").unwrap_or_default();
            pos += next.1;
        } else {
            let end = rest[next.1..].find("</sourcefile>").map(|e| next.1 + e).unwrap_or(rest.len());
            if let Some(c) = ctr.find(&rest[next.1..end]) {
                let ct = c.as_str();
                let m: u64 = attr(ct, "missed").and_then(|v| v.parse().ok()).unwrap_or(0);
                let cv: u64 = attr(ct, "covered").and_then(|v| v.parse().ok()).unwrap_or(0);
                let name = attr(tag, "name").unwrap_or_default();
                let path = if cur_pkg.is_empty() { name } else { format!("{cur_pkg}/{name}") };
                tm += m;
                tc += cv;
                files.push((path, if m + cv == 0 { 1.0 } else { cv as f64 / (m + cv) as f64 }));
            }
            pos += end.max(next.1);
        }
    }
    if files.is_empty() {
        return None;
    }
    let total = tm + tc;
    Some(Cov { overall: if total == 0 { 1.0 } else { tc as f64 / total as f64 }, files })
}

fn parse_coverage(name: &str, text: &str) -> Option<Cov> {
    let n = name.rsplit('/').next().unwrap_or(name).to_lowercase();
    if n.contains("lcov") {
        parse_lcov(text)
    } else if n.contains("jacoco") {
        parse_jacoco(text)
    } else {
        parse_cobertura(text)
    }
}

fn is_cov_name(n: &str) -> bool {
    matches!(n, "coverage.xml" | "lcov.info" | "jacoco.xml" | "cobertura.xml")
}

/// Coverage reports in the snapshot plus `<out>/` (one level deep).
fn find_coverage(ctx: &Ctx, snap: &Snapshot) -> Option<(String, Cov)> {
    for f in &snap.files {
        let name = f.rsplit('/').next().unwrap_or(f);
        if is_cov_name(name) && !f.contains("node_modules/") {
            if let Some(c) = read(snap, f).and_then(|t| parse_coverage(name, &t)) {
                return Some((f.clone(), c));
            }
        }
    }
    let out = ctx.out_dir();
    let mut stack = vec![(out, 0)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if p.is_dir() && depth < 2 {
                stack.push((p, depth + 1));
            } else if is_cov_name(&name) && fs::metadata(&p).map(|m| m.len() <= MAX_READ).unwrap_or(false) {
                if let Some(c) = fs::read_to_string(&p).ok().and_then(|t| parse_coverage(&name, &t)) {
                    return Some((format!("out/{name}"), c));
                }
            }
        }
    }
    None
}

fn is_critical_path(p: &str) -> bool {
    let l = p.to_lowercase();
    ["auth", "payment", "order", "security", "admin"].iter().any(|k| l.contains(k))
}

const LOW_COVERAGE: f64 = 0.60;

/// 10-point band of a coverage percentage (55.0 -> 50): part of the low-coverage fingerprint.
fn cov_band(pct: f64) -> u32 {
    ((pct / 10.0).floor().max(0.0) as u32) * 10
}

fn coverage(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else { return no_snapshot() };
    let case = "suite.coverage";
    let Some((src, cov)) = find_coverage(ctx, snap) else {
        untested(ctx, "no coverage report (add --cov / lcov to [test] command)");
        record(ctx, "qa.suite.coverage", Area::Suite, case, "Coverage report present", ".", ResultStatus::Blocked,
            "no coverage report found", vec![]);
        return Ok(CheckOutput::status(CheckStatus::Skipped(
            "no coverage report (add --cov / lcov to [test] command)".into(),
        )));
    };
    let mut defs = vec![];
    let pct = cov.overall * 100.0;
    if cov.overall < LOW_COVERAGE {
        // The report is the item; the 10-point band is part of the key, so coverage falling into a
        // lower band is a NEW finding instead of hiding behind the old accepted one.
        let band = cov_band(pct);
        defs.push(Def {
            rule: "qa.suite.low_coverage",
            cat: Category::Quality,
            sev: Severity::Medium,
            area: Area::Suite,
            title: format!("Line coverage is {pct:.0}% (below {:.0}%)", LOW_COVERAGE * 100.0),
            component: src.clone(),
            expected: format!("line coverage >= {:.0}%", LOW_COVERAGE * 100.0),
            actual: format!("{pct:.1}% over {} file(s) in {src}", cov.files.len()),
            remediation: "Add tests for the uncovered modules, starting with the riskiest ones.".into(),
            fp_key: format!("overall:{src}:{band}"),
            steps: vec![format!("Open {src} and compare line-rate against the 60% bar")],
        });
    }
    let crit: Vec<&(String, f64)> = cov.files.iter().filter(|(f, r)| *r <= 0.0 && is_critical_path(f)).collect();
    for (f, _) in crit {
        defs.push(Def {
            rule: "qa.suite.critical_uncovered",
            cat: Category::Quality,
            sev: Severity::Medium,
            area: Area::Suite,
            title: format!("Security/business-critical file has 0% coverage: {f}"),
            component: f.clone(),
            expected: "critical paths (auth, payment, order, security, admin) are exercised by tests".into(),
            actual: format!("{f}: 0% line coverage"),
            remediation: "Write tests that execute this module before release.".into(),
            fp_key: f.clone(),
            steps: vec![format!("Open {src} and find {f}")],
        });
    }
    let st = if defs.is_empty() { ResultStatus::Pass } else { ResultStatus::Fail };
    Ok(out(record(ctx, "qa.suite.coverage", Area::Suite, case, "Coverage meets the bar", &src, st,
        &format!("{pct:.1}% from {src}"), defs)))
}

// ------------------------------------------------------------------ 2. routes

#[derive(Debug, Clone, PartialEq)]
struct Route {
    method: String,
    path: String,
    file: String,
    line: usize,
}

impl Route {
    fn label(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

fn extract_routes(file: &str, text: &str) -> Vec<Route> {
    let ext = file.rsplit('.').next().unwrap_or("");
    let name = file.rsplit('/').next().unwrap_or("");
    let mut v = vec![];
    let mut push = |m: &str, p: &str, off: usize| {
        let line = text[..off].matches('\n').count() + 1;
        v.push(Route { method: m.to_uppercase(), path: p.to_string(), file: file.to_string(), line });
    };
    match ext {
        "py" => {
            for c in re(r#"@\w+(?:\.\w+)*\.(get|post|put|delete|patch)\(\s*["']([^"']*)["']"#).captures_iter(text) {
                push(&c[1], &c[2], c.get(0).unwrap().start());
            }
            for c in re(r#"@\w+(?:\.\w+)*\.route\(\s*["']([^"']*)["']([^)]*)"#).captures_iter(text) {
                let methods = re(r#"methods\s*=\s*[\[\(]([^\]\)]*)"#)
                    .captures(&c[2])
                    .map(|m| re(r#"["'](\w+)["']"#).captures_iter(&m[1]).map(|x| x[1].to_uppercase()).collect::<Vec<_>>())
                    .unwrap_or_default();
                let off = c.get(0).unwrap().start();
                if methods.is_empty() {
                    push("GET", &c[1], off);
                } else {
                    for m in methods {
                        push(&m, &c[1], off);
                    }
                }
            }
            if name == "urls.py" {
                for c in re(r#"\b(?:re_)?path\(\s*r?["']([^"']*)["']"#).captures_iter(text) {
                    push("ANY", &c[1], c.get(0).unwrap().start());
                }
            }
        }
        "js" | "ts" | "mjs" | "cjs" | "jsx" | "tsx" => {
            for c in re(r#"\b(?:app|router|server|api)\.(get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]"#)
                .captures_iter(text)
            {
                push(&c[1], &c[2], c.get(0).unwrap().start());
            }
        }
        "java" | "kt" => {
            for c in re(r#"@(Get|Post|Put|Delete|Patch)Mapping\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*"([^"]*)""#)
                .captures_iter(text)
            {
                push(&c[1], &c[2], c.get(0).unwrap().start());
            }
            for c in re(r#"@RequestMapping\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*"([^"]*)"([^)]*)"#).captures_iter(text) {
                let m = re(r"RequestMethod\.(\w+)").captures(&c[2]).map(|x| x[1].to_string()).unwrap_or("ANY".into());
                push(&m, &c[1], c.get(0).unwrap().start());
            }
        }
        _ => {}
    }
    v
}

/// Literal route path -> regex that matches it inside test source (params become a segment wildcard).
fn route_regex(path: &str) -> Option<Regex> {
    let mut p = path.trim().to_string();
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    // Django-style routes end with "/", so do Flask/FastAPI variants; tolerate either.
    let trimmed = p.trim_end_matches('/');
    let p = if trimmed.is_empty() { "/".to_string() } else { trimmed.to_string() };
    let seg = r#"[^/"'`\s?#]+"#;
    let mut rx = String::new();
    if p == "/" {
        return Regex::new(r#"["'`]/["'`?]"#).ok();
    }
    let param = re(r"^(?:\{[^}]*\}|:[A-Za-z_]\w*|<[^>]*>|\(\?P<[^>]*>[^)]*\))$");
    for s in p.split('/').skip(1) {
        rx.push('/');
        if param.is_match(s) || s == "*" {
            rx.push_str(seg);
        } else {
            rx.push_str(&regex::escape(s));
        }
    }
    rx.push_str(r#"/?(?:[?"'`\s)#,;\]]|$)"#);
    Regex::new(&rx).ok()
}

fn routes_tested(routes: &[Route], tests: &[String]) -> Vec<(Route, bool)> {
    routes
        .iter()
        .map(|r| {
            let t = route_regex(&r.path).map(|rx| tests.iter().any(|t| rx.is_match(t))).unwrap_or(true);
            (r.clone(), t)
        })
        .collect()
}

fn routes(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else { return no_snapshot() };
    let (mut rs, mut tests) = (vec![], vec![]);
    for f in &snap.files {
        let ext = f.rsplit('.').next().unwrap_or("");
        if !matches!(ext, "py" | "js" | "ts" | "mjs" | "cjs" | "jsx" | "tsx" | "java" | "kt" | "go") {
            continue;
        }
        if f.contains("node_modules/") || f.contains("/.venv/") || f.starts_with(".venv/") {
            continue;
        }
        let Some(t) = read(snap, f) else { continue };
        if is_test_path(f) {
            tests.push(t);
        } else {
            rs.extend(extract_routes(f, &t));
        }
    }
    let mut seen = BTreeSet::new();
    rs.retain(|r| seen.insert((r.method.clone(), r.path.clone())));
    if rs.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable("no HTTP routes found".into())));
    }
    let res = routes_tested(&rs, &tests);
    if let Some(qa) = &ctx.qa {
        qa.with(|c| {
            for (r, t) in &res {
                c.coverage.set(&r.label(), "has test", if *t { Cell::Pass } else { Cell::Untested });
            }
        });
    }
    let missing: Vec<&Route> = res.iter().filter(|(_, t)| !*t).map(|(r, _)| r).collect();
    let mut defs = vec![];
    for r in missing.iter().take(MAX_ITEM_DEFECTS) {
        defs.push(Def {
            rule: "qa.suite.untested_routes",
            cat: Category::Quality,
            sev: Severity::Medium,
            area: Area::Suite,
            title: format!("Route {} is never referenced by a test", r.label()),
            component: r.label(),
            expected: "every route is exercised by at least one test".into(),
            actual: format!("{} ({}:{})", r.label(), r.file, r.line),
            remediation: "Add tests that call this route (happy path, auth failure and bad input).".into(),
            fp_key: format!("route:{}", r.label()),
            steps: vec![format!("grep the test directories for `{}`", r.path)],
        });
    }
    if missing.len() > MAX_ITEM_DEFECTS {
        let rest: Vec<String> = missing[MAX_ITEM_DEFECTS..].iter().map(|r| r.label()).collect();
        defs.push(Def {
            rule: "qa.suite.untested_routes",
            cat: Category::Quality,
            sev: Severity::Medium,
            area: Area::Suite,
            title: format!("{} more routes are never referenced by a test", rest.len()),
            component: "routes".into(),
            expected: "every route is exercised by at least one test".into(),
            actual: rest.join("\n"),
            remediation: "Add tests that call these routes.".into(),
            fp_key: "routes:overflow".into(),
            steps: vec!["grep the test directories for each listed path".into()],
        });
    }
    let st = if defs.is_empty() { ResultStatus::Pass } else { ResultStatus::Fail };
    Ok(out(record(ctx, "qa.suite.routes", Area::Suite, "suite.routes", "Every route has a test", "routes", st,
        &format!("{}/{} routes referenced by tests", rs.len() - missing.len(), rs.len()), defs)))
}

// ------------------------------------------------------------------ 3. smells

#[derive(Debug, Default, PartialEq)]
struct Smells {
    no_assert: Vec<String>,
    skipped: Vec<String>,
    sleeps: Vec<String>,
}

fn py_assertive(body: &str) -> bool {
    body.contains("assert") || body.contains("pytest.raises") || body.contains("pytest.fail") || body.contains(".raises(")
        || body.contains("pytest.warns") || body.contains("expect(")
}

fn scan_smells(file: &str, text: &str, s: &mut Smells) {
    let ext = file.rsplit('.').next().unwrap_or("");
    let lines: Vec<&str> = text.lines().collect();
    let loc = |i: usize| format!("{file}:{}", i + 1);
    let sleep_py = re(r"\btime\.sleep\(\s*([0-9.]+)");
    let sleep_js = re(r"\bsetTimeout\([^;]*?,\s*([0-9_]+)\s*\)");
    let sleep_java = re(r"\bThread\.sleep\(\s*([0-9_]+)");
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        if t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        match ext {
            "py" => {
                if t.starts_with("@pytest.mark.skip") || t.starts_with("@unittest.skip") || t.starts_with("@skip") {
                    s.skipped.push(loc(i));
                }
                if let Some(c) = sleep_py.captures(l) {
                    if c[1].parse::<f64>().unwrap_or(1.0) >= 1.0 {
                        s.sleeps.push(loc(i));
                    }
                }
            }
            "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => {
                if re(r"\b(?:it|test|describe)\.skip\(|\bx(?:it|describe|test)\(").is_match(l) {
                    s.skipped.push(loc(i));
                }
                if let Some(c) = sleep_js.captures(l) {
                    if c[1].replace('_', "").parse::<u64>().unwrap_or(0) >= 1000 {
                        s.sleeps.push(loc(i));
                    }
                }
            }
            "java" | "kt" => {
                if t.starts_with("@Disabled") || t.starts_with("@Ignore") {
                    s.skipped.push(loc(i));
                }
                if let Some(c) = sleep_java.captures(l) {
                    if c[1].replace('_', "").parse::<u64>().unwrap_or(0) >= 1000 {
                        s.sleeps.push(loc(i));
                    }
                }
            }
            _ => {}
        }
    }
    match ext {
        "py" => {
            let def = re(r"^(\s*)(?:async\s+)?def\s+(test_\w*)\s*\(");
            let mut i = 0;
            while i < lines.len() {
                if let Some(c) = def.captures(lines[i]) {
                    let ind = c[1].len();
                    let mut j = i + 1;
                    let mut body = String::new();
                    while j < lines.len() {
                        let l = lines[j];
                        if !l.trim().is_empty() && l.len() - l.trim_start().len() <= ind {
                            break;
                        }
                        body.push_str(l);
                        body.push('\n');
                        j += 1;
                    }
                    if !py_assertive(&body) {
                        s.no_assert.push(format!("{}:{} {}", file, i + 1, &c[2]));
                    }
                    i = j.max(i + 1);
                } else {
                    i += 1;
                }
            }
        }
        "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => {
            let start = re(r#"^\s*(?:it|test)\(\s*['"`]([^'"`]*)['"`]"#);
            for (i, l) in lines.iter().enumerate() {
                if let Some(c) = start.captures(l) {
                    let (mut depth, mut seen, mut body) = (0i32, false, String::new());
                    for l2 in &lines[i..] {
                        for ch in l2.chars() {
                            if ch == '{' {
                                depth += 1;
                                seen = true;
                            } else if ch == '}' {
                                depth -= 1;
                            }
                        }
                        body.push_str(l2);
                        body.push('\n');
                        if seen && depth <= 0 {
                            break;
                        }
                    }
                    if seen && !(body.contains("expect") || body.contains("assert") || body.contains(".should")) {
                        s.no_assert.push(format!("{}:{} {}", file, i + 1, &c[1]));
                    }
                }
            }
        }
        _ => {}
    }
}

/// `file:line rest` -> (file, line, rest).
fn split_loc(entry: &str) -> (String, String, String) {
    let (loc, rest) = entry.split_once(' ').unwrap_or((entry, ""));
    let (file, line) = loc.rsplit_once(':').unwrap_or((loc, ""));
    (file.to_string(), line.to_string(), rest.to_string())
}

/// One defect per smell. Identity never uses a line number: a test without assertions is keyed by
/// file + test name; skipped tests / sleeps by file + their ordinal within the file, so adding one
/// more of them in a file that already has some is a new fingerprint.
fn smell_defs(s: &Smells) -> Vec<Def> {
    let mut defs: Vec<Def> = vec![];
    let mk = |kind: &str, file: &str, line: &str, name: &str, key: String| {
        let (title, expected, rem) = match kind {
            "no_assert" => (format!("Test `{name}` has no assertions ({file})"), "every test asserts something", "Add assertions."),
            "skipped" => (format!("Skipped test in {file}"), "no test is silently skipped", "Fix or delete the skipped test."),
            _ => (format!("Sleep of 1s or more in a test ({file})"), "tests do not rely on sleeps", "Replace the sleep with polling or a fake clock."),
        };
        Def {
            rule: "qa.suite.test_smells",
            cat: Category::Quality,
            sev: Severity::Low,
            area: Area::Suite,
            title,
            component: file.to_string(),
            expected: expected.into(),
            actual: format!("{file}:{line}{}", if name.is_empty() { String::new() } else { format!(" {name}") }),
            remediation: rem.into(),
            fp_key: key,
            steps: vec![format!("Open {file}:{line}")],
        }
    };
    let mut ordinal: std::collections::BTreeMap<(String, &str), usize> = Default::default();
    for (kind, items) in [("no_assert", &s.no_assert), ("skipped", &s.skipped), ("sleep", &s.sleeps)] {
        for e in items.iter() {
            if defs.len() >= MAX_ITEM_DEFECTS {
                break;
            }
            let (file, line, name) = split_loc(e);
            let key = if kind == "no_assert" {
                format!("smell:no_assert:{file}:{name}")
            } else {
                let n = ordinal.entry((file.clone(), kind)).or_insert(0);
                *n += 1;
                format!("smell:{kind}:{file}:{n}")
            };
            defs.push(mk(kind, &file, &line, &name, key));
        }
    }
    let total = s.no_assert.len() + s.skipped.len() + s.sleeps.len();
    if total > defs.len() {
        defs.push(Def {
            rule: "qa.suite.test_smells",
            cat: Category::Quality,
            sev: Severity::Low,
            area: Area::Suite,
            title: format!("{} more test smells", total - defs.len()),
            component: "tests".into(),
            expected: "every test asserts, none are silently skipped or rely on sleeps".into(),
            actual: format!("{} smell(s) beyond the first {MAX_ITEM_DEFECTS}", total - defs.len()),
            remediation: "Add assertions, delete or fix skipped tests, replace sleeps with polling/fakes.".into(),
            fp_key: "smell:overflow".into(),
            steps: vec![],
        });
    }
    defs
}

fn smells(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else { return no_snapshot() };
    let mut s = Smells::default();
    let mut n_tests = 0;
    for f in &snap.files {
        if !is_test_path(f) || f.contains("node_modules/") {
            continue;
        }
        let ext = f.rsplit('.').next().unwrap_or("");
        if !matches!(ext, "py" | "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" | "java" | "kt") {
            continue;
        }
        if let Some(t) = read(snap, f) {
            n_tests += 1;
            scan_smells(f, &t, &mut s);
        }
    }
    if n_tests == 0 {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable("no test files".into())));
    }
    let total = s.no_assert.len() + s.skipped.len() + s.sleeps.len();
    let defs = smell_defs(&s);
    let st = if defs.is_empty() { ResultStatus::Pass } else { ResultStatus::Fail };
    Ok(out(record(ctx, "qa.suite.smells", Area::Suite, "suite.smells", "Tests are meaningful and stable", "tests", st,
        &format!("{total} smell(s) in {n_tests} test file(s)"), defs)))
}

// ------------------------------------------------------------------ 4. EOL

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn day_num(date: &str) -> Option<i64> {
    let mut it = date.get(..10)?.split('-');
    let y = it.next()?.parse().ok()?;
    let m = it.next()?.parse().ok()?;
    let d = it.next()?.parse().ok()?;
    Some(days_from_civil(y, m, d))
}

#[derive(Debug, Clone, PartialEq)]
struct Runtime {
    product: &'static str,
    version: String,
    source: String,
    /// "exact" (image tag, .python-version, ...) or "min" (>= range lower bound).
    exact: bool,
}

#[derive(Debug, PartialEq)]
enum EolState {
    Eol(String),
    Soon(String, i64),
}

fn debian_codename(t: &str) -> Option<&'static str> {
    Some(match t {
        "jessie" => "8", "stretch" => "9", "buster" => "10", "bullseye" => "11", "bookworm" => "12", "trixie" => "13",
        _ => return None,
    })
}
fn ubuntu_codename(t: &str) -> Option<&'static str> {
    Some(match t {
        "xenial" => "16.04", "bionic" => "18.04", "focal" => "20.04", "jammy" => "22.04", "noble" => "24.04",
        _ => return None,
    })
}

fn from_images(text: &str, file: &str) -> Vec<Runtime> {
    let from = re(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?");
    let mut stages: Vec<String> = vec![];
    let mut out = vec![];
    for c in from.captures_iter(text) {
        let img = c[1].to_string();
        let alias = c.get(2).map(|a| a.as_str().to_lowercase());
        if !stages.contains(&img.to_lowercase()) && !img.contains("$") {
            let base = img.split('@').next().unwrap_or("");
            let last = base.rsplit('/').next().unwrap_or("");
            let (name, tag) = last.split_once(':').unwrap_or((last, ""));
            let product = match name {
                "python" => Some("python"),
                "node" => Some("nodejs"),
                "ubuntu" => Some("ubuntu"),
                "debian" => Some("debian"),
                "alpine" => Some("alpine"),
                "golang" => Some("go"),
                "postgres" => Some("postgresql"),
                _ => None,
            };
            if let Some(p) = product {
                let version = tag_version(p, tag);
                if let Some(v) = version {
                    out.push(Runtime { product: p, version: v, source: file.to_string(), exact: true });
                }
            }
        }
        if let Some(a) = alias {
            stages.push(a);
        }
    }
    out
}

fn tag_version(product: &str, tag: &str) -> Option<String> {
    if tag.is_empty() || tag == "latest" {
        return None;
    }
    let head = tag.split('-').next().unwrap_or(tag);
    if product == "debian" {
        if let Some(v) = debian_codename(head) {
            return Some(v.into());
        }
    }
    if product == "ubuntu" {
        if let Some(v) = ubuntu_codename(head) {
            return Some(v.into());
        }
    }
    if let Some(c) = re(r"^v?(\d+(?:\.\d+)*)").captures(head) {
        return Some(c[1].to_string());
    }
    // python:3.8-slim-bookworm etc. handled above; debian "bookworm-slim" handled by head.
    None
}

fn range_min(spec: &str) -> Option<(String, bool)> {
    let s = spec.trim();
    let c = re(r"^(>=|>|==|~=|\^|~|<=|<)?\s*v?(\d+(?:\.\d+)*)").captures(s)?;
    let op = c.get(1).map(|m| m.as_str()).unwrap_or("");
    let exact = op.is_empty() || op == "==";
    if op.starts_with('<') {
        return None;
    }
    Some((c[2].to_string(), exact))
}

fn runtime_hints(snap: &Snapshot) -> Vec<Runtime> {
    let mut v = vec![];
    for f in &snap.files {
        let name = f.rsplit('/').next().unwrap_or(f);
        match name {
            "pyproject.toml" => {
                if let Some(t) = read(snap, f) {
                    if let Some(c) = re(r#"(?m)^\s*requires-python\s*=\s*["']([^"']+)["']"#).captures(&t) {
                        // first clause only (">=3.8,<4")
                        let first = c[1].split(',').next().unwrap_or("");
                        if let Some((ver, exact)) = range_min(first) {
                            v.push(Runtime { product: "python", version: ver, source: f.clone(), exact });
                        }
                    }
                }
            }
            "package.json" if !f.contains("node_modules/") => {
                if let Some(j) = read(snap, f).and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
                    if let Some(n) = j.pointer("/engines/node").and_then(|x| x.as_str()) {
                        let first = n.split("||").next().unwrap_or(n).split_whitespace().next().unwrap_or("");
                        let first = first.trim_end_matches(".x").trim_end_matches(".*");
                        if let Some((ver, exact)) = range_min(first) {
                            v.push(Runtime { product: "nodejs", version: ver, source: f.clone(), exact });
                        }
                    }
                }
            }
            ".python-version" | ".nvmrc" | ".node-version" => {
                if let Some(t) = read(snap, f) {
                    if let Some(c) = re(r"(\d+(?:\.\d+)*)").captures(t.trim()) {
                        let p = if name == ".python-version" { "python" } else { "nodejs" };
                        v.push(Runtime { product: p, version: c[1].to_string(), source: f.clone(), exact: true });
                    }
                }
            }
            _ => {}
        }
    }
    v
}

/// Look up `version` in the EOL table, trying progressively shorter prefixes (3.8.10 -> 3.8 -> 3).
fn eol_date(table: &Value, product: &str, version: &str) -> Option<(String, String)> {
    let cycles = table.get(product)?.as_array()?;
    let parts: Vec<&str> = version.split('.').collect();
    for n in (1..=parts.len()).rev() {
        let cand = parts[..n].join(".");
        if let Some(c) = cycles.iter().find(|c| c.get("cycle").and_then(|x| x.as_str()) == Some(cand.as_str())) {
            let e = match c.get("eol") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Bool(true)) => "1970-01-01".into(),
                _ => return None,
            };
            return Some((cand, e));
        }
    }
    None
}

fn eol_state(table: &Value, rt: &Runtime, today: &str) -> Option<(String, EolState)> {
    let (cycle, date) = eol_date(table, rt.product, &rt.version)?;
    let (t, e) = (day_num(today)?, day_num(&date)?);
    if e < t {
        Some((cycle, EolState::Eol(date)))
    } else if e - t <= 180 {
        Some((cycle, EolState::Soon(date, e - t)))
    } else {
        None
    }
}

fn eol(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else { return no_snapshot() };
    let table = crate::bundle::endoflife();
    let mut rts = vec![];
    for f in &ctx.facts.dockerfiles {
        if let Some(t) = read(snap, f) {
            rts.extend(from_images(&t, f));
        }
    }
    rts.extend(runtime_hints(snap));
    if rts.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable("no runtime versions detected".into())));
    }
    Ok(out(eol_eval(ctx, &table, &rts, &crate::engine::today())))
}

fn eol_eval(ctx: &Ctx, table: &Value, rts: &[Runtime], today: &str) -> Vec<Finding> {
    let mut defs = vec![];
    let mut seen = BTreeSet::new();
    for rt in rts {
        let Some((cycle, st)) = eol_state(table, rt, today) else { continue };
        if !seen.insert((rt.product, cycle.clone(), rt.source.clone())) {
            continue;
        }
        let (sev, title, actual) = match (&st, rt.exact) {
            (EolState::Eol(d), true) => (Severity::High, format!("{} {} reached end of life on {d}", rt.product, cycle), format!("{} {} (EOL {d}) in {}", rt.product, cycle, rt.source)),
            (EolState::Eol(d), false) => (Severity::Low, format!("{} {} (EOL {d}) is still within the supported range", rt.product, cycle), format!("{} declares support from {} (EOL {d})", rt.source, rt.version)),
            (EolState::Soon(d, n), true) => (Severity::Medium, format!("{} {} reaches end of life in {n} days ({d})", rt.product, cycle), format!("{} {} (EOL {d}) in {}", rt.product, cycle, rt.source)),
            (EolState::Soon(d, n), false) => (Severity::Low, format!("{} {} (declared minimum) ends support in {n} days ({d})", rt.product, cycle), format!("{} declares support from {}", rt.source, rt.version)),
        };
        defs.push(Def {
            rule: "qa.release.eol_runtime",
            cat: Category::SupplyChain,
            sev,
            area: Area::Release,
            title,
            component: rt.source.clone(),
            expected: "runtimes and base images are inside their vendor support window".into(),
            actual,
            remediation: format!("Upgrade {} to a supported release.", rt.product),
            fp_key: format!("eol:{}:{}:{}", rt.product, cycle, rt.source),
            steps: vec![format!("Check {} against https://endoflife.date/{}", rt.source, rt.product)],
        });
    }
    let n = defs.len();
    let st = if n == 0 { ResultStatus::Pass } else { ResultStatus::Fail };
    record(ctx, "qa.release.eol", Area::Release, "release.eol", "Runtimes are supported", ".", st,
        &format!("{} runtime reference(s) checked, {n} at or near EOL", rts.len()), defs)
}

// ------------------------------------------------------------------ 5. migrations

#[derive(Debug, PartialEq)]
enum MigTool {
    Alembic(String),
    Prisma,
    Flyway,
}

fn detect_migrations(files: &[String]) -> Vec<MigTool> {
    let mut v = vec![];
    for f in files {
        if f == "alembic.ini" || f.ends_with("/alembic.ini") {
            let dir = f.trim_end_matches("alembic.ini").trim_end_matches('/').to_string();
            let has_versions = files.iter().any(|x| x.contains("/versions/") && x.ends_with(".py"));
            if has_versions && !v.contains(&MigTool::Alembic(dir.clone())) {
                v.push(MigTool::Alembic(dir));
            }
        }
    }
    if files.iter().any(|f| f.ends_with("prisma/schema.prisma")) && files.iter().any(|f| f.contains("prisma/migrations/")) {
        v.push(MigTool::Prisma);
    }
    if files.iter().any(|f| f.contains("db/migration/V") && f.ends_with(".sql")) {
        v.push(MigTool::Flyway);
    }
    v
}

/// Shell script run inside the app image. Exit code identifies the failing step.
const ALEMBIC_SCRIPT: &str = "echo '##STEP upgrade head'; alembic upgrade head || exit 11; \
echo '##STEP downgrade base'; alembic downgrade base || exit 12; \
echo '##STEP upgrade head (again)'; alembic upgrade head || exit 13";

/// Exit codes that say the TOOLING failed, not the migration: docker run error (125), command
/// not invokable (126) / not found (127: no alembic in the image), SIGKILL/OOM (137), SIGTERM (143).
/// They must not be reported as a migration defect.
fn infra_exit(code: i32) -> Option<&'static str> {
    Some(match code {
        125 => "docker could not run the container (exit 125)",
        126 => "the migration command is not executable in the image (exit 126)",
        127 => "alembic/sh not found in the image (exit 127): is alembic installed in the [test] image?",
        137 => "the container was killed (exit 137: OOM or SIGKILL)",
        143 => "the container was terminated (exit 143)",
        _ => return None,
    })
}

fn step_for_exit(code: i32) -> &'static str {
    match code {
        11 => "alembic upgrade head",
        12 => "alembic downgrade base",
        13 => "alembic upgrade head (after downgrade)",
        _ => "container start / alembic setup",
    }
}

/// Hardening flags shared by both containers. The migration check cannot use `Docker::run`
/// (tools.rs): that API forces `--network none|bridge`, and the app container must reach a
/// sibling database container over a per-run `--internal` network (no internet, no host).
/// So we build the `docker run` ourselves with the same hardening: cap-drop ALL,
/// no-new-privileges, read-only rootfs, pids/memory limits, readyhai.run label, non-root.
fn hardening(run: &str, name: &str, net: &str, mem: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "--rm", "--name", name, "--label", &format!("readyhai.run={run}"), "--network", net,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--pids-limit", "512", "--memory", mem, "--cpus", "2", "--log-driver", "none",
    ]
    .into_iter().map(String::from).collect();
    v.shrink_to_fit();
    v
}

fn pg_args(run: &str, name: &str, net: &str) -> Vec<String> {
    let mut v = vec!["run".to_string(), "-d".into()];
    v.extend(hardening(run, name, net, "512m"));
    v.extend(
        [
            "--user", "70:70",
            "--tmpfs", "/var/lib/postgresql/data:rw,uid=70,gid=70,mode=0700,size=512m",
            "--tmpfs", "/var/run/postgresql:rw,uid=70,gid=70,mode=0755",
            "--tmpfs", "/tmp:rw,size=64m",
            // value is forwarded from the process environment so it never appears in argv
            "-e", "POSTGRES_PASSWORD",
            "-e", "POSTGRES_DB=app",
            "postgres:16-alpine",
        ]
        .map(String::from),
    );
    v
}

fn app_args(run: &str, name: &str, net: &str, src: &Path, workdir: &str, image: &str) -> Vec<String> {
    let mut v = vec!["run".to_string()];
    v.extend(hardening(run, name, net, "1g"));
    v.extend(
        [
            "--user".to_string(), "65534:65534".into(),
            "--tmpfs".into(), "/tmp:rw,exec,size=256m,mode=1777".into(),
            "-e".into(), "HOME=/tmp".into(),
            "-e".into(), "PYTHONDONTWRITEBYTECODE=1".into(),
            "-e".into(), "DATABASE_URL".into(),
            "-e".into(), "SQLALCHEMY_URL".into(),
            "-v".into(), format!("{}:/src:ro", src.display()),
            "-w".into(), format!("/src/{workdir}").trim_end_matches('/').to_string(),
            "--entrypoint".into(), "sh".into(),
            image.into(), "-c".into(), ALEMBIC_SCRIPT.into(),
        ],
    );
    v
}

/// Removes the database container and the per-run network on every exit path.
struct MigEnv {
    run: String,
    pg: String,
    net: String,
}

impl Drop for MigEnv {
    fn drop(&mut self) {
        use std::process::Command;
        let _ = Command::new("docker").args(["rm", "-f", &self.pg]).output();
        if let Ok(o) = Command::new("docker")
            .args(["ps", "-aq", "--filter", &format!("label=readyhai.run={}", self.run), "--filter", &format!("network={}", self.net)])
            .output()
        {
            let ids: Vec<String> = String::from_utf8_lossy(&o.stdout).split_whitespace().map(String::from).collect();
            if !ids.is_empty() {
                let _ = Command::new("docker").arg("rm").arg("-f").args(&ids).output();
            }
        }
        let _ = Command::new("docker").args(["network", "rm", &self.net]).output();
    }
}

struct MigOutcome {
    exit: i32,
    tail: Vec<String>,
}

fn run_alembic(ctx: &Ctx, snap: &Snapshot, dir: &str, image: &str, timeout_secs: u64) -> anyhow::Result<MigOutcome> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let tag: u16 = rand::random();
    let run = ctx.run_id.clone();
    let clean = |s: &str| s.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect::<String>();
    let net = format!("readyhai-{}-mig", clean(&run));
    let pg = format!("readyhai-{}-mig-pg-{tag:04x}", clean(&run));
    let app = format!("readyhai-{}-mig-app-{tag:04x}", clean(&run));
    let pw: String = (0..24).map(|_| (b'a' + rand::random::<u8>() % 26) as char).collect();
    let _guard = MigEnv { run: run.clone(), pg: pg.clone(), net: net.clone() };

    let o = Command::new("docker")
        .args(["network", "create", "--internal", "--label", &format!("readyhai.run={run}"), &net])
        .output()?;
    if !o.status.success() {
        anyhow::bail!("docker network create: {}", String::from_utf8_lossy(&o.stderr).trim());
    }
    let o = Command::new("docker").args(pg_args(&run, &pg, &net)).env("POSTGRES_PASSWORD", &pw).output()?;
    if !o.status.success() {
        anyhow::bail!("starting postgres: {}", String::from_utf8_lossy(&o.stderr).trim());
    }
    let mut ready = false;
    for _ in 0..40 {
        let ok = Command::new("docker")
            .args(["exec", &pg, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "app"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    if !ready {
        anyhow::bail!("postgres did not become ready within 40s");
    }
    let url = format!("postgresql://postgres:{pw}@{pg}:5432/app");
    let log = std::env::temp_dir().join(format!("readyhai-mig-{}-{tag:04x}.log", clean(&run)));
    let f = fs::File::create(&log)?;
    let f2 = f.try_clone()?;
    let mut child = Command::new("docker")
        .args(app_args(&run, &app, &net, &snap.root, dir, image))
        .env("DATABASE_URL", &url)
        .env("SQLALCHEMY_URL", &url)
        .stdin(Stdio::null())
        .stdout(f)
        .stderr(f2)
        .spawn()?;
    let start = Instant::now();
    let code = loop {
        if let Some(s) = child.try_wait()? {
            break s.code().unwrap_or(-1);
        }
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            let _ = Command::new("docker").args(["rm", "-f", &app]).output();
            let _ = child.kill();
            let _ = child.wait();
            break 124;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let text = fs::read_to_string(&log).unwrap_or_default();
    let _ = fs::remove_file(&log);
    let lines: Vec<String> = text.lines().map(|l| crate::logs::redact(&l.replace(&pw, "[REDACTED]"))).collect();
    let tail = lines[lines.len().saturating_sub(40)..].to_vec();
    Ok(MigOutcome { exit: code, tail })
}

fn migrations(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else { return no_snapshot() };
    let tools = detect_migrations(&snap.files);
    if tools.is_empty() {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable("no migrations found".into())));
    }
    let mut dir = None;
    for t in &tools {
        match t {
            MigTool::Alembic(d) => dir = Some(d.clone()),
            MigTool::Prisma => untested(ctx, "prisma migrations detected: up/down/up run not implemented yet"),
            MigTool::Flyway => untested(ctx, "flyway migrations detected: up/down/up run not implemented yet"),
        }
    }
    let Some(dir) = dir else {
        return Ok(CheckOutput::status(CheckStatus::Skipped("only prisma/flyway migrations found; runner not implemented".into())));
    };
    let case = "release.migrations";
    let Some(tcfg) = &ctx.cfg.test else {
        untested(ctx, "alembic migrations not run: set [test] image in readyhai.toml");
        record(ctx, "qa.release.migrations", Area::Release, case, "Migrations apply, roll back and re-apply", &dir,
            ResultStatus::Skipped, "no [test] image configured", vec![]);
        return Ok(CheckOutput::status(CheckStatus::Skipped("set [test] image in readyhai.toml to run migrations".into())));
    };
    if !ctx.docker.available || !matches!(ctx.docker.mode, crate::tools::MountMode::Bind) {
        untested(ctx, "alembic migrations not run: docker (bind-mount mode) unavailable");
        record(ctx, "qa.release.migrations", Area::Release, case, "Migrations apply, roll back and re-apply", &dir,
            ResultStatus::Blocked, "docker unavailable", vec![]);
        return Ok(CheckOutput::status(CheckStatus::Skipped("docker (bind-mount mode) required for migrations".into())));
    }
    let res = run_alembic(ctx, snap, &dir, &tcfg.image, tcfg.timeout_secs.min(600))?;
    if res.exit == 0 {
        return Ok(out(record(ctx, "qa.release.migrations", Area::Release, case, "Migrations apply, roll back and re-apply",
            &dir, ResultStatus::Pass, "alembic upgrade/downgrade/upgrade succeeded", vec![])));
    }
    if let Some(why) = infra_exit(res.exit) {
        // Tooling failure: the migration was never judged. Blocked result, errored check, no defect.
        untested(ctx, &format!("alembic migrations not verified: {why}"));
        let tail = res.tail.iter().rev().take(3).cloned().collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | ");
        record(ctx, "qa.release.migrations", Area::Release, case, "Migrations apply, roll back and re-apply", &dir,
            ResultStatus::Blocked, &format!("{why}; last output: {tail}"), vec![]);
        return Ok(CheckOutput::status(CheckStatus::Errored(format!("migration run did not complete: {why}"))));
    }
    let step = if res.exit == 124 { "timeout" } else { step_for_exit(res.exit) };
    let comp = if dir.is_empty() { "alembic".to_string() } else { format!("{dir}/alembic") };
    let def = Def {
        rule: "qa.release.migration_failure",
        cat: Category::Reliability,
        sev: Severity::High,
        area: Area::Release,
        title: format!("Database migration failed at step: {step}"),
        component: comp,
        expected: "alembic upgrade head, downgrade base and upgrade head all succeed on an empty database".into(),
        actual: format!("exit {} at '{step}'. Last output:\n{}", res.exit, res.tail.join("\n")),
        remediation: "Fix the failing migration (write a real downgrade or mark the revision irreversible) and re-run.".into(),
        fp_key: format!("migration:{step}"),
        steps: vec![
            format!("docker run postgres:16-alpine on an internal network, run the app image `{}` with DATABASE_URL set", tcfg.image),
            "alembic upgrade head && alembic downgrade base && alembic upgrade head".into(),
        ],
    };
    Ok(out(record(ctx, "qa.release.migrations", Area::Release, case, "Migrations apply, roll back and re-apply",
        &dir, ResultStatus::Fail, &format!("failed at {step}"), vec![def])))
}

// ------------------------------------------------------------------ 6. licences

fn sbom_licenses(j: &Value) -> Vec<(String, String)> {
    let mut v = vec![];
    for c in j.get("components").and_then(|x| x.as_array()).into_iter().flatten() {
        let name = c.get("name").and_then(|x| x.as_str()).unwrap_or("?");
        let ver = c.get("version").and_then(|x| x.as_str()).unwrap_or("");
        let id = if ver.is_empty() { name.to_string() } else { format!("{name}@{ver}") };
        let mut any = false;
        for l in c.get("licenses").and_then(|x| x.as_array()).into_iter().flatten() {
            let s = l.pointer("/license/id").or_else(|| l.pointer("/license/name")).or_else(|| l.get("expression"))
                .and_then(|x| x.as_str());
            if let Some(s) = s {
                v.push((id.clone(), s.to_string()));
                any = true;
            }
        }
        if !any {
            v.push((id, "UNKNOWN".into()));
        }
    }
    v
}

fn deny_matches(deny: &[String], lic: &str) -> bool {
    let l = lic.to_lowercase();
    deny.iter().any(|d| {
        let d = d.trim().to_lowercase();
        if d.is_empty() {
            return false;
        }
        match d.strip_suffix('*') {
            Some(p) => l.starts_with(p),
            None => l == d,
        }
    })
}

fn parse_deny(env: &str) -> Vec<String> {
    env.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn licenses(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let p = ctx.out_dir().join("sbom.cdx.json");
    let Some(j) = fs::read_to_string(&p).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) else {
        untested(ctx, "licence policy not evaluated: no sbom.cdx.json (tool.sbom_cve did not run)");
        record(ctx, "qa.release.licenses", Area::Release, "release.licenses", "Dependency licences comply with policy",
            "sbom", ResultStatus::Blocked, "no SBOM available", vec![]);
        return Ok(CheckOutput::status(CheckStatus::Skipped("no sbom.cdx.json in run output".into())));
    };
    let mut deny = ctx.cfg.license.deny.clone();
    deny.extend(parse_deny(&std::env::var("READYHAI_LICENSE_DENY").unwrap_or_default()));
    Ok(out(licenses_eval(ctx, &j, &deny)))
}

fn licenses_eval(ctx: &Ctx, j: &Value, deny: &[String]) -> Vec<Finding> {
    let all = sbom_licenses(j);
    let distinct: BTreeSet<&str> = all.iter().map(|(_, l)| l.as_str()).collect();
    if deny.is_empty() {
        if let Some(qa) = &ctx.qa {
            qa.with(|c| {
                c.notes.push(format!(
                    "Licences: {} component licence(s), {} distinct; no deny policy configured (set READYHAI_LICENSE_DENY).",
                    all.len(), distinct.len()
                ))
            });
        }
        return record(ctx, "qa.release.licenses", Area::Release, "release.licenses", "Dependency licences comply with policy",
            "sbom", ResultStatus::Pass, &format!("{} distinct licence(s); no deny policy", distinct.len()), vec![]);
    }
    let bad: Vec<(String, String)> = all.iter().filter(|(_, l)| deny_matches(deny, l)).cloned().collect();
    let mut defs = vec![];
    // One defect per (package, denied licence); the version is not part of the identity, so a
    // version bump does not re-open an accepted finding but a NEW package does gate.
    let mut seen = BTreeSet::new();
    for (comp, lic) in bad.iter() {
        let name = comp.rsplit_once('@').filter(|(n, _)| !n.is_empty()).map(|x| x.0).unwrap_or(comp);
        if !seen.insert((name.to_string(), lic.clone())) {
            continue;
        }
        if defs.len() >= MAX_ITEM_DEFECTS {
            break;
        }
        defs.push(Def {
            rule: "qa.release.license",
            cat: Category::SupplyChain,
            sev: Severity::High,
            area: Area::Release,
            title: format!("{comp} uses a denied licence ({lic})"),
            component: name.to_string(),
            expected: format!("no licence matching deny list ({})", deny.join(", ")),
            actual: format!("{comp}: {lic}"),
            remediation: "Replace the dependency, obtain a commercial licence, or adjust the policy with legal sign-off.".into(),
            fp_key: format!("license:{name}:{lic}"),
            steps: vec![format!("Inspect licenses[] of {comp} in sbom.cdx.json")],
        });
    }
    if seen.len() > MAX_ITEM_DEFECTS {
        defs.push(Def {
            rule: "qa.release.license",
            cat: Category::SupplyChain,
            sev: Severity::High,
            area: Area::Release,
            title: format!("{} more dependencies use a denied licence", seen.len() - MAX_ITEM_DEFECTS),
            component: "sbom.cdx.json".into(),
            expected: format!("no licence matching deny list ({})", deny.join(", ")),
            actual: bad.iter().skip(MAX_ITEM_DEFECTS).take(50).map(|(c, l)| format!("{c}: {l}")).collect::<Vec<_>>().join("\n"),
            remediation: "Replace the dependencies or adjust the policy with legal sign-off.".into(),
            fp_key: "license:overflow".into(),
            steps: vec![],
        });
    }
    let st = if defs.is_empty() { ResultStatus::Pass } else { ResultStatus::Fail };
    record(ctx, "qa.release.licenses", Area::Release, "release.licenses", "Dependency licences comply with policy",
        "sbom", st, &format!("{} denied of {} component licence(s)", bad.len(), all.len()), defs)
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Target, TargetKind};
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/qa-repo")
    }

    fn ctx_for(tag: &str, qa: bool) -> Ctx {
        let src = fixture();
        let tmp = std::env::temp_dir().join(format!("readyhai-suite-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let snap = crate::snapshot::take(&src, &tmp.join("src"), &[], &[]).unwrap();
        Ctx {
            run_id: "t".into(),
            target: Target { kind: TargetKind::Repo, raw: src.display().to_string(), path: Some(src.clone()), image: None, url: None, openapi: None, host: None, apk: None, device: None },
            profile: Profile::Quick,
            run_dir: tmp.clone(),
            facts: crate::rules::detect_facts(&snap),
            snapshot: Some(snap),
            docker: crate::tools::Docker::detect(&tmp),
            cfg: Default::default(),
            error_lines: Default::default(),
            nonprod: false,
            qa: if qa { Some(crate::qa::QaCtx::new(crate::qa::roles::Roles::default(), None, None, false)) } else { None },
        }
    }

    fn run_one(ctx: &Ctx, id: &str) -> CheckOutput {
        let c = checks().into_iter().find(|c| c.id == id).unwrap();
        (c.run)(ctx).unwrap()
    }

    #[test]
    fn cobertura_lcov_jacoco() {
        let t = fs::read_to_string(fixture().join("coverage.xml")).unwrap();
        let c = parse_cobertura(&t).unwrap();
        assert!((c.overall - 0.42).abs() < 1e-9);
        assert!(c.files.contains(&("app/auth.py".to_string(), 0.0)));

        let l = parse_lcov("SF:src/a.js\nLF:10\nLH:5\nend_of_record\nSF:src/auth.js\nLF:4\nLH:0\nend_of_record\n").unwrap();
        assert!((l.overall - 5.0 / 14.0).abs() < 1e-9);
        assert_eq!(l.files[1], ("src/auth.js".to_string(), 0.0));

        let j = r#"<report><package name="com/x"><sourcefile name="A.java"><counter type="LINE" missed="3" covered="7"/></sourcefile>
<sourcefile name="Pay.java"><counter type="LINE" missed="5" covered="0"/></sourcefile></package></report>"#;
        let j = parse_jacoco(j).unwrap();
        assert!((j.overall - 7.0 / 15.0).abs() < 1e-9);
        assert_eq!(j.files[1], ("com/x/Pay.java".to_string(), 0.0));
    }

    #[test]
    fn route_extraction_all_frameworks() {
        let py = "@app.get(\"/health\")\n@router.post('/orders')\n@bp.route(\"/u\", methods=[\"GET\", \"POST\"])\n@bp.route('/x')\n";
        let r = extract_routes("a.py", py);
        let l: Vec<String> = r.iter().map(|r| r.label()).collect();
        assert_eq!(l, ["GET /health", "POST /orders", "GET /u", "POST /u", "GET /x"]);
        let js = "app.get('/a/:id', h)\nrouter.post(\"/b\", h)\n";
        assert_eq!(extract_routes("a.js", js).len(), 2);
        let java = "@GetMapping(\"/items/{id}\")\n@RequestMapping(value = \"/r\", method = RequestMethod.PUT)\n";
        let r = extract_routes("A.java", java);
        assert_eq!((r[0].label().as_str(), r[1].label().as_str()), ("GET /items/{id}", "PUT /r"));
        let dj = "urlpatterns = [path('users/<int:pk>/', v)]";
        assert_eq!(extract_routes("proj/urls.py", dj)[0].path, "users/<int:pk>/");
        assert!(extract_routes("views.py", dj).is_empty());
    }

    #[test]
    fn route_normalization_matching() {
        let rx = route_regex("/orders/{id}").unwrap();
        assert!(rx.is_match("client.get(\"/orders/42\")"));
        assert!(rx.is_match("f\"/api/orders/{oid}/\""));
        assert!(!rx.is_match("client.get(\"/orders\")"));
        assert!(route_regex("/users/:id").unwrap().is_match("get('/users/7?x=1')"));
        assert!(route_regex("users/<int:pk>/").unwrap().is_match("\"/users/3/\""));
        let o = route_regex("/orders").unwrap();
        assert!(o.is_match("get(\"/orders\")"));
        assert!(!o.is_match("get(\"/orders/5\")"));
        assert!(!o.is_match("get(\"/orders_old\")"));
        assert!(route_regex("/").unwrap().is_match("get(\"/\")"));
    }

    #[test]
    fn smells_in_fixture_and_js() {
        let t = fs::read_to_string(fixture().join("tests/test_orders.py")).unwrap();
        let mut s = Smells::default();
        scan_smells("tests/test_orders.py", &t, &mut s);
        assert_eq!(s.no_assert.len(), 1, "{:?}", s.no_assert);
        assert!(s.no_assert[0].contains("test_orders_no_assert"));
        assert_eq!(s.skipped.len(), 1);
        assert_eq!(s.sleeps.len(), 1);
        let js = "it('a', () => {\n  expect(1).toBe(1);\n});\nit('b', () => {\n  run();\n});\nit.skip('c', () => {});\nsetTimeout(f, 2000);\nsetTimeout(f, 50);\n";
        let mut s = Smells::default();
        scan_smells("a.test.js", js, &mut s);
        assert_eq!(s.no_assert.len(), 1, "{:?}", s.no_assert);
        assert_eq!(s.skipped.len(), 1);
        assert_eq!(s.sleeps.len(), 1);
    }

    fn table() -> Value {
        serde_json::json!({
            "python": [{"cycle":"3.8","eol":"2024-10-07"},{"cycle":"3.12","eol":"2028-10-31"},{"cycle":"3.9","eol":"2026-01-10"}],
            "nodejs": [{"cycle":"16","eol":"2023-09-11"},{"cycle":"22","eol":"2027-04-30"}],
            "debian": [{"cycle":"10","eol":"2022-09-10"}],
            "alpine": [{"cycle":"3.14","eol":"2023-05-01"}],
            "ubuntu": [{"cycle":"20.04","eol":"2025-05-31"}]
        })
    }

    #[test]
    fn dockerfile_from_and_eol_dates() {
        let rts = from_images(
            "FROM python:3.8-slim AS base\nFROM base\nFROM --platform=linux/amd64 docker.io/library/node:16\nFROM debian:buster-slim\nFROM alpine:3.14.2\nFROM ubuntu:focal\nFROM python:latest\nFROM scratch\n",
            "Dockerfile",
        );
        let got: Vec<(&str, &str)> = rts.iter().map(|r| (r.product, r.version.as_str())).collect();
        assert_eq!(got, [("python","3.8"),("nodejs","16"),("debian","10"),("alpine","3.14.2"),("ubuntu","20.04")]);
        let t = table();
        // fixed "today"
        assert_eq!(eol_state(&t, &rts[0], "2026-10-25").unwrap().1, EolState::Eol("2024-10-07".into()));
        assert_eq!(eol_state(&t, &rts[3], "2026-10-25").unwrap().0, "3.14");
        let py39 = Runtime { product: "python", version: "3.9.7".into(), source: "x".into(), exact: true };
        assert!(matches!(eol_state(&t, &py39, "2025-09-01").unwrap().1, EolState::Soon(_, 131)));
        assert!(eol_state(&t, &py39, "2025-01-01").is_none());
        let py312 = Runtime { product: "python", version: "3.12".into(), source: "x".into(), exact: true };
        assert!(eol_state(&t, &py312, "2026-10-25").is_none());
        assert_eq!(day_num("1970-01-02"), Some(1));
        assert_eq!(range_min(">=3.8,<4").unwrap(), ("3.8".to_string(), false));
        assert_eq!(range_min("16.x".trim_end_matches(".x")).unwrap(), ("16".to_string(), true));
    }

    #[test]
    fn fixture_eol_and_hints() {
        let ctx = ctx_for("eol", true);
        let r = run_one(&ctx, "qa.release.eol");
        assert!(r.findings.iter().any(|f| f.rule == "qa.release.eol_runtime" && f.severity == Severity::High
            && f.title.contains("python 3.8")), "{:?}", r.findings.iter().map(|f| &f.title).collect::<Vec<_>>());
        let n = ctx.qa.as_ref().unwrap().with(|c| c.defects.len());
        assert!(n >= 1);
    }

    #[test]
    fn fixture_coverage_routes_smells() {
        let ctx = ctx_for("all", true);
        let cov = run_one(&ctx, "qa.suite.coverage");
        let rules: Vec<&str> = cov.findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.contains(&"qa.suite.low_coverage"), "{rules:?}");
        assert!(cov.findings.iter().any(|f| f.rule == "qa.suite.critical_uncovered" && f.location == "app/auth.py"));
        let r = run_one(&ctx, "qa.suite.routes");
        let fs: Vec<&Finding> = r.findings.iter().filter(|f| f.rule == "qa.suite.untested_routes").collect();
        // one finding PER untested route, each with its own fingerprint
        assert_eq!(fs.len(), 3, "{:?}", fs.iter().map(|f| &f.title).collect::<Vec<_>>());
        for want in ["GET /health", "GET /orders/{id}", "/admin/stats"] {
            assert!(fs.iter().any(|f| f.title.contains(want)), "missing {want}");
        }
        assert!(!fs.iter().any(|f| f.title.contains("Route GET /orders is never")));
        let mut f2: Vec<Finding> = fs.iter().map(|f| (*f).clone()).collect();
        f2.iter_mut().for_each(|f| f.finalize());
        assert_eq!(f2.iter().map(|f| f.fingerprint.clone()).collect::<BTreeSet<_>>().len(), 3);
        let m = ctx.qa.as_ref().unwrap().with(|c| c.coverage.clone());
        assert_eq!(m.rows.len(), 4);
        assert_eq!(m.cells.iter().filter(|c| c.2 == Cell::Pass).count(), 1);
        let s = run_one(&ctx, "qa.suite.smells");
        let sm: Vec<&Finding> = s.findings.iter().filter(|f| f.rule == "qa.suite.test_smells").collect();
        assert_eq!(sm.len(), 3, "{:?}", sm.iter().map(|f| &f.title).collect::<Vec<_>>());
        assert!(sm.iter().any(|f| f.title.contains("test_orders_no_assert") && f.title.contains("no assertions")));
        assert!(sm.iter().any(|f| f.title.starts_with("Skipped test")));
        assert!(sm.iter().any(|f| f.title.starts_with("Sleep of 1s")));
    }

    #[test]
    fn smell_identity_has_no_line_numbers_and_new_items_are_new() {
        let one = Smells { no_assert: vec!["t/a.py:10 test_x".into()], skipped: vec!["t/a.py:3".into()], sleeps: vec![] };
        let moved = Smells { no_assert: vec!["t/a.py:99 test_x".into()], skipped: vec!["t/a.py:40".into()], sleeps: vec![] };
        let keys = |s: &Smells| smell_defs(s).into_iter().map(|d| d.fp_key).collect::<Vec<_>>();
        assert_eq!(keys(&one), keys(&moved), "moving code must not change fingerprints");
        // a second skipped test in the same file is a new item
        let two = Smells { skipped: vec!["t/a.py:3".into(), "t/a.py:50".into()], ..Default::default() };
        assert_eq!(keys(&two), vec!["smell:skipped:t/a.py:1", "smell:skipped:t/a.py:2"]);
        assert!(keys(&one).contains(&"smell:skipped:t/a.py:1".to_string()));
    }

    #[test]
    fn coverage_fingerprint_follows_the_band() {
        assert_eq!(cov_band(55.0), cov_band(51.0));
        assert_ne!(cov_band(55.0), cov_band(35.0));
        assert_eq!((cov_band(0.0), cov_band(59.9), cov_band(100.0)), (0, 50, 100));
        // the fixture (42%) yields the band-40 key
        let ctx = ctx_for("covband", true);
        let f = run_one(&ctx, "qa.suite.coverage");
        let mut low = f.findings.into_iter().find(|f| f.rule == "qa.suite.low_coverage").unwrap();
        low.finalize();
        let want = crate::qa::recommend::fingerprint("qa.suite.low_coverage", "overall:coverage.xml:40");
        assert_eq!(low.fingerprint, want);
    }

    #[test]
    fn missing_coverage_is_blocked() {
        let mut ctx = ctx_for("nocov", true);
        let snap = ctx.snapshot.as_mut().unwrap();
        snap.files.retain(|f| f != "coverage.xml");
        let r = run_one(&ctx, "qa.suite.coverage");
        assert!(matches!(r.status, Some(CheckStatus::Skipped(_))));
        let c = ctx.qa.as_ref().unwrap();
        assert_eq!(c.with(|c| c.results[0].status), ResultStatus::Blocked);
        assert!(c.with(|c| c.untested[0].contains("no coverage report")));
    }

    #[test]
    fn migrations_detect_and_commands() {
        let ctx = ctx_for("mig", true);
        let t = detect_migrations(&ctx.snapshot.as_ref().unwrap().files);
        assert_eq!(t, vec![MigTool::Alembic(String::new())]);
        let r = run_one(&ctx, "qa.release.migrations");
        assert!(matches!(r.status, Some(CheckStatus::Skipped(ref m)) if m.contains("[test] image")));

        let a = app_args("r1", "app", "readyhai-r1-mig", Path::new("/snap"), "svc", "img:1");
        let j = a.join(" ");
        for need in ["--cap-drop ALL", "no-new-privileges", "--read-only", "--pids-limit", "--memory 1g", "readyhai.run=r1",
            "--network readyhai-r1-mig", "/snap:/src:ro", "-w /src/svc", "-e DATABASE_URL ", "img:1"] {
            assert!(j.contains(need), "missing {need} in {j}");
        }
        assert!(!j.contains("postgresql://"));
        let p = pg_args("r1", "pg", "n").join(" ");
        assert!(p.contains("-e POSTGRES_PASSWORD ") && p.contains("--cap-drop ALL") && p.contains("postgres:16-alpine"));
        assert_eq!(step_for_exit(12), "alembic downgrade base");
        assert!(crate::tools::validate_create_policy(&a[1..a.len() - 4].to_vec()).is_ok());
    }

    #[test]
    fn licenses_policy() {
        let ctx = ctx_for("lic", true);
        let sbom = serde_json::json!({"components":[
            {"name":"a","version":"1","licenses":[{"license":{"id":"MIT"}}]},
            {"name":"b","version":"2","licenses":[{"license":{"id":"AGPL-3.0-only"}}]},
            {"name":"c"}]});
        let none = licenses_eval(&ctx, &sbom, &[]);
        assert!(none.is_empty());
        let bad = licenses_eval(&ctx, &sbom, &parse_deny("AGPL-3.0*, GPL-3.0*"));
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].rule, "qa.release.license");
        assert!(bad[0].detail.contains("b@2"));
    }

    #[test]
    fn license_denials_are_per_package() {
        let ctx = ctx_for("lic2", true);
        let deny = parse_deny("AGPL-3.0*");
        let mk = |pkgs: &[(&str, &str)]| serde_json::json!({"components": pkgs.iter().map(|(n, v)| serde_json::json!({"name": n, "version": v, "licenses":[{"license":{"id":"AGPL-3.0-only"}}]})).collect::<Vec<_>>()});
        let fp = |fs: Vec<Finding>| fs.into_iter().map(|mut f| { f.finalize(); f.fingerprint }).collect::<BTreeSet<_>>();
        let a = fp(licenses_eval(&ctx, &mk(&[("b", "2")]), &deny));
        let bumped = fp(licenses_eval(&ctx, &mk(&[("b", "3")]), &deny));
        assert_eq!(a, bumped, "a version bump is the same item");
        let more = fp(licenses_eval(&ctx, &mk(&[("b", "2"), ("c", "1")]), &deny));
        assert_eq!(more.len(), 2);
        assert!(a.is_subset(&more) && more.len() > a.len(), "a NEW denied package is a new fingerprint");
    }

    #[test]
    fn infra_exit_codes_are_not_migration_failures() {
        for c in [125, 126, 127, 137, 143] {
            assert!(infra_exit(c).is_some(), "{c}");
        }
        for c in [11, 12, 13, 124, 1] {
            assert!(infra_exit(c).is_none(), "{c}");
        }
        assert_eq!(step_for_exit(11), "alembic upgrade head");
    }
}
