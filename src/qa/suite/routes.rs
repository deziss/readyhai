use std::collections::BTreeSet;
use regex::Regex;

use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Severity};
use crate::qa::model::*;

use super::common::{Def, MAX_ITEM_DEFECTS, is_test_path, no_snapshot, out, re, read, record};

/// A route a source file declares. Shared with the agent's change analysis (`agent::change`), which
/// maps the routes of changed files to OpenAPI operations.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Route {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) file: String,
    pub(crate) line: usize,
}

impl Route {
    pub(crate) fn label(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

pub(crate) fn extract_routes(file: &str, text: &str) -> Vec<Route> {
    let ext = file.rsplit('.').next().unwrap_or("");
    let name = file.rsplit('/').next().unwrap_or("");
    let mut v = vec![];
    let mut push = |m: &str, p: &str, off: usize| {
        let line = text[..off].matches('\n').count() + 1;
        v.push(Route {
            method: m.to_uppercase(),
            path: p.to_string(),
            file: file.to_string(),
            line,
        });
    };
    match ext {
        "py" => {
            for c in re(r#"@\w+(?:\.\w+)*\.(get|post|put|delete|patch)\(\s*["']([^"']*)["']"#)
                .captures_iter(text)
            {
                push(&c[1], &c[2], c.get(0).unwrap().start());
            }
            for c in re(r#"@\w+(?:\.\w+)*\.route\(\s*["']([^"']*)["']([^)]*)"#).captures_iter(text)
            {
                let methods = re(r#"methods\s*=\s*[\[\(]([^\]\)]*)"#)
                    .captures(&c[2])
                    .map(|m| {
                        re(r#"["'](\w+)["']"#)
                            .captures_iter(&m[1])
                            .map(|x| x[1].to_uppercase())
                            .collect::<Vec<_>>()
                    })
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
            for c in re(r#"@RequestMapping\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*"([^"]*)"([^)]*)"#)
                .captures_iter(text)
            {
                let m = re(r"RequestMethod\.(\w+)")
                    .captures(&c[2])
                    .map(|x| x[1].to_string())
                    .unwrap_or("ANY".into());
                push(&m, &c[1], c.get(0).unwrap().start());
            }
        }
        _ => {}
    }
    v
}

/// A path segment that is a parameter in some framework's syntax: `{id}`, `:id`, `<int:id>`,
/// Django's `(?P<id>...)`, or a bare `*`.
pub(crate) fn is_param_segment(s: &str) -> bool {
    static PARAM: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        re(r"^(?:\{[^}]*\}|:[A-Za-z_]\w*|<[^>]*>|\(\?P<[^>]*>[^)]*\))$")
    });
    PARAM.is_match(s) || s == "*"
}

/// The segments of a route or OpenAPI path as `route_regex` reads them: a leading `/` is implied,
/// query/fragment and the trailing `/` are dropped, a parameter becomes `{}` and a literal is
/// lower-cased. `/Orders/{id}/`, `orders/<int:pk>` and `/orders/:id` all give `["orders", "{}"]`.
pub(crate) fn route_segments(path: &str) -> Vec<String> {
    // a query or fragment ends the path, but the `?` of Django's `(?P<name>...)` does not
    let cut = path
        .char_indices()
        .find(|&(i, c)| (c == '?' && !path[..i].ends_with('(')) || c == '#')
        .map_or(path.len(), |(i, _)| i);
    path[..cut]
        .trim()
        .split('/')
        .map(|s| s.trim_matches(['^', '$']))
        .filter(|s| !s.is_empty())
        .map(|s| {
            if is_param_segment(s) {
                "{}".to_string()
            } else {
                s.to_lowercase()
            }
        })
        .collect()
}

/// Literal route path -> regex that matches it inside test source (params become a segment wildcard).
pub(crate) fn route_regex(path: &str) -> Option<Regex> {
    let mut p = path.trim().to_string();
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    // Django-style routes end with "/", so do Flask/FastAPI variants; tolerate either.
    let trimmed = p.trim_end_matches('/');
    let p = if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    };
    let seg = r#"[^/"'`\s?#]+"#;
    let mut rx = String::new();
    if p == "/" {
        return Regex::new(r#"["'`]/["'`?]"#).ok();
    }
    for s in p.split('/').skip(1) {
        rx.push('/');
        if is_param_segment(s) {
            rx.push_str(seg);
        } else {
            rx.push_str(&regex::escape(s));
        }
    }
    rx.push_str(r#"/?(?:[?"'`\s)#,;\]]|$)"#);
    Regex::new(&rx).ok()
}

pub(crate) fn routes_tested(routes: &[Route], tests: &[String]) -> Vec<(Route, bool)> {
    routes
        .iter()
        .map(|r| {
            let t = route_regex(&r.path)
                .map(|rx| tests.iter().any(|t| rx.is_match(t)))
                .unwrap_or(true);
            (r.clone(), t)
        })
        .collect()
}

pub(crate) fn routes(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(snap) = &ctx.snapshot else {
        return no_snapshot();
    };
    let (mut rs, mut tests) = (vec![], vec![]);
    for f in &snap.files {
        let ext = f.rsplit('.').next().unwrap_or("");
        if !matches!(
            ext,
            "py" | "js" | "ts" | "mjs" | "cjs" | "jsx" | "tsx" | "java" | "kt" | "go"
        ) {
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
        return Ok(CheckOutput::status(CheckStatus::NotApplicable(
            "no HTTP routes found".into(),
        )));
    }
    let res = routes_tested(&rs, &tests);
    if let Some(qa) = &ctx.qa {
        qa.with(|c| {
            for (r, t) in &res {
                c.coverage.set(
                    &r.label(),
                    "has test",
                    if *t { Cell::Pass } else { Cell::Untested },
                );
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
            remediation: "Add tests that call this route (happy path, auth failure and bad input)."
                .into(),
            fp_key: format!("route:{}", r.label()),
            steps: vec![format!("grep the test directories for `{}`", r.path)],
        });
    }
    if missing.len() > MAX_ITEM_DEFECTS {
        let rest: Vec<String> = missing[MAX_ITEM_DEFECTS..]
            .iter()
            .map(|r| r.label())
            .collect();
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
    let st = if defs.is_empty() {
        ResultStatus::Pass
    } else {
        ResultStatus::Fail
    };
    Ok(out(record(
        ctx,
        "qa.suite.routes",
        Area::Suite,
        "suite.routes",
        "Every route has a test",
        "routes",
        st,
        &format!(
            "{}/{} routes referenced by tests",
            rs.len() - missing.len(),
            rs.len()
        ),
        defs,
    )))
}
