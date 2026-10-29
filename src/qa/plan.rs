//! Risk-based test plan: inventory (spec ops, roles) -> risk = impact x likelihood -> budget.
use super::model::*;
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus, Profile, TargetKind};
use anyhow::{Context, Result};
use serde_json::Value;

/// One API operation from the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    pub method: String,
    pub path: String,
    pub operation_id: Option<String>,
    pub secured: bool,
    pub has_body: bool,
}

impl Op {
    pub fn component(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

pub fn checks() -> Vec<Check> {
    vec![Check::new("qa.plan", "QA risk-based test plan", &[TargetKind::Web], Profile::Quick, run).qa()]
}

const METHODS: [&str; 7] = ["get", "put", "post", "delete", "options", "head", "patch"];
const KEYWORDS: [&str; 14] = [
    "auth", "login", "password", "admin", "payment", "pay", "order", "invoice", "user", "account", "token",
    "upload", "delete", "billing",
];
const TOTAL_BUDGET: usize = 2000;
const ITEM_CAP: usize = 60;

/// Load and parse the OpenAPI document: `--spec` (file or http(s) URL) or discovery on the web target.
/// Ok(None) when there is no spec to be found. Reloaded per call (cheap; callers should keep the value).
pub fn load_spec(ctx: &Ctx) -> Result<Option<Value>> {
    let qa = ctx.qa.as_ref().context("not a QA run")?;
    let src = match &qa.spec {
        Some(s) => s.clone(),
        None => {
            let Some(base) = ctx.target.url.as_deref() else { return Ok(None) };
            qa.throttle()?;
            match crate::web::discover_openapi(base) {
                Some(u) => u,
                None => return Ok(None),
            }
        }
    };
    let text = if src.starts_with("http://") || src.starts_with("https://") {
        qa.throttle()?;
        let c = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(20)).build()?;
        let r = c.get(&src).send()?.error_for_status()?;
        r.text()?
    } else {
        std::fs::read_to_string(&src).with_context(|| format!("reading spec {src}"))?
    };
    Ok(Some(parse_doc(&text)?))
}

pub fn parse_doc(text: &str) -> Result<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Ok(v);
    }
    serde_norway::from_str::<Value>(text).context("spec is neither valid JSON nor YAML")
}

/// Operations of the spec (paths x methods). Minimal parse: no $ref resolution.
pub fn ops_from_doc(doc: &Value) -> Vec<Op> {
    let top_secured = sec_nonempty(doc.get("security"));
    let mut out = vec![];
    let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) else { return out };
    for (path, item) in paths {
        for m in METHODS {
            let Some(op) = item.get(m) else { continue };
            let secured = match op.get("security") {
                Some(s) => sec_nonempty(Some(s)),
                None => top_secured,
            };
            out.push(Op {
                method: m.to_ascii_uppercase(),
                path: path.clone(),
                operation_id: op.get("operationId").and_then(|v| v.as_str()).map(String::from),
                secured,
                has_body: op.get("requestBody").is_some(),
            });
        }
    }
    out
}

fn sec_nonempty(v: Option<&Value>) -> bool {
    match v.and_then(|v| v.as_array()) {
        Some(a) => a.iter().any(|r| r.as_object().map(|o| !o.is_empty()).unwrap_or(false)),
        None => false,
    }
}

#[allow(dead_code)]
pub fn spec_ops(ctx: &Ctx) -> Result<Vec<Op>> {
    Ok(load_spec(ctx)?.map(|d| ops_from_doc(&d)).unwrap_or_default())
}

fn is_write(m: &str) -> bool {
    matches!(m, "POST" | "PUT" | "PATCH" | "DELETE")
}

/// Risk 1..=25 = impact x likelihood, with reasons.
/// `has_tests`: None = unknown (no repo snapshot); `is_new`: new versus the baseline spec.
pub fn score(op: &Op, has_tests: Option<bool>, is_new: bool) -> (u8, Vec<String>) {
    let mut reasons = vec![];
    let mut impact: u8 = if op.method == "DELETE" {
        reasons.push("destructive method".into());
        4
    } else if is_write(&op.method) {
        reasons.push("write method".into());
        3
    } else {
        2
    };
    let lp = op.path.to_ascii_lowercase();
    if let Some(k) = KEYWORDS.iter().find(|k| lp.contains(*k)) {
        impact += 1;
        reasons.push(format!("sensitive path keyword '{k}'"));
    }
    if !op.secured && is_write(&op.method) {
        impact += 1;
        reasons.push("write without declared security".into());
    }
    let mut like: u8 = 2;
    if has_tests == Some(false) {
        like += 1;
        reasons.push("no tests reference this path in the repo".into());
    }
    if is_new {
        like += 2;
        reasons.push("new since baseline spec".into());
    }
    if op.has_body {
        like += 1;
        reasons.push("accepts a request body".into());
    }
    (impact.min(5) * like.min(5), reasons)
}

/// Plan risk of an operation known only by its parts (used when the plan has no item for it).
pub fn risk_of(method: &str, path: &str, secured: bool, has_body: bool) -> u8 {
    score(&Op { method: method.to_ascii_uppercase(), path: path.to_string(), operation_id: None, secured, has_body }, None, false).0
}

/// Proportional budgets (min 1, capped per item) summing to about `total`.
pub fn budgets(risks: &[u8], total: usize) -> Vec<usize> {
    let sum: usize = risks.iter().map(|r| *r as usize).sum::<usize>().max(1);
    risks.iter().map(|r| (total * *r as usize / sum).clamp(1, ITEM_CAP)).collect()
}

fn static_prefix(path: &str) -> String {
    let mut s = String::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg.contains('{') {
            break;
        }
        s.push('/');
        s.push_str(seg);
    }
    s
}

fn test_corpus(ctx: &Ctx) -> Option<String> {
    let snap = ctx.snapshot.as_ref()?;
    let mut buf = String::new();
    for f in &snap.files {
        let l = f.to_ascii_lowercase();
        if !(l.contains("test") || l.contains("spec") || l.contains("e2e")) {
            continue;
        }
        if let Ok(t) = std::fs::read_to_string(snap.root.join(f)) {
            if t.len() < 512 * 1024 {
                buf.push_str(&t.to_ascii_lowercase());
                buf.push('\n');
            }
        }
        if buf.len() > 32 * 1024 * 1024 {
            break;
        }
    }
    Some(buf)
}

fn op_keys(ops: &[Op]) -> Vec<String> {
    let mut k: Vec<String> = ops.iter().map(|o| o.component()).collect();
    k.sort();
    k
}

fn run(ctx: &Ctx) -> Result<CheckOutput> {
    run_in(ctx, &crate::engine::data_dir())
}

/// `run` with an explicit data dir (baselines), so tests never touch the real one.
pub(crate) fn run_in(ctx: &Ctx, data: &std::path::Path) -> Result<CheckOutput> {
    let Some(qa) = ctx.qa.as_ref() else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable("not a QA run".into())));
    };
    let (doc, err) = match load_spec(ctx) {
        Ok(d) => (d, None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    let ops = doc.as_ref().map(ops_from_doc).unwrap_or_default();
    let corpus = test_corpus(ctx);

    // Baseline spec: seeded when none exists. This run's operation list is always staged in the
    // run dir; `baseline accept <run>` promotes it (api::accept_spec_baseline).
    let bpath = data.join("baselines").join(format!("{}.spec.json", crate::engine::target_key(&ctx.target)));
    let baseline: Option<Vec<String>> =
        std::fs::read_to_string(&bpath).ok().and_then(|t| serde_json::from_str(&t).ok());
    if !ops.is_empty() {
        let st = super::api::stage_dir(&ctx.run_dir);
        if std::fs::create_dir_all(&st).is_ok() {
            let _ = std::fs::write(st.join("spec-ops.json"), serde_json::to_string_pretty(&op_keys(&ops)).unwrap_or_default());
        }
    }
    if baseline.is_none() && !ops.is_empty() {
        if let Some(dir) = bpath.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&bpath, serde_json::to_string_pretty(&op_keys(&ops)).unwrap_or_default());
    }

    let risks_n: Vec<(Op, u8, Vec<String>)> = ops
        .iter()
        .map(|o| {
            let has_tests = corpus.as_ref().map(|c| {
                let p = static_prefix(&o.path);
                p.is_empty() || c.contains(&p.to_ascii_lowercase())
            });
            let is_new = baseline.as_ref().map(|b| !b.contains(&o.component())).unwrap_or(false);
            let (r, why) = score(o, has_tests, is_new);
            (o.clone(), r, why)
        })
        .collect();
    let total = qa.max_requests.min(TOTAL_BUDGET);
    let b = budgets(&risks_n.iter().map(|x| x.1).collect::<Vec<_>>(), total);

    let roles = qa.roles.names();
    qa.with(|col| {
        for ((o, r, why), bud) in risks_n.iter().zip(b) {
            col.plan.push(PlanItem { component: o.component(), area: Area::Api, risk: *r, reasons: why.clone(), budget: bud });
        }
        col.plan.sort_by(|a, b| b.risk.cmp(&a.risk).then(a.component.cmp(&b.component)));
        if let Some(e) = &err {
            col.notes.push(format!("OpenAPI spec could not be loaded: {e}"));
        }
        if ops.is_empty() {
            col.risks.push(Risk {
                title: "No OpenAPI spec: API functional testing is limited".into(),
                level: "high".into(),
                mitigation: "Provide --spec <openapi.json|url> so operations can be planned and tested.".into(),
            });
            col.untested.push("API functional testing (no OpenAPI operations available)".into());
        } else {
            col.notes.push(format!("{} API operations planned from the spec.", ops.len()));
        }
        if roles.len() < 2 {
            col.risks.push(Risk {
                title: format!("Only {} role(s) configured: authorization is untested", roles.len()),
                level: "high".into(),
                mitigation: "Provide roles.toml with at least two test accounts on nonprod.".into(),
            });
        }
        if !qa.nonprod {
            col.risks.push(Risk {
                title: "Host is not tagged nonprod: write paths are untested (read-only run)".into(),
                level: "medium".into(),
                mitigation: "Tag the host env=nonprod in scope.toml to enable create/update/delete tests.".into(),
            });
        }
        if baseline.is_none() && !ops.is_empty() {
            col.notes.push("Spec baseline recorded for the first time; update it later with `readyhai baseline accept <run>`.".into());
        }
    });
    Ok(CheckOutput::status(if ops.is_empty() {
        CheckStatus::NotApplicable("no API operations found".into())
    } else {
        CheckStatus::Passed
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"{"openapi":"3.0.0","security":[{"bearer":[]}],
      "paths":{
       "/health":{"get":{"operationId":"health","security":[]}},
       "/users/{id}":{"get":{"operationId":"getUser"},"delete":{}},
       "/orders":{"post":{"requestBody":{"content":{}}}}}}"#;

    #[test]
    fn parses_ops() {
        let ops = ops_from_doc(&parse_doc(SPEC).unwrap());
        assert_eq!(ops.len(), 4);
        let h = ops.iter().find(|o| o.path == "/health").unwrap();
        assert!(!h.secured && h.operation_id.as_deref() == Some("health"));
        let p = ops.iter().find(|o| o.method == "POST").unwrap();
        assert!(p.secured && p.has_body);
    }

    #[test]
    fn parses_yaml() {
        let d = parse_doc("openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n").unwrap();
        assert_eq!(ops_from_doc(&d).len(), 1);
    }

    #[test]
    fn risk_ordering_and_budget() {
        let ops = ops_from_doc(&parse_doc(SPEC).unwrap());
        let sc = |m: &str, p: &str, t, n| {
            let o = ops.iter().find(|o| o.method == m && o.path == p).unwrap();
            score(o, t, n).0
        };
        let health = sc("GET", "/health", Some(true), false);
        let del = sc("DELETE", "/users/{id}", Some(false), false);
        let order = sc("POST", "/orders", Some(false), true);
        assert!(del > health && order > health, "{health} {del} {order}");
        assert!(order <= 25);
        let b = budgets(&[health, del, order], 60);
        assert!(b[1] > b[0] && b.iter().all(|x| *x >= 1 && *x <= ITEM_CAP));
    }
}
