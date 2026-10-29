//! OpenAPI-driven functional API testing: generated positive/boundary/negative cases,
//! contract checks, auth matrix, stateful CRUD/BOLA, robustness probes.
pub mod authz;
pub mod contract;
pub mod exec;
pub mod synth;
pub mod spec;
pub mod stateful;
#[cfg(test)]
mod testsrv;
#[cfg(test)]
mod tests;

use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Finding, Profile, Severity, TargetKind};
use crate::qa::QaCtx;
use crate::qa::model::*;
use crate::qa::roles::Role;
use exec::Exchange;
use synth::{Case, Expect};
use serde_json::Value;
use spec::{Op, Spec};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A failed API case is re-run up to this many times to tell a flaky failure from a real one.
pub const MAX_RERUN: u32 = 2;

pub fn checks() -> Vec<Check> {
    let w = &[TargetKind::Web];
    // Order matters: the request budget is shared, so the highest-priority cases (auth matrix,
    // P1) run first, then functional cases by plan risk, then the stateful lifecycle (BOLA).
    vec![
        Check::new("qa.api.authz", "API auth matrix: anonymous, invalid token, roles", w, Profile::Quick, authz::run).qa(),
        Check::new("qa.api.functional", "API functional: positive/boundary/negative, contract, robustness", w, Profile::Quick, functional).qa(),
        Check::new("qa.api.stateful", "API stateful CRUD lifecycle, BOLA, delete semantics", w, Profile::Standard, stateful::run).qa(),
    ]
}

/// Operation with its plan risk (1..=25) and the number of cases the plan budgets for it.
#[derive(Clone)]
pub struct Planned {
    pub op: Op,
    pub risk: u8,
    pub budget: usize,
}

/// Spec operations ordered by plan risk (highest first, spec order within a tie). Risk and budget
/// come from the `qa.plan` items; an operation the plan does not know is scored on the fly.
pub fn plan_order(qa: &QaCtx, spec: &Spec) -> Vec<Planned> {
    let plan: Vec<PlanItem> = qa.with(|c| c.plan.clone());
    let mut v: Vec<Planned> = spec
        .ops
        .iter()
        .map(|op| match plan.iter().find(|p| p.component == op.key()) {
            Some(p) => Planned { op: op.clone(), risk: p.risk, budget: p.budget },
            None => Planned { op: op.clone(), risk: crate::qa::plan::risk_of(&op.method, &op.path, op.secured, op.body.is_some()), budget: 60 },
        })
        .collect();
    v.sort_by(|a, b| b.risk.cmp(&a.risk));
    v
}

/// Requests held back from the functional check for the stateful lifecycle (nonprod standard+).
fn stateful_reserve(ctx: &Ctx, usable_roles: usize) -> usize {
    match ctx.qa.as_ref() {
        Some(q) if q.nonprod && ctx.profile >= Profile::Standard && usable_roles > 0 => (q.max_requests / 10).clamp(20, 200),
        _ => 0,
    }
}

/// Where the run keeps what `baseline accept` promotes (spec snapshot, op list).
pub fn stage_dir(run_dir: &Path) -> PathBuf {
    run_dir.join("artifacts").join("qa-baseline")
}

/// Promote the spec baselines staged by run `run_dir` (`<key>.spec-full.json` for breaking-change
/// diffs, `<key>.spec.json` for "new since baseline" risk). Returns what was promoted.
pub fn accept_spec_baseline_in(data: &Path, key: &str, run_dir: &Path) -> anyhow::Result<Vec<&'static str>> {
    let st = stage_dir(run_dir);
    let dir = data.join("baselines");
    let mut done = vec![];
    for (from, to, what) in [("spec-full.json", format!("{key}.spec-full.json"), "spec snapshot"), ("spec-ops.json", format!("{key}.spec.json"), "spec operation list")] {
        let src = st.join(from);
        if src.is_file() {
            std::fs::create_dir_all(&dir)?;
            std::fs::copy(&src, dir.join(to))?;
            done.push(what);
        }
    }
    if done.is_empty() {
        anyhow::bail!("run recorded no OpenAPI spec snapshot (no --spec / spec not loaded)");
    }
    Ok(done)
}

/// `baseline accept <run>` hook for the spec baselines of that run.
#[allow(dead_code)]
pub fn accept_spec_baseline(target_key: &str, run_id: &str) -> anyhow::Result<Vec<&'static str>> {
    accept_spec_baseline_in(&crate::engine::data_dir(), target_key, &crate::engine::run_dir(run_id))
}

static DEFECT_SEQ: AtomicUsize = AtomicUsize::new(1);
static SPEC_CACHE: Mutex<Option<(String, Option<Arc<Spec>>)>> = Mutex::new(None);

fn cached_spec(ctx: &Ctx) -> anyhow::Result<Option<Arc<Spec>>> {
    let mut g = SPEC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((id, s)) = g.as_ref() {
        if *id == ctx.run_id {
            return Ok(s.clone());
        }
    }
    let s = spec::load(ctx)?.map(Arc::new);
    *g = Some((ctx.run_id.clone(), s.clone()));
    Ok(s)
}

/// Outcome of re-running a failed case: `fails` of `attempts` attempts failed (first included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reruns {
    pub attempts: u32,
    pub fails: u32,
}

impl Reruns {
    /// Fail when every attempt failed, Flaky when at least one attempt passed.
    pub fn status(&self) -> ResultStatus {
        if self.fails >= self.attempts { ResultStatus::Fail } else { ResultStatus::Flaky }
    }
}

/// Reference to a defect recorded for a case.
#[derive(Clone)]
pub struct DefectRef {
    pub id: String,
    pub ev: Option<Evidence>,
}

pub struct Req<'a> {
    pub op: &'a Op,
    pub role: Option<&'a Role>,
    pub case_id: &'a str,
    /// Stable label of the probe (used in fp keys of server_error).
    pub kind: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub body: Option<&'a Value>,
    /// Check documented status + schema.
    pub contract: bool,
}

pub struct NewDefect<'a> {
    pub rule: &'a str,
    pub cat: Category,
    pub sev: Severity,
    pub prio: Priority,
    pub title: String,
    pub expected: String,
    pub actual: String,
    pub fp: String,
    pub remediation: &'a str,
    pub area_cases: &'a str,
    pub component: String,
    pub role: Option<&'a Role>,
    pub method: &'a str,
    pub url: &'a str,
    pub body: Option<&'a Value>,
    pub ex: Option<&'a Exchange>,
}

pub struct Runner<'a> {
    pub ctx: &'a Ctx,
    pub qa: &'a QaCtx,
    /// Finding `check` id of the running check (JUnit/SARIF group findings by it).
    pub check: &'static str,
    /// At least one HTTP response was seen (so a later silence is not just "target down").
    pub responded: bool,
    /// The target stopped answering after a malformed input (do not blame every later case).
    pub down: bool,
    pub spec: Arc<Spec>,
    pub base: String,
    pub tag: String,
    pub findings: Vec<Finding>,
    pub lat: HashMap<String, Vec<u128>>,
    slowest: HashMap<String, (Exchange, String)>,
    ids: HashMap<String, Vec<String>>,
    /// (url, role name) of resources to DELETE at the end.
    pub cleanup: Vec<(String, String)>,
    /// Extra request headers for the next sends (e.g. an invalid token).
    pub extra: Vec<(String, String)>,
    /// (case id, component) of every case this runner planned (see `explain_failures`).
    my_cases: Mutex<Vec<(String, String)>>,
}

impl<'a> Runner<'a> {
    pub fn new(ctx: &'a Ctx, check: &'static str) -> anyhow::Result<Option<Self>> {
        let Some(qa) = ctx.qa.as_ref() else { return Ok(None) };
        let Some(spec) = cached_spec(ctx)? else { return Ok(None) };
        let origin = ctx.target.url.clone().unwrap_or_else(|| ctx.target.raw.clone());
        let base = format!("{}{}", origin.trim_end_matches('/'), spec.base_path);
        Ok(Some(Runner {
            ctx,
            qa,
            check,
            responded: false,
            down: false,
            base,
            tag: format!("readyhai-{}-", ctx.run_id),
            spec,
            findings: vec![],
            lat: HashMap::new(),
            slowest: HashMap::new(),
            ids: HashMap::new(),
            cleanup: vec![],
            extra: vec![],
            my_cases: Mutex::new(vec![]),
        }))
    }

    pub fn usable_roles(&self) -> Vec<&'a Role> {
        let qa = self.qa;
        qa.roles.roles.iter().filter(|r| exec::role_usable(qa, r)).collect()
    }

    pub fn url(&self, op: &Op, pv: &HashMap<String, String>, q: &[(String, String)]) -> String {
        synth::build_url(&self.base, &op.path, pv, q)
    }

    pub fn path_of(&self, op: &Op, pv: &HashMap<String, String>) -> String {
        let u = synth::build_url(&self.base, &op.path, pv, &[]);
        let rest = u.split_once("://").map(|x| x.1).unwrap_or(&u);
        rest.find('/').map(|i| rest[i..].to_string()).unwrap_or_default()
    }

    pub fn add_case(&self, id: &str, op: &Op, tech: Technique, prio: Priority, title: &str, role: Option<&str>, steps: Vec<String>, expected: &str) {
        let c = TestCase {
            id: id.to_string(),
            area: Area::Api,
            technique: tech,
            title: title.to_string(),
            priority: prio,
            component: op.key(),
            role: role.map(String::from),
            steps,
            expected: expected.to_string(),
            source: CaseSource::Deterministic,
        };
        self.my_cases.lock().unwrap_or_else(|e| e.into_inner()).push((id.to_string(), op.key()));
        self.qa.with(|c0| c0.cases.push(c));
    }

    /// Safety net: a failed case of this runner without a defect (a lifecycle step that returned
    /// 4xx, an assertion nobody attached a finding to) gets a `qa.api.case_failed` defect, so no
    /// failure is ever invisible to the gate, the report and the recommendation.
    pub fn explain_failures(&mut self) {
        let mine: Vec<(String, String)> = self.my_cases.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let orphans: Vec<(String, String, String, Vec<String>)> = self.qa.with(|c| {
            c.results
                .iter()
                .filter(|r| r.status == ResultStatus::Fail && r.defect_id.is_none())
                .filter_map(|r| {
                    let comp = mine.iter().find(|m| m.0 == r.case_id)?.1.clone();
                    let steps = c.cases.iter().find(|x| x.id == r.case_id).map(|x| x.steps.clone()).unwrap_or_default();
                    Some((r.case_id.clone(), comp, r.actual.clone(), steps))
                })
                .collect()
        });
        for (cid, comp, actual, steps) in orphans {
            let base = self.base.clone();
            let d = self.defect(NewDefect {
                rule: "qa.api.case_failed", cat: Category::Quality, sev: Severity::Medium, prio: Priority::P3,
                title: format!("{comp}: case {cid} failed"), expected: "the case passes".into(), actual: actual.clone(), fp: cid.clone(),
                remediation: "Re-run the case (steps to reproduce) and compare the response with the documented behaviour.",
                area_cases: &cid, component: comp, role: None, method: "GET", url: &base, body: None, ex: None,
            });
            self.qa.with(|c| {
                for r in c.results.iter_mut().filter(|r| r.case_id == cid) {
                    r.defect_id = Some(d.id.clone());
                }
                if !steps.is_empty() {
                    if let Some(x) = c.defects.iter_mut().find(|x| x.id == d.id) {
                        x.steps_to_reproduce = steps.clone();
                    }
                }
            });
        }
    }

    pub fn result(&self, case_id: &str, status: ResultStatus, actual: &str, ms: u128, defects: &[DefectRef]) {
        self.result_n(case_id, status, actual, ms, defects, 1);
    }

    pub fn result_n(&self, case_id: &str, status: ResultStatus, actual: &str, ms: u128, defects: &[DefectRef], attempts: u32) {
        let r = TestResult {
            case_id: case_id.to_string(),
            status,
            actual: actual.to_string(),
            duration_ms: ms,
            attempts,
            evidence: defects.iter().filter_map(|d| d.ev.clone()).collect(),
            defect_id: defects.first().map(|d| d.id.clone()),
        };
        self.qa.with(|c| c.results.push(r));
    }

    pub fn skip(&self, case_id: &str, why: &str) {
        self.result(case_id, ResultStatus::Skipped, why, 0, &[]);
    }

    /// Re-run a failed probe up to `MAX_RERUN` times (budget permitting, keeping `reserve`
    /// requests for later checks). `again` returns Some(true) when the failure reproduced,
    /// Some(false) when it passed, None when it could not run. The first attempt counts as a failure.
    pub fn rerun(&mut self, reserve: usize, mut again: impl FnMut(&mut Self) -> Option<bool>) -> Reruns {
        let mut rr = Reruns { attempts: 1, fails: 1 };
        for _ in 0..MAX_RERUN {
            if self.qa.remaining() <= reserve {
                break;
            }
            match again(self) {
                Some(failed) => {
                    rr.attempts += 1;
                    if failed {
                        rr.fails += 1;
                    }
                }
                None => break,
            }
        }
        rr
    }

    /// Record "reproduced N of M attempts" on the defects behind a re-run case.
    pub fn note_reproduced(&self, defs: &[DefectRef], rr: &Reruns) {
        if rr.attempts <= 1 {
            return;
        }
        self.qa.with(|c| {
            for d in c.defects.iter_mut().filter(|d| defs.iter().any(|x| x.id == d.id)) {
                // the creating attempt already counted as (1,1)
                d.reproduced.0 += rr.fails - 1;
                d.reproduced.1 += rr.attempts - 1;
            }
        });
    }

    /// Is the target still answering HTTP at all? (any status counts; budget errors count as alive)
    pub fn alive(&mut self) -> bool {
        match exec::send(self.qa, None, "GET", &self.base.clone(), None, &[]) {
            Ok(ex) => {
                if ex.status != 0 {
                    self.responded = true;
                }
                ex.status != 0
            }
            Err(_) => true,
        }
    }

    /// Record (or merge into) a defect; returns its reference.
    pub fn defect(&mut self, d: NewDefect) -> DefectRef {
        let rule = d.rule.to_string();
        let existing = self.qa.with(|c| {
            c.defects.iter_mut().find(|x| x.rule == rule && x.fp_key == d.fp).map(|x| {
                if !x.cases.contains(&d.area_cases.to_string()) {
                    x.cases.push(d.area_cases.to_string());
                }
                (x.id.clone(), x.evidence.first().cloned())
            })
        });
        if let Some((id, ev)) = existing {
            return DefectRef { id, ev };
        }
        let ev = d.ex.and_then(|e| exec::save_evidence(self.ctx, d.area_cases, d.role.map(|r| r.name.as_str()), d.body, e));
        let repro = exec::curl_repro(d.method, d.url, d.role, d.body);
        let def = Defect {
            id: format!("D-API-{:03}", DEFECT_SEQ.fetch_add(1, Ordering::SeqCst)),
            rule: d.rule.to_string(),
            category: d.cat,
            severity: d.sev,
            priority: d.prio,
            area: Area::Api,
            title: d.title,
            component: d.component,
            environment: self.ctx.target.raw.clone(),
            steps_to_reproduce: vec![
                format!("Prepare credentials as environment variables ({}).", d.role.map(|r| r.placeholder()).unwrap_or_else(|| "none: anonymous request".into())),
                repro,
            ],
            expected: d.expected,
            actual: d.actual,
            evidence: ev.iter().cloned().collect(),
            reproduced: (1, 1),
            cases: vec![d.area_cases.to_string()],
            remediation: d.remediation.to_string(),
            fp_key: d.fp,
            fingerprint: String::new(),
            status: Default::default(),
            regression: false,
            ai_note: None,
        };
        self.findings.push(def.to_finding(self.check));
        let id = def.id.clone();
        self.qa.with(|c| c.defects.push(def));
        DefectRef { id, ev }
    }

    /// Send + observe (5xx, error leakage, documented status, schema). Err = could not run.
    pub fn send(&mut self, r: &Req) -> Result<(Exchange, Vec<DefectRef>), String> {
        if exec::is_write(r.method) && !self.qa.nonprod {
            return Err("read-only: host not nonprod".into());
        }
        let extra: Vec<(&str, &str)> = self.extra.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let ex = exec::send(self.qa, r.role, r.method, r.url, r.body, &extra).map_err(|e| e.to_string())?;
        let key = r.op.key();
        self.lat.entry(key.clone()).or_default().push(ex.ms);
        let worst = self.slowest.get(&key).map(|x| x.0.ms).unwrap_or(0);
        if ex.ms >= worst {
            self.slowest.insert(key.clone(), (ex.clone(), r.url.to_string()));
        }
        let mut out = vec![];
        let comp = key.clone();
        let role_name = r.role.map(|x| x.name.as_str()).unwrap_or("anon");
        if ex.status == 0 {
            return Ok((ex, out));
        }
        self.responded = true;
        let mk = |me: &mut Self, rule: &str, cat, sev, prio, title: String, expected: String, actual: String, fp: String, rem: &str| {
            me.defect(NewDefect {
                rule, cat, sev, prio, title, expected, actual, fp, remediation: rem, area_cases: r.case_id, component: comp.clone(),
                role: r.role, method: r.method, url: r.url, body: r.body, ex: Some(&ex),
            })
        };
        if ex.status >= 500 {
            out.push(mk(self, "qa.api.server_error", Category::Reliability, Severity::High, Priority::P2,
                format!("{key} returns {} on {}", ex.status, r.kind), "4xx for invalid input, never a 5xx".into(),
                format!("HTTP {} ({}); body: {}", ex.status, role_name, body_fp_or_empty(&ex.body)), format!("{key}|{}", r.kind),
                "Validate input and handle the failure path; return a 4xx with a structured error body."));
        }
        // Success pages (nav links, docs prose) are never an error disclosure.
        let leak = if ex.status >= 400 { contract::leak_kind(&ex.body) } else { None };
        if let Some(l) = leak {
            out.push(mk(self, "qa.api.error_leak", Category::Security, Severity::Medium, Priority::P2,
                format!("{key} leaks internal error details ({l})"), "generic error body without stack traces or paths".into(),
                format!("response body matched '{l}'"), format!("{key}|{l}"),
                "Return generic error messages; log stack traces server-side only."));
        }
        if r.contract {
            let st = ex.status;
            if !contract::status_documented(r.op, st) && !matches!(st, 401 | 403 | 429) && st < 500 {
                out.push(mk(self, "qa.api.undocumented_status", Category::Quality, Severity::Low, Priority::P4,
                    format!("{key} returned undocumented status {st}"), "only documented statuses".into(),
                    format!("HTTP {st} is not in the spec responses"), format!("{key}|{st}"),
                    "Document the status in the OpenAPI responses or fix the behaviour."));
            }
            if ex.is_2xx() {
                if let (Some(Some(schema)), Some(j)) = (contract::schema_for(r.op, st), ex.json()) {
                    if let Some(m) = contract::validate(schema, &j, "$") {
                        out.push(mk(self, "qa.api.contract_violation", Category::Quality, Severity::Medium, Priority::P3,
                            format!("{key} response violates its schema ({})", m.split(':').next().unwrap_or("")),
                            "response matches the documented schema".into(), m.clone(),
                            format!("{key}|{}", contract::normalize_mismatch(&m)),
                            "Make the implementation and the OpenAPI schema agree."));
                    }
                }
            }
        }
        Ok((ex, out))
    }

    /// Ids of existing resources for `{param}` of `op` (from the collection endpoint), cap 3.
    pub fn ids_for(&mut self, op: &Op) -> Vec<String> {
        let Some(last) = op.path_params().last() else { return vec![] };
        let Some(i) = op.path.rfind('/') else { return vec![] };
        if op.path[i + 1..] != format!("{{{}}}", last.name) || op.path_params().count() != 1 {
            return vec![];
        }
        let list_path = op.path[..i].to_string();
        if let Some(v) = self.ids.get(&list_path) {
            return v.clone();
        }
        let mut found: Vec<String> = vec![];
        let list_op = self.spec.ops.iter().find(|o| o.method == "GET" && o.path == list_path && o.path_params().count() == 0).cloned();
        if let Some(lo) = list_op {
            let url = self.url(&lo, &HashMap::new(), &[]);
            let mut roles: Vec<Option<&Role>> = self.usable_roles().into_iter().map(Some).collect();
            roles.push(None);
            for role in roles {
                if let Ok(ex) = exec::send(self.qa, role, "GET", &url, None, &[]) {
                    if let Some(j) = ex.json() {
                        for it in list_items(&j) {
                            let v = [last.name.as_str(), "id", "uuid", "_id"].iter().find_map(|k| field(&it, k)).map(synth::value_str);
                            if let Some(v) = v {
                                if !found.contains(&v) && found.len() < 3 {
                                    found.push(v);
                                }
                            }
                        }
                    }
                }
                if found.len() >= 3 {
                    break;
                }
            }
        }
        self.ids.insert(list_path, found.clone());
        found
    }

    pub fn id_map(&self, op: &Op, id: Option<&String>) -> HashMap<String, String> {
        let mut m = HashMap::new();
        if let (Some(p), Some(id)) = (op.path_params().last(), id) {
            m.insert(p.name.clone(), id.clone());
        }
        m
    }

    /// DELETE leftovers created during this check; unresolved ones become a note.
    pub fn run_cleanup(&mut self) {
        let items = std::mem::take(&mut self.cleanup);
        let mut left = 0;
        for (url, role) in items {
            let r = self.qa.roles.roles.iter().find(|x| x.name == role);
            // 404 = already gone (e.g. the test deleted it itself)
            let ok = exec::send_cleanup(self.qa, r, &url).map(|e| e.is_2xx() || e.status == 404).unwrap_or(false);
            if !ok {
                left += 1;
            }
        }
        if left > 0 {
            self.qa.with(|c| c.notes.push(format!("cleanup: {left} resource(s) tagged '{}' could not be deleted", self.tag)));
        }
    }

    /// If `ex` is a successful create, schedule DELETE of the new item (when the spec has one).
    pub fn register_created(&mut self, post: &Op, ex: &Exchange, role: Option<&Role>) -> Option<String> {
        if post.method != "POST" {
            return None; // PUT/PATCH/DELETE act on an existing item: nothing was created
        }
        let id = created_id(ex)?;
        let item = self.spec.ops.iter().find(|o| o.method == "DELETE" && o.path.starts_with(&format!("{}/{{", post.path.trim_end_matches('/'))) && o.path_params().count() == post.path_params().count() + 1).cloned();
        if let (Some(d), Some(r)) = (item, role) {
            let mut pv = HashMap::new();
            if let Some(p) = d.path_params().last() {
                pv.insert(p.name.clone(), id.clone());
            }
            let url = self.url(&d, &pv, &[]);
            self.cleanup.push((url, r.name.clone()));
        } else {
            self.qa.with(|c| c.notes.push(format!("leftover: {} created a resource (id {id}) with no DELETE endpoint to clean up", post.key())));
        }
        Some(id)
    }

    pub fn finish_latency(&mut self) {
        let mut keys: Vec<_> = self.lat.keys().cloned().collect();
        keys.sort();
        for k in keys {
            let mut v = self.lat[&k].clone();
            v.sort();
            let p95 = v[((v.len() as f64 * 0.95).ceil() as usize).clamp(1, v.len()) - 1];
            let n = v.len();
            self.qa.with(|c| c.notes.push(format!("latency {k} p95={p95}ms (n={n})")));
            if p95 > 1000 && n >= 2 {
                if let (Some(op), Some((ex, url))) = (self.spec.ops.iter().find(|o| o.key() == k).cloned(), self.slowest.get(&k).cloned()) {
                    self.defect(NewDefect {
                        rule: "qa.api.slow_response", cat: Category::Performance, sev: Severity::Low, prio: Priority::P3,
                        title: format!("{k} is slow (p95 {p95} ms)"), expected: "p95 under 1000 ms".into(),
                        actual: format!("p95={p95}ms over {n} requests"), fp: format!("{k}|slow"),
                        remediation: "Profile the endpoint; add caching, pagination or async processing.",
                        area_cases: &format!("api.{}.{}.perf", op.method, op.path), component: k.clone(),
                        role: None, method: &op.method, url: &url, body: None, ex: Some(&ex),
                    });
                }
            }
        }
    }
}

/// Wrapper keys APIs put around the resource: `{"data": {...}}`, `{"result": {...}}`, JSON:API attributes.
const ENVELOPES: [&str; 4] = ["data", "result", "item", "payload"];

/// `name` from a response object, looking through a `{data:{...}}`-style wrapper (and JSON:API
/// `data.attributes`) when it is not at the top level.
pub fn field<'a>(j: &'a Value, name: &str) -> Option<&'a Value> {
    if let Some(v) = j.get(name) {
        return Some(v);
    }
    for w in ENVELOPES {
        if let Some(inner) = j.get(w) {
            if let Some(v) = inner.get(name) {
                return Some(v);
            }
            if let Some(v) = inner.get("attributes").and_then(|a| a.get(name)) {
                return Some(v);
            }
        }
    }
    None
}

/// Items of a list response: a top-level array, the first array-valued key, or the same inside an envelope.
pub fn list_items(j: &Value) -> Vec<Value> {
    if let Some(a) = j.as_array() {
        return a.clone();
    }
    let first_array = |o: &Value| o.as_object().and_then(|m| m.values().find_map(|v| v.as_array().cloned()));
    if let Some(a) = first_array(j) {
        return a;
    }
    for w in ENVELOPES {
        if let Some(inner) = j.get(w) {
            if let Some(a) = inner.as_array().cloned().or_else(|| first_array(inner)) {
                return a;
            }
        }
    }
    vec![]
}

/// New resource id from Location header (last segment) or JSON id/uuid/_id (also inside `{data:{...}}`).
pub fn created_id(ex: &Exchange) -> Option<String> {
    if let Some(l) = ex.header("location") {
        let seg = l.split(['?', '#']).next().unwrap_or("").trim_end_matches('/').rsplit('/').next().unwrap_or("");
        if !seg.is_empty() {
            return Some(seg.to_string());
        }
    }
    let j = ex.json()?;
    ["id", "uuid", "_id"].iter().find_map(|k| field(&j, k)).map(synth::value_str)
}

pub fn not_applicable() -> CheckOutput {
    CheckOutput::status(CheckStatus::NotApplicable("no OpenAPI spec found (use --spec)".into()))
}

/// First line of an error body worth grouping on (see `contract::body_fingerprint`); explicit
/// marker when the body is empty so triage does not merge unrelated empty 500s.
fn body_fp_or_empty(body: &str) -> String {
    let f = contract::body_fingerprint(body);
    if f.is_empty() { String::new() } else { f }
}

/// Why a response says nothing about the case (credentials / data / rate limit), if so.
pub fn blocked_reason(op: &Op, status: u16, has_id: bool) -> Option<String> {
    match status {
        401 | 403 => Some("no authorized role or valid credential available".into()),
        404 if !has_id && op.path_params().count() > 0 => Some("no valid resource id available".into()),
        429 => Some("rate limited".into()),
        300..=399 => Some("redirect not followed (other host or too many hops)".into()),
        _ => None,
    }
}

/// One generated case about to be executed.
pub struct CaseRun<'x> {
    pub op: &'x Op,
    pub case: &'x Case,
    pub role: Option<&'x Role>,
    pub cid: &'x str,
    pub url: &'x str,
    pub has_id: bool,
}

pub struct Outcome {
    pub status: ResultStatus,
    pub actual: String,
    pub ms: u128,
    pub defs: Vec<DefectRef>,
}

/// Execute one functional case and judge it. `first` = first attempt (re-runs must not register
/// created resources or add latency samples twice). Err = could not send (budget / write guard).
fn run_case(r: &mut Runner, c: &CaseRun, first: bool) -> Result<Outcome, String> {
    let (op, case, role, cid, url) = (c.op, c.case, c.role, c.cid, c.url);
    let key = op.key();
    let req = Req { op, role, case_id: cid, kind: &case.kind, method: &op.method, url, body: case.body.as_ref(), contract: case.expect == Expect::Success || case.expect == Expect::Reject };
    let (ex, mut defs) = r.send(&req)?;
    if ex.status == 0 {
        let msg = ex.error.clone().unwrap_or_default();
        if case.expect != Expect::Success && r.responded && !r.down {
            // The target answered before; silence on a malformed input is a possible crash/hang.
            let alive = r.alive();
            if !alive {
                r.down = true;
            }
            let how = if ex.timed_out { "timed out" } else { "closed the connection / reset" };
            let d = r.defect(NewDefect {
                rule: "qa.api.crash_on_input", cat: Category::Reliability,
                sev: if alive { Severity::High } else { Severity::Critical }, prio: if alive { Priority::P2 } else { Priority::P1 },
                title: format!("{key}: no HTTP response to malformed input ({})", case.kind),
                expected: "a 4xx rejection (the service stays up)".into(),
                actual: format!("request {how}: {msg}; the target {} answers afterwards (possible crash or hang)", if alive { "still" } else { "no longer" }),
                fp: format!("{key}|crash|{}", case.kind),
                remediation: "Reproduce locally: a malformed request must never crash a worker or hang; add input validation and request timeouts.",
                area_cases: cid, component: key.clone(), role, method: &op.method, url, body: case.body.as_ref(), ex: Some(&ex),
            });
            return Ok(Outcome { status: ResultStatus::Fail, actual: format!("no response ({how}); possible crash"), ms: ex.ms, defs: vec![d] });
        }
        return Ok(Outcome { status: ResultStatus::Blocked, actual: format!("transport error: {msg}"), ms: ex.ms, defs: vec![] });
    }
    if first && op.is_write() && ex.is_2xx() && case.expect != Expect::Success {
        r.register_created(op, &ex, role);
    }
    let mut status = ResultStatus::Pass;
    let mut actual = format!("HTTP {} in {} ms", ex.status, ex.ms);
    if let Some(why) = blocked_reason(op, ex.status, c.has_id) {
        status = ResultStatus::Blocked;
        actual = format!("HTTP {}: {why}", ex.status);
    } else {
        match case.expect {
            Expect::Success => {
                if !ex.is_2xx() {
                    status = ResultStatus::Fail;
                    if ex.status < 500 {
                        let d = r.defect(NewDefect {
                            rule: "qa.api.positive_failed", cat: Category::Quality, sev: Severity::Low, prio: Priority::P4,
                            title: format!("{key} rejects a valid request (HTTP {})", ex.status),
                            expected: "2xx for a request built from the spec".into(),
                            actual: format!("HTTP {} for generated valid input ({})", ex.status, case.kind), fp: format!("{key}|positive_failed"),
                            remediation: "Check the spec against the implementation (required fields, formats, business preconditions); if the generated data is unrealistic add an `example` to the spec.",
                            area_cases: cid, component: key.clone(), role, method: &op.method, url, body: case.body.as_ref(), ex: Some(&ex),
                        });
                        defs.push(d);
                    }
                }
                if first && !op.is_write() && ex.ms > 800 && case.kind == "positive" {
                    for _ in 0..2 {
                        let _ = r.send(&Req { op, role, case_id: cid, kind: "latency", method: &op.method, url, body: None, contract: false });
                    }
                }
            }
            Expect::Reject => {
                if ex.is_2xx() {
                    status = ResultStatus::Fail;
                    let d = r.defect(NewDefect {
                        rule: "qa.api.validation_missing", cat: Category::Quality, sev: Severity::Medium, prio: Priority::P3,
                        title: format!("{key} accepts invalid input ({})", case.title), expected: "4xx rejection".into(),
                        actual: format!("HTTP {} accepted it", ex.status), fp: format!("{key}|{}", case.kind),
                        remediation: "Enforce the documented schema constraints server-side.", area_cases: cid,
                        component: key.clone(), role, method: &op.method, url, body: case.body.as_ref(), ex: Some(&ex),
                    });
                    defs.push(d);
                }
            }
            Expect::NoServerError => {
                let ct = ex.header("content-type").unwrap_or("").to_ascii_lowercase();
                if case.marker && ct.contains("html") && ex.body.contains(synth::MARKER) {
                    status = ResultStatus::Fail;
                    let d = r.defect(NewDefect {
                        rule: "qa.api.reflection", cat: Category::Security, sev: Severity::Low, prio: Priority::P3,
                        title: format!("{key} reflects input verbatim in HTML"), expected: "input is encoded or not reflected".into(),
                        actual: "inert marker returned unescaped in text/html".into(), fp: format!("{key}|{}", case.kind),
                        remediation: "HTML-encode reflected values.", area_cases: cid, component: key.clone(),
                        role, method: &op.method, url, body: case.body.as_ref(), ex: Some(&ex),
                    });
                    defs.push(d);
                }
            }
        }
    }
    if ex.status >= 500 || !defs.is_empty() {
        status = ResultStatus::Fail;
        actual = format!("HTTP {} ({} defect(s))", ex.status, defs.len());
    }
    Ok(Outcome { status, actual, ms: ex.ms, defs })
}

fn functional(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    functional_in(ctx, &crate::engine::data_dir())
}

/// `functional` with an explicit data dir (baselines), so tests never touch the real one.
pub(crate) fn functional_in(ctx: &Ctx, data: &Path) -> anyhow::Result<CheckOutput> {
    let Some(mut r) = Runner::new(ctx, "qa.api.functional")? else { return Ok(not_applicable()) };
    let spec = r.spec.clone();
    let qa = r.qa;
    qa.with(|c| c.untested.extend(spec.untested.iter().cloned()));
    let deep = ctx.profile == Profile::Deep;
    let roles = r.usable_roles();
    let reserve = stateful_reserve(ctx, roles.len());
    let mut stopped: Option<String> = None;
    let mut cheapest: Option<(String, u128)> = None;
    // Is the target answering at all? Only then is silence on a malformed input a possible crash.
    if !r.alive() {
        qa.with(|c| c.notes.push("API target did not answer the initial probe: transport failures are reported as blocked, not as crashes".into()));
    }
    // Highest plan risk first; each operation gets at most its plan budget of cases.
    for pl in plan_order(qa, &spec) {
        let op = &pl.op;
        if matches!(op.method.as_str(), "HEAD" | "OPTIONS") {
            continue;
        }
        let k = op.key();
        if stopped.is_none() && qa.remaining() <= reserve {
            stopped = Some(if reserve > 0 { "request budget reserved for the stateful checks".to_string() } else { "request budget exhausted".to_string() });
        }
        let role = roles.iter().find(|x| x.expects(&op.path) != Some(false)).copied();
        let idv = if stopped.is_some() { vec![] } else { r.ids_for(op) };
        let has_id = !idv.is_empty();
        let ids0 = r.id_map(op, idv.first());
        let mut cases: Vec<Case> = synth::generate(op, &r.tag, deep, &ids0);
        // Extra positive cases for the other harvested ids (catches per-record contract bugs).
        if !op.is_write() {
            for (i, id) in idv.iter().enumerate().skip(1) {
                let mut c = cases[0].clone();
                c.kind = format!("positive.{}", i + 1);
                c.path_vals = r.id_map(op, Some(id));
                cases.push(c);
            }
        }
        // writes: the positive case is covered by the stateful lifecycle
        cases.retain(|c| !(op.is_write() && c.kind.starts_with("positive")));
        let budget = pl.budget.max(1);
        if cases.len() > budget {
            let dropped = cases.len() - budget;
            cases.truncate(budget);
            qa.with(|c| c.untested.push(format!("{k}: {dropped} generated case(s) beyond the plan budget ({budget}) were not run")));
        }
        if let Some(why) = &stopped {
            qa.with(|c| c.untested.push(format!("{k}: {why}")));
        }
        let (mut op_fail, mut n_pass) = (false, 0usize);
        for case in cases {
            let cid = format!("api.{}.{}.{}", op.method, op.path, case.kind);
            let url = r.url(op, &case.path_vals, &case.query);
            let curl = exec::curl_repro(&op.method, &url, role, case.body.as_ref());
            let exp = match case.expect {
                Expect::Success => "2xx and a body matching the documented schema",
                Expect::Reject => "4xx (400/422) rejection of the invalid input",
                Expect::NoServerError => "no 5xx and no verbatim reflection",
            };
            r.add_case(&cid, op, case.technique, if case.kind == "positive" { Priority::P2 } else { Priority::P3 }, &case.title, role.map(|x| x.name.as_str()), vec![curl], exp);
            if op.is_write() && !qa.nonprod {
                r.skip(&cid, "read-only: host not nonprod");
                continue;
            }
            if let Some(why) = &stopped {
                r.skip(&cid, why); // planned but never run: counts against "cases executed"
                continue;
            }
            let cr = CaseRun { op, case: &case, role, cid: &cid, url: &url, has_id };
            let out = match run_case(&mut r, &cr, true) {
                Ok(o) => o,
                Err(e) if e.contains("budget") => {
                    r.skip(&cid, &e);
                    stopped = Some(e);
                    continue;
                }
                Err(e) => {
                    r.skip(&cid, &e);
                    continue;
                }
            };
            let (mut status, mut attempts) = (out.status, 1);
            if status == ResultStatus::Fail && !op.is_write() {
                let rr = r.rerun(reserve, |me| run_case(me, &cr, false).ok().map(|o| o.status == ResultStatus::Fail));
                r.note_reproduced(&out.defs, &rr);
                status = rr.status();
                attempts = rr.attempts;
            }
            match status {
                ResultStatus::Fail | ResultStatus::Flaky => op_fail = true,
                ResultStatus::Pass => {
                    n_pass += 1;
                    if case.expect == Expect::Success && !op.is_write() && op.path_params().count() == 0 {
                        let e = cheapest.get_or_insert((k.clone(), u128::MAX));
                        if out.ms < e.1 {
                            *e = (k.clone(), out.ms);
                        }
                    }
                }
                _ => {}
            }
            r.result_n(&cid, status, &out.actual, out.ms, &out.defs, attempts);
        }
        // "functional" is Pass only when something actually ran and passed.
        let cell = if op_fail { Cell::Fail } else if n_pass > 0 { Cell::Pass } else { Cell::Untested };
        qa.with(|c| c.coverage.set(&k, "functional", cell));
        if stopped.is_none() {
            pagination(&mut r, op, role, reserve);
        } else {
            for (name, val) in synth::pagination_probes(op).into_iter().filter(|_| op.method == "GET") {
                let cid = format!("api.{}.{}.pagination.{name}.{val}", op.method, op.path);
                r.add_case(&cid, op, Technique::Boundary, Priority::P3, &format!("pagination {name}={val}"), role.map(|x| x.name.as_str()), vec![], "no 5xx for edge paging values");
                r.skip(&cid, stopped.as_deref().unwrap_or("request budget exhausted"));
            }
        }
    }
    if stopped.is_none() && ctx.profile >= Profile::Standard {
        rate_limit_probe(&mut r, cheapest, &roles);
    }
    r.explain_failures();
    // Cleanup first: nothing below may skip it (errors here only become notes).
    r.run_cleanup();
    if let Err(e) = breaking(&mut r, data) {
        qa.with(|c| c.notes.push(format!("spec baseline comparison skipped: {e:#}")));
    }
    r.finish_latency();
    let f = std::mem::take(&mut r.findings);
    Ok(CheckOutput::findings(f))
}

fn pagination(r: &mut Runner, op: &Op, role: Option<&Role>, reserve: usize) {
    if op.method != "GET" {
        return;
    }
    let ids = r.ids_for(op);
    let pv = r.id_map(op, ids.first());
    for (name, val) in synth::pagination_probes(op) {
        let cid = format!("api.{}.{}.pagination.{name}.{val}", op.method, op.path);
        let url = r.url(op, &pv, &[(name.clone(), val.clone())]);
        r.add_case(&cid, op, Technique::Boundary, Priority::P3, &format!("pagination {name}={val}"), role.map(|x| x.name.as_str()), vec![exec::curl_repro("GET", &url, role, None)], "no 5xx for edge paging values");
        let kind = format!("pagination.{name}={val}");
        let probe = |r: &mut Runner| r.send(&Req { op, role, case_id: &cid, kind: &kind, method: "GET", url: &url, body: None, contract: false });
        match probe(r) {
            Ok((ex, _)) if ex.status == 0 => r.result(&cid, ResultStatus::Blocked, &format!("transport error: {}", ex.error.unwrap_or_default()), ex.ms, &[]),
            Ok((ex, defs)) if defs.is_empty() && blocked_reason(op, ex.status, !ids.is_empty()).is_some() => {
                // a 401/403/429/redirect says nothing about paging edge cases
                r.result(&cid, ResultStatus::Blocked, &format!("HTTP {}: {}", ex.status, blocked_reason(op, ex.status, !ids.is_empty()).unwrap_or_default()), ex.ms, &[])
            }
            Ok((ex, defs)) if defs.is_empty() => r.result(&cid, ResultStatus::Pass, &format!("HTTP {}", ex.status), ex.ms, &[]),
            Ok((ex, defs)) => {
                let rr = r.rerun(reserve, |me| probe(me).ok().map(|(e, d)| e.status != 0 && !d.is_empty()));
                r.note_reproduced(&defs, &rr);
                r.result_n(&cid, rr.status(), &format!("HTTP {}", ex.status), ex.ms, &defs, rr.attempts);
            }
            Err(e) => r.skip(&cid, &e),
        }
    }
}

fn rate_limit_probe(r: &mut Runner, cheapest: Option<(String, u128)>, roles: &[&Role]) {
    let Some((key, _)) = cheapest else { return };
    let Some(op) = r.spec.ops.iter().find(|o| o.key() == key).cloned() else { return };
    let role = roles.iter().find(|x| x.expects(&op.path) != Some(false)).copied();
    let url = r.url(&op, &HashMap::new(), &[]);
    let mut limited = false;
    let mut n = 0;
    for _ in 0..15 {
        match exec::send(r.qa, role, "GET", &url, None, &[]) {
            Ok(ex) => {
                n += 1;
                if ex.status == 429 {
                    limited = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let msg = if limited { format!("rate limiting observed on {key} (429 within {n} rapid requests)") } else { format!("no rate limiting observed on {key} after {n} rapid requests (informational, not a defect)") };
    r.qa.with(|c| c.notes.push(msg));
}

/// Compare the spec with the baseline spec (removed endpoints/fields, new required fields).
/// The current spec is always staged in the run dir so `baseline accept` can promote it; the first
/// run seeds the baseline.
fn breaking(r: &mut Runner, data: &Path) -> anyhow::Result<()> {
    let dir = data.join("baselines");
    let path = dir.join(format!("{}.spec-full.json", crate::engine::target_key(&r.ctx.target)));
    let st = stage_dir(&r.ctx.run_dir);
    std::fs::create_dir_all(&st)?;
    std::fs::write(st.join("spec-full.json"), serde_json::to_vec(&r.spec.raw)?)?;
    match std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| spec::parse(v).ok()) {
        Some(old) => {
            for b in contract::breaking_changes(&old, &r.spec) {
                let base = r.base.clone();
                r.defect(NewDefect {
                    rule: "qa.api.breaking_change", cat: Category::Quality, sev: Severity::Medium, prio: Priority::P3,
                    title: format!("Breaking API change on {}: {}", b.op, b.what), expected: "backward-compatible API".into(),
                    actual: b.what.clone(), fp: b.key.clone(),
                    remediation: "Version the API or restore the removed/required element; if the change is intended run `readyhai baseline accept <run>`.", area_cases: "api.contract.breaking",
                    component: b.op.clone(), role: None, method: "GET", url: &base, body: None, ex: None,
                });
            }
        }
        None => {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&path, serde_json::to_vec(&r.spec.raw)?)?;
            r.qa.with(|c| c.notes.push("spec baseline stored (no breaking-change comparison on first run)".into()));
        }
    }
    Ok(())
}
