//! OpenAPI-driven functional API testing: generated positive/boundary/negative cases,
//! contract checks, auth matrix, stateful CRUD/BOLA, robustness probes.
pub mod authz;
pub mod contract;
pub mod exec;
pub mod synth;
pub mod spec;
pub mod stateful;

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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub fn checks() -> Vec<Check> {
    let w = &[TargetKind::Web];
    vec![
        Check::new("qa.api.functional", "API functional: positive/boundary/negative, contract, robustness", w, Profile::Quick, functional).qa(),
        Check::new("qa.api.authz", "API auth matrix: anonymous, invalid token, roles", w, Profile::Quick, authz::run).qa(),
        Check::new("qa.api.stateful", "API stateful CRUD lifecycle, BOLA, delete semantics", w, Profile::Standard, stateful::run).qa(),
    ]
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
}

impl<'a> Runner<'a> {
    pub fn new(ctx: &'a Ctx) -> anyhow::Result<Option<Self>> {
        let Some(qa) = ctx.qa.as_ref() else { return Ok(None) };
        let Some(spec) = cached_spec(ctx)? else { return Ok(None) };
        let origin = ctx.target.url.clone().unwrap_or_else(|| ctx.target.raw.clone());
        let base = format!("{}{}", origin.trim_end_matches('/'), spec.base_path);
        Ok(Some(Runner {
            ctx,
            qa,
            base,
            tag: format!("readyhai-{}-", ctx.run_id),
            spec,
            findings: vec![],
            lat: HashMap::new(),
            slowest: HashMap::new(),
            ids: HashMap::new(),
            cleanup: vec![],
            extra: vec![],
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
        self.qa.with(|c0| c0.cases.push(c));
    }

    pub fn result(&self, case_id: &str, status: ResultStatus, actual: &str, ms: u128, defects: &[DefectRef]) {
        let r = TestResult {
            case_id: case_id.to_string(),
            status,
            actual: actual.to_string(),
            duration_ms: ms,
            attempts: 1,
            evidence: defects.iter().filter_map(|d| d.ev.clone()).collect(),
            defect_id: defects.first().map(|d| d.id.clone()),
        };
        self.qa.with(|c| c.results.push(r));
    }

    pub fn skip(&self, case_id: &str, why: &str) {
        self.result(case_id, ResultStatus::Skipped, why, 0, &[]);
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
        self.findings.push(def.to_finding(&rule));
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
        let mk = |me: &mut Self, rule: &str, cat, sev, prio, title: String, expected: String, actual: String, fp: String, rem: &str| {
            me.defect(NewDefect {
                rule, cat, sev, prio, title, expected, actual, fp, remediation: rem, area_cases: r.case_id, component: comp.clone(),
                role: r.role, method: r.method, url: r.url, body: r.body, ex: Some(&ex),
            })
        };
        if ex.status >= 500 {
            out.push(mk(self, "qa.api.server_error", Category::Reliability, Severity::High, Priority::P2,
                format!("{key} returns {} on {}", ex.status, r.kind), "4xx for invalid input, never a 5xx".into(),
                format!("HTTP {} ({})", ex.status, role_name), format!("{key}|{}", r.kind),
                "Validate input and handle the failure path; return a 4xx with a structured error body."));
        }
        if let Some(l) = contract::leak_kind(&ex.body) {
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
                        let arr = j.as_array().cloned().or_else(|| j.as_object().and_then(|o| o.values().find_map(|v| v.as_array().cloned())));
                        for it in arr.unwrap_or_default() {
                            let v = [last.name.as_str(), "id", "uuid", "_id"].iter().find_map(|k| it.get(*k)).map(synth::value_str);
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
            let ok = exec::send(self.qa, r, "DELETE", &url, None, &[]).map(|e| e.is_2xx()).unwrap_or(false);
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

/// New resource id from Location header (last segment) or JSON id/uuid/_id.
pub fn created_id(ex: &Exchange) -> Option<String> {
    if let Some(l) = ex.header("location") {
        let seg = l.split(['?', '#']).next().unwrap_or("").trim_end_matches('/').rsplit('/').next().unwrap_or("");
        if !seg.is_empty() {
            return Some(seg.to_string());
        }
    }
    let j = ex.json()?;
    ["id", "uuid", "_id"].iter().find_map(|k| j.get(*k)).map(synth::value_str)
}

pub fn not_applicable() -> CheckOutput {
    CheckOutput::status(CheckStatus::NotApplicable("no OpenAPI spec found (use --spec)".into()))
}

fn functional(ctx: &Ctx) -> anyhow::Result<CheckOutput> {
    let Some(mut r) = Runner::new(ctx)? else { return Ok(not_applicable()) };
    let spec = r.spec.clone();
    let qa = r.qa;
    qa.with(|c| c.untested.extend(spec.untested.iter().cloned()));
    let deep = ctx.profile == Profile::Deep;
    let roles = r.usable_roles();
    let mut stopped = false;
    let mut cheapest: Option<(String, u128)> = None;
    for op in spec.ops.iter() {
        if stopped {
            qa.with(|c| c.untested.push(format!("{}: request budget exhausted", op.key())));
            continue;
        }
        if matches!(op.method.as_str(), "HEAD" | "OPTIONS") {
            continue;
        }
        let role = roles.iter().find(|x| x.expects(&op.path) != Some(false)).copied();
        let idv = r.ids_for(op);
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
        let mut op_fail = false;
        for case in cases {
            if op.is_write() && case.kind.starts_with("positive") {
                continue; // covered by the stateful lifecycle
            }
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
            let req = Req { op, role, case_id: &cid, kind: &case.kind, method: &op.method, url: &url, body: case.body.as_ref(), contract: case.expect == Expect::Success || case.expect == Expect::Reject };
            let (ex, mut defs) = match r.send(&req) {
                Ok(x) => x,
                Err(e) if e.contains("budget") => {
                    r.skip(&cid, &e);
                    stopped = true;
                    break;
                }
                Err(e) => {
                    r.skip(&cid, &e);
                    continue;
                }
            };
            if ex.status == 0 {
                r.result(&cid, ResultStatus::Blocked, &format!("transport error: {}", ex.error.clone().unwrap_or_default()), ex.ms, &[]);
                continue;
            }
            if op.is_write() && ex.is_2xx() && case.expect != Expect::Success {
                r.register_created(op, &ex, role);
            }
            let mut status = ResultStatus::Pass;
            let mut actual = format!("HTTP {} in {} ms", ex.status, ex.ms);
            match case.expect {
                Expect::Success => {
                    if !ex.is_2xx() {
                        if matches!(ex.status, 401 | 403) || (ex.status == 404 && !has_id && op.path_params().count() > 0) {
                            status = ResultStatus::Blocked;
                            actual = format!("HTTP {}: no authorized role / valid resource id available", ex.status);
                        } else {
                            status = ResultStatus::Fail;
                        }
                    }
                    if !op.is_write() && ex.ms > 800 && case.kind == "positive" {
                        for _ in 0..2 {
                            let _ = r.send(&Req { op, role, case_id: &cid, kind: "latency", method: &op.method, url: &url, body: None, contract: false });
                        }
                    }
                    if status == ResultStatus::Pass && !op.is_write() && op.path_params().count() == 0 {
                        let e = cheapest.get_or_insert((op.key(), u128::MAX));
                        if ex.ms < e.1 {
                            *e = (op.key(), ex.ms);
                        }
                    }
                }
                Expect::Reject => {
                    if ex.is_2xx() {
                        status = ResultStatus::Fail;
                        let d = r.defect(NewDefect {
                            rule: "qa.api.validation_missing", cat: Category::Quality, sev: Severity::Medium, prio: Priority::P3,
                            title: format!("{} accepts invalid input ({})", op.key(), case.title), expected: "4xx rejection".into(),
                            actual: format!("HTTP {} accepted it", ex.status), fp: format!("{}|{}", op.key(), case.kind),
                            remediation: "Enforce the documented schema constraints server-side.", area_cases: &cid,
                            component: op.key(), role, method: &op.method, url: &url, body: case.body.as_ref(), ex: Some(&ex),
                        });
                        if op.is_write() {
                            r.register_created(op, &ex, role);
                        }
                        defs.push(d);
                    }
                }
                Expect::NoServerError => {
                    let ct = ex.header("content-type").unwrap_or("").to_ascii_lowercase();
                    if case.marker && ct.contains("html") && ex.body.contains(synth::MARKER) {
                        status = ResultStatus::Fail;
                        let d = r.defect(NewDefect {
                            rule: "qa.api.reflection", cat: Category::Security, sev: Severity::Low, prio: Priority::P3,
                            title: format!("{} reflects input verbatim in HTML", op.key()), expected: "input is encoded or not reflected".into(),
                            actual: "inert marker returned unescaped in text/html".into(), fp: format!("{}|{}", op.key(), case.kind),
                            remediation: "HTML-encode reflected values.", area_cases: &cid, component: op.key(),
                            role, method: &op.method, url: &url, body: case.body.as_ref(), ex: Some(&ex),
                        });
                        defs.push(d);
                    }
                }
            }
            if ex.status >= 500 || !defs.is_empty() {
                status = ResultStatus::Fail;
                actual = format!("HTTP {} ({} defect(s))", ex.status, defs.len());
            }
            if status == ResultStatus::Fail {
                op_fail = true;
            }
            r.result(&cid, status, &actual, ex.ms, &defs);
        }
        let k = op.key();
        qa.with(|c| c.coverage.set(&k, "functional", if op_fail { Cell::Fail } else { Cell::Pass }));
        if !stopped {
            pagination(&mut r, op, role);
        }
    }
    if !stopped && ctx.profile >= Profile::Standard {
        rate_limit_probe(&mut r, cheapest, &roles);
    }
    breaking(&mut r)?;
    r.run_cleanup();
    r.finish_latency();
    let f = std::mem::take(&mut r.findings);
    Ok(CheckOutput::findings(f))
}

fn pagination(r: &mut Runner, op: &Op, role: Option<&Role>) {
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
        match r.send(&Req { op, role, case_id: &cid, kind: &kind, method: "GET", url: &url, body: None, contract: false }) {
            Ok((ex, defs)) => {
                let st = if defs.is_empty() { ResultStatus::Pass } else { ResultStatus::Fail };
                r.result(&cid, st, &format!("HTTP {}", ex.status), ex.ms, &defs);
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

fn breaking(r: &mut Runner) -> anyhow::Result<()> {
    let dir = crate::engine::data_dir().join("baselines");
    let path = dir.join(format!("{}.spec-full.json", crate::engine::target_key(&r.ctx.target)));
    match std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| spec::parse(v).ok()) {
        Some(old) => {
            for b in contract::breaking_changes(&old, &r.spec) {
                r.defect(NewDefect {
                    rule: "qa.api.breaking_change", cat: Category::Quality, sev: Severity::Medium, prio: Priority::P3,
                    title: format!("Breaking API change on {}: {}", b.op, b.what), expected: "backward-compatible API".into(),
                    actual: b.what.clone(), fp: b.key.clone(),
                    remediation: "Version the API or restore the removed/required element.", area_cases: "api.contract.breaking",
                    component: b.op.clone(), role: None, method: "GET", url: &r.base.clone(), body: None, ex: None,
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
