//! HTTP request dispatch, defect creation, resource tracking, and cleanup.
use std::collections::HashMap;
use std::sync::atomic::Ordering;

use super::types::{DEFECT_SEQ, Runner};
use crate::model::{Category, Severity};
use crate::qa::api::contract;
use crate::qa::api::defect_types::{DefectRef, NewDefect, Req};
use crate::qa::api::exec::{self, Exchange};
use crate::qa::api::helpers::{
    MAX_IDS, body_fp_or_empty, collection_of, created_id, ids_in_list,
};
use crate::qa::api::spec::Op;
use crate::qa::api::synth;
use crate::qa::model::{Area, Defect, Priority, Risk};
use crate::qa::roles::Role;

impl<'a> Runner<'a> {
    pub fn usable_roles(&self) -> Vec<&'a Role> {
        let qa = self.qa;
        qa.roles
            .roles
            .iter()
            .filter(|r| exec::role_usable(qa, r))
            .collect()
    }

    pub fn url(&self, op: &Op, pv: &HashMap<String, String>, q: &[(String, String)]) -> String {
        synth::build_url(&self.base, &op.path, pv, q)
    }

    pub fn path_of(&self, op: &Op, pv: &HashMap<String, String>) -> String {
        let u = synth::build_url(&self.base, &op.path, pv, &[]);
        let rest = u.split_once("://").map(|x| x.1).unwrap_or(&u);
        rest.find('/')
            .map(|i| rest[i..].to_string())
            .unwrap_or_default()
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
            c.defects
                .iter_mut()
                .find(|x| x.rule == rule && x.fp_key == d.fp)
                .map(|x| {
                    if !x.cases.contains(&d.area_cases.to_string()) {
                        x.cases.push(d.area_cases.to_string());
                    }
                    (x.id.clone(), x.evidence.first().cloned())
                })
        });
        if let Some((id, ev)) = existing {
            return DefectRef { id, ev };
        }
        let ev = d.ex.and_then(|e| {
            exec::save_evidence(
                self.ctx,
                d.area_cases,
                d.role.map(|r| r.name.as_str()),
                d.body,
                e,
            )
        });
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
                format!(
                    "Prepare credentials as environment variables ({}).",
                    d.role
                        .map(|r| r.placeholder())
                        .unwrap_or_else(|| "none: anonymous request".into())
                ),
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
        let extra: Vec<(&str, &str)> = self
            .extra
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let ex = exec::send(self.qa, r.role, r.method, r.url, r.body, &extra)
            .map_err(|e| e.to_string())?;
        let key = r.op.key();
        self.lat.entry(key.clone()).or_default().push(ex.ms);
        let worst = self.slowest.get(&key).map(|x| x.0.ms).unwrap_or(0);
        if ex.ms >= worst {
            self.slowest
                .insert(key.clone(), (ex.clone(), r.url.to_string()));
        }
        let mut out = vec![];
        let comp = key.clone();
        let role_name = r.role.map(|x| x.name.as_str()).unwrap_or("anon");
        if ex.status == 0 {
            return Ok((ex, out));
        }
        self.responded = true;
        let mk = |me: &mut Self,
                  rule: &str,
                  cat,
                  sev,
                  prio,
                  title: String,
                  expected: String,
                  actual: String,
                  fp: String,
                  rem: &str| {
            me.defect(NewDefect {
                rule,
                cat,
                sev,
                prio,
                title,
                expected,
                actual,
                fp,
                remediation: rem,
                area_cases: r.case_id,
                component: comp.clone(),
                role: r.role,
                method: r.method,
                url: r.url,
                body: r.body,
                ex: Some(&ex),
            })
        };
        if ex.status >= 500 {
            out.push(mk(
                self,
                "qa.api.server_error",
                Category::Reliability,
                Severity::High,
                Priority::P2,
                format!("{key} returns {} on {}", ex.status, r.kind),
                "4xx for invalid input, never a 5xx".into(),
                format!(
                    "HTTP {} ({}); body: {}",
                    ex.status,
                    role_name,
                    body_fp_or_empty(&ex.body)
                ),
                format!("{key}|{}", r.kind),
                "Validate input and handle the failure path; return a 4xx with a structured error body.",
            ));
        }
        // Success pages (nav links, docs prose) are never an error disclosure.
        let leak = if ex.status >= 400 {
            contract::leak_kind(&ex.body)
        } else {
            None
        };
        if let Some(l) = leak {
            out.push(mk(
                self,
                "qa.api.error_leak",
                Category::Security,
                Severity::Medium,
                Priority::P2,
                format!("{key} leaks internal error details ({l})"),
                "generic error body without stack traces or paths".into(),
                format!("response body matched '{l}'"),
                format!("{key}|{l}"),
                "Return generic error messages; log stack traces server-side only.",
            ));
        }
        if r.contract {
            let st = ex.status;
            if contract::undocumented(&r.op.responses, st) {
                out.push(mk(
                    self,
                    "qa.api.undocumented_status",
                    Category::Quality,
                    Severity::Low,
                    Priority::P4,
                    format!("{key} returned undocumented status {st}"),
                    "only documented statuses".into(),
                    format!("HTTP {st} is not in the spec responses"),
                    format!("{key}|{st}"),
                    "Document the status in the OpenAPI responses or fix the behaviour.",
                ));
            }
            if ex.is_2xx()
                && let Some(j) = ex.json()
                && let Some(m) = contract::schema_mismatch(&r.op.responses, st, &j)
            {
                out.push(mk(
                    self,
                    "qa.api.contract_violation",
                    Category::Quality,
                    Severity::Medium,
                    Priority::P3,
                    format!(
                        "{key} response violates its schema ({})",
                        m.split(':').next().unwrap_or("")
                    ),
                    "response matches the documented schema".into(),
                    m.clone(),
                    format!("{key}|{}", contract::normalize_mismatch(&m)),
                    "Make the implementation and the OpenAPI schema agree.",
                ));
            }
        }
        Ok((ex, out))
    }

    /// Ids of existing resources for `{param}` of `op` (from the collection endpoint), cap 3.
    pub fn ids_for(&mut self, op: &Op) -> Vec<String> {
        let Some((list_path, param)) = collection_of(op) else {
            return vec![];
        };
        if let Some(v) = self.ids.get(&list_path) {
            return v.clone();
        }
        let mut found: Vec<String> = vec![];
        let list_op = self
            .spec
            .ops
            .iter()
            .find(|o| o.method == "GET" && o.path == list_path && o.path_params().count() == 0)
            .cloned();
        if let Some(lo) = list_op {
            let url = self.url(&lo, &HashMap::new(), &[]);
            let mut roles: Vec<Option<&Role>> = self.usable_roles().into_iter().map(Some).collect();
            roles.push(None);
            for role in roles {
                if let Ok(ex) = exec::send(self.qa, role, "GET", &url, None, &[])
                    && let Some(j) = ex.json()
                {
                    ids_in_list(&j, &param, &mut found);
                }
                if found.len() >= MAX_IDS {
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

    /// Stop cleaning up `url`: the lifecycle itself deleted it and the re-read proved it gone.
    pub fn forget_cleanup(&mut self, url: &str) {
        self.cleanup.retain(|(u, _)| u != url);
    }

    /// DELETE leftovers created during this check. Whatever could not be deleted is LEAKED test
    /// data: it is named in a note (url + role) and recorded as a risk, never dropped silently.
    pub fn run_cleanup(&mut self) {
        let items = std::mem::take(&mut self.cleanup);
        let mut leaked: Vec<String> = vec![];
        for (url, role) in items {
            let r = self.qa.roles.roles.iter().find(|x| x.name == role);
            // 404 = already gone (e.g. the test deleted it itself)
            let ok = exec::send_cleanup(self.qa, r, &url)
                .map(|e| e.is_2xx() || e.status == 404)
                .unwrap_or(false);
            if !ok {
                leaked.push(format!("DELETE {url} (as {role})"));
            }
        }
        self.record_leaked(leaked);
    }

    /// Note + risk for test data this check could not remove (also for creates that have no
    /// DELETE endpoint at all).
    pub fn record_leaked(&self, leaked: Vec<String>) {
        if leaked.is_empty() {
            return;
        }
        let shown: Vec<&str> = leaked.iter().take(10).map(|s| s.as_str()).collect();
        let more = leaked.len().saturating_sub(10);
        self.qa.with(|c| {
            c.notes.push(format!(
                "cleanup: {} resource(s) tagged '{}' could not be deleted and are LEAKED in the target: {}{}",
                leaked.len(),
                self.tag,
                shown.join("; "),
                if more > 0 { format!("; ... {more} more") } else { String::new() }
            ));
            if !c.risks.iter().any(|r| r.title.starts_with("QA test data left")) {
                c.risks.push(Risk {
                    title: format!(
                        "QA test data left in the target ({} resource(s) tagged '{}')",
                        leaked.len(),
                        self.tag
                    ),
                    level: "medium".into(),
                    mitigation: "Delete the tagged resources by hand (see the cleanup note) and give the spec a DELETE endpoint for them.".into(),
                });
            }
        });
    }

    /// If `ex` is a successful create, schedule DELETE of the new item (when the spec has one).
    pub fn register_created(
        &mut self,
        post: &Op,
        ex: &Exchange,
        role: Option<&Role>,
    ) -> Option<String> {
        if post.method != "POST" {
            return None; // PUT/PATCH/DELETE act on an existing item: nothing was created
        }
        let id = created_id(ex)?;
        let prefix = format!("{}/{{", post.path.trim_end_matches('/'));
        let item = self
            .spec
            .ops
            .iter()
            .find(|o| {
                o.method == "DELETE"
                    && o.path.starts_with(&prefix)
                    && o.path_params().count() == post.path_params().count() + 1
            })
            .cloned();
        if let (Some(d), Some(r)) = (item, role) {
            let mut pv = HashMap::new();
            if let Some(p) = d.path_params().last() {
                pv.insert(p.name.clone(), id.clone());
            }
            let url = self.url(&d, &pv, &[]);
            self.cleanup.push((url, r.name.clone()));
        } else {
            self.record_leaked(vec![format!(
                "{} created resource id {id}: no DELETE endpoint (or no role) to remove it",
                post.key()
            )]);
        }
        Some(id)
    }
}

/// An id of a resource THIS run created for a PUT/PATCH on `/x/{id}`: POST the collection
/// (`/x`) with a synthesised body, register the DELETE cleanup, return the new id. Only on a
/// nonprod host, only when the spec has the DELETE that makes cleanup possible, and `None`
/// otherwise (the caller then uses `unlikely_ids`). It never reads or touches a harvested record.
pub fn scratch_id(r: &mut Runner, op: &Op, role: Option<&Role>) -> Option<String> {
    if !matches!(op.method.as_str(), "PUT" | "PATCH")
        || !r.qa.nonprod
        || op.path_params().count() != 1
    {
        return None;
    }
    let role = role?;
    let last = op.path_params().next()?.name.clone();
    let i = op.path.rfind('/')?;
    if op.path[i + 1..] != format!("{{{last}}}") {
        return None;
    }
    let list_path = op.path[..i].to_string();
    let prefix = format!("{list_path}/{{");
    let post = r
        .spec
        .ops
        .iter()
        .find(|o| o.method == "POST" && o.path == list_path && o.path_params().count() == 0)
        .cloned()?;
    let has_delete = r.spec.ops.iter().any(|o| {
        o.method == "DELETE" && o.path.starts_with(&prefix) && o.path_params().count() == 1
    });
    if !has_delete {
        return None;
    }
    let body = post
        .body
        .as_ref()
        .map(|b| synth::synth(b, "body", &r.tag, 0));
    let url = r.url(&post, &HashMap::new(), &[]);
    let ex = exec::send(r.qa, Some(role), "POST", &url, body.as_ref(), &[]).ok()?;
    if !ex.is_2xx() {
        return None;
    }
    r.register_created(&post, &ex, Some(role))
}
