//! Core Runner structure for OpenAPI test execution.
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use crate::ctx::Ctx;
use crate::model::Finding;
use crate::qa::QaCtx;
use crate::qa::api::baseline::cached_spec;
use crate::qa::api::exec::Exchange;
use crate::qa::api::spec::Spec;

pub static DEFECT_SEQ: AtomicUsize = AtomicUsize::new(1);

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
    pub(crate) slowest: HashMap<String, (Exchange, String)>,
    pub(crate) ids: HashMap<String, Vec<String>>,
    /// (url, role name) of resources to DELETE at the end.
    pub cleanup: Vec<(String, String)>,
    /// Extra request headers for the next sends (e.g. an invalid token).
    pub extra: Vec<(String, String)>,
    /// (case id, component) of every case this runner planned (see `explain_failures`).
    pub(crate) my_cases: Mutex<Vec<(String, String)>>,
}

impl<'a> Runner<'a> {
    pub fn new(ctx: &'a Ctx, check: &'static str) -> anyhow::Result<Option<Self>> {
        let Some(qa) = ctx.qa.as_ref() else {
            return Ok(None);
        };
        let Some(spec) = cached_spec(ctx)? else {
            return Ok(None);
        };
        let origin = ctx
            .target
            .url
            .clone()
            .unwrap_or_else(|| ctx.target.raw.clone());
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
}
