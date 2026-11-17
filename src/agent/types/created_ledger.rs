//! Created-resource ledger, thread-local recording scopes, and cleanup teardown reports.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// One resource the run created on the target (so it can be torn down again).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedResource {
    /// Method of the creating request (POST, PUT, ...).
    pub method: String,
    /// Path of the creating request (collection or resource path), no query string.
    pub path: String,
    /// Identifier the target returned for the new resource.
    pub id: String,
    /// Explicit path to DELETE when it is not `<path>/<id>` (e.g. taken from a Location header).
    #[serde(default)]
    pub delete_path: Option<String>,
    /// Credential role that created it (the same role deletes it, when a token is configured).
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub case_id: Option<String>,
}

impl CreatedResource {
    /// The path a teardown DELETE goes to.
    pub fn teardown_path(&self) -> String {
        if let Some(p) = &self.delete_path {
            return p.clone();
        }
        let base = self.path.trim_end_matches('/');
        if base.rsplit('/').next() == Some(self.id.as_str()) {
            base.to_string()
        } else {
            format!("{base}/{}", self.id)
        }
    }
}

const MAX_CREATED: usize = 500;

fn safe_created_path(p: &str) -> bool {
    p.starts_with('/')
        && !p.starts_with("//")
        && p.len() <= 512
        && !p
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || c == '?' || c == '#')
        && !p.split('/').any(|seg| seg == ".." || seg == ".")
}

fn safe_created_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

/// Resources created during a run, shared between the executor and the pipeline (cheap `Clone`).
///
/// The executor/stateful code records every resource it creates:
/// `CreatedLedger::record("/api/items", "42")` after a 2xx POST that returned `{"id": 42}`, or the
/// free function [`record_created`] (no plumbing: the pipeline installs the run's ledger for the
/// running thread). At the end of a non-dry-run run against a nonprod target the pipeline DELETEs
/// them newest first and lists whatever it could not remove under the report's cleanup section.
#[derive(Debug, Clone, Default)]
pub struct CreatedLedger {
    inner: Arc<Mutex<Vec<CreatedResource>>>,
}

impl CreatedLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// A POST created `id` under `path`. Returns false when the entry is unusable (kept out of the
    /// ledger: ids and paths end up in URLs, so only URL-safe values are accepted).
    pub fn record(&self, path: &str, id: &str) -> bool {
        self.record_with("POST", path, id, None, None)
    }

    pub fn record_with(
        &self,
        method: &str,
        path: &str,
        id: &str,
        role: Option<&str>,
        case_id: Option<&str>,
    ) -> bool {
        self.record_resource(CreatedResource {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            id: id.to_string(),
            delete_path: None,
            role: role.map(str::to_string),
            case_id: case_id.map(str::to_string),
        })
    }

    pub fn record_resource(&self, r: CreatedResource) -> bool {
        if !safe_created_path(&r.path)
            || !safe_created_id(&r.id)
            || r.delete_path
                .as_deref()
                .is_some_and(|p| !safe_created_path(p))
        {
            return false;
        }
        let mut v = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if v.len() >= MAX_CREATED || v.iter().any(|x| x.teardown_path() == r.teardown_path()) {
            return false;
        }
        v.push(r);
        true
    }

    pub fn entries(&self) -> Vec<CreatedResource> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether an entry with the same teardown path is already recorded.
    pub fn contains(&self, r: &CreatedResource) -> bool {
        let t = r.teardown_path();
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|x| x.teardown_path() == t)
    }

    /// How many entries were recorded for this case id (the executor tags every creation).
    pub fn recorded_for_case(&self, case_id: &str) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|x| x.case_id.as_deref() == Some(case_id))
            .count()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Make this the ledger [`record_created`] writes to on the current thread until the guard drops.
    pub fn install(&self) -> CreatedScope {
        let prev = CURRENT_LEDGER.with(|c| c.borrow_mut().replace(self.clone()));
        CreatedScope { prev }
    }
}

thread_local! {
    static CURRENT_LEDGER: RefCell<Option<CreatedLedger>> = const { RefCell::new(None) };
}

/// Restores the previously installed ledger on drop.
pub struct CreatedScope {
    prev: Option<CreatedLedger>,
}

impl Drop for CreatedScope {
    fn drop(&mut self) {
        let prev = self.prev.take();
        CURRENT_LEDGER.with(|c| *c.borrow_mut() = prev);
    }
}

/// Record a created resource on the current run's ledger (no-op, false, when none is installed).
pub fn record_created(path: &str, id: &str) -> bool {
    record_created_with("POST", path, id, None, None)
}

pub fn record_created_with(
    method: &str,
    path: &str,
    id: &str,
    role: Option<&str>,
    case_id: Option<&str>,
) -> bool {
    CURRENT_LEDGER.with(|c| {
        c.borrow()
            .as_ref()
            .is_some_and(|l| l.record_with(method, path, id, role, case_id))
    })
}

/// The ledger installed on the current thread, if any. Code that fans out to other threads (a
/// concurrency burst) takes this clone and hands it to them: the thread-local does not reach them.
pub fn current_ledger() -> Option<CreatedLedger> {
    CURRENT_LEDGER.with(|c| c.borrow().clone())
}

/// [`record_created_with`] for a fully described resource (explicit delete path, role, case id).
pub fn record_created_resource(r: CreatedResource) -> bool {
    CURRENT_LEDGER.with(|c| c.borrow().as_ref().is_some_and(|l| l.record_resource(r)))
}

/// A request that created something: a POST that answered 2xx, or a PUT that answered 201.
pub fn is_creation(method: &str, status: u16) -> bool {
    (method.eq_ignore_ascii_case("POST") && (200..300).contains(&status))
        || (method.eq_ignore_ascii_case("PUT") && status == 201)
}

fn id_from_json(v: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    let scalar = |x: &Value| match x {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let from_obj = |o: &serde_json::Map<String, Value>| {
        ["id", "_id", "uuid"]
            .iter()
            .find_map(|k| o.get(*k).and_then(scalar))
            .or_else(|| {
                o.iter()
                    .find(|(k, _)| k.to_ascii_lowercase().ends_with("_id"))
                    .and_then(|(_, x)| scalar(x))
            })
    };
    let o = v.as_object()?;
    from_obj(o).or_else(|| {
        ["data", "result", "item", "resource"]
            .iter()
            .find_map(|k| o.get(*k).and_then(Value::as_object).and_then(from_obj))
    })
}

/// The id a creation response announced: parsed from the body (or a stored excerpt), or, when the
/// text was cut mid-JSON, from the first `"id": ...` in it.
pub fn id_from_body(body: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        return id_from_json(&v);
    }
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r#""(?:id|_id|uuid)"\s*:\s*(?:"([A-Za-z0-9._~-]{1,128})"|(\d{1,20}))"#)
            .unwrap()
    });
    let c = re.captures(body)?;
    c.get(1)
        .or_else(|| c.get(2))
        .map(|m| m.as_str().to_string())
}

pub fn path_of_url(u: &str) -> Option<String> {
    reqwest::Url::parse(u).ok().map(|u| u.path().to_string())
}

/// Record the resource a creating response produced (see [`is_creation`]): the id comes from the
/// body, the delete path from a same-origin `Location` header when there is one. Written to
/// `ledger` when given, otherwise to the ledger installed on the current thread (a no-op when
/// there is none). Returns whether a new entry was recorded; a response that names no id (and no
/// `Location`) cannot be torn down and is reported by the pipeline as unidentified.
#[allow(clippy::too_many_arguments)]
pub fn record_creation_response(
    ledger: Option<&CreatedLedger>,
    method: &str,
    request_url: &str,
    status: u16,
    headers: &[(String, String)],
    body: &str,
    role: Option<&str>,
    case_id: Option<&str>,
) -> bool {
    if !is_creation(method, status) {
        return false;
    }
    let Ok(req) = reqwest::Url::parse(request_url) else {
        return false;
    };
    let location = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .and_then(|(_, v)| req.join(v).ok())
        .filter(|l| l.origin() == req.origin())
        .map(|l| l.path().to_string());
    let body_id = id_from_body(body);
    let (id, delete_path) = match (&location, body_id) {
        (Some(loc), id) => (
            id.unwrap_or_else(|| {
                loc.trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_string()
            }),
            Some(loc.clone()),
        ),
        (None, Some(id)) => (id, None),
        (None, None) => return false,
    };
    let r = CreatedResource {
        method: method.to_ascii_uppercase(),
        path: req.path().to_string(),
        id,
        delete_path,
        role: role.map(str::to_string),
        case_id: case_id.map(str::to_string),
    };
    match ledger {
        Some(l) => l.record_resource(r),
        None => record_created_resource(r),
    }
}

/// A created resource the teardown could not (or was not allowed to) remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leftover {
    pub method: String,
    pub path: String,
    pub id: String,
    pub reason: String,
}

/// What the end-of-run teardown did. Stored beside the report as `cleanup.json`; the report's notes
/// and the "Cleanup" step carry the same facts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    pub created: usize,
    pub attempted: usize,
    pub deleted: usize,
    /// Why no teardown ran (dry-run, target not confirmed nonprod, nothing created, cancelled).
    #[serde(default)]
    pub skipped: Option<String>,
    #[serde(default)]
    pub leftovers: Vec<Leftover>,
    #[serde(default)]
    pub resources: Vec<CreatedResource>,
    /// Deleted resources a follow-up GET confirmed gone (404/410).
    #[serde(default)]
    pub confirmed_gone: usize,
    /// DELETE answered 2xx but the follow-up GET still found the resource: not removed (also listed
    /// under `leftovers`, reason starting `delete_not_effective`).
    #[serde(default)]
    pub still_present: usize,
    /// DELETE answered 2xx and the read-back proved nothing (401/403/5xx/transport error).
    #[serde(default)]
    pub unconfirmed: usize,
}

impl CleanupReport {
    pub fn summary(&self) -> String {
        match (&self.skipped, self.created) {
            (Some(why), 0) => format!("no cleanup needed: {why}"),
            (Some(why), n) => format!(
                "{n} resource(s) created, teardown skipped ({why}); {} left on the target",
                self.leftovers.len()
            ),
            (None, n) => format!(
                "{n} resource(s) created, {} deleted, {} left on the target (follow-up GET: {} confirmed gone, {} still present after a 2xx DELETE, {} unconfirmed)",
                self.deleted,
                self.leftovers.len(),
                self.confirmed_gone,
                self.still_present,
                self.unconfirmed
            ),
        }
    }
}
