//! Dynamic record identifier harvesting from live collection endpoints.
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use super::tech::SpecDoc;
use crate::agent::budget::RunBudget;
use crate::agent::exec::{Auth, Clients, Credentials, OutReq, resolve_auth};

/// Collections read for ids: a few GETs, never a crawl of the API.
pub const MAX_ID_COLLECTIONS: usize = 6;

/// Read the ids of existing records, so the planner reads and checks real ones (the contract of
/// `GET /orders/2`, not of an id that may not exist). For every `GET /x/{id}` of the spec whose
/// collection `GET /x` exists, ONE read-only GET of the collection (as the acting role, or without
/// credentials when it is public) and the ids found in its answer (`qa::api::ids_in_list`). It is
/// a GET, so it is also sent in a dry run, and it is charged to the run budget. Returns the ids by
/// collection path and the notes to report.
pub fn harvest_ids(
    spec: &SpecDoc,
    target: &str,
    creds: &Credentials,
    timeout: Duration,
    budget: &mut RunBudget,
) -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    use crate::qa::api::{collection_of, ids_in_list, synth};
    let mut ids: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut notes = vec![];
    let api = spec.api_ops();
    let Some(parsed) = reqwest::Url::parse(target)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
    else {
        return (ids, notes);
    };
    let Ok(clients) = Clients::new(timeout, &parsed) else {
        return (ids, notes);
    };
    let host = format!(
        "{}:{}",
        parsed.host_str().unwrap_or(""),
        parsed.port_or_known_default().unwrap_or(0)
    );
    let actor = creds.actor();
    let mut tried: Vec<String> = vec![];
    for item in api.iter().filter(|o| o.method == "GET") {
        let Some((list_path, param)) = collection_of(item) else {
            continue;
        };
        if tried.contains(&list_path) || tried.len() >= MAX_ID_COLLECTIONS {
            continue;
        }
        let Some(list) = api
            .iter()
            .find(|o| o.method == "GET" && o.path == list_path && o.path_params().count() == 0)
        else {
            continue;
        };
        let auth = match (&actor, list.secured) {
            (_, false) => Auth::None,
            (Some(a), true) => Auth::Role(a.clone()),
            (None, true) => continue, // nobody to read it as: not worth a 401
        };
        tried.push(list_path.clone());
        // the operation's own valid request (its required query parameters)
        let probe = synth::generate(list, "readyhai-", false, &HashMap::new());
        let Some(valid) = probe.first() else { continue };
        let url = synth::build_url(
            &format!("{}{}", target.trim_end_matches('/'), spec.base_path),
            &list.path,
            &valid.path_vals,
            &valid.query,
        );
        if budget.take_request(&host).is_err() {
            break;
        }
        let resolved = resolve_auth(&auth, creds);
        let sent = clients.send_resolved(
            &OutReq {
                method: "GET",
                url: &url,
                body: None,
                headers: &[],
                bearer: resolved.bearer.as_ref(),
            },
            &resolved,
        );
        let mut found: Vec<String> = vec![];
        if let Ok(seen) = sent
            && (200..300).contains(&seen.status)
            && let Ok(j) = serde_json::from_str::<Value>(seen.body.trim())
        {
            ids_in_list(&j, &param, &mut found);
        }
        if !found.is_empty() {
            ids.insert(list_path, found);
        }
    }
    if !ids.is_empty() {
        notes.push(format!(
            "read the ids of existing records from {} collection(s) (GET, read-only): {}",
            ids.len(),
            ids.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    (ids, notes)
}

/// `host:port`, the key the budget paces requests by.
pub fn host_key_of(u: &reqwest::Url) -> String {
    format!(
        "{}:{}",
        u.host_str().unwrap_or("").to_ascii_lowercase(),
        u.port_or_known_default().unwrap_or(0)
    )
}
