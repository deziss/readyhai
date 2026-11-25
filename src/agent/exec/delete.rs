use super::auth::{Bearer, ResolvedAuth, role_of};
use super::builder::{RequestSpec, normalize_component};
use super::clients::{Clients, OutReq, Seen, needs_validated_tls};
use crate::agent::types::record_creation_response;

/// What a read-back after a DELETE found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteCheck {
    /// 404 or 410: the resource is no longer there.
    Gone,
    /// A 2xx answer to the GET: the DELETE did not remove it (carries the status).
    StillPresent(u16),
    /// Anything else (401/403, 3xx, 5xx, a transport error, a path that is not a path on the
    /// target): the read-back proves nothing either way.
    Unknown,
}

/// GET `path` on `base`'s origin, anonymously, after a DELETE of it: 404/410 is [`DeleteCheck::Gone`],
/// 2xx is [`DeleteCheck::StillPresent`], anything else [`DeleteCheck::Unknown`]. A target that needs
/// a credential to read answers 401 here, so use [`confirm_deleted_as`] with the deleting role's
/// bearer when the DELETE itself needed one.
pub fn confirm_deleted(clients: &Clients, base: &str, path: &str) -> DeleteCheck {
    confirm_deleted_as(clients, base, path, None)
}

/// [`confirm_deleted`] with an optional credential. `path` is the full path on the origin of `base`
/// (what teardown deletes, e.g. `/api/orders/12`). The GET goes through [`Clients::send`], so a
/// credential is attached only to the run's own target (exact scheme, host and port) and only over
/// a certificate-validating client; the read-back never leaves that target, redirects are not
/// followed (a 3xx is `Unknown`), and it is not charged to the run budget (teardown is not either).
pub fn confirm_deleted_as(
    clients: &Clients,
    base: &str,
    path: &str,
    bearer: Option<&Bearer>,
) -> DeleteCheck {
    let auth = ResolvedAuth {
        bearer: bearer.cloned(),
        extra_headers: vec![],
        authenticated: bearer.is_some(),
        real: needs_validated_tls(bearer),
        note: None,
    };
    confirm_deleted_resolved(clients, base, path, &auth)
}

/// [`confirm_deleted_as`] supporting full multi-modal credentials (`Bearer`, `Cookie`, custom headers).
pub fn confirm_deleted_resolved(
    clients: &Clients,
    base: &str,
    path: &str,
    auth: &ResolvedAuth,
) -> DeleteCheck {
    let Ok(path) = normalize_component(path) else {
        return DeleteCheck::Unknown;
    };
    let Some(origin) = reqwest::Url::parse(base)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .map(|u| u.origin().ascii_serialization())
    else {
        return DeleteCheck::Unknown;
    };
    let url = format!("{origin}{path}");
    if !clients.is_target_url(&url) {
        return DeleteCheck::Unknown;
    }
    let req = OutReq {
        method: "GET",
        url: &url,
        body: None,
        headers: &[],
        bearer: auth.bearer.as_ref(),
    };
    match clients.send_resolved(&req, auth) {
        Ok(seen) => match seen.status {
            404 | 410 => DeleteCheck::Gone,
            200..=299 => DeleteCheck::StillPresent(seen.status),
            _ => DeleteCheck::Unknown,
        },
        Err(_) => DeleteCheck::Unknown,
    }
}

pub(crate) fn out_req<'a>(spec: &'a RequestSpec, bearer: Option<&'a Bearer>) -> OutReq<'a> {
    OutReq {
        method: spec.method,
        url: &spec.url,
        body: spec.body.as_ref(),
        headers: &spec.extra_headers,
        bearer,
    }
}

/// Record on the run's ledger what a 2xx creating request produced (no-op for anything else, and
/// when no ledger is installed on this thread). Called for every attempt of every request the
/// executor sends: normal cases, re-runs and the adaptive-mutation probe (both go through
/// [`exec_http`]).
pub(crate) fn note_creation(case_id: &str, spec: &RequestSpec, seen: &Seen) {
    record_creation_response(
        None,
        spec.method,
        &spec.url,
        seen.status,
        &seen.headers,
        &seen.body,
        role_of(&spec.auth),
        Some(case_id),
    );
}
