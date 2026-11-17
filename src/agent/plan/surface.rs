//! Input surface detection, login wall heuristics, route classification, and ledger row emission.

use super::super::oracle::is_login_location;
use super::super::types::{
    BlockReason, DiscoveredRoute, InputSurface, PlannedCase, SRC_AUTH_WALL, SRC_NOT_APPLICABLE,
};
use super::helpers::mk;
use crate::llm::untrusted;

/// What a route takes as input: what discovery recorded, else derived from the route's shape (a
/// JSON/API route, a form, a query string, a request body). A catch-all route (it answers like a
/// path that cannot exist) and an SPA shell take none: the page is static HTML whatever the query.
pub(crate) fn surface_of(r: &DiscoveredRoute) -> InputSurface {
    let raw = raw_surface_of(r);
    if raw == InputSurface::Form && sits_on_a_login(r) {
        // the form is the login form (a page that asks for a password, or the page a redirect
        // lands on): it is the way in, not something to feed injection payloads
        return InputSurface::None;
    }
    raw
}

/// The route's own page is a login: it redirects to one, or asks for a password.
pub(crate) fn sits_on_a_login(r: &DiscoveredRoute) -> bool {
    r.auth_wall
        || r.redirect_chain
            .iter()
            .any(|h| is_login_location(&h.location))
}

pub(crate) fn raw_surface_of(r: &DiscoveredRoute) -> InputSurface {
    if r.catch_all {
        return InputSurface::None;
    }
    // Discovery verified the route with a GET and the server refused the method (405/501): the
    // route exists but takes another verb whose body shape is unknown without a spec. GET-based
    // input cases there can only ever come back "405, not evidence".
    if matches!(r.status_code, 405 | 501) && r.source != "openapi" {
        return InputSurface::None;
    }
    if r.input_surface != InputSurface::None {
        return r.input_surface;
    }
    if r.is_api {
        InputSurface::Json
    } else if r.is_spa_shell {
        InputSurface::None
    } else if r.has_form {
        InputSurface::Form
    } else if r.path.contains('?') {
        InputSurface::Query
    } else if r.has_body {
        InputSurface::Json
    } else {
        InputSurface::None
    }
}

/// The route needs credentials: a 401, a redirect to a login page, or a page that asks for a
/// password (what discovery recorded in `auth_wall`).
pub(crate) fn is_walled(r: &DiscoveredRoute) -> bool {
    r.auth_wall
        || r.status_code == 401
        || r.redirect_chain
            .iter()
            .any(|h| is_login_location(&h.location))
}

/// (expected status, expected behaviour) of a liveness case on a route that answered `status` (the
/// FIRST hop) in discovery. A redirect the executor follows (`redirected`: discovery recorded the
/// chain) is expected to end on a 2xx page; one with no recorded chain is expected to redirect
/// again (and the executor then does not follow it).
pub(crate) fn liveness_expectation(status: Option<u16>, redirected: bool) -> (Option<u16>, &'static str) {
    match status {
        Some(200..=299) => (Some(200), "HTTP 200 OK with a valid response"),
        Some(300..=399) if redirected => (
            Some(200),
            "the same-origin redirect is followed and the page it leads to answers 2xx",
        ),
        Some(300..=399) => (status, "redirects as it did during discovery"),
        _ => (None, "responds without a server error"),
    }
}

/// A route, with what keeps it from being a target (for the evidence of a ledger row).
pub(crate) fn describe_route(r: &DiscoveredRoute) -> String {
    let why = if r.catch_all {
        "catch-all"
    } else if r.is_spa_shell {
        "SPA shell"
    } else if is_walled(r) {
        "login wall"
    } else if (300..=399).contains(&r.status_code) {
        "redirect"
    } else {
        "no input"
    };
    format!("{} ({why})", r.path)
}

/// A row of the ledger that sends nothing: a technique that has no surface to run on
/// ([`BlockReason::NoSurface`], NOT_APPLICABLE, counted in no denominator) or a surface behind a
/// login wall with no credential ([`BlockReason::AuthWall`], BLOCKED). The executor turns it into
/// its result without a request (see `exec::ledger_row_result`).
pub(crate) fn ledger_row(
    technique: &str,
    reason: BlockReason,
    component: &str,
    considered: &[String],
) -> PlannedCase {
    let label = match technique {
        "injection" => "Injection",
        "boundary" => "Boundary",
        _ => "Negative",
    };
    let (title, source) = match reason {
        BlockReason::AuthWall => (
            format!("{label} tests blocked: the discovered routes are behind a login wall"),
            SRC_AUTH_WALL,
        ),
        _ => (
            format!("{label} tests not applicable: no input surface on the discovered routes"),
            SRC_NOT_APPLICABLE,
        ),
    };
    let hint = untrusted::clean(
        &format!("routes considered: {}", considered.join(", ")),
        300,
    );
    mk(
        technique,
        title,
        "GET",
        component.to_string(),
        &hint,
        None,
        "no request is sent",
        None,
        "low",
        "anon",
        source,
    )
}
