//! Crawl-grounded baseline test case generation (liveness, sensitive files, CORS, and client-side probes).

use super::super::discover::Discovery;
use super::super::exec::Credentials;
use super::super::oracle::Technique;
use super::super::types::{
    BlockReason, DiscoveredRoute, InputSurface, PlannedCase, ResponseContract, StatefulStep,
    TargetTechProfile,
};
use super::helpers::{mk, user_or_anon};
use super::surface::{describe_route, is_walled, ledger_row, liveness_expectation, surface_of};
use super::types::{SQLI, XSS};

pub(crate) fn baseline(d: &Discovery, creds: &Credentials, notes: &mut Vec<String>) -> Vec<PlannedCase> {
    let routes: Vec<&DiscoveredRoute> = d.routes.iter().filter(|r| r.source != "openapi").collect();
    let tech: &TargetTechProfile = &d.tech;
    let user = user_or_anon(creds);
    let user = user.as_str();
    let has_role = creds.actor().is_some();
    let entry = routes
        .iter()
        .find(|r| r.path == "/")
        .map(|r| r.path.as_str())
        .or_else(|| routes.first().map(|r| r.path.as_str()))
        .unwrap_or("/")
        .to_string();
    let entry_route = routes.iter().find(|r| r.path == entry);
    let entry_status = entry_route.map(|r| r.status_code);
    let entry_redirected = entry_route.is_some_and(|r| !r.redirect_chain.is_empty());
    // the entry sits behind a login: with a credential the liveness probe is made as that role
    let live_role = if has_role && entry_route.is_some_and(|r| is_walled(r)) {
        user
    } else {
        "anon"
    };

    // Input surface. Injection, boundary and negative tests are aimed only at a route that takes
    // input (a query string, a form, a JSON/API route, spec parameters) and that is real (not a
    // catch-all answer) and reachable (not behind a login wall when there is no credential to get
    // past it). Probes of sensitive files are not routes of the app.
    let real: Vec<&DiscoveredRoute> = routes
        .iter()
        .copied()
        .filter(|r| r.source != "probe")
        .collect();
    let usable: Vec<&DiscoveredRoute> = real
        .iter()
        .copied()
        .filter(|r| surface_of(r) != InputSurface::None && (has_role || !is_walled(r)))
        .collect();
    // With a spec, the API operations are the spec's: the baseline aims at pages (crawled
    // routes that are not API routes) only. Without one, an API route found by the crawl, a
    // script or the network log is all there is to aim at.
    let attack: Option<&DiscoveredRoute> = usable
        .iter()
        .copied()
        .find(|r| !r.is_api && !r.path.starts_with("/api/"))
        .or_else(|| usable.first().copied().filter(|_| d.spec.is_none()));
    // Discovery learned nothing about the target (no route at all, no spec): it cannot be said
    // that a surface is missing, so the root is probed as before.
    let blind = real.is_empty() && d.spec.is_none();
    let entry_valid_web_page = real
        .iter()
        .find(|r| r.path == entry)
        .map(|r| !r.is_spa_shell && !r.catch_all && !is_walled(r))
        .unwrap_or_else(|| !real.iter().any(|r| is_walled(r)));
    let has_unwalled_web_page = real
        .iter()
        .any(|r| !r.is_spa_shell && !r.catch_all && !is_walled(r));
    let entry_walled = !has_role
        && real
            .iter()
            .find(|r| r.path == entry)
            .is_some_and(|r| is_walled(r));
    let fallback_entry =
        entry_valid_web_page && has_unwalled_web_page && !entry_walled && d.spec.is_none();
    let target_path: Option<String> = attack
        .map(|r| r.path.clone())
        .or_else(|| (blind || fallback_entry).then(|| entry.clone()));
    // a script vector is only reflected by a server-rendered HTML page that reads a parameter
    let xss = match attack {
        Some(r) => {
            r.content_type.to_ascii_lowercase().contains("html")
                && !r.is_spa_shell
                && matches!(surface_of(r), InputSurface::Query | InputSurface::Form)
        }
        None => blind || (fallback_entry && !d.tech.is_spa),
    };
    let content: Vec<&DiscoveredRoute> = real
        .iter()
        .copied()
        .filter(|r| r.path != "/" && !r.path.starts_with("/api/") && !r.catch_all)
        .collect();
    let secondary = content
        .iter()
        .map(|r| r.path.clone())
        .find(|p| Some(p) != target_path.as_ref());
    let form_path = usable
        .iter()
        .find(|r| surface_of(r) == InputSurface::Form)
        .map(|r| r.path.clone());

    let mut out = vec![];
    // liveness of the entry point (and its cookies / headers)
    let (live_status, live_behavior) = liveness_expectation(entry_status, entry_redirected);
    if !matches!(entry_status, Some(401 | 403)) {
        let t = if tech.is_php {
            "Entry page liveness and PHP session cookie hygiene"
        } else {
            "Entry page liveness and session cookie hygiene"
        };
        let mut c = mk(
            "state_transition",
            t.into(),
            "GET",
            entry.clone(),
            if live_role == "anon" {
                "Fetch the entry page without credentials and inspect status and cookies"
            } else {
                "Fetch the entry page, which is behind a login, as the test account and inspect status and cookies"
            },
            None,
            live_behavior,
            live_status,
            "low",
            live_role,
            "deterministic",
        );
        c.route_status = entry_status;
        out.push(c);
    }
    // sensitive-file probes
    for (p, title) in [
        ("/.env", "Environment file is not publicly readable"),
        ("/.git/config", "Git metadata is not publicly readable"),
    ] {
        out.push(mk(
            "authz",
            title.into(),
            "GET",
            p.into(),
            "Direct GET for a sensitive file",
            None,
            "HTTP 403 or 404; no credentials or configuration in the response",
            Some(403),
            "critical",
            "anon",
            "deterministic",
        ));
    }
    if tech.is_php {
        out.push(mk(
            "authz",
            "phpinfo() page is not publicly readable".into(),
            "GET",
            "/phpinfo.php".into(),
            "Direct GET for phpinfo",
            None,
            "HTTP 403 or 404; no PHP configuration dump",
            Some(403),
            "high",
            "anon",
            "deterministic",
        ));
    }
    // routes that demanded credentials during discovery: a forged token must not open them
    for r in routes
        .iter()
        .filter(|r| {
            matches!(r.status_code, 401 | 403)
                && !r.catch_all
                && !matches!(r.source.as_str(), "probe" | "openapi")
        })
        .take(3)
    {
        let mut c = mk(
            "authz",
            format!("Forged bearer token is rejected on {}", r.path),
            "GET",
            r.path.clone(),
            "Send a syntactically valid but forged bearer token",
            None,
            "HTTP 401 or 403",
            Some(401),
            "critical",
            "forged",
            "deterministic",
        );
        c.secured = Some(true);
        c.route_status = Some(r.status_code);
        out.push(c);
    }
    // input cases only when there is a route that takes input to point them at
    if let Some(target_path) = &target_path {
        if xss {
            out.push(mk(
                "injection",
                format!("Reflected XSS probe ({target_path})"),
                "GET",
                target_path.clone(),
                "Inject a script vector into a query parameter",
                Some(format!("q={XSS}")),
                "Payload is not reflected unescaped and causes no server error",
                None,
                "high",
                user,
                "deterministic",
            ));
        }
        out.push(mk(
            "injection",
            format!("SQL injection error probe ({target_path})"),
            "GET",
            target_path.clone(),
            "Inject a SQL tautology into a query parameter",
            Some(format!("q={SQLI}")),
            "No SQL error is disclosed and no server error occurs",
            None,
            "high",
            user,
            "deterministic",
        ));
        match &form_path {
            Some(f) => out.push(mk(
                "boundary",
                format!("Oversized form value tolerance ({f})"),
                "POST",
                f.clone(),
                "4000-character form value",
                Some(format!("data={}", "A".repeat(4000))),
                "Oversized input is handled without a server error",
                None,
                "medium",
                user,
                "deterministic",
            )),
            None => out.push(mk(
                "boundary",
                format!("Oversized query value tolerance ({target_path})"),
                "GET",
                target_path.clone(),
                "4000-character query value",
                Some(format!("q={}", "A".repeat(4000))),
                "Oversized input is handled without a server error",
                None,
                "medium",
                user,
                "deterministic",
            )),
        }
        out.push(mk(
            "negative",
            format!("HEAD verb handling ({target_path})"),
            "HEAD",
            target_path.clone(),
            "HEAD must behave like GET without leaking source or crashing",
            None,
            "HEAD is handled without a server error",
            None,
            "medium",
            user,
            "deterministic",
        ));
        out.push(mk(
            "authz",
            format!("CORS preflight validation ({target_path})"),
            "OPTIONS",
            target_path.clone(),
            "Send a foreign Origin and verify the answer does not reflect it or pair a wildcard with credentials",
            None,
            "A foreign Origin is not granted: Access-Control-Allow-Origin is absent, or does not echo the Origin",
            None,
            "medium",
            "anon",
            "deterministic",
        ));
        out.push(mk(
            "injection",
            format!("Path traversal probe ({target_path})"),
            "GET",
            target_path.clone(),
            "Inject directory traversal sequences into query parameters",
            Some("file=..%2f..%2f..%2fetc%2fpasswd&path=%2e%2e%2f%2e%2e%2fetc%2fpasswd".into()),
            "Path traversal is sanitized or blocked without reading filesystem",
            None,
            "high",
            user,
            "deterministic",
        ));
        out.push(mk(
            "injection",
            format!("NoSQL operator injection probe ({target_path})"),
            "GET",
            target_path.clone(),
            "Inject NoSQL query selectors into query parameters",
            Some("filter[$ne]=null&search[$gt]=".into()),
            "NoSQL query operators are sanitized and cause no database or server error",
            None,
            "high",
            user,
            "deterministic",
        ));
        out.push(mk(
            "boundary",
            format!("Integer overflow & numeric boundary tolerance ({target_path})"),
            "GET",
            target_path.clone(),
            "Inject maximum 64-bit integer and negative bounds",
            Some("id=9223372036854775807&limit=18446744073709551615&offset=-1".into()),
            "Numeric boundaries are handled gracefully without panic or 500 error",
            None,
            "medium",
            user,
            "deterministic",
        ));
    } else if d.spec.is_none() {
        // Nothing to aim an input test at, and no spec to take operations from. Say so in the
        // ledger instead of sending doomed cases at a page that cannot answer them: BLOCKED when
        // the app is behind a login wall and there is no credential (the user can fix that),
        // NOT_APPLICABLE otherwise (nothing takes input; counted in no denominator).
        let walled = !has_role && real.iter().any(|r| !r.catch_all && is_walled(r));
        let reason = if walled {
            BlockReason::AuthWall
        } else {
            BlockReason::NoSurface
        };
        let considered: Vec<String> = real.iter().take(6).map(|r| describe_route(r)).collect();
        for t in ["injection", "boundary", "negative"] {
            out.push(ledger_row(t, reason, &entry, &considered));
        }
        notes.push(if walled {
            format!(
                "no input test was planned: every discovered route with input is behind a login wall and there is no credential ({}). Provide test accounts to test what sits behind it",
                considered.join(", ")
            )
        } else {
            format!(
                "no input test was planned: none of the discovered routes takes input (no query parameter, form or API endpoint: {}). Provide an OpenAPI spec or use the deep profile to find one",
                considered.join(", ")
            )
        });
    }
    if let Some(s) = secondary {
        let route = routes.iter().find(|r| r.path == s);
        let st = route.map(|r| r.status_code);
        let redirected = route.is_some_and(|r| !r.redirect_chain.is_empty());
        let (expected, behavior) = liveness_expectation(st, redirected);
        let mut c = mk(
            "state_transition",
            format!("Page liveness ({s})"),
            "GET",
            s.clone(),
            "Fetch a second discovered page",
            None,
            behavior,
            expected,
            "low",
            "anon",
            "deterministic",
        );
        c.route_status = st;
        out.push(c);
    }
    // The API routes discovery found (no spec describes them): one authenticated read each, the
    // positive path. A walled route is read as the test account; with none there is nothing to
    // learn from the 401 the forged-token case does not already say.
    for r in real
        .iter()
        .filter(|r| {
            r.is_api
                && r.path != "/"
                && r.method.eq_ignore_ascii_case("GET")
                && !r.catch_all
                && !r.path.contains(['{', '?'])
                && (has_role || !is_walled(r))
        })
        .take(3)
    {
        let as_role = has_role && is_walled(r);
        let (expected, behavior) = if as_role {
            (Some(200), "HTTP 2xx with the test account")
        } else {
            liveness_expectation(Some(r.status_code), !r.redirect_chain.is_empty())
        };
        let mut c = mk(
            "state_transition",
            format!("API liveness ({})", r.path),
            "GET",
            r.path.clone(),
            "Read the discovered API route and check it answers",
            None,
            behavior,
            expected,
            "low",
            if as_role { user } else { "anon" },
            "deterministic",
        );
        c.route_status = Some(r.status_code);
        out.push(c);
    }
    // No concurrency burst here: a generic form route declares no request schema, so there is no
    // valid body to send N times. A burst is planned from the spec only (see `spec_cases`).
    if let Some(f) = &form_path {
        out.push(mk(
            "boundary",
            format!("Mass assignment & BOPLA property escalation ({f})"),
            "POST",
            f.clone(),
            "Inject elevated administrative attributes into request body",
            Some(r#"{"role": "admin", "is_admin": true, "is_superuser": true, "permissions": ["*"]}"#.into()),
            "Privilege escalation parameters are safely ignored or rejected",
            None,
            "high",
            user,
            "deterministic",
        ));
    }
    // Stateful BOLA tenant isolation check on discovered API resource routes (never root '/', and never sensitive probe files like .env or .git)
    let is_sensitive_or_static_file = |path: &str| {
        let p = path.to_ascii_lowercase();
        p.starts_with("/.")
            || p.ends_with(".env")
            || p.ends_with(".config")
            || p.ends_with(".bak")
            || p.ends_with(".json")
            || p.ends_with(".yaml")
            || p.ends_with(".yml")
            || p.ends_with(".txt")
    };
    if let Some(api_r) = routes.iter().find(|r| {
        let p = r.path.trim();
        p != "/"
            && !p.is_empty()
            && r.source != "probe"
            && !r.catch_all
            && !is_sensitive_or_static_file(p)
            && (r.is_api || p.starts_with("/api/") || r.has_body)
    }) {
        let step1 = StatefulStep {
            step_number: 1,
            actor: "alice".into(),
            method: "POST".into(),
            path: api_r.path.clone(),
            payload: Some(r#"{"title": "Alice Private Asset"}"#.into()),
            extract_vars: Some(vec!["id".into(), "uuid".into(), "item_id".into()]),
            expected_status: Some(201),
            violation_condition: None,
        };
        let step2 = StatefulStep {
            step_number: 2,
            actor: "bob".into(),
            method: "GET".into(),
            path: format!("{}/{{{{id}}}}", api_r.path.trim_end_matches('/')),
            payload: None,
            extract_vars: None,
            expected_status: Some(403),
            violation_condition: Some("status == 200 || status == 204".into()),
        };
        let mut c = mk(
            "authz",
            format!("Stateful BOLA tenant isolation ({})", api_r.path),
            "POST",
            api_r.path.clone(),
            "Alice creates an object; Bob attempts to read it",
            None,
            "Alice reads her own resource; Bob does not (HTTP 404, or a confirmed 2xx is a breach). Needs RH_ALICE_TOKEN and RH_BOB_TOKEN",
            None,
            "critical",
            "alice",
            "deterministic",
        );
        c.stateful_steps = Some(vec![step1, step2]);
        out.push(c);
    }
    out
}
